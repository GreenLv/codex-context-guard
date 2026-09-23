"""Independent R11 malformed-source and current-consumer holdouts."""
import unittest

from tests import test_answer_review as base


class SourceBoundaryTests(unittest.TestCase):
    setUp = base.ConsumerTests.setUp
    configure = base.ConsumerTests.configure
    stdout = base.ConsumerTests.stdout
    collect = base.ConsumerTests.collect

    def test_unrelated_payload_shapes_do_not_crash_scope(self):
        self.collect()
        original = list(self.host.rows)
        for value in (None, [], 'text', {'item': None}):
            with self.subTest(payload=value):
                self.host.rows = original + [{'type': 'unrelated_record', 'payload': value}]
                self.host.write_rows()
                scope = base.cg.current_scope_projection(self.host.state())
                self.assertNotIn(self.item['id'], scope['current_item_ids'])

    def test_unrelated_records_across_stop_recovery_and_status(self):
        import contextlib
        import copy
        import io
        from types import SimpleNamespace
        self.collect()
        original = list(self.host.rows)
        requirements = copy.deepcopy(self.host.state()['requirements'])
        for value in (None, [], 'text', {'item': None}):
            self.host.rows = original + [{'type': 'unrelated_record', 'payload': value}]
            self.host.write_rows()
            for kind, extra in [('Stop', {'last_assistant_message': '我会继续核实这个问题。'}),
                                ('PreCompact', {}), ('SessionStart', {'source': 'compact'}),
                                ('SessionStart', {'source': 'resume'})]:
                base.cg.dispatch(self.host.event(kind, **extra))
            self.assertEqual(self.host.state()['requirements'], requirements)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(base.cg.command_status(), 0)
                self.assertEqual(base.cg.command_diagnose(SimpleNamespace(limit=3)), 0)

    def test_related_malformed_messages_are_unknown_not_crashes(self):
        self.collect()
        original = list(self.host.rows)
        for value in (None, [], 'text', {'type': 'AgentMessage', 'content': None},
                      {'type': 'AgentMessage', 'content': [None]}):
            self.host.rows = original + [{'type': 'event_msg', 'payload': {'type': 'item_completed', 'item': value}}]
            self.host.write_rows()
            result = base.cg.current_scope_projection(self.host.state())
            self.assertIn(self.item['id'], result['current_item_ids'])
            for kind, extra in [('PreCompact', {}), ('SessionStart', {'source': 'resume'})]:
                base.cg.dispatch(self.host.event(kind, **extra))

    def test_state_integrity_failure_is_not_swallowed(self):
        self.collect()
        state = self.host.state()
        state['integrity']['status'] = 'failed'
        with self.assertRaises(base.cg.StateIntegrityError):
            base.cg.handle_pre_compact(self.directory, state, self.host.event('PreCompact'))

    def test_wrong_message_turn_and_missing_root_turn(self):
        self.collect()
        self.host.rows[-1]['payload']['turn_id'] = 'other-turn'
        self.host.write_rows()
        result = base.cg.current_scope_projection(self.host.state())
        self.assertIn(self.item['id'], result['current_item_ids'])
        h = base.wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        base.cg.dispatch(h.event('UserPromptSubmit', prompt='context-guard on'))
        event = h.event('UserPromptSubmit', prompt='Context Guard 是插件吗？')
        event.pop('turn_id')
        base.cg.dispatch(event)
        with self.assertRaises(ValueError):
            base.cg.answer_review_subject(h.root / 'private/sessions' / h.session_id,
                                          h.state(), h.state()['requirements'][-1])

    def test_future_or_incomparable_signed_asof_is_rejected(self):
        import copy
        identity = self.collect()
        path = self.reviews / ('capture-' + identity + '.json')
        original = base.review.read(path)
        for change in ({'watermark': 999999}, {'source': 'foreign-clock'}, {'watermark': 1}):
            value = copy.deepcopy(original)
            value['payload']['request']['as_of'].update(change)
            value['payload']['record']['as_of'].update(change)
            value['mac'] = base.review.seal(value['payload'], (self.reviews / 'capture.key').read_bytes())
            path.write_bytes(base.review.canonical(value))
            result = base.cg.current_scope_projection(self.host.state())
            self.assertIn(self.item['id'], result['current_item_ids'])

    def test_real_wait_and_cancellation_not_changed_by_review(self):
        import copy
        self.collect()
        h = self.host
        target = h.cwd / 'suite.py'
        h.write_file(target, 'def test_ok(): assert True\n')
        h.turn_id = 'business'
        base.cg.dispatch(h.event('UserPromptSubmit', prompt=f'请运行 "{target}" 的测试并持续执行直到任务完成。'))
        main_id = h.state()['requirements'][-1]['id']
        for control in ('暂停当前任务。', '取消当前任务。'):
            base.cg.dispatch(h.event('UserPromptSubmit', prompt=control))
            state = h.state()
            before = copy.deepcopy(state)
            scope = base.cg.current_scope_projection(state)
            if control.startswith('暂停'):
                self.assertTrue(scope['waiting_conditions'])
            else:
                self.assertNotIn(main_id, scope['current_item_ids'])
            base.cg.reviewed_information(state)
            self.assertEqual(state, before)
            base.cg.dispatch(h.event('PreCompact'))
            after = h.state()
            self.assertEqual(after['wait_conditions'], before['wait_conditions'])
            self.assertEqual(after['requirements'], before['requirements'])
            self.assertEqual(after['root_controls'], before['root_controls'])


class AssociationTests(unittest.TestCase):
    configure = base.ConsumerTests.configure

    def setUp(self):
        base.ConsumerTests.setUp(self)
        h = self.host
        h.turn_id = 'mixed-root'
        base.cg.dispatch(h.event('UserPromptSubmit', prompt='请运行 /work/suite.py 的测试，并介绍这个仓库的主要内容，并解释核心逻辑。'))
        state = h.state()
        self.questions = [i for i in state['requirements'] if i.get('information_source_span')]
        self.assertEqual(len(self.questions), 2)
        self.add_message('a', 3, 'The repository contains the plugin implementation.')

    def add_message(self, identity, started, text):
        event = base.message(mid=identity, turn=self.host.turn_id, text=text)
        event['payload'].update(thread_id=self.host.session_id, started_at_ms=started, completed_at_ms=started + 1)
        self.host.rows.append(event)
        self.host.write_rows()

    def collect_mapping(self, index, mapping):
        import json
        import subprocess
        from unittest.mock import patch
        item = self.questions[index]
        request = base.cg.answer_review_request(self.directory, self.host.state(), item)
        mids = [m['message_id'] for m in request['messages']]
        result = {'verdict': 'complete', 'information_only': True,
                  'message_ids': [m for m in mids if mapping[m] is not None and item['id'] in mapping[m]],
                  'associations': [{'message_id': m, 'question_ids': mapping[m]} for m in mids]}
        stdout = '\n'.join(json.dumps(r) for r in (
            {'type': 'thread.started', 'thread_id': 'independent'}, {'type': 'turn.started'},
            {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': json.dumps(result)}},
            {'type': 'turn.completed'}))
        with patch.object(base.review, 'invoke', return_value=subprocess.CompletedProcess([], 0, stdout, '')):
            return base.review.collect(self.reviews, request, self.binary, self.binary_hash, 'fixture-v1', execute=True)

    def test_new_message_for_other_question_preserves_existing_coverage(self):
        q1, q2 = [i['id'] for i in self.questions]
        self.collect_mapping(0, {'a': [q1]})
        before = base.cg.current_scope_projection(self.host.state())
        self.assertNotIn(q1, before['current_item_ids'])
        self.assertIn(q2, before['current_item_ids'])
        self.add_message('b', 5, 'The core logic binds original requirements to evidence.')
        self.assertIn(q1, base.cg.current_scope_projection(self.host.state())['current_item_ids'])
        self.collect_mapping(1, {'a': [q1], 'b': [q2]})
        result = base.cg.current_scope_projection(self.host.state())
        self.assertNotIn(q1, result['current_item_ids'])
        self.assertNotIn(q2, result['current_item_ids'])
        # The actual mixed execution root is still pending.
        parent = self.questions[0]['parent_id']
        self.assertIn(parent, result['current_item_ids'])
        base.cg.dispatch(self.host.event('PreCompact'))
        base.cg.dispatch(self.host.event('SessionStart', source='resume'))
        result = base.cg.current_scope_projection(self.host.state())
        self.assertNotIn(q1, result['current_item_ids'])
        self.assertIn(parent, result['current_item_ids'])

    def test_conflicting_or_unknown_association_never_picks_latest(self):
        q1, q2 = [i['id'] for i in self.questions]
        self.collect_mapping(0, {'a': [q1]})
        self.add_message('b', 5, 'Another reply.')
        self.collect_mapping(1, {'a': [q2], 'b': None})
        result = base.cg.current_scope_projection(self.host.state())
        self.assertIn(q1, result['current_item_ids'])
        self.assertIn(q2, result['current_item_ids'])

    def test_foreign_question_id_cannot_be_invented_by_reviewer(self):
        with self.assertRaises(ValueError):
            self.collect_mapping(0, {'a': ['R99999']})

    def test_source_parsed_once_per_projection_and_never_cached_across_calls(self):
        from unittest.mock import patch
        with patch.object(base.cg, 'answer_review_source', wraps=base.cg.answer_review_source) as observe:
            base.cg.current_scope_projection(self.host.state())
            self.assertEqual(observe.call_count, 1)
            base.cg.current_scope_projection(self.host.state())
            self.assertEqual(observe.call_count, 2)


class SchedulingTests(unittest.TestCase):
    setUp = base.ConsumerTests.setUp
    configure = base.ConsumerTests.configure
    stdout = base.ConsumerTests.stdout

    def test_one_new_call_no_repeat_on_partial_or_unrelated_growth(self):
        import subprocess
        from unittest.mock import patch
        with patch.object(base.review, 'invoke', return_value=subprocess.CompletedProcess([], 0, self.stdout('partial'), '')) as run:
            preview = base.review.pending_review(self.reviews, [self.request])
            self.assertEqual(preview['status'], 'pending_review')
            run.assert_not_called()
            self.assertEqual(base.review.pending_review(self.reviews, [self.request], execute=True)['model_calls'], 1)
            self.host.rows.append({'type': 'unrelated_record', 'payload': None})
            self.host.write_rows()
            request = base.cg.answer_review_request(self.directory, self.host.state(), self.item)
            self.assertEqual(base.review.pending_review(self.reviews, [request], execute=True)['model_calls'], 0)
            self.assertEqual(run.call_count, 1)

    def test_failed_attempt_is_not_an_automatic_retry_loop(self):
        from unittest.mock import patch
        with patch.object(base.review, 'invoke', side_effect=ValueError('fixture failure')) as run:
            with self.assertRaises(ValueError):
                base.review.pending_review(self.reviews, [self.request], execute=True)
            self.assertEqual(base.review.pending_review(self.reviews, [self.request], execute=True)['model_calls'], 0)
            self.assertEqual(run.call_count, 1)

    def test_new_delivery_replaces_only_validated_unique_predecessor(self):
        import subprocess
        from unittest.mock import patch
        with patch.object(base.review, 'invoke', return_value=subprocess.CompletedProcess([], 0, self.stdout('partial'), '')):
            base.review.pending_review(self.reviews, [self.request], execute=True)
        event = base.message(mid='new', turn=self.host.turn_id, text='The remaining answer.')
        event['payload'].update(thread_id=self.host.session_id, started_at_ms=3, completed_at_ms=4)
        self.host.rows.append(event)
        self.host.write_rows()
        self.request = base.cg.answer_review_request(self.directory, self.host.state(), self.item)
        with patch.object(base.review, 'invoke', return_value=subprocess.CompletedProcess([], 0, self.stdout(), '')):
            base.review.pending_review(self.reviews, [self.request], execute=True)
        self.assertNotIn(self.item['id'], base.cg.current_scope_projection(self.host.state())['current_item_ids'])

    def test_normal_flow_cli_dispatches_one_review_without_state_closure(self):
        import contextlib
        import copy
        import io
        import subprocess
        from types import SimpleNamespace
        from unittest.mock import patch
        state = self.host.state()
        turn, token = base.cg.begin_completion_attempt(state, self.host.event('Stop'), self.host.turn_id)
        base.cg.save_state(self.directory, state)
        before = copy.deepcopy(state['requirements'])
        args = SimpleNamespace(data_dir=self.host.root / 'private', session_id=self.host.session_id,
                               turn_id=turn, token=token, execute=True)
        with patch.object(base.review, 'invoke', return_value=subprocess.CompletedProcess([], 0, self.stdout(), '')) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(base.cg.command_review_pending(args), 0)
                self.assertEqual(base.cg.command_review_pending(args), 0)
            self.assertEqual(run.call_count, 1)
        after = self.host.state()
        self.assertEqual(after['requirements'], before)
        self.assertNotIn(self.item['id'], base.cg.current_scope_projection(after)['current_item_ids'])


class ProcessBoundaryTests(unittest.TestCase):
    def test_unsupported_platform_does_not_launch(self):
        from unittest.mock import patch

        from scripts import cg_process_tree
        with patch.object(cg_process_tree.os, 'name', 'unsupported'), patch.object(cg_process_tree.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(ValueError, 'route_unavailable'):
                cg_process_tree.OwnedProcess.spawn(['fixture'])
            launch.assert_not_called()

    @unittest.skipUnless(base.review.os.name == "posix", "POSIX cleanup route unavailable")
    def test_cleanup_wait_is_bounded(self):
        import subprocess
        from unittest.mock import Mock, patch
        process = Mock(pid=123, returncode=0)
        process.poll.return_value = 0
        process.wait.side_effect = subprocess.TimeoutExpired('fixture', 3)
        with patch.object(base.review.subprocess, 'Popen', return_value=process), patch.object(base.review.os, 'killpg'):
            with self.assertRaisesRegex(ValueError, 'cleanup_timeout'):
                base.review.invoke(['fixture'], '')
        self.assertGreaterEqual(process.wait.call_count, 1)

    @unittest.skipUnless(base.review.os.name == "posix", "POSIX process-group probe unavailable")
    def test_posix_descendant_cleanup_after_parent_exit_and_timeout(self):
        import os
        import sys
        import tempfile
        import time
        from pathlib import Path
        for parent_wait in (False, True):
            with tempfile.TemporaryDirectory() as folder:
                target = Path(folder) / 'pid'
                script = ('import subprocess,sys,time; from pathlib import Path; '
                          'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); '
                          f'Path({str(target)!r}).write_text(str(p.pid)); '
                          + ('time.sleep(30)' if parent_wait else 'print("ok")'))
                if parent_wait:
                    with self.assertRaisesRegex(ValueError, 'review_timeout'):
                        base.review.invoke([sys.executable, '-c', script], '', timeout=0.3)
                else:
                    self.assertEqual(base.review.invoke([sys.executable, '-c', script], '').returncode, 0)
                pid = int(target.read_text())
                deadline = time.monotonic() + 2
                while True:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    if time.monotonic() >= deadline:
                        self.fail('owned descendant remains observable after group cleanup')
                    time.sleep(0.01)
