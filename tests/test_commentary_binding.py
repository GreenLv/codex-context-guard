"""Product source reader regressions; synthetic files, no native acceptance."""
import copy
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from tests import commentary_binding_fixture as fixture
from tests import test_answer_review as reviews

cg = reviews.cg


class BindingTests(unittest.TestCase):
    def setUp(self):
        product_type = type('BoundConsumer', (reviews.ConsumerTests,), {
            'prepare_commentary_source': fixture.prepare})
        self.p = product_type()
        original = cg.dispatch
        def inject_main(event):
            if event.get('prompt') == 'Context Guard 是这个插件的名称吗？':
                original({**event, 'prompt': '请运行 /work/suite.py 的测试并持续执行直到完成。'})
            return original(event)
        with mock.patch.object(cg, 'dispatch', side_effect=inject_main):
            self.p.setUp()
        self.addCleanup(self.p.doCleanups)

    def request(self):
        p = self.p
        return cg.answer_review_request(p.directory, p.host.state(), p.item)

    def modify_payload(self, n, change):
        path = self.p.trace_bundle / f'payloads/{n}.json'
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value), encoding='utf-8')

    def incremental_progress(self):
        fixture.add_progress(self.p)
        self.modify_payload(1, lambda r: r.update(
            previous_response_id='main-response', input=[r['input'][-1]],
        ))

    def append_trace(self, payload):
        path = self.p.trace_bundle / 'trace.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows.append({'schema_version': 1, 'seq': len(rows) + 1,
                     'rollout_id': self.p.host.session_id,
                     'thread_id': self.p.host.session_id,
                     'codex_turn_id': self.p.host.turn_id, 'payload': payload})
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')

    def insert_middle_response(self):
        bundle = self.p.trace_bundle
        request = {'previous_response_id': 'main-response', 'input': [
            {'type': 'custom_tool_call_output', 'call_id': 'old-tool', 'output': 'done'}]}
        response = {'response_id': 'middle-response', 'output_items': [
            {'type': 'reasoning', 'id': 'middle-reasoning'}]}
        for n, value in ((5, request), (6, response)):
            (bundle / f'payloads/{n}.json').write_text(json.dumps(value), encoding='utf-8')
        def ref(n, kind):
            return {'raw_payload_id': f'raw_payload:{n}', 'kind': {'type': kind},
                    'path': f'payloads/{n}.json'}
        path = bundle / 'trace.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        middle = [copy.deepcopy(rows[1]), copy.deepcopy(rows[2])]
        middle[0]['payload'].update(inference_call_id='middle-attempt',
                                    request_payload=ref(5, 'inference_request'))
        middle[1]['payload'].update(inference_call_id='middle-attempt',
                                    response_id='middle-response',
                                    response_payload=ref(6, 'inference_response'))
        rows[3:3] = middle
        for n, row in enumerate(rows, 1):
            row['seq'] = n
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        self.modify_payload(1, lambda r: r.update(previous_response_id='middle-response'))

    def unknown(self):
        with self.assertRaises(ValueError):
            self.request()

    def test_product_binding_is_stable_and_never_core_completion(self):
        before = copy.deepcopy(self.p.host.state())
        self.assertEqual(self.request(), self.request())
        self.assertEqual(self.request()['messages'][0]['association'], 'source_bound_input_response')
        self.p.collect()
        self.assertEqual(self.p.host.state(), before)
        self.assertEqual(cg.reviewed_information(before)[self.p.item['id']]['coverage'], 'complete')

    def test_duplicate_same_text_root_is_unknown(self):
        self.p.collect()
        cg.dispatch(self.p.host.event('UserPromptSubmit', prompt=self.p.request['root_text']))
        self.unknown()
        self.assertEqual(cg.reviewed_information(self.p.host.state())[self.p.item['id']]['coverage'], 'unknown')

    def test_second_same_text_client_cannot_borrow_first_input(self):
        user = copy.deepcopy(self.p.host.rows[-2])
        user['payload']['item'].update(id='different', client_id='different-client')
        self.p.host.rows.append(user)
        self.p.host.write_rows()
        self.unknown()

    def test_queued_unconsumed_and_quoted_question_unknown(self):
        for role in ('assistant', 'tool'):
            with self.subTest(role=role):
                self.modify_payload(1, lambda r: r['input'][0].update(role=role))
                self.unknown()
        self.modify_payload(1, lambda r: r.update(input=[]))
        self.unknown()

    def test_wrong_response_id_and_same_text_wrong_message(self):
        self.modify_payload(2, lambda r: r['output_items'][0].update(id='other-message'))
        self.unknown()
        self.modify_payload(2, lambda r: (r['output_items'][0].update(id='m1'), r.update(response_id='other-response')))
        self.unknown()

    def test_wrong_turn_and_missing_client_remain_unknown(self):
        user = self.p.host.rows[-2]['payload']
        user['turn_id'] = 'other-turn'
        self.p.host.write_rows()
        self.unknown()
        user['turn_id'] = self.p.host.turn_id
        user['item']['client_id'] = None
        self.p.host.write_rows()
        self.unknown()

    def test_fake_edges_do_not_supply_missing_input(self):
        self.modify_payload(1, lambda r: r.update(input=[], trusted=True, root_id=self.p.item['prompt_id'],
                                                  edges=[['client1', 'm1']]))
        self.unknown()

    def test_source_revocation_and_payload_tamper_revoke_review(self):
        self.p.collect()
        state = self.p.host.state()
        with mock.patch.dict(os.environ, CODEX_ROLLOUT_TRACE_ROOT=''):
            self.assertEqual(cg.reviewed_information(state)[self.p.item['id']]['coverage'], 'unknown')
        self.modify_payload(2, lambda r: r['output_items'][0]['content'][0].update(text='Changed answer'))
        self.assertEqual(cg.reviewed_information(state)[self.p.item['id']]['coverage'], 'unknown')

    def test_identical_bytes_replacement_invalidates_old_review(self):
        self.p.collect()
        path = self.p.trace_bundle / 'payloads/1.json'
        replacement = path.with_suffix('.new')
        replacement.write_bytes(path.read_bytes())
        replacement.replace(path)
        self.assertEqual(cg.reviewed_information(self.p.host.state())[self.p.item['id']]['coverage'], 'unknown')

    def test_conflicting_or_truncated_trace_is_unknown(self):
        path = self.p.trace_bundle / 'trace.jsonl'
        path.write_bytes(path.read_bytes()[:-1])
        self.unknown()

    def test_duplicate_user_event_is_idempotent(self):
        before = self.request()['messages']
        self.p.host.rows.append(copy.deepcopy(self.p.host.rows[-2]))
        self.p.host.write_rows()
        self.assertEqual(self.request()['messages'], before)

    def test_unrelated_root_does_not_steal_binding(self):
        before = self.request()['messages']
        cg.dispatch(self.p.host.event('UserPromptSubmit', prompt='为什么需要保留旧缓存？'))
        self.assertEqual(self.request()['messages'], before)
        other = self.p.host.state()['requirements'][-1]
        with self.assertRaisesRegex(ValueError, 'no_source_bound_commentary'):
            cg.answer_review_request(self.p.directory, self.p.host.state(), other)

    def test_unbound_correction_revokes_old_complete_review(self):
        self.p.collect()
        correction = copy.deepcopy(self.p.host.rows[-1])
        correction['payload']['item'].update(id='correction', content=[{'type': 'Text', 'text': 'Correction: earlier answer is wrong.'}])
        correction['payload'].update(started_at_ms=3, completed_at_ms=4)
        self.p.host.rows.append(correction)
        self.p.host.write_rows()
        self.unknown()
        self.assertEqual(cg.reviewed_information(self.p.host.state())[self.p.item['id']]['coverage'], 'unknown')

    def test_conflicting_user_identity_is_unknown(self):
        other = copy.deepcopy(self.p.host.rows[-2])
        other['payload']['item']['content'][0]['text'] = 'Different original input'
        self.p.host.rows.append(other)
        self.p.host.write_rows()
        self.unknown()

    def test_prior_progress_excluded_only_by_explicit_model_input_lineage(self):
        fixture.add_progress(self.p)
        self.p.request = self.request()
        proof = self.p.request['messages'][0]['source_binding']['excluded_prior_messages'][0]
        self.assertEqual(proof['message_id'], 'main-progress')
        self.p.collect()
        self.assertEqual(cg.reviewed_information(self.p.host.state())[self.p.item['id']]['coverage'], 'complete')
        self.modify_payload(1, lambda r: r['input'].pop(1))
        self.unknown()

    def test_incremental_one_hop_progress_consumed_before_question(self):
        self.incremental_progress()
        self.modify_payload(4, lambda r: r['output_items'][0].update(
            internal_chat_message_metadata_passthrough={'source': 'official'},
        ))
        request = self.request()
        proof = request['messages'][0]['source_binding']['excluded_prior_messages'][0]
        self.assertEqual(proof['message_id'], 'main-progress')
        self.assertEqual(proof['causal_hops'], 1)
        self.p.request = request
        before = copy.deepcopy(self.p.host.state())
        self.p.collect()
        self.assertEqual(self.p.host.state(), before)
        self.assertEqual(cg.reviewed_information(before)[self.p.item['id']]['coverage'], 'complete')
        self.modify_payload(4, lambda r: r['output_items'][0]['content'][0].update(
            text='Changed earlier progress',
        ))
        self.assertEqual(cg.reviewed_information(before)[self.p.item['id']]['coverage'], 'unknown')

    def test_incremental_multi_hop_progress_consumed_before_question(self):
        self.incremental_progress()
        self.insert_middle_response()
        proof = self.request()['messages'][0]['source_binding']['excluded_prior_messages'][0]
        self.assertEqual(proof['causal_hops'], 2)

    def test_incremental_question_in_ancestor_request_is_unknown(self):
        self.incremental_progress()
        self.insert_middle_response()
        question = json.loads((self.p.trace_bundle / 'payloads/1.json').read_text())['input'][0]
        self.modify_payload(5, lambda r: r['input'].append(question))
        self.unknown()

    def test_incremental_later_unbound_correction_revokes_review(self):
        self.incremental_progress()
        self.p.request = self.request()
        self.p.collect()
        state = self.p.host.state()
        self.assertEqual(cg.reviewed_information(state)[self.p.item['id']]['coverage'], 'complete')
        correction = copy.deepcopy(self.p.host.rows[-1])
        correction['payload']['item'].update(id='later-correction',
                                             content=[{'type': 'Text', 'text': 'Correction.'}])
        correction['payload'].update(started_at_ms=3, completed_at_ms=4)
        self.p.host.rows.append(correction)
        self.p.host.write_rows()
        self.assertEqual(cg.reviewed_information(self.p.host.state())[self.p.item['id']]['coverage'], 'unknown')

    def test_incremental_persisted_review_cold_replay_and_revocation(self):
        self.incremental_progress()
        self.p.request = self.request()
        self.p.collect()
        program = (
            "import json,sys; from pathlib import Path; "
            "from scripts import context_guard as cg; "
            "state=cg.load_state(Path(sys.argv[1]),{'session_id':sys.argv[2]}); "
            "print(json.dumps(cg.reviewed_information(state)[sys.argv[3]]['coverage']))"
        )
        def cold():
            result = subprocess.run(
                [sys.executable, '-c', program, str(self.p.directory),
                 self.p.host.session_id, self.p.item['id']],
                capture_output=True, text=True, check=True, timeout=15,
                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
            )
            return json.loads(result.stdout)
        self.assertEqual(cold(), 'complete')
        self.modify_payload(4, lambda r: r['output_items'][0]['content'][0].update(
            text='Tampered earlier response'))
        self.assertEqual(cold(), 'unknown')

    def test_incremental_missing_or_duplicate_response_is_unknown(self):
        self.incremental_progress()
        self.modify_payload(1, lambda r: r.update(previous_response_id='missing-response'))
        self.unknown()
        self.modify_payload(1, lambda r: r.update(previous_response_id='main-response'))
        self.append_trace({'type': 'inference_completed', 'inference_call_id': 'duplicate',
                           'response_id': 'main-response', 'response_payload': {
                               'raw_payload_id': 'raw_payload:4',
                               'kind': {'type': 'inference_response'},
                               'path': 'payloads/4.json'}})
        self.unknown()

    def test_incremental_fork_and_failed_attempt_are_unknown(self):
        self.incremental_progress()
        (self.p.trace_bundle / 'payloads/5.json').write_text(json.dumps({
            'previous_response_id': 'main-response', 'input': []}), encoding='utf-8')
        self.append_trace({'type': 'inference_started', 'inference_call_id': 'fork',
                           'thread_id': self.p.host.session_id,
                           'codex_turn_id': self.p.host.turn_id,
                           'request_payload': {'raw_payload_id': 'raw_payload:5',
                                               'kind': {'type': 'inference_request'},
                                               'path': 'payloads/5.json'}})
        self.unknown()
        path = self.p.trace_bundle / 'trace.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()][:-1]
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        self.append_trace({'type': 'inference_failed', 'inference_call_id': 'main-attempt'})
        self.unknown()

    def test_incremental_cycle_and_foreign_scope_are_unknown(self):
        self.incremental_progress()
        self.modify_payload(3, lambda r: r.update(previous_response_id='answer-response'))
        self.unknown()
        self.modify_payload(3, lambda r: r.pop('previous_response_id'))
        path = self.p.trace_bundle / 'trace.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[1]['codex_turn_id'] = 'foreign-turn'
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        self.unknown()
        rows[1]['codex_turn_id'] = self.p.host.turn_id
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')

    def test_incremental_unknown_extra_output_and_truncated_parent_unknown(self):
        self.incremental_progress()
        self.modify_payload(4, lambda r: r['output_items'][0].update(untrusted_status='done'))
        self.unknown()
        self.modify_payload(4, lambda r: r['output_items'][0].pop('untrusted_status'))
        path = self.p.trace_bundle / 'trace.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows = [r for r in rows if not (r['payload'].get('type') == 'inference_completed'
                                        and r['payload'].get('inference_call_id') == 'main-attempt')]
        for n, row in enumerate(rows, 1):
            row['seq'] = n
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        self.unknown()

    def test_incremental_cancelled_and_foreign_rollout_are_unknown(self):
        self.incremental_progress()
        self.append_trace({'type': 'inference_cancelled',
                           'inference_call_id': 'main-attempt'})
        self.unknown()
        path = self.p.trace_bundle / 'trace.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()][:-1]
        rows[1]['rollout_id'] = 'foreign-rollout'
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        self.unknown()

    def test_incremental_answer_terminal_must_follow_start(self):
        self.incremental_progress()
        path = self.p.trace_bundle / 'trace.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[3], rows[4] = rows[4], rows[3]
        for n, row in enumerate(rows, 1):
            row['seq'] = n
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        self.unknown()

    def test_progress_order_in_notifications_is_not_exclusion_authority(self):
        fixture.add_progress(self.p)
        original = self.request()['messages']
        progress = self.p.host.rows.pop(-3)
        self.p.host.rows.append(progress)
        self.p.host.write_rows()
        # Raw source ordinal changes are intentionally excluded here; the
        # derived causal binding itself is unaffected by notification order.
        self.assertEqual(self.request()['messages'][0]['source_binding'], original[0]['source_binding'])
        self.modify_payload(3, lambda r: r.update(previous_response_id='unknown-ancestor'))
        self.unknown()

    def test_root_hash_corruption_is_unknown(self):
        state = self.p.host.state()
        state['prompts'][-1]['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            cg.answer_review_request(self.p.directory, state, self.p.item)

    def test_truncated_root_catalog_cannot_manufacture_uniqueness(self):
        state = self.p.host.state()
        state['prompts'] = state['prompts'][1:]
        with self.assertRaises(ValueError):
            cg.answer_review_request(self.p.directory, state, self.p.item)

    def test_missing_trace_preserves_noninformation_business_projection(self):
        state = self.p.host.state()
        (self.p.trace_bundle / 'trace.jsonl').unlink()
        projection = cg.current_scope_projection(state)
        self.assertTrue(projection)
        self.assertEqual(state, self.p.host.state())

    def test_duplicate_trace_bundle_and_missing_source_are_unknown(self):
        import shutil
        second = self.p.trace_bundle.with_name('trace-second-' + self.p.host.session_id)
        shutil.copytree(self.p.trace_bundle, second)
        path = second / 'manifest.json'
        value = json.loads(path.read_text())
        value['trace_id'] = 'second'
        path.write_text(json.dumps(value), encoding='utf-8')
        self.unknown()
        shutil.rmtree(second)
        (self.p.trace_bundle / 'payloads/1.json').unlink()
        self.unknown()
