"""P1 coordinator counterexamples through real Hook entry points."""
from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
import re

from tests.test_cg122_p0_counterexamples import P0Harness, cg


class SwitchAuthorityTests(P0Harness):
    def test_non_controls_preserve_original_obligations(self):
        cases = (
            '不要切换到新任务，继续检查当前实现。',
            '测试应覆盖“切换到新任务”的情形。',
            '测试应覆盖切换到新任务的情形。',
            'Implement a regression test for switching to a new task.',
            'Do not switch to a new task. Continue checking this implementation.',
            '> Switch to a new task.\n继续检查当前实现。',
            '文档显示独立任务的恢复状态。',
            '是否切换到新任务？',
            'If we switch to a new task, the old one should be parked.',
        )
        for index, text in enumerate(cases):
            with self.subTest(text=text):
                session = f'switch-{index}'
                self.activate(session)
                self.prompt('请修复恢复模块。必须运行测试验证。不要推送。', session)
                self.prompt(text, session)
                state = self.state(session)
                self.assertEqual(len(state['work_units']), 1)
                self.assertEqual(state['requirements'][0]['status'], 'pending')
                self.assertIn('R001', cg.checkpoint_scope_item_ids(state)[0])

    def test_real_switch_mixed_and_long_prompts(self):
        for index, text in enumerate((
            '切换到新任务：检查文档拼写。',
            '新的独立请求:请检查文档拼写。必须运行测试验证。',
            '测试应覆盖切换任务的情形。另外，现在切换到新任务：检查拼写。',
            ('请保留现有调查记录。' * 80) + '现在切换到新任务：检查拼写。',
            'Do not cancel the old requirement. Switch to a new task: inspect spelling.',
        )):
            with self.subTest(index=index):
                session = f'positive-{index}'
                self.activate(session)
                self.prompt('请修复恢复模块。必须运行测试验证。', session)
                self.prompt(text, session)
                state = self.state(session)
                self.assertEqual(len(state['work_units']), 2)
                self.assertEqual(state['work_units'][0]['status'], 'historical_unresolved')
                self.assertEqual(state['requirements'][0]['status'], 'pending')


class WaitIdentityTests(P0Harness):
    def park(self, session='p0'):
        self.activate(session)
        self.prompt('请修复恢复模块。在我确认模型更换完成前，本任务保持等待。必须运行测试验证。不要推送。', session)
        self.dispatch('Stop', session=session, last_assistant_message='已按要求暂停等待确认。')

    def test_unrelated_negative_question_quoted_confirmation_stays_waiting(self):
        for index, text in enumerate((
            '文档已经准备好了。', '文件校验已经完成。', '模型还没换好，先别继续。',
            '模型换好了吗？', 'Is the model ready?', '“模型已换好，继续。”是测试输入。',
            '测试应覆盖模型已换好的情形。', 'Do not resume the current task.',
            '不要继续刚才的任务。', '模型已换好，但还没有确认完成。', '模型还没换好，继续。', '模型未完成，继续。',
            'The model is not ready. Continue.', 'The model is incomplete. Continue.',
        )):
            with self.subTest(text=text):
                session = f'wait-{index}'
                self.park(session)
                self.prompt(text, session)
                state = self.state(session)
                self.assertEqual(state['wait_conditions'][0]['status'], 'waiting')
                self.assertEqual(state['work_units'][0]['status'], 'awaiting_user')

    def test_two_same_type_conditions_release_only_matching_subject(self):
        self.park()
        self.prompt('补充：在我确认文件校验完成前，本任务保持等待。')
        state = self.state()
        self.assertEqual(len(state['wait_conditions']), 2)
        self.prompt('继续。')
        self.assertTrue(all(c['status'] == 'waiting' for c in self.state()['wait_conditions']))
        self.prompt('模型已换好，继续。')
        state = self.state()
        self.assertEqual([c['status'] for c in state['wait_conditions']], ['released', 'waiting'])
        self.assertEqual(state['work_units'][0]['status'], 'awaiting_user')
        self.dispatch('PreCompact')
        self.dispatch('SessionStart', source='resume')
        self.prompt('文件校验已经完成。')
        state = self.state()
        self.assertEqual([c['status'] for c in state['wait_conditions']], ['released', 'released'])
        self.assertEqual(state['work_units'][0]['status'], 'active')
        self.assertEqual(state['requirements'][0]['status'], 'pending')
        # 0.13 transfer of the trailing default-deny pin: wait release no
        # longer re-arms an execution gate because the default path has no
        # execution veto; the released wait still keeps the requirement open.
        self.assertEqual(self.decision('git push origin main')[0], 'allow')

    def test_two_pauses_in_one_prompt_and_replay(self):
        self.activate()
        prompt = '请修复恢复模块。在我确认模型更换完成前，本任务保持等待。在我确认文件校验完成前，本任务保持等待。必须运行测试验证。'
        self.prompt(prompt)
        self.dispatch('Stop', last_assistant_message='已按要求暂停等待确认。')
        self.assertEqual(len(self.state()['wait_conditions']), 2)
        self.prompt('模型已换好，继续。')
        self.prompt(prompt)
        self.assertEqual(len(self.state()['wait_conditions']), 2)
        self.assertEqual([c['status'] for c in self.state()['wait_conditions']], ['released', 'waiting'])

    def test_invalid_or_wrong_authority_source_fails_closed(self):
        self.park()
        original = self.state()
        for value in ('arbitrary', 'P9999', 'E0001', 'P0001'):
            with self.subTest(source=value):
                state = copy.deepcopy(original)
                state['wait_conditions'][0]['raised_by_source'] = value
                with self.assertRaises(cg.StateIntegrityError):
                    cg.validate_wait_conditions(state)
        state = copy.deepcopy(original)
        state['wait_conditions'][0]['condition_type'] = 'external_dependency'
        state['wait_conditions'][0].update(status='released', released_at=cg.utc_now(),
                                           released_by_kind='root_user_confirmation', released_by_source='P0002')
        with self.assertRaises(cg.StateIntegrityError):
            cg.validate_wait_conditions(state)


class CompleteRecoveryTests(P0Harness):
    def page(self, session='p0', cursor=None, limit=4):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cg.command_recovery_page(argparse.Namespace(session_id=session, cursor=cursor, limit=limit))
        return code, json.loads(output.getvalue())

    def test_complete_prompt_suffix_and_explicit_session(self):
        self.activate()
        text = '请审查恢复实现。' + ('中文 and English requirement details. ' * 100) + '最后限制：不得修改任何文件。'
        self.prompt(text)
        self.activate('other')
        self.prompt('请修复另一份独立文档。', 'other')
        cursor = None
        recovered = ''
        offsets = []
        for _ in range(50):
            code, page = self.page(cursor=cursor, limit=2)
            self.assertEqual(code, 0)
            self.assertEqual(page['session_id'], 'p0')
            self.assertLess(len(json.dumps(page, ensure_ascii=False)), 16000)
            for item in page['items']:
                if item['id'] == 'R001':
                    offsets.append(item['text_offset'])
                    recovered += item['text']
            cursor = page['next_cursor']
            if cursor is None:
                break
        self.assertEqual(recovered, text)
        self.assertEqual(offsets, sorted(set(offsets)))
        self.assertIsNone(cursor)

    def test_cursor_rejects_other_session_and_content_mutation(self):
        self.activate()
        self.prompt('请修复恢复模块。必须运行测试验证。')
        _, first = self.page(limit=1)
        self.activate('other')
        self.prompt('请修复恢复模块。必须运行测试验证。', 'other')
        code, error = self.page('other', first['next_cursor'])
        self.assertEqual(code, 2)
        self.assertEqual(error['error'], 'stale_cursor')
        state = self.state()
        state['requirements'][0]['text'] += ' changed'
        self.assertNotEqual(cg.current_scope_projection(state)['revision'], first['revision'])

    def test_parked_other_task_wait_and_completed_items_are_not_current(self):
        self.activate()
        self.prompt('请修复恢复模块。在我确认模型更换完成前，本任务保持等待。')
        self.dispatch('Stop', last_assistant_message='已按要求暂停等待确认。')
        self.prompt('切换到新任务：请审查文档。')
        state = self.state()
        projection = cg.current_scope_projection(state)
        self.assertEqual(projection['waiting_conditions'], [])
        self.assertNotIn('R001', projection['current_item_ids'])
        packet = cg.recovery_packet(self.root / 'private' / 'sessions' / 'p0', state)
        self.assertNotIn('## Unreleased wait conditions', packet)
        state['requirements'][-1]['status'] = 'pass'
        projection = cg.current_scope_projection(state)
        self.assertNotIn(state['requirements'][-1]['id'], projection['current_item_ids'])
        self.assertEqual(cg.checkpoint_status_snapshot(state, 't')['counts']['pending'], 0)

    def test_overflow_counts_match_actual_visible_rows_and_entry_is_usable(self):
        self.activate()
        self.prompt('请审查恢复模块。')
        state = self.state()
        template = state['requirements'][0]
        for i in range(100):
            item = copy.deepcopy(template)
            item.update(id=f'R{i+2:03d}', text=('synthetic current obligation ' * 30) + str(i))
            state['requirements'].append(item)
        self.save_state(state)
        packet = cg.recovery_packet(self.root / 'private' / 'sessions' / 'p0', state)
        self.assertLessEqual(len(packet), 15000)
        total, listed, omitted = map(int, re.search(r'current-set total: (\d+) items; listed in this packet: (\d+); unlisted: (\d+)', packet).groups())
        actual = len(set(re.findall(r'^- (R\d+) \[', packet, re.M)))
        self.assertEqual(listed, actual)
        self.assertEqual(total, listed + omitted)
        self.assertGreater(omitted, 0)
        self.assertIn('--session-id', packet)
        self.assertIn(cg.RECOVERY_COMPLETION_RULE, packet)


class ExternalWaitTests(P0Harness):
    def seed_agent_wait(self):
        self.activate()
        self.prompt('请修复恢复模块。等待子任务结束后再继续。必须运行测试验证。')
        self.dispatch('SubagentStart', agent_id='worker-a', agent_type='worker')
        self.dispatch('Stop', last_assistant_message='当前等待外部结果。')
        self.assertEqual(len(self.state()['wait_conditions']), 1)

    def test_registered_agent_stop_releases_only_bound_lifecycle_wait(self):
        self.seed_agent_wait()
        self.prompt('子任务已经完成，继续。')
        self.assertEqual(self.state()['wait_conditions'][0]['status'], 'waiting')
        self.dispatch('PostToolUse', tool_name='shell', tool_input={'command': 'echo done'},
                      tool_response={'exit_code': 0, 'output': 'worker-a completed'})
        self.assertEqual(self.state()['wait_conditions'][0]['status'], 'waiting')
        self.dispatch('SubagentStop', agent_id='worker-other', last_assistant_message='done')
        self.assertEqual(self.state()['wait_conditions'][0]['status'], 'waiting')
        self.dispatch('SubagentStop', agent_id='worker-a', last_assistant_message='Outcome: incomplete; Evidence: none; Validation: failed; Limitations: blocked; Next: root review')
        state = self.state()
        self.assertEqual(state['wait_conditions'][0]['status'], 'released')
        self.assertEqual(state['wait_conditions'][0]['released_by_kind'], 'external_fact')
        self.assertEqual(state['requirements'][0]['status'], 'pending')
        # A lifecycle stop proves the child ended, never that its result passed.
        self.assertNotEqual(state['work_units'][0]['status'], 'completed')
        self.dispatch('PreCompact')
        self.dispatch('SessionStart', source='resume')
        self.dispatch('SubagentStop', agent_id='worker-a', last_assistant_message='replayed result')
        self.assertEqual(self.state()['wait_conditions'][0]['status'], 'released')

    def test_unbound_or_multiple_agent_facts_do_not_release(self):
        self.activate()
        self.prompt('请修复恢复模块。等待子任务结束后再继续。')
        for name in ('a', 'b'):
            self.dispatch('SubagentStart', agent_id=name)
        self.dispatch('Stop', last_assistant_message='当前等待外部结果。')
        for name in ('a', 'b'):
            self.dispatch('SubagentStop', agent_id=name, last_assistant_message='completed')
        self.assertEqual(self.state()['wait_conditions'][0]['status'], 'waiting')

    def test_wait_is_a_completion_obligation_not_successful_test_evidence(self):
        self.seed_agent_wait()
        self.dispatch('PostToolUse', tool_name='shell', tool_input={'command': 'python -m unittest'},
                      tool_response={'exit_code': 0})
        self.dispatch('Stop', last_assistant_message='任务已经全部完成。')
        state = self.state()
        self.assertNotEqual(state['work_units'][0]['status'], 'completed')
        self.assertEqual(state['wait_conditions'][0]['status'], 'waiting')

    def test_external_migrated_wait_never_becomes_user_controlled(self):
        from tests.test_cg122_p0_counterexamples import SCHEMA10_PARKED_FIXTURE
        state = json.loads(SCHEMA10_PARKED_FIXTURE)
        state['work_units'][0]['status'] = 'awaiting_external'
        state['content_hash'] = cg.state_content_hash(state)
        cg.validate_state_integrity(state)
        migrated = cg.migrate_state(state, {'session_id': 'p0'})
        self.assertEqual(migrated['wait_conditions'][0]['condition_type'], 'external_dependency')
        self.assertFalse(cg.release_matches_condition(migrated['wait_conditions'][0], '已完成，继续。'))


class SupersessionSpeechTests(P0Harness):
    def seed(self):
        self.activate()
        self.prompt('请实现登录功能。必须运行测试验证。')
        self.prompt('请实现审计日志。必须运行测试验证。')

    def test_questions_hypotheticals_and_coverage_words_do_not_revoke(self):
        self.seed()
        for text in ('如果取消 R001，应该如何恢复？', '是否取消 R001？',
                     '提高测试覆盖率。', '测试应覆盖取消 R001，同时取消 R002 的场景。'):
            with self.subTest(text=text):
                result = self.prompt(text)
                self.assertEqual(self.state()['supersedes'], [])
                self.assertNotIn('Supersession target is ambiguous', str(result))

    def test_actual_correction_uses_readable_unique_target(self):
        self.seed()
        self.prompt('取消登录功能，改为只输出摘要。')
        state = self.state()
        self.assertEqual(state['requirements'][0]['status'], 'superseded')
        self.assertEqual(state['requirements'][1]['status'], 'pending')
        self.assertNotIn('A001', cg.current_scope_projection(state)['current_item_ids'])

    def test_negative_other_target_does_not_hide_actual_correction(self):
        self.seed()
        self.prompt('不要取消 R002。另外，取消 R001，改为只输出摘要。')
        self.assertEqual(self.state()['requirements'][0]['status'], 'superseded')
        self.assertEqual(self.state()['requirements'][1]['status'], 'pending')


class ProjectionScopeTests(P0Harness):
    def test_explicit_session_restriction_survives_switch_without_old_business_debt(self):
        self.activate()
        self.prompt('请实现登录功能。本会话始终不要推送任何提交。必须运行测试验证。')
        original = self.state()
        self.prompt('切换到新任务：请审查文档。')
        state = self.state()
        projection = cg.current_scope_projection(state)
        packet = cg.recovery_packet(self.root / 'private' / 'sessions' / 'p0', state)
        self.assertIn('本会话始终不要推送任何提交', packet)
        self.assertNotIn('请实现登录功能', packet)
        self.assertNotIn(original['requirements'][0]['id'], projection['current_item_ids'])
        self.assertTrue(projection['ancestor_constraint_ids'])
        self.assertLess(len(cg.diagnose_context(state)), 4096)

    def test_ancestor_constraint_and_current_wait_use_same_completion_scope(self):
        self.activate()
        self.prompt('请审查架构边界。必须运行测试验证。')
        self.prompt('切换到新任务：请修复恢复模块。在我确认模型更换完成前，本任务保持等待。')
        state = self.state()
        state['work_units'][0]['status'] = 'active'
        state['work_units'][0]['closed_at'] = None
        state['work_units'][1]['parent_id'] = 'WU0001'
        projection = cg.current_scope_projection(state)
        self.assertIn('R001', projection['ancestor_constraint_ids'])
        self.assertEqual(len(projection['waiting_conditions']), 1)
        checkpoint = cg.private_checkpoint(state, {}, {})
        self.assertIn('R001', checkpoint['ancestor_constraints'])
        self.assertTrue(any('wait' in issue for issue in cg.checkpoint_issues(state, checkpoint)))
        summary = cg.checkpoint_status_snapshot(state, 't')
        self.assertEqual(summary['counts']['ancestor_constraints'], len(projection['ancestor_constraint_ids']))


class RecoveryAndPlanBoundaryTests(P0Harness):
    page = CompleteRecoveryTests.page

    def test_recovery_command_cursor_is_valid_after_resume_returns(self):
        import shlex
        self.activate()
        self.prompt('请审查恢复模块。' + '完整保留尾部限制。' * 180 + '不得写入。')
        self.dispatch('PreCompact')
        reply = self.dispatch('SessionStart', source='resume')
        packet = reply['hookSpecificOutput']['additionalContext']
        self.assertLessEqual(len(packet), 15000)
        command = next(line for line in packet.splitlines() if 'context_guard.py recovery-page ' in line)
        parts = shlex.split(command)
        cursor = parts[parts.index('--cursor') + 1]
        code, page = self.page(cursor=cursor)
        self.assertEqual(code, 0)
        self.assertEqual(page['session_id'], 'p0')

    def test_structured_plan_mentions_do_not_create_control_boundaries(self):
        self.activate()
        self.prompt('请实现恢复模块。必须运行测试验证。')
        plan = '''请按以下计划修复产品。
| 根用户事件 | 任务处理 |
| 明确切换到另一独立任务 | 新建兄弟单元 |
| 取消当前任务 | 保留审计事实 |
恢复规则：只有用户明确取消旧要求时，运行时才记录替代。
测试应覆盖取消 R001 的情形，并覆盖换到新任务的情形。
必须保留迁移和原始记录。'''
        result = self.prompt(plan)
        self.assertEqual(len(self.state()['work_units']), 1)
        self.assertEqual(self.state()['supersedes'], [])
        self.assertNotIn('Supersession target is ambiguous', str(result))
        self.assertTrue(any('必须保留迁移' in i['text'] for i in self.state()['requirements']))

    def test_default_json_diagnostics_budget_and_scope(self):
        self.activate()
        self.prompt('请审查恢复模块。必须运行测试验证。')
        state = self.state()
        for index in range(30):
            record = {'id': f'E{index+1:04d}', 'outcome': 'success', 'tool': 'shell', 'summary': '中文验证信息' * 200}
            state['evidence'].append(record)
        for index in range(40):
            item = copy.deepcopy(state['requirements'][0])
            item.update(id=f'R{index+2:03d}', text='中文当前要求' * 300)
            state['requirements'].append(item)
        snapshot = cg.checkpoint_status_snapshot(state, 't')
        self.assertLessEqual(len(json.dumps(snapshot, ensure_ascii=True).encode()), 4096)
        self.assertGreater(snapshot['items_omitted'], 0)
        self.assertEqual(snapshot['counts']['requirements'], 41)


class FinalBoundaryTests(P0Harness):
    page = CompleteRecoveryTests.page

    def test_page_requires_session_and_rejects_damaged_source_without_repair(self):
        self.activate()
        self.prompt('请修复恢复模块。')
        code, error = self.page(session=None)
        self.assertEqual((code, error['error']), (2, 'explicit_session_required'))
        source = self.root / 'private' / 'sessions' / 'p0' / 'prompts' / 'P0002.json'
        original = source.read_bytes()
        source.write_bytes(original.replace('恢复'.encode(), '破坏'.encode()))
        code, error = self.page()
        self.assertEqual((code, error['error']), (2, 'prompt_integrity_failure'))
        self.assertEqual(source.read_bytes(), original.replace('恢复'.encode(), '破坏'.encode()))

    def test_large_verification_metadata_has_complete_bounded_continuation(self):
        self.activate()
        target = self.project / 'metadata.txt'
        target.write_text('subject')
        self.prompt(f'Read {target} and verify its content.')
        state = self.state()
        contract = state['requirements'][0]['verification_contract']
        template = contract['obligations'][0]
        # A valid large persisted contract exercises the serializer, not NLP
        # scope extraction. Every obligation keeps its registered shape.
        contract['obligations'] = [{**template, 'id': f'O-R001-{i+1:03d}'} for i in range(24)]
        self.save_state(state)
        cg.validate_state_integrity(self.state())
        cursor = None
        metadata_text = ''
        metadata_digest = None
        for _ in range(150):
            code, page = self.page(cursor=cursor, limit=8)
            self.assertEqual(code, 0)
            self.assertLess(len(json.dumps(page, ensure_ascii=False).encode()), 16000)
            for item in page['items']:
                if item['id'] == 'R001' and item['part'] == 'metadata':
                    self.assertEqual(item['metadata_offset'], len(metadata_text))
                    metadata_text += item['metadata_json']
                    metadata_digest = item['metadata_sha256']
            cursor = page['next_cursor']
            if cursor is None:
                break
        self.assertIsNone(cursor)
        self.assertTrue(metadata_text)
        self.assertEqual(cg.sha256_text(metadata_text), metadata_digest)
        self.assertEqual(json.loads(metadata_text)['verification_contract'], self.state()['requirements'][0]['verification_contract'])

    def test_session_constraint_remains_visible_after_task_completion(self):
        self.activate()
        self.prompt('请修复恢复模块。本会话始终不要推送任何提交。')
        state = self.state()
        for collection in ('requirements', 'acceptance_items'):
            for item in state[collection]:
                item['status'] = 'pass'
        state['work_units'][0].update(status='completed', closed_at=cg.utc_now())
        self.save_state(state)
        self.prompt('请审查另一份文档。')
        state = self.state()
        packet = cg.recovery_packet(self.root / 'private' / 'sessions' / 'p0', state)
        self.assertIn('本会话始终不要推送任何提交', packet)
        self.assertNotIn('请修复恢复模块', packet)
        self.assertTrue(cg.current_scope_projection(state)['persistent_constraint_ids'])

    def test_wait_sources_are_typed_and_sequence_migration_shape_are_validated(self):
        self.activate()
        self.prompt('请修复恢复模块。在我确认模型更换完成前，本任务保持等待。')
        original = self.state()
        mutations = (
            ('wait_condition_sequence', 0),
            ('raised_by_kind', 'external'),
            ('subject_sha256', 'arbitrary'),
            ('kind', 'migrated_unresolved'),
            ('external_source_sha256', 'a' * 64),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                state = copy.deepcopy(original)
                if key == 'wait_condition_sequence':
                    state[key] = value
                else:
                    state['wait_conditions'][0][key] = value
                with self.assertRaises(cg.StateIntegrityError):
                    cg.validate_wait_conditions(state)
