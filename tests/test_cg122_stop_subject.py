"""CG122-08: synthetic completion subjects and actual Stop entry points."""
from tests import test_context_guard_phase3 as phase3

cg = phase3.cg


class StopSubjectTests(phase3.OrdinaryTerminalCompletionTests):
    def test_subordinate_and_local_completion_are_not_root_completion(self):
        for text in (
            'Atlas 任务已结束，但验收结果不可用。请提供最终回复，我收到后继续验收。',
            '子任务已完成，尚未读回附件。请提供验收附件。',
            'The worker task is complete, but its result is unavailable. Please provide the result.',
            'The external job is finished. Awaiting external review.',
            '阶段任务已完成。请确认验收结果。',
            'For the delegated task, after its final retry and cleanup, the task is complete. Please provide its results.',
            '请提供验收附件；Orion 任务已结束，当前验收尚未完成。',
        ):
            with self.subTest(text=text):
                self.assertFalse(cg.claims_whole_completion(text))
                self.assertNotEqual(cg.classify_stop_decision(text)['outcome'], 'gate_completion_claim')

    def test_nonassertive_subjects_never_claim_root_completion(self):
        for text in (
            '“整个任务已完成”。', '> The task is complete.',
            'The reviewer reported that the task is complete.',
            'If the task is complete, please provide a report.',
            '假设经过多轮验证后整个任务已完成，再提交报告。',
            '整个任务已完成了吗？', 'The task is not complete.',
        ):
            with self.subTest(text=text):
                self.assertFalse(cg.claims_whole_completion(text))

    def test_real_whole_completion_beats_unrelated_wait(self):
        for text in (
            '整个任务已完成。另一个任务等待外部审核。',
            'Another job awaits external review. The current task is complete.',
            'The entire task is complete. Please provide feedback on another project.',
        ):
            with self.subTest(text=text):
                self.assertTrue(cg.claims_whole_completion(text))
                self.assertEqual(cg.classify_stop_decision(text)['outcome'], 'gate_completion_claim')

    def test_subordinate_handoff_does_not_derive_ambiguous_proof(self):
        self.build_single_read_task()
        state = self.state()
        second = dict(state['evidence'][-1])
        second['id'] = 'E9999'
        state['evidence'].append(second)
        state['evidence_sequence'] = 9999
        cg.save_state(self.root / 'private' / 'sessions' / 'p3', state)
        reply = 'Atlas 任务已结束，但结果正文为空，尚无法确认验收结果。请提供最终回复，我收到后继续验收。'
        for _ in range(2):
            self.assertEqual(self.dispatch('Stop', turn='t1', last_assistant_message=reply), {})
        state = self.state()
        self.assertEqual(state['work_units'][0]['status'], 'awaiting_user')
        self.assertEqual(state['requirements'][0]['status'], 'pending')
        self.assertIsNone(state['completion_checkpoint'])
        self.assertEqual(state['continuation_attempts'], 0)
        self.dispatch('PreCompact', turn='t1')
        self.dispatch('SessionStart', turn='t1', source='resume')
        self.assertEqual(self.state()['requirements'][0]['status'], 'pending')

    def test_whole_completion_with_unrelated_wait_still_blocks_ambiguity(self):
        self.build_single_read_task()
        state = self.state()
        second = dict(state['evidence'][-1])
        second['id'] = 'E9999'
        state['evidence'].append(second)
        state['evidence_sequence'] = 9999
        cg.save_state(self.root / 'private' / 'sessions' / 'p3', state)
        reply = '当前整个任务已完成。另一个任务等待外部审核。'
        self.assertEqual(self.dispatch('Stop', turn='t1', last_assistant_message=reply).get('decision'), 'block')
        self.assertIn('evidence_ambiguous', self.state()['decision_log'][-1]['reason_codes'])
        self.assertEqual(self.dispatch('Stop', turn='t1', last_assistant_message=reply), {})
        self.assertEqual(self.state()['requirements'][0]['status'], 'pending')

    def test_typed_subjects_and_sources_are_bounded_without_raw_text(self):
        import json
        cases = (
            ('当前任务已完成。', 'current_work_unit', 'whole'),
            ('子任务已完成。', 'subordinate_external', 'partial'),
            ('阶段任务已完成。', 'local_phase_artifact', 'partial'),
            ('Result is ready.', 'other_unknown', 'partial'),
        )
        for reply, subject, scope in cases:
            with self.subTest(reply=reply):
                result = cg.interpret_stop_reply(reply)
                self.assertEqual(result['claims'][0]['subject'], subject)
                self.assertEqual(result['claims'][0]['scope'], scope)
                self.assertNotIn(reply, json.dumps(result, ensure_ascii=False))
        result = cg.interpret_stop_reply(('子任务已完成。' * 100) + '当前任务已完成。')
        self.assertTrue(result['whole_completion_claim'])
        self.assertEqual(len(result['claims']), 64)
        self.assertGreater(result['omitted_claim_count'], 0)

    def test_mixed_quotes_and_distant_relations_preserve_real_claim(self):
        for text in (
            '“开始说明。整个任务已完成。结束引用。”',
            '```text\n整个任务已完成。\n```',
            '关于委派子任务，经过重新检查和多轮清理后，任务已完成。请提供结果。',
        ):
            with self.subTest(text=text):
                self.assertFalse(cg.claims_whole_completion(text))
        for text in (
            '“子任务已完成。” 但当前任务已完成。',
            'The reviewer said "the task is complete". I confirm the current task is complete.',
            '我声明：“当前任务已完成”。',
        ):
            with self.subTest(text=text):
                self.assertTrue(cg.claims_whole_completion(text))

    def test_current_wait_only_gates_actual_whole_completion(self):
        self.prompt('$context-guard\n请核对验收结果。在我确认模型更换完成前，本任务保持等待。必须运行测试验证。', turn='t1')
        partial = '子任务已完成，结果尚未验收。请提供验收附件。'
        self.assertEqual(self.dispatch('Stop', turn='t1', last_assistant_message=partial), {})
        self.assertEqual(self.state()['wait_conditions'][0]['status'], 'waiting')
        result = self.dispatch('Stop', turn='t1', last_assistant_message='当前任务已完成。')
        self.assertEqual(result.get('decision'), 'block')
        self.assertIn('waiting_condition_pending', self.state()['decision_log'][-1]['reason_codes'])
        self.assertEqual(self.state()['requirements'][0]['status'], 'pending')

    def test_local_milestone_never_fabricates_user_wait_for_actionable_work(self):
        prompt = '$context-guard\n请修复模块并运行测试。持续工作直到任务完成。'
        self.prompt(prompt, turn='t1')
        reply = '局部任务已完成。接下来我会继续修复模块并运行测试。'
        observed = cg.classify_stop_decision(reply, prompt)
        self.assertFalse(observed['interpretation']['whole_completion_claim'])
        self.assertEqual(observed['interpretation']['remaining_action_owner'], 'assistant')
        result = self.dispatch('Stop', turn='t1', last_assistant_message=reply)
        self.assertEqual(result.get('decision'), 'block')
        self.assertNotEqual(self.state()['work_units'][0]['status'], 'awaiting_user')

    def test_real_whole_completion_does_not_hide_actionable_business_work(self):
        self.build_single_read_task()
        reply = '当前任务已完成。接下来我会继续修改文档。'
        result = self.dispatch('Stop', turn='t1', last_assistant_message=reply)
        self.assertEqual(result.get('decision'), 'block')
        self.assertIn('assistant_actionable_work_remains', self.state()['decision_log'][-1]['reason_codes'])
        self.assertIsNone(self.state()['completion_checkpoint'])

    def test_unknown_named_subject_does_not_auto_complete_from_available_evidence(self):
        self.build_single_read_task()
        result = self.dispatch('Stop', turn='t1', last_assistant_message='Nebula 任务已完成。')
        self.assertEqual(result, {})
        self.assertEqual(self.state()['requirements'][0]['status'], 'pending')
        self.assertIsNone(self.state()['completion_checkpoint'])

    def test_quoted_handoff_does_not_fabricate_remaining_action_owner(self):
        reply = '示例：“请先登录账号，完成后告诉我。” 局部阶段已结束。'
        result = cg.interpret_stop_reply(reply)
        self.assertEqual(result['remaining_action_owner'], 'unknown')
        self.assertFalse(result['whole_completion_claim'])

    def test_explicit_unit_identity_uses_state_without_inventing_success(self):
        self.build_single_read_task()
        state = self.state()
        current = 'WU0001 任务已完成。'
        other = 'WU9999 任务已完成。'
        self.assertTrue(cg.claims_whole_completion(current, state=state))
        self.assertTrue(cg.classify_stop_decision(current, state=state)['interpretation']['whole_completion_claim'])
        self.assertFalse(cg.claims_whole_completion(other, state=state))
        self.assertEqual(cg.interpret_stop_reply(other, state=state)['claims'][0]['subject'], 'other_unknown')

    def test_missing_strong_evidence_still_blocks_current_whole_completion(self):
        self.build_single_read_task()
        state = self.state()
        state['evidence'] = []
        cg.save_state(self.root / 'private' / 'sessions' / 'p3', state)
        result = self.dispatch('Stop', turn='t1', last_assistant_message='The current task is complete. Another job awaits review.')
        self.assertEqual(result.get('decision'), 'block')
        self.assertIn('deterministic_obligations_pending', self.state()['decision_log'][-1]['reason_codes'])
        self.assertIsNone(self.state()['completion_checkpoint'])
        self.dispatch('PreCompact', turn='t1')
        self.dispatch('SessionStart', turn='t1', source='resume')
        self.assertEqual(self.dispatch('Stop', turn='t1', last_assistant_message='当前任务已完成。'), {})
        self.assertEqual(self.state()['requirements'][0]['status'], 'pending')
        self.assertEqual(self.state()['continuation_attempts'], 1)

    def test_unrelated_negative_clause_does_not_retract_real_current_completion(self):
        for text in (
            '子任务尚未完成，但当前任务已完成。',
            'The worker task is not complete, but the current task is complete.',
            '“当前任务尚未完成”，现在当前任务已完成。',
        ):
            with self.subTest(text=text):
                self.assertTrue(cg.claims_whole_completion(text))
                self.assertEqual(cg.classify_stop_decision(text)['outcome'], 'gate_completion_claim')

    def test_nested_first_person_is_not_current_speaker_in_actual_stop(self):
        cases = (
            'The report says: "I confirm the current task is complete."',
            '示例：“我声明：当前任务已完成。”',
            'The reviewer wrote: “She said ‘I confirm the current task is complete.’”',
            '报告写道：「示例：『我宣布当前任务已完成。』」',
            '```text\nI confirm the current task is complete.\n```',
            '> I confirm the current task is complete.',
            "The report says: 'I confirm the current task is complete.'",
            'For example, I confirm the current task is complete.',
            '示例：我声明当前任务已完成。',
            'The report states that I confirm the current task is complete.',
            'Morgan said that I confirm the current task is complete.',
            '“第一行。\n我声明当前任务已完成。”',
        )
        for reply in cases:
            with self.subTest(reply=reply):
                self.assertFalse(cg.claims_whole_completion(reply))
                h = phase3.OrdinaryTerminalCompletionTests()
                h.setUp()
                try:
                    h.build_single_read_task()
                    state = h.state()
                    duplicate = dict(state['evidence'][-1])
                    duplicate['id'] = 'E9999'
                    state['evidence'].append(duplicate)
                    state['evidence_sequence'] = 9999
                    cg.save_state(h.root / 'private' / 'sessions' / 'p3', state)
                    self.assertEqual(h.dispatch('Stop', turn='t1', last_assistant_message=reply), {})
                    self.assertEqual(h.state()['requirements'][0]['status'], 'pending')
                    self.assertIsNone(h.state()['completion_checkpoint'])
                    self.assertEqual(h.state()['continuation_attempts'], 0)
                finally:
                    h.doCleanups()

    def test_outer_first_person_and_unquoted_claim_keep_same_evidence_gate(self):
        for reply in (
            '我声明：“当前任务已完成”。',
            'I confirm the current task is complete.',
            'I declare: "The current task is complete."',
            'After reading the report, I confirm the current task is complete.',
            '看完示例后，我确认当前任务已完成。',
            '报告写道：“我声明当前任务已完成。”；当前任务已完成。',
            'The report says "I confirm the current task is complete." But the current task is complete.',
            'The report says "I confirm the current task is complete", but I confirm the current task is complete.',
            '报告写道：“我声明当前任务已完成”，但当前任务已完成。',
            '报告写道：“我声明当前任务已完成”，但任务已完成。',
            'The report says "I confirm the task is complete", but the task is complete.',
        ):
            with self.subTest(reply=reply):
                self.assertTrue(cg.claims_whole_completion(reply))
                h = phase3.OrdinaryTerminalCompletionTests()
                h.setUp()
                try:
                    h.build_single_read_task()
                    state = h.state()
                    duplicate = dict(state['evidence'][-1])
                    duplicate['id'] = 'E9999'
                    state['evidence'].append(duplicate)
                    state['evidence_sequence'] = 9999
                    cg.save_state(h.root / 'private' / 'sessions' / 'p3', state)
                    self.assertEqual(h.dispatch('Stop', turn='t1', last_assistant_message=reply).get('decision'), 'block')
                    self.assertIn('evidence_ambiguous', h.state()['decision_log'][-1]['reason_codes'])
                    self.assertEqual(h.dispatch('Stop', turn='t1', last_assistant_message=reply), {})
                    self.assertEqual(h.state()['requirements'][0]['status'], 'pending')
                finally:
                    h.doCleanups()
