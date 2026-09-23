"""Independent R1 counterexamples with positive controls, through real dispatch."""
import unittest

from tests import test_host_terminal_wire as wire

cg = wire.cg

class ReviewR1Tests(unittest.TestCase):
    def host(self):
        h = wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        return h

    def test_compound_objects_do_not_supply_polarity_or_time(self):
        for name in ('neutral', '不要', '禁止', 'never', 'after', '以前', '描述', 'audit'):
            with self.subTest(name=name):
                text = f'请修改 "/work/{name}/module.py"，并运行 "/work/{name}/module.py" 的测试。'
                parts, related = cg._execution_child_specs(text)
                self.assertEqual([p[3] for p in parts], ['local_edit', 'test_verify'])
                self.assertTrue(related)
                h = self.host()
                h.start(text)
                self.assertEqual([i['execution_kind'] for i in h.state()['requirements'] if 'execution_kind' in i],
                                 ['local_edit', 'test_verify'])
        for text in ('不要修改 "/work/neutral/module.py"，并运行测试。',
                     '请修改 "/work/neutral/module.py"，以后再运行测试。'):
            self.assertEqual(cg._execution_child_specs(text)[0], [])

    def test_unquoted_adjacent_prose_cannot_certify_smaller_action(self):
        for suffix in ('并提交修改', '的测试并持续执行直到任务完成', '后发布结果'):
            h = self.host()
            target = h.cwd / ('suite.py' + suffix)
            h.write_file(target, 'def test_ok(): assert True\n')
            h.start(f'请测试 {target}。')
            self.assertIsNone(cg._root_control_item_action(h.state()['requirements'][0]))
            directory = h.root / 'private/sessions' / h.session_id
            self.assertEqual(cg.current_core_projections(h.state(), directory), [])
        self.assertIsNotNone(cg._root_control_item_action({'text': '请测试 "/work/suite.py并提交修改"。'}))

    def test_pause_and_release_feedback_tracks_same_unit_wait(self):
        h = self.host()
        target = h.cwd / 'suite.py'
        h.write_file(target, 'def test_ok(): assert True\n')
        h.start(f'请运行 {h.root_target(target)} 的测试并持续执行直到任务完成。')
        command = (f"Test-Path -LiteralPath '{target}' -PathType Leaf" if wire.os.name == 'nt' else f"test -f '{target}'")
        h.command('ready', command, stdout='True\r\n' if wire.os.name == 'nt' else '')
        directory = h.root / 'private/sessions' / h.session_id
        h.start('暂停当前任务。')
        view = cg.current_feedback_view(h.state(), directory)
        self.assertEqual(next(i for i in view['items'] if i['id']=='R001')['business_state'], 'waiting')
        h.start('继续。')
        view = cg.current_feedback_view(h.state(), directory)
        self.assertEqual(next(i for i in view['items'] if i['id']=='R001')['business_state'], 'remaining')

    def test_observed_result_is_retained_under_pause_and_sibling_wait_is_inert(self):
        h = self.host()
        target = h.cwd / 'module.py'
        h.write_file(target, 'before\n')
        h.start(f'请修改 {target}，并核对改动后的文件。')
        h.patch('patch', target, 'before\n', 'after\n')
        h.readback('read', target, 'after\n')
        h.start('暂停当前任务。')
        directory = h.root / 'private/sessions' / h.session_id
        view = cg.current_feedback_view(h.state(), directory)
        observed = [r for r in view['items'] if r['business_state']=='observed']
        self.assertTrue(observed)
        self.assertTrue(observed[0]['waiting_condition_ids'])
        state = h.state()
        # A historical sibling wait is not a current action condition.
        for wait in state['wait_conditions']:
            wait['owner_work_unit_id'] = 'not-current-sibling'
        view = cg.current_feedback_view(state, directory)
        self.assertTrue(any(r['business_state']=='observed' and not r['waiting_condition_ids']
                            for r in view['items']))

    def test_ambiguous_object_bytes_are_not_normalized_as_negative_speech(self):
        text = '请测试 /work/suite.py不能不提交修改。'
        self.assertEqual(cg._protected_prompt_clauses(text), [text[:-1]])
