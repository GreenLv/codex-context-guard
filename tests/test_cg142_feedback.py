"""Observed predicates and whole completion are different feedback facts."""

import copy
import os
import re
import unittest
from unittest import mock

from tests import test_host_terminal_wire as wire

cg = wire.cg


class FeedbackTests(unittest.TestCase):
    def setUp(self):
        self.host = wire.HostTerminalWireTests()
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)

    def ready(self, call_id, target):
        command = (f"Test-Path -LiteralPath '{target}' -PathType Leaf" if os.name == "nt"
                   else f"test -f '{target}'")
        self.host.command(call_id, command, stdout="True\r\n" if os.name == "nt" else "")

    def test_ready_persistent_test_survives_false_deferred_or_user_wait(self):
        for disposition, reply in (("deferred", "我稍后再运行测试。"),
                                   ("user_wait", "请确认后我再运行测试。")):
            with self.subTest(disposition=disposition):
                host = wire.HostTerminalWireTests()
                host.setUp()
                self.addCleanup(host.doCleanups)
                target = host.cwd / "suite.py"
                host.write_file(target, "def test_ok(): assert True\n")
                with mock.patch.object(cg.secrets, "token_urlsafe", return_value="test-token"):
                    host.start(f"请运行 {host.root_target(target)} 的测试并持续执行直到任务完成。")
                command = (f"Test-Path -LiteralPath '{target}' -PathType Leaf"
                           if os.name == "nt" else f"test -f {target}")
                host.command("ready", command, stdout="True\r\n" if os.name == "nt" else "")
                state = host.state()
                self.assertEqual(len(state["root_controls"]), 1)
                directory = host.root / "private/sessions" / host.session_id
                view = cg.current_feedback_view(state, directory)
                self.assertTrue(any(row["business_state"] == "remaining"
                                    for row in view["items"]))
                cg.stage_private_disposition(host.root / "private", host.session_id,
                                             host.turn_id, "test-token", disposition)
                result = cg.dispatch(host.event("Stop", last_assistant_message=reply))
                self.assertEqual(result.get("decision"), "block")
                after = host.state()
                self.assertEqual(after["decision_log"][-1]["outcome"], "visible_correction")
                self.assertEqual(after["continuation_attempts"], 1)

    def test_observed_edit_is_not_a_request_to_repeat_work(self):
        h = self.host
        target = h.cwd / "module.py"
        h.write_file(target, "before\n")
        h.start(f"请修改 {h.root_target(target)}，并核对改动后的文件。")
        h.patch("patch", target, "before\n", "after\n")
        h.readback("read", target, "after\n")
        state = h.state()
        original = copy.deepcopy(state)
        directory = h.root / "private/sessions" / h.session_id
        view = cg.current_feedback_view(state, directory)
        observed = [row for row in view["items"] if row["business_state"] == "observed"]
        self.assertTrue(observed)
        self.assertEqual(observed[0]["closure"], "open")
        self.assertEqual(state, original)
        for limit in (15000, 1800):
            packet = cg.recovery_packet(directory, state, char_limit=limit)
            self.assertIn("observed", packet)
            self.assertIn("not a request to repeat", packet)
            self.assertLessEqual(len(packet), limit)
        for source in ("compact", "resume"):
            result = cg.dispatch(h.event("SessionStart", source=source))
            self.assertIn("observed", str(result))

    def test_unrun_test_and_source_loss_are_not_observed(self):
        h = self.host
        target = h.cwd / "suite.py"
        h.write_file(target, "def test_ok(): assert True\n")
        h.start(f"运行 {h.root_target(target)} 的测试。")
        self.ready("exists", target)
        directory = h.root / "private/sessions" / h.session_id
        state = h.state()
        view = cg.current_feedback_view(state, directory)
        self.assertTrue(any(row["business_state"] == "remaining" for row in view["items"]))
        for path in (directory / "prompts").glob("*.json"):
            path.unlink()
        damaged = cg.current_feedback_view(state, directory)
        self.assertFalse(any(row["business_state"] in {"observed", "remaining"}
                             for row in damaged["items"]))

    def test_two_current_tests_are_both_present_in_the_fact_view(self):
        h = self.host
        first, second = h.cwd / "alpha.py", h.cwd / "beta.py"
        for target in (first, second):
            h.write_file(target, "def test_ok(): assert True\n")
        h.start(f'现在分别运行 "{first}" 和 "{second}" 的测试。')
        for index, target in enumerate((first, second)):
            self.ready(f"exists-{index}", target)
        view = cg.current_feedback_view(h.state(), h.root / "private/sessions" / h.session_id)
        tests = [row for row in view["items"] if row["predicate"] == "test_run_completed"]
        self.assertEqual(len(tests), 2)
        self.assertTrue(all(row["business_state"] == "remaining" for row in tests))

    def test_low_budget_omits_whole_conditions_and_preserves_source_state(self):
        h = self.host
        marker = "APPROVE-" + "x" * 1000
        h.start(f"不得发布。收到 {marker} 后才运行测试。")
        state = h.state()
        directory = h.root / "private/sessions" / h.session_id
        packet = cg.recovery_packet(directory, state, char_limit=1800)
        self.assertLessEqual(len(packet), 1800)
        self.assertIn("Integrity status:", packet)
        self.assertIn("recovery-page", packet)
        self.assertIn("omission never releases", packet)
        # A long literal may be omitted with its row, never printed as a prefix
        # that the model could mistake for a shorter release token.
        self.assertTrue(marker in packet or "APPROVE-" not in packet)

    def test_wait_counts_come_from_the_rendered_wait_rows(self):
        h = self.host
        h.start("请修改代码。")
        state = h.state()
        cg.add_wait_condition(state, state["work_state"]["active_work_unit_id"],
                              kind="one_shot", condition_type="input",
                              raised_by_kind="root_user", raised_by_source=state["prompts"][-1]["id"])
        directory = h.root / "private/sessions" / h.session_id
        for limit in (1800, 15000):
            packet = cg.recovery_packet(directory, state, char_limit=limit)
            total, listed, omitted = map(int, re.search(
                r"- waits: (\d+); listed: (\d+); omitted: (\d+)", packet).groups())
            self.assertEqual(total, 1)
            self.assertEqual(listed, len(re.findall(r"(?m)^- WC\d+ \[", packet)))
            self.assertEqual(total, listed + omitted)


if __name__ == "__main__":
    unittest.main()
