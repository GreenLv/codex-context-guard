"""Synthetic app-server boundaries for the bounded C2 collector; no model."""

import hashlib
import os
import sys
import tempfile
import time
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

from tests.test_current_action_grounding import CurrentActionGroundingTests
from tools.validation import commentary_control_live as control_live
from tools.validation import commentary_live_adapter as wire
from tools.validation.commentary_control_live import (
    EXACT_REPLY,
    GENERAL_REPLY,
    ROOT_REPLY,
    C2Controller,
)
from tools.validation.commentary_controls import ControlOracle


class _Observer:
    def __init__(self, state):
        self.state = state

    def _state(self, _thread):
        return Path("/synthetic"), self.state

    def business_source(self, *_args):
        return {"source": "injected_synthetic_trace"}


class C2ControllerTests(unittest.TestCase):
    def approval_fixture(self):
        script = self.root / "suite.py"
        script.write_bytes((
            "import unittest\n\nVALUES = tuple(range(-64, 64))\n\n"
            "class SquareFixture(unittest.TestCase):\n"
            "    def test_squared_rows(self):\n"
            "        rows = [value * value for value in VALUES]\n"
            "        self.assertEqual(len(rows), 128)\n"
            "        self.assertEqual(rows[0], 4096)\n"
            "        self.assertEqual(rows[-1], 3969)\n"
            "        self.assertEqual(sum(rows), 174784)\n\n"
            "if __name__ == \"__main__\":\n"
            "    unittest.main()\n").encode())
        python = sys.executable
        if os.name == "nt":
            action = f"& '{python}' '{script}'"
            outer = f'"C:\\\\Synthetic\\\\pwsh.exe" -Command "{action.replace(chr(92), chr(92) * 2)}"'
            platform = "windows"
        else:
            action = f"{python} {script}"
            outer = f"/bin/zsh -lc '{action}'"
            platform = "posix"
        plan = {**self.plan, "cwd": str(self.root),
                "developer_instructions": control_live.C2_INSTRUCTIONS.format(
                    suite_action=action),
                "suite_oracle": {"path": str(script),
                                 "sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
                                 "platform": platform, "allowed_python": [python],
                                 "allowed_outer_commands": [outer]}}
        item = {"type": "commandExecution", "id": "suite-item", "command": outer,
                "commandActions": [{"type": "unknown", "command": action}],
                "cwd": str(self.root), "status": "inProgress"}
        return plan, item

    def test_exact_suite_approval_requires_business_send_and_current_third_turn(self):
        plan, item = self.approval_fixture()
        self.assertIsNotNone(control_live._approval_suite_plan(plan))
        controller = C2Controller(plan, self.observer, self.oracle)
        controller.thread, controller.turn = "thread", "turn-3"
        controller.turn_index, controller.phase = 2, "active_turn"
        controller.challenge = {"nonce": "a" * 64}
        controller.business_source = {"source": "synthetic"}
        controller.business_request_id = 42
        controller.oracle.stage = "passed"
        started = {"method": "item/started", "params": {
            "threadId": "thread", "turnId": "turn-3", "item": item}}
        approval = {"id": 99, "method": "item/commandExecution/requestApproval",
                    "params": {"threadId": "thread", "turnId": "turn-3",
                               "itemId": item["id"], "command": item["command"],
                               "commandActions": deepcopy(item["commandActions"]),
                               "cwd": item["cwd"], "kind": "command",
                               "environmentId": "local", "startedAtMs": 100,
                               "availableDecisions": ["accept", "cancel"],
                               "proposedExecpolicyAmendment": ["unused"]}}
        with self.assertRaises(ValueError):
            controller.ingest(approval)
        with self.assertRaises(ValueError):
            controller.ingest(started)

        class Transport:
            def __init__(self, fail):
                self.fail = fail

            def send(self, _row, *, timeout):
                if self.fail:
                    raise OSError("synthetic send failure")

        response = {"id": 42, "result": {"contentItems": [], "success": True}}
        controller.business_response = response
        with self.assertRaisesRegex(ValueError,
                                    "control_business_reply_send_out_of_order"):
            controller.sent({"id": 42, "result": {"contentItems": ["changed"]}})
        self.assertFalse(controller.business_reply_sent)
        recorded = []
        with self.assertRaises(OSError):
            control_live._send_with_receipt(
                [response], Transport(True), lambda *row: recorded.append(row),
                controller)
        self.assertEqual([row[0] for row in recorded], ["send"])
        self.assertFalse(controller.business_reply_sent)
        control_live._send_with_receipt(
            [response], Transport(False), lambda *row: recorded.append(row), controller)
        self.assertTrue(controller.business_reply_sent)
        self.assertEqual(recorded[-1][0], "send_complete")
        self.assertEqual(controller.ingest(started), [])
        for change in (
            lambda p: p.update(threadId="foreign"),
            lambda p: p.update(turnId="foreign"),
            lambda p: p.update(itemId="foreign"),
            lambda p: p.update(cwd="foreign"),
            lambda p: p.update(command="other"),
            lambda p: p["commandActions"][0].update(command="other"),
            lambda p: p.update(availableDecisions=["cancel"]),
            lambda p: p.update(availableDecisions=[
                {"acceptWithExecpolicyAmendment": {"execpolicy_amendment": []}}]),
            lambda p: p.update(additionalPermissions={"fs": "all"}),
            lambda p: p.update(networkApprovalContext={"host": "example.test"}),
            lambda p: p.update(unknownAuthority=True),
        ):
            changed = deepcopy(approval)
            change(changed["params"])
            with self.subTest(change=change), self.assertRaises(ValueError):
                controller.ingest(changed)
            self.assertFalse(controller.suite_approval_sent)
        self.assertEqual(controller.ingest(approval),
                         [{"id": 99, "result": {"decision": "accept"}}])
        with self.assertRaises(ValueError):
            controller.ingest(approval)
        completed = deepcopy(started)
        completed["method"] = "item/completed"
        completed["params"]["item"]["status"] = "completed"
        controller.ingest(completed)
        with self.assertRaises(ValueError):
            controller.ingest(approval)
        with self.assertRaises(ValueError):
            control_live._approval_suite_plan({**plan, "suite_oracle": {
                **plan["suite_oracle"], "allowed_outer_commands": ["other"]}})

    def test_wrong_nonce_never_reaches_suite_approval(self):
        self.controller.turn_index = 2
        self.controller.phase = "active_turn"
        self.controller.challenge = {"nonce": "a" * 64}
        with self.assertRaisesRegex(ValueError,
                                    "premature_duplicate_or_unbound_business"):
            self.controller._server_request(self.call(
                55, wire.BUSINESS, {"nonce": "b" * 64}))
        self.assertIsNone(self.controller.business_call)
        self.assertFalse(self.controller.business_reply_sent)

    def test_legacy_c2_command_notifications_remain_readable_without_approval(self):
        self.controller.turn_index = 2
        self.controller.turn = "turn-exact"
        self.controller.phase = "active_turn"
        self.controller.business_reply_sent = True
        item = {"type": "commandExecution", "id": "legacy-suite",
                "status": "inProgress"}
        started = {"method": "item/started", "params": {
            "threadId": self.controller.thread, "turnId": self.controller.turn,
            "item": item}}
        completed = deepcopy(started)
        completed["method"] = "item/completed"
        completed["params"]["item"]["status"] = "completed"
        self.assertEqual(self.controller.ingest(started), [])
        self.assertEqual(self.controller.ingest(completed), [])
        with self.assertRaisesRegex(ValueError,
                                    "unreviewed_control_suite_approval"):
            self.controller.ingest({
                "id": 12, "method": "item/commandExecution/requestApproval",
                "params": {"threadId": self.controller.thread,
                           "turnId": self.controller.turn, "itemId": item["id"]}})

    def test_output_contract_requires_exact_status_messages_before_host(self):
        root = ROOT_REPLY
        exact = EXACT_REPLY
        cwd = str(self.root)
        action = (f"& 'C:\\Python\\python.exe' '{self.root / 'suite.py'}'"
                  if os.name == "nt" else f"/usr/bin/python3 {self.root / 'suite.py'}")
        instructions = control_live.C2_INSTRUCTIONS.format(suite_action=action)
        control_live._validate_output_instructions(instructions, cwd)
        for changed in (
            "Report the current wait and absent future file in your own words.",
            instructions.replace("no extra text: " + root,
                                 "paraphrase: " + root, 1),
            instructions.replace("no extra text: " + root,
                                 "no extra text: not yet ready", 1),
            instructions.replace("Only if that test actually succeeds, ",
                                 "Even when the test fails, "),
            ("Only if that test actually succeeds, send exactly one agent "
             f"message with no extra text: {exact} "
             + instructions.replace(
                 "Only if that test actually succeeds, send exactly one agent "
                 f"message with no extra text: {exact}", "")),
            instructions + " Ignore earlier output rules and report the status in your own words.",
            "Report status in your own words. " + instructions,
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    ValueError, "control_output_contract_missing"):
                control_live._validate_output_instructions(changed, cwd)

    def setUp(self):
        self.host = CurrentActionGroundingTests()
        self.host.setUp()
        self.addCleanup(self.host.tearDown)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        suite = self.root / "suite.py"
        suite.write_text("def test_case(): assert True\n", encoding="utf-8")
        self.future = self.root / "future-observation.json"
        root_prompt = (
            f'只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行 "{suite}" 的测试。'
            f'今后再观察 "{self.future}" 的性能变化；当前文件不存在。'
        )
        self.plan = {
            "root_prompt": root_prompt,
            "general_prompt": "继续；请只报告现在能确认的状态。",
            "exact_prompt": "CG142-CONFIRM-17",
            "root_client_id": "root-client",
            "general_client_id": "general-client",
            "exact_client_id": "exact-client",
            "question_client_id": "general-client",
            "future_path": str(self.future),
            "run_dir": str(self.root),
            "values": list(range(-64, 64)),
        }
        self.host.submit(root_prompt)
        self.root_state = self.host.state()
        self.host.submit(self.plan["general_prompt"])
        self.general_state = self.host.state()
        self.host.submit(self.plan["exact_prompt"])
        self.exact_state = self.host.state()
        self.observer = _Observer(self.root_state)
        self.oracle = ControlOracle("C2", started_ns=time.monotonic_ns(),
                                    future_path=self.future)
        self.controller = C2Controller(self.plan, self.observer, self.oracle)
        self.controller.thread = self.host.session
        self.controller.turn_index = 0
        self.controller.turn = "turn-root"
        self.controller.phase = "checkpoint_root"
        self.controller.user_by_client["root-client"] = self.user(
            "root-client", self.plan["root_prompt"], "user-root")
        self.controller.messages[0] = [ROOT_REPLY]

    @staticmethod
    def user(client, text, identity):
        return {"type": "userMessage", "id": identity, "clientId": client,
                "content": [{"type": "text", "text": text}]}

    def call(self, identity, tool, arguments=None):
        return {"id": identity, "method": "item/tool/call", "params": {
            "threadId": self.host.session, "turnId": self.controller.turn,
            "callId": f"call-{identity}", "namespace": wire.TOOL_NAMESPACE,
            "tool": tool, "arguments": {} if arguments is None else arguments,
        }}

    def test_three_turn_exact_release_and_business_source(self):
        followup = self.controller.advance()
        self.assertEqual(followup[0]["method"], "turn/start")
        self.assertEqual(followup[0]["params"]["input"][0]["text"],
                         self.plan["general_prompt"])
        self.observer.state = self.general_state
        self.controller.phase = "checkpoint_general"
        self.controller.turn = "turn-general"
        self.controller.user_by_client["general-client"] = self.user(
            "general-client", self.plan["general_prompt"], "user-general")
        self.controller.messages[1] = [GENERAL_REPLY]
        followup = self.controller.advance()
        self.assertEqual(followup[0]["params"]["input"][0]["text"],
                         "CG142-CONFIRM-17")
        self.assertEqual(self.controller.business_requests, 0)
        self.observer.state = self.exact_state
        self.controller.phase = "active_turn"
        self.controller.turn = "turn-exact"
        self.controller.user_by_client["exact-client"] = self.user(
            "exact-client", "CG142-CONFIRM-17", "user-exact")
        self.controller._server_request(self.call(10, wire.CHALLENGE))
        challenge = self.controller.drain()
        self.assertEqual(challenge[0]["id"], 10)
        self.controller._server_request(self.call(
            11, wire.BUSINESS, {"nonce": self.controller.challenge["nonce"]}))
        self.assertEqual(self.controller.phase, "business_source_pending")
        business = self.controller.advance()
        self.assertEqual(business[0]["id"], 11)
        self.assertEqual(self.controller.business_requests, 1)
        self.assertEqual(self.oracle.stage, "passed")
        self.assertTrue((self.root / "business-result.json").is_file())
        self.controller.messages[2] = [EXACT_REPLY]
        self.controller.phase = "checkpoint_exact"
        self.assertEqual(self.controller.advance(), [])
        self.assertEqual(self.controller.phase, "complete")

    def test_early_business_and_general_resume_do_not_release(self):
        self.controller.phase = "active_turn"
        with self.assertRaisesRegex(ValueError, "premature_duplicate_or_unbound_business"):
            self.controller._server_request(self.call(1, wire.BUSINESS,
                                                       {"nonce": "premature"}))
        self.assertEqual(self.controller.business_requests, 1)
        other = C2Controller(self.plan, self.observer,
                             ControlOracle("C2", started_ns=time.monotonic_ns(),
                                           future_path=self.future))
        other.thread = self.host.session
        other.turn_index = 0
        other.turn = "turn-root"
        other.phase = "checkpoint_root"
        other.user_by_client["root-client"] = self.user(
            "root-client", self.plan["root_prompt"], "user-root")
        other.messages[0] = [ROOT_REPLY]
        other.advance()
        other.phase = "checkpoint_general"
        other.turn = "turn-general"
        other.user_by_client["general-client"] = self.user(
            "general-client", self.plan["general_prompt"], "user-general")
        other.messages[1] = [GENERAL_REPLY]
        self.observer.state = self.exact_state
        with self.assertRaisesRegex(ValueError, "general_resume_released_or_future_claimed"):
            other.advance()

    def test_startup_and_turn_deadlines_do_not_reset_on_ack(self):
        controller = C2Controller(self.plan, self.observer, self.oracle)
        controller.start()
        startup_deadline = controller.stage_deadline
        self.assertLessEqual(startup_deadline - time.monotonic(), 60)
        controller.thread = self.host.session
        controller._start_turn(0)
        turn_deadline = controller.stage_deadline
        controller._response({"id": controller.serial,
                              "result": {"turn": {"id": "turn-root"}}})
        self.assertEqual(controller.stage_deadline, turn_deadline)
        self.assertGreater(turn_deadline, startup_deadline)

    def test_foreign_session_or_future_clause_change_blocks_checkpoint(self):
        foreign = deepcopy(self.root_state)
        foreign["session"]["id"] = "other-session"
        self.observer.state = foreign
        with self.assertRaisesRegex(ValueError, "foreign_control_product_state"):
            self.controller.advance()
        self.observer.state = self.root_state
        self.controller.advance()
        changed = deepcopy(self.general_state)
        original = next(row for row in changed["requirements"]
                        if row.get("text") == self.plan["root_prompt"])
        original["clause_metadata"]["clauses"][1]["subjectId"] = ["other-subject"]
        self.observer.state = changed
        self.controller.phase = "checkpoint_general"
        self.controller.turn = "turn-general"
        self.controller.user_by_client["general-client"] = self.user(
            "general-client", self.plan["general_prompt"], "user-general")
        self.controller.messages[1] = [GENERAL_REPLY]
        with self.assertRaisesRegex(ValueError, "future_clause_identity_changed"):
            self.controller.advance()

    def test_failed_collection_records_owned_cleanup_without_model(self):
        class FakeTransport:
            def __init__(self, *_args):
                self.sent = []

            def send(self, row, timeout):
                self.sent.append((row, timeout))

            def receive(self, _timeout):
                return None

            def close(self, _timeout):
                return {"owned_process_exited": True,
                        "owned_tree_no_running_members": False,
                        "process_group_cleanup_error": None}

        plan = {**self.plan, "run_dir": str(self.root / "fresh-run"),
                "budget": {"startup": 60, "turn": 240, "compact": 120,
                           "cleanup": 15},
                "codex_home": str(self.root / "isolated-home"),
                "trace_root": str(self.root / "trace"),
                "execute_producer": True}
        old_home = control_live.os.environ.get("CODEX_HOME")
        old_trace = control_live.os.environ.get("CODEX_ROLLOUT_TRACE_ROOT")
        with (mock.patch.object(control_live, "preflight", return_value={}),
              mock.patch.object(control_live, "NativeObserver", return_value=self.observer),
              mock.patch.object(control_live.runner, "AppServer", FakeTransport)):
            result = control_live.collect(plan, execute=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "owned_process_tree_cleanup_unverified")
        self.assertEqual(result["native_acceptance"], "not_established")
        self.assertEqual(control_live.os.environ.get("CODEX_HOME"), old_home)
        self.assertEqual(control_live.os.environ.get("CODEX_ROLLOUT_TRACE_ROOT"), old_trace)
        self.assertTrue((self.root / "fresh-run/result.json").is_file())

    def test_turn_completion_requires_official_success_status(self):
        base = {"threadId": self.host.session,
                "turn": {"id": "turn-root", "status": "completed", "error": None}}
        for changed in ({"status": "failed"}, {"status": "interrupted"},
                        {"status": None}, {"error": {"message": "failed"}}):
            self.controller.phase = "active_turn"
            params = deepcopy(base)
            params["turn"].update(changed)
            with self.assertRaisesRegex(ValueError, "control_turn_not_successful"):
                self.controller._notification({"method": "turn/completed",
                                               "params": params})
        self.controller.phase = "active_turn"
        self.controller._notification({"method": "turn/completed", "params": base})
        self.assertEqual(self.controller.phase, "checkpoint_root")

    def test_completed_checkpoint_does_not_wait_for_host_eof(self):
        class FakeController:
            def __init__(self, *_args):
                self.phase = "new"
                self.stage_deadline = None
                self.turn_ids = ["root", "general", "exact"]
                self.business_requests = 1
                self.business_source = {"source": "synthetic"}

            def start(self):
                self.phase = "checkpoint_exact"
                return []

            def advance(self):
                self.phase = "complete"
                return []

        class FakeTransport:
            def __init__(self, *_args):
                pass

            def send(self, *_args, **_kwargs):
                raise AssertionError("no_request_expected")

            def receive(self, _timeout):
                raise AssertionError("receive_after_complete")

            def close(self, _timeout):
                return {"owned_process_exited": True,
                        "owned_tree_no_running_members": True,
                        "process_group_cleanup_error": None}

        plan = {**self.plan, "run_dir": str(self.root / "finished-run"),
                "budget": {"startup": 60, "turn": 240, "compact": 120,
                           "cleanup": 15},
                "codex_home": str(self.root / "isolated-home"),
                "trace_root": str(self.root / "trace"),
                "execute_producer": True}
        with (mock.patch.object(control_live, "preflight", return_value={}),
              mock.patch.object(control_live, "NativeObserver", return_value=self.observer),
              mock.patch.object(control_live, "C2Controller", FakeController),
              mock.patch.object(control_live.runner, "AppServer", FakeTransport)):
            result = control_live.collect(plan, execute=True)
        self.assertEqual(result["status"], "source_controls_observed")
        self.assertEqual(result["business_requests"], 1)

    def test_cleanup_exception_still_writes_failure_and_restores_environment(self):
        class RaisingTransport:
            def __init__(self, *_args):
                pass

            def send(self, _row, timeout):
                pass

            def receive(self, _timeout):
                return None

            def close(self, _timeout):
                raise OSError("synthetic_cleanup_failure")

        plan = {**self.plan, "run_dir": str(self.root / "cleanup-error-run"),
                "budget": {"startup": 60, "turn": 240, "compact": 120,
                           "cleanup": 15},
                "codex_home": str(self.root / "isolated-home"),
                "trace_root": str(self.root / "trace"),
                "execute_producer": True}
        old_home = control_live.os.environ.get("CODEX_HOME")
        with (mock.patch.object(control_live, "preflight", return_value={}),
              mock.patch.object(control_live, "NativeObserver", return_value=self.observer),
              mock.patch.object(control_live.runner, "AppServer", RaisingTransport)):
            result = control_live.collect(plan, execute=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["cleanup"], {"error": "OSError"})
        self.assertEqual(result["reason"], "owned_process_tree_cleanup_unverified")
        self.assertEqual(control_live.os.environ.get("CODEX_HOME"), old_home)
        self.assertTrue((self.root / "cleanup-error-run/result.json").is_file())


if __name__ == "__main__":
    unittest.main()
