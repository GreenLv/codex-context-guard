"""Synthetic app-server boundaries for the bounded C2 collector; no model."""

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
