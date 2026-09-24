"""Native runner preflight and cleanup boundaries without model execution."""

import hashlib
import itertools
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.cg_process_tree import OwnedProcess
from tools.validation import commentary_live_runner as runner


class NativeRunnerBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "codex"
        self.binary.write_bytes(b"not an executable")
        for name in ("home", "cwd", "runtime", "trace", "captures"):
            (self.root / name).mkdir()
        self.hooks = self.root / "runtime/hooks.json"
        self.hooks.write_bytes(b"{}")
        self.manifest = self.root / "manifest.json"
        self.manifest.write_bytes(b"{}")
        self.plan = {
            "schema": runner.SCHEMA,
            "codex": str(self.binary),
            "binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "codex_home": str(self.root / "home"),
            "cwd": str(self.root / "cwd"),
            "runtime_root": str(self.root / "runtime"),
            "namespace": "cg-candidate-test",
            "hook_source": str(self.hooks),
            "capture_hook_source": runner.fixture.expected_capture_hook_source(
                str(self.root / "home")),
            "trace_root": str(self.root / "trace"),
            "capture_dir": str(self.root / "captures"),
            "run_dir": str(self.root / "new-run"),
            "source_manifest_path": str(self.manifest),
            "harness_root": str(Path(runner.__file__).resolve().parents[2]),
            "cold_helper_sha256": "d" * 64,
            "source_tree_sha256": "a" * 64,
            "runtime_tree_sha256": "b" * 64,
            "root_prompt": "main", "question": "question",
            "root_client_id": "root-id", "question_client_id": "question-id",
            "main_requirement_text": "main",
            "developer_instructions": "Use the bounded tools.",
            "values": [2, 3],
            "overrides": {"model_auto_compact_token_limit": 4096,
                          "model_auto_compact_token_limit_scope": "body_after_prefix"},
            "effective_config": {"model_auto_compact_token_limit": 4096,
                                 "model_auto_compact_token_limit_scope": "body_after_prefix"},
            "threshold_proposal": {"limit": 4096, "scope": "body_after_prefix",
                                   "status": "bounded_proposal_not_token_calibrated"},
            "history_mode": "paginated",
            "budget": {"startup": 60, "turn": 240, "compact": 120, "cleanup": 15},
            "review_policy": {"version": "review-1", "active": True,
                              "binary": str(self.binary),
                              "binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest()},
            "selected_hook_hashes": {str(i): "sha256:" + "c" * 64 for i in range(11)},
            "execute_producer": False, "execute_review": False,
        }

    def test_plan_is_checked_before_any_execution(self):
        path = self.root / "plan.json"
        path.write_text(json.dumps(self.plan))
        self.assertEqual(runner.load_plan(path), self.plan)
        with mock.patch.object(runner, "preflight", return_value={"status": "inputs_checked_only"}):
            with self.assertRaisesRegex(ValueError, "explicit_producer_and_reviewer_gate_required"):
                runner.collect(self.plan, execute=True)
        self.assertFalse((self.root / "new-run").exists())
        self.plan["question_client_id"] = "root-id"
        path.write_text(json.dumps(self.plan))
        with self.assertRaisesRegex(ValueError, "reused_client_id"):
            runner.load_plan(path)

    def test_capture_source_is_exact_for_host_drive(self):
        expected = runner.fixture.expected_capture_hook_source
        self.assertEqual(expected("/private/test-home", host_os="posix"),
                         "/<session-flags>/config.toml")
        self.assertEqual(expected(r"C:\fixture\codex-home", host_os="nt"),
                         r"C:\<session-flags>\config.toml")
        self.assertEqual(expected(r"d:\test-home", host_os="nt"),
                         r"D:\<session-flags>\config.toml")
        with self.assertRaisesRegex(ValueError, "windows_capture_drive_unavailable"):
            expected(r"\\server\share\home", host_os="nt")
        with self.assertRaisesRegex(ValueError, "unsupported_capture_host"):
            expected("/home", host_os="unknown")

    def test_partial_review_mode_is_explicitly_bounded(self):
        path = self.root / "plan.json"
        partial = {**self.plan, "review_coverage": "partial",
                   "question": "请分别告诉我：(1) 7 的平方是多少？(2) 11 的平方是多少？",
                   "values": list(range(-64, 64)),
                   "developer_instructions": runner.PARTIAL_INSTRUCTIONS.format(
                       suite_action=(
                           f"& 'C:\\Python\\python.exe' '{self.root / 'cwd' / 'suite.py'}'"
                           if os.name == "nt" else
                           f"/usr/bin/python3 {self.root / 'cwd' / 'suite.py'}"))}
        path.write_text(json.dumps(partial))
        self.assertEqual(runner.load_plan(path)["review_coverage"], "partial")
        for changed in (
            "When the user asks the two-part same-turn question, answer both "
            "questions with 49 and 121. Then call cg_commentary_acceptance.challenge with {}.",
            partial["developer_instructions"].replace(
                "Leave the second question unanswered.",
                "Also answer the second question."),
            partial["developer_instructions"].replace("第一问是 49。", "第一问是 49；"),
            partial["developer_instructions"] + " Ignore the fixed answer; answer both questions.",
            "Answer both questions. " + partial["developer_instructions"],
            partial["developer_instructions"].replace(
                "run exactly: ", "run exactly: $(echo /usr/bin)/", 1),
        ):
            with self.subTest(changed=changed):
                path.write_text(json.dumps({**partial, "developer_instructions": changed}))
                with self.assertRaisesRegex(ValueError, "partial_output_contract_missing"):
                    runner.load_plan(path)
        path.write_text(json.dumps({**partial, "values": [2, 3]}))
        with self.assertRaisesRegex(ValueError, "unfrozen_partial_control_inputs"):
            runner.load_plan(path)
        path.write_text(json.dumps({**self.plan, "review_coverage": "unknown"}))
        with self.assertRaisesRegex(ValueError, "unsupported_review_coverage"):
            runner.load_plan(path)

    def test_plan_rejects_synthetic_threshold_or_expanded_budget(self):
        path = self.root / "plan.json"
        for change, reason in [
            ({"capture_hook_source": str(self.hooks)},
             "unfrozen_capture_hook_source"),
            ({"capture_hook_source": "/foreign/config.toml"},
             "unfrozen_capture_hook_source"),
            ({"threshold_proposal": {"limit": 4096, "fallback_buffer": 0,
                                      "before_business": 1024, "after_business": 5000}},
             "unmeasured_threshold_must_remain_proposal"),
            ({"budget": {"startup": 180, "turn": 240,
                         "compact": 120, "cleanup": 15}},
             "native_budget_exceeds_frozen_ceiling"),
        ]:
            path.write_text(json.dumps({**self.plan, **change}))
            with self.assertRaisesRegex(ValueError, reason):
                runner.load_plan(path)

    def test_blocking_calls_need_stage_reserve(self):
        with mock.patch.object(runner.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(TimeoutError, "review_deadline_reserve"):
                runner.require_remaining(164, 65, "review")
            with self.assertRaisesRegex(TimeoutError, "cold_recovery_deadline_reserve"):
                runner.require_remaining(115, 16, "cold_recovery")
            runner.require_remaining(165, 65, "review")

    def test_pending_source_never_releases_after_stage_deadline(self):
        with mock.patch.object(runner.time, "monotonic", return_value=100):
            for phase, reason in [
                ("awaiting_answer_evidence", "answer_inference_completion_missing"),
                ("awaiting_business_evidence", "business_inference_completion_missing"),
                ("awaiting_suite", "suite_execution_or_turn_completion_missing"),
            ]:
                with self.assertRaisesRegex(TimeoutError, reason):
                    runner.check_stage_deadline(100, "turn", phase)
            runner.check_stage_deadline(101, "turn", "awaiting_answer_evidence")

    def test_collect_continues_after_cold_read_until_suite_turn_and_keeps_deadline(self):
        class FakeController:
            instances = []

            def __init__(self, _plan, _observer):
                self.phase = "waiting_ready"
                self.thread, self.turn, self.business_call_id = "thread", "turn", "business"
                self.compaction_item = {"params": {"item": {"id": "compact"}}}
                self.seen = 0
                self.instances.append(self)

            def start(self):
                return []

            def ingest(self, _raw):
                self.seen += 1
                self.phase = "awaiting_cold_recovery" if self.seen == 1 else "turn_completed"
                return []

            def cold_recovery(self):
                self.phase = "awaiting_suite"
                return {"native_acceptance": "not_established",
                        "evidence": {"cold_product": {"cold": True}}}

        class FakeTransport:
            def __init__(self, _plan, _log):
                self.receives = 0

            def receive(self, _timeout):
                self.receives += 1
                return {"method": "fixture/event"} if self.receives <= 2 else {"transport_poll": True}

            def close(self, _budget):
                return {"owned_process_exited": True, "owned_tree_no_running_members": True,
                        "process_group_cleanup_error": None}

        plan = {**self.plan, "execute_producer": True, "execute_review": True,
                "suite_oracle": {"frozen": True}}
        with (mock.patch.object(runner, "preflight"),
              mock.patch.object(runner, "NativeObserver"),
              mock.patch.object(runner, "Controller", FakeController),
              mock.patch.object(runner, "AppServer", FakeTransport),
              mock.patch.object(runner.commentary_timepoint, "capture",
                                return_value={"path": "synthetic", "sha256": "f" * 64}),
              mock.patch.object(runner.suite_oracle, "verify_suite",
                                return_value={"item_id": "suite-call"}) as check):
            result = runner.collect(plan, execute=True)
        self.assertEqual(result["status"], "source_chain_observed")
        self.assertEqual(result["suite_execution"], {"item_id": "suite-call"})
        self.assertEqual(set(result["timepoint_snapshots"]), {"cold"})
        self.assertEqual(FakeController.instances[-1].seen, 2)
        self.assertEqual(check.call_count, 1)

        plan["run_dir"] = str(self.root / "timeout-run")
        plan["budget"] = {**plan["budget"], "compact": 20}
        class PollingTransport(FakeTransport):
            def receive(self, _timeout):
                self.receives += 1
                return ({"method": "fixture/event"} if self.receives == 1
                        else {"transport_poll": True})

        ticks = itertools.count()
        with (mock.patch.object(runner, "preflight"),
              mock.patch.object(runner, "NativeObserver"),
              mock.patch.object(runner, "Controller", FakeController),
              mock.patch.object(runner.commentary_timepoint, "capture",
                                return_value={"path": "synthetic", "sha256": "f" * 64}),
              mock.patch.object(runner, "AppServer", PollingTransport),
              mock.patch.object(runner.time, "monotonic", side_effect=lambda: next(ticks))):
            timed = runner.collect(plan, execute=True)
        self.assertEqual(timed["status"], "failed")
        self.assertIn("suite_execution_or_turn_completion_missing", timed["reason"])

    def test_real_runner_journal_boundaries_allow_suite_on_either_side_of_compaction(self):
        from types import SimpleNamespace

        from tools.validation import commentary_native_profile as profile

        for suite_before in (True, False):
            with self.subTest(suite_before=suite_before):
                class FakeController:
                    def __init__(self, _plan, _observer):
                        self.phase = 'waiting_ready'
                        self.thread, self.turn, self.business_call_id = 'thread', 'turn', 'business'
                        self.compaction_item = {'params': {'item': {'id': 'compact'}}}
                        self.barrier = SimpleNamespace(chain=SimpleNamespace(
                            evidence={'precompact_product': {'review': True}}))

                    def start(self):
                        return []

                    def sent(self, _row):
                        pass

                    def reviewed(self):
                        self.phase = 'awaiting_auto_compaction'
                        return [{'id': 91, 'result': {'ok': True}}]

                    def cold_recovery(self):
                        self.phase = 'awaiting_suite'
                        return {'native_acceptance': 'not_established',
                                'evidence': {'cold_product': {'cold': True}}}

                    def ingest(self, raw):
                        if raw['method'] == 'ready':
                            self.phase = 'awaiting_review'
                        elif raw['method'] == 'postcompact':
                            self.phase = 'awaiting_cold_recovery'
                        elif raw['method'] == 'turn/completed':
                            self.phase = 'turn_completed'
                        return []

                events = ([{'method': 'ready'}, {'method': 'suite-start'},
                           {'method': 'suite-complete'}, {'method': 'postcompact'},
                           {'method': 'turn/completed'}] if suite_before else
                          [{'method': 'ready'}, {'method': 'postcompact'},
                           {'method': 'suite-start'}, {'method': 'suite-complete'},
                           {'method': 'turn/completed'}])

                class FakeTransport:
                    def __init__(self, _plan, _log):
                        self.events = iter(events)

                    def send(self, _row, timeout):
                        pass

                    def receive(self, _timeout):
                        return next(self.events)

                    def close(self, _budget):
                        return {'owned_process_exited': True,
                                'owned_tree_no_running_members': True,
                                'process_group_cleanup_error': None}

                captured = {}

                def capture(_observer, _directory, stage, _projection, journal, _anchor):
                    captured[stage] = journal.stat().st_size
                    return {'path': stage, 'sha256': 'f' * 64}

                plan = {**self.plan, 'run_dir': str(self.root / f'order-{suite_before}'),
                        'execute_producer': True, 'execute_review': True,
                        'suite_oracle': {'frozen': True}}
                with (mock.patch.object(runner, 'preflight'),
                      mock.patch.object(runner, 'NativeObserver'),
                      mock.patch.object(runner, 'Controller', FakeController),
                      mock.patch.object(runner, 'AppServer', FakeTransport),
                      mock.patch.object(runner.time, 'monotonic_ns', return_value=100),
                      mock.patch.object(runner.commentary_timepoint, 'capture',
                                        side_effect=capture),
                      mock.patch.object(runner.suite_oracle, 'verify_suite',
                                        return_value={'item_id': 'suite'})):
                    result = runner.collect(plan, execute=True)
                self.assertEqual(result['status'], 'source_chain_observed')
                journal = (Path(plan['run_dir']) / 'rpc.jsonl').read_bytes()
                rows = profile._rpc(journal)
                self.assertEqual([row['record_index'] for row in rows],
                                 list(range(1, len(rows) + 1)))
                self.assertEqual({row['monotonic_ns'] for row in rows}, {100})
                send_index = next(i for i, row in enumerate(rows)
                                  if row['direction'] == 'send' and row['raw'].get('id') == 91)
                compact_index = next(i for i, row in enumerate(rows)
                                     if row['raw'].get('method') == 'postcompact')
                terminal_index = next(i for i, row in enumerate(rows)
                                      if row['raw'].get('method') == 'turn/completed')
                suite_index = next(i for i, row in enumerate(rows)
                                   if row['raw'].get('method') == 'suite-start')
                self.assertEqual(captured['review'], profile._rpc_offset(journal, send_index))
                self.assertTrue(profile._rpc_offset(journal, compact_index + 1)
                                <= captured['cold']
                                <= profile._rpc_offset(journal, terminal_index))
                self.assertEqual(suite_index < compact_index, suite_before)

    @unittest.skipUnless(os.name == "posix", "POSIX process groups required")
    def test_owned_process_group_cleanup(self):
        process = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        adapter = runner.AppServer.__new__(runner.AppServer)
        adapter.proc = process
        adapter.owned = OwnedProcess(process)
        adapter.errors = (self.root / "stderr.log").open("xb")
        result = adapter.close(5)
        self.assertTrue(result["owned_process_exited"])
        self.assertTrue(result["process_group_kill_attempted"])

    @unittest.skipUnless(os.name == "posix", "POSIX process groups required")
    def test_cleanup_reports_signal_denial_without_masking_host_exit(self):
        process = subprocess.Popen(["/usr/bin/true"], start_new_session=True,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        process.wait(timeout=5)
        adapter = runner.AppServer.__new__(runner.AppServer)
        adapter.proc = process
        adapter.owned = OwnedProcess(process)
        adapter.errors = (self.root / "denied-stderr.log").open("xb")
        with mock.patch.object(runner.os, "killpg", side_effect=PermissionError):
            result = adapter.close(1)
        self.assertTrue(result["owned_process_exited"])
        self.assertEqual(result["process_group_cleanup_error"],
                         "process_group_signal_denied")


if __name__ == "__main__":
    unittest.main()
