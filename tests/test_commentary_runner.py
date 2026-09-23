"""Zero-model protocol oracles: explicit synthetic transport, never native proof."""

import copy
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tools.validation import commentary_runner as runner


class Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return round(self.value * 1_000_000_000)


class Fake:
    kind = "fake"

    def __init__(self, events, clock, plan):
        self.plan = plan
        self.events = list(events)
        self.clock = clock
        self.sent = []
        self.closed = []

    def send(self, raw, timeout):
        self.sent.append(copy.deepcopy(raw))
        if raw.get("method") == "hooks/list":
            hooks = [
                {
                    "source": "plugin",
                    "sourcePath": self.plan["hook_source"],
                    "eventName": event,
                    "enabled": True,
                    "trustStatus": "trusted",
                    "currentHash": "official-fixture-hash",
                }
                for event in runner.PRODUCT_EVENTS
            ]
            self.events.insert(
                0,
                (
                    self.clock.value + 0.01,
                    {
                        "id": raw["id"],
                        "result": {
                            "data": [
                                {
                                    "cwd": self.plan["cwd"],
                                    "errors": [],
                                    "warnings": [],
                                    "hooks": hooks,
                                }
                            ]
                        },
                    },
                ),
            )

    def receive(self, timeout):
        if self.events:
            delay, raw = self.events[0]
            if delay <= self.clock.value + timeout:
                self.events.pop(0)
                self.clock.value = max(delay, self.clock.value)
                return raw
        self.clock.value += timeout
        return {"transport_poll": True}

    def close(self, timeout):
        self.closed.append(timeout)
        self.clock.value += 0.125
        return {"owned_process_exited": True, "session_end": "not_inferred"}


class CommentaryRunnerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        for name in ("home", "work", "runtime", "results"):
            (self.root / name).mkdir()
        (self.root / "codex").write_bytes(b"not executed")
        (self.root / "hooks.json").write_bytes(b"{}")
        self.plan = {
            "schema": runner.SCHEMA,
            "budget": {"startup": 10, "turn": 20, "compact": 5, "cleanup": 3},
            "runtime_tree_sha256": "a" * 64,
            "source_tree_sha256": "b" * 64,
            "codex": str(self.root / "codex"),
            "codex_home": str(self.root / "home"),
            "cwd": str(self.root / "work"),
            "runtime_root": str(self.root / "runtime"),
            "hook_source": str(self.root / "hooks.json"),
            "model": "fixture-model",
            "root_prompt": "Modify the file and test it; continue until done.",
            "question": "Why is another login requested?",
            "ready_command": "python before.py",
            "continuation_command": "python after.py",
        }

    @staticmethod
    def response(id, result):
        if "thread" in result:
            result = {**result, "model": "fixture-model"}
        return {"id": id if id == 1 else id + 1, "result": result}

    @staticmethod
    def event(method, **params):
        return {
            "method": method,
            "params": {"threadId": "s1", "turnId": "t1", **params},
        }

    def item(self, item, at=105000):
        return self.event("item/completed", completedAtMs=at, item=item)

    def message(
        self, id="m1", text="Here is the explanation.", phase="commentary", at=105000
    ):
        return self.item(
            {"id": id, "type": "agentMessage", "phase": phase, "text": text}, at
        )

    def hook(self, name, id):
        return self.event(
            "hook/completed",
            run={
                "id": id,
                "eventName": name,
                "sourcePath": self.plan["hook_source"],
                "status": "completed",
                "startedAt": 109 if name == "sessionStart" else 107,
                "completedAt": 109 if name == "sessionStart" else 107,
            },
        )

    def events(self):
        events = [
            (1, self.response(1, {})),
            (2, self.response(2, {"thread": {"id": "s1"}})),
            (3, self.response(3, {"turn": {"id": "t1"}})),
            (
                3.5,
                self.event(
                    "item/started",
                    startedAtMs=103400,
                    item={
                        "type": "commandExecution",
                        "id": "ready",
                        "command": "python before.py",
                        "cwd": self.plan["cwd"],
                    },
                ),
            ),
            (4, self.response(4, {"turnId": "t1"})),
            (5, self.message()),
            (
                6,
                self.item(
                    {
                        "id": "continue",
                        "type": "commandExecution",
                        "command": "python after.py",
                        "cwd": self.plan["cwd"],
                        "status": "completed",
                        "exitCode": 0,
                    },
                    106000,
                ),
            ),
            (6.5, {"method": "diagnostic/ignored", "params": {}}),
            (7.9, self.hook("preCompact", "h1")),
            (8, self.item({"type": "contextCompaction", "id": "compact"}, 108000)),
            (9.9, self.hook("sessionStart", "h2")),
        ]
        for index, received, identity, kind, started, command in [
            (5, 4.5, "m1", "agentMessage", 104500, None),
            (7, 5.5, "continue", "commandExecution", 105500, "python after.py"),
            (10, 6.8, "compact", "contextCompaction", 106700, None),
        ]:
            item = {"id": identity, "type": kind}
            if command is not None:
                item["command"] = command
                item["cwd"] = self.plan["cwd"]
            events.insert(
                index,
                (received, self.event("item/started", startedAtMs=started, item=item)),
            )
        return events

    def run_capture(self, events=None, cancelled=None):
        clock = Clock()
        fake = Fake(self.events() if events is None else events, clock, self.plan)
        directory = (
            self.root
            / "results"
            / ("run-" + str(len(list((self.root / "results").iterdir()))))
        )
        result = runner.collect(
            self.plan,
            directory,
            lambda *_: fake,
            clock=clock,
            offline=True,
            wall_resolution_ns=1,
            mono_resolution_ns=1,
            wall=lambda: 100002000000 + clock(),
            cancelled=cancelled or (lambda: False),
        )
        checked = runner.validate(directory, directory / "validation.json")
        self.assertEqual(checked["status"], result["status"])
        return result, fake, directory

    def test_prepare_has_no_capture_requirement_and_never_spawns(self):
        with (
            patch.object(runner, "runtime_identity", return_value="a" * 64),
            patch.object(runner.subprocess, "Popen") as spawn,
        ):
            result = runner.prepare(self.plan, self.root / "results" / "prepared.json")
        spawn.assert_not_called()
        self.assertEqual(result["status"], "inputs_checked_only")
        self.assertFalse(result["native_ready"])
        self.assertEqual(result["model_requests"], 0)
        self.assertNotIn("capture", result["plan"])

    def test_ordered_notifications_remain_partial_synthetic_evidence(self):
        result, fake, _ = self.run_capture()
        self.assertEqual(result["status"], "capability_missing")
        self.assertEqual(result["transport"], "fake")
        self.assertEqual(result["answer_coverage"], "unknown")
        self.assertEqual(result["native_acceptance"], "not_established")
        self.assertEqual(result["session_end"], "not_inferred")
        self.assertEqual(fake.closed, [3])
        self.assertEqual(
            [x["method"] for x in fake.sent],
            [
                "initialize",
                "initialized",
                "hooks/list",
                "thread/start",
                "turn/start",
                "turn/steer",
            ],
        )
        self.assertEqual(fake.sent[5]["params"]["expectedTurnId"], "t1")

    def test_wrong_session_turn_and_steer_conflict_fail(self):
        for key, wrong in (("threadId", "other"), ("turnId", "old")):
            events = self.events()
            events[6][1]["params"][key] = wrong
            result, _, _ = self.run_capture(events)
            self.assertEqual(result["status"], "failed")
        events = self.events()
        events[4] = (4, self.response(4, {"turnId": "old"}))
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["reason"], "steer_turn_conflict")

    def test_steer_rejection_cannot_schedule_compact(self):
        events = self.events()
        events[4] = (4, {"id": 5, "error": {"message": "expectedTurnId conflict"}})
        result, fake, _ = self.run_capture(events)
        self.assertEqual(result["status"], "capability_missing")
        self.assertNotIn("thread/compact/start", [r["method"] for r in fake.sent])

    def test_partial_promise_correction_duplicate_never_close_coverage(self):
        for text in (
            "Only part one is known.",
            "I will investigate.",
            "Correction: the earlier statement was wrong.",
        ):
            events = self.events()
            events[6] = (5, self.message(text=text))
            events.insert(7, (5.1, self.message(text=text)))
            events.insert(
                8, (5.2, self.message(id="m2", text="Correction follows.", at=105200))
            )
            result, _, _ = self.run_capture(events)
            self.assertEqual(result["status"], "capability_missing")
            self.assertEqual(result["messages"], 2)
            self.assertEqual(result["answer_coverage"], "unknown")

    def test_conflicting_duplicate_and_stale_message_fail(self):
        events = self.events()
        events.insert(7, (5.1, self.message(text="changed")))
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["reason"], "conflicting_item_lifecycle")
        events = self.events()
        events[6] = (5, self.message(at=99999))
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["reason"], "causal_chain_not_proven")

    def test_unsolicited_compact_response_and_early_final_are_not_proof(self):
        events = self.events()
        events[9] = (6.5, {"id": 6, "error": {"message": "active turn"}})
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["reason"], "unpaired_response")
        events = self.events()
        events.insert(
            8, (6.7, self.message(id="final", phase="final_answer", at=106700))
        )
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["reason"], "final_before_active_compact_chain")

    def test_resume_without_precompact_and_compaction_is_missing(self):
        for index in (11, 12):
            events = self.events()
            events.pop(index)
            result, _, _ = self.run_capture(events)
            self.assertEqual(result["status"], "capability_missing")

    def test_early_notification_waits_for_turn_response_binding(self):
        events = self.events()
        early = events.pop(3)
        early[1]["params"]["startedAtMs"] = 102400
        events.insert(2, (2.5, early[1]))
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["status"], "capability_missing")

    def test_approval_delays_share_deadline_no_automatic_grants(self):
        events = self.events()
        events.insert(
            5,
            (
                4.2,
                {
                    "id": 900,
                    "method": "item/commandExecution/requestApproval",
                    "params": {"threadId": "s1", "turnId": "t1"},
                },
            ),
        )
        events.insert(
            6,
            (
                4.8,
                {
                    "id": 901,
                    "method": "item/commandExecution/requestApproval",
                    "params": {"threadId": "s1", "turnId": "t1"},
                },
            ),
        )
        result, fake, _ = self.run_capture(events)
        self.assertEqual(result["approval_requests"], 2)
        self.assertTrue(all("method" in r for r in fake.sent))
        self.assertEqual(result["status"], "capability_missing")
        stalled = events[:7]
        result, fake, _ = self.run_capture(stalled)
        self.assertEqual(result["status"], "capability_missing")
        self.assertEqual(result["as_of_elapsed_ns"], 22_000_000_000)
        self.assertEqual(fake.closed, [3])

    def test_cancel_never_sends_later_business_requests(self):
        calls = 0

        def cancel():
            nonlocal calls
            calls += 1
            return calls >= 4

        result, fake, _ = self.run_capture(cancelled=cancel)
        self.assertEqual(result["status"], "cancelled")
        self.assertNotIn("turn/start", [r["method"] for r in fake.sent])
        machine = runner.Machine(
            self.plan, runner.clock_sample(lambda: 0, lambda: 100000000000, 1)
        )
        machine.cancel()
        machine.request("turn/start", {})
        machine.request("turn/steer", {})
        machine.request("thread/compact/start", {})
        self.assertEqual(machine.drain(), [])

    def test_missing_phase_and_wrong_command_do_not_trigger_compact(self):
        events = self.events()[:9]
        events[6] = (5, self.message(phase=None))
        result, fake, _ = self.run_capture(events)
        self.assertEqual(result["status"], "capability_missing")
        self.assertNotIn("thread/compact/start", [r["method"] for r in fake.sent])
        events = self.events()[:9]
        events[8][1]["params"]["item"]["command"] = "python unrelated.py"
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["status"], "failed")

    def test_budget_validation_and_nonresetting_deadline(self):
        with self.assertRaises(ValueError):
            runner.Budget(turn=True)
        machine = runner.Machine(
            self.plan, runner.clock_sample(lambda: 0, lambda: 100000000000, 1)
        )
        machine.tick(10_000_000_000)
        self.assertEqual(machine.status, "capability_missing")
        self.assertEqual(machine.drain(), [])
        self.assertEqual(runner.Budget(**self.plan["budget"]).total, 38)

    def test_outputs_never_overwrite_and_capture_cannot_enter_source(self):
        result, _, directory = self.run_capture()
        before = (directory / "result.json").read_bytes()
        with self.assertRaises(FileExistsError):
            runner.collect(self.plan, directory, lambda *_: None, offline=True)
        with self.assertRaises(ValueError):
            runner.validate(directory, directory / "validation.json")
        self.assertEqual(before, (directory / "result.json").read_bytes())
        with self.assertRaises(ValueError):
            runner.collect(
                self.plan, self.root / "runtime" / "capture", lambda *_: None
            )

    def test_tampered_journal_and_promoted_fake_origin_reject(self):
        _, _, directory = self.run_capture()
        result = json.loads((directory / "result.json").read_text())
        result["transport"] = "official_stdio"
        (directory / "result.json").write_text(json.dumps(result))
        with self.assertRaises(ValueError):
            runner.validate(directory, directory / "recheck.json")
        result["transport"] = "fake"
        (directory / "result.json").write_text(json.dumps(result))
        with (directory / "rpc.jsonl").open("a") as f:
            f.write("{}\n")
        with self.assertRaises(ValueError):
            runner.validate(directory, directory / "recheck.json")

    def test_rehashed_post_cancel_request_is_rejected(self):
        _, _, directory = self.run_capture(cancelled=lambda: True)
        rows = [
            json.loads(x) for x in (directory / "rpc.jsonl").read_text().splitlines()
        ]
        rows.insert(
            -2,
            {
                "sequence": 0,
                "elapsed_ns": 0,
                "direction": "send",
                "raw": {"id": 1, "method": "turn/start", "params": {}},
            },
        )
        for i, row in enumerate(rows, 1):
            row["sequence"] = i
        raw = "".join(json.dumps(r) + "\n" for r in rows).encode()
        (directory / "rpc.jsonl").write_bytes(raw)
        result = json.loads((directory / "result.json").read_text())
        result["journal_sha256"] = hashlib.sha256(raw).hexdigest()
        (directory / "result.json").write_text(json.dumps(result))
        with self.assertRaises(ValueError):
            runner.validate(directory, directory / "recheck.json")

    def test_stale_hook_and_foreign_approval_cannot_supply_chain(self):
        events = self.events()
        events[11][1]["params"]["run"]["startedAt"] = 100
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["reason"], "causal_chain_not_proven")
        events = self.events()
        events.insert(
            5,
            (
                4.5,
                {
                    "id": 901,
                    "method": "item/commandExecution/requestApproval",
                    "params": {"threadId": "foreign", "turnId": "t1"},
                },
            ),
        )
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["reason"], "foreign_server_request")

    def test_eof_and_transport_exception_keep_failure_receipt(self):
        result, _, _ = self.run_capture([(1, None)])
        self.assertEqual(result["reason"], "transport_eof")
        clock = Clock()
        fake = Fake([], clock, self.plan)

        def broken(raw, timeout):
            raise OSError("synthetic transport failure")

        fake.send = broken
        directory = self.root / "results" / "broken"
        result = runner.collect(
            self.plan,
            directory,
            lambda *_: fake,
            clock=clock,
            offline=True,
            wall_resolution_ns=1,
            mono_resolution_ns=1,
            wall=lambda: 100002000000 + clock(),
        )
        self.assertEqual(result["status"], "failed")
        checked = runner.validate(directory, directory / "validation.json")
        self.assertEqual(checked["status"], "failed")
        self.assertEqual(fake.closed, [3])

    def test_record_limit_retains_bounded_failure(self):
        clock = Clock()
        fake = Fake(self.events(), clock, self.plan)
        directory = self.root / "results" / "limited"
        with patch.object(runner, "MAX_RECORDS", 8):
            result = runner.collect(
                self.plan,
                directory,
                lambda *_: fake,
                clock=clock,
                offline=True,
                wall_resolution_ns=1,
                mono_resolution_ns=1,
                wall=lambda: 100002000000 + clock(),
            )
            self.assertEqual(result["status"], "failed")
            runner.validate(directory, directory / "validation.json")

    def test_cancel_during_approval_prevents_compact(self):
        clock = Clock()
        events = self.events()
        events.insert(
            5,
            (
                4.5,
                {
                    "id": 901,
                    "method": "item/commandExecution/requestApproval",
                    "params": {"threadId": "s1", "turnId": "t1"},
                },
            ),
        )
        fake = Fake(events, clock, self.plan)
        directory = self.root / "results" / "cancel-approval"
        result = runner.collect(
            self.plan,
            directory,
            lambda *_: fake,
            clock=clock,
            offline=True,
            wall_resolution_ns=1,
            mono_resolution_ns=1,
            wall=lambda: 100002000000 + clock(),
            cancelled=lambda: clock.value >= 4.5,
        )
        self.assertEqual(result["status"], "cancelled")
        self.assertNotIn("thread/compact/start", [r["method"] for r in fake.sent])
        runner.validate(directory, directory / "validation.json")

    def test_untrusted_hooks_never_start_model(self):
        machine = runner.Machine(
            self.plan, runner.clock_sample(lambda: 0, lambda: 100000000000, 1)
        )
        for request in machine.drain():
            machine.sent(request, 0)
        machine.ingest(self.response(1, {}), 1)
        for request in machine.drain():
            machine.sent(request, 1)
        machine.ingest(
            {
                "id": 2,
                "result": {
                    "data": [
                        {
                            "cwd": self.plan["cwd"],
                            "hooks": [],
                            "errors": [],
                            "warnings": [],
                        }
                    ]
                },
            },
            2,
        )
        self.assertEqual(machine.reason, "normal_product_hook_trust_required")
        self.assertEqual(machine.drain(), [])

    def test_transport_construction_failure_is_replayable(self):
        directory = self.root / "results" / "no-process"

        def unavailable(*args):
            raise OSError("process unavailable")

        result = runner.collect(
            self.plan,
            directory,
            unavailable,
            clock=lambda: 0,
            offline=True,
            wall_resolution_ns=1,
            mono_resolution_ns=1,
            wall=lambda: 100002000000,
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["transport"], "unavailable")
        runner.validate(directory, directory / "validation.json")

    def test_malformed_rpc_and_nonfinite_journal_cannot_pass(self):
        events = self.events()
        events[2] = (3, self.response(3, {"turn": []}))
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["status"], "failed")
        for raw in (b'{"id":1,"id":2}', b'{"elapsed":NaN}', b"[]"):
            with self.assertRaises(ValueError):
                runner.decode_object(raw)

    def test_real_transport_cleanup_uses_one_budget_without_launch(self):
        transport = runner.StdioTransport.__new__(runner.StdioTransport)
        transport.errors = io.BytesIO()
        proc = Mock()
        proc.stdin = io.BytesIO()
        proc.stdout = io.BytesIO()
        proc.poll.side_effect = [None, 0]
        proc.wait.side_effect = [subprocess.TimeoutExpired("fake", 1), None]
        transport.proc = proc
        with patch.object(
            runner.time, "monotonic_ns", side_effect=[10_000_000_000, 10_750_000_000]
        ):
            result = transport.close(2)
        self.assertEqual(
            [c.kwargs["timeout"] for c in proc.wait.call_args_list], [1, 1.25]
        )
        self.assertTrue(result["owned_process_exited"])
        self.assertEqual(result["session_end"], "not_inferred")
        self.assertTrue(transport.errors.closed)
        self.assertTrue(proc.stdin.closed)
        proc.kill.assert_called_once()

    def test_prepared_runtime_drift_and_uninstalled_source_block_execute(self):
        receipt = self.root / "results" / "prepared.json"
        with patch.object(runner, "runtime_identity", return_value="a" * 64):
            runner.prepare(self.plan, receipt)
        args = [
            "collect",
            "--prepared",
            str(receipt),
            "--run-dir",
            str(self.root / "new-run"),
            "--execute",
        ]
        with (
            patch.object(runner, "runtime_identity", return_value="c" * 64),
            patch.object(runner, "StdioTransport") as transport,
            self.assertRaises(SystemExit),
        ):
            runner.main(args)
        transport.assert_not_called()
        with (
            patch.object(runner, "runtime_identity", return_value="a" * 64),
            patch.object(runner, "StdioTransport") as transport,
            self.assertRaises(SystemExit),
        ):
            runner.main(args)
        transport.assert_not_called()

    def test_unspecified_model_preserves_host_default_and_records_response(self):
        self.plan["model"] = None
        result, fake, _ = self.run_capture()
        self.assertEqual(result["status"], "capability_missing")
        self.assertEqual(result["selected_model"], "fixture-model")
        start = next(r for r in fake.sent if r["method"] == "thread/start")
        self.assertNotIn("model", start["params"])

    def test_cli_collect_without_execute_cannot_launch(self):
        with (
            patch.object(runner, "StdioTransport") as transport,
            self.assertRaises(SystemExit),
        ):
            runner.main(
                [
                    "collect",
                    "--prepared",
                    str(self.root / "missing.json"),
                    "--run-dir",
                    str(self.root / "new"),
                ]
            )
        transport.assert_not_called()


if __name__ == "__main__":
    unittest.main()
