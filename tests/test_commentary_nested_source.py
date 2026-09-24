"""Exec-wrapped dynamic tool provenance from official trace-shaped records."""

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import cg_commentary_binding, cg_commentary_trace
from tools.validation import commentary_fixture as fixture
from tools.validation import commentary_live_adapter as live_wire
from tools.validation import commentary_trace as trace
from tools.validation.commentary_chain import (
    Chain,
    NestedSourcePending,
    nested_business_proof,
)
from tools.validation.commentary_live_controller import Controller
from tools.validation.commentary_live_observer import NativeObserver, PendingEvidence
from tools.validation.commentary_live_runner import (
    advance_pending,
    check_stage_deadline,
)


def nested_source():
    thread, turn = "thread", "turn"
    challenge = {"schema": "cg-business-challenge/v1", "nonce": "f" * 64,
                 "commentary_pair_sha256": "a" * 64}
    expected = fixture.canonical(challenge).decode()
    values = {}

    def payload(number, value):
        values[f"payloads/{number}.json"] = fixture.canonical(value)

    def ref(number, kind):
        return {"raw_payload_id": f"raw_payload:{number}",
                "kind": {"type": kind}, "path": f"payloads/{number}.json"}

    payload(1, {"input": []})
    payload(2, {"response_id": "response-1", "output_items": [
        {"type": "custom_tool_call", "name": "exec", "call_id": "outer-challenge"}]})
    payload(3, {"tool_namespace": "cg_commentary_acceptance",
                "tool_name": "challenge", "payload": {"type": "function", "arguments": "{}"}})
    payload(4, {"type": "code_mode_response", "value": expected})
    payload(5, {"input": [{"type": "custom_tool_call_output",
                             "call_id": "outer-challenge", "output": [
                                 {"type": "input_text", "text": "other metadata"},
                                 {"type": "input_text", "text": expected}]}]})
    payload(6, {"response_id": "response-2", "output_items": [
        {"type": "custom_tool_call", "name": "exec", "call_id": "outer-business"}]})
    payload(7, {"tool_namespace": "cg_commentary_acceptance",
                "tool_name": "business", "payload": {
                    "type": "function", "arguments": json.dumps({"nonce": challenge["nonce"]})}})

    def event(seq, event_type, **fields):
        return {"schema_version": 1, "seq": seq, "rollout_id": thread,
                "thread_id": thread, "codex_turn_id": turn,
                "payload": {"type": event_type, **fields}}

    events = [
        event(1, "inference_started", inference_call_id="prior",
              thread_id=thread, codex_turn_id=turn,
              request_payload=ref(1, "inference_request")),
        event(2, "inference_completed", inference_call_id="prior",
              response_id="response-1", response_payload=ref(2, "inference_response")),
        event(3, "code_cell_started", runtime_cell_id="cell-1",
              model_visible_call_id="outer-challenge"),
        event(4, "tool_call_started", tool_call_id="challenge-inner",
              requester={"type": "code_cell", "runtime_cell_id": "cell-1"},
              kind={"type": "other", "name": "challenge"},
              invocation_payload=ref(3, "tool_invocation")),
        event(5, "tool_call_ended", tool_call_id="challenge-inner",
              status="completed", result_payload=ref(4, "tool_result")),
        event(6, "inference_started", inference_call_id="business-inference",
              thread_id=thread, codex_turn_id=turn,
              request_payload=ref(5, "inference_request")),
        event(7, "code_cell_started", runtime_cell_id="cell-2",
              model_visible_call_id="outer-business"),
        event(8, "tool_call_started", tool_call_id="business-inner",
              requester={"type": "code_cell", "runtime_cell_id": "cell-2"},
              kind={"type": "other", "name": "business"},
              invocation_payload=ref(7, "tool_invocation")),
        event(9, "inference_completed", inference_call_id="business-inference",
              response_id="response-2", response_payload=ref(6, "inference_response")),
    ]
    return events, values, challenge


class NestedBusinessSourceTests(unittest.TestCase):
    def proof(self, events, payloads, challenge):
        return nested_business_proof(
            events, payloads, thread="thread", turn="turn",
            inference_call_id="business-inference", call_id="business-inner",
            challenge_call_id="challenge-inner", challenge=challenge,
        )

    def observer(self, events, payloads, challenge):
        observer = NativeObserver.__new__(NativeObserver)
        observer.trace = trace
        observer._snapshot = lambda _thread: {"events": events, "payloads": payloads}
        return observer.business_source(
            "thread", "turn", "business-inner", "challenge-inner", challenge)

    def test_exact_nested_parent_chain_and_business_result(self):
        events, payloads, challenge = nested_source()
        proof = self.proof(events, payloads, challenge)
        self.assertEqual(proof["mode"], "nested_exec")
        self.assertEqual(proof["outer_call_id"], "outer-business")
        source = self.observer(events, payloads, challenge)
        self.assertEqual(source["inference_call_id"], "business-inference")
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path = Path(directory) / "business.json"
            result, _ = fixture.business_result([2, 3], challenge)
            fixture.exclusive(path, result)
            chain = Chain(thread="thread", turn="turn", cwd="/fixture",
                          hook_source="/fixture/hooks.json",
                          capture_hook_source=fixture.CAPTURE_HOOK_SOURCE,
                          frozen_config={}, threshold={})
            chain.phase = "challenge_issued"
            chain.business_challenge = challenge
            chain.business([2, 3], path, events=events, payloads=payloads,
                           inference_call_id="business-inference",
                           call_id="business-inner", challenge_call_id="challenge-inner")
            self.assertEqual(chain.phase, "business_observed")
            self.assertEqual(chain.business_invocation["mode"], "nested_exec")

    def test_missing_child_stays_pending_without_releasing_business(self):
        events, payloads, challenge = nested_source()
        events = [e for e in events if e["payload"].get("tool_call_id") != "business-inner"]
        with self.assertRaisesRegex(NestedSourcePending, "business_tool_start_pending"):
            self.proof(events, payloads, challenge)
        with self.assertRaisesRegex(PendingEvidence, "business_inference_completion_pending"):
            self.observer(events, payloads, challenge)

    def test_controller_holds_nested_business_until_child_trace_arrives(self):
        events, payloads, challenge = nested_source()
        business = events.pop(7)
        observer = NativeObserver.__new__(NativeObserver)
        observer.trace = trace
        observer._snapshot = lambda _thread: {"events": events, "payloads": payloads}
        controller = Controller({"question_client_id": "question-client"}, observer)
        controller.thread, controller.turn, controller.phase = "thread", "turn", "waiting_business"
        observed = []

        class Barrier:
            pending = None
            challenge_call_id = "challenge-inner"
            chain = SimpleNamespace(business_challenge=challenge)

            def receive(self, raw):
                self.pending = live_wire.parse_call(raw, thread="thread", turn="turn")
                return self.pending

            def observe_business(self, **source):
                observed.append(source)

        controller.barrier = Barrier()
        raw = {"id": 1, "method": "item/tool/call", "params": {
            "threadId": "thread", "turnId": "turn",
            "callId": "business-inner", "namespace": live_wire.TOOL_NAMESPACE,
            "tool": "business", "arguments": {"nonce": challenge["nonce"]}}}
        self.assertEqual(controller.ingest(raw), [])
        self.assertEqual(controller.phase, "awaiting_business_evidence")
        advance_pending(controller, lambda rows: self.fail(f"early release: {rows}"))
        self.assertEqual(observed, [])
        with self.assertRaises(TimeoutError):
            check_stage_deadline(0, "turn", controller.phase)
        events.insert(7, business)
        advance_pending(controller, lambda rows: self.fail(f"early release: {rows}"))
        self.assertEqual(controller.phase, "awaiting_review")
        self.assertEqual(observed[0]["inference_call_id"], "business-inference")

    def test_wrong_identity_duplicate_and_order_fail_closed(self):
        mutations = (
            (lambda e, p: e[7]["payload"]["requester"].update(runtime_cell_id="other"),
             "business_cell_pending"),
            (lambda e, p: e[6]["payload"].update(model_visible_call_id="other"),
             "business_outer_call_mismatch"),
            (lambda e, p: e.append(copy.deepcopy(e[7])), "repeated_business_tool_start"),
            (lambda e, p: e[7].update(seq=2), "business_nested_order_or_rollout"),
            (lambda e, p: e[7].update(rollout_id="foreign"),
             "business_nested_order_or_rollout"),
        )
        for mutation, reason in mutations:
            with self.subTest(reason=reason):
                events, payloads, challenge = nested_source()
                mutation(events, payloads)
                with self.assertRaisesRegex(ValueError, reason):
                    self.proof(events, payloads, challenge)

    def test_wrong_namespace_nonce_and_challenge_source_fail_closed(self):
        mutations = (
            (7, lambda x: x.update(tool_namespace="foreign"),
             "business_invocation_mismatch"),
            (7, lambda x: x["payload"].update(arguments='{"nonce":"wrong"}'),
             "business_invocation_mismatch"),
            (4, lambda x: x.update(value="wrong"), "challenge_result_mismatch"),
            (5, lambda x: x["input"][0].update(call_id="wrong"),
             "business_request_lacks_fresh_challenge"),
        )
        for number, mutation, reason in mutations:
            with self.subTest(reason=reason):
                events, payloads, challenge = nested_source()
                path = f"payloads/{number}.json"
                value = json.loads(payloads[path])
                mutation(value)
                payloads[path] = fixture.canonical(value)
                with self.assertRaisesRegex(ValueError, reason):
                    self.proof(events, payloads, challenge)

    def test_nested_business_output_binds_compaction_input(self):
        events, payloads, challenge = nested_source()
        invocation = self.proof(events, payloads, challenge)
        result, _ = fixture.business_result([2, 3], challenge)
        expected = fixture.canonical(result).decode()
        payloads["payloads/8.json"] = fixture.canonical(
            {"type": "code_mode_response", "value": expected})
        scope = {"schema_version": 1, "rollout_id": "thread",
                 "thread_id": "thread", "codex_turn_id": "turn"}
        events.extend([
            {**scope, "seq": 10, "payload": {
                "type": "tool_call_ended", "tool_call_id": "business-inner",
                "status": "completed", "result_payload": {
                    "raw_payload_id": "raw_payload:8", "kind": {"type": "tool_result"},
                    "path": "payloads/8.json"}}},
            {**scope, "seq": 11, "payload": {
                "type": "code_cell_ended", "runtime_cell_id": "cell-2",
                "status": "completed"}},
        ])
        captures = []
        for event, cid in (("PreCompact", "a" * 32), ("SessionStart", "b" * 32)):
            raw_value = {"session_id": "thread", "hook_event_name": event}
            if event == "PreCompact":
                raw_value.update(turn_id="turn", trigger="auto")
            else:
                raw_value["source"] = "compact"
            raw = fixture.canonical(raw_value)
            notification = {"method": "hook/completed", "params": {
                "threadId": "thread", "turnId": "turn", "run": {
                    "id": event + "-run", "eventName": event[0].lower() + event[1:],
                    "status": "completed", "handlerType": "command",
                    "executionMode": "sync", "sourcePath": "/fixture/hooks.json",
                    "entries": [{"kind": "warning", "text": fixture.marker(raw, cid)}]}}}
            captures.append({"raw": raw, "capture_id": cid, "notification": notification})
        request = {"input": [{"type": "custom_tool_call_output",
                              "call_id": "outer-business", "output": [
                                  {"type": "input_text", "text": expected}]}]}
        args = dict(request=request, business_result=result, invocation=invocation,
                    thread="thread", turn="turn", source_path="/fixture/hooks.json",
                    events=events, payloads=payloads)
        self.assertEqual(fixture.compact_outcome(captures, **args)["business_call_id"],
                         "business-inner")
        args["request"] = {"input": []}
        with self.assertRaisesRegex(fixture.Unknown, "early_or_unbound_compaction"):
            fixture.compact_outcome(captures, **args)
        args["request"] = request
        payloads["payloads/8.json"] = fixture.canonical(
            {"type": "code_mode_response", "value": "wrong"})
        with self.assertRaisesRegex(fixture.Unknown, "nested_business_result_mismatch"):
            fixture.compact_outcome(captures, **args)

    def snapshot_fixture(self, root):
        events, payloads, _challenge = nested_source()
        bundle = root / "trace-trace-id-thread"
        (bundle / "payloads").mkdir(parents=True)
        manifest = {"schema_version": 1, "trace_id": "trace-id",
                    "root_thread_id": "thread", "rollout_id": "thread",
                    "raw_event_log": "trace.jsonl", "payloads_dir": "payloads"}
        (bundle / "manifest.json").write_bytes(fixture.canonical(manifest))
        first = {"schema_version": 1, "seq": 1, "rollout_id": "thread",
                 "thread_id": "thread", "codex_turn_id": None,
                 "payload": {"type": "rollout_started", "trace_id": "trace-id",
                             "root_thread_id": "thread"}}
        shifted = [{**e, "seq": e["seq"] + 1} for e in events]
        (bundle / "trace.jsonl").write_bytes(
            b"".join(fixture.canonical(e) + b"\n" for e in [first, *shifted]))
        for relative, raw in payloads.items():
            (bundle / relative).write_bytes(raw)
        observer = NativeObserver.__new__(NativeObserver)
        observer.plan = {"trace_root": str(root)}
        observer.binding = cg_commentary_binding
        observer.trace = cg_commentary_trace
        return observer, bundle, payloads

    def test_snapshot_reads_nested_payloads_from_same_verified_bundle(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            root = Path(directory)
            observer, _bundle, payloads = self.snapshot_fixture(root)
            with mock.patch.dict(os.environ, {"CODEX_ROLLOUT_TRACE_ROOT": str(root)}):
                snapshot = observer._snapshot("thread")
                self.assertEqual(set(snapshot["payloads"]), set(payloads))

    def test_snapshot_rejects_linked_nested_payload_when_supported(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            root = Path(directory)
            observer, bundle, _payloads = self.snapshot_fixture(root)
            extra = bundle / "payloads/7.json"
            extra.unlink()
            try:
                extra.symlink_to(bundle / "payloads/3.json")
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows host cannot create symlinks")
                raise
            with mock.patch.dict(os.environ, {"CODEX_ROLLOUT_TRACE_ROOT": str(root)}):
                with self.assertRaises(ValueError):
                    observer._snapshot("thread")


if __name__ == "__main__":
    unittest.main()
