"""Official app-server RPC-shaped controller tests; no host/model execution."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.validation import commentary_trace
from tools.validation.commentary_live_adapter import (
    TOOL_NAMESPACE,
    LiveBarrier,
    parse_call,
)
from tools.validation.commentary_live_controller import PRODUCT_EVENTS, Controller
from tools.validation.commentary_live_observer import NativeObserver, PendingEvidence
from tools.validation.commentary_live_runner import advance_pending, deadline_reason
from tools.validation.host_capture import digest_echo, record_payload


class StubChain:
    def __init__(self, thread, turn):
        self.phase = "new"
        self.scope = {"thread": thread, "turn": turn, "source_path": "/hooks.json"}
        self.business_challenge = None
        self.business_output = None

    def configuration(self, request, response, thread_start):
        assert request["method"] == "config/read"
        assert "origins" in response["result"]
        assert thread_start["params"]["historyMode"] == "paginated"
        self.phase = "configured"

    def commentary(self, events, payloads, **kwargs):
        assert events == ["bound"]
        self.phase = "answered_observed"

    def challenge(self, path):
        self.business_challenge = {
            "schema": "cg-business-challenge/v1", "nonce": "f" * 64,
            "commentary_pair_sha256": "a" * 64,
        }
        return self.business_challenge

    def business(self, values, output_path, **kwargs):
        assert kwargs["challenge_call_id"] == "challenge-call"
        assert kwargs["call_id"] == "business-call"
        self.business_output = {"accepted": True}
        self.phase = "business_observed"

    def release_after_review(self, runtime, state, **kwargs):
        if state != {"reviewed": True}:
            raise ValueError("unreviewed")
        self.phase = "review_consumed"

    def compaction(self, captures, **kwargs):
        assert captures == ["paired"]
        assert kwargs["completed_item"]["params"]["item"]["type"] == "contextCompaction"
        self.phase = "recovery_observed"

    def cold_recovery(self, reader):
        assert reader("q", ["main"]) == {"cold": True}
        return {"native_acceptance": "not_established", "phase": "offline_chain_checked"}

    def postbusiness(self, checkpoint, *, item_id, hook_id):
        self.postbusiness_observation = (checkpoint, item_id, hook_id)


class StubObserver:
    def configure_review_policy(self, thread):
        assert thread == "thread"

    def make_chain(self, thread, turn):
        return StubChain(thread, turn)

    def answer_source(self, *args):
        return dict(events=["bound"], payloads={}, client_id="question-id",
                    question="side question", notification={})

    def business_source(self, *args):
        return dict(events=[], payloads={}, inference_call_id="inference")

    def review_projection(self, *args):
        return None, {"reviewed": True}, Path("/private/session"), "q", ["main"]

    def compaction_source(self, *args):
        return ["paired"], dict(events=[], payloads={}, request_id="compact")

    def cold_reader(self, question, main):
        return {"cold": True}

    def postbusiness_projection(self, thread, question, main):
        assert (thread, question, main) == ("thread", "q", ["main"])
        return {"question_id": "q", "main_ids": ["main"],
                "requirements_sha256": "c" * 64,
                "product_projection_sha256": "d" * 64}


class ControllerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.controller = Controller({
            "cwd": self.temp.name, "run_dir": self.temp.name,
            "codex_home": self.temp.name,
            "hook_source": "/hooks.json",
            "capture_hook_source": "/<session-flags>/config.toml",
            "root_client_id": "root-id",
            "root_prompt": "main task", "question_client_id": "question-id",
            "question": "side question", "values": [2, 3],
            "developer_instructions": "Use the three bounded tools in order.",
        }, StubObserver())

    def test_cold_recovery_keeps_suite_turn_alive_with_same_turn_terminal(self):
        controller = self.controller
        controller.plan["suite_oracle"] = {"bounded": True}
        controller.thread, controller.turn = "thread", "turn"
        controller.phase = "awaiting_cold_recovery"
        controller.barrier = SimpleNamespace(chain=StubChain("thread", "turn"))
        terminal = {"method": "turn/completed", "params": {
            "threadId": "thread", "turn": {"id": "turn", "status": "completed", "error": None}}}
        with self.assertRaisesRegex(ValueError, "turn_ended_before_suite"):
            controller._notification(terminal)
        self.assertEqual(controller.cold_recovery()["phase"], "offline_chain_checked")
        self.assertEqual(controller.phase, "awaiting_suite")
        failed = copy.deepcopy(terminal)
        failed["params"]["turn"]["status"] = "failed"
        with self.assertRaisesRegex(ValueError, "turn_ended_before_suite"):
            controller._notification(failed)
        foreign = copy.deepcopy(terminal)
        foreign["params"]["turn"]["id"] = "other"
        with self.assertRaisesRegex(ValueError, "foreign_notification"):
            controller._notification(foreign)
        controller._notification(terminal)
        self.assertEqual(controller.phase, "turn_completed")

    def test_partial_postbusiness_requires_sent_terminal_item_then_product_hook(self):
        controller = self.controller
        controller.plan["review_coverage"] = "partial"
        controller.thread = "thread"
        controller.turn = "turn"
        controller.phase = "awaiting_auto_compaction"
        controller.business_request_id = 7
        controller.business_call_id = "business-call"
        chain = StubChain("thread", "turn")
        chain.question_id, chain.main_ids = "q", ["main"]
        controller.barrier = SimpleNamespace(chain=chain)
        item = {"type": "dynamicToolCall", "id": "business-call",
                "namespace": "cg_commentary_acceptance", "tool": "business",
                "status": "completed", "success": True}
        item_event = {"method": "item/completed", "params": {
            "threadId": "thread", "turnId": "turn", "item": item}}
        hook = {"method": "hook/completed", "params": {
            "threadId": "thread", "turnId": "turn",
            "run": {"id": "post-tool-use:10:/hooks.json:business-call",
                    "sourcePath": "/hooks.json", "source": "plugin",
                    "handlerType": "command", "executionMode": "sync",
                    "scope": "turn", "statusMessage": None,
                    "eventName": "postToolUse", "status": "completed"}}}
        with self.assertRaisesRegex(ValueError, "precompact_before_postbusiness"):
            controller._notification({"method": "hook/completed", "params": {
                "threadId": "thread", "turnId": "turn",
                "run": {"id": "pre", "sourcePath": "/hooks.json",
                        "eventName": "preCompact", "status": "completed"}}})
        controller.sent({"id": 7, "result": {}})
        with self.assertRaisesRegex(ValueError, "intervening_tool_before_postbusiness"):
            controller._notification({"method": "item/completed", "params": {
                "threadId": "thread", "turnId": "turn",
                "item": {"type": "commandExecution", "id": "other"}}})
        with self.assertRaisesRegex(ValueError, "unbound_postbusiness_hook"):
            controller._notification(hook)
        controller._notification(item_event)
        delayed = copy.deepcopy(hook)
        delayed["params"]["run"]["id"] = "post-tool-use:9:/hooks.json:other-call"
        with self.assertRaisesRegex(ValueError, "unbound_postbusiness_hook"):
            controller._notification(delayed)
        failed = copy.deepcopy(hook)
        failed["params"]["run"]["status"] = "failed"
        with self.assertRaisesRegex(ValueError, "unbound_postbusiness_hook"):
            controller._notification(failed)
        controller._notification(hook)
        self.assertEqual(chain.postbusiness_observation[1:],
                         ("business-call", "post-tool-use:10:/hooks.json:business-call"))
        with self.assertRaisesRegex(ValueError, "unbound_postbusiness_hook"):
            controller._notification(hook)

    def test_partial_answer_content_is_bound_before_challenge_release(self):
        controller = self.controller
        controller.plan["review_coverage"] = "partial"
        controller.thread = "thread"
        controller.turn = "turn"
        controller.phase = "awaiting_answer_evidence"
        controller.barrier = SimpleNamespace(
            release_challenge=lambda **_source: {"id": 3, "result": {}})

        def source(text):
            return {"events": [], "payloads": {}, "client_id": "question-id",
                    "question": "side question", "notification": {"params": {
                        "item": {"text": text}}}}

        with mock.patch.object(controller.observer, "answer_source",
                               return_value=source("第一问是 49。第二问是 121。")):
            with self.assertRaisesRegex(ValueError, "partial_answer_content_unfit"):
                controller.try_answer()
        self.assertEqual(controller.phase, "awaiting_answer_evidence")
        with mock.patch.object(controller.observer, "answer_source",
                               return_value=source("第一问是 49。")):
            self.assertTrue(controller.try_answer())
        self.assertEqual(controller.phase, "waiting_business")

    def reply(self, request, result):
        return self.controller.ingest({"id": request["id"], "result": result})

    def start_turn(self):
        initialize, = self.controller.start()
        initialized, config = self.reply(initialize, {})
        self.assertEqual(initialized["method"], "initialized")
        hooks, = self.reply(config, {"config": {}, "origins": {}})
        rows = [dict(source="plugin", sourcePath="/hooks.json", eventName=event,
                     key="plugin:" + event, trustStatus="trusted", enabled=True,
                     currentHash="sha256:" + "a" * 64)
                for event in PRODUCT_EVENTS]
        rows += [dict(source="sessionFlags", sourcePath="/<session-flags>/config.toml",
                      eventName=event, key="capture:" + event,
                      command="capture --digest-echo", trustStatus="trusted",
                      enabled=True, currentHash="sha256:" + "b" * 64)
                 for event in ("preCompact", "sessionStart")]
        self.controller.plan["selected_hook_hashes"] = {
            row["key"]: row["currentHash"] for row in rows
        }
        start, = self.reply(hooks, {"data": [{"cwd": self.temp.name,
                                              "errors": [], "warnings": [], "hooks": rows}]})
        self.assertEqual(start["params"]["historyMode"], "paginated")
        self.assertEqual(start["params"]["developerInstructions"],
                         "Use the three bounded tools in order.")
        self.assertEqual(start["params"]["dynamicTools"][0]["name"], TOOL_NAMESPACE)
        turn, = self.reply(start, {"thread": {"id": "thread"}, "model": "selected-model"})
        self.reply(turn, {"turn": {"id": "turn"}})

    def call(self, name, number):
        return {"id": number, "method": "item/tool/call", "params": {
            "threadId": "thread", "turnId": "turn", "callId": name + "-call",
            "namespace": TOOL_NAMESPACE, "tool": name,
            "arguments": {"nonce": "f" * 64} if name == "business" else {},
        }}

    def test_whole_wire_sequence_needs_review_and_completed_compaction(self):
        self.start_turn()
        steer, = self.controller.ingest(self.call("ready", 10))
        self.assertEqual(steer["params"]["clientUserMessageId"], "question-id")
        ready, = self.reply(steer, {"turnId": "turn"})
        self.assertEqual(ready["id"], 10)
        challenge, = self.controller.ingest(self.call("challenge", 11))
        self.assertEqual(challenge["id"], 11)
        self.assertEqual(self.controller.ingest(self.call("business", 12)), [])
        self.assertEqual(self.controller.phase, "awaiting_review")
        result, = self.controller.reviewed()
        self.assertEqual(result["id"], 12)
        self.assertEqual(self.controller.phase, "awaiting_auto_compaction")
        compact = {"method": "item/completed", "params": {
            "threadId": "thread", "turnId": "turn",
            "item": {"type": "contextCompaction", "id": "compact-1"},
        }}
        self.controller.ingest(compact)
        self.assertEqual(self.controller.cold_recovery()["native_acceptance"], "not_established")

    def test_early_or_foreign_events_never_complete(self):
        self.start_turn()
        with self.assertRaisesRegex(ValueError, "early_or_duplicate_compaction"):
            self.controller.ingest({"method": "item/completed", "params": {
                "threadId": "thread", "turnId": "turn",
                "item": {"type": "contextCompaction", "id": "early"},
            }})
        with self.assertRaisesRegex(ValueError, "unreviewed_server_request"):
            self.controller.ingest({"id": 20, "method": "item/commandExecution/requestApproval",
                                    "params": {"threadId": "thread", "turnId": "turn"}})

    def test_completed_compaction_waits_for_late_hook_and_rejects_repeat(self):
        self.start_turn()
        observer = self.controller.observer
        original = observer.compaction_source

        def late(_thread, _turn, hooks, _item):
            if not hooks:
                raise PendingEvidence("matching_hook_notification_pending")
            return original(_thread, _turn, hooks, _item)

        observer.compaction_source = late
        self.controller.phase = "awaiting_auto_compaction"
        compact = {"method": "item/completed", "params": {
            "threadId": "thread", "turnId": "turn",
            "item": {"type": "contextCompaction", "id": "compact-1"},
        }}
        self.controller.ingest(compact)
        self.assertEqual(self.controller.phase, "awaiting_compaction_evidence")
        self.assertFalse(self.controller.try_compaction())
        with self.assertRaisesRegex(ValueError, "early_or_duplicate_compaction"):
            self.controller.ingest(compact)
        self.controller.ingest({"method": "hook/completed", "params": {
            "threadId": "thread", "run": {"entries": []},
        }})
        self.assertEqual(self.controller.phase, "awaiting_cold_recovery")

    def test_actual_observer_controller_runner_wait_for_answer_trace(self):
        observer = NativeObserver.__new__(NativeObserver)
        observer.trace = commentary_trace
        request = {"input": [{"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": "side question"}]}]}
        response = {"response_id": "response-1", "output_items": [
            {"id": "answer-1", "type": "message", "role": "assistant",
             "phase": "commentary", "content": [{"type": "output_text", "text": "answer"}]},
        ]}

        def ref(number, kind):
            return {"raw_payload_id": f"raw_payload:{number}", "kind": {"type": kind},
                    "path": f"payloads/{number}.json"}

        started = {"schema_version": 1, "rollout_id": "rollout", "thread_id": "thread",
                   "codex_turn_id": "turn", "payload": {
                       "type": "inference_started", "inference_call_id": "call-1",
                       "thread_id": "thread", "codex_turn_id": "turn",
                       "request_payload": ref(1, "inference_request")}}
        completed = {"schema_version": 1, "rollout_id": "rollout", "thread_id": "thread",
                     "codex_turn_id": "turn", "payload": {
                         "type": "inference_completed", "inference_call_id": "call-1",
                         "response_id": "response-1",
                         "response_payload": ref(2, "inference_response")}}
        source = {"events": [started], "payloads": {
            "payloads/1.json": json.dumps(request).encode(),
            "payloads/2.json": json.dumps(response).encode(),
        }}
        observer._snapshot = lambda _thread: source
        self.controller.observer = observer
        self.controller.thread = "thread"
        self.controller.turn = "turn"
        self.controller.phase = "waiting_challenge"
        self.controller.user_items = [{"method": "item/completed", "params": {
            "threadId": "thread", "turnId": "turn", "item": {
                "type": "userMessage", "clientId": "question-id", "id": "user-1",
                "content": [{"type": "text", "text": "side question"}],
            }}}]
        self.controller.answer_items = [{"method": "item/completed", "params": {
            "threadId": "thread", "turnId": "turn", "item": {
                "type": "agentMessage", "phase": "commentary", "id": "answer-1",
                "text": "answer",
            }}}]
        checked = []
        chain = SimpleNamespace(
            phase="configured", scope={"thread": "thread", "turn": "turn",
                                       "source_path": "/hooks.json"},
            commentary=lambda *args, **kwargs: checked.append("bound"),
            challenge=lambda _path: {"nonce": "f" * 64},
        )
        self.controller.barrier = LiveBarrier(
            chain, thread="thread", turn="turn", directory=Path(self.temp.name),
            values=[2, 3],
        )
        self.controller.barrier.phase = "challenge_expected"
        self.assertEqual(self.controller.ingest(self.call("challenge", 11)), [])
        self.assertEqual(self.controller.phase, "awaiting_answer_evidence")
        emitted = []
        advance_pending(self.controller, emitted.extend)
        self.assertEqual(emitted, [])
        self.assertEqual(checked, [])
        with self.assertRaisesRegex(ValueError, "duplicate_or_out_of_phase_call"):
            self.controller.ingest(self.call("challenge", 12))
        source["events"].append(completed)
        advance_pending(self.controller, emitted.extend)
        self.assertEqual(self.controller.phase, "waiting_business")
        self.assertEqual(len(emitted), 1)
        self.assertEqual(checked, ["bound"])
        self.assertEqual(deadline_reason("turn", "awaiting_answer_evidence"),
                         "answer_inference_completion_missing")

    def test_actual_observer_controller_runner_wait_for_business_trace(self):
        observer = NativeObserver.__new__(NativeObserver)
        observer.trace = commentary_trace
        started = {"schema_version": 1, "rollout_id": "rollout", "thread_id": "thread",
                   "codex_turn_id": "turn", "payload": {
                       "type": "inference_started", "inference_call_id": "call-1",
                       "thread_id": "thread", "codex_turn_id": "turn",
                       "request_payload": {"raw_payload_id": "raw_payload:1",
                                           "kind": {"type": "inference_request"},
                                           "path": "payloads/1.json"}}}
        completed = {"schema_version": 1, "rollout_id": "rollout", "thread_id": "thread",
                     "codex_turn_id": "turn", "payload": {
                         "type": "inference_completed", "inference_call_id": "call-1",
                         "response_id": "response-1",
                         "response_payload": {"raw_payload_id": "raw_payload:2",
                                              "kind": {"type": "inference_response"},
                                              "path": "payloads/2.json"}}}
        source = {"events": [started], "payloads": {
            "payloads/1.json": b'{"input":[]}',
            "payloads/2.json": b'{"response_id":"response-1","output_items":['
                               b'{"type":"function_call","call_id":"business-call"}]}',
        }}
        observer._snapshot = lambda _thread: source
        self.controller.observer = observer
        self.controller.thread = "thread"
        self.controller.turn = "turn"
        self.controller.phase = "waiting_business"
        observed = []

        class Barrier:
            pending = None
            challenge_call_id = None
            chain = SimpleNamespace(business_challenge=None)

            def receive(self, raw):
                self.pending = parse_call(raw, thread="thread", turn="turn")
                return self.pending

            def observe_business(self, **source):
                observed.append(source)

        self.controller.barrier = Barrier()
        business = self.call("business", 12)
        self.assertEqual(self.controller.ingest(business), [])
        self.assertEqual(self.controller.phase, "awaiting_business_evidence")
        advance_pending(self.controller, lambda _rows: None)
        self.assertEqual(observed, [])
        source["events"].append(completed)
        advance_pending(self.controller, lambda _rows: None)
        self.assertEqual(self.controller.phase, "awaiting_review")
        self.assertEqual(observed[0]["inference_call_id"], "call-1")
        self.assertEqual(deadline_reason("turn", "awaiting_business_evidence"),
                         "business_inference_completion_missing")

    def test_real_observer_and_controller_bind_late_compact_capture(self):
        observer = NativeObserver.__new__(NativeObserver)
        observer.capture_dir = Path(self.temp.name) / "captures"
        observer.runtime_root = Path(__file__).resolve().parents[1]
        observer.plan = self.controller.plan
        observer.trace = SimpleNamespace(
            decode=commentary_trace.decode,
            attempt_pair=lambda *args, **kwargs: ({}, {}, {"compaction_id": "compact-1"}),
        )
        observer._snapshot = lambda thread: {
            "events": [{"thread_id": thread, "codex_turn_id": "turn",
                        "payload": {"type": "compaction_request_completed",
                                    "compaction_request_id": "request-1"}}],
            "payloads": {"p": b"x"},
        }
        self.controller.observer = observer
        self.controller.thread = "thread"
        self.controller.turn = "turn"
        self.controller.phase = "awaiting_auto_compaction"
        observed = []
        self.controller.barrier = SimpleNamespace(chain=SimpleNamespace(
            compaction=lambda captures, **source: observed.append((captures, source)),
        ))

        def capture(event, **fields):
            raw = json.dumps({"hook_event_name": event, "session_id": "thread",
                              "cwd": self.temp.name, **fields}).encode()
            meta = record_payload(raw, total_bytes=len(raw), truncated=False,
                                  expected_event=event, capture_dir=observer.capture_dir,
                                  runtime_root=observer.runtime_root, echo=True)
            return raw, json.loads(meta.read_bytes())["capture_id"]

        def hook(raw, identity):
            event = json.loads(raw[0])["hook_event_name"]
            return {"method": "hook/completed", "params": {
                "threadId": "thread", "turnId": "turn", "run": {
                    "id": identity, "eventName": event[0].lower() + event[1:],
                    "status": "completed", "handlerType": "command",
                    "executionMode": "sync",
                    "sourcePath": "/<session-flags>/config.toml",
                    "entries": [{"kind": "warning", "text": digest_echo(*raw)}]},
            }}

        startup = capture("SessionStart", source="startup")
        self.controller.ingest(hook(startup, "startup-run"))
        pre = capture("PreCompact", trigger="auto", turn_id="turn")
        self.controller.ingest({"method": "item/completed", "params": {
            "threadId": "thread", "turnId": "turn",
            "item": {"type": "contextCompaction", "id": "compact-1"},
        }})
        self.assertEqual(self.controller.phase, "awaiting_compaction_evidence")
        self.controller.ingest(hook(pre, "pre-run"))
        self.assertEqual(self.controller.phase, "awaiting_compaction_evidence")
        post = capture("SessionStart", source="compact")
        self.assertFalse(self.controller.try_compaction())
        foreign = hook(post, "foreign-run")
        foreign["params"]["turnId"] = "other-turn"
        with self.assertRaisesRegex(ValueError, "foreign_notification"):
            self.controller.ingest(foreign)
        self.controller.ingest(hook(post, "post-run"))
        self.assertEqual(self.controller.phase, "awaiting_cold_recovery")
        self.assertEqual(len(observed), 1)
        self.assertEqual(len(observed[0][0]), 2)

    def test_hook_hash_pin_is_required_before_thread_creation(self):
        initialize, = self.controller.start()
        _initialized, config = self.reply(initialize, {})
        hooks, = self.reply(config, {"config": {}, "origins": {}})
        rows = [dict(source="plugin", sourcePath="/hooks.json", eventName=event,
                     key="plugin:" + event, trustStatus="trusted", enabled=True,
                     currentHash="sha256:" + "a" * 64)
                for event in PRODUCT_EVENTS]
        rows += [dict(source="sessionFlags", sourcePath="/<session-flags>/config.toml",
                      eventName=event, key="capture:" + event,
                      command="capture --digest-echo", trustStatus="trusted", enabled=True,
                      currentHash="sha256:" + "b" * 64)
                 for event in ("preCompact", "sessionStart")]
        self.controller.plan["selected_hook_hashes"] = {
            row["key"]: row["currentHash"] for row in rows
        }
        rows[0]["currentHash"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(ValueError, "exact_trusted_hooks_required"):
            self.reply(hooks, {"data": [{"cwd": self.temp.name,
                                          "errors": [], "warnings": [], "hooks": rows}]})

    def test_capture_hooks_require_the_frozen_session_flags_source(self):
        for field, value in (("source", "user"),
                             ("sourcePath", "/foreign/config.toml")):
            with self.subTest(field=field):
                self.controller = Controller(dict(self.controller.plan), StubObserver())
                initialize, = self.controller.start()
                _initialized, config = self.reply(initialize, {})
                hooks, = self.reply(config, {"config": {}, "origins": {}})
                rows = [dict(source="plugin", sourcePath="/hooks.json", eventName=event,
                             key="plugin:" + event, trustStatus="trusted", enabled=True,
                             currentHash="sha256:" + "a" * 64)
                        for event in PRODUCT_EVENTS]
                rows += [dict(source="sessionFlags",
                              sourcePath="/<session-flags>/config.toml",
                              eventName=event, key="capture:" + event,
                              command="capture --digest-echo", trustStatus="trusted",
                              enabled=True, currentHash="sha256:" + "b" * 64)
                         for event in ("preCompact", "sessionStart")]
                self.controller.plan["selected_hook_hashes"] = {
                    row["key"]: row["currentHash"] for row in rows
                }
                rows[-1][field] = value
                with self.assertRaisesRegex(ValueError, "exact_trusted_hooks_required"):
                    self.reply(hooks, {"data": [{"cwd": self.temp.name,
                                                  "errors": [], "warnings": [],
                                                  "hooks": rows}]})

    def test_capture_hook_readback_rejects_identity_and_trust_drift(self):
        changes = {
            "missing": lambda rows: rows.pop(),
            "duplicate": lambda rows: rows.append(dict(rows[-1])),
            "hash": lambda rows: rows[-1].update(currentHash="sha256:" + "c" * 64),
            "untrusted": lambda rows: rows[-1].update(trustStatus="modified"),
            "disabled": lambda rows: rows[-1].update(enabled=False),
            "event": lambda rows: rows[-1].update(eventName="preCompact"),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                self.controller = Controller(dict(self.controller.plan), StubObserver())
                initialize, = self.controller.start()
                _initialized, config = self.reply(initialize, {})
                hooks, = self.reply(config, {"config": {}, "origins": {}})
                rows = [dict(source="plugin", sourcePath="/hooks.json", eventName=event,
                             key="plugin:" + event, trustStatus="trusted", enabled=True,
                             currentHash="sha256:" + "a" * 64)
                        for event in PRODUCT_EVENTS]
                rows += [dict(source="sessionFlags",
                              sourcePath="/<session-flags>/config.toml",
                              eventName=event, key="capture:" + event,
                              command="capture --digest-echo", trustStatus="trusted",
                              enabled=True, currentHash="sha256:" + "b" * 64)
                         for event in ("preCompact", "sessionStart")]
                self.controller.plan["selected_hook_hashes"] = {
                    row["key"]: row["currentHash"] for row in rows
                }
                change(rows)
                with self.assertRaisesRegex(ValueError, "exact_trusted_hooks_required"):
                    self.reply(hooks, {"data": [{"cwd": self.temp.name,
                                                  "errors": [], "warnings": [],
                                                  "hooks": rows}]})
