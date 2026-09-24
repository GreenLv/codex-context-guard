"""Native observer source selection with bounded, injected offline records."""

import hashlib
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.validation import commentary_trace
from tools.validation.commentary_live_observer import NativeObserver, PendingEvidence
from tools.validation.host_capture import (
    CaptureError,
    digest_echo,
    inspect_directory,
    record_payload,
)


class ObserverSourceTest(unittest.TestCase):
    def setUp(self):
        self.observer = NativeObserver.__new__(NativeObserver)
        self.observer.plan = {"question": "question", "main_requirement_text": "main",
                              "capture_hook_source": "/<session-flags>/config.toml"}
        self.user = {"method": "item/completed", "params": {
            "threadId": "thread", "turnId": "turn",
            "item": {"type": "userMessage", "id": "user-1", "clientId": "client-1",
                     "content": [{"type": "text", "text": "question"}]},
        }}
        self.answer = {"method": "item/completed", "params": {
            "threadId": "thread", "turnId": "turn",
            "item": {"type": "agentMessage", "id": "answer-1",
                     "phase": "commentary", "text": "answer"},
        }}

    def test_cold_reader_uses_frozen_external_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installed = root / "installed"
            harness = root / "harness"
            (installed / "scripts").mkdir(parents=True)
            (installed / "tools/validation").mkdir(parents=True)
            (harness / "tools/validation").mkdir(parents=True)
            (installed / "scripts/context_guard.py").write_text(
                "def session_dir_for(_): return '/unused'\n"
                "def load_state(*_): return {'product': 'installed'}\n"
            )
            (installed / "tools/validation/commentary_fixture.py").write_text(
                "def product_review_checkpoint(*_, **__): return {'wrong': True}\n"
            )
            helper = harness / "tools/validation/commentary_fixture.py"
            helper.write_text(
                "def product_review_checkpoint(_module, state, **kw): "
                "return {'state': state, 'coverage': kw['expected_coverage']}\n"
            )
            self.observer.runtime_root = installed
            self.observer.product_data_root = root / "home/plugins/data/context-guard-candidate"
            self.observer.plan.update({
                "harness_root": str(harness),
                "cold_helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
                "codex_home": str(root / "home"),
                "namespace": "candidate",
            })
            self.observer.thread = "thread"
            self.observer.question_id = "q"
            self.observer.main_ids = ["main"]
            self.assertEqual(self.observer.cold_reader("q", ["main"]),
                             {"state": {"product": "installed"}, "coverage": "complete"})
            self.observer.plan["review_coverage"] = "partial"
            self.assertEqual(self.observer.cold_reader("q", ["main"]),
                             {"state": {"product": "installed"}, "coverage": "partial"})
            helper.write_text("def product_review_checkpoint(*_, **__): return {}\n")
            with self.assertRaisesRegex(ValueError, "cold_product_read_failed"):
                self.observer.cold_reader("q", ["main"])

    def test_answer_source_requires_unique_completed_user_and_answer(self):
        self.observer._snapshot = lambda thread: {"events": [{"type": "trace"}],
                                                  "payloads": {"p": b"x"}}
        def pair(events, _payloads, *, client_id, commentary, **_kwargs):
            users = [e for e in events if e.get("params", {}).get("item", {}).get("clientId") == client_id]
            if len(users) != 1 or commentary.get("params", {}).get("item", {}).get("id") != "answer-1":
                raise ValueError("unbound")
            return {"pair": {"commentary_id": "answer-1"}}
        self.observer.trace = SimpleNamespace(reduce_pair=pair)
        with self.assertRaisesRegex(PendingEvidence, "question_user_event_pending"):
            self.observer.answer_source(
                "thread", "turn", "client-1", "question", [], [self.answer]
            )
        wrong = json.loads(json.dumps(self.user))
        wrong["params"]["item"]["clientId"] = "other-client"
        wrong["params"]["item"]["content"][0]["text_elements"] = []
        with self.assertRaisesRegex(ValueError, "wrong_client_question_event"):
            self.observer.answer_source(
                "thread", "turn", "client-1", "question", [wrong], [self.answer]
            )
        with self.assertRaisesRegex(PendingEvidence, "commentary_item_pending"):
            self.observer.answer_source(
                "thread", "turn", "client-1", "question", [self.user], []
            )
        result = self.observer.answer_source(
            "thread", "turn", "client-1", "question", [self.user], [self.answer]
        )
        self.assertEqual(result["events"], [self.user, {"type": "trace"}])
        for users, answers in [([], [self.answer]), ([self.user] * 2, [self.answer]),
                               ([self.user], []), ([self.user], [self.answer] * 2)]:
            with self.assertRaises(ValueError):
                self.observer.answer_source(
                    "thread", "turn", "client-1", "question", users, answers
                )

    def test_answer_waits_for_matching_inference_completion_then_binds(self):
        request = {"input": [{"type": "message", "role": "user",
                               "content": [{"type": "input_text", "text": "question"}]}]}
        response = {"response_id": "response-1", "output_items": [
            {"type": "message", "id": "answer-1", "role": "assistant",
             "phase": "commentary", "content": [{"type": "output_text", "text": "answer"}]},
        ]}
        def ref(number, kind):
            return {"raw_payload_id": f"raw_payload:{number}",
                    "kind": {"type": kind}, "path": f"payloads/{number}.json"}
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
        self.observer._snapshot = lambda _thread: source
        self.observer.trace = commentary_trace
        with self.assertRaisesRegex(PendingEvidence, "answer_inference_completion_pending"):
            self.observer.answer_source(
                "thread", "turn", "client-1", "question", [self.user], [self.answer]
            )
        source["events"][0]["codex_turn_id"] = "wrong-turn"
        with self.assertRaisesRegex(ValueError, "unique_source_bound_question_answer_required"):
            self.observer.answer_source(
                "thread", "turn", "client-1", "question", [self.user], [self.answer]
            )
        source["events"][0]["codex_turn_id"] = "turn"
        source["payloads"]["payloads/1.json"] = b"bad-json"
        with self.assertRaises(ValueError):
            self.observer.answer_source(
                "thread", "turn", "client-1", "question", [self.user], [self.answer]
            )
        source["payloads"]["payloads/1.json"] = json.dumps(request).encode()
        second = json.loads(json.dumps(started))
        second["payload"]["inference_call_id"] = "call-2"
        source["events"].append(second)
        with self.assertRaisesRegex(ValueError, "repeated_pending_question_inference"):
            self.observer.answer_source(
                "thread", "turn", "client-1", "question", [self.user], [self.answer]
            )
        source["events"].pop()
        source["events"].append(completed)
        result = self.observer.answer_source(
            "thread", "turn", "client-1", "question", [self.user], [self.answer]
        )
        self.assertEqual(result["notification"], self.answer)
        source["events"].append(second)
        with self.assertRaisesRegex(ValueError, "repeated_question_inference"):
            self.observer.answer_source(
                "thread", "turn", "client-1", "question", [self.user], [self.answer]
            )
        source["events"].pop()
        source["events"].reverse()
        self.assertEqual(self.observer.answer_source(
            "thread", "turn", "client-1", "question", [self.user],
            [self.answer])["notification"], self.answer)
        source["events"].reverse()
        repeated_done = json.loads(json.dumps(completed))
        repeated_done["payload"]["response_id"] = "conflicting-response"
        source["events"].append(repeated_done)
        with self.assertRaisesRegex(ValueError, "invalid_question_answer_source"):
            self.observer.answer_source(
                "thread", "turn", "client-1", "question", [self.user], [self.answer]
            )
        source["events"].pop()
        duplicate = json.loads(json.dumps(self.user))
        duplicate["params"]["item"].update(id="other", clientId="other-client")
        with self.assertRaisesRegex(ValueError, "ambiguous_same_text_user_source"):
            self.observer.answer_source(
                "thread", "turn", "client-1", "question", [self.user, duplicate],
                [self.answer],
            )

    def test_business_waits_for_completion_but_rejects_bad_payload(self):
        def ref(number, kind):
            return {"raw_payload_id": f"raw_payload:{number}",
                    "kind": {"type": kind}, "path": f"payloads/{number}.json"}
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
            "payloads/1.json": b'{"input":[]}',
            "payloads/2.json": b'{"response_id":"response-1","output_items":['
                               b'{"type":"function_call","call_id":"business-call"}]}',
        }}
        self.observer._snapshot = lambda _thread: source
        self.observer.trace = commentary_trace
        with self.assertRaisesRegex(PendingEvidence, "business_inference_completion_pending"):
            self.observer.business_source("thread", "turn", "business-call")
        source["events"][0]["codex_turn_id"] = "wrong-turn"
        with self.assertRaisesRegex(ValueError, "unique_business_inference_required"):
            self.observer.business_source("thread", "turn", "business-call")
        source["events"][0]["codex_turn_id"] = "turn"
        source["events"].append(completed)
        self.assertEqual(self.observer.business_source(
            "thread", "turn", "business-call")["inference_call_id"], "call-1")
        repeated_done = json.loads(json.dumps(completed))
        repeated_done["payload"]["response_id"] = "conflicting-response"
        source["events"].append(repeated_done)
        with self.assertRaisesRegex(ValueError, "invalid_completed_business_source"):
            self.observer.business_source("thread", "turn", "business-call")
        source["events"].pop()
        source["payloads"]["payloads/2.json"] = b"not-json"
        with self.assertRaisesRegex(ValueError, "invalid_completed_business_source"):
            self.observer.business_source("thread", "turn", "business-call")

    def test_business_source_requires_one_actual_inference_invocation(self):
        events = [
            {"thread_id": "thread", "codex_turn_id": "turn",
             "payload": {"type": "inference_completed", "inference_call_id": "a"}},
            {"thread_id": "thread", "codex_turn_id": "turn",
             "payload": {"type": "inference_completed", "inference_call_id": "b"}},
        ]
        self.observer._snapshot = lambda thread: {"events": events, "payloads": {"p": b"x"}}

        def pair(_events, _payloads, *, call_id, **_kwargs):
            call = "wanted" if call_id == "b" else "other"
            return {}, {"output_items": [{"type": "function_call", "call_id": call}]}, {}

        self.observer.trace = SimpleNamespace(attempt_pair=pair)
        result = self.observer.business_source("thread", "turn", "wanted")
        self.assertEqual(result["inference_call_id"], "b")
        events.append({"thread_id": "thread", "codex_turn_id": "turn",
                       "payload": {"type": "inference_completed", "inference_call_id": "c"}})
        self.observer.trace = SimpleNamespace(attempt_pair=lambda *a, **k:
                                              ({}, {"output_items": [{"type": "function_call",
                                                                      "call_id": "wanted"}]}, {}))
        with self.assertRaises(ValueError):
            self.observer.business_source("thread", "turn", "wanted")

    def test_review_refuses_absent_operator_policy_before_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.observer.plan["codex_home"] = str(directory.parent)
            question = {"id": "q", "text": "question", "status": "pending"}
            main = {"id": "m", "text": "main", "status": "pending"}
            state = {"requirements": [question, main]}
            self.observer._state = lambda thread: (directory, state)

            class Runtime:
                def answer_review_catalog(self, _directory, _state):
                    return [{"subject": {"turn_id": "turn", "question_id": "q"},
                             "question_text": "question"}]

                def answer_review_request(self, _directory, _state, _item, **_kwargs):
                    return {"subject": {"question_id": "q"}}

                def answer_review_module(self):
                    raise AssertionError("model must not run")

            self.observer.runtime = Runtime()
            with self.assertRaisesRegex(ValueError, "operator_review_policy_required"):
                self.observer.review_projection("thread", "turn")

    def test_policy_is_created_once_from_frozen_operator_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            data = home / "plugins/data/context-guard-candidate"
            self.observer.plan.update({"codex_home": str(home), "namespace": "candidate"})
            self.observer.product_data_root = data
            self.observer.runtime = SimpleNamespace(
                session_dir_for=lambda payload: root / "wrong-daily" / payload["session_id"]
            )
            policy = {"version": "review-1", "active": True,
                      "binary": "/codex", "binary_sha256": "a" * 64}
            self.observer.plan["review_policy"] = policy
            self.observer.configure_review_policy("thread")
            self.observer.configure_review_policy("thread")
            self.assertTrue((data / "sessions/thread/answer-reviews/policy.json").is_file())
            self.assertFalse((root / "wrong-daily").exists())
            for identity in (".", "..", "../escape"):
                with self.subTest(identity=identity), self.assertRaisesRegex(
                    ValueError, "unsafe_product_session_identity"
                ):
                    self.observer.configure_review_policy(identity)
            self.observer.plan["review_policy"] = {**policy, "version": "review-2"}
            with self.assertRaisesRegex(ValueError, "review_policy_already_differs"):
                self.observer.configure_review_policy("thread")

    def test_product_state_uses_isolated_plugin_data_and_rejects_unsafe_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            data = home / "plugins/data/context-guard-candidate"
            self.observer.plan.update({"codex_home": str(home), "namespace": "candidate"})
            self.observer.product_data_root = data
            directory = data / "sessions/thread"
            directory.mkdir(parents=True)
            (directory / "state.json").write_text("{}")
            self.observer.runtime = SimpleNamespace(
                session_dir_for=lambda _payload: root / "wrong-daily",
                load_state=lambda path, payload: {"path": str(path), "thread": payload["session_id"]},
            )
            actual, state = self.observer._state("thread")
            self.assertEqual(actual, directory)
            self.assertEqual(state, {"path": str(directory), "thread": "thread"})
            self.assertFalse((root / "wrong-daily").exists())
            for identity in (".", "..", "../escape"):
                with self.subTest(identity=identity), self.assertRaisesRegex(
                    ValueError, "unsafe_product_session_identity"
                ):
                    self.observer._state(identity)

    def test_product_state_rejects_linked_paths_when_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            data = home / "plugins/data/context-guard-candidate"
            self.observer.plan.update({"codex_home": str(home), "namespace": "candidate"})
            self.observer.product_data_root = data
            directory = data / "sessions/thread"
            directory.mkdir(parents=True)
            state_file = directory / "state.json"
            try:
                state_file.symlink_to(root / "missing")
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows host cannot create symlinks")
                raise
            with self.assertRaisesRegex(ValueError, "product_state_unavailable"):
                self.observer._state("thread")
            state_file.unlink()
            directory.rmdir()
            (data / "sessions").rmdir()
            try:
                (data / "sessions").symlink_to(root, target_is_directory=True)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows host cannot create directory symlinks")
                raise
            with self.assertRaisesRegex(ValueError, "linked_product_data_path"):
                self.observer._state("thread")

    def test_cold_reader_uses_same_session_identity_gate(self):
        self.observer.plan.update({"codex_home": "/tmp/cg-home",
                                   "namespace": "candidate"})
        self.observer.product_data_root = Path(
            "/tmp/cg-home/plugins/data/context-guard-candidate"
        )
        self.observer.question_id = "q"
        self.observer.main_ids = ["main"]
        for identity in (".", "..", "../escape"):
            self.observer.thread = identity
            with self.subTest(identity=identity), self.assertRaisesRegex(
                ValueError, "unsafe_product_session_identity"
            ):
                self.observer.cold_reader("q", ["main"])

    def test_compaction_waits_for_late_session_start_and_ignores_startup_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.observer.capture_dir = Path(temporary) / "captures"
            self.observer.runtime_root = Path(__file__).resolve().parents[1]
            self.observer.trace = SimpleNamespace(
                decode=commentary_trace.decode,
                attempt_pair=lambda *args, **kwargs: ({}, {}, {"compaction_id": "compact-item"}),
            )
            self.observer._snapshot = lambda thread: {
                "events": [{"thread_id": "thread", "codex_turn_id": "turn",
                            "payload": {"type": "compaction_request_completed",
                                        "compaction_request_id": "request-1"}}],
                "payloads": {"p": b"x"},
            }

            def capture(event, **fields):
                raw = json.dumps({"hook_event_name": event, "session_id": "thread",
                                  "cwd": "/fixture", **fields}).encode()
                meta = record_payload(raw, total_bytes=len(raw), truncated=False,
                                      expected_event=event, capture_dir=self.observer.capture_dir,
                                      runtime_root=self.observer.runtime_root, echo=True)
                info = json.loads(meta.read_bytes())
                return raw, info["capture_id"]

            def notification(event, raw, capture_id, identity):
                return {"method": "hook/completed", "params": {
                    "threadId": "thread", "turnId": "turn", "run": {
                        "id": identity, "eventName": event[0].lower() + event[1:],
                        "status": "completed", "handlerType": "command",
                        "executionMode": "sync",
                        "sourcePath": "/<session-flags>/config.toml",
                        "entries": [{"kind": "warning", "text": digest_echo(raw, capture_id)}],
                    },
                }}

            startup = capture("SessionStart", source="startup")
            pre = capture("PreCompact", trigger="auto", turn_id="turn")
            hooks = [notification("SessionStart", *startup, "startup-run"),
                     notification("PreCompact", *pre, "pre-run")]
            completed = {"params": {"item": {"id": "compact-item"}}}
            with self.assertRaises(PendingEvidence):
                self.observer.compaction_source("thread", "turn", hooks, completed)
            post = capture("SessionStart", source="compact")
            with self.assertRaises(PendingEvidence):
                self.observer.compaction_source("thread", "turn", hooks, completed)
            hooks.append(notification("SessionStart", *post, "post-run"))
            captures, source = self.observer.compaction_source(
                "thread", "turn", hooks, completed
            )
            self.assertEqual(len(captures), 2)
            self.assertEqual(source["request_id"], "request-1")
            capture("PreCompact", trigger="auto", turn_id="turn")
            with self.assertRaisesRegex(ValueError, "repeated_auto_compaction_capture"):
                self.observer.compaction_source("thread", "turn", hooks, completed)

    def test_compaction_observer_waits_for_capture_metadata_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.observer.capture_dir = Path(temporary) / "captures"
            self.observer.runtime_root = Path(__file__).resolve().parents[1]
            self.observer.trace = SimpleNamespace(
                decode=commentary_trace.decode,
                attempt_pair=lambda *args, **kwargs: ({}, {}, {"compaction_id": "compact-item"}),
            )
            self.observer._snapshot = lambda _thread: {
                "events": [{"thread_id": "thread", "codex_turn_id": "turn",
                            "payload": {"type": "compaction_request_completed",
                                        "compaction_request_id": "request-1"}}],
                "payloads": {},
            }

            def capture(event, **fields):
                raw = json.dumps({"hook_event_name": event, "session_id": "thread",
                                  "cwd": "/fixture", **fields}).encode()
                meta = record_payload(raw, total_bytes=len(raw), truncated=False,
                                      expected_event=event, capture_dir=self.observer.capture_dir,
                                      runtime_root=self.observer.runtime_root, echo=True)
                return raw, json.loads(meta.read_bytes())["capture_id"]

            def notification(event, raw, capture_id):
                return {"method": "hook/completed", "params": {
                    "threadId": "thread", "turnId": "turn", "run": {
                        "id": event, "eventName": event[0].lower() + event[1:],
                        "status": "completed", "handlerType": "command",
                        "executionMode": "sync",
                        "sourcePath": "/<session-flags>/config.toml",
                        "entries": [{"kind": "warning", "text": digest_echo(raw, capture_id)}],
                    },
                }}

            pre = capture("PreCompact", trigger="auto", turn_id="turn")
            startup = capture("SessionStart", source="startup")
            hooks = [notification("SessionStart", *startup),
                     notification("PreCompact", *pre)]
            completed = {"params": {"item": {"id": "compact-item"}}}
            raw_created = threading.Event()
            allow_meta = threading.Event()
            result = []
            original_replace = os.replace

            def pause_before_publish(source, target):
                raw_created.set()
                if not allow_meta.wait(5):
                    raise TimeoutError("test_metadata_publication_deadline")
                return original_replace(source, target)

            def write_post():
                try:
                    result.append(capture("SessionStart", source="compact"))
                except Exception as exc:  # make worker failure visible to the test
                    result.append(exc)

            with mock.patch("tools.validation.host_capture.os.replace",
                            side_effect=pause_before_publish):
                writer = threading.Thread(target=write_post)
                writer.start()
                try:
                    self.assertTrue(raw_created.wait(5))
                    with self.assertRaisesRegex(
                        PendingEvidence, "matching_hook_notification_pending"
                    ):
                        self.observer.compaction_source("thread", "turn", hooks, completed)
                finally:
                    allow_meta.set()
                    writer.join(5)
            self.assertFalse(writer.is_alive())
            self.assertEqual(len(result), 1)
            if isinstance(result[0], Exception):
                raise result[0]
            self.assertEqual(inspect_directory(
                self.observer.capture_dir, self.observer.runtime_root
            )["capture_count"], 3)
            hooks.append(notification("SessionStart", *result[0]))
            captures, source = self.observer.compaction_source(
                "thread", "turn", hooks, completed
            )
            self.assertEqual(len(captures), 2)
            self.assertEqual(source["request_id"], "request-1")
            malformed_hooks = json.loads(json.dumps(hooks))
            malformed_hooks[-1]["params"]["run"]["entries"] = ["not-an-entry"]
            with self.assertRaisesRegex(ValueError, "invalid_capture_hook_completion"):
                self.observer.compaction_source(
                    "thread", "turn", malformed_hooks, completed
                )

            # A different thread may publish raw bytes at the same instant;
            # the current thread cannot pass until strict global inspection.
            raw_created = threading.Event()
            allow_meta = threading.Event()
            foreign = []

            def write_foreign():
                try:
                    foreign.append(capture("SessionStart", source="startup",
                                           session_id="other-thread"))
                except Exception as exc:
                    foreign.append(exc)

            with mock.patch("tools.validation.host_capture.os.replace",
                            side_effect=pause_before_publish):
                writer = threading.Thread(target=write_foreign)
                writer.start()
                try:
                    self.assertTrue(raw_created.wait(5))
                    with self.assertRaisesRegex(CaptureError, "orphan raw or metadata"):
                        self.observer.compaction_source("thread", "turn", hooks, completed)
                finally:
                    allow_meta.set()
                    writer.join(5)
            self.assertFalse(writer.is_alive())
            if isinstance(foreign[0], Exception):
                raise foreign[0]
            self.assertEqual(len(self.observer.compaction_source(
                "thread", "turn", hooks, completed
            )[0]), 2)

            orphan = self.observer.capture_dir / "capture-000005.raw"
            orphan.write_bytes(b"permanent orphan")
            with self.assertRaisesRegex(CaptureError, "orphan raw or metadata"):
                self.observer.compaction_source("thread", "turn", hooks, completed)
            orphan.unlink()
            outside = Path(temporary) / "outside.json"
            outside.write_text('{"harmless": true}')
            extra_meta = self.observer.capture_dir / "capture-000005.meta.json"
            original_read = Path.read_bytes

            def no_outside_read(path):
                if path.resolve() == outside.resolve():
                    raise AssertionError("outside capture file was read")
                return original_read(path)

            for raw_file in (str(outside), "../outside.json"):
                with self.subTest(raw_file=raw_file):
                    malformed = json.loads((self.observer.capture_dir /
                                            "capture-000001.meta.json").read_bytes())
                    malformed.update(sequence=5, raw_file=raw_file)
                    extra_meta.write_text(json.dumps(malformed))
                    try:
                        with mock.patch.object(Path, "read_bytes", no_outside_read):
                            with self.assertRaises(CaptureError):
                                self.observer.compaction_source(
                                    "thread", "turn", hooks, completed
                                )
                    finally:
                        extra_meta.unlink()
            metadata = self.observer.capture_dir / "capture-000001.meta.json"
            bad = json.loads(metadata.read_bytes())
            bad["raw_sha256"] = "0" * 64
            metadata.write_text(json.dumps(bad))
            with self.assertRaisesRegex(CaptureError, "hash or length mismatch"):
                self.observer.compaction_source("thread", "turn", hooks, completed)


if __name__ == "__main__":
    unittest.main()
