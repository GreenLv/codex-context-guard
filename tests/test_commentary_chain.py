"""Synthetic end-to-end integration; real product receipt consumer, no models."""

import copy
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests import commentary_binding_fixture
from tests import test_answer_review as review_tests
from tools.validation import commentary_fixture as fixture
from tools.validation import commentary_live_adapter as live_wire
from tools.validation import commentary_trace as shared_trace
from tools.validation.commentary_chain import Chain
from tools.validation.commentary_live_observer import NativeObserver


class ChainTests(unittest.TestCase):
    def setUp(self):
        product_type = type('BoundConsumer', (review_tests.ConsumerTests,), {
            'prepare_commentary_source': commentary_binding_fixture.prepare_with_progress})
        self.product = product_type()
        dispatch = review_tests.cg.dispatch

        def main_before_question(event):
            if event.get("prompt") == "Context Guard 是这个插件的名称吗？":
                dispatch(
                    {
                        **event,
                        "prompt": "请运行 /work/suite.py 的测试并持续执行直到完成。",
                    }
                )
            return dispatch(event)

        with mock.patch.object(
            review_tests.cg, "dispatch", side_effect=main_before_question
        ):
            self.product.setUp()
        self.addCleanup(self.product.doCleanups)
        self.host = self.product.host
        self.thread, self.turn = self.host.session_id, self.host.turn_id
        self.main = next(
            item["id"]
            for item in self.host.state()["requirements"]
            if item["text"].startswith("请运行")
        )
        self.question_id = self.product.item["id"]
        self.question = "Context Guard 是这个插件的名称吗？"
        self.answer = self.product.request["answer_texts"]["m1"]
        self.root = self.host.root
        self.scope = dict(threadId=self.thread, turnId=self.turn)
        config = {
            "model_auto_compact_token_limit": 4096,
            "model_auto_compact_token_limit_scope": "body_after_prefix",
        }
        self.chain = Chain(
            thread=self.thread,
            turn=self.turn,
            cwd="/fixture",
            hook_source="/fixture/hooks.json",
            frozen_config=config,
            threshold=dict(
                limit=4096, fallback_buffer=0, before_business=1024, after_business=5000
            ),
        )
        self.config_request = {
            "id": 1,
            "method": "config/read",
            "params": {"cwd": "/fixture"},
        }
        self.config_response = {"id": 1, "result": {"config": config, "origins": {}}}
        self.thread_start = {
            "id": 2,
            "method": "thread/start",
            "params": {"cwd": "/fixture"},
        }

    def test_native_config_keeps_unmeasured_threshold_as_proposal(self):
        self.chain.threshold = {"limit": 4096, "scope": "body_after_prefix",
                                "status": "bounded_proposal_not_token_calibrated"}
        self.chain.configuration(self.config_request, self.config_response,
                                 self.thread_start)
        self.assertEqual(self.chain.evidence["threshold"], {
            "limit": 4096, "scope": "body_after_prefix",
            "threshold_calibrated": False, "source": "effective_config_only",
        })
        self.assertNotIn("before_business", self.chain.evidence["threshold"])

    def attempt(self, kind, request, response, identity="attempt"):
        key = "inference_call_id" if kind == "inference" else "compaction_request_id"
        types = (
            ("inference_started", "inference_completed")
            if kind == "inference"
            else ("compaction_request_started", "compaction_request_completed")
        )

        def ref(n, suffix):
            return {
                "raw_payload_id": f"raw_payload:{n}",
                "kind": {"type": kind + suffix},
                "path": f"payloads/{n}.json",
            }

        a = {
            "type": types[0],
            key: identity,
            "thread_id": self.thread,
            "codex_turn_id": self.turn,
            "request_payload": ref(1, "_request"),
        }
        b = {"type": types[1], key: identity, "response_payload": ref(2, "_response")}
        if kind == "inference":
            b["response_id"] = response["response_id"]
        else:
            a["compaction_id"] = b["compaction_id"] = "compact1"
        events = [
            {
                "schema_version": 1,
                "seq": n,
                "rollout_id": "fixture-rollout",
                "thread_id": self.thread,
                "codex_turn_id": self.turn,
                "payload": p,
            }
            for n, p in enumerate((a, b), 1)
        ]
        payloads = {
            "payloads/1.json": json.dumps(request).encode(),
            "payloads/2.json": json.dumps(response).encode(),
        }
        return events, payloads

    def ready_business(self):
        self.chain.configuration(
            self.config_request, self.config_response, self.thread_start
        )
        source_events, payloads, notification = self.answer_source()
        self.chain.commentary(
            source_events, payloads, client_id="client1",
            question=self.question, notification=notification,
        )
        challenge = self.chain.challenge(self.root / "challenge.json")
        self.values = [2, -3, 5]
        self.output, _ = fixture.business_result(self.values, challenge)
        fixture.exclusive(self.root / "business.json", self.output)
        self.invocation = {
            "type": "function_call",
            "call_id": "business-call",
            "name": "fixture_business",
            "arguments": "{}",
        }
        request = {
            "input": [
                {
                    "type": "function_call_output",
                    "call_id": "barrier-read",
                    "output": fixture.canonical(challenge).decode(),
                }
            ]
        }
        response = {
            "response_id": "business-response",
            "output_items": [self.invocation],
        }
        self.business_events, self.business_payloads = self.attempt(
            "inference", request, response, "business-sampling"
        )

    def answer_source(self):
        user = {
            "method": "item/completed",
            "params": {
                **self.scope,
                "item": {
                    "type": "userMessage",
                    "id": "user1",
                    "clientId": "client1",
                    "content": [{"type": "text", "text": self.question}],
                },
            },
        }
        notification = {
            "method": "item/completed",
            "params": {
                **self.scope,
                "item": {
                    "type": "agentMessage",
                    "id": "m1",
                    "phase": "commentary",
                    "text": self.answer,
                },
            },
        }
        request = {
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": self.question}],
                }
            ]
        }
        response = {
            "response_id": "answer-response",
            "output_items": [
                {
                    "type": "message",
                    "role": "assistant",
                    "id": "m1",
                    "phase": "commentary",
                    "content": [{"type": "output_text", "text": self.answer}],
                }
            ],
        }
        events, payloads = self.attempt("inference", request, response)
        return [user, *events], payloads, notification

    def observe_business(self):
        self.chain.business(
            self.values,
            self.root / "business.json",
            events=self.business_events,
            payloads=self.business_payloads,
            inference_call_id="business-sampling",
            call_id="business-call",
        )

    def review_and_release(self):
        self.product.collect()
        self.chain.release_after_review(
            review_tests.cg,
            self.host.state(),
            session_dir=self.product.directory,
            codex_home=self.host.home,
            question_id=self.question_id,
            main_ids=[self.main],
            barrier_path=self.root / "release.json",
        )

    def compaction_inputs(self):
        captures = []
        for event, extra, run, capture_id in (
            ("PreCompact", {"trigger": "auto", "turn_id": self.turn}, "pre", "a" * 32),
            ("SessionStart", {"source": "compact"}, "post", "b" * 32),
        ):
            raw = json.dumps(
                {"session_id": self.thread, "hook_event_name": event, **extra}
            ).encode()
            notification = {
                "method": "hook/completed",
                "params": {
                    **self.scope,
                    "run": {
                        "id": run,
                        "eventName": event[0].lower() + event[1:],
                        "status": "completed",
                        "handlerType": "command",
                        "executionMode": "sync",
                        "sourcePath": "/fixture/hooks.json",
                        "entries": [
                            {"kind": "warning", "text": fixture.marker(raw, capture_id)}
                        ],
                    },
                },
            }
            captures.append(
                {"raw": raw, "capture_id": capture_id, "notification": notification}
            )
        request = {
            "input": [
                self.invocation,
                {
                    "type": "function_call_output",
                    "call_id": "business-call",
                    "output": fixture.canonical(self.output).decode(),
                },
            ]
        }
        events, payloads = self.attempt(
            "compaction", request, {"output": []}, "compact-request"
        )
        completed = {
            "method": "item/completed",
            "params": {
                **self.scope,
                "item": {"id": "compact1", "type": "contextCompaction"},
            },
        }
        return captures, dict(
            events=events,
            payloads=payloads,
            request_id="compact-request",
            completed_item=completed,
        )

    def test_full_offline_chain_real_product_barrier_and_cold_process(self):
        self.ready_business()
        self.observe_business()
        self.assertFalse((self.root / "release.json").exists())
        self.review_and_release()
        self.assertTrue((self.root / "release.json").is_file())
        captures, inputs = self.compaction_inputs()
        self.chain.compaction(captures, **inputs)
        for event, extra in [
            ("PreCompact", {}),
            ("SessionStart", {"source": "compact"}),
        ]:
            review_tests.cg.dispatch(self.host.event(event, **extra))

        def cold(question, main):
            program = """
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / 'scripts'))
import context_guard as cg
from tools.validation.commentary_fixture import product_review_checkpoint
x=json.load(sys.stdin)
s=cg.load_state(Path(x['directory']), x['event'])
print(json.dumps(product_review_checkpoint(cg,s,session_dir=Path(x['directory']),
    codex_home=Path(x['home']),
    question_id=x['question'],main_ids=x['main'])))
"""
            result = subprocess.run(
                [sys.executable, "-c", program],
                input=json.dumps(
                    {
                        "directory": str(self.product.directory),
                        "home": str(self.host.home),
                        "event": self.host.event("Stop"),
                        "question": question,
                        "main": main,
                    }
                ),
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env={**os.environ,
                     "CODEX_HOME": str(self.root / "foreign-home"),
                     "CONTEXT_GUARD_DATA_DIR": str(self.root / "foreign-data")},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

        result = self.chain.cold_recovery(cold)
        self.assertEqual(result["phase"], "offline_chain_checked")
        self.assertEqual(result["native_acceptance"], "not_established")

    def test_review_release_uses_explicit_product_session_directory(self):
        self.ready_business()
        self.observe_business()
        self.product.collect()
        foreign = self.root / "foreign" / self.thread
        foreign.mkdir(parents=True)
        with mock.patch.object(review_tests.cg, "session_dir_for", return_value=self.product.directory):
            with self.assertRaisesRegex(ValueError, "missing_question_source"):
                self.chain.release_after_review(
                    review_tests.cg, self.host.state(), session_dir=foreign,
                    codex_home=self.host.home,
                    question_id=self.question_id, main_ids=[self.main],
                    barrier_path=self.root / "release.json",
                )
        self.assertFalse((self.root / "release.json").exists())
        with self.assertRaisesRegex(ValueError, "message_source_unknown"):
            self.chain.release_after_review(
                review_tests.cg, self.host.state(), session_dir=self.product.directory,
                codex_home=self.root / "foreign-home",
                question_id=self.question_id, main_ids=[self.main],
                barrier_path=self.root / "release.json",
            )
        self.assertFalse((self.root / "release.json").exists())
        with mock.patch.dict(os.environ, {
            "CODEX_HOME": str(self.root / "foreign-home"),
            "CONTEXT_GUARD_DATA_DIR": str(self.root / "foreign-data"),
        }), mock.patch.object(review_tests.cg, "session_dir_for", return_value=foreign):
            self.chain.release_after_review(
                review_tests.cg, self.host.state(), session_dir=self.product.directory,
                codex_home=self.host.home,
                question_id=self.question_id, main_ids=[self.main],
                barrier_path=self.root / "release.json",
            )
        self.assertTrue((self.root / "release.json").is_file())

    def test_request_echo_and_thread_override_are_not_effective_readback(self):
        for response, start in (
            (self.config_request, self.thread_start),
            (
                self.config_response,
                {
                    **self.thread_start,
                    "params": {
                        "cwd": "/fixture",
                        "config": {"model_auto_compact_token_limit": 1},
                    },
                },
            ),
        ):
            with self.assertRaises(fixture.Unknown):
                self.chain.configuration(self.config_request, response, start)

    def test_missing_nodes_and_no_review_cannot_release(self):
        with self.assertRaises(fixture.Unknown):
            self.chain.challenge(self.root / "early.json")
        self.ready_business()
        self.observe_business()
        with self.assertRaises(ValueError):
            self.chain.release_after_review(
                review_tests.cg,
                self.host.state(),
                session_dir=self.product.directory,
                codex_home=self.host.home,
                question_id=self.question_id,
                main_ids=[self.main],
                barrier_path=self.root / "release.json",
            )
        self.assertFalse((self.root / "release.json").exists())

    def test_wrong_business_call_and_tampered_report(self):
        self.ready_business()
        self.business_events[1]["payload"]["inference_call_id"] = "foreign"
        with self.assertRaises(ValueError):
            self.observe_business()
        self.business_events[1]["payload"]["inference_call_id"] = "business-sampling"
        self.output["validation_report"] = "claimed success"
        (self.root / "business.json").write_bytes(fixture.canonical(self.output))
        with self.assertRaises(fixture.Unknown):
            self.observe_business()

    def test_business_challenge_requires_exact_tool_call_id(self):
        self.ready_business()
        with self.assertRaisesRegex(fixture.Unknown, "business_request_lacks_fresh_challenge"):
            self.chain.business(
                self.values, self.root / "business.json",
                events=self.business_events, payloads=self.business_payloads,
                inference_call_id="business-sampling", call_id="business-call",
                challenge_call_id="different-call",
            )
        self.chain.business(
            self.values, self.root / "business.json",
            events=self.business_events, payloads=self.business_payloads,
            inference_call_id="business-sampling", call_id="business-call",
            challenge_call_id="barrier-read",
        )

    def test_dynamic_tool_barriers_consume_source_and_real_review_projection(self):
        self.chain.configuration(
            self.config_request, self.config_response, self.thread_start
        )
        directory = self.root / "live-barrier"
        directory.mkdir()
        barrier = live_wire.LiveBarrier(
            self.chain, thread=self.thread, turn=self.turn,
            directory=directory, values=[2, -3, 5],
        )

        def call(identity, name, arguments):
            return {"id": identity, "method": "item/tool/call", "params": {
                "threadId": self.thread, "turnId": self.turn,
                "namespace": live_wire.TOOL_NAMESPACE, "tool": name,
                "callId": name + "-call", "arguments": arguments,
            }}

        barrier.receive(call(10, live_wire.READY, {}))
        barrier.release_ready(
            {"id": 20, "method": "turn/steer", "params": {
                "threadId": self.thread, "expectedTurnId": self.turn,
            }},
            {"id": 20, "result": {"turnId": self.turn}},
        )
        barrier.receive(call(11, live_wire.CHALLENGE, {}))
        events, payloads, notification = self.answer_source()
        challenge = barrier.release_challenge(
            events=events, payloads=payloads, client_id="client1",
            question=self.question, notification=notification,
        )
        nonce = self.chain.business_challenge["nonce"]
        self.assertIn(nonce, challenge["result"]["contentItems"][0]["text"])
        barrier.receive(call(12, live_wire.BUSINESS, {"nonce": nonce}))
        sampled = {"input": [{
            "type": "function_call_output", "call_id": "challenge-call",
            "output": [{"type": "input_text", "text":
                        fixture.canonical(self.chain.business_challenge).decode()}],
        }]}
        invoked = {"response_id": "business-dynamic-response", "output_items": [{
            "type": "function_call", "call_id": "business-call",
            "name": live_wire.TOOL_NAMESPACE + ".business", "arguments": "{}",
        }]}
        business_events, business_payloads = self.attempt(
            "inference", sampled, invoked, "business-sampling"
        )
        barrier.observe_business(
            events=business_events, payloads=business_payloads,
            inference_call_id="business-sampling",
        )
        with self.assertRaises(ValueError):
            barrier.release_after_review(
                review_tests.cg, self.host.state(), question_id=self.question_id,
                main_ids=[self.main], session_dir=self.product.directory,
                codex_home=self.host.home,
            )
        self.product.collect()
        result = barrier.release_after_review(
            review_tests.cg, self.host.state(), question_id=self.question_id,
            main_ids=[self.main], session_dir=self.product.directory,
            codex_home=self.host.home,
        )
        self.assertEqual(result["id"], 12)
        self.assertTrue((directory / "review-barrier.json").is_file())

    def test_observer_selects_bound_answer_among_early_progress(self):
        self.chain.configuration(
            self.config_request, self.config_response, self.thread_start
        )
        events, payloads, notification = self.answer_source()
        question_user = copy.deepcopy(events[0])
        question_user["params"]["item"]["content"][0]["text_elements"] = []
        root_user = copy.deepcopy(events[0])
        root_user["params"]["item"].update(
            id="root-user", clientId="root-client",
            content=[{"type": "text", "text": "main task"}],
        )
        early_progress = copy.deepcopy(notification)
        early_progress["params"]["item"].update(
            id="early-progress", text="The main task is ready."
        )
        observer = NativeObserver.__new__(NativeObserver)
        observer._snapshot = lambda thread: {"events": events[1:], "payloads": payloads}
        observer.trace = shared_trace
        result = observer.answer_source(
            self.thread, self.turn, "client1", self.question,
            [root_user, question_user], [early_progress, notification],
        )
        self.assertEqual(result["notification"], notification)
        self.chain.commentary(**result)
        duplicate = copy.deepcopy(question_user)
        duplicate["params"]["item"].update(id="repeated-user", clientId="another")
        with self.assertRaisesRegex(ValueError, "ambiguous_same_text_user_source"):
            observer.answer_source(
                self.thread, self.turn, "client1", self.question,
                [root_user, question_user, duplicate], [early_progress, notification],
            )

    def test_fake_hook_and_install_before_trace_do_not_finish(self):
        self.ready_business()
        self.observe_business()
        self.review_and_release()
        captures, inputs = self.compaction_inputs()
        with self.assertRaises(fixture.Unknown):
            self.chain.compaction(
                [{"event": "PreCompact"}, {"event": "SessionStart"}], **inputs
            )
        altered = copy.deepcopy(inputs)
        altered["completed_item"] = {
            "type": "compaction_installed",
            "compaction_id": "compact1",
        }
        with self.assertRaises(fixture.Unknown):
            self.chain.compaction(captures, **altered)
        # Identical business content from a different call is still unrelated.
        changed = json.loads(inputs["payloads"]["payloads/1.json"])
        changed["input"][-1]["call_id"] = "unrelated-call"
        inputs["payloads"]["payloads/1.json"] = json.dumps(changed).encode()
        with self.assertRaises(fixture.Unknown):
            self.chain.compaction(captures, **inputs)
