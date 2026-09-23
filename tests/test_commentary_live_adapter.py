"""Official dynamic-tool wire contract; no producer or reviewer is started."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.validation import commentary_live_adapter as wire


def request(tool=wire.READY, *, call_id="call-1", **changes):
    params = {
        "threadId": "thread-1", "turnId": "turn-1", "callId": call_id,
        "namespace": wire.TOOL_NAMESPACE, "tool": tool,
        "arguments": {"nonce": "fresh"} if tool == wire.BUSINESS else {},
    }
    params.update(changes)
    return {"id": 5, "method": "item/tool/call", "params": params}


class DynamicToolWireTest(unittest.TestCase):
    def test_three_bounded_tools_and_exact_challenge_output(self):
        specs = wire.specs()
        self.assertEqual([t["name"] for t in specs[0]["tools"]],
                         [wire.READY, wire.CHALLENGE, wire.BUSINESS])
        call = wire.parse_call(request(wire.CHALLENGE), thread="thread-1", turn="turn-1")
        result = wire.response(call, {"nonce": "fresh"})
        self.assertEqual(result["id"], 5)
        self.assertEqual(result["result"]["contentItems"],
                         [{"type": "inputText", "text": '{"nonce":"fresh"}'}])
        for output in ('{"nonce":"fresh"}',
                       [{"type": "input_text", "text": '{"nonce":"fresh"}'}]):
            self.assertEqual(wire.source_output({"type": "function_call_output",
                                                 "call_id": "call-1", "output": output},
                                                call_id="call-1"), '{"nonce":"fresh"}')

    def test_foreign_and_malformed_calls_fail_closed(self):
        for value in [
            request(threadId="other"), request(turnId="other"),
            request(namespace="other"), request(tool="unknown"),
            request(call_id=""), request(arguments={"arbitrary": True}),
            request(wire.BUSINESS, arguments={"nonce": "fresh", "extra": 1}),
            request(wire.BUSINESS, arguments={"nonce": ""}),
            request(arguments={"huge": "a" * wire.MAX_ARGUMENT_BYTES}),
            {"id": 5, "method": "item/tool/call", "params": {}},
        ]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    wire.parse_call(value, thread="thread-1", turn="turn-1")

    def test_source_output_requires_exact_call_and_shape(self):
        for item in [
            {"type": "function_call_output", "call_id": "old", "output": "x"},
            {"type": "function_call_output", "call_id": "call-1", "output": [
                {"type": "input_text", "text": "x"},
                {"type": "input_text", "text": "y"},
            ]},
            {"type": "function_call_output", "call_id": "call-1", "output": [
                {"type": "input_image", "image_url": "x"},
            ]},
            {"type": "function_call", "call_id": "call-1", "output": "x"},
        ]:
            with self.subTest(item=item):
                with self.assertRaises(ValueError):
                    wire.source_output(item, call_id="call-1")

    def test_barrier_holds_each_result_until_its_evidence(self):
        class StubChain:
            phase = "configured"
            scope = {"thread": "thread-1", "turn": "turn-1", "source_path": "/hooks.json"}
            business_challenge = None
            business_output = None

            def commentary(self, events, payloads, **kwargs):
                if events != ["source_pair"]:
                    raise ValueError("unbound_answer")
                self.phase = "answered_observed"

            def challenge(self, path):
                assert self.phase == "answered_observed"
                self.business_challenge = {
                    "schema": "cg-business-challenge/v1",
                    "nonce": "f" * 64,
                    "commentary_pair_sha256": "a" * 64,
                }
                return self.business_challenge

            def business(self, values, output_path, **kwargs):
                if kwargs["challenge_call_id"] != "challenge-call":
                    raise ValueError("unbound_challenge")
                self.business_output = {"nonce": "f" * 64, "rows": len(values)}
                self.phase = "business_observed"

            def release_after_review(self, runtime, state, **kwargs):
                if state != {"reviewed": True}:
                    raise ValueError("unreviewed")
                self.phase = "review_consumed"

        with TemporaryDirectory() as directory:
            chain = StubChain()
            barrier = wire.LiveBarrier(chain, thread="thread-1", turn="turn-1",
                                       directory=Path(directory), values=[2, 3])
            barrier.receive(request(wire.READY, call_id="ready-call"))
            with self.assertRaises(ValueError):
                barrier.release_ready({"method": "turn/steer", "id": 9,
                                       "params": {"threadId": "thread-1",
                                                  "expectedTurnId": "turn-1"}},
                                      {"id": 9, "result": {"turnId": "other"}})
            self.assertEqual(barrier.release_ready(
                {"method": "turn/steer", "id": 9,
                 "params": {"threadId": "thread-1", "expectedTurnId": "turn-1"}},
                {"id": 9, "result": {"turnId": "turn-1"}})["id"], 5)
            with self.assertRaises(ValueError):
                barrier.receive(request(wire.READY, call_id="repeat"))
            challenge_call = request(wire.CHALLENGE, call_id="challenge-call")
            challenge_call["id"] = 6
            barrier.receive(challenge_call)
            with self.assertRaises(ValueError):
                barrier.release_challenge(events=[], payloads={}, client_id="c",
                                          question="q", notification={})
            challenge = barrier.release_challenge(
                events=["source_pair"], payloads={}, client_id="c", question="q",
                notification={})
            self.assertEqual(challenge["result"]["contentItems"][0]["text"],
                             wire.response(
                                 wire.parse_call(challenge_call, thread="thread-1", turn="turn-1"),
                                 chain.business_challenge,
                             )["result"]["contentItems"][0]["text"])
            with self.assertRaises(ValueError):
                barrier.receive(request(wire.BUSINESS, call_id="business-call",
                                        arguments={"nonce": "old"}))
            business_call = request(wire.BUSINESS, call_id="business-call",
                                    arguments={"nonce": "f" * 64})
            business_call["id"] = 7
            barrier.receive(business_call)
            with self.assertRaises(ValueError):
                barrier.release_after_review(None, {}, session_dir=Path("/session"),
                                             codex_home=Path("/home"),
                                             question_id="q", main_ids=["m"])
            barrier.observe_business(events=[], payloads={}, inference_call_id="inference")
            with self.assertRaises(ValueError):
                barrier.release_after_review(None, {}, session_dir=Path("/session"),
                                             codex_home=Path("/home"),
                                             question_id="q", main_ids=["m"])
            result = barrier.release_after_review(
                None, {"reviewed": True}, session_dir=Path("/session"),
                codex_home=Path("/home"),
                question_id="q", main_ids=["m"])
            self.assertEqual(result["id"], 7)
            self.assertEqual(barrier.phase, "business_released")


if __name__ == "__main__":
    unittest.main()
