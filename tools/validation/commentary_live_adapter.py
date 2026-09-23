"""Fail-closed app-server dynamic-tool wire adapter for commentary acceptance.

This module has no transport and never starts a model. The controller must bind
each call to an owned thread/turn, retain the exact call id, and supply source
proof before releasing a challenge or business result. A JSON-RPC receipt alone
is not that proof.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

TOOL_NAMESPACE = "cg_commentary_acceptance"
READY = "ready"
CHALLENGE = "challenge"
BUSINESS = "business"
MAX_ARGUMENT_BYTES = 16 * 1024
MAX_OUTPUT_BYTES = 64 * 1024


def specs() -> list[dict[str, Any]]:
    """Official 0.153.4 ThreadStartParams.dynamicTools shape."""
    return [{
        "type": "namespace",
        "name": TOOL_NAMESPACE,
        "description": "Bounded local acceptance actions in the isolated fixture.",
        "tools": [
            {
                "type": "function",
                "name": READY,
                "description": "Mark the main task ready for a same-turn question.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "type": "function",
                "name": CHALLENGE,
                "description": "Request a fresh business challenge after answering the question.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "type": "function",
                "name": BUSINESS,
                "description": "Compute one bounded report using the issued challenge.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"nonce": {"type": "string"}},
                    "required": ["nonce"],
                    "additionalProperties": False,
                },
            },
        ],
    }]


@dataclass(frozen=True)
class Call:
    request_id: str | int
    thread: str
    turn: str
    call_id: str
    tool: str
    arguments: dict[str, Any]


def parse_call(raw: dict[str, Any], *, thread: str, turn: str) -> Call:
    """Accept only the exact owned item/tool/call server request."""
    if (not isinstance(raw, dict) or raw.get("method") != "item/tool/call"
            or type(raw.get("id")) not in (str, int)
            or type(raw.get("params")) is not dict):
        raise ValueError("invalid_dynamic_tool_request")
    params = raw["params"]
    if (set(params) != {"threadId", "turnId", "callId", "namespace", "tool", "arguments"}
            or params["threadId"] != thread or params["turnId"] != turn
            or params["namespace"] != TOOL_NAMESPACE
            or params["tool"] not in {READY, CHALLENGE, BUSINESS}
            or type(params["callId"]) is not str or not params["callId"]
            or type(params["arguments"]) is not dict):
        raise ValueError("foreign_or_malformed_dynamic_tool")
    arguments = params["arguments"]
    if len(json.dumps(arguments, separators=(",", ":")).encode()) > MAX_ARGUMENT_BYTES:
        raise ValueError("dynamic_tool_arguments_too_large")
    if (params["tool"] in {READY, CHALLENGE} and arguments != {}) or (
        params["tool"] == BUSINESS
        and (set(arguments) != {"nonce"}
             or type(arguments["nonce"]) is not str
             or not arguments["nonce"])
    ):
        raise ValueError("dynamic_tool_arguments_invalid")
    return Call(raw["id"], thread, turn, params["callId"], params["tool"], arguments)


def response(call: Call, payload: dict[str, Any]) -> dict[str, Any]:
    """Official DynamicToolCallResponse; only one canonical text item."""
    if type(payload) is not dict:
        raise ValueError("dynamic_tool_payload_invalid")
    output = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(output.encode()) > MAX_OUTPUT_BYTES:
        raise ValueError("dynamic_tool_output_too_large")
    return {"id": call.request_id, "result": {
        "contentItems": [{"type": "inputText", "text": output}], "success": True,
    }}


def source_output(item: dict[str, Any], *, call_id: str) -> str:
    """Match the literal Responses function_call_output from this adapter.

    The app-server schema declares inputText on the JSON-RPC boundary; the
    underlying Responses item may carry its text as a string or input_text
    content item. Never infer content from a success flag or a different id.
    """
    if (type(call_id) is not str or not call_id
            or type(item) is not dict or item.get("type") != "function_call_output"
            or item.get("call_id") != call_id):
        raise ValueError("wrong_function_output")
    output = item.get("output")
    if type(output) is str:
        return output
    if (type(output) is list and len(output) == 1
            and type(output[0]) is dict
            and set(output[0]) == {"type", "text"}
            and output[0]["type"] == "input_text"
            and type(output[0]["text"]) is str):
        return output[0]["text"]
    raise ValueError("unsupported_function_output_shape")


class LiveBarrier:
    """Gate each tool result on its required independent source evidence.

    This class does not trust request arrival as model sampling. The supplied
    Chain verifies the actual trace and product state before a result is sent.
    The owner remains responsible for collecting those observations and for
    bounded process cleanup if any gate cannot be closed.
    """

    def __init__(self, chain, *, thread: str, turn: str, directory, values):
        if chain.phase != "configured" or chain.scope != {
            "thread": thread, "turn": turn,
            "source_path": chain.scope["source_path"],
        }:
            raise ValueError("unconfigured_or_wrong_chain")
        if not isinstance(values, list) or not values:
            raise ValueError("business_fixture_missing")
        self.chain = chain
        self.thread = thread
        self.turn = turn
        self.directory = directory
        self.values = values
        self.phase = "ready_expected"
        self.pending: Call | None = None
        self.seen_request_ids: set[str | int] = set()
        self.seen_call_ids: set[str] = set()
        self.challenge_call_id: str | None = None
        self.business_output_path = directory / "business-result.json"

    def receive(self, raw: dict[str, Any]) -> Call:
        call = parse_call(raw, thread=self.thread, turn=self.turn)
        expected = {
            "ready_expected": READY,
            "challenge_expected": CHALLENGE,
            "business_expected": BUSINESS,
        }.get(self.phase)
        if (call.tool != expected or self.pending is not None
                or call.request_id in self.seen_request_ids
                or call.call_id in self.seen_call_ids):
            raise ValueError("duplicate_or_out_of_phase_call")
        if call.tool == BUSINESS and call.arguments["nonce"] != self.chain.business_challenge["nonce"]:
            raise ValueError("business_nonce_mismatch")
        self.seen_request_ids.add(call.request_id)
        self.seen_call_ids.add(call.call_id)
        self.pending = call
        self.phase = call.tool + "_pending"
        return call

    def release_ready(self, steer_request: dict, steer_response: dict) -> dict:
        if self.phase != "ready_pending" or self.pending is None:
            raise ValueError("ready_not_pending")
        params = steer_request.get("params", {})
        if (steer_request.get("method") != "turn/steer"
                or type(steer_request.get("id")) not in (int, str)
                or params.get("threadId") != self.thread
                or params.get("expectedTurnId") != self.turn
                or steer_response.get("id") != steer_request["id"]
                or "error" in steer_response
                or steer_response.get("result", {}).get("turnId") != self.turn):
            raise ValueError("same_turn_steer_not_acknowledged")
        answer = response(self.pending, {"ready": True})
        self.pending = None
        self.phase = "challenge_expected"
        return answer

    def release_challenge(self, *, events, payloads, client_id, question,
                          notification) -> dict:
        if self.phase != "challenge_pending" or self.pending is None:
            raise ValueError("challenge_not_pending")
        self.chain.commentary(events, payloads, client_id=client_id,
                              question=question, notification=notification)
        challenge = self.chain.challenge(self.directory / "challenge.json")
        answer = response(self.pending, challenge)
        self.challenge_call_id = self.pending.call_id
        self.pending = None
        self.phase = "business_expected"
        return answer

    def observe_business(self, *, events, payloads, inference_call_id) -> None:
        """Compute one real fixture result, then prove that its call sampled the nonce."""
        if self.phase != "business_pending" or self.pending is None:
            raise ValueError("business_not_pending")
        from tools.validation import commentary_fixture as fixture

        value, _ = fixture.business_result(self.values, self.chain.business_challenge)
        fixture.exclusive(self.business_output_path, value)
        self.chain.business(
            self.values, self.business_output_path, events=events,
            payloads=payloads, inference_call_id=inference_call_id,
            call_id=self.pending.call_id,
            challenge_call_id=self.challenge_call_id,
        )
        self.phase = "review_pending"

    def release_after_review(self, runtime, state, *, session_dir, codex_home,
                             question_id, main_ids) -> dict:
        if self.phase != "review_pending" or self.pending is None:
            raise ValueError("review_not_pending")
        self.chain.release_after_review(
            runtime, state, session_dir=session_dir, codex_home=codex_home,
            question_id=question_id, main_ids=main_ids,
            barrier_path=self.directory / "review-barrier.json",
        )
        answer = response(self.pending, self.chain.business_output)
        self.pending = None
        self.phase = "business_released"
        return answer
