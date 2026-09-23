"""Offline integration of automatic-compaction evidence; native collection disabled.

The controller creates the challenge and releases its business barrier only
through the real product's review projection. Native transport, trust and live
threshold calibration remain separate gates. No method starts Codex or a model.
"""

import hashlib
import re
from pathlib import Path

from tools.validation import commentary_fixture as fixture
from tools.validation import commentary_live_adapter as live_wire
from tools.validation import commentary_trace as trace


class NestedSourcePending(ValueError):
    """An official nested tool edge may still be appended to the live trace."""


def _scoped(events, *, thread, turn, kind):
    return [e for e in events if e.get("thread_id") == thread
            and e.get("codex_turn_id") == turn
            and e.get("payload", {}).get("type") == kind]


def _one(rows, missing, repeated):
    if not rows:
        raise NestedSourcePending(missing)
    if len(rows) != 1:
        raise fixture.Unknown(repeated)
    return rows[0]


def _before(first, second):
    a, b = first.get("seq"), second.get("seq")
    return type(a) is int and type(b) is int and 0 < a < b


def _referenced(payloads, event, field, kind):
    ref = event.get("payload", {}).get(field)
    path = ref.get("path") if isinstance(ref, dict) else None
    if (not isinstance(path, str)
            or not re.fullmatch(r"payloads/[1-9][0-9]{0,12}\.json", path)
            or ref.get("kind") != {"type": kind}
            or ref.get("raw_payload_id") !=
            "raw_payload:" + path.removeprefix("payloads/").removesuffix(".json")
            or path not in payloads):
        raise fixture.Unknown("invalid_nested_payload_reference")
    value = trace.decode(payloads[path])
    if not isinstance(value, dict):
        raise fixture.Unknown("invalid_nested_payload")
    return value, hashlib.sha256(payloads[path]).hexdigest()


def nested_business_proof(events, payloads, *, thread, turn,
                          inference_call_id, call_id, challenge_call_id, challenge):
    """Bind an exec-wrapped dynamic tool to its inference and fresh challenge.

    `item/tool/call.callId` is the *inner* tool_call_id. The model response's
    custom_tool_call.call_id identifies the outer exec cell. Official trace
    code_cell_started and tool_call_started carry the explicit parent links.
    """
    request, response, inference = trace.attempt_pair(
        events, payloads, kind="inference", call_id=inference_call_id,
        thread=thread, turn=turn,
    )
    inference_start = _one(
        [e for e in _scoped(events, thread=thread, turn=turn, kind="inference_started")
         if e["payload"].get("inference_call_id") == inference_call_id],
        "business_inference_start_pending", "repeated_business_inference_start")
    outer = [x for x in response.get("output_items", [])
             if isinstance(x, dict) and x.get("type") == "custom_tool_call"
             and x.get("name") == "exec" and isinstance(x.get("call_id"), str)]
    if not outer:
        raise fixture.Unknown("business_outer_exec_missing")
    cells = _scoped(events, thread=thread, turn=turn, kind="code_cell_started")
    starts = _scoped(events, thread=thread, turn=turn, kind="tool_call_started")
    target = [e for e in starts if e["payload"].get("tool_call_id") == call_id]
    started = _one(target, "business_tool_start_pending", "repeated_business_tool_start")
    body = started["payload"]
    cell_id = body.get("requester", {}).get("runtime_cell_id")
    if (body.get("requester", {}).get("type") != "code_cell"
            or not isinstance(cell_id, str) or not cell_id
            or body.get("kind") != {"type": "other", "name": "business"}):
        raise fixture.Unknown("wrong_business_tool_identity")
    cell = _one([e for e in cells if e["payload"].get("runtime_cell_id") == cell_id],
                "business_cell_pending", "repeated_business_cell")
    outer_call = cell["payload"].get("model_visible_call_id")
    if len([x for x in outer if x.get("call_id") == outer_call]) != 1:
        raise fixture.Unknown("business_outer_call_mismatch")
    if (not _before(inference_start, cell) or not _before(cell, started)
            or any(e.get("rollout_id") != inference_start.get("rollout_id")
                   for e in (cell, started))):
        raise fixture.Unknown("business_nested_order_or_rollout")
    invocation, invocation_hash = _referenced(
        payloads, started, "invocation_payload", "tool_invocation")
    if (invocation.get("tool_namespace") != live_wire.TOOL_NAMESPACE
            or invocation.get("tool_name") != live_wire.BUSINESS
            or invocation.get("payload", {}).get("type") != "function"
            or not isinstance(invocation["payload"].get("arguments"), str)
            or trace.decode(invocation["payload"]["arguments"].encode()) !=
            {"nonce": challenge["nonce"]}):
        raise fixture.Unknown("business_invocation_mismatch")

    # The challenge's *inner* result must be the exact JSON given to the
    # model through its *outer* exec output in this inference request.
    prior = [e for e in starts if e["payload"].get("tool_call_id") == challenge_call_id]
    challenge_start = _one(prior, "challenge_tool_start_pending",
                           "repeated_challenge_tool_start")
    prior_body = challenge_start["payload"]
    prior_cell_id = prior_body.get("requester", {}).get("runtime_cell_id")
    if (prior_body.get("requester", {}).get("type") != "code_cell"
            or not isinstance(prior_cell_id, str) or not prior_cell_id
            or prior_body.get("kind") != {"type": "other", "name": "challenge"}):
        raise fixture.Unknown("wrong_challenge_tool_identity")
    challenge_invocation, _challenge_invocation_hash = _referenced(
        payloads, challenge_start, "invocation_payload", "tool_invocation")
    if (challenge_invocation.get("tool_namespace") != live_wire.TOOL_NAMESPACE
            or challenge_invocation.get("tool_name") != live_wire.CHALLENGE
            or challenge_invocation.get("payload") !=
            {"type": "function", "arguments": "{}"}):
        raise fixture.Unknown("challenge_invocation_mismatch")
    challenge_cell = _one(
        [e for e in cells if e["payload"].get("runtime_cell_id") == prior_cell_id],
        "challenge_cell_pending", "repeated_challenge_cell")
    prior_outer = challenge_cell["payload"].get("model_visible_call_id")
    prior_calls = []
    for e in _scoped(events, thread=thread, turn=turn, kind="inference_completed"):
        identity = e["payload"].get("inference_call_id")
        if not isinstance(identity, str):
            raise fixture.Unknown("malformed_prior_inference")
        _prior_request, prior_response, _prior_proof = trace.attempt_pair(
            events, payloads, kind="inference", call_id=identity,
            thread=thread, turn=turn,
        )
        prior_calls.extend(x for x in prior_response.get("output_items", [])
                           if isinstance(x, dict) and x.get("type") == "custom_tool_call"
                           and x.get("name") == "exec" and x.get("call_id") == prior_outer)
    if len(prior_calls) != 1:
        raise fixture.Unknown("challenge_outer_call_mismatch")
    if not _before(challenge_cell, challenge_start):
        raise fixture.Unknown("challenge_nested_order")
    ends = _scoped(events, thread=thread, turn=turn, kind="tool_call_ended")
    challenge_end = _one(
        [e for e in ends if e["payload"].get("tool_call_id") == challenge_call_id],
        "challenge_tool_end_pending", "repeated_challenge_tool_end")
    if challenge_end["payload"].get("status") != "completed":
        raise fixture.Unknown("challenge_tool_not_completed")
    if (not _before(challenge_start, challenge_end)
            or not _before(challenge_end, inference_start)
            or any(e.get("rollout_id") != inference_start.get("rollout_id")
                   for e in (challenge_cell, challenge_start, challenge_end))):
        raise fixture.Unknown("challenge_result_order_or_rollout")
    challenge_result, result_hash = _referenced(
        payloads, challenge_end, "result_payload", "tool_result")
    expected = fixture.canonical(challenge).decode()
    if challenge_result != {"type": "code_mode_response", "value": expected}:
        raise fixture.Unknown("challenge_result_mismatch")
    input_matches = [item for item in request.get("input", [])
                     if isinstance(item, dict)
                     and item.get("type") == "custom_tool_call_output"
                     and item.get("call_id") == prior_outer]
    if len(input_matches) != 1 or sum(
        isinstance(part, dict) and part == {"type": "input_text", "text": expected}
        for part in input_matches[0].get("output", [])
    ) != 1:
        raise fixture.Unknown("business_request_lacks_fresh_challenge")
    return {"mode": "nested_exec", "inference": inference,
            "outer_call_id": outer_call, "runtime_cell_id": cell_id,
            "tool_call_id": call_id, "challenge_outer_call_id": prior_outer,
            "invocation_sha256": invocation_hash, "challenge_result_sha256": result_hash}


class Chain:
    def __init__(self, *, thread, turn, cwd, hook_source, frozen_config, threshold):
        self.scope = dict(thread=thread, turn=turn, source_path=hook_source)
        self.cwd = cwd
        self.frozen_config = frozen_config
        self.threshold = threshold
        self.phase = "new"
        self.evidence = {}

    def require(self, phase):
        if self.phase != phase:
            raise fixture.Unknown("missing_or_out_of_phase_node")

    def configuration(self, request, response, thread_start):
        self.require("new")
        if (
            request.get("method") != "config/read"
            or "id" not in request
            or request.get("params", {}).get("cwd") != self.cwd
            or response.get("id") != request["id"]
            or "error" in response
            or not isinstance(response.get("result"), dict)
            or "origins" not in response["result"]
        ):
            raise fixture.Unknown("effective_config_readback_required")
        # config/read covers CLI + cwd layers, not arbitrary thread overrides.
        if (
            thread_start.get("method") != "thread/start"
            or thread_start.get("params", {}).get("cwd") != self.cwd
            or thread_start["params"].get("config") not in (None, {})
        ):
            raise fixture.Unknown("unread_thread_override")
        observed = fixture.effective_config(
            self.frozen_config, response["result"].get("config")
        )
        if set(self.threshold) == {"limit", "fallback_buffer", "before_business",
                                   "after_business"}:
            # Offline fixture measurements. The native plan never supplies
            # these fields without source-bound host observations.
            basis = fixture.threshold_basis(**self.threshold)
        elif set(self.threshold) == {"limit", "scope", "status"} and (
            self.threshold["scope"] == "body_after_prefix"
            and self.threshold["status"] == "bounded_proposal_not_token_calibrated"
        ):
            basis = {"limit": self.threshold["limit"],
                     "scope": self.threshold["scope"],
                     "threshold_calibrated": False,
                     "source": "effective_config_only"}
        else:
            raise fixture.Unknown("invalid_threshold_basis")
        if observed["model_auto_compact_token_limit"] != self.threshold["limit"]:
            raise fixture.Unknown("threshold_config_mismatch")
        self.evidence["config_rpc_sha256"] = hashlib.sha256(
            fixture.canonical([request, response, thread_start])
        ).hexdigest()
        self.evidence["threshold"] = basis
        self.phase = "configured"

    def commentary(self, events, payloads, *, client_id, question, notification):
        self.require("configured")
        pair = trace.reduce_pair(
            events,
            payloads,
            thread=self.scope["thread"],
            turn=self.scope["turn"],
            client_id=client_id,
            question=question,
            commentary=notification,
        )
        self.commentary_text = notification["params"]["item"]["text"]
        self.evidence["commentary"] = pair
        self.phase = "answered_observed"

    def challenge(self, path):
        self.require("answered_observed")
        self.business_challenge = fixture.issue_challenge(
            path, self.evidence["commentary"]["pair"]
        )
        self.phase = "challenge_issued"
        return self.business_challenge

    def business(
        self, values, output_path, *, events, payloads, inference_call_id, call_id,
        challenge_call_id=None,
    ):
        self.require("challenge_issued")
        # An explicit fresh nonce in a typed tool result is required in the
        # business sampling input. No previous_response_id reconstruction.
        inference_request, inference_response, source = trace.attempt_pair(
            events,
            payloads,
            kind="inference",
            call_id=inference_call_id,
            thread=self.scope["thread"],
            turn=self.scope["turn"],
        )
        self.evidence["business_inference"] = source
        inputs = inference_request.get("input", [])
        nonce = self.business_challenge["nonce"]
        inputs_with_nonce = []
        for item in inputs:
            if not isinstance(item, dict) or item.get("type") != "function_call_output":
                continue
            if challenge_call_id is not None and item.get("call_id") != challenge_call_id:
                continue
            try:
                output = live_wire.source_output(item, call_id=item.get("call_id"))
            except ValueError:
                continue
            if output == fixture.canonical(self.business_challenge).decode():
                inputs_with_nonce.append(item)
        if len(inputs_with_nonce) != 1:
            direct_input = False
        else:
            direct_input = True
        calls = [
            x
            for x in inference_response.get("output_items", [])
            if isinstance(x, dict)
            and x.get("type") == "function_call"
            and x.get("call_id") == call_id
        ]
        if len(calls) == 1 and direct_input:
            invocation = calls[0]
        elif len(calls) == 1:
            raise fixture.Unknown("business_request_lacks_fresh_challenge")
        elif not calls and not direct_input:
            invocation = nested_business_proof(
                events, payloads, thread=self.scope["thread"],
                turn=self.scope["turn"], inference_call_id=inference_call_id,
                call_id=call_id, challenge_call_id=challenge_call_id,
                challenge=self.business_challenge,
            )
        else:
            raise fixture.Unknown("business_invocation_not_observed")
        raw = Path(output_path).read_bytes()
        result = trace.decode(raw)
        checked = fixture.verify_business(values, self.business_challenge, result)
        if result["nonce"] != nonce:
            raise fixture.Unknown("business_nonce_mismatch")
        self.business_invocation = invocation
        self.business_output = result
        self.evidence["business"] = checked
        self.phase = "business_observed"

    def release_after_review(
        self, runtime, state, *, session_dir, codex_home, question_id, main_ids,
        barrier_path
    ):
        self.require("business_observed")
        items = [
            item
            for item in state.get("requirements", [])
            if item.get("id") == question_id
        ]
        if len(items) != 1:
            raise fixture.Unknown("review_question_identity")
        directory = Path(session_dir)
        if directory.name != state.get("session", {}).get("id"):
            raise fixture.Unknown("review_session_directory_mismatch")
        review_request = runtime.answer_review_request(
            directory, state, items[0], codex_home=Path(codex_home)
        )
        subject = review_request["subject"]
        mid = self.evidence["commentary"]["pair"]["commentary_id"]
        if (
            subject["session_id"] != self.scope["thread"]
            or subject["turn_id"] != self.scope["turn"]
            or [m["message_id"] for m in review_request["messages"]] != [mid]
            or review_request["answer_texts"].get(mid) != self.commentary_text
        ):
            raise fixture.Unknown("review_not_bound_to_observed_answer")
        checkpoint = fixture.product_review_checkpoint(
            runtime, state, session_dir=directory, codex_home=codex_home,
            question_id=question_id, main_ids=main_ids
        )
        # This exclusive file is a real dependency consumed by a bounded tool;
        # a caller-supplied review score cannot release it.
        fixture.exclusive(
            barrier_path,
            {
                "schema": "cg-review-barrier/v1",
                "challenge_nonce": self.business_challenge["nonce"],
                "projection": checkpoint,
            },
        )
        self.question_id, self.main_ids = question_id, list(main_ids)
        self.evidence["precompact_product"] = checkpoint
        self.phase = "review_consumed"

    def compaction(self, captures, *, events, payloads, request_id, completed_item):
        self.require("review_consumed")
        request, _response, source = trace.attempt_pair(
            events,
            payloads,
            kind="compaction",
            call_id=request_id,
            thread=self.scope["thread"],
            turn=self.scope["turn"],
        )
        compaction_id = source["compaction_id"]
        self.evidence["compaction_request"] = source
        bound = fixture.compact_outcome(
            captures,
            request=request,
            business_result=self.business_output,
            invocation=self.business_invocation,
            events=events, payloads=payloads,
            **self.scope,
        )
        params = completed_item.get("params", {})
        item = params.get("item", {})
        # Official legacy remote compact emits this only after awaiting
        # replace_compacted_history; its earlier installed trace is inadequate.
        if (
            completed_item.get("method") != "item/completed"
            or params.get("threadId") != self.scope["thread"]
            or params.get("turnId") != self.scope["turn"]
            or item.get("type") != "contextCompaction"
            or not isinstance(compaction_id, str)
            or not compaction_id
            or item.get("id") != compaction_id
        ):
            raise fixture.Unknown("completed_compaction_required")
        self.evidence["compaction"] = bound
        self.evidence["compaction_id"] = compaction_id
        self.phase = "recovery_observed"

    def cold_recovery(self, read_projection):
        self.require("recovery_observed")
        # The integration owner supplies a fresh-process product read, not an
        # assistant assertion. Test callbacks are explicitly synthetic.
        projection = read_projection(self.question_id, self.main_ids)
        before = self.evidence["precompact_product"]
        if (
            projection.get("question_id") != self.question_id
            or projection.get("main_ids") != self.main_ids
            or projection.get("requirements_sha256") != before["requirements_sha256"]
            or projection.get("product_projection_sha256")
            != before["product_projection_sha256"]
        ):
            raise fixture.Unknown("cold_projection_not_preserved")
        self.evidence["cold_product"] = projection
        self.phase = "offline_chain_checked"
        return {
            "schema": "cg-commentary-offline-chain/v1",
            "phase": self.phase,
            "evidence": self.evidence,
            "native_acceptance": "not_established",
            "limitations": [
                "native transport/source authenticity not certified",
                "threshold basis must be measured on the actual host",
                "cold reader process provenance must be captured",
            ],
        }
