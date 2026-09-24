"""Offline compaction fixture primitives. No model or host execution."""

import hashlib
import ntpath
import os
import re
from pathlib import Path

from tools.validation.commentary_trace import decode
from tools.validation.host_capture import digest_echo as marker


class Unknown(ValueError):
    pass


CAPTURE_HOOK_SOURCE = "/<session-flags>/config.toml"


def expected_capture_hook_source(codex_home, *, host_os=None):
    """Freeze the official host-specific session-flags source path exactly."""
    host_os = os.name if host_os is None else host_os
    if host_os == "posix":
        return CAPTURE_HOOK_SOURCE
    if host_os == "nt":
        drive = ntpath.splitdrive(str(codex_home))[0]
        if not re.fullmatch(r"[A-Za-z]:", drive):
            raise ValueError("windows_capture_drive_unavailable")
        return drive.upper() + r"\<session-flags>\config.toml"
    raise ValueError("unsupported_capture_host")


def pair(raw, capture_id, notification, *, thread, turn, source_path, event):
    """A paired observation only: trust and compaction install remain external."""
    if event not in ("PreCompact", "SessionStart"):
        raise Unknown("unsupported_event")
    value = decode(raw)
    if value.get("hook_event_name") != event or value.get("session_id") != thread:
        raise Unknown("raw_identity_mismatch")
    if event == "PreCompact":
        if value.get("trigger") != "auto" or value.get("turn_id") != turn:
            raise Unknown("not_same_turn_auto_compact")
    elif value.get("source") != "compact":
        raise Unknown("not_compact_session_start")
    if value.get("agent_id") is not None or value.get("agent_type") is not None:
        raise Unknown("subagent_scope")
    if notification.get("method") != "hook/completed":
        raise Unknown("not_completed_notification")
    p = notification.get("params", {})
    r = p.get("run", {})
    if p.get("threadId") != thread or p.get("turnId") != turn:
        raise Unknown("notification_scope_mismatch")
    if (
        r.get("eventName") != event[0].lower() + event[1:]
        or r.get("status") != "completed"
        or r.get("handlerType") != "command"
        or r.get("executionMode") != "sync"
        or r.get("sourcePath") != source_path
        or not isinstance(r.get("id"), str)
        or not r["id"]
    ):
        raise Unknown("unbound_handler")
    expected = {"kind": "warning", "text": marker(raw, capture_id)}
    if r.get("entries") != [expected]:
        raise Unknown("echo_mismatch_or_extra_effect")
    return {
        "schema": "cg-commentary-hook-pair/v1",
        "capture_id": capture_id,
        "run_id": r["id"],
        "event": event,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "trust": "not_established",
        "compaction_installed": "not_established",
        "native_acceptance": "not_established",
    }


class HookPairs:
    """One capture and one official run must form a bijection."""

    def __init__(self):
        self.captures = {}
        self.runs = {}

    def observe(self, raw, capture_id, notification, **scope):
        result = pair(raw, capture_id, notification, **scope)
        fingerprint = hashlib.sha256(
            canonical([raw.hex(), notification, scope])
        ).hexdigest()
        run = result["run_id"]
        if capture_id in self.captures and self.captures[capture_id] != fingerprint:
            raise Unknown("capture_rebound_or_replayed")
        if run in self.runs and self.runs[run] != capture_id:
            raise Unknown("run_rebound")
        self.captures[capture_id] = fingerprint
        self.runs[run] = capture_id
        return result


def canonical(value):
    import json

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def effective_config(requested, observed):
    """Compare explicit effective values; request echoes are not readback."""
    keys = ("model_auto_compact_token_limit", "model_auto_compact_token_limit_scope")
    if not isinstance(requested, dict) or not isinstance(observed, dict):
        raise Unknown("missing_effective_config")
    if any(key not in requested or key not in observed for key in keys):
        raise Unknown("missing_effective_config")
    limit = observed[keys[0]]
    if (
        type(limit) is not int
        or limit < 1
        or limit > 1000000
        or observed[keys[1]] != "body_after_prefix"
        or any(requested[key] != observed[key] for key in keys)
    ):
        raise Unknown("effective_config_mismatch")
    # Origin of `observed` must be established separately from this comparison.
    return {key: observed[key] for key in keys}


def threshold_basis(*, limit, fallback_buffer, before_business, after_business):
    values = (limit, fallback_buffer, before_business, after_business)
    if any(type(x) is not int or x < 0 for x in values) or limit < 1:
        raise Unknown("invalid_threshold_measurements")
    threshold = limit + fallback_buffer
    if not before_business < threshold <= after_business:
        raise Unknown("threshold_not_between_business_boundaries")
    return {
        "effective_threshold": threshold,
        "before_business": before_business,
        "after_business": after_business,
        "native_trigger": "not_established",
    }


def compact_outcome(
    captures, *, request, business_result, invocation, thread, turn, source_path,
    events=None, payloads=None,
):
    """Recheck raw Hook evidence and the exact business invocation identity."""
    direct = isinstance(invocation, dict) and invocation.get("type") == "function_call"
    nested = isinstance(invocation, dict) and invocation.get("mode") == "nested_exec"
    if not (direct or nested):
        raise Unknown("missing_business_invocation")
    if direct and (
        not isinstance(invocation.get("call_id"), str)
        or not invocation["call_id"]
        or not isinstance(invocation.get("name"), str)
        or not invocation["name"]
        or not isinstance(invocation.get("arguments"), str)
    ):
        raise Unknown("missing_business_invocation")
    if nested and any(not isinstance(invocation.get(key), str) or not invocation[key]
                      for key in ("tool_call_id", "outer_call_id", "runtime_cell_id")):
        raise Unknown("missing_business_invocation")
    if not isinstance(captures, list) or len(captures) != 2:
        raise Unknown("missing_or_multiple_compactions")
    registry = HookPairs()
    observed = []
    for capture in captures:
        if not isinstance(capture, dict) or set(capture) != {
            "raw",
            "capture_id",
            "notification",
        }:
            raise Unknown("raw_hook_evidence_required")
        raw = capture["raw"]
        if not isinstance(raw, bytes):
            raise Unknown("raw_hook_evidence_required")
        value = decode(raw)
        event = value.get("hook_event_name") if isinstance(value, dict) else None
        observed.append(
            registry.observe(
                raw,
                capture["capture_id"],
                capture["notification"],
                thread=thread,
                turn=turn,
                source_path=source_path,
                event=event,
            )
        )
    if sorted(x["event"] for x in observed) != ["PreCompact", "SessionStart"]:
        raise Unknown("missing_or_multiple_compactions")
    inputs = request.get("input") if isinstance(request, dict) else None
    if not isinstance(inputs, list):
        raise Unknown("missing_compaction_input")
    expected = canonical(business_result).decode("utf-8")
    from tools.validation import commentary_live_adapter as live_wire

    if direct:
        matches = [
            item for item in inputs if isinstance(item, dict)
            and item.get("type") == "function_call_output"
            and item.get("call_id") == invocation["call_id"]]
        calls = [
            item for item in inputs if isinstance(item, dict)
            and item.get("type") == "function_call"
            and item.get("call_id") == invocation["call_id"]]
        if len(matches) != 1 or calls != [invocation]:
            raise Unknown("early_or_unbound_compaction")
        try:
            if live_wire.source_output(matches[0], call_id=invocation["call_id"]) != expected:
                raise Unknown("early_or_unbound_compaction")
        except ValueError as exc:
            raise Unknown("early_or_unbound_compaction") from exc
        business_call_id = invocation["call_id"]
    else:
        if not isinstance(events, list) or not isinstance(payloads, dict):
            raise Unknown("nested_compaction_trace_required")
        ended = [e for e in events if e.get("thread_id") == thread
                 and e.get("codex_turn_id") == turn
                 and e.get("payload", {}).get("type") == "tool_call_ended"
                 and e["payload"].get("tool_call_id") == invocation["tool_call_id"]]
        cells = [e for e in events if e.get("thread_id") == thread
                 and e.get("codex_turn_id") == turn
                 and e.get("payload", {}).get("type") == "code_cell_ended"
                 and e["payload"].get("runtime_cell_id") == invocation["runtime_cell_id"]]
        if (len(ended) != 1 or len(cells) != 1
                or ended[0]["payload"].get("status") != "completed"
                or cells[0]["payload"].get("status") != "completed"
                or type(ended[0].get("seq")) is not int
                or type(cells[0].get("seq")) is not int
                or ended[0]["seq"] >= cells[0]["seq"]):
            raise Unknown("nested_business_terminal_missing")
        ref = ended[0]["payload"].get("result_payload")
        path = ref.get("path") if isinstance(ref, dict) else None
        if (not isinstance(path, str)
                or not re.fullmatch(r"payloads/[1-9][0-9]{0,12}\.json", path)
                or ref.get("kind") != {"type": "tool_result"}
                or ref.get("raw_payload_id") !=
                "raw_payload:" + path.removeprefix("payloads/").removesuffix(".json")
                or path not in payloads
                or decode(payloads[path]) != {"type": "code_mode_response", "value": expected}):
            raise Unknown("nested_business_result_mismatch")
        matches = [item for item in inputs if isinstance(item, dict)
                   and item.get("type") == "custom_tool_call_output"
                   and item.get("call_id") == invocation["outer_call_id"]]
        if len(matches) != 1 or sum(
            isinstance(part, dict) and part == {"type": "input_text", "text": expected}
            for part in matches[0].get("output", [])
        ) != 1:
            raise Unknown("early_or_unbound_compaction")
        business_call_id = invocation["tool_call_id"]
    return {
        "paired_hook_shapes": True,
        "business_call_id": business_call_id,
        "hook_pairs": observed,
        "compaction_installed": "not_established",
        "native_acceptance": "not_established",
    }


def exclusive(path, value):
    import os

    raw = canonical(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def issue_challenge(path, commentary_pair):
    """Only an offline controller dependency, not a complete-answer certificate."""
    import secrets

    names = ("inference_call_id", "response_id", "commentary_id")
    if not isinstance(commentary_pair, dict) or any(
        not isinstance(commentary_pair.get(k), str) or not commentary_pair[k]
        for k in names
    ):
        raise Unknown("missing_commentary_identity")
    value = {
        "schema": "cg-business-challenge/v1",
        "nonce": secrets.token_hex(32),
        "commentary_pair_sha256": hashlib.sha256(
            canonical(commentary_pair)
        ).hexdigest(),
    }
    exclusive(path, value)
    return value


def business_result(values, challenge):
    """Concrete bounded fixture: square input integers and attest each row."""
    import re

    if (
        not isinstance(values, list)
        or not 1 <= len(values) <= 256
        or any(type(x) is not int or abs(x) > 1000000 for x in values)
    ):
        raise Unknown("business_input_bounds")
    if (
        not isinstance(challenge, dict)
        or challenge.get("schema") != "cg-business-challenge/v1"
        or not isinstance(challenge.get("nonce"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", challenge["nonce"])
        or not isinstance(challenge.get("commentary_pair_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", challenge["commentary_pair_sha256"])
    ):
        raise Unknown("invalid_business_challenge")
    rows = [{"index": i, "input": x, "square": x * x} for i, x in enumerate(values)]
    output = {
        "schema": "cg-business-result/v1",
        "nonce": challenge["nonce"],
        "input_sha256": hashlib.sha256(canonical(values)).hexdigest(),
        "commentary_pair_sha256": challenge["commentary_pair_sha256"],
        "rows": rows,
    }
    report = "\n".join(
        f"row {i}: input={x}, square={x * x}, sha256="
        + hashlib.sha256(canonical(rows[i])).hexdigest()
        for i, x in enumerate(values)
    )
    output["validation_report"] = report
    if len(canonical(output)) > 65536:
        raise Unknown("report_bound")
    return output, report


def verify_business(values, challenge, actual):
    """Independent arithmetic oracle; never trusts exit status or output prose."""
    import re

    if (
        not isinstance(values, list)
        or not 1 <= len(values) <= 256
        or any(type(x) is not int or abs(x) > 1000000 for x in values)
    ):
        raise Unknown("business_input_bounds")
    if (
        not isinstance(challenge, dict)
        or challenge.get("schema") != "cg-business-challenge/v1"
        or any(
            not isinstance(challenge.get(key), str)
            or not re.fullmatch(r"[0-9a-f]{64}", challenge[key])
            for key in ("nonce", "commentary_pair_sha256")
        )
    ):
        raise Unknown("invalid_business_challenge")
    if not isinstance(actual, dict) or len(canonical(actual)) > 65536:
        raise Unknown("business_output_bounds")
    if set(actual) != {
        "schema",
        "nonce",
        "input_sha256",
        "commentary_pair_sha256",
        "rows",
        "validation_report",
    }:
        raise Unknown("business_output_fields")
    if not isinstance(actual, dict) or actual.get("schema") != "cg-business-result/v1":
        raise Unknown("business_output_missing")
    if (
        actual.get("nonce") != challenge.get("nonce")
        or actual.get("commentary_pair_sha256")
        != challenge.get("commentary_pair_sha256")
        or actual.get("input_sha256") != hashlib.sha256(canonical(values)).hexdigest()
    ):
        raise Unknown("business_input_or_challenge_mismatch")
    rows = actual.get("rows")
    if not isinstance(rows, list) or len(rows) != len(values):
        raise Unknown("business_rows_missing")
    for i, (x, row) in enumerate(zip(values, rows)):
        if (
            not isinstance(row, dict)
            or row.get("index") != i
            or row.get("input") != x
            or type(row.get("square")) is not int
            or row["square"] != pow(x, 2)
        ):
            raise Unknown("business_result_incorrect")
    report_rows = []
    for i, x in enumerate(values):
        expected_row = {"index": i, "input": x, "square": pow(x, 2)}
        report_rows.append(
            f"row {i}: input={x}, square={pow(x, 2)}, sha256="
            + hashlib.sha256(canonical(expected_row)).hexdigest()
        )
    if actual["validation_report"] != "\n".join(report_rows):
        raise Unknown("business_report_incomplete_or_tampered")
    return {
        "business_output_sha256": hashlib.sha256(canonical(actual)).hexdigest(),
        "rows_verified": len(rows),
        "native_acceptance": "not_established",
    }


def product_review_checkpoint(runtime, state, *, session_dir, codex_home,
                              question_id, main_ids, expected_coverage="complete",
                              expected_main_current=True):
    """Read the product's sealed-review consumer; never mutate obligations.

    `runtime` is the independently loaded installed/source product module, not
    a reviewer score or a caller-written coverage map. Native callers still
    need exact module identity and a fresh-process state readback.
    """
    import copy

    if not main_ids or question_id in main_ids:
        raise Unknown("missing_distinct_main_obligation")
    if expected_coverage not in {"complete", "partial"}:
        raise Unknown("unsupported_review_coverage")
    if type(expected_main_current) not in (bool, type(None)):
        raise Unknown("invalid_main_current_expectation")
    directory = Path(session_dir)
    if directory.name != state.get("session", {}).get("id"):
        raise Unknown("review_session_directory_mismatch")
    before = copy.deepcopy(state)
    scope = runtime.current_scope_projection(
        state, session_dir=directory, codex_home=Path(codex_home)
    )
    if state != before:
        raise Unknown("projection_mutated_obligations")
    reviews = scope.get("answer_reviews", {})
    current = scope.get("current_item_ids", [])
    if (not isinstance(current, (list, set, tuple))
            or any(item not in {row.get("id") for row in state["requirements"]}
                   for item in main_ids)):
        raise Unknown("main_identity_lost")
    if (
        reviews.get(question_id, {}).get("coverage") != expected_coverage
        or (question_id in current) ==
        (expected_coverage == "complete")
        or (expected_main_current is not None
            and any((item in current) != expected_main_current for item in main_ids))
    ):
        raise Unknown("review_not_consumed_or_main_lost")
    return {
        "question_id": question_id,
        "main_ids": list(main_ids),
        "product_projection_sha256": hashlib.sha256(
            canonical(
                {
                    "current_item_ids": sorted(scope["current_item_ids"]),
                    "question_id": question_id,
                    "coverage": reviews[question_id]["coverage"],
                }
            )
        ).hexdigest(),
        "requirements_sha256": hashlib.sha256(
            canonical(state["requirements"])
        ).hexdigest(),
        "native_acceptance": "not_established",
    }


def main(argv=None):
    """Execute only the deterministic business fixture, never Codex."""
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    values = decode(args.input.read_bytes())
    challenge = decode(args.challenge.read_bytes())
    result, _ = business_result(values, challenge)
    exclusive(args.output, result)
    print(canonical(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
