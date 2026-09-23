"""Bounded official trace joins; never starts a host or certifies acceptance."""

import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path


class Unknown(ValueError):
    pass


def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def reduce_pair(events, payloads, *, thread, turn, client_id, question, commentary):
    """Join concrete inputs, not timestamps or caller-provided causal edges.

    payloads are retained exact bytes keyed by official bundle-local path. This
    prototype deliberately has no filesystem reader, host launcher or closure.
    """
    if not all(isinstance(x, str) and x for x in (thread, turn, client_id, question)):
        raise Unknown("missing_identity")
    expected = commentary.get("params", {})
    item = expected.get("item", {})
    if (
        commentary.get("method") != "item/completed"
        or expected.get("threadId") != thread
        or expected.get("turnId") != turn
        or item.get("type") != "agentMessage"
        or item.get("phase") != "commentary"
        or not isinstance(item.get("id"), str)
        or not item["id"]
        or not isinstance(item.get("text"), str)
        or not item["text"]
    ):
        raise Unknown("unbound_commentary")
    # The separately captured clientId user event is required as a source fact.
    users = [
        e
        for e in events
        if e.get("method") == "item/completed"
        and e.get("params", {}).get("item", {}).get("clientId") == client_id
    ]
    users = {canonical(x): x for x in users}
    if len(users) != 1:
        raise Unknown("missing_or_conflicting_user_event")
    user = next(iter(users.values()))["params"]
    user_content = user["item"].get("content")
    if isinstance(user_content, list) and len(user_content) == 1:
        if not isinstance(user_content[0], dict):
            raise Unknown("malformed_user_content")
        text_part = dict(user_content[0])
        if text_part.get("text_elements") == []:
            del text_part["text_elements"]
        user_content = [text_part]
    if (
        user.get("threadId") != thread
        or user.get("turnId") != turn
        or user["item"].get("type") != "userMessage"
        or user_content != [{"type": "text", "text": question}]
    ):
        raise Unknown("wrong_question_event")
    # clientId is not carried in the inference input. Exact text can connect
    # the two representations only when the captured user source is unique.
    # A second same-text input must not borrow the first input's response,
    # even when it belongs to another turn or was delivered out of order.
    for event in events:
        params = event.get("params", {})
        other = params.get("item", {})
        if (event.get("method") != "item/completed"
                or params.get("threadId") != thread
                or other.get("type") != "userMessage"):
            continue
        content = other.get("content")
        if isinstance(content, list) and len(content) == 1 and isinstance(content[0], dict):
            part = dict(content[0])
            if part.get("text_elements") == []:
                del part["text_elements"]
            if part == {"type": "text", "text": question} and params != user:
                raise Unknown("ambiguous_same_text_user_source")
    calls = {}
    digests = {}
    for event in events:
        if "schema_version" not in event:
            continue
        if type(event["schema_version"]) is not int or event["schema_version"] != 1:
            raise Unknown("unsupported_trace_schema")
        p = event.get("payload", {})
        kind = p.get("type", "")
        if not kind.startswith("inference_"):
            continue
        identity = p.get("inference_call_id")
        if not isinstance(identity, str) or not identity:
            raise Unknown("missing_call_id")
        previous = calls.setdefault(identity, {})
        if kind in previous and previous[kind] != event:
            raise Unknown("conflicting_call_event")
        previous[kind] = event

    def read(ref, kind):
        if not isinstance(ref, dict) or ref.get("kind") != {"type": kind}:
            raise Unknown("wrong_payload_kind")
        path = ref.get("path", "")
        ordinal = path.removeprefix("payloads/").removesuffix(".json")
        if not re.fullmatch(r"payloads/[1-9][0-9]{0,12}\.json", path):
            raise Unknown("unsafe_payload_path")
        if ref.get("raw_payload_id") != f"raw_payload:{int(ordinal)}":
            raise Unknown("payload_identity_mismatch")
        raw = payloads.get(path)
        if not isinstance(raw, bytes):
            raise Unknown("missing_payload")
        digests[path] = hashlib.sha256(raw).hexdigest()
        try:
            value = decode(raw)
        except (ValueError, UnicodeError) as exc:
            raise Unknown("malformed_payload") from exc
        if not isinstance(value, dict):
            raise Unknown("nonobject_payload")
        return value

    matches = []
    for call, rows in calls.items():
        if set(rows) != {"inference_started", "inference_completed"}:
            continue
        start, done = rows["inference_started"], rows["inference_completed"]
        if any(
            e.get("thread_id") != thread or e.get("codex_turn_id") != turn
            for e in (start, done)
        ):
            continue
        if not start.get("rollout_id") or start.get("rollout_id") != done.get(
            "rollout_id"
        ):
            raise Unknown("rollout_identity_mismatch")
        p, q = start["payload"], done["payload"]
        if p.get("thread_id") != thread or p.get("codex_turn_id") != turn:
            raise Unknown("inner_identity_mismatch")
        request = read(p.get("request_payload"), "inference_request")
        response = read(q.get("response_payload"), "inference_response")
        inputs = request.get("input", [])
        if not isinstance(inputs, list):
            raise Unknown("malformed_request_input")
        # No ancestry reconstruction or tool/assistant quoting accepted.
        qs = [
            x
            for x in inputs
            if isinstance(x, dict)
            and x.get("type") == "message"
            and x.get("role") == "user"
            and x.get("content") == [{"type": "input_text", "text": question}]
        ]
        if len(qs) != 1:
            continue
        response_id = q.get("response_id")
        if not response_id or response.get("response_id") != response_id:
            raise Unknown("response_identity_mismatch")
        outputs = response.get("output_items", [])
        if not isinstance(outputs, list):
            raise Unknown("malformed_response_output")
        answers = [
            x for x in outputs if isinstance(x, dict) and x.get("id") == item["id"]
        ]
        if len(answers) != 1:
            continue
        answer = answers[0]
        if (
            answer.get("type") != "message"
            or answer.get("role") != "assistant"
            or answer.get("phase") != "commentary"
            or answer.get("content") != [{"type": "output_text", "text": item["text"]}]
        ):
            raise Unknown("commentary_output_mismatch")
        matches.append(
            {
                "inference_call_id": call,
                "response_id": response_id,
                "commentary_id": item["id"],
            }
        )
    if len(matches) != 1:
        raise Unknown("nonunique_input_response_pair")
    return {
        "schema": "cg-commentary-trace-pair/v1",
        "pair": matches[0],
        "payload_hashes": digests,
        "semantic_completeness": "unknown",
        "native_acceptance": "not_established",
        "core_closure": False,
    }


MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise Unknown("duplicate_json_key")
            value[key] = item
        return value

    def constant(_):
        raise Unknown("nonfinite_json")

    if not isinstance(raw, bytes) or len(raw) > MAX_FILE:
        raise Unknown("json_size_limit")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant
        )

        def check(item, depth=0):
            if depth > 32:
                raise Unknown("json_depth_limit")
            if isinstance(item, str):
                item.encode("utf-8")
            elif isinstance(item, float) and not math.isfinite(item):
                raise Unknown("nonfinite_json")
            elif isinstance(item, (list, dict)):
                for child in (
                    list(item) + list(item.values()) if isinstance(item, dict) else item
                ):
                    check(child, depth + 1)

        check(value)
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Unknown("invalid_json") from exc


def stable_read(root, relative):
    """Bounded cold read; rejects links and before/after changes, no fsync claim."""
    root = Path(root)
    if any(p.is_symlink() for p in (root, *root.parents)) or not root.is_dir():
        raise Unknown("invalid_bundle_root")
    if not re.fullmatch(
        r"(?:manifest\.json|[A-Za-z0-9_-]+\.jsonl|payloads/[1-9][0-9]{0,12}\.json)", relative
    ):
        raise Unknown("unsafe_bundle_path")
    path = root
    for part in relative.split("/"):
        path = path / part
        if path.is_symlink():
            raise Unknown("bundle_symlink")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE:
        raise Unknown("bundle_file_invalid")
    with path.open("rb") as stream:
        first = os.fstat(stream.fileno())
        raw = stream.read(MAX_FILE + 1)
        last = os.fstat(stream.fileno())
    after = path.lstat()

    def full(s):
        return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

    if (
        full(before) != full(after)
        or full(first) != full(last)
        or full(before)[:-1] != full(first)[:-1]
        or len(raw) != first.st_size
    ):
        raise Unknown("bundle_changed")
    return raw


def load_snapshot(root, event_file):
    """Cold snapshot only: request/response bytes remain private in memory."""
    raw = stable_read(root, event_file)
    if not raw.endswith(b"\n"):
        raise Unknown("partial_event_log")
    events, payloads, sequence, rollout = [], {}, 0, None
    total = len(raw)
    for line in raw.splitlines():
        row = decode(line)
        if (
            not isinstance(row, dict)
            or type(row.get("schema_version")) is not int
            or row.get("schema_version") != 1
            or type(row.get("seq")) is not int
            or row["seq"] != sequence + 1
        ):
            raise Unknown("event_sequence_or_schema")
        sequence = row["seq"]
        if not isinstance(row.get("rollout_id"), str) or not row["rollout_id"]:
            raise Unknown("missing_rollout")
        rollout = rollout or row["rollout_id"]
        if row["rollout_id"] != rollout:
            raise Unknown("mixed_rollouts")
        p = row.get("payload")
        if not isinstance(p, dict):
            raise Unknown("malformed_event_payload")
        events.append(row)
        # Only these payload domains support the reducer below.
        fields = {
            "inference_started": "request_payload",
            "inference_completed": "response_payload",
            "compaction_request_started": "request_payload",
            "compaction_request_completed": "response_payload",
            "compaction_installed": "checkpoint_payload",
        }
        if p.get("type") in fields:
            field = fields[p["type"]]
            ref = p.get(field)
            if not isinstance(ref, dict) or not isinstance(ref.get("path"), str):
                raise Unknown("missing_payload_reference")
            path = ref["path"]
            if path not in payloads:
                data = stable_read(root, path)
                total += len(data)
                if total > MAX_TOTAL:
                    raise Unknown("snapshot_size_limit")
                decode(data)
                payloads[path] = data
    # Detect changes across acquisition, not merely within each individual read.
    if stable_read(root, event_file) != raw or any(
        stable_read(root, p) != data for p, data in payloads.items()
    ):
        raise Unknown("snapshot_changed")
    hashes = {event_file: hashlib.sha256(raw).hexdigest()}
    hashes.update({p: hashlib.sha256(v).hexdigest() for p, v in payloads.items()})
    return events, payloads, hashes


def attempt_pair(events, payloads, *, kind, call_id, thread, turn):
    """Select one concrete request/terminal pair from a complete private snapshot."""
    if kind not in ("inference", "compaction"):
        raise Unknown("unsupported_attempt_kind")
    key = "inference_call_id" if kind == "inference" else "compaction_request_id"
    started = (
        "inference_started" if kind == "inference" else "compaction_request_started"
    )
    completed = (
        "inference_completed" if kind == "inference" else "compaction_request_completed"
    )
    rows = {}
    for row in events:
        p = row.get("payload", {})
        if p.get(key) != call_id:
            continue
        if (
            type(row.get("schema_version")) is not int
            or row["schema_version"] != 1
            or row.get("thread_id") != thread
            or row.get("codex_turn_id") != turn
        ):
            raise Unknown("attempt_scope_mismatch")
        event = p.get("type")
        if event in rows and rows[event] != row:
            raise Unknown("conflicting_attempt_event")
        rows[event] = row
    if set(rows) != {started, completed}:
        raise Unknown("attempt_not_uniquely_completed")
    first, last = rows[started], rows[completed]
    a, b = first["payload"], last["payload"]
    if (
        not first.get("rollout_id")
        or first["rollout_id"] != last.get("rollout_id")
        or a.get("thread_id") != thread
        or a.get("codex_turn_id") != turn
    ):
        raise Unknown("attempt_identity_mismatch")
    if kind == "compaction" and (
        not a.get("compaction_id") or a["compaction_id"] != b.get("compaction_id")
    ):
        raise Unknown("compaction_identity_mismatch")
    loaded, hashes = [], {}
    for event, field, payload_kind in (
        (a, "request_payload", kind + "_request"),
        (b, "response_payload", kind + "_response"),
    ):
        ref = event.get(field)
        if not isinstance(ref, dict) or ref.get("kind") != {"type": payload_kind}:
            raise Unknown("attempt_payload_kind")
        path = ref.get("path")
        if not isinstance(path, str) or not re.fullmatch(
            r"payloads/[1-9][0-9]{0,12}\.json", path
        ):
            raise Unknown("attempt_payload_path")
        ordinal = path.split("/")[1][:-5]
        if (
            ref.get("raw_payload_id") != "raw_payload:" + ordinal
            or path not in payloads
        ):
            raise Unknown("attempt_payload_missing")
        raw = payloads[path]
        value = decode(raw)
        if not isinstance(value, dict):
            raise Unknown("attempt_payload_object")
        loaded.append(value)
        hashes[path] = hashlib.sha256(raw).hexdigest()
    if kind == "inference" and (
        not b.get("response_id") or loaded[1].get("response_id") != b["response_id"]
    ):
        raise Unknown("attempt_response_mismatch")
    return (
        loaded[0],
        loaded[1],
        {
            "call_id": call_id,
            "payload_hashes": hashes,
            "compaction_id": a.get("compaction_id"),
            "native_acceptance": "not_established",
        },
    )
