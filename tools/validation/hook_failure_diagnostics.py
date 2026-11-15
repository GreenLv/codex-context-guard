"""Bounded diagnostic projection; entries never leave in plaintext.

The result is diagnostic only and must never satisfy Hook-success pairing.
The caller must pass the same already validated CCG-only inventory and path
matcher used by DailyClientFactory.receive, not an arbitrary hooks/list result.
"""

from __future__ import annotations

import hashlib
import re

EVENTS = frozenset(
    {
        "userPromptSubmit",
        "preToolUse",
        "postToolUse",
        "preCompact",
        "sessionStart",
        "subagentStart",
        "subagentStop",
        "stop",
        "sessionEnd",
    }
)
# Exact enum from the pinned app-server protocol, never arbitrary kind strings.
KINDS = frozenset({"warning", "stop", "feedback", "context", "error"})
PROVED_EVENTS = frozenset({"userPromptSubmit", "postToolUse", "stop", "subagentStop"})
MAX_ENTRIES = 32
MAX_TEXT_BYTES = 16384


def message_pattern(kind: str, text: str, event: str) -> str:
    """A message-pattern match, not a verified cause or execution outcome.

    Patterns mirror error messages in openai/codex at 226fa88979b1a9d76dc36f339ee9c5fbdb2c8e7f.
    A matching text does not authenticate its producer, bind the actual CLI build
    to that source, or establish a cause. Other event wordings remain unknown.
    """
    if kind != "error" or event not in PROVED_EVENTS:
        return "unknown"
    if text == "plugin contents changed; hook approval required":
        return "message_matches_plugin_content_approval"
    if re.fullmatch(r"hook timed out after (?:0|[1-9][0-9]{0,19})s", text):
        return "message_matches_timeout"
    if text.startswith("failed to write hook stdin: ") and len(text) > len(
        "failed to write hook stdin: "
    ):
        return "message_matches_stdin_write_error"
    if text == "hook exited without a status code":
        return "message_matches_exit_without_status"
    match = re.fullmatch(r"hook exited with code (-?(?:0|[1-9][0-9]{0,9}))", text)
    if match is not None:
        code = int(match.group(1))
        if -(2**31) <= code < 2**31 and code != 0:
            return "message_matches_nonzero_exit"
    return "unknown"


def project_failed(message, inventory, source_key):
    """Return None for out-of-scope input, a bounded redacted diagnostic otherwise.

    Never access entries until identity, event, source, handler, ordering and
    execution mode match the trusted, enabled CCG inventory. Unknown shapes fail
    closed to a fixed diagnostic status without serializing input values.
    """
    if type(message) is not dict or message.get("method") != "hook/completed":
        return None
    params = message.get("params")
    if type(params) is not dict:
        return None
    run = params.get("run")
    if type(run) is not dict or run.get("status") != "failed":
        return None
    if (
        type(params.get("threadId")) is not str
        or not params["threadId"]
        or "turnId" not in params
        or (
            params["turnId"] is not None
            and (type(params["turnId"]) is not str or not params["turnId"])
        )
        or type(run.get("id")) is not str
        or not run["id"]
    ):
        return None
    if type(inventory) is not dict:
        return None
    event = run.get("eventName")
    if type(event) is not str or event not in EVENTS:
        return None
    try:
        source = source_key(run.get("sourcePath"), {path for _, path in inventory})
        expected = inventory.get((event, source))
        expected_source = (
            source_key(expected.get("sourcePath"), [source])
            if isinstance(expected, dict) and source is not None
            else None
        )
    except (TypeError, ValueError):
        return None
    if source is None or expected_source != source or type(expected) is not dict:
        return None
    if (
        expected.get("source") != "plugin"
        or expected.get("handlerType") != "command"
        or expected.get("enabled") is not True
        or expected.get("trustStatus") != "trusted"
        or type(expected.get("displayOrder")) is not int
        or type(run.get("displayOrder")) is not int
        or ("async" in expected and type(expected["async"]) is not bool)
        or type(expected.get("key")) is not str
        or not expected["key"]
        or type(expected.get("currentHash")) is not str
        or not expected["currentHash"]
        or any(
            run.get(k) != expected.get(k)
            for k in ("eventName", "source", "handlerType", "displayOrder")
        )
        or run.get("executionMode") != ("async" if expected.get("async") else "sync")
    ):
        return None

    # Guard access to any private entry content until after the scope check.
    entries = run.get("entries")
    if type(entries) is not list:
        return {"status": "unavailable", "reason": "missing_or_invalid_entries"}
    if len(entries) > MAX_ENTRIES:
        return {"status": "unavailable", "reason": "too_many_entries"}
    if not entries:
        return {"status": "unavailable", "reason": "empty_entries"}
    summary = []
    for item in entries:
        if (
            type(item) is not dict
            or set(item) != {"kind", "text"}
            or type(item.get("kind")) is not str
            or item["kind"] not in KINDS
            or type(item.get("text")) is not str
        ):
            return {"status": "unavailable", "reason": "unknown_entry_shape"}
        try:
            data = item["text"].encode("utf-8", "strict")
        except UnicodeEncodeError:
            return {"status": "unavailable", "reason": "invalid_utf8_text"}
        if len(data) > MAX_TEXT_BYTES:
            return {"status": "unavailable", "reason": "entry_too_large"}
        summary.append(
            {
                "kind": item["kind"],
                "utf8_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "classification": message_pattern(item["kind"], item["text"], event),
            }
        )
    return {"status": "redacted", "entries": summary}
