#!/usr/bin/env python3
"""Thin Hook router: stateless fast path for SAFE and generic-AMBIGUOUS
PreToolUse calls.

This module is the PRODUCTION entry point for the `hook` subcommand
(referenced from run_context_guard.sh / run-context-guard.ps1).
It parses minimal JSON from stdin and decides:
  * provably SAFE PreToolUse AND generic/malformed AMBIGUOUS input
    (canonical hook_event_name, normalized ProtocolToolCall) → print {} →
    exit 0: zero subprocess, zero heavy import, zero private-state I/O;
  * CANDIDATE mutations and the candidate-high-risk runner envelope
    (STATE_AMBIGUOUS_CANDIDATE) delegate the ORIGINAL stdin bytes to
    context_guard.py hook via subprocess — only those may read/lock
    private state and consult the profile — writing the heavy core's
    stdout to sys.stdout and its stderr to sys.stderr (never crossed) and
    propagating its exit code;
  * event aliases, unparseable bytes, and non-dict payloads delegate as
    before.

Uses cg_actions (stdlib-only) for the classification and
cg_codex_adapter/cg_protocol for payload normalization. In 0.12 the heavy
core still consumes the original Codex wire JSON directly; cg_protocol is
consumed only by this router/adapter pair (full heavy-core protocol
wiring is a later-phase target and must not be claimed as done).
"""

from __future__ import annotations

import json
import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from cg_actions import (  # noqa: E402
    STATE_AMBIGUOUS,
    STATE_SAFE,
    classify_pre_tool_state,
)
from cg_codex_adapter import codex_to_protocol_event  # noqa: E402
from cg_protocol import ProtocolEventType, ProtocolToolCall  # noqa: E402


def _delegate(raw_stdin: bytes) -> None:
    """Delegate to the heavy context_guard.py core via subprocess.

    Forwards the ORIGINAL stdin bytes untouched, writes the heavy core's
    stdout to sys.stdout and its stderr to sys.stderr (never crossed),
    and exits with the heavy core's exit code."""
    heavy = os.path.join(_SCRIPT_DIR, "context_guard.py")
    import subprocess  # lazy: the SAFE fast path never delegates
    env = os.environ.copy()
    env["PYTHONPATH"] = _SCRIPT_DIR
    result = subprocess.run(
        [sys.executable, heavy, "hook"],
        input=raw_stdin,
        capture_output=True,
        env=env,
        timeout=120,
    )
    sys.stdout.buffer.write(result.stdout)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(result.stderr)
    sys.stderr.buffer.flush()
    sys.exit(result.returncode)


def main() -> int:
    raw = sys.stdin.buffer.read()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        _delegate(raw)  # can't parse → heavy core handles fail-safe
        return  # exec never returns, but for subprocess path:
    if not isinstance(payload, dict):
        _delegate(raw)
        return

    # Fast path requires the CANONICAL hook_event_name. Alias-only payloads
    # (e.g. {"event": "PreToolUse", ...}) and every non-PreToolUse event
    # delegate to the heavy core.
    if payload.get("hook_event_name") != "PreToolUse":
        _delegate(raw)
        return

    # Protocol normalization: the fast path consumes the NORMALIZED
    # ProtocolToolCall (tool_name/tool_input), never the raw payload.
    proto_event = codex_to_protocol_event(payload)
    if (
        proto_event is None
        or proto_event.event_type != ProtocolEventType.TOOL_PRE_EXECUTE
        or not isinstance(proto_event.payload, ProtocolToolCall)
    ):
        _delegate(raw)  # unresolvable → heavy core handles fail-safe
        return

    # Light-layer routing (Phase 4): SAFE and generic AMBIGUOUS both take
    # the silent empty-object fast path with ZERO subprocess, zero heavy
    # import, and zero private-state I/O. Only CANDIDATE mutations and the
    # candidate-high-risk runner envelope (STATE_AMBIGUOUS_CANDIDATE)
    # delegate to the heavy core, which alone may read the profile and
    # lock private state.
    pre_state = classify_pre_tool_state(
        proto_event.payload.tool_name, proto_event.payload.tool_input
    )
    if pre_state in {STATE_SAFE, STATE_AMBIGUOUS}:
        print("{}")
        return

    # Delegate the ORIGINAL stdin bytes to the heavy core for candidate
    # authorization (state I/O, tickets, profile decisions).
    _delegate(raw)


if __name__ == "__main__":
    main()
