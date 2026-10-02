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
    (STATE_AMBIGUOUS_CANDIDATE) run the heavy context_guard.py core in
    this same process (lazy import; one product Python process per event,
    CGN-03) — only those may read/lock private state and consult the
    profile — with the original stdin bytes forwarded untouched, the
    heavy core's stdout JSON and stderr never crossed, and its exit code
    propagated;
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


def _delegate_subprocess(raw_stdin: bytes) -> None:
    """Legacy fallback: run the heavy core in a child process.

    Used only when the in-process import or execution of the heavy core
    fails in this environment. Semantics are identical to the 0.14 router:
    original bytes forwarded untouched, stdout/stderr never crossed, exit
    code propagated, runaway child bounded by a 120s timeout.
    """
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


class _PreReadStdin:
    """Exposes already-consumed hook bytes as ``stdin.buffer``.

    The router must hand the ORIGINAL stdin bytes to the heavy core even
    though it already consumed them for its own classification decision;
    ``command_hook`` tolerates non-file stdin objects (AttributeError
    fallback) and only calls ``.buffer.read()``.
    """

    __slots__ = ("buffer",)

    def __init__(self, raw: bytes) -> None:
        import io  # lazy: the SAFE fast path never delegates

        self.buffer = io.BytesIO(raw)


def _delegate(raw_stdin: bytes) -> None:
    """Run the heavy context_guard.py core in this process.

    Saves the second interpreter start for every non-fast-path event while
    preserving the wire contract: the ORIGINAL stdin bytes are forwarded
    untouched, the heavy core's stdout JSON and stderr stay separated (they
    are the same streams), and the heavy core's exit code becomes this
    process's exit code. The heavy core is stdlib-only, so running it under
    the router's ``-S`` interpreter is equivalent to its previous
    non-``-S`` child. A hard host timeout governs the whole hook either
    way; the child-only 120s bound does not apply in-process and is kept
    only on the subprocess fallback path.
    """
    heavy = os.path.join(_SCRIPT_DIR, "context_guard.py")
    import importlib.util  # lazy: the SAFE fast path never delegates

    try:
        spec = importlib.util.spec_from_file_location("context_guard", heavy)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except BaseException:  # noqa: BLE001 - environment failure keeps old path
        _delegate_subprocess(raw_stdin)
        return
    original_stdin = sys.stdin
    original_argv = sys.argv
    sys.stdin = _PreReadStdin(raw_stdin)  # type: ignore[assignment]
    sys.argv = [heavy, "hook"]
    try:
        code = module.main()
    finally:
        sys.stdin = original_stdin
        sys.argv = original_argv
    sys.stdout.flush()
    sys.exit(code if isinstance(code, int) else 0)


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
