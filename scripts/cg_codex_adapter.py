"""Codex Hook adapter: converts Codex-specific hook payloads into
protocol-semantic events. This module owns the Codex-payload → protocol
translation for the production router (cg_hook.py). The heavy core
(context_guard.py) still parses the original Codex wire JSON directly
for wire compatibility; routing the core through this adapter instead is
a later-phase target and must not be described as current behavior.

Dependency direction (strictly one-way):
    cg_protocol  ←  cg_codex_adapter  ←  cg_hook.py (production entry)
Import-poison tests enforce this boundary.
"""

from __future__ import annotations

from cg_protocol import (
    ProtocolEvent,
    ProtocolEventType,
    ProtocolPrompt,
    ProtocolSession,
    ProtocolSessionEvent,
    ProtocolToolCall,
    ProtocolToolResult,
)

_HOOK_EVENT_MAP = {
    "UserPromptSubmit": ProtocolEventType.PROMPT_SUBMITTED,
    "PreToolUse": ProtocolEventType.TOOL_PRE_EXECUTE,
    "PostToolUse": ProtocolEventType.TOOL_POST_EXECUTE,
    "PreCompact": ProtocolEventType.COMPACTION_REQUESTED,
    "SessionStart": ProtocolEventType.SESSION_STARTED,
    "SessionEnd": ProtocolEventType.SESSION_ENDED,
    "SubagentStart": ProtocolEventType.AGENT_DELEGATION_START,
    "SubagentStop": ProtocolEventType.AGENT_DELEGATION_END,
    "Stop": ProtocolEventType.TURN_END,
}


def _parse_session(payload: dict) -> ProtocolSession:
    return ProtocolSession(
        session_id=str(payload.get("session_id") or "unknown-session"),
        cwd=str(payload.get("cwd") or ""),
        turn_id=str(payload.get("turn_id") or ""),
    )


def codex_to_protocol_event(payload: dict) -> ProtocolEvent | None:
    """Convert a Codex Hook payload into a normalized ProtocolEvent.
    Returns None if the payload is malformed or unrecognized."""
    if not isinstance(payload, dict):
        return None
    raw_event = str(payload.get("hook_event_name") or "")
    event_type = _HOOK_EVENT_MAP.get(raw_event)
    if event_type is None:
        return None
    session = _parse_session(payload)

    if event_type == ProtocolEventType.PROMPT_SUBMITTED:
        return ProtocolEvent(
            event_type=event_type, session=session,
            payload=ProtocolPrompt(
                session=session,
                text=str(payload.get("prompt") or ""),
                origin="root_user",
                authority="root_instruction",
            ),
        )
    if event_type == ProtocolEventType.TOOL_PRE_EXECUTE:
        return ProtocolEvent(
            event_type=event_type, session=session,
            payload=ProtocolToolCall(
                session=session,
                tool_name=str(payload.get("tool_name") or ""),
                tool_input=payload.get("tool_input") or {},
            ),
        )
    if event_type == ProtocolEventType.TOOL_POST_EXECUTE:
        response = payload.get("tool_response")
        exit_code = response.get("exit_code") if isinstance(response, dict) else None
        return ProtocolEvent(
            event_type=event_type, session=session,
            payload=ProtocolToolResult(
                session=session,
                tool_name=str(payload.get("tool_name") or ""),
                tool_input=payload.get("tool_input") or {},
                tool_response=response,
                exit_code=exit_code if isinstance(exit_code, int) else None,
                outcome="success" if exit_code == 0 else "failure" if isinstance(exit_code, int) else "unknown",
            ),
        )
    return ProtocolEvent(
        event_type=event_type, session=session,
        payload=ProtocolSessionEvent(session=session, event_type=event_type),
    )
