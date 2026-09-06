"""Protocol-semantic data model for Context Guard 0.12.

Model/agent-agnostic baseline: protocol semantics live here, separate from
any specific Hook adapter (the Codex mapping is isolated in
cg_codex_adapter; DSH aligns to the same protocol).

What this module ACTUALLY defines in 0.12 (no more, no less):
  * ProtocolSession — normalized session identity;
  * ProtocolToolCall / ProtocolToolResult — normalized tool invocations
    and responses;
  * ProtocolPrompt — normalized user prompt;
  * ProtocolSessionEvent — session lifecycle events;
  * ProtocolEvent — the top-level typed event envelope;
  * ProtocolEventType — stable wire-value event-type constants.

It does NOT yet model work-unit lifecycle, proof/evidence binding,
completion/authorization policy, or recovery. Wiring the heavy core
(context_guard.py) to this protocol is Phase 3 scope; until that lands,
the heavy core consumes the original Codex wire JSON directly and
cg_protocol is consumed only by the production router pair
(cg_codex_adapter ← cg_hook.py). No later version or model generation
is in scope for 0.12.

Dependency direction (strictly one-way):
    cg_protocol  ←  cg_codex_adapter  ←  cg_hook.py (production entry)

This module MUST NOT import cg_codex_adapter, context_guard, cg_ledger,
cg_actions, or cg_release_policy. Import-poison tests enforce this. It
also imports NOTHING at all — not even stdlib — because the Hook hot
path runs under `python -S` with a p95 budget; records are minimal
__slots__ classes instead of dataclasses, and event types are stable
string constants instead of enum members. Phase 3 may formalize these
into richer types without changing the wire values.
"""

from __future__ import annotations


class ProtocolEventType:
    """Stable event-type constants (wire values, not enum members)."""

    PROMPT_SUBMITTED = "prompt_submitted"
    TOOL_PRE_EXECUTE = "tool_pre_execute"
    TOOL_POST_EXECUTE = "tool_post_execute"
    COMPACTION_REQUESTED = "compaction_requested"
    SESSION_STARTED = "session_started"
    SESSION_ENDED = "session_ended"
    AGENT_DELEGATION_START = "agent_delegation_start"
    AGENT_DELEGATION_END = "agent_delegation_end"
    TURN_END = "turn_end"


class _ProtocolRecord:
    """Minimal keyword-only record: __slots__, value equality, repr.

    Keyword-only init with required-field enforcement replaces
    @dataclass(frozen=True) at a fraction of the import cost. Instances
    keep default object identity hashing; no frozen enforcement.
    """

    __slots__ = ()
    _fields: tuple = ()
    _defaults: dict = {}

    def __init__(self, **kwargs):
        cls = type(self)
        missing = [name for name in self._fields if name not in kwargs
                   and name not in self._defaults]
        extra = [name for name in kwargs
                 if name not in self._fields]
        if missing or extra:
            raise TypeError(
                f"{cls.__name__} got missing={missing}, extra={extra}"
            )
        for name in self._fields:
            if name in kwargs:
                setattr(self, name, kwargs[name])
            else:
                setattr(self, name, self._defaults[name]())

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return all(
            getattr(self, name) == getattr(other, name)
            for name in self._fields
        )

    def __repr__(self):
        inner = ", ".join(
            f"{name}={getattr(self, name)!r}" for name in self._fields
        )
        return f"{type(self).__name__}({inner})"


class ProtocolSession(_ProtocolRecord):
    """Normalized session identity."""

    __slots__ = ("session_id", "cwd", "turn_id")
    _fields = __slots__


class ProtocolToolCall(_ProtocolRecord):
    """Normalized tool invocation (pre-execute)."""

    __slots__ = ("session", "tool_name", "tool_input")
    _fields = __slots__


class ProtocolToolResult(_ProtocolRecord):
    """Normalized tool result (post-execute)."""

    __slots__ = ("session", "tool_name", "tool_input", "tool_response",
                 "exit_code", "outcome")
    _fields = __slots__


class ProtocolPrompt(_ProtocolRecord):
    """Normalized user prompt submission."""

    __slots__ = ("session", "text", "origin", "authority")
    _fields = __slots__


class ProtocolSessionEvent(_ProtocolRecord):
    """Normalized session lifecycle event."""

    __slots__ = ("session", "event_type", "detail")
    _fields = __slots__
    _defaults = {"detail": dict}


class ProtocolEvent(_ProtocolRecord):
    """Top-level normalized event envelope."""

    __slots__ = ("event_type", "session", "payload")
    _fields = __slots__
