"""Stop lifecycle decision semantics for Context Guard.

Since 0.13.0 the heavy core stamps ``STOP_PROTOCOL_VERSION = "4.0.0"`` on
its decisions; this module remains the model-agnostic decision ladder that
protocol version consumes (waiting-owner resolution, outcome planning,
obligation/proof matching, bounded feedback). Its historical constants
(``SCHEMA_VERSION_10``, ``WORK_UNIT_PROTOCOL_VERSION_2``) keep their frozen
values because they describe schema-9/10 migration inputs, not the current
ledger. Original scope note: Stop protocol 3.0 and schema-10 lifecycle
semantics for Context Guard.

Protocol-semantic, model-agnostic module (frozen plan section 4.2/4.3).
The Codex Hook wire mapping stays isolated in cg_codex_adapter; this module
owns the protocol layer the heavy core (context_guard.py) actually consumes
on its production Stop/migration/post-tool paths. The Phase-2 router fast
path (cg_hook/cg_actions) never imports this module, so the hook hot path
and its import graph are unchanged.

Everything here is a pure function over explicit inputs: no state I/O, no
clock reads, no environment access. Identity is constructed only from
bounded structured fields — never from adjacent prompt text, log bodies,
error text, or concatenated free text (INV-11). The same canonical input
yields exactly one stable reason code.

Dependency direction (strictly one-way):
    cg_protocol  <-  cg_stop3  <-  context_guard.py (lazy, heavy path only)

Phase 3 scope only: work-unit lifecycle states, the schema 9 -> 10 unit
migration map, canonical subject-readback adapter identity, the structured
waiting-owner ladder and outcome planner, the side-effect-free
obligation/proof matcher, and the bounded Stop feedback / per-turn visible
interruption budget. Profile activation (Phase 4), hook visibility (Phase
5), and shadow/canary (Phase 6) are out of scope.
"""

from __future__ import annotations

import hashlib
import re

try:  # production path: scripts dir is on sys.path
    from cg_protocol import ProtocolEvent, ProtocolEventType, ProtocolSession
except ImportError:  # direct file load (tests import via file location)
    import os as _os
    import sys as _sys

    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    from cg_protocol import ProtocolEvent, ProtocolEventType, ProtocolSession


# ---------------------------------------------------------------------------
# Versions and budgets
# ---------------------------------------------------------------------------

SCHEMA_VERSION_10 = 10
WORK_UNIT_PROTOCOL_VERSION_2 = "2.0.0"
ADAPTER_REGISTRY_VERSION = "2.0.0"
# INV-04: at most one visible Stop continuation per turn. PreToolUse hard
# denies are unrelated to this budget and never consume it.
VISIBLE_INTERRUPTION_BUDGET = 1
# Plan section 4.3: default Stop feedback is at most 240 characters and
# names only the current unit, one reason, and one next step.
STOP_FEEDBACK_CHAR_LIMIT = 240
# Plan section 7.2: the default status view stays under 4 KiB even for
# 100+ turn sessions.
DEFAULT_STATUS_BYTE_LIMIT = 4096

# ---------------------------------------------------------------------------
# Work-unit lifecycle (schema 10)
# ---------------------------------------------------------------------------

WORK_UNIT_PROTOCOL_V1 = "1.0.0"
# Schema-9 statuses are migrated, never silently kept: a unit is either
# live (active), closed by a verified completion, parked at an explicit
# boundary, archived as unresolvable history, or superseded.
WORK_UNIT_STATUSES = frozenset(
    {
        "active",
        "completed",
        "awaiting_user",
        "awaiting_external",
        "deferred",
        "historical_unresolved",
        "superseded",
    }
)
SCHEMA9_WORK_UNIT_STATUSES = frozenset({"active", "passed", "superseded"})
# Units a parked task can be resumed from; historical_unresolved stays
# auditable and is only reopened through the same explicit-resume policy.
RESUMABLE_UNIT_STATUSES = frozenset(
    {"awaiting_user", "awaiting_external", "deferred", "historical_unresolved"}
)
# Waiting units whose owner is a boundary the user can resolve by naming
# the unit; historical chains never auto-reopen on a tie.
WAITING_UNIT_STATUSES = frozenset({"awaiting_user", "awaiting_external"})

UNIT_STATUS_TO_SCHEMA9 = {
    "active": "active",
    "completed": "passed",
    "superseded": "superseded",
}


def migrate_work_units_to_schema10(
    units: list[dict],
    active_work_unit_id: str | None,
    *,
    now: str,
    placeholder_scope_sha256: str,
) -> tuple[list[dict], str | None, dict]:
    """Normalize schema-9 unit records into schema-10 lifecycle records.

    Frozen-plan contract (section 4.2, fixtures in the immutable Phase-1
    baseline): old active parent chains are never marked pass. The current
    active root stays active; every other still-active unit — chain
    ancestors and abandoned siblings alike — becomes
    ``historical_unresolved`` and leaves the default completion gate while
    staying auditable. ``passed`` becomes ``completed``. Waiting candidates
    get ``resume_pending_reopen`` only when their persisted
    ``last_active_seq`` has a unique maximum; missing or tied sequence
    numbers keep every candidate pending explicit selection (no wall-clock,
    array-order, or similarity guessing).

    Records are completed with deterministic defaults so a minimal
    migration fixture yields a valid schema-10 ledger. Returns
    ``(units, active_id, audit)``.
    """
    normalized: list[dict] = []
    ids_in_order: list[str] = []
    for raw in units:
        record = dict(raw) if isinstance(raw, dict) else {}
        unit_id = str(record.get("id") or "")
        if not unit_id:
            continue
        ids_in_order.append(unit_id)
        status = str(record.get("status") or "active")
        if status == "passed":
            status = "completed"
        record["id"] = unit_id
        record["protocol_version"] = WORK_UNIT_PROTOCOL_VERSION_2
        record["parent_id"] = record.get("parent_id")
        record["kind"] = str(record.get("kind") or "general")
        record["status"] = status
        record.setdefault("created_at", now)
        record.setdefault("closed_at", None)
        seq = record.get("last_active_seq")
        record["last_active_seq"] = int(seq) if isinstance(seq, int) else None
        record.setdefault("scope_sha256", placeholder_scope_sha256)
        normalized.append(record)

    by_id = {record["id"]: record for record in normalized}

    active_id = active_work_unit_id if active_work_unit_id in by_id else None
    historical: list[str] = []
    for record in normalized:
        if record["status"] != "active":
            continue
        if active_id is not None and record["id"] == active_id:
            continue
        record["status"] = "historical_unresolved"
        record["closed_at"] = record.get("closed_at") or now
        historical.append(record["id"])

    candidates = [
        record
        for record in normalized
        if record["status"] in WAITING_UNIT_STATUSES
    ]
    seqs = [
        record["last_active_seq"]
        for record in candidates
        if isinstance(record["last_active_seq"], int)
    ]
    # A missing sequence number on any candidate makes the comparison
    # undefined: never guess from wall clock, array order, or similarity.
    unique_max = None
    if candidates and len(seqs) == len(candidates):
        top = max(seqs)
        if sum(1 for value in seqs if value == top) == 1:
            unique_max = top
    resume_reopen: str | None = None
    for record in candidates:
        if (
            unique_max is not None
            and record["last_active_seq"] == unique_max
        ):
            record["resume_pending_reopen"] = True
            resume_reopen = record["id"]
        else:
            record.pop("resume_pending_reopen", None)
    audit = {
        "historical_unresolved": historical,
        "resume_reopen": resume_reopen,
        "resume_requires_selection": bool(candidates) and resume_reopen is None,
    }
    return normalized, active_id, audit


# ---------------------------------------------------------------------------
# Explicit resume intent (plan section 4.2: bounded, deterministic signal)
# ---------------------------------------------------------------------------

RESUME_INTENT_RE = re.compile(
    r"^\s*(?:请)?(?:继续|恢复)(?:刚才|之前|先前|上次|上面|前面|旧|原|那个|该)?"
    r"(?:的)?(?:任务|工作|话题|事项)|"
    r"^\s*继续\b|^\s*恢复\s+\S+|^\s*continue\s*$|"
    r"\b(?:continue|resume)\s+(?:the\s+)?(?:previous|prior|old|unfinished|"
    r"suspended)\s+(?:task|work|topic)\b",
    re.IGNORECASE,
)


def has_explicit_resume_intent(text: str) -> bool:
    """True only for an explicit user request to resume a previous task.

    Ordinary new prompts never match; the match is anchored to the start of
    the authoritative prompt so a passing mention of "继续" cannot reopen a
    parked unit.
    """
    if not text or len(text) > 400:
        return False
    return RESUME_INTENT_RE.search(text.strip()) is not None


# ---------------------------------------------------------------------------
# Canonical subject-readback adapter identity (frozen plan INV-11 / CGP-P1-06)
# ---------------------------------------------------------------------------

IDENTITY_CANONICAL = "canonical"
IDENTITY_TRUSTED_SHORT = "trusted_short"
IDENTITY_AMBIGUOUS = "adapter_identity_ambiguous"
IDENTITY_UNREGISTERED = "unregistered"

# Closed-world registry (frozen plan section 4.4 / INV-11): the fully
# qualified MCP tool name is the canonical key, enumerated explicitly below
# (trusted_namespaces x trusted_short_names, expanded once at import). A
# bare name binds only when it is an explicitly registered short name.
# Nothing matches by suffix, substring, or wildcard: an unregistered name
# never binds, and a registered short name under an unknown namespace stays
# adapter_identity_ambiguous - its evidence may be recorded but it can
# never satisfy a proof obligation.
ADAPTER_REGISTRY: dict[str, dict] = {
    "thread_read": {
        "trusted_namespaces": frozenset({"codex_app"}),
        "trusted_short_names": frozenset({"read_thread"}),
        "input_subject_fields": ("threadId", "thread_id", "thread-id"),
    },
    "file_read": {
        "trusted_namespaces": frozenset({"codex_app", "fs", "filesystem"}),
        "trusted_short_names": frozenset(
            {
                "read",
                "read_file",
                "readfile",
                "read_text_file",
                "view",
                "view_file",
                "open_file",
                "cat_file",
                "show_file",
            }
        ),
        "input_subject_fields": (
            "file_path",
            "path",
            "filename",
            "file",
            "notebook_path",
            "target_file",
        ),
    },
}

for _spec in ADAPTER_REGISTRY.values():
    _spec["canonical_tools"] = frozenset(
        f"mcp__{namespace}__{short}"
        for namespace in sorted(_spec["trusted_namespaces"])
        for short in sorted(_spec["trusted_short_names"])
    )

_MCP_TOOL_NAME_RE = re.compile(r"^mcp__([a-z0-9_-]+)__([a-z0-9_-]+)$", re.IGNORECASE)


def adapter_identity(tool_name: str) -> dict:
    """Resolve a tool name against the closed-world adapter registry.

    Returns ``{"adapter", "identity", "namespace", "short_name"}``.
    ``identity`` is one of: ``canonical`` (fully qualified registered
    name), ``trusted_short`` (bare registered short name),
    ``adapter_identity_ambiguous`` (registered short name under an
    unregistered namespace - evidence may be recorded but no readback
    subject may bind), or ``unregistered`` (name absent from the registry;
    never binds under any namespace).
    """
    raw = str(tool_name or "")
    lowered = raw.lower()
    for adapter, spec in ADAPTER_REGISTRY.items():
        if lowered in spec["canonical_tools"]:
            return {
                "adapter": adapter,
                "identity": IDENTITY_CANONICAL,
                "namespace": None,
                "short_name": lowered.rsplit("__", 1)[-1],
            }
    match = _MCP_TOOL_NAME_RE.match(lowered)
    if match is not None:
        namespace, short = match.group(1), match.group(2)
        registered_adapter = next(
            (
                adapter
                for adapter, spec in ADAPTER_REGISTRY.items()
                if short in spec["trusted_short_names"]
            ),
            None,
        )
        if registered_adapter is None:
            return {
                "adapter": None,
                "identity": IDENTITY_UNREGISTERED,
                "namespace": namespace,
                "short_name": short,
            }
        if namespace in ADAPTER_REGISTRY[registered_adapter]["trusted_namespaces"]:
            return {
                "adapter": registered_adapter,
                "identity": IDENTITY_CANONICAL,
                "namespace": namespace,
                "short_name": short,
            }
        return {
            "adapter": registered_adapter,
            "identity": IDENTITY_AMBIGUOUS,
            "namespace": namespace,
            "short_name": short,
        }
    bare = re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")
    for adapter, spec in ADAPTER_REGISTRY.items():
        if bare in spec["trusted_short_names"]:
            return {
                "adapter": adapter,
                "identity": IDENTITY_TRUSTED_SHORT,
                "namespace": None,
                "short_name": bare,
            }
    return {
        "adapter": None,
        "identity": IDENTITY_UNREGISTERED,
        "namespace": None,
        "short_name": bare,
    }


def identity_binds_readback(identity: dict) -> bool:
    """Only canonical and registry-mapped short names may bind subjects."""
    return identity.get("identity") in {IDENTITY_CANONICAL, IDENTITY_TRUSTED_SHORT}


# ---------------------------------------------------------------------------
# Structured waiting-owner ladder (frozen plan section 4.3, CGR1-P2-D)
# ---------------------------------------------------------------------------

OWNER_ASSISTANT = "assistant"
OWNER_USER = "user"
OWNER_EXTERNAL = "external"
OWNER_DEFERRED = "deferred"
OWNER_UNKNOWN = "unknown"

OUTCOME_SILENT_ASSISTANT_PENDING = "silent_end_assistant_pending_actions"
OUTCOME_SINGLE_BOUNDED_CORRECTION = "single_bounded_correction"
OUTCOME_SILENT_YIELD_PRESERVE_PENDING = "silent_yield_preserve_pending"
OUTCOME_SILENT_OWNER_AMBIGUOUS = "silent_end_owner_ambiguous"

OWNER_FACT_KEYS = (
    "whole_completion_claim",
    "explicit_persistence",
    "authorized_assistant_actions_available",
    "missing_user_only_input_or_approval",
    "registered_external_operation",
    "deferred_by_scope_or_authority",
)


def resolve_waiting_owner(facts: dict) -> str:
    """Rank the structured facts of the current unit (fixed ladder).

    Order is authoritative: assistant-actionable work outranks a missing
    user-only input, which outranks a registered external wait, then an
    explicit deferral; anything else is unknown. Reply wording and the last
    tool event never participate.
    """
    if not isinstance(facts, dict):
        return OWNER_UNKNOWN
    if facts.get("authorized_assistant_actions_available"):
        return OWNER_ASSISTANT
    if facts.get("missing_user_only_input_or_approval"):
        return OWNER_USER
    if facts.get("registered_external_operation"):
        return OWNER_EXTERNAL
    if facts.get("deferred_by_scope_or_authority"):
        return OWNER_DEFERRED
    return OWNER_UNKNOWN


def plan_waiting_outcome(
    facts: dict, declared: str | None = None, *, interruption_index: int = 1
) -> str:
    """Map the structured facts to the protocol's terminal action.

    ``assistant`` never masquerades as a waiting disposition: the single
    per-turn continuation fires only when the user demanded persistent
    completion (or the reply wrongly claims whole completion while
    deterministic obligations are pending — that gate is applied by the
    Stop caller, which owns obligation state). Sub-class differences
    between user_wait/external_wait/deferred never continue a turn, and an
    ``unknown`` owner stays silent with ``owner_ambiguous`` recorded.
    """
    del declared  # advisory only; structured facts are authoritative
    owner = resolve_waiting_owner(facts)
    if owner == OWNER_ASSISTANT:
        if facts.get("explicit_persistence") and _budget_allows(interruption_index):
            return OUTCOME_SINGLE_BOUNDED_CORRECTION
        return OUTCOME_SILENT_ASSISTANT_PENDING
    if owner in {OWNER_USER, OWNER_EXTERNAL, OWNER_DEFERRED}:
        return OUTCOME_SILENT_YIELD_PRESERVE_PENDING
    return OUTCOME_SILENT_OWNER_AMBIGUOUS


def _budget_allows(interruption_index: int) -> bool:
    try:
        index = int(interruption_index)
    except (TypeError, ValueError):
        return False
    return 1 <= index <= VISIBLE_INTERRUPTION_BUDGET


# ---------------------------------------------------------------------------
# Side-effect-free obligation/proof matcher (INV-11)
# ---------------------------------------------------------------------------

OUTCOME_FULFILLED = "fulfilled"
OUTCOME_PENDING = "pending"
OUTCOME_INVALID_BINDING = "invalid_binding"

REASON_UNIQUE_DETERMINISTIC_EVIDENCE = "unique_deterministic_evidence"
REASON_EVIDENCE_AMBIGUOUS = "evidence_ambiguous"
REASON_SUBJECT_BINDING_MISSING = "subject_binding_missing"
REASON_CONTRACT_NOT_ENFORCED = "contract_not_enforced"
REASON_OBLIGATION_REQUIRED = "obligation_required"
REASON_UNKNOWN_OBLIGATION = "unknown_obligation"
REASON_ITEM_IDENTITY_CONFLICT = "item_identity_conflict"
REASON_OBLIGATIONS_EMPTY = "empty_enforced_obligations"
REASON_UNKNOWN_OBLIGATION_KIND = "unknown_obligation_kind"
REASON_ILLEGAL_OBLIGATION_SURFACE = "illegal_obligation_surface"
REASON_MALFORMED_SUBJECT_IDS = "malformed_subject_ids"
REASON_MALFORMED_SCOPE_EXPECTATION = "malformed_scope_expectation"
REASON_MALFORMED_EVIDENCE_RECORD = "malformed_evidence_record"
REASON_EVIDENCE_IDENTITY_MISSING = "evidence_identity_missing"
REASON_DUPLICATE_EVIDENCE_IDENTITY = "duplicate_evidence_identity"
REASON_DUPLICATE_OBLIGATION_IDENTITY = "duplicate_obligation_identity"
REASON_MALFORMED_OBLIGATION_RECORD = "malformed_obligation_record"
REASON_UNKNOWN_EVIDENCE_REFERENCE = "unknown_evidence_reference"

# Registered closed-world obligation kinds and their legal surfaces
# (mirrors what the clause-derived contract generator emits and the
# public JSON schema enumerates; the matcher and the runtime
# state-integrity check share this one table).
OBLIGATION_KIND_SURFACES: dict[str, frozenset[str]] = {
    "subject_readback": frozenset({"artifact", "ui"}),
    "result_visual_readback": frozenset({"ui"}),
    "input_asset_inspection": frozenset({"visual"}),
    "scope_coverage": frozenset({"scope"}),
}
OBLIGATION_KINDS = frozenset(OBLIGATION_KIND_SURFACES)
EVIDENCE_OUTCOMES = frozenset({"success", "failed", "unknown"})
SUBJECT_LIST_MAX_ITEMS = 10000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _subject_list_reason(value, *, field: str, allow_empty: bool = False) -> str | None:
    """Ordered validation for a bounded, unique string list.

    Obligation ``subject_ids`` are normative identity: non-empty by
    contract. Evidence ``subject_ids``/``readback_subjects`` describe an
    event and may legitimately be empty — only malformed entries are
    rejected there.
    """
    del field  # kept for call-site symmetry and diagnostics
    if not isinstance(value, list) or len(value) > SUBJECT_LIST_MAX_ITEMS:
        return REASON_MALFORMED_SUBJECT_IDS
    if not allow_empty and not value:
        return REASON_MALFORMED_SUBJECT_IDS
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item:
            return REASON_MALFORMED_SUBJECT_IDS
        if item in seen:
            return REASON_MALFORMED_SUBJECT_IDS
        seen.add(item)
    return None


def obligation_record_reason(obligation) -> str | None:
    """Validate ONE obligation record against the closed world.

    Returns None when the record is well-formed; otherwise a single
    stable reason code. Shared by the pure matcher and the runtime
    state-integrity validation.
    """
    if not isinstance(obligation, dict):
        return REASON_MALFORMED_OBLIGATION_RECORD
    obligation_id = obligation.get("id")
    if not isinstance(obligation_id, str) or not obligation_id:
        return REASON_MALFORMED_OBLIGATION_RECORD
    kind = obligation.get("kind")
    if not isinstance(kind, str) or kind not in OBLIGATION_KINDS:
        return REASON_UNKNOWN_OBLIGATION_KIND
    surface = obligation.get("surface")
    if not isinstance(surface, str) or surface not in OBLIGATION_KIND_SURFACES[kind]:
        return REASON_ILLEGAL_OBLIGATION_SURFACE
    # scope_coverage is the one kind whose subject_ids are legitimately
    # empty: the cardinality-derived scope has no path subjects. Its
    # expectation fields, when present, must still be well-typed; a null
    # digest marks an underivable (fail-closed) expectation, exactly as
    # the clause-derived contract generator emits it.
    subjects_reason = _subject_list_reason(
        obligation.get("subject_ids"),
        field="subject_ids",
        allow_empty=kind == "scope_coverage",
    )
    if subjects_reason is not None:
        return subjects_reason
    if kind == "scope_coverage":
        count = obligation.get("expected_scope_count")
        if count is not None and (
            not isinstance(count, int) or isinstance(count, bool) or count <= 0
        ):
            return REASON_MALFORMED_SCOPE_EXPECTATION
        digest = obligation.get("expected_scope_sha256")
        if digest is not None and (
            not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)
        ):
            return REASON_MALFORMED_SCOPE_EXPECTATION
    return None


def obligations_reason(obligations) -> str | None:
    """Validate an enforced contract's obligation list (non-empty,
    unique ids, every record well-formed). Order-independent."""
    if not isinstance(obligations, list) or not obligations:
        return REASON_OBLIGATIONS_EMPTY
    seen: set[str] = set()
    for obligation in obligations:
        reason = obligation_record_reason(obligation)
        if reason is not None:
            return reason
        obligation_id = str(obligation["id"])
        if obligation_id in seen:
            return REASON_DUPLICATE_OBLIGATION_IDENTITY
        seen.add(obligation_id)
    return None


def evidence_record_reason(entry) -> str | None:
    """Validate ONE evidence record's matcher-facing fields."""
    if not isinstance(entry, dict):
        return REASON_MALFORMED_EVIDENCE_RECORD
    entry_id = entry.get("id")
    if not isinstance(entry_id, str) or not entry_id:
        return REASON_EVIDENCE_IDENTITY_MISSING
    if entry.get("outcome") not in EVIDENCE_OUTCOMES:
        return REASON_MALFORMED_EVIDENCE_RECORD
    for field in ("subject_ids", "readback_subjects"):
        value = entry.get(field)
        if value is None:
            continue
        reason = _subject_list_reason(value, field=field, allow_empty=True)
        if reason is not None:
            return REASON_MALFORMED_EVIDENCE_RECORD
    return None


_MATCHER_RESULT_KEYS = ("outcome", "reason_code", "obligation", "selected_evidence")


def _unique_candidate_cover(
    candidates: list[dict], required: list[str], *, field: str
) -> tuple[list[str], str]:
    """Resolve the evidence cover for one obligation deterministically.

    For every required subject the candidate set is computed from the
    structured binding field only; a subject covered by exactly one
    candidate contributes that evidence to the cover. A subject with no
    candidate is ``subject_binding_missing``; any subject with more than
    one candidate is ``evidence_ambiguous`` — selection between equally
    valid evidence records is never automatic (CGR1-P2-B). For the
    readback field, evidence binding a superset of the required subjects
    is not a unique derivation and is skipped (fail closed), matching the
    production derivation rule.
    """
    if field != "subject_ids":
        candidates = [
            entry
            for entry in candidates
            if not {str(item) for item in entry.get(field, [])} - set(required)
        ]
    chosen: list[str] = []
    for subject in required:
        covering = [
            str(entry["id"])
            for entry in candidates
            if subject in {str(item) for item in entry.get(field, [])}
        ]
        if not covering:
            return [], REASON_SUBJECT_BINDING_MISSING
        if len(covering) > 1:
            return [], REASON_EVIDENCE_AMBIGUOUS
        if covering[0] not in chosen:
            chosen.append(covering[0])
    return sorted(chosen), REASON_UNIQUE_DETERMINISTIC_EVIDENCE


def evaluate_reason(item_id: str, binding: dict, projection: dict) -> dict:
    """Pure matcher: canonical input -> one stable normalized result.

    ``projection`` carries ``{"item": {"id", "verification_contract"},
    "evidence": [...]}`` in the caller's RAW ledger order; canonicalization
    (sorting by stable identifiers) happens here so permutation, repeated
    execution, and concurrent reads all produce byte-identical results.
    ``binding`` is ``{"itemId", "evidenceIds"}`` plus an optional
    ``"obligationId"`` (required when the item carries multiple
    obligations). The result has exactly the keys ``outcome``,
    ``reason_code``, ``obligation``, ``selected_evidence``.

    Item identity (P1-B): ``item_id``, ``binding["itemId"]``, and
    ``projection["item"]["id"]`` must all be present and exactly equal;
    a missing or conflicting identity is a single stable
    ``item_identity_conflict`` invalid binding — the matcher never
    evaluates an obligation against a different item's contract.
    """
    projection_item = projection.get("item") or {}
    projection_item_id = projection_item.get("id")
    binding_item_id = (binding or {}).get("itemId")
    identity_values = {
        "item_id": item_id if item_id is not None else "",
        "itemId": binding_item_id if binding_item_id is not None else "",
        "projection.item.id": (
            projection_item_id if projection_item_id is not None else ""
        ),
    }
    if (
        not all(isinstance(value, str) and value for value in identity_values.values())
        or len(set(identity_values.values())) != 1
    ):
        return {
            "outcome": OUTCOME_INVALID_BINDING,
            "reason_code": REASON_ITEM_IDENTITY_CONFLICT,
            "obligation": "",
            "selected_evidence": [],
        }
    del identity_values

    # Canonical-projection integrity (P1-B2): malformed or ambiguous
    # projections are rejected with order-independent, single stable
    # reasons BEFORE any matching runs, so a projection can never become
    # fulfilled by reordering its records. Duplicate evidence IDs
    # (same-value or conflicting) are rejected outright — the previous
    # dict construction silently let the LAST record win, making the
    # verdict depend on insertion order.
    raw_evidence = projection.get("evidence")
    if not isinstance(raw_evidence, list):
        raw_evidence = []
    evidence: list[dict] = []
    seen_evidence_ids: set[str] = set()
    for entry in raw_evidence:
        entry_id = entry.get("id") if isinstance(entry, dict) else None
        if not isinstance(entry_id, str) or not entry_id:
            return {
                "outcome": OUTCOME_INVALID_BINDING,
                "reason_code": REASON_EVIDENCE_IDENTITY_MISSING,
                "obligation": "",
                "selected_evidence": [],
            }
        if entry_id in seen_evidence_ids:
            return {
                "outcome": OUTCOME_INVALID_BINDING,
                "reason_code": REASON_DUPLICATE_EVIDENCE_IDENTITY,
                "obligation": "",
                "selected_evidence": [],
            }
        seen_evidence_ids.add(entry_id)
        record_reason = evidence_record_reason(entry)
        if record_reason is not None:
            return {
                "outcome": OUTCOME_INVALID_BINDING,
                "reason_code": record_reason,
                "obligation": "",
                "selected_evidence": [],
            }
        evidence.append(dict(entry))
    evidence.sort(key=lambda entry: str(entry["id"]))

    binding_evidence_ids = (binding or {}).get("evidenceIds")
    if not isinstance(binding_evidence_ids, list):
        binding_evidence_ids = []
    binding_ids: list[str] = []
    for value in binding_evidence_ids:
        if not isinstance(value, str) or not value:
            return {
                "outcome": OUTCOME_INVALID_BINDING,
                "reason_code": REASON_EVIDENCE_IDENTITY_MISSING,
                "obligation": "",
                "selected_evidence": [],
            }
        if value in binding_ids:
            return {
                "outcome": OUTCOME_INVALID_BINDING,
                "reason_code": REASON_DUPLICATE_EVIDENCE_IDENTITY,
                "obligation": "",
                "selected_evidence": [],
            }
        binding_ids.append(value)
    binding_ids.sort()
    unknown_reference = next(
        (value for value in binding_ids if value not in seen_evidence_ids), None
    )
    if unknown_reference is not None:
        return {
            "outcome": OUTCOME_INVALID_BINDING,
            "reason_code": REASON_UNKNOWN_EVIDENCE_REFERENCE,
            "obligation": "",
            "selected_evidence": [],
        }

    contract = projection_item.get("verification_contract")
    if not isinstance(contract, dict) or contract.get("mode") != "enforced":
        return {
            "outcome": OUTCOME_INVALID_BINDING,
            "reason_code": REASON_CONTRACT_NOT_ENFORCED,
            "obligation": "",
            "selected_evidence": [],
        }
    # Shared closed-world verification-contract validation (P1-B3): an
    # enforced contract must carry a non-empty set of well-formed,
    # uniquely identified obligations over the registered kind/surface
    # table with non-empty bounded unique subject_ids; scope expectations
    # must be complete. This is the same constraint the runtime
    # state-integrity check applies to persisted contracts.
    raw_obligations = contract.get("obligations", [])
    obligations_reason_code = obligations_reason(raw_obligations)
    if obligations_reason_code is not None:
        return {
            "outcome": OUTCOME_INVALID_BINDING,
            "reason_code": obligations_reason_code,
            "obligation": "",
            "selected_evidence": [],
        }
    obligations = [dict(entry) for entry in raw_obligations]
    wanted = (binding or {}).get("obligationId")
    if wanted is None:
        if len(obligations) == 1:
            wanted = obligations[0]["id"]
        else:
            return {
                "outcome": OUTCOME_INVALID_BINDING,
                "reason_code": REASON_OBLIGATION_REQUIRED,
                "obligation": "",
                "selected_evidence": [],
            }
    wanted = str(wanted)
    obligation = next(
        (entry for entry in obligations if str(entry["id"]) == wanted), None
    )
    if obligation is None:
        return {
            "outcome": OUTCOME_INVALID_BINDING,
            "reason_code": REASON_UNKNOWN_OBLIGATION,
            "obligation": wanted,
            "selected_evidence": [],
        }
    required = sorted(
        {
            str(subject)
            for subject in obligation.get("subject_ids", [])
            if isinstance(subject, str) and subject
        }
    )
    kind = str(obligation.get("kind"))
    surface = str(obligation.get("surface"))
    if kind == "scope_coverage":
        field = "subject_ids"
    else:
        field = (
            "readback_subjects"
            if kind == "subject_readback" and surface == "artifact"
            else "subject_ids"
        )
    # `evidence` and `binding_ids` were canonicalized and integrity-checked
    # above: no duplicates, no unknown references, no ordering influence.
    by_id = {str(entry["id"]): entry for entry in evidence}
    successful = [
        by_id[value] for value in binding_ids if by_id[value].get("outcome") == "success"
    ]
    if kind == "scope_coverage":
        observed = sorted(
            {
                str(subject)
                for entry in successful
                for subject in entry.get("subject_ids", [])
            }
        )
        expected_count = obligation.get("expected_scope_count")
        expected_sha256 = obligation.get("expected_scope_sha256")
        digest = hashlib.sha256(
            json_canonical(observed).encode("utf-8")
        ).hexdigest()
        if (
            isinstance(expected_count, int)
            and len(observed) == expected_count
            and isinstance(expected_sha256, str)
            and digest == expected_sha256
        ):
            selected, reason = _unique_candidate_cover(
                successful, observed, field=field
            )
            outcome = (
                OUTCOME_FULFILLED if reason == REASON_UNIQUE_DETERMINISTIC_EVIDENCE else OUTCOME_PENDING
            )
            return {
                "outcome": outcome,
                "reason_code": reason,
                "obligation": wanted,
                "selected_evidence": selected,
            }
        return {
            "outcome": OUTCOME_PENDING,
            "reason_code": REASON_SUBJECT_BINDING_MISSING,
            "obligation": wanted,
            "selected_evidence": [],
        }
    selected, reason = _unique_candidate_cover(
        successful, required, field=field
    )
    return {
        "outcome": (
            OUTCOME_FULFILLED
            if reason == REASON_UNIQUE_DETERMINISTIC_EVIDENCE
            else OUTCOME_PENDING
        ),
        "reason_code": reason,
        "obligation": wanted,
        "selected_evidence": selected,
    }


def json_canonical(value) -> str:
    """Stable JSON encoding for digests over canonical sorted values."""
    return json_dumps_sorted(value)


def json_dumps_sorted(value) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Bounded Stop feedback and protocol envelopes
# ---------------------------------------------------------------------------

def bounded_stop_feedback(pending_items: int, reason: str, next_step: str) -> str:
    """Compose the default Stop feedback for the CURRENT work unit.

    The default surface is anonymous by contract (Acceptance-D): it names
    only the unit's pending-item COUNT, one reason, and one next step —
    never a work-unit, requirement, acceptance, or evidence ID, and never
    a reason-code token. Those live exclusively in decision_log and the
    diagnose/--full surfaces. Hard-capped at STOP_FEEDBACK_CHAR_LIMIT with
    deterministic truncation.
    """
    try:
        count = max(0, int(pending_items))
    except (TypeError, ValueError):
        count = 0
    if count == 0:
        unit = "current work unit (no unverified items)"
    else:
        unit = (
            f"current work unit ({count} unverified "
            + ("item" if count == 1 else "items")
            + ")"
        )
    template = "Context Guard: {unit}: {reason}. Next: {step}."
    fixed = len(template.format(unit=unit, reason="", step=""))
    room = STOP_FEEDBACK_CHAR_LIMIT - fixed
    if room <= 20:
        reason_text = _truncate(reason, 40)
        step_text = _truncate(next_step, 40)
    else:
        reason_room = max(24, room // 2)
        step_room = max(24, room - reason_room)
        reason_text = _truncate(reason, reason_room)
        step_text = _truncate(next_step, step_room)
    message = template.format(unit=unit, reason=reason_text, step=step_text)
    if len(message) > STOP_FEEDBACK_CHAR_LIMIT:
        keep = STOP_FEEDBACK_CHAR_LIMIT - 1
        message = message[:keep].rstrip() + "…"
    return message


def _truncate(value: str, limit: int) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def stop_decision_event(session_id: str, turn_id: str, decision: dict) -> ProtocolEvent:
    """Wrap a Stop decision in the model-agnostic protocol envelope.

    The heavy production path consumes this so protocol semantics stay in
    cg_protocol/cg_stop3 while the Codex wire mapping stays in
    cg_codex_adapter.
    """
    session = ProtocolSession(
        session_id=str(session_id or "unknown-session"),
        cwd="",
        turn_id=str(turn_id or ""),
    )
    return ProtocolEvent(
        event_type=ProtocolEventType.TURN_END,
        session=session,
        payload=dict(decision),
    )
