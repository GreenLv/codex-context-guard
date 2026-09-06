"""Structured authorization contract for Context Guard 0.12 (pure layer).

0.12.0 product requirement (root-user authorization UX): authorization is
user-invisible and one-shot. When the root user states a semantic action in
the current work unit — commit, commit-and-push, tag, create/publish a
Release — that statement authorizes the semantic action. The user never has
to restate low-level implementation parameters (remote, branch, commit SHA,
tag target); the repository, current branch/upstream, verified commit,
planned version, and candidate identity are resolved by the agent/runtime
from the current UNIQUE structured task state and bound internally before
execution. Security comes from structured target resolution, uniqueness,
and drift detection — never from re-asking a cooperative user.

Normative target identity (P1-C): every action requires the identity
fields that make its target precise (see ``ACTION_REQUIRED_FIELDS``).
Candidates are normalized onto exactly those fields; a candidate missing a
required field leaves the binding ``target_undetermined``; candidates that
differ in ANY normative field are never collapsed into one; and evaluation
checks the binding against the CURRENT work unit and an authorization
generation, so a binding cannot be replayed from another unit or after it
expired. Combined with drift comparison this is the fail-closed core of
the authorization UX.

Decision ladder (deterministic, pure):
  * ``authorized_unique``     — one reasonable candidate target, action
    within the authorized semantics, same work unit, live generation, no
    drift: proceed without asking (even for tag/Release);
  * ``requires_selection``    — more than one reasonable candidate, or the
    target cannot be determined: ask once, naming the structured options;
  * ``authorization_invalid`` — cross-unit replay, an expired generation,
    a binding that itself lacks its context fields, or a caller omitting
    the mandatory validity facts: fail closed, nothing is evaluated;
  * ``drifted``               — the resolved current target no longer
    matches the bound target: re-bind before executing;
  * ``out_of_scope``          — the requested action is not among the
    authorized semantics (for example force-push after "commit and push").

This module is the structured authorization contract. Since Phase 4 the
PreToolUse standard-profile enforcement consumes it (binding one-statement
work-unit authorizations and evaluating concrete classifier actions); the
release/ticket ceremony stays behind the versioned repository-release
adapter. Nothing in this file performs shell commands, network calls, or
state I/O. The same canonical input always yields the same decision
(INV-11).
"""

from __future__ import annotations

# Semantic action ids (stable contract identifiers, not shell tokens).
ACTION_COMMIT = "commit"
ACTION_PUSH = "push"
ACTION_TAG = "tag"
ACTION_RELEASE = "release"
# Phase 4 vocabulary: precise external-mutation actions that must each be
# matched exactly (never implied by a broader statement).
ACTION_FORCE_PUSH = "force_push"
ACTION_TAG_PUSH = "tag_push"
ACTION_REMOTE_BRANCH_DELETE = "remote_branch_delete"
ACTION_RELEASE_DELETE = "release_delete"
ACTION_PUBLISH = "publish"
# Reverse/registry-maintenance mutations: NEVER implied by a publish
# statement — each is its own exact semantic (frozen plan section 4.4:
# package identity mutations need the exact action and target).
ACTION_UNPUBLISH = "unpublish"
ACTION_YANK = "yank"
ACTION_DEPRECATE = "deprecate"

# Actions implicitly covered by a broader authorized semantic ("提交并推送"
# authorizes both; pushing a tag implies creating it). Publish implies
# nothing: unpublish/yank/deprecate each need their own statement.
IMPLIED_ACTIONS = {
    ACTION_PUSH: frozenset({ACTION_COMMIT}),
    ACTION_TAG_PUSH: frozenset({ACTION_TAG}),
}

# Normative identity fields per action (P1-C): exactly the fields whose
# values make the action's target precise. Bindings and evaluations are
# normalized onto these; anything absent is undetermined, anything
# differing is a distinct candidate or a drift.
ACTION_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    ACTION_COMMIT: ("repository", "ref", "commit_sha256"),
    ACTION_PUSH: ("repository", "remote", "ref", "commit_sha256"),
    ACTION_TAG: ("repository", "ref", "commit_sha256", "tag"),
    ACTION_RELEASE: ("repository", "commit_sha256", "release_version"),
    ACTION_FORCE_PUSH: ("repository", "remote", "ref", "commit_sha256"),
    ACTION_TAG_PUSH: ("repository", "remote", "tag"),
    ACTION_REMOTE_BRANCH_DELETE: ("repository", "remote", "ref"),
    ACTION_RELEASE_DELETE: ("repository", "release_version"),
    # Registry identity: operation rides on the action id; the target pins
    # ecosystem/tool + exact package + version + effective source.
    ACTION_PUBLISH: ("repository", "tool", "package", "release_version",
                     "source", "registry"),
    ACTION_UNPUBLISH: ("repository", "tool", "package", "release_version",
                       "registry"),
    ACTION_YANK: ("repository", "tool", "package", "release_version",
                  "registry"),
    ACTION_DEPRECATE: ("repository", "tool", "package", "release_version",
                       "registry"),
}
NORMATIVE_FIELDS: frozenset[str] = frozenset(
    field for fields in ACTION_REQUIRED_FIELDS.values() for field in fields
)

STATUS_AUTHORIZED_UNIQUE = "authorized_unique"
STATUS_REQUIRES_SELECTION = "requires_selection"
STATUS_AUTHORIZATION_INVALID = "authorization_invalid"
STATUS_DRIFTED = "drifted"
STATUS_OUT_OF_SCOPE = "out_of_scope"
# Typed pending transition: the binding legitimately lacks a FUTURE value
# (the commit the authorized commit-step will produce). It never evaluates
# as authorized until the caller resolves the pending field with an exact
# value produced by that transition.
STATUS_PENDING_TRANSITION = "pending_transition"

# String sentinels are NEVER exact identity values: unresolved/unknown/all
# comparisons have always been how material drift hid (two unresolved are
# not the same target). Field-level exactness is enforced on every
# normative field, in bind and in evaluate.
SENTINEL_VALUES = frozenset({
    "unknown", "unresolved", "all", "none", "n/a", "na", "null", "any",
    "pending", "todo", "tbd",
})


def is_exact_value(value) -> bool:
    """Field-level exact-value check for normative identity.

    Exact means: a non-bool scalar whose stripped text is non-empty, has no
    newline, and is not a string sentinel (unknown/unresolved/all/...).
    Malformed values (lists, dicts, None, bools) are never exact.
    """
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, int):
        return True
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text or "\n" in text or "\r" in text:
        return False
    return text.lower() not in SENTINEL_VALUES


REASON_NO_BINDING = "no_authorization_binding"
REASON_PENDING_TRANSITION = "authorized_commit_not_completed"
REASON_ACTION_COVERED = "action_within_authorized_semantics"
REASON_ACTION_NOT_COVERED = "action_outside_authorized_semantics"
REASON_UNIQUE_TARGET = "unique_structured_target"
REASON_MULTIPLE_TARGETS = "multiple_reasonable_candidates"
REASON_TARGET_UNDETERMINED = "target_undetermined"
REASON_TARGET_DRIFT = "resolved_target_drifted_from_binding"
REASON_CROSS_UNIT_REPLAY = "cross_work_unit_replay"
REASON_GENERATION_EXPIRED = "authorization_generation_expired"
REASON_MISSING_VALIDITY_FACT = "missing_validity_fact"
REASON_BINDING_CONTEXT_INCOMPLETE = "binding_context_incomplete"
REASON_WORK_UNIT_BINDING_REQUIRED = "work_unit_binding_required"
REASON_GENERATION_BINDING_REQUIRED = "generation_binding_required"


def _covers(bound_actions: frozenset[str], requested: str) -> bool:
    if requested in bound_actions:
        return True
    return any(
        requested in IMPLIED_ACTIONS.get(action, frozenset())
        for action in bound_actions
    )


def _required_fields_for(actions: list[str]) -> tuple[str, ...]:
    fields: list[str] = []
    for action in actions:
        for field in ACTION_REQUIRED_FIELDS.get(action, ()):
            if field not in fields:
                fields.append(field)
    return tuple(fields)


def _normalize_target(target: dict, required: tuple[str, ...]) -> dict | None:
    """Project a candidate onto the required normative fields with
    FIELD-LEVEL EXACT VALUE checks.

    Returns None when any required field is missing, empty, non-scalar, or
    a string sentinel (unknown/unresolved/all/...): such a value is not a
    precise identity, and two sentinels must never compare equal into an
    authorization. Extra unrelated fields are dropped — they are not part
    of the identity and must never widen or narrow uniqueness.
    """
    normalized: dict[str, str] = {}
    for field in required:
        value = target.get(field)
        if not is_exact_value(value):
            return None
        normalized[field] = str(value).strip()
    return normalized


PENDING_TRANSITION_SOURCE = "authorized_commit"


def bind_authorization(
    actions: list[str],
    resolved_targets: list[dict],
    *,
    work_unit_id: str,
    generation: int,
    pending: dict | None = None,
) -> dict:
    """Create the internal authorization binding for the current work unit.

    ``actions`` are the semantic actions the root user authorized ("提交并
    推送" -> ``[commit, push]``). ``resolved_targets`` are the structured
    candidates resolved from the current task state. Every required field
    of every bound action must be present on a candidate for the binding
    to be precise; missing fields yield ``target_undetermined`` (the user
    is never asked to enumerate the fields — the runtime resolves them or
    fails closed). Candidates differing in ANY normative field stay
    distinct: two tag candidates are two candidates, never one.
    ``work_unit_id`` and ``generation`` are mandatory validity facts
    (P1-C2): a call that omits either produces NO executable binding —
    the returned record carries ``authorization_invalid`` and authorizes
    nothing. Evaluation later rejects cross-unit replay and expired
    generations against these facts.
    """
    normalized_actions = sorted({str(action) for action in actions})
    normalized_pending: dict[str, str] = {}
    if pending is not None:
        if not isinstance(pending, dict):
            return {
                "actions": normalized_actions,
                "required_fields": [],
                "work_unit_id": str(work_unit_id) if work_unit_id else None,
                "generation": None,
                "status": STATUS_AUTHORIZATION_INVALID,
                "target": None,
                "reason_code": REASON_WORK_UNIT_BINDING_REQUIRED,
            }
        for field, source in sorted(pending.items()):
            if source != PENDING_TRANSITION_SOURCE:
                return {
                    "actions": normalized_actions,
                    "required_fields": [],
                    "work_unit_id": str(work_unit_id) if work_unit_id else None,
                    "generation": None,
                    "status": STATUS_AUTHORIZATION_INVALID,
                    "target": None,
                    "reason_code": REASON_WORK_UNIT_BINDING_REQUIRED,
                }
            normalized_pending[str(field)] = str(source)
    if not isinstance(work_unit_id, str) or not work_unit_id.strip():
        return {
            "actions": normalized_actions,
            "required_fields": [],
            "work_unit_id": None,
            "generation": None,
            "status": STATUS_AUTHORIZATION_INVALID,
            "target": None,
            "reason_code": REASON_WORK_UNIT_BINDING_REQUIRED,
        }
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
        return {
            "actions": normalized_actions,
            "required_fields": [],
            "work_unit_id": str(work_unit_id),
            "generation": None,
            "status": STATUS_AUTHORIZATION_INVALID,
            "target": None,
            "reason_code": REASON_GENERATION_BINDING_REQUIRED,
        }
    required = _required_fields_for(normalized_actions)
    # Typed pending fields are the ONLY legitimate absence: the value will
    # be produced by the named transition (e.g. the authorized commit).
    # Everything else must be exact at bind time.
    exact_required = tuple(
        field for field in required if field not in normalized_pending
    )
    binding: dict = {
        "actions": normalized_actions,
        "required_fields": list(required),
        "work_unit_id": work_unit_id,
        "generation": generation,
    }
    if normalized_pending:
        binding["pending"] = dict(normalized_pending)
    entries = [item for item in (resolved_targets or []) if isinstance(item, dict)]
    normalized: list[dict] = []
    incomplete = not exact_required and not normalized_pending
    if not exact_required and normalized_pending:
        # Every required field is pending: degenerate, reject.
        incomplete = True
    for item in entries:
        projected = _normalize_target(item, exact_required)
        if projected is None:
            # A candidate without a precise normative identity leaves the
            # target undetermined: never guess which fields were meant.
            incomplete = True
            break
        if projected not in normalized:
            normalized.append(projected)
    if incomplete or not entries or not normalized:
        binding["status"] = STATUS_REQUIRES_SELECTION
        binding["target"] = None
        binding["reason_code"] = REASON_TARGET_UNDETERMINED
        return binding
    if len(normalized) == 1:
        if normalized_pending:
            binding["status"] = STATUS_PENDING_TRANSITION
            binding["target"] = normalized[0]
            binding["reason_code"] = REASON_PENDING_TRANSITION
        else:
            binding["status"] = STATUS_AUTHORIZED_UNIQUE
            binding["target"] = normalized[0]
    else:
        binding["status"] = STATUS_REQUIRES_SELECTION
        binding["target"] = None
        binding["candidates"] = normalized
        binding["reason_code"] = REASON_MULTIPLE_TARGETS
    return binding


def evaluate_action_authorization(
    requested_action: str,
    authorization: dict | None,
    resolved_targets: list[dict],
    *,
    current_work_unit_id: str,
    authorization_generation: int,
    action_flags: frozenset[str] | set[str] = frozenset(),
    resolved_pending: dict | None = None,
) -> dict:
    """Decide whether a concrete action may proceed without asking.

    ``action_flags`` carry structured qualifiers from the classifier (for
    example ``force`` on a push); a qualifier that changes the semantics
    beyond the authorized class is out of scope. ``current_work_unit_id``
    and ``authorization_generation`` are MANDATORY validity facts
    (P1-C2): omitting either fails closed with a single stable reason —
    authorization is never evaluated without its context. A binding from
    another work unit, an expired generation, or a binding that itself
    lacks the context fields fails closed as ``authorization_invalid``.
    Resolved current targets are compared to the bound target on the full
    normative vector; any difference is drift.
    """
    requested = str(requested_action)
    if (
        not isinstance(current_work_unit_id, str)
        or not current_work_unit_id.strip()
        or not isinstance(authorization_generation, int)
        or isinstance(authorization_generation, bool)
        or authorization_generation < 0
    ):
        return {
            "status": STATUS_AUTHORIZATION_INVALID,
            "ask_user": True,
            "reason_code": REASON_MISSING_VALIDITY_FACT,
            "target": None,
        }
    if not authorization or not isinstance(authorization, dict):
        return {
            "status": STATUS_OUT_OF_SCOPE,
            "ask_user": True,
            "reason_code": REASON_NO_BINDING,
            "target": None,
        }
    if not _covers(frozenset(authorization.get("actions", [])), requested):
        return {
            "status": STATUS_OUT_OF_SCOPE,
            "ask_user": True,
            "reason_code": REASON_ACTION_NOT_COVERED,
            "target": None,
        }
    binding_unit = authorization.get("work_unit_id")
    binding_generation = authorization.get("generation")
    if not isinstance(binding_unit, str) or not binding_unit.strip() or (
        not isinstance(binding_generation, int)
        or isinstance(binding_generation, bool)
    ):
        return {
            "status": STATUS_AUTHORIZATION_INVALID,
            "ask_user": True,
            "reason_code": REASON_BINDING_CONTEXT_INCOMPLETE,
            "target": None,
        }
    if binding_unit != current_work_unit_id:
        return {
            "status": STATUS_AUTHORIZATION_INVALID,
            "ask_user": True,
            "reason_code": REASON_CROSS_UNIT_REPLAY,
            "target": None,
        }
    if binding_generation != authorization_generation:
        return {
            "status": STATUS_AUTHORIZATION_INVALID,
            "ask_user": True,
            "reason_code": REASON_GENERATION_EXPIRED,
            "target": None,
        }
    if authorization.get("status") == STATUS_REQUIRES_SELECTION:
        return {
            "status": STATUS_REQUIRES_SELECTION,
            "ask_user": True,
            "reason_code": str(
                authorization.get("reason_code") or REASON_MULTIPLE_TARGETS
            ),
            "target": None,
        }
    pending_fields = {
        str(field): str(source)
        for field, source in (authorization.get("pending") or {}).items()
    }
    resolved_pending_values: dict[str, str] = {}
    if pending_fields:
        supplied = resolved_pending or {}
        for field in pending_fields:
            value = supplied.get(field)
            if not is_exact_value(value):
                # The typed transition has not produced its exact value yet;
                # a sentinel can never stand in for it.
                return {
                    "status": STATUS_PENDING_TRANSITION,
                    "ask_user": True,
                    "reason_code": REASON_PENDING_TRANSITION,
                    "target": None,
                }
            resolved_pending_values[field] = str(value).strip()
    elif resolved_pending:
        # A caller may not invent pending resolutions for a binding that
        # declared none: ignore-with-intent is a replay vector.
        resolved_pending_values = {}
    if action_flags:
        # A qualifier outside the authorized semantic class (force-push,
        # target rewrite, yank) is a scope boundary even when the base
        # action is authorized.
        return {
            "status": STATUS_OUT_OF_SCOPE,
            "ask_user": True,
            "reason_code": REASON_ACTION_NOT_COVERED,
            "target": authorization.get("target"),
        }
    required = _required_fields_for([requested])
    resolved: list[dict] = []
    for item in resolved_targets or []:
        if not isinstance(item, dict):
            continue
        projected = _normalize_target(item, required)
        if projected is not None and projected not in resolved:
            resolved.append(projected)
    if not resolved and required:
        return {
            "status": STATUS_REQUIRES_SELECTION,
            "ask_user": True,
            "reason_code": REASON_TARGET_UNDETERMINED,
            "target": None,
        }
    incomplete = any(
        isinstance(item, dict) and _normalize_target(item, required) is None
        for item in (resolved_targets or [])
    )
    bound = authorization.get("target") or {}
    if len(resolved) == 1 and not incomplete:
        # Drift is judged on the requested action's normative fields: a
        # field bound for a sibling action (a tag on a push binding) that
        # the current resolution does not carry is not drift.
        comparison_fields = sorted(required)
        current = {
            field: resolved[0].get(field, "") for field in comparison_fields
        }
        expected = {field: str(bound.get(field, "")) for field in comparison_fields}
        # The typed pending dimension: EXPECTED comes from the transition's
        # resolved exact value; CURRENT stays whatever the execution
        # actually resolved, so post-transition movement still reads as
        # drift. Sentinels never stand in on either side.
        for field, value in resolved_pending_values.items():
            if field in expected:
                expected[field] = value
        if current == expected:
            return {
                "status": STATUS_AUTHORIZED_UNIQUE,
                "ask_user": False,
                "reason_code": REASON_ACTION_COVERED,
                "target": bound,
            }
        return {
            "status": STATUS_DRIFTED,
            "ask_user": True,
            "reason_code": REASON_TARGET_DRIFT,
            "target": resolved[0],
        }
    if len(resolved) != 1 or incomplete:
        reason = (
            REASON_MULTIPLE_TARGETS
            if len(resolved) > 1
            else REASON_TARGET_UNDETERMINED
        )
        return {
            "status": STATUS_REQUIRES_SELECTION,
            "ask_user": True,
            "reason_code": reason,
            "target": None,
        }
    return {
        "status": STATUS_DRIFTED,
        "ask_user": True,
        "reason_code": REASON_TARGET_DRIFT,
        "target": None,
    }
