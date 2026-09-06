"""Minimal versioned release-facts adapter for Context Guard 0.12.

The frozen plan (section 4.4, INV-07) keeps ``repository-release`` as the
owner of the release contract: Context Guard only EXECUTES the facts an
adopted contract carries. This module is that execution boundary and
nothing more — a single versioned schema (“release-adapter/v1”) that reads
candidate-closure, publication-readiness, and one-shot ``action-ticket/v1``
facts from the private execution ledger for the ``release`` profile.

Boundaries:
  * stdlib-only, no heavy imports, no workflow text, no policy prose;
  * called ONLY after a candidate mutation was identified in the release
    profile — the standard/strict/observe/inactive paths never import or
    execute it;
  * file existence, Skill/AGENTS text, or install state can never enable
    the release profile: facts come exclusively from the adopted contract
    records in private state;
  * matching is deterministic on the exact normative identity vector
    (repository, candidate commit, contract revision/hash, semantic
    action, target, surface, input hash, release version, expiry).
"""

from __future__ import annotations

import re
from typing import Any

RELEASE_ADAPTER_SCHEMA = "release-adapter/v1"
TICKET_SCHEMA = "action-ticket/v1"

_SHA256_RE = re.compile(r"[0-9a-f]{40}")


def _active_contract(execution: Any) -> dict[str, Any] | None:
    if not isinstance(execution, dict):
        return None
    contract = execution.get("contract")
    if isinstance(contract, dict) and contract.get("state") == "active":
        return contract
    return None


def release_facts(state: dict[str, Any], action: dict[str, str]) -> dict[str, Any]:
    """Read the versioned release facts for one candidate action.

    Returns a closed-world record: schema identity, the active contract
    revision/hash (or None), whether the action carries a ticket whose
    candidate-closure and publication-readiness facts passed, and the
    matching ticket record when one exists. No field of this record is
    influenced by anything outside the adopted contract ledger.
    """
    execution = state.get("execution")
    contract = _active_contract(execution)
    facts: dict[str, Any] = {
        "schema": RELEASE_ADAPTER_SCHEMA,
        "ticket_schema": TICKET_SCHEMA,
        "contract_active": contract is not None,
        "contract_revision": contract.get("revision") if contract else None,
        "ticket_matched": False,
        "ticket": None,
        "reason": None,
    }
    if contract is None:
        facts["reason"] = "no_adopted_release_contract"
        return facts
    ticket = match_action_ticket(execution, action)
    if ticket is None:
        facts["reason"] = "no_exact_unexpired_action_ticket"
        return facts
    facts["ticket_matched"] = True
    facts["ticket"] = ticket
    return facts


def match_action_ticket(
    execution: Any, action: dict[str, str], now: str | None = None
) -> dict[str, Any] | None:
    """Exact-match one reserved one-shot ticket for the candidate action.

    Deterministic pure matching on the full identity vector; a ticket bound
    to a different candidate commit/contract revision is invalidated in
    place (stale binding can never be replayed). Returns the matched
    ticket record or None.
    """
    if not isinstance(execution, dict):
        return None
    if not _SHA256_RE.fullmatch(str(action.get("candidate_commit", ""))):
        return None
    contract = _active_contract(execution)
    if contract is None:
        return None
    tickets = execution.get("action_tickets")
    if not isinstance(tickets, list):
        return None
    for ticket in tickets:
        if not isinstance(ticket, dict) or ticket.get("state") != "reserved":
            continue
        if (
            ticket.get("repository_id") == action["repository_id"]
            and (
                ticket.get("candidate_commit") != action["candidate_commit"]
                or ticket.get("contract_revision") != contract.get("revision")
                or ticket.get("contract_sha256") != contract.get("canonical_sha256")
            )
        ):
            ticket["state"] = "invalidated"
            if now is not None:
                ticket["settled_at"] = now
            continue
        exact = (
            ticket.get("ticket_schema") == TICKET_SCHEMA
            and ticket.get("contract_revision") == contract.get("revision")
            and ticket.get("contract_sha256") == contract.get("canonical_sha256")
            and ticket.get("semantic_action_id") == action["semantic_action_id"]
            and ticket.get("canonical_target_id") == action["canonical_target_id"]
            and ticket.get("write_surface_id") == action["write_surface_id"]
            and ticket.get("repository_id") == action["repository_id"]
            and ticket.get("candidate_commit") == action["candidate_commit"]
            and (
                action["release_version"] == "unresolved"
                or ticket.get("release_version") == action["release_version"]
            )
            and ticket.get("input_sha256") == action["input_sha256"]
        )
        if exact:
            return ticket
    return None


def reserve_ticket(
    ticket: dict[str, Any], tool_use_id: str, now: str
) -> None:
    """Move a matched one-shot ticket into ``in_flight`` for this tool use.

    The reservation is the only mutation this adapter performs; settlement
    (consumed/reserved/invalidated on success/failure/ambiguity) stays in
    the heavy core's PostToolUse path, and the ticket can never be reserved
    twice — the second attempt finds no ``reserved`` ticket and fails
    closed.
    """
    ticket["state"] = "in_flight"
    ticket["tool_use_id"] = tool_use_id
    ticket["attempt_count"] = int(ticket.get("attempt_count") or 0) + 1
    ticket["reserved_at"] = now
