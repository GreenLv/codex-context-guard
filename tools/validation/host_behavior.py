#!/usr/bin/env python3
"""Host-behavior acceptance profile: separate collector and validator (r2).

Evidence provenance model. The ``Collector`` is the only component allowed to
turn raw captured bytes into event records: it reads raw JSON lines, computes
each record's ``payload_sha256`` itself from those bytes, and rejects records
with caller-claimed digest fields, malformed fields, or unknown payload data.
Normalized records carry no status authority. The ``Validator`` is the only
status authority; it derives gate outcomes from the normalized records and the
declared subject identity.

Capture bundles declare their origin:

* ``collector_v1``  - assembled by this collector from raw captured bytes.
* ``external_normalized`` - assembled outside this repository's collector.
* ``synthetic`` - parser unit fixtures.

Capability limit (honest, by design): serialized capture bundles have no
acceptance authority.  A reviewed mapping is accepted only when this entrypoint
invokes the repository-owned adapter against immutable raw evidence and passes
its in-memory receipt to the validator. Parser chain validity is
reported per gate as ``chain`` (``absent``/``incomplete``/``valid``/
``contradicted``) and stays distinct from host acceptance: a valid chain still
yields ``pending`` (``awaiting_live_capture_support``). Contradictory observed
evidence - reordered pairs, reversed pair roles, duplicate or replayed event
IDs, subject/reference mismatches, cross-scenario/session/runtime
contamination, producer version mismatch - fails the result and takes
precedence over pending. Incomplete or unrun evidence stays pending.
An accepted mapping may pass only the gates named by its receipt; unobserved
gates stay pending, and overall passed requires all six gates.

Cleanup must be evidenced by observed ``cleanup_observed`` records carrying
their own ``remaining_ids`` facts; a handwritten cleanup status is ignored.
The full result document is private (it retains session/scenario binding);
only ``public_annex`` is sanitized for publication, and its tokens are
redacted when they are not plain public identifiers - even for
attacker-controlled values.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import tempfile
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

RESULT_SCHEMA = "native-acceptance/v2"
CAPTURE_SCHEMA = "host-behavior-capture/v2"
EVENT_SCHEMA = "host-behavior-events/v2"
PROFILE = "host_behavior"
PLUGIN_VERSION_DEFAULT = "0.13.3"
ORIGIN_COLLECTOR = "collector_v1"
ORIGIN_EXTERNAL = "external_normalized"
ORIGIN_SYNTHETIC = "synthetic"
ORIGIN_REVIEWED = "reviewed_mapping_v1"
SUPPORTED_ORIGINS = (
    ORIGIN_COLLECTOR, ORIGIN_EXTERNAL, ORIGIN_SYNTHETIC, ORIGIN_REVIEWED,
)
VALIDATOR_SCHEMA = "host-behavior-validator/v3"
REVIEWED_MAPPING_GATES = (
    "hook_trust",
    "commit_event",
    "local_push_readback",
)
REVIEWED_CONTINUITY_GATES = (
    "continuity_wait",
    "compact_resume",
    "cleanup",
)
REQUIRED_GATES = (
    "hook_trust",
    "continuity_wait",
    "compact_resume",
    "commit_event",
    "local_push_readback",
    "cleanup",
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
PUBLIC_TOKEN_REPLACEMENT = "[redacted]"

_EVENT_REQUIRED = {
    "schema",
    "event_id",
    "observed_at",
    "sequence",
    "session_id",
    "scenario_id",
    "event_type",
    "producer",
}
_EVENT_OPTIONAL = {
    "subject_id",
    "pair_id",
    "pair_role",
    "remaining_ids",
    "synthetic",
}
_PRODUCER_REQUIRED = {"kind", "runtime_tree_sha256", "plugin_version"}
_HOST_PRODUCER_KINDS = {
    "codex_hook": "hook_event",
    "codex_tool": "tool_name",
    "host_gate_adapter": "adapter_sha256",
}
_CAPTURE_REQUIRED = {
    "schema",
    "origin",
    "subject",
    "session_id",
    "plugin_version",
    "scenarios",
    "host",
    "events",
}
_SUBJECT_REQUIRED = (
    "source_commit",
    "prepared_source_sha256",
    "runtime_tree_sha256",
)
_ANNEX_EVENT_FIELDS = ("event_type", "scenario_id", "payload_sha256")

# Ordered causal chains per gate. Every chain event must share one
# subject_id (the actual fact identity); the commit chain additionally binds
# its first two records as a request/response pair via a shared pair_id with
# exact roles in capture order.
_GATE_CHAINS: dict[str, tuple[str, ...]] = {
    "hook_trust": ("hook_trust_reviewed", "hook_trust_granted"),
    "continuity_wait": (
        "requirement_registered",
        "wait_started",
        "wait_released",
    ),
    "compact_resume": (
        "compact_started",
        "session_resumed",
        "recovery_page_shown",
    ),
    "commit_event": (
        "commit_requested",
        "commit_observed",
        "commit_readback_observed",
    ),
    "local_push_readback": ("push_requested", "push_readback_observed"),
    "cleanup": ("cleanup_observed",),
}
# The public annex is a true allowlist: only these known protocol labels may
# be published. Unknown values are redacted even when they look like harmless
# lowercase identifiers.
_PUBLIC_EVENT_TYPES = frozenset(
    event_type for chain in _GATE_CHAINS.values() for event_type in chain
)
_PUBLIC_SCENARIOS = frozenset(REQUIRED_GATES)
_EXIT_CODES = {"passed": 0, "failed": 1, "pending": 3}
_CHAIN_STATES = ("absent", "incomplete", "valid", "contradicted")


class HostBehaviorError(ValueError):
    """Raised when host-behavior evidence or its declared subject is invalid."""


def _reject(condition: bool, message: str) -> None:
    if condition:
        raise HostBehaviorError(message)


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class Collector:
    """Normalize raw captured bytes into event records; never judge them."""

    def collect_raw(self, raw_events: Sequence[Any]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_events):
            _reject(
                not isinstance(raw, str),
                f"event {index} raw bytes must be captured text",
            )
            try:
                record = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise HostBehaviorError(
                    f"event {index} raw bytes are not JSON: {exc}"
                ) from exc
            normalized.append(self._normalize(index, record, raw))
        return normalized

    def _normalize(
        self, index: int, raw_record: Any, raw_text: str
    ) -> dict[str, Any]:
        _reject(
            not isinstance(raw_record, dict),
            f"event {index} is not a JSON object",
        )
        unknown = set(raw_record) - _EVENT_REQUIRED - _EVENT_OPTIONAL
        _reject(
            bool(unknown),
            f"event {index} carries non-evidence fields: {sorted(unknown)}",
        )
        missing = _EVENT_REQUIRED - set(raw_record)
        _reject(
            bool(missing),
            f"event {index} is missing required fields: {sorted(missing)}",
        )
        _reject(
            raw_record["schema"] != EVENT_SCHEMA,
            f"event {index} schema mismatch",
        )
        for field in ("event_id", "session_id", "scenario_id", "event_type"):
            _reject(
                not isinstance(raw_record[field], str) or not raw_record[field],
                f"event {index} has an empty {field}",
            )
        if "subject_id" in raw_record:
            _reject(
                not isinstance(raw_record["subject_id"], str)
                or not raw_record["subject_id"],
                f"event {index} subject_id must be a non-empty string when present",
            )
        _reject(
            not _valid_timestamp(raw_record["observed_at"]),
            f"event {index} has an invalid observed_at timestamp",
        )
        _reject(
            not _is_int(raw_record["sequence"]),
            f"event {index} sequence must be an integer",
        )
        producer = raw_record["producer"]
        _reject(
            not isinstance(producer, dict) or not _PRODUCER_REQUIRED <= set(producer),
            f"event {index} producer identity is incomplete",
        )
        _reject(
            not isinstance(producer["plugin_version"], str)
            or not producer["plugin_version"],
            f"event {index} producer plugin_version must be a non-empty string",
        )
        _reject(
            not isinstance(producer["runtime_tree_sha256"], str)
            or not HEX64.fullmatch(producer["runtime_tree_sha256"]),
            f"event {index} producer runtime digest must be lowercase hex64",
        )
        kind = producer.get("kind")
        _reject(
            not isinstance(kind, str) or not kind,
            f"event {index} producer kind must be a non-empty string",
        )
        if kind in _HOST_PRODUCER_KINDS:
            identity_field = _HOST_PRODUCER_KINDS[kind]
            _reject(
                not isinstance(producer.get(identity_field), str)
                or not producer[identity_field],
                f"event {index} producer kind {kind} requires {identity_field}",
            )
        pair_role = raw_record.get("pair_role")
        _reject(
            pair_role is not None and pair_role not in {"request", "response"},
            f"event {index} pair_role must be request or response",
        )
        _reject(
            (raw_record.get("pair_id") is None) != (pair_role is None),
            f"event {index} must bind pair_id and pair_role together",
        )
        if "remaining_ids" in raw_record:
            _reject(
                raw_record["event_type"] != "cleanup_observed",
                f"event {index} may carry remaining_ids only on cleanup_observed",
            )
            _reject(
                not isinstance(raw_record["remaining_ids"], list)
                or not all(isinstance(item, str) for item in raw_record["remaining_ids"]),
                f"event {index} remaining_ids must be a list of strings",
            )
        _reject(
            not isinstance(raw_record.get("synthetic", False), bool),
            f"event {index} synthetic marker must be a boolean",
        )
        record = dict(raw_record)
        # The digest is computed here, from the captured raw bytes; records
        # never accept a caller-claimed payload digest.
        record["payload_sha256"] = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        return record

    def load_capture(self, path: Path) -> dict[str, Any]:
        try:
            capture = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HostBehaviorError(f"capture bundle unreadable: {exc}") from exc
        _reject(
            not isinstance(capture, dict),
            "capture bundle must be a JSON object",
        )
        _reject(
            not isinstance(capture.get("events"), list),
            "capture events must be a list of raw captured lines",
        )
        return capture


def _event_gate(event_type: str) -> str | None:
    for gate_id, chain in _GATE_CHAINS.items():
        if event_type in chain:
            return gate_id
    return None


class Validator:
    """Derive host_behavior gate outcomes; the only status authority."""

    def __init__(
        self,
        declared: dict[str, str],
        plugin_version: str = PLUGIN_VERSION_DEFAULT,
    ) -> None:
        for field in ("source_commit", "prepared_source_sha256",
                      "runtime_tree_sha256"):
            value = declared.get(field)
            _reject(
                not isinstance(value, str) or not value,
                f"declared {field} is required",
            )
        _reject(
            not HEX40.fullmatch(declared["source_commit"]),
            "declared source_commit must be a lowercase hex40 commit",
        )
        _reject(
            not HEX64.fullmatch(declared["prepared_source_sha256"])
            or not HEX64.fullmatch(declared["runtime_tree_sha256"]),
            "declared digests must be lowercase hex64",
        )
        _reject(
            not isinstance(plugin_version, str) or not plugin_version,
            "declared plugin_version must be a non-empty string",
        )
        self._declared = {
            "source_commit": declared["source_commit"],
            "prepared_source_sha256": declared["prepared_source_sha256"],
            "runtime_tree_sha256": declared["runtime_tree_sha256"],
        }
        self._plugin_version = plugin_version

    def validate(
        self,
        capture: dict[str, Any],
        reviewed_mapping: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        origin = capture.get("origin")
        events = capture.get("events")
        if (
            capture.get("schema") != CAPTURE_SCHEMA
            or origin not in SUPPORTED_ORIGINS
            or not isinstance(events, list)
            or not all(isinstance(item, str) for item in events)
        ):
            return self._unverified_bundle(
                "bundle is not a supported host-behavior-capture/v2 with a "
                "supported origin; it is not accepted as host evidence"
            )
        records = Collector().collect_raw(events)
        contradictions, pend_reasons = self._evaluate(records, capture)
        digest = self._declared["runtime_tree_sha256"]
        origin_synthetic = origin == ORIGIN_SYNTHETIC
        mapped_gates = self._reviewed_gates(capture, reviewed_mapping)
        gates = []
        for gate_id in REQUIRED_GATES:
            chain, chain_note, pend, gate_synthetic = self._chain_verdict(
                gate_id, records, contradictions, pend_reasons,
                origin_synthetic, origin,
            )
            if chain == "contradicted":
                status = "failed"
            elif chain == "valid" and gate_id in mapped_gates:
                status = "passed"
            else:
                status = "pending"
            gates.append(
                _gate(
                    gate_id, digest, status, chain=chain, note=chain_note,
                    mode=self._mode(
                        chain, pend, gate_synthetic, origin,
                        gate_id in mapped_gates,
                    ),
                )
            )
        overall = _overall(gates)
        result = assemble_result(
            capture, self._declared, gates, overall, records,
            reviewed_mapping=reviewed_mapping,
        )
        result["capability_note"] = (
            "parser validity and live-host acceptance are separate; only gates "
            "verified by the in-memory reviewed-mapping receipt can pass, "
            "and overall passed requires all six gates"
        )
        return result

    def _reviewed_gates(
        self,
        capture: dict[str, Any],
        receipt: dict[str, Any] | None,
    ) -> frozenset[str]:
        if receipt is None:
            return frozenset()
        schema = receipt.get("schema")
        if schema == "context-guard-reviewed-host-continuity-receipt/v1":
            return self._reviewed_continuity_gates(capture, receipt)
        required = {
            "schema", "manifest_sha256", "adapter_sha256",
            "collector_sha256", "validator_sha256", "runtime_tree_sha256",
            "mapped_gates", "capture_report_sha256", "trust_review_sha256",
            "trust_contract_sha256", "raw_sha256", "git_readback_sha256",
        }
        _reject(set(receipt) != required, "reviewed mapping receipt shape mismatch")
        _reject(
            receipt.get("schema")
            != "context-guard-reviewed-host-mapping-receipt/v1",
            "reviewed mapping receipt schema mismatch",
        )
        for field in (
            "manifest_sha256", "adapter_sha256", "collector_sha256",
            "validator_sha256", "runtime_tree_sha256",
            "capture_report_sha256", "trust_review_sha256",
            "trust_contract_sha256", "git_readback_sha256",
        ):
            _reject(
                not isinstance(receipt.get(field), str)
                or not HEX64.fullmatch(receipt[field]),
                f"reviewed mapping {field} is invalid",
            )
        _reject(
            receipt["validator_sha256"]
            != hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "reviewed mapping validator identity differs",
        )
        _reject(
            receipt["adapter_sha256"]
            != hashlib.sha256(
                Path(__file__).with_name("host_raw_mapping.py").read_bytes()
            ).hexdigest(),
            "reviewed mapping adapter identity differs",
        )
        _reject(
            receipt["collector_sha256"]
            != hashlib.sha256(
                Path(__file__).with_name("host_capture.py").read_bytes()
            ).hexdigest(),
            "reviewed mapping collector identity differs",
        )
        _reject(
            receipt["runtime_tree_sha256"]
            != self._declared["runtime_tree_sha256"],
            "reviewed mapping runtime identity differs",
        )
        gates = receipt.get("mapped_gates")
        _reject(
            not isinstance(gates, list)
            or len(gates) != len(set(gates))
            or any(gate not in REQUIRED_GATES for gate in gates),
            "reviewed mapping gate set is invalid",
        )
        _reject(
            gates != list(REVIEWED_MAPPING_GATES),
            "reviewed mapping may authorize only the accepted three-gate set",
        )
        _reject(
            capture.get("origin") != ORIGIN_REVIEWED,
            "reviewed mapping capture origin differs",
        )
        _reject(
            sorted(capture.get("scenarios", [])) != sorted(gates),
            "reviewed mapping scenarios differ from its receipt",
        )
        raw_hashes = receipt.get("raw_sha256")
        _reject(
            not isinstance(raw_hashes, list)
            or not raw_hashes
            or len(raw_hashes) != len(set(raw_hashes))
            or any(not isinstance(value, str) or not HEX64.fullmatch(value)
                   for value in raw_hashes),
            "reviewed mapping raw evidence hashes are invalid",
        )
        return frozenset(gates)

    def _reviewed_continuity_gates(
        self, capture: dict[str, Any], receipt: dict[str, Any]
    ) -> frozenset[str]:
        required = {
            "schema", "manifest_sha256", "adapter_sha256",
            "collector_sha256", "state_collector_sha256",
            "validator_sha256", "runtime_tree_sha256", "mapped_gates",
            "capture_report_sha256", "trust_review_sha256", "raw_sha256",
            "snapshot_sha256",
        }
        _reject(set(receipt) != required, "continuity mapping receipt shape mismatch")
        for field in (
            "manifest_sha256", "adapter_sha256", "collector_sha256",
            "state_collector_sha256", "validator_sha256",
            "runtime_tree_sha256", "capture_report_sha256", "trust_review_sha256",
        ):
            _reject(
                not isinstance(receipt.get(field), str)
                or not HEX64.fullmatch(receipt[field]),
                f"continuity mapping {field} is invalid",
            )
        identities = {
            "adapter_sha256": "host_continuity_mapping.py",
            "collector_sha256": "host_capture.py",
            "state_collector_sha256": "host_state_capture.py",
            "validator_sha256": "host_behavior.py",
        }
        for field, name in identities.items():
            _reject(
                receipt[field]
                != hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest(),
                f"continuity mapping {field.removesuffix('_sha256')} identity differs",
            )
        _reject(
            receipt["runtime_tree_sha256"] != self._declared["runtime_tree_sha256"],
            "continuity mapping runtime identity differs",
        )
        gates = receipt.get("mapped_gates")
        _reject(
            gates != list(REVIEWED_CONTINUITY_GATES),
            "continuity mapping may authorize only the accepted remaining-gate set",
        )
        _reject(
            capture.get("origin") != ORIGIN_REVIEWED,
            "continuity mapping capture origin differs",
        )
        _reject(
            sorted(capture.get("scenarios", [])) != sorted(gates),
            "continuity mapping scenarios differ from its receipt",
        )
        for field in ("raw_sha256", "snapshot_sha256"):
            values = receipt.get(field)
            _reject(
                not isinstance(values, list)
                or not values
                or len(values) != len(set(values))
                or any(not isinstance(value, str) or not HEX64.fullmatch(value)
                       for value in values),
                f"continuity mapping {field} evidence hashes are invalid",
            )
        return frozenset(gates)

    def _unverified_bundle(self, reason: str) -> dict[str, Any]:
        digest = self._declared["runtime_tree_sha256"]
        gates = [
            _gate(
                gate_id, digest, "pending", chain="absent",
                note=reason, mode="unverified_origin",
            )
            for gate_id in REQUIRED_GATES
        ]
        result = assemble_result(None, self._declared, gates, "pending")
        result["capability_note"] = (
            f"unverified capture ({reason}); host passed stays unreachable"
        )
        return result

    def _mode(
        self,
        chain: str,
        pend: str | None,
        synthetic: bool,
        origin: str,
        reviewed: bool = False,
    ) -> str:
        if chain == "contradicted":
            return "contradicted_evidence"
        if pend:
            return pend
        if chain == "valid":
            if reviewed:
                return "reviewed_raw_mapping"
            if synthetic:
                return "synthetic_unit_fixture"
            if origin == ORIGIN_EXTERNAL:
                return "unverified_origin"
            return "awaiting_live_capture_support"
        if chain == "incomplete":
            return "incomplete_capture"
        return "no_host_events"

    def _evaluate(
        self, records: list[dict[str, Any]], capture: dict[str, Any]
    ) -> tuple[list[str], dict[str, str]]:
        """Binding/contradiction scan shared by all gates.

        Returns contradictions (fail the whole result) and per-gate pending
        reasons that are weaker than contradictions.
        """
        contradictions: list[str] = []
        seen_ids: dict[str, str] = {}
        seen_raw: dict[str, str] = {}
        previous_sequence = None
        session_id = capture.get("session_id")
        scenarios = capture.get("scenarios")
        capture_version = capture.get("plugin_version")
        subject = capture.get("subject")
        if not isinstance(session_id, str) or not session_id:
            contradictions.append("capture session_id is missing or invalid")
        if not isinstance(scenarios, list) or not all(
            isinstance(item, str) for item in scenarios
        ):
            contradictions.append("capture scenarios is missing or invalid")
            scenarios = []
        if capture_version != self._plugin_version:
            contradictions.append(
                f"capture plugin_version {capture_version!r} does not bind to "
                f"the declared candidate {self._plugin_version!r}"
            )
        if not isinstance(subject, dict) or any(
            subject.get(field) != self._declared[field]
            for field in _SUBJECT_REQUIRED
        ):
            contradictions.append(
                "capture subject does not match the declared prepared source, "
                "source commit, and runtime tree"
            )
        for record in records:
            if record["event_id"] in seen_ids:
                contradictions.append(
                    f"event {record['event_id']} duplicates "
                    f"{seen_ids[record['event_id']]}"
                )
            seen_ids.setdefault(record["event_id"], record["event_id"])
            if record["payload_sha256"] in seen_raw:
                contradictions.append(
                    f"event {record['event_id']} replays captured bytes of "
                    f"{seen_raw[record['payload_sha256']]}"
                )
            seen_raw.setdefault(record["payload_sha256"], record["event_id"])
            if session_id and record["session_id"] != session_id:
                contradictions.append(
                    f"event {record['event_id']} belongs to a foreign session"
                )
            if isinstance(scenarios, list) and record["scenario_id"] not in scenarios:
                contradictions.append(
                    f"event {record['event_id']} names an undeclared scenario"
                )
            if (
                record["producer"]["runtime_tree_sha256"]
                != self._declared["runtime_tree_sha256"]
            ):
                contradictions.append(
                    f"event {record['event_id']} was produced by a foreign runtime"
                )
            if (
                record["producer"]["plugin_version"]
                != capture.get("plugin_version")
            ):
                contradictions.append(
                    f"event {record['event_id']} producer version contradicts "
                    "the capture provenance"
                )
            if (
                previous_sequence is not None
                and record["sequence"] <= previous_sequence
            ):
                contradictions.append(
                    f"event {record['event_id']} breaks capture sequence order"
                )
            previous_sequence = record["sequence"]
        return contradictions, {}

    def _chain_verdict(
        self,
        gate_id: str,
        records: list[dict[str, Any]],
        contradictions: list[str],
        pend_reasons: dict[str, str],
        origin_synthetic: bool,
        origin: str,
    ) -> tuple[str, str, str | None, bool]:
        """Return (chain state, note, pending reason override, synthetic).

        Contradictory observed facts - role/pair violations, order violations,
        reference conflicts, non-empty observed cleanup facts - always win
        over pending reasons such as missing bindings, unverified producers,
        or unrun prefixes.
        """
        if contradictions:
            return (
                "contradicted",
                f"binding violation: {contradictions[0]}",
                None,
                False,
            )
        chain = _GATE_CHAINS[gate_id]
        scoped = [
            record
            for record in records
            if record["scenario_id"] == gate_id
            and record["event_type"] in chain
        ]
        synthetic = origin_synthetic or any(
            record.get("synthetic", False) for record in scoped
        )
        foreign = sorted(
            record["event_type"]
            for record in records
            if record["scenario_id"] == gate_id
            and _event_gate(record["event_type"]) not in (None, gate_id)
        )
        if foreign:
            return (
                "contradicted",
                f"cross-scenario events inside {gate_id}: {foreign}",
                None,
                synthetic,
            )
        if not scoped:
            return (
                "absent",
                "no host event records captured for this capability",
                None,
                synthetic,
            )
        # Contradiction checks first: none of the pending reasons below may
        # mask an observed contradiction.
        subjects = {
            record["subject_id"] for record in scoped if record.get("subject_id")
        }
        if len(subjects) > 1:
            return (
                "contradicted",
                f"chain events reference different fact identities: "
                f"{sorted(subjects)}",
                None,
                synthetic,
            )
        if gate_id == "commit_event":
            role_problem = self._pair_problem(scoped)
            if role_problem:
                return "contradicted", role_problem, None, synthetic
        if gate_id == "cleanup":
            remaining = [
                item
                for record in scoped
                for item in record.get("remaining_ids", [])
            ]
            if remaining:
                return (
                    "contradicted",
                    f"observed cleanup facts report remaining ids: {remaining}",
                    None,
                    synthetic,
                )
        types = [record["event_type"] for record in scoped]
        if types != list(chain):
            if len(types) < len(chain) and types == list(chain)[: len(types)]:
                return (
                    "incomplete",
                    f"observed prefix {types} of expected chain {list(chain)}; "
                    "capability unrun in this capture",
                    None,
                    synthetic,
                )
            return (
                "contradicted",
                f"expected causal chain {list(chain)}, observed {types}",
                None,
                synthetic,
            )
        # Pending reasons only after all contradiction checks passed.
        if any(not record.get("subject_id") for record in scoped):
            return (
                "incomplete",
                "chain events lack a fact identity binding",
                "insufficient_binding",
                synthetic,
            )
        if gate_id == "cleanup" and any(
            "remaining_ids" not in record for record in scoped
        ):
            return (
                "incomplete",
                "cleanup records omit their observed remaining_ids facts",
                "missing_cleanup_facts",
                synthetic,
            )
        unverified = sorted(
            record["event_id"]
            for record in scoped
            if record["producer"]["kind"] not in _HOST_PRODUCER_KINDS
        )
        if unverified:
            return (
                "incomplete" if types != list(chain) else "valid",
                f"records lack a supported host producer identity: {unverified}",
                "unverified_producer",
                synthetic,
            )
        return (
            "valid",
            "causal chain and fact bindings verified by the parser",
            None,
            synthetic,
        )

    @staticmethod
    def _pair_problem(scoped: list[dict[str, Any]]) -> str | None:
        request = next(
            (r for r in scoped if r["event_type"] == "commit_requested"), None
        )
        response = next(
            (r for r in scoped if r["event_type"] == "commit_observed"), None
        )
        if request is None or response is None:
            return None
        if (
            request.get("pair_role") != "request"
            or response.get("pair_role") != "response"
        ):
            return "commit pair roles are reversed or missing"
        if request.get("pair_id") != response.get("pair_id"):
            return "commit pair_id mismatch between request and response"
        return None


def _gate(
    gate_id: str,
    digest: str,
    status: str,
    *,
    chain: str,
    note: str,
    mode: str,
) -> dict[str, Any]:
    return {
        "id": gate_id,
        "required": True,
        "status": status,
        "chain": chain,
        "subject": {"kind": "runtime_tree", "id": digest},
        "exit_code": _EXIT_CODES[status],
        "note": note,
        "evidence": {
            "mode": mode,
            "source_result_sha256": None,
            "source_gate_id": None,
            "invalidation_reason": "host_events_changed",
        },
    }


def _overall(gates: list[dict[str, Any]]) -> str:
    statuses = {gate["status"] for gate in gates}
    if "failed" in statuses:
        return "failed"
    if statuses == {"passed"}:
        return "passed"
    return "pending"


def _public_event_label(value: str, session_id: str | None) -> str:
    if value != session_id and value in _PUBLIC_EVENT_TYPES:
        return value
    return PUBLIC_TOKEN_REPLACEMENT


def _public_scenario_label(value: str, session_id: str | None) -> str:
    if value != session_id and value in _PUBLIC_SCENARIOS:
        return value
    return PUBLIC_TOKEN_REPLACEMENT


def redact_events(
    records: Sequence[dict[str, Any]], session_id: str | None = None
) -> list[dict[str, Any]]:
    annex: list[dict[str, Any]] = []
    for record in records:
        annex.append(
            {
                "event_type": _public_event_label(
                    record["event_type"], session_id
                ),
                "scenario_id": _public_scenario_label(
                    record["scenario_id"], session_id
                ),
                "payload_sha256": record["payload_sha256"],
            }
        )
    return annex


def assemble_result(
    capture: dict[str, Any] | None,
    declared: dict[str, str],
    gates: list[dict[str, Any]],
    overall: str,
    records: Sequence[dict[str, Any]] = (),
    reviewed_mapping: dict[str, Any] | None = None,
) -> dict[str, Any]:
    capture = capture or {}
    host = capture.get("host") or {
        "os": "unavailable",
        "python": "unavailable",
        "codex": "unavailable",
    }
    session_id = capture.get("session_id")
    if not isinstance(session_id, str):
        session_id = None
    return {
        "schema": RESULT_SCHEMA,
        "status": overall,
        "product": "codex_context_guard",
        "gate_profile": PROFILE,
        "validation": {
            "schema": VALIDATOR_SCHEMA,
            "validator_sha256": hashlib.sha256(
                Path(__file__).read_bytes()
            ).hexdigest(),
            "mapping_manifest_sha256": (
                reviewed_mapping.get("manifest_sha256")
                if reviewed_mapping else None
            ),
            "adapter_sha256": (
                reviewed_mapping.get("adapter_sha256")
                if reviewed_mapping else None
            ),
            "collector_sha256": (
                reviewed_mapping.get("collector_sha256")
                if reviewed_mapping else None
            ),
            "trust_contract_sha256": (
                reviewed_mapping.get("trust_contract_sha256")
                if reviewed_mapping else None
            ),
        },
        "visibility": {
            # The full result keeps private session/scenario binding and is
            # NOT publication-safe; only public_annex is sanitized.
            "full_result_is_public": False,
            "public_annex_sanitized": True,
            "host_passed_reachable": (
                reviewed_mapping is not None
                and set(reviewed_mapping.get("mapped_gates", []))
                == set(REQUIRED_GATES)
            ),
        },
        "subject": {
            "kind": "prepared_host_behavior",
            "source_commit": declared["source_commit"],
            "prepared_source_sha256": declared["prepared_source_sha256"],
            "runtime_tree_sha256": declared["runtime_tree_sha256"],
        },
        "repository": {"url": None, "commit": declared["source_commit"]},
        "runtime_tree_sha256": declared["runtime_tree_sha256"],
        "artifact": None,
        "platform": {
            "os": host.get("os", "unavailable"),
            "shell": "real-host-capture",
            "toolchain": {
                "python": host.get("python", "unavailable"),
                "codex": host.get("codex", "unavailable"),
            },
        },
        "sessions": [
            {
                "session_id": session_id or "unavailable",
                "scenarios": list(capture.get("scenarios", []) or []),
            }
        ],
        "gates": gates,
        "cleanup": {
            "status": "observed_facts_required",
            "remaining_ids": [],
            "note": (
                "cleanup derives from observed cleanup_observed records; no "
                "handwritten status is accepted"
            ),
        },
        "public_annex": {
            "events": redact_events(records, session_id),
        },
        "run": {"started_at": None, "finished_at": None, "run_url": None},
        "unperformed_actions": [
            "commit",
            "push",
            "merge",
            "tag",
            "release",
            "public_promotion",
        ],
    }


def capability_record(
    declared: dict[str, str], plugin_version: str, reason: str
) -> dict[str, Any]:
    digest = declared["runtime_tree_sha256"]
    gates = [
        _gate(
            gate_id, digest, "pending", chain="absent",
            note="capability unrun: no real host capture was available",
            mode="no_host_events",
        )
        for gate_id in REQUIRED_GATES
    ]
    result = assemble_result(None, declared, gates, "pending")
    result["capability_note"] = (
        f"pending capability ({reason}): the host_behavior profile records the "
        "declared subject and required gate set without claiming any host "
        "fact; passed requires an observed and accepted raw-to-gate mapping (P4)"
    )
    return result


def adopt_portable_result(
    portable: dict[str, Any], declared: dict[str, str]
) -> dict[str, Any]:
    raise HostBehaviorError(
        "a portable_runtime result can never substitute for host_behavior "
        "evidence; run a real-host capture instead"
    )


def check_output_path(output: Path, repo_root: Path) -> None:
    """Check result storage before collection/replay, without replacing evidence."""
    if output.exists() or output.is_symlink():
        raise HostBehaviorError("output already exists; keep it and choose a new result path")
    if output.resolve().is_relative_to(repo_root.resolve()):
        raise HostBehaviorError("output must be outside the source repository")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile(dir=output.parent) as probe:
        probe.write(b"result-path-check")
        probe.flush()


def write_result(output: Path, result: dict[str, Any]) -> None:
    """Use exclusive creation so a late collision cannot overwrite a result."""
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run exact-runtime acceptance and emit native-acceptance/v2; "
            "profile host_behavior validates real-host captures only"
        )
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--preflight", action="store_true",
                        help="check inputs and result storage without writing acceptance evidence")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--run-url")
    parser.add_argument(
        "--profile",
        choices=("portable_runtime", PROFILE),
        default="portable_runtime",
    )
    parser.add_argument("--prepared-source-sha256")
    parser.add_argument("--runtime-tree-sha256")
    parser.add_argument("--plugin-version", default=PLUGIN_VERSION_DEFAULT)
    parser.add_argument("--capability-reason", default="no_host_capture")
    parser.add_argument("--events-bundle", type=Path)
    parser.add_argument("--reviewed-mapping-manifest", type=Path)
    parser.add_argument("--reviewed-mapping-manifest-sha256")
    parser.add_argument("--runtime-root", type=Path)
    return parser


def run_host_behavior(args: argparse.Namespace) -> dict[str, Any]:
    _reject(
        not HEX64.fullmatch(args.prepared_source_sha256 or "")
        or not HEX64.fullmatch(args.runtime_tree_sha256 or ""),
        "host_behavior requires --prepared-source-sha256 and "
        "--runtime-tree-sha256 as lowercase hex64",
    )
    declared = {
        "source_commit": args.source_commit,
        "prepared_source_sha256": args.prepared_source_sha256,
        "runtime_tree_sha256": args.runtime_tree_sha256,
    }
    _reject(
        args.events_bundle is not None
        and args.reviewed_mapping_manifest is not None,
        "choose either --events-bundle or --reviewed-mapping-manifest",
    )
    if args.reviewed_mapping_manifest is not None:
        _reject(
            args.runtime_root is None
            or not HEX64.fullmatch(args.reviewed_mapping_manifest_sha256 or ""),
            "reviewed mapping requires --runtime-root and the exact manifest SHA-256",
        )
        adapter_path = Path(__file__).with_name("host_raw_mapping.py")
        spec = importlib.util.spec_from_file_location(
            "host_behavior_reviewed_mapping", adapter_path
        )
        _reject(spec is None or spec.loader is None, "reviewed mapping adapter unavailable")
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        try:
            bundle, receipt = adapter.adapt(
                args.reviewed_mapping_manifest,
                args.runtime_root,
                args.reviewed_mapping_manifest_sha256,
            )
        except adapter.MappingError as exc:
            raise HostBehaviorError(
                f"reviewed mapping rejected: {exc}"
            ) from exc
        _reject(
            bundle.get("subject") != declared,
            "reviewed mapping subject differs from command-line declaration",
        )
        return Validator(declared, args.plugin_version).validate(
            bundle, reviewed_mapping=receipt
        )
    if args.events_bundle is None:
        return capability_record(declared, args.plugin_version, args.capability_reason)
    capture = Collector().load_capture(args.events_bundle)
    return Validator(declared, args.plugin_version).validate(capture)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        check_output_path(args.output, args.repo_root)
        result = run_host_behavior(args)
        if args.preflight:
            print("native_preflight=" + ("failed" if result["status"] == "failed" else "passed")
                      + "; acceptance_not_written; capture_status=" + result["status"])
            return 1 if result["status"] == "failed" else 0
        write_result(args.output, result)
    except (HostBehaviorError, OSError) as exc:
        parser.error(str(exc))
    print(f"native_acceptance={result['status']}")
    return _EXIT_CODES[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
