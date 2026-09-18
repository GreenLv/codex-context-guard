"""Host-neutral, side-effect-free core v2 projection. No execution authority.

Input trust belongs to the host adapter; this is not a public receipt API.
All temporal joins are bounded by the caller's explicit as-of watermark.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from typing import Any

from cg_core_v2_schema import load_strict, validate_snapshot

SCHEMA = "core-observation/v2"
DOMAIN = b"context-guard/core/v2\0"
MAX_INTEGER = 9007199254740991


def canonical_bytes(value: Any) -> bytes:
    def check(node: Any) -> None:
        if node is None or isinstance(node, bool):
            return
        if isinstance(node, str):
            node.encode("utf-8", "strict")
            return
        if type(node) is int and abs(node) <= MAX_INTEGER:
            return
        if isinstance(node, list):
            for child in node:
                check(child)
            return
        if isinstance(node, dict) and all(isinstance(k, str) for k in node):
            for key, child in node.items():
                check(key)
                check(child)
            return
        raise ValueError("noncanonical_value")

    check(value)
    # Unicode scalar order and UTF-8 byte order coincide.
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(DOMAIN + canonical_bytes(value)).hexdigest()


def _index(rows: list[dict], watermark: int) -> dict[str, dict]:
    result: dict[str, dict] = {}
    seen: set[str] = set()
    for row in rows:
        if row["id"] in seen:
            raise ValueError("duplicate_identity")
        seen.add(row["id"])
        if row["seq"] <= watermark:
            result[row["id"]] = row
    return result


def _source_matches(
    span: dict, sources: dict[str, dict], *, root: bool = False
) -> bool:
    source = sources.get(span["source_id"])
    if source and source["text"] is not None:
        raw = source["text"].encode("utf-8")
        try:
            raw[: span["start"]].decode("utf-8")
            raw[: span["end"]].decode("utf-8")
        except UnicodeDecodeError:
            return False
    return bool(
        source
        and (not root or source["kind"] == "root")
        and span["sha256"] == source["sha256"]
        and 0 <= span["start"] < span["end"] <= source["byte_length"]
    )


def project(snapshot: dict) -> dict:
    """Compute predicates/Stop diagnostics, never tool permission or effects."""
    validate_snapshot(snapshot)
    canonical_bytes(snapshot)
    if snapshot.get("schema") != SCHEMA:
        raise ValueError("unsupported_core_schema")
    watermark = snapshot["as_of"]
    unit, revision = snapshot["unit"], snapshot["revision"]
    sources = _index(snapshot["sources"], watermark)
    for source in sources.values():
        if source.get("target") is not None and source["kind"] != "host_call":
            raise ValueError("selection_target_requires_host_call")
        if source.get("origin_root_source_id") is not None:
            origin = sources.get(source["origin_root_source_id"])
            if (source["kind"] != "host_call" or origin is None
                    or origin["kind"] != "root" or origin["unit"] != source["unit"]
                    or origin["seq"] > source["seq"]
                    or origin["turn"] != source["turn"]):
                raise ValueError("host_call_origin_root_mismatch")
        if (source.get("target") is None) != (source.get("target_kind") is None):
            raise ValueError("selection_target_kind_pair_required")
        if (source.get("locator_base") is not None or source.get("locator_flavor") is not None) and source["kind"] != "root":
            raise ValueError("locator_base_requires_root")
        if (source.get("locator_base") is None) != (source.get("locator_flavor") is None):
            raise ValueError("locator_base_flavor_pair_required")
        if source["kind"] == "root":
            text = source["text"]
            if (
                text is None
                or len(text.encode("utf-8")) != source["byte_length"]
                or hashlib.sha256(text.encode("utf-8")).hexdigest() != source["sha256"]
            ):
                raise ValueError("root_source_identity_mismatch")
    unit_rows = {u["id"]: u for u in snapshot["units"]}
    if len(unit_rows) != len(snapshot["units"]) or unit not in unit_rows:
        raise ValueError("unit_identity_invalid")
    for row in unit_rows.values():
        source = sources.get(row["source_id"])
        if not source or source["kind"] != "root" or source["unit"] != row["id"]:
            raise ValueError("unit_source_invalid")
        visited = {row["id"]}
        parent = row["parent_id"]
        while parent is not None:
            if parent in visited or parent not in unit_rows:
                raise ValueError("unit_parent_invalid")
            visited.add(parent)
            parent = unit_rows[parent]["parent_id"]
    units = {unit}
    while True:
        added = {
            key
            for key, row in unit_rows.items()
            if row["required"] and row["parent_id"] in units
        } - units
        if not added:
            break
        units.update(added)
    coverage_errors = []
    unknown_coverage = []
    for key, source in sources.items():
        if source["kind"] != "root" or source["unit"] not in units:
            continue
        if source["unit"] == unit and source["revision"] != revision:
            continue
        spans = sorted(
            (c for c in snapshot["coverage"] if c["source"]["source_id"] == key),
            key=lambda c: c["source"]["start"],
        )
        cursor = 0
        for coverage in spans:
            span = coverage["source"]
            if not _source_matches(span, sources, root=True) or span["start"] != cursor:
                coverage_errors.append(key)
            cursor = span["end"]
            if coverage["kind"] == "unknown":
                unknown_coverage.append(key)
        if cursor != source["byte_length"]:
            coverage_errors.append(key)
    requirements = _index(snapshot["requirements"], watermark)
    facts = _index(snapshot["facts"], watermark)
    current = {
        key: row
        for key, row in requirements.items()
        if row["unit"] in units and (row["unit"] != unit or row["revision"] == revision)
    }
    if any(
        r["parent_id"] is not None and r["parent_id"] not in requirements
        for r in current.values()
    ):
        raise ValueError("requirement_parent_missing")
    valid_facts: dict[str, dict] = {}
    for key, fact in facts.items():
        source = sources.get(fact["source_id"])
        if not source or source["seq"] > fact["seq"]:
            continue
        if (source["unit"], source["revision"]) != (fact["unit"], fact["revision"]):
            continue
        if fact["kind"] in {"action_event", "state_outcome", "readiness"}:
            call = sources.get(fact["call_source_id"])
            if (
                not call
                or call["kind"] != "host_call"
                or source["kind"] != "host_result"
            ):
                continue
            if not call["call_id"] or call["call_id"] != source["call_id"]:
                continue
            # A result may describe a different object from the call that
            # produced it.  Result prose or a fact's requirement_id cannot
            # turn that call into evidence for the requested target.
            if call.get("target") != fact["target"] or call.get("target_kind") is None:
                continue
            origin_id = call.get("origin_root_source_id")
            fact_requirement = current.get(fact["requirement_id"])
            if (origin_id is not None and fact_requirement is not None
                    and fact_requirement["kind"] != "constraint"
                    and sources[origin_id]["seq"] <
                    sources[fact_requirement["source"]["source_id"]]["seq"]):
                continue
            if call["seq"] >= source["seq"] or (call["unit"], call["revision"]) != (
                fact["unit"],
                fact["revision"],
            ):
                continue
        elif source["kind"] != {
            "state_outcome": "host_result",
            "delivery": "final_delivery",
            "readiness": "host_result",
            "external_operation": "external_lifecycle",
        }.get(fact["kind"]):
            continue
        valid_facts[key] = fact
    historical_effect_facts = dict(valid_facts)
    invalidated = {
        fid
        for f in valid_facts.values()
        for fid in f["invalidates"]
        if fid in valid_facts and valid_facts[fid]["seq"] < f["seq"]
    }
    valid_facts = {key: f for key, f in valid_facts.items() if key not in invalidated}
    conditions = {c["id"]: c for c in snapshot["conditions"]}
    if len(conditions) != len(snapshot["conditions"]):
        raise ValueError("duplicate_condition")
    released = set()
    for key, condition in conditions.items():
        req = current.get(condition["requirement_id"])
        if not req or not _source_matches(condition["source"], sources, root=True):
            continue
        if condition["source"]["source_id"] != req["source"]["source_id"]:
            continue
        if condition["status"] == "released" and any(
            fid in valid_facts
            and valid_facts[fid]["condition_id"] == key
            and valid_facts[fid]["requirement_id"] == req["id"]
            and valid_facts[fid]["outcome"] == "success"
            for fid in condition["fact_ids"]
        ):
            released.add(key)
    for coverage in snapshot["coverage"]:
        span = coverage["source"]
        source = sources.get(span["source_id"])
        if (
            not source
            or source["unit"] not in units
            or coverage["kind"] != "interpreted"
        ):
            continue
        covered = sorted(
            (r["source"]["start"], r["source"]["end"])
            for r in current.values()
            if r["source"]["source_id"] == span["source_id"]
            and r["source"]["start"] < span["end"]
            and r["source"]["end"] > span["start"]
        )
        cursor = span["start"]
        for start, end in covered:
            if start > cursor:
                break
            cursor = max(cursor, end)
        if cursor < span["end"]:
            coverage_errors.append(span["source_id"])
    predicates: dict[str, str] = {}
    delivery: list[str] = []
    for key, req in current.items():
        source = sources.get(req["source"]["source_id"])
        source_valid = (
            _source_matches(req["source"], sources, root=True)
            and source["unit"] == req["unit"]
            and source["revision"] == req["revision"]
        )
        origin = req["target_origin"]
        constraint = origin["root_constraint"]
        target_span = origin["root_constraint_source"]
        target_source = sources.get(target_span["source_id"])
        root_target_valid = bool(
            _source_matches(target_span, sources, root=True)
            and target_source["unit"] == req["unit"]
            and target_source["revision"] == req["revision"]
            and target_source["text"]
            .encode("utf-8")[target_span["start"] : target_span["end"]]
            .decode("utf-8")
            == constraint
        )
        constraint_kind = origin["constraint_kind"]
        resolved_constraint = origin.get("resolved_constraint")
        relative_constraint = resolved_constraint is not None
        base = target_source.get("locator_base") if target_source else None
        flavor = target_source.get("locator_flavor") if target_source else None
        relative_literal = (
            constraint[:-1] if constraint_kind == "directory" and constraint.endswith("/")
            else constraint
        )
        subject_kind = origin["subject_kind"]
        filesystem_subject = subject_kind == "filesystem"
        inherently_filesystem = (
            req["action"] in {"local_edit", "local_commit", "remote_push"}
            or any(f["requirement_id"] == key and f["kind"] == "readiness"
                   and f["predicate"] == "file_exists" for f in valid_facts.values())
        )
        if inherently_filesystem and not filesystem_subject:
            root_target_valid = False
        target_is_absolute = bool(
            (req["target"].startswith("/") and not req["target"].startswith("//")
             and posixpath.normpath(req["target"]) == req["target"])
            or re.fullmatch(r"[A-Za-z]:[\\/][^:]+", req["target"])
        )
        if relative_constraint and not filesystem_subject:
            root_target_valid = False
        if relative_constraint:
            valid_relative = bool(
                flavor == "posix" and isinstance(base, str) and base.startswith("/")
                and posixpath.normpath(base) == base
                and not base.startswith("//")
                and not constraint.startswith(("/", "\\"))
                and ":" not in relative_literal and "\\" not in relative_literal
                and not relative_literal.startswith(("~", "$", "%"))
                and not constraint.endswith("//")
                and all(part not in {"", ".", ".."} for part in relative_literal.split("/"))
                and posixpath.join(base, relative_literal) == resolved_constraint
                and constraint_kind in {"exact", "directory"}
            )
            if not valid_relative:
                root_target_valid = False
        elif constraint_kind in {"exact", "directory"} and filesystem_subject and not (
            constraint.startswith("/") or (len(constraint) >= 3 and constraint[1:3] in {":\\", ":/"})
        ):
            root_target_valid = False
        selection_source_id = origin["selection_source_id"]
        selection = sources.get(selection_source_id) if selection_source_id else None
        selected_by_host = bool(
            selection
            and selection["kind"] == "host_call"
            and selection.get("target") == req["target"]
            and selection.get("target_kind") == subject_kind
            and selection["unit"] == req["unit"]
            and selection["revision"] == req["revision"]
            and source is not None
            and source["seq"] <= selection["seq"] <= watermark
            and any(
                fact["call_source_id"] == selection_source_id
                and fact["target"] == req["target"]
                and fact["requirement_id"] == req["id"]
                for fact in valid_facts.values()
            )
        )
        if constraint_kind == "exact":
            root_target_allowed = (
                resolved_constraint == req["target"] and (selected_by_host or req["kind"] == "constraint")
                if relative_constraint else constraint == req["target"]
            )
        elif constraint_kind == "directory":
            directory = resolved_constraint if relative_constraint else constraint.rstrip("/")
            root_target_allowed = bool(
                directory and req["target"].startswith(directory + "/")
                and ".." not in req["target"].split("/")
                and ((selected_by_host or req["kind"] == "constraint")
                     if relative_constraint else constraint.endswith("/"))
            )
        else:
            root_target_allowed = selected_by_host
        typed_host_conflict = any(
            f["requirement_id"] == key and f["target"] == req["target"]
            and f["kind"] in {"readiness", "action_event", "state_outcome"}
            and sources[f["call_source_id"]].get("target_kind") != subject_kind
            for f in valid_facts.values()
        )
        target_valid = (
            root_target_valid
            and not typed_host_conflict
            and (not filesystem_subject or target_is_absolute)
            and (not filesystem_subject or not (constraint_kind in {"exact", "directory"} and not relative_constraint and not target_is_absolute))
            and origin["resolved"] == req["target"]
            and (origin["observed"] is None if req["kind"] == "constraint"
                 else origin["observed"] == req["target"])
            and root_target_allowed
            and (constraint_kind != "work_unit" or selected_by_host)
            and (origin["implementation_choice"] is None if req["kind"] == "constraint"
                 else origin["implementation_choice"] == req["target"])
            and (origin["host_selection"] is None if req["kind"] == "constraint"
                 else origin["host_selection"] == req["target"])
        )
        if req["status"] == "legacy_review" or not source_valid or not target_valid:
            predicates[key] = "legacy_review"
            continue
        if req["kind"] == "constraint":
            mutation_facts = [f for f in historical_effect_facts.values() if (
                f["requirement_id"] == key
                and f["unit"] == req["unit"]
                and f["revision"] == req["revision"]
                and f["target"] == req["target"]
                and f["kind"] == "action_event"
                and f["predicate"] == "mutation_applied"
                and f["outcome"] == "success"
                and sources[f["call_source_id"]].get("target") == req["target"]
                and sources[f["call_source_id"]].get("target_kind") == subject_kind
            )] if req["predicate"] == "no_mutation" else []
            root_seq = sources[req["source"]["source_id"]]["seq"]
            def origin_bound(f: dict) -> int:
                call = sources[f["call_source_id"]]
                origin_id = call.get("origin_root_source_id")
                return sources[origin_id]["seq"] if origin_id is not None else call["seq"]

            violated = any(
                origin_bound(f) >= root_seq
                and sources[f["call_source_id"]]["seq"] > root_seq
                and f["seq"] <= watermark for f in mutation_facts
            )
            crossing = any(
                origin_bound(f) < root_seq <= f["seq"]
                or sources[f["call_source_id"]]["seq"] <= root_seq <= f["seq"]
                for f in mutation_facts
            )
            predicates[key] = (
                "constraint_violated" if violated else
                "constraint_unresolved" if crossing else "constraint_active"
            )
            continue
        matched = [
            f
            for f in valid_facts.values()
            if (f["unit"], f["revision"], f["target"], f["predicate"])
            == (req["unit"], req["revision"], req["target"], req["predicate"])
            and f["requirement_id"] == key
            and f["kind"] == req["evidence_kind"]
            and (f["kind"] == "delivery" or sources[f["call_source_id"]].get("target_kind") == subject_kind)
            and f["seq"] >= req["seq"]
        ]
        matched.sort(key=lambda f: f["seq"])
        matched = matched[-1:] if matched else []
        matched = [f for f in matched if f["outcome"] == "success"]
        if req["kind"] == "information":
            matched = [
                f
                for f in matched
                if f["kind"] == "delivery"
                and sources[f["source_id"]]["turn"] == snapshot["turn"]
            ]
            if matched:
                delivery.append(key)
        else:
            matched = [
                f for f in matched if f["kind"] in {"action_event", "state_outcome"}
            ]
        predicates[key] = (
            "satisfied" if matched and req["kind"] != "unknown" else "insufficient"
        )
    actions: list[dict] = []
    rejected: list[dict] = []
    for candidate in snapshot["actions"]:
        reason = "action_basis_insufficient"
        req = current.get(candidate["requirement_id"])
        if candidate["seq"] > watermark:
            continue
        valid = bool(
            req
            and candidate["schema"] == "current-action-basis/v1"
            and candidate["state"] == "current"
            and candidate["owner"] == "assistant"
            and candidate["action"] not in {"generic_work", "unknown"}
            and predicates[req["id"]] == "insufficient"
            and req["kind"] in {"execution", "proof"}
            and _source_matches(candidate["source"], sources, root=True)
            and candidate["source"] == req["source"]
            and all(
                candidate[k] == req[k]
                for k in ("unit", "revision", "scope_sha256", "target", "predicate")
            )
            and candidate["seq"] >= req["seq"]
            and all(cid in released for cid in req["condition_ids"])
        )
        if valid:
            relation = candidate["relation"]
            valid = relation == "direct" and candidate["action"] == req["action"]
            # Substep admissibility is explicit in the root requirement predicate,
            # never inferred from a broad resume or caller-supplied owner.
            valid |= (
                relation == "verification_substep"
                and req["predicate"] == "test_passed"
                and candidate["action"] == "test_verify"
            )
            valid |= (
                relation == "readback_substep"
                and req["predicate"] == "state_matches"
                and candidate["action"] == "readback"
            )
        ready = candidate["readiness_fact_ids"]
        valid = (
            valid
            and bool(ready)
            and all(
                fid in valid_facts
                and valid_facts[fid]["kind"] == "readiness"
                and valid_facts[fid]["outcome"] == "success"
                and valid_facts[fid]["requirement_id"] == candidate["requirement_id"]
                and (
                    valid_facts[fid]["unit"],
                    valid_facts[fid]["revision"],
                    valid_facts[fid]["target"],
                )
                == (candidate["unit"], candidate["revision"], candidate["target"])
                for fid in ready
            )
        )
        if valid:
            actions.append(
                {
                    k: candidate[k]
                    for k in (
                        "requirement_id",
                        "unit",
                        "revision",
                        "action",
                        "target",
                        "predicate",
                        "owner",
                        "source",
                        "seq",
                    )
                }
            )
        else:
            rejected.append(
                {"requirement_id": candidate["requirement_id"], "reason": reason}
            )
    intent = snapshot["intent"]
    intent_span = intent["source"]
    intent_source = sources.get(intent_span["source_id"]) if intent_span else None
    intent_valid = bool(
        intent_span
        and _source_matches(intent_span, sources, root=True)
        and intent_source["unit"] == unit
        and intent_source["revision"] == revision
    )
    intent_text = ""
    if intent_valid:
        intent_text = (
            intent_source["text"]
            .encode("utf-8")[intent_span["start"] : intent_span["end"]]
            .decode("utf-8")
            .strip()
        )
    # Reuse the accepted recognizers without adding words or requiring a
    # rewritten prompt. Source spans still require a current root binding.
    from pathlib import Path

    rules = load_strict(
        (
            Path(__file__).resolve().parent.parent / "assets/core-intent-v2.json"
        ).read_text(encoding="utf-8")
    )["patterns"]
    # Quotes and code are data, even when they contain a persistence phrase.
    speech = re.sub(
        r"```[\s\S]*?```|`[^`]*`|“[^”]*”|‘[^’]*’|\"[^\"]*\"|(?m:^\s*>.*$)",
        "",
        intent_text,
    )
    resume_match = bool(re.search(rules["EXECUTION_RESUME_RE"], speech, re.I))
    persistence_match = bool(
        re.search(rules["USER_PERSISTENCE_RE"], speech, re.I | re.S)
    )
    persistence = bool(
        intent_valid
        and persistence_match
        and intent["kind"] in {"persistence", "persistence_and_resume"}
    )
    resumed = bool(
        intent_valid
        and resume_match
        and intent["kind"] in {"resume", "persistence_and_resume"}
        and actions
    )
    external = sorted(
        {
            f["operation_id"]
            for f in valid_facts.values()
            if f["unit"] in units
            and f["kind"] == "external_operation"
            and f["outcome"] == "unknown"
            and f["operation_id"]
            and f["requirement_id"] in current
            and f["revision"] == current[f["requirement_id"]]["revision"]
            and f["condition_id"] in conditions
            and f["condition_id"] not in released
            and conditions[f["condition_id"]]["kind"] == "external_dependency"
            and conditions[f["condition_id"]]["operation_id"] == f["operation_id"]
            and f["condition_id"] in current[f["requirement_id"]]["condition_ids"]
        }
    )
    missing = sorted(
        k
        for k, r in current.items()
        if r["required"] and predicates[k] not in {"satisfied", "constraint_active"}
    )
    # A parent cannot certify around required children, nor can an empty
    # interpretation certify an unrepresented root source.
    represented = {r["source"]["source_id"] for r in current.values()}
    missing_sources = {
        key
        for key, source in sources.items()
        if source["kind"] == "root"
        and source["unit"] in units
        and (source["unit"] != unit or source["revision"] == revision)
    } - represented
    certifiable = not (
        missing or coverage_errors or unknown_coverage or missing_sources
    )
    reasons = []
    if snapshot["completion_claim"] and not certifiable:
        reasons.append("wrong_whole_completion")
    if snapshot["proof_violation"]:
        reasons.append("explicit_proof_unsatisfied")
    if actions and persistence:
        reasons.append("explicit_user_persistence")
    if resumed:
        reasons.append("resume_with_actionable_work")
    correction = bool(
        reasons and snapshot["corrections_used"] == 0 and snapshot["progress_changed"]
    )
    return {
        "schema": "core-state/v2",
        "unit": unit,
        "revision": revision,
        "as_of": watermark,
        "coverage": snapshot["coverage"],
        "predicates": predicates,
        "delivery": sorted(delivery),
        "facts": sorted(valid_facts),
        "current_actions": actions,
        "rejected_actions": rejected,
        "unmet_requirements": missing,
        "certifiable": certifiable,
        "coverage_errors": sorted(set(coverage_errors)),
        "unknown_coverage": sorted(set(unknown_coverage)),
        "target_origins": {k: r["target_origin"] for k, r in current.items()},
        "conditions": {
            k: "released" if k in released else "pending" for k in conditions
        },
        "explicit_user_persistence": persistence,
        "resume_with_actionable_work": resumed,
        "registered_external_operations": external,
        "ordinary_path_interference": False,
        "stop": "bounded_correction"
        if correction
        else "typed_wait"
        if external and not actions
        else "ordinary_end",
        "reason_codes": reasons,
        "correction_count": int(correction),
        "goal_complete_allowed": not snapshot["goal_contract_adopted"] or certifiable,
        "release_state": snapshot["release_state"],
    }


if __name__ == "__main__":
    import sys

    print(canonical_bytes(project(load_strict(sys.stdin.read()))).decode("utf-8"))
