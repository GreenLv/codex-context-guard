#!/usr/bin/env python3
"""Zero-model batch checks. Passing is input readiness, never host acceptance.

Local manifests may contain fixture paths; results contain only bounded IDs,
digests and reason codes. No login, model call, permission change or network
operation is performed. A missing effective execution route stays unknown.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

SCHEMA = "cg-native-batch/v1"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
INPUT_ROLES = {"hook_capture", "git_witness", "continuity_witness", "cleanup_witness", "oracle"}
CONTRACTS = {f"INV-{index:02d}" for index in range(1, 11)} | {
    f"CG142-{index:02d}" for index in range(1, 5)}


def read_json(path: Path) -> dict[str, Any]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result
    if path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("unsafe_manifest")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("manifest_not_object")
    return value


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wait_budget(turns: int, turn_seconds: int, *, startup: int, compact: int,
                cleanup: int) -> dict[str, int]:
    if any(type(n) is not int or n <= 0 for n in (turns, turn_seconds, startup, compact, cleanup)):
        raise ValueError("invalid_budget")
    return {"inner_turn": turn_seconds,
            "outer_run": startup + turns * turn_seconds + compact + cleanup,
            "outer_resume": startup + turn_seconds + cleanup}


def validate_batch(plan: dict[str, Any]) -> dict[str, Any]:
    errors: set[str] = set()
    unknown = ["effective_child_permissions", "official_hook_trust", "native_lifecycle",
               "commentary_answer_binding", "windows_host_behavior"]
    if plan.get("schema") != SCHEMA:
        errors.add("unsupported_schema")
    for field, pattern in (("source_commit", HEX40), ("runtime_tree_sha256", HEX64),
                           ("plan_sha256", HEX64)):
        if not isinstance(plan.get(field), str) or not pattern.fullmatch(plan[field]):
            errors.add("invalid_" + field)
    fixtures = plan.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        errors.add("fixtures_required")
    else:
        for fixture in fixtures:
            if not isinstance(fixture, dict):
                errors.add("invalid_fixture")
                continue
            initial = fixture.get("initial_head")
            if not isinstance(initial, str) or not HEX40.fullmatch(initial):
                errors.add("initial_head_required_root_commit_unsupported")
                continue
            repo = fixture.get("repo")
            if not isinstance(repo, str) or not Path(repo).is_dir():
                errors.add("fixture_unavailable")
                continue
            # Local Git object inspection only; no credential lane is used.
            result = subprocess.run(["git", "-C", repo, "rev-parse", "--verify", "HEAD"],
                                    capture_output=True, check=False)
            if result.returncode or result.stdout.decode("ascii", errors="replace").strip() != initial:
                errors.add("fixture_head_mismatch")
            paths = fixture.get("changed_paths")
            if (not isinstance(paths, list) or not paths or len(set(map(str, paths))) != len(paths)
                    or any(not isinstance(p, str) or not p or p.startswith(("/", "\\"))
                           or ".." in p.replace("\\", "/").split("/") or ":" in p for p in paths)):
                errors.add("invalid_changed_paths")
    sessions = plan.get("sessions")
    if not isinstance(sessions, list) or any(not isinstance(s, dict) for s in sessions):
        errors.add("sessions_required")
    else:
        ids = [s.get("id") for s in sessions]
        if any(not isinstance(s, str) or not s for s in ids) or len(set(map(str, ids))) != len(ids):
            errors.add("independent_sessions_required")
        if {s.get("role") for s in sessions} != {"git_trust", "continuity"} or len(sessions) != 2:
            errors.add("composite_roles_required")
    inputs = plan.get("inputs")
    seen_roles: set[str] = set()
    if not isinstance(inputs, list):
        errors.add("input_inventory_required")
    else:
        for item in inputs:
            if not isinstance(item, dict) or item.get("role") not in INPUT_ROLES:
                errors.add("invalid_input_role")
                continue
            seen_roles.add(item["role"])
            path = item.get("path")
            expected = item.get("sha256")
            if not isinstance(path, str) or not isinstance(expected, str) or not HEX64.fullmatch(expected):
                errors.add("invalid_input_identity")
                continue
            candidate = Path(path)
            if candidate.is_symlink() or not candidate.is_file():
                errors.add("input_unavailable")
            elif candidate.stat().st_size > 8 * 1024 * 1024 or sha(candidate) != expected:
                errors.add("input_digest_mismatch")
    if seen_roles != INPUT_ROLES:
        errors.add("incomplete_input_inventory")
    expectations = plan.get("expectations")
    if not isinstance(expectations, list) or not expectations:
        errors.add("expectation_mapping_required")
    else:
        for row in expectations:
            if not isinstance(row, dict) or row.get("contract") not in CONTRACTS:
                errors.add("expectation_without_contract")
            elif row.get("kind") != "current_contract":
                errors.add("new_expectation_requires_scope_decision")
            elif row.get("assertion") in {"typed_phase_wait", "root_controls_nonempty"}:
                errors.add("withdrawn_expectation_not_a_product_failure")
    try:
        budget = wait_budget(**plan.get("budget", {}))
        if plan.get("driver_timeouts") != budget:
            errors.add("driver_timeout_chain_mismatch")
    except (TypeError, ValueError):
        budget = None
        errors.add("invalid_budget")
    # Parent filesystem access and a claimed elevated route are not evidence of
    # the tool child's sandbox/ACL. This preflight intentionally cannot pass it.
    if plan.get("permission_route") not in {"same_restricted_route", "unavailable"}:
        errors.add("permission_route_unverified")
    return {"schema": "cg-native-batch-preflight/v1",
            "status": "failed" if errors else "inputs_ready",
            "errors": sorted(errors), "unknown": unknown, "budget": budget,
            "model_requests": 0, "acceptance": "not_run"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        plan = read_json(args.manifest)
        result = validate_batch(plan)
        result["manifest_sha256"] = sha(args.manifest)
        # Exclusive output preserves failed attempts and prevents receipt reuse.
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
    except (OSError, ValueError, TypeError):
        print("batch_preflight=failed; input_or_output_invalid")
        return 2
    print("batch_preflight=" + result["status"] + "; acceptance_not_run")
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
