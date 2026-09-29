#!/usr/bin/env python3
"""Validate repository-only GitHub Actions topology and immutable action refs."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
EXTERNAL_USE = re.compile(r"^\s*(?:-\s*)?uses:\s+([^\s#]+)@([^\s#]+)", re.MULTILINE)
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.validation.ci_policy import CI_LANES, DAILY_FOCUSED, DAILY_FULL  # noqa: E402


def validate_action_pins(workflows: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted((*workflows.glob("*.yml"), *workflows.glob("*.yaml"))):
        text = path.read_text(encoding="utf-8")
        for action, ref in EXTERNAL_USE.findall(text):
            if action.startswith("./"):
                continue
            if not FULL_COMMIT.fullmatch(ref):
                errors.append(
                    f"{path.name}: external action {action}@{ref} must use a full commit"
                )
    return errors


def validate_lane_failure_propagation(lane: str) -> list[str]:
    """A later successful command must not mask a failed regression suite."""
    steps = re.split(r"(?=^      - )", lane, flags=re.MULTILINE)
    commands = (
        "python scripts/run_current_behavior_suite.py",
        "python scripts/check_phase3_transition.py",
    )
    owners = [
        [index for index, step in enumerate(steps) if command in step]
        for command in commands
    ]
    if any(len(indices) != 1 for indices in owners) or owners[0] == owners[1]:
        return ["current-behavior and phase3 must run in distinct CI steps"]
    if any("continue-on-error:" in steps[indices[0]] for indices in owners):
        return ["current-behavior and phase3 CI steps must propagate failures"]
    return []


def validate_locked_tools(workflow: str) -> list[str]:
    """CI must check lock freshness and consume its resolved tool closure."""
    if 'uv sync --locked --only-group validation' not in workflow:
        return ['validation tools must consume the checked lockfile']
    return []


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    workflows = root / ".github" / "workflows"
    try:
        candidate = (workflows / "ci.yml").read_text(encoding="utf-8")
        lane = (workflows / "ci-lane.yml").read_text(encoding="utf-8")
        pull_request = (workflows / "validation-shadow.yml").read_text(encoding="utf-8")
    except OSError as exc:
        return [f"invalid CI workflow: {exc}"]

    errors.extend(validate_action_pins(workflows))
    errors.extend(validate_lane_failure_propagation(lane))
    errors.extend(validate_locked_tools(candidate))
    errors.extend(validate_locked_tools(pull_request))
    if "strategy:" in candidate or "matrix:" in candidate:
        errors.append("candidate lanes must remain independent jobs")
    reusable_call = "uses: ./.github/workflows/ci-lane.yml"
    if candidate.count(reusable_call) != len(CI_LANES) + len(DAILY_FOCUSED):
        errors.append("candidate CI must declare all full and focused lanes")
    for job_id, display_name, runner, python_version in CI_LANES:
        expected = (
            f"  {job_id}:\n"
            f"    name: {display_name}\n"
            "    needs: classify\n"
            + ("" if job_id in DAILY_FULL else "    if: needs.classify.outputs.profile == 'full'\n")
            + f"    {reusable_call}\n"
            "    with:\n"
            f"      runner: {runner}\n"
            f'      python-version: "{python_version}"'
        )
        if expected not in candidate:
            errors.append(f"candidate lane is missing or malformed: {job_id}")
    required_section = candidate.split("  required:\n", 1)[-1]
    for job_id in ["classify", "static", *[row[0] for row in CI_LANES], *DAILY_FOCUSED, "portable_windows"]:
        if f"      - {job_id}\n" not in required_section:
            errors.append(f"required summary does not depend on {job_id}")
    for job_id, version in zip(DAILY_FOCUSED, ("3.10", "3.14")):
        expected = (
            f"  {job_id}:\n"
            f"    name: Windows platform / Python {version}\n"
            "    needs: classify\n"
            "    if: needs.classify.outputs.profile == 'daily'\n"
            f"    {reusable_call}\n"
            "    with:\n"
            "      runner: windows-latest\n"
            f'      python-version: "{version}"\n'
            "      suite: windows-platform"
        )
        if expected not in candidate:
            errors.append(f"focused platform lane is missing or malformed: {job_id}")
    if "continue-on-error" in candidate or "continue-on-error" in lane:
        errors.append("candidate jobs must propagate failures")
    for forbidden in ("pull_request:", 'tags: ["v*"]'):
        if forbidden in candidate:
            errors.append(f"candidate CI must not run on {forbidden.rstrip(':')}")
    for fragment in (
        "  static:",
        "python scripts/audit_commit_identity.py .",
        "python scripts/validate_public_repo.py .",
        "python tools/validation/validate_workflows.py .",
        "python scripts/audit_public_tree.py .",
        "ruff check .",
        "python -m compileall -q scripts tests tools",
        "  required:",
        "if: always()",
        "python -m tools.validation.ci_policy verify",
        "${{ toJSON(needs) }}",
        "default: full",
        "python -m tools.validation.ci_policy select",
    ):
        if fragment not in candidate:
            errors.append(f"candidate workflow contract is missing: {fragment}")
    for fragment in (
        "workflow_call:",
        "runs-on: ${{ inputs.runner }}",
        "python-version: ${{ inputs.python-version }}",
        "python scripts/run_current_behavior_suite.py",
        "python scripts/check_phase3_transition.py",
        "python scripts/context_guard.py self-test",
        "python -m tools.validation.run_windows_platform_suite",
        "if: inputs.suite == 'full'",
        "if: inputs.suite == 'windows-platform'",
    ):
        if fragment not in lane:
            errors.append(f"reusable lane contract is missing: {fragment}")
    for fragment in (
        "pull_request:",
        "cancel-in-progress: true",
        "name: PR validation required",
        "if: always()",
    ):
        if fragment not in pull_request:
            errors.append(f"PR workflow contract is missing: {fragment}")
    if "continue-on-error" in pull_request:
        errors.append("PR validation must remain blocking")
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    errors = validate(args.repo_root.resolve())
    for error in errors:
        print(f"[ERROR] {error}")
    if errors:
        return 1
    print("[OK] repository workflow contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
