#!/usr/bin/env python3
"""Validate repository-only GitHub Actions topology and immutable action refs."""

from __future__ import annotations

import argparse
import re
from collections.abc import Sequence
from pathlib import Path

FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
EXTERNAL_USE = re.compile(r"^\s*(?:-\s*)?uses:\s+([^\s#]+)@([^\s#]+)", re.MULTILINE)
CI_LANES = (
    ("ubuntu_py310", "Ubuntu / Python 3.10", "ubuntu-latest", "3.10"),
    ("ubuntu_py311", "Ubuntu / Python 3.11", "ubuntu-latest", "3.11"),
    ("ubuntu_py312", "Ubuntu / Python 3.12", "ubuntu-latest", "3.12"),
    ("ubuntu_py313", "Ubuntu / Python 3.13", "ubuntu-latest", "3.13"),
    ("macos_py310", "macOS / Python 3.10", "macos-latest", "3.10"),
    ("macos_py311", "macOS / Python 3.11", "macos-latest", "3.11"),
    ("macos_py312", "macOS / Python 3.12", "macos-latest", "3.12"),
    ("macos_py313", "macOS / Python 3.13", "macos-latest", "3.13"),
    ("windows_py310", "Windows / Python 3.10", "windows-latest", "3.10"),
    ("windows_py311", "Windows / Python 3.11", "windows-latest", "3.11"),
    ("windows_py312", "Windows / Python 3.12", "windows-latest", "3.12"),
    ("windows_py313", "Windows / Python 3.13", "windows-latest", "3.13"),
)


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
    if "strategy:" in candidate or "matrix:" in candidate:
        errors.append("candidate lanes must remain independent jobs")
    reusable_call = "uses: ./.github/workflows/ci-lane.yml"
    if candidate.count(reusable_call) != len(CI_LANES):
        errors.append(f"candidate CI must call exactly {len(CI_LANES)} lanes")
    for job_id, display_name, runner, python_version in CI_LANES:
        expected = (
            f"  {job_id}:\n"
            f"    name: {display_name}\n"
            f"    {reusable_call}\n"
            "    with:\n"
            f"      runner: {runner}\n"
            f'      python-version: "{python_version}"'
        )
        if expected not in candidate:
            errors.append(f"candidate lane is missing or malformed: {job_id}")
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
        "python tools/validation/verify_required_jobs.py",
    ):
        if fragment not in candidate:
            errors.append(f"candidate workflow contract is missing: {fragment}")
    for fragment in (
        "workflow_call:",
        "runs-on: ${{ inputs.runner }}",
        "python-version: ${{ inputs.python-version }}",
        'python -m unittest discover -s tests -p "test_*.py"',
        "python scripts/context_guard.py self-test",
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
