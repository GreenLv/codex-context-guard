#!/usr/bin/env python3
"""Run repository-owned commands for one validated change-scope plan."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

PLAN_SCHEMA = "change-scoped-validation-plan/v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
ROOT = Path(__file__).resolve().parents[2]
HISTORICAL = "tests.test_context_guard_012_baseline"
TEST_PATH = re.compile(r"^tests/(test_[a-zA-Z0-9_]+)\.py$")
KNOWN_GATES = {
    "artifact_identity", "contract_tests", "docs_contract", "focused_tests",
    "full_candidate", "install_lifecycle", "lint_compile", "repo_contract",
    "runtime_tests", "self_test",
}


class RunSelectionError(ValueError):
    """Raised when a plan cannot be mapped to a closed command set."""


def unique(commands: list[list[str]]) -> list[list[str]]:
    result: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for command in commands:
        key = tuple(command)
        if key not in seen:
            seen.add(key)
            result.append(command)
    return result


def validate_plan(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != PLAN_SCHEMA:
        raise RunSelectionError(f"plan schema must be {PLAN_SCHEMA}")
    gates = value.get("gates")
    paths = value.get("changed_paths")
    if not isinstance(gates, list) or not gates or any(gate not in KNOWN_GATES for gate in gates):
        raise RunSelectionError("plan contains an empty or unknown gate set")
    if not isinstance(paths, list) or any(not isinstance(path, str) or not path for path in paths):
        raise RunSelectionError("plan changed_paths is invalid")
    for key in ("base_sha", "head_sha"):
        if value.get(key) is not None and not HEX40.fullmatch(value[key]):
            raise RunSelectionError(f"plan {key} is invalid")
    return value


def focused_modules(paths: list[str], root: Path = ROOT) -> list[str] | None:
    """Select changed test modules and their transitive static test importers.

    Shared fixtures, runtime changes, deleted modules, and unknown owners keep
    the full-candidate fallback. Do not guess ownership from a filename stem.
    """
    selected: set[str] = set()
    for path in paths:
        match = TEST_PATH.fullmatch(path)
        if match is None or not (root / path).is_file():
            return None
        name = "tests." + match.group(1)
        if name == HISTORICAL:
            return None
        selected.add(name)
    if not selected:
        return None
    imports: dict[str, set[str]] = {}
    try:
        for path in (root / "tests").glob("test_*.py"):
            name = "tests." + path.stem
            if name == HISTORICAL:
                continue
            dependencies: set[str] = set()
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    dependencies.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if node.level == 1:
                        module = "tests" + ("." + module if module else "")
                    dependencies.add(module)
                    if module == "tests":
                        dependencies.update("tests." + alias.name for alias in node.names)
            imports[name] = dependencies
    except (OSError, UnicodeError, SyntaxError):
        return None
    while True:
        expanded = selected | {name for name, dependencies in imports.items()
                               if dependencies & selected}
        if expanded == selected:
            return sorted(selected)
        selected = expanded


def commands_for(value: Any) -> list[list[str]]:
    plan = validate_plan(value)
    gates = set(plan["gates"])
    focused: list[str] = []
    if "focused_tests" in gates and "full_candidate" not in gates:
        selection = focused_modules(plan["changed_paths"])
        if selection is None:
            gates.add("full_candidate")
        else:
            focused = selection
    validate_repo = [sys.executable, "scripts/validate_public_repo.py", "."]
    audit_tree = [sys.executable, "scripts/audit_public_tree.py", "."]
    public_contract = [sys.executable, "-m", "unittest", "tests.test_public_contract"]
    current_behavior = [sys.executable, "scripts/run_current_behavior_suite.py"]
    historical_transition = [sys.executable, "scripts/check_phase3_transition.py"]
    commands: list[list[str]] = []
    # Full-candidate discovery covers all module subsets; focused selection
    # covers only its owning/importer modules and must retain other gate checks.
    if "full_candidate" in gates:
        commands.extend([
            validate_repo,
            audit_tree,
            current_behavior,
            historical_transition,
            [sys.executable, "scripts/context_guard.py", "self-test"],
            ["ruff", "check", "."],
            [sys.executable, "-m", "compileall", "-q", "scripts", "tests", "tools"],
        ])
    else:
        if {"docs_contract", "repo_contract", "artifact_identity"} & gates:
            commands.extend([validate_repo, audit_tree])
        if {"docs_contract", "repo_contract"} & gates:
            commands.append(public_contract)
        if "contract_tests" in gates:
            commands.append([
                sys.executable, "-m", "unittest",
                "tests.test_conformance_fixtures", "tests.test_reference_digest_encoder",
            ])
        if "runtime_tests" in gates:
            commands.append([
                sys.executable, "-m", "unittest",
                "tests.test_context_guard", "tests.test_context_guard_v095",
            ])
        if "focused_tests" in gates:
            commands.append([sys.executable, "-m", "unittest", *focused])
        if "install_lifecycle" in gates:
            commands.append([
                sys.executable, "-m", "unittest",
                "tests.test_manage_plugin", "tests.test_smoke_installed",
            ])
        if "self_test" in gates:
            commands.append([sys.executable, "scripts/context_guard.py", "self-test"])
        if "lint_compile" in gates:
            commands.extend([
                ["ruff", "check", "."],
                [sys.executable, "-m", "compileall", "-q", "scripts", "tests", "tools"],
            ])
    # Combine unittest modules so a shared owner selected by two gates runs once.
    modules = sorted({module for command in commands
                      if command[:3] == [sys.executable, "-m", "unittest"]
                      for module in command[3:]})
    if modules:
        commands = [command for command in commands
                    if command[:3] != [sys.executable, "-m", "unittest"]]
        commands.insert(0, [sys.executable, "-m", "unittest", *modules])
    if plan.get("base_sha") and plan.get("head_sha"):
        commands.append(["git", "diff", "--check", plan["base_sha"], plan["head_sha"], "--"])
    return unique(commands)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-json", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--list", action="store_true", dest="list_only")
    args = parser.parse_args(argv)
    try:
        commands = commands_for(json.loads(args.plan_json))
    except (json.JSONDecodeError, RunSelectionError) as exc:
        print(f"selected_validation=invalid: {exc}", file=sys.stderr)
        return 2
    if args.list_only:
        print(json.dumps(commands, indent=2))
        return 0
    for command in commands:
        print("+ " + " ".join(command), flush=True)
        result = subprocess.run(command, cwd=args.repo_root, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
