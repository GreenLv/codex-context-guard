"""Regression tests for selected validation command mapping."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "tools" / "validation" / "run_selected_validation.py"
SPEC = importlib.util.spec_from_file_location("run_selected_validation", SCRIPT)
assert SPEC and SPEC.loader
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def plan(gates: list[str], paths: list[str]) -> dict[str, object]:
    return {
        "schema": "change-scoped-validation-plan/v1",
        "gates": gates,
        "changed_paths": paths,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
    }


class SelectedValidationTests(unittest.TestCase):
    def test_docs_do_not_run_runtime_or_install_gates(self) -> None:
        commands = RUNNER.commands_for(plan(["docs_contract"], ["README.md"]))
        joined = [" ".join(command) for command in commands]
        self.assertTrue(any("validate_public_repo.py" in item for item in joined))
        self.assertTrue(any("tests.test_public_contract" in item for item in joined))
        self.assertFalse(any("test_context_guard" in item or "test_manage_plugin" in item for item in joined))

    def test_runtime_commands_are_deduplicated(self) -> None:
        commands = RUNNER.commands_for(
            plan(["focused_tests", "lint_compile", "repo_contract", "runtime_tests", "self_test"], ["scripts/context_guard.py"])
        )
        joined = [" ".join(command) for command in commands]
        self.assertEqual(sum(item == "ruff check ." for item in joined), 1)
        self.assertEqual(sum("scripts/context_guard.py self-test" in item for item in joined), 1)

    def test_unknown_gate_fails_closed(self) -> None:
        with self.assertRaisesRegex(RUNNER.RunSelectionError, "unknown gate"):
            RUNNER.commands_for(plan(["invented"], ["scripts/context_guard.py"]))

    def test_full_candidate_runs_full_suite_once(self) -> None:
        commands = RUNNER.commands_for(plan(["full_candidate"], ["validation-map.json"]))
        joined = [" ".join(command) for command in commands]
        self.assertEqual(sum("unittest discover" in item for item in joined), 1)
        self.assertEqual(sum(item == "ruff check ." for item in joined), 1)
        self.assertTrue(any("compileall -q scripts tests tools" in item for item in joined))


if __name__ == "__main__":
    unittest.main()
