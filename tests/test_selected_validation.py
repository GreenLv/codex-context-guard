"""Regression tests for selected validation command mapping."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
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
    def test_single_test_change_runs_owning_module_without_full_suite(self) -> None:
        commands = RUNNER.commands_for(plan(
            ["focused_tests", "repo_contract"], ["tests/test_native_acceptance.py"],
        ))
        modules = [command for command in commands if command[1:3] == ["-m", "unittest"]]
        self.assertEqual(len(modules), 1)
        self.assertEqual(set(modules[0][3:]), {
            "tests.test_native_acceptance", "tests.test_public_contract",
        })
        self.assertFalse(any("scripts/run_current_behavior_suite.py" in command for command in commands))

    def test_shared_test_harness_includes_all_static_importers(self) -> None:
        selected = RUNNER.focused_modules(["tests/test_cg122_p0_counterexamples.py"])
        self.assertIn("tests.test_cg122_p1_repair", selected)
        self.assertIn("tests.test_cg122_p2_scope_timing", selected)
        self.assertIn("tests.test_host_direct_git_gates", selected)
        self.assertNotIn("tests.test_native_acceptance", selected)

    def test_transitive_and_relative_test_importers_are_selected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            files = {
                "test_a.py": "VALUE = 1\n",
                "test_b.py": "from tests.test_a import VALUE\n",
                "test_c.py": "from . import test_b\n",
                "test_d.py": "from tests import test_c\n",
                "test_unrelated.py": "VALUE = 2\n",
            }
            for name, content in files.items():
                (root / "tests" / name).write_text(content, encoding="utf-8")
            self.assertEqual(RUNNER.focused_modules(["tests/test_a.py"], root), [
                "tests.test_a", "tests.test_b", "tests.test_c", "tests.test_d",
            ])
            (root / "tests" / "test_b.py").write_text("bad syntax [", encoding="utf-8")
            self.assertIsNone(RUNNER.focused_modules(["tests/test_a.py"], root))

    def test_unknown_deleted_and_historical_owners_keep_full_candidate(self) -> None:
        for path in ("tests/fixtures/unknown.json", "tests/test_deleted.py",
                     "tests/test_context_guard_012_baseline.py", "scripts/context_guard.py"):
            with self.subTest(path=path):
                commands = RUNNER.commands_for(plan(["focused_tests"], [path]))
                self.assertTrue(any("scripts/run_current_behavior_suite.py" in command for command in commands))
                self.assertTrue(any("scripts/check_phase3_transition.py" in command for command in commands))
                self.assertIn(["ruff", "check", "."], commands)

    def test_selected_command_executes_nonempty_owner_and_propagates_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            (root / "tests" / "__init__.py").touch()
            target = root / "tests" / "test_selected.py"
            target.write_text("import unittest\nclass Test(unittest.TestCase):\n"
                              "    def test_result(self): self.assertEqual(1, 2)\n", encoding="utf-8")
            modules = RUNNER.focused_modules(["tests/test_selected.py"], root)
            result = subprocess.run([sys.executable, "-m", "unittest", *modules],
                                    cwd=root, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Ran 1 test", result.stderr)

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

    def test_full_behavior_selection_does_not_repeat_covered_test_modules(self) -> None:
        commands = RUNNER.commands_for(plan(
            ["focused_tests", "runtime_tests", "contract_tests", "repo_contract",
             "install_lifecycle", "lint_compile", "self_test"],
            ["scripts/context_guard.py", "tests/test_context_guard.py"],
        ))
        joined = [" ".join(command) for command in commands]
        self.assertEqual(sum("run_current_behavior_suite.py" in item for item in joined), 1)
        self.assertEqual(sum("check_phase3_transition.py" in item for item in joined), 1)
        self.assertFalse(any("-m unittest" in item for item in joined))
        for standalone in ("validate_public_repo.py", "audit_public_tree.py",
                           "context_guard.py self-test", "ruff check .",
                           "compileall -q scripts tests tools"):
            self.assertTrue(any(standalone in item for item in joined), standalone)

    def test_subsets_still_execute_without_full_behavior_selection(self) -> None:
        commands = RUNNER.commands_for(plan(
            ["runtime_tests", "contract_tests", "repo_contract", "install_lifecycle"],
            ["scripts/context_guard.py"],
        ))
        joined = "\n".join(" ".join(command) for command in commands)
        for module in ("tests.test_context_guard", "tests.test_context_guard_v095",
                       "tests.test_conformance_fixtures", "tests.test_reference_digest_encoder",
                       "tests.test_public_contract", "tests.test_manage_plugin",
                       "tests.test_smoke_installed"):
            self.assertIn(module, joined)
        self.assertNotIn("run_current_behavior_suite.py", joined)

    def test_deduplicated_subsets_are_in_current_behavior_discovery(self) -> None:
        census_path = SCRIPT.parents[2] / "scripts" / "run_current_behavior_suite.py"
        spec = importlib.util.spec_from_file_location("selected_validation_census", census_path)
        assert spec and spec.loader
        census = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(census)
        discovered = set(census.discover_current_modules())
        subsets = RUNNER.commands_for(plan(
            ["runtime_tests", "contract_tests", "repo_contract", "install_lifecycle"], []
        ))
        module_names = {arg.removeprefix("tests.") for command in subsets for arg in command
                        if arg.startswith("tests.")}
        self.assertTrue(module_names)
        self.assertTrue(module_names <= discovered, module_names - discovered)

    def test_unknown_gate_fails_closed(self) -> None:
        with self.assertRaisesRegex(RUNNER.RunSelectionError, "unknown gate"):
            RUNNER.commands_for(plan(["invented"], ["scripts/context_guard.py"]))

    def test_full_candidate_runs_full_suite_once(self) -> None:
        commands = RUNNER.commands_for(plan(["full_candidate"], ["validation-map.json"]))
        joined = [" ".join(command) for command in commands]
        self.assertEqual(sum("run_current_behavior_suite.py" in item for item in joined), 1)
        self.assertEqual(sum("check_phase3_transition.py" in item for item in joined), 1)
        self.assertFalse(any("unittest discover" in item for item in joined))
        self.assertEqual(sum(item == "ruff check ." for item in joined), 1)
        self.assertTrue(any("compileall -q scripts tests tools" in item for item in joined))


if __name__ == "__main__":
    unittest.main()
