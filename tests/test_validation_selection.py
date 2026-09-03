#!/usr/bin/env python3
"""Golden tests for this repository's validation selection policy."""

from __future__ import annotations

import importlib.util
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "select_validation", ROOT / "tools" / "validation" / "select_validation.py"
)
assert SPEC and SPEC.loader
SELECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SELECTOR)


class ValidationSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mapping, cls.map_sha256 = SELECTOR.load_map(ROOT / "validation-map.json")

    def classify(self, *paths: str) -> dict[str, object]:
        return SELECTOR.classify(self.mapping, list(paths), map_sha256=self.map_sha256, base="a" * 40, head="b" * 40)

    def test_docs_only_preserves_runtime_and_artifact(self) -> None:
        plan = self.classify("docs/ARCHITECTURE.md")
        self.assertEqual(plan["gates"], ["docs_contract"])
        self.assertEqual(plan["invalidates"], ["documentation"])
        self.assertFalse(plan["full_required"])

    def test_test_only_selects_focused_group(self) -> None:
        plan = self.classify("tests/test_context_guard.py")
        self.assertEqual(plan["gates"], ["focused_tests", "repo_contract"])
        self.assertEqual(plan["invalidates"], ["candidate_matrix"])

    def test_runtime_invalidates_native_evidence(self) -> None:
        plan = self.classify("scripts/context_guard.py")
        self.assertIn("runtime_tests", plan["gates"])
        self.assertIn("native_runtime", plan["invalidates"])

    def test_packaging_invalidates_artifact_and_downstream_evidence(self) -> None:
        plan = self.classify("pyproject.toml")
        self.assertEqual(
            plan["invalidates"],
            ["artifact", "native_artifact", "native_runtime", "publication_identity"],
        )

    def test_packaged_repository_tool_invalidates_runtime_tree_evidence(self) -> None:
        plan = self.classify("scripts/validate_public_repo.py")
        for evidence in ("artifact", "native_artifact", "native_runtime", "publication_identity"):
            self.assertIn(evidence, plan["invalidates"])

    def test_ci_tool_does_not_invalidate_plugin_runtime_tree(self) -> None:
        plan = self.classify("tools/validation/validate_workflows.py")
        self.assertEqual(plan["invalidates"], ["candidate_matrix"])

    def test_removing_legacy_packaged_ci_tool_invalidates_old_runtime_tree(self) -> None:
        plan = self.classify("scripts/select_validation.py")
        self.assertIn("artifact", plan["invalidates"])
        self.assertIn("native_runtime", plan["invalidates"])

    def test_shared_contract_selects_peer_gate(self) -> None:
        plan = self.classify("tests/fixtures/conformance/digest_v3/cases.json")
        self.assertEqual(plan["contracts"], ["context_guard_semantics_v1", "digest_v3"])
        self.assertEqual(plan["peer_gates"], {"dsh_context_guard": ["contract_tests"]})

    def test_release_authorization_contract_selects_codex_sync_peer_gate(self) -> None:
        plan = self.classify("contracts/release-authorization-compatibility.json")
        self.assertEqual(plan["contracts"], ["release_authorization_compatibility_v1"])
        self.assertEqual(
            plan["peer_gates"],
            {"codex_sync": ["release_contract_tests"]},
        )
        self.assertIn("cross_repository_contract", plan["invalidates"])
        self.assertIn("publication_identity", plan["invalidates"])

    def test_conformance_test_code_does_not_invalidate_peer_contract(self) -> None:
        plan = self.classify("tests/test_conformance_fixtures.py")
        self.assertEqual(plan["contracts"], [])
        self.assertEqual(plan["peer_gates"], {})

    def test_unknown_path_fails_closed(self) -> None:
        plan = self.classify("unexpected/new-format.bin")
        self.assertTrue(plan["full_required"])
        self.assertEqual(plan["unknown_paths"], ["unexpected/new-format.bin"])
        self.assertEqual(plan["gates"], ["full_candidate"])

    def test_validation_infrastructure_requires_full_candidate(self) -> None:
        plan = self.classify("validation-map.json")
        self.assertTrue(plan["full_required"])
        self.assertEqual(plan["gates"], ["full_candidate"])

    def test_overlapping_rules_are_additive(self) -> None:
        plan = self.classify("docs/SEMANTIC_COMPATIBILITY.md")
        self.assertEqual(plan["gates"], ["contract_tests", "docs_contract", "focused_tests"])

    def test_empty_diff_selects_nothing(self) -> None:
        plan = self.classify()
        self.assertEqual(plan["gates"], [])
        self.assertFalse(plan["full_required"])

    def test_current_tracked_tree_has_no_unknown_paths(self) -> None:
        paths = subprocess.run(["git", "-C", str(ROOT), "ls-files"], text=True, capture_output=True, check=True).stdout.splitlines()
        self.assertEqual(self.classify(*paths)["unknown_paths"], [])

    def test_rejects_unsafe_changed_path(self) -> None:
        with self.assertRaises(SELECTOR.SelectionError):
            self.classify("../outside")


if __name__ == "__main__":
    unittest.main()
