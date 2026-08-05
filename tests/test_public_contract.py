#!/usr/bin/env python3
"""Regression tests for the standalone public repository contract."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = load("audit_public_tree", ROOT / "scripts" / "audit_public_tree.py")
contract = load("validate_public_repo", ROOT / "scripts" / "validate_public_repo.py")


class PublicContractTests(unittest.TestCase):
    def test_repository_contract(self) -> None:
        self.assertEqual(contract.validate(ROOT), [])

    def test_public_tree_has_no_private_material(self) -> None:
        self.assertEqual(audit.findings(ROOT), [])

    def test_audit_detects_private_material_and_generated_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "leak.txt").write_text(
                "private path: " + "/Users" + "/example/secret\n", encoding="utf-8"
            )
            (root / ".DS_Store").write_text("generated\n", encoding="utf-8")
            issues = audit.findings(root)
            self.assertTrue(any("macOS user-specific path" in item for item in issues))
            self.assertTrue(any("generated/private" in item for item in issues))


if __name__ == "__main__":
    unittest.main()
