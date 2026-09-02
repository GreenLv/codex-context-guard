"""Focused tests for the portable native acceptance entrypoint."""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).parents[1] / "tools" / "validation" / "native_acceptance.py"
SPEC = importlib.util.spec_from_file_location("native_acceptance", SCRIPT)
assert SPEC and SPEC.loader
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)


class FakeManager:
    @staticmethod
    def tree_manifest(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
            for path in sorted(root.rglob("*")) if path.is_file()
        }


class NativeAcceptanceEntrypointTests(unittest.TestCase):
    def test_normalizes_public_github_ssh_remote(self) -> None:
        self.assertEqual(
            NATIVE.normalize_repository_url("git@github.com:owner/repo.git"),
            "https://github.com/owner/repo.git",
        )

    def test_rejects_credentialed_or_non_github_remote(self) -> None:
        for value in ("https://token@github.com/owner/repo.git", "ssh://example.invalid/repo"):
            with self.subTest(value=value), self.assertRaises(NATIVE.NativeRunError):
                NATIVE.normalize_repository_url(value)

    def test_runtime_digest_is_stable_and_byte_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "runtime.py"
            path.write_text("one", encoding="utf-8")
            first = NATIVE.runtime_digest(FakeManager, root)
            self.assertEqual(first, NATIVE.runtime_digest(FakeManager, root))
            path.write_text("two", encoding="utf-8")
            self.assertNotEqual(first, NATIVE.runtime_digest(FakeManager, root))

    def test_gate_is_bound_to_runtime_digest(self) -> None:
        value = NATIVE.gate("self_test", "a" * 64, passed=True)
        self.assertEqual(value["subject"], {"kind": "runtime_tree", "id": "a" * 64})
        self.assertEqual(value["evidence"]["mode"], "executed")

    def test_resolves_platform_launcher(self) -> None:
        with mock.patch.object(NATIVE.shutil, "which", return_value=r"C:\\npm\\codex.cmd"):
            self.assertEqual(
                NATIVE.resolve_executable("codex"),
                r"C:\\npm\\codex.cmd",
            )

    def test_rejects_missing_launcher(self) -> None:
        with mock.patch.object(NATIVE.shutil, "which", return_value=None):
            with self.assertRaisesRegex(NATIVE.NativeRunError, "executable not found"):
                NATIVE.resolve_executable("codex")

    def test_exact_source_rejects_untracked_files(self) -> None:
        source_commit = "a" * 40
        results = [
            subprocess.CompletedProcess(["git"], 0, source_commit + "\n", ""),
            subprocess.CompletedProcess(["git"], 0, "?? stray.txt\n", ""),
        ]
        with mock.patch.object(NATIVE, "run", side_effect=results) as command:
            with self.assertRaisesRegex(NATIVE.NativeRunError, "untracked"):
                NATIVE.verify_exact_source(Path("."), source_commit)
        self.assertIn("--untracked-files=all", command.call_args_list[1].args)

    def test_portable_entrypoint_does_not_repeat_source_matrix(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for fragment in ("validate_public_repo.py", "audit_public_tree.py", '"regression_tests"', '("ruff",'):
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, source)


if __name__ == "__main__":
    unittest.main()
