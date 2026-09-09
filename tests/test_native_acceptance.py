"""Focused tests for the portable native acceptance entrypoint."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
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
    def test_existing_result_stops_before_portable_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            output.write_bytes(b"original evidence")
            with mock.patch.object(NATIVE, "portable_acceptance") as execute, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                NATIVE.main(["--source-commit", "a" * 40, "--output", str(output)])
            self.assertEqual(caught.exception.code, 2)
            execute.assert_not_called()
            self.assertEqual(output.read_bytes(), b"original evidence")

    def test_output_precheck_creates_parent_but_not_result_and_rejects_source(self) -> None:
        behavior = NATIVE.load_host_behavior()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            output = Path(directory) / "retained" / "result.json"
            behavior.check_output_path(output, root)
            self.assertTrue(output.parent.is_dir())
            self.assertEqual(list(output.parent.iterdir()), [])
            with self.assertRaises(behavior.HostBehaviorError):
                behavior.check_output_path(root / "result.json", root)

    def test_result_write_uses_private_lf_bytes_and_never_overwrites(self) -> None:
        behavior = NATIVE.load_host_behavior()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            behavior.write_result(output, {"status": "pending"})
            before = output.read_bytes()
            self.assertNotIn(b"\r\n", before)
            self.assertEqual(json.loads(before)["status"], "pending")
            if os.name != "nt":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                behavior.write_result(output, {"status": "passed"})
            self.assertEqual(output.read_bytes(), before)

    def test_preflight_checks_inputs_without_installing_or_creating_annex(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            replies = [subprocess.CompletedProcess([], 0, "https://example.invalid/repo.git\n", ""),
                       subprocess.CompletedProcess([], 0, "codex test-version\n", "")]
            with mock.patch.object(NATIVE, "resolve_executable", return_value="codex"), \
                    mock.patch.object(NATIVE, "verify_exact_source") as verify, \
                    mock.patch.object(NATIVE, "load_manager"), \
                    mock.patch.object(NATIVE, "runtime_digest", return_value="b" * 64), \
                    mock.patch.object(NATIVE, "run", side_effect=replies), \
                    mock.patch.object(NATIVE, "portable_acceptance") as execute, \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(NATIVE.main(["--source-commit", "a" * 40,
                                             "--output", str(output), "--preflight"]), 0)
            verify.assert_called_once()
            execute.assert_not_called()
            self.assertFalse(output.exists())
            self.assertIn("acceptance_not_run", stdout.getvalue())

    def test_unusable_result_parent_fails_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "file"
            parent.write_text("keep", encoding="utf-8")
            with mock.patch.object(NATIVE, "portable_acceptance") as execute, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                NATIVE.main(["--source-commit", "a" * 40, "--output", str(parent / "result.json")])
            execute.assert_not_called()

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
