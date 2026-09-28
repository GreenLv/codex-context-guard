"""Canonical prepared-source identity tests (review r4 item 3).

Real temporary git repositories prove: new-directory content changes the
digest, deleted/renamed/special-character paths bind explicitly, different
HEADs never share identity, and unknown file types are rejected rather than
encoded as missing.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools" / "validation"))
import acceptance_identity as ai  # noqa: E402


class TempRepo:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "T")
        (self.root / "seed.txt").write_text("seed", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-qm", "seed")

    def git(self, *argv):
        return subprocess.run(["git", *argv], cwd=self.root,
                              capture_output=True, text=True, check=True)

    def identity(self):
        return ai.prepared_source_identity(self.root)


class PreparedIdentityTests(unittest.TestCase):
    def test_new_directory_content_changes_identity(self):
        repo = TempRepo()
        try:
            before = repo.identity()
            (repo.root / "newdir").mkdir()
            (repo.root / "newdir" / "a.py").write_text("one", encoding="utf-8")
            after_one = repo.identity()
            (repo.root / "newdir" / "a.py").write_text("two", encoding="utf-8")
            after_two = repo.identity()
            self.assertIn("newdir/a.py", after_one["dirty_paths"])
            self.assertNotEqual(before["prepared_source_sha256"],
                                after_one["prepared_source_sha256"])
            self.assertNotEqual(after_one["prepared_source_sha256"],
                                after_two["prepared_source_sha256"])
        finally:
            repo.temp.cleanup()

    def test_special_character_paths_bind(self):
        repo = TempRepo()
        try:
            names = ["with space.txt", "中文文件.py", 'quote".txt',
                     "line\nbreak.txt"]
            for name in names:
                with self.subTest(path=name):
                    if os.name == "nt" and ('"' in name or "\n" in name):
                        self.skipTest("Windows forbids quote/newline file names")
                    (repo.root / name).write_text(name, encoding="utf-8")
                    self.assertIn(name, repo.identity()["dirty_paths"])
        finally:
            repo.temp.cleanup()

    def test_deleted_path_binds(self):
        repo = TempRepo()
        try:
            victim = repo.root / "seed.txt"
            victim.write_text("changed", encoding="utf-8")
            modified = repo.identity()
            victim.unlink()
            deleted = repo.identity()
            self.assertNotEqual(modified["prepared_source_sha256"],
                                deleted["prepared_source_sha256"])
            self.assertIn("seed.txt", deleted["dirty_paths"])
        finally:
            repo.temp.cleanup()

    def test_rename_binds_both_sides(self):
        repo = TempRepo()
        try:
            repo.git("mv", "seed.txt", "renamed.txt")
            identity = repo.identity()
            self.assertIn("renamed.txt", identity["dirty_paths"])
            self.assertIn("seed.txt", identity["renamed_away"])
        finally:
            repo.temp.cleanup()

    def test_head_bounds_identity(self):
        repo = TempRepo()
        try:
            (repo.root / "dirty.txt").write_text("d", encoding="utf-8")
            first = repo.identity()
            repo.git("stash", "-q", "--include-untracked")
            (repo.root / "next.txt").write_text("n", encoding="utf-8")
            repo.git("add", "-A")
            repo.git("commit", "-qm", "next")
            repo.git("stash", "pop", "-q")
            second = repo.identity()
            self.assertEqual(first["dirty_paths"], second["dirty_paths"])
            self.assertNotEqual(first["prepared_source_sha256"],
                                second["prepared_source_sha256"],
                                "same dirty set on a different HEAD must "
                                "not share identity")
        finally:
            repo.temp.cleanup()

    def test_symlink_encoding_explicit(self):
        repo = TempRepo()
        try:
            try:
                os.symlink("seed.txt", repo.root / "link.txt")
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows host lacks symlink creation privilege")
                raise
            identity = repo.identity()
            self.assertIn("link.txt", identity["dirty_paths"])
            os.remove(repo.root / "link.txt")
            os.symlink("other.txt", repo.root / "link.txt")
            changed = repo.identity()
            self.assertNotEqual(identity["prepared_source_sha256"],
                                changed["prepared_source_sha256"])
        finally:
            repo.temp.cleanup()

    def test_unknown_file_type_rejected(self):
        """git status does not list fifos, so the binding itself must raise
        if ever handed a non-regular, non-symlink path."""
        repo = TempRepo()
        try:
            # A directory exercises the non-regular rejection on every OS;
            # additionally cover FIFO where the host can create one.
            (repo.root / "directory").mkdir()
            with self.assertRaises(ValueError):
                ai._file_binding(repo.root, "directory")
            if hasattr(os, "mkfifo"):
                os.mkfifo(repo.root / "pipe")
                with self.assertRaises(ValueError):
                    ai._file_binding(repo.root, "pipe")
        finally:
            repo.temp.cleanup()

    def test_shared_with_checker_and_windows_encoding(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "cic", REPO_ROOT / "scripts" / "check_incident_coverage.py")
        cic = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cic)
        tool_identity = ai.prepared_source_identity(REPO_ROOT)
        checker_identity = cic.prepared_source_identity(REPO_ROOT)
        self.assertEqual(tool_identity["prepared_source_sha256"],
                         checker_identity["prepared_source_sha256"])
        completed = subprocess.run(
            [sys.executable,
             str(REPO_ROOT / "tools/validation/acceptance_identity.py"),
             "--repo-root", str(REPO_ROOT)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)
                         ["prepared_source_sha256"],
                         tool_identity["prepared_source_sha256"])


if __name__ == "__main__":
    unittest.main()
