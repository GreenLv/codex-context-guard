"""Replay guide heredoc against a synthetic checkout; Git is fully mocked."""

import contextlib
import hashlib
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.validation import supplement_post_close as supplement


class RecipeTests(unittest.TestCase):
    def test_manifest_round_trip_and_exclusive_create(self):
        recipe = (
            Path(__file__).resolve().parents[1]
            / "tools/validation/NATIVE_BETWEEN_TURNS_ACCEPTANCE.md"
        ).read_text()
        source = recipe.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as t:
            root = Path(t).resolve()
            repo, private = root / "repo", root / "private"
            directory = repo / "tools/validation"
            directory.mkdir(parents=True)
            private.mkdir()
            for name in supplement.READER_FILES:
                shutil.copyfile(
                    Path(supplement.__file__).resolve().parent / name, directory / name
                )
            output = private / "reader-identity.json"

            def git(argv, **kwargs):
                if "rev-parse" in argv:
                    data = ("a" * 40 + "\n").encode()
                elif "status" in argv:
                    data = b""
                else:
                    data = b"tracked"
                return subprocess.CompletedProcess(argv, 0, stdout=data)

            with (
                mock.patch.object(sys, "argv", ["-", str(repo), str(output)]),
                mock.patch.object(subprocess, "run", side_effect=git),
                contextlib.redirect_stdout(io.StringIO()) as printed,
            ):
                exec(compile(source, "<synthetic-guide>", "exec"), {})  # noqa: S102 -- guide replay
            digest = hashlib.sha256(output.read_bytes()).hexdigest()
            self.assertIn("reader_manifest_sha256=" + digest, printed.getvalue())
            with (
                mock.patch.object(
                    supplement,
                    "readonly_git",
                    side_effect=lambda repo, *args: git(list(args)).stdout,
                ),
                mock.patch.object(
                    supplement, "__file__", str(directory / "supplement_post_close.py")
                ),
                mock.patch.object(
                    supplement.shared_verify,
                    "__file__",
                    str(directory / "shared_verify.py"),
                ),
            ):
                identity = supplement.verified_reader(output, digest)
            self.assertEqual(identity["source_commit"], "a" * 40)
            with (
                mock.patch.object(sys, "argv", ["-", str(repo), str(output)]),
                mock.patch.object(subprocess, "run", side_effect=git),
                self.assertRaises(FileExistsError),
            ):
                exec(compile(source, "<synthetic-guide>", "exec"), {})  # noqa: S102 -- guide replay


if __name__ == "__main__":
    unittest.main()
