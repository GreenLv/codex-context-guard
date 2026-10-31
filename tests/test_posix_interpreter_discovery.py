"""Hermetic global-location discovery controls; no system paths are modified."""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts/run_context_guard.sh"


@unittest.skipIf(os.name == "nt", "POSIX global-location fallback")
class PosixInterpreterDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.outer = Path(self.tmp.name).resolve()
        self.cache = self.outer / "runtime"
        for name in ("scripts", "assets", "skills", ".codex-plugin"):
            shutil.copytree(ROOT / name, self.cache / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
        self.bin = self.outer / "restricted-bin"
        self.bin.mkdir()
        for command in ("dirname", "head", "mktemp", "cat", "rm"):
            found = shutil.which(command)
            self.assertIsNotNone(found)
            (self.bin / command).symlink_to(found)
        for command in ("python3", "python"):
            self.executable(self.bin / command, "exit 1\n")
        self.home = self.outer / "home"
        self.home.mkdir()
        self.environment = {"PATH":str(self.bin), "HOME":str(self.outer / "os-home"),
            "CODEX_HOME":str(self.home), "PLUGIN_DATA":str(self.outer / "private-state"),
            "TMPDIR":str(self.outer)}

    def executable(self, path, body):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
        return path

    def candidate(self, name, kind="supported"):
        path = self.outer / "global-fixture" / name
        log = path.with_name(path.name + ".calls")
        prefix = ('if [ "$1 $2 $3 $4" = "-B -I -S -c" ]; then\n'
                  f"    printf 'probe\\n' >> {shlex.quote(str(log))}\n"
                  'else\n' + f"    printf 'run\\n' >> {shlex.quote(str(log))}\n" + 'fi\n')
        if kind == "old":
            code = 'import sys; sys.version_info=(3,9,0); exec(sys.argv[1])'
            body = prefix + f'exec {shlex.quote(sys.executable)} -B -I -S -c {shlex.quote(code)} "$5"\n'
        elif kind == "empty":
            body = prefix + f'exec {shlex.quote(shutil.which("true"))} "$@"\n'
        else:
            body = prefix + f'exec {shlex.quote(sys.executable)} "$@"\n'
        return self.executable(path, body), log

    def configure_globals(self, candidates):
        source = LAUNCHER.read_text()
        start = source.index("for candidate in \\\n")
        end = source.index("\ndo\n", start)
        # Replace only the literal location list in this disposable launcher.
        source = source[:start] + "for candidate in " + " ".join(shlex.quote(str(p)) for p in candidates) + source[end:]
        (self.cache / "scripts/run_context_guard.sh").write_text(source)

    def snapshot(self):
        return {p.relative_to(self.cache).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.cache.rglob("*") if p.is_file()}

    def hook(self):
        before = self.snapshot()
        result = subprocess.run(["/bin/sh",str(self.cache / "scripts/run_context_guard.sh"),"hook"],
            input=json.dumps({"hook_event_name":"UserPromptSubmit","session_id":"synthetic-discovery",
                              "cwd":str(self.outer),"prompt":"hello"}), env=self.environment,
            text=True,capture_output=True,timeout=30,check=False)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(list(self.cache.rglob("*.pyc")))
        self.assertNotIn("PYTHONDONTWRITEBYTECODE", self.environment)
        return result

    def test_restricted_path_uses_a_supported_global_without_creating_a_binding(self):
        candidate, log = self.candidate("python3.12")
        self.configure_globals([candidate])
        result = self.hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsInstance(json.loads(result.stdout), dict)
        self.assertEqual(log.read_text().splitlines(), ["probe","run"])
        self.assertEqual(list(self.home.iterdir()), [])

    def test_unsupported_version_and_empty_output_are_rejected(self):
        for kind in ("old", "empty"):
            with self.subTest(kind=kind):
                candidate, log = self.candidate(kind, kind)
                self.configure_globals([candidate])
                result = self.hook()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("requires Python 3.10", result.stderr)
                self.assertEqual(log.read_text().splitlines(), ["probe"])
                self.assertFalse((self.outer / "private-state").exists())

    def test_empty_output_generic_path_program_does_not_hide_the_fallback(self):
        self.executable(self.bin / "python3", f'exec {shlex.quote(shutil.which("true"))} "$@"\n')
        candidate, log = self.candidate("fallback-python3.12")
        self.configure_globals([candidate])
        result = self.hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.read_text().splitlines(), ["probe", "run"])

    def test_only_the_first_supported_global_is_used(self):
        old, old_log = self.candidate("first-old", "old")
        good, good_log = self.candidate("second-supported")
        later, later_log = self.candidate("third-supported")
        self.configure_globals([old,good,later])
        result = self.hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(old_log.read_text().splitlines(), ["probe"])
        self.assertEqual(good_log.read_text().splitlines(), ["probe","run"])
        self.assertFalse(later_log.exists())

    def test_path_python_precedes_globals(self):
        (self.bin / "python3.12").symlink_to(sys.executable)
        candidate, log = self.candidate("not-selected")
        self.configure_globals([candidate])
        result = self.hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(log.exists())

    def test_explicit_binding_precedes_path_and_globals(self):
        path_python, path_log = self.candidate("path-python")
        (self.bin / "python3.12").symlink_to(path_python)
        global_python, global_log = self.candidate("global-python")
        self.configure_globals([global_python])
        conf = self.home / "context-guard/interpreter.conf"
        conf.parent.mkdir()
        conf.write_text(str(Path(sys.executable).resolve()) + "\n")
        before = conf.read_bytes()
        result = self.hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(conf.read_bytes(), before)
        self.assertFalse(path_log.exists())
        self.assertFalse(global_log.exists())

    def test_bad_explicit_binding_keeps_its_error_and_does_not_fallback(self):
        candidate, log = self.candidate("not-selected")
        self.configure_globals([candidate])
        conf = self.home / "context-guard/interpreter.conf"
        conf.parent.mkdir()
        conf.write_text(str(self.outer / "missing-python") + "\n")
        result = self.hook()
        self.assertEqual(result.returncode, 2)
        self.assertIn("configuration is missing or not executable", result.stderr)
        self.assertFalse(log.exists())

    def test_no_global_candidate_fails_visibly(self):
        self.configure_globals([self.outer / "missing-python"])
        result = self.hook()
        self.assertEqual(result.returncode, 2)
        self.assertIn("supported global installation locations", result.stderr)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_declared_locations_are_only_explicit_global_families(self):
        source = LAUNCHER.read_text()
        start = source.index("for candidate in \\\n")
        end = source.index("\ndo\n",start)
        block = source[start:end]
        self.assertIn("/opt/anaconda3/bin/python3",block)
        self.assertIn("/opt/homebrew/bin/python3.12",block)
        self.assertIn("/usr/local/bin/python3.12",block)
        self.assertIn("/Library/Frameworks/Python.framework/Versions/3.10/bin/python3",block)
        self.assertNotIn("$HOME",block)
        self.assertNotIn("/Users/",block)
