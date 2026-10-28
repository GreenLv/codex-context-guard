"""Real PATH resolver controls; native cases require Windows PowerShell 5.1.

Run only with private HOME/USERPROFILE/CODEX_HOME/data/TMP environment.
These controls establish selection and launch behavior, not performance acceptance.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

LAUNCHER = Path(__file__).resolve().parents[1] / "scripts/run-context-guard.ps1"
SOURCE = LAUNCHER.read_text(encoding="utf-8")
OLD_SOURCE = SOURCE.replace("$resolved = Resolve-ContextGuardPythonCommand $candidate.Command",
                            "$resolved = Get-Command $candidate.Command -ErrorAction SilentlyContinue")
RESOLVER = SOURCE[SOURCE.index("$pythonPathDirectories ="):SOURCE.index("$candidates = @(")]


class ResolverBoundary(unittest.TestCase):
    def test_only_discovery_call_changes_after_candidates(self):
        tail = SOURCE[SOURCE.index("$candidates = @("):]
        self.assertIn("$resolved = Resolve-ContextGuardPythonCommand $candidate.Command", tail)
        self.assertNotIn("Get-Command", tail)
        self.assertIn("$global:LASTEXITCODE = 2", tail)
        self.assertIn("$probeExitCode = $global:LASTEXITCODE", tail)
        self.assertIn("$hookExitCode = $global:LASTEXITCODE", tail)


@unittest.skipUnless(os.name == "nt" and shutil.which("powershell.exe"),
                     "requires actual Windows PowerShell 5.1")
class WindowsPathResolver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        cls.venv = cls.base / "解释器 space"
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(cls.venv)],
                       check=True, capture_output=True, timeout=120)
        cls.python = cls.venv / "Scripts/python.exe"
        cls.powershell = shutil.which("powershell.exe")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=self.base))
        self.first = self.root / "第一 space"
        self.second = self.root / "second"
        self.first.mkdir()
        self.second.mkdir()
        self.appdata = self.root / "appdata"
        self.localappdata = self.root / "localappdata"
        self.module_cache = self.root / "module-cache/ModuleAnalysisCache"
        for directory in (self.appdata, self.localappdata, self.module_cache.parent):
            directory.mkdir()
        self.env = dict(os.environ)
        for key in ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT",
                    "CONTEXT_GUARD_HOOK_TRACE_DIR"):
            self.env.pop(key, None)
        self.env.update(HOME=str(self.root / "home"), USERPROFILE=str(self.root / "home"),
                        CODEX_HOME=str(self.root / "codex"),
                        CONTEXT_GUARD_DATA_DIR=str(self.root / "data"),
                        TMP=str(self.root), TEMP=str(self.root), TMPDIR=str(self.root),
                        APPDATA=str(self.appdata), LOCALAPPDATA=str(self.localappdata),
                        PSModuleAnalysisCachePath=str(self.module_cache),
                        PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8",
                        PATH=f"{self.first};{self.second}", PATHEXT=".COM;.EXE;.BAT;.CMD",
                        CG_REAL_PYTHON=str(self.python))

    def run_ps(self, source, payload=b""):
        script = self.root / "case.ps1"
        script.write_text("$ErrorActionPreference = 'Stop'\n"
                          "if ($PSVersionTable.PSVersion.Major -ne 5 -or "
                          "$PSVersionTable.PSVersion.Minor -ne 1) { exit 91 }\n"
                          "[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)\n"
                          "[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)\n"
                          "$OutputEncoding = [Console]::OutputEncoding\n" + source,
                          encoding="utf-8-sig")
        return subprocess.run([self.powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
                               "-File", str(script)], input=payload, capture_output=True,
                              env=self.env, cwd=self.root, timeout=60)

    def compare(self, name="python"):
        self.env["CG_NAME"] = name
        result = self.run_ps(RESOLVER + r'''
$old = Get-Command $env:CG_NAME -ErrorAction SilentlyContinue
$new = Resolve-ContextGuardPythonCommand $env:CG_NAME
@{old=$old.Source; new=$new.Source} | ConvertTo-Json -Compress
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        values = json.loads(result.stdout.decode("utf-8-sig"))
        self.assertEqual(values["old"], values["new"])
        return values["new"]

    def test_native_directory_and_pathext_priority(self):
        for directory, name in ((self.first, "python.cmd"), (self.second, "python.exe")):
            (directory / name).write_bytes(b"placeholder")
        self.assertEqual(Path(self.compare()), self.first / "python.cmd")
        (self.first / "python.exe").write_bytes(b"placeholder")
        for extensions, expected in ((".CMD;.EXE;.COM;.BAT", "python.cmd"),
                                     (".exe;.cmd;.bat;.com", "python.exe")):
            self.env["PATHEXT"] = extensions
            self.assertEqual(Path(self.compare()), self.first / expected)

    def test_script_bare_and_edge_domains_reach_legacy_resolver(self):
        # A trap proves actual fallback reachability independently of its
        # chosen result; all ordinary misses must avoid this discovery path.
        domains = [(str(self.first), "", None), (".", ".EXE", None),
                   (f'"{self.first}"', ".EXE", None), ("~", ".EXE", None),
                   (str(self.first), ".EXE;CUSTOM", None),
                   (str(self.first), ".EXE;.CUSTOM", "python.CUSTOM"),
                   (str(self.first), ".EXE", "python.ps1"),
                   (str(self.first), ".EXE", "python")]
        for path, extensions, filename in domains:
            with self.subTest(path=path, extensions=extensions, filename=filename):
                self.env.update(PATH=path, PATHEXT=extensions)
                if filename:
                    (self.first / filename).write_text("# fixture", encoding="ascii")
                result = self.run_ps(RESOLVER + r'''
function Get-Command { param($Name, $ErrorAction); 'legacy-reached' }
Resolve-ContextGuardPythonCommand python
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), b"legacy-reached")
                if filename:
                    (self.first / filename).unlink()

    def test_cwd_only_does_not_become_path(self):
        shutil.copyfile(self.python, self.root / "python.exe")
        self.assertIsNone(self.compare())

    def test_session_function_preserves_original_source_semantics(self):
        result = self.run_ps(RESOLVER + r'''
function python { throw 'must not execute during discovery' }
$old = Get-Command python
$new = Resolve-ContextGuardPythonCommand python
@{old=$old.Source; new=$new.Source; type=$new.CommandType.ToString()} | ConvertTo-Json -Compress
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        values = json.loads(result.stdout.decode("utf-8-sig"))
        self.assertEqual(values["old"], values["new"])
        self.assertEqual(values["type"], "Function")

    def launch(self, source, *, trap=False):
        launcher = self.root / "run-context-guard.ps1"
        launcher.write_text(source, encoding="utf-8")
        (self.root / "cg_hook.py").write_text(
            "import json,sys\njson.dump(json.load(sys.stdin),sys.stdout,ensure_ascii=False)\n",
            encoding="utf-8")
        self.env["CG_LAUNCHER"] = str(launcher)
        prelude = "function Get-Command { throw 'general discovery reached' }\n" if trap else ""
        return self.run_ps(prelude + "& $env:CG_LAUNCHER hook SessionEnd\nexit $global:LASTEXITCODE\n",
                           json.dumps({"text": "修复 café 🧪"}, ensure_ascii=False).encode("utf-8"))

    def test_real_generic_python_old_fails_discovery_trap_new_passes_unicode(self):
        # Use a real venv location rather than a copied venv executable whose
        # Python home would no longer be valid.
        self.env.update(PATH=str(self.python.parent),
                        PATHEXT=".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC")
        negative = self.launch(OLD_SOURCE, trap=True)
        self.assertNotEqual(negative.returncode, 0)
        self.assertIn(b"general discovery reached", negative.stderr)
        positive = self.launch(SOURCE, trap=True)
        self.assertEqual(positive.returncode, 0, positive.stderr)
        self.assertEqual(positive.stderr, b"")
        self.assertEqual(json.loads(positive.stdout.decode("utf-8")), {"text": "修复 café 🧪"})
        self.assertIn("修复".encode("utf-8"), positive.stdout)

    def test_real_com_and_version_named_executable(self):
        self.env["PATH"] = str(self.python.parent)
        for name in ("python.com", "python3.14.exe"):
            with self.subTest(name=name):
                executable = self.python.parent / name
                shutil.copyfile(self.python, executable)
                try:
                    self.assertEqual(Path(self.compare(name.split(".exe")[0] if name.endswith(".exe")
                                                       else "python")), executable)
                    for source in (OLD_SOURCE, SOURCE):
                        result = self.launch(source)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(json.loads(result.stdout.decode("utf-8")),
                                         {"text": "修复 café 🧪"})
                finally:
                    executable.unlink()

    def test_batch_script_forms_and_generic_version_rejection(self):
        for extension in (".cmd", ".bat", ".ps1"):
            with self.subTest(extension=extension):
                shim = self.first / ("python" + extension)
                shim.write_text("& $env:CG_REAL_PYTHON @args\n" if extension == ".ps1" else
                                '@echo off\n"%CG_REAL_PYTHON%" %*\nexit /b %errorlevel%\n',
                                encoding="ascii")
                self.assertEqual(Path(self.compare()), shim)
                for source in (OLD_SOURCE, SOURCE):
                    result = self.launch(source)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout.decode("utf-8")),
                                     {"text": "修复 café 🧪"})
                shim.unlink()
        # A generic candidate that fails the unchanged version probe cannot
        # supply runtime success; no alternative Python is on this PATH.
        (self.first / "python.cmd").write_text("@echo off\nexit /b 1\n", encoding="ascii")
        for source in (OLD_SOURCE, SOURCE):
            result = self.launch(source)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(b"no supported interpreter", result.stderr)


if __name__ == "__main__":
    unittest.main()
