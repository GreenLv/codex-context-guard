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

    def run_ps(self, source, payload=b"", *, post_start_env=None):
        script = self.root / "case.ps1"
        # Only forced-domain controls override startup normalization. Parent
        # environment compatibility cases deliberately omit this injection.
        injected = "".join(f"$env:{key} = '{value.replace(chr(39), chr(39) * 2)}'\n"
                           for key, value in (post_start_env or {}).items())
        script.write_text("$ErrorActionPreference = 'Stop'\n"
                          "if ($PSVersionTable.PSVersion.Major -ne 5 -or "
                          "$PSVersionTable.PSVersion.Minor -ne 1) { exit 91 }\n"
                          "[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)\n"
                          "[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)\n"
                          "$OutputEncoding = [Console]::OutputEncoding\n" + injected + source,
                          encoding="utf-8-sig")
        return subprocess.run([self.powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
                               "-File", str(script)], input=payload, capture_output=True,
                              env=self.env, cwd=self.root, timeout=60)

    def compare(self, name="python", *, expected=None, allow_missing=False):
        self.env["CG_NAME"] = name
        result = self.run_ps(RESOLVER + r'''
$old = Get-Command $env:CG_NAME -ErrorAction SilentlyContinue
$new = Resolve-ContextGuardPythonCommand $env:CG_NAME
@{old=$old.Source; new=$new.Source; seen_path=[string]$env:PATH; seen_pathext=[string]$env:PATHEXT} | ConvertTo-Json -Compress
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        values = json.loads(result.stdout.decode("utf-8-sig"))
        values.update(name=name, expected_fixture=str(expected) if expected else None)
        self.last_lookup = values  # Retain raw Sources and consumed environment.
        print("resolver-observation: " + json.dumps(values, ensure_ascii=False), file=sys.stderr)
        if values["old"] is None or values["new"] is None:
            self.assertIsNone(values["old"], values)
            self.assertIsNone(values["new"], values)
            self.assertTrue(expected is None or allow_missing, values)
            return None
        self.assertIsNotNone(expected, values)
        for source in (values["old"], values["new"], expected):
            self.assertTrue(Path(source).is_file(), values)
        # samefile compares stat device/file identities, including Windows
        # volume/file identity; casing and spelling alone establish neither.
        self.assertTrue(os.path.samefile(values["old"], values["new"]), values)
        self.assertTrue(os.path.samefile(values["new"], expected), values)
        return values["new"]

    def test_native_directory_and_pathext_priority(self):
        files = [self.first / "python.cmd", self.second / "python.exe", self.first / "python.exe"]
        try:
            for file in files[:2]:
                file.write_bytes(b"placeholder")
            self.compare(expected=files[0])
            files[2].write_bytes(b"placeholder")
            for extensions, expected in ((".CMD;.EXE;.COM;.BAT", files[0]),
                                         (".exe;.cmd;.bat;.com", files[2])):
                self.env["PATHEXT"] = extensions
                self.compare(expected=expected)
        finally:
            for file in files:
                file.unlink(missing_ok=True)
                self.assertFalse(file.exists())

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
                try:
                    result = self.run_ps(RESOLVER + r'''
$global:legacyHits = 0
function Get-Command { param($Name, $ErrorAction); $global:legacyHits++; 'legacy-reached' }
$resolved = Resolve-ContextGuardPythonCommand python
@{resolved=$resolved; legacy_hits=$global:legacyHits; seen_path=[string]$env:PATH; seen_pathext=[string]$env:PATHEXT} | ConvertTo-Json -Compress
''', post_start_env={"PATH": path, "PATHEXT": extensions})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    seen = json.loads(result.stdout.decode("utf-8-sig"))
                    print("resolver-forced-domain: " + json.dumps(seen, ensure_ascii=False),
                          file=sys.stderr)
                    self.assertEqual(seen["seen_path"], path, seen)
                    self.assertEqual(seen["seen_pathext"], extensions, seen)
                    self.assertEqual(seen["resolved"], "legacy-reached", seen)
                    self.assertEqual(seen["legacy_hits"], 1, seen)
                finally:
                    if filename:
                        (self.first / filename).unlink(missing_ok=True)
                        self.assertFalse((self.first / filename).exists())

    def test_parent_empty_pathext_preserves_startup_compatibility(self):
        # Keep the original parent-empty condition independent of the forced
        # empty-domain control above. PS5 may normalize this before our code.
        shim = self.first / "python.cmd"
        shim.write_text('@echo off\n"%CG_REAL_PYTHON%" %*\nexit /b %errorlevel%\n', encoding="ascii")
        self.env["PATHEXT"] = ""
        try:
            selected = self.compare(expected=shim, allow_missing=True)
            for source in (OLD_SOURCE, SOURCE):
                result = self.launch(source)
                self.assertEqual(result.returncode, 0 if selected else 2,
                                 (self.last_lookup, result.stderr))
                if selected:
                    self.assertEqual(json.loads(result.stdout.decode("utf-8")),
                                     {"text": "修复 café 🧪"})
                else:
                    self.assertIn(b"no supported interpreter", result.stderr)
        finally:
            shim.unlink(missing_ok=True)
            self.assertFalse(shim.exists())

    def test_explicit_cwd_path_uses_legacy_without_implicit_cwd_search(self):
        executable = self.root / "python.exe"
        shutil.copyfile(self.python, executable)
        try:
            self.compare(r".\python", expected=executable)
            self.compare()
            result = self.run_ps(RESOLVER + r'''
$global:legacyHits = 0
function Get-Command { param($Name, $ErrorAction); $global:legacyHits++; 'legacy-reached' }
$resolved = Resolve-ContextGuardPythonCommand '.\python'
@{resolved=$resolved; legacy_hits=$global:legacyHits} | ConvertTo-Json -Compress
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout.decode("utf-8-sig")),
                             {"resolved": "legacy-reached", "legacy_hits": 1})
        finally:
            executable.unlink(missing_ok=True)
            self.assertFalse(executable.exists())

    def test_cwd_only_does_not_become_path(self):
        executable = self.root / "python.exe"
        shutil.copyfile(self.python, executable)
        try:
            self.assertIsNone(self.compare())
        finally:
            executable.unlink(missing_ok=True)
            self.assertFalse(executable.exists())

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
                    self.compare(name.split(".exe")[0] if name.endswith(".exe") else "python",
                                 expected=executable)
                    for source in (OLD_SOURCE, SOURCE):
                        result = self.launch(source)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(json.loads(result.stdout.decode("utf-8")),
                                         {"text": "修复 café 🧪"})
                finally:
                    executable.unlink(missing_ok=True)
                    self.assertFalse(executable.exists())

    def test_batch_script_forms_and_generic_version_rejection(self):
        for extension in (".cmd", ".bat", ".ps1"):
            with self.subTest(extension=extension):
                with tempfile.TemporaryDirectory(dir=self.root) as temporary:
                    directory = Path(temporary)
                    self.env["PATH"] = str(directory)
                    shim = directory / ("python" + extension)
                    shim.write_text("& $env:CG_REAL_PYTHON @args\n" if extension == ".ps1" else
                                    '@echo off\n"%CG_REAL_PYTHON%" %*\nexit /b %errorlevel%\n',
                                    encoding="ascii")
                    try:
                        self.compare(expected=shim)
                        for source in (OLD_SOURCE, SOURCE):
                            result = self.launch(source)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(json.loads(result.stdout.decode("utf-8")),
                                             {"text": "修复 café 🧪"})
                    finally:
                        shim.unlink(missing_ok=True)
                        self.assertFalse(shim.exists())
        # A generic candidate that fails the unchanged version probe cannot
        # supply runtime success. Its fresh PATH cannot inherit forwarding
        # fixtures, and the marker proves this exact shim received the probe.
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            directory = Path(temporary)
            self.env["PATH"] = str(directory)
            shim = directory / "python.cmd"
            marker = directory / "probe-marker.txt"
            self.env["CG_PROBE_MARKER"] = str(marker)
            shim.write_text('@echo off\nif "%~1"=="-c" echo probe-ran>"%CG_PROBE_MARKER%"\n'
                            'exit /b 1\n', encoding="ascii")
            try:
                self.compare(expected=shim)
                for source in (OLD_SOURCE, SOURCE):
                    marker.unlink(missing_ok=True)
                    result = self.launch(source)
                    self.assertEqual(marker.read_bytes().strip(), b"probe-ran",
                                     (self.last_lookup, result.stderr))
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, b"")
                    self.assertIn(b"no supported interpreter", result.stderr)
            finally:
                shim.unlink(missing_ok=True)
                marker.unlink(missing_ok=True)
                self.assertFalse(shim.exists())
                self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
