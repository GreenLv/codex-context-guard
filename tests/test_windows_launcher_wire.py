"""Configured launcher wire checks; native cases require Windows PowerShell 5.1.

Run with an explicitly private HOME/USERPROFILE/CODEX_HOME/data/TMP root:
python -B -m unittest discover -s tests -p test_windows_launcher_wire.py -v
No login, trust, installation into a daily HOME, or third-party package is used.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

LAUNCHER = Path(__file__).resolve().parents[1] / "scripts/run-context-guard.ps1"
SOURCE = LAUNCHER.read_text(encoding="utf-8")
CAPTURE_CODE = re.search(r"\$captureCode = @'\n(.*?)\n'@", SOURCE, re.S).group(1)
WIRE_CODE = re.search(r"\$wireCode = @'\n(.*?)\n'@", SOURCE, re.S).group(1)
PAYLOAD = {"prompt": "修复 café 文件 🧪", "path": "研究目录/含 空格.txt"}


class CapturePythonContract(unittest.TestCase):
    def test_capture_runs_actual_hook_with_private_unicode_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = dict(os.environ)
            for key in ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT"):
                env.pop(key, None)
            env.update(HOME=str(root / "os-home"), USERPROFILE=str(root / "os-home"),
                       CODEX_HOME=str(root / "codex-home"),
                       CONTEXT_GUARD_DATA_DIR=str(root / "data"),
                       PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
            payload = {"hook_event_name": "UserPromptSubmit", "session_id": "capture-wire",
                       "turn_id": "t1", "cwd": str(root), "prompt": PAYLOAD["prompt"]}
            output = root / "output.json"
            proc = subprocess.run(
                [sys.executable, "-S", "-c", CAPTURE_CODE, str(output),
                 str(LAUNCHER.parent / "cg_hook.py"), "hook", "UserPromptSubmit"],
                input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                capture_output=True, env=env, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIsInstance(json.loads(output.read_bytes()), dict)
            session = root / "data/sessions-v2/capture-wire"
            self.assertTrue((session / "state.json").is_file())
            prompts = [json.loads(path.read_bytes()) for path in (session / "prompts").glob("P*.json")]
            self.assertTrue(any(item.get("text") == PAYLOAD["prompt"] for item in prompts))

    def test_exact_capture_code_preserves_unicode_argv_and_wire(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime.py"
            runtime.write_text(
                "import json, sys\n"
                "payload = json.load(sys.stdin)\n"
                "assert sys.argv[1:] == ['hook', 'PreToolUse']\n"
                "json.dump(payload, sys.stdout, ensure_ascii=False)\n",
                encoding="utf-8")
            output = root / "output.json"
            proc = subprocess.run(
                [sys.executable, "-S", "-c", CAPTURE_CODE, str(output),
                 str(runtime), "hook", "PreToolUse"],
                input=json.dumps(PAYLOAD, ensure_ascii=False).encode("utf-8"),
                capture_output=True, env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, b"")
            self.assertEqual(json.loads(output.read_bytes()), PAYLOAD)
            self.assertIn("修复".encode("utf-8"), output.read_bytes())
            checked = subprocess.run(
                [sys.executable, "-I", "-S", "-c", WIRE_CODE, str(output)],
                capture_output=True, timeout=30)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(checked.stdout.strip(), b"CG-HOOK-WIRE-VERIFIED")

    def test_capture_keeps_nonzero_runtime_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime.py"
            runtime.write_text("raise SystemExit(7)\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-S", "-c", CAPTURE_CODE,
                 str(root / "out"), str(runtime), "hook"],
                capture_output=True, timeout=30)
            self.assertEqual(proc.returncode, 7)


@unittest.skipUnless(os.name == "nt" and shutil.which("powershell.exe"),
                     "requires actual Windows PowerShell 5.1")
class WindowsPowerShellWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        # A real venv checks BOM-less UTF-8 configuration and a functioning
        # Python at a non-ASCII absolute path with spaces, without symlinks.
        cls.venv = cls.base / "解释器 space"
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(cls.venv)],
                       check=True, capture_output=True, timeout=120)
        cls.interpreter = cls.venv / "Scripts/python.exe"

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=self.base))
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        self.home = self.root / "home"
        self.conf = self.home / "context-guard/interpreter.conf"
        self.conf.parent.mkdir(parents=True)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        shutil.copyfile(LAUNCHER, self.scripts / LAUNCHER.name)
        self.runtime = self.scripts / "cg_hook.py"
        self.runtime.write_text(
            "import json, sys\n"
            "json.dump(json.load(sys.stdin), sys.stdout, ensure_ascii=False)\n",
            encoding="utf-8")
        self.env = dict(os.environ)
        for key in ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT",
                    "CONTEXT_GUARD_HOOK_TRACE_DIR"):
            self.env.pop(key, None)
        self.env.update(HOME=str(self.root / "os-home"),
                        USERPROFILE=str(self.root / "os-home"), CODEX_HOME=str(self.home),
                        CONTEXT_GUARD_DATA_DIR=str(self.root / "data"),
                        TMP=str(self.tmp), TEMP=str(self.tmp), TMPDIR=str(self.tmp),
                        PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="cp1252",
                        CG_TEST_LAUNCHER=str(self.scripts / LAUNCHER.name),
                        CG_TEST_RECEIPT=str(self.root / "receipt.json"))
        self.conf.write_text(str(self.interpreter) + "\n", encoding="utf-8")

    def invoke(self, payload=PAYLOAD, event="PreToolUse", *, caller_exit=None,
               global_exit=0, route="hook", prelude=""):
        self.env["CG_TEST_EVENT"] = event
        self.env["CG_TEST_ROUTE"] = route
        self.env["CG_TEST_GLOBAL_EXIT"] = str(global_exit)
        self.env["CG_TEST_CALLER_EXIT"] = "" if caller_exit is None else str(caller_exit)
        wrapper = self.root / "invoke.ps1"
        wrapper_source = r'''
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { exit 91 }
[Console]::InputEncoding = [Text.Encoding]::ASCII
[Console]::OutputEncoding = [Text.Encoding]::ASCII
$OutputEncoding = [Text.Encoding]::ASCII
$before = @([Console]::InputEncoding.CodePage, [Console]::OutputEncoding.CodePage, $OutputEncoding.CodePage, $env:PYTHONIOENCODING)
$global:LASTEXITCODE = [int]$env:CG_TEST_GLOBAL_EXIT
if ($env:CG_TEST_CALLER_EXIT -ne '') { $script:LASTEXITCODE = [int]$env:CG_TEST_CALLER_EXIT }
# TEST_PRELUDE
try {
    if ($env:CG_TEST_ROUTE -eq 'hook') {
        & $env:CG_TEST_LAUNCHER hook $env:CG_TEST_EVENT
    } else {
        & $env:CG_TEST_LAUNCHER $env:CG_TEST_ROUTE
    }
    $code = $global:LASTEXITCODE
} finally {
    $after = @([Console]::InputEncoding.CodePage, [Console]::OutputEncoding.CodePage, $OutputEncoding.CodePage, $env:PYTHONIOENCODING)
    $receipt = @{before=$before; after=$after; version=$PSVersionTable.PSVersion.ToString()} | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($env:CG_TEST_RECEIPT, $receipt, (New-Object Text.UTF8Encoding($false)))
}
exit $code
'''
        wrapper.write_text(wrapper_source.replace("# TEST_PRELUDE", prelude), encoding="ascii")
        proc = subprocess.run(
            [shutil.which("powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", str(wrapper)],
            input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            capture_output=True, env=self.env, timeout=60)
        receipt = json.loads(Path(self.env["CG_TEST_RECEIPT"]).read_bytes())
        self.assertEqual(receipt["before"], receipt["after"])
        self.assertEqual(list(self.tmp.iterdir()), [], "temporary stdout leaked")
        return proc

    def test_utf8_config_and_exact_non_ascii_hook_roundtrip(self):
        proc = self.invoke()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout.decode("utf-8")), PAYLOAD)

    def test_utf8_bom_absolute_config_executes_bound_interpreter(self):
        self.conf.write_text(str(self.interpreter) + "\n", encoding="utf-8-sig")
        self.runtime.write_text(
            "import json, sys\n"
            "payload = json.load(sys.stdin)\n"
            "payload['interpreter'] = sys.executable\n"
            "json.dump(payload, sys.stdout, ensure_ascii=False)\n",
            encoding="utf-8")
        proc = self.invoke()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(Path(result.pop("interpreter")).resolve(), self.interpreter.resolve())
        self.assertEqual(result, PAYLOAD)
        self.assertNotIn(b"ignoring", proc.stderr)

    def test_utf8_bom_absolute_missing_binding_never_falls_back(self):
        self.conf.write_text(str(self.root / "missing.exe") + "\n", encoding="utf-8-sig")
        proc = self.invoke()
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"missing or not executable", proc.stderr)
        self.assertNotIn(b"ignoring", proc.stderr)

    def test_utf16_and_utf32_config_are_not_auto_detected(self):
        for encoding in ("utf-16", "utf-32"):
            with self.subTest(encoding=encoding):
                self.conf.write_text(str(self.interpreter) + "\n", encoding=encoding)
                proc = self.invoke()
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(proc.stdout, b"")
                self.assertIn(b"could not be read as UTF-8", proc.stderr)
                self.assertNotIn(b"ignoring", proc.stderr)

    def test_session_end_core_uses_exact_utf8_capture(self):
        shutil.copyfile(self.runtime, self.scripts / "context_guard.py")
        proc = self.invoke(event="SessionEnd")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout.decode("utf-8")), PAYLOAD)

    def test_actual_hook_accepts_and_retains_non_ascii_input(self):
        self.env["CG_TEST_LAUNCHER"] = str(LAUNCHER)
        payload = {"hook_event_name": "UserPromptSubmit", "session_id": "ps5-wire",
                   "turn_id": "t1", "cwd": str(self.root), "prompt": PAYLOAD["prompt"]}
        proc = self.invoke(payload, "UserPromptSubmit")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIsInstance(json.loads(proc.stdout.decode("utf-8")), dict)
        session = Path(self.env["CONTEXT_GUARD_DATA_DIR"]) / "sessions-v2/ps5-wire"
        self.assertTrue((session / "state.json").is_file())
        prompts = [json.loads(path.read_bytes()) for path in (session / "prompts").glob("P*.json")]
        self.assertTrue(any(item.get("text") == PAYLOAD["prompt"] for item in prompts), prompts)

    def test_nonpython_empty_or_json_output_is_rejected(self):
        for output in ("", "{}", '{"continue":true}', "{broken"):
            with self.subTest(output=output):
                fake = self.root / "fake.cmd"
                fake.write_text("@echo off\n" + ("echo " + output + "\n" if output else "")
                                + "exit /b 0\n", encoding="ascii")
                self.conf.write_text(str(fake) + "\n", encoding="utf-8")
                proc = self.invoke()
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(proc.stdout, b"")
                self.assertIn(b"not a working Context Guard runtime", proc.stderr)

    def test_runtime_nonzero_is_preserved_and_cleaned(self):
        self.runtime.write_text("raise SystemExit(7)\n", encoding="utf-8")
        self.assertEqual(self.invoke().returncode, 7)

    def test_absolute_missing_binding_never_falls_back(self):
        self.conf.write_text(str(self.root / "missing.exe") + "\n", encoding="utf-8")
        proc = self.invoke()
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn(b"missing or not executable", proc.stderr)

    def test_nested_caller_shadow_preserves_native_hook_exit_zero_and_seven(self):
        for event in ("PreToolUse", "SessionEnd"):
            runtime = self.runtime if event == "PreToolUse" else self.scripts / "context_guard.py"
            for code in (0, 7):
                for caller_exit in (None, 2):
                    with self.subTest(event=event, code=code, caller_exit=caller_exit):
                        runtime.write_text(
                            "import json, sys\n"
                            "json.dump(json.load(sys.stdin), sys.stdout, ensure_ascii=False)\n"
                            f"raise SystemExit({code})\n", encoding="utf-8")
                        proc = self.invoke(event=event, caller_exit=caller_exit)
                        self.assertEqual(proc.returncode, code, proc.stderr)
                        self.assertEqual(json.loads(proc.stdout.decode("utf-8")), PAYLOAD)
                        self.assertEqual(proc.stderr, b"")

    def test_nested_nonhook_preserves_native_exit_zero_and_seven(self):
        runtime = self.scripts / "context_guard.py"
        for code in (0, 7):
            with self.subTest(code=code):
                runtime.write_text(f"print('native-marker')\nraise SystemExit({code})\n",
                                   encoding="utf-8")
                proc = self.invoke(route="self-test", caller_exit=2)
                self.assertEqual(proc.returncode, code, proc.stderr)
                self.assertEqual(proc.stdout.strip(), b"native-marker")
                self.assertEqual(proc.stderr, b"")

    def test_nested_configured_command_without_native_start_cannot_reuse_zero(self):
        fake = self.root / "no-native.ps1"
        fake.write_text("# Deliberately never starts a native process.\n", encoding="ascii")
        self.conf.write_text(str(fake) + "\n", encoding="utf-8")
        for route in ("hook", "self-test"):
            with self.subTest(route=route):
                proc = self.invoke(route=route, caller_exit=0, global_exit=0)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(proc.stdout, b"")

    def test_nested_wire_verifier_nonzero_or_no_native_start_is_rejected(self):
        fake = self.root / "wire-shim.ps1"
        self.env["CG_TEST_PYTHON"] = str(self.interpreter)
        self.conf.write_text(str(fake) + "\n", encoding="utf-8")
        for wire_exit in (None, 7):
            with self.subTest(wire_exit=wire_exit):
                native = ("" if wire_exit is None else
                          f"& $env:CG_TEST_PYTHON -c 'raise SystemExit({wire_exit})'\n")
                fake.write_text(
                    "if ($args[0] -eq '-I') {\n" + native +
                    "Write-Output 'CG-HOOK-WIRE-VERIFIED'\n"
                    "} else { & $env:CG_TEST_PYTHON @args }\n", encoding="ascii")
                proc = self.invoke(caller_exit=0, global_exit=0)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(proc.stdout, b"")
                self.assertIn(b"not a working Context Guard runtime", proc.stderr)

    def test_nested_malformed_wire_is_rejected_with_caller_shadow(self):
        for output in ("[]", "null", "{broken", ""):
            with self.subTest(output=output):
                self.runtime.write_text(f"print({output!r}, end='')\n", encoding="utf-8")
                proc = self.invoke(caller_exit=0, global_exit=0)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(proc.stdout, b"")
                self.assertIn(b"not a working Context Guard runtime", proc.stderr)

    def fallback_prelude(self, source, candidate):
        # Limit command discovery to one known source without depending on the
        # Windows host's installed Python versions or PATH aliases.
        self.conf.unlink(missing_ok=True)
        self.env["CG_TEST_FALLBACK_SOURCE"] = str(source)
        self.env["CG_TEST_FALLBACK_CANDIDATE"] = candidate
        return r'''
function Get-Command {
    param([string]$Name, $ErrorAction)
    if ($Name -eq $env:CG_TEST_FALLBACK_CANDIDATE) {
        [pscustomobject]@{Source=$env:CG_TEST_FALLBACK_SOURCE}
    }
}
'''

    def test_nested_fallback_probe_and_runtime_preserve_native_exit(self):
        for candidate in ("python3.14", "python"):
            for code in (0, 7):
                with self.subTest(candidate=candidate, code=code):
                    self.runtime.write_text(
                        f"print('native-marker')\nraise SystemExit({code})\n",
                        encoding="utf-8")
                    prelude = self.fallback_prelude(self.interpreter, candidate)
                    proc = self.invoke(caller_exit=2, prelude=prelude)
                    self.assertEqual(proc.returncode, code, proc.stderr)
                    self.assertEqual(proc.stdout.strip(), b"native-marker")
                    self.assertEqual(proc.stderr, b"")

    def test_nested_fallback_without_native_start_cannot_reuse_zero(self):
        fake = self.root / "no-native.ps1"
        fake.write_text("# Deliberately never starts a native process.\n", encoding="ascii")
        for candidate in ("python3.14", "python"):
            with self.subTest(candidate=candidate):
                prelude = self.fallback_prelude(fake, candidate)
                proc = self.invoke(caller_exit=0, global_exit=0, prelude=prelude)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(proc.stdout, b"")
                if candidate == "python":
                    self.assertIn(b"no supported interpreter", proc.stderr)

    def test_nested_failed_fallback_probe_continues_to_working_candidate(self):
        fake = self.root / "failed-probe.ps1"
        fake.write_text("& $env:CG_TEST_PYTHON -c 'raise SystemExit(7)'\n", encoding="ascii")
        self.env["CG_TEST_PYTHON"] = str(self.interpreter)
        self.runtime.write_text("print('native-marker')\n", encoding="ascii")
        prelude = self.fallback_prelude(fake, "python") + r'''
function Get-Command {
    param([string]$Name, $ErrorAction)
    if ($Name -eq 'python') { [pscustomobject]@{Source=$env:CG_TEST_FALLBACK_SOURCE} }
    if ($Name -eq 'python3') { [pscustomobject]@{Source=$env:CG_TEST_PYTHON} }
}
'''
        proc = self.invoke(caller_exit=2, prelude=prelude)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), b"native-marker")
        self.assertEqual(proc.stderr, b"")

    def test_relative_config_keeps_warning_and_fallback_with_caller_shadow(self):
        for encoding in ("utf-8", "utf-8-sig"):
            with self.subTest(encoding=encoding):
                prelude = self.fallback_prelude(self.interpreter, "python3.14")
                self.conf.write_text("relative.exe\n", encoding=encoding)
                proc = self.invoke(payload={}, caller_exit=2, prelude=prelude)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(json.loads(proc.stdout.decode("utf-8")), {})
                self.assertIn(b"must contain an absolute path; ignoring", proc.stderr)


if __name__ == "__main__":
    unittest.main()
