"""Wire contracts for the native acceptance toolkit thin launchers.

The POSIX sh and PowerShell launchers must dispatch to the same Python cores
with passthrough arguments, never rewrite or filter them, and fail closed with
exit code 2 when the target or the interpreter is unavailable. PowerShell
syntax stays 5.1/7 compatible.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SH = ROOT / "tools/validation/run_native_acceptance.sh"
PS1 = ROOT / "tools/validation/run_native_acceptance.ps1"

DISPATCH = {
    "upgrade": "native_upgrade_acceptance.py",
    "between-turns": "native_between_turns_acceptance.py",
    "acceptance": "native_acceptance.py",
    "retention": "windows_retention_native.py",
    "scheduler": "native_scheduler_batch.py",
}


class LauncherWire(unittest.TestCase):
    def _check_documented_phase_recipe(self, language, shell, stub):
        text = (ROOT / "tools/validation/NATIVE_BETWEEN_TURNS_ACCEPTANCE.md").read_text(encoding="utf-8")
        section = text.split("## Run the phases", 1)[1]
        recipes = re.findall(r"```" + language + r"\n(.*?)```", section, re.S)
        # Select the maintained four-phase native recipe; the guide also has
        # separate identity-freeze and retained-result commands.
        recipes = [recipe for recipe in recipes if "--preflight-commands" in recipe]
        self.assertEqual(len(recipes), 1)
        phases = ["--preflight-commands", "--preflight", "--run", "--verify-result"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            launchers = root / "tools/validation"
            launchers.mkdir(parents=True)
            for name in ("run_native_acceptance", "run_daily_upgrade"):
                launcher = launchers / (name + (".sh" if language == "sh" else ".ps1"))
                launcher.write_text(stub)
                launcher.chmod(0o700)
            trace = root / "trace.txt"
            for failure in ["", *phases]:
                with self.subTest(language=language, failure=failure):
                    trace.write_text("")
                    result = subprocess.run(
                        [*shell, recipes[0]], cwd=root,
                        env={**os.environ, "CG_DOC_TRACE": trace.name, "CG_DOC_FAIL": failure},
                        capture_output=True, timeout=20,
                    )
                    expected = phases if not failure else phases[:phases.index(failure) + 1]
                    self.assertIsInstance(result.stderr, bytes)
                    self.assertIn(b"\xff", result.stderr)
                    self.assertEqual(trace.read_text(encoding="utf-8").splitlines(), expected)
                    self.assertEqual(result.returncode == 0, not failure, result.stderr)

    @unittest.skipUnless(shutil.which("sh"), "POSIX sh unavailable")
    def test_documented_shell_phases_stop_after_first_failure(self):
        self._check_documented_phase_recipe("sh", ["sh", "-c"], """#!/bin/sh
for cg_doc_phase do :; done
printf '\\377' >&2
printf '%s\\n' "$cg_doc_phase" >> "$CG_DOC_TRACE"
[ "$cg_doc_phase" != "$CG_DOC_FAIL" ] || exit 7
""")

    def test_documented_powershell_phases_stop_after_first_failure(self):
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if shell is None:
            self.skipTest("no PowerShell executable on PATH")
        self._check_documented_phase_recipe(
            "powershell", [shell, "-NoProfile", "-NonInteractive", "-Command"], """
param([string]$Target, [string[]]$Arguments)
[Console]::OpenStandardError().WriteByte(255)
$cgDocPhase = $Arguments[-1]
[IO.File]::AppendAllText($env:CG_DOC_TRACE, $cgDocPhase + [Environment]::NewLine)
if ($cgDocPhase -eq $env:CG_DOC_FAIL) { exit 7 }
exit 0
""")

    def test_launcher_files_exist_and_declare_their_runtime(self):
        self.assertTrue(SH.is_file())
        self.assertTrue(PS1.is_file())
        self.assertIn("#!/bin/sh", SH.read_text(encoding="utf-8"))
        self.assertIn("POSIX sh", SH.read_text(encoding="utf-8"))
        ps1 = PS1.read_text(encoding="utf-8")
        self.assertIn("Windows PowerShell 5.1 and PowerShell 7", ps1)

    def test_dispatch_table_is_identical_in_both_launchers(self):
        sh_text = SH.read_text(encoding="utf-8")
        ps1_text = PS1.read_text(encoding="utf-8")
        for name, module in DISPATCH.items():
            with self.subTest(target=name):
                self.assertIn(f"{module}", sh_text)
                self.assertIn(f"{module}", ps1_text)
                self.assertLess(sh_text.index(name), sh_text.index(module))
        for name, module in DISPATCH.items():
            self.assertIn(f'"{module}"', ps1_text)

    @unittest.skipUnless(shutil.which("sh"), "POSIX sh unavailable; PowerShell launcher is checked separately")
    def test_sh_launcher_requires_a_known_target(self):
        result = subprocess.run(["sh", str(SH)], capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    @unittest.skipUnless(shutil.which("sh"), "POSIX sh unavailable; PowerShell launcher is checked separately")
    def test_sh_launcher_rejects_unknown_target(self):
        result = subprocess.run(["sh", str(SH), "unknown-target"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2)

    @unittest.skipUnless(shutil.which("sh"), "POSIX sh unavailable; PowerShell launcher is checked separately")
    def test_sh_launcher_passes_arguments_through_to_the_core(self):
        result = subprocess.run(["sh", str(SH), "upgrade", "--help"],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--plan PLAN", result.stdout)

    @unittest.skipUnless(shutil.which("sh"), "POSIX sh unavailable; PowerShell launcher is checked separately")
    def test_between_turns_launcher_reaches_versioned_entry(self):
        result = subprocess.run(["sh", str(SH), "between-turns", "--help"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--verify-result", result.stdout)
        self.assertIn("--preflight", result.stdout)

    def test_sh_launcher_starts_python_exactly_once_with_b(self):
        sh_text = SH.read_text(encoding="utf-8")
        self.assertEqual(sh_text.count("exec \"$candidate\" -B \"$target\" \"$@\""), 2)
        self.assertNotIn("eval ", sh_text)

    def test_ps1_launcher_stays_51_and_7_compatible(self):
        ps1_text = PS1.read_text(encoding="utf-8")
        # PowerShell 7-only syntax that would break Windows PowerShell 5.1.
        for forbidden in (" ?? ", " ??=", "? ", "&&", "||"):
            self.assertNotIn(forbidden, ps1_text)
        self.assertIn("[CmdletBinding()]", ps1_text)
        self.assertIn("$Arguments = @()", ps1_text)
        self.assertIn("Test-PythonRuntime", ps1_text)
        self.assertIn("CG-PYTHON-3.10-RUNTIME-VERIFIED", ps1_text)
        self.assertIn("exit $LASTEXITCODE", ps1_text)

    def test_installed_powershell_launchers_run_python_core(self):
        shells = [path for name in ("powershell", "pwsh") if (path := shutil.which(name))]
        if not shells:
            self.skipTest("no PowerShell executable on PATH")
        command = "& $env:CG_LAUNCHER_UNDER_TEST -Target upgrade -Arguments @('--help'); exit $LASTEXITCODE"
        env = {**os.environ, "CG_LAUNCHER_UNDER_TEST": str(PS1), "PATH": str(Path(sys.executable).parent)}
        for shell in shells:
            with self.subTest(shell=shell):
                result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", command],
                                        env=env, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                self.assertIn(b"--plan PLAN", result.stdout)


if __name__ == "__main__":
    unittest.main()
