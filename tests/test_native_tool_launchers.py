"""Wire contracts for the native acceptance toolkit thin launchers.

The POSIX sh and PowerShell launchers must dispatch to the same Python cores
with passthrough arguments, never rewrite or filter them, and fail closed with
exit code 2 when the target or the interpreter is unavailable. PowerShell
syntax stays 5.1/7 compatible.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SH = ROOT / "tools/validation/run_native_acceptance.sh"
PS1 = ROOT / "tools/validation/run_native_acceptance.ps1"

DISPATCH = {
    "upgrade": "native_upgrade_acceptance.py",
    "acceptance": "native_acceptance.py",
    "retention": "windows_retention_native.py",
    "scheduler": "native_scheduler_batch.py",
}


class LauncherWire(unittest.TestCase):
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

    def test_sh_launcher_requires_a_known_target(self):
        result = subprocess.run(["sh", str(SH)], capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_sh_launcher_rejects_unknown_target(self):
        result = subprocess.run(["sh", str(SH), "unknown-target"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2)

    def test_sh_launcher_passes_arguments_through_to_the_core(self):
        result = subprocess.run(["sh", str(SH), "upgrade", "--help"],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--plan PLAN", result.stdout)

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

    def test_installed_powershell_parsers_accept_launcher(self):
        shells = [path for name in ("powershell", "pwsh") if (path := shutil.which(name))]
        if not shells:
            self.skipTest("no PowerShell executable on PATH")
        command = (
            "$tokens = $errors = $null; "
            "[void][System.Management.Automation.Language.Parser]::ParseFile("
            "$env:CG_LAUNCHER_UNDER_TEST, [ref]$tokens, [ref]$errors); "
            "if ($errors.Count -ne 0) { $errors | Out-String | Write-Output; exit 1 }"
        )
        for shell in shells:
            with self.subTest(shell=shell):
                result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", command],
                                        env={**os.environ, "CG_LAUNCHER_UNDER_TEST": str(PS1)},
                                        capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))


if __name__ == "__main__":
    unittest.main()
