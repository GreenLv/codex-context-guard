"""Native discovery controls; original marketplace acceptance stays unchanged."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.cg_process_tree import OwnedProcess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/run-context-guard.ps1").read_text(encoding="utf-8")
RESOLVER_START = "$pythonPathDirectories ="
RESOLVER_END = "$candidates = @("


@unittest.skipUnless(os.name == "nt" and shutil.which("powershell.exe"),
                     "requires Windows PowerShell 5.1")
class WindowsModuleDiscovery(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        (self.home / "context-guard").mkdir(parents=True)
        self.modules = self.root / "modules"
        trap = self.modules / "AAACgDiscoveryTrap"
        trap.mkdir(parents=True)
        (trap / "AAACgDiscoveryTrap.psd1").write_text(
            "@{ModuleVersion='1.0';RootModule='AAACgDiscoveryTrap.psm1';"
            "FunctionsToExport='*';CmdletsToExport=@();AliasesToExport=@()}\n",
            encoding="utf-8")
        (trap / "AAACgDiscoveryTrap.psm1").write_text(
            "function Get-CgUnrelatedCommand {}\n", encoding="utf-8")
        self.trace = self.root / "trace.log"
        self.launcher = self.root / "run-context-guard.ps1"
        self.launcher.write_bytes(SOURCE.encode("utf-8"))
        (self.root / "cg_hook.py").write_text(
            "import json,sys\njson.dump(json.load(sys.stdin),sys.stdout)\n",
            encoding="utf-8")
        self.env = {key: os.environ[key] for key in
                    ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT") if key in os.environ}
        self.env.update(PATH=str(Path(sys.executable).parent) + os.pathsep + os.defpath,
                        HOME=str(self.root / "os-home"), USERPROFILE=str(self.root / "os-home"),
                        CODEX_HOME=str(self.home), PLUGIN_DATA=str(self.root / "data"),
                        TMP=str(self.root), TEMP=str(self.root), TMPDIR=str(self.root),
                        PSModulePath=str(self.modules),
                        PSModuleAnalysisCachePath=str(self.root / "module-cache"),
                        CG_TEST_LAUNCHER=str(self.launcher), CG_TEST_TRACE=str(self.trace))

    def run_trace(self, expression):
        wrapper = self.root / "wrapper.ps1"
        # Utility enables tracing only; Management must still be resolved by
        # the launcher. A fresh private module cache makes the trap observable.
        wrapper.write_text(
            "$ErrorActionPreference = 'Stop'\n"
            "if ($PSVersionTable.PSVersion.Major -ne 5) { exit 91 }\n"
            "$utility = [IO.Path]::Combine($PSHOME, 'Modules/Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1')\n"
            "Microsoft.PowerShell.Core\\Import-Module -Name $utility -ErrorAction Stop\n"
            "Microsoft.PowerShell.Utility\\Trace-Command -Name CommandDiscovery,Modules "
            "-Option All -FilePath $env:CG_TEST_TRACE -Expression {\n" + expression + "\n}\n",
            encoding="utf-8")
        owner = OwnedProcess.spawn(
            [shutil.which("powershell.exe"), "-NoProfile", "-NonInteractive", "-File", str(wrapper)],
            env=self.env, cwd=self.root, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = owner.process.communicate(b'{"probe":true}', timeout=30)
            code = owner.process.returncode
        finally:
            cleanup = owner.close(timeout=5)
            self.assertTrue(all(cleanup.get(key) is True for key in
                                ("cleanup_complete", "owned_process_exited", "owned_tree_no_running_members")))
        self.assertEqual(code, 0, stderr.decode("utf-8", errors="replace"))
        raw = self.trace.read_bytes()
        trace = raw.decode("utf-16" if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else "utf-8-sig")
        self.assertFalse("AAACgDiscoveryTrap" in trace,
                         "launcher analyzed an unrelated available module")
        return json.loads(stdout)

    def test_unconfigured_launch_avoids_unrelated_module_analysis(self):
        self.assertEqual(self.run_trace("& $env:CG_TEST_LAUNCHER hook UserPromptSubmit"),
                         {"probe": True})

    def test_configured_launch_avoids_unrelated_module_analysis(self):
        (self.home / "context-guard/interpreter.conf").write_text(
            str(Path(sys.executable).resolve()) + "\n", encoding="utf-8")
        self.assertEqual(self.run_trace("& $env:CG_TEST_LAUNCHER hook UserPromptSubmit"),
                         {"probe": True})

    def test_missing_relative_path_candidate_does_not_scan_modules(self):
        resolver = SOURCE[SOURCE.index(RESOLVER_START):SOURCE.index(RESOLVER_END)]
        result = self.run_trace(resolver + r'''
$PSModuleAutoLoadingPreference = 'All'
$before = $env:PATH
$result = Resolve-ContextGuardPythonCommand cg-unavailable-python-candidate
@{missing=($null -eq $result); preference=$PSModuleAutoLoadingPreference; path_same=($before -ceq $env:PATH)} | ConvertTo-Json -Compress
''')
        self.assertEqual(result, {"missing": True, "preference": "All", "path_same": True})

    def test_loaded_alias_and_function_keep_resolution_and_preference(self):
        resolver = SOURCE[SOURCE.index(RESOLVER_START):SOURCE.index(RESOLVER_END)]
        result = self.run_trace(resolver + r'''
$PSModuleAutoLoadingPreference = 'All'
function cg-session-python { throw 'discovery must not execute this function' }
Set-Alias cg-session-alias cg-session-python
$function = Resolve-ContextGuardPythonCommand cg-session-python
$alias = Resolve-ContextGuardPythonCommand cg-session-alias
@{function=$function.CommandType.ToString(); alias=$alias.CommandType.ToString(); preference=$PSModuleAutoLoadingPreference} | ConvertTo-Json -Compress
''')
        self.assertEqual(result, {"function": "Function", "alias": "Alias", "preference": "All"})

    def test_missing_global_preference_stays_absent(self):
        resolver = SOURCE[SOURCE.index(RESOLVER_START):SOURCE.index(RESOLVER_END)]
        result = self.run_trace(resolver + r'''
Remove-Variable PSModuleAutoLoadingPreference -Scope Global -ErrorAction SilentlyContinue
$result = Resolve-ContextGuardPythonCommand cg-unavailable-python-candidate
@{missing=($null -eq $result); absent=($null -eq (Get-Variable PSModuleAutoLoadingPreference -Scope Global -ErrorAction SilentlyContinue))} | ConvertTo-Json -Compress
''')
        self.assertEqual(result, {"missing": True, "absent": True})

    def test_discovery_exception_restores_global_preference(self):
        resolver = SOURCE[SOURCE.index(RESOLVER_START):SOURCE.index(RESOLVER_END)]
        result = self.run_trace(resolver + r'''
$global:PSModuleAutoLoadingPreference = 'ModuleQualified'
function Get-Command { throw 'synthetic discovery failure' }
$failed = $false
try { Resolve-ContextGuardPythonCommand cg-unavailable-python-candidate } catch { $failed = $true }
@{failed=$failed; preference=$global:PSModuleAutoLoadingPreference} | ConvertTo-Json -Compress
''')
        self.assertEqual(result, {"failed": True, "preference": "ModuleQualified"})
