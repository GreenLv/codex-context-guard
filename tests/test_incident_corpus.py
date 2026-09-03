#!/usr/bin/env python3
"""Contract tests for the private incident-corpus tooling and public fixtures."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "incident_corpus.py"
FIXTURES = ROOT / "tests" / "fixtures" / "incidents" / "public_incidents.json"
RUNTIME = ROOT / "scripts" / "context_guard.py"

WINDOWS_ACL_READBACK_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$path = $env:CONTEXT_GUARD_TEST_PATH
$isDirectory = $env:CONTEXT_GUARD_TEST_KIND -eq 'directory'
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administrators = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$required = @($current, $system, $administrators)
function Get-Label([System.Security.Principal.SecurityIdentifier]$sid) {
    for ($index = 0; $index -lt $required.Count; $index++) {
        if ($sid -eq $required[$index]) {
            return @('current', 'system', 'administrators')[$index]
        }
    }
    return 'unexpected'
}
if ($isDirectory) {
    $item = [System.IO.DirectoryInfo]::new($path)
} else {
    $item = [System.IO.FileInfo]::new($path)
}
$accessSections = [System.Security.AccessControl.AccessControlSections]::Access
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $observed = [System.IO.FileSystemAclExtensions]::GetAccessControl(
        $item,
        $accessSections
    )
} else {
    $observed = $item.GetAccessControl($accessSections)
}
$rules = $observed.GetAccessRules(
    $true,
    $true,
    [System.Security.Principal.SecurityIdentifier]
)
$descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
    $observed.GetSecurityDescriptorBinaryForm(),
    0
)
$rulePrincipals = @($rules | ForEach-Object {
    Get-Label ([System.Security.Principal.SecurityIdentifier]$_.IdentityReference)
} | Sort-Object)
$rawPrincipals = @($descriptor.DiscretionaryAcl | ForEach-Object {
    Get-Label $_.SecurityIdentifier
} | Sort-Object)
[ordered]@{
    protected = $observed.AreAccessRulesProtected
    raw_protected = $descriptor.ControlFlags.HasFlag(
        [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    )
    rules_count = $rules.Count
    raw_count = $descriptor.DiscretionaryAcl.Count
    rule_principals = $rulePrincipals
    raw_principals = $rawPrincipals
    rule_types = @($rules | ForEach-Object { $_.AccessControlType.ToString() })
    rule_rights = @($rules | ForEach-Object { [int]$_.FileSystemRights })
    rule_inheritance = @($rules | ForEach-Object { $_.InheritanceFlags.ToString() })
    rule_propagation = @($rules | ForEach-Object { $_.PropagationFlags.ToString() })
    rule_inherited = @($rules | ForEach-Object { $_.IsInherited })
    raw_qualifiers = @($descriptor.DiscretionaryAcl | ForEach-Object {
        $_.AceQualifier.ToString()
    })
    raw_masks = @($descriptor.DiscretionaryAcl | ForEach-Object { $_.AccessMask })
    raw_flags = @($descriptor.DiscretionaryAcl | ForEach-Object {
        $_.AceFlags.ToString()
    })
} | ConvertTo-Json -Compress
"""

WINDOWS_ACL_MUTATE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ContextGuardAclTestMutation {
    public const int SeFileObject = 1;
    public const uint DaclSecurityInformation = 0x00000004;
    public const uint ProtectedDaclSecurityInformation = 0x80000000;
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern uint SetNamedSecurityInfoW(
        string objectName, int objectType, uint securityInfo,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl
    );
}
'@
$path = $env:CONTEXT_GUARD_TEST_PATH
$isDirectory = $env:CONTEXT_GUARD_TEST_KIND -eq 'directory'
$scenario = $env:CONTEXT_GUARD_TEST_SCENARIO
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administrators = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$localService = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-19')
$principals = @($current, $system, $administrators)
if ($scenario -eq 'missing') {
    $principals = @($current, $administrators)
} elseif ($scenario -eq 'extra') {
    $principals = @($current, $system, $administrators, $localService)
}
$flags = [System.Security.AccessControl.AceFlags]::None
if ($isDirectory) {
    $flags = [System.Security.AccessControl.AceFlags](
        [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
        [int][System.Security.AccessControl.AceFlags]::ObjectInherit
    )
}
$extra = if ($scenario -eq 'deny') { 1 } else { 0 }
$acl = [System.Security.AccessControl.RawAcl]::new(2, $principals.Count + $extra)
if ($scenario -eq 'deny') {
    $acl.InsertAce(0, [System.Security.AccessControl.CommonAce]::new(
        $flags,
        [System.Security.AccessControl.AceQualifier]::AccessDenied,
        [int][System.Security.AccessControl.FileSystemRights]::ReadData,
        $localService,
        $false,
        $null
    ))
}
foreach ($sid in $principals) {
    $acl.InsertAce($acl.Count, [System.Security.AccessControl.CommonAce]::new(
        $flags,
        [System.Security.AccessControl.AceQualifier]::AccessAllowed,
        [int][System.Security.AccessControl.FileSystemRights]::FullControl,
        $sid,
        $false,
        $null
    ))
}
$bytes = [byte[]]::new($acl.BinaryLength)
$acl.GetBinaryForm($bytes, 0)
$pointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
try {
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $pointer, $bytes.Length)
    $result = [ContextGuardAclTestMutation]::SetNamedSecurityInfoW(
        $path,
        [ContextGuardAclTestMutation]::SeFileObject,
        [ContextGuardAclTestMutation]::DaclSecurityInformation -bor
            [ContextGuardAclTestMutation]::ProtectedDaclSecurityInformation,
        [IntPtr]::Zero,
        [IntPtr]::Zero,
        $pointer,
        [IntPtr]::Zero
    )
    if ($result -ne 0) { throw "ACL mutation failed with code $result" }
} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
}
'CONTEXT_GUARD_TEST_ACL_MUTATED'
"""


def load_tool():
    spec = importlib.util.spec_from_file_location("incident_corpus", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_windows_acl_script(
    script: str, path: Path, *, directory: bool, scenario: str | None = None
) -> subprocess.CompletedProcess[str]:
    shell = next(
        (
            candidate
            for name in ("pwsh.exe", "pwsh", "powershell.exe", "powershell")
            if (candidate := shutil.which(name)) is not None
        ),
        None,
    )
    if shell is None:
        raise unittest.SkipTest("Windows ACL tests require PowerShell")
    environment = os.environ.copy()
    environment.update(
        {
            "CONTEXT_GUARD_TEST_PATH": str(path),
            "CONTEXT_GUARD_TEST_KIND": "directory" if directory else "file",
        }
    )
    if scenario is not None:
        environment["CONTEXT_GUARD_TEST_SCENARIO"] = scenario
    return subprocess.run(
        [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
        env=environment,
    )


class IncidentCorpusTests(unittest.TestCase):
    def test_public_fixture_contract_and_taxonomy(self) -> None:
        tool = load_tool()
        fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
        self.assertTrue({item["root_cause"] for item in fixtures}.issubset(tool.ROOT_CAUSES))
        self.assertIn("pre_action_authorization", tool.ROOT_CAUSES)
        for fixture in fixtures:
            self.assertEqual(tool.validate_record(fixture, public=True), [])

    def test_v2_private_record_requires_bounded_authorization_metadata(self) -> None:
        tool = load_tool()
        fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))[0]
        fixture.update(
            {
                "record_schema": "incident-corpus/v2",
                "root_cause": "pre_action_authorization",
                "protocol_surface": "pre_action_authorization",
                "execution_contract_state": "absent",
                "action_ticket_state": "absent",
                "tool_input_sha256": "f" * 64,
                "incident_group_sha256": "e" * 64,
                "reproduction_status": "documented_only",
            }
        )
        self.assertEqual(tool.validate_record(fixture), [])
        public = {key: value for key, value in fixture.items() if key in tool.PUBLIC_FIELDS}
        self.assertNotIn("incident_group_sha256", public)
        self.assertEqual(tool.validate_record(public, public=True), [])

    def test_v2_fields_without_schema_fail_closed(self) -> None:
        tool = load_tool()
        fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))[0]
        fixture["protocol_surface"] = "stop"
        self.assertIn(
            "v2 incident fields require record_schema incident-corpus/v2",
            tool.validate_record(fixture),
        )

    def test_benchmark_dispatches_non_stop_protocol_surfaces(self) -> None:
        tool = load_tool()
        runtime = tool.load_runtime(RUNTIME)
        base = json.loads(FIXTURES.read_text(encoding="utf-8"))[0]
        cases = (
            (
                "pre_action_authorization",
                {"risk_tier": "A", "execution_contract_state": "absent", "action_ticket_state": "absent", "input_matches": False},
                "deny_high_risk_action_without_ticket",
            ),
            (
                "supersession_attribution",
                {"supersession_phrase_origin": "quoted", "explicit_target_count": 1},
                "preserve_prior_requirement",
            ),
            (
                "scope_transition_authority",
                {"authorized_work_unit": "merge_cleanup", "attempted_transition": "new_product_repair", "separate_authorization": False},
                "deny_unapproved_scope_transition",
            ),
        )
        for fixture_kind, event, expected in cases:
            with self.subTest(fixture_kind=fixture_kind):
                fixture = dict(base)
                fixture.update(
                    {
                        "fixture_kind": fixture_kind,
                        "minimal_event": event,
                        "expected_authoritative_outcome": expected,
                    }
                )
                result = tool.benchmark_fixture(runtime, fixture)
                self.assertTrue(result["pass"], result)

    def test_current_runtime_passes_public_benchmark_without_false_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "benchmark",
                    "--fixtures",
                    str(FIXTURES),
                    "--runtime",
                    str(RUNTIME),
                    "--report-dir",
                    temporary,
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            generated = sorted(Path(temporary).iterdir())
            self.assertEqual(
                [item.name for item in generated],
                [
                    "stop-2-1-0.json",
                    "stop-2-1-0.manifest.json",
                    "stop-2-1-0.md",
                ],
            )
            tool = load_tool()
            self.assertTrue(
                all(
                    tool.private_path_permission_error(item, directory=False) is None
                    for item in generated
                )
            )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["plugin_stop_protocol"], "2.1.0")
        self.assertEqual(report["plugin_execution_protocol"], "2.0.0")
        self.assertEqual(report["fixtures"], report["passed"])
        self.assertEqual(report["false_continuations"], 0)
        self.assertIsInstance(report["diagnostic_accuracy"], float)
        self.assertEqual(report["taxonomy_coverage"]["covered"], report["fixtures"])
        self.assertIn("pre_action_authorization", report["taxonomy_coverage"]["uncovered"])
        self.assertEqual(
            report["taxonomy_coverage"]["by_root_cause"]["pre_action_authorization"],
            0,
        )
        self.assertAlmostEqual(
            report["taxonomy_coverage"]["coverage_rate"],
            report["taxonomy_coverage"]["covered"]
            / report["taxonomy_coverage"]["total"],
        )

    def test_append_only_ingest_validate_and_summary_excludes_documented_only(self) -> None:
        tool = load_tool()
        fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))[0]
        fixture.update({"reproduction_status": "documented_only", "public_reviewed": True, "public_fixture_id": "public-CGI-2026-001"})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "corpus"
            source = Path(temporary) / "record.json"
            source.write_text(json.dumps(fixture), encoding="utf-8")
            args = type("Args", (), {"root": str(root), "record": str(source)})()
            self.assertEqual(tool.command_ingest(args), 0)
            self.assertIsNone(tool.private_path_permission_error(root, directory=True))
            record_path = root / "records" / "CGI-2026-001.json"
            self.assertIsNone(
                tool.private_path_permission_error(record_path, directory=False)
            )
            records, errors = tool.load_records(root)
            self.assertEqual(errors, [])
            report = tool.summarize(records)
            self.assertEqual(report["documented_only"], 1)
            self.assertEqual(report["eligible_denominator"], 0)
            exported = Path(temporary) / "public.json"
            export_args = type(
                "Args", (), {"root": str(root), "output": str(exported)}
            )()
            self.assertEqual(tool.command_export_public(export_args), 0)
            self.assertIsNone(
                tool.private_path_permission_error(exported, directory=False)
            )
            public = json.loads(exported.read_text(encoding="utf-8"))
            self.assertEqual(len(public), 1)
            self.assertNotIn("public_reviewed", public[0])
            with self.assertRaises(ValueError):
                tool.command_ingest(args)

    def test_status_promotion_requires_append_only_successor(self) -> None:
        tool = load_tool()
        fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))[0]
        fixture["reproduction_status"] = "documented_only"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "corpus"
            source = Path(temporary) / "record.json"
            source.write_text(json.dumps(fixture), encoding="utf-8")
            first = type("Args", (), {"root": str(root), "record": str(source), "supersede_start": None})()
            self.assertEqual(tool.command_ingest(first), 0)
            successor = dict(fixture)
            successor["reproduction_status"] = "reproduced"
            source.write_text(json.dumps(successor), encoding="utf-8")
            second = type("Args", (), {"root": str(root), "record": str(source), "supersede_start": 101})()
            self.assertEqual(tool.command_ingest(second), 0)
            records, errors = tool.load_records(root)
            self.assertEqual(errors, [])
            self.assertEqual(tool.active_records(records)[0]["incident_id"], "CGI-2026-101")
            invalid = dict(successor)
            invalid["reproduction_status"] = "documented_only"
            invalid["incident_id"] = "CGI-2026-102"
            invalid["supersedes"] = "CGI-2026-101"
            target = root / "records" / "CGI-2026-102.json"
            target.write_text(json.dumps(invalid), encoding="utf-8")
            tool.restrict_private_path(target, directory=False)
            _records, errors = tool.load_records(root)
            self.assertTrue(any("invalid append-only status transition" in error for error in errors))

    def test_windows_private_paths_use_acl_instead_of_posix_mode_bits(self) -> None:
        tool = load_tool()
        path = Path("private-artifact")
        with (
            mock.patch.object(tool, "IS_WINDOWS", True),
            mock.patch.object(tool, "_windows_acl_error", return_value=None) as acl,
            mock.patch.object(tool.os, "chmod") as chmod,
        ):
            tool.restrict_private_path(path, directory=True)
            self.assertIsNone(tool.private_path_permission_error(path, directory=True))
        chmod.assert_not_called()
        self.assertEqual(
            acl.call_args_list,
            [
                mock.call(path, directory=True, apply=True),
                mock.call(path, directory=True, apply=False),
            ],
        )

    def test_windows_acl_failure_is_fail_closed(self) -> None:
        tool = load_tool()
        path = Path("private-artifact")
        with (
            mock.patch.object(tool, "IS_WINDOWS", True),
            mock.patch.object(
                tool,
                "_windows_acl_error",
                return_value="Windows private ACL could not be verified",
            ),
        ):
            with self.assertRaisesRegex(ValueError, "could not be verified"):
                tool.restrict_private_path(path, directory=False)

    @unittest.skipUnless(
        sys.platform == "win32" and shutil.which("powershell.exe"),
        "Windows PowerShell 5.1 ACL regression",
    )
    def test_windows_acl_script_supports_windows_powershell_51(self) -> None:
        tool = load_tool()
        shell = shutil.which("powershell.exe")
        assert shell is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = (
                (root / "legacy-directory", True),
                (root / "legacy-file.dat", False),
            )
            for path, is_directory in cases:
                if is_directory:
                    path.mkdir()
                else:
                    path.write_bytes(b"")
                for action in ("apply", "verify"):
                    environment = os.environ.copy()
                    environment.update(
                        {
                            "CONTEXT_GUARD_PRIVATE_PATH": str(path),
                            "CONTEXT_GUARD_PRIVATE_KIND": (
                                "directory" if is_directory else "file"
                            ),
                            "CONTEXT_GUARD_PRIVATE_ACL_ACTION": action,
                        }
                    )
                    result = subprocess.run(
                        [
                            shell,
                            "-NoLogo",
                            "-NoProfile",
                            "-NonInteractive",
                            "-Command",
                            tool.WINDOWS_ACL_SCRIPT,
                        ],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=30,
                        env=environment,
                    )
                    self.assertEqual(
                        result.returncode,
                        0,
                        result.stderr,
                    )
                    self.assertEqual(result.stdout.strip(), tool.WINDOWS_ACL_MARKER)

    def test_windows_acl_script_writes_only_a_protected_dacl(self) -> None:
        tool = load_tool()
        script = tool.WINDOWS_ACL_SCRIPT
        self.assertIn("SetNamedSecurityInfoW", script)
        self.assertIn("DaclSecurityInformation", script)
        self.assertIn("ProtectedDaclSecurityInformation", script)
        self.assertIn("GetAccessRules", script)
        self.assertIn("RawSecurityDescriptor", script)
        self.assertIn("[IntPtr]::Zero", script)
        self.assertNotIn("$observed.Access", script)
        self.assertNotIn("Set-Acl", script)
        self.assertNotIn("SetOwner", script)
        self.assertNotIn("SaclSecurityInformation", script)
        self.assertNotIn("SACL_SECURITY_INFORMATION", script)

    @unittest.skipUnless(sys.platform == "win32", "Windows ACL regression")
    def test_windows_native_acl_round_trip_has_exact_rules(self) -> None:
        tool = load_tool()
        expected_principals = ["administrators", "current", "system"]
        full_control = 2032127
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "private-directory"
            file_path = root / "private-file.dat"
            directory.mkdir()
            file_path.write_bytes(b"")
            for path, is_directory, inheritance, raw_flags in (
                (
                    directory,
                    True,
                    "ContainerInherit, ObjectInherit",
                    "ObjectInherit, ContainerInherit",
                ),
                (file_path, False, "None", "None"),
            ):
                tool.restrict_private_path(path, directory=is_directory)
                self.assertIsNone(
                    tool.private_path_permission_error(
                        path, directory=is_directory
                    )
                )
                result = run_windows_acl_script(
                    WINDOWS_ACL_READBACK_SCRIPT,
                    path,
                    directory=is_directory,
                )
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                observed = json.loads(result.stdout)
                self.assertTrue(observed["protected"])
                self.assertTrue(observed["raw_protected"])
                self.assertEqual(observed["rules_count"], 3)
                self.assertEqual(observed["raw_count"], 3)
                self.assertEqual(observed["rule_principals"], expected_principals)
                self.assertEqual(observed["raw_principals"], expected_principals)
                self.assertEqual(observed["rule_types"], ["Allow"] * 3)
                self.assertEqual(observed["rule_rights"], [full_control] * 3)
                self.assertEqual(observed["rule_inheritance"], [inheritance] * 3)
                self.assertEqual(observed["rule_propagation"], ["None"] * 3)
                self.assertEqual(observed["rule_inherited"], [False] * 3)
                self.assertEqual(observed["raw_qualifiers"], ["AccessAllowed"] * 3)
                self.assertEqual(observed["raw_masks"], [full_control] * 3)
                self.assertEqual(observed["raw_flags"], [raw_flags] * 3)

    @unittest.skipUnless(sys.platform == "win32", "Windows ACL regression")
    def test_windows_native_acl_rejects_missing_extra_and_deny_aces(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private-file.dat"
            path.write_bytes(b"")
            for scenario in ("missing", "extra", "deny"):
                tool.restrict_private_path(path, directory=False)
                result = run_windows_acl_script(
                    WINDOWS_ACL_MUTATE_SCRIPT,
                    path,
                    directory=False,
                    scenario=scenario,
                )
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                self.assertEqual(
                    result.stdout.strip(), "CONTEXT_GUARD_TEST_ACL_MUTATED"
                )
                self.assertIsNotNone(
                    tool.private_path_permission_error(path, directory=False)
                )

    @unittest.skipUnless(sys.platform == "win32", "Windows ACL regression")
    def test_windows_native_acl_readback_failure_is_fail_closed(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing-file.dat"
            self.assertIsNotNone(
                tool.private_path_permission_error(missing, directory=False)
            )


if __name__ == "__main__":
    unittest.main()
