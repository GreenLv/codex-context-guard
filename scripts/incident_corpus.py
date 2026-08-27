#!/usr/bin/env python3
"""Maintain and benchmark a private, append-only Context Guard incident corpus.

The corpus is intentionally separate from the public repository.  This module
uses only the Python standard library, never opens the network, and exports
only records that a maintainer has explicitly marked as publicly reviewed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

INCIDENT_RE = re.compile(r"^CGI-[0-9]{4}-[0-9]{3}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PRIVATE_RE = re.compile(
    r"(?:/Users/|[A-Za-z]:\\Users\\|codex://threads/|"
    r"\b(?:token|password|secret|api[_-]?key)\s*[:=]|"
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b)",
    re.IGNORECASE,
)
ROOT_CAUSES = {
    "completion_semantics",
    "action_handoff",
    "privacy_metadata",
    "receipt_adapter",
    "proof_scope_visual",
    "compaction_recovery",
    "hook_cache_lifecycle",
    "cross_platform",
}
REPRODUCTION_STATES = {
    "documented_only",
    "source_confirmed",
    "reproduced",
    "contained",
    "fixed",
}
REQUIRED_FIELDS = {
    "incident_id",
    "observed_version",
    "hook_event",
    "platform",
    "expected_authoritative_outcome",
    "actual_authoritative_outcome",
    "diagnostic_outcome",
    "reason_codes",
    "root_cause",
    "reproduction_status",
    "remediation_version",
    "minimal_event",
    "source_evidence_sha256",
}
PUBLIC_FIELDS = {
    "incident_id",
    "observed_version",
    "hook_event",
    "platform",
    "expected_authoritative_outcome",
    "actual_authoritative_outcome",
    "diagnostic_outcome",
    "reason_codes",
    "root_cause",
    "reproduction_status",
    "remediation_version",
    "minimal_event",
    "source_evidence_sha256",
    "wording_patch",
    "regression_versions",
    "fixture_kind",
    "expected_by_stop_protocol",
    "public_fixture_id",
}
IS_WINDOWS = os.name == "nt"
WINDOWS_ACL_MARKER = "CONTEXT_GUARD_PRIVATE_ACL_OK"
WINDOWS_ACL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class ContextGuardNativeAcl {
    public const int SeFileObject = 1;
    public const uint DaclSecurityInformation = 0x00000004;
    public const uint ProtectedDaclSecurityInformation = 0x80000000;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern uint SetNamedSecurityInfoW(
        string objectName,
        int objectType,
        uint securityInfo,
        IntPtr owner,
        IntPtr group,
        IntPtr dacl,
        IntPtr sacl
    );
}
'@
$path = $env:CONTEXT_GUARD_PRIVATE_PATH
$isDirectory = $env:CONTEXT_GUARD_PRIVATE_KIND -eq 'directory'
$apply = $env:CONTEXT_GUARD_PRIVATE_ACL_ACTION -eq 'apply'
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administrators = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$required = @($current, $system, $administrators)
$fullControlMask = [int][System.Security.AccessControl.FileSystemRights]::FullControl
$expectedAceFlags = [System.Security.AccessControl.AceFlags]::None
$expectedInheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
if ($isDirectory) {
    $expectedAceFlags = [System.Security.AccessControl.AceFlags](
        [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor
        [int][System.Security.AccessControl.AceFlags]::ObjectInherit
    )
    $expectedInheritanceFlags = [System.Security.AccessControl.InheritanceFlags](
        [int][System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
}
$allowed = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
foreach ($sid in $required) {
    [void]$allowed.Add($sid.Value)
}

if ($apply) {
    $rawAcl = [System.Security.AccessControl.RawAcl]::new(2, $required.Count)
    foreach ($sid in $required) {
        $ace = [System.Security.AccessControl.CommonAce]::new(
            $expectedAceFlags,
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            $fullControlMask,
            $sid,
            $false,
            $null
        )
        $rawAcl.InsertAce($rawAcl.Count, $ace)
    }
    if ($rawAcl.Count -ne $required.Count) {
        throw 'private ACL construction produced the wrong ACE count'
    }
    $constructed = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($ace in $rawAcl) {
        if ($ace -isnot [System.Security.AccessControl.CommonAce] -or
            $ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed -or
            $ace.AccessMask -ne $fullControlMask -or
            $ace.AceFlags -ne $expectedAceFlags -or
            -not $allowed.Contains($ace.SecurityIdentifier.Value) -or
            -not $constructed.Add($ace.SecurityIdentifier.Value)) {
            throw 'private ACL construction produced an invalid ACE'
        }
    }
    $bytes = [byte[]]::new($rawAcl.BinaryLength)
    $rawAcl.GetBinaryForm($bytes, 0)
    $binarySize = [BitConverter]::ToUInt16($bytes, 2)
    $binaryAceCount = [BitConverter]::ToUInt16($bytes, 4)
    if ($bytes.Length -ne $rawAcl.BinaryLength -or
        $binarySize -ne $bytes.Length -or
        $binaryAceCount -ne $required.Count) {
        throw 'private ACL binary form is inconsistent'
    }
    $dacl = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
    try {
        if ($dacl -eq [IntPtr]::Zero) {
            throw 'private ACL native pointer is null'
        }
        [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $dacl, $bytes.Length)
        $securityInfo = [ContextGuardNativeAcl]::DaclSecurityInformation -bor
            [ContextGuardNativeAcl]::ProtectedDaclSecurityInformation
        $result = [ContextGuardNativeAcl]::SetNamedSecurityInfoW(
            $path,
            [ContextGuardNativeAcl]::SeFileObject,
            $securityInfo,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            $dacl,
            [IntPtr]::Zero
        )
        if ($result -ne 0) {
            throw [System.ComponentModel.Win32Exception]::new([int]$result)
        }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($dacl)
    }
}

if ($isDirectory) {
    $item = [System.IO.DirectoryInfo]::new($path)
} else {
    $item = [System.IO.FileInfo]::new($path)
}
$observed = [System.IO.FileSystemAclExtensions]::GetAccessControl(
    $item,
    [System.Security.AccessControl.AccessControlSections]::Access
)
if (-not $observed.AreAccessRulesProtected) {
    throw 'private ACL still inherits access rules'
}
$rules = $observed.GetAccessRules(
    $true,
    $true,
    [System.Security.Principal.SecurityIdentifier]
)
if ($rules.Count -ne $required.Count) {
    throw 'private ACL has the wrong access-rule count'
}
$ruleSids = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
foreach ($rule in $rules) {
    $sid = ([System.Security.Principal.SecurityIdentifier]$rule.IdentityReference).Value
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        [int]$rule.FileSystemRights -ne $fullControlMask -or
        $rule.InheritanceFlags -ne $expectedInheritanceFlags -or
        $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None -or
        $rule.IsInherited -or
        -not $allowed.Contains($sid) -or
        -not $ruleSids.Add($sid)) {
        throw 'private ACL access-rule contract failed'
    }
}
foreach ($sid in $required) {
    if (-not $ruleSids.Contains($sid.Value)) {
        throw 'private ACL omits a required principal'
    }
}

$descriptorBytes = $observed.GetSecurityDescriptorBinaryForm()
$descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
    $descriptorBytes,
    0
)
if ($null -eq $descriptor.DiscretionaryAcl) {
    throw 'private ACL raw descriptor omits the DACL'
}
if (-not $descriptor.ControlFlags.HasFlag(
    [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
)) {
    throw 'private ACL raw descriptor still inherits access rules'
}
if ($descriptor.DiscretionaryAcl.Count -ne $required.Count) {
    throw 'private ACL raw descriptor has the wrong ACE count'
}
$rawSids = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
foreach ($ace in $descriptor.DiscretionaryAcl) {
    if ($ace -isnot [System.Security.AccessControl.CommonAce] -or
        $ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed -or
        $ace.AccessMask -ne $fullControlMask -or
        $ace.AceFlags -ne $expectedAceFlags -or
        -not $allowed.Contains($ace.SecurityIdentifier.Value) -or
        -not $rawSids.Add($ace.SecurityIdentifier.Value)) {
        throw 'private ACL raw-descriptor contract failed'
    }
}
foreach ($sid in $required) {
    if (-not $rawSids.Contains($sid.Value)) {
        throw 'private ACL raw descriptor omits a required principal'
    }
}
Write-Output 'CONTEXT_GUARD_PRIVATE_ACL_OK'
"""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def records_dir(root: Path) -> Path:
    return root / "records"


def _windows_acl_error(path: Path, *, directory: bool, apply: bool) -> str | None:
    shell = next(
        (
            candidate
            for name in ("pwsh.exe", "pwsh", "powershell.exe", "powershell")
            if (candidate := shutil.which(name)) is not None
        ),
        None,
    )
    if shell is None:
        return "Windows private ACL requires PowerShell"
    environment = os.environ.copy()
    environment.update(
        {
            "CONTEXT_GUARD_PRIVATE_PATH": str(path),
            "CONTEXT_GUARD_PRIVATE_KIND": "directory" if directory else "file",
            "CONTEXT_GUARD_PRIVATE_ACL_ACTION": "apply" if apply else "verify",
        }
    )
    try:
        result = subprocess.run(
            [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_ACL_SCRIPT],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "Windows private ACL command could not run"
    if result.returncode != 0 or result.stdout.strip() != WINDOWS_ACL_MARKER:
        return "Windows private ACL is not restricted to the current user and system principals"
    return None


def private_path_permission_error(path: Path, *, directory: bool) -> str | None:
    if IS_WINDOWS:
        return _windows_acl_error(path, directory=directory, apply=False)
    expected = 0o700 if directory else 0o600
    observed = stat.S_IMODE(path.stat().st_mode)
    if observed != expected:
        return f"mode must be {expected:04o}"
    return None


def restrict_private_path(path: Path, *, directory: bool) -> None:
    if IS_WINDOWS:
        error = _windows_acl_error(path, directory=directory, apply=True)
    else:
        os.chmod(path, 0o700 if directory else 0o600)
        error = private_path_permission_error(path, directory=directory)
    if error:
        raise ValueError(error)


def ensure_private_root(root: Path, *, create: bool) -> None:
    if create:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        records_dir(root).mkdir(mode=0o700, exist_ok=True)
    if not root.is_dir():
        raise ValueError(f"corpus root is not a directory: {root}")
    if (root / ".git").exists():
        raise ValueError("incident corpus must not be a Git repository")
    restrict_private_path(root, directory=True)
    if records_dir(root).exists():
        restrict_private_path(records_dir(root), directory=True)


def validate_record(record: Any, *, public: bool = False) -> list[str]:
    errors: list[str] = []
    if not isinstance(record, dict):
        return ["record must be an object"]
    missing = REQUIRED_FIELDS.difference(record)
    if missing:
        errors.append("missing fields: " + ", ".join(sorted(missing)))
    incident_id = record.get("incident_id")
    if not isinstance(incident_id, str) or not INCIDENT_RE.fullmatch(incident_id):
        errors.append("incident_id must match CGI-YYYY-NNN")
    if record.get("root_cause") not in ROOT_CAUSES:
        errors.append("root_cause is not in the public taxonomy")
    if record.get("reproduction_status") not in REPRODUCTION_STATES:
        errors.append("invalid reproduction_status")
    reasons = record.get("reason_codes")
    if not isinstance(reasons, list) or not reasons or not all(
        isinstance(item, str) and item for item in reasons
    ):
        errors.append("reason_codes must be a non-empty string list")
    event = record.get("minimal_event")
    if not isinstance(event, dict):
        errors.append("minimal_event must be an object")
    evidence_hash = record.get("source_evidence_sha256")
    if not isinstance(evidence_hash, str) or not SHA256_RE.fullmatch(evidence_hash):
        errors.append("source_evidence_sha256 must be a lowercase SHA-256")
    if public:
        serialized = canonical_json(record)
        if PRIVATE_RE.search(serialized):
            errors.append("public record contains a private path, identifier, or secret label")
        extra = set(record).difference(PUBLIC_FIELDS)
        if extra:
            errors.append("public record has non-exportable fields: " + ", ".join(sorted(extra)))
    supersedes = record.get("supersedes")
    if supersedes is not None and (
        not isinstance(supersedes, str) or not INCIDENT_RE.fullmatch(supersedes)
    ):
        errors.append("supersedes must name an earlier CGI record")
    return errors


def load_records(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    paths = sorted(records_dir(root).glob("CGI-*.json")) if records_dir(root).is_dir() else []
    for path in paths:
        try:
            record = read_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path.name}: invalid JSON: {exc}")
            continue
        item_errors = validate_record(record)
        errors.extend(f"{path.name}: {item}" for item in item_errors)
        incident_id = record.get("incident_id")
        if isinstance(incident_id, str):
            if incident_id in seen:
                errors.append(f"duplicate incident_id: {incident_id}")
            seen.add(incident_id)
            if path.name != f"{incident_id}.json":
                errors.append(f"{path.name}: filename does not match incident_id")
        if isinstance(record, dict):
            records.append(record)
        permission_error = private_path_permission_error(path, directory=False)
        if permission_error:
            errors.append(f"{path.name}: {permission_error}")
    by_id = {str(item.get("incident_id")): item for item in records}
    for item in records:
        supersedes = item.get("supersedes")
        if supersedes and supersedes not in by_id:
            errors.append(f"{item.get('incident_id')}: supersedes unknown record {supersedes}")
        if supersedes and supersedes >= str(item.get("incident_id")):
            errors.append(f"{item.get('incident_id')}: supersedes must point backward")
    return records, errors


def active_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    superseded = {str(item["supersedes"]) for item in records if item.get("supersedes")}
    return [item for item in records if str(item.get("incident_id")) not in superseded]


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    active = active_records(records)
    eligible = [item for item in active if item.get("reproduction_status") != "documented_only"]
    reproduced = [
        item for item in eligible if item.get("reproduction_status") in {"reproduced", "contained", "fixed"}
    ]
    recurrent = [item for item in eligible if len(item.get("regression_versions", [])) > 1]
    covered = [item for item in eligible if item.get("public_fixture_id")]
    wording_debt = [item for item in active if item.get("wording_patch") is True]
    return {
        "records_total": len(records),
        "active_records": len(active),
        "documented_only": sum(item.get("reproduction_status") == "documented_only" for item in active),
        "eligible_denominator": len(eligible),
        "reproduced": len(reproduced),
        "reproduction_rate": len(reproduced) / len(eligible) if eligible else None,
        "recurrences": len(recurrent),
        "recurrence_rate": len(recurrent) / len(eligible) if eligible else None,
        "public_regression_coverage": len(covered) / len(eligible) if eligible else None,
        "wording_patch_debt": len(wording_debt),
        "versions": dict(sorted(Counter(str(item.get("observed_version")) for item in active).items())),
        "root_causes": dict(sorted(Counter(str(item.get("root_cause")) for item in active).items())),
    }


def load_runtime(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("context_guard_benchmark_runtime", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load runtime: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def benchmark_fixture(runtime: Any, fixture: dict[str, Any]) -> dict[str, Any]:
    event = fixture["minimal_event"]
    reply = str(event.get("assistant_reply", ""))
    diagnostic = "gate_completion_claim" if runtime.claims_whole_completion(reply) else "allow_neutral"
    fixture_kind = fixture.get("fixture_kind", "protocol_policy")
    if fixture_kind == "privacy_metadata":
        classification, _ = runtime.classify_private_metadata(reply)
        outcome = (
            "allow_neutral"
            if classification == "explanatory_reference"
            else "fail_closed_integrity"
        )
        policy = "privacy_metadata"
    elif fixture_kind == "invalid_control":
        try:
            runtime.validate_staged_control(event.get("staged_control"))
        except (TypeError, ValueError):
            outcome = "fail_closed_integrity"
        else:
            outcome = "allow_neutral"
        policy = "invalid_control"
    else:
        outcome = ""
        policy = ""
    declared = event.get("declared_disposition")
    persistence = bool(event.get("explicit_user_persistence", False))
    deferred = bool(event.get("persistence_allows_deferred", False))
    if fixture_kind == "protocol_policy" and str(runtime.STOP_PROTOCOL_VERSION).startswith("1."):
        policy = runtime.terminal_stop_policy(
            whole_completion=diagnostic == "gate_completion_claim",
            explicit_persistence=persistence,
            persistence_allows_deferred=deferred,
            declared_disposition=declared,
        )
    elif fixture_kind == "protocol_policy":
        policy = runtime.terminal_stop_policy(
            explicit_persistence=persistence,
            persistence_allows_deferred=deferred,
            declared_disposition=declared,
        )
    if fixture_kind == "protocol_policy":
        outcome = {
            "gate_completion_claim": "gate_completion_claim",
            "gate_explicit_persistence": "gate_authorized_remaining_work",
            "yield_user_wait": "allow_user_handoff",
            "yield_external_wait": "allow_external_wait",
            "yield_deferred": "allow_out_of_scope_deferred",
            "yield_continue_advisory": "allow_neutral",
            "yield_default": "allow_neutral",
        }[policy]
    expected = fixture.get("expected_by_stop_protocol", {}).get(
        runtime.STOP_PROTOCOL_VERSION,
        fixture["expected_authoritative_outcome"],
    )
    return {
        "incident_id": fixture["incident_id"],
        "expected": expected,
        "target_expected": fixture["expected_authoritative_outcome"],
        "actual": outcome,
        "diagnostic": diagnostic,
        "pass": outcome == expected,
        "false_continuations": int(
            outcome == "gate_completion_claim"
            and fixture["expected_authoritative_outcome"] != "gate_completion_claim"
        ),
    }


def command_ingest(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    ensure_private_root(root, create=True)
    payload = read_json(Path(args.record))
    pending = payload if isinstance(payload, list) else [payload]
    if not pending:
        raise ValueError("ingest input must contain at least one record")
    supersede_start = getattr(args, "supersede_start", None)
    if supersede_start is not None:
        existing, existing_errors = load_records(root)
        if existing_errors:
            raise ValueError("; ".join(existing_errors))
        existing_ids = {str(item.get("incident_id")) for item in existing}
        revised: list[dict[str, Any]] = []
        for offset, source in enumerate(pending):
            if not isinstance(source, dict):
                raise ValueError("superseding ingest records must be objects")
            old_id = str(source.get("incident_id") or "")
            if old_id not in existing_ids:
                raise ValueError(f"cannot supersede unknown incident: {old_id}")
            year = old_id.split("-")[1]
            item = dict(source)
            item["incident_id"] = f"CGI-{year}-{supersede_start + offset:03d}"
            item["supersedes"] = old_id
            item.setdefault("public_fixture_id", old_id)
            revised.append(item)
        pending = revised
    identifiers: list[str] = []
    for record in pending:
        errors = validate_record(record)
        if errors:
            raise ValueError("; ".join(errors))
        incident_id = str(record["incident_id"])
        if incident_id in identifiers:
            raise ValueError(f"duplicate incident_id in ingest input: {incident_id}")
        target = records_dir(root) / f"{incident_id}.json"
        if target.exists():
            raise ValueError(f"append-only corpus already contains {incident_id}")
        identifiers.append(incident_id)
    digests: dict[str, str] = {}
    for record in pending:
        target = records_dir(root) / f"{record['incident_id']}.json"
        target.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        restrict_private_path(target, directory=False)
        digests[str(record["incident_id"])] = sha256_bytes(target.read_bytes())
    print(canonical_json({"ingested": identifiers, "sha256": digests}))
    return 0


def command_validate(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    ensure_private_root(root, create=False)
    records, errors = load_records(root)
    result = {"records": len(records), "valid": not errors, "errors": errors}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


def command_summarize(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    ensure_private_root(root, create=False)
    records, errors = load_records(root)
    if errors:
        raise ValueError("; ".join(errors))
    report = summarize(records)
    if args.format == "markdown":
        print("# Context Guard incident summary\n")
        for key, value in report.items():
            print(f"- {key}: `{json.dumps(value, ensure_ascii=False, sort_keys=True)}`")
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def command_benchmark(args: argparse.Namespace) -> int:
    runtime = load_runtime(Path(args.runtime).resolve())
    fixture_bytes = Path(args.fixtures).read_bytes()
    fixtures = json.loads(fixture_bytes)
    if not isinstance(fixtures, list):
        raise ValueError("fixtures must be a JSON list")
    errors = [
        f"fixture {index}: {item}"
        for index, fixture in enumerate(fixtures)
        for item in validate_record(fixture, public=True)
    ]
    if errors:
        raise ValueError("; ".join(errors))
    results = [benchmark_fixture(runtime, fixture) for fixture in fixtures]
    report = {
        "plugin_stop_protocol": runtime.STOP_PROTOCOL_VERSION,
        "fixture_manifest_sha256": sha256_bytes(fixture_bytes),
        "fixtures": len(results),
        "passed": sum(item["pass"] for item in results),
        "false_continuations": sum(item["false_continuations"] for item in results),
        "diagnostic_accuracy": sum(
            item["diagnostic"] == fixtures[index]["diagnostic_outcome"]
            for index, item in enumerate(results)
        ) / len(results) if results else None,
        "results": results,
    }
    if args.report_dir:
        report_dir = Path(args.report_dir).expanduser().resolve()
        report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        restrict_private_path(report_dir, directory=True)
        stem = "stop-" + str(runtime.STOP_PROTOCOL_VERSION).replace(".", "-")
        json_path = report_dir / f"{stem}.json"
        markdown_path = report_dir / f"{stem}.md"
        manifest_path = report_dir / f"{stem}.manifest.json"
        json_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        lines = [
            f"# Stop protocol {runtime.STOP_PROTOCOL_VERSION} incident benchmark",
            "",
            f"- Fixture manifest: `{report['fixture_manifest_sha256']}`",
            f"- Fixtures passed: `{report['passed']}/{report['fixtures']}`",
            f"- Target false continuations: `{report['false_continuations']}`",
            f"- Diagnostic accuracy: `{report['diagnostic_accuracy']}`",
            "",
            "| Incident | Target | Actual | Diagnostic | Pass |",
            "| --- | --- | --- | --- | --- |",
        ]
        lines.extend(
            "| {incident_id} | {target_expected} | {actual} | {diagnostic} | {passed} |".format(
                passed="yes" if item["pass"] else "no", **item
            )
            for item in results
        )
        markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        manifest = {
            "stop_protocol": runtime.STOP_PROTOCOL_VERSION,
            "fixture_manifest_sha256": report["fixture_manifest_sha256"],
            "files": {
                json_path.name: sha256_bytes(json_path.read_bytes()),
                markdown_path.name: sha256_bytes(markdown_path.read_bytes()),
            },
        }
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        for path in (json_path, markdown_path, manifest_path):
            restrict_private_path(path, directory=False)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if all(item["pass"] for item in results) else 1


def command_export_public(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    ensure_private_root(root, create=False)
    records, errors = load_records(root)
    if errors:
        raise ValueError("; ".join(errors))
    exported: list[dict[str, Any]] = []
    for record in active_records(records):
        if record.get("public_reviewed") is not True:
            continue
        public = {key: record[key] for key in PUBLIC_FIELDS if key in record}
        public_errors = validate_record(public, public=True)
        if public_errors:
            raise ValueError(f"{record['incident_id']}: " + "; ".join(public_errors))
        exported.append(public)
    output = Path(args.output).resolve()
    output.write_text(json.dumps(exported, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    restrict_private_path(output, directory=False)
    print(canonical_json({"exported": len(exported), "sha256": sha256_bytes(output.read_bytes())}))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser("ingest")
    ingest.add_argument("--root", required=True)
    ingest.add_argument("--record", required=True)
    ingest.add_argument("--supersede-start", type=int)
    ingest.set_defaults(handler=command_ingest)
    validate = commands.add_parser("validate")
    validate.add_argument("--root", required=True)
    validate.set_defaults(handler=command_validate)
    summary = commands.add_parser("summarize")
    summary.add_argument("--root", required=True)
    summary.add_argument("--format", choices=("json", "markdown"), default="json")
    summary.set_defaults(handler=command_summarize)
    benchmark = commands.add_parser("benchmark")
    benchmark.add_argument("--fixtures", required=True)
    benchmark.add_argument("--runtime", required=True)
    benchmark.add_argument("--report-dir")
    benchmark.set_defaults(handler=command_benchmark)
    export = commands.add_parser("export-public")
    export.add_argument("--root", required=True)
    export.add_argument("--output", required=True)
    export.set_defaults(handler=command_export_public)
    return result


def main() -> int:
    try:
        args = parser().parse_args()
        return int(args.handler(args))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"incident corpus error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
