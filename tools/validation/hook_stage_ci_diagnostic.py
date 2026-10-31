"""Instrumented fixed-1178 launcher observations; never original-byte acceptance."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import hook_timeout_ci_diagnostic as base

LAUNCHER = "scripts/run-context-guard.ps1"
LAUNCHER_SHA = "420fbc7706a0cdb2b6f152af0beba146f700b51f4bab6b3eabf885817c46f60b"
PHASES = {"script_entry", "original_trace_complete", "config_start", "config_end",
          "resolver_setup_end", "resolve_start", "resolve_end", "probe_start", "probe_end",
          "runtime_start", "runtime_end"}
PRELUDE = r'''try {
    [System.IO.File]::AppendAllText($env:CG_DIAGNOSTIC_STAGE_FILE, '{"phase":"script_entry","candidate":-1,"elapsed_ms":0,"value":0}' + "`n")
} catch {}
$cgStageClock = [System.Diagnostics.Stopwatch]::StartNew()
$cgCandidateIndex = -1
function Write-CgDiagnosticStage([string]$phase, [int]$candidate = -1, [int]$value = 0) {
    try {
        $record = '{"phase":"' + $phase + '","candidate":' + $candidate + ',"elapsed_ms":' + [int][Math]::Round($cgStageClock.Elapsed.TotalMilliseconds) + ',"value":' + $value + '}' + "`n"
        [System.IO.File]::AppendAllText($env:CG_DIAGNOSTIC_STAGE_FILE, $record)
    } catch {}
}
'''


def instrument(original):
    """Insert only fixed observations; retain every original line in order."""
    if hashlib.sha256(original).hexdigest() != LAUNCHER_SHA:
        raise ValueError("launcher_identity_differs")
    text = original.decode("utf-8")
    insertions = [
        ("function Write-HookTraceEnd([int]$code) {", "Write-CgDiagnosticStage 'original_trace_complete'\n", False),
        ("$configuredInterpreter = $null\n$configRoot", "Write-CgDiagnosticStage 'config_start'\n", False),
        ("# Avoid PowerShell's general command discovery for ordinary local PATHs.",
         "Write-CgDiagnosticStage 'config_end'\n", False),
        ("$candidates = @(", "Write-CgDiagnosticStage 'resolver_setup_end'\n", False),
        ("foreach ($candidate in $candidates) {",
         "\n    $cgCandidateIndex++\n    Write-CgDiagnosticStage 'resolve_start' $cgCandidateIndex", True),
        ("    $resolved = Resolve-ContextGuardPythonCommand $candidate.Command",
         "\n    Write-CgDiagnosticStage 'resolve_end' $cgCandidateIndex ([int]($null -ne $resolved))", True),
        ("    if ($candidate.Probe) {", "\n        Write-CgDiagnosticStage 'probe_start' $cgCandidateIndex", True),
        ("        if ($probeExitCode -ne 0) {",
         "        Write-CgDiagnosticStage 'probe_end' $cgCandidateIndex $probeExitCode\n", False),
        ("    if ($isHook -and -not $isSessionEnd) {",
         "    Write-CgDiagnosticStage 'runtime_start' $cgCandidateIndex\n", False),
        ("    $hookExitCode = $global:LASTEXITCODE\n    Write-HookTraceEnd $hookExitCode\n    exit $hookExitCode\n}\n\n[Console]",
         "    Write-CgDiagnosticStage 'runtime_end' $cgCandidateIndex $hookExitCode\n", False),
    ]
    # The last insertion belongs after the assignment, before the original trace.
    for anchor, addition, after in insertions[:-1]:
        if text.count(anchor) != 1:
            raise ValueError("instrumentation_anchor_differs")
        text = text.replace(anchor, anchor + addition if after else addition + anchor)
    anchor = insertions[-1][0]
    if text.count(anchor) != 1:
        raise ValueError("instrumentation_anchor_differs")
    assignment = "    $hookExitCode = $global:LASTEXITCODE\n"
    text = text.replace(anchor, assignment + insertions[-1][1] + anchor[len(assignment):])
    return (PRELUDE + text).encode("utf-8")


def stages(path):
    """All-or-unavailable: never echo malformed, extra, or unbounded content."""
    try:
        if not path.exists():
            return {"state": "absent", "records": []}
        if path.is_symlink() or path.stat().st_size > 16384:
            return {"state": "unavailable"}
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            v = json.loads(line)
            if (not isinstance(v, dict) or set(v) != {"phase", "candidate", "elapsed_ms", "value"}
                    or v["phase"] not in PHASES
                    or any(type(v[k]) is not int for k in ("candidate", "elapsed_ms", "value"))
                    or not -1 <= v["candidate"] <= 11 or not 0 <= v["elapsed_ms"] <= 3600000
                    or not -2147483648 <= v["value"] <= 2147483647 or len(records) >= 100):
                return {"state": "unavailable"}
            records.append(v)
        return {"state": "observed", "records": records}
    except (OSError, ValueError, UnicodeError):
        return {"state": "unavailable"}


def expected_artifact(subject, installed, identity, patched):
    expected = identity.distribution_manifest(subject)
    for relative in expected:
        file = installed / relative
        if file.is_symlink() or file.read_bytes() != (patched if relative == LAUNCHER else
                                                     (subject / relative).read_bytes()):
            return False
    actual = {p.relative_to(installed).as_posix() for p in installed.rglob("*") if p.is_file()}
    return actual == set(expected)


def observe(subject, outer, trace_enabled, shell, identity, owned_process):
    row = {"instrumented_launcher": True, "original_trace_enabled": trace_enabled,
           "timeout_seconds": 30, "configured": False, "event": "UserPromptSubmit",
           "result": "driver_error"}
    owner = None
    cleanup = {}
    stdout = stderr = b""
    installed = outer / "installed"
    stage_file = outer / "stages.jsonl"
    patched = b""
    try:
        installed.mkdir()
        for relative in identity.distribution_manifest(subject):
            target = installed / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((subject / relative).read_bytes())
        identity.compare_artifact(subject, installed)
        row["original_artifact_verified"] = True
        patched = instrument((installed / LAUNCHER).read_bytes())
        (installed / LAUNCHER).write_bytes(patched)
        row["instrumented_launcher_sha256"] = hashlib.sha256(patched).hexdigest()
        for name in ("home", "project", "trace"):
            (outer / name).mkdir()
        environment = base.environment_for(outer, "trace_only", sys.executable)
        if not trace_enabled:
            environment.pop("CONTEXT_GUARD_HOOK_TRACE_DIR")
        environment["CG_DIAGNOSTIC_STAGE_FILE"] = str(stage_file)
        row["path_has_exact_dot"] = "." in environment["PATH"].split(os.pathsep)
        command = [shell, "-NoProfile", "-NonInteractive", "-File", str(installed / LAUNCHER), "hook"]
        payload = {"hook_event_name": "UserPromptSubmit", "session_id": "synthetic-bytecode",
            "cwd": str(outer / "project"), "prompt": "hello", "trigger": "manual",
            "last_assistant_message": "waiting"}
        started = time.monotonic()
        owner = owned_process.spawn(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=environment, cwd=subject)
        row["spawn_elapsed_ms"] = round((time.monotonic() - started) * 1000)
        started = time.monotonic()
        try:
            stdout, stderr = owner.process.communicate(json.dumps(payload).encode(), timeout=30)
            row.update(result="returned", returncode=owner.process.returncode)
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.output or b"", error.stderr or b""
            row["result"] = "timeout"
        row["communicate_elapsed_ms"] = round((time.monotonic() - started) * 1000)
        row["before_cleanup"] = base.tree_observation(owner)
    except Exception as error:
        row["exception_kind"] = base.kind(error)
        cleanup = getattr(error, "cleanup", None) or {}
    finally:
        if owner is not None:
            try:
                cleanup = owner.close(timeout=5)
            except Exception as error:
                cleanup = getattr(error, "cleanup", None) or {}
                row["cleanup_exception_kind"] = base.kind(error)
            try:
                owner.process.communicate(timeout=2)
                row["pipes_drained"] = True
            except Exception:
                row["pipes_drained"] = False
        row["cleanup"] = {k: cleanup.get(k) is True for k in
            ("cleanup_complete", "owned_process_exited", "owned_tree_no_running_members")}
    row.update(stdout_length=len(stdout), stderr_length=len(stderr),
               stdout_json_object=base.wire_shape(stdout), stages=stages(stage_file),
               original_trace=base.trace_shape(outer / "trace"))
    try:
        row["state_present"] = (outer / "data/sessions-v2/synthetic-bytecode/state.json").is_file()
        row["instrumented_artifact_matches_expected"] = expected_artifact(subject, installed, identity, patched)
        row["no_bytecode"] = not list(installed.rglob("*.pyc"))
    except (OSError, ValueError, RuntimeError):
        row["instrumented_artifact_matches_expected"] = False
    safe = (row["cleanup"]["cleanup_complete"] and row["cleanup"]["owned_tree_no_running_members"]
            and row.get("pipes_drained") is True)
    if owner is None:
        safe = cleanup.get("cleanup_complete") is True
    row["fixture_cleanup"] = "retained"
    if safe:
        try:
            shutil.rmtree(outer)
            row["fixture_cleanup"] = "removed"
        except OSError:
            row["fixture_cleanup"] = "failed"
    return row


def main():
    report = {"schema": "hook-stage-ci-diagnostic/v1", "native_acceptance": False,
              "release_gate": False, "instrumented_copy": True, "subject_commit": base.SUBJECT,
              "runtime_tree_sha256": base.RUNTIME, "original_launcher_sha256": LAUNCHER_SHA,
              "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "stage_semantics": "PowerShell boundaries; runtime_start does not prove Python entry",
              "status": "diagnostic_error"}
    output = None
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--subject-root", type=Path, required=True)
        parser.add_argument("--output", type=Path, required=True)
        parser.add_argument("--original-trace", choices=("on", "off"), required=True)
        args = parser.parse_args()
        output = args.output
        if os.name != "nt" or output.exists() or output.is_symlink():
            raise ValueError("unsupported_or_existing_output")
        subject = args.subject_root.resolve(strict=True)
        head = subprocess.run(["git", "-C", str(subject), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        if head != base.SUBJECT:
            raise ValueError("subject_commit_differs")
        sys.path.insert(0, str(subject))
        from scripts import artifact_identity as identity
        from scripts.cg_process_tree import OwnedProcess
        digest = hashlib.sha256(json.dumps(identity.tree_manifest(subject), ensure_ascii=True,
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if digest != base.RUNTIME:
            raise ValueError("subject_runtime_differs")
        shell = shutil.which("powershell.exe")
        if shell is None:
            raise ValueError("windows_powershell_unavailable")
        report.update(python=list(sys.version_info[:3]), shell="powershell")
        outer = Path(tempfile.mkdtemp(prefix="cg-hook-stage-diagnostic-"))
        row = observe(subject, outer, args.original_trace == "on", shell, identity, OwnedProcess)
        report["observation"] = row
        if (row["fixture_cleanup"] == "removed" and row["result"] != "driver_error"
                and row.get("instrumented_artifact_matches_expected") and row.get("no_bytecode")):
            report["status"] = "observations_recorded_not_acceptance"
    except Exception as error:
        report["exception_kind"] = base.kind(error)
    print(json.dumps(report, sort_keys=True))
    if output is not None:
        try:
            with output.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, sort_keys=True)
        except Exception:
            return 2
    return 0 if report["status"] == "observations_recorded_not_acceptance" else 2


if __name__ == "__main__":
    raise SystemExit(main())
