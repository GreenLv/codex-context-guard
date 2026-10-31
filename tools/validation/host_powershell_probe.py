"""Three bounded host-only PS5.1 commands; no product Hook or acceptance."""
import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import launcher_pair_ci_diagnostic as common

SUBJECT = "1178b1426254654cff4ab84d1dd2dff33c6de3d6"
HELPER_SHA = "ef23ca2b815bac448b22434224dc2eb137d1e8df45d5896f3bd136b0c0d788ae"
CASES = ("bare_join", "qualified_join", "fixed_manifest_import_then_join")
PHASES = {"entry", "command_begin", "command_end", "import_begin", "import_end"}
PRELUDE = r'''$cgVersion = $PSVersionTable.PSVersion.ToString()
[IO.File]::AppendAllText($env:CG_HOST_STAGE, '{"phase":"entry","elapsed_ms":0,"version":"' + $cgVersion + '"}' + "`n")
$cgClock = [Diagnostics.Stopwatch]::StartNew()
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { exit 91 }
function Write-CgHostStage([string]$phase) {
    [IO.File]::AppendAllText($env:CG_HOST_STAGE, '{"phase":"' + $phase + '","elapsed_ms":' + [int][Math]::Round($cgClock.Elapsed.TotalMilliseconds) + ',"version":"' + $cgVersion + '"}' + "`n")
}
'''


def script_for(case):
    if case not in CASES:
        raise ValueError("unknown_probe")
    source = PRELUDE
    if case == CASES[2]:
        source += r'''$cgManifest = [IO.Path]::Combine($PSHOME, 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1')
Write-CgHostStage 'import_begin'
Microsoft.PowerShell.Core\Import-Module -Name $cgManifest -ErrorAction Stop
Write-CgHostStage 'import_end'
'''
    command = "Microsoft.PowerShell.Management\\Join-Path" if case == CASES[1] else "Join-Path"
    source += "Write-CgHostStage 'command_begin'\n$cgResult = " + command + " $PSScriptRoot 'probe-child'\n"
    source += r'''Write-CgHostStage 'command_end'
if ($cgResult -cne [IO.Path]::Combine($PSScriptRoot, 'probe-child')) { exit 92 }
[Console]::Out.Write('{"host_probe_completed":true}')
'''
    return source.encode("ascii")


def phases(path):
    if not path.exists():
        return {"state": "absent", "records": []}
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > 4096:
        raise ValueError("stage_file_unavailable")
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if (not isinstance(value, dict) or set(value) != {"phase", "elapsed_ms", "version"}
                or value["phase"] not in PHASES or type(value["elapsed_ms"]) is not int
                or not 0 <= value["elapsed_ms"] <= 3600000
                or not isinstance(value["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", value["version"])
                or len(records) >= 8):
            raise ValueError("stage_record_unavailable")
        records.append(value)
    return {"state": "observed", "records": records}


def cwd_candidate_count(root, pathext):
    extensions = {"", ".ps1"}
    for extension in pathext.split(";"):
        if not re.fullmatch(r"\.[A-Za-z0-9]+", extension):
            raise ValueError("unsupported_pathext")
        extensions.add(extension.lower())
    count = 0
    for extension in extensions:
        path = root / ("Join-Path" + extension)
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            count += 1
    return count


def run_probe(subject, outer, case, shell, owned_process, payload):
    row = {"case": case, "timeout_seconds": 30, "result": "driver_error",
           "stdin_length": len(payload), "stdin_matches_original_fixture": True}
    owner = None
    cleanup = {}
    stdout = stderr = b""
    try:
        for name in ("home", "project"):
            (outer / name).mkdir()
        script = outer / "probe.ps1"
        script.write_bytes(script_for(case))
        row["script_sha256"] = common.sha(script.read_bytes())
        environment = common.environment_for(outer, sys.executable)
        environment["CG_HOST_STAGE"] = str(outer / "stages.jsonl")
        started = time.monotonic()
        owner = owned_process.spawn([shell, "-NoProfile", "-NonInteractive", "-File", str(script)],
            env=environment, cwd=subject, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        row["spawn_elapsed_ms"] = round((time.monotonic() - started) * 1000)
        started = time.monotonic()
        try:
            stdout, stderr = owner.process.communicate(payload, timeout=30)
            row.update(result="returned", returncode=owner.process.returncode)
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.output or b"", error.stderr or b""
            row["result"] = "timeout"
        row["communicate_elapsed_ms"] = round((time.monotonic() - started) * 1000)
        row["before_cleanup"] = common.tree_observation(owner)
    except Exception as error:
        row["exception_kind"] = common.kind(error)
        cleanup = getattr(error, "cleanup", None) or {}
    finally:
        if owner is not None:
            try:
                cleanup = owner.close(timeout=5)
            except Exception as error:
                cleanup = getattr(error, "cleanup", None) or {}
                row["cleanup_exception_kind"] = common.kind(error)
            try:
                owner.process.communicate(timeout=2)
                row["pipes_drained"] = True
            except Exception:
                row["pipes_drained"] = False
        row["cleanup"] = {key: cleanup.get(key) is True for key in
            ("cleanup_complete", "owned_process_exited", "owned_tree_no_running_members")}
    row.update(stdout_length=len(stdout), stderr_length=len(stderr))
    try:
        row["fixed_completion_json"] = json.loads(stdout) == {"host_probe_completed": True}
    except (ValueError, TypeError):
        row["fixed_completion_json"] = False
    try:
        row["stages"] = phases(outer / "stages.jsonl")
    except (OSError, ValueError, UnicodeError) as error:
        row["stages"] = {"state": "unavailable"}
        row["stage_error_kind"] = common.kind(error)
    row["fixture_cleanup"] = "retained"
    if (all(row["cleanup"].values()) and row.get("pipes_drained") is True
            and row["stages"]["state"] != "unavailable"):
        shutil.rmtree(outer)
        row["fixture_cleanup"] = "removed"
    return row


def main():
    report = {"schema": "host-powershell-probe/v1", "product_executed": False,
        "native_acceptance": False, "release_gate": False, "subject_for_helper_and_cwd": SUBJECT,
        "order": list(CASES), "cold_state_comparison": False, "observations": [],
        "driver_sha256": common.sha(Path(__file__).read_bytes()), "owned_helper_sha256": HELPER_SHA,
        "same_stdin_across_probes": True, "status": "diagnostic_error"}
    output = None
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--subject-root", type=Path, required=True)
        parser.add_argument("--output", type=Path, required=True)
        args = parser.parse_args()
        output = args.output
        if sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Windows":
            raise ValueError("unsupported_environment")
        temp_root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        subject = args.subject_root.resolve(strict=True)
        if output.exists() or output.is_symlink() or temp_root not in output.resolve().parents or subject in output.resolve().parents:
            raise ValueError("unsupported_output")
        head = subprocess.run(["git", "-C", str(subject), "rev-parse", "HEAD"], capture_output=True,
                              encoding="utf-8", check=True, timeout=10).stdout.strip()
        if head != SUBJECT or common.sha((subject / "scripts/cg_process_tree.py").read_bytes()) != HELPER_SHA:
            raise ValueError("helper_identity_differs")
        report["cwd_candidate_count"] = cwd_candidate_count(subject, os.environ.get("PATHEXT", ""))
        report["cwd_candidates_absent"] = report["cwd_candidate_count"] == 0
        if not report["cwd_candidates_absent"]:
            raise ValueError("cwd_command_candidate_present")
        sys.path.insert(0, str(subject))
        from scripts.cg_process_tree import OwnedProcess
        shell = shutil.which("powershell.exe")
        if shell is None:
            raise ValueError("powershell_unavailable")
        outer = Path(tempfile.mkdtemp(prefix="cg-host-command-probe-", dir=temp_root))
        payload = json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "synthetic-bytecode",
            "cwd": str(outer / "project"), "prompt": "hello", "trigger": "manual",
            "last_assistant_message": "waiting"}).encode()
        for index, case in enumerate(CASES):
            row = run_probe(subject, outer, case, shell, OwnedProcess, payload)
            report["observations"].append(row)
            if (row["fixture_cleanup"] != "removed" or row["result"] == "driver_error"
                    or row.get("before_cleanup", {}).get("active_processes") is None):
                break
            if index < len(CASES) - 1:
                outer.mkdir()
        if len(report["observations"]) == 3 and all(
                row["fixture_cleanup"] == "removed" and row["result"] != "driver_error"
                and row.get("before_cleanup", {}).get("active_processes") is not None
                for row in report["observations"]):
            report["status"] = "observations_recorded_not_acceptance"
    except Exception as error:
        report["exception_kind"] = common.kind(error)
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
