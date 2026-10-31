"""Utility-controlled CommandDiscovery observation; host-only, never acceptance."""
import argparse
import codecs
import json
import ntpath
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path

import host_powershell_probe as host

CASES = ("utility_control", "utility_trace")
PHASES = {"entry", "utility_import_begin", "utility_import_end", "invocation_begin",
          "invocation_end", "target_begin", "target_end"}
MODULE_IDS = {"microsoft.powershell.core": "core", "microsoft.powershell.utility": "utility",
              "microsoft.powershell.management": "management", "microsoft.powershell.security": "security",
              "microsoft.powershell.diagnostics": "diagnostics", "microsoft.wsman.management": "wsman"}
LIMIT = 65536


def script_for(case):
    if case not in CASES:
        raise ValueError("unknown_case")
    source = host.PRELUDE + r'''
$cgUtility = [IO.Path]::Combine($PSHOME, 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
Write-CgHostStage 'utility_import_begin'
Microsoft.PowerShell.Core\Import-Module -Name $cgUtility -ErrorAction Stop
Write-CgHostStage 'utility_import_end'
$cgExpression = {
    Write-CgHostStage 'target_begin'
    $cgResult = Join-Path $PSScriptRoot 'probe-child'
    if ($cgResult -cne [IO.Path]::Combine($PSScriptRoot, 'probe-child')) { exit 92 }
    Write-CgHostStage 'target_end'
}
Write-CgHostStage 'invocation_begin'
'''
    source += ("& $cgExpression\n" if case == CASES[0] else
        "Microsoft.PowerShell.Utility\\Trace-Command -Name CommandDiscovery -Option All "
        "-ListenerOption DateTime -FilePath $env:CG_HOST_RAW_TRACE -Expression $cgExpression\n")
    return (source + "Write-CgHostStage 'invocation_end'\n"
            "[Console]::Out.Write('{\"host_probe_completed\":true}')\n").encode("ascii")


def stage_records(path):
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
                or not 0 <= value["elapsed_ms"] <= 3600000 or len(records) >= 12
                or not isinstance(value["version"], str) or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value["version"])):
            raise ValueError("stage_record_unavailable")
        records.append(value)
    return {"state": "observed", "records": records}


def path_kind(value):
    value = value.strip('"')
    if value.startswith('\\\\'):
        return "unc"
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return "drive_absolute"
    if re.match(r"^[A-Za-z][A-Za-z0-9]*:", value):
        return "provider_or_drive_relative"
    return "relative_or_unknown"


def module_id(value, pshome):
    value = value.strip("'\"")
    if value.lower() in MODULE_IDS:
        return MODULE_IDS[value.lower()]
    root = ntpath.normcase(ntpath.join(str(pshome), "Modules")) + "\\"
    normalized = ntpath.normcase(ntpath.normpath(value))
    if normalized.startswith(root):
        component = normalized[len(root):].split("\\")[0]
        return MODULE_IDS.get(component)
    return None


def event(message, pshome):
    if message == "Looking up command: Join-Path":
        return {"type": "lookup_join", "command": "Join-Path"}
    if message.startswith("PATH: "):
        return {"type": "environment_path_suppressed"}
    match = re.fullmatch(r"Looking for Join-Path(?:\.[A-Za-z0-9*]+)? in (.+)", message)
    if match:
        return {"type": "path_scan", "command": "Join-Path", "path_kind": path_kind(match[1])}
    if message == "Executing non module-qualified search: Join-Path":
        return {"type": "nonqualified_search", "command": "Join-Path"}
    if message in {"Executing module-qualified search: Microsoft.PowerShell.Management\\Join-Path",
                   "Executing module-qualified search: Microsoft.PowerShell.Core\\Import-Module"}:
        return {"type": "qualified_search"}
    if message.startswith("Attempting to load module: "):
        identifier = module_id(message[len("Attempting to load module: "):], pshome)
        return {"type": "module_load_attempt", "module_id": identifier} if identifier else None
    if message.startswith("Encountered error importing module: "):
        return {"type": "module_import_error"}
    if re.fullmatch(r"Cmdlet found: Join-Path\s+Microsoft\.PowerShell\.Commands\.JoinPathCommand(?:,.*)?", message):
        return {"type": "cmdlet_join_found", "command": "Join-Path"}
    return None


def trace_summary(path, pshome):
    result = {"state": "unknown", "total_bytes": None, "window_bytes": 0,
        "window_complete": False, "discarded_first_fragment": False, "unknown_count": None,
        "unknown_count_scope": "parsed_window", "events": [], "counts": {}}
    try:
        try:
            info = path.lstat()
        except FileNotFoundError:
            result.update(state="absent", window_complete=True)
            return result
        result["total_bytes"] = info.st_size
        if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("trace_not_regular")
        if info.st_size == 0:
            result.update(state="empty", window_complete=True, unknown_count=0)
            return result
        with path.open("rb") as stream:
            head = stream.read(4)
            encoding = "utf-16-le" if head.startswith(codecs.BOM_UTF16_LE) else (
                "utf-16-be" if head.startswith(codecs.BOM_UTF16_BE) else "utf-8-sig")
            start = max(0, info.st_size - LIMIT)
            if encoding.startswith("utf-16") and start % 2:
                start += 1
            stream.seek(start)
            raw = stream.read(LIMIT)
            if os.fstat(stream.fileno()).st_size != info.st_size:
                raise ValueError("trace_changed_during_read")
        result.update(window_bytes=len(raw), window_complete=start == 0)
        truncated = start > 0
        if truncated:
            separator = b"\n\x00" if encoding == "utf-16-le" else (b"\x00\n" if encoding == "utf-16-be" else b"\n")
            first = (next((index for index in range(0, len(raw) - 1, 2)
                           if raw[index:index + 2] == separator), -1)
                     if encoding.startswith("utf-16") else raw.find(separator))
            raw = raw[first + len(separator):] if first >= 0 else b""
            result["discarded_first_fragment"] = True
        result["parsed_window_bytes"] = len(raw)
        text = raw.decode(encoding).lstrip("\ufeff")
        result["unknown_count"] = 0
        counts = Counter()
        retained = deque(maxlen=16)
        pending = None
        for line in text.splitlines():
            if not line.strip():
                continue
            timestamp = re.fullmatch(r"\s*DateTime=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z)\s*", line)
            if timestamp:
                try:
                    datetime.fromisoformat(timestamp[1].replace("Z", "+00:00"))
                except ValueError:
                    result["unknown_count"] += 1
                else:
                    if pending is not None and pending["timestamp_utc"] is None:
                        pending["timestamp_utc"] = timestamp[1]
                pending = None
                continue
            match = re.fullmatch(r"(?:DEBUG:\s*)?CommandDiscovery Information:\s*\d+\s*:\s*(.*)", line.strip())
            pending = event(match[1], pshome) if match else None
            if pending is None:
                result["unknown_count"] += 1
            else:
                counts[pending["type"]] += 1
                pending["timestamp_utc"] = None
                retained.append(pending)
        recognized = sum(counts.values()) > 0
        result.update(state="truncated" if truncated else ("recognized" if recognized else "unrecognized"),
                      format_state="recognized" if recognized else "unrecognized",
                      events=list(retained), counts=dict(counts))
    except UnicodeError:
        result.update(state="truncated" if result["total_bytes"] and result["total_bytes"] > LIMIT else "unrecognized",
                      format_state="unrecognized")
    except (OSError, ValueError) as error:
        result["read_error_kind"] = host.common.kind(error)
    return result


def run_case(subject, outer, case, shell, owned_process, payload):
    row = {"case": case, "result": "driver_error", "timeout_seconds": 30,
           "stdin_length": len(payload), "stdin_matches_original_fixture": True}
    owner = None
    cleanup = {}
    stdout = stderr = b""
    try:
        for name in ("home", "project"):
            (outer / name).mkdir()
        script = outer / "probe.ps1"
        script.write_bytes(script_for(case))
        row["script_sha256"] = host.common.sha(script.read_bytes())
        environment = host.common.environment_for(outer, sys.executable)
        environment.update(CG_HOST_STAGE=str(outer / "stages.jsonl"), CG_HOST_RAW_TRACE=str(outer / "raw-command-discovery.log"))
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
        row["before_cleanup"] = host.common.tree_observation(owner)
    except Exception as error:
        row["exception_kind"] = host.common.kind(error)
        cleanup = getattr(error, "cleanup", None) or {}
    finally:
        if owner is not None:
            try:
                cleanup = owner.close(timeout=5)
            except Exception as error:
                cleanup = getattr(error, "cleanup", None) or {}
                row["cleanup_exception_kind"] = host.common.kind(error)
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
        row["stages"] = stage_records(outer / "stages.jsonl")
    except (OSError, ValueError, UnicodeError) as error:
        row["stages"] = {"state": "unknown", "error_kind": host.common.kind(error)}
    row["trace"] = trace_summary(outer / "raw-command-discovery.log", Path(shell).parent) if case == CASES[1] else {"state": "not_requested"}
    row["fixture_cleanup"] = "retained"
    if (all(row["cleanup"].values()) and row.get("pipes_drained") is True and row["stages"]["state"] != "unknown"
            and row["trace"]["state"] != "unknown"):
        if case == CASES[0]:
            shutil.rmtree(outer)
            row["fixture_cleanup"] = "removed"
        else:
            row["fixture_cleanup"] = "retained_runner_local_raw_trace"
    return row


def collection_complete(observations):
    return len(observations) == 2 and all(
        row["fixture_cleanup"] != "retained" and row["result"] != "driver_error"
        and row.get("before_cleanup", {}).get("active_processes") is not None
        for row in observations)


def main():
    report = {"schema": "host-discovery-trace/v1", "product_executed": False,
        "native_acceptance": False, "release_gate": False, "subject_for_helper_and_cwd": host.SUBJECT,
        "driver_sha256": host.common.sha(Path(__file__).read_bytes()), "order": list(CASES),
        "utility_preloaded_in_both": True, "cold_state_comparison": False,
        "raw_trace_uploaded": False, "observations": [], "status": "diagnostic_error"}
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
        if head != host.SUBJECT or host.common.sha((subject / "scripts/cg_process_tree.py").read_bytes()) != host.HELPER_SHA:
            raise ValueError("helper_identity_differs")
        report["cwd_candidate_count"] = host.cwd_candidate_count(subject, os.environ.get("PATHEXT", ""))
        if report["cwd_candidate_count"]:
            raise ValueError("cwd_command_candidate_present")
        sys.path.insert(0, str(subject))
        from scripts.cg_process_tree import OwnedProcess
        shell = shutil.which("powershell.exe")
        if shell is None:
            raise ValueError("powershell_unavailable")
        outer = Path(tempfile.mkdtemp(prefix="cg-host-discovery-trace-", dir=temp_root))
        payload = json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "synthetic-bytecode",
            "cwd": str(outer / "project"), "prompt": "hello", "trigger": "manual",
            "last_assistant_message": "waiting"}).encode()
        for index, case in enumerate(CASES):
            row = run_case(subject, outer, case, shell, OwnedProcess, payload)
            report["observations"].append(row)
            if (row["result"] == "driver_error" or row["fixture_cleanup"] == "retained"
                    or row.get("before_cleanup", {}).get("active_processes") is None):
                break
            if index == 0:
                outer.mkdir()
        if collection_complete(report["observations"]):
            report["status"] = "observations_recorded_not_acceptance"
    except Exception as error:
        report["exception_kind"] = host.common.kind(error)
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
