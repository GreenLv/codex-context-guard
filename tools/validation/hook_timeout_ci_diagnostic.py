"""Fixed-candidate hosted Windows observations; never release acceptance."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SUBJECT = "1178b1426254654cff4ab84d1dd2dff33c6de3d6"
RUNTIME = "7b288ef2d82fb99da6a64ac8ca0a03647116d251665180d162cc409e9a9123c2"
CASES = ("original", "trace_only", "configured_trace", "path_without_dot_trace")


def kind(error):
    name = type(error).__name__
    return name if name in {"OSError", "PermissionError", "FileNotFoundError",
                           "ValueError", "TimeoutExpired", "RuntimeError"} else "other"


def wire_shape(output):
    try:
        return isinstance(json.loads(output), dict)
    except (ValueError, TypeError):
        return False


def environment_for(outer, case, interpreter):
    """Original test inputs; each comparison changes only its named input."""
    home = outer / "home"
    environment = {"PATH": str(Path(interpreter).parent) + os.pathsep + os.defpath,
        "HOME": str(outer / "os-home"), "USERPROFILE": str(outer / "os-home"),
        "CODEX_HOME": str(home), "PLUGIN_DATA": str(outer / "data"),
        "TMPDIR": str(outer)}
    environment.update({key: os.environ[key] for key in
                       ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT") if key in os.environ})
    if case != "original":
        environment["CONTEXT_GUARD_HOOK_TRACE_DIR"] = str(outer / "trace")
    if case == "path_without_dot_trace":
        environment["PATH"] = os.pathsep.join(
            entry for entry in environment["PATH"].split(os.pathsep) if entry != ".")
    return environment


def trace_shape(directory):
    """Never emit filenames, arbitrary fields or raw records."""
    records = []
    try:
        files = list(directory.glob("*.jsonl"))
        if len(files) > 1:
            return {"state": "unexpected_count"}
        for file in files:
            if file.is_symlink() or file.stat().st_size > 4096:
                return {"state": "unavailable"}
            for line in file.read_text(encoding="utf-8").splitlines():
                value = json.loads(line)
                if (not isinstance(value, dict) or value.get("phase") not in {"start", "end"}
                        or type(value.get("elapsed_ms")) is not int
                        or not 0 <= value["elapsed_ms"] <= 3600000
                        or set(value) != ({"phase", "elapsed_ms", "exit_code"}
                                          if value["phase"] == "end" else {"phase", "elapsed_ms"})
                        or (value["phase"] == "end" and type(value["exit_code"]) is not int)):
                    return {"state": "unavailable"}
                records.append(value)
        return {"state": "observed", "records": records}
    except (OSError, ValueError):
        return {"state": "unavailable"}


def tree_observation(owner):
    """Observe before cleanup; termination is never evidence of natural exit."""
    observation = {"leader_returncode": owner.process.poll()}
    try:
        accounting = owner.accounting_type()
        valid = owner.api.QueryInformationJobObject(owner.job, 1,
            ctypes.byref(accounting), ctypes.sizeof(accounting), None)
        observation["active_processes"] = int(accounting.ActiveProcesses) if valid else None
    except (OSError, AttributeError, TypeError):
        observation["active_processes"] = None
    return observation


def run_case(subject, outer, case, shell, identity, owned_process):
    row = {"case": case, "timeout_seconds": 30, "event": "UserPromptSubmit",
           "configured": case == "configured_trace", "result": "driver_error"}
    owner = None
    stdout = stderr = b""
    cleanup = {}
    try:
        installed = outer / "installed"
        installed.mkdir()
        for relative in identity.distribution_manifest(subject):
            target = installed / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((subject / relative).read_bytes())
        identity.compare_artifact(subject, installed)
        for name in ("home", "project", "trace"):
            (outer / name).mkdir()
        if row["configured"]:
            config = outer / "home/context-guard"
            config.mkdir()
            (config / "interpreter.conf").write_text(str(Path(sys.executable).resolve()) + "\n")
        environment = environment_for(outer, case, sys.executable)
        command = [shell, "-NoProfile", "-NonInteractive", "-File",
                   str(installed / "scripts/run-context-guard.ps1"), "hook"]
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
        row["before_cleanup"] = tree_observation(owner)
    except Exception as error:
        row["exception_kind"] = kind(error)
        cleanup = getattr(error, "cleanup", None) or {}
    finally:
        if owner is not None:
            try:
                cleanup = owner.close(timeout=5)
            except Exception as error:
                cleanup = getattr(error, "cleanup", None) or {}
                row["cleanup_exception_kind"] = kind(error)
            try:
                owner.process.communicate(timeout=2)
                row["pipes_drained"] = True
            except Exception:
                row["pipes_drained"] = False
        row["cleanup"] = {key: cleanup.get(key) is True for key in
            ("cleanup_complete", "owned_process_exited", "owned_tree_no_running_members")}
    row.update(stdout_length=len(stdout), stderr_length=len(stderr),
               stdout_json_object=wire_shape(stdout), trace=trace_shape(outer / "trace"))
    try:
        row["state_present"] = (outer / "data/sessions-v2/synthetic-bytecode/state.json").is_file()
    except OSError:
        row["state_present"] = None
    installed = outer / "installed"
    try:
        identity.compare_artifact(subject, installed)
        row["artifact_parity_unchanged"] = True
    except (OSError, ValueError, RuntimeError):
        row["artifact_parity_unchanged"] = False
    row["no_bytecode"] = not list(installed.rglob("*.pyc"))
    safe = (row["cleanup"]["cleanup_complete"]
            and row["cleanup"]["owned_tree_no_running_members"] and row.get("pipes_drained") is True)
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
    report = {"schema": "hook-timeout-ci-diagnostic/v1", "native_acceptance": False,
              "release_gate": False, "subject_commit": SUBJECT, "runtime_tree_sha256": RUNTIME,
              "diagnostic_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "observations": [], "status": "diagnostic_error"}
    output = None
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--subject-root", type=Path, required=True)
        parser.add_argument("--output", type=Path, required=True)
        args = parser.parse_args()
        output = args.output
        if output.exists() or output.is_symlink() or os.name != "nt":
            raise ValueError("unsupported_or_existing_output")
        subject = args.subject_root.resolve(strict=True)
        head = subprocess.run(["git", "-C", str(subject), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        if head != SUBJECT:
            raise ValueError("subject_commit_differs")
        sys.path.insert(0, str(subject))
        from scripts import artifact_identity as identity
        from scripts.cg_process_tree import OwnedProcess
        digest = hashlib.sha256(json.dumps(identity.tree_manifest(subject), ensure_ascii=True,
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if digest != RUNTIME:
            raise ValueError("subject_runtime_differs")
        shell = shutil.which("powershell") or shutil.which("pwsh")
        if shell is None:
            raise ValueError("shell_unavailable")
        report.update(python=list(sys.version_info[:3]), shell="powershell" if
                      Path(shell).stem.lower() == "powershell" else "pwsh")
        for case in CASES:
            outer = Path(tempfile.mkdtemp(prefix="cg-hook-timeout-diagnostic-"))
            row = run_case(subject, outer, case, shell, identity, OwnedProcess)
            report["observations"].append(row)
            if (row["fixture_cleanup"] != "removed" or row["result"] == "driver_error"
                    or not row["artifact_parity_unchanged"] or not row["no_bytecode"]):
                break
        if len(report["observations"]) == len(CASES) and all(
                row["fixture_cleanup"] == "removed" and row["artifact_parity_unchanged"]
                and row["no_bytecode"] and row["result"] != "driver_error"
                for row in report["observations"]):
            report["status"] = "observations_recorded_not_acceptance"
    except Exception as error:
        report["exception_kind"] = kind(error)
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
