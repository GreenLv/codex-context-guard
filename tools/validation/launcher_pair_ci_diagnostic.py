"""One original-input Hook observation per fresh runner; never acceptance."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time

SUBJECT = "1178b1426254654cff4ab84d1dd2dff33c6de3d6"
RUNTIME = "7b288ef2d82fb99da6a64ac8ca0a03647116d251665180d162cc409e9a9123c2"
LAUNCHER = "scripts/run-context-guard.ps1"
ORIGINAL_SHA256 = "420fbc7706a0cdb2b6f152af0beba146f700b51f4bab6b3eabf885817c46f60b"
CANDIDATE_SHA256 = "d514e162f8b7e0deda5b56b6413f01b691e98fa171a4af48d5842e9f37225b55"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def kind(error):
    name = type(error).__name__
    return name if name in {"OSError", "PermissionError", "FileNotFoundError",
        "ValueError", "RuntimeError", "TimeoutExpired"} else "other"


def candidate_bytes(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > 262144):
        raise ValueError("candidate_not_regular")
    raw = path.read_bytes()
    if sha(raw) != CANDIDATE_SHA256 or CANDIDATE_SHA256 == ORIGINAL_SHA256:
        raise ValueError("candidate_digest_differs")
    return raw


def environment_for(outer, interpreter):
    environment = {"PATH": str(Path(interpreter).parent) + os.pathsep + os.defpath,
        "HOME": str(outer / "os-home"), "USERPROFILE": str(outer / "os-home"),
        "CODEX_HOME": str(outer / "home"), "PLUGIN_DATA": str(outer / "data"),
        "TMPDIR": str(outer)}
    environment.update({key: os.environ[key] for key in
        ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT") if key in os.environ})
    return environment


def verify_variant(installed, expected):
    actual = {}
    for path in installed.rglob("*"):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("unexpected_link")
        if stat.S_ISREG(info.st_mode):
            actual[path.relative_to(installed).as_posix()] = sha(path.read_bytes())
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError("unexpected_object")
    if actual != expected:
        raise ValueError("controlled_variant_differs")


def wire_object(output):
    try:
        return isinstance(json.loads(output), dict)
    except (ValueError, TypeError):
        return False


def tree_observation(owner):
    result = {"leader_returncode": owner.process.poll()}
    try:
        accounting = owner.accounting_type()
        valid = owner.api.QueryInformationJobObject(owner.job, 1,
            ctypes.byref(accounting), ctypes.sizeof(accounting), None)
        result["active_processes"] = int(accounting.ActiveProcesses) if valid else None
    except (OSError, AttributeError, TypeError):
        result["active_processes"] = None
    return result


def run_case(subject, outer, variant, shell, identity, owned_process, candidate):
    row = {"variant": variant, "event": "UserPromptSubmit", "configured": False,
        "trace_enabled": False, "timeout_seconds": 30, "result": "driver_error"}
    owner = None
    cleanup = {}
    stdout = stderr = b""
    expected = None
    installed = outer / "installed"
    try:
        expected = identity.distribution_manifest(subject)
        if expected.get(LAUNCHER) != ORIGINAL_SHA256 or sha(candidate) != CANDIDATE_SHA256:
            raise ValueError("input_digest_differs")
        installed.mkdir()
        for relative in expected:
            target = installed / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((subject / relative).read_bytes())
        identity.compare_artifact(subject, installed)
        expected = dict(expected)
        if variant == "candidate":
            (installed / LAUNCHER).write_bytes(candidate)
            expected[LAUNCHER] = CANDIDATE_SHA256
        elif variant != "original":
            raise ValueError("unknown_variant")
        verify_variant(installed, expected)
        row["launcher_sha256"] = expected[LAUNCHER]
        # Preserve the original no-config fixture, including absent os-home.
        for leaf in ("home", "project"):
            (outer / leaf).mkdir()
        environment = environment_for(outer, sys.executable)
        row["path_has_exact_dot"] = "." in environment["PATH"].split(os.pathsep)
        if not row["path_has_exact_dot"]:
            raise ValueError("original_dot_path_unavailable")
        command = [shell, "-NoProfile", "-NonInteractive", "-File",
            str(installed / LAUNCHER), "hook"]
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
        stdout_json_object=wire_object(stdout))
    row["hook_returned_zero_json_object"] = (row["result"] == "returned"
        and row.get("returncode") == 0 and row["stdout_json_object"])
    try:
        row["state_present"] = (outer / "data/sessions-v2/synthetic-bytecode/state.json").is_file()
    except OSError:
        row["state_present"] = None
    try:
        if expected is None:
            raise ValueError("variant_not_prepared")
        verify_variant(installed, expected)
        row["controlled_variant_bytes_unchanged"] = True
        row["other_distribution_bytes_match_subject"] = True
    except (OSError, ValueError):
        row["controlled_variant_bytes_unchanged"] = False
        row["other_distribution_bytes_match_subject"] = False
    row["no_bytecode"] = not list(installed.rglob("*.pyc"))
    safe = (all(row["cleanup"].values()) and row.get("pipes_drained") is True)
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
    report = {"schema": "launcher-pair-diagnostic/v1", "native_acceptance": False,
        "release_gate": False, "subject_commit": SUBJECT, "base_runtime_sha256": RUNTIME,
        "original_launcher_sha256": ORIGINAL_SHA256, "candidate_launcher_sha256": CANDIDATE_SHA256,
        "candidate_is_full_release_artifact": False,
        "diagnostic_source_sha256": sha(Path(__file__).read_bytes()),
        "status": "diagnostic_error"}
    output = None
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--subject-root", type=Path, required=True)
        parser.add_argument("--variant", choices=("original", "candidate"), required=True)
        parser.add_argument("--output", type=Path, required=True)
        args = parser.parse_args()
        output = args.output
        if (sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true"
                or os.environ.get("RUNNER_OS") != "Windows"):
            raise ValueError("unsupported_environment")
        temp_root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        resolved_output = output.resolve()
        subject = args.subject_root.resolve(strict=True)
        if (output.exists() or output.is_symlink() or temp_root not in resolved_output.parents
                or subject == resolved_output or subject in resolved_output.parents):
            raise ValueError("unsupported_output")
        candidate = candidate_bytes(Path(__file__).with_name("candidate-launcher.ps1"))
        head = subprocess.run(["git", "-C", str(subject), "rev-parse", "HEAD"],
            capture_output=True, encoding="utf-8", check=True, timeout=10).stdout.strip()
        if head != SUBJECT:
            raise ValueError("subject_commit_differs")
        sys.path.insert(0, str(subject))
        from scripts import artifact_identity as identity
        from scripts.cg_process_tree import OwnedProcess
        runtime = sha(json.dumps(identity.tree_manifest(subject), ensure_ascii=True,
            sort_keys=True, separators=(",", ":")).encode())
        if runtime != RUNTIME:
            raise ValueError("subject_runtime_differs")
        shell = shutil.which("powershell") or shutil.which("pwsh")
        if shell is None:
            raise ValueError("shell_unavailable")
        report.update(python=list(sys.version_info[:3]), variant=args.variant,
            shell="powershell" if Path(shell).stem.lower() == "powershell" else "pwsh")
        outer = Path(tempfile.mkdtemp(prefix="cg-launcher-pair-", dir=temp_root))
        row = run_case(subject, outer, args.variant, shell, identity, OwnedProcess, candidate)
        report["observation"] = row
        if (row["fixture_cleanup"] == "removed" and row["result"] != "driver_error"
                and row["controlled_variant_bytes_unchanged"] and row["no_bytecode"]):
            report["status"] = "observation_recorded_not_acceptance"
    except Exception as error:
        report["exception_kind"] = kind(error)
    print(json.dumps(report, sort_keys=True))
    if output is not None:
        try:
            with output.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, sort_keys=True)
        except Exception:
            return 2
    return 0 if report["status"] == "observation_recorded_not_acceptance" else 2


if __name__ == "__main__":
    raise SystemExit(main())
