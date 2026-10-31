"""One ordered public-v0.15.1/1178 Windows comparison; never acceptance."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import launcher_pair_ci_diagnostic as common

ORDER = ("published_v0151", "candidate_1178")
COMMITS = ("111fe03b98803c6b06e8a70c010d27ca04d81af3", "1178b1426254654cff4ab84d1dd2dff33c6de3d6")
MANIFEST_SHA = "eeaeddcb6be76da8d8508f7bd4f9e77365c2d756d9fd8a5a521576835b136c6b"
LAUNCHER = "scripts/run-context-guard.ps1"


def manifest_bytes(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("manifest_not_regular")
    raw = path.read_bytes()
    if common.sha(raw) != MANIFEST_SHA:
        raise ValueError("manifest_digest_differs")
    return json.loads(raw)


def git_blobs(root, descriptor):
    """Read pinned Git object bytes, independent of checkout newline settings."""
    head = subprocess.run(["git", "--no-replace-objects", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True, encoding="utf-8", check=True, timeout=10).stdout.strip()
    if head != descriptor["commit"]:
        raise ValueError("source_commit_differs")
    names = sorted(descriptor["files"])
    query = "".join(descriptor["commit"] + ":" + name + "\n" for name in names).encode()
    result = subprocess.run(["git", "--no-replace-objects", "-C", str(root), "cat-file", "--batch"],
        input=query, capture_output=True, check=True, timeout=30).stdout
    offset = 0
    files = {}
    for name in names:
        end = result.index(b"\n", offset)
        header = result[offset:end].split()
        if len(header) != 3 or header[1] != b"blob":
            raise ValueError("git_object_not_blob")
        size = int(header[2])
        raw = result[end + 1:end + 1 + size]
        offset = end + 2 + size
        if common.sha(raw) != descriptor["files"][name] or result[offset - 1:offset] != b"\n":
            raise ValueError("git_blob_digest_differs")
        files[name] = raw
    if offset != len(result):
        raise ValueError("git_batch_trailing_data")
    return files


def original_files_unchanged(installed, files):
    for name, raw in files.items():
        path = installed / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                or path.read_bytes() != raw):
            return False
    return True


def observe(outer, files, environment, payload, shell, owned_process, process_cwd):
    row = {"event": "UserPromptSubmit", "configured": False, "trace_enabled": False,
           "timeout_seconds": 30, "result": "driver_error"}
    owner = None
    cleanup = {}
    stdout = stderr = b""
    installed = outer / "installed"
    try:
        for name, raw in files.items():
            target = installed / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        if not original_files_unchanged(installed, files):
            raise ValueError("runtime_copy_differs")
        for name in ("home", "project"):
            (outer / name).mkdir()
        command = [shell, "-NoProfile", "-NonInteractive", "-File", str(installed / LAUNCHER), "hook"]
        started = time.monotonic()
        owner = owned_process.spawn(command, env=environment, cwd=process_cwd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        row["cleanup"] = {k: cleanup.get(k) is True for k in
            ("cleanup_complete", "owned_process_exited", "owned_tree_no_running_members")}
    row.update(stdout_length=len(stdout), stderr_length=len(stderr),
        stdout_sha256=common.sha(stdout), stderr_sha256=common.sha(stderr),
        stdout_json_object=common.wire_object(stdout))
    row["hook_returned_zero_json_object"] = (row["result"] == "returned"
        and row.get("returncode") == 0 and row["stdout_json_object"])
    try:
        row["state_present"] = (outer / "data/sessions-v2/synthetic-bytecode/state.json").is_file()
        row["original_runtime_files_unchanged"] = original_files_unchanged(installed, files)
        # Published 0.15.1 can legitimately create bytecode: observation only.
        row["bytecode_file_count"] = len(list(installed.rglob("*.pyc")))
    except (OSError, ValueError):
        row["original_runtime_files_unchanged"] = False
    return row


def safe_to_reset(row):
    return all(row["cleanup"].values()) and row.get("pipes_drained") is True


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)


def main():
    report = {"schema": "published-baseline-diagnostic/v1", "native_acceptance": False,
        "release_gate": False, "order": list(ORDER), "cold_state_comparison": False,
        "same_runner_fixed_order_may_warm_caches": True, "observations": [],
        "runtime_manifests_sha256": MANIFEST_SHA,
        "driver_sha256": common.sha(Path(__file__).read_bytes()), "status": "diagnostic_error"}
    output = None
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--release-root", type=Path, required=True)
        parser.add_argument("--candidate-root", type=Path, required=True)
        parser.add_argument("--output", type=Path, required=True)
        args = parser.parse_args()
        output = args.output
        if (sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true"
                or os.environ.get("RUNNER_OS") != "Windows"):
            raise ValueError("unsupported_environment")
        temp_root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        roots = (args.release_root.resolve(strict=True), args.candidate_root.resolve(strict=True))
        outputs = [output] + [output.with_name(output.stem + "-" + str(i) + ".json") for i in range(2)]
        if any(p.exists() or p.is_symlink() or temp_root not in p.resolve().parents
               or any(root == p.resolve() or root in p.resolve().parents for root in roots) for p in outputs):
            raise ValueError("unsupported_or_existing_output")
        descriptors = manifest_bytes(Path(__file__).with_name("published_baseline_manifests.json"))
        if tuple(descriptors[k]["commit"] for k in ORDER) != COMMITS:
            raise ValueError("subject_identity_differs")
        runtime = [git_blobs(root, descriptors[label]) for root, label in zip(roots, ORDER)]
        diagnostic_root = Path(__file__).resolve().parents[2]
        helper = diagnostic_root / "scripts/cg_process_tree.py"
        if common.sha(helper.read_bytes()) != descriptors[ORDER[1]]["files"]["scripts/cg_process_tree.py"]:
            raise ValueError("owned_helper_digest_differs")
        sys.path.insert(0, str(diagnostic_root))
        from scripts.cg_process_tree import OwnedProcess
        shell = shutil.which("powershell.exe")
        if shell is None:
            raise ValueError("windows_powershell_unavailable")
        report.update(python=list(sys.version_info[:3]), shell="powershell")
        outer = Path(tempfile.mkdtemp(prefix="cg-published-baseline-", dir=temp_root))
        environment = common.environment_for(outer, sys.executable)
        if "." not in environment["PATH"].split(os.pathsep):
            raise ValueError("original_dot_path_unavailable")
        payload = json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "synthetic-bytecode",
            "cwd": str(outer / "project"), "prompt": "hello", "trigger": "manual",
            "last_assistant_message": "waiting"}).encode()
        report["same_environment_payload_and_cwd"] = True
        report["os_cwd_is_candidate_checkout"] = True
        report["payload_cwd_is_synthetic_project"] = True
        for index, (label, files) in enumerate(zip(ORDER, runtime)):
            row = observe(outer, files, environment, payload, shell, OwnedProcess, roots[1])
            row.update(subject=label, commit=descriptors[label]["commit"],
                runtime_manifest_sha256=descriptors[label]["manifest_sha256"],
                launcher_sha256=descriptors[label]["files"][LAUNCHER], ordinal=index + 1)
            report["observations"].append(row)
            # Preserve each observation outside the disposable tree before reset.
            write_new(outputs[index + 1], row)
            if not safe_to_reset(row):
                report["fixture_cleanup"] = "retained"
                break
            shutil.rmtree(outer)
            report["fixture_cleanup"] = "removed"
            if row["result"] == "driver_error" or not row.get("original_runtime_files_unchanged"):
                break
            if index == 0:
                outer.mkdir()
                report["reset_between_sides_after_owned_cleanup"] = True
        if (len(report["observations"]) == 2 and report.get("fixture_cleanup") == "removed"
                and all(row["result"] != "driver_error" and row.get("original_runtime_files_unchanged")
                        for row in report["observations"])):
            report["status"] = "observations_recorded_not_acceptance"
    except Exception as error:
        report["exception_kind"] = common.kind(error)
    print(json.dumps(report, sort_keys=True))
    if output is not None:
        try:
            write_new(output, report)
        except Exception:
            return 2
    return 0 if report["status"] == "observations_recorded_not_acceptance" else 2


if __name__ == "__main__":
    raise SystemExit(main())
