#!/usr/bin/env python3
"""Deterministic synthetic resolver-reader sharing probe; no acceptance replacement.

PowerShell, isolated hosted Windows, fresh pinned checkout:
  python -B cg_r05_resolver_barrier_1178.py --repo "$env:GITHUB_WORKSPACE" --output "$env:RUNNER_TEMP/resolver-barrier-310.json"
Workflow: timeout-minutes: 5; upload the output with if: always().
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from unittest import mock

PIN = "1178b1426254654cff4ab84d1dd2dff33c6de3d6"


def inside(path, parent):
    return path == parent or parent in path.parents


def error_fact(exc):
    # Do not export exception messages, source paths, state or prompt contents.
    return {"type": type(exc).__name__, "winerror": getattr(exc, "winerror", None)}


def write_report(path, report):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=True, indent=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cell", choices=("crt", "share7"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not __debug__:
        parser.error("optimized Python would disable the diagnostic assertions")
    if (sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_OS") != "Windows"):
        parser.error("requires isolated hosted Windows Actions")
    repo = args.repo.resolve(strict=True)
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    output = args.output.resolve()
    if output.exists() or not inside(output, runner_temp) or inside(output, repo):
        parser.error("output must be unused beneath RUNNER_TEMP, outside checkout")
    head = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    if head != PIN:
        parser.error("candidate HEAD differs from exact pin")
    if subprocess.check_output(
            ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"],
            text=True).strip():
        parser.error("tracked checkout must be clean")
    names = ("scripts/context_guard.py", "tests/test_cg0151_readonly_snapshot.py",
             "tests/test_cg122_p0_counterexamples.py")
    def digests():
        return {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                for name in names}
    before = digests()
    scratch = Path(tempfile.mkdtemp(prefix="cg-resolver-barrier-1178-", dir=runner_temp))
    for leaf in ("home", "codex", "private", "fixtures"):
        (scratch / leaf).mkdir()
    # Set every fallback before importing any product or fixture module.
    os.environ.update(HOME=str(scratch / "home"), USERPROFILE=str(scratch / "home"),
                      CODEX_HOME=str(scratch / "codex"),
                      CONTEXT_GUARD_DATA_DIR=str(scratch / "private"),
                      TMP=str(scratch / "fixtures"), TEMP=str(scratch / "fixtures"),
                      PYTHONDONTWRITEBYTECODE="1")
    tempfile.tempdir = str(scratch / "fixtures")
    sys.dont_write_bytecode = True
    if args.cell is None:
        cells = []
        unknown = False
        for label in ("crt", "share7"):
            cell_path = scratch / (label + ".json")
            child = subprocess.Popen(
                [sys.executable, "-B", str(Path(__file__).resolve()),
                 "--repo", str(repo), "--output", str(cell_path), "--cell", label],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                code = child.wait(timeout=90)
            except subprocess.TimeoutExpired:
                unknown = True
                kill_code = None
                kill_error = None
                try:
                    killed = subprocess.run(
                        [str(Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"),
                         "/PID", str(child.pid), "/T", "/F"],
                        capture_output=True, check=False, timeout=15)
                    kill_code = killed.returncode
                except (OSError, subprocess.TimeoutExpired) as exc:
                    kill_error = type(exc).__name__
                    try:
                        child.kill()
                    except OSError:
                        pass
                try:
                    child.wait(timeout=10)
                    exited = True
                except subprocess.TimeoutExpired:
                    exited = False
                cells.append(dict(cell=label, timeout=True, cleanup_unknown=True,
                                  taskkill_returncode=kill_code, taskkill_error=kill_error,
                                  owned_root_exit_confirmed=exited))
                break
            cell = dict(cell=label, exit_code=code, owned_root_exit_confirmed=True)
            try:
                cell["report"] = json.loads(cell_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                cell["missing_or_invalid_report"] = True
                unknown = True
            cells.append(cell)
            if unknown or cell.get("report", {}).get("cleanup_unknown", True):
                unknown = True
                break
        after = digests()
        report = dict(schema="cg-resolver-barrier-supervisor/v1", commit=head,
                      python=sys.version, cleanup_unknown=unknown, cells=cells,
                      source_hashes_before=before, source_hashes_after=after,
                      source_unchanged=before == after,
                      boundary="Synthetic deterministic mechanism only; historical CI lock owner remains unproven")
        write_report(output, report)
        print(json.dumps({"cells": len(cells), "cleanup_unknown": unknown,
                          "source_unchanged": before == after}))
        return 0 if (not unknown and before == after and len(cells) == 2
                     and all(c["exit_code"] == 0 for c in cells)) else 1

    sys.path.insert(0, str(repo))
    from tests.test_cg0151_readonly_snapshot import ReadOnlySnapshotTests, cg
    report = dict(schema="cg-resolver-barrier-cell/v1", commit=head, cell=args.cell,
                  python=sys.version, cleanup_unknown=False, rename_calls=[],
                  resolver_loads=0, replacement_opens=0, successful=False)
    fixture = ReadOnlySnapshotTests("test_r05_writer_publication_yields_whole_revisions")
    thread = None
    release = threading.Event()
    entered = threading.Event()
    query_result = []
    query_errors = []
    real_load = cg.json.load
    real_open = Path.open
    real_dll = ctypes.WinDLL

    class RenameObserver:
        def __init__(self, native):
            object.__setattr__(self, "native", native)
        def __getattr__(self, name):
            return getattr(self.native, name)
        def __setattr__(self, name, value):
            setattr(self.native, name, value)
        def __call__(self, *values):
            start = time.monotonic_ns()
            result = self.native(*values)
            error = ctypes.get_last_error()
            finish = time.monotonic_ns()
            report["rename_calls"].append(dict(ok=bool(result),
                winerror=None if result else error, start_ns=start, end_ns=finish,
                information_class=int(values[1])))
            ctypes.set_last_error(error)
            return result

    class KernelObserver:
        def __init__(self, native):
            self.native = native
            self.SetFileInformationByHandle = RenameObserver(native.SetFileInformationByHandle)
        def __getattr__(self, name):
            return getattr(self.native, name)

    def dll(name, *values, **options):
        native = real_dll(name, *values, **options)
        return KernelObserver(native) if str(name).lower() == "kernel32" else native

    try:
        fixture.setUp()
        fixture.ready()
        target = fixture.session_dir / "state.json"
        old_bytes = target.read_bytes()
        pending = fixture.state()
        pending["wait_condition_sequence"] += 1

        def is_reader():
            return threading.current_thread() is thread

        def open_control(path, *values, **options):
            # Only this exact resolver read is varied. Other query reads,
            # writer behavior, JSON decoding and identity checks are unchanged.
            if (args.cell == "share7" and is_reader() and path == target
                    and inspect.currentframe().f_back.f_code.co_name == "read_json"):
                assert values == ("r",) and options == {"encoding": "utf-8"}
                descriptor = cg._open_committed_state(path)
                report["replacement_opens"] += 1
                try:
                    return os.fdopen(descriptor, "r", encoding="utf-8")
                except BaseException:
                    os.close(descriptor)
                    raise
            return real_open(path, *values, **options)

        def load_barrier(handle, *values, **options):
            caller = inspect.currentframe().f_back
            if (is_reader() and getattr(handle, "name", None) is not None
                    and caller.f_code.co_name == "read_json"
                    and caller.f_back.f_code.co_name == "resolve_supplied_session"):
                # Path.open's return name is an fd integer in share7; pin the
                # exact path through the caller local instead of fd.name.
                if caller.f_locals.get("path") == target:
                    report["resolver_loads"] += 1
                    assert report["resolver_loads"] == 1
                    info = os.fstat(handle.fileno())
                    report["held_reader"] = dict(dev=info.st_dev, ino=info.st_ino,
                                                   size=info.st_size,
                                                   inheritable=os.get_inheritable(handle.fileno()))
                    report["reader_open_ns"] = time.monotonic_ns()
                    entered.set()
                    if not release.wait(timeout=30):
                        raise RuntimeError("barrier_release_timeout")
                    report["reader_release_ns"] = time.monotonic_ns()
            return real_load(handle, *values, **options)

        def reader():
            try:
                query_result.append(fixture.query())
            except BaseException as exc:
                query_errors.append(error_fact(exc))

        # Observer begins after fixture preparation: exactly one attempted
        # committed-state rename is expected in each cell.
        with mock.patch.object(Path, "open", open_control), \
                mock.patch.object(cg.json, "load", load_barrier), \
                mock.patch.object(ctypes, "WinDLL", dll):
            thread = threading.Thread(target=reader, name="owned-resolver-reader")
            thread.start()
            try:
                assert entered.wait(timeout=15), "resolver_barrier_not_entered"
                assert thread.is_alive(), "reader_not_held"
                report["writer_started_ns"] = time.monotonic_ns()
                writer_error = None
                try:
                    with cg.session_lock(fixture.session_dir):
                        fixture.save_state(pending)
                except BaseException as exc:
                    writer_error = error_fact(exc)
                report["writer_finished_ns"] = time.monotonic_ns()
                report["writer_error"] = writer_error
            finally:
                release.set()
                thread.join(timeout=10)
        assert not thread.is_alive(), "owned_reader_not_terminated"
        report["query_errors"] = query_errors
        assert report["resolver_loads"] == 1, "wrong_resolver_load_count"
        assert len(report["rename_calls"]) == 1, "wrong_rename_count"
        native = report["rename_calls"][0]
        assert native["information_class"] == 22, "wrong_information_class"
        assert (report["reader_open_ns"] <= native["start_ns"]
                <= native["end_ns"] <= report["reader_release_ns"]), "rename_not_inside_held_reader"
        assert not query_errors and len(query_result) == 1, "query_did_not_complete"
        current_bytes = target.read_bytes()
        current = json.loads(current_bytes)
        cg.validate_state_integrity(current)
        assert query_result[0]["revision"] == current["content_hash"], "query_revision_mismatch"
        if args.cell == "crt":
            assert report["replacement_opens"] == 0
            assert writer_error == {"type": "PermissionError", "winerror": 32}, "CRT_reader_did_not_reproduce"
            assert not native["ok"] and native["winerror"] == 32
            assert current_bytes == old_bytes, "denied_publish_changed_target"
        else:
            assert report["replacement_opens"] == 1
            assert writer_error is None and native["ok"], "share7_publish_not_successful"
            assert current_bytes != old_bytes, "successful_publish_did_not_change_revision"
            assert current["wait_condition_sequence"] == pending["wait_condition_sequence"]
        report["successful"] = True
    except BaseException as exc:
        report["diagnostic_error"] = error_fact(exc)
    finally:
        release.set()
        if thread is not None and thread.ident is not None:
            thread.join(timeout=10)
        if thread is not None and thread.is_alive():
            report["cleanup_unknown"] = True
        else:
            try:
                if not fixture.doCleanups():
                    report["cleanup_unknown"] = True
            except BaseException as exc:
                report["cleanup_unknown"] = True
                report["cleanup_error"] = error_fact(exc)
        report["source_hashes_before"] = before
        report["source_hashes_after"] = digests()
        report["source_unchanged"] = before == report["source_hashes_after"]
        write_report(output, report)
    code = 0 if (report["successful"] and report["source_unchanged"]
                 and not report["cleanup_unknown"]) else 1
    if report["cleanup_unknown"]:
        # Never enter another cell or wait indefinitely for a leaked thread.
        os._exit(2)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
