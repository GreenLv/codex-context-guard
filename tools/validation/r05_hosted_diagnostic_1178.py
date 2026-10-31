#!/usr/bin/env python3
"""Synthetic hosted-Windows diagnosis, not a release acceptance replacement.

Run from a fresh checkout of the pinned commit, once per Python lane:
  python -B cg_r05_hosted_diagnostic_1178.py --repo "$env:GITHUB_WORKSPACE" \
      --output "$env:RUNNER_TEMP/r05-diagnostic-310.json"
No source/cache/install edits, network operations, rename retries or oracle edits.
Original R05 is run unchanged as E. A-D are separate mechanism experiments.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

PIN = "1178b1426254654cff4ab84d1dd2dff33c6de3d6"


def within(path, parent):
    return path == parent or parent in path.parents


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--phase", choices=("A", "B", "C", "D", "M", "E"),
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    if (sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_OS") != "Windows"):
        parser.error("only an isolated GitHub-hosted Windows diagnostic is supported")
    repo = args.repo.resolve(strict=True)
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    output = args.output.resolve()
    if not within(output, runner_temp) or within(output, repo) or output.exists():
        parser.error("output must be unused and beneath RUNNER_TEMP, outside checkout")
    head = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    if head != PIN:
        parser.error("checkout is not the exact pinned candidate")
    if subprocess.check_output(
            ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"],
            text=True).strip():
        parser.error("tracked checkout must be clean")
    subjects = [repo / name for name in (
        "scripts/context_guard.py", "tests/test_cg0151_readonly_snapshot.py",
        "tests/test_cg122_p0_counterexamples.py")]
    digest = lambda: {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in subjects}
    before = digest()
    scratch = Path(tempfile.mkdtemp(prefix="cg-r05-1178-", dir=runner_temp))
    for name in ("home", "codex", "private", "fixtures"):
        (scratch / name).mkdir()
    # Process-local environment only, before any product/test import.
    os.environ.update(HOME=str(scratch / "home"), USERPROFILE=str(scratch / "home"),
                      CODEX_HOME=str(scratch / "codex"),
                      CONTEXT_GUARD_DATA_DIR=str(scratch / "private"),
                      TMP=str(scratch / "fixtures"), TEMP=str(scratch / "fixtures"),
                      PYTHONDONTWRITEBYTECODE="1")
    tempfile.tempdir = str(scratch / "fixtures")
    sys.dont_write_bytecode = True
    if args.phase is None:
        # Every cell owns a fresh process, including the unchanged E oracle.
        # A worker that survives unittest's join prevents child exit; the
        # supervisor then terminates only that owned tree and stops the batch.
        cells = []
        cleanup_unknown = False
        for label in ("A", "B", "C", "D", "M", "E"):
            cell_output = scratch / ("cell-" + label + ".json")
            child = subprocess.Popen(
                [sys.executable, "-B", str(Path(__file__).resolve()),
                 "--repo", str(repo), "--output", str(cell_output),
                 "--phase", label],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                code = child.wait(timeout=90)
            except subprocess.TimeoutExpired:
                cleanup_unknown = True
                # PID comes exclusively from this supervisor's Popen; never
                # identify or kill processes by name or by ambient discovery.
                kill_code = None
                kill_error = None
                try:
                    kill_result = subprocess.run(
                        [str(Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"),
                         "/PID", str(child.pid), "/T", "/F"],
                        capture_output=True, timeout=15, check=False)
                    kill_code = kill_result.returncode
                except (OSError, subprocess.TimeoutExpired) as exc:
                    kill_error = type(exc).__name__
                    # Root-only fallback is not descendant-cleanup evidence.
                    try:
                        child.kill()
                    except OSError:
                        pass
                try:
                    child.wait(timeout=10)
                    root_exited = True
                except subprocess.TimeoutExpired:
                    root_exited = False
                cells.append(dict(phase=label, timeout=True,
                                  taskkill_returncode=kill_code,
                                  taskkill_error=kill_error,
                                  owned_root_exit_confirmed=root_exited,
                                  cleanup="unknown; no subsequent cell started"))
                break
            cell = dict(phase=label, exit_code=code, owned_root_exit_confirmed=True)
            if cell_output.exists():
                cell["report"] = json.loads(cell_output.read_text(encoding="utf-8"))
            else:
                cell["missing_report"] = True
            cells.append(cell)
            # An abnormal child without a completed report is not a known
            # diagnostic result. Do not continue after uncertain teardown.
            if "report" not in cell:
                cleanup_unknown = True
                break
        after = digest()
        report = dict(schema="cg-r05-owned-process-diagnostic/v2", commit=head,
                      python=sys.version, source_hashes_before=before,
                      source_hashes_after=after, source_unchanged=before == after,
                      cleanup_unknown=cleanup_unknown, cells=cells,
                      boundary="Synthetic diagnosis only; no root-cause or acceptance claim")
        with output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=True, indent=2)
        print(json.dumps({"commit": head, "cells": len(cells),
                          "cleanup_unknown": cleanup_unknown}))
        return 0 if (not cleanup_unknown and before == after
                     and all(cell["exit_code"] == 0 for cell in cells)) else 1
    sys.path.insert(0, str(repo))
    from tests.test_cg0151_readonly_snapshot import ReadOnlySnapshotTests, cg

    events = []
    phase = ["setup"]
    real_dll = ctypes.WinDLL

    class ObservedRename:
        def __init__(self, native):
            object.__setattr__(self, "native", native)

        def __getattr__(self, name):
            return getattr(self.native, name)

        def __setattr__(self, name, value):
            setattr(self.native, name, value)

        def __call__(self, *values):
            start = time.monotonic_ns()
            result = self.native(*values)
            error = ctypes.get_last_error()  # immediately, before another WinAPI call
            end = time.monotonic_ns()
            events.append(dict(phase=phase[0], call=len(events),
                               thread=threading.get_ident(), start_ns=start,
                               end_ns=end, ok=bool(result),
                               winerror=None if result else error,
                               information_class=int(values[1])))
            ctypes.set_last_error(error)
            return result

    class ObservedKernel:
        def __init__(self, native):
            self.native = native
            self.SetFileInformationByHandle = ObservedRename(
                native.SetFileInformationByHandle)

        def __getattr__(self, name):
            return getattr(self.native, name)

    def observed_dll(name, *values, **options):
        native = real_dll(name, *values, **options)
        return ObservedKernel(native) if str(name).lower() == "kernel32" else native

    def open_known(path, access, share):
        from ctypes import wintypes
        kernel = real_dll("kernel32", use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                           wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                           wintypes.HANDLE]
        create.restype = wintypes.HANDLE
        close = kernel.CloseHandle
        close.argtypes = [wintypes.HANDLE]
        close.restype = wintypes.BOOL
        handle = create(str(path), access, share, None, 3, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle, close

    class Mechanism(ReadOnlySnapshotTests):
        variant = "A"

        def runTest(self):
            self.ready()
            path = self.session_dir / "state.json"
            published = [self.state()["content_hash"]]
            failures = []
            started = threading.Event()
            stop = threading.Event()
            holder = None
            try:
                if self.variant in ("B", "C", "M"):
                    access, share = ((0x80, 0) if self.variant == "M" else
                                     (0x80000000, 7 if self.variant == "B" else 3))
                    holder = open_known(path, access, share)
                    events.append(dict(phase=phase[0], kind="known_holder",
                                       access=access, share=share))
                if self.variant == "C":
                    negative = path.with_name(".diagnostic-negative")
                    negative.write_bytes(b"synthetic negative control")
                    old = path.read_bytes()
                    try:
                        with self.assertRaises(PermissionError) as caught:
                            os.replace(negative, path)
                        self.assertIn(caught.exception.winerror, (5, 32))
                        self.assertEqual(path.read_bytes(), old)
                        events.append(dict(phase=phase[0], kind="legacy_negative",
                                           winerror=caught.exception.winerror))
                    finally:
                        negative.unlink(missing_ok=True)

                def writer():
                    try:
                        started.set()
                        for index in range(24):
                            with cg.session_lock(self.session_dir):
                                state = self.state()
                                state["wait_condition_sequence"] = index + 1
                                fd = cg._open_committed_state(path)
                                try:
                                    info = os.fstat(fd)
                                    events.append(dict(phase=phase[0], kind="publication",
                                                       index=index, dev=info.st_dev,
                                                       ino=info.st_ino))
                                    self.save_state(state)
                                finally:
                                    os.close(fd)
                                published.append(self.state()["content_hash"])
                    except BaseException as exc:
                        failures.append(exc)
                    finally:
                        stop.set()

                thread = threading.Thread(target=writer)
                thread.start()
                started.wait(timeout=10)
                try:
                    if self.variant == "D":
                        for _ in range(2000):
                            if stop.is_set():
                                break
                            path.lstat()
                            path.is_file()
                finally:
                    thread.join(timeout=30)
                self.assertFalse(thread.is_alive(), "diagnostic writer did not finish")
                if failures:
                    raise failures[0]
                self.assertEqual(len(published), 25)
            finally:
                if holder is not None:
                    handle, close = holder
                    self.assertTrue(close(handle))
            final = self.query()
            self.assertIn(final["revision"], published)

    results = []
    with mock.patch.object(ctypes, "WinDLL", observed_dll):
        for label in (args.phase,):
            phase[0] = label
            case = (ReadOnlySnapshotTests("test_r05_writer_publication_yields_whole_revisions")
                    if label == "E" else Mechanism())
            if label != "E":
                case.variant = label
            result = unittest.TestResult()
            case.run(result)
            redact = lambda text: text.replace(str(scratch), "<synthetic-scratch>").replace(
                str(repo), "<pinned-checkout>")
            results.append(dict(phase=label, successful=result.wasSuccessful(),
                                tests=result.testsRun,
                                errors=[redact(text) for _, text in result.errors],
                                failures=[redact(text) for _, text in result.failures],
                                skipped=[reason for _, reason in result.skipped]))
    after = digest()
    report = dict(schema="cg-r05-synthetic-diagnostic/v1", commit=head,
                  python=sys.version, platform=sys.platform,
                  initial_observation="R05 FileRenameInfoEx WinError32 on CI Python 3.10 and 3.11",
                  source_hashes_before=before, source_hashes_after=after,
                  source_unchanged=before == after, results=results, events=events,
                  boundary="Synthetic diagnosis only; no acceptance replacement or root-cause claim")
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=True, indent=2)
    print(json.dumps({"commit": head, "source_unchanged": before == after,
                      "results": [{"phase": r["phase"], "successful": r["successful"]}
                                  for r in results]}))
    return 0 if before == after and all(r["successful"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
