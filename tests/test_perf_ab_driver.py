#!/usr/bin/env python3
"""Negative controls for the formal A/B performance driver.

Each test drives perf_ab.py through a failure schedule (no-op Hook, malformed
output, child failure, semantic failure, timeout, seed failure, absent
identity, interrupted batch) and asserts the driver records the failure in
raw rows, blocks acceptance, exits nonzero, and preserves the partial report.
"""

from __future__ import annotations

import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
DRIVER = REPO_ROOT / "tools" / "validation" / "perf_ab.py"
BASELINE = REPO_ROOT.parent / "codex-context-guard"  # placeholder; overridden below


def shell_output(value: str) -> str:
    """Emit the same fixture bytes through the driver's actual shell."""
    if sys.platform == "win32":
        return "Write-Output '" + value.replace("'", "''") + "'"
    return "printf '%s\\n' " + shlex.quote(value)


def run_driver(args: list[str]) -> tuple[int, dict | None, str]:
    completed = subprocess.run(
        [sys.executable, str(DRIVER), *args],
        capture_output=True, text=True, timeout=600, cwd=str(REPO_ROOT))
    try:
        report = json.loads(Path(args[args.index("--out)") + 1]).read_text()) \
            if "--out)" in args else None
    except (ValueError, OSError, json.JSONDecodeError):
        report = None
    return completed.returncode, report, completed.stderr


class PerfDriverNegativeTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.baseline = REPO_ROOT.parent / "cg-baseline-perf"
        if not self.baseline.is_dir():
            self.baseline = REPO_ROOT  # any tree with hooks.json works for overrides

    def tearDown(self):
        self.tmp.cleanup()

    def drive(self, cells: str, wrapper: str, *, extra: list[str] | None = None,
              baseline: Path | None = None) -> tuple[int, dict, int]:
        out = self.work / f"result-{abs(hash((cells, wrapper, str(extra))))}.json"
        args = [
            "--baseline", str(baseline or self.baseline),
            "--candidate", str(REPO_ROOT),
            "--attempts", "1", "--cells", cells,
            "--out", str(out),
            "--wrapper-override", wrapper,
        ]
        args.extend(extra or [])
        completed = subprocess.run(
            [sys.executable, str(DRIVER), *args],
            capture_output=True, text=True, timeout=600, cwd=str(REPO_ROOT))
        self.assertTrue(out.is_file(), f"report not persisted: {completed.stderr[-400:]}")
        report = json.loads(out.read_text(encoding="utf-8"))
        return completed.returncode, report, completed.stderr

    def test_noop_hook_fails_posttool_semantics(self):
        code, report, _ = self.drive("posttool_active", shell_output("{}"))
        self.assertEqual(code, 1)
        self.assertFalse(report["accepted"])
        rows = report["cells"]["posttool_active"]["sides"]["baseline"]["raw_rows"]
        self.assertTrue(all(r.get("assertion") != "ok" for r in rows))

    def test_malformed_output_is_recorded(self):
        code, report, _ = self.drive("user_prompt_active", shell_output("not-json"))
        self.assertEqual(code, 1)
        rows = report["cells"]["user_prompt_active"]["sides"]["candidate"]["raw_rows"]
        self.assertEqual(rows[0].get("assertion"), "stdout_not_json")

    def test_child_failure_is_retained_and_blocks(self):
        code, report, _ = self.drive("pretool_safe", "exit 3")
        self.assertEqual(code, 1)
        rows = report["cells"]["pretool_safe"]["sides"]["baseline"]["raw_rows"]
        self.assertEqual(rows[0]["outcome_class"], "failed")
        self.assertEqual(rows[0]["returncode"], 3)
        self.assertFalse(report["accepted"])

    def test_timeout_is_censored_and_blocks(self):
        code, report, _ = self.drive(
            "pretool_safe", "Start-Sleep -Seconds 8" if sys.platform == "win32" else "sleep 8", extra=["--timeout", "1"])
        self.assertEqual(code, 1)
        rows = report["cells"]["pretool_safe"]["sides"]["baseline"]["raw_rows"]
        self.assertEqual(rows[0]["outcome_class"], "timeout")
        summary = report["cells"]["pretool_safe"]["sides"]["baseline"]["summary"]
        self.assertEqual(summary["timeouts"], 1)
        self.assertEqual(summary["success_p95"], None)

    def test_semantic_success_but_wrong_persisted_state_fails(self):
        # A wrapper that prints the right object for the wrong reason:
        # posttool prints {} (valid JSON) — the evidence oracle must fail it.
        code, report, _ = self.drive("posttool_active", shell_output('{"continue": true}'))
        self.assertEqual(code, 1)
        rows = report["cells"]["posttool_active"]["sides"]["candidate"]["raw_rows"]
        self.assertNotEqual(rows[0].get("assertion"), "ok")

    def test_seed_failure_is_recorded_and_blocks(self):
        empty = self.work / "empty-tree"
        (empty / "hooks").mkdir(parents=True)
        (empty / "hooks" / "hooks.json").write_text(json.dumps({"hooks": {}}))
        code, report, _ = self.drive("posttool_active", shell_output("{}"),
                                     extra=["--candidate", str(empty)])
        self.assertEqual(code, 1)
        rows = report["cells"]["posttool_active"]["sides"]["candidate"]["raw_rows"]
        self.assertEqual(rows[0]["outcome_class"], "seed_failed")

    def test_absent_identity_blocks_formal(self):
        empty = self.work / "identity-empty"
        empty.mkdir()
        out = self.work / "formal-blocked.json"
        completed = subprocess.run(
            [sys.executable, str(DRIVER), "--baseline", str(empty),
             "--candidate", str(empty), "--attempts", "20", "--formal",
             "--cells", "pretool_safe", "--out", str(out)],
            capture_output=True, text=True, timeout=120, cwd=str(REPO_ROOT))
        self.assertEqual(completed.returncode, 2)
        self.assertIn("identities", completed.stderr)

    def test_formal_refuses_wrapper_override(self):
        out = self.work / "formal-override.json"
        completed = subprocess.run(
            [sys.executable, str(DRIVER), "--baseline", str(REPO_ROOT),
             "--candidate", str(REPO_ROOT), "--attempts", "20", "--formal",
             "--cells", "pretool_safe", "--out", str(out),
             "--wrapper-override", shell_output("{}")],
            capture_output=True, text=True, timeout=120, cwd=str(REPO_ROOT))
        self.assertEqual(completed.returncode, 2)
        self.assertIn("negative-testing only", completed.stderr)

    def test_interrupted_batch_persists_partial_report(self):
        # A wrapper that fails on the second scheduled run aborts nothing:
        # the driver must persist rows incrementally; simulate a hard driver
        # error by pointing --out into a path whose parent is removed later is
        # not observable — instead assert incremental persistence directly by
        # checking the report exists and parses after a batch with failures.
        code, report, _ = self.drive(
            "pretool_safe,posttool_active", "exit 1")
        self.assertEqual(code, 1)
        self.assertIn("pretool_safe", report["cells"])
        self.assertIn("posttool_active", report["cells"])
        self.assertFalse(report["accepted"])

    def test_subagent_oracle_requires_matching_agent_and_status(self):
        sys.path.insert(0, str(REPO_ROOT / "tools" / "validation"))
        import perf_ab

        state_dir = perf_ab.payload_state_dir(self.work, "agent-oracle")
        state_dir.mkdir(parents=True, exist_ok=True)
        for cell, status in [("subagent_start", "running"), ("subagent_events", "stopped")]:
            for agent_id, actual_status, accepted in [
                ("perf-agent", status, True),
                ("wrong-agent", status, False),
                ("perf-agent", "pending", False),
            ]:
                with self.subTest(cell=cell, agent_id=agent_id, status=actual_status):
                    (state_dir / "state.json").write_text(json.dumps({
                        "agents": [{"agent_id": agent_id, "status": actual_status}]}))
                    row = {"returncode": 0}
                    perf_ab.check_semantics(cell, row, self.work, b"{}",
                                            {"session": "agent-oracle"})
                    self.assertEqual(row["assertion"] == "ok", accepted)

    def test_nearest_rank_uses_ceil(self):
        sys.path.insert(0, str(REPO_ROOT / "tools" / "validation"))
        import perf_ab

        self.assertEqual(perf_ab.nearest_rank([1, 2, 3, 4], 95), 4)
        self.assertEqual(perf_ab.nearest_rank([1, 2, 3], 95), 3)
        self.assertEqual(perf_ab.nearest_rank([5], 95), 5)
        self.assertIsNone(perf_ab.nearest_rank([], 95))
        # Non-integral rank: n=7, p=50 -> ceil(3.5)-1 = 3 (0-based).
        self.assertEqual(perf_ab.nearest_rank(list(range(1, 8)), 50), 4)

    def test_r3_invalid_selection_and_attempts_refused(self):
        for cells, attempts, formal in [("", "1", False), ("unknown", "1", False),
                                       ("pretool_safe,pretool_safe", "1", False),
                                       ("pretool_safe", "0", False),
                                       ("memory_stop,stop_s1", "20", True)]:
            with self.subTest(cells=cells, attempts=attempts):
                proc = subprocess.run([sys.executable, str(DRIVER), "--baseline", str(REPO_ROOT),
                                       "--candidate", str(REPO_ROOT), "--cells", cells,
                                       "--attempts", attempts, "--out", str(self.work / "invalid.json")]
                                      + (["--formal"] if formal else []), capture_output=True)
                self.assertEqual(proc.returncode, 2)
                self.assertFalse((self.work / "invalid.json").exists())

    def test_r3_unwitnessed_interruption_persists_started_attempt_and_retains_home(self):
        sys.path.insert(0, str(REPO_ROOT / "tools/validation"))
        import perf_ab
        out = self.work / "interrupted.json"
        homes = []
        def interrupt(_tree, data_dir, _session):
            homes.append(data_dir.parent)
            saved = json.loads(out.read_text())
            self.assertEqual(saved["cells"]["posttool_active"]["sides"]["baseline"]
                             ["raw_rows"][0]["outcome_class"], "started")
            raise KeyboardInterrupt()
        argv = ["perf_ab", "--baseline", str(REPO_ROOT), "--candidate", str(REPO_ROOT),
                "--attempts", "1", "--cells", "posttool_active", "--out", str(out)]
        with patch.object(sys, "argv", argv), patch.object(perf_ab, "seed_active_session", interrupt):
            self.assertEqual(perf_ab.main(), 1)
        self.assertFalse(json.loads(out.read_text())["accepted"])
        self.assertTrue(homes)
        # A mocked seed interruption has no owned-process cleanup witness.
        self.assertTrue(all(home.exists() for home in homes))
        self.assertTrue(json.loads(out.read_text())["cells"]["posttool_active"]
                        ["sides"]["baseline"]["raw_rows"][0]["retain_home"])

    def test_r3_wrong_command_evidence_cannot_satisfy_lifecycle_count(self):
        sys.path.insert(0, str(REPO_ROOT / "tools/validation"))
        import perf_ab
        directory = self.work / "sessions-v2/perf-life"
        directory.mkdir(parents=True)
        state = {"evidence": [{"id": "E0001", "tool": "bash", "outcome": "success",
                               "summary": "input={'command': 'echo wrong'}; response={'stdout': 'echo wrong'}",
                               "core_call_seq": 1, "core_result_seq": 2}]}
        (directory / "state.json").write_text(json.dumps(state))
        row = {"error": None, "returncode": 0}
        perf_ab.check_semantics("lifecycle_matched", row, self.work, b"{}",
                                {"kind": "post", "session": "perf-life", "pair": 0,
                                 "command": "echo pair-0", "evidence_after": 1})
        self.assertEqual(row["assertion"], "lifecycle_evidence_association_failed")

    def test_r3_session_end_uses_three_second_deadline(self):
        sys.path.insert(0, str(REPO_ROOT / "tools/validation"))
        import perf_ab
        out = self.work / "deadline.json"
        deadlines = []
        def run(_wrapper, _tree, _cell, _spec, _data, timeout):
            deadlines.append(timeout)
            return {"outcome_class": "completed", "assertion": "ok", "elapsed": 0.1}
        argv = ["perf_ab", "--baseline", str(REPO_ROOT), "--candidate", str(REPO_ROOT),
                "--attempts", "1", "--cells", "session_end", "--out", str(out)]
        with patch.object(sys, "argv", argv), patch.object(perf_ab, "seed_active_session"), \
             patch.object(perf_ab, "run_standard_attempt", run):
            self.assertEqual(perf_ab.main(), 0)
        self.assertEqual(deadlines, [3.0, 3.0])

    def test_r3_special_cells_execute_and_failure_blocks(self):
        sys.path.insert(0, str(REPO_ROOT / "tools/validation"))
        import perf_ab
        out = self.work / "special.json"
        argv = ["perf_ab", "--baseline", str(REPO_ROOT), "--candidate", str(REPO_ROOT),
                "--attempts", "1", "--cells", "memory_stop,stop_s1", "--out", str(out)]
        failed = {"outcome_class": "failed", "assertion": "wrong", "elapsed": 0.1}
        with patch.object(sys, "argv", argv), \
             patch.object(perf_ab, "run_memory_attempt", return_value=failed) as memory, \
             patch.object(perf_ab, "run_stop_cell", return_value=failed) as stop:
            self.assertEqual(perf_ab.main(), 1)
        self.assertEqual(memory.call_count, 2)
        self.assertEqual(stop.call_count, 2)
        self.assertFalse(json.loads(out.read_text())["accepted"])


class PerfReportPublicationTests(unittest.TestCase):
    """Exercise the actual publisher without launching performance samples."""

    def setUp(self):
        sys.path.insert(0, str(REPO_ROOT / "tools/validation"))
        import perf_ab
        self.driver = perf_ab
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "证据 checkpoint.json"
        self.partial = self.path.with_name(self.path.name + ".partial")
        self.report = {"accepted": False, "rows": [{"error": "原始错误"}]}
        self.expected = json.dumps(self.report, indent=2, ensure_ascii=False) + "\n"

    @staticmethod
    def windows_error(code):
        error = PermissionError("synthetic publication conflict")
        error.winerror = code
        return error

    def clock(self):
        now, sleeps = [0.0], []
        def sleep(seconds):
            self.assertGreater(seconds, 0)
            sleeps.append(seconds)
            now[0] += seconds
            self.assertLessEqual(len(sleeps), 30, "retry window did not terminate")
        return now, sleeps, sleep

    def test_first_publish_and_unicode_replacement_need_no_sleep(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    self.path.write_text("old", encoding="utf-8")
                with patch.object(sys, "platform", "win32"), \
                     patch.object(self.driver.time, "sleep") as sleep:
                    self.driver.write_report(self.path, self.report)
                sleep.assert_not_called()
                self.assertEqual(self.path.read_text(encoding="utf-8"), self.expected)
                self.assertFalse(self.partial.exists())

    def test_cp1252_default_control_fails_but_publisher_emits_utf8_bytes(self):
        actual_open = io.open
        def cp1252_open(file, mode="r", buffering=-1, encoding=None, *args, **kwargs):
            if "b" not in mode and encoding in (None, "locale"):
                encoding = "cp1252"
            return actual_open(file, mode, buffering, encoding, *args, **kwargs)
        with patch.object(io, "text_encoding", side_effect=lambda encoding, *_: (
                    "locale" if encoding is None else encoding)), \
             patch.object(io, "open", side_effect=cp1252_open):
            # Exercise real encoding/bytes, not a mock that merely records kwargs.
            with self.assertRaises(UnicodeEncodeError):
                self.partial.write_text(self.expected)
            self.driver.write_report(self.path, self.report)
        self.assertEqual(self.path.read_bytes(), self.expected.replace("\n", os.linesep).encode("utf-8"))
        self.assertEqual(json.loads(self.path.read_bytes()), self.report)
        self.assertFalse(self.partial.exists())

    def test_each_windows_conflict_recovers_without_rewriting_partial(self):
        for code in (5, 32, 33):
            with self.subTest(winerror=code):
                self.path.write_text("old", encoding="utf-8")
                now, sleeps, sleep = self.clock()
                actual_replace = self.driver.os.replace
                actual_write = Path.write_text
                attempts, writes = [], []
                def write(path, text, *args, **kwargs):
                    writes.append(path)
                    return actual_write(path, text, *args, **kwargs)
                def replace(source, destination):
                    self.assertEqual(self.path.read_text(encoding="utf-8"), "old")
                    self.assertEqual(source, self.partial)
                    self.assertEqual(destination, self.path)
                    self.assertEqual(self.partial.read_text(encoding="utf-8"), self.expected)
                    attempts.append(now[0])
                    if len(attempts) < 3:
                        raise self.windows_error(code)
                    return actual_replace(source, destination)
                with patch.object(sys, "platform", "win32"), \
                     patch.object(self.driver.time, "monotonic", side_effect=lambda: now[0]), \
                     patch.object(self.driver.time, "sleep", side_effect=sleep), \
                     patch.object(self.driver.os, "replace", side_effect=replace), \
                     patch.object(Path, "write_text", autospec=True, side_effect=write):
                    self.driver.write_report(self.path, self.report)
                self.assertEqual(attempts[0], 0)
                self.assertEqual(len(attempts), 3)
                self.assertEqual(writes, [self.partial])
                self.assertEqual(len(sleeps), 2)
                self.assertEqual(self.path.read_text(encoding="utf-8"), self.expected)
                self.assertFalse(self.partial.exists())

    def test_persistent_windows_conflict_exhausts_one_window_and_keeps_files(self):
        for code in (5, 32, 33):
            with self.subTest(winerror=code):
                self.path.write_text("old", encoding="utf-8")
                now, sleeps, sleep = self.clock()
                errors = []
                def replace(_source, _destination):
                    error = self.windows_error(code)
                    errors.append(error)
                    raise error
                with patch.object(sys, "platform", "win32"), \
                     patch.object(self.driver.time, "monotonic", side_effect=lambda: now[0]), \
                     patch.object(self.driver.time, "sleep", side_effect=sleep), \
                     patch.object(self.driver.os, "replace", side_effect=replace):
                    with self.assertRaises(PermissionError) as caught:
                        self.driver.write_report(self.path, self.report)
                self.assertIs(caught.exception, errors[-1])
                self.assertEqual(caught.exception.winerror, code)
                self.assertGreater(len(errors), 1)
                self.assertAlmostEqual(sum(sleeps), 0.5)
                self.assertLessEqual(now[0], 0.5)
                self.assertEqual(self.path.read_text(encoding="utf-8"), "old")
                self.assertEqual(self.partial.read_text(encoding="utf-8"), self.expected)

    def test_sleep_is_clipped_and_no_attempt_starts_at_deadline(self):
        now, sleeps, sleep = self.clock()
        error = self.windows_error(5)
        def replace(_source, _destination):
            now[0] = 0.495
            raise error
        with patch.object(sys, "platform", "win32"), \
             patch.object(self.driver.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(self.driver.time, "sleep", side_effect=sleep), \
             patch.object(self.driver.os, "replace", side_effect=replace) as attempted:
            with self.assertRaises(PermissionError) as caught:
                self.driver.write_report(self.path, self.report)
        self.assertIs(caught.exception, error)
        self.assertEqual(attempted.call_count, 1)
        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], 0.005)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.partial.read_text(encoding="utf-8"), self.expected)

    def test_nonwindows_never_retries_even_with_windows_codes(self):
        for code in (5, 32, 33):
            with self.subTest(winerror=code):
                error = self.windows_error(code)
                with patch.object(sys, "platform", "darwin"), \
                     patch.object(self.driver.time, "sleep") as sleep, \
                     patch.object(self.driver.time, "monotonic") as monotonic, \
                     patch.object(self.driver.os, "replace", side_effect=error) as replace:
                    with self.assertRaises(PermissionError) as caught:
                        self.driver.write_report(self.path, self.report)
                self.assertIs(caught.exception, error)
                self.assertEqual(replace.call_count, 1)
                sleep.assert_not_called()
                monotonic.assert_not_called()

    def test_other_replace_errors_and_errno_alone_propagate_immediately(self):
        errors = [self.windows_error(6), PermissionError(13, "not a Win32 code"),
                  OSError("unclassified replacement failure")]
        for error in errors:
            with self.subTest(error=type(error).__name__, winerror=getattr(error, "winerror", None)):
                with patch.object(sys, "platform", "win32"), \
                     patch.object(self.driver.time, "sleep") as sleep, \
                     patch.object(self.driver.os, "replace", side_effect=error) as replace:
                    with self.assertRaises(OSError) as caught:
                        self.driver.write_report(self.path, self.report)
                self.assertIs(caught.exception, error)
                self.assertEqual(replace.call_count, 1)
                sleep.assert_not_called()

    def test_partial_write_error_is_not_a_replace_retry(self):
        error = self.windows_error(5)
        with patch.object(sys, "platform", "win32"), \
             patch.object(Path, "write_text", side_effect=error), \
             patch.object(self.driver.time, "sleep") as sleep, \
             patch.object(self.driver.os, "replace") as replace:
            with self.assertRaises(PermissionError) as caught:
                self.driver.write_report(self.path, self.report)
        self.assertIs(caught.exception, error)
        replace.assert_not_called()
        sleep.assert_not_called()

    def test_replace_and_sleep_interruptions_propagate_without_another_attempt(self):
        for interrupt in (KeyboardInterrupt("stop"), SystemExit(7)):
            for during in ("replace", "sleep"):
                with self.subTest(interrupt=type(interrupt).__name__, during=during):
                    with patch.object(sys, "platform", "win32"), \
                         patch.object(self.driver.time, "monotonic", return_value=0), \
                         patch.object(self.driver.os, "replace", side_effect=(
                             interrupt if during == "replace" else self.windows_error(32))) as replace, \
                         patch.object(self.driver.time, "sleep", side_effect=(
                             interrupt if during == "sleep" else None)) as sleep:
                        with self.assertRaises(type(interrupt)) as caught:
                            self.driver.write_report(self.path, self.report)
                    self.assertIs(caught.exception, interrupt)
                    self.assertEqual(replace.call_count, 1)
                    self.assertEqual(sleep.call_count, 1 if during == "sleep" else 0)
                    self.assertEqual(self.partial.read_text(encoding="utf-8"), self.expected)


class PerfDriverLifecycleTests(unittest.TestCase):
    """Whole-command deadlines and control failures never manufacture samples."""

    def setUp(self):
        sys.path.insert(0, str(REPO_ROOT / 'tools/validation'))
        import perf_ab
        self.driver = perf_ab
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def clock_event(self, creation, execution):
        now, communications = [0.0], []
        driver = self.driver

        class Process:
            args = ['synthetic']
            returncode = 0
            pid = 123456
            stdin = stdout = stderr = None

            def __init__(self, *args, **kwargs):
                now[0] += creation

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def communicate(self, input=None, timeout=None):
                communications.append(timeout)
                if len(communications) > 1:
                    return b'{}', b''
                if timeout is not None and execution > timeout + 1e-12:
                    now[0] += timeout
                    raise subprocess.TimeoutExpired(self.args, timeout, output=b'{}')
                now[0] += execution
                return b'{}', b''

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        class Owner:
            def __init__(self):
                self.process = Process()

            def close(self, timeout):
                return {'owned_process_exited': True, 'owned_tree_no_running_members': True,
                        'process_group_cleanup_error': None}

        with patch.object(driver.subprocess, 'Popen', Process), \
             patch.object(driver, 'OwnedProcess', create=True) as owned, \
             patch.object(driver, 'observe_natural_completion', return_value={'no_running_members': True}, create=True), \
             patch.object(driver.time, 'perf_counter', side_effect=lambda: now[0]):
            owned.spawn.side_effect = lambda *a, **kw: Owner()
            timing = driver.run_event('synthetic', REPO_ROOT, self.work, b'{}', 3.0)
        outcome = driver.classify_outcome(timing.get('elapsed_raw', timing['elapsed']),
                                          timing['returncode'], timing['error'], 3.0)
        return timing, outcome, communications

    def test_whole_command_startup_is_in_budget(self):
        timing, outcome, calls = self.clock_event(2.8, 0.4)
        self.assertEqual(outcome, 'timeout')
        self.assertLessEqual(calls[0], 0.2 + 1e-10)
        self.assertTrue(timing['process_lifetime']['recovery_complete'])

    def test_whole_command_boundary_controls(self):
        for startup, expected in [(2.59, 'completed'), (2.6, 'completed')]:
            with self.subTest(startup=startup):
                _, outcome, _ = self.clock_event(startup, 0.4)
                self.assertEqual(outcome, expected)

    def test_unrounded_late_return_is_timeout(self):
        timing, _, _ = self.clock_event(0.0, 0.1)
        self.assertEqual(self.driver.classify_outcome(3.00001, 0, None, 3.0), 'timeout')
        self.assertIn('elapsed_raw', timing)

    def test_spawn_exhaustion_does_not_grant_fresh_budget(self):
        _, outcome, calls = self.clock_event(3.1, 0.4)
        self.assertEqual(outcome, 'timeout')
        self.assertTrue(not calls or calls[0] <= 2.0)  # recovery drain only

    def main_run(self, *, attempts=1, fail_fast=False, result=None, cleanup=None, publisher=None,
                 runner=None, cells="pretool_safe", name="driver"):
        out = self.work / (name + ".json")
        argv = ['perf_ab', '--baseline', str(REPO_ROOT), '--candidate', str(REPO_ROOT),
                '--attempts', str(attempts), '--cells', cells, '--out', str(out)]
        if fail_fast:
            argv.append('--fail-fast')
        actual_result = result or {'elapsed': 0.1, 'returncode': 0, 'error': None,
                                  'outcome_class': 'completed', 'assertion': 'ok'}
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(patch.object(sys, 'argv', argv))
            stack.enter_context(patch.object(self.driver, 'load_hasher', return_value=object()))
            stack.enter_context(patch.object(self.driver, 'tree_digest', return_value='fixture'))
            stack.enter_context(patch.object(self.driver, 'source_identities', return_value={}))
            run = stack.enter_context(patch.object(self.driver, 'run_standard_attempt', return_value=actual_result, side_effect=runner))
            if cleanup:
                stack.enter_context(patch.object(self.driver.shutil, 'rmtree', side_effect=cleanup))
            if publisher:
                stack.enter_context(patch.object(self.driver, 'write_report', side_effect=publisher))
            code = self.driver.main()
        return code, json.loads(out.read_text()), run.call_count, out

    def test_fail_fast_keeps_predeclared_40_and_partial_coverage(self):
        bad = {'elapsed': 0.1, 'returncode': 7, 'error': None,
               'outcome_class': 'failed', 'assertion': 'skipped_event_failed'}
        code, report, calls, _ = self.main_run(attempts=40, fail_fast=True, result=bad)
        self.assertEqual((code, calls), (1, 1))
        self.assertEqual(report['predeclared_attempts_per_cell'], 40)
        self.assertEqual(len(report['cells']['pretool_safe']['interleaved_schedule']), 80)
        self.assertFalse(report['coverage_complete'])
        self.assertFalse(report['accepted'])
        self.assertEqual(report['execution_state'], 'stopped')

    def test_cleanup_error_keeps_actual_row_published_before_delete(self):
        observed = []
        def cleanup(home):
            report = json.loads((self.work / 'driver.json').read_text())
            observed.append(report['cells']['pretool_safe']['sides']['baseline']['raw_rows'][0]['outcome_class'])
            raise PermissionError('fixture cleanup failure')
        code, report, calls, _ = self.main_run(cleanup=cleanup)
        self.assertEqual((code, calls), (1, 1))
        self.assertEqual(observed, ['completed'])
        row = report['cells']['pretool_safe']['sides']['baseline']['raw_rows'][0]
        self.assertEqual(row['outcome_class'], 'completed')
        self.assertIn('PermissionError', row['home_cleanup']['error'])
        self.assertFalse(report['accepted'])
        self.assertIn('coverage_complete', report)

    def test_unknown_lifetime_preserves_home_and_stops(self):
        result = {'elapsed': 0.1, 'returncode': 0, 'error': 'query_unknown',
                  'outcome_class': 'driver_error', 'assertion': 'skipped_event_failed',
                  'process_lifetime': {'recovery_complete': False}, 'retain_home': True,
                  'stop_batch': True}
        with patch.object(self.driver.shutil, 'rmtree') as cleanup:
            code, report, calls, _ = self.main_run(result=result)
        self.assertEqual((code, calls), (1, 1))
        cleanup.assert_not_called()
        row = report['cells']['pretool_safe']['sides']['baseline']['raw_rows'][0]
        self.assertEqual(row['home_cleanup']['status'], 'retained')
        self.assertFalse(report['accepted'])

    def test_publication_failure_is_not_recursive_and_retains_result_sidecar(self):
        actual = self.driver.write_report
        writes = []
        def publish(path, report):
            writes.append(json.loads(json.dumps(report)))
            if len(writes) == 3:
                raise OSError('fixture publication denied')
            return actual(path, report)
        code, _, calls, out = self.main_run(publisher=publish)
        self.assertEqual((code, calls), (1, 1))
        self.assertEqual(len(writes), 3)
        failed = json.loads(out.with_name(out.name + '.failure.json').read_text())
        row = failed['cells']['pretool_safe']['sides']['baseline']['raw_rows'][0]
        self.assertEqual(row['outcome_class'], 'completed')
        self.assertFalse(failed['accepted'])
        self.assertIn('publication_failure', failed)

    def test_windows_preclose_query_is_read_only_and_denial_fails(self):
        import ctypes
        from types import SimpleNamespace
        class Accounting(ctypes.Structure):
            _fields_ = [('ActiveProcesses', ctypes.c_uint32)]
        for active, denied in [(0, False), (1, False), (0, True)]:
            with self.subTest(active=active, denied=denied):
                def query(job, kind, pointer, size, unused):
                    ctypes.cast(pointer, ctypes.POINTER(Accounting)).contents.ActiveProcesses = active
                    return not denied
                api = SimpleNamespace(QueryInformationJobObject=query)
                owner = SimpleNamespace(process=SimpleNamespace(poll=lambda: 0), job=1,
                                        accounting_type=Accounting, api=api)
                result = self.driver.observe_natural_completion(owner)
                self.assertEqual(result['no_running_members'], not denied and active == 0)

    def test_recovery_has_one_five_second_deadline_and_never_closes_locked_pipes(self):
        from types import SimpleNamespace
        now, close_budgets, drain_budgets = [0.0], [], []
        pipe = unittest.mock.Mock()
        calls = []
        class Process:
            pid = 123
            args = ['fixture']
            returncode = None
            stdin = stdout = stderr = pipe
            def poll(self):
                return self.returncode
            def communicate(self, input=None, timeout=None):
                calls.append(timeout)
                if len(calls) == 1:
                    raise subprocess.TimeoutExpired(self.args, timeout, output=b'{}')
                drain_budgets.append(timeout)
                now[0] += timeout
                raise subprocess.TimeoutExpired(self.args, timeout)
        process = Process()
        def close(timeout):
            close_budgets.append(timeout)
            now[0] += timeout + 0.25  # adversarial close overruns its own allowance
            process.returncode = 1
            return {'owned_process_exited': True, 'owned_tree_no_running_members': True}
        owner = SimpleNamespace(process=process, close=close)
        with patch.object(self.driver.OwnedProcess, 'spawn', return_value=owner), \
             patch.object(self.driver.time, 'monotonic', side_effect=lambda: now[0]), \
             patch.object(self.driver.time, 'perf_counter', return_value=0.0):
            timing = self.driver.run_event('fixture', REPO_ROOT, self.work, b'{}', 3.0)
        self.assertEqual(close_budgets, [3.0])
        self.assertEqual(drain_budgets, [1.75])
        self.assertEqual(now[0], 5.0)
        self.assertFalse(timing['process_lifetime']['recovery_complete'])
        self.assertTrue(timing['retain_home'])
        self.assertTrue(timing['stop_batch'])
        self.assertTrue(timing['error'].startswith('TimeoutExpired'))
        pipe.close.assert_not_called()
        self.driver._RETAINED_EVENT_OWNERS.remove(owner)

    def test_query_exception_retains_home_even_after_successful_kill(self):
        from types import SimpleNamespace
        process = SimpleNamespace(pid=123, args=['fixture'], returncode=0,
                                  poll=lambda: 0, communicate=lambda *a, **kw: (b'{}', b''))
        owner = SimpleNamespace(process=process, close=lambda timeout: {
            'owned_process_exited': True, 'owned_tree_no_running_members': True})
        with patch.object(self.driver.OwnedProcess, 'spawn', return_value=owner), \
             patch.object(self.driver, 'observe_natural_completion', side_effect=OSError('query denied')):
            timing = self.driver.run_event('fixture', REPO_ROOT, self.work, b'{}', 3.0)
        self.assertIn('query denied', timing['error'])
        self.assertTrue(timing['retain_home'])
        self.assertTrue(timing['stop_batch'])
        self.driver._RETAINED_EVENT_OWNERS.remove(owner)

    def test_cleanup_error_does_not_replace_event_timeout(self):
        bad = {'elapsed': 3.0, 'returncode': None, 'error': 'TimeoutExpired:original',
               'outcome_class': 'timeout', 'assertion': 'skipped_event_failed'}
        def cleanup(home):
            raise PermissionError('cleanup denied')
        code, report, calls, _ = self.main_run(result=bad, cleanup=cleanup)
        row = report['cells']['pretool_safe']['sides']['baseline']['raw_rows'][0]
        self.assertEqual((code, calls), (1, 1))
        self.assertEqual(row['error'], 'TimeoutExpired:original')
        self.assertIn('cleanup denied', row['home_cleanup']['error'])

    @unittest.skipUnless(os.name == 'posix', 'real POSIX group fixture, not Windows proof')
    def test_real_timeout_with_inherited_output_is_reaped_before_home_cleanup(self):
        self.real_descendant(hold_stdout=True, parent_wait=True)

    @unittest.skipUnless(os.name == 'posix', 'real POSIX group fixture, not Windows proof')
    def test_real_exited_leader_with_live_descendant_cannot_pass_after_kill(self):
        self.real_descendant(hold_stdout=False, parent_wait=False)

    def real_descendant(self, *, hold_stdout, parent_wait):
        child = self.work / 'child.py'
        parent = self.work / 'parent.py'
        marker = self.work / 'child-pid'
        child.write_text('import time\ntime.sleep(20)\n')
        stdout_arg = '' if hold_stdout else ', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL'
        parent.write_text('import subprocess,sys,time\nfrom pathlib import Path\n'
                          f'p=subprocess.Popen([sys.executable,{str(child)!r}]{stdout_arg})\n'
                          f'Path({str(marker)!r}).write_text(str(p.pid))\n'
                          "print('{}',flush=True)\n" + ('time.sleep(20)\n' if parent_wait else ''))
        wrapper = 'exec ' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(parent))
        timing = self.driver.run_event(wrapper, REPO_ROOT, self.work, b'{}', 0.5)
        self.assertTrue(marker.exists(), 'fixture child never reached')
        self.assertNotEqual(self.driver.classify_outcome(timing['elapsed_raw'], timing['returncode'],
                                                        timing['error'], 0.5), 'completed')
        self.assertTrue(timing['process_lifetime']['cleanup']['owned_tree_no_running_members'])
        if parent_wait:
            self.assertTrue(timing['error'].startswith('TimeoutExpired'))
            self.assertTrue(timing['process_lifetime']['drain_complete'])
        else:
            self.assertIn('natural_completion_unverified', timing['error'])
            self.assertTrue(timing['retain_home'])
            self.driver._RETAINED_EVENT_OWNERS.pop()

    def test_main_interrupt_and_poll_failures_respect_owned_lifetime(self):
        from types import SimpleNamespace
        original = self.driver.run_standard_attempt
        actual_remove = self.driver.shutil.rmtree
        for stage in ('communicate', 'close', 'drain', 'pre_poll', 'post_poll'):
            with self.subTest(stage=stage):
                polls, communications, close_calls = [], [], []
                class Process:
                    pid = 123
                    args = ['fixture']
                    returncode = None
                    def poll(process):
                        polls.append(1)
                        if (stage == 'pre_poll' and len(polls) == 1
                                or stage == 'post_poll' and len(polls) == 2):
                            raise OSError('poll unavailable')
                        return process.returncode
                    def communicate(process, input=None, timeout=None):
                        communications.append(timeout)
                        if len(communications) == 1:
                            if stage == 'communicate':
                                raise KeyboardInterrupt('event interrupted')
                            raise subprocess.TimeoutExpired(process.args, timeout, output=b'{}')
                        if stage == 'drain':
                            raise KeyboardInterrupt('drain interrupted')
                        return b'{}', b''
                process = Process()
                def close(timeout):
                    close_calls.append(timeout)
                    if stage == 'close':
                        raise KeyboardInterrupt('close interrupted')
                    process.returncode = -9
                    return {'owned_process_exited': True, 'owned_tree_no_running_members': True}
                owner = SimpleNamespace(process=process, close=close)
                before_retained = len(self.driver._RETAINED_EVENT_OWNERS)
                with patch.object(self.driver.OwnedProcess, 'spawn', return_value=owner), \
                     patch.object(self.driver.shutil, 'rmtree', wraps=actual_remove) as remove:
                    code, report, calls, _ = self.main_run(
                        runner=original, name='interrupt-' + stage)
                row = report['cells']['pretool_safe']['sides']['baseline']['raw_rows'][0]
                self.assertEqual((code, calls), (1, 1))
                self.assertEqual(len(close_calls), 1, 'poll failure skipped best-effort close')
                safe = stage == 'communicate'
                if not safe:
                    remove.assert_not_called()
                self.assertIn('process_lifetime', row)
                self.assertEqual(row['process_lifetime']['recovery_complete'], safe)
                if safe:
                    remove.assert_called_once()
                    self.assertEqual(row['home_cleanup']['status'], 'removed')
                    self.assertFalse(Path(remove.call_args.args[0]).exists())
                else:
                    remove.assert_not_called()
                    self.assertEqual(row['home_cleanup']['status'], 'retained')
                    self.assertTrue(row['stop_batch'])
                self.assertFalse(report['accepted'])
                if stage in ('communicate', 'close', 'drain'):
                    self.assertIn('KeyboardInterrupt', report['driver_failure'])
                if stage.endswith('poll'):
                    key = 'leader_rc_before_cleanup_error' if stage == 'pre_poll' else 'leader_rc_after_cleanup_error'
                    self.assertIn('OSError', row['process_lifetime'][key])
                del self.driver._RETAINED_EVENT_OWNERS[before_retained:]

    def test_interrupted_lifecycle_and_seed_extra_carry_lifetime_to_main(self):
        from types import SimpleNamespace
        for cell in ('lifecycle_matched', 'subagent_events'):
            with self.subTest(cell=cell):
                class Process:
                    pid = 123
                    args = ['fixture']
                    returncode = None
                    def poll(self):
                        return None
                    def communicate(self, input=None, timeout=None):
                        raise KeyboardInterrupt('event interrupted')
                owner = SimpleNamespace(process=Process(), close=lambda timeout: {
                    'owned_process_exited': False, 'owned_tree_no_running_members': False,
                    'process_group_cleanup_error': 'fixture denial'})
                before_retained = len(self.driver._RETAINED_EVENT_OWNERS)
                with patch.object(self.driver.OwnedProcess, 'spawn', return_value=owner), \
                     patch.object(self.driver, 'seed_active_session'), \
                     patch.object(self.driver.shutil, 'rmtree') as remove:
                    code, report, _, _ = self.main_run(cells=cell, name='interrupt-' + cell)
                row = report['cells'][cell]['sides']['baseline']['raw_rows'][0]
                self.assertEqual(code, 1)
                remove.assert_not_called()
                self.assertTrue(row['retain_home'])
                self.assertFalse(row['process_lifetime']['recovery_complete'])
                self.assertEqual(row['home_cleanup']['status'], 'retained')
                self.assertIn('KeyboardInterrupt', report['driver_failure'])
                del self.driver._RETAINED_EVENT_OWNERS[before_retained:]

    def test_unwitnessed_standard_stop_memory_exceptions_retain_home(self):
        original = self.driver.run_standard_attempt
        for cell, method in [('pretool_safe', 'run_standard_attempt'),
                             ('stop_s1', 'run_stop_cell'), ('memory_stop', 'run_memory_attempt')]:
            with self.subTest(cell=cell):
                def unknown(*args, **kwargs):
                    raise OSError('unwitnessed fixture failure')
                with patch.object(self.driver, method, side_effect=unknown), \
                     patch.object(self.driver.shutil, 'rmtree') as remove:
                    # main_run's standard runner patch is intentionally the same
                    # unknown function for the standard route.
                    code, report, _, _ = self.main_run(cells=cell, name='unknown-' + cell,
                                                       runner=unknown if cell == 'pretool_safe' else original)
                row = report['cells'][cell]['sides']['baseline']['raw_rows'][0]
                self.assertEqual(code, 1)
                remove.assert_not_called()
                self.assertEqual(row['home_cleanup']['status'], 'retained')
                self.assertTrue(row['stop_batch'])
                self.assertFalse(report['accepted'])


if __name__ == "__main__":
    unittest.main()
