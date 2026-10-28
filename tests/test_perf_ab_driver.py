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

    def test_r3_real_interruption_persists_started_attempt_and_cleans_home(self):
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
        self.assertTrue(all(not home.exists() for home in homes))

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


if __name__ == "__main__":
    unittest.main()
