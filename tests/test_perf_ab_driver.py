#!/usr/bin/env python3
"""Negative controls for the formal A/B performance driver.

Each test drives perf_ab.py through a failure schedule (no-op Hook, malformed
output, child failure, semantic failure, timeout, seed failure, absent
identity, interrupted batch) and asserts the driver records the failure in
raw rows, blocks acceptance, exits nonzero, and preserves the partial report.
"""

from __future__ import annotations

import json
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


if __name__ == "__main__":
    unittest.main()
