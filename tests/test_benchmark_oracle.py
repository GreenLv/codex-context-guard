"""Benchmark oracle negative controls (review R3 family closure).

A timing gate may never pass on a wrong business result. Each test feeds the
runner a forged-but-fast hook record or instrument gap from the review's
counterexample family (fail-closed JSON, blocked JSON, missing counters,
pretool decision, no-overwrite) and proves the runner rejects it.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools" / "validation"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import benchmark_stop as benchmark  # noqa: E402


def fake_record(**overrides):
    record = {"classification": "completed", "wall": 0.01,
              "returncode": 0, "stderr": "",
              "stdout_json": {}, "decision_log_len": 999,
              "integrity": "ok", "residual_lock": False,
              "final_outcome": "silent_end_owner_ambiguous",
              "final_turn": "t-final"}
    record.update(overrides)
    return record


class BenchmarkOracleTests(unittest.TestCase):
    def run_process_with(self, record, shape="S0"):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(benchmark, "_run_hook_cli",
                                   return_value=record):
                return benchmark.run_process_mode(shape, 1,
                                                  Path(directory))

    def test_wrong_fail_closed_stdout_rejected(self):
        result = self.run_process_with(fake_record(
            stdout_json={"continue": False,
                         "stopReason": "synthetic fail-closed decision"}))
        self.assertEqual(result["verdict"], "failed")
        self.assertTrue(any("stdout" in p and "oracle" in p
                            for p in result.get("problems", [])),
                        result.get("problems"))

    def test_wrong_blocked_stdout_rejected(self):
        result = self.run_process_with(fake_record(
            stdout_json={"decision": "block", "reason": "fast but wrong"}))
        self.assertEqual(result["verdict"], "failed")

    def test_wrong_decision_outcome_rejected(self):
        result = self.run_process_with(fake_record(final_outcome="visible_correction"))
        self.assertEqual(result["verdict"], "failed")
        self.assertTrue(any("outcome/turn" in p for p in result["problems"]))

    def test_wrong_turn_binding_rejected(self):
        result = self.run_process_with(fake_record(final_turn="other-turn"))
        self.assertEqual(result["verdict"], "failed")
        self.assertTrue(any("outcome/turn" in p for p in result["problems"]))

    def test_missing_decision_growth_rejected(self):
        # gold fixture has zero prior decisions; a sample claiming exactly
        # the baseline count never appended this event's decision.
        result = self.run_process_with(fake_record(decision_log_len=0))
        self.assertEqual(result["verdict"], "failed")
        self.assertTrue(any("did not grow" in p for p in result["problems"]))

    def test_missing_counter_key_rejected_in_count_mode(self):
        import context_guard as cg

        with tempfile.TemporaryDirectory() as root:
            built = {"counters": {}, "state_integrity": "ok",
                     "stop_event": {}, "session_dir": Path(root)}
            with mock.patch.object(benchmark.fixture, "build_session",
                                   return_value=built), \
                 mock.patch.object(cg, "dispatch", return_value={}) as disp:
                report = benchmark.run_count_mode("S0", Path(root))
        self.assertTrue(disp.called)
        self.assertEqual(report["verdict"], "failed")
        self.assertTrue(any("missing counter" in f for f in report["failures"]),
                        report["failures"])

    def test_pretool_decision_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(benchmark, "_run_hook_cli",
                                   return_value=fake_record(
                                       stdout_json={"decision": "block"})):
                result = benchmark.run_pretool_mode(1, Path(directory))
        self.assertEqual(result["verdict"], "failed")
        self.assertIn("silently allowed", result.get("error", ""))

    def test_environment_vs_candidate_failure_split(self):
        self.assertEqual(benchmark._classify_subprocess_failure(
            "SyntaxError: invalid syntax"), "failed")
        self.assertEqual(benchmark._classify_subprocess_failure(
            "ModuleNotFoundError: No module named 'x'"),
            "environment_unavailable")

    def test_report_file_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "out.json"
            target.write_text("existing result", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "tools/validation/benchmark_stop.py",
                 "--mode", "count", "--shape", "S0", "--json", str(target)],
                capture_output=True, text=True, cwd=str(REPO_ROOT),
                timeout=300)
            self.assertEqual(completed.returncode, 3)
            self.assertIn("refusing to overwrite", completed.stderr)
            self.assertEqual(target.read_text(encoding="utf-8"),
                             "existing result")


if __name__ == "__main__":
    unittest.main()
