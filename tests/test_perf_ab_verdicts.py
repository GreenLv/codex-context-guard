"""RV-05 (sixth round): the A/B verdict gate must judge every gated
(metric, statistic) pair on its own — a tail-only regression whose median
cannot move is still a declared slowdown, never folded into noise."""
import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = (Path(__file__).resolve().parents[1]
               / "tools" / "validation" / "perf_ab_verdicts.py")
SPEC = importlib.util.spec_from_file_location("perf_ab_verdicts", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
verdicts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verdicts)


def _rows(values):
    return [{"elapsed": v, "outcome_class": "completed", "assertion": "ok"}
            for v in values]


def _raw(baseline_values, candidate_values):
    return {"cells": {"synthetic-cell": {"sides": {
        "baseline": {"raw_rows": _rows(baseline_values)},
        "candidate": {"raw_rows": _rows(candidate_values)}}}},
        "identities": {"synthetic": True}}


class PerfVerdictGateTests(unittest.TestCase):
    def test_tail_only_regression_is_declared(self) -> None:
        """The persistent tail-oracle negative control: baseline 40 identical
        samples, candidate 30 identical + 10 doubled. The median LoCI is
        exactly 1.0 and cannot trigger; the nearest-rank p95 LoCI is 2.0 and
        must declare the cell on its own (the sixth review found a generator
        that gated on the median only)."""
        report = verdicts.verdicts_from_raw(verdicts.synthetic_tail_only())
        cell = report["verdicts"]["synthetic-tail-only-regression"]
        self.assertEqual(cell["verdict"], "DECLARED-SLOWER(p95)")
        self.assertLessEqual(cell["median_elapsed_lo99"], 1.0)
        self.assertGreater(cell["p95_elapsed_lo99"], 1.0)
        self.assertTrue(report["declared_regressions"])
        pair = report["declared_regressions"][0]
        self.assertEqual(pair["metric"], "elapsed")
        self.assertEqual(pair["statistic"], "p95")

    def test_median_only_regression_is_declared(self) -> None:
        """A uniform median shift declares on the median statistic even when
        the tail moves with it."""
        report = verdicts.verdicts_from_raw(_raw([1.0] * 40, [1.1] * 40))
        cell = report["verdicts"]["synthetic-cell"]
        self.assertEqual(cell["verdict"], "DECLARED-SLOWER(median)")
        self.assertGreater(cell["median_elapsed_lo99"], 1.0)

    def test_identical_samples_declare_nothing(self) -> None:
        """No-regression control: identical distributions must produce no
        declared pairs (the false-positive calibration shape)."""
        report = verdicts.verdicts_from_raw(_raw([1.0] * 40, [1.0] * 40))
        self.assertEqual(report["declared_regressions"], [])
        self.assertEqual(report["verdicts"]["synthetic-cell"]["verdict"],
                         "not-distinguishable-from-noise")

    def test_builtin_tail_oracle_check_passes(self) -> None:
        """The tool's own negative-control mode must keep declaring the
        synthetic tail-only regression."""
        report = verdicts.verdicts_from_raw(verdicts.synthetic_tail_only())
        cell = report["verdicts"]["synthetic-tail-only-regression"]
        self.assertEqual(cell["verdict"], "DECLARED-SLOWER(p95)")
        self.assertTrue(any(p["statistic"] == "p95"
                            for p in report["declared_regressions"]))


if __name__ == "__main__":
    unittest.main()
