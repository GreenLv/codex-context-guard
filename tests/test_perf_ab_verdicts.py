"""RV-05 (sixth round): the A/B verdict gate must judge every gated
(metric, statistic) pair on its own — a tail-only regression whose median
cannot move is still a declared slowdown, never folded into noise."""
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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


class PerfVerdictEncodingTests(unittest.TestCase):
    def test_utf8_input_and_output_survive_cp1252_default_io(self):
        raw = _raw([1.0, 1.0], [1.0, 1.0])
        raw["identities"]["label"] = "证据 路径"
        original = json.dumps(raw, ensure_ascii=False).encode("utf-8")
        expected = (json.dumps(verdicts.verdicts_from_raw(raw), indent=1) + "\n").replace("\n", os.linesep).encode("utf-8")
        # Patch Path.open: Python 3.10 caches io.open in its path accessor.
        actual_open = Path.open
        opened = []
        def cp1252_open(file, mode="r", buffering=-1, encoding=None, *args, **kwargs):
            if "b" not in mode and encoding in (None, "locale"):
                encoding = "cp1252"
            opened.append((Path(file), mode, encoding))
            return actual_open(file, mode, buffering, encoding, *args, **kwargs)
        with tempfile.TemporaryDirectory() as temporary:
            raw_path = Path(temporary) / "原始 输入.json"
            target = Path(temporary) / "统计 输出.json"
            raw_path.write_bytes(original)
            with patch.object(io, "text_encoding", side_effect=lambda encoding, *_: (
                        "locale" if encoding is None else encoding)), \
                 patch.object(Path, "open", new=cp1252_open), \
                 patch("sys.stdout", new_callable=io.StringIO):
                with self.assertRaises(UnicodeDecodeError):
                    raw_path.read_text()
                self.assertEqual(verdicts.main([str(raw_path), "--out", str(target)]), 0)
            self.assertEqual(raw_path.read_bytes(), original)
            self.assertEqual(target.read_bytes(), expected)
            self.assertEqual(json.loads(target.read_bytes())["identities"], raw["identities"])
            # Output JSON still escapes Unicode under its original format, so
            # bytes alone cannot distinguish cp1252 from UTF-8 on that write.
            self.assertIn((target, "w", "utf-8"), opened)
            self.assertIn((raw_path, "r", "utf-8"), opened)


if __name__ == "__main__":
    unittest.main()
