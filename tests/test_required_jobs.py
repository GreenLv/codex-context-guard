#!/usr/bin/env python3
"""Regression tests for fail-closed required-job summaries."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "tools" / "validation" / "verify_required_jobs.py"
SPEC = importlib.util.spec_from_file_location("verify_required_jobs", SCRIPT)
assert SPEC and SPEC.loader
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


class RequiredSummaryTests(unittest.TestCase):
    def test_accepts_all_required_successes(self) -> None:
        result = SUMMARY.evaluate(["static", "focused_tests"], {"static": "success", "focused_tests": "success", "optional": "skipped"})
        self.assertEqual(result["passed"], ["focused_tests", "static"])

    def test_rejects_missing_job(self) -> None:
        with self.assertRaisesRegex(SUMMARY.SummaryError, "missing=focused_tests"):
            SUMMARY.evaluate(["static", "focused_tests"], {"static": "success"})

    def test_rejects_skipped_cancelled_and_failed_jobs(self) -> None:
        for result in ("skipped", "cancelled", "failure"):
            with self.subTest(result=result), self.assertRaisesRegex(SUMMARY.SummaryError, "non_success=required"):
                SUMMARY.evaluate(["required"], {"required": result})


if __name__ == "__main__":
    unittest.main()
