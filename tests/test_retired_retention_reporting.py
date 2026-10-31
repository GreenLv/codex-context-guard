"""Retirement is an explicit report, never a passing or silently filtered test."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("current_runner_retirement", ROOT / "scripts/run_current_behavior_suite.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class RetiredRetentionReporting(unittest.TestCase):
    def test_manifest_matches_explicit_skips_and_preserves_original_xfail(self):
        rows = runner.load_retired_retention_tests()
        self.assertEqual(len(rows), 30)
        previous_xfails = [node for node, row in rows.items() if row["previous_expected_failure"]]
        self.assertEqual(previous_xfails, ["tests.test_cg0160_repair_family.RV03BoundedEnumeration.test_longer_decided_prefix_still_reaches_the_tail"])
        suite = unittest.defaultTestLoader.loadTestsFromNames(list(rows))
        result = unittest.TestResult()
        suite.run(result)
        self.assertEqual(result.failures, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.expectedFailures, [])
        self.assertEqual(len(result.skipped), len(rows))
        self.assertTrue(all(reason.startswith(runner.RETIRED_RETENTION_PREFIX) for _, reason in result.skipped))
        self.assertEqual({test.id() for test, _ in result.skipped}, set(rows))

    def test_tampered_method_digest_is_rejected(self):
        record = json.loads((ROOT / "tests/retired_retention_cleanup.json").read_text(encoding="utf-8"))
        record["tests"][0]["original_source_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                runner.load_retired_retention_tests(path)

    def test_official_main_reports_retirement_and_prior_xfail_without_counting_pass(self):
        import contextlib
        import io
        import sys
        import types
        from unittest import mock

        module = types.ModuleType("tests.synthetic_retirement_report")

        @unittest.skip(runner.RETIRED_RETENTION_PREFIX + " synthetic explicit retirement")
        @unittest.expectedFailure
        def method(self):
            self.fail("retired former limitation")

        case = type("Retired", (unittest.TestCase,), {"test_retired": method})
        case.__module__ = module.__name__
        module.Retired = case
        node = module.__name__ + ".Retired.test_retired"
        row = {"node": node, "previous_expected_failure": True, "reason": "synthetic retired limitation"}
        stdout = io.StringIO()
        with mock.patch.dict(sys.modules, {module.__name__: module}), \
                mock.patch.object(runner, "discover_current_modules", return_value=["synthetic_retirement_report"]), \
                mock.patch.object(runner, "load_retired_retention_tests", return_value={node: row}), \
                mock.patch.object(sys, "argv", ["runner"]), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(runner.main(), 0)
        summary = json.loads(stdout.getvalue().splitlines()[0])
        self.assertEqual(summary["retired_tests"], [row])
        self.assertEqual(summary["retired_expected_failures"], 1)
        self.assertEqual(summary["expected_failures"], 0)
        self.assertEqual(summary["skipped"], 1)

        # An actual explicit retirement without its manifest entry fails.
        with mock.patch.dict(sys.modules, {module.__name__: module}), \
                mock.patch.object(runner, "discover_current_modules", return_value=["synthetic_retirement_report"]), \
                mock.patch.object(runner, "load_retired_retention_tests", return_value={}), \
                mock.patch.object(sys, "argv", ["runner"]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertNotEqual(runner.main(), 0)

    def test_retained_method_body_tampering_is_rejected(self):
        from unittest import mock

        record = json.loads((ROOT / "tests/retired_retention_cleanup.json").read_text(encoding="utf-8"))
        row = record["tests"][0]
        record["tests"] = [row]
        _, module, _, method = row["node"].split(".")
        source = (ROOT / "tests" / (module + ".py")).read_text(encoding="utf-8")
        # Keep the explicit skip and xfail metadata intact, change only its body.
        start = source.index("    def " + method + "(")
        end = source.index("\n", start)
        source = source[:end + 1] + '        self.fail("synthetic retained-body mutation")\n' + source[end + 1:]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / (module + ".py")).write_text(source, encoding="utf-8")
            path = root / "manifest.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            with mock.patch.object(runner, "TESTS_DIR", root):
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    runner.load_retired_retention_tests(path)

    def test_retirement_baseline_xfail_and_node_mismatches_are_rejected(self):
        for field, replacement in (("source_commit", "0" * 40),
                                   ("previous_expected_failure", True),
                                   ("node", "tests.test_missing.Missing.test_missing")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                record = json.loads((ROOT / "tests/retired_retention_cleanup.json").read_text(encoding="utf-8"))
                record["tests"][0][field] = replacement
                path = Path(directory) / "manifest.json"
                path.write_text(json.dumps(record), encoding="utf-8")
                with self.assertRaises((ValueError, OSError)):
                    runner.load_retired_retention_tests(path)
