"""The official suite consumer must propagate every unittest terminal
state. A test marked expectedFailure that unexpectedly passes is a broken
pin: the official entry point must fail the run (seventh review found the
consumer folding unexpected successes into an exit-0 pass). These controls
drive the unmodified official ``main`` with in-memory synthetic modules and
assert both directions."""
import contextlib
import importlib.util
import io
import json
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = (Path(__file__).resolve().parents[1]
               / "scripts" / "run_current_behavior_suite.py")
SPEC = importlib.util.spec_from_file_location("suite_consumer_under_test",
                                              MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def run_official_main(method, module_label):
    synthetic = types.ModuleType(f"tests.{module_label}")
    setattr(synthetic, "SyntheticCase",
            type("SyntheticCase", (unittest.TestCase,), {"test_case": method}))
    stdout, stderr = io.StringIO(), io.StringIO()
    with mock.patch.dict(sys.modules, {synthetic.__name__: synthetic}), \
            mock.patch.object(runner, "discover_current_modules",
                              return_value=[module_label]), \
            mock.patch.object(runner, "load_retired_retention_tests", return_value={}), \
            mock.patch.object(sys, "argv", ["run_current_behavior_suite.py"]), \
            contextlib.redirect_stdout(stdout), \
            contextlib.redirect_stderr(stderr):
        code = runner.main()
    # The official main prints the summary JSON first, then '!' failure
    # lines; the summary is therefore the first stdout line.
    return code, json.loads(stdout.getvalue().splitlines()[0])


class SuiteConsumerTerminalStateTests(unittest.TestCase):
    def test_ordinary_failure_fails_the_official_gate(self) -> None:
        """Positive control: an ordinary assertion failure must exit nonzero
        through the official main."""
        def method(self):
            self.fail("synthetic ordinary failure control")

        code, summary = run_official_main(method, "synthetic_consumer_fail")
        self.assertNotEqual(code, 0)
        self.assertEqual(summary["failures"], 1)

    def test_unexpected_success_fails_the_official_gate(self) -> None:
        """The seventh-review negative control: a test marked expectedFailure
        whose body passes must fail the official gate with an explicit
        unexpected-successes count — never folded into an exit-0 pass."""
        @unittest.expectedFailure
        def method(self):
            pass  # unexpectedly succeeds

        code, summary = run_official_main(method,
                                          "synthetic_consumer_xsuccess")
        self.assertNotEqual(code, 0)
        self.assertEqual(summary["unexpected_successes"], 1)
        self.assertEqual(summary["failures"], 0)

    def test_expected_failure_is_counted_and_passes_the_gate(self) -> None:
        """A genuinely failing expectedFailure is counted in its own column
        and does not fail the run."""
        @unittest.expectedFailure
        def method(self):
            self.fail("expected broken pin")

        code, summary = run_official_main(method,
                                          "synthetic_consumer_xfail")
        self.assertEqual(code, 0)
        self.assertEqual(summary["expected_failures"], 1)
        self.assertEqual(summary["unexpected_successes"], 0)

    def test_real_pass_is_counted_as_a_pass(self) -> None:
        """A passing test with no decorator counts as a true pass, distinct
        from expected failures and skips."""
        def method(self):
            pass

        code, summary = run_official_main(method, "synthetic_consumer_pass")
        self.assertEqual(code, 0)
        self.assertGreaterEqual(summary["tests"], 1)
        self.assertEqual(summary["failures"], 0)
        self.assertEqual(summary["expected_failures"], 0)
        self.assertEqual(summary["unexpected_successes"], 0)


if __name__ == "__main__":
    unittest.main()
