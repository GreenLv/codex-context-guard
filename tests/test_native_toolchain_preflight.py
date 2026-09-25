"""Regression runner results must reflect terminal failures and exact inputs."""
import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tools.validation import native_toolchain_preflight as preflight


class NativeToolchainPreflightTests(unittest.TestCase):
    def evaluate(self, case, identities=("a" * 64, "a" * 64)):
        suite = unittest.TestSuite([case])
        with patch.object(preflight, "input_identity", side_effect=identities), \
                patch.object(unittest.TestLoader, "loadTestsFromNames", return_value=suite), \
                redirect_stderr(io.StringIO()):
            return preflight.evaluate(Path("."), checks=("synthetic",))

    def test_terminal_pass_retains_native_unknowns(self):
        result = self.evaluate(unittest.FunctionTestCase(lambda: None))
        self.assertEqual(result["status"], "synthetic_checks_passed")
        self.assertEqual(result["model_requests"], 0)
        self.assertEqual(result["native_acceptance"], "not_run")
        self.assertIn("live_hook_trust", result["unknown"])

    def test_failure_and_error_cannot_become_pass(self):
        for error in (AssertionError, RuntimeError):
            def fail(error=error):
                raise error("synthetic")
            with self.subTest(error=error):
                result = self.evaluate(unittest.FunctionTestCase(fail))
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["failures"] + result["errors"], 1)

    def test_input_drift_and_all_skipped_fail(self):
        result = self.evaluate(unittest.FunctionTestCase(lambda: None), ("a", "b"))
        self.assertEqual(result["status"], "failed")
        def skip():
            raise unittest.SkipTest("unsupported")
        self.assertEqual(self.evaluate(unittest.FunctionTestCase(skip))["status"], "coverage_incomplete")

    def test_non_checkout_fails_before_tests(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(unittest.TestLoader, "loadTestsFromNames") as load:
            with self.assertRaises((subprocess.CalledProcessError, ValueError)):
                preflight.evaluate(Path(tmp))
            load.assert_not_called()

    def test_disk_identity_includes_uncommitted_toolkit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "tools").mkdir()
            path = root / "tools/runner.py"
            path.write_text("before\n")
            subprocess.run(["git", "-C", str(root), "add", "tools"], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture",
                            "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                            "commit", "-qm", "fixture"], check=True)
            before = preflight.input_identity(root)
            path.write_text("after\n")
            self.assertNotEqual(before, preflight.input_identity(root))

    def test_output_is_reserved_empty_before_execution_and_never_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "receipt.json"
            def interrupted(_root):
                self.assertTrue(output.is_file())
                self.assertEqual(output.read_bytes(), b"")
                raise OSError("synthetic interruption")
            with patch.object(preflight.sys, "argv", ["preflight", "--output", str(output)]), \
                    patch.object(preflight, "evaluate", side_effect=interrupted), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main(), 2)
            self.assertEqual(output.read_bytes(), b"")
            with patch.object(preflight.sys, "argv", ["preflight", "--output", str(output)]), \
                    patch.object(preflight, "evaluate") as evaluate, \
                    redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    preflight.main()
                evaluate.assert_not_called()

    def test_empty_suite_fails(self):
        with patch.object(preflight, "input_identity", return_value="a"), \
                patch.object(unittest.TestLoader, "loadTestsFromNames", return_value=unittest.TestSuite()), \
                redirect_stderr(io.StringIO()):
            self.assertEqual(preflight.evaluate(Path("."))["status"], "failed")

    def test_unexpected_partial_skip_is_incomplete_even_with_passing_tests(self):
        def skip():
            raise unittest.SkipTest("unexpected host problem")
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None),
                                    unittest.FunctionTestCase(skip)])
        with patch.object(preflight, "input_identity", return_value="a"), \
                patch.object(unittest.TestLoader, "loadTestsFromNames", return_value=suite), \
                redirect_stderr(io.StringIO()):
            result = preflight.evaluate(Path("."))
        self.assertEqual(result["status"], "coverage_incomplete")
        self.assertEqual(len(result["unexpected_skips"]), 1)
        self.assertEqual(result["skip_details"][0]["reason"], "unexpected host problem")

    def test_windows_only_skips_are_allowed_only_off_windows(self):
        def skip():
            raise unittest.SkipTest("Windows-only")
        for host in ("Darwin", "Windows"):
            skipped = unittest.FunctionTestCase(skip)
            skipped.id = lambda: sorted(preflight.WINDOWS_ONLY)[0]
            suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None), skipped])
            with self.subTest(host=host), \
                    patch.object(preflight.platform, "system", return_value=host), \
                    patch.object(preflight, "input_identity", return_value="a"), \
                    patch.object(unittest.TestLoader, "loadTestsFromNames", return_value=suite), \
                    redirect_stderr(io.StringIO()):
                result = preflight.evaluate(Path("."))
            self.assertEqual(result["status"], "coverage_incomplete" if host == "Windows" else "synthetic_checks_passed")

    def test_incomplete_cli_is_nonzero_and_retains_result(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "receipt.json"
            with patch.object(preflight.sys, "argv", ["preflight", "--output", str(output)]), \
                    patch.object(preflight, "evaluate", return_value={"status": "coverage_incomplete"}), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main(), 3)
            self.assertEqual(json.loads(output.read_text())["status"], "coverage_incomplete")


if __name__ == "__main__":
    unittest.main()
