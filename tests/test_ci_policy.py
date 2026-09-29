"""Profile selection and summary fail-closed regressions."""
import unittest
from unittest import mock

from tools.validation import ci_policy as policy
from tools.validation import run_windows_platform_suite as platform
from tools.validation.verify_required_jobs import SummaryError


class CIPolicyTests(unittest.TestCase):
    def test_daily_full_and_focused_coverage(self):
        jobs = policy.required_jobs('daily', False)
        self.assertEqual(set(jobs) - {'classify', 'static'}, policy.DAILY_FULL | set(policy.DAILY_FOCUSED))
        self.assertEqual(len(jobs), 8)
        full = policy.required_jobs('full', True)
        self.assertEqual(len(full), 18)
        self.assertTrue(all(row[0] in full for row in policy.CI_LANES))
        self.assertFalse(set(policy.DAILY_FOCUSED) & set(full))

    def test_sensitive_paths_and_unknowns_expand_but_routine_changes_do_not(self):
        for path in ('pyproject.toml', 'uv.lock', '.github/workflows/ci.yml',
                     '.codex-plugin/plugin.json', 'scripts/manage_plugin.py',
                     'scripts/run-context-guard.ps1', 'docs/COMPATIBILITY.md', 'unknown/new.file'):
            with self.subTest(path=path):
                self.assertEqual(policy.select_profile('auto', [path]), 'full')
        self.assertEqual(policy.select_profile('auto', ['README.md', 'scripts/context_guard.py', 'tests/test_example.py']), 'daily')
        self.assertEqual(policy.select_profile('full', []), 'full')
        self.assertEqual(policy.select_profile('daily', ['.github/workflows/ci.yml']), 'daily')
        with self.assertRaises(ValueError):
            policy.select_profile('typo', [])

    def test_every_required_failure_cancel_skip_or_absence_rejected(self):
        for profile in ('daily', 'full'):
            for portable in (True, False):
                required = policy.required_jobs(profile, portable)
                for job in required:
                    for status in ('failure', 'cancelled', 'skipped', None):
                        with self.subTest(profile=profile, portable=portable, job=job, status=status):
                            needs = {j: {'result': 'success'} for j in required}
                            if status is None:
                                del needs[job]
                            else:
                                needs[job]['result'] = status
                            with self.assertRaises(SummaryError):
                                policy.verify(profile, portable, needs)

    def test_only_unselected_jobs_may_skip(self):
        all_jobs = set(policy.required_jobs('full', True)) | set(policy.DAILY_FOCUSED)
        for profile in ('daily', 'full'):
            required = policy.required_jobs(profile, False)
            needs = {j: {'result': 'success' if j in required else 'skipped'} for j in all_jobs}
            self.assertEqual(policy.verify(profile, False, needs)['passed'], sorted(required))
        with self.assertRaises(ValueError):
            policy.verify('', False, {})

    def test_platform_runner_rejects_missing_empty_skipped_or_failed_modules(self):
        with self.assertRaises(ValueError):
            platform.run(())
        for total, skipped, success in ((0, 0, True), (2, 2, True), (1, 0, False)):
            result = mock.Mock(testsRun=total, skipped=[None] * skipped)
            result.wasSuccessful.return_value = success
            suite = mock.Mock()
            suite.countTestCases.return_value = total
            with mock.patch.object(platform.unittest.defaultTestLoader, 'loadTestsFromName', return_value=suite), mock.patch.object(platform.unittest, 'TextTestRunner') as runner:
                runner.return_value.run.return_value = result
                self.assertEqual(platform.run(('tests.fake',)), 1)


if __name__ == '__main__':
    unittest.main()
