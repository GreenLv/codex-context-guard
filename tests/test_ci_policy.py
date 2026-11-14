"""Profile selection and summary fail-closed regressions."""
import hashlib
import json
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
                     '.codex-plugin/plugin.json', 'scripts/artifact_identity.py',
                     'scripts/run-context-guard.ps1', 'docs/COMPATIBILITY.md', 'unknown/new.file'):
            with self.subTest(path=path):
                self.assertEqual(policy.select_profile('auto', [path]), 'full')
        self.assertEqual(policy.select_profile('auto', ['README.md', 'scripts/context_guard.py', 'tests/test_example.py']), 'daily')
        self.assertEqual(policy.select_profile('full', []), 'full')
        self.assertEqual(policy.select_profile('daily', ['.github/workflows/ci.yml']), 'full')
        with self.assertRaises(ValueError):
            policy.select_profile('typo', [])

    def test_release_builder_changes_require_full_coverage(self):
        self.assertEqual(policy.select_profile('auto', ['scripts/build_release_artifact.py']), 'full')
        self.assertEqual(policy.select_profile('daily', ['README.md', 'scripts/build_release_artifact.py']), 'full')

    def test_only_version_changes_can_be_waived(self):
        fixtures = {
            'pyproject.toml': '[project]\nname = "x"\nversion = "0.1"\nrequires-python = ">=3.10"\n',
            'uv.lock': '[[package]]\nname = "codex-context-guard"\nversion = "0.1"\nsource = { virtual = "." }\n',
            '.codex-plugin/plugin.json': '{"version":"0.1","name":"context-guard"}',
        }
        for path, before in fixtures.items():
            with self.subTest(path=path):
                after = before.replace('0.1', '0.2')
                if path.endswith(('.toml', '.lock')) and policy.tomllib is None:
                    self.assertFalse(policy.version_only(path, before, after))
                    continue
                self.assertTrue(policy.version_only(path, before, after))
                self.assertFalse(policy.version_only(path, before, after.replace('context-guard', 'other')) if path != 'pyproject.toml' else policy.version_only(path, before, after.replace('>=3.10', '>=3.11')))
                self.assertEqual(policy.select_profile('auto', [path], {path}), 'daily')
                self.assertEqual(policy.select_profile('auto', [path, 'unknown/new.file'], {path}), 'full')
        self.assertFalse(policy.version_only('.codex-plugin/plugin.json',
            '{"version":"0.1","name":"x","name":"y"}',
            '{"version":"0.2","name":"x","name":"y"}'))

    def test_manifest_waiver_requires_changed_blob_identity(self):
        blob = {('base', 'docs/CI_POLICY.md'): b'old', ('head', 'docs/CI_POLICY.md'): b'new'}
        def manifest(key):
            files = {'docs/CI_POLICY.md': hashlib.sha256(blob[(key, 'docs/CI_POLICY.md')]).hexdigest()}
            return json.dumps({'schema': 'cg-distribution-manifest/v1', 'file_count': 1, 'files': files})
        old, new = manifest('base'), manifest('head')
        def read(rev, path):
            return blob[(rev, path)]
        self.assertTrue(policy.manifest_only(old, new, ['docs/CI_POLICY.md'], set(), read))
        self.assertFalse(policy.manifest_only(old, new, [], set(), read))
        blob[('head', 'docs/CI_POLICY.md')] = b'bad'
        self.assertFalse(policy.manifest_only(old, new, ['docs/CI_POLICY.md'], set(), read))
        self.assertFalse(policy.manifest_only(old, new.replace('CI_POLICY.md', '../CI_POLICY.md'),
                                              ['docs/CI_POLICY.md'], set(), read))

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

    def test_reuse_requires_the_full_profile_and_the_evidence_job(self):
        with self.assertRaises(ValueError):
            policy.required_jobs('daily', False, reuse=True)
        with self.assertRaises(ValueError):
            policy.verify('daily', False, {}, reuse=True)
        required = policy.required_jobs('full', False, reuse=True)
        self.assertEqual(required, ['classify', 'static', 'ci_reuse'])
        needs = {'classify': {'result': 'success'}, 'static': {'result': 'success'},
                 'ci_reuse': {'result': 'success'}}
        self.assertEqual(policy.verify('full', False, needs, reuse=True)['passed'],
                         ['ci_reuse', 'classify', 'static'])
        # The reuse evidence job itself is never exempt.
        needs['ci_reuse'] = {'result': 'skipped'}
        with self.assertRaises(SummaryError):
            policy.verify('full', False, needs, reuse=True)

    def test_reuse_never_lets_any_other_job_fail_or_cancel(self):
        all_jobs = set(policy.required_jobs('full', True)) | set(policy.DAILY_FOCUSED)
        base = {'classify': {'result': 'success'}, 'static': {'result': 'success'},
                'ci_reuse': {'result': 'success'}}
        for job in sorted(all_jobs - set(base)):
            for status in ('failure', 'cancelled'):
                with self.subTest(job=job, status=status):
                    needs = dict(base)
                    needs[job] = {'result': status}
                    with self.assertRaises(SummaryError):
                        policy.verify('full', True, needs, reuse=True)

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
