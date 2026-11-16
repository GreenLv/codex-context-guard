"""Profile selection and summary fail-closed regressions."""
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.validation import ci_policy as policy
from tools.validation import run_windows_platform_suite as platform
from tools.validation.verify_required_jobs import SummaryError


class CIPolicyTests(unittest.TestCase):
    def test_selected_profile_requires_every_owned_platform_lane(self):
        required = policy.required_jobs("tests", False)
        self.assertEqual(set(required), {"classify", "static", "ci_reuse", *policy.TEST_LANES})
        base = {job: {"result": "success"} for job in required}
        self.assertEqual(set(policy.verify("tests", False, base)["passed"]), set(required))
        for job in required:
            for failure in ("skipped", "failure", "cancelled", "missing"):
                with self.subTest(job=job, failure=failure):
                    observed = dict(base)
                    if failure == "missing":
                        del observed[job]
                    else:
                        observed[job] = {"result": failure}
                    with self.assertRaises(SummaryError):
                        policy.verify("tests", False, observed)
        for portable, reuse in ((True, False), (False, True)):
            with self.assertRaises(ValueError):
                policy.required_jobs("tests", portable, reuse)

    def test_pr_summary_enforces_all_selected_lanes_and_unknown_profile(self):
        selected = {job: {"result": "success"} for job in
                    ("classify", "selected_validation", *policy.TEST_LANES)}
        policy.verify_pr("tests", selected)
        for job in policy.TEST_LANES:
            for status in ("missing", "skipped", "failure", "cancelled"):
                observed = dict(selected)
                if status == "missing":
                    del observed[job]
                else:
                    observed[job] = {"result": status}
                with self.subTest(job=job, status=status), self.assertRaises(SummaryError):
                    policy.verify_pr("tests", observed)
        with self.assertRaises(ValueError):
            policy.verify_pr("", selected)
        with self.assertRaises(SummaryError):
            policy.verify_pr("daily", {"classify": {"result": "success"},
                                       "selected_validation": {"result": "success"},
                                       "selected_windows_py312": {"result": "failure"}})

    def test_static_importer_expands_its_registered_dynamic_family(self):
        source = (Path(__file__).resolve().parents[1] / "validation-map.json").read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL).decode().strip()
            git("init", "-q")
            (root / "tests").mkdir()
            (root / "validation-map.json").write_bytes(source)
            (root / "scripts").mkdir()
            runtime = root / "scripts/runtime.py"
            runtime.write_text("VERSION = 1\n", encoding="utf-8")
            (root / "tools/validation").mkdir(parents=True)
            controller = root / "tools/validation/ci_policy.py"
            controller.write_text("VERSION = 1\n", encoding="utf-8")
            owner = root / "tests/test_private_upgrade_output.py"
            original = "import unittest\nclass Owner(unittest.TestCase):\n    def test_old(self): pass\n"
            owner.write_text(original, encoding="utf-8")
            (root / "tests/test_native_between_turns_acceptance.py").write_text(
                "from tests.test_private_upgrade_output import Owner\n", encoding="utf-8")
            (root / "tests/test_native_between_turns_acceptance_families.py").write_text("import unittest\n", encoding="utf-8")
            (root / "tests/test_last.py").write_text(
                "from tests.test_native_between_turns_acceptance_families import helper\n", encoding="utf-8")
            git("add", ".")
            def commit():
                git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
                return git("rev-parse", "HEAD")
            base = commit()
            owner.write_text(original + "    def test_new(self): pass\n", encoding="utf-8")
            git("add", ".")
            head = commit()
            result = policy.test_modules_for_diff(root, base, head)
            self.assertEqual(set(result), {"tests.test_private_upgrade_output", "tests.test_native_between_turns_acceptance",
                                           "tests.test_native_between_turns_acceptance_families", "tests.test_last"})
            runtime.write_text("VERSION = 2\n", encoding="utf-8")
            self.assertIsNone(policy.test_modules_for_diff(root, base, head))
            runtime.write_text("VERSION = 1\n", encoding="utf-8")
            controller.write_text("VERSION = 2\n", encoding="utf-8")
            self.assertIsNone(policy.test_modules_for_diff(root, base, head))
            controller.write_text("VERSION = 1\n", encoding="utf-8")
            (root / "new_untracked.txt").write_text("x = 1\n", encoding="utf-8")
            self.assertIsNone(policy.test_modules_for_diff(root, base, head))

    def test_real_git_diff_selects_only_provable_test_methods(self):
        source = (Path(__file__).resolve().parents[1] / "validation-map.json").read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL).decode().strip()
            git("init", "-q")
            (root / "tests").mkdir()
            (root / "validation-map.json").write_bytes(source)
            test = root / "tests/test_daily_upgrade.py"
            for name in ("test_native_between_turns_acceptance.py", "test_native_between_turns_acceptance_families.py"):
                (root / "tests" / name).write_text("import unittest\n", encoding="utf-8")
            (root / "tests/test_reported_paths.py").write_text(
                "from tests.test_native_between_turns_acceptance import helper\n", encoding="utf-8")
            (root / "tests/test_indirect.py").write_text(
                "from tests.test_reported_paths import helper\n", encoding="utf-8")
            original = "import unittest\nclass Owner(unittest.TestCase):\n    def test_old(self): self.assertTrue(True)\n"
            test.write_text(original, encoding="utf-8")
            git("add", ".")
            def commit():
                git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
                return git("rev-parse", "HEAD")
            base = commit()
            def check(body, extra=None, expect=True):
                test.write_text(body, encoding="utf-8")
                if extra:
                    path = root / extra
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("changed", encoding="utf-8")
                git("add", "-A")
                head = commit()
                selected = policy.test_modules_for_diff(root, base, head)
                if expect:
                    self.assertIn("tests.test_daily_upgrade", selected)
                    self.assertIn("tests.test_native_between_turns_acceptance_families", selected)
                    self.assertIn("tests.test_reported_paths", selected)
                    self.assertIn("tests.test_indirect", selected)
                else:
                    self.assertIsNone(selected)
                git("reset", "--hard", "-q", base)
            check(original + "    def test_new(self): self.assertTrue(True)\n")
            check(original.replace("assertTrue(True)", "assertEqual(1, 1)"))
            check(original + "    def helper(self): pass\n", expect=False)
            check(original.replace("test_old", "test_renamed"), expect=False)
            check(original + "    def test_new(self): __import__('other')\n", expect=False)
            check(original + "    def test_new(self): from tests import helper\n", expect=False)
            check(original + "    def test_new(self): pass\n", "tests/fixture.txt", expect=False)
            check(original + "    def test_new(self): pass\n", "scripts/runtime.py", expect=False)
            check(original + "    def test_new(self): pass\n", "tests/test_unknown.py", expect=False)
            check(original + "    def test_new(self): pass\n", "validation-map-extra.json", expect=False)
            git("rm", "-q", "tests/test_daily_upgrade.py")
            removed = commit()
            self.assertIsNone(policy.test_modules_for_diff(root, base, removed))
            git("reset", "--hard", "-q", base)
            git("mv", "tests/test_daily_upgrade.py", "tests/test_daily_upgrade_moved.py")
            renamed = commit()
            self.assertIsNone(policy.test_modules_for_diff(root, base, renamed))
            git("reset", "--hard", "-q", base)
            git("update-index", "--chmod=+x", "tests/test_daily_upgrade.py")
            executable = commit()
            self.assertIsNone(policy.test_modules_for_diff(root, base, executable))
            self.assertIsNone(policy.test_modules_for_diff(root, base, base))
            self.assertIsNone(policy.test_modules_for_diff(root, "bad", base))

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

    def test_ci_controllers_and_their_contracts_never_downgrade(self):
        paths = ("scripts/run_current_behavior_suite.py", "scripts/check_phase3_transition.py",
                 "scripts/audit_commit_identity.py", "scripts/validate_public_repo.py", "scripts/audit_public_tree.py",
                 "tools/validation/ci_policy.py", "tools/validation/select_validation.py",
                 "tools/validation/run_selected_validation.py", "tools/validation/verify_required_jobs.py",
                 "tools/validation/ci_reuse.py", "tools/validation/validate_workflows.py",
                 "tools/validation/run_windows_platform_suite.py", "tools/validation/CI_POLICY.md",
                 "tests/test_ci_policy.py", "tests/test_ci_reuse.py", "tests/test_validation_selection.py",
                 "tests/test_selected_validation.py", "tests/test_required_jobs.py", "tests/test_public_contract.py")
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(policy.select_profile("auto", [path]), "full")
                self.assertEqual(policy.select_profile("daily", ["tests/test_daily_upgrade.py", path]), "full")

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
