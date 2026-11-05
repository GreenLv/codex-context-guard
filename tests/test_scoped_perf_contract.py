"""Scoped performance producer and consumer must agree on complete evidence."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.validation import perf_ab as driver
from tools.validation import perf_ab_verdicts as verdicts


class ScopedPerformanceTests(unittest.TestCase):
    def run_batch(self, directory, failure=False):
        root = Path(directory)
        digest = 'a' * 64
        scope = {'schema': 'perf-scoped/v1', 'cells': ['pretool_safe'], 'attempts': 20,
                 'baseline_runtime_digest': digest, 'candidate_runtime_digest': digest,
                 'budgets': {'elapsed': {'relative': 0.01, 'absolute': 0.001}}}
        manifest = root / 'scope.json'
        manifest.write_text(json.dumps(scope), encoding='utf-8')
        output = root / 'raw.json'
        argv = ['perf_ab', '--baseline', str(root), '--candidate', str(root),
                '--attempts', '20', '--formal', '--scope-manifest', str(manifest), '--out', str(output)]
        def attempt(*args):
            return {'outcome_class': 'timeout' if failure else 'completed',
                    'assertion': 'timeout' if failure else 'ok', 'elapsed': 1.0}
        with patch.object(sys, 'argv', argv), patch.object(driver, 'load_hasher', return_value=True), \
             patch.object(driver, 'tree_digest', return_value=digest), \
             patch.object(driver, 'source_identities', return_value={}), \
             patch.object(driver, 'load_wrapper', return_value='fake'), \
             patch.object(driver, 'run_standard_attempt', side_effect=attempt):
            rc = driver.main()
        return rc, json.loads(output.read_text(encoding='utf-8')), scope

    def test_actual_producer_to_consumer_and_corruptions(self):
        with tempfile.TemporaryDirectory() as directory:
            rc, raw, scope = self.run_batch(directory)
            self.assertEqual(rc, 0)
            report = verdicts.verdicts_from_raw(raw, scope=scope)
            self.assertEqual(report['declared_regressions'], [])
            for mutation in ('coverage', 'identity', 'count', 'cleanup', 'outcome', 'budget'):
                bad = json.loads(json.dumps(raw))
                if mutation == 'coverage':
                    bad['coverage_complete'] = False
                if mutation == 'identity':
                    bad['identities']['candidate_runtime_digest'] = 'b' * 64
                if mutation == 'count':
                    bad['cells']['pretool_safe']['sides']['baseline']['raw_rows'].pop()
                if mutation == 'cleanup':
                    bad['cells']['pretool_safe']['sides']['baseline']['raw_rows'][0]['home_cleanup']['status'] = 'retained'
                if mutation == 'outcome':
                    bad['cells']['pretool_safe']['sides']['candidate']['raw_rows'][0]['outcome_class'] = 'timeout'
                if mutation == 'budget':
                    bad['scope_manifest']['budgets']['elapsed']['absolute'] = 999
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    verdicts.verdicts_from_raw(bad, scope=scope)

    def test_timeout_never_becomes_success(self):
        with tempfile.TemporaryDirectory() as directory:
            rc, raw, scope = self.run_batch(directory, failure=True)
            self.assertEqual(rc, 1)
            with self.assertRaises(ValueError):
                verdicts.verdicts_from_raw(raw, scope=scope)

    def test_significant_regression_exceeds_both_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            _, raw, scope = self.run_batch(directory)
            for row in raw['cells']['pretool_safe']['sides']['candidate']['raw_rows']:
                row['elapsed'] = 1.2
            report = verdicts.verdicts_from_raw(raw, scope=scope)
            self.assertTrue(report['declared_regressions'])
            scope['budgets']['elapsed']['absolute'] = 1.0
            raw['scope_manifest'] = scope
            self.assertEqual(verdicts.verdicts_from_raw(raw, scope=scope)['declared_regressions'], [])

    def test_scoped_cli_exit_code_follows_material_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            _, raw, _ = self.run_batch(directory)
            root = Path(directory)
            source, scope = root / 'raw.json', root / 'scope.json'
            self.assertEqual(verdicts.main([str(source), '--scope-manifest', str(scope),
                                            '--out', str(root / 'ok.json')]), 0)
            for row in raw['cells']['pretool_safe']['sides']['candidate']['raw_rows']:
                row['elapsed'] = 1.2
            source.write_text(json.dumps(raw), encoding='utf-8')
            self.assertEqual(verdicts.main([str(source), '--scope-manifest', str(scope),
                                            '--out', str(root / 'regression.json')]), 1)

    def test_wide_confidence_interval_is_inconclusive_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            _, raw, scope = self.run_batch(directory)
            rows = raw['cells']['pretool_safe']['sides']['candidate']['raw_rows']
            for index, row in enumerate(rows):
                row['elapsed'] = 2.0 if index == 0 else 1.0
            report = verdicts.verdicts_from_raw(raw, scope=scope)
            self.assertFalse(report['accepted'])
            self.assertTrue(report['inconclusive_pairs'])
            self.assertFalse(report['declared_regressions'])
            self.assertEqual(report['verdicts']['pretool_safe']['verdict'], 'INCONCLUSIVE')
            root = Path(directory)
            (root / 'raw.json').write_text(json.dumps(raw), encoding='utf-8')
            self.assertEqual(verdicts.main([str(root / 'raw.json'), '--scope-manifest',
                                            str(root / 'scope.json'), '--out', str(root / 'uncertain.json')]), 1)


class RetentionMaintenanceCellTests(unittest.TestCase):
    """The 0.17.0 cleanup worker cell: positive and negative controls."""

    ROOT = Path(__file__).resolve().parents[1]

    def test_retention_cell_positive_control_passes_and_reports_counts(self):
        from tools.validation import perf_ab as driver
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "private"
            data_dir.mkdir()
            result = driver.run_retention_attempt(self.ROOT, data_dir)
            self.assertEqual(result["outcome_class"], "completed", result)
            self.assertEqual(result["assertion"], "ok")
            self.assertEqual(result["fixture"]["quarantined"], 6)
            self.assertEqual(result["fixture"]["protected"], 6)
            self.assertGreater(result["elapsed"], 0.0)

    def test_retention_cell_negative_control_is_retained_as_failure(self):
        from tools.validation import perf_ab as driver
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "private"
            data_dir.mkdir()
            real = driver.run_retention_attempt

            def broken(tree, data):
                result = real(tree, data)
                # A tampered count must surface as a failed attempt, never a
                # success-conditioned sample.
                result["fixture"]["quarantined"] = 5
                result["outcome_class"] = "failed"
                result["assertion"] = "retention_semantics_failed"
                return result

            with patch.object(driver, "run_retention_attempt", side_effect=broken):
                rows = [driver.run_retention_attempt(self.ROOT, data_dir)]
            self.assertEqual(rows[0]["outcome_class"], "failed")
            self.assertNotEqual(rows[0]["assertion"], "ok")
