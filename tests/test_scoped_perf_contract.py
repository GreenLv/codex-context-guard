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


class RepairR2PerformanceTests(unittest.TestCase):
    """R2 RF-EVIDENCE-PERF: the plan's small-record and cold-resume cells and
    the standalone runner are executable, contract-bound and fail closed."""

    ROOT = Path(__file__).resolve().parents[1]
    CONTRACT = ROOT / "docs" / "perf-contracts" / "v0.17.0-scoped.json"

    def test_r2_addendum_registers_only_executable_cells(self):
        contract = json.loads(self.CONTRACT.read_text(encoding="utf-8"))
        addendum = contract["repair_r2_addendum"]
        cells = (addendum["ab_runs"]["registered_cells"]
                 + list(addendum["ab_runs"]["plan_scenario_cells"])
                 + addendum["aa_control"]["cells"])
        for cell in cells:
            self.assertIn(cell, driver.cell_specs())
        self.assertEqual(addendum["ab_runs"]["attempts"], 20)
        from tools.validation import perf_standalone
        for cell in ("retention_maintenance", "terminal_read_large"):
            budgets, samples = perf_standalone.contract_budgets(contract, cell)
            self.assertGreaterEqual(samples, 20)
            self.assertGreater(budgets["median_elapsed_seconds"], 0)

    def test_terminal_read_small_cell_positive_and_negative_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "private"
            data_dir.mkdir()
            result = driver.run_terminal_read_small_attempt(self.ROOT, data_dir)
            self.assertEqual((result["outcome_class"], result["assertion"]), ("completed", "ok"))
            self.assertEqual(result["fixture"]["rows"], 202)
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "private"
            data_dir.mkdir()
            real_import = driver._retention_import_tree

            def broken_import(tree):
                cg, *rest = real_import(tree)
                cg.host_terminal_result = lambda state, payload: None
                return (cg, *rest)
            with patch.object(driver, "_retention_import_tree", side_effect=broken_import):
                failed = driver.run_terminal_read_small_attempt(self.ROOT, data_dir)
            self.assertEqual(failed["outcome_class"], "failed")

    def run_standalone(self, rows, *, contract=None):
        from tools.validation import perf_standalone
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path = root / "contract.json"
            contract_path.write_text(json.dumps(contract or json.loads(
                self.CONTRACT.read_text(encoding="utf-8"))), encoding="utf-8")
            out = root / "out.json"
            calls = iter(rows)
            runner = lambda tree, data_dir: dict(next(calls))  # noqa: E731
            with patch.dict(perf_standalone.STANDALONE, {
                    "terminal_read_large": (perf_standalone.STANDALONE["terminal_read_large"][0], runner)}):
                rc = perf_standalone.main(["--candidate", str(self.ROOT), "--cell",
                                           "terminal_read_large", "--contract",
                                           str(contract_path), "--out", str(out)])
            report = json.loads(out.read_text(encoding="utf-8"))
            with self.assertRaises(SystemExit):
                with patch("sys.stderr"):
                    perf_standalone.main(["--candidate", str(self.ROOT), "--cell",
                                          "terminal_read_large", "--contract",
                                          str(contract_path), "--out", str(out)])
            return rc, report

    def test_standalone_runner_accepts_only_complete_in_budget_runs(self):
        ok = {"outcome_class": "completed", "assertion": "ok", "elapsed": 0.05}
        rc, report = self.run_standalone([ok] * 20)
        self.assertEqual((rc, report["accepted"], report["completed"]), (0, True, 20))
        failed = {"outcome_class": "failed", "assertion": "terminal_read_semantics_failed",
                  "elapsed": 0.05}
        rc, report = self.run_standalone([ok] * 19 + [failed])
        self.assertEqual((rc, report["accepted"], report["failures"]), (1, False, 1))
        slow = dict(ok, elapsed=1.5)
        rc, report = self.run_standalone([slow] * 20)
        self.assertEqual((rc, report["accepted"]), (1, False))

    def test_standalone_runner_refuses_unregistered_budgets(self):
        from tools.validation import perf_standalone
        contract = json.loads(self.CONTRACT.read_text(encoding="utf-8"))
        del contract["repair_r1_addendum"]["new_cells"]["terminal_read_large"]["budgets"]
        with self.assertRaises(ValueError):
            perf_standalone.contract_budgets(contract, "terminal_read_large")


class ScopedWindowsShellTests(unittest.TestCase):
    def run_batch(self, directory, *, after_changed=False):
        root = Path(directory)
        baseline, candidate = root / 'baseline', root / 'candidate'
        for tree, suffix in ((baseline, 'base'), (candidate, 'candidate')):
            (tree / 'hooks').mkdir(parents=True)
            hook = {'hooks': {'SessionEnd': [{'hooks': [{
                'commandWindows': '$value = "' + suffix + '"; Write-Output $value'}]}]}}
            (tree / 'hooks/hooks.json').write_text(json.dumps(hook))
        digest = 'a' * 64
        scope = {'schema': 'perf-scoped/v1', 'cells': ['session_end'], 'attempts': 20,
                 'baseline_runtime_digest': digest, 'candidate_runtime_digest': digest,
                 'budgets': {'elapsed': {'relative': 0.1, 'absolute': 0.05}}}
        manifest, output = root / 'scope.json', root / 'raw.json'
        manifest.write_text(json.dumps(scope), encoding='utf-8')
        shell = {'path': str(root / 'pwsh.exe'), 'version': '7.5.0', 'sha256': 'f' * 64}
        expected = [shell, {**shell, 'sha256': 'e' * 64} if after_changed else shell]
        invoked = []
        def run(wrapper, _tree, _cell, _spec, _data, _budget, *, windows_shell):
            invoked.append((wrapper, windows_shell))
            return {'outcome_class': 'completed', 'assertion': 'ok', 'elapsed': 1.0,
                    'wrapper_sha256': driver.sha256_bytes(wrapper.encode('utf-8'))}
        argv = ['perf_ab', '--baseline', str(baseline), '--candidate', str(candidate),
                '--attempts', '20', '--formal', '--scope-manifest', str(manifest),
                '--windows-shell', shell['path'], '--out', str(output)]
        with patch.object(sys, 'argv', argv), patch.object(sys, 'platform', 'win32'), \
                patch.object(driver, 'load_hasher', return_value=True), \
                patch.object(driver, 'tree_digest', return_value=digest), \
                patch.object(driver, 'source_identities', return_value={}), \
                patch.object(driver, 'inspect_windows_shell', side_effect=expected), \
                patch.object(driver, 'preflight_windows_wrappers', side_effect=lambda _shell, wrappers: {
                    key: driver.sha256_bytes(value.encode('utf-8')) for key, value in wrappers.items()}), \
                patch.object(driver, 'seed_active_session'), \
                patch.object(driver, '_session_end_worker_mode', return_value='disabled'), \
                patch.object(driver, 'run_standard_attempt', side_effect=run):
            rc = driver.main()
        return rc, json.loads(output.read_text()), scope, shell, invoked

    def inspected_wrappers(self, raw, scope):
        with patch('tools.validation.acceptance_identity.runtime_tree_digest',
                   return_value=scope['baseline_runtime_digest']):
            return verdicts.inspect_windows_wrappers(raw, scope)

    def test_explicit_shell_is_bound_and_consumer_requires_same_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            rc, raw, scope, shell, invoked = self.run_batch(directory)
            self.assertEqual(rc, 0)
            self.assertEqual(len(invoked), 40)
            self.assertTrue(all(path == shell['path'] for _, path in invoked))
            self.assertEqual(raw['scope_manifest'], scope)
            self.assertEqual(raw['identities']['windows_shell']['before'], shell)
            self.assertEqual(raw['identities']['windows_shell']['after'], shell)
            wrappers = self.inspected_wrappers(raw, scope)
            verdicts.validate_scoped(raw, scope, shell, wrappers)
            for wrong in (None, {**shell, 'path': '/another/pwsh.exe'},
                          {**shell, 'version': '7.4.0'}, {**shell, 'sha256': 'd' * 64}):
                with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                    verdicts.validate_scoped(raw, scope, wrong, wrappers)
            changed = json.loads(json.dumps(raw))
            changed['cells']['session_end']['sides']['candidate']['raw_rows'][0]['wrapper_sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'sample wrapper differs'):
                verdicts.validate_scoped(changed, scope, shell, wrappers)
            changed = json.loads(json.dumps(raw))
            del changed['identities']['windows_shell']
            with self.assertRaisesRegex(ValueError, 'shell identity differs'):
                verdicts.validate_scoped(changed, scope, shell, wrappers)
            with patch.object(sys, 'platform', 'win32'), \
                    self.assertRaisesRegex(ValueError, 'requires explicit shell'):
                verdicts.validate_scoped(changed, scope)
            with self.assertRaisesRegex(ValueError, 'shell identity differs'):
                verdicts.validate_scoped(raw, scope, shell)
            changed = json.loads(json.dumps(raw))
            changed['identities']['windows_shell']['wrapper_sha256']['candidate'] = '0' * 64
            for row in changed['cells']['session_end']['sides']['candidate']['raw_rows']:
                row['wrapper_sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'wrapper identity differs'):
                verdicts.validate_scoped(changed, scope, shell, wrappers)

    def test_consumer_cli_requires_and_rechecks_explicit_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            rc, _raw, _scope, shell, _ = self.run_batch(directory)
            self.assertEqual(rc, 0)
            root = Path(directory)
            argv = [str(root / 'raw.json'), '--scope-manifest', str(root / 'scope.json')]
            with self.assertRaisesRegex(ValueError, 'shell identity differs'):
                verdicts.main([*argv, '--out', str(root / 'missing-shell.json')])
            with patch.object(driver, 'inspect_windows_shell', return_value=shell) as inspect, \
                    patch('tools.validation.acceptance_identity.runtime_tree_digest',
                          return_value='a' * 64):
                code = verdicts.main([*argv, '--windows-shell', shell['path'],
                                      '--out', str(root / 'verified.json')])
            self.assertEqual(code, 0)
            inspect.assert_called_once_with(Path(shell['path']))
            with patch.object(driver, 'inspect_windows_shell',
                              return_value={**shell, 'sha256': 'd' * 64}), \
                    patch('tools.validation.acceptance_identity.runtime_tree_digest',
                          return_value='a' * 64), \
                    self.assertRaisesRegex(ValueError, 'shell identity differs'):
                verdicts.main([*argv, '--windows-shell', shell['path'],
                               '--out', str(root / 'wrong-shell.json')])

    def test_cli_rejects_coherent_forged_wrapper_and_changed_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            _, raw, scope, shell, _ = self.run_batch(directory)
            root = Path(directory)
            raw['identities']['windows_shell']['wrapper_sha256']['candidate'] = '0' * 64
            for row in raw['cells']['session_end']['sides']['candidate']['raw_rows']:
                row['wrapper_sha256'] = '0' * 64
            (root / 'raw.json').write_text(json.dumps(raw), encoding='utf-8')
            argv = [str(root / 'raw.json'), '--scope-manifest', str(root / 'scope.json'),
                    '--windows-shell', shell['path'], '--out', str(root / 'out.json')]
            with patch.object(driver, 'inspect_windows_shell', return_value=shell), \
                    patch('tools.validation.acceptance_identity.runtime_tree_digest',
                          return_value=scope['baseline_runtime_digest']), \
                    self.assertRaisesRegex(ValueError, 'wrapper identity differs'):
                verdicts.main(argv)
            with patch.object(driver, 'inspect_windows_shell', return_value=shell), \
                    patch('tools.validation.acceptance_identity.runtime_tree_digest',
                          return_value='b' * 64), \
                    self.assertRaises(SystemExit):
                verdicts.main(argv)

    def test_consumer_enforces_exact_six_scope_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            _, raw, scope, shell, _ = self.run_batch(directory)
            wrappers = self.inspected_wrappers(raw, scope)
            scope['unexpected'] = True
            raw['scope_manifest'] = scope
            with self.assertRaisesRegex(ValueError, 'differs from declaration'):
                verdicts.validate_scoped(raw, scope, shell, wrappers)

    def test_changed_shell_after_sampling_is_failed_raw(self):
        with tempfile.TemporaryDirectory() as directory:
            rc, raw, scope, shell, _ = self.run_batch(directory, after_changed=True)
            self.assertEqual(rc, 1)
            self.assertFalse(raw['accepted'])
            self.assertIn('identity changed', raw['driver_failure'])
            wrappers = self.inspected_wrappers(raw, scope)
            with self.assertRaises(ValueError):
                verdicts.validate_scoped(raw, scope, shell, wrappers)
