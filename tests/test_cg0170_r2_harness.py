"""0.17.0 R2 RF-HARNESS: the retention batch entry and its oracles cannot
certify themselves.

Preflight checks inputs without running a scenario or touching a result;
results are created exclusively; the consumer requires the exact identity
and scenario set; and meta-tests prove that removing lock protection,
destroying should-keep ledgers or skipping restore verification makes the
batch fail. Synthetic data only.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_acceptance_r2", ROOT / "tools" / "validation" / "native_acceptance.py")
assert SPEC is not None and SPEC.loader is not None
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)

COMMIT = "a" * 40
DIGEST = "b" * 64


def mutated_scenarios(mutate):
    """Run the real scenario family with ``mutate(module)`` applied to the
    freshly loaded runtime module the batch drives."""
    original = importlib.util.spec_from_file_location

    def spec_with_mutant(name, location, *args, **kwargs):
        spec = original(name, location, *args, **kwargs)
        if name != "context_guard_batch":
            return spec
        load = spec.loader.exec_module

        def exec_module(module):
            load(module)
            mutate(module)
        spec.loader.exec_module = exec_module
        return spec
    with mock.patch.object(importlib.util, "spec_from_file_location",
                           side_effect=spec_with_mutant):
        return native.run_retention_batch_scenarios(ROOT)


def finish(scenarios, output_dir):
    return native._finish_retention_batch(
        Path(output_dir) / "result.json", scenarios, COMMIT, DIGEST, native.timestamp())


def by_name(scenarios):
    return {row["name"]: row for row in scenarios}


class RetentionBatchHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real = native.run_retention_batch_scenarios(ROOT)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def test_real_family_passes_and_the_consumer_accepts_it(self):
        self.assertEqual([row["name"] for row in self.real
                          if row["status"] != "passed"], [])
        result = finish(self.real, self.temp.name)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(native.validate_retention_batch_result(
            result, source_commit=COMMIT, runtime_tree_sha256=DIGEST), [])

    def test_consumer_rejects_identity_set_and_oracle_forgeries(self):
        result = finish(self.real, self.temp.name)

        def errors(mutated, **identity):
            return native.validate_retention_batch_result(
                mutated, source_commit=identity.get("commit", COMMIT),
                runtime_tree_sha256=identity.get("digest", DIGEST))
        self.assertIn("source_commit", errors(result, commit="c" * 40))
        self.assertIn("runtime_tree_sha256", errors(result, digest="d" * 64))
        self.assertIn("schema", errors(dict(result, schema="cg-retention-native-batch/v1")))
        missing = dict(result, scenarios=[row for row in result["scenarios"]
                                          if row["name"] != "busy_lock_contention"])
        self.assertIn("scenario_set", errors(missing))
        extra = dict(result, scenarios=result["scenarios"] + [
            {"name": "bonus", "status": "passed", "detail": {"checks": {"x": True}}}])
        self.assertIn("scenario_set", errors(extra))
        forged = json.loads(json.dumps(result))
        forged["scenarios"][0]["detail"]["checks"] = {
            key: False for key in forged["scenarios"][0]["detail"]["checks"]}
        self.assertTrue(errors(forged))
        self.assertIn("status_claims_pass", errors(forged))
        short = json.loads(json.dumps(result))
        kept = by_name(short["scenarios"])["kept_ledger_readback"]
        kept["detail"]["objects"] = kept["detail"]["objects"][:5]
        self.assertIn("kept_ledger_objects", errors(short))
        empty = json.loads(json.dumps(result))
        by_name(empty["scenarios"])["purge_complete"]["detail"]["checks"] = {}
        self.assertIn("checks:purge_complete", errors(empty))

    def test_consumer_rederives_fresh_process_facts(self):
        """v3 (R5, plan D1): the consumer re-derives the fresh-process facts
        from the recorded runs; a row whose own checks still claim success
        is rejected when its runs contradict the contract."""
        result = finish(self.real, self.temp.name)

        def errors(mutated):
            return native.validate_retention_batch_result(
                mutated, source_commit=COMMIT, runtime_tree_sha256=DIGEST)
        self.assertEqual(errors(result), [])
        claimed = json.loads(json.dumps(result))
        beyond = by_name(claimed["scenarios"])["fresh_process_capacity_exceeded"]
        beyond["detail"]["runs"][-1]["scan_complete"] = True
        self.assertIn("capacity_exceeded_runs", errors(claimed))
        hidden = json.loads(json.dumps(result))
        beyond = by_name(hidden["scenarios"])["fresh_process_capacity_exceeded"]
        beyond["detail"]["runs"][-1]["capacity_exceeded"] = False
        self.assertIn("capacity_exceeded_runs", errors(hidden))
        stalled = json.loads(json.dumps(result))
        purge = by_name(stalled["scenarios"])["fresh_process_purge_progress"]
        purge["detail"]["remaining"] = [22, 22, 22, 22]
        self.assertIn("purge_progress_runs", errors(stalled))
        regressed = json.loads(json.dumps(result))
        purge = by_name(regressed["scenarios"])["fresh_process_purge_progress"]
        purge["detail"]["remaining"] = [22, 19, 20, 0]
        self.assertIn("purge_progress_runs", errors(regressed))
        late = json.loads(json.dumps(result))
        within = by_name(late["scenarios"])["fresh_process_discovery_within_capacity"]
        within["detail"]["tail_reached_run"] = 9
        self.assertIn("within_capacity_runs", errors(late))
        self.assertIn("schema", errors(dict(result, schema="cg-retention-native-batch/v2")))

    def test_destroyed_should_keep_ledgers_fail_the_batch(self):
        def mutate(module):
            real = module.cleanup_old_sessions

            def corrupt(root, *args, **kwargs):
                report = real(root, *args, **kwargs)
                for state in (root / "sessions-v2").glob("kept-*/state.json"):
                    state.unlink()
                return report
            module.cleanup_old_sessions = corrupt
        scenarios = mutated_scenarios(mutate)
        self.assertEqual(by_name(scenarios)["kept_ledger_readback"]["status"], "failed")
        result = finish(scenarios, self.temp.name)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(native.validate_retention_batch_result(
            result, source_commit=COMMIT, runtime_tree_sha256=DIGEST))

    def test_removed_lock_protection_fails_the_batch(self):
        def mutate(module):
            module._retention_probe_lifecycle_lock = lambda candidate: (False, None)
            module._retention_acquire_lifecycle_lock = lambda candidate: (lambda: None)
        scenarios = mutated_scenarios(mutate)
        self.assertEqual(by_name(scenarios)["busy_lock_contention"]["status"], "failed")
        self.assertEqual(finish(scenarios, self.temp.name)["status"], "failed")

    def test_unverified_restore_fails_the_batch(self):
        def mutate(module):
            module._retention_verify_restorable = lambda target, record, deadline: ""
        scenarios = mutated_scenarios(mutate)
        self.assertEqual(by_name(scenarios)["explicit_restore_verified"]["status"], "failed")

    def test_preflight_never_runs_scenarios_or_touches_the_result(self):
        existing = Path(self.temp.name) / "existing.json"
        existing.write_text("keep", encoding="utf-8")
        argv = ["--source-commit", COMMIT, "--repo-root", str(ROOT),
                "--retention-batch", str(existing), "--preflight"]
        with mock.patch.object(native, "retention_native_batch",
                               side_effect=AssertionError("batch executed")), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(native.main(argv), 2)
        self.assertEqual(existing.read_text(encoding="utf-8"), "keep")
        fresh = Path(self.temp.name) / "fresh.json"
        argv[argv.index(str(existing))] = str(fresh)
        with mock.patch.object(native, "check_retention_batch_inputs") as checked, \
                mock.patch.object(native, "retention_native_batch",
                                  side_effect=AssertionError("batch executed")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(native.main(argv), 0)
        checked.assert_called_once_with(ROOT.resolve(), COMMIT, fresh)
        self.assertFalse(fresh.exists())

    def test_inputs_check_refuses_wrong_identity_and_unsafe_output(self):
        with self.assertRaises(native.NativeRunError):
            native.check_retention_batch_inputs(
                ROOT, "0" * 40, Path(self.temp.name) / "out.json")
        with mock.patch.object(native, "verify_exact_source"):
            with self.assertRaises(native.NativeRunError):
                native.check_retention_batch_inputs(ROOT, COMMIT, ROOT / "inside.json")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(native.main(["--source-commit", "abc", "--retention-batch",
                                          str(Path(self.temp.name) / "x.json")]), 2)

    def test_results_are_created_exclusively(self):
        output = Path(self.temp.name) / "once.json"
        finish(self.real, self.temp.name)
        native.load_host_behavior().write_result(output, {"a": 1})
        with self.assertRaises(FileExistsError):
            native.load_host_behavior().write_result(output, {"a": 2})
        self.assertEqual(json.loads(output.read_text())["a"], 1)


if __name__ == "__main__":
    unittest.main()
