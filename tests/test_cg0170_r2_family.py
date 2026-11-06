"""0.17.0 R2 problem-family regressions (RF-F03-JSON, RF-C01-TXN,
RF-C01-DISCOVERY, RF-SCHED).

Each class closes one family by its invariant, not by the reviewer's single
counterexample: a differential JSON grammar matrix against the strict
canonical decoder; the complete quarantine/restore/purge state machine with
every interrupted boundary, thread/process lock ownership and live-lock
deferral; discovery that bounds all work by the pass deadline while still
reaching every finite registered name; and the scheduler lifecycle through
its adapter seam on both platforms. Synthetic data only; no test reaches the
host's real launchd or Task Scheduler.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cg0170_host_evidence_family import HostEvidenceFamilyTests  # noqa: E402
from test_cg0170_retention_restored import (  # noqa: E402
    RetentionFixtureBase,
    acquire_exclusive_lock,
    cg,
    release_exclusive_lock,
)


def canonical_outer(text: str):
    """Strict canonical reading: None when rejected, else the decoded outer
    members with non-string values reduced to Ellipsis."""
    try:
        value = cg._host_strict_json_loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(value, dict):
        return None
    return {key: (item if isinstance(item, str) else ...) for key, item in value.items()}


class HostJsonGrammarTests(unittest.TestCase):
    """RF-F03-JSON: one strict interpretation for every row size."""

    MATRIX = [
        # (label, text)
        ("empty_object", "{}"),
        ("escaped_key_value", '{"t\\u0079pe":"resp\\u006fnse_item"}'),
        ("escaped_duplicate_outer", '{"type":"response_item","\\u0074ype":"event_msg"}'),
        ("plain_duplicate_outer", '{"type":"response_item","type":"response_item"}'),
        ("nested_duplicate", '{"type":"response_item","p":{"a":1,"a":2}}'),
        ("nested_fake_type", '{"type":"response_item","p":{"type":"event_msg"}}'),
        ("string_fake_type", '{"type":"response_item","p":"\\"type\\":\\"event_msg\\""}'),
        ("numbers_valid", '{"a":0,"b":-0.5,"c":1e5,"d":2E-3,"e":-12.75e+2}'),
        ("number_leading_zero", '{"a":01}'),
        ("number_bare_minus", '{"a":-}'),
        ("number_trailing_dot", '{"a":1.}'),
        ("number_plus", '{"a":+1}'),
        ("literals_valid", '{"a":true,"b":false,"c":null}'),
        ("literal_bad_case", '{"a":truE}'),
        ("literal_trailing", '{"a":nullx}'),
        ("nan_constant", '{"a":NaN}'),
        ("infinity_constant", '{"a":-Infinity}'),
        ("container_mismatch", '{"a":[1}'),
        ("container_unclosed", '{"a":{"b":1}'),
        ("trailing_comma_object", '{"a":1,}'),
        ("trailing_comma_array", '{"a":[1,]}'),
        ("missing_colon", '{"a" 1}'),
        ("missing_comma", '{"a":1 "b":2}'),
        ("unicode_escape_pair", '{"a":"\\ud83d\\ude00"}'),
        ("unicode_escape_short", '{"a":"\\u00e"}'),
        ("invalid_escape", '{"a":"\\x41"}'),
        ("raw_control_char", '{"a":"\x01"}'),
        ("trailing_content", '{"a":1} {}'),
        ("trailing_whitespace", '{"a":1} \r\n'),
        ("top_level_array", '[{"type":"response_item"}]'),
        ("non_string_type", '{"type":1}'),
    ]

    def test_differential_matrix_matches_strict_canonical_reader(self):
        for label, text in self.MATRIX:
            with self.subTest(case=label):
                self.assertEqual(cg._host_json_outer_members(text), canonical_outer(text))

    def test_seeded_differential_fuzz_matches_canonical_reader(self):
        alphabet = list('{}[]",:01-.eE+tfrunlasx\\ \n') + [
            '"type"', '"\\u0074ype"', '"a"', "true", "null", "1.5", '{"b":1', ',"b":2}']
        rng = random.Random(20261106)
        for _ in range(4000):
            text = "{" + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 18)))
            with self.subTest(text=text):
                self.assertEqual(cg._host_json_outer_members(text), canonical_outer(text))

    def test_depth_and_work_are_bounded(self):
        bound = cg.HOST_JSON_MAX_DEPTH
        inside = '{"a":' + "[" * (bound - 1) + "]" * (bound - 1) + "}"
        beyond = '{"a":' + "[" * bound + "]" * bound + "}"
        self.assertEqual(cg._host_json_outer_members(inside), {"a": ...})
        self.assertIsNone(cg._host_json_outer_members(beyond))
        big = '{"type":"response_item","p":' + json.dumps("x" * (4 * 1024 * 1024)) + "}\n"
        started = time.monotonic()
        self.assertTrue(cg._oversized_host_record_skippable(big.encode()))
        self.assertLess(time.monotonic() - started, 2.0)

    def test_skippable_requires_one_never_candidate_string_type(self):
        cases = {
            '{"type":"response_item"}': True,
            '{"t\\u0079pe":"turn_context"}': True,
            '{"type":"event_msg"}': False,
            '{"type":"unknown_kind"}': False,
            '{"payload":1}': False,
            '{"type":["response_item"]}': False,
            '{"type":"response_item","\\u0074ype":"response_item"}': False,
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertIs(cg._oversized_host_record_skippable(text.encode()), expected)
        self.assertFalse(cg._oversized_host_record_skippable(b'{"type":"response_item"\xff}'))


class HostOversizedRowFamilyTests(HostEvidenceFamilyTests):
    """End to end through ``host_terminal_result`` with oversized rows."""

    def padding(self):
        return json.dumps("x" * (cg.HOST_TRANSCRIPT_LINE_LIMIT + 32))

    def test_escaped_duplicate_outer_type_keeps_snapshot_unavailable(self):
        bad = self.command_item("synthetic-read", code=1, output="failed\n")
        good = self.command_item("synthetic-read", output="ok\n")
        hidden = ('{"type":"response_item","padding":' + self.padding()
                  + ',"\\u0074ype":"event_msg","payload":'
                  + json.dumps(self.event_row(bad)["payload"]) + "}\n").encode()
        self.assertIsNone(self.run_mixed([self.meta_row(), hidden, self.event_row(good)]))

    def test_malformed_scalar_in_oversized_row_is_unknown(self):
        good = self.command_item("synthetic-read", output="ok\n")
        for scalar in ("truE", "01", "NaN", '"\\x41"'):
            with self.subTest(scalar=scalar):
                row = ('{"type":"response_item","padding":' + self.padding()
                       + ',"payload":' + scalar + "}\n").encode()
                self.assertIsNone(self.run_mixed([self.meta_row(), row, self.event_row(good)]))

    def test_escaped_unique_type_key_is_still_skippable(self):
        good = self.command_item("synthetic-read", output="ok\n")
        row = ('{"t\\u0079pe":"response_item","padding":' + self.padding() + "}\n").encode()
        value = self.run_mixed([self.meta_row(), row, self.event_row(good)])
        self.assertIsNotNone(value)
        self.assertEqual(value["outcome"], "success")

    def test_ordinary_rows_share_the_strict_interpretation(self):
        good = self.command_item("synthetic-read", output="ok\n")
        bad = self.command_item("synthetic-read", code=1, output="failed\n")
        duplicate = ('{"type":"response_item","type":"event_msg","payload":'
                     + json.dumps(self.event_row(bad)["payload"]) + "}\n").encode()
        self.assertIsNone(self.run_mixed([self.meta_row(), duplicate, self.event_row(good)]))
        constant = b'{"type":"response_item","payload":NaN}\n'
        self.assertIsNone(self.run_mixed([self.meta_row(), constant, self.event_row(good)]))


class RetentionTransactionR2Tests(RetentionFixtureBase):
    """RF-C01-TXN: one state machine, one lock owner model."""

    def quarantine(self, name, **policy):
        old = self.make_session(name, ended_days_ago=45)
        self.enable_policy(quarantine_days=1, **policy)
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record_path = next(path for path, record in cg._retention_iter_records(qdir)
                           if record["original_name"] == old.name)
        record = json.loads(record_path.read_text(encoding="utf-8"))
        return old, qdir, record_path, record, qdir / record["quarantine_object"]

    def future(self, days=2):
        real = cg.dt.datetime
        moment = real.now(cg.dt.timezone.utc) + cg.dt.timedelta(days=days)

        class Future(real):
            @classmethod
            def now(cls, tz=None):
                return moment if tz is not None else moment.replace(tzinfo=None)
        return moment, mock.patch.object(cg.dt, "datetime", Future)

    # -- lock ownership -------------------------------------------------
    def test_second_thread_blocks_until_the_owner_releases(self):
        self.make_session("lock", ended_days_ago=45)
        inside, release, second = threading.Event(), threading.Event(), threading.Event()

        def owner():
            with cg._retention_maintenance_lock(self.data_dir):
                inside.set()
                release.wait(3)

        def contender():
            with cg._retention_maintenance_lock(self.data_dir):
                second.set()
        first = threading.Thread(target=owner)
        first.start()
        self.assertTrue(inside.wait(2))
        other = threading.Thread(target=contender)
        other.start()
        self.assertFalse(second.wait(0.3))
        release.set()
        first.join(3)
        other.join(3)
        self.assertTrue(second.is_set())

    def test_same_thread_reentry_pairs_and_keeps_the_lock_until_outermost_exit(self):
        self.make_session("reentry", ended_days_ago=45)
        got = threading.Event()

        def contender():
            with cg._retention_maintenance_lock(self.data_dir, deadline=time.monotonic() + 3):
                got.set()
        with cg._retention_maintenance_lock(self.data_dir):
            with cg._retention_maintenance_lock(self.data_dir):
                pass
            worker = threading.Thread(target=contender)
            worker.start()
            self.assertFalse(got.wait(0.3), "nested exit released the outer hold")
        worker.join(3)
        self.assertTrue(got.is_set())

    def test_lock_wait_consumes_the_callers_deadline(self):
        self.make_session("deadline", ended_days_ago=45)
        held, done = threading.Event(), threading.Event()

        def owner():
            with cg._retention_maintenance_lock(self.data_dir):
                held.set()
                done.wait(5)
        worker = threading.Thread(target=owner)
        worker.start()
        self.assertTrue(held.wait(2))
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            cg.cleanup_old_sessions(self.data_dir, deadline=time.monotonic() + 0.2)
        self.assertLess(time.monotonic() - started, 2.0)
        done.set()
        worker.join(3)

    @unittest.skipIf(os.name == "nt", "POSIX flock child; Windows has its own gate")
    def test_another_process_holding_the_kernel_lock_excludes_this_process(self):
        self.make_session("process", ended_days_ago=45)
        lock = self.data_dir / cg.V2_NAMESPACE / ".locks" / "retention-maintenance.lock"
        lock.parent.mkdir(parents=True, exist_ok=True)
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import fcntl,sys,time;f=open(sys.argv[1],'a+b');"
             "fcntl.flock(f.fileno(),fcntl.LOCK_EX);print('held',flush=True);time.sleep(5)",
             str(lock)], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "held")
            with self.assertRaises(TimeoutError):
                with cg._retention_maintenance_lock(self.data_dir,
                                                    deadline=time.monotonic() + 0.3):
                    pass
        finally:
            child.kill()
            child.wait(5)

    # -- quarantine and recovery boundaries ------------------------------
    def test_intent_before_rename_rolls_back_with_the_namespace_home(self):
        old = self.make_session("intent", ended_days_ago=45)
        self.enable_policy()
        with mock.patch.object(cg.os, "rename", side_effect=OSError("crash")), \
                mock.patch.object(cg.Path, "unlink", side_effect=OSError("crash")):
            cg.cleanup_old_sessions(self.data_dir, apply=True)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        self.assertEqual([r["state"] for _p, r in cg._retention_iter_records(qdir)], ["planned"])
        summary = cg._retention_recover_records(qdir, cg.dt.datetime.now(cg.dt.timezone.utc))
        self.assertEqual(summary["rolled_back"], 1)
        self.assertEqual(cg._retention_iter_records(qdir), [])
        self.assertTrue(old.is_dir())

    def test_rename_landed_without_commit_is_promoted(self):
        old = self.make_session("landed", ended_days_ago=45)
        self.enable_policy()
        real = cg._retention_write_record

        def lose_commit(path, body):
            if body.get("state") == "quarantined":
                raise OSError("crash after rename")
            return real(path, body)
        with mock.patch.object(cg, "_retention_write_record", side_effect=lose_commit):
            cg.cleanup_old_sessions(self.data_dir, apply=True)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        self.assertFalse(old.exists())
        summary = cg._retention_recover_records(qdir, cg.dt.datetime.now(cg.dt.timezone.utc))
        self.assertEqual(summary["recovered"], 1)
        self.assertEqual([r["state"] for _p, r in cg._retention_iter_records(qdir)],
                         ["quarantined"])

    def test_lost_original_and_target_stay_indeterminate_and_visible(self):
        old, qdir, record_path, record, target = self.quarantine("lost")
        record["state"] = "planned"
        record_path.write_text(json.dumps(record), encoding="utf-8")
        import shutil
        shutil.rmtree(target)
        summary = cg._retention_recover_records(qdir, cg.dt.datetime.now(cg.dt.timezone.utc))
        self.assertEqual(summary["indeterminate"], 1)
        self.assertTrue(record_path.exists())
        self.assertEqual(cg.retention_restore(self.data_dir, old.name)["outcome"], "refused")

    def test_interrupted_restore_is_settled_both_ways(self):
        old, qdir, record_path, record, target = self.quarantine("restore-crash")
        with mock.patch.object(cg.os, "rename", side_effect=OSError("crash")):
            failed = cg.retention_restore(self.data_dir, old.name)
        self.assertEqual(failed["outcome"], "failed")
        self.assertEqual(json.loads(record_path.read_text())["state"], "quarantined")
        # Rename landed, record retirement lost: recovery completes it.
        with mock.patch.object(cg.Path, "unlink", side_effect=OSError("crash")):
            restored = cg.retention_restore(self.data_dir, old.name)
        self.assertEqual(restored["outcome"], "restored")
        self.assertTrue(restored.get("record_pending"))
        self.assertEqual(json.loads(record_path.read_text())["state"], "restore_planned")
        summary = cg._retention_recover_records(qdir, cg.dt.datetime.now(cg.dt.timezone.utc))
        self.assertEqual(summary["completed"], 1)
        self.assertFalse(record_path.exists())
        self.assertTrue((old / "state.json").is_file())

    def test_expired_deadline_after_intent_never_starts_the_rename(self):
        old = self.make_session("late", ended_days_ago=45)
        self.enable_policy()
        policy = cg.read_retention_policy(self.data_dir)
        now = cg.dt.datetime.now(cg.dt.timezone.utc)
        entry = cg._retention_adjudicate(old, policy, now)
        manifest = {"policy_version": policy["policy_version"], "manifest_sha256": "same-pass"}
        renames = []
        with mock.patch.object(cg.os, "rename", side_effect=lambda *a: renames.append(a)):
            outcome = cg._retention_quarantine_object(
                self.data_dir, old, entry, manifest, now, policy=policy,
                deadline=time.monotonic() - 1)
        self.assertEqual(outcome["reason"], "deadline")
        self.assertEqual(renames, [])
        self.assertEqual(cg._retention_iter_records(cg._retention_quarantine_dir(self.data_dir)), [])
        self.assertTrue(old.is_dir())

    # -- purge ------------------------------------------------------------
    def test_purge_defers_while_the_original_name_lifecycle_lock_is_held(self):
        old, qdir, record_path, record, target = self.quarantine("busy-origin")
        handle = acquire_exclusive_lock(cg.lifecycle_lock_path(old))
        _moment, clock = self.future()
        try:
            with clock:
                busy = cg.cleanup_old_sessions(self.data_dir, apply=True)
        finally:
            release_exclusive_lock(handle)
        self.assertEqual(busy["purge"]["purge_busy"], 1)
        self.assertTrue(target.is_dir())
        self.assertEqual(json.loads(record_path.read_text())["state"], "quarantined")
        with clock:
            done = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(done["purge"]["purged"], 1)
        self.assertFalse(target.exists())

    def test_tombstone_write_failure_is_completed_by_the_next_pass(self):
        old, qdir, record_path, record, target = self.quarantine("tombstone-loss")
        moment, _clock = self.future()
        policy = cg.read_retention_policy(self.data_dir)
        real = cg._retention_write_record

        def fail_tombstone(path, body):
            if path.name.endswith(".tombstone.json"):
                raise OSError("disk full after data deletion")
            return real(path, body)
        with mock.patch.object(cg, "_retention_write_record", side_effect=fail_tombstone):
            first = cg._retention_purge_pass(self.data_dir, policy, moment, None)
        self.assertEqual(first["tombstone_pending"], 1)
        self.assertFalse(target.exists())
        self.assertEqual(json.loads(record_path.read_text())["state"], "purge_planned")
        with self.assertRaises(cg.RetentionRecreationRefused):
            cg._retention_recreation_guard(old)
        second = cg._retention_purge_pass(self.data_dir, policy, moment, None)
        self.assertEqual(second["purged"], 1)
        self.assertFalse(record_path.exists())
        self.assertTrue(list(qdir.glob("*.tombstone.json")))

    def test_partial_purge_is_never_restorable_and_completes_later(self):
        old, qdir, record_path, record, target = self.quarantine("partial")
        moment, _clock = self.future()
        policy = cg.read_retention_policy(self.data_dir)

        def interrupted(path, deadline):
            (path / "state.json").unlink()
            return False
        with mock.patch.object(cg, "_retention_purge_tree", side_effect=interrupted):
            partial = cg._retention_purge_pass(self.data_dir, policy, moment, None)
        self.assertEqual(partial["purge_partial"], 1)
        restore = cg.retention_restore(self.data_dir, old.name)
        self.assertEqual((restore["outcome"], restore["reason"]),
                         ("unavailable", "purge_in_progress"))
        self.assertFalse(old.exists())
        done = cg._retention_purge_pass(self.data_dir, policy, moment, None)
        self.assertEqual(done["purged"], 1)
        self.assertFalse(target.exists())

    def test_policy_revocation_after_quarantine_stops_purge(self):
        old, qdir, record_path, record, target = self.quarantine("revoked")
        cg.write_retention_policy(self.data_dir, enabled=True, purge_enabled=False)
        moment, _clock = self.future()
        report = cg._retention_purge_pass(
            self.data_dir, cg.read_retention_policy(self.data_dir), moment, None)
        self.assertEqual(report["purge_disabled"], 1)
        self.assertTrue(target.is_dir())

    # -- restore integrity ---------------------------------------------------
    def test_restore_refuses_an_incomplete_object_and_keeps_it(self):
        for mutation in ("state_rewritten", "file_removed", "file_added"):
            with self.subTest(mutation=mutation):
                old, qdir, record_path, record, target = self.quarantine(f"damaged-{mutation}")
                if mutation == "state_rewritten":
                    (target / "state.json").write_text("{}", encoding="utf-8")
                elif mutation == "file_removed":
                    victim = next(path for path in target.rglob("*")
                                  if path.is_file() and path.name != "state.json")
                    victim.unlink()
                else:
                    (target / "planted.txt").write_text("x", encoding="utf-8")
                report = cg.retention_restore(self.data_dir, old.name)
                self.assertEqual(report["outcome"], "refused")
                self.assertEqual(report["reason"], "content_mismatch")
                self.assertTrue(target.is_dir())
                self.assertTrue(record_path.exists())
                self.assertFalse(old.exists())

    # -- record validity and unknown objects --------------------------------
    def test_unknown_record_naming_a_session_blocks_recreation_and_is_never_purged(self):
        old, qdir, record_path, record, target = self.quarantine("unknown")
        record["schema"] = "cg-retention-quarantine/v99"
        record_path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(cg.RetentionRecreationRefused):
            cg._retention_recreation_guard(old)
        moment, _clock = self.future()
        report = cg._retention_purge_pass(
            self.data_dir, cg.read_retention_policy(self.data_dir), moment, None)
        self.assertEqual(report["purged"], 0)
        self.assertTrue(target.is_dir())

    def test_record_cannot_point_at_another_names_object(self):
        _old, qdir, record_path, record, target = self.quarantine("pointer")
        record["original_name"] = "someone-else"
        record_path.write_text(json.dumps(record), encoding="utf-8")
        self.assertIsNone(cg._retention_read_record(record_path))

    def test_r1_v2_records_stay_readable_for_their_two_states(self):
        _old, qdir, record_path, record, target = self.quarantine("legacy")
        record["schema"] = "cg-retention-quarantine/v2"
        record.pop("tree")
        record_path.write_text(json.dumps(record), encoding="utf-8")
        self.assertIsNotNone(cg._retention_read_record(record_path))
        record["state"] = "purge_planned"
        record_path.write_text(json.dumps(record), encoding="utf-8")
        self.assertIsNone(cg._retention_read_record(record_path))


class RetentionDiscoveryR2Tests(RetentionFixtureBase):
    """RF-C01-DISCOVERY: real total budget and eventual arrival together."""

    def charged_pass(self, budget, *, per_entry=0.001):
        """Fake monotonic clock: every readdir entry and adjudication costs
        ``per_entry``; records each rename's time."""
        clock = [0.0]
        visited: list = []
        renames: list = []
        real_adjudicate = cg._retention_adjudicate
        real_rename = cg.os.rename

        def adjudicate(*args, **kwargs):
            clock[0] += per_entry
            return real_adjudicate(*args, **kwargs)

        def rename(*args, **kwargs):
            renames.append(clock[0])
            return real_rename(*args, **kwargs)
        with self.scan_stub(self.data_dir / cg.V2_NAMESPACE, visited, clock), \
                mock.patch.object(cg.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(cg, "_retention_adjudicate", side_effect=adjudicate), \
                mock.patch.object(cg.os, "rename", side_effect=rename):
            report = cg.cleanup_old_sessions(self.data_dir, apply=True, deadline=budget)
        return report, clock[0], renames

    def test_decided_prefix_cannot_carry_destruction_past_the_deadline(self):
        for index in range(20):
            self.make_session(f"prefix-{index:02}", ended_days_ago=45, finished=False)
        tail = self.make_session("zz-eligible-tail", ended_days_ago=45)
        self.enable_policy()
        cg._write_cleanup_state(self.data_dir, "prefix-19", [], deadline=None)
        report, elapsed, renames = self.charged_pass(0.003)
        self.assertTrue(all(at < 0.003 for at in renames), renames)
        self.assertFalse(tail.exists() and elapsed > 0.003 and renames)
        self.assertLessEqual(elapsed, 0.003 + 0.003 + 1e-9)

    def test_every_finite_registered_name_is_reached_under_tight_budgets(self):
        for index in range(15):
            self.make_session(f"keep-{index:02}", ended_days_ago=45, finished=False)
        for index in range(5):
            self.make_session(f"take-{index:02}", ended_days_ago=45)
        self.enable_policy()
        for _ in range(40):
            report, _elapsed, renames = self.charged_pass(0.0045)
            self.assertTrue(all(at < 0.0045 for at in renames))
        for index in range(5):
            self.assertFalse(self.session_dir(f"take-{index:02}").exists())
        for index in range(15):
            self.assertTrue(self.session_dir(f"keep-{index:02}").is_dir())

    def test_deadline_cut_transition_is_requeued_and_served_first(self):
        self.make_session("tail", ended_days_ago=45)
        self.enable_policy()
        # Budget lets adjudication start but not the locked re-verification.
        report, _elapsed, renames = self.charged_pass(0.0025)
        self.assertEqual(renames, [])
        _cursor, pending = cg._read_cleanup_state(self.data_dir)
        self.assertIn("tail", pending)
        report, _elapsed, renames = self.charged_pass(0.0035)
        self.assertEqual(len(renames), 1)
        self.assertFalse(self.session_dir("tail").exists())

    def test_missing_or_corrupt_registry_is_rebuilt_by_the_backfill(self):
        for name in ("alpha", "bravo", "charlie"):
            self.make_session(name, ended_days_ago=45)
        cg.write_retention_policy(self.data_dir, enabled=False)  # adopted, inert
        registry = cg._cleanup_registry_path(self.data_dir)
        for damage in ("delete", "garbage"):
            with self.subTest(damage=damage):
                if damage == "delete":
                    registry.unlink(missing_ok=True)
                else:
                    registry.write_text("../escape\n\x00bad\n", encoding="utf-8")
                cg._REGISTRY_ENTRIES_THIS_PROCESS.clear()
                report = cg.cleanup_old_sessions(self.data_dir)
                self.assertTrue(report["discovery"]["backfill_complete"])
                self.assertEqual(
                    {e["name"] for e in report["entries"]}, {"alpha", "bravo", "charlie"})
                self.assertEqual(cg._read_discovery_registry(self.data_dir),
                                 {"alpha", "bravo", "charlie"})

    def test_unregistered_names_from_older_runtimes_are_discovered(self):
        self.make_session("registered", ended_days_ago=45)
        legacy = self.make_session("legacy-created", ended_days_ago=45)
        registry = cg._cleanup_registry_path(self.data_dir)
        registry.write_text("registered\n", encoding="utf-8")
        cg._REGISTRY_ENTRIES_THIS_PROCESS.clear()
        self.enable_policy()
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertFalse(legacy.exists())

    def test_insertion_and_deletion_between_passes_still_converge(self):
        for index in range(6):
            self.make_session(f"n-{index}", ended_days_ago=45, finished=False)
        self.enable_policy()
        self.charged_pass(0.004)
        import shutil
        shutil.rmtree(self.session_dir("n-0"))
        late = self.make_session("a-late-eligible", ended_days_ago=45)
        for _ in range(20):
            self.charged_pass(0.004)
        self.assertFalse(late.exists())

    def test_registration_follows_adoption_and_never_precedes_it(self):
        # Without a policy object hooks create no maintenance object.
        self.make_session("before", ended_days_ago=None, finished=False)
        self.assertFalse(cg._cleanup_registry_path(self.data_dir).exists())
        # Enabling the policy registers every existing session at once...
        self.enable_policy()
        self.assertEqual(cg._read_discovery_registry(self.data_dir), {"before"})
        # ...and every later session registers itself at creation.
        self.make_session("after", ended_days_ago=None, finished=False)
        self.assertEqual(cg._read_discovery_registry(self.data_dir), {"before", "after"})


class FakeLaunchd:
    """In-memory launchctl: loaded labels and command log."""

    def __init__(self, *, bootstrap_rc=0):
        self.loaded: set[str] = set()
        self.calls: list[list[str]] = []
        self.bootstrap_rc = bootstrap_rc

    def __call__(self, argv):
        self.calls.append(list(argv))
        tool, verb = argv[0], argv[1]
        assert tool == "launchctl", argv
        if verb == "print":
            return subprocess.CompletedProcess(argv, 0 if argv[2].rsplit("/", 1)[-1] in self.loaded else 113, b"", b"")
        if verb == "bootstrap":
            import plistlib
            label = plistlib.loads(Path(argv[3]).read_bytes())["Label"]
            if self.bootstrap_rc == 0:
                self.loaded.add(label)
            return subprocess.CompletedProcess(argv, self.bootstrap_rc, b"", b"")
        if verb == "bootout":
            label = argv[2].rsplit("/", 1)[-1]
            rc = 0 if label in self.loaded else 3
            self.loaded.discard(label)
            return subprocess.CompletedProcess(argv, rc, b"", b"")
        if verb == "enable":
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(argv)

    def verbs(self):
        return [call[1] for call in self.calls]


class FakeSchtasks:
    """In-memory Task Scheduler speaking the schtasks /XML contract: it keeps
    the registered definition's Command/Arguments/Description/Enabled and
    answers ``/Query /XML`` in UTF-16 like the real tool."""

    NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"

    def __init__(self):
        self.tasks: dict[str, dict] = {}
        self.calls: list[list[str]] = []
        self.definitions: list[str] = []

    @classmethod
    def parse(cls, text):
        import xml.etree.ElementTree as ElementTree
        root = ElementTree.fromstring(text.lstrip("\ufeff").split("?>", 1)[1])

        def text_of(*parts):
            node = root
            for part in parts:
                node = node.find(cls.NS + part)
            return node.text or ""
        return {"command": text_of("Actions", "Exec", "Command"),
                "arguments": text_of("Actions", "Exec", "Arguments"),
                "description": text_of("RegistrationInfo", "Description"),
                "enabled": text_of("Settings", "Enabled") == "true"}

    def render(self, task):
        from xml.sax.saxutils import escape
        return ('<?xml version="1.0" encoding="UTF-16"?><Task xmlns="http://schemas.'
                'microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>'
                f'{escape(task["description"])}</Description></RegistrationInfo><Settings>'
                f'<Enabled>{"true" if task["enabled"] else "false"}</Enabled></Settings>'
                f'<Actions><Exec><Command>{escape(task["command"])}</Command><Arguments>'
                f'{escape(task["arguments"])}</Arguments></Exec></Actions></Task>')

    def __call__(self, argv):
        self.calls.append(list(argv))
        assert argv[0] == "schtasks", argv
        verb = argv[1]
        name = argv[argv.index("/TN") + 1]
        if verb == "/Create":
            assert "/TR" not in argv, argv
            if name in self.tasks and "/F" not in argv:
                return subprocess.CompletedProcess(argv, 1, b"", b"exists")
            text = Path(argv[argv.index("/XML") + 1]).read_text(encoding="utf-16")
            self.definitions.append(text)
            self.tasks[name] = self.parse(text)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if verb == "/Query":
            task = self.tasks.get(name)
            if task is None:
                return subprocess.CompletedProcess(argv, 1, b"", b"missing")
            return subprocess.CompletedProcess(argv, 0, self.render(task).encode("utf-16"), b"")
        if verb == "/Change":
            self.tasks[name]["enabled"] = True
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if verb == "/Delete":
            if name not in self.tasks:
                return subprocess.CompletedProcess(argv, 1, b"", b"")
            del self.tasks[name]
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(argv)


class RetentionScheduleLifecycleTests(RetentionFixtureBase):
    """RF-SCHED: one enable/disable/status contract on both platforms."""

    LABEL = "context-guard-retention"

    def setUp(self):
        super().setUp()
        self.data_dir = self.root / "guard data with spaces"
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(self.data_dir)
        (self.data_dir / cg.V2_NAMESPACE).mkdir(parents=True)

    def on(self, platform, adapter):
        return mock.patch.multiple(cg, _retention_schedule_platform=lambda: platform,
                                   _retention_scheduler_run=adapter)

    def test_macos_enable_loads_status_reads_back_and_disable_unloads(self):
        launchd = FakeLaunchd()
        with self.on("macos", launchd):
            code, enabled = cg._retention_maintenance_enable(self.data_dir, self.LABEL)
            self.assertEqual((code, enabled["status"], enabled["state"]), (0, "enabled", "enabled"))
            plist = Path(enabled["entry"])
            import plistlib
            program = plistlib.loads(plist.read_bytes())["ProgramArguments"]
            self.assertEqual(program[0], str(Path(sys.executable).absolute()))
            self.assertEqual(program[2], str(Path(cg.__file__).resolve()))
            self.assertIn(str(self.data_dir), program)
            self.assertIn("bootstrap", launchd.verbs())
            before, calls = plist.read_bytes(), len(launchd.calls)
            code, again = cg._retention_maintenance_enable(self.data_dir, self.LABEL)
            self.assertEqual((code, again.get("no_op")), (0, True))
            self.assertEqual(plist.read_bytes(), before)
            self.assertNotIn("bootstrap", launchd.verbs()[calls:])
            self.assertTrue(cg._retention_maintenance_status(self.data_dir, self.LABEL)[1]["registered"])
            code, disabled = cg._retention_maintenance_disable(self.data_dir, self.LABEL)
            self.assertEqual((code, disabled["state"]), (0, "disabled"))
            self.assertIn("bootout", launchd.verbs())
            self.assertFalse(plist.exists())
            self.assertEqual(launchd.loaded, set())
            code, gone = cg._retention_maintenance_disable(self.data_dir, self.LABEL)
            self.assertEqual((code, gone.get("no_op")), (0, True))

    def test_macos_prepared_file_is_not_reported_enabled_until_loaded(self):
        launchd = FakeLaunchd()
        with self.on("macos", launchd):
            cg._retention_maintenance_enable(self.data_dir, self.LABEL)
            launchd.loaded.clear()  # e.g. after a logout without RunAtLoad
            status = cg._retention_maintenance_status(self.data_dir, self.LABEL)[1]
            self.assertEqual((status["state"], status["registered"]), ("prepared", False))
            code, enabled = cg._retention_maintenance_enable(self.data_dir, self.LABEL)
            self.assertEqual((code, enabled["state"]), (0, "enabled"))

    def test_macos_foreign_entry_is_never_overwritten_unloaded_or_removed(self):
        launchd = FakeLaunchd()
        plist = cg._retention_macos_plist_path(self.LABEL)
        plist.parent.mkdir(parents=True, exist_ok=True)
        plist.write_text("<plist>someone else's job</plist>", encoding="utf-8")
        launchd.loaded.add(self.LABEL)
        with self.on("macos", launchd):
            for action in (cg._retention_maintenance_enable, cg._retention_maintenance_disable):
                code, result = action(self.data_dir, self.LABEL)
                self.assertEqual((code, result["reason"]), (2, "foreign_entry"))
        self.assertEqual(plist.read_text(encoding="utf-8"), "<plist>someone else's job</plist>")
        self.assertNotIn("bootout", launchd.verbs())
        self.assertNotIn("bootstrap", launchd.verbs())

    def test_macos_loaded_label_without_a_managed_file_is_refused(self):
        launchd = FakeLaunchd()
        launchd.loaded.add(self.LABEL)
        with self.on("macos", launchd):
            code, result = cg._retention_maintenance_disable(self.data_dir, self.LABEL)
        self.assertEqual((code, result["state"]), (2, "loaded_unmanaged"))
        self.assertIn(self.LABEL, launchd.loaded)

    def test_macos_stale_owned_entry_is_replaced_and_reloaded(self):
        launchd = FakeLaunchd()
        with self.on("macos", launchd):
            cg._retention_maintenance_enable(self.data_dir, self.LABEL)
            plist = cg._retention_macos_plist_path(self.LABEL)
            stale = plist.read_text(encoding="utf-8").replace("cleanup", "cleanup-old")
            plist.write_text(stale, encoding="utf-8")
            entries = cg._retention_read_schedule_manifest(self.data_dir)
            entries[f"macos:{self.LABEL}"]["body_sha256"] = cg.sha256_text(stale)
            cg._retention_write_schedule_manifest(self.data_dir, entries)
            self.assertEqual(cg._retention_maintenance_status(self.data_dir, self.LABEL)[1]["state"],
                             "stale")
            code, result = cg._retention_maintenance_enable(self.data_dir, self.LABEL)
            self.assertEqual((code, result["state"]), (0, "enabled"))
            self.assertNotIn("cleanup-old", plist.read_text(encoding="utf-8"))
            self.assertIn("bootout", launchd.verbs())

    def test_macos_failed_load_rolls_back_the_created_definition(self):
        launchd = FakeLaunchd(bootstrap_rc=5)
        with self.on("macos", launchd):
            code, result = cg._retention_maintenance_enable(self.data_dir, self.LABEL)
        self.assertEqual((code, result["reason"]), (2, "load_failed"))
        self.assertFalse(cg._retention_macos_plist_path(self.LABEL).exists())
        self.assertEqual(cg._retention_read_schedule_manifest(self.data_dir), {})

    def test_windows_task_definition_binds_interpreter_and_exact_argv(self):
        # Migrated oracle of the reviewer's SCHED-windows control: the task
        # runs the verified interpreter (never a POSIX env launcher), every
        # path survives Windows argv quoting, there is no /TR length limit,
        # and nothing forces an overwrite without proven ownership.
        tasks = FakeSchtasks()
        deep = self.data_dir / ("nested segment " * 12).strip()
        (deep / cg.V2_NAMESPACE).mkdir(parents=True)
        with self.on("windows", tasks):
            code, result = cg._retention_maintenance_enable(deep, self.LABEL)
        self.assertEqual((code, result["state"]), (0, "enabled"))
        task = tasks.tasks[self.LABEL]
        self.assertEqual(task["command"], str(Path(sys.executable).absolute()))
        self.assertNotIn("/usr/bin/env", task["command"] + task["arguments"])
        argv = cg._retention_maintenance_executor_command(deep)
        self.assertEqual(task["arguments"], subprocess.list2cmdline(argv[1:]))
        self.assertIn(f'"{deep}"', task["arguments"])
        self.assertGreater(len(task["command"]) + len(task["arguments"]), 261)
        create = [call for call in tasks.calls if call[1] == "/Create"]
        self.assertEqual(len(create), 1)
        self.assertNotIn("/F", create[0])
        self.assertNotIn("/F", cg._retention_windows_schtasks_command(self.LABEL, Path("x.xml")))
        self.assertIn("/F", cg._retention_windows_schtasks_command(self.LABEL, Path("x.xml"),
                                                                   replace=True))
        self.assertFalse(list((deep / cg.V2_NAMESPACE / ".locks").glob("retention-task-*.xml")))

    def test_windows_enable_status_noop_and_disable(self):
        tasks = FakeSchtasks()
        with self.on("windows", tasks):
            code, enabled = cg._retention_maintenance_enable(self.data_dir, self.LABEL)
            self.assertEqual((code, enabled["state"]), (0, "enabled"))
            create = [call for call in tasks.calls if call[1] == "/Create"]
            self.assertEqual(len(create), 1)
            self.assertNotIn("/F", create[0])
            calls = len(tasks.calls)
            code, again = cg._retention_maintenance_enable(self.data_dir, self.LABEL)
            self.assertEqual((code, again.get("no_op")), (0, True))
            self.assertFalse([c for c in tasks.calls[calls:] if c[1] != "/Query"])
            tasks.tasks[self.LABEL]["enabled"] = False
            self.assertEqual(cg._retention_maintenance_status(self.data_dir, self.LABEL)[1]["state"],
                             "prepared")
            code, re_enabled = cg._retention_maintenance_enable(self.data_dir, self.LABEL)
            self.assertEqual((code, re_enabled["state"]), (0, "enabled"))
            self.assertEqual(tasks.calls[-2][1], "/Change")
            code, disabled = cg._retention_maintenance_disable(self.data_dir, self.LABEL)
            self.assertEqual((code, disabled["state"]), (0, "disabled"))
            self.assertNotIn(self.LABEL, tasks.tasks)
            code, gone = cg._retention_maintenance_disable(self.data_dir, self.LABEL)
            self.assertEqual((code, gone.get("no_op")), (0, True))

    def test_windows_foreign_task_is_never_replaced_or_deleted(self):
        tasks = FakeSchtasks()
        tasks.tasks[self.LABEL] = {"command": "C:\\Tools\\other.exe", "arguments": "--job",
                                   "description": "someone else", "enabled": True}
        with self.on("windows", tasks):
            for action in (cg._retention_maintenance_enable, cg._retention_maintenance_disable):
                code, result = action(self.data_dir, self.LABEL)
                self.assertEqual((code, result["reason"]), (2, "foreign_entry"))
        self.assertEqual(tasks.tasks[self.LABEL]["command"], "C:\\Tools\\other.exe")
        self.assertFalse([c for c in tasks.calls if c[1] in {"/Create", "/Delete"}])

    def test_windows_stale_owned_task_is_replaced_with_force(self):
        tasks = FakeSchtasks()
        with self.on("windows", tasks):
            cg._retention_maintenance_enable(self.data_dir, self.LABEL)
            tasks.tasks[self.LABEL]["arguments"] += " --stale"
            old_action = [tasks.tasks[self.LABEL]["command"], tasks.tasks[self.LABEL]["arguments"]]
            entries = cg._retention_read_schedule_manifest(self.data_dir)
            entries[f"windows:{self.LABEL}"]["action"] = old_action
            cg._retention_write_schedule_manifest(self.data_dir, entries)
            code, result = cg._retention_maintenance_enable(self.data_dir, self.LABEL)
        self.assertEqual((code, result["state"]), (0, "enabled"))
        self.assertIn("/F", [c for c in tasks.calls if c[1] == "/Create"][-1])

    def test_platform_selector_maps_real_platform_names(self):
        # Unpatched: every other scheduler test replaces the selector.
        for name, expected in (("darwin", "macos"), ("win32", "windows"),
                               ("linux", None)):
            with self.subTest(platform=name), mock.patch.object(cg.sys, "platform", name):
                self.assertEqual(cg._retention_schedule_platform(), expected)
        with mock.patch.object(cg.sys, "platform", "linux"):
            code, result = cg._retention_maintenance_status(self.data_dir, self.LABEL)
        self.assertEqual((code, result["status"]), (2, "unsupported_platform"))

    def test_status_reaches_the_adapter_through_the_real_selector(self):
        launchd = FakeLaunchd()
        with mock.patch.object(cg.sys, "platform", "darwin"), \
                mock.patch.object(cg, "_retention_scheduler_run", launchd):
            code, result = cg._retention_maintenance_status(self.data_dir, self.LABEL)
        self.assertEqual((code, result["state"]), (0, "disabled"))
        self.assertEqual(launchd.verbs(), ["print"])

    def test_labels_are_single_safe_components(self):
        for label in ("../x", "a/b", "", "x" * 101, "-lead"):
            with self.subTest(label=label):
                self.assertEqual(cg._retention_maintenance_enable(self.data_dir, label)[0], 2)

    def test_maintenance_passes_never_touch_the_scheduler(self):
        self.make_session("old", ended_days_ago=45)
        self.enable_policy()

        def forbidden(argv):
            raise AssertionError(f"scheduler reached: {argv}")
        with mock.patch.object(cg, "_retention_scheduler_run", side_effect=forbidden):
            cg.cleanup_old_sessions(self.data_dir)
            cg.cleanup_old_sessions(self.data_dir, apply=True)
            cg.dispatch(self.payload("SessionEnd", "old"))


if __name__ == "__main__":
    unittest.main()
