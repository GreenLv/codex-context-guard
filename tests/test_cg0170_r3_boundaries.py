"""0.17.0 R3 regressions: retention root identity and enumeration budget.

RF-C01-TXN: for quarantine, restore and purge, the record's identity is
re-bound after every durable intent and checked on the object actually
moved or opened; a substituted object is left (or put back) untouched and
the transaction never reports success. Matrix: entry x {replaced after the
intent, replaced between the final check and the move, put-back impossible,
parent boundary substituted, recovery of the left state}.

RF-C01-DISCOVERY: every listing (quarantine records, per-name lookups, tree
digest, purge listings, registry parse, namespace backfill) checks the
caller's deadline per unit, and resumable listings reach every finite
entry across passes of one process. Synthetic data only.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cg0170_retention_restored import RetentionFixtureBase, cg  # noqa: E402


class _Base(RetentionFixtureBase):
    def quarantined(self, name):
        old = self.make_session(name, ended_days_ago=45)
        self.enable_policy(quarantine_days=1)
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
        return mock.patch.object(cg.dt, "datetime", Future)

    def after_write(self, predicate, action):
        """Run ``action`` once, right after the first durable record write
        matching ``predicate`` (the intent boundary)."""
        real = cg._retention_write_record
        fired = []

        def write(path, body):
            real(path, body)
            if not fired and predicate(path, body):
                fired.append(True)
                action()
        return mock.patch.object(cg, "_retention_write_record", side_effect=write), fired

    def before_rename(self, source, action):
        """Run ``action`` once immediately before the real rename of
        ``source`` (between the final check and the move)."""
        real = cg.os.rename
        fired = []

        def rename(src, dst, *args, **kwargs):
            if not fired and Path(src) == source:
                fired.append(True)
                action()
            return real(src, dst, *args, **kwargs)
        return mock.patch.object(cg.os, "rename", side_effect=rename), fired


class QuarantineIdentityTests(_Base):
    def setup_swap(self):
        self.old = self.make_session("swap-me", ended_days_ago=45)
        self.enable_policy()
        self.replacement = self.make_session("unfinished-other", finished=False)
        self.aside = self.root / "original-aside"
        self.replacement_state = (self.replacement / "state.json").read_bytes()

    def swap(self):
        os.rename(self.old, self.aside)
        os.rename(self.replacement, self.old)

    def assert_replacement_untouched(self, report):
        self.assertEqual(report["counts"]["quarantined"], 0)
        self.assertEqual((self.old / "state.json").read_bytes(), self.replacement_state)
        self.assertTrue((self.aside / "state.json").is_file())

    def test_replaced_after_intent_is_refused_and_intent_dropped(self):
        self.setup_swap()
        patch, fired = self.after_write(
            lambda p, b: b.get("state") == "planned", self.swap)
        with patch:
            report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertTrue(fired)
        self.assert_replacement_untouched(report)
        self.assertEqual(cg._retention_iter_records(cg._retention_quarantine_dir(self.data_dir)), [])
        self.assertIn("identity_changed", json.dumps(report["entries"]))

    def test_replaced_between_check_and_move_is_put_back(self):
        self.setup_swap()
        patch, fired = self.before_rename(self.old, self.swap)
        with patch:
            report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertTrue(fired)
        self.assert_replacement_untouched(report)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        self.assertEqual(cg._retention_iter_records(qdir), [])
        self.assertEqual([p for p in qdir.iterdir() if p.is_dir()], [])

    def test_put_back_impossible_keeps_both_objects_and_an_indeterminate_intent(self):
        self.setup_swap()
        real = cg.os.rename
        # Swap right before the move, and occupy the name right after it,
        # so the wrongly moved object cannot be put back.
        calls = {"n": 0}

        def composed(src, dst, *args, **kwargs):
            if calls["n"] == 0 and Path(src) == self.old:
                calls["n"] += 1
                self.swap()
                result = real(src, dst, *args, **kwargs)
                self.old.mkdir()
                (self.old / "occupant").write_text("x", encoding="utf-8")
                return result
            return real(src, dst, *args, **kwargs)
        with mock.patch.object(cg.os, "rename", side_effect=composed):
            report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(report["counts"]["quarantined"], 0)
        self.assertIn("identity_changed_unresolved", json.dumps(report["entries"]))
        qdir = cg._retention_quarantine_dir(self.data_dir)
        records = cg._retention_iter_records(qdir)
        self.assertEqual([r["state"] for _p, r in records], ["planned"])
        moved = qdir / records[0][1]["quarantine_object"]
        self.assertEqual((moved / "state.json").read_bytes(), self.replacement_state)
        self.assertTrue((self.aside / "state.json").is_file())
        summary = cg._retention_recover_records(qdir, cg.dt.datetime.now(cg.dt.timezone.utc))
        self.assertEqual(summary["indeterminate"], 1)
        self.assertTrue(moved.is_dir())

    def test_substituted_quarantine_parent_is_refused(self):
        old = self.make_session("parent-swap", ended_days_ago=45)
        self.enable_policy()
        qdir = cg._retention_quarantine_dir(self.data_dir)
        qdir.mkdir(parents=True, exist_ok=True)
        outside = self.root / "outside-quarantine"
        outside.mkdir()

        def substitute():
            os.rename(qdir, self.root / "real-quarantine-aside")
            os.symlink(outside, qdir, target_is_directory=True)
        patch, fired = self.after_write(
            lambda p, b: b.get("state") == "planned", substitute)
        with patch:
            report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertTrue(fired)
        self.assertEqual(report["counts"]["quarantined"], 0)
        self.assertTrue((old / "state.json").is_file())
        self.assertEqual(list(outside.iterdir()), [])


class RestoreIdentityTests(_Base):
    def test_replaced_after_intent_is_refused_and_record_reverted(self):
        old, qdir, record_path, record, target = self.quarantined("restore-a")
        aside = qdir / "aside"

        def swap():
            os.rename(target, aside)
            target.mkdir()
            (target / "unrelated").write_text("stay", encoding="utf-8")
        patch, fired = self.after_write(
            lambda p, b: p == record_path and b.get("state") == "restore_planned", swap)
        with patch:
            report = cg.retention_restore(self.data_dir, old.name)
        self.assertTrue(fired)
        self.assertEqual((report["outcome"], report["reason"]), ("refused", "identity_changed"))
        self.assertFalse(old.exists())
        self.assertTrue((target / "unrelated").is_file())
        self.assertEqual(json.loads(record_path.read_text())["state"], "quarantined")

    def test_content_changed_after_intent_is_refused(self):
        old, qdir, record_path, record, target = self.quarantined("restore-b")
        patch, fired = self.after_write(
            lambda p, b: p == record_path and b.get("state") == "restore_planned",
            lambda: (target / "state.json").write_text("{}", encoding="utf-8"))
        with patch:
            report = cg.retention_restore(self.data_dir, old.name)
        self.assertEqual((report["outcome"], report["reason"]), ("refused", "identity_changed"))
        self.assertFalse(old.exists())
        self.assertTrue(target.is_dir())

    def test_replaced_between_check_and_move_is_put_back(self):
        old, qdir, record_path, record, target = self.quarantined("restore-c")
        aside = qdir / "aside"

        def swap():
            os.rename(target, aside)
            target.mkdir()
            (target / "unrelated").write_text("stay", encoding="utf-8")
        patch, fired = self.before_rename(target, swap)
        with patch:
            report = cg.retention_restore(self.data_dir, old.name)
        self.assertTrue(fired)
        self.assertEqual((report["outcome"], report["reason"]), ("refused", "identity_changed"))
        self.assertFalse(old.exists())
        self.assertTrue((target / "unrelated").is_file())
        self.assertTrue((aside / "state.json").is_file())
        self.assertEqual(json.loads(record_path.read_text())["state"], "quarantined")


class PurgeIdentityTests(_Base):
    def swap_target(self, target, qdir):
        aside = qdir / "aside"

        def swap():
            os.rename(target, aside)
            target.mkdir()
            (target / "sentinel").write_text("must survive", encoding="utf-8")
        return aside, swap

    def test_replaced_after_intent_is_refused_and_sentinel_survives(self):
        old, qdir, record_path, record, target = self.quarantined("purge-a")
        aside, swap = self.swap_target(target, qdir)
        patch, fired = self.after_write(
            lambda p, b: p == record_path and b.get("state") == "purge_planned", swap)
        with patch, self.future():
            report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertTrue(fired)
        self.assertEqual(report["purge"]["purged"], 0)
        self.assertEqual(report["purge"]["purge_refused"], 1)
        self.assertTrue((target / "sentinel").is_file())
        self.assertTrue((aside / "state.json").is_file())
        self.assertEqual(json.loads(record_path.read_text())["state"], "purge_planned")
        # Later passes keep refusing; nothing is ever deleted.
        with self.future():
            again = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(again["purge"]["purge_refused"], 1)
        self.assertTrue((target / "sentinel").is_file())

    def test_replaced_inside_the_removal_window_is_refused(self):
        old, qdir, record_path, record, target = self.quarantined("purge-b")
        aside, swap = self.swap_target(target, qdir)
        real = cg._retention_purge_tree

        def swap_then_remove(path, deadline):
            swap()
            return real(path, deadline)
        with mock.patch.object(cg, "_retention_purge_tree", side_effect=swap_then_remove), \
                self.future():
            report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(report["purge"]["purge_refused"], 1)
        self.assertTrue((target / "sentinel").is_file())
        self.assertTrue((aside / "state.json").is_file())

    def test_bound_removal_refuses_without_the_pass(self):
        _old, qdir, _rp, record, target = self.quarantined("purge-c")
        other = qdir / "other-dir"
        other.mkdir()
        (other / "sentinel").write_text("x", encoding="utf-8")
        with cg._retention_expect_root(record["identity"]):
            self.assertFalse(cg._retention_purge_tree(other, None))
        self.assertTrue((other / "sentinel").is_file())
        with cg._retention_expect_root(record["identity"]):
            self.assertTrue(cg._retention_purge_tree(target, None))
        self.assertFalse(target.exists())


class EnumerationBudgetTests(_Base):
    def charged(self, target_name):
        """Fake clock charging 1 ms per call of ``target_name``."""
        clock = [1000.0]
        real = getattr(cg, target_name)

        def charged(*args, **kwargs):
            clock[0] += 0.001
            return real(*args, **kwargs)
        return clock, mock.patch.object(cg, target_name, side_effect=charged), \
            mock.patch.object(cg.time, "monotonic", side_effect=lambda: clock[0])

    def unknown_records(self, count):
        qdir = cg._retention_quarantine_dir(self.data_dir)
        qdir.mkdir(parents=True, exist_ok=True)
        for index in range(count):
            (qdir / f"unknown-{index:03}.record.json").write_text("{}", encoding="utf-8")
        return qdir

    def test_record_scan_stays_within_budget_and_resumes_to_the_end(self):
        self.make_session("control", ended_days_ago=45)
        self.enable_policy()
        self.unknown_records(100)
        clock, read_patch, time_patch = self.charged("_retention_read_record")
        seen = 0
        with read_patch, time_patch:
            for _ in range(150):
                start = clock[0]
                report = cg.cleanup_old_sessions(self.data_dir, deadline=start + 0.003)
                self.assertLessEqual(clock[0] - start, 0.003 + 0.001 + 1e-9)
                seen += report["unknown_records"]
                if report["records_scan_complete"] and seen >= 100:
                    break
        self.assertEqual(seen, 100)

    def test_per_name_lookup_fails_closed_when_cut(self):
        session = self.make_session("lookup", ended_days_ago=45)
        self.enable_policy()
        self.unknown_records(20)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        expired = time.monotonic() - 1
        lookup = cg._retention_collect_records(qdir, expired, prefix="lookup.")
        self.assertFalse(lookup["complete"])
        shutil.rmtree(session)
        with self.assertRaises(cg.RetentionRecreationRefused):
            cg._retention_recreation_guard(session, deadline=expired)
        report = cg.retention_restore(self.data_dir, "lookup", deadline=time.monotonic() + 5)
        self.assertEqual(report["outcome"], "not_found")

    def test_tree_digest_and_purge_listing_stop_at_the_deadline(self):
        old = self.make_session("tree", ended_days_ago=45)
        for index in range(50):
            (old / f"extra-{index}.txt").write_text("x", encoding="utf-8")
        expired = time.monotonic() - 1
        self.assertIsNone(cg._retention_tree_digest(old, expired))
        self.assertFalse(cg._retention_purge_tree(old, expired))
        self.assertTrue((old / "state.json").is_file())

    def test_registry_parse_respects_the_deadline(self):
        self.make_session("reg", ended_days_ago=45)
        self.enable_policy()
        registry = cg._cleanup_registry_path(self.data_dir)
        registry.write_text("".join(f"name-{i}\n" for i in range(5000)), encoding="utf-8")
        partial = cg._read_discovery_registry(self.data_dir, deadline=time.monotonic() - 1)
        full = cg._read_discovery_registry(self.data_dir)
        self.assertLess(len(partial), len(full))
        self.assertEqual(len(full), 5000)


class UnregisteredTailFairnessTests(_Base):
    def build(self, *, adopt=True, damage=None):
        for index in range(8):
            self.make_session(f"a-prefix-{index:02}", finished=False)
        if adopt:
            self.enable_policy()
        before = cg._read_discovery_registry(self.data_dir)
        tail = self.make_session("z-legacy-tail", ended_days_ago=45)
        registry = cg._cleanup_registry_path(self.data_dir)
        if adopt:
            cg._compact_discovery_registry(self.data_dir, before)
        if damage == "missing":
            registry.unlink(missing_ok=True)
        elif damage == "corrupt":
            registry.write_text("\x00garbage\n../escape\n", encoding="utf-8")
        elif damage == "oversized":
            registry.write_text("x" * 64, encoding="utf-8")  # read with a tiny limit
        return tail

    def passes(self, count, *, apply=True, limit=None):
        clock = [1000.0]
        visited: list = []
        reports = []
        with contextlib.ExitStack() as stack:
            stack.enter_context(self.scan_stub(self.data_dir / "sessions-v2", visited, clock))
            stack.enter_context(mock.patch.object(
                cg.time, "monotonic", side_effect=lambda: clock[0]))
            if limit is not None:
                stack.enter_context(mock.patch.object(
                    cg, "_RETENTION_REGISTRY_READ_LIMIT", limit))
            for _ in range(count):
                start = clock[0]
                reports.append(cg.cleanup_old_sessions(
                    self.data_dir, apply=apply, deadline=start + 0.003))
                self.assertLessEqual(clock[0] - start, 0.003 + 0.001 + 1e-9)
        return visited, reports

    def test_lost_registration_tail_is_reached_within_budget(self):
        tail = self.build()
        visited, _reports = self.passes(20)
        self.assertFalse(tail.exists())
        # The listing resumed instead of re-reading its first entries each
        # pass: the first generation covers all nine names before repeating.
        self.assertEqual(sorted(visited[:9]),
                         [f"a-prefix-{i:02}" for i in range(8)] + ["z-legacy-tail"])

    def test_damaged_registry_variants_still_reach_the_tail(self):
        for damage, limit in (("missing", None), ("corrupt", None), ("oversized", 8)):
            with self.subTest(damage=damage):
                self.tearDown()
                self.setUp()
                tail = self.build(damage=damage)
                self.passes(30, limit=limit)
                self.assertFalse(tail.exists())

    def test_unadopted_preview_reports_the_tail_without_writing(self):
        self.build(adopt=False)
        registry = cg._cleanup_registry_path(self.data_dir)
        visited, reports = self.passes(20, apply=False)
        names = {entry["name"] for report in reports for entry in report["entries"]}
        self.assertIn("z-legacy-tail", names)
        self.assertFalse(registry.exists())

    def test_generation_completes_and_restarts_for_later_insertions(self):
        tail = self.build()
        self.passes(20)
        self.assertFalse(tail.exists())
        late = self.make_session("zz-later", ended_days_ago=45)
        cg._compact_discovery_registry(self.data_dir, cg._read_discovery_registry(self.data_dir) - {"zz-later"})
        self.passes(20)
        self.assertFalse(late.exists())


if __name__ == "__main__":
    unittest.main()
