"""0.17.0 R5 (plan D1): durable discovery and purge progress across FRESH
processes.

Every maintenance invocation below is a new interpreter running the real
``cleanup_old_sessions`` entry (``cg0170_fresh_process_driver.py``), the same
lifetime as the scheduled ``cleanup --apply`` executor: only on-disk state
carries over. Cost model (virtual clock, see the driver): each listed
namespace / quarantine entry costs ``list_ms``, each adjudication ``adj_ms``,
each entry listed inside an object being purged ``purge_ms``, and every
deadline check one microsecond. Unchecked single steps (one C-level sort of
names a listing just produced, one bounded file read/write) are not charged
here; production charges them on the real clock.

Contract under test (approved amendment plan D1 to constraint lines 45/47):
within capacity -- one names-only listing of the namespace and the
quarantine directory, plus commit, fits one invocation's budget -- every
unregistered name is reached by fresh processes after a bounded number of
invocations, including after missing/damaged hints, crashes at every
persistence boundary and unreliable mtime; beyond capacity every invocation
reports ``capacity_exceeded`` with backlog and never ``scan_complete``,
while registered names (session journal, quarantine records) keep
advancing. Purge of a registered quarantined object makes durable progress
under short budgets and restarts. Synthetic data only.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cg0170_retention_restored import RetentionFixtureBase, cg  # noqa: E402

DRIVER = Path(__file__).with_name("cg0170_fresh_process_driver.py")


class FreshProcessBase(RetentionFixtureBase):
    def fresh(self, budget_ms, *, list_ms=1.0, adj_ms=0.0, purge_ms=0.0,
              apply=True, extra=(), crash=None):
        command = [sys.executable, "-B", str(DRIVER),
                   "--data-dir", str(self.data_dir),
                   "--budget-ms", str(budget_ms), "--list-ms", str(list_ms),
                   "--adj-ms", str(adj_ms), "--purge-ms", str(purge_ms)]
        if apply:
            command.append("--apply")
        if crash:
            command += ["--crash", crash]
        command += list(extra)
        done = subprocess.run(command, capture_output=True, text=True,
                              timeout=120, env=dict(os.environ))
        if crash:
            self.assertEqual(done.returncode, 137,
                             f"crash point {crash} was not reached: {done.stdout[-400:]}"
                             f"{done.stderr[-1200:]}")
            return None
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        out = json.loads(done.stdout.strip().splitlines()[-1])
        # The pass ends within its budget plus at most the unit in flight
        # (one listed entry, one transition = adjudicate + two locked
        # re-verifications, or one purged entry) and the per-check epsilons.
        unit = max(list_ms, 3 * adj_ms, purge_ms)
        self.assertLessEqual(out["virtual_ms"], budget_ms + unit + 1.0, out)
        return out

    def hints(self):
        return cg._read_discovery_registry(self.data_dir)

    def legacy_copy(self, template: Path, name: str) -> Path:
        """An old runtime's session: the directory appears, no journal hint."""
        target = self.data_dir / "sessions-v2" / name
        shutil.copytree(template, target)
        return target

    def template(self) -> Path:
        source = self.make_session("template-eligible", ended_days_ago=45)
        keep = self.root / "template"
        shutil.copytree(source, keep)
        shutil.rmtree(source)
        lock = cg.lifecycle_lock_path(source)
        if lock.exists():
            lock.unlink()
        return keep

    def build_prefix_and_tail(self, prefix=8, *, adopt=True, registered_eligible=None):
        for index in range(prefix):
            self.make_session(f"a-prefix-{index:02}", finished=False)
        if registered_eligible:
            self.make_session(registered_eligible, ended_days_ago=45)
        if adopt:
            self.enable_policy()
        before = self.hints()
        tail = self.make_session("z-legacy-tail", ended_days_ago=45)
        if adopt:
            # An old runtime created the tail: no hint carries it.
            cg._compact_discovery_registry(self.data_dir, before)
            self.assertNotIn("z-legacy-tail", self.hints())
        return tail


class CapacityExceededTests(FreshProcessBase):
    """Migrated R3 oracle (plan D1): the literal input -- eight registered
    prefix sessions plus one unregistered eligible tail, 1 ms per listed
    entry, 3 ms per invocation -- is beyond capacity (one listing needs
    about 10 ms). Original verdict (R3 probe, history): the tail was never
    reached in 20 fresh processes = contract violated. Migrated verdict:
    every invocation reports ``capacity_exceeded`` (after the first full
    attempt), backlog and no ``scan_complete``; registered work advances."""

    def test_literal_input_reports_capacity_and_never_completes(self):
        tail = self.build_prefix_and_tail()
        runs = [self.fresh(3.0) for _ in range(20)]
        self.assertTrue(all(run["backlog"] for run in runs))
        self.assertFalse(any(run["scan_complete"] for run in runs))
        first_full = next(index for index, run in enumerate(runs)
                          if run["discovery"]["share"] == 1.0)
        self.assertLessEqual(first_full, 1)
        self.assertTrue(all(run["capacity_exceeded"] for run in runs[first_full:]))
        self.assertFalse(runs[0]["capacity_exceeded"])
        # Stable progress fields are exposed on every invocation.
        for run in runs:
            for key in ("generation", "attempts", "max_listed",
                        "capacity_exceeded", "window_cursor", "debt"):
                self.assertIn(key, run["discovery"])
        self.assertGreaterEqual(max(run["discovery"]["max_listed"] for run in runs), 3)
        # Not promised beyond capacity, and never claimed.
        self.assertTrue(tail.exists())

    def test_registered_eligible_work_advances_while_capacity_is_exceeded(self):
        tail = self.build_prefix_and_tail(registered_eligible="y-registered-eligible")
        registered = self.session_dir("y-registered-eligible")
        self.assertIn(registered.name, self.hints())
        # One transition costs three charged units (adjudication plus two
        # locked re-verifications), so the budget is 4 ms; one listing of
        # this namespace still needs about 11 ms (beyond capacity).
        runs = []
        for _ in range(20):
            runs.append(self.fresh(4.0, adj_ms=1.0))
            if not registered.exists():
                break
        self.assertFalse(registered.exists(), "registered eligible work starved")
        self.assertTrue(any(run["capacity_exceeded"] for run in runs))
        self.assertFalse(any(run["scan_complete"] for run in runs))
        self.assertTrue(tail.exists())
        quarantined = [record["original_name"] for _p, record in cg._retention_iter_records(
            cg._retention_quarantine_dir(self.data_dir))]
        self.assertEqual(quarantined, [registered.name])

    def test_capacity_clears_after_a_later_complete_generation(self):
        self.build_prefix_and_tail()
        runs = [self.fresh(3.0) for _ in range(4)]
        self.assertTrue(runs[-1]["capacity_exceeded"])
        # Conditions change (a larger budget): a full listing succeeds within
        # the bounded backoff and the state returns to normal.
        later = [self.fresh(40.0) for _ in range(10)]
        cleared = next(index for index, run in enumerate(later)
                       if not run["capacity_exceeded"])
        self.assertLessEqual(cleared, cg._DISCOVERY_PERIODIC_INVOCATIONS + 1)
        self.assertTrue(later[-1]["scan_complete"])
        self.assertFalse(later[-1]["backlog"])


class WithinCapacityTests(FreshProcessBase):
    """Within capacity but beyond half the budget (N*c <= B < 2*N*c): the
    R3 fixed half share never finishes here; plan D1 escalates."""

    BUDGET = 12.0  # namespace listing: 9 sessions + .locks = 10 entries = 10 ms

    def damage(self, kind):
        locks = self.data_dir / "sessions-v2" / ".locks"
        snapshot = cg._discovery_snapshot_path(self.data_dir, "namespace")
        journal = cg._discovery_journal_path(self.data_dir, "namespace")
        state = cg._discovery_state_path(self.data_dir)
        if kind == "hints_missing":
            snapshot.unlink(missing_ok=True)
            journal.unlink(missing_ok=True)
        elif kind == "snapshot_garbage":
            snapshot.write_bytes(b"\x00garbage\n../escape\n")
        elif kind == "snapshot_silent_subset":
            # A legitimate-looking but incomplete snapshot (valid header).
            cg._discovery_write_snapshot(self.data_dir, "namespace", ["a-prefix-00"])
        elif kind == "journal_torn_interleaved":
            with open(journal, "ab") as handle:
                handle.write(b"z-legacy")  # torn record ...
                handle.write(b"-tail\t00000000\n")  # ... merged with a later one
        elif kind == "state_missing":
            state.unlink()
        elif kind == "state_corrupt":
            state.write_text('{"schema": "cg-retention-discovery/v1", "debt": -1}')
        elif kind != "first_time":
            raise AssertionError(kind)
        self.assertTrue(locks.is_dir())

    def test_band_reaches_the_tail_with_escalation_for_every_damage(self):
        for kind in ("first_time", "hints_missing", "snapshot_garbage",
                     "snapshot_silent_subset", "journal_torn_interleaved",
                     "state_missing", "state_corrupt"):
            with self.subTest(kind=kind):
                self.tearDown()
                self.setUp()
                tail = self.build_prefix_and_tail()
                self.fresh(40.0)  # settle a complete generation first
                self.damage(kind)
                runs = []
                for _ in range(3):
                    runs.append(self.fresh(self.BUDGET))
                    if not tail.exists():
                        break
                self.assertFalse(tail.exists(), (kind, runs))
                self.assertFalse(any(run["capacity_exceeded"] for run in runs))
                shares = [run["discovery"]["share"] for run in runs]
                if len(runs) > 1:
                    self.assertEqual(shares[:2], [0.5, 1.0], (kind, runs))
                for _ in range(4):
                    final = self.fresh(self.BUDGET)
                    if final["scan_complete"]:
                        break
                self.assertTrue(final["scan_complete"], (kind, final))
                self.assertFalse(final["backlog"])

    def test_fixed_half_share_would_not_finish_this_band(self):
        """Control: half of this budget cannot list the namespace once, so
        the escalation (not luck or order) is what reaches the tail."""
        self.build_prefix_and_tail()
        first = self.fresh(self.BUDGET)
        self.assertEqual(first["discovery"]["share"], 0.5)
        self.assertFalse(first["discovery"]["generation_complete"])
        self.assertLess(first["discovery"]["listed"], 10)

    def test_frozen_mtime_relies_on_the_periodic_generation(self):
        self.enable_policy()
        for index in range(4):
            self.make_session(f"a-prefix-{index:02}", finished=False)
        frozen = ["--frozen-mtime"]
        for _ in range(3):
            settled = self.fresh(40.0, extra=frozen)
        self.assertFalse(settled["discovery"]["needed"], settled)
        before = self.hints()
        tail = self.make_session("z-legacy-tail", ended_days_ago=45)
        cg._compact_discovery_registry(self.data_dir, before)
        runs = []
        for _ in range(cg._DISCOVERY_PERIODIC_INVOCATIONS + 3):
            runs.append(self.fresh(40.0, extra=frozen))
            if not tail.exists():
                break
        self.assertFalse(tail.exists())
        self.assertIn("periodic", runs[-1]["discovery"]["reasons"])
        self.assertGreater(len(runs), 1, "mtime was not actually frozen")

    def test_unadopted_preview_reports_the_tail_and_writes_no_discovery_object(self):
        """Unadopted roots keep no discovery state or hints (R3 cursor and
        maintenance-lock behavior is unchanged and not asserted here)."""
        self.build_prefix_and_tail(adopt=False)
        discovery_objects = [cg._discovery_state_path(self.data_dir)] + [
            path for scope in cg._DISCOVERY_SCOPES for path in (
                cg._discovery_snapshot_path(self.data_dir, scope),
                cg._discovery_journal_path(self.data_dir, scope),
                cg._discovery_merging_path(self.data_dir, scope))]
        within = self.fresh(self.BUDGET, apply=False)
        self.assertIn("z-legacy-tail", {name for name, _v, _r in within["entries"]})
        self.assertFalse(within["capacity_exceeded"])
        beyond = self.fresh(3.0, apply=False)
        self.assertTrue(beyond["capacity_exceeded"])
        self.assertFalse(beyond["scan_complete"])
        self.assertTrue(beyond["backlog"])
        self.assertEqual([path for path in discovery_objects if path.exists()], [])
        self.assertTrue(self.session_dir("z-legacy-tail").exists())


class CrashBoundaryTests(FreshProcessBase):
    """A process killed at each durable boundary leaves state the next fresh
    process resumes from; the tail is still reached within the band."""

    POINTS = (
        ("attempt_open", 12.0), ("journal_append", 40.0),
        ("listing_end", 12.0), ("snapshot#1", 40.0), ("snapshot#2", 40.0),
        ("rotation#1", 40.0), ("commit#2", 40.0), ("before_finish", 40.0),
        ("record_write#1", 40.0), ("record_write#2", 40.0),
    )

    def test_every_boundary_recovers_from_a_cold_restart(self):
        for point, budget in self.POINTS:
            with self.subTest(point=point):
                self.tearDown()
                self.setUp()
                tail = self.build_prefix_and_tail()
                if point == "rotation#1":
                    # Give the commit a journal to rotate.
                    cg._add_cleanup_registry_entries(self.data_dir, ["a-prefix-00"])
                self.fresh(budget, crash=point)
                runs = []
                for _ in range(4):
                    runs.append(self.fresh(WithinCapacityTests.BUDGET))
                    if not tail.exists():
                        break
                self.assertFalse(tail.exists(), (point, runs))
                self.assertIsNotNone(cg._discovery_read_state(self.data_dir))
                qdir = cg._retention_quarantine_dir(self.data_dir)
                states = [record["state"] for _p, record in cg._retention_iter_records(qdir)]
                self.assertEqual(states, ["quarantined"], (point, states))

    def test_repeated_crashes_are_counted_and_still_escalate(self):
        tail = self.build_prefix_and_tail()
        for _ in range(6):
            self.fresh(WithinCapacityTests.BUDGET, crash="listing_end")
        state = cg._discovery_read_state(self.data_dir)
        self.assertGreaterEqual(state["attempts"], 6)
        self.assertIsNotNone(state["attempt_open"])
        first = self.fresh(WithinCapacityTests.BUDGET)
        self.assertGreaterEqual(first["discovery"]["debt"] + first["discovery"]["generation"], 1)
        runs = [first]
        while tail.exists() and len(runs) < 3:
            runs.append(self.fresh(WithinCapacityTests.BUDGET))
        self.assertFalse(tail.exists(), runs)


class RegisteredProgressTests(FreshProcessBase):
    def test_long_registered_prefix_reaches_the_tail_with_a_bounded_count(self):
        """Registered names need no capacity bound: the durable cursor
        advances across fresh processes. Bound: ceil(p / k) + 1 invocations
        with k adjudications per invocation once listing cost is paid."""
        prefix = 60
        for index in range(prefix):
            self.make_session(f"p-{index:03}", finished=False)
        self.make_session("zz-registered-tail", ended_days_ago=45)
        self.enable_policy()
        tail = self.session_dir("zz-registered-tail")
        budget, adj, listing = 12.0, 1.0, 0.01
        per_invocation = math.floor((budget - (prefix + 2) * listing - 1.0) / adj)
        bound = math.ceil((prefix + 1) / per_invocation) + 1
        runs = []
        while tail.exists() and len(runs) < bound:
            runs.append(self.fresh(budget, list_ms=listing, adj_ms=adj))
        self.assertFalse(tail.exists(), (bound, len(runs)))

    def test_long_registered_prefix_advances_even_beyond_capacity(self):
        prefix = 40
        for index in range(prefix):
            self.make_session(f"p-{index:03}", finished=False)
        self.make_session("zz-registered-tail", ended_days_ago=45)
        self.enable_policy()
        tail = self.session_dir("zz-registered-tail")
        runs = []
        while tail.exists() and len(runs) < 20:
            runs.append(self.fresh(12.0, list_ms=1.0, adj_ms=1.0))
        self.assertFalse(tail.exists(), len(runs))
        self.assertTrue(any(run["capacity_exceeded"] for run in runs))
        self.assertFalse(any(run["scan_complete"] for run in runs))

    def test_controlled_growth_registered_and_legacy_creations(self):
        template = self.template()
        self.enable_policy()
        for index in range(4):
            self.make_session(f"a-prefix-{index:02}", finished=False)
        self.fresh(40.0)
        for round_index in range(5):
            registered = self.make_session(f"r-new-{round_index}", ended_days_ago=45)
            legacy = self.legacy_copy(template, f"l-old-{round_index}")
            self.assertNotIn(legacy.name, self.hints())
            for _ in range(2):
                self.fresh(40.0)
            self.assertFalse(registered.exists(), round_index)
            self.assertFalse(legacy.exists(), round_index)
        # Deleting a hinted session leaves only a stale hint, dropped by the
        # next generation.
        survivor = self.make_session("s-deleted", finished=False)
        shutil.rmtree(survivor)
        for _ in range(2):
            self.fresh(40.0)
        self.assertNotIn("s-deleted", self.hints())

    def test_creation_during_the_listing_survives_compaction(self):
        template = self.template()
        self.enable_policy()
        for index in range(6):
            self.make_session(f"m-prefix-{index:02}", finished=False)
        self.fresh(40.0)
        for kind in ("registered", "legacy"):
            with self.subTest(kind=kind):
                name = f"aa-late-{kind}"
                late = self.data_dir / "sessions-v2" / name
                spec = f"{name}:3:{kind}:{template}"
                # Force a generation so the listing runs while the creation
                # lands behind its position (sorted order, "aa-" first).
                cg._discovery_state_path(self.data_dir).unlink()
                run = self.fresh(40.0, extra=["--create-during-listing", spec])
                self.assertTrue(run["discovery"]["generation_complete"])
                if kind == "registered":
                    # Journaled while the listing ran past its position: the
                    # completed generation's compaction keeps the hint.
                    self.assertIn(name, self.hints())
                else:
                    # mkdir only, behind the listing: unseen this time; the
                    # namespace mtime change triggers the next generation.
                    self.assertTrue(late.exists())
                    self.assertNotIn(name, self.hints())
                runs = 0
                while late.exists() and runs < 2:
                    self.fresh(40.0)
                    runs += 1
                self.assertFalse(late.exists(), kind)


class PurgeProgressTests(FreshProcessBase):
    """Matrix item 5: a registered quarantined object of 19 children purged
    under 3 ms budgets at 1 ms per listed child (R4 review probe input)."""

    def quarantine_wide(self, name="purge-finite-wide", payload=16):
        old = self.make_session(name, ended_days_ago=45)
        for index in range(payload):
            (old / f"payload-{index:02}").write_text("synthetic", encoding="utf-8")
        self.enable_policy(quarantine_days=1)
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record_path = next(path for path, record in cg._retention_iter_records(qdir)
                           if record["original_name"] == old.name)
        record = json.loads(record_path.read_text(encoding="utf-8"))
        return qdir, record_path, record, qdir / record["quarantine_object"]

    def children(self, target):
        """Every entry still inside the object, at any depth."""
        if not target.exists():
            return 0
        return sum(len(dirs) + len(files) for _d, dirs, files in os.walk(target))

    def purge_run(self, budget=3.0, crash=None):
        return self.fresh(budget, list_ms=1.0, purge_ms=1.0,
                          extra=["--future-days", "2"], crash=crash)

    def test_short_budgets_make_durable_progress_and_finish(self):
        qdir, record_path, record, target = self.quarantine_wide()
        before = self.children(target)
        self.assertGreaterEqual(before, 19)
        counts = [before]
        runs = []
        while target.exists() and len(runs) < 15:
            runs.append(self.purge_run())
            counts.append(self.children(target))
        self.assertFalse(target.exists(), counts)
        # Never regresses, and never two invocations in a row without
        # deleting something (a full-share discovery invocation may spend
        # its budget on listing; the next one serves the purge).
        self.assertTrue(all(b <= a for a, b in zip(counts, counts[1:])), counts)
        self.assertFalse(any(a == b == c for a, b, c in zip(counts, counts[1:], counts[2:])
                             if c), counts)
        self.assertFalse(record_path.exists())
        self.assertTrue((qdir / (record["quarantine_object"] + ".tombstone.json")).is_file())
        restored = cg.retention_restore(self.data_dir, record["original_name"])
        self.assertNotEqual(restored.get("outcome"), "restored")

    def test_kill_inside_the_removal_then_restart_keeps_progressing(self):
        qdir, record_path, record, target = self.quarantine_wide()
        before = self.children(target)
        self.purge_run(budget=40.0, crash="purge_unlink#3")
        middle = self.children(target)
        self.assertLess(middle, before)
        state = json.loads(record_path.read_text(encoding="utf-8"))["state"]
        self.assertEqual(state, "purge_planned")
        refused = cg.retention_restore(self.data_dir, record["original_name"])
        self.assertNotEqual(refused.get("outcome"), "restored")
        runs = 0
        while target.exists() and runs < 15:
            self.purge_run()
            runs += 1
        self.assertFalse(target.exists())
        self.assertFalse(record_path.exists())
        self.assertTrue((qdir / (record["quarantine_object"] + ".tombstone.json")).is_file())

    def test_replacement_after_partial_progress_keeps_the_sentinel(self):
        qdir, record_path, record, target = self.quarantine_wide()
        self.purge_run()
        self.assertTrue(target.exists())
        self.assertEqual(json.loads(record_path.read_text(encoding="utf-8"))["state"],
                         "purge_planned")
        shutil.rmtree(target)
        target.mkdir()
        sentinel = target / "replacement-sentinel.txt"
        sentinel.write_text("must survive", encoding="utf-8")
        runs = [self.purge_run() for _ in range(4)]
        self.assertTrue(sentinel.is_file())
        self.assertTrue(any(run["purge"]["purge_refused"] >= 1 for run in runs), runs)
        self.assertFalse(any(run["purge"]["purged"] for run in runs))
        self.assertTrue(record_path.exists())
        self.assertEqual(json.loads(record_path.read_text(encoding="utf-8"))["state"],
                         "purge_planned")

    def test_registered_records_advance_when_the_quarantine_listing_exceeds_capacity(self):
        qdir, record_path, record, target = self.quarantine_wide(payload=0)
        # Unregistered clutter makes one quarantine listing far exceed the
        # budget; the registered record is still reached through its hint.
        for index in range(60):
            (qdir / f"a-unknown-{index:03}.record.json").write_text("{}", encoding="utf-8")
        self.assertLess(record_path.name[:2], "zz")
        self.assertGreater(record_path.name, "a-unknown-059.record.json")
        runs = [self.fresh(6.0, list_ms=1.0, purge_ms=0.1,
                           extra=["--future-days", "2"]) for _ in range(6)]
        self.assertFalse(target.exists())
        self.assertFalse(record_path.exists())
        self.assertTrue((qdir / (record["quarantine_object"] + ".tombstone.json")).is_file())
        # One listing of the quarantine directory (60+ entries) never fits.
        self.assertTrue(all(run["capacity_exceeded"] for run in runs[1:]), runs)
        self.assertFalse(any(run["scan_complete"] for run in runs))


if __name__ == "__main__":
    unittest.main()
