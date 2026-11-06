"""0.17.0 R6: Windows newline compatibility of the discovery hints and
replacement-object binding of the purge stage.

N1 (Windows native batch, four failures): the product's own discovery
snapshot writer went through a text-mode temporary file without an explicit
newline, so Windows wrote CRLF; the strict snapshot reader rejected those
bytes as ``corrupt`` and the hints were lost after the journal rotation.
The family below drives the official writer under emulated Windows
text-mode translation, reads the raw bytes back from a NEW process, and
replays the retention batch with that emulation. A CRLF snapshot from an
older candidate stays ``corrupt`` (never trusted) and is rebuilt; records
that discovery restores in a pass are still served in that pass.

N2 (Linux CI, Python 3.10-3.14): a quarantined object bound only by
``(dev, ino)`` can be impersonated by a replacement directory that reuses
the freed inode. The fresh-process family below forces exactly that reuse
(the record identity equals the replacement's) and requires the
replacement and its sentinel to survive, while normal purge, crash restart
and partial progress keep advancing. It runs with the platform's creation
time and again on a modeled filesystem without one (change-time binding).

R7 closes the same ownership-provenance invariant at the two remaining
entries that minted a binding from whatever occupied the quarantine name
(the commit after the rename and the ``planned`` recovery) and at the
outer write-back that turned a refused opened-root check into "I
partially removed it". ``OwnershipProvenanceTests`` and the change-time
refusal test force the identity-reuse model with real timestamps or the
modeled no-creation-time filesystem; a refused, unknown or not-executed
removal never becomes authority. Synthetic data only.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cg0170_r5_discovery as r5  # noqa: E402
from cg0170_fresh_process_driver import windows_text_tempfile  # noqa: E402
from test_cg0170_retention_restored import cg  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "context_guard.py"

FRESH_READER = r"""
import importlib.util, json, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("cg_reader", sys.argv[1])
cg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cg)
hints = cg._discovery_read_hints(Path(sys.argv[2]), sys.argv[3])
print(json.dumps({"snapshot": hints.facts["snapshot"], "names": sorted(hints.names())}))
"""


def windows_text_mode():
    return mock.patch.object(cg, "tempfile", windows_text_tempfile())


class WindowsNewlineTests(r5.FreshProcessBase):
    def fresh_read(self, scope):
        done = subprocess.run(
            [sys.executable, "-I", "-B", "-c", FRESH_READER, str(SCRIPT),
             str(self.data_dir), scope], capture_output=True, text=True,
            timeout=60, check=True)
        return json.loads(done.stdout)

    def test_emulation_translates_an_unspecified_newline(self):
        # Control: the emulation is real, so the tests below can fail.
        probe = self.root / "probe.json"
        with windows_text_mode():
            cg.atomic_write_text(probe, "a\nb\n")
        self.assertEqual(probe.read_bytes(), b"a\r\nb\r\n")

    def test_official_snapshot_writer_publishes_lf_bytes_for_a_fresh_reader(self):
        self.make_session("alpha-session")
        self.enable_policy()
        names = sorted(["alpha-one", "beta-two", "gamma-three"])
        with windows_text_mode():
            self.assertTrue(cg._discovery_write_snapshot(self.data_dir, "namespace", names))
        raw = cg._discovery_snapshot_path(self.data_dir, "namespace").read_bytes()
        self.assertNotIn(b"\r", raw)
        read = self.fresh_read("namespace")
        self.assertEqual(read["snapshot"], "ok")
        self.assertEqual(read["names"], names)

    def test_compacted_registry_survives_a_fresh_process_under_windows_text_mode(self):
        self.make_session("registered-one", ended_days_ago=45)
        self.enable_policy()
        before = cg._read_discovery_registry(self.data_dir)
        self.assertIn(self.session_dir("registered-one").name, before)
        with windows_text_mode():
            cg._compact_discovery_registry(self.data_dir, before)
        read = self.fresh_read("namespace")
        self.assertEqual(read["snapshot"], "ok")
        self.assertEqual(set(read["names"]), before)

    def test_a_crlf_snapshot_is_never_trusted_and_is_rebuilt_with_lf(self):
        self.make_session("crlf-registered", ended_days_ago=45, finished=False)
        self.enable_policy()
        names = sorted(cg._read_discovery_registry(self.data_dir))
        self.assertTrue(cg._discovery_write_snapshot(self.data_dir, "namespace", names))
        path = cg._discovery_snapshot_path(self.data_dir, "namespace")
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        read = self.fresh_read("namespace")
        self.assertEqual(read["snapshot"], "corrupt")
        run = self.fresh(200.0)
        self.assertIn("namespace_snapshot_corrupt", run["discovery"]["reasons"])
        runs = 0
        while b"\r" in path.read_bytes() and runs < 4:
            self.fresh(200.0)
            runs += 1
        self.assertNotIn(b"\r", path.read_bytes())
        self.assertEqual(self.fresh_read("namespace")["snapshot"], "ok")

    def test_records_restored_by_discovery_are_served_in_the_same_pass(self):
        qdir, record_path, record, target = r5.PurgeProgressTests.quarantine_wide(
            self, name="window-reopen", payload=2)
        # The records hints are lost (damaged snapshot, rotated journal):
        # only this pass's discovery listing can find the record again.
        snapshot = cg._discovery_snapshot_path(self.data_dir, "records")
        snapshot.write_bytes(b"damaged\r\n")
        for path in (cg._discovery_journal_path(self.data_dir, "records"),
                     cg._discovery_merging_path(self.data_dir, "records")):
            path.unlink(missing_ok=True)
        run = self.fresh(5000.0, list_ms=0.01, purge_ms=0.01,
                         extra=["--future-days", "2"])
        self.assertIn("records_snapshot_corrupt", run["discovery"]["reasons"])
        self.assertEqual(run["purge"]["purged"], 1, run)
        self.assertFalse(target.exists())
        self.assertFalse(record_path.exists())
        self.assertTrue((qdir / (record["quarantine_object"] + ".tombstone.json")).is_file())

    def test_registered_work_advances_beyond_capacity_under_windows_text_mode(self):
        registered_name = "y-registered-eligible"
        for index in range(8):
            self.make_session(f"a-prefix-{index:02}", finished=False)
        self.make_session(registered_name, ended_days_ago=45)
        with windows_text_mode():
            self.enable_policy()
            before = cg._read_discovery_registry(self.data_dir)
            tail = self.make_session("z-legacy-tail", ended_days_ago=45)
            cg._compact_discovery_registry(self.data_dir, before)
        registered = self.session_dir(registered_name)
        runs = [self.fresh(4.0, list_ms=1.0, extra=["--windows-newlines"])
                for _ in range(8)]
        self.assertFalse(registered.exists(), runs)
        self.assertTrue(tail.exists())
        self.assertTrue(all(run["backlog"] for run in runs))
        self.assertFalse(any(run["scan_complete"] for run in runs))

    def test_partial_purge_completes_across_fresh_processes_under_windows_text_mode(self):
        with windows_text_mode():
            qdir, record_path, record, target = r5.PurgeProgressTests.quarantine_wide(self)
        runs = 0
        while target.exists() and runs < 15:
            self.fresh(3.0, list_ms=1.0, purge_ms=1.0,
                       extra=["--future-days", "2", "--windows-newlines"])
            runs += 1
        self.assertFalse(target.exists())
        self.assertFalse(record_path.exists())
        self.assertTrue((qdir / (record["quarantine_object"] + ".tombstone.json")).is_file())


def _native_module():
    spec = importlib.util.spec_from_file_location(
        "native_acceptance_r6", ROOT / "tools" / "validation" / "native_acceptance.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class WindowsNewlineBatchTests(unittest.TestCase):
    """The real retention batch with Windows text-mode translation emulated
    in the runtime module it drives (the four original Windows failures
    were reproduced this way on the R5 source; macOS emulation is source
    evidence, never Windows native acceptance)."""

    def test_the_batch_family_passes_under_emulated_windows_newlines(self):
        native = _native_module()
        original = importlib.util.spec_from_file_location

        def spec_with_windows_text(name, location, *args, **kwargs):
            spec = original(name, location, *args, **kwargs)
            if name != "context_guard_batch":
                return spec
            load = spec.loader.exec_module

            def exec_module(module):
                load(module)
                module.tempfile = windows_text_tempfile()
            spec.loader.exec_module = exec_module
            return spec
        with mock.patch.object(importlib.util, "spec_from_file_location",
                               side_effect=spec_with_windows_text):
            scenarios = native.run_retention_batch_scenarios(ROOT)
        failed = {row["name"]: row["detail"].get("checks") for row in scenarios
                  if row["status"] != "passed"}
        self.assertEqual(failed, {})
        with tempfile.TemporaryDirectory() as temp:
            result = native._finish_retention_batch(
                Path(temp) / "result.json", scenarios, "a" * 40, "b" * 64,
                native.timestamp())
        self.assertEqual(native.validate_retention_batch_result(
            result, source_commit="a" * 40, runtime_tree_sha256="b" * 64), [])


class ReplacementBindingTests(r5.FreshProcessBase):
    """A replacement that reuses the bound ``(dev, ino)`` -- forced here by
    rebinding the record to the replacement's identity, the observable
    effect of fast inode reuse -- is never purged."""

    quarantine_wide = r5.PurgeProgressTests.quarantine_wide
    children = r5.PurgeProgressTests.children

    def purge_run(self, budget=3.0, crash=None):
        return self.fresh(budget, list_ms=1.0, purge_ms=1.0,
                          extra=["--future-days", "2"], crash=crash)

    def reuse_identity(self, record_path, target):
        """Rebind the record to the replacement's identity, exactly what a
        reused inode number looks like to an ``(dev, ino)`` comparison."""
        info = target.lstat()
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["identity"] = [info.st_dev, info.st_ino]
        record_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    def replace(self, target):
        shutil.rmtree(target)
        target.mkdir()
        sentinel = target / "replacement-sentinel.txt"
        sentinel.write_text("must survive", encoding="utf-8")
        return sentinel

    def state(self, record_path):
        return json.loads(record_path.read_text(encoding="utf-8"))["state"]

    def assert_refused(self, runs, sentinel, record_path, state):
        self.assertTrue(sentinel.is_file())
        self.assertTrue(any(run["purge"]["purge_refused"] >= 1 for run in runs), runs)
        self.assertFalse(any(run["purge"]["purged"] for run in runs), runs)
        self.assertTrue(record_path.exists())
        self.assertEqual(self.state(record_path), state)

    def test_whole_replacement_reusing_the_identity_is_refused(self):
        qdir, record_path, record, target = self.quarantine_wide(payload=2)
        sentinel = self.replace(target)
        self.reuse_identity(record_path, target)
        runs = [self.purge_run(budget=40.0) for _ in range(3)]
        self.assert_refused(runs, sentinel, record_path, "quarantined")
        self.assertFalse((qdir / (record["quarantine_object"] + ".tombstone.json")).exists())

    def test_replacement_after_partial_progress_reusing_the_identity_is_refused(self):
        qdir, record_path, record, target = self.quarantine_wide()
        self.purge_run()
        self.assertTrue(target.exists())
        self.assertEqual(self.state(record_path), "purge_planned")
        sentinel = self.replace(target)
        self.reuse_identity(record_path, target)
        runs = [self.purge_run() for _ in range(4)]
        self.assert_refused(runs, sentinel, record_path, "purge_planned")

    def test_crash_inside_removal_then_identity_reusing_replacement_is_refused(self):
        qdir, record_path, record, target = self.quarantine_wide()
        self.purge_run(budget=40.0, crash="purge_unlink#3")
        self.assertEqual(self.state(record_path), "purge_planned")
        sentinel = self.replace(target)
        self.reuse_identity(record_path, target)
        runs = [self.purge_run(budget=40.0) for _ in range(3)]
        self.assert_refused(runs, sentinel, record_path, "purge_planned")

    def test_linked_replacement_is_refused_and_the_outside_object_kept(self):
        outside = self.root / "outside-object"
        outside.mkdir()
        keep = outside / "keep.txt"
        keep.write_text("outside", encoding="utf-8")
        qdir, record_path, record, target = self.quarantine_wide()
        self.purge_run()
        self.assertEqual(self.state(record_path), "purge_planned")
        shutil.rmtree(target)
        try:
            os.symlink(outside, target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links unavailable")
        runs = [self.purge_run(budget=40.0) for _ in range(2)]
        self.assertTrue(keep.is_file())
        self.assertTrue(any(run["purge"]["purge_refused"] for run in runs), runs)
        self.assertTrue(record_path.exists())

    def test_external_hard_link_inside_the_object_survives_the_purge(self):
        outside = self.root / "outside-file.txt"
        outside.write_text("outside", encoding="utf-8")
        old = self.make_session("hardlinked", ended_days_ago=45)
        try:
            os.link(outside, old / "linked.txt")
        except (OSError, NotImplementedError):
            self.skipTest("hard links unavailable")
        self.enable_policy(quarantine_days=1)
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record_path, record = next((path, record) for path, record
                                   in cg._retention_iter_records(qdir))
        target = qdir / record["quarantine_object"]
        runs = 0
        while target.exists() and runs < 4:
            self.purge_run(budget=40.0)
            runs += 1
        self.assertFalse(target.exists())
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside")

    def test_crash_after_the_purge_intent_resumes(self):
        qdir, record_path, record, target = self.quarantine_wide()
        # The first record write of a purge invocation is the purge intent.
        self.purge_run(budget=40.0, crash="record_write#1")
        self.assertEqual(self.state(record_path), "purge_planned")
        runs = 0
        while target.exists() and runs < 15:
            self.purge_run()
            runs += 1
        self.assertFalse(target.exists())
        self.assertFalse(record_path.exists())
        self.assertTrue((qdir / (record["quarantine_object"] + ".tombstone.json")).is_file())

    def test_the_stamp_is_bound_at_quarantine_and_survives_partial_removal(self):
        qdir, record_path, record, target = self.quarantine_wide()
        stamp = record["object_stamp"]
        self.assertIn(stamp["kind"], ("birth", "ctime"))
        if os.name == "nt" or sys.platform == "darwin":
            self.assertEqual(stamp["kind"], "birth")
        self.purge_run()
        self.assertEqual(self.state(record_path), "purge_planned")
        after = json.loads(record_path.read_text(encoding="utf-8"))["object_stamp"]
        if stamp["kind"] == "birth":
            self.assertEqual(after, stamp)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux statx path")
    def test_linux_creation_time_is_read_consistently_or_reported_absent(self):
        probe = self.root / "statx-probe"
        probe.mkdir()
        info = probe.lstat()
        by_path = cg._retention_linux_birth_ns(probe, info.st_ino)
        fd = os.open(probe, os.O_RDONLY)
        try:
            by_fd = cg._retention_linux_birth_ns(fd, os.fstat(fd).st_ino)
        finally:
            os.close(fd)
        self.assertEqual(by_path, by_fd)
        if by_path is not None:
            self.assertLess(abs(by_path - info.st_mtime_ns), 5_000_000_000)
            self.assertIsNone(cg._retention_linux_birth_ns(probe, info.st_ino + 1))

    def test_a_record_without_the_stamp_is_verified_by_its_tree(self):
        qdir, record_path, record, target = self.quarantine_wide(payload=2)
        legacy = json.loads(record_path.read_text(encoding="utf-8"))
        legacy.pop("object_stamp", None)
        record_path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
        run = self.purge_run(budget=40.0)
        self.assertEqual(run["purge"]["purged"], 1, run)
        self.assertFalse(target.exists())
        # Negative: the same legacy shape over an identity-reusing
        # replacement is refused by the tree comparison.
        qdir, record_path, record, target = self.quarantine_wide(
            name="legacy-replaced", payload=2)
        legacy = json.loads(record_path.read_text(encoding="utf-8"))
        legacy.pop("object_stamp", None)
        record_path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
        sentinel = self.replace(target)
        self.reuse_identity(record_path, target)
        runs = [self.purge_run(budget=40.0) for _ in range(2)]
        self.assert_refused(runs, sentinel, record_path, "quarantined")


class ChangeTimeBindingTests(ReplacementBindingTests):
    """The same family on a modeled filesystem without creation time: the
    binding is the change time, re-recorded after each own partial removal.
    A crash inside a removal leaves an unexplained change, which is refused
    (data kept) -- the documented boundary of such filesystems."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(cg, "_retention_birth_ns", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def purge_run(self, budget=3.0, crash=None):
        return self.fresh(budget, list_ms=1.0, purge_ms=1.0,
                          extra=["--future-days", "2", "--no-birth-time"], crash=crash)

    def test_the_stamp_is_bound_at_quarantine_and_survives_partial_removal(self):
        qdir, record_path, record, target = self.quarantine_wide()
        self.assertEqual(record["object_stamp"]["kind"], "ctime")
        runs = 0
        while target.exists() and runs < 15:
            self.purge_run()
            runs += 1
        self.assertFalse(target.exists())
        self.assertTrue((qdir / (record["quarantine_object"] + ".tombstone.json")).is_file())

    def test_crash_inside_a_removal_is_refused_and_keeps_the_data(self):
        qdir, record_path, record, target = self.quarantine_wide()
        self.purge_run(budget=40.0, crash="purge_unlink#3")
        middle = self.children(target)
        runs = [self.purge_run(budget=40.0) for _ in range(2)]
        self.assertEqual(self.children(target), middle)
        self.assertTrue(all(run["purge"]["purge_refused"] for run in runs), runs)
        self.assertEqual(self.state(record_path), "purge_planned")
        refused = cg.retention_restore(self.data_dir, record["original_name"])
        self.assertNotEqual(refused.get("outcome"), "restored")

    def test_refusal_before_any_removal_never_adopts_the_current_stamp(self):
        # R7 entry 1: the real opened-root check refuses a replacement
        # (identity-reuse model, no creation time on this modeled
        # filesystem); the outer pass must count a refusal and must not
        # write the replacement's change time as the record's binding --
        # which the next pass would then purge.
        qdir, record_path, record, target = self.quarantine_wide()
        original_stamp = dict(record["object_stamp"])
        self.assertEqual(original_stamp["kind"], "ctime")
        real_purge = cg._retention_purge_tree
        sentinel = target / "replacement-sentinel.txt"

        def swap_then_real_purge(path, deadline):
            self.assertEqual(path, target)
            os.rename(target, self.root / "original-preserved")
            target.mkdir()
            sentinel.write_text("must survive", encoding="utf-8")
            current = json.loads(record_path.read_text(encoding="utf-8"))
            info = target.lstat()
            current["identity"] = [info.st_dev, info.st_ino]
            cg._retention_write_record(record_path, current)
            # The real helper refuses this different change time and has
            # removed nothing of the replacement.
            removed = real_purge(path, deadline)
            self.assertFalse(removed)
            self.assertTrue(sentinel.is_file())
            return removed

        real_datetime = cg.dt.datetime
        future = real_datetime.now(cg.dt.timezone.utc) + cg.dt.timedelta(days=2)

        class FutureClock(real_datetime):
            @classmethod
            def now(cls, tz=None):
                return future if tz else future.replace(tzinfo=None)

        with mock.patch.object(cg.dt, "datetime", FutureClock):
            with mock.patch.object(cg, "_retention_purge_tree",
                                   side_effect=swap_then_real_purge):
                first = cg.cleanup_old_sessions(self.data_dir, apply=True)
            self.assertEqual(first["purge"]["purge_partial"], 0, first)
            self.assertEqual(first["purge"]["purge_refused"], 1, first)
            persisted = json.loads(record_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["object_stamp"], original_stamp)
            second = cg.cleanup_old_sessions(self.data_dir, apply=True)
            self.assertEqual(second["purge"]["purged"], 0, second)
            self.assertEqual(second["purge"]["purge_refused"], 1, second)
        self.assertTrue(sentinel.is_file())
        self.assertTrue((self.root / "original-preserved").is_dir())


class OwnershipProvenanceTests(ReplacementBindingTests):
    """R7 (N2): one ownership-provenance invariant across the chain.

    A current object or timestamp becomes destructive authority only when
    it is proven to still belong to the originally selected object. Two
    entries minted authority from whatever occupied the quarantine name:
    the ``quarantined`` commit after the rename and the ``planned``
    recovery. Both tests force the identity-reuse model (the record's
    ``(dev, ino)`` equals the replacement's, exactly what a fast inode
    reuse looks like) with real platform creation times, and keep a
    sentinel the maintenance must never remove.
    """

    def future_pass(self):
        real = cg.dt.datetime
        now = real.now(cg.dt.timezone.utc) + cg.dt.timedelta(days=2)

        class Clock(real):
            @classmethod
            def now(cls, tz=None):
                return now if tz else now.replace(tzinfo=None)

        with mock.patch.object(cg.dt, "datetime", Clock):
            return cg.cleanup_old_sessions(self.data_dir, apply=True)

    def test_commit_after_a_name_swap_keeps_the_original_binding(self):
        # The swap lands between the real rename and the quarantined
        # commit; the recorded identity is rebound to the replacement. The
        # commit must refuse instead of sampling the replacement's stamp.
        old = self.make_session("mint-race", ended_days_ago=45)
        old_stamp = cg._retention_object_stamp(old, old.lstat())
        self.enable_policy(quarantine_days=1)
        rename, holds = cg.os.rename, cg._retention_holds
        moved = {}

        def replace_after_move(source, target):
            rename(source, target)
            if Path(source) == old:
                target = Path(target)
                rename(target, self.root / "original-preserved")
                target.mkdir()
                (target / "replacement-sentinel.txt").write_text(
                    "must survive", encoding="utf-8")
                moved["target"] = target

        def model_identity(path, record):
            if Path(path) == moved.get("target"):
                info = Path(path).lstat()
                record["identity"] = [info.st_dev, info.st_ino]
            return holds(path, record)

        with mock.patch.object(cg.os, "rename", side_effect=replace_after_move), \
                mock.patch.object(cg, "_retention_holds",
                                  side_effect=model_identity):
            first = cg.cleanup_old_sessions(self.data_dir, apply=True)
        target = moved["target"]
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record_path = next(qdir.glob("*.record.json"))
        persisted = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(first["counts"]["quarantined"], 0, first)
        self.assertEqual(first["counts"]["skipped"], 1, first)
        self.assertEqual(persisted["state"], "planned")
        self.assertEqual(persisted.get("object_stamp"), old_stamp)
        second = self.future_pass()
        self.assertEqual(second["purge"]["purged"], 0, second)
        self.assertTrue((target / "replacement-sentinel.txt").is_file())
        self.assertTrue((self.root / "original-preserved").is_dir())

    def test_planned_recovery_over_an_identity_reuse_is_indeterminate(self):
        qdir, record_path, record, target = self.quarantine_wide(payload=2)
        record.pop("object_stamp")  # intent shape before the R7 binding
        record.update(state="planned", quarantined_at=None)
        os.rename(target, self.root / "original-preserved")
        target.mkdir()
        sentinel = target / "replacement-sentinel.txt"
        sentinel.write_text("must survive", encoding="utf-8")
        info = target.lstat()
        record["identity"] = [info.st_dev, info.st_ino]
        record_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        verdict = cg._retention_settle_record(
            self.data_dir, qdir, record_path, record,
            cg.dt.datetime.now(cg.dt.timezone.utc))
        self.assertEqual(verdict, "indeterminate")
        settled = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertNotIn("object_stamp", settled)
        later = self.future_pass()
        self.assertEqual(later["purge"]["purged"], 0, later)
        self.assertTrue(sentinel.is_file())
        self.assertTrue((self.root / "original-preserved").is_dir())

    def test_legitimate_planned_intent_still_recovers_with_its_binding(self):
        # Positive control for the same gate: a real interruption between
        # the rename and the commit recovers, keeps the pre-move binding,
        # and purges once the grace period has passed.
        qdir, record_path, record, target = self.quarantine_wide(payload=2)
        binding = record["object_stamp"]
        record.update(state="planned", quarantined_at=None)
        record_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        verdict = cg._retention_settle_record(
            self.data_dir, qdir, record_path, record,
            cg.dt.datetime.now(cg.dt.timezone.utc))
        self.assertEqual(verdict, "recovered")
        settled = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(settled["state"], "quarantined")
        self.assertEqual(settled["object_stamp"], binding)
        later = self.future_pass()
        self.assertEqual(later["purge"]["purged"], 1, later)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
