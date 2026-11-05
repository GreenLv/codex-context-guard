"""0.17.0 C01: restored session-retention maintenance under contract
``cg-retention-report/v1``.

Positive evidence: bounded multi-batch backlog processing with fairness,
policy-gated apply, quarantine with restore, purge after grace, tombstones.
Negative evidence: active, resumable, unprovened, busy-locked, partial,
legacy, linked and out-of-scope objects are never touched. Adversarial
evidence: identity replacement, manifest binding, cursor starvation.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

try:
    import fcntl
except ImportError:  # Windows: msvcrt fixtures cover locks
    fcntl = None

import importlib.util

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard_0170", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)


def acquire_exclusive_lock(lock_path: Path):
    handle = open(lock_path, "a+b")
    if os.name == "nt":
        import msvcrt
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        return handle
    assert fcntl is not None
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def release_exclusive_lock(handle) -> None:
    try:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        elif fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


class RetentionFixtureBase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.data_dir = self.root / "guard-data"
        self.codex_home = self.root / "codex-home"
        self.os_home = self.root / "os-home"
        self._env = dict(os.environ)
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(self.data_dir)
        os.environ["CODEX_HOME"] = str(self.codex_home)
        os.environ["HOME"] = str(self.os_home)
        os.environ["USERPROFILE"] = str(self.os_home)
        for name in ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT"):
            os.environ.pop(name, None)
        self.project = self.root / "project"
        self.project.mkdir()

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env)
        self.temporary.cleanup()

    def payload(self, event: str, session: str, **extra) -> dict:
        base = {"hook_event_name": event, "session_id": session,
                "cwd": str(self.project)}
        base.update(extra)
        return base

    def session_dir(self, session: str) -> Path:
        return self.data_dir / "sessions-v2" / cg.safe_session_id(session)

    def snapshot(self, root: Path) -> dict:
        return {str(path.relative_to(root)): path.read_bytes()
                for path in root.rglob("*") if path.is_file()}

    def make_session(self, name: str, *, ended_days_ago: float | None = None,
                     finished: bool = True, reopen_pending: bool = False) -> Path:
        """A real journaled session in the exact schema-13 shape."""
        cg.dispatch(self.payload(
            "UserPromptSubmit", name,
            prompt="请先核对验收说明。", turn_id="t1"))
        state_path = self.session_dir(name) / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if finished:
            for item in state.get("requirements", []):
                item["status"] = "pass"
            for item in state.get("acceptance_items", []):
                item["status"] = "pass"
            for unit in state.get("work_units", []):
                unit["status"] = "completed"
                unit["closed_at"] = cg.utc_now()
            state["open_items"] = []
            state["wait_conditions"] = []
        if reopen_pending:
            state["open_items"] = [
                item["id"] for item in state.get("requirements", [])[:1]]
        if ended_days_ago is not None:
            state["session"]["ended_at"] = (
                cg.dt.datetime.now(cg.dt.timezone.utc)
                - cg.dt.timedelta(days=ended_days_ago)
            ).isoformat().replace("+00:00", "Z")
        state["content_hash"] = cg.state_content_hash(state)
        state_path.write_text(
            json.dumps(state, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        if ended_days_ago is not None:
            old = time.time() - ended_days_ago * 86400
            os.utime(state_path, (old, old))
        return self.session_dir(name)

    def enable_policy(self, **overrides) -> dict:
        return cg.write_retention_policy(self.data_dir, enabled=True, **overrides)

    def scan_stub(self, sessions: Path, visited: list, clock: list):
        """scandir stub charging 1ms per entry so budgets cut mid-scan."""
        real_scandir = os.scandir

        class Entry:
            def __init__(self, name):
                self.name = name
                self.path = str(sessions / name)

            def is_symlink(self):
                return False

            def is_dir(self, **kwargs):
                return True

        class Scan:
            def __init__(self):
                with real_scandir(sessions) as source:
                    names = sorted(entry.name for entry in source)
                self.items = iter(name for name in names if name != ".locks")

            def __iter__(self):
                return self

            def __next__(self):
                name = next(self.items)
                clock[0] += 0.001
                visited.append(name)
                return Entry(name)

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def scanner(path):
            if Path(path) == sessions:
                return Scan()
            return real_scandir(path)

        return mock.patch.object(cg.os, "scandir", side_effect=scanner)


class RetentionPolicyTests(RetentionFixtureBase):
    def test_default_policy_is_disabled_and_absent_file_never_authorizes(self):
        policy = cg.read_retention_policy(self.data_dir)
        self.assertFalse(policy["enabled"])
        self.assertFalse((self.data_dir / "sessions-v2" / ".locks").exists()
                         and (cg._retention_policy_path(self.data_dir)).exists())

    def test_enable_disable_round_trip_is_readable_and_no_op_repeat(self):
        first = cg.write_retention_policy(self.data_dir, enabled=True)
        self.assertTrue(first["enabled"])
        self.assertEqual(first["min_age_days"], 30)
        self.assertEqual(first["quarantine_days"], 7)
        again = cg.write_retention_policy(self.data_dir, enabled=True)
        self.assertEqual(
            {key: again[key] for key in
             ("schema", "enabled", "min_age_days", "quarantine_days",
              "purge_enabled")},
            {key: first[key] for key in
             ("schema", "enabled", "min_age_days", "quarantine_days",
              "purge_enabled")})
        self.assertGreater(again["policy_version"], first["policy_version"])
        disabled = cg.write_retention_policy(self.data_dir, enabled=False)
        self.assertFalse(cg.read_retention_policy(self.data_dir)["enabled"])
        self.assertGreater(disabled["policy_version"], again["policy_version"])

    def test_policy_values_are_clamped_into_safe_ranges(self):
        policy = cg.write_retention_policy(
            self.data_dir, enabled=True, min_age_days=0, quarantine_days=-5)
        self.assertEqual(policy["min_age_days"], 1)
        self.assertEqual(policy["quarantine_days"], 1)
        hostile = cg._retention_policy_path(self.data_dir)
        hostile.write_text(json.dumps({
            "schema": cg.RETENTION_POLICY_SCHEMA, "enabled": True,
            "min_age_days": -100, "quarantine_days": 10 ** 6,
            "policy_version": 1}), encoding="utf-8")
        read = cg.read_retention_policy(self.data_dir)
        self.assertEqual(read["min_age_days"], 1)
        self.assertEqual(read["quarantine_days"], 365)

    def test_corrupted_or_linked_policy_reads_disabled(self):
        self.enable_policy()
        path = cg._retention_policy_path(self.data_dir)
        path.write_text("{corrupted", encoding="utf-8")
        self.assertFalse(cg.read_retention_policy(self.data_dir)["enabled"])
        path.unlink()
        outside = self.root / "outside-policy.json"
        outside.write_text("external", encoding="utf-8")
        (cg._retention_policy_path(self.data_dir)).symlink_to(outside)
        self.assertFalse(cg.read_retention_policy(self.data_dir)["enabled"])
        self.assertEqual(outside.read_text(), "external")

    def test_apply_without_policy_is_refused_and_preview_stays_available(self):
        self.make_session("old", ended_days_ago=45)
        with self.assertRaisesRegex(RuntimeError, "enabled policy"):
            cg.cleanup_old_sessions(self.data_dir, apply=True)
        report = cg.cleanup_old_sessions(self.data_dir)
        self.assertEqual(report["mode"], "preview")
        self.assertTrue(self.session_dir("old").is_dir())


class RetentionEligibilityTests(RetentionFixtureBase):
    def run_preview(self, **kwargs):
        return cg.cleanup_old_sessions(self.data_dir, **kwargs)

    def verdicts(self, report) -> dict:
        return {entry["name"]: entry for entry in report["entries"]}

    def test_expired_finished_session_is_eligible_in_preview(self):
        self.make_session("old", ended_days_ago=45)
        report = self.run_preview()
        entry = self.verdicts(report)[cg.safe_session_id("old")]
        self.assertEqual(entry["verdict"], "eligible")
        self.assertNotIn("reason", entry)

    def test_active_and_resumable_sessions_are_protected(self):
        self.make_session("live", finished=False)
        self.make_session("ended-pending", ended_days_ago=45,
                          finished=False, reopen_pending=True)
        report = self.run_preview()
        verdicts = self.verdicts(report)
        self.assertEqual(verdicts[cg.safe_session_id("live")]["verdict"],
                         "protected")
        self.assertEqual(
            verdicts[cg.safe_session_id("ended-pending")]["reason"],
            "unfinished_work")

    def test_unexpired_and_missing_end_time_are_protected(self):
        self.make_session("young", ended_days_ago=2)
        self.make_session("no-end", ended_days_ago=None)
        report = self.run_preview()
        verdicts = self.verdicts(report)
        self.assertEqual(verdicts[cg.safe_session_id("young")]["reason"],
                         "not_expired")
        self.assertEqual(verdicts[cg.safe_session_id("no-end")]["reason"],
                         "no_end_time")

    def test_unsupported_schema_and_corrupt_state_are_protected(self):
        old = self.make_session("old", ended_days_ago=45)
        state = json.loads((old / "state.json").read_text(encoding="utf-8"))
        state["schema_version"] = 9
        state["content_hash"] = cg.state_content_hash(state)
        (old / "state.json").write_text(json.dumps(state), encoding="utf-8")
        corrupt = self.make_session("corrupt", ended_days_ago=45)
        (corrupt / "state.json").write_text("{broken", encoding="utf-8")
        report = self.run_preview()
        verdicts = self.verdicts(report)
        # An old schema fails integrity validation before the schema gate;
        # both stay protected with a named reason.
        self.assertEqual(verdicts[old.name]["reason"], "state_unreadable")
        self.assertEqual(verdicts[corrupt.name]["reason"], "state_unreadable")

    def test_partial_marker_blocks_eligibility_and_stays_in_place(self):
        old = self.make_session("old", ended_days_ago=45)
        marker = old / cg.CLEANUP_PARTIAL_MARKER
        marker.write_text("historical partial deletion\n", encoding="utf-8")
        report = self.run_preview()
        entry = self.verdicts(report)[old.name]
        self.assertEqual(entry["reason"], "partial_marker")
        self.assertTrue(marker.exists())

    def test_busy_lifecycle_lock_is_skipped_without_force(self):
        if os.name != "nt" and fcntl is None:  # pragma: no cover
            self.skipTest("no POSIX fcntl available on this host")
        old = self.make_session("old", ended_days_ago=45)
        locks = self.data_dir / "sessions-v2" / ".locks"
        locks.mkdir(parents=True, exist_ok=True)
        handle = acquire_exclusive_lock(locks / f"{old.name}.lock")
        try:
            report = self.run_preview()
            entry = self.verdicts(report)[old.name]
            self.assertEqual(entry["reason"], "busy_lock")
            self.assertTrue(old.is_dir())
        finally:
            release_exclusive_lock(handle)
        # Once the owner releases, the same object can be cleaned normally.
        self.enable_policy()
        applied = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(applied["counts"]["quarantined"], 1)
        self.assertFalse(old.exists())

    def test_symlinked_session_object_is_reported_not_followed(self):
        outside = self.root / "outside-session"
        outside.mkdir()
        (outside / "state.json").write_text("external fixture", encoding="utf-8")
        link = self.data_dir / "sessions-v2" / "old-link"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside, target_is_directory=True)
        report = self.run_preview()
        entry = self.verdicts(report)["old-link"]
        self.assertEqual(entry["verdict"], "protected")
        self.assertEqual(entry["reason"], "not_directory")
        self.assertEqual((outside / "state.json").read_text(), "external fixture")

    def test_same_name_file_replacement_is_protected_not_deleted(self):
        # A same-name plain file is not a session object; the pass names it
        # protected and never deletes or hardens it.
        namespace = self.data_dir / "sessions-v2"
        namespace.mkdir(parents=True, exist_ok=True)
        (namespace / "replaced-by-file").write_text("plain file", encoding="utf-8")
        report = self.run_preview()
        entry = self.verdicts(report)["replaced-by-file"]
        self.assertEqual(entry["verdict"], "protected")
        self.assertEqual(entry["reason"], "not_directory")
        self.assertEqual((namespace / "replaced-by-file").read_text(),
                         "plain file")

    def test_unreadable_identity_is_protected_and_retried_next_pass(self):
        old = self.make_session("old", ended_days_ago=45)
        real_lstat = Path.lstat

        def failing_lstat(path, *args, **kwargs):
            if path == old and not refused[0]:
                refused[0] = True
                raise OSError("identity unavailable")
            return real_lstat(path, *args, **kwargs)

        refused = [False]
        with mock.patch.object(Path, "lstat", failing_lstat):
            first = self.run_preview()
        entry = self.verdicts(first)[old.name]
        self.assertEqual(entry["reason"], "boundary")
        self.assertTrue(old.is_dir())
        # The next pass retries the same object without a persisted skip.
        second = self.run_preview()
        self.assertEqual(self.verdicts(second)[old.name]["verdict"],
                         "eligible")

    def test_lifecycle_lock_probe_is_noncreating(self):
        old = self.make_session("old", ended_days_ago=45)
        lock_path = cg.lifecycle_lock_path(old)
        # A journaled session already owns a lock file; remove it to prove
        # the probe itself never recreates one.
        lock_path.unlink()
        self.assertFalse(lock_path.exists())
        busy, handle = cg._retention_probe_lifecycle_lock(old)
        self.assertFalse(busy)
        self.assertIsNone(handle)
        self.assertFalse(lock_path.exists(),
                         "the probe must never create the lock file")

    @unittest.skipUnless(os.name == "posix", "POSIX permission-mode contract")
    def test_permission_refusal_blocks_reads_and_deletion(self):
        old = self.make_session("old", ended_days_ago=45)
        (old / "state.json").chmod(0o000)
        try:
            report = self.run_preview()
            entry = self.verdicts(report)[old.name]
            self.assertEqual(entry["reason"], "state_unreadable")
            self.assertTrue(old.is_dir())
            self.enable_policy()
            applied = cg.cleanup_old_sessions(self.data_dir, apply=True)
            self.assertEqual(applied["counts"]["quarantined"], 0)
            self.assertTrue(old.is_dir())
        finally:
            (old / "state.json").chmod(0o644)

    def test_expired_deadline_processes_nothing(self):
        self.make_session("old", ended_days_ago=45)
        report = cg.cleanup_old_sessions(
            self.data_dir, deadline=time.monotonic() - 1.0)
        self.assertEqual(report["counts"]["scanned"], 0)
        self.assertFalse(report["scan_complete"])
        self.assertTrue(report["backlog"])
        self.assertTrue(self.session_dir("old").is_dir())

    def test_legacy_namespace_is_never_scanned_or_touched(self):
        legacy = self.data_dir / cg.LEGACY_NAMESPACE / "legacy-old"
        legacy.mkdir(parents=True)
        (legacy / "state.json").write_text("legacy fixture", encoding="utf-8")
        report = self.run_preview()
        self.assertNotIn("legacy-old", self.verdicts(report))
        self.assertEqual((legacy / "state.json").read_text(), "legacy fixture")


class RetentionApplyTests(RetentionFixtureBase):
    def test_preview_then_policy_apply_quarantines_only_eligible(self):
        old = self.make_session("old", ended_days_ago=45)
        live = self.make_session("live", finished=False)
        self.enable_policy()
        preview = cg.cleanup_old_sessions(self.data_dir)
        self.assertEqual(preview["counts"]["quarantined"], 0)
        report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(report["mode"], "apply")
        self.assertEqual(report["counts"]["quarantined"], 1)
        self.assertFalse(old.exists())
        self.assertTrue(live.is_dir())
        qdir = cg._retention_quarantine_dir(self.data_dir)
        quarantined = [path for path in qdir.iterdir() if path.is_dir()]
        self.assertEqual(len(quarantined), 1)
        # The quarantined object keeps its full state for the restore path.
        state = json.loads(
            (quarantined[0] / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["session"]["id"],
                         json.loads(json.dumps("old")))
        self.assertIn("manifest_sha256", report)

    def test_saved_manifest_binds_apply_and_rejects_changes(self):
        old = self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        preview = cg.cleanup_old_sessions(self.data_dir, with_manifest=True)
        manifest = preview["manifest"]
        self.assertEqual(manifest["schema"], cg.RETENTION_MANIFEST_SCHEMA)
        # Any later state change invalidates the exact binding.
        state_path = old / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["session"]["ended_at"] = cg.utc_now()
        state["content_hash"] = cg.state_content_hash(state)
        state_path.write_text(json.dumps(state), encoding="utf-8")
        report = cg.cleanup_old_sessions(
            self.data_dir, apply=True, manifest=manifest)
        self.assertEqual(report["counts"]["quarantined"], 0)
        self.assertEqual(report["counts"]["skipped"], 1)
        self.assertTrue(old.exists())

    def test_manifest_refuses_foreign_root_and_policy_change(self):
        self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        preview = cg.cleanup_old_sessions(self.data_dir, with_manifest=True)
        manifest = preview["manifest"]
        other_root = self.root / "other-data"
        other_root.mkdir()
        with self.assertRaisesRegex(RuntimeError, "data root"):
            cg.cleanup_old_sessions(other_root, apply=True, manifest=manifest)
        cg.write_retention_policy(self.data_dir, enabled=True,
                                  min_age_days=60)
        with self.assertRaisesRegex(RuntimeError, "policy"):
            cg.cleanup_old_sessions(
                self.data_dir, apply=True, manifest=manifest)
        self.assertTrue(self.session_dir("old").is_dir())

    def test_manifest_digest_mismatch_is_refused(self):
        self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        preview = cg.cleanup_old_sessions(self.data_dir, with_manifest=True)
        manifest = preview["manifest"]
        manifest["manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "digest"):
            cg.cleanup_old_sessions(
                self.data_dir, apply=True, manifest=manifest)

    def test_new_objects_after_manifest_generation_are_not_authorized(self):
        self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        preview = cg.cleanup_old_sessions(self.data_dir, with_manifest=True)
        manifest = preview["manifest"]
        fresh = self.make_session("fresh", ended_days_ago=90)
        report = cg.cleanup_old_sessions(
            self.data_dir, apply=True, manifest=manifest)
        self.assertEqual(report["counts"]["quarantined"], 1)
        self.assertTrue(fresh.exists())

    def test_identity_replacement_under_the_lock_is_skipped(self):
        old = self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        retained = self.root / "retained-original"
        real_probe = cg._retention_probe_lifecycle_lock
        calls: list[Path] = []

        def interleave_probe(candidate, *args, **kwargs):
            calls.append(candidate)
            # The second probe for this object is the apply-phase lock right
            # before re-verification: a completed writer transaction wins at
            # exactly that point, replacing the object under the same name.
            if candidate == old and calls.count(candidate) >= 2:
                os.rename(old, retained)
                old.mkdir()
                (old / "keep.txt").write_text("new object", encoding="utf-8")
            return real_probe(candidate, *args, **kwargs)

        with mock.patch.object(cg, "_retention_probe_lifecycle_lock",
                               interleave_probe):
            report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(report["counts"]["quarantined"], 0)
        self.assertEqual(report["counts"]["skipped"], 1)
        self.assertEqual((old / "keep.txt").read_text(), "new object")
        self.assertTrue((retained / "state.json").exists())

    def test_restore_returns_quarantined_object_and_official_reader_reads_it(self):
        old = self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertFalse(old.exists())
        report = cg.retention_restore(self.data_dir, old.name)
        self.assertEqual(report["outcome"], "restored")
        self.assertTrue(old.is_dir())
        # Official readback: the restored session still loads with its
        # recorded state, not as a fresh uninitialized session.
        state = json.loads((old / "state.json").read_text(encoding="utf-8"))
        self.assertTrue(state["session"]["ended_at"])
        self.assertEqual(state["schema_version"], cg.SCHEMA_VERSION)
        # A second restore attempt has nothing to restore.
        self.assertEqual(
            cg.retention_restore(self.data_dir, old.name)["outcome"],
            "not_found")

    def test_restore_refuses_to_overwrite_a_live_successor(self):
        self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        cg.dispatch(self.payload(
            "UserPromptSubmit", "old", prompt="new owner", turn_id="t1"))
        report = cg.retention_restore(
            self.data_dir, cg.safe_session_id("old"))
        self.assertEqual(report["outcome"], "refused")
        self.assertEqual(report["reason"], "live_successor_exists")


class RetentionPurgeTests(RetentionFixtureBase):
    def _quarantine_one(self, name="old", days=45) -> Path:
        old = self.make_session(name, ended_days_ago=days)
        self.enable_policy()
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        return old

    def test_purge_waits_for_the_quarantine_grace_period(self):
        old = self._quarantine_one()
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record = next(qdir.glob("*.record.json"))
        data = json.loads(record.read_text(encoding="utf-8"))
        data["quarantined_at"] = (
            cg.dt.datetime.now(cg.dt.timezone.utc)
            - cg.dt.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record.write_text(json.dumps(data), encoding="utf-8")
        report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(report["purge"]["purged"], 0)
        self.assertGreaterEqual(report["purge"]["purge_pending"], 1)
        self.assertTrue(old.is_dir() or
                        any(qdir.glob("old*")))

    def test_purge_after_grace_removes_object_and_writes_tombstone(self):
        self._quarantine_one()
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record = next(qdir.glob("*.record.json"))
        data = json.loads(record.read_text(encoding="utf-8"))
        data["quarantined_at"] = (
            cg.dt.datetime.now(cg.dt.timezone.utc)
            - cg.dt.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record.write_text(json.dumps(data), encoding="utf-8")
        report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(report["purge"]["purged"], 1)
        self.assertFalse([path for path in qdir.iterdir() if path.is_dir()])
        tombstones = list(qdir.glob("*.tombstone.json"))
        self.assertEqual(len(tombstones), 1)
        tombstone = json.loads(tombstones[0].read_text(encoding="utf-8"))
        self.assertEqual(tombstone["schema"], cg.RETENTION_TOMBSTONE_SCHEMA)
        self.assertEqual(tombstone["restore"], "unavailable_after_purge")
        name = tombstone["original_name"]
        # After purge there is no restore path, and the message says so.
        outcome = cg.retention_restore(self.data_dir, name)
        self.assertEqual(outcome["outcome"], "not_found")

    def test_purge_disabled_keeps_objects_past_grace(self):
        self._quarantine_one()
        cg.write_retention_policy(self.data_dir, enabled=True,
                                  purge_enabled=False)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record = next(qdir.glob("*.record.json"))
        data = json.loads(record.read_text(encoding="utf-8"))
        data["quarantined_at"] = "2020-01-01T00:00:00Z"
        record.write_text(json.dumps(data), encoding="utf-8")
        report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(report["purge"]["purged"], 0)
        self.assertGreaterEqual(report["purge"]["purge_disabled"], 1)
        self.assertTrue([path for path in qdir.iterdir() if path.is_dir()])

    def test_interrupted_purge_keeps_record_and_resumes(self):
        self._quarantine_one()
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record = next(qdir.glob("*.record.json"))
        data = json.loads(record.read_text(encoding="utf-8"))
        data["quarantined_at"] = "2020-01-01T00:00:00Z"
        record.write_text(json.dumps(data), encoding="utf-8")
        # A deadline that expires before any work produces a partial pass
        # with the record still authoritative.
        with mock.patch.object(cg.time, "monotonic",
                               side_effect=lambda: 10 ** 12):
            report = cg.cleanup_old_sessions(
                self.data_dir, apply=True,
                deadline=time.monotonic() + 0.0)
        # The interrupted pass claims no completion and leaves the record
        # authoritative for the next pass.
        self.assertEqual(report["purge"]["purged"], 0)
        self.assertTrue(list(qdir.glob("*.record.json")))
        # The next unbounded pass completes the purge deterministically.
        report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(report["purge"]["purged"], 1)
        self.assertFalse([path for path in qdir.iterdir() if path.is_dir()])


class RetentionFairnessTests(RetentionFixtureBase):
    def _fake_clock_pass(self, *, per_pass_entries: int, **pass_kwargs):
        """Run passes with a scan stub that charges fake monotonic time."""
        clock = [0.0]
        visited: list = []
        base = time.monotonic()
        stub = self.scan_stub(self.data_dir / "sessions-v2", visited, clock)
        with stub, mock.patch.object(cg.time, "monotonic",
                                     side_effect=lambda: base + clock[0]):
            report = cg.cleanup_old_sessions(
                self.data_dir,
                deadline=base + per_pass_entries * 0.001 + 0.0005,
                **pass_kwargs)
        return report

    def test_repeated_short_passes_complete_a_large_backlog(self):
        total = 24
        for index in range(total):
            self.make_session(f"batch-{index:02d}", ended_days_ago=45)
        self.enable_policy()
        passes = 0
        while True:
            passes += 1
            report = self._fake_clock_pass(
                per_pass_entries=4, apply=True)
            if not report["backlog"] or passes > 60:
                break
        self.assertLessEqual(passes, 60)
        self.assertGreater(passes, 1, "a single pass should not cover 24 items")
        qdir = cg._retention_quarantine_dir(self.data_dir)
        quarantined = [path for path in qdir.iterdir() if path.is_dir()]
        self.assertEqual(len(quarantined), total)
        namespace = self.data_dir / "sessions-v2"
        self.assertEqual(
            [path.name for path in namespace.iterdir() if path.name != ".locks"],
            [])

    def test_zero_deletions_in_a_pass_is_reported_as_backlog_not_completion(self):
        for index in range(6):
            self.make_session(f"kept-{index}", ended_days_ago=45,
                              finished=False, reopen_pending=True)
        self.enable_policy()
        report = self._fake_clock_pass(per_pass_entries=2, apply=True)
        self.assertTrue(report["backlog"])
        self.assertEqual(report["counts"]["quarantined"], 0)

    def test_long_decided_prefix_still_reaches_the_tail(self):
        # Historical expected failure RV03: a long protected prefix must not
        # starve the eligible tail. The persisted cursor plus the pending
        # queue guarantee tail progress across repeated bounded passes.
        for index in range(20):
            self.make_session(f"protected-{index:02d}", ended_days_ago=45,
                              finished=False, reopen_pending=True)
        self.make_session("tail-eligible", ended_days_ago=90)
        self.enable_policy()
        reached_tail = False
        for _ in range(40):
            report = self._fake_clock_pass(per_pass_entries=3, apply=True)
            if report["counts"]["quarantined"] >= 1:
                reached_tail = True
                break
        self.assertTrue(reached_tail, "the eligible tail starved")
        self.assertFalse(self.session_dir("tail-eligible").exists())

    def test_order_change_between_passes_still_reaches_every_entry(self):
        self.make_session("alpha", ended_days_ago=45)
        self.make_session("bravo", ended_days_ago=45)
        self.make_session("charlie", ended_days_ago=45)
        self.enable_policy()
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        # A new object sorts before the persisted cursor: the next pass must
        # still adjudicate it instead of trusting the old order.
        self.make_session("aardvark", ended_days_ago=45)
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        quarantined = [path for path in qdir.iterdir() if path.is_dir()]
        self.assertEqual(len(quarantined), 4)
        self.assertFalse(self.session_dir("aardvark").exists())


class RetentionSessionEndBoundaryTests(RetentionFixtureBase):
    def test_session_end_never_runs_maintenance_or_creates_policy(self):
        self.make_session("old", ended_days_ago=45)
        self.make_session("current", ended_days_ago=None, finished=False)
        before = self.snapshot(self.data_dir)
        with mock.patch.object(
                cg, "cleanup_old_sessions",
                side_effect=AssertionError("retired SessionEnd sweep reached")):
            self.assertEqual(
                cg.dispatch(self.payload("SessionEnd", "current")), {})
        self.assertFalse(cg._retention_policy_path(self.data_dir).exists())
        self.assertTrue(self.session_dir("old").is_dir())
        after = self.snapshot(self.data_dir)
        # Only the current session's own state changed.
        changed = {key for key in set(before) | set(after)
                   if before.get(key) != after.get(key)}
        self.assertTrue(changed)
        self.assertTrue(all(key.startswith("sessions-v2") and
                            "current" in key for key in changed))

    def test_cli_cleanup_without_root_refuses_before_any_resolution(self):
        default_home = self.root / "never-created-codex-home"
        env = dict(os.environ, CODEX_HOME=str(default_home),
                   PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(
            [sys.executable, "-B", str(MODULE_PATH), "cleanup"],
            env=env, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--data-dir", result.stderr)
        self.assertFalse(default_home.exists())

    def test_cli_preview_reports_and_never_mutates_sessions(self):
        self.make_session("old", ended_days_ago=45)
        before = self.snapshot(self.data_dir)
        result = subprocess.run(
            [sys.executable, "-B", str(MODULE_PATH), "cleanup",
             "--data-dir", str(self.data_dir)],
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("eligible=1", result.stdout)
        after = self.snapshot(self.data_dir)
        # Bounded discovery hints under .locks may be appended; no session
        # object and no policy object may appear or change.
        changed = {key for key in set(before) | set(after)
                   if before.get(key) != after.get(key)
                   and "/.locks/" not in key}
        self.assertEqual(changed, set())
        self.assertFalse(cg._retention_policy_path(self.data_dir).exists())


class RetentionMappingContractTests(unittest.TestCase):
    """The 30 retired retention nodes are individually accounted for."""

    def test_mapping_covers_all_retired_nodes_with_passing_oracles(self):
        retired = json.loads(
            (Path(__file__).resolve().parents[1] /
             "tests/retired_retention_cleanup.json").read_text(encoding="utf-8"))
        mapping = json.loads(
            (Path(__file__).resolve().parents[1] /
             "tests/retention_restoration_mapping.json").read_text(encoding="utf-8"))
        retired_nodes = {row["node"] for row in retired["tests"]}
        mapped_nodes = {row["old_node"] for row in mapping["rows"]}
        self.assertEqual(retired_nodes, mapped_nodes)
        self.assertEqual(mapping["count"], 30)
        for row in mapping["rows"]:
            with self.subTest(node=row["old_node"]):
                self.assertIn(row["disposition"], {
                    "restored", "replaced", "superseded_stricter",
                    "restored_expected_failure_converted", "not_applicable"})
                self.assertTrue(row["reason"])
                self.assertTrue(row["replacement_node"])
                self.assertEqual(row["result"], "passed")
        # The retained historical expected failure is converted on its own
        # original risk, not skipped or renamed away.
        converted = [row for row in mapping["rows"]
                     if row["previous_expected_failure"]]
        self.assertEqual(len(converted), 1)
        self.assertEqual(converted[0]["disposition"],
                         "restored_expected_failure_converted")
        self.assertIn("test_long_decided_prefix_still_reaches_the_tail",
                      converted[0]["replacement_node"])


if __name__ == "__main__":
    unittest.main()
