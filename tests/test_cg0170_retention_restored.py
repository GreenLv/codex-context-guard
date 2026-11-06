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
import shutil
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


def symlink_or_skip(test, link: Path, target: Path, **kwargs) -> None:
    try:
        link.symlink_to(target, **kwargs)
    except OSError as exc:
        import errno
        if (getattr(exc, "winerror", None) == 1314
                or exc.errno in {errno.ENOSYS, errno.ENOTSUP}):
            test.skipTest("symlink creation capability unavailable")
        raise


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
        # Resumable listings are per process; never carry one into the next
        # test's temporary root.
        close = getattr(cg, "_retention_close_all_enumerations", None)
        if close is not None:
            close()
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

    def test_policy_values_are_clamped_on_write_and_invalid_on_read(self):
        # The explicit write path clamps into the documented safe ranges.
        policy = cg.write_retention_policy(
            self.data_dir, enabled=True, min_age_days=0, quarantine_days=-5)
        self.assertEqual(policy["min_age_days"], 1)
        self.assertEqual(policy["quarantine_days"], 1)
        # A hostile hand-edited file is never clamped into authorization:
        # any missing field, wrong type or out-of-range value makes the
        # whole policy invalid and disabled with the failing fact named.
        hostile = cg._retention_policy_path(self.data_dir)
        for mutation in (
                {"min_age_days": -100},
                {"min_age_days": 10 ** 6},
                {"quarantine_days": 10 ** 6},
                {"quarantine_days": "7"},
                {"purge_enabled": None},
                {"enabled": "yes"},
                {"policy_version": 0},
                {"updated_at": "not-a-time"}):
            good = cg.write_retention_policy(self.data_dir, enabled=True)
            data = {**good, **mutation}
            hostile.write_text(json.dumps(data), encoding="utf-8")
            read = cg.read_retention_policy(self.data_dir)
            self.assertFalse(read["enabled"], mutation)
            self.assertTrue(read.get("policy_invalid"), mutation)

    def test_corrupted_or_linked_policy_reads_disabled(self):
        self.enable_policy()
        path = cg._retention_policy_path(self.data_dir)
        path.write_text("{corrupted", encoding="utf-8")
        self.assertFalse(cg.read_retention_policy(self.data_dir)["enabled"])
        path.unlink()
        outside = self.root / "outside-policy.json"
        outside.write_text("external", encoding="utf-8")
        symlink_or_skip(self, cg._retention_policy_path(self.data_dir), outside)
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
        symlink_or_skip(self, link, outside, target_is_directory=True)
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

    def test_manifest_entries_carry_the_selection_creation_identity(self):
        # Plan D2: the manifest keeps the creation identity bound at
        # selection, so apply re-verifies the selected object and never
        # re-samples identity from whatever the path holds at execution.
        old = self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        preview = cg.cleanup_old_sessions(self.data_dir, with_manifest=True)
        entry = preview["manifest"]["entries"][0]
        self.assertEqual(entry["object_stamp"]["kind"], "birth")
        self.assertEqual(cg._retention_birth_ns(old, old.lstat()),
                         entry["object_stamp"]["ns"])

    def test_a_same_shape_replacement_never_extends_a_manifest(self):
        # The replacement reuses the recorded (dev, ino) and has byte-
        # identical state (same shape, same digest): only the creation
        # identity differs, and that refusal is exactly what stops the
        # apply from re-sampling the current occupant.
        old = self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        manifest = cg.cleanup_old_sessions(
            self.data_dir, with_manifest=True)["manifest"]
        retained = self.root / "retained-original"
        os.rename(old, retained)
        old.mkdir()
        shutil.copy2(retained / "state.json", old / "state.json")
        info = old.lstat()
        entry = manifest["entries"][0]
        entry["identity"] = [info.st_dev, info.st_ino]
        manifest["manifest_sha256"] = cg._retention_manifest_digest(manifest)
        report = cg.cleanup_old_sessions(
            self.data_dir, apply=True, manifest=manifest)
        self.assertEqual(report["counts"]["quarantined"], 0, report)
        self.assertEqual(report["counts"]["skipped"], 1, report)
        skipped = [e for e in report["entries"]
                   if e["name"] == "old" and e["verdict"] == "skipped"]
        self.assertEqual(len(skipped), 1, report["entries"])
        self.assertEqual(skipped[0].get("reason"), "identity_changed")
        self.assertTrue(old.is_dir())
        self.assertTrue((retained / "state.json").exists())

    def test_a_manifest_entry_without_a_creation_stamp_is_unverifiable(self):
        # An older manifest shape whose entries carry no creation identity
        # protects instead of minting one at apply time (plan D2).
        self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        manifest = cg.cleanup_old_sessions(
            self.data_dir, with_manifest=True)["manifest"]
        for entry in manifest["entries"]:
            entry.pop("object_stamp", None)
        manifest["manifest_sha256"] = cg._retention_manifest_digest(manifest)
        report = cg.cleanup_old_sessions(
            self.data_dir, apply=True, manifest=manifest)
        self.assertEqual(report["counts"]["quarantined"], 0, report)
        skipped = [e for e in report["entries"]
                   if e["name"] == "old" and e["verdict"] == "skipped"]
        self.assertEqual(len(skipped), 1, report["entries"])
        self.assertEqual(skipped[0].get("reason"), "identity_unverifiable")
        self.assertTrue(self.session_dir("old").is_dir())

    def test_identity_replacement_under_the_lock_is_skipped(self):
        old = self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        retained = self.root / "retained-original"
        real_acquire = cg._retention_acquire_lifecycle_lock
        calls: list[Path] = []

        def interleave_acquire(candidate, *args, **kwargs):
            calls.append(candidate)
            # The apply-phase lock acquire is the last serialization point
            # before the rename: a completed writer transaction wins at
            # exactly that point, replacing the object under the same name.
            if candidate == old and calls.count(candidate) >= 1:
                os.rename(old, retained)
                old.mkdir()
                (old / "keep.txt").write_text("new object", encoding="utf-8")
            return real_acquire(candidate, *args, **kwargs)

        with mock.patch.object(cg, "_retention_acquire_lifecycle_lock",
                               interleave_acquire):
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

    def test_quarantined_resume_transparently_restores_the_ledger(self):
        # B02: a late resume or a new prompt on a quarantined name must
        # never silently re-initialize over recoverable data. The official
        # reader transparently restores the quarantined object, so the
        # original ledger continues; only an unrestorable state refuses
        # visibly.
        old = self.make_session("old", ended_days_ago=45)
        before = json.loads((old / "state.json").read_text(encoding="utf-8"))
        self.enable_policy()
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertFalse(old.exists())
        cg.dispatch(self.payload(
            "SessionStart", "old", source="resume"))
        state = json.loads(
            (old / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["requirements"], before["requirements"])
        # A following prompt continues the same ledger.
        cg.dispatch(self.payload(
            "UserPromptSubmit", "old", prompt="继续原任务。", turn_id="t2"))
        after = json.loads((old / "state.json").read_text(encoding="utf-8"))
        self.assertIn(before["requirements"][0], after["requirements"])
        # The quarantine record is consumed by the transparent restore.
        self.assertEqual(
            cg.retention_restore(self.data_dir, old.name)["outcome"],
            "not_found")

    def test_restore_refuses_to_overwrite_a_real_live_successor(self):
        self.make_session("old", ended_days_ago=45)
        self.enable_policy()
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        # Simulate a successor created before the recreation guard existed
        # (for example by an older runtime): the restore still refuses to
        # overwrite a live directory at the home position.
        self.session_dir("old").mkdir()
        (self.session_dir("old") / "state.json").write_text("successor", encoding="utf-8")
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
        """Run passes with a fake monotonic clock that charges 1 ms for
        every readdir entry AND every adjudication, so a pass's budget
        bounds all of its work (R2: registry-driven discovery is not free)."""
        clock = [0.0]
        visited: list = []
        base = time.monotonic()
        stub = self.scan_stub(self.data_dir / "sessions-v2", visited, clock)
        real_adjudicate = cg._retention_adjudicate

        def charged_adjudicate(*args, **kwargs):
            clock[0] += 0.001
            return real_adjudicate(*args, **kwargs)

        deadline = base + per_pass_entries * 0.001 + 0.0005
        renames: list[float] = []
        real_rename = cg.os.rename

        def timed_rename(*args, **kwargs):
            renames.append(base + clock[0])
            return real_rename(*args, **kwargs)

        with stub, mock.patch.object(cg.time, "monotonic",
                                     side_effect=lambda: base + clock[0]), \
                mock.patch.object(cg, "_retention_adjudicate",
                                  side_effect=charged_adjudicate), \
                mock.patch.object(cg.os, "rename", side_effect=timed_rename):
            report = cg.cleanup_old_sessions(
                self.data_dir, deadline=deadline, **pass_kwargs)
        # No destructive transition STARTS after the deadline, and the whole
        # pass overshoots by at most the one candidate in flight (adjudicate
        # plus its two locked re-verifications = 3 charged units).
        self.assertTrue(all(at < deadline for at in renames), renames)
        self.assertLessEqual(base + clock[0], deadline + 0.003 + 1e-9)
        self.assertLessEqual(report["counts"]["scanned"], per_pass_entries + 1)
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
        # object and no policy object may appear or change. The allowed
        # directory is matched by path component, not by a POSIX separator
        # substring: Windows snapshot keys use backslashes (R7 N3).
        changed = {key for key in set(before) | set(after)
                   if before.get(key) != after.get(key)
                   and ".locks" not in key.replace("\\", "/").split("/")}
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


class RetentionRepairR1Tests(RetentionFixtureBase):
    """Repair-r1 contract regressions (review probes B01-B04/B05 family)."""

    def test_purge_never_follows_a_replaced_quarantine_target(self):
        # B01: a quarantine target replaced by a symlink is never purged
        # through; the outside sentinel survives and the refusal is named.
        self.make_session("old", ended_days_ago=45)
        self.enable_policy(quarantine_days=1)
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record_path = next(qdir.glob("*.record.json"))
        record = json.loads(record_path.read_text(encoding="utf-8"))
        target = qdir / record["quarantine_object"]
        target.rename(target.with_name(target.name + ".retained"))
        outside = self.root / "outside-product-data"
        outside.mkdir()
        sentinel = outside / "must-keep.txt"
        sentinel.write_text("synthetic outside-product bytes")
        symlink_or_skip(self, target, outside, target_is_directory=True)
        future = cg.dt.datetime.now(cg.dt.timezone.utc) + cg.dt.timedelta(days=2)
        purge = cg._retention_purge_pass(
            self.data_dir, cg.read_retention_policy(self.data_dir), future, None)
        self.assertTrue(sentinel.exists())
        self.assertEqual(purge["purge_refused"], 1)
        self.assertEqual(purge["purged"], 0)
        self.assertTrue((qdir / (record["quarantine_object"] + ".retained")).exists())

    @unittest.skipUnless(os.name == "nt", "Windows native junction control")
    def test_purge_refuses_a_real_windows_junction_and_keeps_both_trees(self):
        self.make_session("old-junction", ended_days_ago=45)
        self.enable_policy(quarantine_days=1)
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record_path = next(qdir.glob("*.record.json"))
        record = json.loads(record_path.read_text(encoding="utf-8"))
        target = qdir / record["quarantine_object"]
        retained = target.with_name(target.name + ".retained")
        target.rename(retained)
        outside = self.root / "outside-junction"
        outside.mkdir()
        sentinel = outside / "must-keep.txt"
        sentinel.write_text("junction target must survive", encoding="utf-8")
        result = subprocess.run(
            [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J",
             str(target), str(outside)], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertTrue(target.lstat().st_file_attributes & 0x400)
        future = cg.dt.datetime.now(cg.dt.timezone.utc) + cg.dt.timedelta(days=2)
        summary = cg._retention_purge_pass(
            self.data_dir, cg.read_retention_policy(self.data_dir), future, None)
        self.assertEqual(summary["purged"], 0)
        self.assertEqual(summary["purge_refused"], 1)
        self.assertEqual(sentinel.read_text(encoding="utf-8"),
                         "junction target must survive")
        self.assertTrue((retained / "state.json").is_file())
        self.assertTrue(record_path.is_file())

    def test_identity_bound_purge_refuses_replaced_directory(self):
        self.make_session("old", ended_days_ago=45)
        self.enable_policy(quarantine_days=1)
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record_path = next(qdir.glob("*.record.json"))
        record = json.loads(record_path.read_text(encoding="utf-8"))
        target = qdir / record["quarantine_object"]
        retained = target.with_name(target.name + ".retained")
        target.rename(retained)
        target.mkdir()  # same name, different inode: a replacement object
        (target / "keep.txt").write_text("new object", encoding="utf-8")
        future = cg.dt.datetime.now(cg.dt.timezone.utc) + cg.dt.timedelta(days=2)
        purge = cg._retention_purge_pass(
            self.data_dir, cg.read_retention_policy(self.data_dir), future, None)
        self.assertEqual(purge["purge_refused"], 1)
        self.assertEqual((target / "keep.txt").read_text(), "new object")
        self.assertTrue((retained / "state.json").exists())

    def test_intent_record_precedes_the_rename(self):
        # B02a: a record-write failure before the rename leaves the object
        # in place with no quarantine entry and no lost session.
        old = self.make_session("crash-before-rename", ended_days_ago=45)
        self.enable_policy()
        with mock.patch.object(cg, "_retention_write_record",
                               side_effect=OSError("synthetic-disk-full")):
            report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(report["counts"]["quarantined"], 0)
        self.assertTrue(old.exists())
        qdir = cg._retention_quarantine_dir(self.data_dir)
        if qdir.exists():
            self.assertEqual([p for p in qdir.iterdir()], [])

    def test_interrupted_commit_is_recovered_by_the_next_pass(self):
        # B02a: a crash between the rename and the commit write leaves a
        # planned record; the next pass promotes it and restore works.
        old = self.make_session("crash-after-rename", ended_days_ago=45)
        self.enable_policy()
        real = cg._retention_write_record
        state = {"calls": 0}

        def fail_commit(path, payload):
            state["calls"] += 1
            if state["calls"] == 1:
                return real(path, payload)  # planned record succeeds
            raise OSError("synthetic-disk-full")  # commit write fails

        with mock.patch.object(cg, "_retention_write_record",
                               side_effect=fail_commit):
            cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertFalse(old.exists())
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record_path = next(qdir.glob("*.record.json"))
        self.assertEqual(json.loads(record_path.read_text())["state"], "planned")
        preview = cg.cleanup_old_sessions(self.data_dir)
        self.assertGreaterEqual(preview["recovery"]["recovered"], 1)
        self.assertEqual(
            json.loads(record_path.read_text())["state"], "quarantined")
        restored = cg.retention_restore(self.data_dir, old.name)
        self.assertEqual(restored["outcome"], "restored")
        self.assertTrue(old.exists())

    def test_tombstone_blocks_recreation_until_expiry(self):
        old = self.make_session("purged-name", ended_days_ago=45)
        self.enable_policy(quarantine_days=1)
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record_path = next(qdir.glob("*.record.json"))
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["quarantined_at"] = "2020-01-01T00:00:00Z"
        record_path.write_text(json.dumps(record), encoding="utf-8")
        cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertFalse(old.exists())
        # Inside the tombstone window the name cannot start a new ledger.
        with self.assertRaises(cg.RetentionRecreationRefused):
            cg.dispatch(self.payload(
                "UserPromptSubmit", "purged-name", prompt="new task",
                turn_id="t1"))
        # An expired tombstone no longer blocks.
        tombstone_path = next(qdir.glob("*.tombstone.json"))
        tombstone = json.loads(tombstone_path.read_text(encoding="utf-8"))
        tombstone["purged_at"] = "2000-01-01T00:00:00Z"
        tombstone_path.write_text(json.dumps(tombstone), encoding="utf-8")
        cg.dispatch(self.payload(
            "UserPromptSubmit", "purged-name", prompt="new task", turn_id="t2"))
        self.assertTrue(self.session_dir("purged-name").is_dir())

    def test_minimal_malformed_policy_never_authorizes(self):
        # B03: the review probe's exact hostile shape (schema + enabled only)
        # reads disabled with the failing fact named; nothing is clamped
        # into an aggressive one-day default.
        self.make_session("strict-policy", ended_days_ago=45)
        self.enable_policy()
        p = cg._retention_policy_path(self.data_dir)
        p.write_text(json.dumps(
            {"schema": cg.RETENTION_POLICY_SCHEMA, "enabled": True}),
            encoding="utf-8")
        policy = cg.read_retention_policy(self.data_dir)
        self.assertFalse(policy["enabled"])
        self.assertTrue(policy["policy_invalid"])
        with self.assertRaisesRegex(RuntimeError, "enabled policy"):
            cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertTrue(self.session_dir("strict-policy").exists())

    def test_policy_revocation_before_the_rename_is_respected(self):
        # B03: a revocation landing between adjudication and the rename is
        # honored: the per-object in-lock policy re-read sees disabled.
        old = self.make_session("revoke-before-rename", ended_days_ago=45)
        self.enable_policy()
        original = cg._retention_apply_object

        def revoke_then_apply(*args, **kwargs):
            cg.write_retention_policy(self.data_dir, enabled=False)
            return original(*args, **kwargs)

        with mock.patch.object(cg, "_retention_apply_object",
                               side_effect=revoke_then_apply):
            r = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(r["counts"]["quarantined"], 0)
        self.assertTrue(old.exists())

    def test_decided_prefix_never_consumes_the_adjudication_cap(self):
        # B04: the cap counts only undecided candidates, so a protected
        # prefix cannot starve the eligible tail of a finite namespace.
        for i in range(5):
            self.make_session(f"prefix-{i}", ended_days_ago=45, finished=False)
        tail = self.make_session("zz-tail-eligible", ended_days_ago=45)
        self.enable_policy()
        visited: list = []
        clock = [0.0]
        with self.scan_stub(self.data_dir / cg.V2_NAMESPACE, visited, clock), \
                mock.patch.object(cg, "_RETENTION_SCAN_ENTRY_CAP", 3):
            reached = False
            for _ in range(8):
                report = cg.cleanup_old_sessions(self.data_dir, apply=True)
                if report["counts"]["quarantined"] >= 1:
                    reached = True
                    break
        self.assertTrue(reached, "the eligible tail starved under the cap")
        self.assertIn("zz-tail-eligible", visited)
        self.assertFalse(tail.exists())

    def test_cli_manifest_end_to_end_preview_save_apply_restore(self):
        # B05: the user-facing CLI must produce an appliable manifest.
        old = self.make_session("cli-e2e", ended_days_ago=45)
        self.enable_policy()
        manifest_path = self.root / "selected-manifest.json"
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

        def run(*args):
            return subprocess.run(
                [sys.executable, "-B", str(MODULE_PATH), "cleanup",
                 "--data-dir", str(self.data_dir), *args],
                env=env, text=True, capture_output=True, check=False)

        preview = run("--save-manifest", str(manifest_path))
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertTrue(manifest_path.exists())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(
            [entry["name"] for entry in manifest["entries"]],
            [old.name])
        # The saved manifest binds the exact object: apply quarantines it.
        applied = run("--apply-manifest", str(manifest_path))
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertFalse(old.exists())
        restored = run("--restore", old.name)
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertTrue(old.exists())


# The opt-in scheduler lifecycle (B10) moved to
# tests/test_cg0170_r2_family.py::RetentionScheduleLifecycleTests in R2: the
# entry now drives the platform loader, so its contract is exercised through
# the scheduler adapter seam and never against the host's real launchd or
# Task Scheduler (an isolated HOME does not isolate launchd).
