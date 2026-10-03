"""CGI-20261003 read-only snapshot regression (CG-0151 D3).

The checkpoint_status diagnostic read path must be a whole-query property:
no lifecycle lock creation or owner write, no chmod/mkdir, no migration,
rebuild, backup or sidecar write, and no fabricated freshness. Every row
below witnesses the byte/filesystem state of the private tree before and
after real queries; the native two-platform restricted-child facts stay a
separate pending gate.
"""
from __future__ import annotations

import json
import os
import stat
import threading
import unittest
from pathlib import Path
from unittest import mock

from tests.test_cg122_p0_counterexamples import P0Harness, cg


def tree_inventory(root: Path) -> dict[str, list]:
    result: dict[str, list] = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        info = path.lstat()
        result[rel] = [
            stat.S_ISLNK(info.st_mode),
            stat.S_ISDIR(info.st_mode),
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            info.st_ino,
        ]
    return result


class ReadOnlySnapshotTests(P0Harness):
    def ready(self, session: str = "p0"):
        self.activate(session)
        self.prompt("请核对示例诊断结果。", session)
        state = self.state(session)
        self.turn = state["completion_attempt"]["turn_id"]
        self.session_dir = self.root / "private" / "sessions-v2" / session
        return state

    def query(self, session: str = "p0", turn: str | None = None, **kw):
        return cg.checkpoint_status(
            self.root / "private", session, turn or self.turn, "p0token", **kw
        )

    # -- R01: every mode succeeds with a byte-stable private tree --------
    def test_r01_all_modes_read_without_tree_changes(self):
        self.ready()
        # A writer flow first, so a lock file exists and must not change.
        self.dispatch("Stop", last_assistant_message="诊断中。")
        lock_path = self.root / "private" / "sessions-v2" / ".locks" / "p0.lock"
        lock_before = lock_path.read_bytes()
        before = tree_inventory(self.root / "private")
        turn = self.state()["completion_attempt"]["turn_id"]
        default = self.query(turn=turn)
        self.assertEqual(default["mode"], "current_work_unit")
        self.assertNotIn("advanced_commands", default)
        commands = self.query(turn=turn, commands=True)
        self.assertIn("advanced_commands", commands)
        full = self.query(turn=turn, full=True)
        self.assertEqual(full["mode"], "full")
        item = self.query(turn=turn, item_id="R001")
        self.assertEqual(item["item"]["id"], "R001")
        revision = default["revision"]
        unchanged = self.query(turn=turn, after_revision=revision)
        self.assertTrue(unchanged.get("unchanged"))
        after = tree_inventory(self.root / "private")
        self.assertEqual(before, after)
        self.assertEqual(lock_path.read_bytes(), lock_before)

    # -- R02: read-only directory still serves the query ------------------
    def test_r02_write_denied_tree_still_readable(self):
        if os.geteuid() == 0:
            self.skipTest("permission denial requires a non-root runner")
        self.ready()
        self.dispatch("Stop", last_assistant_message="诊断中。")
        before = tree_inventory(self.root / "private")
        session_dir = self.root / "private" / "sessions-v2" / "p0"
        original_mode = session_dir.stat().st_mode
        try:
            session_dir.chmod(0o500)
            turn = self.state()["completion_attempt"]["turn_id"]
            result = self.query(turn=turn)
            self.assertEqual(result["mode"], "current_work_unit")
            after = tree_inventory(self.root / "private")
            # APFS chmod can rescale directory sizes; the write witness is
            # the exact path set plus byte-level stability of regular files.
            self.assertEqual(set(after), set(before))
            self.assertEqual(
                {k: v for k, v in after.items() if not v[1]},
                {k: v for k, v in before.items() if not v[1]})
        finally:
            session_dir.chmod(original_mode)
        # Not an unexercised mkdir: a real write must fail on this tree
        # while the reader succeeds on the same bytes.
        session_dir.chmod(0o500)
        try:
            with self.assertRaises(OSError):
                (session_dir / "probe").write_text("x")
            turn = self.state()["completion_attempt"]["turn_id"]
            self.assertEqual(self.query(turn=turn)["mode"], "current_work_unit")
        finally:
            session_dir.chmod(original_mode)

    # -- R03: fresh and legacy boundaries create nothing ------------------
    def test_r03_missing_and_legacy_sessions_create_nothing(self):
        self.ready()
        self.dispatch("Stop", last_assistant_message="诊断中。")
        before = tree_inventory(self.root / "private")
        with self.assertRaisesRegex(RuntimeError, "session_not_found"):
            self.query(session="missing-session")
        self.assertEqual(tree_inventory(self.root / "private"), before)
        # Legacy namespace bytes stay untouched by the same runtime.
        legacy_root = self.root / "private" / "sessions" / "legacy-s"
        legacy_root.mkdir(parents=True)
        legacy_state = self.state()
        legacy_state["session"]["id"] = "legacy-s"
        legacy_state["content_hash"] = cg.state_content_hash(legacy_state)
        legacy_state_path = legacy_root / "state.json"
        legacy_state_path.write_text(json.dumps(legacy_state),
                                     encoding="utf-8")
        legacy_before = legacy_state_path.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "invalid private completion"):
            cg.checkpoint_status(
                self.root / "private", "legacy-s", self.turn, "wrong")
        self.assertEqual(legacy_state_path.read_bytes(), legacy_before)
        after = tree_inventory(self.root / "private")
        self.assertEqual(sorted(set(after) - set(before)),
                         ["sessions", "sessions/legacy-s",
                          "sessions/legacy-s/state.json"])

    # -- R04: damaged states fail explicitly without repair ---------------
    def test_r04_damaged_states_fail_without_rebuild_or_backup(self):
        self.ready()
        self.dispatch("Stop", last_assistant_message="诊断中。")
        state_path = self.session_dir / "state.json"
        original = state_path.read_bytes()
        turn = json.loads(original)["completion_attempt"]["turn_id"]
        unknown_schema = json.loads(original)
        unknown_schema["schema_version"] = 99
        unknown_schema["content_hash"] = cg.state_content_hash(unknown_schema)
        hash_mismatch = json.loads(original)
        hash_mismatch["requirements"] = []
        hash_mismatch["content_hash"] = "0" * 64
        cases = {
            "corrupt": (b"{not json at all", "state_file_not_valid_json"),
            "truncated": (original[: len(original) // 2],
                          "state_file_not_valid_json|state_integrity_failed"),
            "unknown-schema": (json.dumps(unknown_schema).encode(),
                               "unsupported_state_schema_for_readonly_snapshot"),
            "hash-mismatch": (json.dumps(hash_mismatch).encode(),
                              "state_integrity_failed"),
        }
        before_state_files = {
            key for key in tree_inventory(self.root / "private")
            if "state" in key
        }
        try:
            for label, (payload, expected) in cases.items():
                with self.subTest(case=label):
                    state_path.write_bytes(payload)
                    with self.assertRaisesRegex(RuntimeError, expected):
                        self.query(turn=turn)
                    after_state_files = {
                        key
                        for key in tree_inventory(self.root / "private")
                        if "state" in key
                    }
                    self.assertEqual(after_state_files,
                                     set(before_state_files), label)
                    self.assertFalse(
                        list(self.session_dir.glob("state.corrupt.*.json")))
                    self.assertFalse(list(self.session_dir.glob("*.bak")))
        finally:
            state_path.write_bytes(original)

    def test_r04b_replaced_state_file_identity_is_rejected(self):
        self.ready()
        state_path = self.session_dir / "state.json"
        state_path.unlink()
        record = next(item for item in
                      (self.session_dir / "prompts").iterdir()
                      if item.is_file())
        state_path.symlink_to(record)
        with self.assertRaisesRegex(RuntimeError,
                                    "state_file_not_a_regular_file"):
            self.query()

    # -- R05: concurrent publication returns one consistent revision -----
    def test_r05_writer_publication_yields_whole_revisions(self):
        self.ready()
        published: list[str] = [self.state()["content_hash"]]
        stop = threading.Event()

        def writer():
            index = 0
            while not stop.is_set() and index < 24:
                state = self.state()
                state["wait_condition_sequence"] = index + 1
                self.save_state(state)
                published.append(self.state()["content_hash"])
                index += 1

        thread = threading.Thread(target=writer)
        thread.start()
        try:
            revisions = set()
            for _ in range(20):
                try:
                    result = self.query()
                except RuntimeError as exc:
                    # A bounded transient failure is allowed; an invented
                    # revision never is.
                    self.assertIn(str(exc), {
                        "state_changed_during_read", "state_read_unstable"})
                    continue
                revisions.add(result["revision"])
            thread.join(timeout=10)
            stop.set()
            self.assertTrue(revisions)
            self.assertTrue(revisions <= set(published),
                            (revisions, published))
            final = self.query()
            self.assertIn(final["revision"], published)
        finally:
            stop.set()
            thread.join(timeout=10)

    # -- R06: replaced lock path and cleanup races stay read-only --------
    def test_r06_replaced_lock_path_neither_read_nor_repaired(self):
        self.ready()
        self.dispatch("Stop", last_assistant_message="诊断中。")
        lock_path = self.root / "private" / "sessions-v2" / ".locks" / "p0.lock"
        decoy = self.root / "private" / "sessions-v2" / ".locks" / "decoy.lock"
        decoy.write_bytes(b"decoy")
        lock_path.unlink()
        lock_path.symlink_to(decoy)
        try:
            turn = self.state()["completion_attempt"]["turn_id"]
            result = self.query(turn=turn)
            self.assertEqual(result["mode"], "current_work_unit")
            self.assertTrue(lock_path.is_symlink())
            self.assertEqual(decoy.read_bytes(), b"decoy")
            # The reader never revived the session or weakened the writer
            # contract: a writer still fails closed on the linked path.
            with self.assertRaises(cg.StateIntegrityError):
                with cg.session_lock(self.session_dir):
                    pass
        finally:
            lock_path.unlink()
            decoy.unlink()

    # -- R07: missing or corrupt derived sidecar writes nothing ----------
    def test_r07_missing_or_corrupt_sidecar_writes_nothing(self):
        self.ready()
        self.dispatch("Stop", last_assistant_message="诊断中。")
        turn = self.state()["completion_attempt"]["turn_id"]
        observation = self.session_dir / "commentary-observation.json"
        result = self.query(turn=turn)
        self.assertEqual(result["commentary_observation"]["status"], "absent")
        self.assertFalse(observation.exists())
        observation.write_text("{broken", encoding="utf-8")
        before_broken = tree_inventory(self.root / "private")
        try:
            result = self.query(turn=turn)
            self.assertEqual(
                result["commentary_observation"]["status"], "unknown")
            after = tree_inventory(self.root / "private")
            self.assertEqual(after, before_broken)
            self.assertEqual(observation.read_text(encoding="utf-8"),
                             "{broken")
        finally:
            observation.unlink()

    # -- R08: bounded retries end in an explicit unknown ------------------
    def test_r08_continuous_change_returns_explicit_failure(self):
        self.ready()
        state_path = self.session_dir / "state.json"
        original = state_path.read_bytes()
        payload = json.loads(original)
        turn = payload["completion_attempt"]["turn_id"]
        real_open = os.open
        replacements = {"count": 0}

        def replace_then_open(path: object, flags: int, *rest: object,
                              **keywords: object) -> int:
            descriptor = real_open(path, flags, *rest, **keywords)
            if (os.fsdecode(path) == str(state_path)
                    and replacements["count"] < 8):
                replacements["count"] += 1
                payload["wait_condition_sequence"] = 100 + replacements["count"]
                cg.atomic_write_json(state_path, payload)
            return descriptor

        try:
            with mock.patch.object(cg.os, "open", side_effect=replace_then_open):
                with self.assertRaisesRegex(
                    RuntimeError, "state_changed_during_read"
                ):
                    self.query(turn=turn)
            self.assertLessEqual(replacements["count"], 8)
        finally:
            state_path.write_bytes(original)

    # -- R09: writer lifecycle is unaffected by the read path -------------
    def test_r09_writer_lifecycle_still_owns_the_kernel_lock(self):
        self.ready()
        turn_a = self.state()["completion_attempt"]["turn_id"]
        self.assertEqual(self.query(turn=turn_a)["mode"], "current_work_unit")
        with cg.session_lock(self.session_dir):
            state = self.state()
            state["wait_condition_sequence"] = 7
            state["content_hash"] = cg.state_content_hash(state)
            cg.save_state(self.session_dir, state)
        turn_b = self.state()["completion_attempt"]["turn_id"]
        self.assertEqual(self.query(turn=turn_b)["mode"], "current_work_unit")
        lock_path = self.root / "private" / "sessions-v2" / ".locks" / "p0.lock"
        self.assertTrue(lock_path.exists())
        lock_content = json.loads(lock_path.read_bytes())
        self.assertEqual(lock_content["lock_protocol"], 2)

    # -- R10: private bindings stay inside the private discovery path ----
    def test_r10_default_snapshot_carries_no_advanced_commands(self):
        self.ready()
        turn = self.state()["completion_attempt"]["turn_id"]
        default = self.query(turn=turn)
        serialized = json.dumps(default, ensure_ascii=True)
        self.assertNotIn("advanced_commands", serialized)
        self.assertNotIn("stage-checkpoint", serialized)
        self.assertNotIn("register-proof", serialized)
        commands = self.query(turn=turn, commands=True)
        self.assertIn("advanced_commands", json.dumps(commands))


if __name__ == "__main__":
    unittest.main()
