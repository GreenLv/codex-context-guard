#!/usr/bin/env python3
"""sessions-v2 namespace isolation and legacy read-only refusal regressions.

Implements the R3 coordinator decision: new sessions use sessions-v2; legacy
trees are strictly read-only for the new runtime (no repair, no prompt
creation, no cleanup, no migration); ordinary business tools keep their
approval-free path; an adopted release posture stays fail-closed. The
coordinator's legacy_ended_not_immutable probe is converted to the invariant
that ended_at is not a terminal barrier, which is exactly why legacy trees
must never be touched by this runtime.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)


class NamespaceResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(self.root / "private")

    def tearDown(self) -> None:
        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
        self.temp.cleanup()

    def _dispatch(self, event: str, session: str = "sess", **extra):
        payload = {"hook_event_name": event, "session_id": session,
                   "cwd": str(self.root), **extra}
        with mock.patch.object(cg.secrets, "token_urlsafe",
                               return_value="test-token"):
            return cg.dispatch(payload)

    def test_fresh_session_lands_in_v2(self):
        self._dispatch("UserPromptSubmit",
                       prompt="实现模块A。必须运行测试提供验收证据。")
        state = self.root / "private" / "sessions-v2" / "sess" / "state.json"
        self.assertTrue(state.is_file())
        self.assertEqual(
            cg.session_namespace(self.root / "private", "sess"), "v2")

    def test_missing_checkpoint_status_never_creates_legacy_binding(self):
        private = self.root / "private"
        with self.assertRaisesRegex(RuntimeError, "session_not_found"):
            cg.checkpoint_status(private, "sess", "missing-turn", "invalid")
        self.assertFalse(private.exists())
        self._dispatch("UserPromptSubmit", prompt="实现新任务并测试。")
        self.assertTrue((private / "sessions-v2/sess/state.json").is_file())
        self.assertFalse((private / "sessions").exists())

    def test_checkpoint_status_missing_state_does_not_create_locks(self):
        private = self.root / "private"
        for namespace in ("sessions", "sessions-v2"):
            with self.subTest(namespace=namespace):
                directory = private / namespace / namespace
                directory.mkdir(parents=True)
                before = sorted(p.relative_to(private).as_posix()
                                for p in private.rglob("*"))
                with self.assertRaisesRegex(RuntimeError, "session_not_found"):
                    cg.checkpoint_status(private, namespace, "t", "invalid")
                self.assertEqual(before, sorted(p.relative_to(private).as_posix()
                                                for p in private.rglob("*")))

    def test_legacy_session_is_refused_on_every_write_event(self):
        legacy = self.root / "private" / "sessions" / "old"
        legacy.mkdir(parents=True)
        state = cg.new_state({"session_id": "old"})
        state["mode"]["active"] = True
        cg.save_state(legacy, state)
        before = (legacy / "state.json").read_bytes()

        cases = [
            ("UserPromptSubmit",
             self._dispatch("UserPromptSubmit", session="old",
                            prompt="继续旧任务并完成剩余需求。"),
             lambda r: "systemMessage" in r and "previous" in r["systemMessage"]),
            ("Stop",
             self._dispatch("Stop", session="old",
                            last_assistant_message="任务已经全部完成。"),
             lambda r: r.get("continue") is False and "stopReason" in r),
            ("PreCompact", self._dispatch("PreCompact", session="old",
                                          trigger="manual"),
             lambda r: r.get("continue") is False),
            ("SessionEnd", self._dispatch("SessionEnd", session="old"),
             lambda r: "systemMessage" in r),
            ("PostToolUse",
             self._dispatch("PostToolUse", session="old", tool_name="bash",
                            tool_input={"command": "echo hi"},
                            tool_response={"stdout": "hi", "exit_code": 0}),
             lambda r: "systemMessage" in r),
        ]
        for event, result, check in cases:
            with self.subTest(event=event):
                self.assertTrue(check(result), result)
        # Nothing was written, no v2 twin was created, no cleanup ran.
        self.assertEqual((legacy / "state.json").read_bytes(), before)
        self.assertFalse((self.root / "private" / "sessions-v2" / "old").exists())
        self.assertFalse((legacy / "recovery.json").exists())

    def test_legacy_session_prompt_is_never_journaled(self):
        legacy = self.root / "private" / "sessions" / "old"
        legacy.mkdir(parents=True)
        state = cg.new_state({"session_id": "old"})
        state["mode"]["active"] = True
        cg.save_state(legacy, state)
        self._dispatch("UserPromptSubmit", session="old", prompt="新的根需求。")
        reloaded = json.loads((legacy / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(reloaded["prompts"], [])
        self.assertEqual(reloaded["requirements"], [])

    def test_legacy_pretooluse_keeps_ordinary_tools_approval_free(self):
        legacy = self.root / "private" / "sessions" / "old"
        legacy.mkdir(parents=True)
        state = cg.new_state({"session_id": "old"})
        state["mode"]["active"] = True
        cg.save_state(legacy, state)
        self.assertEqual(
            self._dispatch("PreToolUse", session="old", tool_name="bash",
                           tool_input={"command": "echo hello"}),
            {})

    def test_legacy_release_posture_stays_fail_closed(self):
        legacy = self.root / "private" / "sessions" / "old"
        legacy.mkdir(parents=True)
        state = cg.new_state({"session_id": "old"})
        state["mode"]["active"] = True
        state["mode"]["profile"] = "release"
        cg.save_state(legacy, state)
        (legacy / "release-required").write_text(
            json.dumps({"schema": "release-posture/v1"}), encoding="utf-8")
        result = self._dispatch("PreToolUse", session="old", tool_name="shell",
                                tool_input={"command": "git tag v1.2.3"})
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_read_paths_still_resolve_legacy_read_only(self):
        legacy = self.root / "private" / "sessions" / "old"
        legacy.mkdir(parents=True)
        state = cg.new_state({"session_id": "old"})
        cg.save_state(legacy, state)
        resolved = cg.session_dir_for({"session_id": "old"})
        self.assertEqual(resolved, legacy)
        self.assertEqual(
            cg.session_dir_for({"session_id": "brand-new"}),
            self.root / "private" / "sessions-v2" / "brand-new")

    def test_write_commands_refuse_legacy_fail_closed(self):
        legacy = self.root / "private" / "sessions" / "old"
        legacy.mkdir(parents=True)
        state = cg.new_state({"session_id": "old"})
        cg.save_state(legacy, state)
        with self.assertRaises(cg.LegacySessionWriteRefused):
            cg.writable_session_dir(self.root / "private", "old")
        self.assertEqual(
            cg.writable_session_dir(self.root / "private", "fresh"),
            self.root / "private" / "sessions-v2" / "fresh")

    def test_cleanup_skips_legacy_and_active_v2_and_never_deletes_locks(self):
        # Expired v2 session.
        expired_dir = self.root / "private" / "sessions-v2" / "expired"
        expired_dir.mkdir(parents=True)
        expired = cg.new_state({"session_id": "expired"})
        expired["session"]["ended_at"] = "2026-07-01T00:00:00+00:00"
        cg.save_state(expired_dir, expired)
        # Active v2 session.
        active_dir = self.root / "private" / "sessions-v2" / "active"
        active_dir.mkdir(parents=True)
        active = cg.new_state({"session_id": "active"})
        cg.save_state(active_dir, active)
        # Ended legacy session: never swept by this runtime.
        legacy_dir = self.root / "private" / "sessions" / "old"
        legacy_dir.mkdir(parents=True)
        old = cg.new_state({"session_id": "old"})
        old["session"]["ended_at"] = "2026-07-01T00:00:00+00:00"
        cg.save_state(legacy_dir, old)

        removed = cg.cleanup_old_sessions(self.root / "private")
        self.assertEqual(removed, 1)
        self.assertFalse(expired_dir.exists())
        self.assertTrue(active_dir.exists())
        self.assertTrue(legacy_dir.exists())
        # Lifecycle lock files live outside the subtrees and survive.
        self.assertTrue(
            cg.lifecycle_lock_path(expired_dir).exists())

    def test_cleanup_rechecks_eligibility_under_lifecycle_lock(self):
        active_dir = self.root / "private" / "sessions-v2" / "writer-holds"
        active_dir.mkdir(parents=True)
        state = cg.new_state({"session_id": "writer-holds"})
        state["session"]["ended_at"] = "2026-07-01T00:00:00+00:00"
        cg.save_state(active_dir, state)
        # Rewind mtime so the eligibility window is otherwise satisfied.
        import time as time_module
        old = time_module.time() - 10_000_000
        os.utime(active_dir / "state.json", (old, old))
        with cg.session_lock(active_dir, timeout=1.0):
            removed = cg.cleanup_old_sessions(self.root / "private")
            self.assertEqual(removed, 0)
            self.assertTrue(active_dir.exists())
        removed = cg.cleanup_old_sessions(self.root / "private")
        self.assertEqual(removed, 1)

    def test_ended_at_is_not_a_terminal_barrier_in_the_product(self):
        """Coordinator probe legacy_ended_not_immutable, converted: a session
        whose ended_at is set still journals a later prompt (any runtime).
        This is exactly why legacy trees must be read-only for this runtime:
        no timestamp proves a legacy writer is gone."""
        session_dir = self.root / "private" / "sessions-v2" / "ended"
        self._dispatch("UserPromptSubmit", session="ended",
                       prompt="实现需求一。必须运行测试提供验收证据。")
        self._dispatch("SessionEnd", session="ended")
        state = json.loads(
            (session_dir / "state.json").read_text(encoding="utf-8"))
        self.assertIsNotNone(state["session"]["ended_at"])
        prompts_before = len(state["prompts"])
        self._dispatch("UserPromptSubmit", session="ended",
                       prompt="结束后的新需求。必须运行测试提供验收证据。")
        state = json.loads(
            (session_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(len(state["prompts"]), prompts_before + 1)
        self.assertIsNone(state["session"]["ended_at"])

    def test_legacy_checkpoint_status_does_not_repair_corruption(self):
        legacy = self.root / "private/sessions/old"
        legacy.mkdir(parents=True)
        path = legacy / "state.json"
        path.write_text("{broken")
        before = {p.relative_to(legacy).as_posix(): p.read_bytes()
                  for p in legacy.rglob("*") if p.is_file()}
        with self.assertRaises((ValueError, cg.StateIntegrityError)):
            cg.checkpoint_status(self.root / "private", "old", "t", "token")
        after = {p.relative_to(legacy).as_posix(): p.read_bytes()
                 for p in legacy.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse((self.root / "private/sessions-v2/old").exists())

    def test_legacy_remaining_hook_events_are_read_only(self):
        legacy = self.root / "private/sessions/old"
        legacy.mkdir(parents=True)
        state = cg.new_state({"session_id": "old"})
        cg.save_state(legacy, state)
        before = (legacy / "state.json").read_bytes()
        names_before = sorted(p.name for p in legacy.iterdir())
        for event in ("SessionStart", "SubagentStart", "SubagentStop"):
            with self.subTest(event=event):
                self.assertIn("systemMessage", self._dispatch(event, session="old"))
        self.assertEqual((legacy / "state.json").read_bytes(), before)
        self.assertEqual(sorted(p.name for p in legacy.iterdir()), names_before)

    def test_lifecycle_lock_precedes_session_creation(self):
        directory = self.root / "private/sessions-v2/not-created"
        observed = []
        original = cg.filesystem_session_lock
        from contextlib import contextmanager
        @contextmanager
        def check(path, timeout):
            self.assertFalse(directory.exists())
            with original(path, timeout) as guard:
                observed.append(path)
                yield guard
        with mock.patch.object(cg, "filesystem_session_lock", check):
            with cg.session_lock(directory):
                self.assertTrue(directory.is_dir())
        self.assertEqual(observed, [cg.lifecycle_lock_path(directory)])

    def test_every_private_write_api_refuses_legacy_before_loading(self):
        legacy = self.root / "private/sessions/old"
        legacy.mkdir(parents=True)
        path = legacy / "state.json"
        path.write_text("{broken")
        root = self.root / "private"
        operations = [
            lambda: cg.clear_pending_request(root, "old", "t", "token"),
            lambda: cg.validate_checkpoint_request(root, "old", "t", "token", [], []),
            lambda: cg.validate_disposition_request(root, "old", "t", "token", "deferred"),
            lambda: cg.validate_proof_request(root, "old", "t", "token", self.root / "absent"),
            lambda: cg.stage_private_checkpoint(root, "old", "t", "token", [], []),
            lambda: cg.stage_private_disposition(root, "old", "t", "token", "deferred"),
        ]
        with mock.patch.object(cg, "load_state", side_effect=AssertionError("must not load")):
            for operation in operations:
                with self.assertRaises(cg.LegacySessionWriteRefused):
                    operation()
        self.assertEqual(path.read_text(), "{broken")
        self.assertFalse((root / "sessions-v2/old").exists())

    def test_cleanup_does_not_treat_lock_registry_as_a_session(self):
        directory = self.root / "private/sessions-v2/expired"
        directory.mkdir(parents=True)
        state = cg.new_state({"session_id": "expired"})
        state["session"]["ended_at"] = "2026-07-01T00:00:00+00:00"
        cg.save_state(directory, state)
        cg.cleanup_old_sessions(self.root / "private")
        cg.cleanup_old_sessions(self.root / "private")
        self.assertEqual([p.name for p in directory.parent.joinpath(".locks").iterdir()],
                         ["expired.lock"])

    def test_zero_inode_never_certifies_lock_ownership(self):
        from types import SimpleNamespace
        guard = cg.SessionLockGuard(self.root / "lock", 1)
        zero = SimpleNamespace(st_ino=0, st_dev=1)
        with mock.patch.object(cg.os, "fstat", return_value=zero), \
             mock.patch.object(cg.os, "stat", return_value=zero):
            with self.assertRaises(cg.LockOwnershipError):
                guard.verify_ownership()

    def test_linked_v2_session_is_refused_before_writing(self):
        target = self.root / "elsewhere"
        target.mkdir()
        directory = self.root / "private/sessions-v2/linked"
        directory.parent.mkdir(parents=True)
        try:
            directory.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink capability unavailable: {exc}")
        with self.assertRaises(cg.StateIntegrityError):
            with cg.session_lock(directory):
                self.fail("linked session acquired")
        self.assertEqual(list(target.iterdir()), [])

    def test_reserved_directory_ids_are_never_sessions(self):
        for identity in (".", "..", ".locks"):
            with self.subTest(identity=identity):
                with self.assertRaises(ValueError):
                    cg.write_session_dir({"session_id": identity})
        self.assertFalse((self.root / "private").exists())

    def test_resumed_v2_session_is_not_cleaned_by_stale_end_marker(self):
        self._dispatch("UserPromptSubmit", session="resumed",
                       prompt="实现模块，必须验证。")
        directory = self.root / "private/sessions-v2/resumed"
        state = cg.load_state(directory, {"session_id": "resumed"})
        state["session"]["ended_at"] = "2026-07-01T00:00:00+00:00"
        cg.save_state(directory, state)
        self._dispatch("UserPromptSubmit", session="resumed",
                       prompt="继续未完成需求，必须运行验证。")
        self.assertEqual(cg.cleanup_old_sessions(self.root / "private"), 0)
        self.assertTrue(directory.is_dir())
        self.assertTrue(cg.load_state(directory, {"session_id": "resumed"})["requirements"])


if __name__ == "__main__":
    unittest.main()
