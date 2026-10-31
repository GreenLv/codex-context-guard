"""Pending decision: explicit no-retention-deletion contract controls."""
import json
import os
import subprocess
import sys
from unittest import mock

from tests import test_cg0160_repair_family as fixtures

cg = fixtures.cg


class RetentionDisabledCandidate(fixtures.IsolatedEnvironment):
    _make_session = fixtures.F08BoundedSessionEndCleanup._make_session

    def fixture_tree(self):
        self._make_session("old", ended_days_ago=45)
        old = self.session_dir("old")
        (old / cg.CLEANUP_PARTIAL_MARKER).write_text("eligible cleanup marker (content-free)\n")
        legacy = self.data_dir / cg.LEGACY_NAMESPACE / "legacy-old"
        legacy.mkdir(parents=True)
        (legacy / "state.json").write_text("legacy fixture")
        return old, legacy

    def snapshot(self, root):
        return {str(path.relative_to(root)): path.read_bytes()
                for path in root.rglob("*") if path.is_file()}

    def test_session_end_saves_current_and_recovery_without_entering_cleanup(self):
        old, legacy = self.fixture_tree()
        before = self.snapshot(old), self.snapshot(legacy)
        cg.dispatch(self.payload("UserPromptSubmit", "current", prompt="Please fix main.py", turn_id="t1"))
        state_path = self.session_dir("current") / "state.json"
        state = json.loads(state_path.read_text())
        state["mode"]["active"] = True
        state["content_hash"] = cg.state_content_hash(state)
        state_path.write_text(json.dumps(state), encoding="utf-8")
        with mock.patch.object(cg, "cleanup_old_sessions", side_effect=AssertionError("retired cleanup reached")):
            self.assertEqual(cg.dispatch(self.payload("SessionEnd", "current")), {})
        current = self.session_dir("current")
        state = json.loads((current / "state.json").read_text())
        self.assertIsNotNone(state["session"]["ended_at"])
        self.assertTrue((current / "recovery.md").is_file())
        self.assertEqual((self.snapshot(old), self.snapshot(legacy)), before)

    def test_explicit_cleanup_reports_unavailable_and_preserves_data(self):
        self.fixture_tree()
        before = self.snapshot(self.data_dir)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-B", str(fixtures.MODULE_PATH), "cleanup"],
                                env=env, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("cleanup is disabled", result.stderr)
        self.assertNotIn("Removed", result.stdout)
        self.assertEqual(self.snapshot(self.data_dir), before)

    def test_direct_api_reports_unavailable_without_mutation(self):
        old, _ = self.fixture_tree()
        before = self.snapshot(self.data_dir)
        with self.assertRaisesRegex(RuntimeError, "cleanup is disabled"):
            cg.cleanup_old_sessions(self.data_dir)
        self.assertTrue(old.is_dir())
        self.assertEqual(self.snapshot(self.data_dir), before)

    def test_internal_delete_reports_unavailable_without_mutation(self):
        old, _ = self.fixture_tree()
        before = self.snapshot(self.data_dir)
        with self.assertRaisesRegex(RuntimeError, "cleanup is disabled"):
            cg._delete_session_tree_bounded(old, lambda: True)
        self.assertTrue(old.is_dir())
        self.assertEqual(self.snapshot(self.data_dir), before)

    def test_resume_of_retained_old_session_remains_live(self):
        old, _ = self.fixture_tree()
        cg.dispatch(self.payload("UserPromptSubmit", "old", prompt="Continue main.py", turn_id="t2"))
        cg.dispatch(self.payload("SessionEnd", "different-current"))
        self.assertTrue(old.is_dir())
        self.assertIsNone(json.loads((old / "state.json").read_text())["session"]["ended_at"])
        self.assertFalse((old / cg.CLEANUP_PARTIAL_MARKER).exists())

    def test_private_boundary_failure_still_refuses_session_end(self):
        cg.dispatch(self.payload("UserPromptSubmit", "current", prompt="Please fix main.py", turn_id="t1"))
        before = (self.session_dir("current") / "state.json").read_bytes()
        with mock.patch.object(cg, "secure_directory", side_effect=cg.PrivateBoundaryError("synthetic refusal")):
            with self.assertRaises(cg.PrivateBoundaryError):
                cg.dispatch(self.payload("SessionEnd", "current"))
        self.assertEqual((self.session_dir("current") / "state.json").read_bytes(), before)

    def test_expired_and_invalid_budget_still_save_without_cleanup(self):
        for index, start in enumerate((None, True, -1, float("nan"), 0.0)):
            name = f"budget-{index}"
            cg.dispatch(self.payload("UserPromptSubmit", name, prompt="Please fix main.py", turn_id="t1"))
            with mock.patch.object(cg, "cleanup_old_sessions", side_effect=AssertionError("retired cleanup reached")):
                cg.dispatch(self.payload("SessionEnd", name), budget_started_at=start)
            self.assertIsNotNone(json.loads((self.session_dir(name) / "state.json").read_text())["session"]["ended_at"])

    def test_session_end_preserves_old_lifecycle_lock_identity(self):
        old, _ = self.fixture_tree()
        lock = cg.lifecycle_lock_path(old)
        before = lock.stat()
        cg.dispatch(self.payload("SessionEnd", "current"))
        after = lock.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertTrue(old.is_dir())

    def test_old_directory_link_and_external_target_are_untouched(self):
        self._make_session("current", ended_days_ago=None)
        outside = self.root / "outside"
        outside.mkdir()
        keep = outside / "keep.txt"
        keep.write_text("outside fixture")
        link = self.data_dir / cg.V2_NAMESPACE / "old-link"
        fixtures.symlink_or_skip(self, link, outside, target_is_directory=True)
        cg.dispatch(self.payload("SessionEnd", "current"))
        self.assertTrue(link.is_symlink())
        self.assertEqual(keep.read_text(), "outside fixture")
        self.assertEqual(sorted(path.name for path in outside.iterdir()), ["keep.txt"])

    def test_cleanup_command_does_not_create_default_home_or_mutate_environment(self):
        default_home = self.root / "never-created-codex-home"
        env = dict(os.environ, CODEX_HOME=str(default_home),
                   CONTEXT_GUARD_DATA_DIR="", PLUGIN_DATA="", CLAUDE_PLUGIN_DATA="",
                   PYTHONDONTWRITEBYTECODE="1")
        before_environment = dict(os.environ)
        result = subprocess.run([sys.executable, "-B", str(fixtures.MODULE_PATH), "cleanup"],
                                env=env, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("cleanup is disabled", result.stderr)
        self.assertFalse(default_home.exists())
        self.assertEqual(dict(os.environ), before_environment)

    def test_direct_disabled_entries_never_inspect_or_mutate_supplied_paths(self):
        supplied = self.root / "uncreated-data-root"
        before_environment = dict(os.environ)
        with mock.patch.object(cg.os, "scandir", side_effect=AssertionError("unexpected enumeration")), \
                mock.patch.object(cg, "_maintenance_boundary_ok", side_effect=AssertionError("unexpected path inspection")), \
                mock.patch.object(cg, "secure_directory", side_effect=AssertionError("unexpected permission mutation")):
            for operation in (lambda: cg.cleanup_old_sessions(supplied),
                              lambda: cg._delete_session_tree_bounded(supplied, lambda: True)):
                with self.assertRaisesRegex(RuntimeError, "cleanup is disabled"):
                    operation()
        self.assertFalse(supplied.exists())
        self.assertEqual(dict(os.environ), before_environment)

    def _run_hook_process(self, event, session, **extra):
        payload = self.payload(event, session, **extra)
        result = subprocess.run(
            [sys.executable, "-B", str(fixtures.MODULE_PATH), "hook"],
            input=json.dumps(payload, ensure_ascii=False), text=True, encoding="utf-8",
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        response = json.loads(result.stdout)
        self.assertIsInstance(response, dict)
        if event == "SessionEnd":
            self.assertEqual(response, {})

    def test_repeated_hook_processes_preserve_old_registry_bytes_and_identity(self):
        session = "registry-current"
        self._make_session(session, ended_days_ago=None)
        current = self.session_dir(session)
        state_path = current / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["mode"]["active"] = True
        state["content_hash"] = cg.state_content_hash(state)
        state_path.write_text(json.dumps(state), encoding="utf-8")
        marker = current / cg.CLEANUP_PARTIAL_MARKER
        marker.write_text("historical partial deletion", encoding="utf-8")
        registry = cg._cleanup_registry_path(self.data_dir)
        registry.write_text("old-session\nold-session\n", encoding="utf-8")
        before = registry.read_bytes()
        info = registry.stat()
        for turn in ("t2", "t3"):
            self._run_hook_process("UserPromptSubmit", session, prompt="continue fixture", turn_id=turn)
            self.assertFalse(marker.exists())
        marker.write_text("old marker before non-resume save", encoding="utf-8")
        self._run_hook_process("SessionEnd", session)
        after = registry.stat()
        self.assertEqual(registry.read_bytes(), before)
        self.assertEqual((after.st_dev, after.st_ino, after.st_mode),
                         (info.st_dev, info.st_ino, info.st_mode))
        self.assertFalse(marker.exists())
        final_state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertIsNotNone(final_state["session"]["ended_at"])
        self.assertGreaterEqual(len(final_state["prompts"]), 3)
        self.assertTrue((current / "recovery.md").is_file())

    def test_fresh_hook_processes_do_not_create_missing_registry(self):
        registry = cg._cleanup_registry_path(self.data_dir)
        self.assertFalse(registry.exists())
        self._run_hook_process("UserPromptSubmit", "no-registry", prompt="fixture", turn_id="t1")
        self._run_hook_process("SessionEnd", "no-registry")
        self.assertFalse(registry.exists())
        self.assertIsNotNone(json.loads(
            (self.session_dir("no-registry") / "state.json").read_text(encoding="utf-8")
        )["session"]["ended_at"])

    def test_state_save_ignores_linked_registry_without_external_writes(self):
        self._make_session("linked-registry", ended_days_ago=None)
        registry = cg._cleanup_registry_path(self.data_dir)
        registry.unlink(missing_ok=True)
        outside = self.root / "outside-registry.txt"
        outside.write_text("external fixture\n", encoding="utf-8")
        fixtures.symlink_or_skip(self, registry, outside)
        before = outside.read_bytes()
        info = outside.stat()
        self._run_hook_process("UserPromptSubmit", "linked-registry", prompt="continue", turn_id="t2")
        self._run_hook_process("SessionEnd", "linked-registry")
        self.assertTrue(registry.is_symlink())
        self.assertEqual(outside.read_bytes(), before)
        self.assertEqual((outside.stat().st_dev, outside.stat().st_ino, outside.stat().st_mode),
                         (info.st_dev, info.st_ino, info.st_mode))
