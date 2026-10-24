#!/usr/bin/env python3
"""0.16.0 repair-family regressions for F01-F03 and F06-F10.

Every test here encodes a probe that reproduced on the published 0.15.1
baseline (see the phase-A reproduction record) and must hold after the
0.16.0 candidate. Windows-only behavior is covered by source-level checks
with explicit mock boundaries; native Windows facts stay separate gates.
"""

from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard_0160", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)

MARKER_PW = "synthetic-PW-7f3a9c"
MARKER_KEY = "synthetic-KEY-1b2c3d"


class IsolatedEnvironment(unittest.TestCase):
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
        for name in ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT"):
            os.environ.pop(name, None)
        self.project = self.root / "project"
        self.project.mkdir()

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env)
        self.temporary.cleanup()

    def payload(self, event: str, session: str, **extra) -> dict:
        base = {
            "hook_event_name": event,
            "session_id": session,
            "cwd": str(self.project),
        }
        base.update(extra)
        return base

    def session_dir(self, session: str) -> Path:
        return self.data_dir / "sessions-v2" / cg.safe_session_id(session)

    def load_state(self, session: str) -> dict:
        return json.loads(
            (self.session_dir(session) / "state.json").read_text(encoding="utf-8")
        )


class F01StructuredSecretRedaction(IsolatedEnvironment):
    def test_tool_credentials_never_reach_state_or_export(self) -> None:
        session = "f01-structured"
        cg.dispatch(self.payload(
            "UserPromptSubmit", session, prompt="Repair demo.py and run tests.",
            turn_id="t1"))
        tool_output = json.dumps({
            "status": "ok",
            "password": MARKER_PW,
            "credentials": {"api_key": MARKER_KEY},
        })
        cg.dispatch(self.payload(
            "PostToolUse", session, tool_name="Bash",
            tool_input={"command": "cat config.json"},
            tool_response={"output": tool_output, "exit_code": 0},
            turn_id="t1"))
        state_text = json.dumps(self.load_state(session))
        self.assertNotIn(MARKER_PW, state_text)
        self.assertNotIn(MARKER_KEY, state_text)

        out = cg.export_handoff(
            self.session_dir(session), self.load_state(session),
            "handoff-f01.md")
        export_text = out.read_text(encoding="utf-8")
        self.assertNotIn(MARKER_PW, export_text)
        self.assertNotIn(MARKER_KEY, export_text)
        self.assertNotIn(str(self.data_dir), export_text)

    def test_serialized_json_text_is_redacted_by_the_text_fallback(self) -> None:
        for sample in (
            f'{{"password": "{MARKER_PW}"}}',
            f"password = '{MARKER_PW}'",
            f'"api_key":"{MARKER_KEY}"',
            f"Client-Secret: {MARKER_PW}",
            f"secret_key={MARKER_KEY}",
        ):
            redacted = cg.redact_text(sample)
            self.assertNotIn(MARKER_PW, redacted, sample)
            self.assertNotIn(MARKER_KEY, redacted, sample)

    def test_url_userinfo_and_common_token_shapes_are_redacted(self) -> None:
        samples = [
            "postgres://admin:hunter2-secret@example.internal/db",
            "token sk-abc1234567890xyzDONE",
            "ghp_" + "a" * 36,
            "github_pat_" + "b" * 40,
            "xoxb-" + "c" * 20,
            "AKIA" + "D" * 16,
            "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 8,
        ]
        for sample in samples:
            redacted = cg.redact_text(sample)
            self.assertNotEqual(sample, redacted, sample)
            self.assertNotIn("hunter2-secret", redacted)
            for shape in ("[REDACTED]", "[user:secret-redacted]"):
                if shape in redacted:
                    break
            else:
                self.fail(f"no redaction marker in {redacted!r}")

    def test_same_shaped_business_values_survive(self) -> None:
        keep = cg.sanitize_evidence_value({
            "password_policy": "rotate every 90 days",
            "secrets_management": {"docs": "see runbook"},
            "api_version": "2024-01-01",
        })
        self.assertEqual(keep["password_policy"], "rotate every 90 days")
        self.assertEqual(keep["api_version"], "2024-01-01")

    def test_key_matching_ignores_case_and_separator_shape(self) -> None:
        redacted = cg.sanitize_evidence_value({
            "API-KEY": MARKER_KEY,
            "Access_Token": MARKER_PW,
            "clientsecret": MARKER_PW,
        })
        self.assertEqual(redacted["API-KEY"], "[REDACTED]")
        self.assertEqual(redacted["Access_Token"], "[REDACTED]")
        self.assertEqual(redacted["clientsecret"], "[REDACTED]")

    def test_private_paths_are_scrubbed_from_exports(self) -> None:
        session = "f01-paths"
        cg.dispatch(self.payload(
            "UserPromptSubmit", session,
            prompt="Read the state at %s and report counts." % self.data_dir,
            turn_id="t1"))
        out = cg.export_handoff(
            self.session_dir(session), self.load_state(session), "handoff.md")
        export_text = out.read_text(encoding="utf-8")
        self.assertNotIn(str(self.data_dir), export_text)
        self.assertIn("[private path omitted]", export_text)


class F02F06ExportWriter(IsolatedEnvironment):
    def _active_state(self, session: str = "f02-export") -> dict:
        cg.dispatch(self.payload(
            "UserPromptSubmit", session, prompt="Task for export tests.",
            turn_id="t1"))
        return self.load_state(session)

    def test_existing_target_is_never_overwritten(self) -> None:
        state = self._active_state()
        existing = self.project / "NOTES.md"
        original = "user's uncommitted notes"
        existing.write_text(original, encoding="utf-8")
        with self.assertRaisesRegex(
            cg.ExportTargetExistsError, "already exists"
        ):
            cg.export_handoff(self.session_dir("f02-export"), state, "NOTES.md")
        self.assertEqual(existing.read_text(encoding="utf-8"), original)

    def test_parent_directory_permissions_are_preserved(self) -> None:
        state = self._active_state()
        self.project.chmod(0o755)
        out = cg.export_handoff(
            self.session_dir("f02-export"), state, "handoff-new.md")
        self.assertEqual(stat.S_IMODE(self.project.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)

    def test_directory_and_symlink_targets_are_refused(self) -> None:
        state = self._active_state()
        target_dir = self.project / "target.md"
        target_dir.mkdir()
        with self.assertRaises(cg.ExportTargetExistsError):
            cg.export_handoff(self.session_dir("f02-export"), state, "target.md")
        link = self.project / "link.md"
        link.symlink_to(self.project / "other.txt")
        with self.assertRaises(ValueError):
            cg.export_handoff(self.session_dir("f02-export"), state, "link.md")
        self.assertFalse((self.project / "other.txt").exists())

    def test_failed_export_leaves_no_partial_file(self) -> None:
        state = self._active_state()
        (self.project / "blocked.md").write_text("keep", encoding="utf-8")
        with self.assertRaises(cg.ExportTargetExistsError):
            cg.export_handoff(self.session_dir("f02-export"), state, "blocked.md")
        leftovers = [
            entry.name for entry in self.project.iterdir()
            if entry.name.startswith(".blocked.md")
        ]
        self.assertEqual(leftovers, [])

    def test_concurrent_same_name_exports_produce_exactly_one_file(self) -> None:
        state = self._active_state()
        results: list[BaseException | None] = []

        def worker() -> None:
            try:
                cg.export_handoff(
                    self.session_dir("f02-export"), state, "race.md")
                results.append(None)
            except BaseException as exc:  # noqa: BLE001
                results.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        successes = sum(1 for item in results if item is None)
        self.assertEqual(successes, 1)
        target = self.project / "race.md"
        self.assertTrue(target.is_file())
        self.assertTrue(target.read_text(encoding="utf-8").startswith("# Context Guard Handoff"))
        leftovers = [
            entry.name for entry in self.project.iterdir()
            if entry.name.startswith(".race.md")
        ]
        self.assertEqual(leftovers, [])


class F03PrivatePermissionBoundary(IsolatedEnvironment):
    def test_chmod_failure_is_visible_and_fail_closed(self) -> None:
        loose = self.root / "loose"
        loose.mkdir(mode=0o755)
        with mock.patch.object(
            cg.os, "chmod", side_effect=PermissionError("denied")
        ):
            with self.assertRaises(cg.PrivateBoundaryError):
                cg.secure_directory(loose)
        self.assertEqual(stat.S_IMODE(loose.stat().st_mode), 0o755)

    def test_mode_verification_failure_is_visible(self) -> None:
        target = self.root / "sneaky"
        target.mkdir(mode=0o700)

        class FakeStat:
            st_mode = 0o40755  # directory with a loose mode

        with mock.patch.object(Path, "stat", return_value=FakeStat()):
            with self.assertRaises(cg.PrivateBoundaryError):
                cg.secure_directory(target)

    def test_existing_loose_private_directory_is_tightened(self) -> None:
        loose = self.data_dir / "sessions-v2" / "late"
        loose.mkdir(parents=True, mode=0o755)
        cg.secure_directory(loose)
        self.assertEqual(stat.S_IMODE(loose.stat().st_mode), 0o700)

    def test_hot_path_existing_hardened_directory_is_unchanged(self) -> None:
        hardened = self.data_dir / "sessions-v2" / "hot"
        hardened.mkdir(parents=True, mode=0o700)
        before = hardened.stat().st_mtime_ns
        cg.secure_directory(hardened)
        self.assertEqual(stat.S_IMODE(hardened.stat().st_mode), 0o700)
        self.assertGreaterEqual(hardened.stat().st_mtime_ns, before)

    def test_windows_sddl_expectation_shape(self) -> None:
        with mock.patch.object(
            cg, "_windows_current_user_sid", return_value="S-1-5-21-1"
        ):
            directory_sddl = cg._windows_expected_sddl(is_directory=True)
            file_sddl = cg._windows_expected_sddl(is_directory=False)
        self.assertEqual(
            directory_sddl,
            "D:P(A;OICI;FA;;;S-1-5-21-1)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        )
        self.assertEqual(
            file_sddl,
            "D:P(A;;FA;;;S-1-5-21-1)(A;;FA;;;SY)(A;;FA;;;BA)",
        )

    def test_windows_harden_rejects_when_dacl_cannot_match(self) -> None:
        target = self.root / "winish"
        target.mkdir()
        calls: list[str] = []
        with mock.patch.object(
            cg, "_windows_current_user_sid", return_value="S-1-5-21-1"
        ), mock.patch.object(
            cg, "_windows_query_dacl_sddl",
            side_effect=lambda path: calls.append("query") or "D:P(A;;FA;;;BA)",
        ), mock.patch.object(
            cg, "_windows_apply_protected_dacl",
            side_effect=lambda path, sddl: calls.append("apply"),
        ):
            with self.assertRaises(cg.PrivateBoundaryError):
                cg._harden_private_directory_windows(target)
        self.assertEqual(calls.count("apply"), 1)

    def test_windows_harden_rejects_when_query_fails(self) -> None:
        target = self.root / "winish2"
        target.mkdir()
        with mock.patch.object(
            cg, "_windows_current_user_sid", return_value="S-1-5-21-1"
        ), mock.patch.object(
            cg, "_windows_query_dacl_sddl", return_value=None
        ), mock.patch.object(
            cg, "_windows_apply_protected_dacl",
            side_effect=OSError(" SetNamedSecurityInfoW failed"),
        ) as apply_mock:
            with self.assertRaises(cg.PrivateBoundaryError):
                cg._harden_private_directory_windows(target)
        apply_mock.assert_called_once()


class F07SessionIdentity(IsolatedEnvironment):
    def test_distinct_raw_ids_never_share_a_directory(self) -> None:
        cg.dispatch(self.payload(
            "UserPromptSubmit", "aaa/bbb", prompt="first", turn_id="t1"))
        cg.dispatch(self.payload(
            "UserPromptSubmit", "aaa_bbb", prompt="second", turn_id="t1"))
        first = json.loads((self.session_dir("aaa/bbb") / "state.json").read_text())
        second = json.loads((self.session_dir("aaa_bbb") / "state.json").read_text())
        self.assertEqual([row["id"] for row in first["prompts"]], ["P0001"])
        self.assertEqual([row["id"] for row in second["prompts"]], ["P0001"])

    def test_missing_session_id_is_refused_without_writing(self) -> None:
        result = cg.safe_dispatch({
            "hook_event_name": "UserPromptSubmit",
            "session_id": "",
            "prompt": "orphan",
            "cwd": str(self.project),
        })
        self.assertNotEqual(result, {})
        self.assertFalse((self.data_dir / "sessions-v2" / "unknown-session").exists())

    def test_reserved_and_windows_device_names_are_rejected(self) -> None:
        for bad in (".", "..", ".locks", "CON", "com1", "LPT9.tar"):
            with self.assertRaises(cg.SessionIdentityError, msg=bad):
                cg.safe_session_id(bad)

    def test_long_ids_truncate_without_collision(self) -> None:
        base = "S" * 200
        first = cg.safe_session_id(base)
        second = cg.safe_session_id(base + "-different-tail")
        self.assertNotEqual(first, second)
        self.assertLessEqual(len(first), 120)
        self.assertLessEqual(len(second), 120)

    def test_unicode_and_separator_ids_are_injectively_encoded(self) -> None:
        encoded = cg.safe_session_id("会话/ID:一号")
        self.assertNotIn("会话", encoded)
        self.assertEqual(cg.safe_session_id("会话/ID:一号"), encoded)
        self.assertNotEqual(encoded, cg.safe_session_id("会话/ID:二号"))

    def test_state_identity_mismatch_fails_closed(self) -> None:
        cg.dispatch(self.payload(
            "UserPromptSubmit", "uuid-1111", prompt="owner", turn_id="t1"))
        # Corrupt the recorded owner identity without touching the directory
        # name; a colliding raw id must be refused before any write.
        state_path = self.session_dir("uuid-1111") / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["session"]["id"] = "uuid-2222"
        state["content_hash"] = cg.state_content_hash(state)
        state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n",
                              encoding="utf-8")
        result = cg.safe_dispatch(self.payload(
            "UserPromptSubmit", "uuid-1111", prompt="impostor", turn_id="t2"))
        self.assertNotEqual(result, {})
        prompts = json.loads(state_path.read_text(encoding="utf-8"))["prompts"]
        self.assertEqual(len(prompts), 1)

    def test_casefold_sibling_creation_is_refused(self) -> None:
        cg.dispatch(self.payload(
            "UserPromptSubmit", "abc", prompt="first", turn_id="t1"))
        result = cg.safe_dispatch(self.payload(
            "UserPromptSubmit", "ABC", prompt="second", turn_id="t1"))
        self.assertNotEqual(result, {})
        v2 = self.data_dir / "sessions-v2"
        names = sorted(
            entry.name for entry in v2.iterdir()
            if entry.name != ".locks" and entry.is_dir()
        )
        self.assertEqual(names, ["abc"])

    def test_uuid_shaped_ids_keep_their_exact_mapping(self) -> None:
        uuid_like = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
        self.assertEqual(cg.safe_session_id(uuid_like), uuid_like)


class F09DataRootPriority(IsolatedEnvironment):
    def test_explicit_roots_win_in_declared_order(self) -> None:
        os.environ["CONTEXT_GUARD_DATA_DIR"] = ""
        os.environ["PLUGIN_DATA"] = str(self.root / "plugin-data")
        self.assertEqual(cg.data_root(), self.root / "plugin-data")
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(self.root / "explicit")
        self.assertEqual(cg.data_root(), self.root / "explicit")

    def test_empty_values_fall_through_to_codex_home(self) -> None:
        os.environ["CONTEXT_GUARD_DATA_DIR"] = "  "
        os.environ["PLUGIN_DATA"] = ""
        self.assertEqual(cg.data_root(), self.codex_home / "context-guard")

    def test_codex_home_owns_its_private_data_root(self) -> None:
        first = self.root / "home-a"
        second = self.root / "home-b"
        os.environ["CONTEXT_GUARD_DATA_DIR"] = ""
        os.environ["CODEX_HOME"] = str(first)
        cg.dispatch(self.payload(
            "UserPromptSubmit", "iso-1", prompt="home a task", turn_id="t1"))
        os.environ["CODEX_HOME"] = str(second)
        cg.dispatch(self.payload(
            "UserPromptSubmit", "iso-2", prompt="home b task", turn_id="t1"))
        self.assertTrue((first / "context-guard" / "sessions-v2" / "iso-1").is_dir())
        self.assertTrue((second / "context-guard" / "sessions-v2" / "iso-2").is_dir())
        self.assertFalse((first / "context-guard" / "sessions-v2" / "iso-2").exists())

    def test_default_without_codex_home_is_unchanged(self) -> None:
        os.environ["CODEX_HOME"] = ""
        os.environ["CONTEXT_GUARD_DATA_DIR"] = ""
        self.assertEqual(
            cg.data_root(), self.os_home / ".codex" / "context-guard")


class F08BoundedSessionEndCleanup(IsolatedEnvironment):
    def _make_session(self, name: str, *, ended_days_ago: float | None) -> None:
        # A real journaled session keeps the full schema-13 shape that
        # validate_state_integrity requires; synthetic minimal states are
        # rejected as corrupt and would never be cleanup-eligible.
        cg.dispatch(self.payload(
            "UserPromptSubmit", name, prompt="expired task", turn_id="t1"))
        if ended_days_ago is None:
            return
        state_path = self.session_dir(name) / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["session"]["ended_at"] = (
            cg.dt.datetime.now(cg.dt.timezone.utc)
            - cg.dt.timedelta(days=ended_days_ago)
        ).isoformat().replace("+00:00", "Z")
        state["content_hash"] = cg.state_content_hash(state)
        state_path.write_text(
            json.dumps(state, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        # The mtime pre-filter must see an untouched old file.
        old = time.time() - ended_days_ago * 86400
        os.utime(state_path, (old, old))

    def test_busy_locks_cannot_overrun_the_three_second_budget(self) -> None:
        cg.dispatch(self.payload(
            "UserPromptSubmit", "current-live", prompt="current", turn_id="t1"))
        handles = []
        locks_dir = self.data_dir / "sessions-v2" / ".locks"
        locks_dir.mkdir(parents=True, exist_ok=True)
        for index in range(16):
            name = f"locked-{index:02d}"
            self._make_session(name, ended_days_ago=45)
            handle = open(locks_dir / f"{name}.lock", "a+b")
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handles.append(handle)
        started = time.monotonic()
        cg.dispatch(self.payload("SessionEnd", "current-live"))
        elapsed = time.monotonic() - started
        for handle in handles:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()
        self.assertLess(elapsed, 3.0)
        # Locked sessions are skipped, not deleted and not force-taken.
        for index in range(16):
            self.assertTrue(
                (self.data_dir / "sessions-v2" / f"locked-{index:02d}").is_dir()
            )
        self.assertIsNotNone(
            json.loads(
                (self.session_dir("current-live") / "state.json").read_text()
            )["session"]["ended_at"]
        )

    def test_repeated_passes_complete_a_large_backlog(self) -> None:
        for index in range(40):
            self._make_session(f"old-{index:03d}", ended_days_ago=45)
        removed_total = 0
        for _ in range(12):
            removed_total += cg.cleanup_old_sessions(
                self.data_dir, deadline=time.monotonic() + 0.35)
        self.assertEqual(removed_total, 40)
        remaining = [
            entry.name for entry in
            (self.data_dir / "sessions-v2").iterdir()
            if entry.name.startswith("old-")
        ]
        self.assertEqual(remaining, [])

    def test_interrupted_deletion_resumes_from_marker(self) -> None:
        session_dir = self.data_dir / "sessions-v2" / "huge"
        self._make_session("huge", ended_days_ago=45)
        bulk = session_dir / "bulk"
        bulk.mkdir()
        for index in range(2000):
            (bulk / f"f-{index:05d}.txt").write_text("x" * 64, encoding="utf-8")
        # A tiny deadline stops the sweep mid-tree.
        cg.cleanup_old_sessions(self.data_dir, deadline=time.monotonic() + 0.02)
        self.assertTrue(session_dir.exists())
        marker = session_dir / cg.CLEANUP_PARTIAL_MARKER
        self.assertTrue(marker.exists())
        # The next pass with budget resumes and completes the deletion.
        removed = cg.cleanup_old_sessions(
            self.data_dir, deadline=time.monotonic() + 30.0)
        self.assertEqual(removed, 1)
        self.assertFalse(session_dir.exists())

    def test_active_and_current_sessions_are_never_deleted(self) -> None:
        self._make_session("active-recent", ended_days_ago=1)
        cg.dispatch(self.payload(
            "UserPromptSubmit", "current-keep", prompt="live", turn_id="t1"))
        removed = cg.cleanup_old_sessions(
            self.data_dir,
            current=self.session_dir("current-keep"),
            deadline=time.monotonic() + 5.0,
        )
        self.assertEqual(removed, 0)
        self.assertTrue(
            (self.data_dir / "sessions-v2" / "active-recent").is_dir())
        self.assertTrue(self.session_dir("current-keep").is_dir())

    def test_legacy_sessions_are_never_touched(self) -> None:
        legacy = self.data_dir / "sessions" / "legacy-old"
        legacy.mkdir(parents=True)
        (legacy / "state.json").write_text("{}", encoding="utf-8")
        cg.cleanup_old_sessions(self.data_dir, deadline=time.monotonic() + 5.0)
        self.assertTrue((legacy / "state.json").exists())


class F10PromptReplayHandling(IsolatedEnvironment):
    def test_same_event_replay_collapses_to_one_root(self) -> None:
        event = self.payload(
            "UserPromptSubmit", "f10-replay",
            prompt="继续修复 demo.py 并运行测试", turn_id="turn-1")
        first = cg.dispatch(dict(event))
        first_state = self.load_state("f10-replay")
        second = cg.dispatch(dict(event))
        state = self.load_state("f10-replay")
        self.assertEqual(len(state["prompts"]), 1)
        self.assertEqual(len(state["requirements"]), len(first_state["requirements"]))
        replays = state.get("prompt_replays", [])
        self.assertEqual(len(replays), 1)
        self.assertEqual(replays[0]["replay_count"], 1)
        self.assertNotIn("prompt_sha256_text", json.dumps(replays))
        # The re-delivered copy returned no second batch of context.
        self.assertEqual(second, {})
        self.assertNotEqual(first, second)

    def test_replayed_root_keeps_post_tool_attribution(self) -> None:
        event = self.payload(
            "UserPromptSubmit", "f10-attr",
            prompt="fix demo.py", turn_id="turn-1")
        cg.dispatch(dict(event))
        cg.dispatch(dict(event))
        cg.dispatch(self.payload(
            "PostToolUse", "f10-attr", tool_name="Bash",
            tool_input={"command": "pytest -q tests/test_demo.py"},
            tool_response={"output": "1 passed", "exit_code": 0},
            turn_id="turn-1"))
        state = self.load_state("f10-attr")
        self.assertEqual(len(state["prompts"]), 1)
        attribution = cg.core_host_origin_prompt(state, {
            "turn_id": "turn-1",
            "work_state": state.get("work_state", {}),
            "requirements": state.get("requirements", []),
            "prompts": state.get("prompts", []),
        })
        self.assertEqual(attribution, "P0001")

    def test_same_turn_different_text_stays_independent(self) -> None:
        cg.dispatch(self.payload(
            "UserPromptSubmit", "f10-turn",
            prompt="pause the current work", turn_id="turn-1"))
        cg.dispatch(self.payload(
            "UserPromptSubmit", "f10-turn",
            prompt="also check the logs", turn_id="turn-1"))
        state = self.load_state("f10-turn")
        self.assertEqual(len(state["prompts"]), 2)

    def test_same_text_different_turn_stays_independent(self) -> None:
        for turn in ("turn-1", "turn-2"):
            cg.dispatch(self.payload(
                "UserPromptSubmit", "f10-cross",
                prompt="pause the current work", turn_id=turn))
        state = self.load_state("f10-cross")
        self.assertEqual(len(state["prompts"]), 2)
        waits = [w for w in state.get("wait_conditions", [])]
        self.assertEqual(len(waits), 2)

    def test_missing_turn_id_keeps_legacy_unduplicated_key_behavior(self) -> None:
        payload = self.payload(
            "UserPromptSubmit", "f10-legacy", prompt="identical text")
        payload.pop("turn_id", None)
        cg.dispatch(dict(payload))
        cg.dispatch(dict(payload))
        state = self.load_state("f10-legacy")
        self.assertEqual(len(state["prompts"]), 2)


class D01DocumentationContract(IsolatedEnvironment):
    def test_product_version_is_the_unreleased_candidate(self) -> None:
        self.assertEqual(cg.PRODUCT_VERSION, "0.16.0")
        self.assertEqual(cg.SCHEMA_VERSION, 13)
        self.assertEqual(cg.STOP_PROTOCOL_VERSION, "5.0.0")

    def test_security_md_states_the_current_support_line(self) -> None:
        security = (Path(__file__).resolve().parents[1] / "SECURITY.md").read_text(
            encoding="utf-8")
        self.assertNotIn("0.7.x", security)
        self.assertNotIn("1.1.0", security)


if __name__ == "__main__":
    unittest.main()
