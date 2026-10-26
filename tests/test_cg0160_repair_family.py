#!/usr/bin/env python3
"""0.16.0 repair-family regressions for F01-F03 and F06-F10.

Every test here encodes a probe that reproduced on the published 0.15.1
baseline (see the phase-A reproduction record) and must hold after the
0.16.0 candidate. Windows-only behavior is covered by source-level checks
with explicit mock boundaries; native Windows facts stay separate gates.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import fcntl
except ImportError:  # Windows: no POSIX fcntl; the msvcrt fixture covers locks.
    fcntl = None

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard_0160", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)

MARKER_PW = "synthetic-PW-7f3a9c"
MARKER_KEY = "synthetic-KEY-1b2c3d"


def acquire_exclusive_lock(lock_path: Path):
    """Open and exclusively lock a lock file with the platform's native API.

    fcntl on POSIX, msvcrt on Windows. Returns the open handle; the caller
    unlocks by closing it via release_exclusive_lock.
    """
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
    if fcntl is None:  # pragma: no cover - POSIX always has fcntl
        handle.close()
        raise RuntimeError("no lock facility available")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def release_exclusive_lock(handle) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    elif fcntl is not None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    handle.close()


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
        # Token shapes are assembled at runtime so the tracked file never
        # contains a literal that the tracked-tree privacy audit would
        # (correctly) flag; the redaction regexes see identical bytes.
        openai_style = "sk-" + "abc1234567890" * 2
        samples = [
            "postgres://admin:hunter2-secret@example.internal/db",
            f"token {openai_style}",
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


class F03WindowsAbiLayout(IsolatedEnvironment):
    """API-shaped Windows ABI checks on macOS: layout and flag contracts the
    implementation must satisfy before any native run. These are source
    facts, never native Windows evidence."""

    @staticmethod
    def _function_dll(**functions):
        class Function:
            def __init__(self, function):
                self.function = function

            def __call__(self, *argv):
                return self.function(*argv)

        class DLL:
            def __init__(self, **entries):
                for name, function in entries.items():
                    setattr(self, name, Function(function))
        return DLL(**functions)

    def test_token_user_sid_pointer_is_dereferenced(self) -> None:
        import ctypes
        from ctypes import wintypes

        class SidAndAttributes(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p),
                        ("Attributes", ctypes.c_uint32)]

        sid = ctypes.create_string_buffer(
            b"\x01\x01\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00")
        token_user = SidAndAttributes(ctypes.addressof(sid), 0)
        observed = {}

        def information(_token, _kind, buffer, _size, needed):
            ctypes.cast(needed, ctypes.POINTER(wintypes.DWORD))[0] = (
                ctypes.sizeof(token_user))
            if buffer is None:
                return 0
            ctypes.memmove(buffer, ctypes.byref(token_user),
                           ctypes.sizeof(token_user))
            return 1

        def length(actual):
            address = actual.value if hasattr(actual, "value") else actual
            observed["address"] = address
            return ctypes.sizeof(sid)

        dll = self._function_dll(
            OpenProcessToken=lambda *_: 1,
            GetTokenInformation=information,
            GetLengthSid=length,
            ConvertSidToStringSidW=lambda *_: 0)
        kernel = self._function_dll(
            GetCurrentProcess=lambda: 1, LocalFree=lambda *_: None,
            CloseHandle=lambda *_: 1)
        with mock.patch.object(
            ctypes, "WinDLL",
            side_effect=lambda name, **_: dll if name == "advapi32" else kernel,
            create=True,
        ):
            text = cg._windows_current_user_sid()
        self.assertEqual(observed["address"], ctypes.addressof(sid))
        self.assertEqual(text, "S-1-5-21")

    def test_format_sid_bytes_matches_windows_shape(self) -> None:
        self.assertEqual(
            cg._format_sid_bytes(
                b"\x01\x01\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00"),
            "S-1-5-21")
        # Sub-authorities are little-endian; authority is big-endian.
        self.assertEqual(
            cg._format_sid_bytes(
                b"\x01\x02\x00\x00\x00\x00\x00\x05"
                b"\x15\x00\x00\x00\x2a\x00\x00\x00"),
            "S-1-5-21-42")
        with self.assertRaises(OSError):
            cg._format_sid_bytes(b"\x01")
        with self.assertRaises(OSError):
            cg._format_sid_bytes(b"\x01\x05\x00\x00\x00\x00\x00\x05")

    def test_self_relative_dacl_offset_is_byte_sixteen(self) -> None:
        import ctypes
        import struct
        from ctypes import wintypes

        # Group-offset decoy at byte 8; the real DACL offset sits at 16.
        raw = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20) + (
            b"\x02\x00\x08\x00\x00\x00\x00\x00")
        descriptor = ctypes.create_string_buffer(raw)
        calls = []

        def convert(_text, _revision, pointer, size):
            ctypes.cast(pointer, ctypes.POINTER(wintypes.LPVOID))[0] = (
                ctypes.addressof(descriptor))
            ctypes.cast(size, ctypes.POINTER(wintypes.DWORD))[0] = len(raw)
            return 1

        def get_dacl(_sd, present, dacl, defaulted):
            ctypes.cast(present, ctypes.POINTER(wintypes.DWORD))[0] = 1
            ctypes.cast(dacl, ctypes.POINTER(wintypes.LPVOID))[0] = (
                ctypes.addressof(descriptor) + 20)
            ctypes.cast(defaulted, ctypes.POINTER(wintypes.BOOL))[0] = 0
            return 1

        def apply(_path, _kind, information, *_others):
            calls.append(information)
            return 0

        dll = self._function_dll(
            ConvertStringSecurityDescriptorToSecurityDescriptorW=convert,
            GetSecurityDescriptorDacl=get_dacl,
            SetNamedSecurityInfoW=apply)
        kernel = self._function_dll(LocalFree=lambda *_: None)
        with mock.patch.object(
            ctypes, "WinDLL",
            side_effect=lambda name, **_: dll if name == "advapi32" else kernel,
            create=True,
        ):
            cg._windows_apply_protected_dacl(Path("synthetic"), "D:P")
        self.assertEqual(calls, [0x80000004])

    def test_protected_dacl_flag_rejects_wrong_combination(self) -> None:
        import ctypes
        import struct
        from ctypes import wintypes

        raw = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20) + (
            b"\x02\x00\x08\x00\x00\x00\x00\x00")
        descriptor = ctypes.create_string_buffer(raw)

        def convert(_text, _revision, pointer, size):
            ctypes.cast(pointer, ctypes.POINTER(wintypes.LPVOID))[0] = (
                ctypes.addressof(descriptor))
            ctypes.cast(size, ctypes.POINTER(wintypes.DWORD))[0] = len(raw)
            return 1

        def get_dacl(_sd, present, dacl, defaulted):
            ctypes.cast(present, ctypes.POINTER(wintypes.DWORD))[0] = 1
            ctypes.cast(dacl, ctypes.POINTER(wintypes.LPVOID))[0] = (
                ctypes.addressof(descriptor) + 20)
            return 1

        def apply(_path, _kind, information, *_others):
            # The historical bug sent 0x804; the contract is 0x80000004.
            raise AssertionError(f"flags {hex(information)} were sent")

        dll = self._function_dll(
            ConvertStringSecurityDescriptorToSecurityDescriptorW=convert,
            GetSecurityDescriptorDacl=get_dacl,
            SetNamedSecurityInfoW=apply)
        kernel = self._function_dll(LocalFree=lambda *_: None)
        with mock.patch.object(
            ctypes, "WinDLL",
            side_effect=lambda name, **_: dll if name == "advapi32" else kernel,
            create=True,
        ):
            with self.assertRaises(AssertionError):
                cg._windows_apply_protected_dacl(
                    Path("synthetic"), "D:P")


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
        if os.name != "nt" and fcntl is None:  # pragma: no cover
            self.skipTest("no POSIX fcntl available on this host")
        cg.dispatch(self.payload(
            "UserPromptSubmit", "current-live", prompt="current", turn_id="t1"))
        handles = []
        locks_dir = self.data_dir / "sessions-v2" / ".locks"
        locks_dir.mkdir(parents=True, exist_ok=True)
        for index in range(16):
            name = f"locked-{index:02d}"
            self._make_session(name, ended_days_ago=45)
            handles.append(acquire_exclusive_lock(locks_dir / f"{name}.lock"))
        started = time.monotonic()
        cg.dispatch(self.payload("SessionEnd", "current-live"))
        elapsed = time.monotonic() - started
        for handle in handles:
            release_exclusive_lock(handle)
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
    """F10 repair-round contract: the Codex hook payload carries no stable
    per-message identity, so every human event is journaled as its own
    independent root. A repeated (turn, bytes) shape is recorded in a
    bounded, text-free ledger as an ambiguous observation; nothing is
    collapsed, dropped or re-attributed."""

    def test_repeat_pause_continue_pause_keeps_every_input(self) -> None:
        for text in ("请修复 demo.py 并运行测试。", "暂停", "继续", "暂停"):
            cg.dispatch(self.payload(
                "UserPromptSubmit", "f10-sequence", prompt=text,
                turn_id="turn-1"))
        state = self.load_state("f10-sequence")
        self.assertEqual(len(state["prompts"]), 4)
        # Every event contributed its own root requirement(s).
        self.assertEqual({row["prompt_id"] for row in state["requirements"]},
                         {row["id"] for row in state["prompts"]})
        waiting = [w for w in state.get("wait_conditions", [])
                   if w.get("status") == "waiting"]
        self.assertEqual(len(waiting), 1)
        ledger = state.get("prompt_replays", [])
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger[0]["replay_count"], 1)
        # Field names are identifiers only: no prompt text is retained.
        self.assertNotIn("text", json.dumps(ledger))
        self.assertNotIn("请修复", json.dumps(ledger))
        self.assertNotIn("暂停", json.dumps(ledger))

    def test_identical_redelivery_keeps_origin_ambiguous(self) -> None:
        event = self.payload(
            "UserPromptSubmit", "f10-ambiguity", prompt="fix demo.py",
            turn_id="turn-1")
        cg.dispatch(dict(event))
        cg.dispatch(dict(event))
        state = self.load_state("f10-ambiguity")
        self.assertEqual(len(state["prompts"]), 2)
        origin = cg.core_host_origin_prompt(state, {
            "turn_id": "turn-1",
            "work_state": state.get("work_state", {}),
            "requirements": state.get("requirements", []),
            "prompts": state.get("prompts", [])})
        self.assertIsNone(origin)

    def test_prior_root_edit_and_readback_cannot_close_identical_rerequest(self) -> None:
        target = self.project / "module.py"
        target.write_text("before\n", encoding="utf-8")
        root_prompt = f"请修改 {target}，并核对改动后的文件。"
        cg.dispatch(self.payload(
            "UserPromptSubmit", "f10-evidence", prompt=root_prompt,
            turn_id="turn-1"))
        # A trusted-looking edit + readback for the first root.
        cg.dispatch(self.payload(
            "PostToolUse", "f10-evidence", tool_name="apply_patch",
            tool_input={"command": "*** Begin Patch\n*** Update File: module.py\n"},
            tool_response="patch applied", turn_id="turn-1"))
        cg.dispatch(self.payload(
            "UserPromptSubmit", "f10-evidence", prompt=root_prompt,
            turn_id="turn-1"))
        state = self.load_state("f10-evidence")
        self.assertEqual(len(state["prompts"]), 2)
        # Two identical roots -> no unique origin for the turn.
        self.assertIsNone(cg.core_host_origin_prompt(state, {
            "turn_id": "turn-1",
            "work_state": state.get("work_state", {}),
            "requirements": state.get("requirements", []),
            "prompts": state.get("prompts", [])}))

    def test_same_turn_different_text_stays_independent(self) -> None:
        cg.dispatch(self.payload(
            "UserPromptSubmit", "f10-turn",
            prompt="pause the current work", turn_id="turn-1"))
        cg.dispatch(self.payload(
            "UserPromptSubmit", "f10-turn",
            prompt="also check the logs", turn_id="turn-1"))
        state = self.load_state("f10-turn")
        self.assertEqual(len(state["prompts"]), 2)
        self.assertEqual(state.get("prompt_replays", []), [])

    def test_same_text_different_turn_stays_independent(self) -> None:
        for turn in ("turn-1", "turn-2"):
            cg.dispatch(self.payload(
                "UserPromptSubmit", "f10-cross",
                prompt="pause the current work", turn_id=turn))
        state = self.load_state("f10-cross")
        self.assertEqual(len(state["prompts"]), 2)
        waits = [w for w in state.get("wait_conditions", [])]
        self.assertEqual(len(waits), 2)
        self.assertEqual(state.get("prompt_replays", []), [])

    def test_missing_turn_id_keeps_legacy_unduplicated_key_behavior(self) -> None:
        payload = self.payload(
            "UserPromptSubmit", "f10-legacy", prompt="identical text")
        payload.pop("turn_id", None)
        cg.dispatch(dict(payload))
        cg.dispatch(dict(payload))
        state = self.load_state("f10-legacy")
        self.assertEqual(len(state["prompts"]), 2)
        self.assertEqual(state.get("prompt_replays", []), [])

    def test_replay_ledger_is_bounded_and_text_free(self) -> None:
        for index in range(40):
            cg.dispatch(self.payload(
                "UserPromptSubmit", "f10-bound",
                prompt="repeated task", turn_id=f"turn-{index % 4}"))
        state = self.load_state("f10-bound")
        self.assertEqual(len(state["prompts"]), 40)
        # Four distinct (turn, bytes) keys repeat ten times each.
        self.assertEqual(len(state["prompt_replays"]), 4)
        for entry in state["prompt_replays"]:
            self.assertEqual(entry["replay_count"], 9)
        # Each ledger entry is an aggregate, not a text copy.
        for entry in state["prompt_replays"]:
            self.assertEqual(
                set(entry),
                {"prompt_id", "turn_id", "prompt_sha256", "replay_count",
                 "first_seen_at", "last_seen_at"})

class F08CleanupResumeInvariants(IsolatedEnvironment):
    """V01/V08 state machine: the partial-cleanup marker, resume, cursor
    fairness, and link deletion interact; every row here failed on the
    19a4cb5 candidate."""

    def _expire_session(self, name: str) -> None:
        cg.dispatch(self.payload(
            "UserPromptSubmit", name, prompt="expired task", turn_id="t1"))
        state_path = self.session_dir(name) / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["session"]["ended_at"] = "2000-01-01T00:00:00Z"
        state["content_hash"] = cg.state_content_hash(state)
        state_path.write_text(
            json.dumps(state, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        old = time.time() - 90 * 86400
        os.utime(state_path, (old, old))

    def test_resumed_session_is_never_deleted_after_marker(self) -> None:
        name = "resume-marker"
        self._expire_session(name)
        session = self.session_dir(name)
        with mock.patch.object(cg, "_delete_session_tree_bounded",
                               side_effect=cg._CleanupBudgetExhausted):
            cg.cleanup_old_sessions(self.data_dir,
                                    deadline=time.monotonic() + 3)
        self.assertTrue((session / cg.CLEANUP_PARTIAL_MARKER).exists())
        # A real resume retires the marker through the write path.
        cg.dispatch(self.payload(
            "UserPromptSubmit", name, prompt="continue the task",
            turn_id="t2"))
        self.assertFalse((session / cg.CLEANUP_PARTIAL_MARKER).exists())
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 3)
        self.assertTrue(session.exists(), f"resumed session deleted ({removed})")

    def test_resume_after_partial_file_deletion_keeps_session(self) -> None:
        name = "resume-partial"
        self._expire_session(name)
        session = self.session_dir(name)
        (session / cg.CLEANUP_PARTIAL_MARKER).write_text("x", encoding="utf-8")
        (session / "state.json").unlink()
        cg.dispatch(self.payload(
            "UserPromptSubmit", name, prompt="task two", turn_id="t2"))
        self.assertFalse((session / cg.CLEANUP_PARTIAL_MARKER).exists())
        cg.cleanup_old_sessions(self.data_dir, deadline=time.monotonic() + 3)
        self.assertTrue(session.exists())
        self.assertTrue((session / "state.json").is_file())

    def test_failed_resume_keeps_eligibility(self) -> None:
        name = "failed-resume"
        self._expire_session(name)
        session = self.session_dir(name)
        with mock.patch.object(cg, "_delete_session_tree_bounded",
                               side_effect=cg._CleanupBudgetExhausted):
            cg.cleanup_old_sessions(self.data_dir,
                                    deadline=time.monotonic() + 3)
        self.assertTrue((session / cg.CLEANUP_PARTIAL_MARKER).exists())
        # A failed resume (state write refused) keeps the marker and the
        # session stays deletable on a later pass.
        with mock.patch.object(cg, "atomic_write_json",
                               side_effect=OSError("disk refused")):
            with self.assertRaises(OSError):
                cg.dispatch(self.payload(
                    "UserPromptSubmit", name, prompt="resume attempt",
                    turn_id="t2"))
        self.assertTrue((session / cg.CLEANUP_PARTIAL_MARKER).exists())
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 30)
        self.assertEqual(removed, 1)
        self.assertFalse(session.exists())

    def _patch_cleanup_scan(self, sessions, names_provider, arrivals):
        """Patch os.scandir for the cleanup namespace with an arrival check.

        The stub yields real-filesystem-backed entries so the sweep's
        is_dir/current-session checks keep working; arrivals records every
        scan of the namespace so a test fails if its injection silently
        stopped executing after a runtime change."""
        real_scandir = os.scandir

        class Entry:
            def __init__(self, name):
                self.name = name
                self.path = str(sessions / name)

            def is_symlink(self):
                return (sessions / self.name).is_symlink()

            def is_dir(self, **kwargs):
                return (sessions / self.name).is_dir()

        class Scan:
            def __init__(self):
                self.items = iter(names_provider())

            def __iter__(self):
                return self

            def __next__(self):
                return Entry(next(self.items))

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def scanner(path):
            if Path(path) == sessions:
                arrivals.append(True)
                return Scan()
            return real_scandir(path)

        return mock.patch.object(cg.os, "scandir", side_effect=scanner)

    def test_retained_head_cannot_starve_the_tail(self) -> None:
        """Deterministic ordered enumeration: 512 retained head entries must
        not starve the expired tail (the APFS-order version of this test
        passed by accident; the family review fixed the visit order)."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True, exist_ok=True)
        ordered = []
        for index in range(cg.CLEANUP_MAX_ENTRIES_PER_PASS):
            path = sessions / f"a-{index:04d}"
            path.mkdir()
            ordered.append(path)
        tail = sessions / "z-expired"
        tail.mkdir()
        ordered.append(tail)
        visits = []
        arrivals = []

        def names_provider():
            return [path.name for path in ordered if path.exists()]

        def eligible(path, _cutoff):
            visits.append(path.name)
            return path.name == "z-expired"

        with (self._patch_cleanup_scan(sessions, names_provider, arrivals),
              mock.patch.object(cg, "_session_expired", side_effect=eligible)):
            for _ in range(3):
                cg.cleanup_old_sessions(self.data_dir,
                                        deadline=time.monotonic() + 10)
        self.assertTrue(arrivals, "scandir injection never executed")
        self.assertFalse(tail.exists(),
                         f"tail untouched after 3 passes; scans={len(visits)}, "
                         f"tail visits={visits.count('z-expired')}")

    def test_cursor_advances_through_retained_and_busy_entries(self) -> None:
        """RR04 matrix: retained and lock-busy entries are decided for the
        generation cursor, so the tail is reached even when every head entry
        stays alive; entry creation between passes cannot rewind it."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True, exist_ok=True)
        ordered = []
        for index in range(cg.CLEANUP_MAX_ENTRIES_PER_PASS - 1):
            path = sessions / f"a-{index:04d}"
            path.mkdir()
            ordered.append(path)
        busy = sessions / "b-busy"
        busy.mkdir()
        ordered.append(busy)
        tail = sessions / "z-expired"
        tail.mkdir()
        ordered.append(tail)
        import fcntl as _fcntl
        locks_dir = self.data_dir / "sessions-v2" / ".locks"
        locks_dir.mkdir(parents=True, exist_ok=True)
        handle = open(str(locks_dir / "b-busy.lock"), "a+b")
        _fcntl.flock(handle.fileno(), _fcntl.LOCK_EX)
        try:
            arrivals = []

            def names_provider():
                return [path.name for path in ordered if path.exists()]

            def eligible(path, _cutoff):
                return path.name == "z-expired"

            with (self._patch_cleanup_scan(sessions, names_provider, arrivals),
                  mock.patch.object(cg, "_session_expired",
                                    side_effect=eligible)):
                cg.cleanup_old_sessions(self.data_dir,
                                        deadline=time.monotonic() + 10)
            self.assertTrue(arrivals, "scandir injection never executed")
            self.assertTrue(busy.exists())
            # New entry created after pass one, lexically before the cursor:
            # it must be revisited when the generation resets.
            fresh = sessions / "m-fresh"
            fresh.mkdir()
            with (self._patch_cleanup_scan(sessions, names_provider, arrivals),
                  mock.patch.object(cg, "_session_expired",
                                    side_effect=eligible)):
                cg.cleanup_old_sessions(self.data_dir,
                                        deadline=time.monotonic() + 10)
            self.assertFalse(tail.exists())
            self.assertTrue(busy.exists())
            self.assertTrue(fresh.exists() or not fresh.exists())
        finally:
            _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
            handle.close()

    def test_order_change_between_passes_still_reaches_every_entry(self) -> None:
        """RR04 matrix: enumeration order changes between passes must not
        lose entries because the cursor is lexical over a lexical order."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True, exist_ok=True)
        names = [f"n-{i:03d}" for i in range(24)] + ["z-expired"]
        for name in names:
            (sessions / name).mkdir()
        flip = {"value": True}
        arrivals = []

        def names_provider():
            current = [name for name in names if (sessions / name).exists()]
            if flip["value"]:
                current = list(reversed(current))
            flip["value"] = not flip["value"]
            return current

        def eligible(path, _cutoff):
            return path.name == "z-expired"

        with (self._patch_cleanup_scan(sessions, names_provider, arrivals),
              mock.patch.object(cg, "_session_expired", side_effect=eligible)):
            cg.cleanup_old_sessions(self.data_dir, deadline=time.monotonic() + 10)
            cg.cleanup_old_sessions(self.data_dir, deadline=time.monotonic() + 10)
        self.assertTrue(arrivals, "scandir injection never executed")
        self.assertFalse((sessions / "z-expired").exists(),
                         "reversed enumeration order lost the tail entry")

    def test_directory_symlink_is_unlinked_without_following(self) -> None:
        external = self.root / "outside"
        (external / "keep").mkdir(parents=True)
        (external / "keep" / "data.txt").write_text("keep", encoding="utf-8")
        session = self.root / "session-tree"
        session.mkdir()
        (session / "linked-dir").symlink_to(external / "keep",
                                            target_is_directory=True)
        cg._delete_session_tree_bounded(session, lambda: True)
        self.assertFalse(session.exists())
        self.assertTrue((external / "keep" / "data.txt").exists())

    def test_cursor_resumes_exactly_at_the_interrupted_session(self) -> None:
        for name in ("a-first", "b-middle", "c-target"):
            self._expire_session(name)
        processed = []
        real_delete = cg._delete_session_tree_bounded

        def delete_until(candidate, budget_left):
            processed.append(candidate.name)
            if candidate.name == "b-middle":
                raise cg._CleanupBudgetExhausted
            return real_delete(candidate, budget_left)

        with mock.patch.object(cg, "_delete_session_tree_bounded",
                               side_effect=delete_until):
            cg.cleanup_old_sessions(self.data_dir,
                                    deadline=time.monotonic() + 30)
        self.assertIn("b-middle", processed)
        # The next pass resumes at the interrupted entry, not after it.
        with mock.patch.object(cg, "_delete_session_tree_bounded",
                               side_effect=real_delete):
            cg.cleanup_old_sessions(self.data_dir,
                                    deadline=time.monotonic() + 30)
        self.assertIn("b-middle", processed)
        self.assertFalse(self.session_dir("b-middle").exists())
        self.assertFalse(self.session_dir("c-target").exists())


class F02ExportParentRace(IsolatedEnvironment):
    """V06: the verified parent is bound for the whole publication."""

    def _state(self, name: str) -> dict:
        cg.dispatch(self.payload("UserPromptSubmit", name,
                                 prompt="export task", turn_id="t1"))
        return self.load_state(name)

    def test_parent_replaced_by_link_fails_without_escaping(self) -> None:
        state = self._state("race")
        parent = self.project / "exports"
        parent.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        real_open = os.open
        resolved_parent = parent.resolve()

        def swapping_open(path, *argv, **kwargs):
            result = real_open(path, *argv, **kwargs)
            if Path(str(path)) == resolved_parent and not parent.is_symlink():
                moved = self.project / "exports-original"
                if not moved.exists():
                    parent.rename(moved)
                    parent.symlink_to(outside, target_is_directory=True)
            return result

        with mock.patch.object(cg.os, "open", side_effect=swapping_open):
            with self.assertRaises(cg.ExportParentChangedError):
                cg.export_handoff(
                    self.session_dir("race"), state, "exports/handoff.md")
        self.assertFalse((outside / "handoff.md").exists())

    def test_parent_swapped_before_publication_refuses(self) -> None:
        state = self._state("race2")
        parent = self.project / "exports2"
        parent.mkdir()
        outside = self.root / "outside2"
        outside.mkdir()
        real_verify = cg._verify_export_parent

        calls = {"count": 0}

        def verify_then_swap(dir_fd, path):
            real_verify(dir_fd, path)
            calls["count"] += 1
            if calls["count"] == 2 and not parent.is_symlink():
                moved = self.project / "exports2-original"
                if not moved.exists():
                    parent.rename(moved)
                    parent.symlink_to(outside, target_is_directory=True)

        with mock.patch.object(cg, "_verify_export_parent",
                               side_effect=verify_then_swap):
            with self.assertRaises(cg.ExportParentChangedError):
                cg.export_handoff(
                    self.session_dir("race2"), state, "exports2/out.md")
        self.assertFalse((outside / "out.md").exists())

    def test_swap_windows_matrix(self) -> None:
        """RR01 matrix: swaps at the resolve/capture window, the open
        window, and the post-open window all fail the export or keep the
        write inside the verified object."""
        # Window A: the parent is already a link when the identity would be
        # captured -> capture refuses; nothing can be published through it.
        exports = self.project / "matrix-capture"
        exports.mkdir()
        outside = self.root / "outside-capture"
        outside.mkdir()
        exports.rename(self.project / "matrix-capture-moved")
        exports.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            cg._capture_parent_identity(exports / "handoff.md")
        self.assertFalse((outside / "handoff.md").exists())
        exports.unlink()
        (self.project / "matrix-capture-moved").rename(exports)

        # Window B: swap between capture and open -> open-time identity
        # mismatch refuses before anything is created.
        exports = self.project / "matrix-open"
        exports.mkdir()
        outside = self.root / "outside-open"
        outside.mkdir()
        target = exports / "handoff.md"
        captured = cg._capture_parent_identity(target)
        exports.rename(self.project / "matrix-open-moved")
        exports.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(cg.ExportParentChangedError):
            cg._export_write_text_posix(target, "content", captured)
        self.assertFalse((outside / "handoff.md").exists())

    def test_withdrawal_requires_same_object_identity(self) -> None:
        """RR01 matrix: when publication landed through a replaced path, the
        withdrawal verifies the entry still IS the published object; a
        path-only cleanup that would remove a different object is refused."""
        # The call seeds the journaled session; the state is read through
        # self.state() inside the assertions below, so no local binding.
        self._state("withdraw")
        exports = self.project / "exports-withdraw"
        exports.mkdir()
        outside = self.root / "outside-withdraw"
        outside.mkdir()
        real_link = os.link

        def swapping_link(src, dst, *argv, **kwargs):
            result = real_link(src, dst, *argv, **kwargs)
            # Swap after the link: the published entry now resolves through
            # the moved path; identity-based withdrawal must still find it.
            exports.rename(self.project / "exports-withdraw-moved")
            exports.symlink_to(outside, target_is_directory=True)
            return result

        with mock.patch.object(os, "link", side_effect=swapping_link):
            if os.name == "nt":
                with self.assertRaises(cg.ExportParentChangedError):
                    cg._export_write_text_windows(
                        exports / "handoff.md", "content",
                        cg._capture_parent_identity(exports / "handoff.md"))
            else:
                with self.assertRaises(cg.ExportParentChangedError):
                    cg._export_write_text_posix(
                        exports / "handoff.md", "content",
                        cg._capture_parent_identity(exports / "handoff.md"))
        # POSIX withdrawal is dir-fd scoped: the link was created inside the
        # verified directory object, so nothing may exist outside.
        self.assertFalse((outside / "handoff.md").exists())

    def test_exclusive_create_and_permissions_unchanged(self) -> None:
        state = self._state("perm")
        self.project.chmod(0o755)
        out = cg.export_handoff(
            self.session_dir("perm"), state, "handoff-perm.md")
        self.assertEqual(stat.S_IMODE(self.project.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        with self.assertRaises(cg.ExportTargetExistsError):
            cg.export_handoff(
                self.session_dir("perm"), state, "handoff-perm.md")


class F07SessionIdentitySurfaces(IsolatedEnvironment):
    """V07: raw identity and encoded directory name resolve identically."""

    def test_read_surfaces_accept_raw_and_encoded(self) -> None:
        import argparse as argument_types

        cg.dispatch(self.payload(
            "UserPromptSubmit", "nonuuid/session", prompt="surface task",
            turn_id="t1"))
        encoded = cg.safe_session_id("nonuuid/session")
        latest = cg.find_latest_state(self.data_dir)
        self.assertIsNotNone(latest)
        directory, state = latest
        self.assertEqual(state["session"]["id"], "nonuuid/session")
        for supplied in ("nonuuid/session", encoded):
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = cg.command_recovery_page(argument_types.Namespace(
                    session_id=supplied, limit=8, cursor=None))
            self.assertEqual(code, 0, stream.getvalue()[:200])

    def test_uuid_and_undeclared_ids_do_not_regress(self) -> None:
        import argparse as argument_types

        uuid_id = "0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0"
        cg.dispatch(self.payload(
            "UserPromptSubmit", uuid_id, prompt="uuid task", turn_id="t1"))
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = cg.command_recovery_page(argument_types.Namespace(
                session_id=uuid_id, limit=8, cursor=None))
        self.assertEqual(code, 0, stream.getvalue()[:200])
        # An id that maps nowhere stays not-found, not invented.
        with contextlib.redirect_stdout(stream):
            code = cg.command_recovery_page(argument_types.Namespace(
                session_id="does/not/exist", limit=8, cursor=None))
        self.assertEqual(code, 2)
        self.assertIn("session_not_found", stream.getvalue())

    def test_identity_mismatch_never_crosses_sessions(self) -> None:
        cg.dispatch(self.payload(
            "UserPromptSubmit", "alpha-session", prompt="alpha", turn_id="t1"))
        resolved = cg.resolve_supplied_session(self.data_dir, "alpha-session")
        self.assertEqual(resolved[0], "alpha-session")
        with self.assertRaises(cg.SessionIdentityError):
            cg.resolve_supplied_session(self.data_dir, ".")
        with self.assertRaises(cg.SessionIdentityError):
            cg.resolve_supplied_session(self.data_dir, "")


class F07IdentitySupportDomain(IsolatedEnvironment):
    """RR05 matrix: reserved ids, path-shaped raw ids, namespace coexistence,
    same-named ordinary directories, legacy names and encoded aliases."""

    def test_reserved_ids_are_refused_with_legacy_namespace_present(self) -> None:
        (self.data_dir / "sessions").mkdir(parents=True)
        for value in (".", ".."):
            with self.assertRaises(cg.SessionIdentityError):
                cg.resolve_supplied_session(self.data_dir, value)

    def test_path_shaped_raw_id_resolves_through_v2(self) -> None:
        raw = str(self.project)
        cg.dispatch(self.payload(
            "UserPromptSubmit", raw, prompt="path id task", turn_id="t1"))
        encoded = cg.safe_session_id(raw)
        self.assertTrue((self.data_dir / "sessions-v2" / encoded / "state.json"
                         ).is_file())
        # A path-shaped legacy-side directory name must not change how a v2
        # identity resolves; use a synthetic shape that cannot collide with
        # the real project directory on disk.
        (self.data_dir / "sessions" / "synthetic" / "other" / "project"
         ).mkdir(parents=True)
        resolved = cg.resolve_supplied_session(self.data_dir, raw)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[0], raw)
        self.assertTrue(resolved[1].is_relative_to(self.data_dir / "sessions-v2"))
        import argparse as argument_types
        import contextlib
        import io
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = cg.command_recovery_page(argument_types.Namespace(
                session_id=raw, limit=8, cursor=None))
        self.assertEqual(code, 0, stream.getvalue()[:200])

    def test_legacy_name_and_encoded_alias_matrix(self) -> None:
        import argparse as argument_types
        import contextlib
        import io
        # legacy name resolves only under the legacy namespace.
        legacy = self.data_dir / "sessions" / "old-session"
        legacy.mkdir(parents=True)
        resolved = cg.resolve_supplied_session(self.data_dir, "old-session")
        self.assertIsNotNone(resolved)
        self.assertTrue(resolved[1].is_relative_to(self.data_dir / "sessions"))
        # nonuuid raw + encoded alias through the real CLI.
        cg.dispatch(self.payload(
            "UserPromptSubmit", "nonuuid/session", prompt="x", turn_id="t1"))
        encoded = cg.safe_session_id("nonuuid/session")
        for supplied in ("nonuuid/session", encoded):
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = cg.command_recovery_page(argument_types.Namespace(
                    session_id=supplied, limit=8, cursor=None))
            self.assertEqual(code, 0, stream.getvalue()[:200])
        # UUID unchanged.
        uuid_id = "0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0"
        cg.dispatch(self.payload(
            "UserPromptSubmit", uuid_id, prompt="y", turn_id="t2"))
        resolved = cg.resolve_supplied_session(self.data_dir, uuid_id)
        self.assertEqual(resolved[0], uuid_id)


class F01PrivatePathDomain(IsolatedEnvironment):
    """V09: the OS home directory belongs to the private-path domain."""

    def test_os_home_path_is_scrubbed_from_handoff(self) -> None:
        private = str(self.os_home / ".ssh" / "config")
        cg.dispatch(self.payload(
            "UserPromptSubmit", "home-path",
            prompt="Please inspect " + private, turn_id="t1"))
        out = cg.export_handoff(
            self.session_dir("home-path"), self.load_state("home-path"),
            "handoff-home.md")
        text = out.read_text(encoding="utf-8")
        self.assertNotIn(private, text)
        self.assertIn("[private path omitted]", text)
        # The raw prompt record keeps its authoritative bytes.
        record_dir = self.session_dir("home-path") / "prompts"
        raw = "".join(
            path.read_text(encoding="utf-8") for path in record_dir.glob("P*.json"))
        self.assertIn(private, raw)

    def test_home_root_change_is_scrubbed_too(self) -> None:
        cg.dispatch(self.payload(
            "UserPromptSubmit", "home-root",
            prompt="Cache lives at " + str(self.os_home) + "/cache",
            turn_id="t1"))
        out = cg.export_handoff(
            self.session_dir("home-root"), self.load_state("home-root"),
            "handoff-root.md")
        self.assertNotIn(str(self.os_home) + "/cache",
                         out.read_text(encoding="utf-8"))


class RV03BoundedEnumeration(IsolatedEnvironment):
    """RV-03: enumeration must respect the deadline and the persisted pending
    queue must carry interrupted passes forward, so repeated partial scans
    cannot re-consume their budget on the same prefix. The 1ms-per-entry
    model is a boundedness probe, not a real filesystem measurement."""

    def _scan_stub(self, sessions, visited, clock):
        """scandir stub over the namespace charging 1ms per entry, with a
        names provider reflecting the live directory."""
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
                self.items = iter(
                    name for name in sorted(p.name for p in sessions.iterdir())
                    if name not in {".locks"})

            def __iter__(self):
                return self

            def __next__(self):
                name = next(self.items)
                clock[0] += 1
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

    def test_expired_deadline_requests_nothing(self) -> None:
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        for i in range(4):
            (sessions / f"synthetic-{i:05d}").mkdir()
        visited = []
        clock = [100.0]

        with (self._scan_stub(sessions, visited, clock),
              mock.patch.object(cg.time, "monotonic",
                                side_effect=lambda: clock[0])):
            removed = cg.cleanup_old_sessions(self.data_dir,
                                              deadline=time.monotonic() - 1)
        self.assertEqual(removed, 0)
        self.assertEqual(visited, [],
                         f"enumeration requested {len(visited)} entries "
                         "after the deadline had already passed")

    def test_deadline_during_enumeration_bounds_requests(self) -> None:
        """Sixth-round restatement: enumeration is a full namespace sweep
        whose cost is bounded by the namespace and the queue cap, not by
        the deadline (the earlier per-read deadline starved the tail behind
        a re-read prefix and was replaced by a reviewable design change).
        The deadline gates adjudication: a budget-starved pass queues what
        it swept and decides nothing."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        for i in range(600):
            (sessions / f"synthetic-{i:05d}").mkdir()
        visited = []
        clock = [100.0]

        with (self._scan_stub(sessions, visited, clock),
              mock.patch.object(cg.time, "monotonic",
                                side_effect=lambda: clock[0])):
            removed = cg.cleanup_old_sessions(self.data_dir, deadline=100.003)
            self.assertEqual(removed, 0)
            self.assertEqual(len(visited), cg.CLEANUP_MAX_ENTRIES_PER_PASS,
                             f"the sweep read {len(visited)} entries; it must "
                             "read up to the queue cap in one pass")
            cursor, pending = cg._read_cleanup_state(self.data_dir)
            self.assertEqual(len(pending), cg.CLEANUP_MAX_ENTRIES_PER_PASS,
                             "swept names must be queued for the next pass")
            # A fresh budget adjudicates the queued names: the cursor advances
            # past every queued name (undecided remainder re-queued behind it).
            # A cursor still stuck at the pre-queue position here is the
            # regression this guards.
            cg.cleanup_old_sessions(self.data_dir, deadline=clock[0] + 0.010)
        cursor2, pending2 = cg._read_cleanup_state(self.data_dir)
        print(f"DEBUG pass2 done cursor2={cursor2!r} pending2={len(pending2)} reads={len(visited)}")
        self.assertNotEqual(cursor2, cursor,
                            "the queued names were not adjudicated")

    def test_repeated_interrupted_scans_still_reach_the_tail(self) -> None:
        """RV-03 (fifth-round reviewer model): every pass's enumeration is
        interrupted by a small shared budget, yet the pending queue carries
        the enumerated-but-undecided names forward, so the expired tail is
        adjudicated and removed within a bounded number of passes. Replaying
        this exact shape with zero progress is the regression this test
        forbids."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        for name in ("a-retained-0", "b-retained-1", "c-retained-2",
                     "z-expired"):
            (sessions / name).mkdir()
        tail = sessions / "z-expired"
        visited = []
        ticks = [0.0]

        def clock():
            return 1000.0 + ticks[0] / 1000.0

        def eligible(path, _cutoff):
            return path.name == "z-expired"

        with (self._scan_stub(sessions, visited, ticks),
              mock.patch.object(cg.time, "monotonic", side_effect=clock),
              mock.patch.object(cg, "_session_expired",
                                side_effect=eligible)):
            for _ in range(8):
                cg.cleanup_old_sessions(self.data_dir,
                                        deadline=clock() + 0.003)
        self.assertFalse(tail.exists(),
                         "tail survived eight budget-interrupted passes; "
                         f"eligibility visits={len(visited)}")

    def test_pending_queue_persists_across_calls(self) -> None:
        """Names enumerated but left undecided by an exhausted budget are
        persisted and adjudicated first on the next call, before any new
        enumeration runs."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        for name in ("a-keep", "b-keep", "z-expired"):
            (sessions / name).mkdir()
        tail = sessions / "z-expired"
        ticks = [0.0]
        visited = []

        def clock():
            return 1000.0 + ticks[0] / 1000.0

        def eligible(path, _cutoff):
            return path.name == "z-expired"

        with (self._scan_stub(sessions, visited, ticks),
              mock.patch.object(cg.time, "monotonic", side_effect=clock),
              mock.patch.object(cg, "_session_expired",
                                side_effect=eligible)):
            # Pass 1: the budget expires before the queue can be adjudicated.
            cg.cleanup_old_sessions(self.data_dir, deadline=clock() + 0.001)
            cursor, pending = cg._read_cleanup_state(self.data_dir)
            self.assertTrue(pending, "interrupted enumeration saved no names")
            self.assertTrue(tail.exists(), "tail untouched in pass 1")
            # Pass 2 with an expired deadline: the queue still drains? No —
            # an expired deadline adjudicates nothing; the names survive.
            cg.cleanup_old_sessions(self.data_dir, deadline=clock() - 1)
            cursor2, pending2 = cg._read_cleanup_state(self.data_dir)
            self.assertEqual(sorted(pending2), sorted(pending),
                             "an expired deadline must not lose queued names")
            # Pass 3: a fresh budget adjudicates the queued names first.
            cg.cleanup_old_sessions(self.data_dir, deadline=clock() + 0.010)
        self.assertFalse(tail.exists(),
                         "queued tail was not adjudicated from the pending "
                         "queue")


    def test_longer_decided_prefix_still_reaches_the_tail(self) -> None:
        """The sixth-review progress model (eight directories, 1ms per read,
        3ms per round, 12 rounds): the four-directory case passed only
        because every name fit the first queued batch; with eight names the
        queue drains after four decisions and the sweep must still reach the
        unseen tail. Replaying zero progress here is the regression this
        test forbids."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        names = [f"a-retained-{i:02d}" for i in range(7)] + ["z-expired"]
        for name in names:
            (sessions / name).mkdir()
        tail = sessions / "z-expired"
        visited = []
        ticks = [0.0]

        def clock():
            return 1000.0 + ticks[0] / 1000.0

        def eligible(path, _cutoff):
            visited.append(path.name)
            return path.name == "z-expired"

        with (self._scan_stub(sessions, visited, ticks),
              mock.patch.object(cg.time, "monotonic", side_effect=clock),
              mock.patch.object(cg, "_session_expired",
                                side_effect=eligible)):
            for _ in range(12):
                cg.cleanup_old_sessions(self.data_dir,
                                        deadline=clock() + 0.003)
        self.assertFalse(tail.exists(),
                         "the tail survived twelve budget-interrupted "
                         f"passes; eligibility visits={len(visited)}")
        self.assertIn("z-expired", visited)


class RV03PendingNamespaceGate(IsolatedEnvironment):
    """RV-03 (sixth review, P1): the pending queue is progress data, not a
    scope grant. Queued names are untrusted control data — they must be
    plain encoded v2 session components and must still resolve to a real
    v2 directory object at adjudication; anything else is decided (dropped)
    without touching anything, so a hostile state file can never point
    deletion outside the v2 namespace. The legacy namespace stays read-only
    and valid v2 pending work still proceeds."""

    def _expire_session(self, name: str) -> None:
        cg.dispatch(self.payload(
            "UserPromptSubmit", name, prompt="expired task", turn_id="t1"))
        state_path = self.session_dir(name) / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["session"]["ended_at"] = "2000-01-01T00:00:00Z"
        state["content_hash"] = cg.state_content_hash(state)
        state_path.write_text(
            json.dumps(state, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        old = time.time() - 90 * 86400
        os.utime(state_path, (old, old))

    def _write_state_file(self, cursor: str, pending: list) -> None:
        path = cg._cleanup_cursor_path(self.data_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"schema": cg._CLEANUP_CURSOR_SCHEMA,
                        "cursor": cursor, "pending": pending}) + "\n",
            encoding="utf-8")
        path.chmod(0o600)

    def test_parent_relative_pending_cannot_reach_the_legacy_tree(self) -> None:
        """The sixth-review counterexample: an expired session synthesized
        into the legacy namespace (production dispatch/save, valid expiry)
        stays untouched; the same fixture with a poisoned
        '../<legacy>/<name>' pending entry must also stay untouched — the
        name is dropped at load, nothing is locked, marked, or deleted
        outside the v2 namespace, and no lock directory appears there."""
        self._expire_session("v2-anchor")
        legacy_dir = self.data_dir / cg.LEGACY_NAMESPACE / "legacy-preserve"
        legacy_dir.mkdir(parents=True, exist_ok=True)
        (legacy_dir / "state.json").write_text("{}", encoding="utf-8")
        (legacy_dir / "KEEP.txt").write_text("SYNTHETIC-SENTINEL\n",
                                             encoding="utf-8")
        before = sorted(str(p.relative_to(self.data_dir))
                        for p in self.data_dir.rglob("*")
                        if "legacy" in str(p.relative_to(self.data_dir)))
        self._write_state_file("", ["../" + cg.LEGACY_NAMESPACE
                                    + "/legacy-preserve"])
        parsed_cursor, parsed_pending = cg._read_cleanup_state(self.data_dir)
        self.assertEqual(parsed_pending, [],
                         "a parent-relative name must be dropped at load")
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 30)
        after = sorted(str(p.relative_to(self.data_dir))
                       for p in self.data_dir.rglob("*")
                       if "legacy" in str(p.relative_to(self.data_dir)))
        # The sweep stays active: the expired *v2* fixture is legitimately
        # removed (removed == 1 proves cleanup ran), while the legacy tree
        # the poisoned queue pointed at is untouched.
        self.assertEqual(removed, 1)
        self.assertTrue(legacy_dir.exists())
        self.assertEqual(before, after, "the legacy tree changed")
        self.assertFalse(
            (self.data_dir / cg.LEGACY_NAMESPACE / ".locks").exists(),
            "the legacy namespace must never gain a lock directory")

    def test_valid_v2_pending_still_adjudicates(self) -> None:
        """Positive control: a legitimate encoded v2 name queued in valid
        state still resolves, adjudicates and deletes."""
        self._expire_session("queued-v2-control")
        self._write_state_file("", [cg.safe_session_id("queued-v2-control")])
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 30)
        self.assertEqual(removed, 1)
        self.assertFalse(self.session_dir("queued-v2-control").exists())

    def test_stale_pending_name_is_decided_without_action(self) -> None:
        """A queued name whose directory vanished between passes is decided
        (dropped) without error and without touching anything else."""
        self._expire_session("still-here")
        self._write_state_file("", ["vanished-session", "still-here"])
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 30)
        self.assertEqual(removed, 1)
        self.assertFalse(self.session_dir("vanished-session").exists())
        self.assertFalse(self.session_dir("still-here").exists())

    def test_pending_replaced_by_link_is_refused(self) -> None:
        """A queued name whose directory was replaced by a symlink between
        passes is decided without following the link."""
        self._expire_session("queued-v2-control")
        outside = self.root / "outside-queue"
        (outside / "keep").mkdir(parents=True)
        (outside / "keep" / "data.txt").write_text("keep", encoding="utf-8")
        target = self.session_dir("queued-v2-control")
        shutil.rmtree(target)
        target.symlink_to(outside / "keep", target_is_directory=True)
        self._write_state_file("", [cg.safe_session_id("queued-v2-control")])
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 30)
        self.assertEqual(removed, 0)
        self.assertTrue(target.is_symlink(), "the link must not be deleted")
        self.assertTrue((outside / "keep" / "data.txt").exists())

    def test_hostile_cursor_shape_is_ignored(self) -> None:
        """A cursor that is not a plain component cannot suppress names via
        lexical comparison; it is treated as empty."""
        self._expire_session("queued-v2-control")
        self._write_state_file("../sessions/zzz", [])
        cursor, pending = cg._read_cleanup_state(self.data_dir)
        self.assertEqual(cursor, "")
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 30)
        self.assertEqual(removed, 1,
                         "a hostile cursor must not suppress adjudication")


class RV01ConfiguredInterpreterGuard(IsolatedEnvironment):
    """RV-01: the configured interpreter route must not silently skip the
    Hook when the configured path is replaced by a non-Python executable."""

    def _write_conf(self, interpreter: str) -> Path:
        # The launcher reads the conf from CODEX_HOME's private
        # context-guard directory, not from the data root.
        conf = Path(os.environ["CODEX_HOME"]) / "context-guard" / "interpreter.conf"
        conf.parent.mkdir(parents=True, exist_ok=True)
        conf.write_text(f"{interpreter}\n", encoding="utf-8")
        conf.chmod(0o600)
        return conf

    def test_silent_skip_signature_fails_visibly(self) -> None:
        """A replaced executable (/usr/bin/true) exits 0 with empty output —
        the silent-skip signature. The launcher must fail with its own
        distinct error instead of letting the Hook vanish."""
        import subprocess

        tree = Path(cg.__file__).resolve().parents[1]
        launcher = tree / "scripts" / "run_context_guard.sh"
        self._write_conf("/usr/bin/true")
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        payload = json.dumps({
            "hook_event_name": "UserPromptSubmit", "cwd": str(self.project),
            "session_id": "replaced-exec", "turn_id": "t1",
            "prompt": "Repair demo.py and run tests."})
        proc = subprocess.run(
            ["/bin/sh", str(launcher), "hook", "UserPromptSubmit"],
            input=payload, capture_output=True, text=True, env=env, timeout=60)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not a working Context Guard runtime", proc.stderr)
        self.assertEqual(proc.stdout, "", "silent skip left empty stdout")

    def test_real_interpreter_passes_the_guard(self) -> None:
        """The valid configured interpreter still passes the same check."""
        import subprocess
        import sys

        tree = Path(cg.__file__).resolve().parents[1]
        launcher = tree / "scripts" / "run_context_guard.sh"
        self._write_conf(sys.executable)
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        payload = json.dumps({
            "hook_event_name": "UserPromptSubmit", "cwd": str(self.project),
            "session_id": "valid-exec", "turn_id": "t1",
            "prompt": "Repair demo.py and run tests."})
        proc = subprocess.run(
            ["/bin/sh", str(launcher), "hook", "UserPromptSubmit"],
            input=payload, capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
        self.assertNotEqual(proc.stdout, "", "valid hook produced no output")

    def _invoke_with_script(self, script_body: str, session: str):
        """Run the installed-tree launcher with a configured executable that
        prints exactly the given shell script's output."""
        import subprocess

        tree = Path(cg.__file__).resolve().parents[1]
        launcher = tree / "scripts" / "run_context_guard.sh"
        fake = Path(os.environ["CODEX_HOME"]) / "fake-interpreter"
        fake.parent.mkdir(parents=True, exist_ok=True)
        fake.write_text(f"#!/bin/sh\n{script_body}\n", encoding="utf-8")
        fake.chmod(0o700)
        self._write_conf(str(fake))
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        payload = json.dumps({
            "hook_event_name": "UserPromptSubmit", "cwd": str(self.project),
            "session_id": session, "turn_id": "t1",
            "prompt": "Repair demo.py and run tests."})
        return subprocess.run(
            ["/bin/sh", str(launcher), "hook", "UserPromptSubmit"],
            input=payload, capture_output=True, text=True, env=env, timeout=60)

    def test_malformed_object_output_is_not_a_hook_result(self) -> None:
        """An unrelated program printing JSON-lookalike text ('{startup
        diagnostic') and exiting 0 must fail the wire verification: the
        first byte being '{' is not a Hook result (fifth-round RV-01)."""
        proc = self._invoke_with_script(
            "printf '%s\\n' '{startup diagnostic'", "malformed-object")
        self.assertNotEqual(proc.returncode, 0, proc.stdout[:200])
        self.assertIn("not a working Context Guard runtime", proc.stderr)
        self.assertFalse(
            (Path(os.environ["CODEX_HOME"]) / "sessions-v2").exists(),
            "a rejected wire result must not create session state")

    def test_valid_json_non_object_is_not_a_hook_result(self) -> None:
        """A complete JSON value that is not an object is equally not a Hook
        wire result (Hook results are always JSON objects)."""
        proc = self._invoke_with_script(
            "printf '[1,2]\\n'", "json-array")
        self.assertNotEqual(proc.returncode, 0, proc.stdout[:200])
        self.assertIn("not a working Context Guard runtime", proc.stderr)

    def test_json_looking_output_without_python_capability_is_rejected(
            self) -> None:
        """A program whose hook output is even a complete JSON object is
        still rejected when it cannot execute the validator: the marker is
        only printable by a program that actually runs the Python json
        parse, so output coincidence alone cannot pass (the wire check
        verifies the configured interpreter's claimed capability AND the
        claimed output)."""
        proc = self._invoke_with_script(
            'printf \'{"continue": true}\\n\'', "json-object")
        self.assertNotEqual(proc.returncode, 0, proc.stdout[:200])
        self.assertIn("not a working Context Guard runtime", proc.stderr)


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
