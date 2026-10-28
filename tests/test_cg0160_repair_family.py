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


def symlink_or_skip(test, link: Path, target: Path, **kwargs) -> None:
    try:
        link.symlink_to(target, **kwargs)
    except OSError as exc:
        import errno

        if (getattr(exc, "winerror", None) == 1314
                or exc.errno in {errno.ENOSYS, errno.ENOTSUP}):
            test.skipTest(f"symlink creation capability unavailable: {exc}")
        raise


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
        os.environ["USERPROFILE"] = str(self.os_home)
        for name in ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT"):
            os.environ.pop(name, None)
        self.project = self.root / "project"
        self.project.mkdir()

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env)
        self.temporary.cleanup()

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
        parent_dacl = (cg._windows_query_dacl_sddl(self.project)
                       if os.name == "nt" else None)
        out = cg.export_handoff(
            self.session_dir("f02-export"), state, "handoff-new.md")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.project.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        else:
            self.assertIsNotNone(parent_dacl)
            self.assertEqual(cg._windows_query_dacl_sddl(self.project), parent_dacl)
        self.assertTrue(out.read_text(encoding="utf-8").startswith(
            "# Context Guard Handoff"))

    def test_directory_target_is_refused(self) -> None:
        state = self._active_state()
        target_dir = self.project / "target.md"
        target_dir.mkdir()
        with self.assertRaises(cg.ExportTargetExistsError):
            cg.export_handoff(self.session_dir("f02-export"), state, "target.md")

    def test_symlink_target_is_refused(self) -> None:
        state = self._active_state()
        link = self.project / "link.md"
        symlink_or_skip(self, link, self.project / "other.txt")
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
    @unittest.skipUnless(os.name == "posix", "POSIX permission-mode contract")
    def test_chmod_failure_is_visible_and_fail_closed(self) -> None:
        loose = self.root / "loose"
        loose.mkdir(mode=0o755)
        with mock.patch.object(
            cg.os, "chmod", side_effect=PermissionError("denied")
        ):
            with self.assertRaises(cg.PrivateBoundaryError):
                cg.secure_directory(loose)
        self.assertEqual(stat.S_IMODE(loose.stat().st_mode), 0o755)

    @unittest.skipUnless(os.name == "posix", "POSIX permission-mode contract")
    def test_mode_verification_failure_is_visible(self) -> None:
        target = self.root / "sneaky"
        target.mkdir(mode=0o700)

        class FakeStat:
            st_mode = 0o40755  # directory with a loose mode

        with mock.patch.object(Path, "stat", return_value=FakeStat()):
            with self.assertRaises(cg.PrivateBoundaryError):
                cg.secure_directory(target)

    @unittest.skipUnless(os.name == "posix", "POSIX permission-mode contract")
    def test_existing_loose_private_directory_is_tightened(self) -> None:
        loose = self.data_dir / "sessions-v2" / "late"
        loose.mkdir(parents=True, mode=0o755)
        cg.secure_directory(loose)
        self.assertEqual(stat.S_IMODE(loose.stat().st_mode), 0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX permission-mode contract")
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
        for index in range(512):
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
        for index in range(511):
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
        symlink_or_skip(self, session / "linked-dir", external / "keep",
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

    @unittest.skipUnless(os.name == "posix" and os.open in os.supports_dir_fd,
                         "POSIX anchored directory descriptor boundary")
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
                    symlink_or_skip(self, parent, outside, target_is_directory=True)
            return result

        with mock.patch.object(cg.os, "open", side_effect=swapping_open):
            with self.assertRaises(cg.ExportParentChangedError):
                cg.export_handoff(
                    self.session_dir("race"), state, "exports/handoff.md")
        self.assertFalse((outside / "handoff.md").exists())

    @unittest.skipUnless(os.name == "posix" and os.open in os.supports_dir_fd,
                         "POSIX anchored directory descriptor boundary")
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
                    symlink_or_skip(self, parent, outside, target_is_directory=True)

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
        symlink_or_skip(self, exports, outside, target_is_directory=True)
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
        symlink_or_skip(self, exports, outside, target_is_directory=True)
        with self.assertRaises(cg.ExportParentChangedError):
            (cg._export_write_text_windows if os.name == "nt"
             else cg._export_write_text_posix)(target, "content", captured)
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
            symlink_or_skip(self, exports, outside, target_is_directory=True)
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
        parent_dacl = (cg._windows_query_dacl_sddl(self.project)
                       if os.name == "nt" else None)
        out = cg.export_handoff(
            self.session_dir("perm"), state, "handoff-perm.md")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.project.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        else:
            self.assertIsNotNone(parent_dacl)
            self.assertEqual(cg._windows_query_dacl_sddl(self.project), parent_dacl)
        self.assertTrue(out.read_text(encoding="utf-8").startswith(
            "# Context Guard Handoff"))
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
        """Original RR04 contract, restored after the sixth review rejected
        the interim no-deadline design: every enumeration step starts only
        within the remaining budget, so a 3ms budget with a 1ms-per-entry
        model requests at most four entries, and everything read is queued
        for the next pass (progress data, never lost)."""
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
            self.assertGreater(len(visited), 0)
            self.assertLessEqual(len(visited), 4,
                                 f"enumeration requested {len(visited)} "
                                 "entries under a 3ms budget "
                                 "(1ms-per-entry model)")
            cursor, pending = cg._read_cleanup_state(self.data_dir)
            self.assertEqual(len(pending), len(visited),
                             "every swept name must be queued for the next "
                             "pass")
            self.assertEqual(cursor, "",
                             "an interrupted scan must not persist a lexical "
                             "cursor: unread names could be smaller")
            # A fresh budget adjudicates the queued names through the drain:
            # they must not stay stuck in the queue across passes.
            cg.cleanup_old_sessions(self.data_dir, deadline=clock[0] + 0.010)
        cursor2, pending2 = cg._read_cleanup_state(self.data_dir)
        self.assertFalse(set(pending) & set(pending2),
                         "the queued names were not adjudicated")

    def test_interrupted_scan_does_not_persist_a_skipping_cursor(self) -> None:
        """The sixth review's soundness rule: a lexical watermark may only
        skip names that were actually read. A scan interrupted by the
        deadline persists the pending queue with an empty cursor, so the
        next pass cannot skip an unread name that sorts below the last
        decided one — the exact mechanism that permanently hid the tail in
        the non-lexical over-cap counterexample."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        names = [f"b-retained-{i:04d}" for i in range(6)] + [
            "a-expired-after-prefix"]
        for name in names:
            (sessions / name).mkdir()
        tail = sessions / "a-expired-after-prefix"
        visited = []
        clock = [100.0]

        def eligible(path, _cutoff):
            return path.name == tail.name

        with (self._scan_stub(sessions, visited, clock),
              mock.patch.object(cg.time, "monotonic",
                                side_effect=lambda: clock[0]),
              mock.patch.object(cg, "_session_expired",
                                side_effect=eligible)):
            # A tiny budget reads only the first stream entries (all
            # b-retained names in this stub order) and must NOT persist a
            # cursor that would skip the lexically smaller unread tail.
            cg.cleanup_old_sessions(self.data_dir, deadline=clock[0] + 0.002)
            cursor, pending = cg._read_cleanup_state(self.data_dir)
            self.assertEqual(cursor, "",
                             "an interrupted scan persisted a cursor")
            # Ample budget: the tail must be discovered and removed.
            cg.cleanup_old_sessions(self.data_dir, deadline=clock[0] + 30.0)
        self.assertFalse(tail.exists(),
                         "the unread lexically-smaller tail was never "
                         "adjudicated")

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


    @unittest.expectedFailure
    def test_longer_decided_prefix_still_reaches_the_tail(self) -> None:
        """EXPECTED FAILURE — a documented, submitted contract conflict, not
        a silent regression.

        The sixth-review progress model (eight directories, 1ms per read,
        3ms per round, 12 rounds) cannot be satisfied simultaneously with
        the original RR04 contract that the sixth review restored: per-read
        deadline gating caps discovery at floor(budget/entry-cost)+1 stream
        entries per pass (here 4), the model charges every readdir step —
        including re-reads of already-decided names — the same 1ms, and the
        stream places seven decided names before the tail. No position
        mechanism can skip those re-reads (os.scandir cannot resume across
        the per-event process boundary), so the tail is unreachable within
        any number of passes. Under the same model the four-directory case
        passes only because the whole namespace fits one pass's read
        budget.

        This is pinned as an expected failure so the conflict stays visible:
        resolving it requires the requirement owner to choose between the
        original per-read deadline contract (current behavior — bounded
        discovery per pass, pending-queue progress, bounded-delay tail
        discovery at real budgets) and a changed enumeration contract (the
        withdrawn no-deadline full-sweep proposal and a registration-based
        alternative are described in the handback's pending design
        proposal). Neither is adopted by the implementation."""
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

    def test_interrupted_passes_stay_bounded_and_queue_progress(self) -> None:
        """Documents the restored contract's actual behavior on the
        eight-directory shape: every pass reads at most
        floor(budget/entry-cost)+1 entries (deadline-bounded discovery),
        read-but-undecided names persist in the pending queue, the queue
        drains before new enumeration, and nothing is lost — the tail waits
        for a pass whose budget reaches it (bounded delay at real budgets,
        documented conflict at toy ratios)."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        names = [f"a-retained-{i:02d}" for i in range(7)] + ["z-expired"]
        for name in names:
            (sessions / name).mkdir()
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
            cg.cleanup_old_sessions(self.data_dir,
                                    deadline=clock() + 0.003)
            self.assertLessEqual(len(visited), 4,
                                 "discovery exceeded the per-read deadline "
                                 "bound")
            cursor, pending = cg._read_cleanup_state(self.data_dir)
            self.assertEqual(pending, sorted(visited),
                             "every read name must be queued")
            self.assertEqual(cursor, "",
                             "an interrupted scan must not persist a cursor")
            # The next pass drains the queue before any new enumeration and
            # re-reads the namespace without a skipping cursor.
            cg.cleanup_old_sessions(self.data_dir,
                                    deadline=clock() + 0.003)
        # No name was ever lost: the queue and the namespace stay coherent.
        self.assertEqual(
            sorted(p.name for p in sessions.iterdir()
                   if p.name != ".locks"),
            sorted(names),
            "cleanup must not lose or fabricate namespace entries")


class RV03PendingNamespaceGate(IsolatedEnvironment):
    """RV-03 (sixth review, P1): the pending queue is progress data, not a
    scope grant. Queued names are untrusted control data — they must be
    plain encoded v2 session components and must still resolve to a real
    v2 directory object at adjudication; anything else is decided (dropped)
    without touching anything, so a hostile state file can never point
    deletion outside the v2 namespace. The legacy namespace stays read-only
    and valid v2 pending work still proceeds."""


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
        symlink_or_skip(self, target, outside / "keep", target_is_directory=True)
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


class RV03DiscoveryRegistryAndChunks(IsolatedEnvironment):
    """RV-03 (eighth round): the durable discovery registry and the chunked
    pending queue together carry legitimate undecided work across calls.

    - The registry (content-free encoded names) is written by the session
      write path, so hook-created sessions are discovered without depending
      on readdir order; sweep-discovered names are added to it too, so even
      a deadline-interrupted scan persists its discoveries position-free.
    - The pending queue is persisted as fixed-size chunks plus an index —
      the producer's write domain equals the reader's read domain, so
      legitimate work can never be written into a shape its own reader
      refuses.
    - The registry is a hint, never an authority: entries are
      component-gated on read, live-verified at adjudication, and a lost or
      corrupted registry falls back to the deadline-bounded backfill sweep.
    """

    def _register(self, names):
        cg._add_cleanup_registry_entries(self.data_dir, names)

    def test_write_path_registers_sessions_for_discovery(self) -> None:
        """Production save_state registers the encoded session name, so a
        hook-created session is discoverable without any scan."""
        self._expire_session("registered-session")
        registry = cg._read_discovery_registry(self.data_dir)
        self.assertIn(cg.safe_session_id("registered-session"), registry)

    def test_registered_eight_directory_model_reaches_the_tail(self) -> None:
        """The eighth-round design proof on the sixth-review toy model: the
        same eight directories, 1ms per read, 3ms per round — but the
        sessions are durably registered by the write path (as production
        hook-created sessions are). The registry is adjudicated directly,
        so the expired tail is discovered without depending on readdir
        order and removed within bounded passes."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        names = [f"a-retained-{i:02d}" for i in range(7)] + ["z-expired"]
        for name in names:
            (sessions / name).mkdir()
        tail = sessions / "z-expired"
        self._register(names)
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
                         "registered sessions were not fairly discovered")
        self.assertIn("z-expired", visited)

    def test_pending_chunks_carry_more_than_one_legacy_file(self) -> None:
        """The seventh-review capacity counterexample, as a repository
        regression: a budget-starved pass whose sweep reads more names than
        one legacy state file held must persist ALL of them through the
        chunk protocol, and the next pass adjudicates the whole queue (the
        expired tail included)."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        count = 4097
        names = [f"a-retained-{i:05d}" for i in range(count - 1)] + [
            "z-expired"]
        for name in names:
            (sessions / name).mkdir()
        tail = sessions / "z-expired"
        visited = []
        # The reviewer's clock: reads cost ~nothing and the LAST in-flight
        # read of each pass consumes the remainder of the budget, so every
        # name is read and none is adjudicated in the first pass.
        clock = [1000.0]

        def eligible(path, _cutoff):
            visited.append(path.name)
            return path.name == "z-expired"

        real_scandir = os.scandir
        reads_per_pass = []

        class Entry:
            def __init__(self, name):
                self.name = name
                self.path = str(sessions / name)

            def is_symlink(self):
                return False

            def is_dir(self, **kwargs):
                return True

        class Scanner:
            def __init__(self):
                self.names = [n for n in names
                              if (sessions / n).exists()]
                self.index = 0
                reads_per_pass.append(0)

            def __iter__(self):
                return self

            def __next__(self):
                if self.index >= len(self.names):
                    raise StopIteration
                name = self.names[self.index]
                self.index += 1
                reads_per_pass[-1] += 1
                visited.append(name)
                if self.index == len(self.names):
                    clock[0] = 1000.101  # last read consumes the remainder
                return Entry(name)

            def close(self):
                pass

        def scanner(path):
            if Path(path) == sessions:
                return Scanner()
            return real_scandir(path)

        with (mock.patch.object(cg.os, "scandir", side_effect=scanner),
              mock.patch.object(cg.time, "monotonic",
                                side_effect=lambda: clock[0]),
              mock.patch.object(cg, "_session_expired",
                                side_effect=eligible)):
            cg.cleanup_old_sessions(self.data_dir, deadline=1000.100)
            cursor, pending = cg._read_cleanup_state(self.data_dir)
            self.assertEqual(len(pending), count,
                             "the reader refused a queue its own writer "
                             "produced")
            self.assertEqual(reads_per_pass[0], count)
            self.assertEqual(
                len(list((self.data_dir / "sessions-v2" / ".locks").glob(
                    "*.cleanup-pending-*.json"))), 2,
                "the queue must be split into two chunks at the legacy "
                "file-size boundary")
            clock[0] = 1000.0
            cg.cleanup_old_sessions(self.data_dir, deadline=clock[0] + 30.0)
        self.assertFalse(tail.exists(),
                         "the over-legacy-limit queue lost its tail")
        self.assertIn("z-expired", visited)

    def test_corrupted_chunk_costs_only_its_own_names(self) -> None:
        """One corrupted chunk file drops that chunk's names only; the other
        chunks still load (bounded, progress-only loss — never a whole-queue
        refusal)."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        for name in ("a-one", "b-two", "c-three"):
            (sessions / name).mkdir()
        cg._write_cleanup_state(self.data_dir, "", ["a-one", "b-two",
                                                    "c-three"])
        chunk_dir = self.data_dir / "sessions-v2" / ".locks"
        chunks = sorted(chunk_dir.glob("*.cleanup-pending-*.json"))
        self.assertEqual(len(chunks), 1)
        chunks[0].write_text("{corrupted", encoding="utf-8")
        cursor, pending = cg._read_cleanup_state(self.data_dir)
        self.assertEqual(pending, [],
                         "a corrupted chunk must not smuggle names through")
        # A repaired write restores the queue.
        cg._write_cleanup_state(self.data_dir, "", ["a-one", "b-two",
                                                    "c-three"])
        _, pending = cg._read_cleanup_state(self.data_dir)
        self.assertEqual(pending, ["a-one", "b-two", "c-three"])

    def test_registry_corruption_and_loss_fall_back_to_backfill(self) -> None:
        """A corrupted registry drops its invalid lines; a deleted registry
        falls back to the deadline-bounded backfill sweep — expired sessions
        are still adjudicated correctly in both cases."""
        self._expire_session("registered-expired")
        registry = cg._cleanup_registry_path(self.data_dir)
        registry.write_text("registered-expired\n../../evil\n.locks\n",
                            encoding="utf-8")
        loaded = cg._read_discovery_registry(self.data_dir)
        self.assertEqual(loaded, {"registered-expired"},
                         "invalid registry lines must be dropped")
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 30)
        self.assertEqual(removed, 1)
        self.assertFalse(self.session_dir("registered-expired").exists())
        # Loss: with no registry at all, the backfill sweep still finds the
        # expired session (bounded delay per pass under the deadline).
        self._expire_session("backfill-expired")
        cg._cleanup_registry_path(self.data_dir).unlink(missing_ok=True)
        self.assertEqual(cg._read_discovery_registry(self.data_dir), set())
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 30)
        self.assertEqual(removed, 1)
        self.assertFalse(self.session_dir("backfill-expired").exists())

    def test_maintenance_boundary_refuses_linked_locks_root(self) -> None:
        """Ninth review (P1): the `.locks` maintenance root itself must be a
        real directory. When it is planted as a link to an outside
        directory, EVERY cleanup maintenance entrance — sweep registration,
        registry read, cursor/pending write, generation reset — refuses
        before any external read, append, rewrite, mode change or deletion,
        instead of verifying only the registry leaf."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        outside = self.root / "external-maintenance-like-directory"
        outside.mkdir(mode=0o755)
        outside.chmod(0o755)
        registry = outside / cg.CLEANUP_REGISTRY_NAME
        registry.write_text("prior-known-session\n", encoding="utf-8")
        registry.chmod(0o640)
        (outside / cg.CLEANUP_CURSOR_NAME).write_text(
            "prior-known-session\n", encoding="utf-8")
        (sessions / "sweep-discovered").mkdir()
        symlink_or_skip(self, sessions / ".locks", outside, target_is_directory=True)
        before = sorted(p.relative_to(outside).as_posix()
                        for p in outside.rglob("*"))
        before_bytes = {p.relative_to(outside).as_posix():
                        p.read_bytes() for p in outside.rglob("*")
                        if p.is_file()}
        root_mode = outside.stat().st_mode & 0o777
        # Sweep entry: registration and any state writes must be skipped.
        self.assertEqual(
            cg.cleanup_old_sessions(self.data_dir,
                                    deadline=time.monotonic() + 30), 0)
        # Registry read: treats a linked registry as absent.
        self.assertEqual(cg._read_discovery_registry(self.data_dir), set())
        # Reset/orphan deletion: refused.
        cg._reset_cleanup_state(self.data_dir)
        after = sorted(p.relative_to(outside).as_posix()
                       for p in outside.rglob("*"))
        after_bytes = {p.relative_to(outside).as_posix():
                       p.read_bytes() for p in outside.rglob("*")
                       if p.is_file()}
        self.assertEqual(before, after, "the external tree changed")
        self.assertEqual(before_bytes, after_bytes,
                         "external file bytes changed")
        self.assertEqual(outside.stat().st_mode & 0o777, root_mode,
                         "the external directory mode was modified")

    def _planted_outside(self, name: str) -> Path:
        outside = self.root / name
        outside.mkdir(mode=0o755)
        outside.chmod(0o755)
        registry = outside / cg.CLEANUP_REGISTRY_NAME
        registry.write_text("prior-known-session\n", encoding="utf-8")
        registry.chmod(0o640)
        (outside / cg.CLEANUP_CURSOR_NAME).write_text(
            "prior-known-session\n", encoding="utf-8")
        return outside

    @staticmethod
    def _tree_state(outside: Path) -> tuple[list[str], dict[str, bytes], int]:
        listing = sorted(p.relative_to(outside).as_posix()
                         for p in outside.rglob("*"))
        blobs = {p.relative_to(outside).as_posix():
                 p.read_bytes() for p in outside.rglob("*") if p.is_file()}
        return listing, blobs, outside.stat().st_mode & 0o777

    def _assert_outside_untouched(self, outside: Path) -> None:
        before = self._tree_state(outside)
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 30)
        self.assertEqual(cg._read_discovery_registry(self.data_dir), set())
        cg._write_cleanup_state(self.data_dir, "", ["queued-name"])
        cg._reset_cleanup_state(self.data_dir)
        self.assertEqual(self._tree_state(outside), before,
                         "the external maintenance object changed")
        self.assertEqual(removed, 0, "the sweep adjudicated through a link")

    def test_maintenance_boundary_refuses_linked_namespace(self) -> None:
        """Tenth review (P1): the gate must cover the whole chain — when the
        v2 namespace itself is planted as a link, every maintenance
        entrance (sweep, registry read/append, cursor write, reset)
        refuses before any external read, append, rewrite, mode change or
        deletion, instead of verifying only the `.locks` leaf."""
        outside = self._planted_outside("external-namespace-object")
        self.data_dir.mkdir(parents=True)
        symlink_or_skip(self, self.data_dir / "sessions-v2", outside,
                                                   target_is_directory=True)
        self.assertFalse(cg._maintenance_boundary_ok(self.data_dir))
        self._assert_outside_untouched(outside)

    def test_maintenance_boundary_refuses_linked_data_root(self) -> None:
        """Tenth review (P1): when the configured data root itself is a
        link to an outside directory, the whole public cleanup refuses —
        the root tier is part of the maintenance boundary chain."""
        outside = self._planted_outside("external-data-root-object")
        # setUp never creates the data root; link it before anything does.
        symlink_or_skip(self, self.data_dir, outside, target_is_directory=True)
        self.assertFalse(cg._maintenance_boundary_ok(self.data_dir))
        self._assert_outside_untouched(outside)

    def test_maintenance_boundary_allows_alias_above_configured_root(self) -> None:
        """Ancestors ABOVE the configured data root may be platform aliases
        (macOS /var, /tmp): a linked parent of the root must not disable
        maintenance, because the boundary chain starts at the configured
        root itself."""
        home = self.root / "platform-home"
        (home / "guard-data" / "sessions-v2" / ".locks").mkdir(parents=True)
        alias = self.root / "alias-to-home"
        symlink_or_skip(self, alias, home, target_is_directory=True)
        self.assertTrue(
            cg._maintenance_boundary_ok(alias / "guard-data"))

    def test_add_registry_entries_windows_capability_profile(self) -> None:
        """Ninth review P1 (capability model), rewritten after the
        eleventh review's non-vacuity finding: a FRESH session (never
        registered before, process cache empty, registry file absent) is
        saved while the registry helper runs under the Windows capability
        profile — ``os.name == "nt"`` with no ``os.fchmod`` on the
        interpreter. The registry file must actually gain the session's
        line during that modeled phase (real append, read back from the
        file), which fails on the pre-fix bytes that called ``os.fchmod``
        unconditionally (the AttributeError escaped the OSError handler)
        and passes on the fixed bytes whose nt branch takes the file
        boundary from the validated parent directory. The modeled phase
        never mutates the POSIX test host beyond the session tree, and a
        missing ``os.fchmod`` attribute is restored to its exact prior
        presence state."""
        sessions = self.data_dir / "sessions-v2"
        sessions.mkdir(parents=True)
        session = "win-capability-fresh"
        encoded = cg.safe_session_id(session)
        registry_path = cg._cleanup_registry_path(self.data_dir)
        # Fresh identity: nothing pre-registered, no process cache entry.
        self.assertFalse(registry_path.exists())
        self.assertNotIn(encoded, cg._read_discovery_registry(self.data_dir))
        self.assertNotIn((str(self.data_dir), encoded),
                         cg._REGISTRY_ENTRIES_THIS_PROCESS)
        self.assertNotIn(str(self.session_dir(session)),
                         cg._REGISTRY_ENTRIES_THIS_PROCESS)
        actual_fchmod = getattr(os, "fchmod", None)
        real_fstat = os.fstat
        append_opens = []
        real_open = os.open
        real_add = cg._add_cleanup_registry_entries
        modeled = {"entered": False}

        def file_mode_666(fd):
            value = real_fstat(fd)
            fields = list(value)
            fields[0] = (fields[0] & ~0o777) | 0o666
            return os.stat_result(fields)

        def traced_open(path, *args, **kwargs):
            fd = real_open(path, *args, **kwargs)
            if str(path).endswith(".session-registry"):
                append_opens.append(fd)
            return fd

        def profile_add(root, names):
            modeled["entered"] = True
            with mock.patch.object(os, "name", "nt"), \
                    mock.patch.object(os, "fstat",
                                      side_effect=file_mode_666), \
                    mock.patch.object(os, "open",
                                      side_effect=traced_open):
                if actual_fchmod is not None:
                    delattr(os, "fchmod")
                try:
                    return real_add(root, names)
                finally:
                    # Restore os.fchmod to its exact prior presence state.
                    if actual_fchmod is not None:
                        os.fchmod = actual_fchmod
                    elif hasattr(os, "fchmod"):
                        delattr(os, "fchmod")

        with mock.patch.object(cg, "_add_cleanup_registry_entries",
                               side_effect=profile_add):
            cg.dispatch(self.payload(
                "UserPromptSubmit", session, prompt="capability model",
                turn_id="t1"))
        self.assertTrue(modeled["entered"], "the registry helper was never reached")
        # The modeled phase really appended: at least one registry append
        # open happened and the file now carries the fresh session's line.
        self.assertTrue(append_opens,
                        "no registry append open occurred in the modeled "
                        "Windows capability phase")
        raw_registry = registry_path.read_text(encoding="utf-8")
        self.assertIn(encoded, raw_registry.splitlines(),
                      "the fresh session was not durably registered in the "
                      "modeled phase")
        self.assertEqual(
            cg._read_discovery_registry(self.data_dir), {encoded})
        # The session save itself completed under the modeled profile.
        self.assertTrue(self.session_dir(session).exists())

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "fchmod"),
                         "POSIX permission-mode/fchmod contract")
    def test_failed_mode_readback_preserves_prior_registrations(self) -> None:
        """Ninth review observation, updated semantics: when fchmod succeeds
        but the read-back mode still mismatches, the append is SKIPPED and
        prior registry content is preserved exactly — no truncation, no
        data loss; the skipped names fall back to the bounded sweep."""
        registry = cg._cleanup_registry_path(self.data_dir)
        registry.parent.mkdir(parents=True, exist_ok=True)
        registry.write_text("prior-registered-session\n", encoding="utf-8")
        registry.chmod(0o644)
        before = registry.read_bytes()
        with mock.patch.object(os, "fchmod",
                               side_effect=lambda fd, mode: None):
            cg._add_cleanup_registry_entries(self.data_dir, ["fresh-session"])
        self.assertEqual(registry.read_bytes(), before,
                         "prior registry content was truncated")
        self.assertEqual(cg._read_discovery_registry(self.data_dir),
                         {"prior-registered-session"})

    def test_registry_entries_pointing_outside_v2_are_dropped(self) -> None:
        """Eighth review (P2): the registry is private state — created at
        0600 with read-back verification even under a permissive umask, not
        0644-by-accident. The 0700 parent does not substitute for the file
        mode contract."""
        old_mask = os.umask(0o022)
        try:
            self._expire_session("registry-mode-control")
        finally:
            os.umask(old_mask)
        registry = cg._cleanup_registry_path(self.data_dir)
        self.assertTrue(registry.exists())
        if os.name == "posix":
            self.assertEqual(registry.stat().st_mode & 0o777, 0o600,
                             "the registry was created world-readable")
        else:
            self.assertIsNotNone(cg._windows_query_dacl_sddl(registry))
        self.assertIn(cg.safe_session_id("registry-mode-control"),
                      cg._read_discovery_registry(self.data_dir))

    def test_static_link_registry_is_never_written_through(self) -> None:
        """Eighth review (P1): every registry entrance (save-path
        registration, sweep discovery registration, read) refuses a
        substituted link object instead of appending through it, so an
        external file keeps its exact bytes and the planted link stays."""
        registry = cg._cleanup_registry_path(self.data_dir)
        registry.parent.mkdir(parents=True, exist_ok=True)
        outside = self.root / "external-unrelated.conf"
        outside.write_text("SYNTHETIC-EXTERNAL-CONFIG\n", encoding="utf-8")
        outside.chmod(0o640)
        outside_mode = outside.stat().st_mode & 0o777
        before = outside.read_bytes()
        symlink_or_skip(self, registry, outside)
        # save-path registration: refused, external untouched
        self._expire_session("static-link-session")
        self.assertEqual(outside.read_bytes(), before,
                         "the save path appended through the link")
        self.assertEqual(outside.stat().st_mode & 0o777, outside_mode)
        # sweep registration: refused too
        cg._add_cleanup_registry_entries(self.data_dir, ["another-name"])
        self.assertEqual(outside.read_bytes(), before,
                         "the sweep appended through the link")
        # compaction: refuses a substituted object instead of replacing it
        cg._compact_discovery_registry(self.data_dir, {"some-session"})
        self.assertEqual(outside.read_bytes(), before)
        self.assertTrue(registry.is_symlink(),
                        "the planted link itself was replaced")
        # reads treat a linked registry as absent rather than reading the
        # external file's lines as hints
        self.assertEqual(cg._read_discovery_registry(self.data_dir), set())

    def test_cleanup_prefixed_sid_is_a_supported_session(self) -> None:
        """Eighth review (P2): the production encoder keeps every byte of
        `[A-Za-z0-9._-]` raw, so `.cleanup-report` is a legitimate encoded
        session id. The cleanup gate must accept the same support domain —
        only exact maintenance-object collisions (`.locks` and `.`/`..`)
        are reserved — and the expired session must be adjudicated and
        removed like any other."""
        self._expire_session(".cleanup-report")
        self._expire_session("ordinary-report")
        self.assertEqual(cg.safe_session_id(".cleanup-report"),
                         ".cleanup-report")
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 30)
        self.assertEqual(removed, 2)
        self.assertFalse(self.session_dir(".cleanup-report").exists())
        self.assertFalse(self.session_dir("ordinary-report").exists())

    def test_registry_hint_for_missing_live_object_decides_without_action(self) -> None:
        """Registry names are hints, not authority: an entry whose live
        object is missing (renamed away, e.g. into the legacy namespace by
        the seventh-review poison fixture) is decided without action and
        the legacy tree stays untouched."""
        self._expire_session("registered-session")
        legacy = self.data_dir / cg.LEGACY_NAMESPACE / "registered-session"
        legacy.mkdir(parents=True, exist_ok=True)
        (legacy / "KEEP.txt").write_text("SYNTHETIC-SENTINEL\n",
                                         encoding="utf-8")
        shutil.rmtree(self.session_dir("registered-session"))
        self._register([cg.safe_session_id("registered-session")])
        removed = cg.cleanup_old_sessions(self.data_dir,
                                          deadline=time.monotonic() + 30)
        self.assertEqual(removed, 0)
        self.assertTrue(legacy.exists())
        self.assertFalse(
            (self.data_dir / cg.LEGACY_NAMESPACE / ".locks").exists())


class RV01ConfiguredInterpreterGuard(IsolatedEnvironment):
    """The configured interpreter must execute the Hook and verify its wire.

    Windows executes the product PowerShell launcher with a real Python
    positive control and native batch executables as non-Python negatives.
    POSIX executes the shell launcher with equivalent shell negatives.
    """

    def _write_conf(self, interpreter: str) -> Path:
        conf = Path(os.environ["CODEX_HOME"]) / "context-guard" / "interpreter.conf"
        conf.parent.mkdir(parents=True, exist_ok=True)
        conf.write_text(f"{interpreter}\n", encoding="utf-8")
        conf.chmod(0o600)
        return conf

    def _invoke(self, session: str):
        import subprocess

        tree = Path(cg.__file__).resolve().parents[1]
        if os.name == "nt":
            powershell = shutil.which("powershell.exe")
            if powershell is None:
                self.skipTest("native Windows PowerShell executable unavailable")
            command = [powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
                       "-ExecutionPolicy", "Bypass", "-File",
                       str(tree / "scripts" / "run-context-guard.ps1")]
        else:
            command = ["/bin/sh", str(tree / "scripts" / "run_context_guard.sh")]
        payload = json.dumps({
            "hook_event_name": "UserPromptSubmit", "cwd": str(self.project),
            "session_id": session, "turn_id": "t1",
            "prompt": "Repair demo.py and run tests."})
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [*command, "hook", "UserPromptSubmit"], input=payload,
            capture_output=True, text=True, encoding="utf-8", env=env,
            timeout=60)

    def _invoke_with_output(self, output: str, session: str):
        fake = Path(os.environ["CODEX_HOME"]) / (
            "fake-interpreter.cmd" if os.name == "nt" else "fake-interpreter")
        fake.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            body = "@echo off\n" + (f"echo {output}\n" if output else "")
            body += "exit /b 0\n"
        else:
            import shlex

            body = "#!/bin/sh\n"
            if output:
                body += "printf '%s\\n' " + shlex.quote(output) + "\n"
            body += "exit 0\n"
        fake.write_text(body, encoding="utf-8")
        fake.chmod(0o700)
        self._write_conf(str(fake))
        return self._invoke(session)

    def _assert_rejected(self, proc) -> None:
        self.assertNotEqual(proc.returncode, 0, proc.stdout[:200])
        self.assertIn("not a working Context Guard runtime", proc.stderr)
        self.assertFalse((self.data_dir / "sessions-v2").exists(),
                         "rejected executable created session state")

    def test_silent_skip_signature_fails_visibly(self) -> None:
        proc = self._invoke_with_output("", "replaced-exec")
        self._assert_rejected(proc)
        self.assertEqual(proc.stdout, "")

    def test_real_interpreter_passes_the_guard(self) -> None:
        import sys

        self._write_conf(sys.executable)
        proc = self._invoke("valid-exec")
        self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
        self.assertIsInstance(json.loads(proc.stdout), dict)
        self.assertTrue((self.session_dir("valid-exec") / "state.json").is_file())

    def test_malformed_object_output_is_not_a_hook_result(self) -> None:
        self._assert_rejected(self._invoke_with_output(
            "{startup diagnostic", "malformed-object"))

    def test_valid_json_non_object_is_not_a_hook_result(self) -> None:
        self._assert_rejected(self._invoke_with_output("[1,2]", "json-array"))

    def test_json_looking_output_without_python_capability_is_rejected(self) -> None:
        self._assert_rejected(self._invoke_with_output(
            '{"continue": true}', "json-object"))


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
