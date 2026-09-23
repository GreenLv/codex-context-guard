"""Bounded child-tree ownership without model or network calls."""
import ctypes
import errno
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import cg_answer_review as review
from scripts import cg_process_tree as tree


class _BasicLimit(ctypes.Structure):
    _fields_ = [("LimitFlags", ctypes.c_uint32)]


class _Limit(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimit)]


class _Accounting(ctypes.Structure):
    _fields_ = [("ActiveProcesses", ctypes.c_uint32)]


class _Process:
    pid = 123
    _handle = 456

    def __init__(self):
        self.killed = False
        self.waited = False

    def kill(self):
        self.killed = True

    def wait(self, timeout):
        self.waited = True
        return 0

    def poll(self):
        return 0 if self.waited else None


class _WindowsApi:
    def __init__(self, *, deny=None):
        self.deny = deny
        self.closed = []
        self.terminated = 0

    def CreateJobObjectW(self, *_):
        return 111

    def SetInformationJobObject(self, *_):
        return self.deny != "limit"

    def AssignProcessToJobObject(self, *_):
        return self.deny != "assign"

    def ResumeThread(self, *_):
        return 0 if self.deny == "resume" else 1

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return self.deny != "close"

    def TerminateJobObject(self, *_):
        self.terminated += 1
        return self.deny != "terminate"

    def QueryInformationJobObject(self, _job, _kind, pointer, _size, _unused):
        if self.deny == "query":
            return False
        ctypes.cast(pointer, ctypes.POINTER(_Accounting)).contents.ActiveProcesses = 0
        return True


class ProcessTreeTest(unittest.TestCase):
    def windows_spawn(self, deny=None):
        api, process = _WindowsApi(deny=deny), _Process()
        with (mock.patch.object(tree.os, "name", "nt"),
              mock.patch.object(tree, "_windows_api", return_value=(api, _Limit, _Accounting, object)),
              mock.patch.object(tree, "_initial_thread", return_value=222),
              mock.patch.object(tree.subprocess, "Popen", return_value=process) as launch):
            if deny in {"limit", "assign", "resume"}:
                with self.assertRaisesRegex(tree.ProcessTreeError, "denied|failed"):
                    tree.OwnedProcess.spawn(["fixture"])
                if deny == "limit":
                    launch.assert_not_called()
                else:
                    self.assertTrue(process.killed)
                self.assertIn(111, api.closed)
                return
            owned = tree.OwnedProcess.spawn(["fixture"])
        self.assertEqual(launch.call_args.kwargs["creationflags"] & 0x4, 0x4)
        self.assertIn(222, api.closed)
        return owned, api

    def test_windows_suspended_assignment_and_repeat_close(self):
        owned, api = self.windows_spawn()
        result = owned.close(1)
        self.assertTrue(result["owned_tree_empty"])
        self.assertTrue(result["owned_process_exited"])
        self.assertTrue(result["owned_tree_no_running_members"])
        self.assertIsNone(result["process_group_absent"])
        self.assertEqual(owned.close(1), result)
        self.assertEqual(api.terminated, 1)
        self.assertEqual(api.closed.count(111), 1)

    def test_windows_partial_start_failure_is_fail_closed(self):
        for failure in ("limit", "assign", "resume"):
            with self.subTest(failure=failure):
                self.windows_spawn(failure)

    def test_windows_cleanup_denial_never_claims_empty_tree(self):
        for failure in ("terminate", "query", "close"):
            with self.subTest(failure=failure):
                owned, _api = self.windows_spawn(failure)
                result = owned.close(1)
                self.assertFalse(result["owned_tree_empty"])
                self.assertIsNotNone(result["process_group_cleanup_error"])

    @unittest.skipUnless(os.name == "posix", "POSIX group query")
    def test_signal_sent_without_group_disappearance_stays_unknown(self):
        process = _Process()
        process.wait(1)
        with mock.patch.object(tree.os, "killpg", return_value=None) as signal_group:
            result = tree.OwnedProcess(process).close(0.05)
        self.assertFalse(result["owned_tree_empty"])
        self.assertTrue(any(call.args[1] == 0 for call in signal_group.call_args_list))

    @unittest.skipUnless(os.name == "posix", "POSIX group query")
    def test_group_disappearance_after_signal_is_observed(self):
        process = _Process()
        process.wait(1)
        with mock.patch.object(tree.os, "killpg", side_effect=[None, None, ProcessLookupError]):
            result = tree.OwnedProcess(process).close(1)
        self.assertTrue(result["owned_tree_empty"])
        self.assertTrue(result["owned_tree_no_running_members"])
        self.assertTrue(result["process_group_absent"])

    @unittest.skipUnless(sys.platform == "darwin", "Darwin group state reader")
    def test_darwin_group_reader_distinguishes_zombie_from_live(self):
        class Function:
            def __init__(self, body):
                self.body = body

            def __call__(self, *args):
                return self.body(*args)

        class API:
            status = 5
            length = 64
            reported_pid = 4321
            reported_pgid = 1234
            capacity = 1
            query_errno = 0

            def __init__(self):
                self.proc_listpgrppids = Function(self.list_group)
                self.proc_pidinfo = Function(self.info)

            def list_group(self, pgid, buffer, size):
                if buffer is None:
                    ctypes.set_errno(self.query_errno)
                    return self.capacity
                buffer[0] = 4321
                return 1

            def info(self, pid, _flavor, _arg, buffer, size):
                if self.status in {"exited", "denied"}:
                    ctypes.set_errno(errno.ESRCH if self.status == "exited" else errno.EPERM)
                    return 0
                ctypes.memmove(buffer, struct.pack("=IIII", self.reported_pid, 1,
                                                   self.reported_pgid, self.status), 16)
                return self.length

        api = API()
        with mock.patch.object(tree.ctypes, "CDLL", return_value=api):
            self.assertTrue(tree._darwin_group_no_running_members(1234))
            api.status = 2
            self.assertFalse(tree._darwin_group_no_running_members(1234))
            api.status = "exited"
            self.assertTrue(tree._darwin_group_no_running_members(1234))
            api.status = "denied"
            with self.assertRaisesRegex(tree.ProcessTreeError, "state_unavailable"):
                tree._darwin_group_no_running_members(1234)
            api.status = 5
            api.length = 63
            with self.assertRaisesRegex(tree.ProcessTreeError, "state_unavailable"):
                tree._darwin_group_no_running_members(1234)
            api.length = 64
            for field in ("reported_pid", "reported_pgid", "status"):
                with self.subTest(field=field):
                    original = getattr(api, field)
                    setattr(api, field, 0)
                    with self.assertRaisesRegex(tree.ProcessTreeError, "state_invalid"):
                        tree._darwin_group_no_running_members(1234)
                    setattr(api, field, original)
            api.capacity = 0
            api.query_errno = errno.ESRCH
            self.assertFalse(tree._darwin_group_no_running_members(1234))
            api.query_errno = errno.EPERM
            with self.assertRaisesRegex(tree.ProcessTreeError, "members_unavailable"):
                tree._darwin_group_no_running_members(1234)
        self.assertFalse(tree._darwin_group_no_running_members(os.getpgrp()))

    @unittest.skipUnless(sys.platform == "darwin", "Darwin cleanup classification")
    def test_darwin_zombie_readback_is_distinct_from_group_disappearance(self):
        process = _Process()
        process.wait(1)
        with (mock.patch.object(tree.os, "killpg", return_value=None),
              mock.patch.object(tree, "_darwin_group_no_running_members", return_value=True)):
            result = tree.OwnedProcess(process).close(1)
        self.assertFalse(result["owned_tree_empty"])
        self.assertFalse(result["process_group_absent"])
        self.assertTrue(result["owned_tree_no_running_members"])

    @unittest.skipUnless(sys.platform == "darwin", "Darwin cleanup classification")
    def test_darwin_readback_after_late_signal_and_query_denial(self):
        process = _Process()
        process.wait(1)
        def signal_group(_pgid, signal):
            if signal != tree.signal.SIGTERM:
                raise PermissionError
        with (mock.patch.object(tree.os, "killpg", side_effect=signal_group),
              mock.patch.object(tree, "_darwin_group_no_running_members", return_value=True)):
            result = tree.OwnedProcess(process).close(1)
        self.assertIsNone(result["process_group_cleanup_error"])
        self.assertTrue(result["owned_tree_no_running_members"])
        self.assertFalse(result["process_group_absent"])
        self.assertTrue(result["process_group_signal_denied"])
        self.assertTrue(result["process_group_query_denied"])

    @unittest.skipUnless(sys.platform == "darwin", "Darwin disappearing group")
    def test_darwin_empty_first_snapshot_requires_group_recheck(self):
        process = _Process()
        process.wait(1)
        with (mock.patch.object(tree.os, "killpg",
                                side_effect=[None, None, None, ProcessLookupError]),
              mock.patch.object(tree, "_darwin_group_no_running_members",
                                return_value=False) as reader):
            result = tree.OwnedProcess(process).close(1)
        reader.assert_called_once()
        self.assertTrue(result["process_group_absent"])
        self.assertTrue(result["owned_tree_no_running_members"])

    @unittest.skipUnless(sys.platform == "darwin", "Darwin cleanup classification")
    def test_darwin_live_or_unreadable_group_fails_closed(self):
        for observation, expected_error in ((False, None),
                                            (tree.ProcessTreeError("state_unavailable"),
                                             "state_unavailable")):
            with self.subTest(observation=observation):
                process = _Process()
                process.wait(1)
                reader = (mock.Mock(side_effect=observation)
                          if isinstance(observation, Exception)
                          else mock.Mock(return_value=observation))
                with (mock.patch.object(tree.os, "killpg", return_value=None),
                      mock.patch.object(tree, "_darwin_group_no_running_members", reader)):
                    result = tree.OwnedProcess(process).close(0.05)
                self.assertFalse(result["owned_tree_no_running_members"])
                self.assertEqual(result["process_group_cleanup_error"], expected_error)

    @unittest.skipUnless(os.name in {"posix", "nt"}, "owned process-tree probe")
    def test_short_lived_leader_keeps_child_owned(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "pid"
            child = "import time; time.sleep(30)"
            script = ("import subprocess,time; from pathlib import Path; "
                      f"p=subprocess.Popen([{sys.executable!r},'-c',{child!r}]); "
                      f"Path({str(marker)!r}).write_text(str(p.pid))")
            owned = tree.OwnedProcess.spawn([sys.executable, "-c", script],
                                             stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL)
            owned.process.wait(timeout=5)
            self.assertTrue(marker.exists())
            cleanup = owned.close(3)
            self.assertTrue(cleanup["owned_tree_no_running_members"])
            if os.name == "nt":
                self.assertIsNone(cleanup["process_group_absent"])
            else:
                self.assertEqual(cleanup["process_group_absent"],
                                 cleanup["owned_tree_empty"])

    def test_review_child_receives_only_explicit_home(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            host = root / "isolated-home"
            host.mkdir()
            with mock.patch.dict(os.environ, {"CODEX_HOME": str(root / "wrong-home")}):
                result = review.invoke(
                    [sys.executable, "-c", "import os; print(os.environ['CODEX_HOME'])"],
                    "", codex_home=host,
                )
            self.assertEqual(result.stdout.strip(), str(host))
            with self.assertRaisesRegex(ValueError, "review_home_unavailable"):
                review.invoke([sys.executable, "-c", "pass"], "", codex_home=root / "missing")

    def test_reviewer_cleanup_failure_preserves_primary_error(self):
        class Process:
            returncode = 0

            def __init__(self, pending):
                self.pending = pending

            def poll(self):
                return None if self.pending else 0

        class Owned:
            def __init__(self, pending):
                self.process = Process(pending)

            def close(self, _timeout):
                return {"owned_process_exited": False, "owned_tree_empty": False,
                        "owned_tree_no_running_members": False,
                        "process_group_cleanup_error": "denied"}

        for pending, expected in ((True, "review_timeout"), (False, "review_cleanup_timeout")):
            with self.subTest(pending=pending):
                factory = mock.Mock(return_value=Owned(pending))
                fake = SimpleNamespace(OwnedProcess=SimpleNamespace(spawn=factory))
                with mock.patch.object(review, "process_tree_module", return_value=fake):
                    with self.assertRaisesRegex(ValueError, expected) as raised:
                        review.invoke(["fixture"], "", timeout=0.05)
                if pending:
                    self.assertIsInstance(raised.exception.__cause__, ValueError)
                    self.assertIn("review_cleanup_timeout", str(raised.exception.__cause__))
                else:
                    self.assertIsNone(raised.exception.__cause__)
