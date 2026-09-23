"""Bounded child-tree ownership without model or network calls."""
import ctypes
import os
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
            self.assertTrue(owned.close(3)["owned_tree_empty"])

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
