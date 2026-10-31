"""Original product entry points with synthetic Windows APIs and processes."""
import ctypes
import io
import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from scripts import cg_answer_review as review
from scripts import cg_process_tree as tree


class Basic(ctypes.Structure):
    _fields_ = [("LimitFlags", ctypes.c_uint32)]


class Limit(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", Basic)]


class Accounting(ctypes.Structure):
    _fields_ = [("ActiveProcesses", ctypes.c_uint32)]


class Entry(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_uint32), ("th32ThreadID", ctypes.c_uint32),
                ("th32OwnerProcessID", ctypes.c_uint32)]


class Process:
    pid, _handle = 123, 456

    def __init__(self):
        self.calls = []
        self.returncode = None
        self.kill_error = self.wait_error = False

    def kill(self):
        self.calls.append("kill")
        if self.kill_error:
            raise OSError("synthetic-private-command")
        self.returncode = 1

    def wait(self, timeout):
        self.calls.append("wait")
        assert 0 < timeout <= 3.001
        if self.wait_error:
            raise subprocess.TimeoutExpired("synthetic-private-command", timeout)
        self.returncode = 0 if self.returncode is None else self.returncode
        return self.returncode

    def poll(self):
        self.calls.append("poll")
        return self.returncode


class API:
    def __init__(self, close_failures=None, *, assign=True, resume=1, enumerate_ok=True):
        self.failures = close_failures or {}
        self.assign, self.resume, self.enumerate_ok = assign, resume, enumerate_ok
        self.calls, self.closes = [], []
        self.terminated = False

    def CreateJobObjectW(self, *_):
        self.calls.append("create_job")
        return 111

    def SetInformationJobObject(self, *_):
        self.calls.append("limit")
        return True

    def AssignProcessToJobObject(self, *_):
        self.calls.append("assign")
        return self.assign

    def CreateToolhelp32Snapshot(self, *_):
        self.calls.append("snapshot")
        return 333

    def Thread32First(self, _snapshot, pointer):
        entry = ctypes.cast(pointer, ctypes.POINTER(Entry)).contents
        entry.th32ThreadID, entry.th32OwnerProcessID = 42, 123
        return self.enumerate_ok

    def Thread32Next(self, *_):
        return False

    def OpenThread(self, *_):
        self.calls.append("open_thread")
        return 222

    def ResumeThread(self, *_):
        self.calls.append("resume")
        if isinstance(self.resume, BaseException):
            raise self.resume
        return self.resume

    def CloseHandle(self, handle):
        self.closes.append(handle)
        self.calls.append("close_" + str(handle))
        failure = self.failures.get(handle)
        if isinstance(failure, BaseException):
            raise failure
        return failure is not False

    def TerminateJobObject(self, *_):
        self.calls.append("terminate")
        self.terminated = True
        return True

    def QueryInformationJobObject(self, _job, _kind, pointer, *_):
        self.calls.append("query")
        ctypes.cast(pointer, ctypes.POINTER(Accounting)).contents.ActiveProcesses = 0
        return True


class Stream(io.BytesIO):
    def fileno(self):
        return 7


class WindowsCleanupTest(unittest.TestCase):
    def patches(self, api, process):
        return (mock.patch.object(tree.os, "name", "nt"),
                mock.patch.object(tree, "_windows_api", return_value=(api, Limit, Accounting, Entry)),
                mock.patch.object(tree.subprocess, "Popen", return_value=process))

    def failed_spawn(self, api, process=None, expected=tree.ProcessTreeError):
        process = process or Process()
        a, b, c = self.patches(api, process)
        with a, b, c:
            try:
                tree.OwnedProcess.spawn(["synthetic-private-command"])
            except BaseException as exc:
                error = exc
            else:
                self.fail("startup unexpectedly returned success")
        self.assertIsInstance(error, expected, "startup lost its safe primary error type")
        self.assertNotIn("synthetic-private-command", str(error))
        self.assertIsInstance(getattr(error, "cleanup", None), dict,
                              "bounded spawn cleanup observations missing")
        self.assertNotIn("synthetic-private-command", json.dumps(error.cleanup))
        return error, process

    def test_positive_suspended_job_order_and_snapshot_before_thread(self):
        api, process = API(), Process()
        a, b, c = self.patches(api, process)
        with a, b, c:
            owned = tree.OwnedProcess.spawn(["synthetic"])
            result = owned.close(1)
        self.assertLess(api.calls.index("assign"), api.calls.index("resume"))
        self.assertLess(api.calls.index("close_333"), api.calls.index("open_thread"))
        self.assertTrue(result["owned_tree_no_running_members"])
        self.assertEqual([333, 222, 111], api.closes)

    def test_snapshot_false_or_exception_never_opens_thread_or_resumes(self):
        for failure in (False, OSError("synthetic-private-command"), KeyboardInterrupt()):
            api = API({333: failure})
            error, _ = self.failed_spawn(api, expected=KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else tree.ProcessTreeError)
            self.assertNotIn("open_thread", api.calls)
            self.assertNotIn("resume", api.calls)
            self.assertTrue(api.terminated)
            self.assertEqual(1, api.closes.count(333))
            self.assertFalse(error.cleanup["startup_cleanup"]["snapshot_close_confirmed"])
            self.assertFalse(error.cleanup["cleanup_complete"])

    def test_enumeration_primary_and_snapshot_secondary_are_preserved(self):
        api = API({333: False}, enumerate_ok=False)
        error, _ = self.failed_spawn(api)
        self.assertEqual("thread_snapshot_empty", str(error).split(":", 1)[0])
        self.assertIn("snapshot_close_denied", error.cleanup["cleanup_errors"])
        self.assertNotIn("open_thread", api.calls)

    def test_resumed_thread_close_false_or_exception_stops_and_cleans_job(self):
        for failure in (False, OSError("synthetic-private-command"), KeyboardInterrupt()):
            api = API({222: failure})
            error, process = self.failed_spawn(api, expected=KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else tree.ProcessTreeError)
            self.assertIn("resume", api.calls)
            self.assertTrue(api.terminated)
            self.assertIn("wait", process.calls)
            self.assertIn("query", api.calls)
            self.assertNotIn("kill", process.calls)  # No leader-only substitute for Job cleanup.
            self.assertFalse(error.cleanup["thread_close_confirmed"])
            self.assertFalse(error.cleanup["cleanup_complete"])
            self.assertEqual(1, api.closes.count(222))

    def test_resume_primary_and_thread_secondary_both_visible(self):
        api = API({222: False}, resume=0)
        error, _ = self.failed_spawn(api)
        self.assertEqual("initial_thread_resume_failed", str(error).split(":", 1)[0])
        self.assertIn("thread_close_denied", error.cleanup["cleanup_errors"])
        self.assertTrue(error.cleanup["job_assignment_confirmed"])

    def test_assign_denied_kill_failure_still_waits_and_never_infers_exit_from_job(self):
        for job_failure in (None, False, OSError("synthetic-private-command"), KeyboardInterrupt()):
            api, process = API({111: job_failure}, assign=False), Process()
            process.kill_error = process.wait_error = True
            error, _ = self.failed_spawn(api, process, expected=KeyboardInterrupt if isinstance(job_failure, KeyboardInterrupt) else tree.ProcessTreeError)
            self.assertEqual("job_assignment_denied", getattr(error, "primary_reason", str(error)).split(":", 1)[0])
            self.assertIn("wait", process.calls)
            self.assertFalse(error.cleanup["job_assignment_confirmed"])
            self.assertFalse(error.cleanup["owned_process_exited"])
            self.assertFalse(error.cleanup["owned_tree_no_running_members"])
            self.assertFalse(error.cleanup["cleanup_complete"])
            self.assertIn("leader_kill_exception", error.cleanup["cleanup_errors"])
            self.assertIn("leader_cleanup_timeout", error.cleanup["cleanup_errors"])
            self.assertEqual(job_failure is None, error.cleanup["job_close_confirmed"])
            self.assertNotIn("query", api.calls)
            self.assertNotIn("resume", api.calls)

    def test_spawn_interrupt_still_cleans_assigned_job_and_keeps_secondary(self):
        api = API({222: OSError("synthetic-private-command"), 111: False}, resume=KeyboardInterrupt())
        error, process = self.failed_spawn(api, expected=KeyboardInterrupt)
        self.assertEqual("initial_thread_resume_interrupted", error.primary_reason)
        self.assertTrue(api.terminated)
        self.assertIn("wait", process.calls)
        self.assertIn("job_close_denied", error.cleanup["cleanup_errors"])
        self.assertIn("thread_close_exception", error.cleanup["cleanup_errors"])

    def test_system_exit_retains_type_and_numeric_code_after_cleanup(self):
        api = API({222: False}, resume=SystemExit(7))
        error, process = self.failed_spawn(api, expected=SystemExit)
        self.assertEqual(7, error.code)
        self.assertEqual("initial_thread_resume_interrupted", error.primary_reason)
        self.assertTrue(api.terminated)
        self.assertIn("wait", process.calls)
        self.assertIn("thread_close_denied", error.cleanup["cleanup_errors"])

    def test_primary_system_exit_wins_over_secondary_exit_and_preserves_safe_codes(self):
        for code in (None, False, 73):
            primary = SystemExit(code)
            api = API({111: SystemExit(9)}, resume=primary)
            error, _ = self.failed_spawn(api, expected=SystemExit)
            self.assertIs(primary, error)
            self.assertIs(code, error.code)
            self.assertIn(9, error.cleanup["system_exit_codes"])
            self.assertIn("job_close_exception", error.cleanup["cleanup_errors"])

    def test_native_reason_code_and_safe_os_error_fields_are_preserved(self):
        with mock.patch.object(tree.ctypes, "get_last_error", return_value=5, create=True):
            error, _ = self.failed_spawn(API(assign=False))
        self.assertEqual("job_assignment_denied:5", str(error))
        api = API(resume=OSError(13, "synthetic-private-command"))
        error, _ = self.failed_spawn(api)
        self.assertEqual({"kind": "os_error", "errno": 13}, error.cleanup["primary_error"])

    def test_normal_close_api_exceptions_still_wait_close_and_record_unknown(self):
        for operation in ("TerminateJobObject", "QueryInformationJobObject"):
            api, process = API(), Process()
            a, b, c = self.patches(api, process)
            with a, b, c:
                owned = tree.OwnedProcess.spawn(["synthetic"])
            with mock.patch.object(api, operation, side_effect=OSError("synthetic-private-command")):
                try:
                    result = owned.close(1)
                except BaseException:
                    self.fail("normal close skipped its safe terminal result")
            self.assertIn("wait", process.calls)
            self.assertEqual(1, api.closes.count(111))
            self.assertFalse(result["cleanup_complete"])
            self.assertFalse(result["owned_tree_no_running_members"])
            self.assertNotIn("synthetic-private-command", json.dumps(result))

    def test_normal_close_interrupt_has_terminal_state_and_no_blind_retry(self):
        api, process = API(), Process()
        a, b, c = self.patches(api, process)
        with a, b, c:
            owned = tree.OwnedProcess.spawn(["synthetic"])
        api.failures[111] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught:
            owned.close(1)
        self.assertIn("wait", process.calls)
        self.assertIsInstance(getattr(caught.exception, "cleanup", None), dict,
                              "cleanup interrupt lost its terminal observations")
        self.assertFalse(caught.exception.cleanup["job_close_confirmed"])
        self.assertIsInstance(owned._closed, dict)
        self.assertFalse(owned.close(1)["cleanup_complete"])
        self.assertEqual(1, api.closes.count(111))

    def test_cleanup_interruptions_still_attempt_remaining_cleanup(self):
        for operation in ("TerminateJobObject", "QueryInformationJobObject"):
            for interruption in (KeyboardInterrupt(), SystemExit(9)):
                api = API({222: False})
                with mock.patch.object(api, operation, side_effect=interruption):
                    expected = KeyboardInterrupt if isinstance(interruption, KeyboardInterrupt) else SystemExit
                    error, process = self.failed_spawn(api, expected=expected)
                self.assertIn("wait", process.calls)
                self.assertIn(111, api.closes)
                self.assertFalse(error.cleanup["cleanup_complete"])
                self.assertTrue(error.cleanup["job_close_confirmed"])

    def test_failed_popen_does_not_claim_child_creation_or_exit_known(self):
        api = API()
        with mock.patch.object(tree.os, "name", "nt"), mock.patch.object(tree, "_windows_api", return_value=(api, Limit, Accounting, Entry)), mock.patch.object(tree.subprocess, "Popen", side_effect=OSError("synthetic-private-command")):
            try:
                tree.OwnedProcess.spawn(["synthetic-private-command"])
            except BaseException as exc:
                error = exc
            else:
                self.fail("failed Popen unexpectedly returned success")
        self.assertIsInstance(error, tree.ProcessTreeError, "Popen exception text was not sanitized")
        self.assertEqual("process_spawn_failed", str(error))
        self.assertTrue(error.cleanup["process_creation_unknown"])
        self.assertIsNone(error.cleanup["owned_process_exited"])
        self.assertFalse(error.cleanup["cleanup_complete"])

    def test_cleanup_clock_interrupt_still_closes_job(self):
        api = API({222: False})
        with mock.patch.object(tree.time, "monotonic", side_effect=KeyboardInterrupt()):
            error, process = self.failed_spawn(api, expected=KeyboardInterrupt)
        self.assertTrue(api.terminated)
        self.assertIn("wait", process.calls)
        self.assertIn(111, api.closes)
        self.assertIn("cleanup_clock_exception", error.cleanup["cleanup_errors"])

    def test_answer_review_rc0_body_cannot_return_success_after_temporary_close_failure(self):
        for handle in (333, 222):
            for failure in (False, OSError("synthetic-private-command")):
                api, process = API({handle: failure}), Process()
                process.returncode = 0
                a, b, c = self.patches(api, process)
                with a, b, c, mock.patch.object(review, "process_tree_module", return_value=tree), mock.patch.object(review.tempfile, "TemporaryFile", side_effect=Stream), mock.patch.object(review.os, "fstat", return_value=SimpleNamespace(st_size=0)):
                    with self.assertRaises(tree.ProcessTreeError):
                        review.invoke(["synthetic-private-command"], "synthetic", timeout=1)

    def test_answer_review_existing_primary_keeps_job_cleanup_cause(self):
        api, process = API({111: False}), Process()
        process.returncode = 0
        a, b, c = self.patches(api, process)
        with a, b, c, mock.patch.object(review, "process_tree_module", return_value=tree), mock.patch.object(review.tempfile, "TemporaryFile", side_effect=Stream), mock.patch.object(review.os, "fstat", side_effect=ValueError("synthetic_primary")):
            with self.assertRaisesRegex(ValueError, "synthetic_primary") as caught:
                review.invoke(["synthetic"], "synthetic", timeout=1)
        self.assertIsNotNone(caught.exception.__cause__)

    def test_answer_review_primary_is_not_replaced_by_cleanup_interrupt(self):
        api, process = API({111: KeyboardInterrupt()}), Process()
        process.returncode = 0
        a, b, c = self.patches(api, process)
        with a, b, c, mock.patch.object(review, "process_tree_module", return_value=tree), mock.patch.object(review.tempfile, "TemporaryFile", side_effect=Stream), mock.patch.object(review.os, "fstat", side_effect=ValueError("synthetic_primary")):
            try:
                review.invoke(["synthetic"], "synthetic", timeout=1)
            except BaseException as exc:
                error = exc
            else:
                self.fail("review unexpectedly returned success")
        self.assertIsInstance(error, ValueError, "cleanup interrupt replaced the original primary")
        self.assertEqual("synthetic_primary", str(error))
        self.assertIsInstance(error.__cause__, KeyboardInterrupt)
        self.assertIn("wait", process.calls)


if __name__ == "__main__":
    unittest.main()
