"""Own one bounded child process tree without third-party dependencies.

Windows starts the leader suspended, assigns it to a kill-on-close Job Object,
then resumes its sole initial thread. No child can run before assignment.
Unsupported or denied Job operations fail closed; there is no parent-only
termination fallback.
"""
from __future__ import annotations

import ctypes
import errno
import os
import signal
import struct
import subprocess
import sys
import time


class ProcessTreeError(ValueError):
    def __init__(self, reason, *, cleanup=None):
        super().__init__(reason)
        self.cleanup = cleanup


def _close_windows_handle(api, handle, role):
    try:
        return (None if api.CloseHandle(handle) else role + "_close_denied"), None
    except BaseException as exc:
        return role + "_close_exception", exc


def _remember_interrupt(cleanup, exc):
    if isinstance(exc, (KeyboardInterrupt, SystemExit)):
        cleanup.setdefault("interrupts", []).append(
            "KeyboardInterrupt" if isinstance(exc, KeyboardInterrupt) else "SystemExit")
        if isinstance(exc, SystemExit):
            code = exc.code if exc.code is None or type(exc.code) in (int, bool) else 1
            cleanup.setdefault("system_exit_code", code)
            cleanup.setdefault("system_exit_codes", []).append(code)


def _primary_observation(primary):
    kind = ("os_error" if isinstance(primary, OSError) else
            "timeout" if isinstance(primary, subprocess.TimeoutExpired) else
            "keyboard_interrupt" if isinstance(primary, KeyboardInterrupt) else
            "system_exit" if isinstance(primary, SystemExit) else "operation_error")
    result = {"kind": kind}
    for field in ("errno", "winerror"):
        value = getattr(primary, field, None)
        if type(value) is int and 0 <= value <= 0xffffffff:
            result[field] = value
    return result


def _startup_failure(primary, stage, cleanup):
    # Preserve known native reasons, never command-bearing Popen/OSError text.
    known = {"job_limit_denied", "job_assignment_denied", "initial_thread_resume_failed",
             "thread_snapshot_unavailable", "thread_snapshot_empty", "initial_thread_not_unique",
             "initial_thread_unavailable", "snapshot_close_denied", "snapshot_close_exception",
             "thread_close_denied", "thread_close_exception"}
    original_reason = (str(primary) if isinstance(primary, ProcessTreeError)
                       else getattr(primary, "primary_reason", ""))
    reason, _, code = original_reason.partition(":")
    native_reason_safe = reason in known and (
        not code or code == "unavailable" or (
            len(code) <= 10 and code.isascii() and code.isdigit() and int(code) <= 0xffffffff))
    reason = reason if reason in known else stage + (
        "_interrupted" if isinstance(primary, (KeyboardInterrupt, SystemExit)) else "_failed")
    if native_reason_safe:
        reason = original_reason
    previous = getattr(primary, "cleanup", None)
    if isinstance(previous, dict):
        cleanup["startup_cleanup"] = previous
        for error in previous.get("cleanup_errors", []):
            cleanup["cleanup_errors"].append(error)
        if previous.get("cleanup_errors"):
            cleanup["cleanup_complete"] = False
            cleanup["process_group_cleanup_error"] = (
                cleanup.get("process_group_cleanup_error") or previous["cleanup_errors"][0])
        cleanup.setdefault("interrupts", []).extend(previous.get("interrupts", []))
        if "system_exit_code" in previous:
            cleanup.setdefault("system_exit_code", previous["system_exit_code"])
        cleanup.setdefault("system_exit_codes", []).extend(previous.get("system_exit_codes", []))
    cleanup["primary_error"] = (previous.get("primary_error", _primary_observation(primary))
                                if isinstance(previous, dict) else _primary_observation(primary))
    _remember_interrupt(cleanup, primary)
    if cleanup.get("interrupts"):
        # Preserve cancellation type after all bounded cleanup, but never copy
        # arbitrary exception arguments or command-bearing exception chains.
        interruption = ("KeyboardInterrupt" if isinstance(primary, KeyboardInterrupt)
                        else "SystemExit" if isinstance(primary, SystemExit) else cleanup["interrupts"][0])
        if isinstance(primary, KeyboardInterrupt) and not primary.args:
            error = primary
        elif isinstance(primary, SystemExit) and (primary.code is None or type(primary.code) in (int, bool)):
            error = primary  # A secondary SystemExit must not replace the primary code.
        else:
            error = (KeyboardInterrupt(reason) if interruption == "KeyboardInterrupt"
                     else SystemExit(cleanup.get("system_exit_code", 1)))
        error.cleanup, error.primary_reason = cleanup, reason
        return error
    if native_reason_safe and isinstance(primary, ProcessTreeError):
        primary.cleanup = cleanup
        return primary
    return ProcessTreeError(reason, cleanup=cleanup)


def _windows_cleanup(api, job, process, accounting_type, *, assigned, timeout):
    """One deadline and one close attempt; failed/unobserved states stay explicit."""
    errors = []
    interruption_record = {}
    def interrupted(exc):
        _remember_interrupt(interruption_record, exc)
    try:
        deadline = time.monotonic() + timeout
    except BaseException as exc:
        deadline = None
        errors.append("cleanup_clock_exception")
        interrupted(exc)

    def remaining():
        if deadline is None:
            return 0
        try:
            return max(0, deadline - time.monotonic())
        except BaseException as exc:
            errors.append("cleanup_clock_exception")
            interrupted(exc)
            return 0
    leader_exited, no_members = None, None
    if assigned:
        try:
            if not api.TerminateJobObject(job, 1):
                errors.append("job_termination_denied")
        except BaseException as exc:
            errors.append("job_termination_exception")
            interrupted(exc)
    elif process is not None:
        try:
            process.kill()  # Not assigned, therefore the initial thread never ran.
        except BaseException as exc:
            errors.append("leader_kill_exception")
            interrupted(exc)
    if process is not None:
        try:
            process.wait(timeout=max(0.001, remaining()))
        except subprocess.TimeoutExpired:
            errors.append("leader_cleanup_timeout")
        except BaseException as exc:
            errors.append("leader_wait_exception")
            interrupted(exc)
        try:
            leader_exited = process.poll() is not None
        except BaseException as exc:
            errors.append("leader_poll_exception")
            interrupted(exc)
        if leader_exited is not True:
            errors.append("leader_exit_unconfirmed")
    if assigned:
        while True:
            try:
                accounting = accounting_type()
                if not api.QueryInformationJobObject(
                        job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
                    errors.append("job_query_denied")
                    break
                no_members = accounting.ActiveProcesses == 0
            except BaseException as exc:
                errors.append("job_query_exception")
                interrupted(exc)
                break
            if no_members or remaining() <= 0:
                break
            try:
                time.sleep(min(0.02, remaining()))
            except BaseException as exc:
                errors.append("job_wait_exception")
                interrupted(exc)
                break
        if no_members is not True:
            errors.append("job_members_unconfirmed")
    elif process is not None:
        # An empty unrelated Job is never evidence for this suspended leader.
        no_members = leader_exited
    close_error, close_exception = _close_windows_handle(api, job, "job")
    interrupted(close_exception)
    if close_error:
        errors.append(close_error)
    complete = (not errors and (process is None or leader_exited is True)
                and (process is None or no_members is True))
    return {"owned_process_exited": leader_exited,
            "process_group_kill_attempted": True,
            "process_group_cleanup_error": errors[0] if errors else None,
            "cleanup_errors": errors, **interruption_record, "job_assignment_confirmed": assigned,
            "job_close_confirmed": close_error is None,
            "process_created": process is not None, "cleanup_complete": complete,
            "owned_tree_empty": no_members is True and complete,
            "owned_tree_no_running_members": no_members is True and complete,
            "process_group_absent": None, "process_group_signal_denied": False,
            "process_group_query_denied": "job_query_denied" in errors,
            "escaped_descendants": "not_established"}


def _darwin_group_no_running_members(pgid):
    """Check a signalled group with libproc; zombies are not running children.

    Apple proc_info.h defines PROC_PIDT_SHORTBSDINFO=13 and SZOMB=5. An
    unavailable or incomplete read never certifies cleanup.
    """
    try:
        api = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        list_group = api.proc_listpgrppids
        list_group.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        list_group.restype = ctypes.c_int
        info = api.proc_pidinfo
        info.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                         ctypes.c_void_p, ctypes.c_int]
        info.restype = ctypes.c_int
        ctypes.set_errno(0)
        capacity = list_group(pgid, None, 0)
        if capacity == 0 and ctypes.get_errno() in (0, errno.ESRCH):
            return False  # Recheck killpg; a vanished group is not a read error.
        if capacity <= 0 or capacity > 65536:
            raise ProcessTreeError("process_group_members_unavailable")
        capacity = max(128, capacity + 64)
        members = (ctypes.c_int * capacity)()
        count = list_group(pgid, members, ctypes.sizeof(members))
        if count < 0 or count >= capacity:
            raise ProcessTreeError("process_group_members_unavailable")
        if count == 0:
            return False  # Recheck killpg; an empty snapshot is not group absence.
        for pid in set(members[:count]):
            if pid <= 0:
                raise ProcessTreeError("process_group_members_invalid")
            row = ctypes.create_string_buffer(64)  # sizeof(proc_bsdshortinfo)
            ctypes.set_errno(0)
            length = info(pid, 13, 0, row, ctypes.sizeof(row))
            if length == 0 and ctypes.get_errno() == errno.ESRCH:
                continue  # Already exited; libproc no longer exposes its state.
            if length != ctypes.sizeof(row):
                raise ProcessTreeError("process_group_state_unavailable")
            actual_pid, _ppid, actual_pgid, status = struct.unpack_from("=IIII", row)
            if actual_pid != pid or actual_pgid != pgid or status not in range(1, 6):
                raise ProcessTreeError("process_group_state_invalid")
            if status != 5:
                return False
        return True
    except (AttributeError, OSError) as exc:
        raise ProcessTreeError("process_group_state_unavailable") from exc


def _windows_api():
    from ctypes import wintypes as w

    class BasicLimit(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", w.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", w.DWORD), ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in
                    ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                     "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class ExtendedLimit(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BasicLimit), ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    class BasicAccounting(ctypes.Structure):
        _fields_ = [("TotalUserTime", ctypes.c_longlong),
                    ("TotalKernelTime", ctypes.c_longlong),
                    ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                    ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                    ("TotalPageFaultCount", w.DWORD), ("TotalProcesses", w.DWORD),
                    ("ActiveProcesses", w.DWORD), ("TotalTerminatedProcesses", w.DWORD)]

    class ThreadEntry(ctypes.Structure):
        _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD),
                    ("th32ThreadID", w.DWORD), ("th32OwnerProcessID", w.DWORD),
                    ("tpBasePri", w.LONG), ("tpDeltaPri", w.LONG), ("dwFlags", w.DWORD)]

    api = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateJobObjectW": (w.HANDLE, [ctypes.c_void_p, w.LPCWSTR]),
        "SetInformationJobObject": (w.BOOL, [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]),
        "AssignProcessToJobObject": (w.BOOL, [w.HANDLE, w.HANDLE]),
        "TerminateJobObject": (w.BOOL, [w.HANDLE, w.UINT]),
        "QueryInformationJobObject": (w.BOOL, [w.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                w.DWORD, ctypes.c_void_p]),
        "CreateToolhelp32Snapshot": (w.HANDLE, [w.DWORD, w.DWORD]),
        "Thread32First": (w.BOOL, [w.HANDLE, ctypes.POINTER(ThreadEntry)]),
        "Thread32Next": (w.BOOL, [w.HANDLE, ctypes.POINTER(ThreadEntry)]),
        "OpenThread": (w.HANDLE, [w.DWORD, w.BOOL, w.DWORD]),
        "ResumeThread": (w.DWORD, [w.HANDLE]),
        "CloseHandle": (w.BOOL, [w.HANDLE]),
    }
    for name, (result, arguments) in signatures.items():
        function = getattr(api, name)
        function.restype, function.argtypes = result, arguments
    return api, ExtendedLimit, BasicAccounting, ThreadEntry


def _win_error(reason):
    code = getattr(ctypes, "get_last_error", lambda: "unavailable")()
    raise ProcessTreeError(reason + ":" + str(code))


def _initial_thread(api, entry_type, pid):
    snapshot = api.CreateToolhelp32Snapshot(0x00000004, 0)
    if not snapshot or int(snapshot) == ctypes.c_void_p(-1).value:
        _win_error("thread_snapshot_unavailable")
    primary = None
    try:
        entry = entry_type()
        entry.dwSize = ctypes.sizeof(entry)
        matches = []
        if not api.Thread32First(snapshot, ctypes.byref(entry)):
            _win_error("thread_snapshot_empty")
        while True:
            if entry.th32OwnerProcessID == pid:
                matches.append(entry.th32ThreadID)
            if not api.Thread32Next(snapshot, ctypes.byref(entry)):
                break
        if len(matches) != 1:
            raise ProcessTreeError("initial_thread_not_unique")
    except BaseException as exc:
        primary = exc
    close_error, close_exception = _close_windows_handle(api, snapshot, "snapshot")
    if primary is not None or close_error:
        cleanup = {"snapshot_close_confirmed": close_error is None,
                   "cleanup_errors": [close_error] if close_error else []}
        _remember_interrupt(cleanup, close_exception)
        raise _startup_failure(primary or close_exception or ProcessTreeError(close_error),
                               "thread_enumeration", cleanup) from None
    # Do not acquire a thread handle until snapshot close is confirmed. This
    # removes the former finally-raises path that lost an already-open thread.
    thread = api.OpenThread(0x0002, False, matches[0])
    if not thread:
        _win_error("initial_thread_unavailable")
    return thread


class OwnedProcess:
    def __init__(self, process, *, api=None, job=None, accounting_type=None):
        self.process, self.api, self.job = process, api, job
        self.accounting_type = accounting_type
        self._closed = None

    @classmethod
    def spawn(cls, command, **kwargs):
        if os.name == "posix":
            return cls(subprocess.Popen(command, start_new_session=True, **kwargs))
        if os.name != "nt":
            raise ProcessTreeError("bounded_process_tree_route_unavailable")
        api, limit_type, accounting_type, entry_type = _windows_api()
        job = api.CreateJobObjectW(None, None)
        if not job:
            _win_error("job_creation_denied")
        process, assigned = None, False
        stage = "job_limit"
        thread_close_error = thread_close_exception = None
        try:
            limit = limit_type()
            limit.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
            if not api.SetInformationJobObject(job, 9, ctypes.byref(limit), ctypes.sizeof(limit)):
                _win_error("job_limit_denied")
            flags = kwargs.pop("creationflags", 0)
            stage = "process_spawn"
            process = subprocess.Popen(command, creationflags=flags | 0x00000004, **kwargs)
            stage = "job_assignment"
            if not api.AssignProcessToJobObject(job, int(process._handle)):
                _win_error("job_assignment_denied")
            assigned = True
            stage = "initial_thread"
            thread = _initial_thread(api, entry_type, process.pid)
            primary = None
            try:
                stage = "initial_thread_resume"
                if api.ResumeThread(thread) != 1:
                    _win_error("initial_thread_resume_failed")
            except BaseException as exc:
                primary = exc
            thread_close_error, thread_close_exception = _close_windows_handle(api, thread, "thread")
            if primary is not None:
                raise primary
            if thread_close_error:
                if isinstance(thread_close_exception, (KeyboardInterrupt, SystemExit)):
                    raise thread_close_exception
                raise ProcessTreeError(thread_close_error)
            return cls(process, api=api, job=job, accounting_type=accounting_type)
        except BaseException as exc:
            cleanup = _windows_cleanup(api, job, process, accounting_type,
                                       assigned=assigned, timeout=3)
            if stage == "process_spawn" and process is None:
                cleanup["process_creation_unknown"] = True
                cleanup["cleanup_complete"] = False
            if thread_close_error:
                cleanup["thread_close_confirmed"] = False
                cleanup["cleanup_errors"].append(thread_close_error)
                cleanup["cleanup_complete"] = False
                cleanup["process_group_cleanup_error"] = (
                    cleanup["process_group_cleanup_error"] or thread_close_error)
                _remember_interrupt(cleanup, thread_close_exception)
            raise _startup_failure(exc, stage, cleanup) from None

    def close(self, timeout):
        if self._closed is not None:
            return dict(self._closed)
        if type(timeout) not in (int, float) or timeout <= 0:
            raise ProcessTreeError("invalid_cleanup_deadline")
        if self.job is not None:
            self._closed = _windows_cleanup(self.api, self.job, self.process,
                                             self.accounting_type, assigned=True, timeout=timeout)
            self.job = None  # Terminal observation is cached; never blindly close again.
            if self._closed.get("interrupts"):
                raise _startup_failure(None, "process_cleanup", self._closed) from None
            return dict(self._closed)
        deadline = time.monotonic() + timeout
        error = None
        tree_empty = False
        no_running_members = False
        signal_denied = False
        query_denied = False
        posix_group = True
        signal_delivered = False
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
            signal_delivered = True
        except ProcessLookupError:
            pass
        except PermissionError:
            signal_denied = True
            error = "process_group_signal_denied"
        try:
            self.process.wait(timeout=min(1, max(0.001, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
            signal_delivered = True
        except ProcessLookupError:
            tree_empty = True
            no_running_members = True
        except PermissionError:
            signal_denied = True
            if not signal_delivered:
                error = "process_group_signal_denied"
        while not tree_empty and error is None and time.monotonic() < deadline:
            try:
                os.killpg(self.process.pid, 0)
            except ProcessLookupError:
                tree_empty = True
                no_running_members = True
            except PermissionError:
                query_denied = True
                if sys.platform != "darwin" or not signal_delivered:
                    error = "process_group_query_denied"
            if sys.platform == "darwin" and not tree_empty and error is None:
                try:
                    no_running_members = _darwin_group_no_running_members(
                        self.process.pid)
                except ProcessTreeError as exc:
                    error = str(exc)
                if no_running_members:
                    break
            time.sleep(0.02)
        if not tree_empty and not no_running_members and error is None:
            if signal_denied:
                error = "process_group_signal_denied"
            elif query_denied:
                error = "process_group_query_denied"
        try:
            self.process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            error = error or "leader_cleanup_timeout"
        self._closed = {
            "owned_process_exited": self.process.poll() is not None,
            "process_group_kill_attempted": True,
            "process_group_cleanup_error": error,
            "owned_tree_empty": tree_empty and error is None,
            "owned_tree_no_running_members": no_running_members and error is None,
            "process_group_absent": tree_empty if posix_group else None,
            "process_group_signal_denied": signal_denied,
            "process_group_query_denied": query_denied,
            "escaped_descendants": "not_established",
        }
        return dict(self._closed)
