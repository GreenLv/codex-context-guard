"""Own one bounded child process tree without third-party dependencies.

Windows starts the leader suspended, assigns it to a kill-on-close Job Object,
then resumes its sole initial thread. No child can run before assignment.
Unsupported or denied Job operations fail closed; there is no parent-only
termination fallback.
"""
from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import time


class ProcessTreeError(ValueError):
    pass


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
        thread = api.OpenThread(0x0002, False, matches[0])
        if not thread:
            _win_error("initial_thread_unavailable")
        return thread
    finally:
        api.CloseHandle(snapshot)


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
        process = None
        try:
            limit = limit_type()
            limit.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
            if not api.SetInformationJobObject(job, 9, ctypes.byref(limit), ctypes.sizeof(limit)):
                _win_error("job_limit_denied")
            flags = kwargs.pop("creationflags", 0)
            process = subprocess.Popen(command, creationflags=flags | 0x00000004, **kwargs)
            if not api.AssignProcessToJobObject(job, int(process._handle)):
                _win_error("job_assignment_denied")
            thread = _initial_thread(api, entry_type, process.pid)
            try:
                if api.ResumeThread(thread) != 1:
                    _win_error("initial_thread_resume_failed")
            finally:
                api.CloseHandle(thread)
            return cls(process, api=api, job=job, accounting_type=accounting_type)
        except BaseException:
            if process is not None:
                try:
                    process.kill()  # Initial thread is still suspended on failure.
                    process.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            api.CloseHandle(job)
            raise

    def close(self, timeout):
        if self._closed is not None:
            return dict(self._closed)
        if type(timeout) not in (int, float) or timeout <= 0:
            raise ProcessTreeError("invalid_cleanup_deadline")
        deadline = time.monotonic() + timeout
        error = None
        tree_empty = False
        if self.job is not None:
            try:
                if not self.api.TerminateJobObject(self.job, 1):
                    _win_error("job_termination_denied")
                while time.monotonic() < deadline:
                    accounting = self.accounting_type()
                    if not self.api.QueryInformationJobObject(
                            self.job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
                        _win_error("job_query_denied")
                    if accounting.ActiveProcesses == 0:
                        tree_empty = True
                        break
                    time.sleep(0.02)
            except ProcessTreeError as exc:
                error = str(exc).split(":", 1)[0]
            finally:
                if not self.api.CloseHandle(self.job):
                    error = error or "job_close_denied"
                self.job = None
        else:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError:
                error = "process_group_signal_denied"
            try:
                self.process.wait(timeout=min(1, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                tree_empty = True
            except PermissionError:
                error = "process_group_signal_denied"
            while not tree_empty and error is None and time.monotonic() < deadline:
                try:
                    os.killpg(self.process.pid, 0)
                except ProcessLookupError:
                    tree_empty = True
                except PermissionError:
                    error = "process_group_query_denied"
                else:
                    time.sleep(0.02)
        try:
            self.process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            error = error or "leader_cleanup_timeout"
        self._closed = {
            "owned_process_exited": self.process.poll() is not None,
            "process_group_kill_attempted": True,
            "process_group_cleanup_error": error,
            "owned_tree_empty": tree_empty and error is None,
            "escaped_descendants": "not_established",
        }
        return dict(self._closed)
