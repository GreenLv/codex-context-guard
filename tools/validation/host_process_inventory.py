"""Read-only host process inventory by executable identity and parentage.

Distinguishes the pinned Desktop host executable, its descendant helpers,
pinned sandbox-service executables and unrelated processes. Identification
uses full executable paths and parent-child links for positive identity.
On Windows, a complete OS image-name snapshot can exclude an image whose
exact basename differs from the pinned executable; a matching basename
never proves identity. No fuzzy names, window titles, or operator declaration
such as ``--host-stopped`` can establish absence. An
unreadable identity or an incomplete enumeration is reported as unknown and
never as absence.

Owner rules are structural, not name-based. A process whose identity cannot
be read is still excluded from Desktop candidacy when it provably cannot be
the invoking user's GUI host: on POSIX it is owned by another uid, and on
Windows it is the kernel family (pid 0 or 4, or parent pid 4) or a guarded
snapshot proves a different executable basename.
Every other unreadable row keeps Desktop candidacy and the inventory status
becomes ``unknown``.

Privacy: per-process executable paths are retained only for rows that the
decision actually consumes (Desktop host, its descendants, pinned sandbox
services). Unrelated rows contribute counts only.
"""
from __future__ import annotations

import ctypes
import ntpath
import os
import posixpath
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA = "cg-host-process-inventory/v1"
MAX_PROCESSES = 100000
COMMAND_TIMEOUT = 30.0

IDENTITY_OBSERVED = "observed"
IDENTITY_UNREADABLE = "unreadable"

CLASS_DESKTOP = "desktop_host"
CLASS_DESCENDANT = "desktop_descendant"
CLASS_SANDBOX = "sandbox_service"
CLASS_SYSTEM = "system_kernel"
CLASS_UNREADABLE = "unreadable"
CLASS_UNRELATED = "unrelated"


class InventoryError(ValueError):
    pass


def _require(value, message):
    if not value:
        raise InventoryError(message)


def _normalize(path: str, *, windows: bool) -> str:
    """Path semantics follow the enumeration source, not the running host."""
    if windows:
        return ntpath.normpath(path.replace("/", "\\")).casefold()
    return posixpath.normpath(path)


def _readable_int(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 2**31 - 1 else None


# ---------------------------------------------------------------- POSIX ----

_DARWIN_LIBPROC = "/usr/lib/libproc.dylib"
# Apple proc_info.h: PROC_PIDT_SHORTBSDINFO = 13, SZOMB = 5 (see also
# scripts/cg_process_tree.py, which uses the same bindings for owned trees).
_PROC_PIDT_SHORTBSDINFO = 13
_BSD_SHORT_SIZE = 64


def _darwin_pids() -> list[int]:
    api = ctypes.CDLL(_DARWIN_LIBPROC, use_errno=True)
    listall = api.proc_listallpids
    listall.argtypes = [ctypes.c_void_p, ctypes.c_int]
    listall.restype = ctypes.c_int
    ctypes.set_errno(0)
    capacity = listall(None, 0)
    if capacity <= 0 or capacity > MAX_PROCESSES:
        raise InventoryError("process_list_unavailable")
    buffer = (ctypes.c_int * (capacity + 64))()
    count = listall(buffer, ctypes.sizeof(buffer))
    if count <= 0 or count > len(buffer):
        raise InventoryError("process_list_unavailable")
    return [int(pid) for pid in buffer[:count] if pid > 0]


def _darwin_executable(pid: int) -> str | None:
    """Full executable path for a pid, or None when unreadable/unavailable.

    A live same-user process whose ``proc_pidpath`` returns ENOENT is an
    external state (observed natively, r-series) and stays an unreadable
    candidate here. The ``ps`` comm column reports ``argv[0]`` (per Apple's
    print.c), not the image identity, so it is never used as a fallback;
    no process-name or argument guessing is performed.
    """
    api = ctypes.CDLL(_DARWIN_LIBPROC, use_errno=True)
    pidpath = api.proc_pidpath
    pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    pidpath.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(os.pathconf("/", "PC_PATH_MAX"))
    length = pidpath(pid, buffer, len(buffer))
    if length <= 0:
        return None
    try:
        return buffer.value.decode("utf-8", "surrogateescape")
    except ValueError:  # pragma: no cover - defensive
        return None


_PS_ARGUMENTS = ["-axww", "-o", "pid=,ppid=,uid="]


def _ps_rows(ps: str) -> list[dict]:
    """pid/ppid/uid rows from a read-only ps query (POSIX fallback source)."""
    result = subprocess.run([ps, *_PS_ARGUMENTS], capture_output=True,
                            timeout=COMMAND_TIMEOUT)
    if result.returncode != 0:
        raise InventoryError("process_list_unavailable")
    rows = []
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 3 or any(not re.fullmatch(r"\d+", field) for field in fields):
            raise InventoryError("enumeration_output_unparsable")
        rows.append({"pid": int(fields[0]), "ppid": int(fields[1]), "uid": int(fields[2])})
    return rows


def _enumerate_darwin(ps: str | None = None) -> dict:
    resolved = ps or shutil.which("ps")
    if resolved is None:
        raise InventoryError("ps_unavailable")
    ps = resolved
    rows = _ps_rows(ps)
    pids = set(_darwin_pids())
    # The ps snapshot and the libproc snapshot are two bounded reads; a pid
    # present in one but not the other exited in between and is recorded as
    # unreadable rather than silently dropped.
    for row in rows:
        pid = row["pid"]
        if pid not in pids:
            row.update({"executable": None, "identity": IDENTITY_UNREADABLE})
            continue
        executable = _darwin_executable(pid)
        row.update({"executable": executable,
                    "identity": IDENTITY_OBSERVED if executable else IDENTITY_UNREADABLE})
    missing = pids - {row["pid"] for row in rows}
    for pid in sorted(missing):
        rows.append({"pid": pid, "ppid": None, "uid": None,
                     "executable": None, "identity": IDENTITY_UNREADABLE})
    return {"source": "darwin-ps-libproc", "ps_path": ps, "ps_arguments": _PS_ARGUMENTS,
            "observer_uid": os.getuid(), "rows": rows}


def _enumerate_linux() -> dict:
    rows = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        row: dict = {"pid": pid, "ppid": None, "uid": None,
                     "executable": None, "identity": IDENTITY_UNREADABLE}
        try:
            stat_text = Path("/proc", entry, "stat").read_text(encoding="utf-8", errors="replace")
            tail = stat_text.rsplit(")", 1)
            if len(tail) == 2:
                fields = tail[1].split()
                row["ppid"] = int(fields[1])
            row["uid"] = Path("/proc", entry).stat().st_uid
            executable = os.readlink(Path("/proc", entry, "exe"))
            row["executable"] = executable
            row["identity"] = IDENTITY_OBSERVED
        except (OSError, ValueError, IndexError):
            pass
        rows.append(row)
    if not rows:
        raise InventoryError("process_list_unavailable")
    return {"source": "linux-proc", "observer_uid": os.getuid(), "rows": rows}


# -------------------------------------------------------------- Windows ----

_WIN_SNAPSHOT_ALL = 0x00000002          # TH32CS_SNAPPROCESS
_WIN_QUERY_LIMITED = 0x1000             # PROCESS_QUERY_LIMITED_INFORMATION
_WIN_ERROR_NO_MORE_FILES = 18
_WIN_MAX_PATH = 260                     # PROCESSENTRY32W.szExeFile capacity
_WIN_IMAGE_BUFFER = 1024
_WIN_CANDIDATE_LIMIT = 64
_WIN_TRUNCATION_GUARD = _WIN_MAX_PATH - 1


class _ProcessEntry32W(ctypes.Structure):
    """Microsoft PROCESSENTRY32W: pid, parent pid and the image file name."""

    _fields_ = [("dwSize", ctypes.c_ulong),
                ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", ctypes.c_ulong),
                ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong),
                ("szExeFile", ctypes.c_wchar * _WIN_MAX_PATH)]


def _windows_kernel32():
    """The real kernel32 binding; tests inject a fake api object instead."""
    if os.name != "nt":
        raise InventoryError("windows_route_unavailable")
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateToolhelp32Snapshot": (ctypes.c_void_p, [ctypes.c_ulong, ctypes.c_ulong]),
        "Process32FirstW": (ctypes.c_int, [ctypes.c_void_p, ctypes.POINTER(_ProcessEntry32W)]),
        "Process32NextW": (ctypes.c_int, [ctypes.c_void_p, ctypes.POINTER(_ProcessEntry32W)]),
        "OpenProcess": (ctypes.c_void_p, [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]),
        "QueryFullProcessImageNameW": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_ulong,
                                                      ctypes.POINTER(ctypes.c_wchar),
                                                      ctypes.POINTER(ctypes.c_ulong)]),
        "CloseHandle": (ctypes.c_int, [ctypes.c_void_p]),
    }
    for name, (result, arguments) in signatures.items():
        function = getattr(api, name)
        function.restype, function.argtypes = result, arguments
    api.get_last_error = ctypes.get_last_error  # portable error channel
    return api


def _last_error(api) -> int:
    """The api's error channel; fake apis carry their own."""
    return api.get_last_error()


def _windows_snapshot_rows(api, label) -> list[tuple[int, int, str]]:
    """One complete system snapshot; an incomplete walk or an unclosed
    snapshot handle fails the whole enumeration, never a partial table."""
    handle = api.CreateToolhelp32Snapshot(_WIN_SNAPSHOT_ALL, 0)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise InventoryError(label + "_unavailable")
    rows: list[tuple[int, int, str]] = []
    seen = set()
    try:
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not api.Process32FirstW(handle, ctypes.byref(entry)):
            raise InventoryError(label + "_unavailable_or_empty")
        while True:
            _require(len(rows) < MAX_PROCESSES, "windows_process_snapshot_oversized")
            pid = int(entry.th32ProcessID)
            _require(pid not in seen, "windows_process_snapshot_duplicate_pid")
            seen.add(pid)
            rows.append((pid, int(entry.th32ParentProcessID),
                         str(entry.szExeFile)))
            if not api.Process32NextW(handle, ctypes.byref(entry)):
                _require(_last_error(api) == _WIN_ERROR_NO_MORE_FILES,
                         label + "_walk_incomplete")
                break
    finally:
        if not api.CloseHandle(handle):
            raise InventoryError(label + "_handle_close_failed")
    return rows


def _windows_image_path(api, pid) -> str | None:
    """Full image path for one bounded candidate; a failure keeps candidacy."""
    handle = api.OpenProcess(_WIN_QUERY_LIMITED, 0, pid)
    if not handle or handle == ctypes.c_void_p(-1).value:
        return None
    try:
        size = ctypes.c_ulong(_WIN_IMAGE_BUFFER)
        buffer = ctypes.create_unicode_buffer(_WIN_IMAGE_BUFFER)
        if not api.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        if size.value >= _WIN_IMAGE_BUFFER:
            return None  # a full buffer is a possibly truncated identity
        return buffer.value
    finally:
        if not api.CloseHandle(handle):
            raise InventoryError("image_path_handle_close_failed")


def _usable_windows_basename(name) -> bool:
    return (isinstance(name, str) and 0 < len(name) < _WIN_TRUNCATION_GUARD
            and name not in (".", "..")
            and not any(char in '\\/:<>"|?*' or ord(char) < 32 for char in name))


def windows_candidate_basenames(desktop_executables, sandbox_markers=()) -> set:
    """Casefolded basenames of the pinned identities, under Toolhelp capacity."""
    names = set()
    for path in (*desktop_executables, *sandbox_markers):
        basename = ntpath.basename(str(path))
        _require(_usable_windows_basename(basename),
                 "pinned_identity_basename_unavailable_or_exceeds_toolhelp_capacity")
        names.add(ntpath.normcase(basename))
    return names


def _enumerate_windows(candidate_basenames: set | None = None, api: Any = None) -> dict:
    """One Windows observation, per the guarded design review:

    - one complete Toolhelp snapshot provides pid/ppid/image basename for
      every process without elevation, across sessions;
    - a usable basename that differs from every pinned candidate basename is
      necessary-condition negative evidence for that exact pinned image only;
    - same-basename rows are candidates: a second complete snapshot must
      confirm the pid still reports the same basename (PID-reuse guard) and
      only then a bounded QueryFullProcessImageName read may prove identity;
    - unreadable, truncated, separator-bearing or shape-anomalous names and
      unreadable image paths keep Desktop candidacy (unknown); they never
      become absence. WMI Name never participates.
    """
    api = api or _windows_kernel32()
    candidates = {ntpath.normcase(name) for name in (candidate_basenames or set())}
    first = _windows_snapshot_rows(api, "windows_process_snapshot")
    rows: list[dict] = []
    candidate_pids: dict[int, str] = {}
    for pid, ppid, name in first:
        row = {"pid": pid, "ppid": ppid, "executable": None, "exe_name": None,
               "uid": None, "identity": IDENTITY_UNREADABLE}
        if _usable_windows_basename(name):
            row["exe_name"] = name
            if ntpath.normcase(name) in candidates:
                candidate_pids[pid] = name
        rows.append(row)
    _require(len(candidate_pids) <= _WIN_CANDIDATE_LIMIT,
             "pinned identity basename matches too many live images; pin a more specific executable")
    reads = {"ok": 0, "failed": 0}
    if candidate_pids:
        # PID-reuse guard: the pid must still report the same basename in a
        # second complete snapshot before any full-path read is trusted.
        second = _windows_snapshot_rows(api, "windows_candidate_snapshot")
        second_names = {pid: ntpath.normcase(name) for pid, _ppid, name in second
                        if _usable_windows_basename(name)}
        for row in rows:
            pid = row["pid"]
            if (pid not in candidate_pids
                    or second_names.get(pid) != ntpath.normcase(candidate_pids[pid])):
                continue  # the pid changed identity between snapshots
            # This helper owns and closes its one handle, including failures.
            path = _windows_image_path(api, pid)
            if path:
                row["executable"] = path
                row["identity"] = IDENTITY_OBSERVED
                reads["ok"] += 1
            else:
                reads["failed"] += 1
    return {"source": "windows-toolhelp",
            "snapshot": {"snapshots": 2 if candidate_pids else 1,
                         "processes": len(first),
                         "candidates": len(candidate_pids),
                         "image_path_reads": reads},
            "rows": rows}


# ------------------------------------------------------------- classify ----

def enumerate_processes(ps: str | None = None,
                        candidate_basenames: set | None = None) -> dict:
    """One bounded read-only enumeration. Never raises for host conditions.

    The pinned ``ps`` executable from the subject identity is consumed on
    darwin instead of a fresh PATH re-resolution; the actually used
    executable and arguments are reported in the payload. Windows uses one
    complete Toolhelp snapshot plus the guarded candidate full-path reads
    (see ``_enumerate_windows``). A failed enumeration returns status
    ``failed`` with a reason; it is the caller's contract to treat that as
    unknown, never as absence.
    """
    if os.name == "nt":
        route = lambda: _enumerate_windows(candidate_basenames)  # noqa: E731 - closed over the pinned candidates
    elif sys.platform == "darwin":
        route = lambda: _enumerate_darwin(ps)  # noqa: E731 - closed over the pinned ps
    elif os.name == "posix":
        route = _enumerate_linux
    else:
        return {"status": "failed", "reason": "platform_route_unavailable",
                "source": None, "rows": []}
    try:
        payload = route()
    except (InventoryError, OSError, subprocess.SubprocessError) as exc:
        return {"status": "failed", "reason": type(exc).__name__ if not isinstance(exc, InventoryError) else str(exc),
                "source": None, "rows": []}
    return {"status": "observed", "reason": None, **payload}


def _kernel_family(row: dict, source: str, observer_uid: int | None) -> bool:
    """Structural rule: this unreadable row cannot be the invoking user's GUI host.

    Windows: the kernel family (pid 0 System Idle or pid 4 System, or a
    direct System child with parent pid 4). POSIX: any owner other than the
    enumeration's own ``observer_uid`` — a
    process owned by another uid cannot be that observer's Desktop host. No
    platform-specific call happens here, so synthetic classifications run on
    every platform; a row without owner evidence or without an observed
    observer uid keeps Desktop candidacy.
    """
    if source == "windows-toolhelp":
        pid, ppid = row.get("pid"), row.get("ppid")
        return pid is not None and ppid is not None and (pid in (0, 4) or ppid == 4)
    uid = row.get("uid")
    return uid is not None and observer_uid is not None and uid != observer_uid


def classify(enumeration: dict, desktop_executables, sandbox_markers=()) -> dict:
    """Classify one enumeration against exact pinned executable identities.

    ``desktop_executables`` and ``sandbox_markers`` are exact absolute paths.
    Comparison uses the path semantics of the enumeration source (Windows
    case-insensitive for ``windows-toolhelp``, POSIX-sensitive otherwise). No
    broad name matching is performed.
    """
    _require(isinstance(enumeration, dict), "enumeration shape invalid")
    source = enumeration.get("source")
    windows = source == "windows-toolhelp"
    if enumeration.get("status") == "failed":
        return {"schema": SCHEMA, "status": "unknown", "reason": enumeration.get("reason"),
                "enumeration": {"status": "failed", "source": source, "process_count": 0},
                "pinned": {"desktop_executables": sorted(_normalize(str(p), windows=windows)
                                                         for p in desktop_executables),
                           "sandbox_markers": sorted(_normalize(str(p), windows=windows)
                                                     for p in sandbox_markers)},
                "counts": {}, "desktop_host_processes": [], "sandbox_service_processes": [],
                "desktop_descendant_processes": [], "unreadable_processes": []}
    _require(enumeration.get("status") == "observed", "enumeration incomplete")
    rows = enumeration.get("rows")
    _require(isinstance(rows, list) and len(rows) <= MAX_PROCESSES, "enumeration rows invalid")
    pids = set()
    for row in rows:
        _require(isinstance(row, dict), "enumeration row invalid")
        pid = _readable_int(row.get("pid"))
        _require(pid is not None and pid >= 0, "enumeration pid invalid")
        _require(pid not in pids, "duplicate pid in enumeration")
        pids.add(pid)

    desktop = {_normalize(str(path), windows=windows) for path in desktop_executables}
    sandbox = {_normalize(str(path), windows=windows) for path in sandbox_markers}
    _require(not (desktop & sandbox), "desktop and sandbox identities overlap")
    # Toolhelp necessary-condition negative evidence: a usable snapshot
    # basename that differs from every pinned candidate basename excludes the
    # row only from those exact pinned images. Same-name rows and rows
    # without usable name evidence keep Desktop candidacy (unknown).
    desktop_basenames = set()
    sandbox_basenames = set()
    if source == "windows-toolhelp":
        desktop_basenames = windows_candidate_basenames(desktop_executables)
        sandbox_basenames = windows_candidate_basenames(sandbox_markers)

    by_pid = {row["pid"]: row for row in rows}

    def readable_executable(pid):
        row = by_pid.get(pid)
        if row is None or row.get("identity") != IDENTITY_OBSERVED:
            return None
        return row.get("executable")

    def descendant_of_desktop(row) -> bool | None:
        """True/False when the parent chain resolves; None when it cannot.

        A parent pid absent from the snapshot means that parent already
        exited: the chain is resolved as 'no living Desktop ancestor'.
        """
        seen = {row["pid"]}
        current = row.get("ppid")
        while current is not None:
            if current in seen:
                return None
            seen.add(current)
            parent = by_pid.get(current)
            if parent is None:
                return False
            executable = readable_executable(current)
            if executable is not None and _normalize(executable, windows=windows) in desktop:
                return True
            current = parent.get("ppid")
        return False

    observer_uid = enumeration.get("observer_uid")
    _require(observer_uid is None or _readable_int(observer_uid) == observer_uid,
             "enumeration observer uid invalid")
    counts = {CLASS_DESKTOP: 0, CLASS_DESCENDANT: 0, CLASS_SANDBOX: 0,
              CLASS_SYSTEM: 0, CLASS_UNREADABLE: 0, CLASS_UNRELATED: 0}
    desktop_rows, sandbox_rows, descendant_rows, unreadable_rows = [], [], [], []
    unverified_sandbox = []
    for row in rows:
        executable = row.get("executable")
        observed = row.get("identity") == IDENTITY_OBSERVED and executable
        if observed and _normalize(executable, windows=windows) in desktop:
            counts[CLASS_DESKTOP] += 1
            desktop_rows.append({"pid": row["pid"], "ppid": row.get("ppid"),
                                 "executable": executable})
            continue
        if observed and _normalize(executable, windows=windows) in sandbox:
            counts[CLASS_SANDBOX] += 1
            sandbox_rows.append({"pid": row["pid"], "ppid": row.get("ppid"),
                                 "executable": executable})
            continue
        if observed:
            if descendant_of_desktop(row) is True:
                counts[CLASS_DESCENDANT] += 1
                descendant_rows.append({"pid": row["pid"], "ppid": row.get("ppid"),
                                        "executable": executable})
            else:
                counts[CLASS_UNRELATED] += 1
            continue
        # Unreadable identity. Exclude kernel-family rows structurally; a
        # row that descends from a living Desktop host is its descendant
        # even without a readable path; everything else keeps Desktop
        # candidacy and forces status unknown.
        if descendant_of_desktop(row) is True:
            counts[CLASS_DESCENDANT] += 1
            descendant_rows.append({"pid": row["pid"], "ppid": row.get("ppid"),
                                    "executable": None})
            continue
        if _kernel_family(row, source, observer_uid):
            counts[CLASS_SYSTEM] += 1
            continue
        name = row.get("exe_name")
        if source == "windows-toolhelp" and _usable_windows_basename(name) \
                and ntpath.normcase(name) not in desktop_basenames:
            if ntpath.normcase(name) in sandbox_basenames:
                unverified_sandbox.append({"pid": row["pid"], "ppid": row.get("ppid")})
            counts[CLASS_UNRELATED] += 1
            continue
        counts[CLASS_UNREADABLE] += 1
        unreadable_rows.append({"pid": row["pid"], "ppid": row.get("ppid")})

    if counts[CLASS_DESKTOP]:
        status, reason = "running", None
    elif counts[CLASS_UNREADABLE]:
        status, reason = "unknown", "unreadable process identities keep Desktop candidacy"
    else:
        status, reason = "absent", None
    return {"schema": SCHEMA, "status": status, "reason": reason,
            "enumeration": {"status": "observed", "source": source,
                            "process_count": len(rows),
                            **{key: value for key, value in enumeration.items()
                               if key in ("ps_path", "ps_arguments", "powershell", "snapshot")}},
            "pinned": {"desktop_executables": sorted(desktop),
                       "sandbox_markers": sorted(sandbox)},
            "counts": counts, "desktop_host_processes": desktop_rows,
            "sandbox_service_processes": sandbox_rows,
            "unverified_sandbox_candidates": unverified_sandbox,
            "desktop_descendant_processes": descendant_rows,
            "unreadable_processes": unreadable_rows}
