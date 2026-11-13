"""Read-only host process inventory by executable identity and parentage.

Distinguishes the pinned Desktop host executable, its descendant helpers,
pinned sandbox-service executables and unrelated processes. Identification
uses executable paths and parent-child links only — never process names,
window titles, or any operator declaration such as ``--host-stopped``. An
unreadable identity or an incomplete enumeration is reported as unknown and
never as absence.

Owner rules are structural, not name-based. A process whose identity cannot
be read is still excluded from Desktop candidacy when it provably cannot be
the invoking user's GUI host: on POSIX it is owned by another uid, and on
Windows it is the kernel family (pid or parent pid <= 4, the System process).
Every other unreadable row keeps Desktop candidacy and the inventory status
becomes ``unknown``.

Privacy: per-process executable paths are retained only for rows that the
decision actually consumes (Desktop host, its descendants, pinned sandbox
services). Unrelated rows contribute counts only.
"""
from __future__ import annotations

import ctypes
import json
import ntpath
import os
import posixpath
import re
import shutil
import subprocess
import sys
from pathlib import Path

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
    """Full executable path for a pid, or None when unreadable/unavailable."""
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

_CIM_SCRIPT = (
    "$ErrorActionPreference = 'Stop'\n"
    "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n"
    "$rows = @(Get-CimInstance -ClassName Win32_Process | ForEach-Object { "
    "[ordered]@{ pid = $_.ProcessId; ppid = $_.ParentProcessId; exe = $_.ExecutablePath } })\n"
    "ConvertTo-Json -InputObject $rows -Compress\n"
)


def _enumerate_windows(powershell: str | None) -> dict:
    shell = powershell or shutil.which("pwsh") or shutil.which("powershell.exe")
    if shell is None:
        raise InventoryError("powershell_unavailable")
    env = {key: value for key, value in os.environ.items()
           if not re.search(r"TOKEN|PASSWORD|SECRET|API_KEY|CREDENTIAL", key, re.I)}
    result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", _CIM_SCRIPT],
                            capture_output=True, timeout=COMMAND_TIMEOUT, env=env)
    if result.returncode != 0:
        raise InventoryError("process_list_unavailable")
    try:
        payload = json.loads(result.stdout.decode("utf-8-sig"))
    except (UnicodeError, ValueError):
        raise InventoryError("enumeration_output_unparsable") from None
    payload = payload if isinstance(payload, list) else [payload]
    _require(len(payload) <= MAX_PROCESSES, "enumeration output oversized")
    rows = []
    for item in payload:
        if not isinstance(item, dict):
            raise InventoryError("enumeration_output_unparsable")
        pid = _readable_int(item.get("pid"))
        ppid = _readable_int(item.get("ppid"))
        if pid is None:
            raise InventoryError("enumeration_output_unparsable")
        executable = item.get("exe")
        executable = executable if isinstance(executable, str) and executable else None
        rows.append({"pid": pid, "ppid": ppid, "uid": None,
                     "executable": executable,
                     "identity": IDENTITY_OBSERVED if executable else IDENTITY_UNREADABLE})
    return {"source": "windows-cim", "powershell": shell, "rows": rows}


# ------------------------------------------------------------- classify ----

def enumerate_processes(powershell: str | None = None,
                        ps: str | None = None) -> dict:
    """One bounded read-only enumeration. Never raises for host conditions.

    The pinned ``ps``/``powershell`` executables from the subject identity are
    consumed here instead of a fresh PATH re-resolution; the actually used
    executable and arguments are reported in the payload. A failed
    enumeration returns status ``failed`` with a reason; it is the caller's
    contract to treat that as unknown, never as absence.
    """
    if os.name == "nt":
        route = lambda: _enumerate_windows(powershell)  # noqa: E731 - closed over the pinned shell
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

    Windows: the kernel family (pid or parent pid <= 4, the System process).
    POSIX: any owner other than the enumeration's own ``observer_uid`` — a
    process owned by another uid cannot be that observer's Desktop host. No
    platform-specific call happens here, so synthetic classifications run on
    every platform; a row without owner evidence or without an observed
    observer uid keeps Desktop candidacy.
    """
    if source == "windows-cim":
        pid, ppid = row.get("pid"), row.get("ppid")
        return pid is not None and ppid is not None and (pid <= 4 or ppid <= 4)
    uid = row.get("uid")
    return uid is not None and observer_uid is not None and uid != observer_uid


def classify(enumeration: dict, desktop_executables, sandbox_markers=()) -> dict:
    """Classify one enumeration against exact pinned executable identities.

    ``desktop_executables`` and ``sandbox_markers`` are exact absolute paths.
    Comparison uses the path semantics of the enumeration source (Windows
    case-insensitive for ``windows-cim``, POSIX-sensitive otherwise). No
    broad name matching is performed.
    """
    _require(isinstance(enumeration, dict), "enumeration shape invalid")
    source = enumeration.get("source")
    windows = source == "windows-cim"
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
                               if key in ("ps_path", "ps_arguments", "powershell")}},
            "pinned": {"desktop_executables": sorted(desktop),
                       "sandbox_markers": sorted(sandbox)},
            "counts": counts, "desktop_host_processes": desktop_rows,
            "sandbox_service_processes": sandbox_rows,
            "desktop_descendant_processes": descendant_rows,
            "unreadable_processes": unreadable_rows}
