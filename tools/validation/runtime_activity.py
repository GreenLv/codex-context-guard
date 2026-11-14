"""Read-only bounded observation of old Context Guard runtime processes.

``clear`` is a snapshot, not a lock or proof that a future turn cannot start.
Do not persist or print command lines; Windows classification stays in its
query process. The caller must maintain the user's between-turn pause.
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import posixpath
import re
import shlex
import stat
import subprocess
from pathlib import Path

from scripts.cg_process_tree import OwnedProcess, ProcessTreeError

MAX_BYTES = 16 * 1024 * 1024
MAX_CANDIDATES = 32
TIMEOUT = 20
SCRIPT_NAMES = ("run_context_guard.sh", "run-context-guard.ps1", "cg_hook.py", "context_guard.py")


class ObservationError(ValueError):
    def __init__(self, reason, *, query_cleanup=None):
        super().__init__(reason)
        self.query_cleanup = query_cleanup


def _scrub_env():
    excluded = {"CODEX_HOME", "PLUGIN_ROOT", "PLUGIN_DATA", "CLAUDE_PLUGIN_DATA",
                "CONTEXT_GUARD_DATA_DIR", "GIT_ASKPASS", "SSH_ASKPASS"}
    return {k: os.environ[k] for k in os.environ
            if k.upper() not in excluded and not k.upper().startswith("GIT_CONFIG_")
            and not re.search(r"TOKEN|PASSWORD|SECRET|API_KEY|ACCESS_KEY|CREDENTIAL", k, re.I)}


def _query(args: list[str]) -> tuple[int, int, bytes]:
    owned = OwnedProcess.spawn(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=_scrub_env())
    child = owned.process
    timed_out = False
    try:
        raw, _ = child.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        timed_out = True
        raw = b""
    finally:
        try:
            cleanup = owned.close(timeout=3)
        except Exception:
            raise ObservationError("process query cleanup failed", query_cleanup="unconfirmed") from None
    confirmed = (cleanup.get("owned_process_exited") is True
                 and cleanup.get("owned_tree_no_running_members") is True
                 and cleanup.get("process_group_cleanup_error") is None
                 and cleanup.get("cleanup_complete", True) is True)
    if timed_out or not confirmed:
        raise ObservationError("process query timed out" if timed_out else "process query cleanup failed",
                               query_cleanup="confirmed" if confirmed else "unconfirmed")
    return child.pid, child.returncode, raw


def _inline_commands(hooks: dict, field: str) -> list[str]:
    try:
        groups = hooks["hooks"]
        result = [item[field] for entries in groups.values() for group in entries
                  for item in group["hooks"]]
    except (KeyError, TypeError, AttributeError) as exc:
        raise ObservationError("verified Hook definitions unavailable") from exc
    if len(result) != 9 or not all(isinstance(s, str) and s for s in result):
        raise ObservationError("verified Hook definitions incomplete")
    return sorted(set(result))


def _posix_classify(command: str, slots: list[str], inline: list[str], depth: int = 0) -> str | None:
    """Classify exact invocation slots, never arbitrary arguments/text mentions."""
    if not isinstance(command, str) or not command.strip():
        return "ambiguous_unreadable_command"
    if re.fullmatch(r"\?+", command.strip()):
        return "ambiguous_unreadable_command"
    if re.fullmatch(r"\((?:python(?:3(?:\.\d+)?)?|sh|bash|zsh|dash)\)", command.strip()):
        return "ambiguous_unreadable_command"
    try:
        args = shlex.split(command, posix=True)
    except ValueError:
        # An unparseable candidate is not negative evidence; unrelated rows
        # without the exact cache root or Hook body remain irrelevant.
        return ("ambiguous_parse" if any(s in command for s in slots)
                or any(x in command for x in inline) else None)
    if not args:
        return "ambiguous_unreadable_command"
    head = posixpath.basename(args[0])
    targets = {posixpath.normpath(posixpath.join(s, "scripts", n)): n
               for s in slots for n in SCRIPT_NAMES}
    first = posixpath.normpath(args[0])
    if first in targets:
        return "runtime_script"
    python = re.fullmatch(r"python(?:3(?:\.\d+)?)?", head) is not None
    shell = head in {"sh", "bash", "zsh", "dash"}
    if python:
        idx = 1
        while idx < len(args) and args[idx].startswith("-"):
            if args[idx] == "-c":
                code = args[idx + 1] if idx + 1 < len(args) else ""
                if ("runpy" in code or "importlib" in code) and any(
                    posixpath.normpath(part) in targets for part in args[idx + 2:]
                ):
                    return "ambiguous_parse"
                return None
            if args[idx] == "-m":
                return None
            if args[idx] in ("-W", "-X", "--check-hash-based-pycs"):
                idx += 1
            idx += 1
        if idx < len(args) and posixpath.normpath(args[idx]) in targets:
            return "runtime_python"
    if shell:
        if len(args) >= 3 and args[1] in ("-c", "-lc"):
            body = args[2] if len(args) == 3 else ""
            # ps may display argv joined without shell quoting. The unquoted
            # tail is accepted only when it equals a whole verified definition
            # or its extracted `sh -c` body, never a substring of echo text.
            tail = command.split(None, 2)[2] if len(command.split(None, 2)) == 3 else ""
            bodies = set(inline)
            for value in inline:
                try:
                    parts = shlex.split(value)
                    if len(parts) >= 3 and parts[1] in ("-c", "-lc"):
                        bodies.add(parts[2])
                except ValueError:
                    raise ObservationError("invalid verified Hook command") from None
            if body in bodies or tail in bodies:
                return "ambiguous_inline_hook_home"
            if depth < 2:
                nested = body or tail
                child = _posix_classify(nested, slots, inline, depth + 1)
                if child:
                    return child
            return None
        elif len(args) >= 2 and posixpath.normpath(args[1]) in targets:
            return "runtime_launcher"
    # ps does not promise shell-escaped output for path names with spaces.
    # Do not infer an invocation from a substring; leave such a candidate
    # unresolved rather than falsely claiming idle.
    if (python or shell) and any(" " in s and s in command for s in slots):
        return "ambiguous_spaced_path"
    return None


def _parse_ps(raw: bytes, excluded: set[int], slots: list[str], inline: list[str]) -> dict[int, dict]:
    if len(raw) > MAX_BYTES:
        raise ObservationError("process snapshot too large")
    rows = {}
    for line in raw.decode("utf-8", "surrogateescape").splitlines():
        fields = line.split(None, 8)
        if len(fields) != 9 or not all(x.isdigit() for x in fields[:3]):
            raise ObservationError("unparseable process snapshot")
        pid, ppid, uid = map(int, fields[:3])
        if pid in excluded:
            continue
        if pid in rows:
            raise ObservationError("duplicate process identity")
        category = _posix_classify(fields[8], slots, inline)
        # ps cannot reveal an inaccessible same-user command. Other-user
        # processes with an unreadable name are not asserted to be this
        # user's runtime; actual readable exact paths remain candidates.
        if category == "ambiguous_unreadable_command" and uid != os.getuid():
            category = None
        if category:
            rows[pid] = {"pid": pid, "ppid": ppid, "start": " ".join(fields[3:8]),
                         "category": category}
    return rows


def _ps_snapshot(ps: str, slots: list[str], inline: list[str]) -> dict[int, dict]:
    query_pid, returncode, raw = _query([ps, "-axww", "-o", "pid=,ppid=,uid=,lstart=,command="])
    if returncode != 0:
        raise ObservationError("process query failed")
    rows = _parse_ps(raw, {os.getpid(), query_pid}, slots, inline)
    for pid, row in rows.items():
        identity = _darwin_identity(pid)
        if identity is None or identity["ppid"] != row["ppid"]:
            row["category"] = "ambiguous_identity_unavailable"
        else:
            row["start"] = identity["start"]
    return rows


class _DarwinBSDInfo(ctypes.Structure):
    # macOS sys/proc_info.h: PROC_PIDTBSDINFO struct proc_bsdinfo.
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "reserved"
    )] + [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)] + [
        (name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "tdev", "tpgid")
    ] + [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]


def _darwin_identity(pid: int) -> dict | None:
    try:
        lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        func = lib.proc_pidinfo
        func.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        func.restype = ctypes.c_int
        info = _DarwinBSDInfo()
        size = func(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        if size != ctypes.sizeof(info) or info.pid != pid or info.start_sec == 0:
            return None
        return {"ppid": info.ppid, "start": f"{info.start_sec}.{info.start_usec:06d}"}
    except (OSError, ValueError):
        return None


def _reconcile(before: dict[int, dict], after: dict[int, dict]) -> dict:
    candidates = []
    for pid in sorted(set(before) | set(after)):
        a, b = before.get(pid), after.get(pid)
        if a is None or b is None or a != b:
            row = b or a
            candidates.append({**row, "category": "ambiguous_identity_changed"})
        else:
            candidates.append(b)
    if len(candidates) > MAX_CANDIDATES:
        return {"status": "unknown", "candidates": [], "reason": "too_many_candidates"}
    if any(r["category"].startswith("ambiguous_") for r in candidates):
        return {"status": "unknown", "candidates": candidates, "reason": "candidate_ambiguous"}
    return {"status": "active" if candidates else "clear", "candidates": candidates}


def _windows_snapshot(shell: str, slots: list[str], inline: list[str]) -> dict[int, dict]:
    helper = Path(__file__).with_name("runtime_activity_windows.ps1")
    config = {"slots": slots, "inline": inline, "ignorePids": [os.getpid()]}
    payload = base64.b64encode(json.dumps(config).encode("utf-8")).decode("ascii")
    _query_pid, returncode, raw = _query([shell, "-NoProfile", "-NonInteractive", "-File", str(helper),
                                          "-ConfigBase64", payload])
    if returncode != 0 or len(raw) > MAX_BYTES:
        raise ObservationError("Windows process query failed")
    value = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(value, list):
        raise ObservationError("Windows process query malformed")
    rows = {}
    for row in value:
        if (not isinstance(row, dict) or set(row) != {"pid", "ppid", "start", "category"}
                or type(row["pid"]) is not int or type(row["ppid"]) is not int
                or not isinstance(row["start"], str) or not row["start"]
                or row["category"] not in {"runtime_launcher", "runtime_python", "runtime_script",
                                           "ambiguous_inline_hook_home", "ambiguous_unreadable_command",
                                           "ambiguous_parse"} or row["pid"] in rows):
            raise ObservationError("Windows process row invalid")
        rows[row["pid"]] = row
    return rows


def observe(daily_home: Path, version: str, host_tools: dict, *, hooks: dict | None = None,
            slots: list[Path] | None = None, allow_absent: bool = False,
            platform_name: str | None = None) -> dict:
    """Return clear/active/unknown; hooks must be the verified old definitions.

    The first three positional arguments preserve the existing caller shape.
    Production integration must pass verified hooks explicitly; omission is
    unknown, never a partial-clear result. slots supports explicitly selected
    installed version/local roots; omitted observes both existing candidates.
    """
    try:
        if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", version):
            raise ObservationError("invalid selected version")
        if hooks is None:
            raise ObservationError("verified Hook definitions required")
        _inline_commands(hooks, "command")
        _inline_commands(hooks, "commandWindows")
        home = Path(daily_home)
        if (not home.is_absolute() or os.path.normpath(str(home)) != str(home)
                or home.resolve(strict=True) != home):
            raise ObservationError("daily HOME must be a canonical directory")
        if type(allow_absent) is not bool:
            raise ObservationError("allow_absent must be boolean")
        if allow_absent and slots is None:
            raise ObservationError("absent slots require explicit selection")
        root = home / "plugins/cache/codex-context-guard/context-guard"
        allowed = [root / version, root / "local"]
        def slot_exists(path: Path) -> bool:
            current = home
            for component in path.relative_to(home).parts:
                current = current / component
                try:
                    info = current.lstat()
                except FileNotFoundError:
                    return False
                if (not stat.S_ISDIR(info.st_mode) or getattr(info, "st_reparse_tag", 0)
                        or getattr(info, "st_file_attributes", 0) & 0x400):
                    raise ObservationError("slot ancestor is a link or non-directory")
            return True
        selected_paths = ([Path(p) for p in slots] if slots is not None
                          else [p for p in allowed if slot_exists(p)])
        if (not selected_paths or any(not p.is_absolute() or p not in allowed for p in selected_paths)
                or len(set(selected_paths)) != len(selected_paths)):
            raise ObservationError("selected installed cache slots unavailable or ambiguous")
        for p in selected_paths:
            if not slot_exists(p) and not (allow_absent and slots is not None):
                raise ObservationError("selected installed cache slot is absent")
        selected = [str(p) for p in selected_paths]
        kind = platform_name or ("windows" if os.name == "nt" else "darwin")
        if kind == "darwin":
            ps = (host_tools.get("ps") or {}).get("path")
            if not ps:
                raise ObservationError("pinned ps unavailable")
            inline = _inline_commands(hooks, "command")
            return _reconcile(_ps_snapshot(ps, selected, inline), _ps_snapshot(ps, selected, inline))
        if kind == "windows":
            shell = (host_tools.get("powershell") or {}).get("path")
            if not shell:
                raise ObservationError("pinned PowerShell unavailable")
            inline = _inline_commands(hooks, "commandWindows")
            return _reconcile(_windows_snapshot(shell, selected, inline),
                              _windows_snapshot(shell, selected, inline))
        raise ObservationError("unsupported platform")
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeError) as exc:
        result = {"status": "unknown", "candidates": [], "reason": str(exc) if isinstance(exc, ObservationError) else type(exc).__name__}
        if isinstance(exc, ObservationError) and exc.query_cleanup is not None:
            result["query_cleanup"] = exc.query_cleanup
        elif isinstance(exc, ProcessTreeError):
            result["query_cleanup"] = "unconfirmed"
        return result
