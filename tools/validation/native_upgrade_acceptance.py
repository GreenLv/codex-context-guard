#!/usr/bin/env python3
"""Bounded native cross-version upgrade acceptance.

This tool does not log in, copy credentials, edit trust or a consumed cache.
Only real observations can satisfy an acceptance gate; missing host capability
is pending, never a pass. Evidence is private and belongs outside the checkout.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import platform
import queue
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.validation import native_acceptance as native  # noqa: E402
from tools.validation import native_cli_adoption as adoption  # noqa: E402
from tools.validation import native_scheduler_batch as scheduler  # noqa: E402
from tools.validation import stop_host_acceptance as host  # noqa: E402

PLAN = "cg-native-upgrade-plan/v1"
REPORT = "cg-native-upgrade-acceptance/v1"
HEX40 = re.compile(r"[a-f0-9]{40}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
SENTINEL = re.compile(r"cg-u01-sentinel-[a-z0-9][a-z0-9-]{0,48}\Z")
EVENTS = frozenset(host.EVENTS)
OLD_MARKETS = {"0.15.1": "codex-context-guard", "0.16.1": "codex-context-guard-v016"}
NEW_MARKET = "codex-context-guard"
OLD_0151_COMMIT = "111fe03b98803c6b06e8a70c010d27ca04d81af3"
OLD_0151_EXPORT_SHA256 = "37899ae37bc5e09c62c459e6b840b0929b0ba368d7dd51873732b78f7a5102f6"
OLD_0161_ZIP_SHA256 = "d554dc732b900412bd46d8c0b2b01e3e1304cb823f163a11c49e0e7c3687fb92"


class UpgradeError(ValueError):
    """Inputs or evidence cannot establish the requested outcome."""


class CapabilityPending(UpgradeError):
    """A native capability requires separate evidence before execution."""


def require(value: Any, message: str) -> None:
    if not value:
        raise UpgradeError(message)


def _credential_name(name: str) -> bool:
    folded = name.casefold()
    return (folded in {"auth.json", "credentials", "credentials.json", "credential.json", "tokens",
                       "token.json", "secrets", "secret.json", ".env", ".envrc", ".netrc", "_netrc",
                       ".npmrc", ".pypirc", ".ssh", ".aws", "id_rsa", "id_ed25519",
                       "keychain", "keychain-db"}
            or folded.startswith((".env.", "auth.json."))
            or folded.endswith((".pem", ".key", ".p12", ".pfx"))
            or re.fullmatch(r".*(?:token|password|secret|credential).*\.json", folded) is not None)


def _reject_credential_path(path: Path) -> None:
    require(not any(_credential_name(part) for part in path.parts), "credential-named path refused")


def _no_link_ancestors(path: Path) -> None:
    require(path.is_absolute(), "absolute path required")
    for component in reversed((path, *path.parents)):
        if not component.exists() and not component.is_symlink():
            continue
        info = component.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "linked ancestor refused")


def _stat_identity(info: os.stat_result) -> tuple[Any, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _windows_executable(path: Path) -> bool:
    return os.name == "nt" and path.suffix.casefold() in {".exe", ".com", ".bat", ".cmd"}


def _common_identity(info: os.stat_result, *, windows_executable: bool = False) -> tuple[Any, ...]:
    # Windows path and opened-handle providers can report different ctime for
    # the same object. Path stat also adds execute bits for known executable
    # suffixes; preserve the complete mode within each provider separately.
    values = list(_stat_identity(info)[:-1])
    if windows_executable:
        values[2] &= ~0o111
    return tuple(values)


def sha(path: Path, *, expected: tuple[Any, ...] | None = None) -> str:
    _reject_credential_path(path)
    _no_link_ancestors(path.absolute())
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and not getattr(before, "st_file_attributes", 0) & 0x400,
            "digest input must be a real single-link file")
    require(expected is None or _stat_identity(before) == expected, "digest input differs from metadata scan")
    _reject_credential_path(path.resolve(strict=True))
    fd = native.open_snapshot_file(path)
    try:
        opened = os.fstat(fd)
        execute_alias = _windows_executable(path)
        require(_common_identity(before, windows_executable=execute_alias)
                == _common_identity(opened, windows_executable=execute_alias), "digest input changed before open")
        output = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            output.update(chunk)
        require(_stat_identity(opened) == _stat_identity(os.fstat(fd))
                and _stat_identity(before) == _stat_identity(path.lstat()),
                "digest input changed during read")
        return output.hexdigest()
    finally:
        os.close(fd)


def digest(value: Any) -> str:
    data = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def source_files(root: Path) -> dict[str, str]:
    """Complete non-link file inventory, without user HOME or credentials."""
    # Refuse all unsafe names/objects in a metadata-only pass before any file
    # is opened or hashed. Hash only that fixed file list, using identities
    # from the first pass, then require identical metadata on a second pass.
    _reject_credential_path(root)
    _no_link_ancestors(root.absolute())

    def metadata() -> dict[str, tuple[str, tuple[Any, ...]]]:
        objects: dict[str, tuple[str, tuple[Any, ...]]] = {}
        stack = [root]
        while stack:
            current = stack.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    require(len(objects) < 10000 and not _credential_name(entry.name),
                            "credential-named or oversized artifact tree refused")
                    # DirEntry's cached Windows metadata omits dev/ino/nlink.
                    # Use a fresh no-follow path stat; zero cached fields are
                    # never evidence that a real single-link file is unsafe.
                    info = Path(entry.path).lstat()
                    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                            "linked artifact object refused")
                    path = Path(entry.path)
                    name = path.relative_to(root).as_posix()
                    if stat.S_ISDIR(info.st_mode):
                        objects[name] = ("dir", _stat_identity(info))
                        stack.append(path)
                    else:
                        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                                "non-regular or hard-linked artifact object refused")
                        objects[name] = ("file", _stat_identity(info))
        return objects

    before = metadata()
    files = {name: sha(root / name, expected=identity) for name, (kind, identity) in sorted(before.items())
             if kind == "file"}
    require(metadata() == before, "artifact tree changed during hashing")
    return files


def _load_artifacts_no_pyc(root: Path) -> Any:
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        return native.load_artifacts(root)
    finally:
        sys.dont_write_bytecode = previous


def _old_provenance(product: Path, old: Path, version: str, plan: dict[str, Any],
                    expected_files: dict[str, str], old_zip_identity: tuple[Any, ...] | None = None) -> dict[str, str]:
    if version == "0.16.1":
        archive = _absolute_real(plan.get("old_release_zip"), "old release ZIP", file=True)
        identity = old_zip_identity if old_zip_identity is not None else _zip_metadata(archive)
        require(sha(archive, expected=identity) == OLD_0161_ZIP_SHA256, "old published ZIP digest differs")
        manager = _load_artifacts_no_pyc(old)
        require(manager.distribution_manifest(old) == expected_files, "old release manifest differs")
        _zip_exact(archive, identity, expected_files)
        return {"kind": "published_release_zip", "sha256": OLD_0161_ZIP_SHA256}
    process = scheduler._command(native, product,
                                 ["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf",
                                  "archive", "--format=tar", OLD_0151_COMMIT], timeout=90)
    require(process.returncode == 0 and hashlib.sha256(process.stdout).hexdigest() == OLD_0151_EXPORT_SHA256,
            "old published commit export differs")
    archived = {}
    with tarfile.open(fileobj=io.BytesIO(process.stdout), mode="r:") as archive:
        for member in archive:
            if member.isdir():
                continue
            require(member.isfile() and member.name not in archived, "old export has unsupported object")
            stream = archive.extractfile(member)
            require(stream is not None, "old export member unavailable")
            archived[member.name] = hashlib.sha256(stream.read()).hexdigest()
    require(archived == expected_files, "old source differs from published commit export")
    return {"kind": "published_tag_source_export", "commit": OLD_0151_COMMIT,
            "sha256": OLD_0151_EXPORT_SHA256}


def _read_json_with_sha(path: Path) -> tuple[dict[str, Any], str]:
    _reject_credential_path(path)
    _no_link_ancestors(path.absolute())
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and not getattr(before, "st_file_attributes", 0) & 0x400 and before.st_size <= 16 * 1024 * 1024,
            "regular bounded JSON input required")
    _reject_credential_path(path.resolve(strict=True))
    fd = native.open_snapshot_file(path)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        execute_alias = _windows_executable(path)
        require(_common_identity(opened, windows_executable=execute_alias)
                == _common_identity(before, windows_executable=execute_alias), "JSON changed before read")
        content = stream.read(16 * 1024 * 1024 + 1)
        require(len(content) <= 16 * 1024 * 1024 and
                _stat_identity(os.fstat(stream.fileno())) == _stat_identity(opened) and
                _stat_identity(path.lstat()) == _stat_identity(before),
                "JSON changed during read")
    value = adoption.strict_json(content.decode("utf-8"))
    require(isinstance(value, dict), "JSON object required")
    return value, hashlib.sha256(content).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    return _read_json_with_sha(path)[0]


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _zip_metadata(path: Path) -> tuple[Any, ...]:
    """Inspect only ZIP central-directory metadata before any whole-ZIP hash."""
    _reject_credential_path(path)
    _no_link_ancestors(path.absolute())
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and not getattr(before, "st_file_attributes", 0) & 0x400
            and before.st_size <= 512 * 1024 * 1024,
            "ZIP input unavailable or oversized")
    fd = native.open_snapshot_file(path)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        execute_alias = _windows_executable(path)
        require(_common_identity(opened, windows_executable=execute_alias)
                == _common_identity(before, windows_executable=execute_alias), "ZIP changed before metadata read")
        with zipfile.ZipFile(stream) as archive:
            rows = archive.infolist()
        require(0 < len(rows) <= 10000, "ZIP entry count invalid")
        names: set[str] = set()
        total = 0
        for item in rows:
            name = item.filename
            parts = name.rstrip("/").split("/")
            require(bool(name) and "\\" not in name and not name.startswith("/")
                    and ":" not in parts[0] and all(ord(char) >= 32 and ord(char) != 127 for char in name)
                    and all(part not in ("", ".", "..") and not _credential_name(part) for part in parts),
                    "unsafe or credential-named ZIP member")
            require(name not in names, "duplicate ZIP member")
            names.add(name)
            mode = item.external_attr >> 16
            require(not stat.S_ISLNK(mode), "linked ZIP member refused")
            total += item.file_size
            require(item.file_size <= 256 * 1024 * 1024 and total <= 512 * 1024 * 1024,
                    "ZIP expanded size exceeds bound")
        require(_stat_identity(os.fstat(stream.fileno())) == _stat_identity(opened)
                and _stat_identity(path.lstat()) == _stat_identity(before),
                "ZIP changed during metadata read")
    return _stat_identity(before)


def _zip_exact(path: Path, identity: tuple[Any, ...], expected: dict[str, str]) -> None:
    """Read only members of a previously metadata-reviewed, unchanged ZIP."""
    before = path.lstat()
    require(_stat_identity(before) == identity, "ZIP changed before member open")
    fd = native.open_snapshot_file(path)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        execute_alias = _windows_executable(path)
        require(_common_identity(opened, windows_executable=execute_alias)
                == _common_identity(before, windows_executable=execute_alias), "ZIP changed before member read")
        with zipfile.ZipFile(stream) as archive:
            names = archive.namelist()
            require(len(names) == len(expected) and set(names) == set(expected), "ZIP file set differs")
            for name, expected_sha in expected.items():
                require(hashlib.sha256(archive.read(name)).hexdigest() == expected_sha, "ZIP member bytes differ")
        require(_stat_identity(os.fstat(stream.fileno())) == _stat_identity(opened)
                and _stat_identity(path.lstat()) == identity,
                "ZIP changed during member read")


def _sha(value: Any) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _absolute_real(value: Any, label: str, *, file: bool = False,
                   allow_hardlinks: bool = False) -> Path:
    require(isinstance(value, str), f"{label} must be a path")
    path = Path(value)
    _reject_credential_path(path)
    require(path.is_absolute() and not path.is_symlink(), f"{label} must be an absolute real path")
    _no_link_ancestors(path)
    info = path.lstat()
    require(not getattr(info, "st_file_attributes", 0) & 0x400, f"{label} may not be a reparse object")
    if file:
        require(stat.S_ISREG(info.st_mode) and (allow_hardlinks or info.st_nlink == 1),
                f"{label} must be a regular permitted file")
    path = path.resolve(strict=True)
    _reject_credential_path(path)
    require(path.is_file() if file else path.is_dir(), f"{label} unavailable")
    return path


def _new_outside(output: Path, protected: list[Path]) -> None:
    """Reject before any mkdir, writability probe or authentication read."""
    _reject_credential_path(output)
    require(output.is_absolute() and not output.exists() and not output.is_symlink(),
            "output must be a new absolute path")
    _no_link_ancestors(output.parent)
    parent = output.parent.resolve(strict=True)
    require(parent.is_dir() and not output.parent.is_symlink(), "output parent must exist")
    destination = parent / output.name
    require(all(not _within(destination, root) for root in protected), "output overlaps protected root")
    _private_directory(parent)


def _private_directory(parent: Path) -> None:
    if os.name == "posix":
        info = parent.stat()
        require(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077,
                "directory must be owner private")
    else:
        # Reuse the reviewed native DACL check without constructing a scheduler
        # driver or requiring Task Scheduler. Never substitute POSIX mode bits.
        powershell = shutil.which("powershell.exe")
        require(powershell is not None, "Windows private output DACL capability unavailable")
        driver = object.__new__(scheduler._Windows)
        driver.native, driver.source, driver.powershell = native, ROOT, powershell
        driver.env = {key: os.environ[key] for key in
                      ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP")
                      if key in os.environ}
        require(driver.private_parent(parent), "Windows directory is not private")


def _data_candidate(home: Path, value: Any, label: str) -> Path:
    require(isinstance(value, str) and Path(value).is_absolute(), label + " must be absolute")
    path = Path(value)
    _reject_credential_path(path)
    require(not path.is_symlink(), label + " cannot be a link")
    _no_link_ancestors(path)
    resolved = path.resolve(strict=False)
    _reject_credential_path(resolved)
    require(home in resolved.parents, label + " must be inside the isolated HOME")
    # Do not create it or search the HOME. Resolution of an existing ancestor
    # ensures a linked ancestor cannot redirect outside the isolated HOME.
    return resolved


def _distinct_homes(homes: list[Path]) -> None:
    require(all(not _within(first, second) and not _within(second, first)
                for index, first in enumerate(homes) for second in homes[index + 1:]),
            "authentication HOMEs overlap")


def _invocation_paths(plan_path: Path, output: Path, home_value: Path,
                      other_values: list[Path], prepared: Path | None,
                      verify_output: Path | None = None) -> tuple[Path, list[Path]]:
    """Establish HOME boundaries from CLI args before opening any plan file."""
    home = _absolute_real(str(home_value), "isolated authentication HOME")
    require(1 <= len(other_values) <= 32, "other authentication HOME arguments required")
    others = [_absolute_real(str(value), "other authentication HOME") for value in other_values]
    _distinct_homes([home, *others])
    daily = (Path.home() / ".codex").resolve()
    protected = [home, daily, *others]
    inherited = os.environ.get("CODEX_HOME")
    if inherited and Path(inherited).is_absolute():
        protected.append(Path(inherited).resolve())
    for candidate in (plan_path, output, *([prepared] if prepared is not None else []),
                      *([verify_output] if verify_output is not None else [])):
        _reject_credential_path(candidate)
        require(candidate.is_absolute(), "external input/output must be absolute")
        _no_link_ancestors(candidate if candidate.exists() else candidate.parent)
        resolved = candidate.resolve(strict=False)
        require(all(not _within(resolved, root) and not _within(root, resolved) for root in protected),
                "input/output overlaps an authentication HOME")
    return home, others


def _cli_scope(codex: Path, daily: Path, auth_homes: list[Path]) -> None:
    """Only the verified public standalone exe is exempt from daily HOME."""
    require(all(not _within(codex, root) and not _within(root, codex) for root in auth_homes),
            "CLI path overlaps an acceptance authentication HOME")
    if _within(codex, daily) or _within(daily, codex):
        allowed = daily / "packages/standalone/releases/0.165.0-x86_64-pc-windows-msvc/bin/codex.exe"
        require(platform.system() == "Windows"
                and native._official_path_matches(str(codex), allowed, windows=True),
                "CLI inside daily HOME is not the known public standalone executable")
    else:
        require(codex.name.casefold() in {"codex", "codex.exe"}, "unrecognized public CLI filename")
        if os.name == "posix":
            require(os.access(codex, os.X_OK), "public CLI is not executable")


def _sentinel_paths(home: Path, spec: Any) -> tuple[str, dict[str, Path]]:
    """Validate both synthetic marker paths before opening either file."""
    value = _object(spec)
    name = value.get("marketplace")
    require(isinstance(name, str) and SENTINEL.fullmatch(name), "invalid sentinel marketplace")
    paths: dict[str, Path] = {}
    for key, base in (("cache_marker", home / "plugins/cache" / name),
                      ("data_marker", home / "u01-sentinel" / name)):
        raw = value.get(key)
        require(isinstance(raw, str) and Path(raw).is_absolute(), "sentinel path must be absolute")
        path = Path(raw)
        _reject_credential_path(path)
        require(not path.is_symlink() and path.is_file() and path.stat().st_nlink == 1,
                "sentinel marker unavailable or linked")
        resolved = path.resolve(strict=True)
        require(base.resolve(strict=True) in resolved.parents, "sentinel marker outside synthetic scope")
        cursor = home
        for part in path.relative_to(home).parts:
            cursor = cursor / part
            info = cursor.lstat()
            require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                    "linked sentinel path refused")
        _reject_credential_path(resolved)
        paths[key] = resolved
    return name, paths


def _sentinel_files(home: Path, spec: Any) -> dict[str, Any]:
    """Read only two explicit synthetic markers, never a HOME snapshot."""
    name, paths = _sentinel_paths(home, spec)
    result: dict[str, Any] = {"marketplace": name}
    for key, resolved in paths.items():
        info = resolved.stat()
        result[key] = {"path": str(resolved), "sha256": sha(resolved), "size": info.st_size,
                       "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode)}
    return result


def _inventory(value: Any, sources: dict[str, str]) -> dict[tuple[str, str], dict[str, Any]]:
    """Validate real hooks/list records, never infer trust from an operator signal."""
    rows = value.get("data") if isinstance(value, dict) else None
    require(isinstance(rows, list) and len(rows) == 1, "one Hook inventory required")
    row = _object(rows[0])
    require(not row.get("errors") and not row.get("warnings"), "Hook inventory errors")
    hooks = row.get("hooks")
    require(isinstance(hooks, list) and len(hooks) == 9 * len(sources), "Hook count differs")
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for item in hooks:
        require(isinstance(item, dict), "Hook record malformed")
        event, source = item.get("eventName"), _source_key(item.get("sourcePath"), sources)
        require(event in EVENTS and source is not None and item.get("source") == "plugin"
                and item.get("handlerType") == "command" and item.get("enabled") is True
                and item.get("trustStatus") == "trusted" and isinstance(item.get("key"), str)
                and bool(item["key"]) and isinstance(item.get("currentHash"), str)
                and bool(item["currentHash"]) and type(item.get("displayOrder")) is int
                and item["displayOrder"] >= 0, "Hook source or trust differs")
        key = (event, source)
        require(key not in result, "duplicate Hook event and source")
        result[key] = _hook_projection(item)
    require(all((event, source) in result for source in sources for event in EVENTS),
            "incomplete Hook source family")
    return result


def _source_key(raw: Any, sources: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    matches = [source for source in sources if isinstance(source, str)
               and native._official_path_matches(raw, Path(source), windows=platform.system() == "Windows")]
    return matches[0] if len(matches) == 1 else None


def _require_distinct_sources(old_source: str, new_source: str) -> None:
    require(not native._official_path_matches(new_source, Path(old_source), windows=platform.system() == "Windows"),
            "old and new Hook definitions have ambiguous source paths")


def _hook_projection(item: dict[str, Any]) -> dict[str, Any]:
    return {field: item[field] for field in
            ("eventName", "sourcePath", "source", "handlerType", "enabled", "trustStatus",
             "key", "currentHash", "displayOrder", "async") if field in item}


def _paired(rows: Any, inventory: dict[tuple[str, str], dict[str, Any]],
            thread: str, event: str, *, turn: str | None = None,
            after_index: int = 0) -> list[dict[str, Any]]:
    require(isinstance(rows, list), "RPC journal unavailable")
    started: dict[str, dict[str, Any]] = {}
    completed = []
    for entry in rows[after_index:]:
        if not isinstance(entry, dict) or entry.get("direction") != "response":
            continue
        msg = _object(entry.get("message"))
        method, params = msg.get("method"), _object(msg.get("params"))
        if method not in ("hook/started", "hook/completed") or params.get("threadId") != thread:
            continue
        if turn is not None and params.get("turnId") != turn:
            continue
        run = _object(params.get("run"))
        if run.get("eventName") != event:
            continue
        source = _source_key(run.get("sourcePath"), {path for _, path in inventory})
        key = (run.get("eventName"), source)
        expected = inventory.get(key)
        require(expected is not None, "unreviewed Hook source")
        require(all(run.get(k) == expected.get(k) for k in
                    ("eventName", "source", "handlerType", "displayOrder"))
                and _source_key(run.get("sourcePath"), [source]) == source,
                "Hook runtime notification differs from inventory")
        require(run.get("executionMode") == ("async" if expected.get("async") else "sync"),
                "Hook execution mode differs")
        rid = run.get("id")
        require(isinstance(rid, str) and bool(rid), "Hook run id missing")
        if method == "hook/started":
            require(rid not in started, "duplicate Hook start")
            started[rid] = run
        else:
            prior = started.pop(rid, None)
            require(prior is not None and _source_key(prior.get("sourcePath"), [source]) == source,
                    "unpaired Hook completion")
            duration = run.get("durationMs")
            require(run.get("status") == "completed" and type(duration) is int and duration >= 0,
                    "Hook was not completed")
            require(event != "sessionEnd" or duration <= 3000, "SessionEnd exceeded host budget")
            completed.append(run)
    require(not started, "unfinished Hook run")
    return completed


def _pending(state: Any, *, allow_empty: bool = False) -> set[tuple[str, str]]:
    rows = _object(state).get("requirements")
    require(isinstance(rows, list), "requirements unavailable")
    pending = [r for r in rows if isinstance(r, dict) and r.get("status") == "pending"]
    require(all(isinstance(r.get("id"), str) and bool(r["id"]) and _sha(r.get("sha256"))
                for r in pending), "pending requirement identity unavailable")
    values = {(r["id"], r["sha256"]) for r in pending}
    require(len(values) == len(pending), "duplicate pending requirement")
    require(allow_empty or values, "no verifiable pending requirement")
    return values


def _state_projection(value: Any) -> dict[str, Any]:
    """Persist only continuity fields, never prompts or full private state."""
    state = _object(value)
    session = _object(state.get("session"))
    requirements = state.get("requirements")
    compactions = state.get("compactions")
    require(isinstance(session.get("id"), str) and isinstance(requirements, list)
            and isinstance(compactions, list), "state projection unavailable")
    projected = []
    for item in requirements:
        require(isinstance(item, dict) and isinstance(item.get("id"), str)
                and _sha(item.get("sha256")) and isinstance(item.get("status"), str)
                and (item.get("status") != "pending" or
                     (isinstance(item.get("work_unit_id"), str) and bool(item["work_unit_id"]))),
                "requirement projection unavailable")
        projected.append({key: item.get(key) for key in ("id", "sha256", "status", "work_unit_id")})
    recovery = _object(_object(state.get("pending")).get("recovery"))
    return {"session": {"id": session["id"]}, "requirements": projected,
            "mode": {"active": _object(state.get("mode")).get("active")},
            "compactions_count": len(compactions), "recovery_state": recovery.get("state")}


def _pending_bound(state: Any) -> list[dict[str, str]]:
    ids = _pending(state)
    all_rows = _object(state).get("requirements", [])
    require(all(isinstance(row, dict) for row in all_rows), "requirement entries malformed")
    rows = [row for row in all_rows if row.get("status") == "pending"]
    require(all(isinstance(row.get("work_unit_id"), str) and row["work_unit_id"] for row in rows),
            "pending work-unit identity unavailable")
    result = [{"id": row["id"], "sha256": row["sha256"], "work_unit_id": row["work_unit_id"]} for row in rows]
    require(len(result) == len(ids) and len({row["work_unit_id"] for row in result}) == 1,
            "pending task is not uniquely scoped")
    return sorted(result, key=lambda row: row["id"])


def _old_scope(installed: Path, state_path: Path, home: Path) -> dict[str, Any]:
    """Evaluate only the owned synthetic state with its exact installed old runtime."""
    code = '''import importlib.util,json,os,stat,sys
from pathlib import Path
script=Path(sys.argv[1]);sys.path.insert(0,str(script.parent))
spec=importlib.util.spec_from_file_location("cg_u01_owned",script)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
path=Path(sys.argv[2]);before=path.lstat()
if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or getattr(before,"st_file_attributes",0)&0x400:
 raise ValueError("unsafe state object")
fd=module._open_windows_committed_state(path) if os.name=="nt" else os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
def ident(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns)
with os.fdopen(fd,"r",encoding="utf-8") as stream:
 opened=os.fstat(stream.fileno())
 if ident(opened)!=ident(before):raise ValueError("state identity changed")
 state=json.load(stream)
 finished=os.fstat(stream.fileno());after=path.lstat()
 if ident(opened)!=ident(finished) or opened.st_ctime_ns!=finished.st_ctime_ns or ident(before)!=ident(after) or before.st_ctime_ns!=after.st_ctime_ns:
  raise ValueError("state changed during read")
module.validate_state_integrity(state)
scope=module.current_scope_projection(state)
print(json.dumps({"current":sorted(scope["current_item_ids"]),
 "ancestor":sorted(scope["ancestor_constraint_ids"]),"waiting":len(scope["waiting_conditions"])}))'''
    before = sha(state_path)
    child = scheduler._command(native, ROOT, [sys.executable, "-I", "-B", "-c", code,
        str(installed / "scripts/context_guard.py"), str(state_path)], env=isolated_env(home), timeout=30)
    require(child.returncode == 0 and len(child.stdout) <= 4096 and sha(state_path) == before,
            "old-runtime scope evaluation unavailable")
    scope = _json_output(child)
    require(set(scope) == {"current", "ancestor", "waiting"}
            and isinstance(scope["current"], list) and isinstance(scope["ancestor"], list)
            and type(scope["waiting"]) is int, "old-runtime scope malformed")
    return scope


def _cancel_evidence(before: Any, after: Any, scope: dict[str, Any]) -> dict[str, Any]:
    prior = _pending_bound(before)
    unit = prior[0]["work_unit_id"]
    state = _object(after)
    session = _object(state.get("session")).get("id")
    require(isinstance(session, str) and session == _object(_object(before).get("session")).get("id"),
            "cancelled task identity changed")
    cancel_sha = hashlib.sha256("取消当前任务。".encode()).hexdigest()
    prompts = [row for row in state.get("prompts", []) if isinstance(row, dict) and row.get("sha256") == cancel_sha]
    require(len(prompts) == 1 and isinstance(prompts[0].get("id"), str), "cancellation prompt unavailable")
    prompt_id = prompts[0]["id"]
    earlier = _object(before).get("requirements")
    later = state.get("requirements")
    require(isinstance(earlier, list) and isinstance(later, list)
            and all(isinstance(row, dict) and isinstance(row.get("id"), str) for row in earlier + later),
            "cancellation requirement records malformed")
    earlier_by_id = {row["id"]: row for row in earlier}
    later_by_id = {row["id"]: row for row in later}
    require(len(earlier_by_id) == len(earlier) and len(later_by_id) == len(later)
            and set(earlier_by_id) <= set(later_by_id)
            and all(later_by_id[key].get("sha256") == row.get("sha256")
                    and later_by_id[key].get("work_unit_id") == row.get("work_unit_id")
                    for key, row in earlier_by_id.items())
            and all(row.get("prompt_id") == prompt_id and row.get("status") == "answered"
                    for key, row in later_by_id.items() if key not in earlier_by_id),
            "cancellation changed old obligations or introduced unfinished work")
    controls = [row for row in state.get("root_controls", []) if isinstance(row, dict)
                and row.get("kind") == "cancel" and row.get("source_prompt_id") == prompt_id
                and row.get("scope_kind") == "current_unit" and row.get("work_unit_id") == unit]
    require(len(controls) == 1 and _sha(controls[0].get("catalog_sha256"))
            and _sha(prompts[0].get("record_sha256")) and prompts[0].get("origin", "human") == "human"
            and controls[0].get("source_record_sha256") == prompts[0].get("record_sha256")
            and type(prompts[0].get("core_event_seq")) is int
            and controls[0].get("source_seq") == prompts[0].get("core_event_seq"),
            "bound cancellation unavailable")
    items = controls[0].get("items")
    require(isinstance(items, list) and all(isinstance(row, dict) for row in items), "cancel catalog malformed")
    covered = sorted([{"id": row.get("id"), "sha256": row.get("source_sha256"),
                       "work_unit_id": row.get("work_unit_id")} for row in items], key=lambda row: str(row["id"]))
    require(covered == prior, "cancel catalog does not cover all original obligations")
    unit_rows = [row for row in state.get("work_units", []) if isinstance(row, dict) and row.get("id") == unit]
    cancel_rows = [row for row in state.get("requirements", []) if isinstance(row, dict)
                   and row.get("prompt_id") == prompt_id]
    require(len(unit_rows) == 1 and unit_rows[0].get("status") == "historical_unresolved"
            and cancel_rows and all(row.get("status") == "answered" for row in cancel_rows),
            "cancellation was not recorded as a closed control")
    require(scope == {"current": [], "ancestor": [], "waiting": 0}, "unfinished current scope remains")
    def safe_req(row: dict[str, Any]) -> dict[str, Any]:
        return {key: row.get(key) for key in ("id", "sha256", "work_unit_id", "status", "prompt_id")}
    safe_control = {key: controls[0].get(key) for key in
                    ("kind", "source_prompt_id", "source_record_sha256", "source_seq",
                     "scope_kind", "work_unit_id", "catalog_sha256")}
    safe_control["items"] = [{key: row.get(key) for key in ("id", "source_sha256", "work_unit_id")} for row in items]
    return {"session_id": session, "initial_pending": prior, "covered": covered,
            "cancel_prompt_sha256": cancel_sha, "catalog_sha256": controls[0]["catalog_sha256"],
            "work_unit_status": "historical_unresolved", "cancel_control_status": "answered", "scope": scope,
            "before": {"session": {"id": session}, "requirements": [safe_req(row) for row in earlier]},
            "after": {"session": {"id": session}, "requirements": [safe_req(row) for row in later],
                      "prompts": [{"id": prompt_id, "sha256": cancel_sha,
                                   "record_sha256": prompts[0]["record_sha256"],
                                   "origin": prompts[0].get("origin", "human"),
                                   "core_event_seq": prompts[0]["core_event_seq"]}], "root_controls": [safe_control],
                      "work_units": [{"id": unit, "status": "historical_unresolved"}]}}


def _check_cancel_evidence(value: Any, before: Any, session: str) -> None:
    proof = _object(value)
    rebuilt = _cancel_evidence(proof.get("before"), proof.get("after"), _object(proof.get("scope")))
    require({key: val for key, val in proof.items() if key != "state_sha256"} == rebuilt
            and _pending_bound(proof.get("before")) == _pending_bound(before), "cancel projection or original debt differs")
    pending = proof.get("initial_pending")
    require(isinstance(pending, list) and pending and all(isinstance(row, dict)
            and set(row) == {"id", "sha256", "work_unit_id"}
            and isinstance(row["id"], str) and _sha(row["sha256"])
            and isinstance(row["work_unit_id"], str) and bool(row["work_unit_id"]) for row in pending),
            "cancelled obligation identity malformed")
    require({(row["id"], row["sha256"]) for row in pending} == _pending(before)
            and len({row["id"] for row in pending}) == len(pending)
            and len({row["work_unit_id"] for row in pending}) == 1
            and proof.get("covered") == pending and proof.get("session_id") == session
            and proof.get("cancel_prompt_sha256") == hashlib.sha256("取消当前任务。".encode()).hexdigest()
            and _sha(proof.get("catalog_sha256")) and _sha(proof.get("state_sha256"))
            and proof.get("work_unit_status") == "historical_unresolved"
            and proof.get("cancel_control_status") == "answered"
            and proof.get("scope") == {"current": [], "ancestor": [], "waiting": 0},
            "cancelled task evidence differs")


def _cache_identity(root: Path) -> str:
    """Bind all owned cache objects without persisting platform object IDs."""
    _no_link_ancestors(root.absolute())
    values = []
    stack = [root]
    while stack:
        path = stack.pop()
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "linked cache object refused")
        require(stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                "invalid cache object")
        require(type(info.st_dev) is int and info.st_dev >= 0 and type(info.st_ino) is int and info.st_ino > 0,
                "cache object identity unavailable")
        values.append((path.relative_to(root).as_posix(), info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)))
        require(len(values) <= 10000, "cache object limit")
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    require(not _credential_name(entry.name), "credential-named cache object refused")
                    stack.append(Path(entry.path))
    return digest(sorted(values))


def validate_continuity(before: Any, after: Any) -> None:
    """No implicit state migration: verify requirements in the observed data root."""
    old, new = _object(before), _object(after)
    require(_object(old.get("session")).get("id") == _object(new.get("session")).get("id")
            and isinstance(_object(old.get("session")).get("id"), str), "session changed")
    require(_pending(old) <= _pending(new), "unfinished requirements not preserved")


def _approved_read_command(raw: Any, expected: str) -> bool:
    """Accept only the precise controlled read and its known visible wrapper."""
    if expected == "cat native-read.txt":
        return raw in (expected, "/bin/zsh -c 'cat native-read.txt'", "/bin/zsh -lc 'cat native-read.txt'")
    if expected == "Get-Content -LiteralPath native-read.txt":
        return raw == expected
    return False


def verify_read_tool(rows: Any, inventory: dict[tuple[str, str], dict[str, Any]],
                     thread: str, turn: str, command: str, cwd: Path) -> None:
    """Require the same real read-only command and corresponding Hook pair."""
    require(isinstance(rows, list), "RPC journal unavailable")
    starts: dict[str, dict[str, Any]] = {}
    completed = []
    item_start = item_end = None
    pre_end: list[int] = []
    post_start: list[int] = []
    for index, row in enumerate(rows):
        entry = _object(row)
        message = _object(entry.get("message"))
        params = _object(message.get("params"))
        if (entry.get("direction") != "response" or params.get("threadId") != thread
                or params.get("turnId") != turn):
            continue
        item = _object(params.get("item"))
        run = _object(params.get("run"))
        if message.get("method") == "hook/completed" and run.get("eventName") == "preToolUse":
            pre_end.append(index)
        if message.get("method") == "hook/started" and run.get("eventName") == "postToolUse":
            post_start.append(index)
        if item:
            require(item.get("type") in ("commandExecution", "contextCompaction", "agentMessage",
                                          "userMessage", "reasoning", "plan"),
                    "unrelated or unsupported item observed in read turn")
        if item.get("type") != "commandExecution":
            continue
        require(_approved_read_command(item.get("command"), command), "unapproved command observed in read turn")
        item_id = item.get("id")
        require(isinstance(item_id, str) and bool(item_id)
                and native._official_path_matches(item.get("cwd"), cwd, windows=platform.system() == "Windows"),
                "read command identity differs")
        if message.get("method") == "item/started":
            require(item_id not in starts, "duplicate read command start")
            starts[item_id] = item
            require(item_start is None, "multiple read commands")
            item_start = index
        elif message.get("method") == "item/completed":
            require(item_id in starts and type(item.get("exitCode")) is int and item["exitCode"] == 0,
                    "read command did not complete")
            require(item.get("command") == starts[item_id].get("command")
                    and item.get("cwd") == starts[item_id].get("cwd"), "read command changed during execution")
            starts.pop(item_id)
            completed.append(item_id)
            item_end = index
    require(len(completed) == 1 and not starts, "one completed read command required")
    require(_paired(rows, inventory, thread, "preToolUse", turn=turn)
            and _paired(rows, inventory, thread, "postToolUse", turn=turn), "read tool Hooks missing")
    require(pre_end and post_start and item_start is not None and item_end is not None
            and max(pre_end) < item_start < item_end < min(post_start),
            "read tool Hook order not established")


def verify_archive(rows: Any, inventory: dict[tuple[str, str], dict[str, Any]],
                   thread: str) -> None:
    require(isinstance(rows, list), "RPC journal unavailable")
    indices = [i for i, row in enumerate(rows) if isinstance(row, dict)
               and row.get("direction") == "request"
               and _object(row.get("message")).get("method") == "thread/archive"
               and _object(_object(row.get("message")).get("params")).get("threadId") == thread]
    require(len(indices) == 1, "one actual thread/archive request required")
    request = _object(rows[indices[0]].get("message"))
    request_id = request.get("id")
    require(type(request_id) is int, "archive request id missing")
    responses = [_object(row.get("message")) for row in rows[indices[0] + 1:]
                 if isinstance(row, dict) and row.get("direction") == "response"
                 and _object(row.get("message")).get("id") == request_id]
    require(len(responses) == 1 and "error" not in responses[0]
            and isinstance(responses[0].get("result"), dict), "archive response missing or rejected")
    require(_paired(rows, inventory, thread, "sessionEnd", after_index=indices[0] + 1),
            "archive lacks actual SessionEnd")


class UpgradeClient(host.Client):
    """Existing owned app-server transport with source-aware Hook validation."""

    def __init__(self, plan: dict[str, Any], directory: Path,
                 sources: dict[str, str] | None = None, sequence_base: int = 0, *, turn_limit: int):
        require(type(turn_limit) is int and 1 <= turn_limit <= 7, "invalid model turn limit")
        self.turn_limit = turn_limit
        self.approved: dict[tuple[str, str], dict[str, Any]] = {}
        self.initial_sources = sources or {str(Path(plan["plugin_root"]) / "hooks/hooks.json"): "old"}
        self.observation_old_sources = set(self.initial_sources)
        self.initial_approved: dict[tuple[str, str], dict[str, Any]] = {}
        self.guard_diagnostic: dict[str, Any] | None = None
        self.observation_thread: str | None = None
        self.observation_inventory: dict[tuple[str, str], dict[str, Any]] | None = None
        self.turn_count = 0
        self.plan, self.rows, self.pending, self.sequence = plan, [], {}, sequence_base
        self.q = queue.Queue(maxsize=10000)
        self.log = (directory / "rpc.jsonl").open("x", encoding="utf-8")
        self.err = open(os.devnull, "wb")
        self.owned = None
        try:
            self.owned = host.OwnedProcess.spawn(
                [plan["codex"], "app-server"], cwd=plan["cwd"], env=isolated_env(Path(plan["home"])),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                text=True, encoding="utf-8")
            threading.Thread(target=self.reader, daemon=True).start()
            self.rpc("initialize", {"clientInfo": {"name": "cg-native-upgrade", "version": "1"},
                                    "capabilities": {"experimentalApi": True}})
            self.send({"method": "initialized", "params": {}})
            inventory = self.rpc("hooks/list", {"cwds": [plan["cwd"]]})
            rows = inventory.get("data") if isinstance(inventory, dict) else None
            require(isinstance(rows, list) and len(rows) == 1, "initial Hook inventory unavailable")
            self.initial_approved = _inventory(inventory, self.initial_sources)
            self.inventory = {h["eventName"]: h for h in self.initial_approved.values()}
            self.approved = self.initial_approved
        except BaseException:
            self.close()
            raise

    def validate_inventory(self, product: Any, expected_path: Path) -> None:
        del expected_path
        self.initial_approved = _inventory({"data": [{"hooks": product}]}, self.initial_sources)

    def send(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        require(method in {"initialize", "initialized", "hooks/list", "turn/start", "thread/start",
                           "thread/compact/start", "thread/unsubscribe", "thread/resume", "thread/archive",
                           "config/batchWrite"}, "RPC method outside U01 scope")
        if method == "config/batchWrite":
            require(_object(message.get("params")) == {"edits": [{"keyPath":
                    'plugins."context-guard@codex-context-guard".enabled', "value": False,
                    "mergeStrategy": "upsert"}], "reloadUserConfig": True}, "configuration mutation outside U01")
        if type(message.get("id")) is int:
            self.pending[message["id"]] = method
        super().send(message)

    def _projection(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Retain only fields needed by the U01 consumer; reject unknown data."""
        if type(message.get("id")) is int:
            request_id = message["id"]
            method = self.pending.pop(request_id, None)
            require(isinstance(method, str), "unmatched RPC response")
            if "error" in message:
                return {"id": request_id, "error": {"redacted": True}}
            result = _object(message.get("result"))
            if method == "hooks/list":
                data = result.get("data")
                require(isinstance(data, list), "Hook inventory projection unavailable")
                rows = []
                for row in data:
                    require(isinstance(row, dict) and isinstance(row.get("hooks"), list),
                            "Hook inventory projection malformed")
                    rows.append({"hooks": [_hook_projection(x) for x in row["hooks"] if isinstance(x, dict)],
                                 "errors": ["redacted"] if row.get("errors") else [],
                                 "warnings": ["redacted"] if row.get("warnings") else []})
                result = {"data": rows}
            elif method == "thread/start":
                permitted = {"model": {"gpt-6.1-sol", "gpt-6-astra"}, "modelProvider": {"openai"}}
                values = {key: value for key, allowed in permitted.items() if
                          isinstance((value := result.get(key)), str) and value in allowed}
                result = {"thread": {"id": _object(result.get("thread")).get("id")}, **values}
            elif method == "turn/start":
                result = {"turn": {"id": _object(result.get("turn")).get("id")}}
            else:
                result = {}
            return {"id": request_id, "result": result}
        method = message.get("method")
        params = _object(message.get("params"))
        common = {key: params[key] for key in ("threadId", "turnId") if key in params}
        if method in ("hook/started", "hook/completed"):
            run = _object(params.get("run"))
            common["run"] = {key: run[key] for key in
                             ("id", "eventName", "sourcePath", "source", "handlerType", "displayOrder",
                              "executionMode", "status", "durationMs") if key in run}
        elif method in ("turn/started", "turn/completed"):
            turn = _object(params.get("turn"))
            common["turn"] = {key: turn[key] for key in ("id", "status") if key in turn}
        elif method in ("item/started", "item/completed"):
            item = _object(params.get("item"))
            require(isinstance(item.get("type"), str), "item type unavailable")
            common["item"] = {key: item[key] for key in ("id", "type", "cwd", "exitCode") if key in item}
            if item.get("type") == "commandExecution":
                expected = ("Get-Content -LiteralPath native-read.txt" if platform.system() == "Windows"
                            else "cat native-read.txt")
                command = item.get("command")
                common["item"]["command"] = command if _approved_read_command(command, expected) else "<unapproved>"
        elif method == "thread/status/changed":
            common["status"] = {"type": _object(params.get("status")).get("type")}
        else:
            return None
        return {"method": method, "params": common}

    def receive(self, deadline: float) -> dict[str, Any]:
        require(len(self.rows) < 10000, "RPC row limit")
        try:
            message = self.journal_response(self.q.get(timeout=max(.01, deadline - time.monotonic())))
        except queue.Empty as exc:
            raise TimeoutError("RPC response deadline") from exc
        require(not ("reader_error" in message or ("method" in message and "id" in message)),
                "unexpected app-server input")
        if message.get("method") in ("hook/started", "hook/completed") and self.approved:
            params = _object(message.get("params"))
            run = _object(params.get("run"))
            inventory = (self.observation_inventory if getattr(self, "observation_inventory", None) is not None
                         and params.get("threadId") == getattr(self, "observation_thread", None) else self.approved)
            source = _source_key(run.get("sourcePath"), {path for _, path in inventory})
            raw_event = run.get("eventName")
            event = raw_event if isinstance(raw_event, str) and raw_event in EVENTS else "other"
            expected = inventory.get((event, source))
            fields = ("eventName", "source", "handlerType", "displayOrder")
            matches = {key: expected is not None and run.get(key) == expected.get(key) for key in fields}
            mode_match = expected is not None and run.get("executionMode") == ("async" if expected.get("async") else "sync")
            if not all(matches.values()) or not mode_match:
                old = self.initial_approved.get((event, source))
                self.guard_diagnostic = {"schema": "cg-u01-guard-diagnostic/v1", "stage": "receive",
                    "method": message["method"],
                    "event": event,
                    "source_class": ("old" if source in getattr(self, "observation_old_sources", self.initial_sources)
                                     else "new" if source else "other"),
                    "event_source_approved": expected is not None, "source_matches": matches["source"],
                    "handler_matches": matches["handlerType"], "order_matches": matches["displayOrder"],
                    "mode_matches": mode_match,
                    "target_thread_matches": (getattr(self, "observation_thread", None) is not None
                                              and _object(message.get("params")).get("threadId") == self.observation_thread),
                    "old_inventory_order_matches": old is not None and run.get("displayOrder") == old.get("displayOrder")}
                raise UpgradeError("unexpected running Hook")
        projection = self._projection(message)
        if projection is not None:
            self.rows.append(projection)
            self.log.write(json.dumps({"direction": "response", "message": projection}) + "\n")
            self.log.flush()
        return message

    def refresh(self, sources: dict[str, str]) -> dict[tuple[str, str], dict[str, Any]]:
        result = self.rpc("hooks/list", {"cwds": [self.plan["cwd"]]})
        self.approved = _inventory(result, sources)
        return self.approved

    def start(self, instructions: str = "") -> str:
        del instructions
        params = {"cwd": self.plan["cwd"], "sandbox": "read-only", "approvalPolicy": "on-request",
                  "developerInstructions": ("Isolated acceptance only. You may read exactly the workspace file "
                    "native-read.txt when requested. Do not read configuration, credentials, other files, "
                    "or directories; do not search, access network, or modify anything. Follow the prompt.")}
        return self.rpc("thread/start", params)["thread"]["id"]

    def observed_turn(self, thread: str, prompt: str) -> tuple[str, list[dict[str, Any]]]:
        require(self.turn_count < self.turn_limit, "model turn budget exhausted")
        self.turn_count += 1
        begin = len(self.rows)
        turn = self.rpc("turn/start", {"threadId": thread,
                        "input": [{"type": "text", "text": prompt}]})["turn"]["id"]
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            row = self.receive(deadline)
            if (row.get("method") == "turn/completed"
                    and _object(_object(row.get("params")).get("turn")).get("id") == turn):
                require(row["params"]["turn"].get("status") == "completed", "turn failed")
                rows = [{"direction": "response", "message": item} for item in self.rows[begin:]]
                inventory = (self.observation_inventory if self.observation_inventory is not None
                             and thread == self.observation_thread else self.approved)
                require(_paired(rows, inventory, thread, "stop", turn=turn), "Stop not observed")
                return turn, rows
        raise TimeoutError("turn completion deadline")

    def observed_compact(self, thread: str) -> None:
        """One real pre-upgrade compact with the existing same-turn oracle."""
        require(len(self.approved) == 9, "compact requires exactly one reviewed old source")
        single = {event: item for (event, _source), item in self.approved.items()}
        require(set(single) == EVENTS, "single-source compact inventory incomplete")
        begin = len(self.rows)
        self.rpc("thread/compact/start", {"threadId": thread})
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if host.compact_complete(self.rows[begin:], thread, single):
                return
            self.receive(deadline)
        raise TimeoutError("compact completion and idle deadline")


def preflight(plan: Any, output: Path) -> dict[str, Any]:
    require(isinstance(plan, dict) and plan.get("schema") == PLAN, "wrong plan schema")
    product = _absolute_real(plan.get("product_root"), "product root")
    tool_root = ROOT.resolve(strict=True)
    home = _absolute_real(plan.get("home"), "isolated Codex HOME")
    workspace = _absolute_real(plan.get("workspace"), "workspace")
    old = _absolute_real(plan.get("old_artifact"), "old artifact")
    new = _absolute_real(plan.get("new_artifact"), "new artifact")
    archive = _absolute_real(plan.get("release_zip"), "release ZIP", file=True)
    codex = _absolute_real(plan.get("codex"), "Codex CLI", file=True, allow_hardlinks=True)
    version = plan.get("old_version")
    require(version in OLD_MARKETS, "unsupported starting version")
    require(plan.get("transition_strategy") in ("observe-open", "finish-old"),
            "explicit transition strategy required")
    old_archive = (_absolute_real(plan.get("old_release_zip"), "old release ZIP", file=True)
                   if version == "0.16.1" else None)
    daily = (Path.home() / ".codex").resolve()
    extra = plan.get("other_homes", [])
    require(isinstance(extra, list) and 1 <= len(extra) <= 32,
            "other isolated authentication HOMEs must be listed")
    other_homes = [_absolute_real(value, "other isolated HOME") for value in extra]
    _distinct_homes([home, *other_homes])
    homes = [home, daily, *other_homes]
    auth_homes = [home, *other_homes]
    inherited = os.environ.get("CODEX_HOME")
    if inherited and Path(inherited).is_absolute():
        inherited_home = Path(inherited).resolve()
        homes.append(inherited_home)
        if inherited_home != daily:
            auth_homes.append(inherited_home)
    _cli_scope(codex, daily, auth_homes)
    # Alias enumeration is not available here.  Stop before *any* file hash
    # or executable launch when the public CLI has multiple hard links.
    if codex.stat().st_nlink != 1:
        raise CapabilityPending("public CLI hard-link aliases require review")
    # Check both directions, before any artifact content or digest is read.
    # The exact verified public Codex executable is deliberately exempt.
    for artifact in (old, new, archive, *([old_archive] if old_archive is not None else [])):
        require(all(not _within(artifact, protected_home) and not _within(protected_home, artifact)
                    for protected_home in homes), "artifact overlaps an authentication HOME")
    require(all(not _within(workspace, protected_home) and not _within(protected_home, workspace)
                for protected_home in homes), "workspace overlaps an authentication HOME")
    protected = [product, tool_root, *homes, workspace, old, new]
    _new_outside(output, protected)
    _private_directory(home)
    _private_directory(workspace)
    require(not _within(home, daily) and not _within(daily, home), "daily Codex HOME forbidden")
    require(all(not _within(home, p) and not _within(p, home) for p in (product, tool_root, workspace, old, new)),
            "isolated HOME overlaps another input")
    old_data = _data_candidate(home, plan.get("old_data_root"), "old data root")
    new_data = _data_candidate(home, plan.get("new_data_root"), "new data root")
    _sentinel_paths(home, plan.get("sentinel"))
    zip_identity = _zip_metadata(archive)
    old_zip_identity = _zip_metadata(old_archive) if old_archive is not None else None
    sentinel_facts = _sentinel_files(home, plan.get("sentinel"))
    read_file = workspace / "native-read.txt"
    require(not read_file.is_symlink() and read_file.is_file() and read_file.stat().st_nlink == 1,
            "controlled read fixture unavailable")
    require(_sha(plan.get("read_file_sha256")) and sha(read_file) == plan["read_file_sha256"],
            "controlled read fixture differs")
    require(platform.system() in ("Darwin", "Windows"), "native platform unsupported")
    for key in ("product_commit", "toolkit_commit"):
        require(isinstance(plan.get(key), str) and HEX40.fullmatch(plan[key]), key + " invalid")
    require(_sha(plan.get("release_zip_sha256")) and sha(archive, expected=zip_identity) == plan["release_zip_sha256"],
            "release ZIP digest differs")
    require(_sha(plan.get("codex_sha256")) and sha(codex) == plan["codex_sha256"], "CLI digest differs")
    old_files = source_files(old)
    new_files = source_files(new)  # metadata-only refusal precedes any read in this tree
    old_plugin = _read_json(old / ".codex-plugin/plugin.json")
    old_market = _read_json(old / ".agents/plugins/marketplace.json")
    old_hooks = _read_json(old / "hooks/hooks.json")
    require(old_plugin.get("name") == "context-guard" and old_plugin.get("version") == version
            and old_market.get("name") == OLD_MARKETS[version], "old fixture identity differs")
    require(set(_object(old_hooks.get("hooks"))) == {e[0].upper() + e[1:] for e in EVENTS},
            "old fixture Hook family differs")
    old_tree_sha = digest(old_files)
    require(_sha(plan.get("old_tree_sha256")) and old_tree_sha == plan["old_tree_sha256"],
            "old fixture file inventory differs")
    native.verify_exact_source(product, plan["product_commit"])
    native.verify_exact_source(tool_root, plan["toolkit_commit"])
    provenance = _old_provenance(product, old, version, plan, old_files, old_zip_identity)
    manager = _load_artifacts_no_pyc(product)
    runtime = native.runtime_digest(manager, product)
    require(_sha(plan.get("runtime_sha256")) and runtime == plan["runtime_sha256"], "runtime differs")
    require(adoption.VERSION == plan.get("cli_version"), "explicit CLI capability adoption required")
    # Exact source/ZIP/extracted release parity. No installed cache is needed
    # before initial installation, and no existing cache is copied or edited.
    require(manager.distribution_manifest(product) == new_files, "release manifest differs")
    _zip_exact(archive, zip_identity, new_files)
    return {"product_commit": plan["product_commit"], "toolkit_commit": plan["toolkit_commit"],
            "runtime_sha256": runtime, "release_zip_sha256": plan["release_zip_sha256"],
            "codex_sha256": plan["codex_sha256"], "old_version": version,
            "old_tree_sha256": old_tree_sha, "old_fixture_files": len(old_files), "old_provenance": provenance,
            "home": str(home), "workspace": str(workspace), "product_root": str(product),
            "other_homes": sorted(str(path) for path in other_homes),
            "old_artifact": str(old), "new_artifact": str(new), "release_zip": str(archive),
            "codex": str(codex), "old_data_root": str(old_data), "new_data_root": str(new_data),
            "transition_strategy": plan["transition_strategy"], "platform": platform.system(),
            "sentinel": sentinel_facts, "read_file_sha256": plan["read_file_sha256"],
            "codex_hardlink_count": codex.stat().st_nlink,
            "tool_sha256": sha(Path(__file__))}


def isolated_env(home: Path) -> dict[str, str]:
    """Keep host credentials out of inherited overrides; auth is not read."""
    env = {key: value for key, value in os.environ.items()
           if not re.search(r"TOKEN|PASSWORD|SECRET|API_KEY|CREDENTIAL", key, re.I)}
    for key in ("CONTEXT_GUARD_DATA_DIR", "PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT"):
        env.pop(key, None)
    env.update(CODEX_HOME=str(home), HOME=str(home), USERPROFILE=str(home),
               PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")
    return env


@contextlib.contextmanager
def _launch_environment(home: Path):
    previous = dict(os.environ)
    selected = isolated_env(home)
    try:
        os.environ.clear()
        os.environ.update(selected)
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def _official_install_identity(added: Any, listed: Any, old: Path, home: Path,
                               version: str) -> Path:
    market = OLD_MARKETS[version]
    plugin_id = "context-guard@" + market
    obj = _object(added)
    records = _object(listed).get("installed")
    require(isinstance(records, list), "official installed list unavailable")
    matches = [x for x in records if isinstance(x, dict) and x.get("pluginId") == plugin_id]
    require(len(matches) == 1, "official old plugin identity missing or ambiguous")
    row = matches[0]
    expected = {"pluginId": plugin_id, "name": "context-guard", "marketplaceName": market,
                "version": version}
    require(all(obj.get(k) == v and row.get(k) == v for k, v in expected.items())
            and row.get("installed") is True and row.get("enabled") is True,
            "official old plugin identity differs")
    source = _object(row.get("source"))
    market_source = _object(row.get("marketplaceSource"))
    require(source.get("source") == "local" and market_source.get("sourceType") == "local"
            and native._official_path_matches(source.get("path"), old, windows=os.name == "nt")
            and native._official_path_matches(market_source.get("source"), old, windows=os.name == "nt"),
            "official old marketplace source differs")
    installed_raw = obj.get("installedPath")
    require(isinstance(installed_raw, str), "official installedPath missing")
    cache = home / "plugins" / "cache" / market / "context-guard"
    possible = [cache / version, cache / "local"]
    installed = next((p for p in possible if native._official_path_matches(
        installed_raw, p, windows=os.name == "nt")), None)
    require(installed is not None and not installed.is_symlink() and installed.is_dir(),
            "official installedPath outside target cache")
    return installed


def _json_output(result: Any) -> dict[str, Any]:
    require(result.returncode == 0, "official command failed")
    value = adoption.strict_json(result.stdout.decode("utf-8-sig"))
    require(isinstance(value, dict), "official command did not emit an object")
    return value


def _market_names(result: Any) -> set[str]:
    require(result.returncode == 0, "official marketplace inventory failed")
    value = adoption.strict_json(result.stdout.decode("utf-8-sig"))
    rows = value if isinstance(value, list) else _object(value).get("marketplaces")
    require(isinstance(rows, list) and all(isinstance(item, dict) and isinstance(item.get("name"), str)
                                           for item in rows), "official marketplace inventory shape unavailable")
    names = [item["name"] for item in rows]
    require(len(names) == len(set(names)), "duplicate marketplace identity")
    return set(names)


def _market_entries(result: Any) -> dict[str, dict[str, Any]]:
    names = _market_names(result)
    value = adoption.strict_json(result.stdout.decode("utf-8-sig"))
    rows = value if isinstance(value, list) else value["marketplaces"]
    entries = {item["name"]: item for item in rows}
    require(set(entries) == names, "marketplace entries differ")
    return entries


def _market_source(entries: dict[str, dict[str, Any]], name: str, source: Path) -> None:
    entry = _object(entries.get(name))
    origin = _object(entry.get("marketplaceSource"))
    require(origin.get("sourceType") == "local"
            and native._official_path_matches(entry.get("root"), source, windows=os.name == "nt")
            and native._official_path_matches(origin.get("source"), source, windows=os.name == "nt"),
            "official marketplace source differs")


def _project_cli(argv: list[str], result: Any, selected: set[str]) -> Any:
    """Keep only public, scoped CLI fields; never retain arbitrary output."""
    if argv[1:] == ["--version"]:
        value = result.stdout.decode("utf-8-sig").strip()
        require(value == adoption.VERSION, "CLI version differs")
        return {"version": value}
    if argv[1:4] == ["plugin", "marketplace", "list"]:
        entries = _market_entries(result)
        rows = []
        for name in sorted(entries):
            entry = entries[name]
            item = {"name": name}
            if name in selected:
                source = _object(entry.get("marketplaceSource"))
                if source.get("sourceType") == "local":
                    item.update(root=entry.get("root"),
                                marketplaceSource={"sourceType": "local", "source": source.get("source")})
            rows.append(item)
        return {"marketplaces": rows}
    if argv[1:3] == ["plugin", "list"]:
        require(len(argv) == 6 and argv[3] == "--marketplace" and argv[5] == "--json",
                "plugin inventory must be marketplace scoped")
        value = _json_output(result)
        entries = value.get("installed")
        require(isinstance(entries, list), "official plugin inventory unavailable")
        rows = []
        for entry in entries:
            require(isinstance(entry, dict) and isinstance(entry.get("pluginId"), str)
                    and entry.get("marketplaceName") == argv[4],
                    "official plugin entry malformed")
            item = {"pluginId": entry["pluginId"]}
            if entry.get("marketplaceName") in selected:
                for key in ("name", "marketplaceName", "version", "installed", "enabled"):
                    item[key] = entry.get(key)
                for key in ("source", "marketplaceSource"):
                    data = _object(entry.get(key))
                    if data.get("source") == "local":
                        item[key] = {"source": "local", "path": data.get("path")}
                    elif data.get("sourceType") == "local":
                        item[key] = {"sourceType": "local", "source": data.get("source")}
            rows.append(item)
        return {"installed": rows}
    if argv[1:3] == ["plugin", "add"]:
        value = _json_output(result)
        return {key: value.get(key) for key in
                ("pluginId", "name", "marketplaceName", "version", "installedPath")}
    return None


def _write_new(path: Path, value: dict[str, Any]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _run_official(result: dict[str, Any], argv: list[str], env: dict[str, str],
                  selected: set[str], stage: str) -> Any:
    """Record the attempted operation before launching; never retain process output."""
    fact: dict[str, Any] = {"stage": stage, "argv": argv, "status": "started",
                            "started_monotonic_ns": time.monotonic_ns()}
    result["commands"].append(fact)
    try:
        run = scheduler._command(native, ROOT, argv, env=env, timeout=90)
        fact.update(exit_code=run.returncode, stderr_nonempty=bool(run.stderr))
        require(run.returncode == 0, "official command failed")
        fact["observation"] = _project_cli(argv, run, selected)
        fact["status"] = "completed"
        return run
    except BaseException as exc:
        fact.update(status="failed", failure_type=type(exc).__name__)
        raise
    finally:
        fact["completed_monotonic_ns"] = time.monotonic_ns()


def prepare(plan: dict[str, Any], output: Path) -> dict[str, Any]:
    """Install only the old official fixture; pause for normal Hook review."""
    subject = preflight(plan, output)
    if subject.get("codex_hardlink_count", 1) != 1:
        raise CapabilityPending("public CLI hard-link aliases require review")
    home, old, codex = (Path(plan[key]).resolve(strict=True) for key in ("home", "old_artifact", "codex"))
    market = OLD_MARKETS[plan["old_version"]]
    # A normally opened HOME can already have non-target config/user state.
    # Check only our target cache; official readback below checks registrations.
    target_cache = home / "plugins/cache" / market / "context-guard"
    require(not target_cache.exists() and not target_cache.is_symlink(),
            "fresh isolated HOME required before installation")
    output.mkdir(mode=0o700)
    result: dict[str, Any] = {"schema": REPORT, "status": "pending", "subject": subject,
                              "stage": "prepare", "commands": [],
                              "pending": ["normal_hook_review", "open_task", "cold_resume",
                                          "transition", "session_end", "disable", "removal"]}
    env = isolated_env(home)
    try:
        def run_command(argv: list[str]) -> Any:
            return _run_official(result, argv, env, {market, NEW_MARKET,
                                 _object(plan.get("sentinel")).get("marketplace")}, "prepare")

        version = run_command([str(codex), "--version"])
        require(version.stdout.decode("utf-8-sig").strip() == plan["cli_version"],
                "official CLI version differs")
        markets = _market_names(run_command([str(codex), "plugin", "marketplace", "list", "--json"]))
        require(market not in markets, "target marketplace already registered")
        result["sentinel_before"] = _sentinel_files(home, plan.get("sentinel"))
        require(result["sentinel_before"]["marketplace"] in markets, "sentinel marketplace missing")
        sentinel_market = result["sentinel_before"]["marketplace"]
        before = _json_output(run_command([str(codex), "plugin", "list", "--marketplace", sentinel_market, "--json"]))
        entries = before.get("installed")
        require(isinstance(entries, list) and all(isinstance(x, dict) for x in entries),
                "official plugin inventory unavailable")
        result["before"] = {"marketplace_count": len(markets), "sentinel_installed_count": len(entries),
                            "target_marketplace_absent": True, "target_cache_absent": True,
                            "target_cache_path": str(target_cache)}
        result["sentinel_phases"] = {}

        def observe_sentinel(stage: str) -> None:
            entries = _market_entries(run_command([str(codex), "plugin", "marketplace", "list", "--json"]))
            facts = _sentinel_files(home, plan.get("sentinel"))
            require(facts == result["sentinel_before"] and facts["marketplace"] in entries,
                    "unrelated sentinel changed")
            _market_source(entries, market, old)
            result["sentinel_phases"][stage] = facts

        run_command([str(codex), "plugin", "marketplace", "add", str(old)])
        observe_sentinel("after_marketplace_add")
        added = _json_output(run_command([str(codex), "plugin", "add", "context-guard@" + market, "--json"]))
        observe_sentinel("after_plugin_add")
        listed = _json_output(run_command([str(codex), "plugin", "list", "--marketplace", market, "--json"]))
        installed = _official_install_identity(added, listed, old, home, plan["old_version"])
        installed_files = source_files(installed)
        require(installed_files == source_files(old), "old source/cache full-file parity differs")
        observe_sentinel("after_plugin_list")
        result["sentinel_after"] = _sentinel_files(home, plan.get("sentinel"))
        require(result["sentinel_before"] == result["sentinel_after"], "unrelated sentinel changed")
        result["official_add"] = {key: added[key] for key in
                                  ("pluginId", "name", "marketplaceName", "version", "installedPath")}
        result["installed"] = {"path": str(installed), "file_count": len(installed_files),
                               "files_sha256": digest(installed_files),
                               "marketplace": market, "version": plan["old_version"]}
    except BaseException as exc:
        result["status"] = "failed"
        result["failure"] = type(exc).__name__
    _write_new(output / "prepare.json", result)
    return result


def _state_at(home: Path, root_value: Any, thread: str) -> tuple[Path, dict[str, Any]]:
    require(isinstance(root_value, str) and isinstance(thread, str)
            and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", thread), "invalid state subject")
    root = Path(root_value)
    require(root.is_absolute() and not root.is_symlink(), "data root must be absolute and real")
    root = root.resolve(strict=True)
    require(home in root.parents, "data root outside isolated HOME")
    path = host.session_state_path(root, thread)
    require(path.resolve(strict=True).is_relative_to(root), "state path escapes data root")
    for component in (root / "sessions-v2", root / "sessions", path.parent, path):
        if component.exists() or component.is_symlink():
            info = component.lstat()
            require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                    "linked state path refused")
    require(path.is_file() and path.stat().st_nlink == 1, "observed task state missing or linked")
    state = _read_json(path)
    require(_object(state.get("session")).get("id") == thread, "state thread identity differs")
    return root, state


def _state_at_bound(home: Path, root_value: Any, thread: str) -> tuple[Path, dict[str, Any], str]:
    root, _ = _state_at(home, root_value, thread)
    candidates = [root / "sessions-v2" / thread / "state.json", root / "sessions" / thread / "state.json"]
    present = [path for path in candidates if path.exists() or path.is_symlink()]
    require(len(present) == 1, "ambiguous task state paths")
    state, raw_sha = _read_json_with_sha(present[0])
    require([path for path in candidates if path.exists() or path.is_symlink()] == present,
            "task state path changed during read")
    require(_object(state.get("session")).get("id") == thread, "state thread identity differs")
    return root, state, raw_sha


def _write_bound_state(path: Path, state: dict[str, Any], raw_sha: str) -> None:
    require(_sha(raw_sha), "state snapshot digest unavailable")
    _write_new(path, {"source_state_sha256": raw_sha, "state": _state_projection(state)})


def _reviewed_sources(client: UpgradeClient, allowed: dict[str, str], required: str,
                      timeout: float = 300.0) -> dict[tuple[str, str], dict[str, Any]]:
    """Wait for normal external review; an operator signal is never evidence."""
    deadline = time.monotonic() + timeout
    last_error = "Hook inventory unavailable"
    while time.monotonic() < deadline:
        value = client.rpc("hooks/list", {"cwds": [client.plan["cwd"]]})
        rows = value.get("data") if isinstance(value, dict) else None
        hooks = _object(rows[0]).get("hooks") if isinstance(rows, list) and len(rows) == 1 else None
        if not isinstance(hooks, list):
            raise UpgradeError("Hook inventory unavailable")
        paths = {_source_key(item.get("sourcePath"), allowed) for item in hooks if isinstance(item, dict)}
        if paths and None not in paths and required in paths:
            try:
                approved = _inventory(value, {p: allowed[p] for p in paths})
                client.approved = approved
                return approved
            except UpgradeError as exc:
                last_error = str(exc)
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
    raise UpgradeError("normal Hook review pending: " + last_error)


def _pre_disable_projection(value: Any, old_source: str, new_source: str) -> list[dict[str, Any]]:
    rows = _object(value).get("data")
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict)
            and not rows[0].get("errors") and not rows[0].get("warnings")
            and isinstance(rows[0].get("hooks"), list), "pre-disable Hook inventory unavailable")
    projected = []
    for item in rows[0]["hooks"]:
        require(isinstance(item, dict) and item.get("eventName") in EVENTS
                and type(item.get("enabled")) is bool and item.get("trustStatus") in ("trusted", "untrusted"),
                "pre-disable Hook entry malformed")
        source = _source_key(item.get("sourcePath"), [old_source, new_source])
        require(source is not None, "unexpected pre-disable Hook source")
        projected.append({"event": item["eventName"], "source": "old" if source == old_source else "new",
                          "enabled": item["enabled"], "trust": item["trustStatus"]})
    for label in ("old", "new"):
        selected = [item for item in projected if item["source"] == label]
        require((len(selected) == 9 if label == "old" else len(selected) in (0, 9))
                and len({item["event"] for item in selected}) == len(selected), "pre-disable Hook family differs")
        if label == "old":
            require(all(item["enabled"] and item["trust"] == "trusted" for item in selected),
                    "old Hooks not trusted before disable")
        else:
            require(all(not (item["enabled"] and item["trust"] == "trusted") for item in selected),
                    "both Hook identities trusted at pre-disable sample")
    return sorted(projected, key=lambda item: (item["source"], item["event"]))


def _sample_pre_disable(client: UpgradeClient, old_source: str, new_source: str, result: dict[str, Any]) -> None:
    sample = client.rpc("hooks/list", {"cwds": [client.plan["cwd"]]})
    result["pre_disable_inventory"] = _pre_disable_projection(sample, old_source, new_source)
    client.log.write(json.dumps({"direction": "observation", "event": "pre_disable_sample",
        "pid": client.owned.process.pid, "monotonic_ns": time.monotonic_ns()}) + "\n")
    client.log.flush()


def _archive_owned(client: UpgradeClient, thread: str) -> None:
    client.rpc("thread/archive", {"threadId": thread})
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        client.log.flush()
        rows = [adoption.strict_json(line) for line in
                (Path(client.log.name)).read_text(encoding="utf-8").splitlines()]
        try:
            inventory = (client.observation_inventory if client.observation_inventory is not None
                         and thread == client.observation_thread else client.approved)
            verify_archive(rows, inventory, thread)
            return
        except UpgradeError:
            client.receive(deadline)
    raise UpgradeError("archive SessionEnd was not established")


def _mark(client: UpgradeClient, event: str) -> None:
    require(event in ("transition_started", "transition_completed", "disable_completed",
                      "plugin_removed", "marketplace_removed"), "invalid local transition marker")
    require(client.owned.process.poll() is None, "owned app-server exited")
    client.log.write(json.dumps({"direction": "local", "event": event,
                                 "pid": client.owned.process.pid,
                                 "monotonic_ns": time.monotonic_ns()}) + "\n")
    client.log.flush()


def _wait_hook(client: UpgradeClient, thread: str, event: str, begin: int,
               timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = [{"direction": "response", "message": x} for x in client.rows[begin:]]
        inventory = (client.observation_inventory if client.observation_inventory is not None
                     and thread == client.observation_thread else client.approved)
        try:
            if _paired(rows, inventory, thread, event):
                return
        except UpgradeError as exc:
            if str(exc) != "unfinished Hook run":
                raise
        client.receive(deadline)
    raise UpgradeError(event + " not established")


def _try_wait_cold_start(client: UpgradeClient, thread: str, begin: int) -> None:
    """Allow a missing pre-turn notification; it must still occur before Stop."""
    try:
        _wait_hook(client, thread, "sessionStart", begin, timeout=3.0)
    except TimeoutError:
        return
    except UpgradeError as exc:
        if str(exc) != "sessionStart not established":
            raise


def _selected_states(home: Path, roots: list[tuple[str, str]]) -> dict[str, str]:
    facts = {}
    for root, thread in roots:
        actual, state = _state_at(home, root, thread)
        facts[str(actual) + "/" + thread] = digest(state)
    return facts


def _close_observation(client: UpgradeClient, role: str, system: str) -> dict[str, Any]:
    pid = client.owned.process.pid
    facts = client.close()
    require(isinstance(facts, dict) and facts.get("owned_process_exited") is True
            and facts.get("owned_tree_no_running_members") is True
            and facts.get("process_group_cleanup_error") is None, "observation process cleanup unknown")
    if system == "Windows":
        require(facts.get("cleanup_complete") is True and facts.get("job_close_confirmed") is True,
                "observation Job cleanup unknown")
    return {"role": role, "pid": pid, "closed_monotonic_ns": time.monotonic_ns(), "facts": facts}


def _root_snapshots(home: Path, old_root: Path, new_root: Path, thread: str) -> dict[str, Any]:
    snapshots = {}
    for label, root in (("old", old_root), ("new", new_root)):
        candidates = [root / "sessions-v2" / thread / "state.json", root / "sessions" / thread / "state.json"]
        present = [path for path in candidates if path.exists() or path.is_symlink()]
        require(len(present) <= 1, "ambiguous task state paths")
        if not present:
            snapshots[label] = {"present": False, "prompts": []}
            continue
        _actual_root, state, state_sha = _state_at_bound(home, str(root), thread)
        rows = state.get("prompts")
        require(isinstance(rows, list) and len(rows) <= 10000, "task prompt markers unavailable")
        markers = []
        for row in rows:
            require(isinstance(row, dict), "task prompt marker malformed")
            turn = row.get("turn_id")
            if turn is None:
                continue
            require(isinstance(turn, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", turn)
                    and isinstance(row.get("id"), str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", row["id"])
                    and _sha(row.get("sha256")) and _sha(row.get("record_sha256"))
                    and type(row.get("core_event_seq")) is int and row["core_event_seq"] > 0,
                    "task prompt marker identity unavailable")
            markers.append({key: row[key] for key in ("id", "turn_id", "sha256", "record_sha256", "core_event_seq")})
        snapshots[label] = {"present": True, "state_sha256": state_sha, "prompts": markers}
    return snapshots


def _root_turn_trace(before: Any, after: Any, thread: str, turn: str, *, shared: bool) -> dict[str, Any]:
    expected = hashlib.sha256("请仅回复观察结束。".encode()).hexdigest()
    found = []
    for label in ("old", "new"):
        prior, later = _object(_object(before).get(label)), _object(_object(after).get(label))
        require(type(prior.get("present")) is bool and type(later.get("present")) is bool
                and isinstance(prior.get("prompts"), list) and isinstance(later.get("prompts"), list),
                "root snapshots malformed")
        for snapshot in (prior, later):
            require((_sha(snapshot.get("state_sha256")) if snapshot["present"] else
                     snapshot.get("state_sha256") is None and not snapshot["prompts"]), "root state marker malformed")
            require(all(isinstance(row, dict) and set(row) == {"id", "turn_id", "sha256", "record_sha256", "core_event_seq"}
                    and isinstance(row.get("id"), str) and isinstance(row.get("turn_id"), str)
                    and _sha(row.get("sha256")) and _sha(row.get("record_sha256"))
                    and type(row.get("core_event_seq")) is int and row["core_event_seq"] > 0
                    for row in snapshot["prompts"]), "root markers malformed")
        require(not any(row.get("turn_id") == turn for row in prior["prompts"]), "turn already existed before observation")
        matches = [row for row in later["prompts"] if row.get("turn_id") == turn]
        if matches:
            require(len(matches) == 1 and matches[0].get("sha256") == expected
                    and _sha(matches[0].get("record_sha256")) and type(matches[0].get("core_event_seq")) is int,
                    "observed turn is not bound to the controlled prompt")
            require(not prior["present"] or prior.get("state_sha256") != later.get("state_sha256"),
                    "observed turn did not change the data-root state")
            found.append(label)
    if shared:
        require(_object(before).get("old") == _object(before).get("new")
                and _object(after).get("old") == _object(after).get("new") and found == ["old", "new"],
                "shared root turn not established")
        root = "shared"
    else:
        require(len(found) == 1, "actual turn data root unknown or ambiguous")
        root = found[0]
    return {"thread": thread, "turn": turn, "actual_root": root, "before": before, "after": after}


def _validate_root_snapshot_map(value: Any) -> None:
    snapshots = _object(value)
    require(set(snapshots) == {"old", "new"}, "root snapshot labels differ")
    for snapshot in snapshots.values():
        require(isinstance(snapshot, dict) and type(snapshot.get("present")) is bool
                and isinstance(snapshot.get("prompts"), list), "root snapshot malformed")
        require((_sha(snapshot.get("state_sha256")) if snapshot["present"] else
                 snapshot.get("state_sha256") is None and not snapshot["prompts"]), "root presence marker differs")


def _run_observation(plan: dict[str, Any], output: Path, subject: dict[str, Any],
                     previous: dict[str, Any], installed: Path) -> dict[str, Any]:
    """Observe one deliberately open old task; never certify safe migration."""
    home, old, new, workspace, codex = (Path(plan[k]).resolve(strict=True) for k in
                                        ("home", "old_artifact", "new_artifact", "workspace", "codex"))
    old_market = OLD_MARKETS[plan["old_version"]]
    output.mkdir(mode=0o700)
    live_dir, cold_dir = output / "live", output / "cold"
    live_dir.mkdir(mode=0o700)
    cold_dir.mkdir(mode=0o700)
    result: dict[str, Any] = {"schema": REPORT, "stage": "observe_open", "status": "pending",
                              "subject": subject, "commands": [], "cleanup": [],
                              "pending": ["independent_consumer"],
                              "limitations": ["deliberately open old task is observation only; no safe-upgrade claim"]}
    env = isolated_env(home)
    live = cold = None
    try:
        def command(argv: list[str]) -> Any:
            return _run_official(result, argv, env, {old_market, NEW_MARKET,
                                 _object(plan.get("sentinel")).get("marketplace")}, "observe_open")
        sentinel = _sentinel_files(home, plan.get("sentinel"))
        require(sentinel == subject.get("sentinel") == previous.get("sentinel_after"), "sentinel changed")
        markets = _market_entries(command([str(codex), "plugin", "marketplace", "list", "--json"]))
        require(sentinel["marketplace"] in markets, "sentinel marketplace missing")
        _market_source(markets, old_market, old)
        prior = _json_output(command([str(codex), "plugin", "list", "--marketplace", old_market, "--json"]))
        require(_official_install_identity(previous.get("official_add"), prior, old, home,
                                          plan["old_version"]) == installed, "old installation differs")
        old_files = source_files(installed)
        require(old_files == source_files(old), "old cache bytes differ")
        cache_before = {"files_sha256": digest(old_files), "objects_sha256": _cache_identity(installed)}
        client_plan = {"codex": str(codex), "cwd": str(workspace), "home": str(home),
                       "plugin_root": str(installed)}
        with _launch_environment(home):
            live = UpgradeClient(client_plan, live_dir, turn_limit=2)
        old_source = str(installed / "hooks/hooks.json")
        old_inventory = dict(live.approved)
        result["old_inventory"] = list(old_inventory.values())
        thread = live.start()
        read_command = ("Get-Content -LiteralPath native-read.txt" if platform.system() == "Windows"
                        else "cat native-read.txt")
        read_file = workspace / "native-read.txt"
        require(sha(read_file) == subject["read_file_sha256"], "read fixture differs")
        first, first_rows = live.observed_turn(thread, "$context-guard\n请验证 native-read.txt 的 SHA256，"
            "收到我的允许后再进行。先仅读取一次，执行精确命令：" + read_command)
        verify_read_tool(first_rows, old_inventory, thread, first, read_command, workspace)
        old_data, before, before_state_sha = _state_at_bound(home, plan.get("old_data_root"), thread)
        _pending(before)
        _write_bound_state(output / "old-before.json", before, before_state_sha)
        result["before"] = {"thread": thread, "turn": first, "old_data_root": str(old_data),
                            "read_command": read_command, "read_file_sha256": sha(read_file),
                            "state_sha256": before_state_sha,
                            "app_server_pid": live.owned.process.pid}
        _mark(live, "transition_started")
        if old_market == NEW_MARKET:
            command([str(codex), "plugin", "marketplace", "remove", old_market])
        command([str(codex), "plugin", "marketplace", "add", str(new)])
        added = _json_output(command([str(codex), "plugin", "add", "context-guard@" + NEW_MARKET, "--json"]))
        listed = _json_output(command([str(codex), "plugin", "list", "--marketplace", NEW_MARKET, "--json"]))
        new_installed = native.official_identity(listed, added, new, home, "0.17.0")
        public_files = _load_artifacts_no_pyc(Path(plan["product_root"])).distribution_manifest(Path(plan["product_root"]))
        native.exact_artifact_parity(new_installed, public_files)
        require(source_files(new_installed) == public_files, "new cache bytes differ")
        new_source = str(new_installed / "hooks/hooks.json")
        _require_distinct_sources(old_source, new_source)
        result["installed_new"] = {"path": str(new_installed), "source": str(new), "version": "0.17.0",
                                   "files": public_files, "old_cache_exists": installed.is_dir()}
        if old_market != NEW_MARKET:
            after_install = {"files_sha256": digest(source_files(installed)), "objects_sha256": _cache_identity(installed)}
            require(after_install == cache_before, "old cache changed during stable installation")
            result["old_cache_preservation"] = {"before": cache_before, "after_new_install": after_install}
        _mark(live, "transition_completed")
        if old_market != NEW_MARKET:
            _sample_pre_disable(live, old_source, new_source, result)
        _write_new(output / "review-required.json", {"message": ("Disable the old experimental plugin normally, "
            "then review the stable Hooks in the official CLI TUI." if old_market != NEW_MARKET
            else "Review Hooks normally in the official CLI TUI.")})
        if old_market != NEW_MARKET:
            deadline = time.monotonic() + 300
            while True:
                old_list = _json_output(command([str(codex), "plugin", "list", "--marketplace", old_market, "--json"]))
                row = _selected_plugin(old_list, "context-guard@" + old_market)
                if row is not None and row.get("version") == plan["old_version"] and row.get("installed") is True and row.get("enabled") is False:
                    break
                require(time.monotonic() < deadline, "normal old-plugin disable pending")
                time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
            stable = _json_output(command([str(codex), "plugin", "list", "--marketplace", NEW_MARKET, "--json"]))
            row = _selected_plugin(stable, "context-guard@" + NEW_MARKET)
            require(row is not None and row.get("version") == "0.17.0"
                    and row.get("installed") is True and row.get("enabled") is True, "stable plugin is not enabled")
            after_disable = {"files_sha256": digest(source_files(installed)), "objects_sha256": _cache_identity(installed)}
            require(after_disable == cache_before, "old cache changed during normal disable")
            result["old_cache_preservation"]["after_old_disable"] = after_disable
            live.log.write(json.dumps({"direction": "observation", "event": "old_identity_disabled",
                "pid": live.owned.process.pid, "monotonic_ns": time.monotonic_ns()}) + "\n")
            live.log.flush()
        new_inventory = _reviewed_sources(live, {new_source: "0.17.0"}, new_source)
        result["new_inventory"] = list(new_inventory.values())
        live.observation_thread = thread
        live.observation_inventory = {**old_inventory, **new_inventory}
        new_root = Path(plan["new_data_root"])
        shared_root = old_data == new_root
        live_roots_before = _root_snapshots(home, old_data, new_root, thread)
        require(live_roots_before["old"].get("state_sha256") == before_state_sha,
                "old baseline state changed before observation")
        result["live_observation"] = {"status": "pending"}
        try:
            turn, rows = live.observed_turn(thread, "请仅回复观察结束。")
            stops = _paired(rows, live.observation_inventory, thread, "stop", turn=turn)
            sources = sorted({"old" if _source_key(row.get("sourcePath"), [old_source]) else "new" for row in stops})
            result["live_observation"] = {"status": "observed", "turn": turn, "stop_sources": sources}
            live.rpc("thread/unsubscribe", {"threadId": thread})
        except UpgradeError:
            require(live.guard_diagnostic is not None and live.guard_diagnostic.get("target_thread_matches") is True,
                    "live observation failed without a scoped guard reason")
            _write_new(output / "live-guard.json", live.guard_diagnostic)
            result["live_observation"] = {"status": "unsupported_guard"}
        result["cleanup"].append(_close_observation(live, "old_live", subject["platform"]))
        live = None
        _, after_live, old_live_sha = _state_at_bound(home, plan.get("old_data_root"), thread)
        validate_continuity(before, after_live)
        _write_bound_state(output / "old-after-live.json", after_live, old_live_sha)
        live_roots_after = _root_snapshots(home, old_data, new_root, thread)
        require(live_roots_after["old"].get("state_sha256") == old_live_sha, "old live state snapshot changed")
        if result["live_observation"]["status"] == "observed":
            try:
                trace = _root_turn_trace(live_roots_before, live_roots_after, thread,
                                         result["live_observation"]["turn"], shared=shared_root)
                result["live_observation"]["actual_root"] = trace["actual_root"]
            except UpgradeError:
                trace = {"thread": thread, "turn": result["live_observation"]["turn"], "actual_root": "unknown",
                         "before": live_roots_before, "after": live_roots_after}
                result["live_observation"].update(status="root_unobserved", actual_root="unknown")
        else:
            trace = {"thread": thread, "turn": None, "actual_root": "unknown",
                     "before": live_roots_before, "after": live_roots_after}
            result["live_observation"]["actual_root"] = "unknown"
        _write_new(output / "live-roots.json", trace)
        new_path = host.session_state_path(new_root, thread)
        result["data_observations"] = {"old_root": str(old_data), "new_root": str(new_root), "new_after_live": "absent"}
        if new_path.exists() or new_path.is_symlink():
            _, state, new_live_sha = _state_at_bound(home, str(new_root), thread)
            require(live_roots_after["new"].get("state_sha256") == new_live_sha, "new live state snapshot changed")
            _write_bound_state(output / "new-after-live.json", state, new_live_sha)
            result["data_observations"]["new_after_live"] = "observed"
        if result["live_observation"]["actual_root"] == "unknown":
            result["live_observation"]["ledger_compatibility"] = "unobserved"
        else:
            actual_state = after_live if result["live_observation"]["actual_root"] in ("old", "shared") else state
            result["live_observation"]["ledger_compatibility"] = (
                "preserved" if _pending(before) <= _pending(actual_state, allow_empty=True) else "lost")
        cold_plan = {**client_plan, "plugin_root": str(new_installed)}
        with _launch_environment(home):
            cold = UpgradeClient(cold_plan, cold_dir, sources={new_source: "0.17.0"}, turn_limit=1)
        cold.log.write(json.dumps({"direction": "observation", "event": "cold_client_started",
            "pid": cold.owned.process.pid, "monotonic_ns": time.monotonic_ns()}) + "\n")
        cold.log.flush()
        cold.observation_thread = thread
        cold.observation_inventory = {**old_inventory, **cold.approved}
        cold.observation_old_sources = {old_source}
        cold_roots_before = _root_snapshots(home, old_data, new_root, thread)
        result["cold_observation"] = {"status": "pending"}
        try:
            begin = len(cold.rows)
            try:
                cold.rpc("thread/resume", {"threadId": thread, "cwd": str(workspace),
                                           "sandbox": "read-only", "approvalPolicy": "on-request"})
            except ValueError as exc:
                if str(exc) != "RPC rejected: thread/resume":
                    raise
                result["cold_observation"] = {"status": "unsupported_resume"}
            if result["cold_observation"]["status"] == "pending":
                _try_wait_cold_start(cold, thread, begin)
                turn, rows = cold.observed_turn(thread, "请仅回复观察结束。")
                stops = _paired(rows, cold.observation_inventory, thread, "stop", turn=turn)
                cold.log.flush()
                journal = _journal(cold_dir / "rpc.jsonl")
                phase = None
                for candidate, label in ((new_source, "new"), (old_source, "old")):
                    try:
                        phase = (*_cold_session_phase(journal, cold.observation_inventory, thread, turn, candidate), label)
                        break
                    except UpgradeError:
                        continue
                _archive_owned(cold, thread)
                result["cold_observation"] = {"status": "observed" if phase is not None else "session_start_unobserved", "turn": turn,
                    "stop_sources": sorted({"old" if _source_key(row.get("sourcePath"), [old_source]) else "new" for row in stops}),
                    "session_start_phase": phase[0] if phase is not None else None,
                    "session_started_before_first_turn": phase[1] if phase is not None else None,
                    "session_start_source": phase[2] if phase is not None else None, "late_archive": "observed"}
        except UpgradeError:
            require(cold.guard_diagnostic is not None and cold.guard_diagnostic.get("target_thread_matches") is True,
                    "cold observation failed without a scoped guard reason")
            _write_new(output / "cold-guard.json", cold.guard_diagnostic)
            result["cold_observation"] = {"status": "unsupported_guard"}
        result["cleanup"].append(_close_observation(cold, "cold", subject["platform"]))
        cold = None
        _, after_cold, old_cold_sha = _state_at_bound(home, plan.get("old_data_root"), thread)
        validate_continuity(before, after_cold)
        _write_bound_state(output / "old-after-cold.json", after_cold, old_cold_sha)
        cold_roots_after = _root_snapshots(home, old_data, new_root, thread)
        require(cold_roots_after["old"].get("state_sha256") == old_cold_sha, "old cold state snapshot changed")
        if result["cold_observation"]["status"] in ("observed", "session_start_unobserved"):
            try:
                trace = _root_turn_trace(cold_roots_before, cold_roots_after, thread,
                                         result["cold_observation"]["turn"], shared=shared_root)
                result["cold_observation"]["actual_root"] = trace["actual_root"]
            except UpgradeError:
                trace = {"thread": thread, "turn": result["cold_observation"]["turn"], "actual_root": "unknown",
                         "before": cold_roots_before, "after": cold_roots_after}
                result["cold_observation"].update(status="root_unobserved", actual_root="unknown")
        else:
            trace = {"thread": thread, "turn": None, "actual_root": "unknown",
                     "before": cold_roots_before, "after": cold_roots_after}
            result["cold_observation"]["actual_root"] = "unknown"
        _write_new(output / "cold-roots.json", trace)
        result["data_observations"]["new_after_cold"] = "absent"
        if new_path.exists() or new_path.is_symlink():
            _, state, new_cold_sha = _state_at_bound(home, str(new_root), thread)
            require(cold_roots_after["new"].get("state_sha256") == new_cold_sha, "new cold state snapshot changed")
            _write_bound_state(output / "new-after-cold.json", state, new_cold_sha)
            result["data_observations"]["new_after_cold"] = "observed"
        if result["cold_observation"]["actual_root"] == "unknown":
            result["cold_observation"]["ledger_compatibility"] = "unobserved"
        else:
            actual_state = after_cold if result["cold_observation"]["actual_root"] in ("old", "shared") else state
            result["cold_observation"]["ledger_compatibility"] = (
                "preserved" if _pending(before) <= _pending(actual_state, allow_empty=True) else "lost")
        result["sentinel_after"] = _sentinel_files(home, plan.get("sentinel"))
        require(result["sentinel_after"] == sentinel, "sentinel changed during observation")
        final_markets = _market_entries(command([str(codex), "plugin", "marketplace", "list", "--json"]))
        require(sentinel["marketplace"] in final_markets, "sentinel marketplace missing after observation")
        _market_source(final_markets, NEW_MARKET, new)
        if old_market != NEW_MARKET:
            _market_source(final_markets, old_market, old)
        statuses = (result["live_observation"]["status"], result["cold_observation"]["status"])
        ledgers = (result["live_observation"]["ledger_compatibility"], result["cold_observation"]["ledger_compatibility"])
        result["status"] = ("observation_complete" if statuses == ("observed", "observed") and ledgers == ("preserved", "preserved") else
                            "observation_pending" if any(s in ("root_unobserved", "session_start_unobserved") for s in statuses)
                            else "unsupported_continuity")
    except BaseException as exc:
        result["status"], result["failure"] = "failed", type(exc).__name__
    finally:
        for role, client in (("cold", cold), ("old_live", live)):
            if client is not None:
                try:
                    result["cleanup"].append(_close_observation(client, role, subject["platform"]))
                except BaseException as exc:
                    result["cleanup"].append({"role": role, "cleanup_unknown": type(exc).__name__})
                    result["status"] = "failed"
        names = ("live/rpc.jsonl", "cold/rpc.jsonl", "old-before.json", "old-after-live.json", "live-roots.json", "cold-roots.json",
                 "old-after-cold.json", "new-after-live.json", "new-after-cold.json", "live-guard.json", "cold-guard.json")
        result["artifacts"] = {name: sha(output / name) for name in names if (output / name).is_file()}
        _write_new(output / "result.json", result)
    return result


def run_open_transition(plan: dict[str, Any], output: Path, prepared: Path) -> dict[str, Any]:
    """Run the distinct-identity leg; unsupported routes stay explicitly pending."""
    subject = preflight(plan, output)
    if subject.get("codex_hardlink_count", 1) != 1:
        raise CapabilityPending("public CLI hard-link aliases require review")
    home = Path(plan["home"]).resolve(strict=True)
    require(prepared.is_absolute() and not prepared.is_symlink() and prepared.name == "prepare.json"
            and all(not _within(prepared.resolve(strict=True), root) for root in
                    (home, (Path.home() / ".codex").resolve(),
                     *(Path(value) for value in subject.get("other_homes", [])))),
            "invalid external prepare receipt")
    _no_link_ancestors(prepared)
    previous = _read_json(prepared)
    require(previous.get("schema") == REPORT and previous.get("stage") == "prepare"
            and previous.get("status") == "pending" and previous.get("subject") == subject,
            "prepare receipt does not bind these inputs")
    home, old, new, workspace, codex = (Path(plan[k]).resolve(strict=True) for k in
                                      ("home", "old_artifact", "new_artifact", "workspace", "codex"))
    read_file = workspace / "native-read.txt"
    require(not read_file.is_symlink() and read_file.is_file() and read_file.stat().st_nlink == 1,
            "controlled read fixture unavailable")
    read_sha = sha(read_file)
    require(read_sha == subject["read_file_sha256"], "controlled read fixture changed after preflight")
    installed = _absolute_real(_object(previous.get("installed")).get("path"), "old installed cache")
    old_market = OLD_MARKETS[plan["old_version"]]
    require(_within(installed, home / "plugins/cache" / old_market / "context-guard")
            and source_files(installed) == source_files(old), "old installed cache differs")
    if plan["transition_strategy"] == "observe-open":
        return _run_observation(plan, output, subject, previous, installed)
    output.mkdir(mode=0o700)
    live_dir, cold_dir = output / "live", output / "cold"
    live_dir.mkdir(mode=0o700)
    cold_dir.mkdir(mode=0o700)
    result: dict[str, Any] = {"schema": REPORT, "status": "pending", "stage": "open_transition",
                              "subject": subject, "commands": [],
                              "limitations": ["Hook sourcePath identifies the reviewed definition; "
                                              "literal PLUGIN_DATA and transient executed script path are not observed",
                                              "owned app-server stderr is discarded to avoid credential retention",
                                              "all task content is synthetic and state outputs are redacted projections"],
                              "pending": ["transition", "open_task", "cold_resume", "session_end",
                                          "disable", "removal", "unrelated_sentinel"]}
    env = isolated_env(home)
    live = cold = None
    try:
        def command(argv: list[str]) -> Any:
            return _run_official(result, argv, env, {old_market, NEW_MARKET,
                                 _object(plan.get("sentinel")).get("marketplace")}, "open_transition")

        sentinel = _sentinel_files(home, plan.get("sentinel"))
        require(sentinel == subject.get("sentinel") == previous.get("sentinel_after"),
                "unrelated sentinel changed before transition")
        result["sentinel_phases"] = {}

        def observe_sentinel(stage: str) -> dict[str, dict[str, Any]]:
            entries = _market_entries(command([str(codex), "plugin", "marketplace", "list", "--json"]))
            facts = _sentinel_files(home, plan.get("sentinel"))
            require(facts == sentinel and sentinel["marketplace"] in entries, "unrelated sentinel changed")
            result["sentinel_phases"][stage] = facts
            return entries

        initial_markets = observe_sentinel("before")
        _market_source(initial_markets, old_market, old)
        prior_list = command([str(codex), "plugin", "list", "--marketplace", old_market, "--json"])
        rechecked = _official_install_identity(previous.get("official_add"), _json_output(prior_list),
                                                old, home, plan["old_version"])
        require(rechecked == installed, "old official installation changed before execution")
        old_cache_before = {"files_sha256": digest(source_files(installed)), "objects_sha256": _cache_identity(installed)}
        observe_sentinel("after_old_list")
        client_plan = {"codex": str(codex), "cwd": str(workspace), "home": str(home),
                       "plugin_root": str(installed)}
        with _launch_environment(home):
            live = UpgradeClient(client_plan, live_dir, turn_limit=7)
        old_source = str(installed / "hooks/hooks.json")
        result["old_inventory"] = list(live.approved.values())
        task_a = live.start()
        task_b = live.start()
        read_command = ("Get-Content -LiteralPath native-read.txt" if platform.system() == "Windows"
                        else "cat native-read.txt")
        prompt = ("$context-guard\n请验证 native-read.txt 的 SHA256，收到我的允许后再进行。"
                  "现在只回复等待。")
        turn_a, rows_a = live.observed_turn(
            task_a, prompt + " 先仅调用一次只读 shell，执行精确命令：" + read_command)
        verify_read_tool(rows_a, live.approved, task_a, turn_a, read_command, workspace)
        require(sha(read_file) == read_sha, "read fixture changed")
        turn_b, rows_b = live.observed_turn(task_b, prompt)
        old_data, before_compact = _state_at(home, plan.get("old_data_root"), task_a)
        _, before_b = _state_at(home, plan.get("old_data_root"), task_b)
        _pending(before_compact)
        _pending(before_b)
        _write_new(output / "before-compact.json", _state_projection(before_compact))
        live.observed_compact(task_a)
        compact_turn, compact_rows = live.observed_turn(task_a, "继续。")
        _, before_a = _state_at(home, plan.get("old_data_root"), task_a)
        host.verify_recovery(before_compact, before_a)
        _write_new(output / "before-a.json", _state_projection(before_a))
        _write_new(output / "before-b.json", _state_projection(before_b))
        strategy = plan.get("transition_strategy")
        cancel_turns: dict[str, str] = {}
        if strategy == "finish-old":
            for name, task, old_state in (("a", task_a, before_a), ("b", task_b, before_b)):
                cancel_turn, cancel_rows = live.observed_turn(task, "取消当前任务。")
                require(_paired(cancel_rows, live.approved, task, "stop", turn=cancel_turn),
                        "old cancellation Stop missing")
                _, after_cancel = _state_at(home, plan.get("old_data_root"), task)
                path = host.session_state_path(old_data, task)
                proof = _cancel_evidence(old_state, after_cancel, _old_scope(installed, path, home))
                proof["state_sha256"] = sha(path)
                _write_new(output / ("cancel-" + name + ".json"), proof)
                cancel_turns[name] = cancel_turn
            _archive_owned(live, task_a)
            _archive_owned(live, task_b)
        else:
            live.rpc("thread/unsubscribe", {"threadId": task_b})
        _, transition_a = _state_at(home, plan.get("old_data_root"), task_a)
        _, transition_b = _state_at(home, plan.get("old_data_root"), task_b)
        old_a_bytes = sha(host.session_state_path(old_data, task_a))
        old_b_bytes = sha(host.session_state_path(old_data, task_b))
        _pending(transition_a)
        _pending(transition_b)
        require(live.owned.process.poll() is None, "original app-server is not live")
        result["before"] = {"thread_a": task_a, "thread_b": task_b, "turn_a": turn_a,
                            "turn_b": turn_b, "data_root": str(old_data),
                            "post_compact_turn": compact_turn,
                            "cancel_turns": cancel_turns,
                            "app_server_pid": live.owned.process.pid,
                            "read_file_sha256": read_sha, "read_command": read_command,
                            "state_a_sha256": old_a_bytes, "state_b_sha256": old_b_bytes,
                            "old_a_stop_count": len(_paired(rows_a, live.approved, task_a, "stop", turn=turn_a)),
                            "old_b_stop_count": len(_paired(rows_b, live.approved, task_b, "stop", turn=turn_b)),
                            "post_compact_stop_count": len(_paired(compact_rows, live.approved, task_a,
                                                                   "stop", turn=compact_turn)),
                            "scope": ("old synthetic tasks explicitly cancelled before transition" if strategy == "finish-old"
                                      else "open idle task, no in-flight-upgrade claim")}
        _mark(live, "transition_started")
        if plan["old_version"] == "0.15.1":
            # The official same-name route removes the old marketplace first;
            # the isolated experiment records any resulting old cache loss.
            command([str(codex), "plugin", "marketplace", "remove", old_market])
            markets = observe_sentinel("after_old_marketplace_remove")
            require(old_market not in markets, "old marketplace removal not observed")
        else:
            require(NEW_MARKET not in initial_markets, "stable marketplace already present")
        command([str(codex), "plugin", "marketplace", "add", str(new)])
        markets = observe_sentinel("after_new_marketplace_add")
        _market_source(markets, NEW_MARKET, new)
        added = _json_output(command([str(codex), "plugin", "add", "context-guard@" + NEW_MARKET, "--json"]))
        observe_sentinel("after_new_plugin_add")
        listed = _json_output(command([str(codex), "plugin", "list", "--marketplace", NEW_MARKET, "--json"]))
        observe_sentinel("after_new_plugin_list")
        _mark(live, "transition_completed")
        new_installed = native.official_identity(listed, added, new, home, "0.17.0")
        public_files = _load_artifacts_no_pyc(Path(plan["product_root"])).distribution_manifest(Path(plan["product_root"]))
        native.exact_artifact_parity(new_installed, public_files)
        actual_files = source_files(new_installed)
        require(actual_files == public_files, "new full-file parity differs")
        new_source = str(new_installed / "hooks/hooks.json")
        old_still_exists = installed.is_dir() and not installed.is_symlink()
        result["installed_new"] = {"path": str(new_installed), "source": str(new), "version": "0.17.0",
                                   "files": actual_files,
                                   "old_cache_exists": old_still_exists,
                                   "old_cache_files_sha256": digest(source_files(installed)) if old_still_exists else None}
        if old_market != NEW_MARKET:
            after_new_install = {"files_sha256": digest(source_files(installed)), "objects_sha256": _cache_identity(installed)}
            require(after_new_install == old_cache_before, "old cache changed during stable installation")
            result["old_cache_preservation"] = {"before": old_cache_before, "after_new_install": after_new_install}
        _, retained_a = _state_at(home, plan.get("old_data_root"), task_a)
        _, retained_b = _state_at(home, plan.get("old_data_root"), task_b)
        require(sha(host.session_state_path(old_data, task_a)) == old_a_bytes
                and sha(host.session_state_path(old_data, task_b)) == old_b_bytes,
                "old task state bytes changed during marketplace transition")
        validate_continuity(before_a, retained_a)
        validate_continuity(before_b, retained_b)
        _write_new(output / "retained-a.json", _state_projection(retained_a))
        _write_new(output / "retained-b.json", _state_projection(retained_b))
        result["old_data_after_transition"] = {"thread_a_sha256": sha(host.session_state_path(old_data, task_a)),
                                               "thread_b_sha256": sha(host.session_state_path(old_data, task_b))}
        if old_market != NEW_MARKET and strategy == "finish-old":
            _sample_pre_disable(live, old_source, new_source, result)
        _write_new(output / "review-required.json", {"message": ("Disable the old experimental plugin normally, "
            "then review the stable Hooks in the official CLI TUI." if old_market != NEW_MARKET and strategy == "finish-old"
            else "Review Hooks normally in the official CLI TUI.")})
        if old_market != NEW_MARKET and strategy == "finish-old":
            deadline = time.monotonic() + 300
            while True:
                old_readback = _json_output(command([str(codex), "plugin", "list", "--marketplace", old_market, "--json"]))
                old_row = _selected_plugin(old_readback, "context-guard@" + old_market)
                if (old_row is not None and old_row.get("installed") is True and old_row.get("enabled") is False
                        and old_row.get("version") == plan["old_version"]):
                    break
                require(time.monotonic() < deadline, "normal old-plugin disable pending")
                time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
            after_disable = {"files_sha256": digest(source_files(installed)), "objects_sha256": _cache_identity(installed)}
            require(after_disable == old_cache_before, "old cache changed during normal disable")
            stable_readback = _json_output(command([str(codex), "plugin", "list", "--marketplace", NEW_MARKET, "--json"]))
            stable_row = _selected_plugin(stable_readback, "context-guard@" + NEW_MARKET)
            require(stable_row is not None and stable_row.get("installed") is True
                    and stable_row.get("enabled") is True and stable_row.get("version") == "0.17.0",
                    "stable plugin is not enabled after old disable")
            result["old_cache_preservation"]["after_old_disable"] = after_disable
            live.log.write(json.dumps({"direction": "observation", "event": "old_identity_disabled",
                "pid": live.owned.process.pid, "monotonic_ns": time.monotonic_ns()}) + "\n")
            live.log.flush()
        allowed_sources = {new_source: "0.17.0"}
        if strategy == "observe-open" and old_market != NEW_MARKET:
            allowed_sources[old_source] = plan["old_version"]
        approved = _reviewed_sources(live, allowed_sources, new_source)
        result["new_inventory"] = list(approved.values())
        require(live.owned.process.poll() is None, "original app-server exited during transition")
        continuation = "请继续保留之前未完成的要求，不执行它，只回复等待。"
        if strategy == "finish-old":
            fresh = live.start()
            fresh_turn, fresh_rows = live.observed_turn(fresh, prompt + " 先仅调用一次只读 shell，执行精确命令：" + read_command)
            verify_read_tool(fresh_rows, approved, fresh, fresh_turn, read_command, workspace)
            require(sha(read_file) == read_sha, "fresh read fixture changed")
            new_data, fresh_state = _state_at(home, plan.get("new_data_root"), fresh)
            _pending(fresh_state)
            _write_new(output / "fresh-after-transition.json", _state_projection(fresh_state))
            fresh_stops = _paired(fresh_rows, approved, fresh, "stop", turn=fresh_turn)
            require(any(_source_key(run.get("sourcePath"), [new_source]) == new_source for run in fresh_stops),
                    "fresh task did not run the stable Hook source")
            live.observed_compact(fresh)
            fresh_compact_turn, _ = live.observed_turn(fresh, "继续。")
            _, compact_state = _state_at(home, plan.get("new_data_root"), fresh)
            host.verify_recovery(fresh_state, compact_state)
            _write_new(output / "fresh-after-compact.json", _state_projection(compact_state))
            live.rpc("thread/unsubscribe", {"threadId": fresh})
            cold_plan = {**client_plan, "plugin_root": str(new_installed)}
            with _launch_environment(home):
                cold = UpgradeClient(cold_plan, cold_dir, sources={new_source: "0.17.0"}, turn_limit=2)
            cold.log.write(json.dumps({"direction": "observation", "event": "cold_client_started",
                "pid": cold.owned.process.pid, "monotonic_ns": time.monotonic_ns()}) + "\n")
            cold.log.flush()
            begin = len(cold.rows)
            cold.rpc("thread/resume", {"threadId": fresh, "cwd": str(workspace),
                                       "sandbox": "read-only", "approvalPolicy": "on-request"})
            _try_wait_cold_start(cold, fresh, begin)
            fresh_cold_turn, cold_rows = cold.observed_turn(fresh, "继续。")
            cold.log.flush()
            cold_phase, cold_started_before = _cold_session_phase(_journal(cold_dir / "rpc.jsonl"), cold.approved,
                                                                   fresh, fresh_cold_turn, new_source)
            _, cold_state = _state_at(home, plan.get("new_data_root"), fresh)
            validate_continuity(compact_state, cold_state)
            _write_new(output / "fresh-after-cold.json", _state_projection(cold_state))
            cold_stops = _paired(cold_rows, cold.approved, fresh, "stop", turn=fresh_cold_turn)
            require(any(_source_key(run.get("sourcePath"), [new_source]) == new_source for run in cold_stops),
                    "cold fresh task did not run the stable Hook source")
            fresh_cancel_turn, fresh_cancel_rows = cold.observed_turn(fresh, "取消当前任务。")
            require(_paired(fresh_cancel_rows, cold.approved, fresh, "stop", turn=fresh_cancel_turn),
                    "fresh cancellation Stop missing")
            _, fresh_cancel_state = _state_at(home, plan.get("new_data_root"), fresh)
            fresh_state_path = host.session_state_path(new_data, fresh)
            fresh_cancel = _cancel_evidence(cold_state, fresh_cancel_state, _old_scope(new_installed, fresh_state_path, home))
            fresh_cancel["state_sha256"] = sha(fresh_state_path)
            _write_new(output / "fresh-cancel.json", fresh_cancel)
            _archive_owned(cold, fresh)
            result["after"] = {"fresh_thread": fresh, "fresh_turn": fresh_turn, "data_root": str(new_data),
                               "fresh_stop_sources": sorted({run["sourcePath"] for run in fresh_stops}),
                               "fresh_compact_turn": fresh_compact_turn, "fresh_cold_turn": fresh_cold_turn,
                               "fresh_cancel_turn": fresh_cancel_turn,
                               "cold_session_start_phase": cold_phase,
                               "cold_session_started_before_first_turn": cold_started_before,
                               "scope": "old tasks explicitly cancelled before transition; no continuity claim"}
        else:
            turn_after_a, rows_after_a = live.observed_turn(task_a, continuation)
            new_data, after_a = _state_at(home, plan.get("new_data_root"), task_a)
            validate_continuity(before_a, after_a)
            _write_new(output / "after-a.json", _state_projection(after_a))
            cold_plan = {**client_plan, "plugin_root": str(new_installed)}
            with _launch_environment(home):
                cold = UpgradeClient(cold_plan, cold_dir,
                                     sources={p: ("0.17.0" if p == new_source else plan["old_version"])
                                              for _, p in approved}, turn_limit=1)
            begin = len(cold.rows)
            cold.rpc("thread/resume", {"threadId": task_b, "cwd": str(workspace),
                                        "sandbox": "read-only", "approvalPolicy": "on-request"})
            _try_wait_cold_start(cold, task_b, begin)
            turn_after_b, rows_after_b = cold.observed_turn(task_b, continuation)
            cold.log.flush()
            cold_phase, cold_started_before = _cold_session_phase(_journal(cold_dir / "rpc.jsonl"), cold.approved,
                                                                   task_b, turn_after_b, new_source)
            _, after_b = _state_at(home, plan.get("new_data_root"), task_b)
            validate_continuity(before_b, after_b)
            _write_new(output / "after-b.json", _state_projection(after_b))
            _archive_owned(live, task_a)
            _archive_owned(cold, task_b)
            live_stops = _paired(rows_after_a, approved, task_a, "stop", turn=turn_after_a)
            cold_stops = _paired(rows_after_b, cold.approved, task_b, "stop", turn=turn_after_b)
            result["after"] = {"thread_a": task_a, "thread_b": task_b, "turn_a": turn_after_a,
                               "turn_b": turn_after_b, "data_root": str(new_data),
                               "live_stop_sources": sorted({run["sourcePath"] for run in live_stops}),
                               "cold_stop_sources": sorted({run["sourcePath"] for run in cold_stops}),
                               "cold_session_start_phase": cold_phase,
                               "cold_session_started_before_first_turn": cold_started_before}
        tracked_states = [(str(old_data), task_a), (str(old_data), task_b)]
        tracked_states += ([(str(new_data), fresh)] if strategy == "finish-old"
                           else [(str(new_data), task_a), (str(new_data), task_b)])
        before_removal = _selected_states(home, tracked_states)
        result["selected_data_before_removal"] = before_removal
        stable_id = "context-guard@" + NEW_MARKET
        live.rpc("config/batchWrite", {"edits": [{"keyPath": 'plugins."' + stable_id + '".enabled',
                      "value": False, "mergeStrategy": "upsert"}], "reloadUserConfig": True})
        disabled = live.rpc("hooks/list", {"cwds": [str(workspace)]})
        rows = disabled.get("data") if isinstance(disabled, dict) else None
        require(isinstance(rows, list) and len(rows) == 1 and not _object(rows[0]).get("errors")
                and not _object(rows[0]).get("warnings"), "disabled Hook readback unavailable")
        remaining = _object(rows[0]).get("hooks")
        require(isinstance(remaining, list) and all(isinstance(x, dict)
                                                     and _source_key(x.get("sourcePath"), [new_source]) is None
                                                     for x in remaining), "selected Hooks remain enabled")
        remaining = [_hook_projection(item) for item in remaining]
        previously_other = [h for (event, source), h in approved.items() if source != new_source]
        require(sorted(remaining, key=lambda h: (h.get("sourcePath"), h.get("eventName")))
                == sorted(previously_other, key=lambda h: (h.get("sourcePath"), h.get("eventName"))),
                "unrelated Hook inventory changed")
        result["disabled_inventory"] = remaining
        disabled_list = _json_output(command([str(codex), "plugin", "list", "--marketplace", NEW_MARKET, "--json"]))
        disabled_entries = disabled_list.get("installed")
        require(isinstance(disabled_entries, list), "disabled plugin readback unavailable")
        selected = [x for x in disabled_entries if isinstance(x, dict) and x.get("pluginId") == stable_id]
        require(len(selected) == 1 and selected[0].get("installed") is True
                and selected[0].get("enabled") is False, "selected plugin did not disable")
        _mark(live, "disable_completed")
        require(_selected_states(home, tracked_states) == before_removal, "selected data changed on disable")
        observe_sentinel("after_disable")
        command([str(codex), "plugin", "remove", stable_id])
        after_remove = _json_output(command([str(codex), "plugin", "list", "--marketplace", NEW_MARKET, "--json"]))
        remaining_installed = after_remove.get("installed")
        require(isinstance(remaining_installed, list)
                and not any(isinstance(x, dict) and x.get("pluginId") == stable_id for x in remaining_installed),
                "selected plugin remains installed")
        require(not new_installed.exists(), "selected plugin cache remains after removal")
        _mark(live, "plugin_removed")
        require(_selected_states(home, tracked_states) == before_removal, "selected data changed on removal")
        observe_sentinel("after_plugin_remove")
        command([str(codex), "plugin", "marketplace", "remove", NEW_MARKET])
        after_market_remove = observe_sentinel("after_marketplace_remove")
        require(NEW_MARKET not in after_market_remove, "selected marketplace remains registered")
        _mark(live, "marketplace_removed")
        if old_market != NEW_MARKET:
            _market_source(after_market_remove, old_market, old)
        require(_selected_states(home, tracked_states) == before_removal, "selected data changed on marketplace removal")
        result["selected_data_after_removal"] = before_removal
        result["pending"] = ["independent_consumer"]
    except BaseException as exc:
        result["status"] = "failed"
        result["failure"] = type(exc).__name__
    finally:
        result["cleanup"] = []
        for role, client in (("cold", cold), ("live", live)):
            if client is not None:
                try:
                    result["cleanup"].append(_close_observation(client, role, subject["platform"]))
                except BaseException as exc:
                    result["cleanup"].append({"role": role, "cleanup_unknown": type(exc).__name__})
                    result["status"] = "failed"
        diagnostics = [client.guard_diagnostic for client in (live, cold)
                       if client is not None and isinstance(getattr(client, "guard_diagnostic", None), dict)]
        if diagnostics:
            _write_new(output / "guard-diagnostic.json", {"schema": "cg-u01-guard-diagnostics/v1",
                                                          "entries": diagnostics})
        artifacts = ("live/rpc.jsonl", "cold/rpc.jsonl", "before-compact.json", "before-a.json",
                     "before-b.json", "retained-a.json", "retained-b.json", "after-a.json", "after-b.json",
                     "fresh-after-transition.json", "fresh-after-compact.json", "fresh-after-cold.json", "fresh-cancel.json",
                     "cancel-a.json", "cancel-b.json", "guard-diagnostic.json")
        result["artifacts"] = {name: sha(output / name) for name in artifacts if (output / name).is_file()}
        _write_new(output / "result.json", result)
    return result


def _journal(path: Path) -> list[dict[str, Any]]:
    _reject_credential_path(path)
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 16 * 1024 * 1024,
            "bounded RPC journal unavailable")
    rows = [adoption.strict_json(line) for line in path.read_text(encoding="utf-8").splitlines()]
    require(len(rows) <= 20000 and all(isinstance(row, dict) for row in rows), "RPC journal malformed")
    return rows


def _validate_rpc_requests(rows: list[dict[str, Any]], *, cold: bool) -> None:
    allowed = {"initialize", "initialized", "hooks/list", "turn/start", "thread/archive"}
    allowed |= ({"thread/resume"} if cold else
                {"thread/start", "thread/compact/start", "thread/unsubscribe", "config/batchWrite"})
    require(all(_object(row.get("message")).get("method") in allowed
                for row in rows if row.get("direction") == "request"), "unexpected RPC request")


def _evidence_path(directory: Path, relative: str) -> Path:
    root = directory.resolve(strict=True)
    parts = Path(relative).parts
    require(parts and all(part not in ("", ".", "..") and not _credential_name(part) for part in parts),
            "invalid evidence path")
    cursor = root
    for part in parts:
        cursor = cursor / part
        info = cursor.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "linked evidence path refused")
    require(cursor.resolve(strict=True).is_relative_to(root) and cursor.is_file()
            and cursor.stat().st_nlink == 1, "evidence path escapes result directory")
    return cursor


def _rpc_pairs(rows: list[dict[str, Any]], method: str) -> list[tuple[int, int, dict[str, Any], dict[str, Any]]]:
    pairs = []
    for index, row in enumerate(rows):
        message = _object(row.get("message"))
        if row.get("direction") != "request" or message.get("method") != method:
            continue
        request_id = message.get("id")
        require(type(request_id) is int, "RPC request id missing")
        replies = [(i, _object(r.get("message"))) for i, r in enumerate(rows[index + 1:], index + 1)
                   if r.get("direction") == "response" and _object(r.get("message")).get("id") == request_id]
        require(len(replies) == 1 and "error" not in replies[0][1]
                and isinstance(replies[0][1].get("result"), dict), "RPC response absent or rejected")
        pairs.append((index, replies[0][0], message, replies[0][1]["result"]))
    return pairs


def _turn_bounds(rows: list[dict[str, Any]], thread: str, turn: str) -> tuple[int, int]:
    matches = [(start, response) for start, response, request, result in _rpc_pairs(rows, "turn/start")
               if _object(request.get("params")).get("threadId") == thread
               and _object(result.get("turn")).get("id") == turn]
    require(len(matches) == 1, "turn start is not bound to thread")
    completed = [i for i, row in enumerate(rows) if row.get("direction") == "response"
                 and _object(row.get("message")).get("method") == "turn/completed"
                 and _object(_object(row.get("message")).get("params")).get("threadId") == thread
                 and _object(_object(_object(row.get("message")).get("params")).get("turn")).get("id") == turn
                 and _object(_object(_object(row.get("message")).get("params")).get("turn")).get("status") == "completed"]
    require(len(completed) == 1 and matches[0][0] < matches[0][1] < completed[0], "turn completion unavailable")
    return matches[0][0], completed[0]


def _cold_session_phase(rows: list[dict[str, Any]], inventory: dict[tuple[str, str], dict[str, Any]],
                        thread: str, turn: str, new_source: str) -> tuple[str, bool]:
    resumes = [(i, j) for i, j, req, _ in _rpc_pairs(rows, "thread/resume")
               if _object(req.get("params")).get("threadId") == thread]
    start, end = _turn_bounds(rows, thread, turn)
    require(len(resumes) == 1 and resumes[0][1] < start < end, "cold turn did not follow resume")
    stops = []
    for index in range(start, end + 1):
        message = _object(rows[index].get("message"))
        params, run = _object(message.get("params")), _object(_object(message.get("params")).get("run"))
        if (rows[index].get("direction") == "response" and message.get("method") == "hook/completed"
                and params.get("threadId") == thread and params.get("turnId") == turn
                and run.get("eventName") == "stop" and run.get("status") == "completed"):
            stops.append(index)
    require(stops, "first cold Stop missing")
    stop_index = min(stops)
    paired = _paired(rows[resumes[0][0] + 1:stop_index], inventory, thread, "sessionStart")
    selected = [run for run in paired if _source_key(run.get("sourcePath"), [new_source]) == new_source]
    require(len(selected) == 1, "new-source cold SessionStart pair missing or ambiguous")
    started, completion = [], []
    for index in range(resumes[0][0] + 1, stop_index):
        message = _object(rows[index].get("message"))
        params, run = _object(message.get("params")), _object(_object(message.get("params")).get("run"))
        if (rows[index].get("direction") == "response" and message.get("method") in ("hook/started", "hook/completed")
                and params.get("threadId") == thread and run.get("id") == selected[0].get("id")
                and run.get("eventName") == "sessionStart"
                and _source_key(run.get("sourcePath"), [new_source]) == new_source):
            (started if message["method"] == "hook/started" else completion).append(index)
    require(len(started) == len(completion) == 1 and started[0] < completion[0], "cold SessionStart pair ambiguous")
    return ("before_first_turn" if completion[0] < start else "during_first_turn", started[0] < start)


def _thread_start_index(rows: list[dict[str, Any]], thread: str) -> int:
    starts = [i for i, _j, _request, result in _rpc_pairs(rows, "thread/start")
              if _object(result.get("thread")).get("id") == thread]
    require(len(starts) == 1, "owned thread start not proved")
    return starts[0]


def _inventory_in_journal(rows: list[dict[str, Any]], expected: list[Any],
                          sources: dict[str, str], *, before: int | None = None,
                          after: int = -1) -> dict[tuple[str, str], dict[str, Any]]:
    wanted = _inventory({"data": [{"hooks": expected}]}, sources)
    matches = []
    for start, end, _request, result in _rpc_pairs(rows, "hooks/list"):
        if start <= after or (before is not None and end >= before):
            continue
        try:
            current = _inventory(result, sources)
        except UpgradeError:
            continue
        if current == wanted:
            matches.append(current)
    require(matches, "reviewed Hook inventory not found in RPC journal")
    return matches[-1]


def _validate_projected_state(value: Any, *, allow_empty: bool = False) -> dict[str, Any]:
    require(isinstance(value, dict), "state projection must be an object")
    require(set(value) == {"session", "requirements", "mode", "compactions_count", "recovery_state"},
            "state output is not a strict projection")
    require(set(_object(value.get("session"))) == {"id"}
            and set(_object(value.get("mode"))) == {"active"}, "state projection shape differs")
    rows = value.get("requirements")
    require(isinstance(rows, list) and all(isinstance(row, dict) and set(row) == {"id", "sha256", "status", "work_unit_id"}
                                           for row in rows), "requirement projection shape differs")
    _pending(value, allow_empty=allow_empty)
    return value


def _projected_state(path: Path, *, allow_empty: bool = False) -> dict[str, Any]:
    return _validate_projected_state(_read_json(path), allow_empty=allow_empty)


def _bound_projection(path: Path, *, allow_empty: bool = False) -> tuple[dict[str, Any], str]:
    value = _read_json(path)
    require(set(value) == {"source_state_sha256", "state"} and _sha(value.get("source_state_sha256")),
            "state source binding unavailable")
    return _validate_projected_state(value["state"], allow_empty=allow_empty), value["source_state_sha256"]


def _command_index(commands: list[Any], expected: list[str], start: int = -1) -> tuple[int, dict[str, Any]]:
    matches = [(i, item) for i, item in enumerate(commands) if i > start and isinstance(item, dict)
               and item.get("argv") == expected]
    require(matches, "official lifecycle command missing")
    index, item = matches[0]
    require(type(item.get("exit_code")) is int and item["exit_code"] == 0, "official lifecycle command failed")
    return index, _object(item.get("observation"))


def _selected_plugin(observation: dict[str, Any], plugin_id: str) -> dict[str, Any] | None:
    rows = observation.get("installed")
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows), "plugin readback missing")
    matches = [row for row in rows if row.get("pluginId") == plugin_id]
    require(len(matches) <= 1, "ambiguous plugin readback")
    return matches[0] if matches else None


def _command_observation(commands: list[Any], index: int) -> dict[str, Any]:
    require(0 <= index < len(commands) and isinstance(commands[index], dict), "command fact missing")
    item = commands[index]
    require(type(item.get("exit_code")) is int and item["exit_code"] == 0, "command failed")
    return _object(item.get("observation"))


def _verify_prepared(subject: dict[str, Any], prepared: dict[str, Any]) -> None:
    codex, old_market = subject["codex"], OLD_MARKETS[subject["old_version"]]
    old_source = Path(subject["old_artifact"])
    sentinel = subject["sentinel"]
    old_id = "context-guard@" + old_market
    initial = prepared.get("commands")
    require(isinstance(initial, list), "prepare command facts unavailable")
    expected_prepare = [[codex, "--version"], [codex, "plugin", "marketplace", "list", "--json"],
                        [codex, "plugin", "list", "--marketplace", sentinel["marketplace"], "--json"],
                        [codex, "plugin", "marketplace", "add", str(old_source)],
                        [codex, "plugin", "marketplace", "list", "--json"],
                        [codex, "plugin", "add", old_id, "--json"],
                        [codex, "plugin", "marketplace", "list", "--json"],
                        [codex, "plugin", "list", "--marketplace", old_market, "--json"],
                        [codex, "plugin", "marketplace", "list", "--json"]]
    require(len(initial) == len(expected_prepare)
            and all(isinstance(item, dict) and item.get("argv") == expected
                    and type(item.get("exit_code")) is int and item["exit_code"] == 0
                    for item, expected in zip(initial, expected_prepare)), "prepare command sequence differs")
    initial_markets = _object(initial[1].get("observation")).get("marketplaces")
    sentinel_plugins = _object(initial[2].get("observation")).get("installed")
    before = _object(prepared.get("before"))
    require(isinstance(initial_markets, list) and all(isinstance(row, dict) and isinstance(row.get("name"), str)
                                                       for row in initial_markets)
            and old_market not in [row["name"] for row in initial_markets]
            and sentinel["marketplace"] in [row["name"] for row in initial_markets]
            and isinstance(sentinel_plugins, list)
            and all(isinstance(row, dict) and isinstance(row.get("pluginId"), str)
                    and row.get("marketplaceName") == sentinel["marketplace"] for row in sentinel_plugins)
            and before.get("sentinel_installed_count") == len(sentinel_plugins)
            and before.get("target_marketplace_absent") is True and before.get("target_cache_absent") is True
            and before.get("target_cache_path") == str(Path(subject["home"]) / "plugins/cache" / old_market / "context-guard"),
            "initial scoped marketplace or target cache evidence missing")
    index, _ = _command_index(initial, [codex, "plugin", "marketplace", "add", str(old_source)])
    index, old_add = _command_index(initial, [codex, "plugin", "add", old_id, "--json"], index)
    index, old_list = _command_index(initial, [codex, "plugin", "list", "--marketplace", old_market, "--json"], index)
    old_entry = _selected_plugin(old_list, old_id)
    require(old_add == prepared.get("official_add") and old_entry is not None
            and old_entry.get("version") == subject["old_version"]
            and old_entry.get("installed") is True and old_entry.get("enabled") is True,
            "old official installation readback differs")
    require(native._official_path_matches(_object(old_entry.get("source")).get("path"), old_source,
                                          windows=platform.system() == "Windows")
            and native._official_path_matches(_object(old_entry.get("marketplaceSource")).get("source"), old_source,
                                               windows=platform.system() == "Windows"),
            "old official source differs")
    require(prepared.get("sentinel_before") == prepared.get("sentinel_after") == sentinel,
            "prepare sentinel changed")
    phases = _object(prepared.get("sentinel_phases"))
    require(set(phases) == {"after_marketplace_add", "after_plugin_add", "after_plugin_list"}
            and all(facts == sentinel for facts in phases.values()), "prepare sentinel phases incomplete")


def _verify_cli_lifecycle(subject: dict[str, Any], prepared: dict[str, Any], result: dict[str, Any]) -> None:
    _verify_prepared(subject, prepared)
    codex, old_market = subject["codex"], OLD_MARKETS[subject["old_version"]]
    new_source = Path(subject["new_artifact"])
    sentinel = subject["sentinel"]
    stable_id = "context-guard@" + NEW_MARKET
    old_id = "context-guard@" + old_market
    commands = result.get("commands")
    require(isinstance(commands, list), "transition command facts unavailable")
    allowed = [[codex, "plugin", "marketplace", "list", "--json"],
               [codex, "plugin", "list", "--marketplace", old_market, "--json"],
               [codex, "plugin", "marketplace", "add", str(new_source)],
               [codex, "plugin", "add", stable_id, "--json"],
               [codex, "plugin", "list", "--marketplace", NEW_MARKET, "--json"],
               [codex, "plugin", "remove", stable_id],
               [codex, "plugin", "marketplace", "remove", NEW_MARKET]]
    require(all(isinstance(item, dict) and item.get("argv") in allowed
                and type(item.get("exit_code")) is int and item["exit_code"] == 0 for item in commands),
            "unexpected or failed official command")
    for argv, count in (([codex, "plugin", "marketplace", "add", str(new_source)], 1),
                        ([codex, "plugin", "add", stable_id, "--json"], 1),
                        ([codex, "plugin", "remove", stable_id], 1),
                        ([codex, "plugin", "marketplace", "remove", NEW_MARKET],
                         2 if subject["old_version"] == "0.15.1" else 1)):
        require(sum(item.get("argv") == argv for item in commands) == count, "official mutation count differs")
    index, initial_old = _command_index(commands,
        [codex, "plugin", "list", "--marketplace", old_market, "--json"])
    old_row = _selected_plugin(initial_old, old_id)
    require(old_row is not None and old_row.get("version") == subject["old_version"]
            and old_row.get("installed") is True and old_row.get("enabled") is True,
            "old pre-transition identity not observed")
    if subject["old_version"] == "0.15.1":
        index, _ = _command_index(commands, [codex, "plugin", "marketplace", "remove", old_market], index)
    index, _ = _command_index(commands, [codex, "plugin", "marketplace", "add", str(new_source)], index)
    market_add_index = index
    index, added = _command_index(commands, [codex, "plugin", "add", stable_id, "--json"], index)
    index, new_list = _command_index(commands, [codex, "plugin", "list", "--marketplace", NEW_MARKET, "--json"], index)
    new_row = _selected_plugin(new_list, stable_id)
    require(added.get("pluginId") == stable_id and added.get("version") == "0.17.0"
            and added.get("installedPath") == _object(result.get("installed_new")).get("path")
            and new_row is not None and new_row.get("version") == "0.17.0"
            and new_row.get("installed") is True and new_row.get("enabled") is True,
            "new official installation readback differs")
    require(native._official_path_matches(_object(new_row.get("source")).get("path"), new_source,
                                          windows=platform.system() == "Windows")
            and native._official_path_matches(_object(new_row.get("marketplaceSource")).get("source"), new_source,
                                               windows=platform.system() == "Windows"),
            "new official source differs")
    disabled_reads = [(i, _object(item.get("observation"))) for i, item in enumerate(commands)
                      if i > index and isinstance(item, dict) and item.get("argv") ==
                      [codex, "plugin", "list", "--marketplace", NEW_MARKET, "--json"]
                      and (row := _selected_plugin(_object(item.get("observation")), stable_id)) is not None
                      and row.get("enabled") is False]
    require(len(disabled_reads) == 1, "official disabled plugin readback ambiguous")
    index, disabled = disabled_reads[0]
    selected = _selected_plugin(disabled, stable_id)
    require(selected is not None and selected.get("installed") is True and selected.get("enabled") is False,
            "official disabled plugin readback missing")
    index, _ = _command_index(commands, [codex, "plugin", "remove", stable_id], index)
    index, removed = _command_index(commands, [codex, "plugin", "list", "--marketplace", NEW_MARKET, "--json"], index)
    removed_rows = removed.get("installed")
    require(isinstance(removed_rows, list) and all(isinstance(row, dict)
            and isinstance(row.get("pluginId"), str) and row.get("marketplaceName") == NEW_MARKET
            for row in removed_rows), "scoped removal readback malformed")
    require(_selected_plugin(removed, stable_id) is None, "plugin removal not observed")
    index, _ = _command_index(commands, [codex, "plugin", "marketplace", "remove", NEW_MARKET], index)
    market_lists = [(i, _object(item.get("observation"))) for i, item in enumerate(commands)
                    if isinstance(item, dict) and item.get("argv") ==
                    [codex, "plugin", "marketplace", "list", "--json"]]
    require(market_lists and market_lists[-1][0] > index, "final marketplace readback missing")
    for _i, observation in market_lists:
        entries = observation.get("marketplaces")
        require(isinstance(entries, list) and any(isinstance(x, dict) and x.get("name") == sentinel["marketplace"]
                                                   for x in entries), "unrelated marketplace missing")
    require(not any(x.get("name") == NEW_MARKET for x in market_lists[-1][1]["marketplaces"]
                    if isinstance(x, dict)), "marketplace removal not observed")
    added_markets = [observation for i, observation in market_lists if market_add_index < i < index]
    require(added_markets, "new marketplace source readback missing")
    first_after_add = _object(added_markets[0]).get("marketplaces")
    require(isinstance(first_after_add, list), "new marketplace source malformed")
    _market_source({x["name"]: x for x in first_after_add if isinstance(x, dict) and isinstance(x.get("name"), str)},
                   NEW_MARKET, new_source)
    phase_names = {"before", "after_old_list", "after_new_marketplace_add", "after_new_plugin_add",
                   "after_new_plugin_list", "after_disable", "after_plugin_remove", "after_marketplace_remove"}
    if subject["old_version"] == "0.15.1":
        phase_names.add("after_old_marketplace_remove")
    phases = _object(result.get("sentinel_phases"))
    require(set(phases) == phase_names and all(facts == sentinel for facts in phases.values()),
            "transition sentinel observations incomplete")
    require(_sentinel_files(Path(subject["home"]), plan_sentinel_from_facts(sentinel)) == sentinel,
            "unrelated sentinel readback differs")


def plan_sentinel_from_facts(facts: dict[str, Any]) -> dict[str, Any]:
    return {"marketplace": facts.get("marketplace"),
            "cache_marker": _object(facts.get("cache_marker")).get("path"),
            "data_marker": _object(facts.get("data_marker")).get("path")}


def _verify_pre_disable(live: list[dict[str, Any]], result: dict[str, Any], old_source: str,
                        new_source: str, transition_end: int, disabled_index: int, pid: int) -> None:
    markers = [(i, row) for i, row in enumerate(live) if row.get("direction") == "observation"
               and row.get("event") == "pre_disable_sample"]
    require(len(markers) == 1 and transition_end < markers[0][0] < disabled_index
            and markers[0][1].get("pid") == pid and type(markers[0][1].get("monotonic_ns")) is int,
            "pre-disable sample marker unavailable")
    reads = [(i, j, value) for i, j, _request, value in _rpc_pairs(live, "hooks/list")
             if transition_end < i < j < markers[0][0]]
    require(len(reads) == 1 and _pre_disable_projection(reads[0][2], old_source, new_source) ==
            result.get("pre_disable_inventory"), "pre-disable sampled Hook identities differ")


def _verify_old_disable(subject: dict[str, Any], result: dict[str, Any], live: list[dict[str, Any]],
                        marks: dict[str, int], new_source: str, installed: Path) -> None:
    if subject["old_version"] != "0.16.1" or subject["transition_strategy"] != "finish-old":
        return
    evidence = _object(result.get("old_cache_preservation"))
    original = _object(evidence.get("before"))
    require(set(original) == {"files_sha256", "objects_sha256"} and all(_sha(v) for v in original.values())
            and evidence.get("after_new_install") == original and evidence.get("after_old_disable") == original
            and digest(source_files(installed)) == original["files_sha256"]
            and _cache_identity(installed) == original["objects_sha256"], "old cache preservation not proved")
    markers = [(i, row) for i, row in enumerate(live) if row.get("direction") == "observation"
               and row.get("event") == "old_identity_disabled"]
    require(len(markers) == 1 and marks["transition_completed"] < markers[0][0] < marks["disable_completed"]
            and type(markers[0][1].get("monotonic_ns")) is int, "normal old disable marker unavailable")
    marker_index, marker = markers[0]
    require(marker.get("pid") == live[marks["transition_started"]].get("pid"), "app-server identity differs")
    _verify_pre_disable(live, result, str(installed / "hooks/hooks.json"), new_source,
                        marks["transition_completed"], marker_index, marker["pid"])
    codex = subject["codex"]
    commands = result.get("commands")
    require(isinstance(commands, list), "normal disable command evidence missing")
    def last_read(market: str) -> dict[str, Any]:
        rows = [row for row in commands if isinstance(row, dict) and row.get("argv") ==
                [codex, "plugin", "list", "--marketplace", market, "--json"]
                and type(row.get("completed_monotonic_ns")) is int
                and row["completed_monotonic_ns"] < marker["monotonic_ns"]]
        require(rows, "normal disable scoped readback missing")
        return _object(rows[-1].get("observation"))
    old = _selected_plugin(last_read(OLD_MARKETS["0.16.1"]), "context-guard@" + OLD_MARKETS["0.16.1"])
    new = _selected_plugin(last_read(NEW_MARKET), "context-guard@" + NEW_MARKET)
    require(old is not None and old.get("version") == "0.16.1" and old.get("installed") is True
            and old.get("marketplaceName") == OLD_MARKETS["0.16.1"] and old.get("enabled") is False
            and new is not None and new.get("version") == "0.17.0" and new.get("marketplaceName") == NEW_MARKET
            and new.get("installed") is True and new.get("enabled") is True, "normal old disable not observed")
    require(_object(old.get("source")).get("source") == "local"
            and _object(new.get("source")).get("source") == "local"
            and _object(old.get("marketplaceSource")).get("sourceType") == "local"
            and _object(new.get("marketplaceSource")).get("sourceType") == "local"
            and native._official_path_matches(_object(old.get("source")).get("path"), Path(subject["old_artifact"]),
                                          windows=platform.system() == "Windows")
            and native._official_path_matches(_object(new.get("source")).get("path"), Path(subject["new_artifact"]),
                                               windows=platform.system() == "Windows")
            and native._official_path_matches(_object(old.get("marketplaceSource")).get("source"),
                                               Path(subject["old_artifact"]), windows=platform.system() == "Windows")
            and native._official_path_matches(_object(new.get("marketplaceSource")).get("source"),
                                               Path(subject["new_artifact"]), windows=platform.system() == "Windows"),
            "plugin source differs after disable")
    fresh = _object(result.get("after")).get("fresh_thread")
    require(isinstance(fresh, str), "fresh task identity missing")
    fresh_start = _thread_start_index(live, fresh)
    require(marker_index < fresh_start, "fresh task preceded normal old disable")
    _inventory_in_journal(live, result.get("new_inventory"), {new_source: "0.17.0"},
                          after=marker_index, before=fresh_start)


def _verify_disable_rpc(live: list[dict[str, Any]], marks: dict[str, int],
                        new_source: str, new_inv: dict[tuple[str, str], dict[str, Any]],
                        disabled_inventory: Any, version: str) -> None:
    all_writes = _rpc_pairs(live, "config/batchWrite")
    require(len(all_writes) == 1, "unexpected configuration mutation")
    writes = [(i, j, request) for i, j, request, _response in all_writes
              if _object(request.get("params")) == {"edits": [{"keyPath":
                  'plugins."context-guard@codex-context-guard".enabled', "value": False,
                  "mergeStrategy": "upsert"}], "reloadUserConfig": True}]
    require(len(writes) == 1 and marks["transition_completed"] < writes[0][0]
            < writes[0][1] < marks["disable_completed"], "official disable request not proved")
    require(isinstance(disabled_inventory, list)
            and all(isinstance(x, dict) and _source_key(x.get("sourcePath"), [new_source]) is None
                    for x in disabled_inventory),
            "disabled Hook inventory differs")
    other_sources = {path: version for _, path in new_inv if path != new_source}
    disabled = _inventory_in_journal(live, disabled_inventory, other_sources,
                                     after=writes[0][1], before=marks["disable_completed"])
    require(disabled == {key: value for key, value in new_inv.items() if key[1] != new_source},
            "unrelated trusted Hooks changed on disable")


def _marks(rows: list[dict[str, Any]]) -> dict[str, int]:
    expected = ("transition_started", "transition_completed", "disable_completed", "plugin_removed", "marketplace_removed")
    matches = [(i, row) for i, row in enumerate(rows) if row.get("direction") == "local"]
    require(len(matches) == len(expected) and [row.get("event") for _, row in matches] == list(expected),
            "lifecycle timing markers incomplete")
    pids = {row.get("pid") for _, row in matches}
    times = [row.get("monotonic_ns") for _, row in matches]
    require(len(pids) == 1 and all(type(value) is int and value > 0 for value in times)
            and all(a < b for a, b in zip(times, times[1:])), "lifecycle timing facts differ")
    return {name: index for name, (index, _row) in zip(expected, matches)}


def _verify_observation(subject: dict[str, Any], prepared: dict[str, Any], result: dict[str, Any],
                        output: Path, prepared_path: Path) -> dict[str, Any]:
    require(subject.get("transition_strategy") == "observe-open" and prepared.get("schema") == REPORT
            and prepared.get("stage") == "prepare" and prepared.get("status") == "pending"
            and prepared.get("subject") == subject and result.get("schema") == REPORT
            and result.get("stage") == "observe_open" and result.get("subject") == subject
            and result.get("status") in ("observation_complete", "observation_pending", "unsupported_continuity")
            and "failure" not in result and result.get("pending") == ["independent_consumer"],
            "observation receipt is incomplete")
    _verify_prepared(subject, prepared)
    artifacts = _object(result.get("artifacts"))
    required = {"live/rpc.jsonl", "cold/rpc.jsonl", "old-before.json", "old-after-live.json", "old-after-cold.json",
                "live-roots.json", "cold-roots.json"}
    data = _object(result.get("data_observations"))
    for phase in ("live", "cold"):
        value = data.get("new_after_" + phase)
        require(value in ("observed", "absent"), "new data-root observation missing")
        if value == "observed":
            required.add("new-after-" + phase + ".json")
        else:
            name = "new-after-" + phase + ".json"
            require(name not in artifacts and not (output / name).exists() and not (output / name).is_symlink(),
                    "absent new data root has a conflicting projection")
    for phase in ("live", "cold"):
        if _object(result.get(phase + "_observation")).get("status") == "unsupported_guard":
            required.add(phase + "-guard.json")
    require(required <= set(artifacts) and all(_sha(artifacts.get(name))
            and sha(_evidence_path(output, name)) == artifacts[name] for name in required),
            "observation artifacts differ")
    live = _journal(_evidence_path(output, "live/rpc.jsonl"))
    cold = _journal(_evidence_path(output, "cold/rpc.jsonl"))
    _validate_rpc_requests(live, cold=False)
    _validate_rpc_requests(cold, cold=True)
    require(sum(row.get("direction") == "request" and _object(row.get("message")).get("method") == "turn/start"
                for row in live) == 2
            and sum(row.get("direction") == "request" and _object(row.get("message")).get("method") == "turn/start"
                    for row in cold) <= 1, "observation model turn budget differs")
    before = _object(result.get("before"))
    thread, first = before.get("thread"), before.get("turn")
    require(isinstance(thread, str) and isinstance(first, str) and before.get("old_data_root") == subject["old_data_root"]
            and data.get("old_root") == subject["old_data_root"] and data.get("new_root") == subject["new_data_root"]
            and before.get("read_file_sha256") == subject["read_file_sha256"] and _sha(before.get("state_sha256")),
            "observation subject differs")
    old_installed = _object(prepared.get("installed")).get("path")
    new_installed = _object(result.get("installed_new")).get("path")
    require(isinstance(old_installed, str) and isinstance(new_installed, str), "observation installation missing")
    old_market = OLD_MARKETS[subject["old_version"]]
    old_cache = Path(subject["home"]) / "plugins/cache" / old_market / "context-guard"
    new_cache = Path(subject["home"]) / "plugins/cache" / NEW_MARKET / "context-guard"
    require(any(native._official_path_matches(old_installed, old_cache / part, windows=os.name == "nt")
                for part in (subject["old_version"], "local"))
            and any(native._official_path_matches(new_installed, new_cache / part, windows=os.name == "nt")
                    for part in ("0.17.0", "local")), "observation cache path differs")
    public = _load_artifacts_no_pyc(Path(subject["product_root"])).distribution_manifest(Path(subject["product_root"]))
    require(_object(result.get("installed_new")).get("files") == public
            and source_files(Path(new_installed)) == public, "observation stable cache differs")
    old_exists = _object(result.get("installed_new")).get("old_cache_exists")
    require(type(old_exists) is bool and old_exists == Path(old_installed).is_dir(),
            "observed old cache availability changed or is unknown")
    old_source = str(Path(old_installed) / "hooks/hooks.json")
    new_source = str(Path(new_installed) / "hooks/hooks.json")
    _require_distinct_sources(old_source, new_source)
    markers = [(i, row) for i, row in enumerate(live) if row.get("direction") == "local"]
    require(len(markers) == 2 and [row.get("event") for _, row in markers] ==
            ["transition_started", "transition_completed"] and all(row.get("pid") == before.get("app_server_pid")
            and type(row.get("monotonic_ns")) is int for _, row in markers)
            and markers[0][1]["monotonic_ns"] < markers[1][1]["monotonic_ns"], "observation transition timing differs")
    transition_start, transition_end = markers[0][0], markers[1][0]
    old_inv = _inventory_in_journal(live, result.get("old_inventory"), {old_source: subject["old_version"]},
                                    before=transition_start)
    new_inv = _inventory_in_journal(live, result.get("new_inventory"), {new_source: "0.17.0"}, after=transition_end)
    start, end = _turn_bounds(live, thread, first)
    require(_thread_start_index(live, thread) < start < end < transition_start
            and _paired(live[start:end + 1], old_inv, thread, "stop", turn=first), "old baseline not observed")
    expected_read = "Get-Content -LiteralPath native-read.txt" if subject["platform"] == "Windows" else "cat native-read.txt"
    require(before.get("read_command") == expected_read, "observation read command differs")
    verify_read_tool(live[start:end + 1], old_inv, thread, first, expected_read, Path(subject["workspace"]))
    initial, initial_sha = _bound_projection(_evidence_path(output, "old-before.json"))
    require(_object(initial.get("session")).get("id") == thread and initial_sha == before["state_sha256"],
            "old baseline task or state binding differs")
    old_bound = {phase: _bound_projection(_evidence_path(output, "old-after-" + phase + ".json"))
                 for phase in ("live", "cold")}
    old_states = {phase: pair[0] for phase, pair in old_bound.items()}
    for state in old_states.values():
        validate_continuity(initial, state)
    new_states, new_shas = {}, {}
    for phase in ("live", "cold"):
        if data["new_after_" + phase] == "observed":
            state, raw_sha = _bound_projection(_evidence_path(output, "new-after-" + phase + ".json"), allow_empty=True)
            require(_object(state.get("session")).get("id") == thread, "new data-root task differs")
            new_states[phase] = state
            new_shas[phase] = raw_sha
    commands = result.get("commands")
    require(isinstance(commands, list) and all(isinstance(row, dict) and type(row.get("exit_code")) is int
            and row.get("exit_code") == 0
            and isinstance(row.get("argv"), list) for row in commands), "observation command facts unavailable")
    codex = subject["codex"]
    allowed = [[codex, "plugin", "marketplace", "list", "--json"],
               [codex, "plugin", "list", "--marketplace", old_market, "--json"],
               [codex, "plugin", "list", "--marketplace", NEW_MARKET, "--json"],
               [codex, "plugin", "marketplace", "add", subject["new_artifact"]],
               [codex, "plugin", "add", "context-guard@" + NEW_MARKET, "--json"]]
    if old_market == NEW_MARKET:
        allowed.append([codex, "plugin", "marketplace", "remove", old_market])
    require(all(row["argv"] in allowed for row in commands), "unexpected observation command")
    old_list_index, old_list = _command_index(commands, [codex, "plugin", "list", "--marketplace", old_market, "--json"])
    old_row = _selected_plugin(old_list, "context-guard@" + old_market)
    require(old_row is not None and old_row.get("version") == subject["old_version"]
            and old_row.get("installed") is True and old_row.get("enabled") is True
            and _object(old_row.get("source")).get("source") == "local"
            and _object(old_row.get("marketplaceSource")).get("sourceType") == "local"
            and _object(prepared.get("official_add")).get("installedPath") == old_installed
            and type(commands[old_list_index].get("completed_monotonic_ns")) is int
            and commands[old_list_index]["completed_monotonic_ns"] < markers[0][1]["monotonic_ns"]
            and native._official_path_matches(_object(old_row.get("source")).get("path"), Path(subject["old_artifact"]),
                                               windows=platform.system() == "Windows")
            and native._official_path_matches(_object(old_row.get("marketplaceSource")).get("source"),
                                               Path(subject["old_artifact"]), windows=platform.system() == "Windows"),
            "old observation identity differs")
    add_index, _ = _command_index(commands, [codex, "plugin", "marketplace", "add", subject["new_artifact"]], old_list_index)
    add_index, added = _command_index(commands, [codex, "plugin", "add", "context-guard@" + NEW_MARKET, "--json"], add_index)
    _index, new_list = _command_index(commands, [codex, "plugin", "list", "--marketplace", NEW_MARKET, "--json"], add_index)
    new_row = _selected_plugin(new_list, "context-guard@" + NEW_MARKET)
    require(added.get("pluginId") == "context-guard@" + NEW_MARKET and added.get("version") == "0.17.0"
            and added.get("installedPath") == new_installed and new_row is not None
            and new_row.get("installed") is True and new_row.get("enabled") is True and new_row.get("version") == "0.17.0"
            and _object(new_row.get("source")).get("source") == "local"
            and _object(new_row.get("marketplaceSource")).get("sourceType") == "local"
            and native._official_path_matches(_object(new_row.get("source")).get("path"), Path(subject["new_artifact"]),
                                               windows=platform.system() == "Windows")
            and native._official_path_matches(_object(new_row.get("marketplaceSource")).get("source"),
                                               Path(subject["new_artifact"]), windows=platform.system() == "Windows"),
            "new observation identity differs")
    for argv in ([codex, "plugin", "marketplace", "add", subject["new_artifact"]],
                 [codex, "plugin", "add", "context-guard@" + NEW_MARKET, "--json"],
                 *([[codex, "plugin", "marketplace", "remove", old_market]] if old_market == NEW_MARKET else [])):
        matches = [row for row in commands if row["argv"] == argv]
        require(len(matches) == 1 and type(matches[0].get("started_monotonic_ns")) is int
                and type(matches[0].get("completed_monotonic_ns")) is int
                and markers[0][1]["monotonic_ns"] < matches[0]["started_monotonic_ns"]
                <= matches[0]["completed_monotonic_ns"] < markers[1][1]["monotonic_ns"], "observation mutation timing differs")
    sentinel = subject["sentinel"]
    require(result.get("sentinel_after") == sentinel
            and _sentinel_files(Path(subject["home"]), plan_sentinel_from_facts(sentinel)) == sentinel,
            "observation sentinel changed")
    market_reads = [_object(row.get("observation")) for row in commands if row["argv"] ==
                    [codex, "plugin", "marketplace", "list", "--json"]]
    require(len(market_reads) >= 2 and all(isinstance(row.get("marketplaces"), list)
            and any(_object(item).get("name") == sentinel["marketplace"] for item in row["marketplaces"])
            for row in market_reads), "unrelated marketplace not preserved")
    for entries, market, source in ((market_reads[0]["marketplaces"], old_market, Path(subject["old_artifact"])),
                                    (market_reads[-1]["marketplaces"], NEW_MARKET, Path(subject["new_artifact"]))):
        _market_source({row["name"]: row for row in entries if isinstance(row, dict) and isinstance(row.get("name"), str)},
                       market, source)
    if old_market != NEW_MARKET:
        preserved = _object(result.get("old_cache_preservation"))
        original = _object(preserved.get("before"))
        require(set(original) == {"files_sha256", "objects_sha256"} and all(_sha(x) for x in original.values())
                and preserved.get("after_new_install") == preserved.get("after_old_disable") == original
                and digest(source_files(Path(old_installed))) == original["files_sha256"]
                and _cache_identity(Path(old_installed)) == original["objects_sha256"], "old cache not preserved")
        disabled_markers = [(i, row) for i, row in enumerate(live) if row.get("direction") == "observation"
                            and row.get("event") == "old_identity_disabled"]
        require(len(disabled_markers) == 1 and transition_end < disabled_markers[0][0]
                and disabled_markers[0][1].get("pid") == before.get("app_server_pid"), "normal old disable missing")
        _verify_pre_disable(live, result, old_source, new_source, transition_end,
                            disabled_markers[0][0], before["app_server_pid"])
        stamp = disabled_markers[0][1].get("monotonic_ns")
        require(type(stamp) is int, "normal old disable timestamp unavailable")
        def read_at_marker(market: str) -> dict[str, Any] | None:
            rows = [row for row in commands if row["argv"] == [codex, "plugin", "list", "--marketplace", market, "--json"]
                    and type(row.get("completed_monotonic_ns")) is int and row["completed_monotonic_ns"] < stamp]
            return _selected_plugin(_object(rows[-1].get("observation")), "context-guard@" + market) if rows else None
        old_row, new_row = read_at_marker(old_market), read_at_marker(NEW_MARKET)
        require(old_row is not None and old_row.get("version") == subject["old_version"]
                and old_row.get("installed") is True and old_row.get("enabled") is False
                and new_row is not None and new_row.get("version") == "0.17.0"
                and new_row.get("installed") is True and new_row.get("enabled") is True
                and native._official_path_matches(_object(old_row.get("source")).get("path"), Path(subject["old_artifact"]),
                                                   windows=platform.system() == "Windows")
                and native._official_path_matches(_object(new_row.get("source")).get("path"), Path(subject["new_artifact"]),
                                                   windows=platform.system() == "Windows"),
                "normal plugin disable or stable enable unproved")
        _inventory_in_journal(live, result.get("new_inventory"), {new_source: "0.17.0"}, after=disabled_markers[0][0])
    combined = {**old_inv, **new_inv}
    traces = {phase: _read_json(_evidence_path(output, phase + "-roots.json")) for phase in ("live", "cold")}
    require(traces["live"].get("after") == traces["cold"].get("before"), "observation root snapshots are discontinuous")
    shared_root = Path(subject["old_data_root"]) == Path(subject["new_data_root"])
    for phase, trace in traces.items():
        _validate_root_snapshot_map(trace.get("before"))
        _validate_root_snapshot_map(trace.get("after"))
        after_roots = trace["after"]
        require(after_roots["old"]["present"] is True
                and after_roots["new"]["present"] == (data["new_after_" + phase] == "observed"),
                "data-root presence contradicts turn snapshots")
        require(after_roots["old"].get("state_sha256") == old_bound[phase][1]
                and (phase not in new_shas or after_roots["new"].get("state_sha256") == new_shas[phase]),
                "turn trace and projected state came from different source bytes")
        if shared_root:
            require(trace["before"]["old"] == trace["before"]["new"]
                    and trace["after"]["old"] == trace["after"]["new"], "shared root snapshots differ")
    require(traces["live"]["before"]["old"].get("state_sha256") == initial_sha,
            "old baseline and pre-observation snapshot differ")
    outcomes = []
    ledgers = []
    for role, rows in (("live", live), ("cold", cold)):
        observation = _object(result.get(role + "_observation"))
        status = observation.get("status")
        require(status in ({"observed", "root_unobserved", "unsupported_guard"} if role == "live" else
                           {"observed", "root_unobserved", "session_start_unobserved", "unsupported_guard",
                            "unsupported_resume"}), "invalid observation status")
        if status == "unsupported_guard":
            diagnostic = _read_json(_evidence_path(output, role + "-guard.json"))
            require(set(diagnostic) == {"schema", "stage", "method", "event", "source_class", "event_source_approved",
                    "source_matches", "handler_matches", "order_matches", "mode_matches", "target_thread_matches",
                    "old_inventory_order_matches"} and diagnostic.get("schema") == "cg-u01-guard-diagnostic/v1"
                    and diagnostic.get("stage") == "receive" and diagnostic.get("target_thread_matches") is True
                    and diagnostic.get("method") in ("hook/started", "hook/completed")
                    and diagnostic.get("event") in EVENTS | {"other"}
                    and diagnostic.get("source_class") in ("old", "new", "other")
                    and all(type(diagnostic.get(key)) is bool for key in
                            ("event_source_approved", "source_matches", "handler_matches", "order_matches",
                             "mode_matches", "target_thread_matches", "old_inventory_order_matches"))
                    and any(diagnostic.get(key) is False for key in
                            ("event_source_approved", "source_matches", "handler_matches", "order_matches", "mode_matches")),
                    "unsupported guard evidence missing")
        if role == "live":
            requests = [(i, _object(row.get("message"))) for i, row in enumerate(rows)
                        if i > transition_end and row.get("direction") == "request"
                        and _object(row.get("message")).get("method") == "turn/start"
                        and _object(_object(row.get("message")).get("params")).get("threadId") == thread]
            require(len(requests) == 1, "same-server old task observation was not attempted")
            require(_object(requests[0][1].get("params")).get("input") ==
                    [{"type": "text", "text": "请仅回复观察结束。"}], "live observation prompt differs")
            _inventory_in_journal(live, result.get("new_inventory"), {new_source: "0.17.0"},
                                  after=transition_end, before=requests[0][0])
            if old_market != NEW_MARKET:
                require(disabled_markers[0][0] < requests[0][0], "live observation preceded old disable")
                _inventory_in_journal(live, result.get("new_inventory"), {new_source: "0.17.0"},
                                      after=disabled_markers[0][0], before=requests[0][0])
        else:
            requests = [(i, _object(row.get("message"))) for i, row in enumerate(rows)
                        if row.get("direction") == "request" and _object(row.get("message")).get("method") == "thread/resume"
                        and _object(_object(row.get("message")).get("params")).get("threadId") == thread]
            require(len(requests) == 1, "cold old task observation was not attempted")
            _inventory_in_journal(cold, result.get("new_inventory"), {new_source: "0.17.0"}, before=requests[0][0])
            if status == "unsupported_resume":
                request_id = requests[0][1].get("id")
                require(any(row.get("direction") == "response" and _object(row.get("message")).get("id") == request_id
                            and _object(row.get("message")).get("error") == {"redacted": True} for row in rows),
                        "unsupported resume was not observed")
        if status in ("observed", "root_unobserved", "session_start_unobserved"):
            turn = observation.get("turn")
            require(isinstance(turn, str), "observation turn missing")
            trace = traces[role]
            if status == "root_unobserved":
                require(trace.get("thread") == thread and trace.get("turn") == turn
                        and trace.get("actual_root") == "unknown" and observation.get("actual_root") == "unknown",
                        "unknown root observation differs")
                try:
                    _root_turn_trace(trace.get("before"), trace.get("after"), thread, turn, shared=shared_root)
                except UpgradeError:
                    pass
                else:
                    raise UpgradeError("observed root was incorrectly labeled unknown")
            else:
                require(trace == _root_turn_trace(trace.get("before"), trace.get("after"), thread, turn, shared=shared_root)
                        and observation.get("actual_root") == trace.get("actual_root"),
                        "actual data-root observation not bound to turn")
            start, end = _turn_bounds(rows, thread, turn)
            require((start == requests[0][0] if role == "live" else start > requests[0][0])
                    and _object(_object(rows[start].get("message")).get("params")).get("input") ==
                    [{"type": "text", "text": "请仅回复观察结束。"}], "observation turn order or prompt differs")
            stops = _paired(rows[start:end + 1], combined, thread, "stop", turn=turn)
            sources = sorted({"old" if _source_key(run.get("sourcePath"), [old_source]) else "new" for run in stops})
            require(bool(stops) and observation.get("stop_sources") == sources, "actual observation Hook source differs")
            if role == "cold":
                if status == "session_start_unobserved" or observation.get("session_start_source") is None:
                    require(status in ("session_start_unobserved", "root_unobserved")
                            and observation.get("session_start_source") is None
                            and observation.get("session_start_phase") is None
                            and observation.get("session_started_before_first_turn") is None,
                            "unobserved SessionStart has a claimed phase")
                    for candidate in (old_source, new_source):
                        try:
                            _cold_session_phase(rows, combined, thread, turn, candidate)
                        except UpgradeError:
                            continue
                        raise UpgradeError("SessionStart was incorrectly labeled unobserved")
                else:
                    require(observation.get("session_start_source") in ("old", "new")
                            and type(observation.get("session_started_before_first_turn")) is bool,
                            "cold SessionStart source or phase missing")
                    source = new_source if observation.get("session_start_source") == "new" else old_source
                    phase = _cold_session_phase(rows, combined, thread, turn, source)
                    require((observation.get("session_start_phase"), observation.get("session_started_before_first_turn")) == phase,
                            "cold SessionStart observation differs")
                require(observation.get("late_archive") == "observed", "late archive missing")
                verify_archive(rows, combined, thread)
        else:
            require(traces[role].get("thread") == thread and traces[role].get("turn") is None
                    and traces[role].get("actual_root") == "unknown" and observation.get("actual_root") == "unknown",
                    "unsupported observation claimed a data root")
        actual_root = observation.get("actual_root")
        if actual_root == "unknown":
            compatibility = "unobserved"
        else:
            require(actual_root in ("old", "new", "shared"), "invalid observed data root")
            require(actual_root != "new" or role in new_states, "actual new root state unavailable")
            state = old_states[role] if actual_root in ("old", "shared") else new_states[role]
            compatibility = "preserved" if _pending(initial) <= _pending(state, allow_empty=True) else "lost"
        require(observation.get("ledger_compatibility") == compatibility, "actual-root ledger compatibility differs")
        ledgers.append(compatibility)
        outcomes.append(status)
    cleanup = result.get("cleanup")
    require(isinstance(cleanup, list) and len(cleanup) == 2 and {x.get("role") for x in cleanup if isinstance(x, dict)} ==
            {"old_live", "cold"} and all(isinstance(x, dict) and type(x.get("pid")) is int
            and _object(x.get("facts")).get("owned_process_exited") is True
            and _object(x.get("facts")).get("owned_tree_no_running_members") is True
            and _object(x.get("facts")).get("process_group_cleanup_error") is None for x in cleanup),
            "observation process cleanup incomplete")
    if subject["platform"] == "Windows":
        require(all(_object(row.get("facts")).get("cleanup_complete") is True
                    and _object(row.get("facts")).get("job_close_confirmed") is True for row in cleanup),
                "observation Job cleanup incomplete")
    old_cleanup = next(row for row in cleanup if row["role"] == "old_live")
    cold_cleanup = next(row for row in cleanup if row["role"] == "cold")
    cold_markers = [row for row in cold if row.get("direction") == "observation"
                    and row.get("event") == "cold_client_started"]
    require(old_cleanup["pid"] == before.get("app_server_pid") and len(cold_markers) == 1
            and cold_markers[0].get("pid") == cold_cleanup["pid"]
            and type(old_cleanup.get("closed_monotonic_ns")) is int
            and type(cold_cleanup.get("closed_monotonic_ns")) is int
            and type(cold_markers[0].get("monotonic_ns")) is int
            and old_cleanup["closed_monotonic_ns"] < cold_markers[0]["monotonic_ns"] < cold_cleanup["closed_monotonic_ns"],
            "observation process identity or cleanup order differs")
    status = ("observation_complete" if outcomes == ["observed", "observed"] and ledgers == ["preserved", "preserved"] else
              "observation_pending" if any(s in ("root_unobserved", "session_start_unobserved") for s in outcomes)
              else "unsupported_continuity")
    require(result.get("status") == status, "observation status differs from facts")
    return {"schema": REPORT, "status": status, "observed_boundary": status, "subject": subject,
            "execution_result_sha256": sha(_evidence_path(output, "result.json")),
            "prepare_result_sha256": sha(prepared_path), "artifact_sha256": artifacts,
            "limitations": ["deliberately open old task was observed; no safe-upgrade or in-flight claim"]}


def verify(plan: dict[str, Any], output: Path, prepared: Path) -> dict[str, Any]:
    """Derive the bounded result from official projections, RPC and readback."""
    require(output.is_absolute() and not output.is_symlink() and output.is_dir(), "result directory unavailable")
    _reject_credential_path(output)
    probe = output.parent / (".cg-u01-verify-" + str(os.getpid()))
    subject = preflight(plan, probe)
    home = Path(subject["home"])
    daily = (Path.home() / ".codex").resolve()
    require(all(not _within(output.resolve(strict=True), root) for root in
                (home, daily, ROOT.resolve(), Path(subject["product_root"]), Path(subject["workspace"]))),
            "result inside protected root")
    require(prepared.is_absolute() and not prepared.is_symlink() and prepared.name == "prepare.json"
            and all(not _within(prepared.resolve(strict=True), root) for root in
                    (home, daily, *(Path(value) for value in subject.get("other_homes", [])))),
            "invalid external prepare receipt")
    _no_link_ancestors(prepared)
    old = _read_json(prepared)
    result = _read_json(_evidence_path(output, "result.json"))
    if subject["transition_strategy"] == "observe-open":
        return _verify_observation(subject, old, result, output, prepared)
    require(not (output / "guard-diagnostic.json").exists()
            and not (output / "guard-diagnostic.json").is_symlink(), "rejected Hook diagnostic present")
    require(old.get("schema") == REPORT and old.get("stage") == "prepare"
            and old.get("subject") == subject and old.get("status") == "pending", "prepare subject differs")
    require(result.get("schema") == REPORT and result.get("stage") == "open_transition"
            and result.get("subject") == subject and result.get("status") == "pending" and "failure" not in result
            and result.get("pending") == ["independent_consumer"], "execution remains incomplete")
    artifacts = _object(result.get("artifacts"))
    required_files = {"live/rpc.jsonl", "before-compact.json", "before-a.json", "before-b.json",
                      "retained-a.json", "retained-b.json"}
    strategy = subject["transition_strategy"]
    if strategy == "observe-open":
        required_files |= {"cold/rpc.jsonl", "after-a.json", "after-b.json"}
    else:
        required_files |= {"fresh-after-transition.json", "fresh-after-compact.json", "fresh-after-cold.json", "fresh-cancel.json",
                           "cold/rpc.jsonl", "cancel-a.json", "cancel-b.json"}
    require(required_files <= set(artifacts) and all(_sha(artifacts.get(name))
            and sha(_evidence_path(output, name)) == artifacts[name] for name in required_files), "artifact digest differs")
    live = _journal(_evidence_path(output, "live/rpc.jsonl"))
    _validate_rpc_requests(live, cold=False)
    require(sum(row.get("direction") == "request" and _object(row.get("message")).get("method") == "turn/start"
                for row in live) == 7, "supported lifecycle model turn budget differs")
    marks = _marks(live)
    before, after = _object(result.get("before")), _object(result.get("after"))
    require(type(before.get("app_server_pid")) is int and before["app_server_pid"] > 0
            and live[marks["transition_started"]].get("pid") == before["app_server_pid"],
            "original live app-server identity differs")
    task_a, task_b = before.get("thread_a"), before.get("thread_b")
    require(isinstance(task_a, str) and isinstance(task_b, str) and task_a != task_b, "old task IDs differ")
    old_installed = _object(old.get("installed")).get("path")
    installed = _object(result.get("installed_new"))
    new_installed = installed.get("path")
    require(isinstance(old_installed, str) and isinstance(new_installed, str), "installed path missing")
    old_cache = home / "plugins/cache" / OLD_MARKETS[subject["old_version"]] / "context-guard"
    require(any(native._official_path_matches(old_installed, old_cache / name, windows=os.name == "nt")
                for name in (subject["old_version"], "local")), "old installed path outside trusted cache")
    cache = home / "plugins/cache" / NEW_MARKET / "context-guard"
    require(any(native._official_path_matches(new_installed, cache / name, windows=os.name == "nt")
                for name in ("0.17.0", "local")), "new installed path outside trusted cache")
    manager = _load_artifacts_no_pyc(Path(subject["product_root"]))
    require(installed.get("source") == subject["new_artifact"] and installed.get("version") == "0.17.0"
            and installed.get("files") == manager.distribution_manifest(Path(subject["product_root"])),
            "new installed file evidence differs")
    old_source = str(Path(old_installed) / "hooks/hooks.json")
    new_source = str(Path(new_installed) / "hooks/hooks.json")
    old_hooks, new_hooks = result.get("old_inventory"), result.get("new_inventory")
    old_inv = _inventory_in_journal(live, old_hooks, {old_source: subject["old_version"]},
                                    before=marks["transition_started"])
    require(isinstance(new_hooks, list), "new Hook inventory missing")
    new_paths = {_source_key(h.get("sourcePath"), [old_source, new_source])
                 for h in new_hooks if isinstance(h, dict)}
    require(new_source in new_paths and None not in new_paths, "new Hook sources differ")
    new_inv = _inventory_in_journal(live, new_hooks,
                                    {p: ("0.17.0" if p == new_source else subject["old_version"])
                                     for p in new_paths}, after=marks["transition_completed"])
    _verify_old_disable(subject, result, live, marks, new_source, Path(old_installed))
    for thread, field in ((task_a, "turn_a"), (task_b, "turn_b"), (task_a, "post_compact_turn")):
        turn = before.get(field)
        require(isinstance(turn, str), "old turn missing")
        start, end = _turn_bounds(live, thread, turn)
        require(_thread_start_index(live, thread) < start, "old thread not started by this app-server")
        require(end < marks["transition_started"], "old task did not finish its baseline turn")
        require(_paired(live[start:end + 1], old_inv, thread, "stop", turn=turn), "old Stop missing")
    old_turn = before["turn_a"]
    verify_read_tool(live[:marks["transition_started"]], old_inv, task_a, old_turn,
                     before.get("read_command"), Path(subject["workspace"]))
    expected_command = ("Get-Content -LiteralPath native-read.txt" if subject["platform"] == "Windows"
                        else "cat native-read.txt")
    require(before.get("read_command") == expected_command
            and before.get("read_file_sha256") == subject["read_file_sha256"], "read fixture differs")
    compact_rows = [row["message"] for row in live[:marks["transition_started"]]
                    if row.get("direction") == "response"]
    require(host.compact_complete(compact_rows, task_a, {event: item for (event, _), item in old_inv.items()}),
            "real compact not proved")
    compact_before = _projected_state(_evidence_path(output, "before-compact.json"))
    a_before, b_before = (_projected_state(_evidence_path(output, "before-a.json")),
                          _projected_state(_evidence_path(output, "before-b.json")))
    require(compact_before["mode"].get("active") is True and a_before["mode"].get("active") is True
            and type(compact_before.get("compactions_count")) is int
            and type(a_before.get("compactions_count")) is int
            and a_before["compactions_count"] > compact_before["compactions_count"]
            and a_before.get("recovery_state") == "consumed", "compact recovery not proved")
    validate_continuity(compact_before, a_before)
    validate_continuity(a_before, _projected_state(_evidence_path(output, "retained-a.json")))
    validate_continuity(b_before, _projected_state(_evidence_path(output, "retained-b.json")))
    old_after = _object(result.get("old_data_after_transition"))
    require(_sha(before.get("state_a_sha256")) and _sha(before.get("state_b_sha256"))
            and old_after.get("thread_a_sha256") == before["state_a_sha256"]
            and old_after.get("thread_b_sha256") == before["state_b_sha256"],
            "old task state was not byte-preserved across transition")
    require(_object(a_before["session"]).get("id") == task_a
            and _object(b_before["session"]).get("id") == task_b, "saved old task differs")
    if strategy == "finish-old":
        turns = _object(before.get("cancel_turns"))
        for name, thread, old_state in (("a", task_a, a_before), ("b", task_b, b_before)):
            _check_cancel_evidence(_read_json(_evidence_path(output, "cancel-" + name + ".json")), old_state, thread)
            cancel_turn = turns.get(name)
            require(isinstance(cancel_turn, str), "cancel turn missing")
            start, end = _turn_bounds(live, thread, cancel_turn)
            request = _object(_object(live[start]).get("message"))
            require(_object(request.get("params")).get("input") == [{"type": "text", "text": "取消当前任务。"}]
                    and end < marks["transition_started"]
                    and _paired(live[start:end + 1], old_inv, thread, "stop", turn=cancel_turn),
                    "old cancellation turn was not completed")
            archive = [(i, j) for i, j, req, _ in _rpc_pairs(live, "thread/archive")
                       if _object(req.get("params")).get("threadId") == thread]
            require(len(archive) == 1 and end < archive[0][0] < archive[0][1] < marks["transition_started"],
                    "cancellation did not precede old task archive")
        verify_archive(live[:marks["transition_started"]], old_inv, task_a)
        verify_archive(live[:marks["transition_started"]], old_inv, task_b)
        fresh, turn = after.get("fresh_thread"), after.get("fresh_turn")
        require(isinstance(fresh, str) and fresh not in (task_a, task_b) and isinstance(turn, str), "fresh task missing")
        start, end = _turn_bounds(live, fresh, turn)
        require(marks["transition_completed"] < _thread_start_index(live, fresh) < start
                and end < marks["disable_completed"], "fresh turn order differs")
        stops = _paired(live[start:end + 1], new_inv, fresh, "stop", turn=turn)
        require(any(_source_key(run.get("sourcePath"), [new_source]) == new_source for run in stops),
                "fresh stable Hook did not run")
        verify_read_tool(live[start:end + 1], new_inv, fresh, turn, expected_command, Path(subject["workspace"]))
        initial_fresh = _projected_state(_evidence_path(output, "fresh-after-transition.json"))
        compact_fresh = _projected_state(_evidence_path(output, "fresh-after-compact.json"))
        cold_fresh = _projected_state(_evidence_path(output, "fresh-after-cold.json"))
        require(all(_object(state["session"]).get("id") == fresh for state in
                    (initial_fresh, compact_fresh, cold_fresh)), "fresh state belongs to another task")
        require(compact_fresh["compactions_count"] > initial_fresh["compactions_count"]
                and compact_fresh.get("recovery_state") == "consumed", "fresh compact recovery not proved")
        validate_continuity(initial_fresh, compact_fresh)
        validate_continuity(compact_fresh, cold_fresh)
        compact_turn, cold_turn = after.get("fresh_compact_turn"), after.get("fresh_cold_turn")
        require(isinstance(compact_turn, str) and isinstance(cold_turn, str), "fresh continuation missing")
        compact_start, compact_end = _turn_bounds(live, fresh, compact_turn)
        require(end < compact_start < compact_end < marks["disable_completed"]
                and _paired(live[compact_start:compact_end + 1], new_inv, fresh, "stop", turn=compact_turn),
                "fresh compact continuation missing")
        fresh_messages = [row["message"] for row in live[end:compact_end + 1] if row.get("direction") == "response"]
        require(host.compact_complete(fresh_messages, fresh, {event: item for (event, path), item in new_inv.items()
                                                               if path == new_source}), "fresh compact not proved")
        unsubs = [(i, j) for i, j, req, _ in _rpc_pairs(live, "thread/unsubscribe")
                  if _object(req.get("params")).get("threadId") == fresh]
        require(len(unsubs) == 1 and compact_end < unsubs[0][0] < unsubs[0][1] < marks["disable_completed"],
                "fresh unsubscribe not proved")
        cold = _journal(_evidence_path(output, "cold/rpc.jsonl"))
        _validate_rpc_requests(cold, cold=True)
        require(sum(row.get("direction") == "request" and _object(row.get("message")).get("method") == "turn/start"
                    for row in cold) == 2, "supported cold model turn budget differs")
        resumes = [(i, j) for i, j, req, _ in _rpc_pairs(cold, "thread/resume")
                   if _object(req.get("params")).get("threadId") == fresh]
        require(len(resumes) == 1, "fresh cold resume missing")
        cold_inv = _inventory_in_journal(cold, new_hooks, {new_source: "0.17.0"}, before=resumes[0][0])
        cold_start, cold_end = _turn_bounds(cold, fresh, cold_turn)
        require(resumes[0][1] < cold_start < cold_end
                and _paired(cold[cold_start:cold_end + 1], cold_inv, fresh, "stop", turn=cold_turn),
                "fresh cold Stop missing")
        require(type(after.get("cold_session_started_before_first_turn")) is bool
                and (after.get("cold_session_start_phase"), after.get("cold_session_started_before_first_turn")) ==
                _cold_session_phase(cold, cold_inv, fresh, cold_turn, new_source),
                "fresh cold SessionStart phase differs")
        _check_cancel_evidence(_read_json(_evidence_path(output, "fresh-cancel.json")), cold_fresh, fresh)
        fresh_cancel_turn = after.get("fresh_cancel_turn")
        require(isinstance(fresh_cancel_turn, str), "fresh cancellation turn missing")
        cancel_start, cancel_end = _turn_bounds(cold, fresh, fresh_cancel_turn)
        require(cold_end < cancel_start < cancel_end
                and _object(_object(cold[cancel_start].get("message")).get("params")).get("input") ==
                    [{"type": "text", "text": "取消当前任务。"}]
                and _paired(cold[cancel_start:cancel_end + 1], cold_inv, fresh, "stop", turn=fresh_cancel_turn),
                "fresh cancellation turn not established")
        fresh_archives = [(i, j) for i, j, req, _ in _rpc_pairs(cold, "thread/archive")
                          if _object(req.get("params")).get("threadId") == fresh]
        require(len(fresh_archives) == 1 and cancel_end < fresh_archives[0][0] < fresh_archives[0][1],
                "fresh task archive preceded cancellation")
        verify_archive(cold, cold_inv, fresh)
        tracked = [(subject["old_data_root"], task_a), (subject["old_data_root"], task_b),
                   (subject["new_data_root"], fresh)]
        boundary = "cancelled_old_before_transition"
    else:
        require(after.get("thread_a") == task_a and after.get("thread_b") == task_b, "resumed task IDs differ")
        unsubscribed = [i for i, j, request, _ in _rpc_pairs(live, "thread/unsubscribe")
                        if _object(request.get("params")).get("threadId") == task_b
                        and j < marks["transition_started"]]
        require(len(unsubscribed) == 1, "cold task unsubscribe before transition not proved")
        turn_a, turn_b = after.get("turn_a"), after.get("turn_b")
        require(isinstance(turn_a, str) and isinstance(turn_b, str), "continued turn missing")
        start, end = _turn_bounds(live, task_a, turn_a)
        require(start > marks["transition_completed"] and end < marks["disable_completed"], "open task order differs")
        require(_paired(live[start:end + 1], new_inv, task_a, "stop", turn=turn_a), "open task Stop missing")
        validate_continuity(a_before, _projected_state(_evidence_path(output, "after-a.json")))
        verify_archive(live[:marks["disable_completed"]], new_inv, task_a)
        cold = _journal(_evidence_path(output, "cold/rpc.jsonl"))
        _validate_rpc_requests(cold, cold=True)
        cold_inv = _inventory_in_journal(cold, new_hooks,
                                         {p: ("0.17.0" if p == new_source else subject["old_version"])
                                          for p in new_paths})
        resumes = [(i, j) for i, j, request, _ in _rpc_pairs(cold, "thread/resume")
                   if _object(request.get("params")).get("threadId") == task_b]
        require(len(resumes) == 1, "cold resume not proved")
        cold_start, cold_end = _turn_bounds(cold, task_b, turn_b)
        require(cold_start > resumes[0][1]
                and type(after.get("cold_session_started_before_first_turn")) is bool
                and (after.get("cold_session_start_phase"), after.get("cold_session_started_before_first_turn")) ==
                _cold_session_phase(cold, cold_inv, task_b, turn_b, new_source),
                "cold SessionStart phase differs")
        require(_paired(cold[cold_start:cold_end + 1], cold_inv, task_b, "stop", turn=turn_b), "cold Stop missing")
        validate_continuity(b_before, _projected_state(_evidence_path(output, "after-b.json")))
        verify_archive(cold, cold_inv, task_b)
        tracked = [(subject["old_data_root"], task_a), (subject["old_data_root"], task_b),
                   (subject["new_data_root"], task_a), (subject["new_data_root"], task_b)]
        boundary = "observed_open_and_cold_continuity"
    require(after.get("data_root") == subject["new_data_root"] and before.get("data_root") == subject["old_data_root"],
            "observed data root differs")
    require(result.get("selected_data_before_removal") == result.get("selected_data_after_removal")
            == _selected_states(home, tracked), "selected task data changed or is unavailable")
    _verify_disable_rpc(live, marks, new_source, new_inv, result.get("disabled_inventory"), subject["old_version"])
    _verify_cli_lifecycle(subject, old, result)
    timed = result.get("commands")
    require(isinstance(timed, list) and all(isinstance(item, dict)
            and type(item.get("started_monotonic_ns")) is int
            and type(item.get("completed_monotonic_ns")) is int
            and 0 < item["started_monotonic_ns"] <= item["completed_monotonic_ns"] for item in timed),
            "CLI timing facts unavailable")
    require(all(left["completed_monotonic_ns"] <= right["started_monotonic_ns"]
                for left, right in zip(timed, timed[1:])), "CLI command order differs")
    marker_times = {name: live[index]["monotonic_ns"] for name, index in marks.items()}
    codex = subject["codex"]
    transition_mutations = [[codex, "plugin", "marketplace", "add", subject["new_artifact"]],
                            [codex, "plugin", "add", "context-guard@" + NEW_MARKET, "--json"]]
    if subject["old_version"] == "0.15.1":
        transition_mutations.insert(0, [codex, "plugin", "marketplace", "remove", NEW_MARKET])
    for argv in transition_mutations:
        candidates = [item for item in timed if item.get("argv") == argv
                      and marker_times["transition_started"] < item["started_monotonic_ns"]
                      <= item["completed_monotonic_ns"] < marker_times["transition_completed"]]
        require(len(candidates) == 1, "transition command timing not proved")
    for argv, lo, hi in (([codex, "plugin", "remove", "context-guard@" + NEW_MARKET],
                          "disable_completed", "plugin_removed"),
                         ([codex, "plugin", "marketplace", "remove", NEW_MARKET],
                          "plugin_removed", "marketplace_removed")):
        require(sum(item.get("argv") == argv and marker_times[lo] < item["started_monotonic_ns"]
                    <= item["completed_monotonic_ns"] < marker_times[hi] for item in timed) == 1,
                "removal command timing not proved")
    require(not Path(new_installed).exists(), "removed selected cache reappeared")
    cleanup = result.get("cleanup")
    require(isinstance(cleanup, list) and len(cleanup) == 2
            and {item.get("role") for item in cleanup if isinstance(item, dict)} == {"live", "cold"}
            and all(isinstance(item, dict) and type(item.get("pid")) is int
                    and type(item.get("closed_monotonic_ns")) is int
                    and _object(item.get("facts")).get("owned_process_exited") is True
                    and _object(item.get("facts")).get("owned_tree_no_running_members") is True
                    and _object(item.get("facts")).get("process_group_cleanup_error") is None for item in cleanup),
            "owned app-server cleanup incomplete")
    live_close = next(item for item in cleanup if item["role"] == "live")
    cold_close = next(item for item in cleanup if item["role"] == "cold")
    cold_markers = [(i, row) for i, row in enumerate(cold) if row.get("direction") == "observation"
                    and row.get("event") == "cold_client_started"]
    require(len(cold_markers) == 1 and cold_markers[0][0] < resumes[0][0]
            and cold_markers[0][1].get("pid") == cold_close["pid"]
            and live_close["pid"] == before.get("app_server_pid") and live_close["pid"] != cold_close["pid"]
            and type(cold_markers[0][1].get("monotonic_ns")) is int
            and cold_markers[0][1]["monotonic_ns"] < cold_close["closed_monotonic_ns"]
            and cold_markers[0][1]["monotonic_ns"] < live_close["closed_monotonic_ns"],
            "cold and live app-server identities are not independently bound")
    if subject["platform"] == "Windows":
        require(all(_object(item.get("facts")).get("cleanup_complete") is True
                    and _object(item.get("facts")).get("job_close_confirmed") is True
                    for item in cleanup), "Windows owned Job cleanup incomplete")
    return {"schema": REPORT, "status": "passed", "observed_boundary": boundary,
            "subject": subject, "execution_result_sha256": sha(_evidence_path(output, "result.json")),
            "prepare_result_sha256": sha(prepared), "artifact_sha256": artifacts,
            "limitations": [("old tasks explicitly cancelled before transition; no continuity claim" if strategy == "finish-old"
                             else "open task was idle during transition; no in-flight claim"),
                            "literal PLUGIN_DATA and transient executed script path were not observed",
                            "this verifies one host and one starting version, not the whole matrix"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--auth-home", type=Path, required=True,
                        help="isolated authentication HOME, used for path checks before reading the plan")
    parser.add_argument("--other-auth-home", type=Path, action="append", required=True,
                        help="another isolated authentication HOME; repeat for each HOME")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--preflight", action="store_true")
    actions.add_argument("--prepare", action="store_true")
    actions.add_argument("--run-open-transition", action="store_true")
    actions.add_argument("--verify", action="store_true")
    parser.add_argument("--prepared-result", type=Path)
    parser.add_argument("--verify-output", type=Path,
                        help="new external result for the independent consumer")
    args = parser.parse_args(argv)
    if (args.run_open_transition or args.verify) != (args.prepared_result is not None):
        parser.error("--run-open-transition and --verify require --prepared-result")
    if args.verify != (args.verify_output is not None):
        parser.error("--verify requires --verify-output; other actions must omit it")
    try:
        home, other_homes = _invocation_paths(args.plan, args.output, args.auth_home,
                                               args.other_auth_home, args.prepared_result, args.verify_output)
        plan = _read_json(args.plan)
        require(_absolute_real(plan.get("home"), "plan HOME") == home
                and sorted(_absolute_real(item, "plan other HOME") for item in plan.get("other_homes", []))
                == sorted(other_homes), "CLI and plan HOME boundaries differ")
        if args.preflight:
            subject = preflight(plan, args.output)
            if subject["codex_hardlink_count"] != 1:
                raise CapabilityPending("public CLI hard-link aliases require review")
            print("upgrade_preflight=passed; installation_and_native_acceptance_not_run")
            return 0
        if args.verify:
            result = verify(plan, args.output, args.prepared_result)
            roots = [home, *other_homes, ROOT.resolve(), Path(result["subject"]["product_root"]),
                     Path(result["subject"]["workspace"]), Path(result["subject"]["old_artifact"]),
                     Path(result["subject"]["new_artifact"]), (Path.home() / ".codex").resolve()]
            _new_outside(args.verify_output, roots)
            _write_new(args.verify_output, result)
            print(json.dumps({"status": result["status"], "observed_boundary": result["observed_boundary"]}))
            return 0 if result["status"] in ("passed", "observation_complete") else 1
        if args.prepare:
            result = prepare(plan, args.output)
        else:
            result = run_open_transition(plan, args.output, args.prepared_result)
    except CapabilityPending as exc:
        print("upgrade=pending; " + str(exc), file=sys.stderr)
        return 1
    except (UpgradeError, OSError, RuntimeError, ValueError, KeyError, TypeError,
            zipfile.BadZipFile, tarfile.TarError) as exc:
        print("upgrade=refused; " + type(exc).__name__, file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"], "stage": result["stage"],
                      "pending": result["pending"]}))
    if result["status"] == "failed" or (args.run_open_transition and result["status"] != "passed"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
