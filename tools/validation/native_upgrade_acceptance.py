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


def _common_identity(info: os.stat_result) -> tuple[Any, ...]:
    # Windows path and opened-handle providers can report different ctime for
    # the same object. Compare it within each provider, never across them.
    return _stat_identity(info)[:-1]


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
        require(_common_identity(before) == _common_identity(opened), "digest input changed before open")
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


def _old_provenance(product: Path, old: Path, version: str, plan: dict[str, Any],
                    expected_files: dict[str, str], old_zip_identity: tuple[Any, ...] | None = None) -> dict[str, str]:
    if version == "0.16.1":
        archive = _absolute_real(plan.get("old_release_zip"), "old release ZIP", file=True)
        identity = old_zip_identity if old_zip_identity is not None else _zip_metadata(archive)
        require(sha(archive, expected=identity) == OLD_0161_ZIP_SHA256, "old published ZIP digest differs")
        manager = native.load_artifacts(old)
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


def _read_json(path: Path) -> dict[str, Any]:
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
        require(_common_identity(opened) == _common_identity(before), "JSON changed before read")
        content = stream.read(16 * 1024 * 1024 + 1)
        require(len(content) <= 16 * 1024 * 1024 and
                _stat_identity(os.fstat(stream.fileno())) == _stat_identity(opened) and
                _stat_identity(path.lstat()) == _stat_identity(before),
                "JSON changed during read")
    value = adoption.strict_json(content.decode("utf-8"))
    require(isinstance(value, dict), "JSON object required")
    return value


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
        require(_common_identity(opened) == _common_identity(before), "ZIP changed before metadata read")
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
        require(_common_identity(opened) == _common_identity(before), "ZIP changed before member read")
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


def _invocation_paths(plan_path: Path, output: Path, home_value: Path,
                      other_values: list[Path], prepared: Path | None,
                      verify_output: Path | None = None) -> tuple[Path, list[Path]]:
    """Establish HOME boundaries from CLI args before opening any plan file."""
    home = _absolute_real(str(home_value), "isolated authentication HOME")
    require(1 <= len(other_values) <= 8, "other authentication HOME arguments required")
    others = [_absolute_real(str(value), "other authentication HOME") for value in other_values]
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
                and bool(item["currentHash"]), "Hook source or trust differs")
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


def _pending(state: Any) -> set[tuple[str, str]]:
    rows = _object(state).get("requirements")
    require(isinstance(rows, list), "requirements unavailable")
    pending = [r for r in rows if isinstance(r, dict) and r.get("status") == "pending"]
    require(all(isinstance(r.get("id"), str) and bool(r["id"]) and _sha(r.get("sha256"))
                for r in pending), "pending requirement identity unavailable")
    values = {(r["id"], r["sha256"]) for r in pending}
    require(len(values) == len(pending), "duplicate pending requirement")
    require(values, "no verifiable pending requirement")
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
                and _sha(item.get("sha256")) and isinstance(item.get("status"), str),
                "requirement projection unavailable")
        projected.append({key: item[key] for key in ("id", "sha256", "status")})
    recovery = _object(_object(state.get("pending")).get("recovery"))
    return {"session": {"id": session["id"]}, "requirements": projected,
            "mode": {"active": _object(state.get("mode")).get("active")},
            "compactions_count": len(compactions), "recovery_state": recovery.get("state")}


def validate_continuity(before: Any, after: Any) -> None:
    """No implicit state migration: verify requirements in the observed data root."""
    old, new = _object(before), _object(after)
    require(_object(old.get("session")).get("id") == _object(new.get("session")).get("id")
            and isinstance(_object(old.get("session")).get("id"), str), "session changed")
    require(_pending(old) <= _pending(new), "unfinished requirements not preserved")


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
        require(item.get("command") == command, "unapproved command observed in read turn")
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
                 sources: dict[str, str] | None = None):
        self.approved: dict[tuple[str, str], dict[str, Any]] = {}
        self.initial_sources = sources or {str(Path(plan["plugin_root"]) / "hooks/hooks.json"): "old"}
        self.initial_approved: dict[tuple[str, str], dict[str, Any]] = {}
        self.turn_count = 0
        self.plan, self.rows, self.pending, self.sequence = plan, [], {}, 0
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
                result = {"thread": {"id": _object(result.get("thread")).get("id")}}
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
                common["item"]["command"] = expected if item.get("command") == expected else "<unapproved>"
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
            run = _object(_object(message.get("params")).get("run"))
            source = _source_key(run.get("sourcePath"), {path for _, path in self.approved})
            expected = self.approved.get((run.get("eventName"), source))
            require(expected is not None and all(run.get(k) == expected.get(k) for k in
                    ("eventName", "source", "handlerType", "displayOrder")),
                    "unexpected running Hook source")
            require(run.get("executionMode") == ("async" if expected.get("async") else "sync"),
                    "unexpected Hook execution mode")
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
        require(self.turn_count < 6, "model turn budget exhausted")
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
                require(_paired(rows, self.approved, thread, "stop", turn=turn), "Stop not observed")
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
    require(isinstance(extra, list) and 1 <= len(extra) <= 8,
            "other isolated authentication HOMEs must be listed")
    other_homes = [_absolute_real(value, "other isolated HOME") for value in extra]
    require(all(not _within(home, other) and not _within(other, home) for other in other_homes),
            "isolated HOMEs overlap")
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
    manager = native.load_artifacts(product)
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


def _archive_owned(client: UpgradeClient, thread: str) -> None:
    client.rpc("thread/archive", {"threadId": thread})
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        client.log.flush()
        rows = [adoption.strict_json(line) for line in
                (Path(client.log.name)).read_text(encoding="utf-8").splitlines()]
        try:
            verify_archive(rows, client.approved, thread)
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
        try:
            if _paired(rows, client.approved, thread, event):
                return
        except UpgradeError as exc:
            if str(exc) != "unfinished Hook run":
                raise
        client.receive(deadline)
    raise UpgradeError(event + " not established")


def _selected_states(home: Path, roots: list[tuple[str, str]]) -> dict[str, str]:
    facts = {}
    for root, thread in roots:
        actual, state = _state_at(home, root, thread)
        facts[str(actual) + "/" + thread] = digest(state)
    return facts


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
        observe_sentinel("after_old_list")
        client_plan = {"codex": str(codex), "cwd": str(workspace), "home": str(home),
                       "plugin_root": str(installed)}
        with _launch_environment(home):
            live = UpgradeClient(client_plan, live_dir)
        old_source = str(installed / "hooks/hooks.json")
        result["old_inventory"] = list(live.approved.values())
        task_a = live.start()
        task_b = live.start()
        read_command = ("Get-Content -LiteralPath native-read.txt" if platform.system() == "Windows"
                        else "cat native-read.txt")
        prompt = ("$context-guard\n请记录一项尚未完成的验收要求：等待我明确同意后再提交。"
                  "现在不要执行或完成该要求，只回复等待。")
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
        compact_turn, compact_rows = live.observed_turn(task_a, "压缩后保持之前的未完成要求，不执行，只回复等待。")
        _, before_a = _state_at(home, plan.get("old_data_root"), task_a)
        host.verify_recovery(before_compact, before_a)
        _write_new(output / "before-a.json", _state_projection(before_a))
        _write_new(output / "before-b.json", _state_projection(before_b))
        strategy = plan.get("transition_strategy")
        if strategy == "finish-old":
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
                            "app_server_pid": live.owned.process.pid,
                            "read_file_sha256": read_sha, "read_command": read_command,
                            "state_a_sha256": old_a_bytes, "state_b_sha256": old_b_bytes,
                            "old_a_stop_count": len(_paired(rows_a, live.approved, task_a, "stop", turn=turn_a)),
                            "old_b_stop_count": len(_paired(rows_b, live.approved, task_b, "stop", turn=turn_b)),
                            "post_compact_stop_count": len(_paired(compact_rows, live.approved, task_a,
                                                                   "stop", turn=compact_turn)),
                            "scope": ("old tasks archived before transition" if strategy == "finish-old"
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
        public_files = native.load_artifacts(Path(plan["product_root"])).distribution_manifest(Path(plan["product_root"]))
        native.exact_artifact_parity(new_installed, public_files)
        actual_files = source_files(new_installed)
        require(actual_files == public_files, "new full-file parity differs")
        new_source = str(new_installed / "hooks/hooks.json")
        old_still_exists = installed.is_dir() and not installed.is_symlink()
        result["installed_new"] = {"path": str(new_installed), "source": str(new), "version": "0.17.0",
                                   "files": actual_files,
                                   "old_cache_exists": old_still_exists,
                                   "old_cache_files_sha256": digest(source_files(installed)) if old_still_exists else None}
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
        _write_new(output / "review-required.json", {"message": "Review Hooks normally in the official CLI TUI."})
        approved = _reviewed_sources(live, {old_source: plan["old_version"], new_source: "0.17.0"}, new_source)
        result["new_inventory"] = list(approved.values())
        require(live.owned.process.poll() is None, "original app-server exited during transition")
        continuation = "请继续保留之前未完成的要求，不执行它，只回复等待。"
        if strategy == "finish-old":
            fresh = live.start()
            fresh_turn, fresh_rows = live.observed_turn(fresh, prompt)
            new_data, fresh_state = _state_at(home, plan.get("new_data_root"), fresh)
            _pending(fresh_state)
            _write_new(output / "fresh-after-transition.json", _state_projection(fresh_state))
            _archive_owned(live, fresh)
            fresh_stops = _paired(fresh_rows, approved, fresh, "stop", turn=fresh_turn)
            require(any(_source_key(run.get("sourcePath"), [new_source]) == new_source for run in fresh_stops),
                    "fresh task did not run the stable Hook source")
            result["after"] = {"fresh_thread": fresh, "fresh_turn": fresh_turn, "data_root": str(new_data),
                               "fresh_stop_sources": sorted({run["sourcePath"] for run in fresh_stops}),
                               "scope": "old tasks finished before transition; no continuity claim"}
        else:
            turn_after_a, rows_after_a = live.observed_turn(task_a, continuation)
            new_data, after_a = _state_at(home, plan.get("new_data_root"), task_a)
            validate_continuity(before_a, after_a)
            _write_new(output / "after-a.json", _state_projection(after_a))
            cold_plan = {**client_plan, "plugin_root": str(new_installed)}
            with _launch_environment(home):
                cold = UpgradeClient(cold_plan, cold_dir,
                                     sources={p: ("0.17.0" if p == new_source else plan["old_version"])
                                              for _, p in approved})
            begin = len(cold.rows)
            cold.rpc("thread/resume", {"threadId": task_b, "cwd": str(workspace),
                                        "sandbox": "read-only", "approvalPolicy": "on-request"})
            _wait_hook(cold, task_b, "sessionStart", begin)
            turn_after_b, rows_after_b = cold.observed_turn(task_b, continuation)
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
                               "cold_stop_sources": sorted({run["sourcePath"] for run in cold_stops})}
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
        for client in (cold, live):
            if client is not None:
                try:
                    result["cleanup"].append(client.close())
                except BaseException as exc:
                    result["cleanup"].append({"cleanup_unknown": type(exc).__name__})
        artifacts = ("live/rpc.jsonl", "cold/rpc.jsonl", "before-compact.json", "before-a.json",
                     "before-b.json", "retained-a.json", "retained-b.json", "after-a.json", "after-b.json",
                     "fresh-after-transition.json")
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


def _projected_state(path: Path) -> dict[str, Any]:
    value = _read_json(path)
    require(set(value) == {"session", "requirements", "mode", "compactions_count", "recovery_state"},
            "state output is not a strict projection")
    require(set(_object(value.get("session"))) == {"id"}
            and set(_object(value.get("mode"))) == {"active"}, "state projection shape differs")
    rows = value.get("requirements")
    require(isinstance(rows, list) and all(isinstance(row, dict) and set(row) == {"id", "sha256", "status"}
                                           for row in rows), "requirement projection shape differs")
    _pending(value)
    return value


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


def _verify_cli_lifecycle(subject: dict[str, Any], prepared: dict[str, Any], result: dict[str, Any]) -> None:
    codex, old_market = subject["codex"], OLD_MARKETS[subject["old_version"]]
    old_source, new_source = Path(subject["old_artifact"]), Path(subject["new_artifact"])
    sentinel = subject["sentinel"]
    stable_id = "context-guard@" + NEW_MARKET
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
    index, disabled = _command_index(commands, [codex, "plugin", "list", "--marketplace", NEW_MARKET, "--json"], index)
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
        required_files.add("fresh-after-transition.json")
    require(required_files <= set(artifacts) and all(_sha(artifacts.get(name))
            and sha(_evidence_path(output, name)) == artifacts[name] for name in required_files), "artifact digest differs")
    live = _journal(_evidence_path(output, "live/rpc.jsonl"))
    _validate_rpc_requests(live, cold=False)
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
    manager = native.load_artifacts(Path(subject["product_root"]))
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
        require(_object(_projected_state(_evidence_path(output, "fresh-after-transition.json"))["session"]).get("id") == fresh,
                "fresh state belongs to another task")
        verify_archive(live[:marks["disable_completed"]], new_inv, fresh)
        tracked = [(subject["old_data_root"], task_a), (subject["old_data_root"], task_b),
                   (subject["new_data_root"], fresh)]
        boundary = "finish_old_before_transition"
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
        require(_paired(cold[resumes[0][0]:], cold_inv, task_b, "sessionStart"), "cold SessionStart missing")
        cold_start, cold_end = _turn_bounds(cold, task_b, turn_b)
        require(cold_start > resumes[0][0], "cold turn preceded resume")
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
    require(isinstance(cleanup, list) and len(cleanup) == (2 if strategy == "observe-open" else 1)
            and all(isinstance(item, dict) and item.get("owned_process_exited") is True
                    and item.get("owned_tree_no_running_members") is True
                    and item.get("process_group_cleanup_error") is None for item in cleanup),
            "owned app-server cleanup incomplete")
    if subject["platform"] == "Windows":
        require(all(item.get("cleanup_complete") is True and item.get("job_close_confirmed") is True
                    for item in cleanup), "Windows owned Job cleanup incomplete")
    return {"schema": REPORT, "status": "passed", "observed_boundary": boundary,
            "subject": subject, "execution_result_sha256": sha(_evidence_path(output, "result.json")),
            "prepare_result_sha256": sha(prepared), "artifact_sha256": artifacts,
            "limitations": [("old tasks finished before transition; no continuity claim" if strategy == "finish-old"
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
            return 0
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
