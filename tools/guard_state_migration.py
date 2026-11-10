#!/usr/bin/env python3
"""Guard private-state inventory, migration and recovery.

Read-only inventory is the default. An apply must explicitly select the source
and target identities, the session scope and the conflict policy, and it only
ever creates new target state: existing target sessions are never overwritten,
an unresolvable same-identity conflict is isolated outside the data root, and
the compensating restore removes exactly what this run created.

Legacy ``sessions`` trees are never migrated: the product contract keeps them
read-only under their original runtime, so the inventory reports them as
``retain_in_place`` and an active legacy task must finish under its original
loaded runtime before its HOME's daily entry changes.

This tool is repository tooling, not plugin runtime: it lives outside the
runtime-tree roots, changes no Hook, schema or installed artifact, and writes
nothing into the repository. Private state never enters Git, cross-host
transfers or public attachments. Outputs contain object names, digests and
counts. The tool reads state for structural checks and emits no prompt or
requirement text.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import ntpath
import os
import platform
import re
import shutil
import stat
import sys
import time
from pathlib import Path, PureWindowsPath
from typing import Any

SCHEMA = "cg-guard-state-migration/v1"
PLAN_SCHEMA = "cg-guard-state-migration-plan/v1"
STABLE_DATA_ROOT = "context-guard-codex-context-guard"
DATA_ROOT_PREFIX = "context-guard-"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SESSION_NAME = re.compile(r"[A-Za-z0-9._~-]{1,120}\Z")
IDENTITY_NAME = re.compile(r"[A-Za-z0-9_-]{1,120}\Z")
# Maintenance and bookkeeping namespaces that are never session scope and
# never copied: they are per-root runtime state, not task state.
EXCLUDED_SESSION_NAMES = frozenset({".locks"})
SUPPORTED_SCHEMAS = frozenset({13})
LOCK_DEADLINE_SECONDS = 10.0


class MigrationError(ValueError):
    """Inputs, state or observations cannot establish the requested outcome."""


def require(value: Any, message: str) -> None:
    if not value:
        raise MigrationError(message)


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _no_link_ancestors(path: Path) -> None:
    """Refuse symlinked or reparse ancestors before any read or write."""
    current = path.absolute()
    require(".." not in current.parts, "parent traversal refused")
    for parent in (current, *current.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise MigrationError(f"link ancestor refused: {parent}")


def _absolute_real(value: Any, name: str, *, file: bool = False) -> Path:
    require(isinstance(value, str) and value, f"{name} must be a path string")
    path = Path(value).expanduser().absolute()
    _no_link_ancestors(path)
    try:
        path = path.resolve(strict=True)
    except OSError as exc:
        raise MigrationError(f"{name} is not an existing real path: {value}") from exc
    if file and not path.is_file():
        raise MigrationError(f"{name} must be an existing file")
    _no_link_ancestors(path)
    return path


def _new_directory(value: Any, name: str, *protected: Path) -> Path:
    require(isinstance(value, str) and value, f"{name} must be a path string")
    path = Path(value).expanduser().absolute()
    _no_link_ancestors(path)
    require(all(not _within(root, path) and not _within(path, root) for root in protected),
            f"{name} overlaps a protected root")
    if path.exists() or path.is_symlink():
        raise MigrationError(f"{name} must be a new path: {path}")
    _no_link_ancestors(path.parent)
    path.mkdir(mode=0o700, parents=True)
    _protect_created_directory(path)
    return path


def _protect_created_directory(path: Path) -> None:
    if os.name == "nt":
        scripts = Path(__file__).resolve().parents[1] / "scripts"
        sys.path.insert(0, str(scripts))
        try:
            from context_guard import PrivateBoundaryError, secure_directory

            secure_directory(path)
        except PrivateBoundaryError as exc:
            raise MigrationError("new directory could not be made private") from exc
        finally:
            sys.path.pop(0)


def _exclusive_json(path: Path, payload: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise MigrationError(f"result path already exists: {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _supersede_then_write(path: Path, payload: dict[str, Any]) -> None:
    """Write a fresh result for an idempotent stage, keeping every prior one.

    Re-running verify or restore on the same workspace is expected to be
    idempotent, so the previous result of this tool's own stage record is
    rotated aside by run time instead of being overwritten or refusing.
    """
    if path.exists() or path.is_symlink():
        path.rename(path.with_name(f"{path.stem}.{time.time_ns()}{path.suffix}"))
    _exclusive_json(path, payload)


def _sha(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX64.fullmatch(value))


def _tree_digest(root: Path) -> tuple[str, int, list[str]]:
    """Sorted relative-path digest inventory of a session tree."""
    _no_link_ancestors(root)
    require(root.is_dir(), "session directory unavailable")
    entries: dict[str, str] = {}
    bytes_total = 0
    def fail_walk(exc: OSError) -> None:
        raise exc

    for base, dirnames, filenames in os.walk(root, onerror=fail_walk):
        dirnames[:] = sorted(dirnames)
        for dirname in dirnames:
            _no_link_ancestors(Path(base) / dirname)
        for filename in sorted(filenames):
            path = Path(base) / filename
            relative = path.relative_to(root).as_posix()
            require(filename.casefold() != "auth.json", "credential-named session entry refused")
            _no_link_ancestors(path)
            if not path.is_file() or path.stat().st_nlink != 1:
                raise MigrationError(f"unsupported session entry: {relative}")
            entries[relative] = _digest_file(path)
            bytes_total += path.stat().st_size
    if not entries:
        return "empty", 0, []
    combined = hashlib.sha256()
    for name in sorted(entries):
        combined.update(name.encode("utf-8"))
        combined.update(entries[name].encode("ascii"))
    return combined.hexdigest(), bytes_total, sorted(entries)


def _session_identity(directory: Path) -> dict[str, Any]:
    """Structural facts only; requirement text is never read or emitted."""
    state_path = directory / "state.json"
    facts: dict[str, Any] = {"state_present": state_path.is_file()}
    if facts["state_present"]:
        try:
            payload = json.loads(state_path.read_text(encoding="utf-8"))
        except (UnicodeError, json.JSONDecodeError, OSError) as exc:
            facts["state_readable"] = False
            facts["state_error"] = type(exc).__name__
            return facts
        if not isinstance(payload, dict):
            facts["state_readable"] = False
            return facts
        facts["state_readable"] = True
        schema = payload.get("schema_version")
        facts["state_schema"] = schema if type(schema) is int else None
        session = payload.get("session")
        if isinstance(session, dict) and isinstance(session.get("id"), str):
            facts["state_session_id"] = session["id"]
        facts["state_top_level_keys"] = sorted(str(k) for k in payload)
    return facts


def _lock_probe(lock_path: Path) -> str:
    """Non-blocking writer probe on the lifecycle lock; no data writes."""
    try:
        _no_link_ancestors(lock_path)
        if not lock_path.is_file():
            return "absent"
        descriptor = os.open(lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    except (MigrationError, OSError):
        return "unknown"
    try:
        _flock_nonblocking(descriptor)
    except OSError:
        return "writer_active"
    else:
        _funlock(descriptor)
        return "free"
    finally:
        os.close(descriptor)


def _flock_nonblocking(descriptor: int) -> None:
    """Acquire an exclusive kernel lock without waiting (POSIX/Windows)."""
    if platform.system() == "Windows":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _funlock(descriptor: int) -> None:
    if platform.system() == "Windows":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


class _LifecycleLock:
    """Bounded exclusive hold on one session lifecycle lock file."""

    def __init__(self, lock_path: Path, deadline: float, *, create: bool = True) -> None:
        self._path = lock_path
        self._deadline = deadline
        self._create = create
        self._descriptor: int | None = None

    def __enter__(self) -> "_LifecycleLock":
        _no_link_ancestors(self._path)
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        if self._create:
            flags |= os.O_CREAT
        while True:
            try:
                self._descriptor = os.open(self._path, flags, 0o600)
            except OSError as exc:
                raise MigrationError(f"lifecycle lock unavailable: {self._path}") from exc
            try:
                info = os.fstat(self._descriptor)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_ino,
                        "lifecycle lock must be a single regular file")
                _flock_nonblocking(self._descriptor)
                self.verify()
                return self
            except (OSError, MigrationError) as exc:
                os.close(self._descriptor)
                self._descriptor = None
                if isinstance(exc, MigrationError):
                    raise
                if time.monotonic() >= self._deadline:
                    raise MigrationError(
                        f"session writer still active past deadline: {self._path}")
                time.sleep(0.2)

    def verify(self) -> None:
        _no_link_ancestors(self._path)
        current = self._path.lstat()
        held = os.fstat(self._descriptor)
        require((current.st_dev, current.st_ino) == (held.st_dev, held.st_ino),
                "lifecycle lock replaced during migration")

    def __exit__(self, *_exc: Any) -> None:
        if self._descriptor is not None:
            with contextlib.suppress(OSError, ValueError):
                _funlock(self._descriptor)
            with contextlib.suppress(OSError):
                os.close(self._descriptor)
            self._descriptor = None


def _codex_homes(args: argparse.Namespace) -> list[Path]:
    homes = [_absolute_real(home, "home") for home in args.home]
    require(homes, "at least one explicit --home is required; there is no default")
    distinct: dict[str, Path] = {}
    for home in homes:
        distinct.setdefault(str(home), home)
    return list(distinct.values())


def _data_roots(home: Path) -> dict[str, Path]:
    """Identity name -> data root inside one HOME; names are classified, not guessed."""
    roots: dict[str, Path] = {}
    plugin_data = home / "plugins" / "data"
    _no_link_ancestors(plugin_data)
    if plugin_data.is_dir():
        for entry in sorted(plugin_data.iterdir()):
            if not entry.is_dir() or entry.is_symlink():
                continue
            if entry.name.startswith(DATA_ROOT_PREFIX) and len(entry.name) > len(DATA_ROOT_PREFIX):
                roots[entry.name[len(DATA_ROOT_PREFIX):]] = entry
    direct = home / "context-guard"
    if direct.is_dir() and not direct.is_symlink():
        roots["<direct>"] = direct
    return roots


def _session_roots(data_root: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for namespace in ("sessions-v2", "sessions"):
        path = data_root / namespace
        if path.is_dir() and not path.is_symlink():
            found[namespace] = path
    return found


def _inventory_home(home: Path) -> dict[str, Any]:
    installed_versions: dict[str, str] = {}
    cache = home / "plugins" / "cache"
    _no_link_ancestors(cache)
    if cache.is_dir():
        for market_dir in sorted(cache.iterdir()):
            plugin_dir = market_dir / "context-guard"
            _no_link_ancestors(plugin_dir)
            if plugin_dir.is_dir():
                versions = sorted(entry.name for entry in plugin_dir.iterdir()
                                  if entry.is_dir())
                if versions:
                    installed_versions[market_dir.name] = versions[-1]
    roots: list[dict[str, Any]] = []
    for identity, data_root in _data_roots(home).items():
        _no_link_ancestors(data_root)
        root_facts: dict[str, Any] = {
            "identity": identity,
            "path": str(data_root),
            "installed_version_observation": installed_versions.get(identity),
            "namespaces": {},
        }
        for namespace, session_root in _session_roots(data_root).items():
            _no_link_ancestors(session_root)
            sessions: list[dict[str, Any]] = []
            for entry in sorted(session_root.iterdir()):
                if entry.name in EXCLUDED_SESSION_NAMES or not entry.is_dir() \
                        or entry.is_symlink():
                    continue
                digest, size, files = _tree_digest(entry)
                facts = _session_identity(entry)
                facts.update({
                    "id": entry.name,
                    "namespace": namespace,
                    "tree_sha256": digest,
                    "file_count": len(files),
                    "bytes": size,
                    "writer_probe": _lock_probe(
                        data_root / "sessions-v2" / ".locks" / f"{entry.name}.lock"),
                })
                sessions.append(facts)
            root_facts["namespaces"][namespace] = {
                "path": str(session_root),
                "session_count": len(sessions),
                "sessions": sessions,
            }
        roots.append(root_facts)
    return {"home": str(home), "data_roots": roots}


def _session_index(inventory: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """id -> entries across every home/root/namespace with the same id."""
    index: dict[str, list[dict[str, Any]]] = {}
    for home in inventory["homes"]:
        for root in home["data_roots"]:
            for namespace, facts in root["namespaces"].items():
                for session in facts["sessions"]:
                    index.setdefault(session["id"], []).append({
                        "home": home["home"],
                        "identity": root["identity"],
                        "namespace": namespace,
                        "tree_sha256": session["tree_sha256"],
                        "state_schema": session.get("state_schema"),
                        "state_present": session.get("state_present"),
                        "writer_probe": session.get("writer_probe"),
                    })
    return index


def _conflict_summary(index: dict[str, str]) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    for session_id, entries in sorted(index.items()):
        digests = {entry["tree_sha256"] for entry in entries}
        if len(digests) <= 1:
            continue
        conflicts.append({
            "id": session_id,
            "entries": entries,
            "decision": "isolate_or_manual",
            "note": "same session id with different tree digests; timestamps "
                    "never decide, the daily environment stays untouched",
        })
    return conflicts


def cmd_inventory(args: argparse.Namespace) -> int:
    home_paths = _codex_homes(args)
    destination = _output_path(args.output, *home_paths)
    homes = [_inventory_home(home) for home in home_paths]
    inventory = {"schema": SCHEMA, "stage": "inventory", "read_only": True,
                 "platform": platform.system(), "homes": homes}
    index = _session_index(inventory)
    inventory["unique_session_ids"] = len(index)
    inventory["same_id_multiple_roots"] = sum(
        1 for entries in index.values() if len(entries) > 1)
    inventory["conflicts"] = _conflict_summary(index)
    inventory["legacy_sessions_policy"] = (
        "retain_in_place: legacy sessions stay under their original runtime; "
        "finish active legacy tasks before changing that HOME's entry")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _exclusive_json(destination, inventory)
    print(json.dumps({"unique_session_ids": inventory["unique_session_ids"],
                      "same_id_multiple_roots": inventory["same_id_multiple_roots"],
                      "conflicts": len(inventory["conflicts"]),
                      "output": str(destination)}))
    return 0


def _validate_plan_inputs(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    source_home = _absolute_real(args.source_home, "source home")
    target_home = _absolute_real(args.target_home, "target home")
    require(source_home != target_home or args.source_identity != args.target_identity,
            "source and target must differ")
    for identity in (args.source_identity, args.target_identity):
        require(isinstance(identity, str) and identity,
                "source/target identity must be named explicitly")
    require(args.target_identity == STABLE_DATA_ROOT[len(DATA_ROOT_PREFIX):],
            f"target identity must be the stable identity "
            f"{STABLE_DATA_ROOT[len(DATA_ROOT_PREFIX):]}; not another versioned identity")
    source_root = _resolve_identity_root(source_home, args.source_identity)
    target_root = _resolve_identity_root(target_home, args.target_identity)
    require(not _within(source_root, target_root) and not _within(target_root, source_root),
            "source and target data roots must be disjoint")
    return source_root, target_root, target_home


def _resolve_identity_root(home: Path, identity: str) -> Path:
    if identity == "<direct>":
        root = home / "context-guard"
    else:
        require(isinstance(identity, str) and IDENTITY_NAME.fullmatch(identity),
                "unsupported data-root identity")
        root = home / "plugins" / "data" / (DATA_ROOT_PREFIX + identity)
    require(root.is_dir() and not root.is_symlink(),
            f"data root for identity {identity} not found in {home}")
    _no_link_ancestors(root)
    return root


def _within(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _output_path(value: str, *protected: Path) -> Path:
    path = Path(value).expanduser().absolute()
    _no_link_ancestors(path)
    require(not path.exists(), "result path already exists")
    require(all(not _within(root, path) for root in (*protected, Path(__file__).resolve().parents[1])),
            "result path is inside a protected root")
    return path


def _casefold_safe(target_root: Path, name: str) -> None:
    probe = target_root / name
    _no_link_ancestors(probe)
    if any(entry.name != name and entry.name.casefold() == name.casefold()
           for entry in target_root.iterdir()):
        raise MigrationError(f"case-only sibling collision for {name}")


def cmd_plan(args: argparse.Namespace) -> int:
    source_root, target_root, target_home = _validate_plan_inputs(args)
    include = set(args.include or [])
    sessions: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    source_session_root = source_root / "sessions-v2"
    require(source_session_root.is_dir(),
            "source identity has no sessions-v2 namespace; legacy trees are "
            "never migrated (retain_in_place under the original runtime)")
    target_session_root = target_root / "sessions-v2"
    _no_link_ancestors(source_session_root)
    _no_link_ancestors(target_session_root)
    for entry in sorted(source_session_root.iterdir()):
        if entry.name in EXCLUDED_SESSION_NAMES or not entry.is_dir():
            continue
        if entry.is_symlink():
            # Linked entries are never followed; the plan records the anomaly
            # so the scope narrowing stays visible instead of silent.
            sessions.append({"id": entry.name, "source": str(entry),
                             "decision": "excluded_symlink",
                             "note": "symlink or reparse entry; never followed"})
            continue
        if include and entry.name not in include:
            continue
        digest, size, files = _tree_digest(entry)
        facts = _session_identity(entry)
        schema = facts.get("state_schema")
        row: dict[str, Any] = {
            "id": entry.name,
            "source": str(entry),
            "tree_sha256": digest,
            "bytes": size,
            "file_count": len(files),
            "state_schema": schema,
        }
        if facts.get("state_present") and facts.get("state_readable") is not False:
            schema_ok = schema in SUPPORTED_SCHEMAS
            row["schema_supported"] = schema_ok
        else:
            row["schema_supported"] = False
            row["note"] = "missing or unreadable state.json; not migrated by default"
        target_entry = target_session_root / entry.name
        _no_link_ancestors(target_entry)
        if not row["schema_supported"]:
            row["decision"] = "excluded_unsupported_state"
        elif target_session_root.is_dir() and target_entry.exists():
            target_digest, _, _ = _tree_digest(target_entry)
            if target_digest == digest:
                row["decision"] = "idempotent_skip"
            else:
                row["decision"] = "isolate"
                conflicts.append({
                    "id": entry.name,
                    "source_tree_sha256": digest,
                    "target_tree_sha256": target_digest,
                    "decision": "isolate_outside_data_root",
                })
        else:
            row["decision"] = "copy"
        sessions.append(row)
    legacy_root = source_root / "sessions"
    legacy_count = 0
    if legacy_root.is_dir():
        legacy_count = sum(1 for entry in legacy_root.iterdir()
                           if entry.is_dir() and not entry.is_symlink()
                           and entry.name not in EXCLUDED_SESSION_NAMES)
    plan = {
        "schema": PLAN_SCHEMA,
        "source_identity": args.source_identity,
        "source_home": str(Path(args.source_home).expanduser().resolve(strict=True)),
        "target_home": str(target_home),
        "target_identity": args.target_identity,
        "source_data_root": str(source_root),
        "target_data_root": str(target_root),
        "conflict_policy": args.conflict_policy,
        "scope": "sessions-v2 only; legacy sessions are retain_in_place",
        "legacy_session_count": legacy_count,
        "sessions": sessions,
        "conflicts": conflicts,
        "rule": "same id + same digest is idempotent; same id + different "
                "digest is isolated outside the data root; timestamps never "
                "overwrite; no new completion facts are created",
    }
    destination = _output_path(args.output, source_root, target_root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _exclusive_json(destination, plan)
    counts: dict[str, int] = {}
    for row in sessions:
        counts[row["decision"]] = counts.get(row["decision"], 0) + 1
    print(json.dumps({"copy": counts.get("copy", 0),
                      "idempotent_skip": counts.get("idempotent_skip", 0),
                      "isolate": counts.get("isolate", 0),
                      "excluded_unsupported_state": counts.get("excluded_unsupported_state", 0),
                      "legacy_retained": legacy_count,
                      "plan": str(destination)}))
    return 0


def _copy_tree(source: Path, target: Path) -> list[str]:
    """Fill an owned directory and return the copied relative paths."""
    created = ["."]
    for base, dirnames, filenames in os.walk(source):
        dirnames[:] = sorted(dirnames)
        relative_base = Path(base).relative_to(source)
        for dirname in sorted(dirnames):
            (target / relative_base / dirname).mkdir(mode=0o700)
        for filename in sorted(filenames):
            source_file = Path(base) / filename
            _no_link_ancestors(source_file)
            require(source_file.is_file() and source_file.stat().st_nlink == 1,
                    f"unsupported session source: {filename}")
            target_file = target / relative_base / filename
            descriptor = os.open(target_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as sink, source_file.open("rb") as reader:
                shutil.copyfileobj(reader, sink, 1024 * 1024)
            created.append((target_file.relative_to(target)).as_posix())
    return created


def _directory_identity(path: Path) -> list[int]:
    _no_link_ancestors(path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_ino, "session directory identity unavailable")
    return [info.st_dev, info.st_ino]


def _copy_tree_exclusive(source: Path, target: Path, expected: str) -> dict[str, Any]:
    """Remove a partial copy only when this call exclusively created its inode."""
    target.mkdir(mode=0o700)
    identity = _directory_identity(target)
    try:
        _protect_created_directory(target)
        created = _copy_tree(source, target)
        require(_tree_digest(target)[0] == expected, "copied digest differs")
        require(_directory_identity(target) == identity, "copy directory replaced")
    except BaseException:
        if _directory_identity(target) == identity:
            shutil.rmtree(target)
        raise
    return {"path": str(target), "tree_sha256": expected, "created": created,
            "directory_identity": identity}


def _validate_session_name(value: Any) -> None:
    require(isinstance(value, str) and SESSION_NAME.fullmatch(value)
            and value.casefold() not in {".", "..", ".locks"}
            and not _windows_reserved(value),
            "unsupported session directory name")


def _windows_reserved(value: str) -> bool:
    if hasattr(ntpath, "isreserved"):
        return ntpath.isreserved(value)
    return value.endswith(".") or PureWindowsPath(value).is_reserved()


def _check_apply_plan(plan_path: Path) -> dict[str, Any]:
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MigrationError(f"plan unreadable: {type(exc).__name__}") from exc
    require(isinstance(plan, dict) and plan.get("schema") == PLAN_SCHEMA,
            "plan schema mismatch")
    require(plan.get("conflict_policy") in ("isolate", "skip"),
            "conflict policy must be isolate or skip")
    require(isinstance(plan.get("sessions"), list), "plan sessions missing")
    source, target, _ = _validate_plan_inputs(argparse.Namespace(**{
        key: plan.get(key) for key in ("source_home", "source_identity", "target_home", "target_identity")
    }))
    require(str(source) == plan.get("source_data_root") and str(target) == plan.get("target_data_root"),
            "plan data roots differ from the declared HOME and identity")
    names: set[str] = set()
    for row in plan["sessions"]:
        require(isinstance(row, dict), "plan session row is invalid")
        name = row.get("id")
        _validate_session_name(name)
        require(name.casefold() not in names, "duplicate or case-alias session in plan")
        names.add(name.casefold())
        require(row.get("source") == str(source / "sessions-v2" / name), "plan session source differs")
        decision = row.get("decision")
        require(isinstance(decision, str) and decision in {"copy", "isolate", "idempotent_skip",
                             "excluded_unsupported_state", "excluded_symlink"}, "invalid migration decision")
        if decision in {"copy", "isolate", "idempotent_skip"}:
            require(_sha(row.get("tree_sha256")), "plan session digest is invalid")
    return plan


def _apply_copy_row(row: dict[str, Any], source_entry: Path,
                    target_session_root: Path, lock_path: Path, deadline: float,
                    manifest: dict[str, Any]) -> None:
    """Copy one planned session into the target under its lifecycle lock."""
    with _LifecycleLock(lock_path, deadline) as lock:
        _casefold_safe(target_session_root, row["id"])
        target_entry = target_session_root / row["id"]
        if target_entry.exists():
            existing = _tree_digest(target_entry)[0]
            if existing == row["tree_sha256"]:
                manifest["skipped"].append(
                    {"id": row["id"], "reason": "target identical"})
                return
            raise MigrationError(
                "target session appeared with different content during apply; "
                f"isolated decisions only: {row['id']}")
        admission_dir = lock_path.parent / ".identity"
        _no_link_ancestors(admission_dir)
        admission_dir.mkdir(mode=0o700, exist_ok=True)
        admission = admission_dir / f"{row['id'].casefold()}.lock"
        with _LifecycleLock(admission, deadline):
            _casefold_safe(target_session_root, row["id"])
            legacy = target_session_root.parent / "sessions"
            quarantine = lock_path.parent / "retention-quarantine"
            for directory in (legacy, quarantine):
                _no_link_ancestors(directory)
            name = row["id"].casefold()
            require(not legacy.is_dir() or all(item.name.casefold() != name for item in legacy.iterdir()),
                    "target has a legacy session with this identity")
            require(not quarantine.is_dir() or all(not item.name.casefold().startswith(name + ".")
                    for item in quarantine.iterdir()), "target has retention history for this identity")
            receipt = _copy_tree_exclusive(source_entry, target_entry, row["tree_sha256"])
            manifest["created"].append({"id": row["id"], **receipt})
            lock.verify()


def _apply_session(row: dict[str, Any], source_root: Path, target_root: Path,
                   workspace: Path, policy: str, manifest: dict[str, Any]) -> None:
    name, decision = row["id"], row["decision"]
    if decision not in {"copy", "idempotent_skip", "isolate"} or (decision == "isolate" and policy == "skip"):
        manifest["skipped"].append({"id": name, "reason": decision})
        return
    source_entry = source_root / name
    deadline = time.monotonic() + LOCK_DEADLINE_SECONDS
    with _LifecycleLock(source_root / ".locks" / f"{name}.lock", deadline, create=False) as source_lock:
        require(_tree_digest(source_entry)[0] == row["tree_sha256"], "source changed since plan; rerun plan")
        require(_session_identity(source_entry).get("state_schema") in SUPPORTED_SCHEMAS,
                "source state schema cannot be migrated")
        source_lock.verify()
        if decision == "isolate":
            destination = workspace / "conflicts" / name
            destination.parent.mkdir(mode=0o700, exist_ok=True)
            copied = _copy_tree_exclusive(source_entry, destination, row["tree_sha256"])
            manifest["isolated"].append({"id": name, **copied})
        else:
            lock_dir = target_root / ".locks"
            _no_link_ancestors(lock_dir)
            lock_dir.mkdir(mode=0o700, exist_ok=True)
            lock = lock_dir / f"{name}.lock"
            if decision == "idempotent_skip":
                with _LifecycleLock(lock, deadline, create=False):
                    require(_tree_digest(target_root / name)[0] == row["tree_sha256"],
                            "target changed since plan; rerun plan")
                    manifest["skipped"].append({"id": name, "reason": "same digest"})
            else:
                _apply_copy_row(row, source_entry, target_root, lock, deadline, manifest)


def _persist_apply_result(path: Path, manifest: dict[str, Any]) -> None:
    temporary = path.with_suffix(".next")
    _exclusive_json(temporary, manifest)
    os.replace(temporary, path)


def cmd_apply(args: argparse.Namespace) -> int:
    plan_path = _absolute_real(args.plan, "plan", file=True)
    plan = _check_apply_plan(plan_path)
    source_root = Path(plan["source_data_root"])
    target_root = Path(plan["target_data_root"])
    source_sessions = source_root / "sessions-v2"
    target_sessions = target_root / "sessions-v2"
    _no_link_ancestors(source_sessions)
    _no_link_ancestors(target_sessions)
    workspace = _new_directory(args.workspace, "workspace", source_root, target_root,
                               Path(__file__).resolve().parents[1])
    result_path = workspace / "apply-manifest.json"
    manifest: dict[str, Any] = {
        "schema": SCHEMA, "stage": "apply", "plan": str(plan_path),
        "plan_sha256": _digest_file(plan_path), "workspace": str(workspace),
        "status": "running", "in_progress": None,
        "created": [], "skipped": [], "isolated": [], "failed": [],
    }
    _exclusive_json(result_path, manifest)
    target_sessions.mkdir(mode=0o700, exist_ok=True)
    for row in plan["sessions"]:
        manifest["in_progress"] = row["id"]
        _persist_apply_result(result_path, manifest)
        try:
            _apply_session(row, source_sessions, target_sessions, workspace, plan["conflict_policy"], manifest)
        except (MigrationError, OSError) as exc:
            manifest["failed"].append({"id": row["id"], "reason": str(exc)})
        except KeyboardInterrupt:
            manifest["failed"].append({"id": row["id"], "reason": "interrupted"})
            manifest.update(status="interrupted", in_progress=None)
            _persist_apply_result(result_path, manifest)
            return 1
        manifest["in_progress"] = None
        _persist_apply_result(result_path, manifest)
    manifest.update(status="failed" if manifest["failed"] else "applied", finished_at_epoch=time.time())
    _persist_apply_result(result_path, manifest)
    # r1 D3b control: the operation is COMPLETE and durably recorded here;
    # a summary construction failure is recorded as a fact and never
    # rolls back, never re-applies, and never changes the exit code (which
    # derives from the structured manifest state only).
    try:
        summary = {"created": len(manifest["created"]),
                   "skipped": len(manifest["skipped"]),
                   "isolated": len(manifest["isolated"]),
                   "failed": len(manifest["failed"]),
                   "workspace": str(workspace)}
        print(json.dumps(summary))
    except (KeyError, TypeError, ValueError) as exc:
        # Building OR serializing the run summary failed after the
        # operation completed: record the fact, print a bounded fallback,
        # and leave the exit code to the structured manifest state. Never
        # a rollback, never a re-apply.
        manifest["summary_unavailable"] = type(exc).__name__
        _persist_apply_result(result_path, manifest)
        print(json.dumps({"summary_unavailable": manifest["summary_unavailable"],
                          "workspace": str(workspace)}))
    return 0 if not manifest["failed"] else 1


def _export_summary(workspace: Path) -> tuple[dict, list[Path]]:
    """Re-read/export the operation summary from the persisted structured
    artifacts ONLY (apply-manifest.json, verify-result.json): the repair
    path for a lost or unreadable run summary. Read-only -- never rolls
    back, never re-applies, never restores, never touches a data root.

    Everything reported binds the CURRENT plan/apply/workspace/objects
    (r1 B3): the apply manifest goes through the same checked-manifest
    validation as verify (so a truncated or unbound file -- e.g. missing
    the ``created`` group -- is refused instead of silently exporting
    zeros); a verify result without the binding triple (workspace, plan
    digest, apply-manifest digest) is reported as the historical snapshot
    it is (``historical_unbound``), never as the current state; a bound
    verify result is re-checked read-only against the CURRENT copies, so
    a target changed after verify is reported ``stale`` with the changed
    rows named. Returns (summary, protected_roots) where the protected
    roots are the plan's data roots that an export output path must never
    enter.
    """
    manifest = _checked_manifest(workspace)
    plan_path = _absolute_real(manifest.get("plan"), "apply plan", file=True)
    plan = _check_apply_plan(plan_path)
    protected = [Path(plan["source_data_root"]).resolve(strict=True),
                 Path(plan["target_data_root"]).resolve(strict=True)]
    exported = {
        "schema": "cg-guard-state-summary/v1",
        "workspace": str(workspace),
        "plan_sha256": manifest.get("plan_sha256"),
        "apply_status": manifest.get("status"),
        "created": len(manifest.get("created") or []),
        "skipped": len(manifest.get("skipped") or []),
        "isolated": len(manifest.get("isolated") or []),
        "failed": len(manifest.get("failed") or []),
        "summary_unavailable": manifest.get("summary_unavailable"),
    }
    verify_path = workspace / "verify-result.json"
    if verify_path.is_symlink() or not verify_path.is_file():
        exported["verify_status"] = "not_verified"
        return exported, protected
    try:
        verify = json.loads(verify_path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        verify = None
    bound = (isinstance(verify, dict) and verify.get("schema") == SCHEMA
             and verify.get("stage") == "verify"
             and verify.get("workspace") == str(workspace)
             and verify.get("plan_sha256") == manifest.get("plan_sha256")
             and verify.get("apply_manifest_sha256")
             == _digest_file(workspace / "apply-manifest.json"))
    if not bound:
        # A verify file that cannot prove it belongs to THIS workspace,
        # plan and apply transaction is history, not current state.
        exported["verify_status"] = "historical_unbound"
        return exported, protected
    stale: list[dict[str, str]] = []
    for row in manifest["created"] + manifest["isolated"]:
        try:
            _check_recorded_copy(row, Path(row["path"]))
        except (MigrationError, OSError) as exc:
            stale.append({"id": row.get("id"), "reason": str(exc)})
    if stale:
        exported["verify_status"] = "stale"
        exported["verify_stale"] = stale
    else:
        exported["verify_status"] = verify.get("status")
        exported["verify_problems"] = len(verify.get("problems") or [])
    return exported, protected


def cmd_summary(args: argparse.Namespace) -> int:
    workspace = _absolute_real(args.workspace, "workspace")
    exported, protected = _export_summary(workspace)
    print(json.dumps(exported))
    if args.out:
        # A NEW export file. Refusals come BEFORE any creation: an
        # existing object is never replaced, a link (including a dangling
        # symlink pointing into a data root) is never followed, and the
        # target may not live inside a protected data root. Creation is
        # exclusive with no handle left open.
        raw = Path(args.out)
        require(not raw.is_symlink() and not raw.exists(),
                "summary output already exists or is a link; exports never replace")
        resolved = raw.resolve(strict=False)
        for root in protected:
            require(root != resolved and not _within(resolved, root)
                    and not _within(root, resolved),
                    "summary output must stay outside the protected data roots")
        _no_link_ancestors(resolved.parent)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        require(not resolved.exists() and not resolved.is_symlink(),
                "summary output appeared during export; exports never replace")
        fd = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, (json.dumps(exported, indent=2) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    return 0


def _checked_manifest(workspace: Path, plan_path: Path | None = None) -> dict[str, Any]:
    manifest_path = _absolute_real(str(workspace / "apply-manifest.json"), "apply manifest", file=True)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MigrationError("apply manifest unreadable") from exc
    require(isinstance(manifest, dict) and manifest.get("schema") == SCHEMA
            and manifest.get("stage") == "apply" and manifest.get("workspace") == str(workspace)
            and manifest.get("status") in ("running", "interrupted", "failed", "applied"),
            "apply manifest does not bind this workspace")
    original_plan = _absolute_real(manifest.get("plan"), "apply plan", file=True)
    require(plan_path is None or original_plan == plan_path, "verify requires the original apply plan")
    require(_digest_file(original_plan) == manifest.get("plan_sha256"), "apply plan changed")
    plan = _check_apply_plan(original_plan)
    source, target = (Path(plan[key]) for key in ("source_data_root", "target_data_root"))
    require(all(not _within(root, workspace) and not _within(workspace, root) for root in (source, target)),
            "apply workspace overlaps a data root")
    expected = {row["id"]: row for row in plan["sessions"]}
    in_progress = manifest.get("in_progress")
    require("in_progress" in manifest and
            (in_progress is None or isinstance(in_progress, str) and in_progress in expected),
            "unexpected in-progress session")
    seen: set[str] = set()
    for group, decision, parent in (("created", "copy", target / "sessions-v2"),
                                    ("isolated", "isolate", workspace / "conflicts")):
        require(isinstance(manifest.get(group), list), "apply manifest rows missing")
        for row in manifest[group]:
            require(isinstance(row, dict), "apply manifest row invalid")
            name = row.get("id")
            _validate_session_name(name)
            planned = expected.get(name, {})
            identity = row.get("directory_identity")
            require(name not in seen and planned.get("decision") == decision
                    and row.get("path") == str(parent / name)
                    and row.get("tree_sha256") == planned.get("tree_sha256")
                    and isinstance(identity, list) and len(identity) == 2
                    and all(type(value) is int and value >= 0 for value in identity)
                    and identity[1] != 0, "apply manifest row differs from the plan")
            seen.add(name)
    return manifest


def _check_recorded_copy(row: dict[str, Any], path: Path) -> None:
    require(_directory_identity(path) == row["directory_identity"], "copied directory replaced")
    require(_tree_digest(path)[0] == row["tree_sha256"], "copied directory contents changed")


def cmd_verify(args: argparse.Namespace) -> int:
    plan_path = _absolute_real(args.plan, "plan", file=True)
    workspace = _absolute_real(args.workspace, "workspace")
    manifest = _checked_manifest(workspace, plan_path)
    problems: list[dict[str, str]] = []
    if manifest["status"] != "applied":
        problems.append({"reason": "apply did not complete every planned row"})
    for row in manifest["created"] + manifest["isolated"]:
        try:
            _check_recorded_copy(row, Path(row["path"]))
        except (MigrationError, OSError) as exc:
            problems.append({"id": row["id"], "reason": str(exc)})
    result = {
        "schema": SCHEMA, "stage": "verify",
        # Binding facts (r1 B3): a verify result that does not bind THIS
        # workspace, plan and apply manifest is a historical snapshot and
        # is never presented as the current state by the summary export.
        "workspace": str(workspace),
        "plan_sha256": _digest_file(plan_path),
        "apply_manifest_sha256": _digest_file(workspace / "apply-manifest.json"),
        "created": len(manifest["created"]),
        "isolated": len(manifest["isolated"]),
        "problems": problems,
        "status": "verified" if not problems else "problems",
    }
    _supersede_then_write(workspace / "verify-result.json", result)
    try:
        printed = {"status": result["status"], "problems": len(problems)}
        print(json.dumps(printed))
    except (KeyError, TypeError, ValueError) as exc:
        result["summary_unavailable"] = type(exc).__name__
        _supersede_then_write(workspace / "verify-result.json", result)
        print(json.dumps({"summary_unavailable":
                          result["summary_unavailable"]}))
    return 0 if not problems else 1


def cmd_restore(args: argparse.Namespace) -> int:
    """Undo exactly this migration's recorded writes."""
    workspace = _absolute_real(args.workspace, "workspace")
    manifest = _checked_manifest(workspace)
    removed, refused = [], []
    if manifest["in_progress"] is not None:
        refused.append({"id": manifest["in_progress"], "reason": "interrupted row needs independent review"})
    for row in manifest["created"] + manifest["isolated"]:
        path = Path(row["path"])
        try:
            _no_link_ancestors(path)
            if not path.exists():
                removed.append({"id": row["id"], "already_absent": True})
                continue
            if path.is_relative_to(workspace):
                lock = contextlib.nullcontext()
            else:
                lock = _LifecycleLock(path.parent / ".locks" / f"{path.name}.lock",
                                      time.monotonic() + LOCK_DEADLINE_SECONDS, create=False)
            with lock:
                _check_recorded_copy(row, path)
                shutil.rmtree(path)
            removed.append({"id": row["id"]})
        except (MigrationError, OSError) as exc:
            refused.append({"id": row["id"], "reason": str(exc)})
    result = {"schema": SCHEMA, "stage": "restore",
              "removed": removed, "refused": refused,
              "status": "restored" if not refused else "partial_refused"}
    _supersede_then_write(workspace / "restore-result.json", result)
    print(json.dumps({"removed": len(removed), "refused": len(refused),
                      "status": result["status"]}))
    return 0 if not refused else 1


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Guard private-state inventory, migration and recovery; "
                    "read-only by default, apply is explicit and copy-only")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory = subparsers.add_parser(
        "inventory", help="read-only inventory of one or more explicit homes")
    inventory.add_argument("--home", action="append", required=True,
                           help="explicit Codex HOME; repeatable; no default")
    inventory.add_argument("--output", required=True,
                           help="new JSON output path outside the repository")
    inventory.set_defaults(func=cmd_inventory)

    plan = subparsers.add_parser(
        "plan", help="build an explicit migration plan; no writes to state")
    plan.add_argument("--source-home", required=True)
    plan.add_argument("--source-identity", required=True,
                      help="data-root identity under plugins/data, or <direct>")
    plan.add_argument("--target-home", required=True)
    plan.add_argument("--target-identity", required=True)
    plan.add_argument("--include", action="append",
                      help="restrict to these session ids; default all eligible")
    plan.add_argument("--conflict-policy", choices=("isolate", "skip"),
                      default="isolate")
    plan.add_argument("--output", required=True)
    plan.set_defaults(func=cmd_plan)

    apply_parser = subparsers.add_parser(
        "apply", help="execute a plan copy-only into a new workspace manifest")
    apply_parser.add_argument("--plan", required=True)
    apply_parser.add_argument("--workspace", required=True,
                              help="new directory outside the data roots")
    apply_parser.set_defaults(func=cmd_apply)

    verify = subparsers.add_parser(
        "verify", help="re-derive digests of created and isolated copies")
    verify.add_argument("--plan", required=True)
    verify.add_argument("--workspace", required=True)
    verify.set_defaults(func=cmd_verify)

    summary = subparsers.add_parser(
        "summary",
        help="re-read/export the operation summary from the persisted "
             "structured artifacts (read-only; the repair path for a lost "
             "run summary -- never a rollback)")
    summary.add_argument("--workspace", required=True)
    summary.add_argument("--out", default=None,
                         help="write the exported summary to this new file")
    summary.set_defaults(func=cmd_summary)
    restore = subparsers.add_parser(
        "restore", help="remove exactly this migration's created paths")
    restore.add_argument("--workspace", required=True)
    restore.set_defaults(func=cmd_restore)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except MigrationError as exc:
        print(f"guard_state_migration=refused; {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"guard_state_migration=failed; {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
