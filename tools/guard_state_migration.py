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
counts; prompt and requirement text is never read or emitted.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any

SCHEMA = "cg-guard-state-migration/v1"
PLAN_SCHEMA = "cg-guard-state-migration-plan/v1"
STABLE_DATA_ROOT = "context-guard-codex-context-guard"
DATA_ROOT_PREFIX = "context-guard-"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UUID_SHAPE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
                        r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\Z")
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
    for parent in (current, *current.parents):
        if parent.is_symlink():
            raise MigrationError(f"link ancestor refused: {parent}")


def _absolute_real(value: Any, name: str, *, file: bool = False) -> Path:
    require(isinstance(value, str) and value, f"{name} must be a path string")
    path = Path(value).expanduser()
    try:
        path = path.resolve(strict=True)
    except OSError as exc:
        raise MigrationError(f"{name} is not an existing real path: {value}") from exc
    if file and not path.is_file():
        raise MigrationError(f"{name} must be an existing file")
    _no_link_ancestors(path)
    return path


def _new_directory(value: Any, name: str) -> Path:
    require(isinstance(value, str) and value, f"{name} must be a path string")
    path = Path(value).expanduser().absolute()
    if path.exists() or path.is_symlink():
        raise MigrationError(f"{name} must be a new path: {path}")
    _no_link_ancestors(path.parent)
    path.mkdir(parents=True)
    return path


def _exclusive_json(path: Path, payload: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise MigrationError(f"result path already exists: {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


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
    entries: dict[str, str] = {}
    bytes_total = 0
    for base, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(dirnames)
        for filename in sorted(filenames):
            path = Path(base) / filename
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or not path.is_file():
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
        facts["state_schema"] = payload.get("schema")
        for key in ("session_id", "id", "session"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                facts["state_session_id"] = value
                break
        facts["state_top_level_keys"] = sorted(str(k) for k in payload)
    return facts


def _lock_probe(lock_path: Path) -> str:
    """Non-blocking writer probe on the lifecycle lock; no data writes."""
    if not lock_path.is_file():
        return "absent"
    try:
        descriptor = os.open(lock_path, os.O_RDONLY)
    except OSError:
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

    def __init__(self, lock_path: Path, deadline: float) -> None:
        self._path = lock_path
        self._deadline = deadline
        self._descriptor: int | None = None

    def __enter__(self) -> "_LifecycleLock":
        while True:
            try:
                self._descriptor = os.open(self._path,
                                           os.O_RDWR | os.O_CREAT, 0o600)
            except OSError as exc:
                raise MigrationError(f"lifecycle lock unavailable: {self._path}") from exc
            try:
                _flock_nonblocking(self._descriptor)
                return self
            except OSError:
                os.close(self._descriptor)
                self._descriptor = None
                if time.monotonic() >= self._deadline:
                    raise MigrationError(
                        f"session writer still active past deadline: {self._path}")
                time.sleep(0.2)

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
    if cache.is_dir():
        for market_dir in sorted(cache.iterdir()):
            plugin_dir = market_dir / "context-guard"
            if plugin_dir.is_dir():
                versions = sorted(entry.name for entry in plugin_dir.iterdir()
                                  if entry.is_dir())
                if versions:
                    installed_versions[market_dir.name] = versions[-1]
    roots: list[dict[str, Any]] = []
    for identity, data_root in _data_roots(home).items():
        root_facts: dict[str, Any] = {
            "identity": identity,
            "path": str(data_root),
            "installed_version_observation": installed_versions.get(identity),
            "namespaces": {},
        }
        for namespace, session_root in _session_roots(data_root).items():
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
    homes = [_inventory_home(home) for home in _codex_homes(args)]
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
    destination = Path(args.output).expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise MigrationError(f"output must be a new path: {destination}")
    _no_link_ancestors(destination.parent)
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


def _casefold_safe(target_root: Path, name: str) -> None:
    probe = target_root / name
    if probe.exists():
        return
    folded = {entry.name.casefold() for entry in target_root.iterdir()}
    if name.casefold() in folded:
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
        if target_session_root.is_dir() and target_entry.exists():
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
        elif not row["schema_supported"]:
            row["decision"] = "excluded_unsupported_state"
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
    destination = Path(args.output).expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise MigrationError(f"plan output must be a new path: {destination}")
    _no_link_ancestors(destination.parent)
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


def _copy_tree_exclusive(source: Path, target: Path) -> list[str]:
    """Create target exclusively; copy byte-exact; return created relative paths."""
    created: list[str] = []
    target.mkdir(mode=0o700)
    created.append(".")
    for base, dirnames, filenames in os.walk(source):
        dirnames[:] = sorted(dirnames)
        relative_base = Path(base).relative_to(source)
        for dirname in sorted(dirnames):
            (target / relative_base / dirname).mkdir(mode=0o700)
        for filename in sorted(filenames):
            source_file = Path(base) / filename
            if source_file.is_symlink():
                raise MigrationError(f"symlink refused in session source: {filename}")
            target_file = target / relative_base / filename
            descriptor = os.open(target_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as sink, source_file.open("rb") as reader:
                shutil.copyfileobj(reader, sink, 1024 * 1024)
            created.append((target_file.relative_to(target)).as_posix())
    return created


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
    return plan


def _apply_copy_row(row: dict[str, Any], source_entry: Path,
                    target_session_root: Path, lock_path: Path, deadline: float,
                    manifest: dict[str, Any]) -> None:
    """Copy one planned session into the target under its lifecycle lock."""
    with _LifecycleLock(lock_path, deadline):
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
        created = _copy_tree_exclusive(source_entry, target_entry)
        copied_digest = _tree_digest(target_entry)[0]
        if copied_digest != row["tree_sha256"]:
            raise MigrationError("copied digest differs; failing closed")
    manifest["created"].append({
        "id": row["id"], "path": str(target_entry),
        "tree_sha256": copied_digest, "created": created,
    })


def _discard_partial_target(target_entry: Path) -> None:
    """Remove only a partially copied target created by this failing attempt.

    The apply path creates target sessions exclusively while holding the
    lifecycle lock, so a directory present after a failed copy is this run's
    own partial work; anything a concurrent writer could have produced is
    refused before any copy starts.
    """
    if target_entry.is_dir() and not target_entry.is_symlink():
        with contextlib.suppress(OSError):
            shutil.rmtree(target_entry)


def cmd_apply(args: argparse.Namespace) -> int:
    plan_path = _absolute_real(args.plan, "plan", file=True)
    plan = _check_apply_plan(plan_path)
    workspace = _new_directory(args.workspace, "workspace")
    source_root = Path(plan["source_data_root"])
    target_root = Path(plan["target_data_root"])
    _no_link_ancestors(source_root)
    _no_link_ancestors(target_root)
    require(source_root.is_dir() and target_root.is_dir(),
            "plan data roots must both exist before apply")
    manifest: dict[str, Any] = {
        "schema": SCHEMA, "stage": "apply", "plan": str(plan_path),
        "workspace": str(workspace),
        "created": [], "skipped": [], "isolated": [], "failed": [],
    }
    deadline = time.monotonic() + LOCK_DEADLINE_SECONDS
    target_session_root = target_root / "sessions-v2"
    target_session_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for row in plan["sessions"]:
        decision = row["decision"]
        if decision == "idempotent_skip":
            manifest["skipped"].append({"id": row["id"], "reason": "same digest"})
            continue
        if decision != "copy":
            try:
                if decision == "isolate" and plan["conflict_policy"] == "isolate":
                    conflicts_dir = workspace / "conflicts" / row["id"]
                    conflicts_dir.parent.mkdir(parents=True, exist_ok=True)
                    if conflicts_dir.exists():
                        manifest["failed"].append(
                            {"id": row["id"], "reason": "conflict copy path exists"})
                        continue
                    created = _copy_tree_exclusive(
                        source_root / "sessions-v2" / row["id"], conflicts_dir)
                    digest = _tree_digest(conflicts_dir)[0]
                    manifest["isolated"].append({
                        "id": row["id"], "path": str(conflicts_dir),
                        "tree_sha256": digest,
                        "expected_tree_sha256": row["tree_sha256"],
                        "created": created,
                    })
                    if digest != row["tree_sha256"]:
                        manifest["failed"].append(
                            {"id": row["id"], "reason": "isolated copy digest differs"})
                else:
                    manifest["skipped"].append({"id": row["id"], "reason": decision})
            except (MigrationError, OSError) as exc:
                conflicts_dir = workspace / "conflicts" / row["id"]
                if conflicts_dir.is_dir() and not conflicts_dir.is_symlink():
                    with contextlib.suppress(OSError):
                        shutil.rmtree(conflicts_dir)
                manifest["failed"].append(
                    {"id": row["id"], "reason": str(exc)})
            continue
        # Controlled write window: hold the source lifecycle read window and
        # the target lifecycle lock before the session directory exists,
        # mirroring the runtime's own lifecycle-before-admission ordering.
        lock_path = target_root / "sessions-v2" / ".locks" / f"{row['id']}.lock"
        lock_path.parent.mkdir(mode=0o700, exist_ok=lock_path.parent.is_dir())
        source_lock = source_root / "sessions-v2" / ".locks" / f"{row['id']}.lock"
        source_entry = source_root / "sessions-v2" / row["id"]
        try:
            digest_now = _tree_digest(source_entry)[0]
            require(digest_now == row["tree_sha256"],
                    "source changed since plan; rerun plan")
            source_descriptor = None
            if source_lock.is_file():
                # An existing source lock file means a runtime writer may hold
                # it; a busy lock fails the row instead of copying torn state.
                source_descriptor = os.open(source_lock, os.O_RDONLY)
                try:
                    _flock_nonblocking(source_descriptor)
                except OSError:
                    raise MigrationError(
                        f"source writer still active: {source_lock}")
            try:
                _apply_copy_row(row, source_entry, target_session_root, lock_path,
                                deadline, manifest)
            finally:
                if source_descriptor is not None:
                    with contextlib.suppress(OSError, ValueError):
                        _funlock(source_descriptor)
                    with contextlib.suppress(OSError):
                        os.close(source_descriptor)
        except MigrationError as exc:
            _discard_partial_target(target_session_root / row["id"])
            manifest["failed"].append({"id": row["id"], "reason": str(exc)})
        except OSError as exc:
            _discard_partial_target(target_session_root / row["id"])
            manifest["failed"].append(
                {"id": row["id"], "reason": f"oserror: {exc}"})
    manifest["finished_at_epoch"] = time.time()
    _exclusive_json(workspace / "apply-manifest.json", manifest)
    print(json.dumps({"created": len(manifest["created"]),
                      "skipped": len(manifest["skipped"]),
                      "isolated": len(manifest["isolated"]),
                      "failed": len(manifest["failed"]),
                      "workspace": str(workspace)}))
    return 0 if not manifest["failed"] else 1


def cmd_verify(args: argparse.Namespace) -> int:
    plan_path = _absolute_real(args.plan, "plan", file=True)
    plan = _check_apply_plan(plan_path)
    workspace = _absolute_real(args.workspace, "workspace")
    manifest_path = workspace / "apply-manifest.json"
    require(manifest_path.is_file(), "apply manifest missing; nothing to verify")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = {row["id"]: row["tree_sha256"] for row in plan["sessions"]}
    problems: list[dict[str, str]] = []
    for row in manifest["created"]:
        path = Path(row["path"])
        if not path.is_dir():
            problems.append({"id": row["id"], "reason": "created session missing"})
            continue
        digest = _tree_digest(path)[0]
        if digest != row["tree_sha256"] or expected.get(row["id"]) != row["tree_sha256"]:
            problems.append({"id": row["id"], "reason": "digest mismatch"})
    for row in manifest["isolated"]:
        path = Path(row["path"])
        if not path.is_dir() or _tree_digest(path)[0] != row["tree_sha256"]:
            problems.append({"id": row["id"], "reason": "isolated copy mismatch"})
    result = {
        "schema": SCHEMA, "stage": "verify",
        "created": len(manifest["created"]),
        "isolated": len(manifest["isolated"]),
        "problems": problems,
        "status": "verified" if not problems else "problems",
    }
    _supersede_then_write(workspace / "verify-result.json", result)
    print(json.dumps({"status": result["status"], "problems": len(problems)}))
    return 0 if not problems else 1


def cmd_restore(args: argparse.Namespace) -> int:
    """Undo exactly this migration's writes; never touch anything else."""
    workspace = _absolute_real(args.workspace, "workspace")
    manifest_path = workspace / "apply-manifest.json"
    require(manifest_path.is_file(), "apply manifest missing; nothing to restore")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    removed, refused = [], []
    for row in manifest["created"]:
        path = Path(row["path"])
        try:
            if not path.exists() and not path.is_symlink():
                removed.append({"id": row["id"], "already_absent": True})
                continue
            digest = _tree_digest(path)[0]
            if digest != row["tree_sha256"]:
                refused.append({"id": row["id"],
                                "reason": "target changed after apply; not removed"})
                continue
            shutil.rmtree(path)
            removed.append({"id": row["id"]})
        except OSError as exc:
            refused.append({"id": row["id"], "reason": f"oserror: {exc}"})
    for row in manifest["isolated"]:
        path = Path(row["path"])
        try:
            if not path.exists():
                continue
            if _tree_digest(path)[0] != row["tree_sha256"]:
                refused.append({"id": row["id"],
                                "reason": "conflict copy changed; not removed"})
                continue
            shutil.rmtree(path)
            removed.append({"id": row["id"], "conflict": True})
        except OSError as exc:
            refused.append({"id": row["id"], "reason": f"oserror: {exc}"})
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
