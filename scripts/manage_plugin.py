#!/usr/bin/env python3
"""Safely register, install, and check the repo-local Context Guard plugin."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

MARKETPLACE = "codex-context-guard"
PLUGIN_NAME = "context-guard"
PLUGIN_ID = "context-guard@codex-context-guard"
MINIMUM_CODEX = (0, 146, 0)
IGNORED_TREE_NAMES = {".DS_Store", ".git", "Thumbs.db", "__pycache__"}
PLUGIN_TREE_ROOTS: set[str] | None = {".codex-plugin", "assets", "hooks", "scripts", "skills"}
ARCHIVE_INDEX_NAME = "archive-index.json"
ARCHIVE_SCHEMA_VERSION = 1


def run(codex: str, *args: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [codex, *args], text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).strip()
        raise RuntimeError(f"{' '.join((codex,) + args)} failed\n{detail}")
    return result


def codex_version(codex: str) -> tuple[int, int, int]:
    output = run(codex, "--version").stdout
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", output)
    if not match:
        raise RuntimeError(f"could not parse Codex version from {output!r}")
    return tuple(int(value) for value in match.groups())


def json_output(codex: str, *args: str) -> dict:
    output = run(codex, *args).stdout
    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Codex returned invalid JSON for {' '.join(args)}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"Codex returned an unexpected JSON value for {' '.join(args)}")
    return value


def marketplace_entry(codex: str) -> dict | None:
    value = json_output(codex, "plugin", "marketplace", "list", "--json")
    for entry in value.get("marketplaces", []):
        if entry.get("name") == MARKETPLACE:
            return entry
    return None


def same_path(left: str | Path, right: str | Path) -> bool:
    return Path(left).expanduser().resolve() == Path(right).expanduser().resolve()


def _ignored_tree_names(directory: str, names: list[str]) -> set[str]:
    """Mirror tree_manifest's ignored-name rule for copy-time filtering."""
    return {
        name
        for name in names
        if name in IGNORED_TREE_NAMES or name.endswith((".pyc", ".pyo"))
    }


def marketplace_staging_root(codex_home: Path, repo_root: Path) -> Path:
    return (
        codex_home.expanduser().resolve()
        / "upstreams"
        / PLUGIN_NAME
        / (repo_root.name + ".marketplace")
    )


def marketplace_staging(codex_home: Path, repo_root: Path) -> Path:
    """Return a sanitized marketplace root for the Codex CLI to clone from.

    The Codex CLI materializes plugin caches from the registered marketplace
    directory without filtering, so registering the verified immutable Git
    checkout directly leaks its ``.git`` metadata into the live cache whenever
    the CLI refreshes the cache (the trusted-archive repair only runs under
    ``--apply``). Registering an on-disk filtered copy of the product tree
    removes that possibility at the source.
    """
    staged = marketplace_staging_root(codex_home, repo_root)
    if staged.is_dir() and tree_manifest(staged) == tree_manifest(repo_root):
        if embedded_git_metadata(staged) is None:
            return staged
    staged.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".marketplace-", dir=staged.parent))
    try:
        filtered = temporary / "tree"
        shutil.copytree(repo_root, filtered, ignore=_ignored_tree_names)
        if tree_manifest(filtered) != tree_manifest(repo_root):
            raise RuntimeError("sanitized marketplace staging failed manifest parity")
        if embedded_git_metadata(filtered) is not None:
            raise RuntimeError("sanitized marketplace staging still carries Git metadata")
        _replace_tree_atomically(filtered, staged)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    print(f"[OK] staged sanitized marketplace root: {staged}")
    return staged


def ensure_marketplace(
    codex: str, repo_root: Path, codex_home: Path, apply: bool
) -> bool:
    staging = marketplace_staging_root(codex_home, repo_root)
    entry = marketplace_entry(codex)
    if entry is not None:
        root = entry.get("root")
        source = entry.get("marketplaceSource", {}).get("source")
        known = {value for value in (root, source) if value}
        if any(same_path(value, staging) for value in known):
            if apply:
                marketplace_staging(codex_home, repo_root)
            elif (
                not staging.is_dir()
                or tree_manifest(staging) != tree_manifest(repo_root)
                or embedded_git_metadata(staging) is not None
            ):
                raise RuntimeError(
                    f"marketplace {MARKETPLACE!r} points to a stale or missing "
                    "sanitized staging root; run --apply to refresh it"
                )
            print(f"[OK] marketplace {MARKETPLACE} points to {staging}")
            return False
        if any(same_path(value, repo_root) for value in known):
            if not apply:
                raise RuntimeError(
                    f"marketplace {MARKETPLACE!r} still points at the Git checkout; "
                    "run --apply to repoint it at the sanitized staging root"
                )
            marketplace_staging(codex_home, repo_root)
            run(codex, "plugin", "marketplace", "remove", MARKETPLACE)
            run(codex, "plugin", "marketplace", "add", str(staging), "--json")
            entry = marketplace_entry(codex)
            if entry is None or not any(
                same_path(value, staging) for value in (entry.get("root"), entry.get("marketplaceSource", {}).get("source")) if value
            ):
                raise RuntimeError(
                    f"marketplace {MARKETPLACE!r} was not visible at the sanitized "
                    "staging root after repointing"
                )
            print(
                f"[OK] repointed marketplace {MARKETPLACE} at sanitized staging root: {staging}"
            )
            return True
        raise RuntimeError(
            f"marketplace {MARKETPLACE!r} already points elsewhere: "
            f"root={root!r}, source={source!r}"
        )
    if not apply:
        raise RuntimeError(f"marketplace {MARKETPLACE!r} is not registered")
    marketplace_staging(codex_home, repo_root)
    run(codex, "plugin", "marketplace", "add", str(staging), "--json")
    entry = marketplace_entry(codex)
    if entry is None or not any(
        same_path(value, staging)
        for value in (entry.get("root"), entry.get("marketplaceSource", {}).get("source"))
        if value
    ):
        raise RuntimeError(
            f"marketplace {MARKETPLACE!r} was not visible at the sanitized staging root"
        )
    print(f"[OK] registered marketplace {MARKETPLACE}: {staging}")
    return True


def plugin_entry(codex: str) -> dict | None:
    value = json_output(codex, "plugin", "list", "--json")
    for entry in value.get("installed", []):
        if entry.get("pluginId") == PLUGIN_ID:
            return entry
    return None


def default_codex_home() -> Path:
    configured = os.environ.get("CODEX_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".codex"


def source_plugin_root(repo_root: Path) -> Path:
    return repo_root


def source_plugin_version(plugin_root: Path) -> str:
    manifest_path = plugin_root / ".codex-plugin" / "plugin.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"could not read plugin manifest {manifest_path}") from exc
    if manifest.get("name") != PLUGIN_NAME:
        raise RuntimeError(f"{manifest_path} does not describe {PLUGIN_NAME!r}")
    version = manifest.get("version")
    if not isinstance(version, str) or not version.strip():
        raise RuntimeError(f"{manifest_path} has no plugin version")
    return version


def plugin_cache_root(codex_home: Path) -> Path:
    return (
        codex_home.expanduser().resolve()
        / "plugins"
        / "cache"
        / MARKETPLACE
        / PLUGIN_NAME
    )


def cache_archive_root(codex_home: Path) -> Path:
    return (
        codex_home.expanduser().resolve()
        / "plugins"
        / "cache-archive"
        / MARKETPLACE
        / PLUGIN_NAME
    )


def embedded_git_metadata(root: Path) -> Path | None:
    candidate = root / ".git"
    return candidate if candidate.exists() or candidate.is_symlink() else None


def remove_embedded_git_metadata(candidate: Path) -> None:
    def remove_read_only(
        function: Callable[[str], object],
        path: str,
        error: tuple[type[BaseException], BaseException, Any],
    ) -> None:
        exception = error[1]
        if not isinstance(exception, PermissionError):
            raise exception
        blocked = Path(path)
        if blocked.is_symlink():
            blocked.unlink()
            return
        os.chmod(blocked, stat.S_IWRITE)
        function(path)

    if candidate.is_dir() and not candidate.is_symlink():
        shutil.rmtree(candidate, onerror=remove_read_only)
    else:
        if not candidate.is_symlink():
            os.chmod(candidate, stat.S_IWRITE)
        candidate.unlink()


def sanitize_untrusted_current_cache(
    cache_root: Path, archive_root: Path, version: str
) -> bool:
    """Remove installer-copied Git metadata before the version is trusted."""
    versions = _archive_index(archive_root)
    candidate = embedded_git_metadata(cache_root / version)
    if candidate is None:
        return False
    if version in versions:
        # A trusted archive, not an in-place deletion, is the repair authority.
        # audit_cache_archive() will restore this live tree atomically.
        return False
    remove_embedded_git_metadata(candidate)
    return True


def require_no_embedded_git_metadata(
    cache_root: Path, archive_root: Path, version: str
) -> None:
    for root in (cache_root / version, archive_root / version):
        if embedded_git_metadata(root) is not None:
            raise RuntimeError(
                f"Context Guard cache {version} contains embedded Git metadata"
            )


def tree_manifest(root: Path) -> dict[str, str]:
    if not root.is_dir():
        return {}
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if PLUGIN_TREE_ROOTS is not None and (
            not relative.parts or relative.parts[0] not in PLUGIN_TREE_ROOTS
        ):
            continue
        if any(
            part in IGNORED_TREE_NAMES or part.endswith((".pyc", ".pyo"))
            for part in relative.parts
        ):
            continue
        if path.is_symlink():
            raise RuntimeError(f"unsafe symlink in plugin tree: {path}")
        if path.is_file():
            manifest[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def tree_difference(
    source_root: Path, cache_root: Path, *, allow_cache_extras: bool = False
) -> list[str]:
    source = tree_manifest(source_root)
    cached = tree_manifest(cache_root)
    differences = [
        f"missing {name}" for name in sorted(set(source).difference(cached))
    ]
    if not allow_cache_extras:
        differences.extend(
            f"unexpected {name}" for name in sorted(set(cached).difference(source))
        )
    differences.extend(
        f"changed {name}"
        for name in sorted(set(source).intersection(cached))
        if source[name] != cached[name]
    )
    return differences


def require_cache_parity(
    source_root: Path, cache_root: Path, version: str, *, same_version: bool
) -> None:
    differences = tree_difference(source_root, cache_root)
    if not differences:
        return
    detail = ", ".join(differences[:5])
    if len(differences) > 5:
        detail += f", and {len(differences) - 5} more"
    if same_version:
        raise RuntimeError(
            f"installed {PLUGIN_ID} {version} cache differs from its source ({detail}); "
            "refusing an in-place refresh because active tasks may still execute this "
            "versioned Hook path. Bump the plugin version before applying the update"
        )
    raise RuntimeError(
        f"installed {PLUGIN_ID} {version} cache does not match its source ({detail})"
    )


def _copy_file_atomically(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.restore-{os.getpid()}")
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def cache_install_lock(cache_root: Path) -> Iterator[None]:
    cache_root.parent.mkdir(parents=True, exist_ok=True)
    lock_path = cache_root.parent / f".{PLUGIN_NAME}.install.lock"
    with lock_path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False, prefix=f".{path.name}."
    )
    temporary = Path(handle.name)
    try:
        with handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _archive_index(archive_root: Path) -> dict[str, dict[str, str]]:
    index_path = archive_root / ARCHIVE_INDEX_NAME
    if not index_path.exists():
        existing = (
            [path.name for path in archive_root.iterdir() if path.is_dir()]
            if archive_root.is_dir()
            else []
        )
        if existing:
            raise RuntimeError(
                "cache archive has version directories but no trusted index: "
                + ", ".join(sorted(existing))
            )
        return {}
    try:
        value = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cache archive index is unreadable: {index_path}") from exc
    versions = value.get("versions") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != ARCHIVE_SCHEMA_VERSION
        or not isinstance(versions, dict)
    ):
        raise RuntimeError("cache archive index has an unsupported schema")
    for version, manifest in versions.items():
        if not isinstance(version, str) or not isinstance(manifest, dict) or not manifest:
            raise RuntimeError("cache archive index contains an invalid version manifest")
        if any(
            not isinstance(name, str)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for name, digest in manifest.items()
        ):
            raise RuntimeError(
                f"cache archive index contains invalid hashes for {version}"
            )
    return versions


def _write_archive_index(
    archive_root: Path, versions: dict[str, dict[str, str]]
) -> None:
    _atomic_json(
        archive_root / ARCHIVE_INDEX_NAME,
        {
            "schema_version": ARCHIVE_SCHEMA_VERSION,
            "versions": dict(sorted(versions.items())),
        },
    )


def _replace_tree_atomically(source_root: Path, target_root: Path) -> None:
    target_root.parent.mkdir(parents=True, exist_ok=True)
    temporary_parent = Path(
        tempfile.mkdtemp(prefix=f".{target_root.name}.staged-", dir=target_root.parent)
    )
    staged = temporary_parent / "tree"
    backup = target_root.with_name(f".{target_root.name}.replaced-{os.getpid()}")
    moved_existing = False
    try:
        shutil.copytree(source_root, staged)
        if target_root.exists():
            if backup.exists():
                shutil.rmtree(backup)
            os.replace(target_root, backup)
            moved_existing = True
        os.replace(staged, target_root)
        if moved_existing:
            shutil.rmtree(backup)
    except BaseException:
        if moved_existing and not target_root.exists() and backup.exists():
            os.replace(backup, target_root)
        raise
    finally:
        shutil.rmtree(temporary_parent, ignore_errors=True)
        if backup.exists() and target_root.exists():
            shutil.rmtree(backup, ignore_errors=True)


def archive_live_versions(cache_root: Path, archive_root: Path) -> list[str]:
    versions = _archive_index(archive_root)
    archived: list[str] = []
    live_versions = (
        sorted(path for path in cache_root.iterdir() if path.is_dir())
        if cache_root.is_dir()
        else []
    )
    for live in live_versions:
        if live.is_symlink():
            raise RuntimeError(f"unsafe live cache symlink: {live}")
        live_manifest = tree_manifest(live)
        if not live_manifest:
            raise RuntimeError(f"live cache {live.name} is empty or unreadable")
        archived_root = archive_root / live.name
        expected = versions.get(live.name)
        if expected is not None:
            if not archived_root.is_dir() or tree_manifest(archived_root) != expected:
                raise RuntimeError(
                    f"trusted cache archive {live.name} is missing or corrupt"
                )
            if live_manifest != expected:
                raise RuntimeError(
                    f"live cache {live.name} differs from its trusted archive"
                )
            continue
        if archived_root.exists():
            raise RuntimeError(
                f"cache archive {live.name} exists without a trusted index entry"
            )
        _replace_tree_atomically(live, archived_root)
        versions[live.name] = live_manifest
        _write_archive_index(archive_root, versions)
        archived.append(live.name)
    return archived


def archive_verified_current_version(
    source_root: Path,
    cache_root: Path,
    archive_root: Path,
    version: str,
) -> tuple[bool, list[str]]:
    """Trust only a source-identical current cache during first adoption."""
    live = cache_root / version
    versions = _archive_index(archive_root)
    if version in versions:
        repaired = audit_cache_archive(
            cache_root,
            archive_root,
            repair=True,
        )
        require_cache_parity(source_root, live, version, same_version=True)
        return False, repaired

    if live.is_symlink():
        raise RuntimeError(f"installed {PLUGIN_ID} {version} cache is unsafe")
    require_cache_parity(source_root, live, version, same_version=True)
    live_manifest = tree_manifest(live)
    if not live_manifest:
        raise RuntimeError(f"live cache {version} is empty or unreadable")

    repaired = audit_cache_archive(
        cache_root,
        archive_root,
        repair=True,
        allow_unarchived={version},
    )
    archived_root = archive_root / version
    if archived_root.exists():
        raise RuntimeError(
            f"cache archive {version} exists without a trusted index entry"
        )
    _replace_tree_atomically(live, archived_root)
    if tree_manifest(archived_root) != live_manifest:
        raise RuntimeError(f"cache archive {version} could not be verified")
    versions[version] = live_manifest
    _write_archive_index(archive_root, versions)
    audit_cache_archive(cache_root, archive_root, repair=False)
    require_cache_parity(source_root, live, version, same_version=True)
    return True, repaired


def audit_cache_archive(
    cache_root: Path,
    archive_root: Path,
    *,
    repair: bool,
    allow_unarchived: set[str] | None = None,
) -> list[str]:
    allowed = allow_unarchived or set()
    versions = _archive_index(archive_root)
    archive_dirs = (
        {path.name for path in archive_root.iterdir() if path.is_dir()}
        if archive_root.is_dir()
        else set()
    )
    unexpected = sorted(archive_dirs.difference(versions))
    if unexpected:
        raise RuntimeError(
            "cache archive contains unindexed version directories: "
            + ", ".join(unexpected)
        )
    repaired: list[str] = []
    issues: list[str] = []
    for version, expected in sorted(versions.items()):
        archived = archive_root / version
        if not archived.is_dir():
            issues.append(f"archive {version} is missing")
            continue
        try:
            archive_manifest = tree_manifest(archived)
        except RuntimeError as exc:
            issues.append(str(exc))
            continue
        if archive_manifest != expected:
            issues.append(f"archive {version} failed its trusted hash manifest")
            continue
        archive_git_metadata = embedded_git_metadata(archived)
        if archive_git_metadata is not None:
            if not repair:
                issues.append(f"archive {version} contains embedded Git metadata")
                continue
            remove_embedded_git_metadata(archive_git_metadata)
            if (
                embedded_git_metadata(archived) is not None
                or tree_manifest(archived) != expected
            ):
                issues.append(
                    f"archive {version} Git metadata cleanup changed trusted bytes"
                )
                continue
            print(
                "[OK] removed non-product Git metadata from trusted cache archive: "
                + version
            )
        live = cache_root / version
        live_manifest = tree_manifest(live) if live.is_dir() else {}
        live_git_metadata = embedded_git_metadata(live)
        if live_manifest == expected and live_git_metadata is None:
            continue
        if repair:
            _replace_tree_atomically(archived, live)
            if (
                tree_manifest(live) != expected
                or embedded_git_metadata(live) is not None
            ):
                issues.append(f"live cache {version} could not be repaired")
            else:
                repaired.append(version)
        else:
            issues.append(
                f"live cache {version} is missing, differs from its trusted archive, "
                "or contains embedded Git metadata"
            )
    live_dirs = (
        {path.name for path in cache_root.iterdir() if path.is_dir()}
        if cache_root.is_dir()
        else set()
    )
    unarchived = sorted(live_dirs.difference(versions).difference(allowed))
    if unarchived:
        issues.append(
            "live cache version(s) have no trusted archive: " + ", ".join(unarchived)
        )
    if issues:
        raise RuntimeError("cache archive audit failed: " + "; ".join(issues))
    return repaired


def ensure_plugin(
    codex: str, repo_root: Path, codex_home: Path, apply: bool
) -> bool:
    source_root = source_plugin_root(repo_root)
    desired_version = source_plugin_version(source_root)
    cache_root = plugin_cache_root(codex_home)
    archive_root = cache_archive_root(codex_home)
    entry = plugin_entry(codex)
    was_installed = entry is not None

    if (
        entry is not None
        and entry.get("version") == desired_version
        and not apply
    ):
        git_meta = (
            embedded_git_metadata(cache_root / desired_version)
            or embedded_git_metadata(archive_root / desired_version)
        )
        if git_meta is not None:
            raise RuntimeError(
                f"Context Guard cache {desired_version} contains embedded Git metadata; "
                "run with --apply to restore the live cache from the trusted archive"
            )
        repaired = audit_cache_archive(
            cache_root, archive_root, repair=apply
        )
        require_cache_parity(
            source_root,
            cache_root / desired_version,
            desired_version,
            same_version=True,
        )
        if repaired:
            print(
                "[OK] repaired live Context Guard cache version(s): "
                + ", ".join(repaired)
            )
        if not entry.get("enabled"):
            raise RuntimeError(
                f"plugin {PLUGIN_ID!r} is installed but disabled; apply the shared config"
            )
        print(
            f"[OK] plugin {PLUGIN_ID} {desired_version} is current; "
            "skipped cache refresh"
        )
        return False

    if entry is not None and entry.get("version") == desired_version:
        with cache_install_lock(cache_root):
            entry = plugin_entry(codex)
            if entry is not None and entry.get("version") == desired_version:
                sanitized = sanitize_untrusted_current_cache(
                    cache_root, archive_root, desired_version
                )
                archived_current, repaired = archive_verified_current_version(
                    source_root,
                    cache_root,
                    archive_root,
                    desired_version,
                )
                if archived_current:
                    print(
                        "[OK] archived verified current Context Guard cache: "
                        + desired_version
                    )
                if repaired:
                    print(
                        "[OK] repaired live Context Guard cache version(s): "
                        + ", ".join(repaired)
                    )
                if sanitized:
                    print("[OK] removed untrusted embedded Git metadata")
                require_no_embedded_git_metadata(
                    cache_root, archive_root, desired_version
                )
                if not entry.get("enabled"):
                    raise RuntimeError(
                        f"plugin {PLUGIN_ID!r} is installed but disabled; "
                        "apply the shared config"
                    )
                print(
                    f"[OK] plugin {PLUGIN_ID} {desired_version} is current; "
                    "skipped cache refresh"
                )
                return False

    if not apply:
        if entry is None:
            raise RuntimeError(f"plugin {PLUGIN_ID!r} is not installed")
        raise RuntimeError(
            f"plugin {PLUGIN_ID!r} is {entry.get('version')!r}, "
            f"but the repository requires {desired_version!r}"
        )

    with cache_install_lock(cache_root):
        entry = plugin_entry(codex)
        if entry is not None and entry.get("version") == desired_version:
            sanitized = sanitize_untrusted_current_cache(
                cache_root, archive_root, desired_version
            )
            archived_current, repaired = archive_verified_current_version(
                source_root,
                cache_root,
                archive_root,
                desired_version,
            )
            if archived_current:
                print(
                    "[OK] archived verified current Context Guard cache: "
                    + desired_version
                )
            if repaired:
                print(
                    "[OK] repaired live Context Guard cache version(s): "
                    + ", ".join(repaired)
                )
            if sanitized:
                print("[OK] removed untrusted embedded Git metadata")
        else:
            unarchived_live = (
                {path.name for path in cache_root.iterdir() if path.is_dir()}
                if cache_root.is_dir()
                else set()
            )
            repaired = audit_cache_archive(
                cache_root,
                archive_root,
                repair=True,
                allow_unarchived=unarchived_live,
            )
            archived = archive_live_versions(cache_root, archive_root)
            try:
                run(codex, "plugin", "add", PLUGIN_ID, "--json")
            except BaseException:
                audit_cache_archive(cache_root, archive_root, repair=True)
                raise
            sanitized = sanitize_untrusted_current_cache(
                cache_root, archive_root, desired_version
            )
            repaired.extend(
                audit_cache_archive(
                    cache_root,
                    archive_root,
                    repair=True,
                    allow_unarchived={desired_version},
                )
            )
            archived.extend(archive_live_versions(cache_root, archive_root))
            audit_cache_archive(cache_root, archive_root, repair=False)
            if archived:
                print(
                    "[OK] archived Context Guard cache version(s): "
                    + ", ".join(dict.fromkeys(archived))
                )
            if repaired:
                print(
                    "[OK] repaired live Context Guard cache version(s): "
                    + ", ".join(dict.fromkeys(repaired))
                )
            if sanitized:
                print("[OK] removed untrusted embedded Git metadata")
        entry = plugin_entry(codex)

    if entry is None:
        raise RuntimeError(f"plugin {PLUGIN_ID!r} was not visible after install/update")
    if entry.get("version") != desired_version:
        raise RuntimeError(
            f"plugin {PLUGIN_ID!r} remained at {entry.get('version')!r}; "
            f"expected {desired_version!r}"
        )
    require_cache_parity(
        source_root,
        cache_root / desired_version,
        desired_version,
        same_version=False,
    )
    require_no_embedded_git_metadata(cache_root, archive_root, desired_version)
    if not entry.get("enabled"):
        raise RuntimeError(
            f"plugin {PLUGIN_ID!r} is installed but disabled; apply the shared config"
        )
    action = "updated" if was_installed else "installed"
    print(f"[OK] {action} plugin {PLUGIN_ID} {desired_version}")
    return not was_installed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--codex-home", type=Path, default=default_codex_home())
    parser.add_argument("--codex", default="codex")
    parser.add_argument(
        "--apply", action="store_true", help="register/install missing components"
    )
    args = parser.parse_args()
    repo_root = args.repo_root.expanduser().resolve()
    codex_home = args.codex_home.expanduser().resolve()
    # Every Codex subprocess must use the same home that this script validates.
    # Otherwise --codex-home can inspect an isolated cache while plugin commands
    # silently mutate the caller's default ~/.codex installation.
    os.environ["CODEX_HOME"] = str(codex_home)
    try:
        version = codex_version(args.codex)
        if version < MINIMUM_CODEX:
            minimum = ".".join(map(str, MINIMUM_CODEX))
            actual = ".".join(map(str, version))
            raise RuntimeError(
                f"Codex {actual} is below the Context Guard baseline {minimum}; upgrade first"
            )
        print(f"[OK] Codex version supports stable hooks: {'.'.join(map(str, version))}")
        ensure_marketplace(args.codex, repo_root, codex_home, args.apply)
        ensure_plugin(args.codex, repo_root, codex_home, args.apply)
    except (OSError, RuntimeError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
