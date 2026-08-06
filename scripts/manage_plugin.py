#!/usr/bin/env python3
"""Safely register, install, and check the repo-local Context Guard plugin."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

MARKETPLACE = "codex-context-guard"
PLUGIN_NAME = "context-guard"
PLUGIN_ID = "context-guard@codex-context-guard"
MINIMUM_CODEX = (0, 146, 0)
IGNORED_TREE_NAMES = {".DS_Store", "Thumbs.db", "__pycache__"}
PLUGIN_TREE_ROOTS = {".codex-plugin", "assets", "hooks", "scripts", "skills"}


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


def ensure_marketplace(codex: str, repo_root: Path, apply: bool) -> bool:
    entry = marketplace_entry(codex)
    if entry is not None:
        root = entry.get("root")
        source = entry.get("marketplaceSource", {}).get("source")
        if not any(
            value and same_path(value, repo_root)
            for value in (root, source)
        ):
            raise RuntimeError(
                f"marketplace {MARKETPLACE!r} already points elsewhere: "
                f"root={root!r}, source={source!r}"
            )
        print(f"[OK] marketplace {MARKETPLACE} points to {repo_root}")
        return False
    if not apply:
        raise RuntimeError(f"marketplace {MARKETPLACE!r} is not registered")
    run(codex, "plugin", "marketplace", "add", str(repo_root), "--json")
    entry = marketplace_entry(codex)
    if entry is None:
        raise RuntimeError(f"marketplace {MARKETPLACE!r} was not visible after registration")
    print(f"[OK] registered marketplace {MARKETPLACE}: {repo_root}")
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


def tree_manifest(root: Path) -> dict[str, str]:
    if not root.is_dir():
        return {}
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if not relative.parts or relative.parts[0] not in PLUGIN_TREE_ROOTS:
            continue
        if any(
            part in IGNORED_TREE_NAMES or part.endswith((".pyc", ".pyo"))
            for part in relative.parts
        ):
            continue
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


def restore_tree(source_root: Path, target_root: Path) -> None:
    files = [path for path in source_root.rglob("*") if path.is_file()]
    hook_script = Path("scripts") / "context_guard.py"
    files.sort(
        key=lambda path: (
            path.relative_to(source_root) != hook_script,
            path.relative_to(source_root).as_posix(),
        )
    )
    for source in files:
        _copy_file_atomically(source, target_root / source.relative_to(source_root))


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


@contextmanager
def preserve_cached_versions(cache_root: Path) -> Iterator[list[str]]:
    cached_versions = (
        sorted(path for path in cache_root.iterdir() if path.is_dir())
        if cache_root.is_dir()
        else []
    )
    with tempfile.TemporaryDirectory(prefix=f"{PLUGIN_NAME}-cache-backup-") as temp:
        backup_root = Path(temp)
        for cached in cached_versions:
            shutil.copytree(cached, backup_root / cached.name)
        try:
            yield [path.name for path in cached_versions]
        finally:
            for backup in sorted(backup_root.iterdir()):
                target = cache_root / backup.name
                restore_tree(backup, target)
                restored_difference = tree_difference(
                    backup, target, allow_cache_extras=True
                )
                if restored_difference:
                    raise RuntimeError(
                        f"failed to restore cached {PLUGIN_NAME} {backup.name}: "
                        + ", ".join(restored_difference[:5])
                    )


def ensure_plugin(
    codex: str, repo_root: Path, codex_home: Path, apply: bool
) -> bool:
    source_root = source_plugin_root(repo_root)
    desired_version = source_plugin_version(source_root)
    cache_root = plugin_cache_root(codex_home)
    entry = plugin_entry(codex)
    was_installed = entry is not None

    if entry is not None and entry.get("version") == desired_version:
        require_cache_parity(
            source_root,
            cache_root / desired_version,
            desired_version,
            same_version=True,
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
            require_cache_parity(
                source_root,
                cache_root / desired_version,
                desired_version,
                same_version=True,
            )
        else:
            with preserve_cached_versions(cache_root) as preserved:
                run(codex, "plugin", "add", PLUGIN_ID, "--json")
            if preserved:
                print(
                    "[OK] preserved prior Context Guard cache version(s): "
                    + ", ".join(preserved)
                )
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
        ensure_marketplace(args.codex, repo_root, args.apply)
        ensure_plugin(args.codex, repo_root, codex_home, args.apply)
    except (OSError, RuntimeError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
