#!/usr/bin/env python3
"""Canonical prepared-source identity for acceptance batches (v2).

Single implementation shared by ``scripts/check_incident_coverage.py``, the
Windows batch package and the handoff generator. Properties (all covered by
tests/test_acceptance_identity.py):

- **HEAD-bound**: the digest starts from the base HEAD, so two different
  HEADs never share a dirty-only identity.
- **Complete untracked expansion**: ``git status --porcelain=v1 -z
  --untracked-files=all`` (NUL separated) — new directories are expanded to
  every file, and paths with spaces, CJK characters, quotes or newlines are
  handled byte-exactly (no shell quoting).
- **Deletes and renames**: a deleted path binds ``b"deleted"``; a rename
  binds the destination content AND the origin path with
  ``b"renamed-away"``.
- **Explicit special files**: symlinks hash ``b"symlink:" + target``;
  anything else that is not a regular file (submodule directory, fifo,
  socket) raises instead of silently encoding ``missing``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def _git(root: Path, *argv: str) -> bytes:
    completed = subprocess.run(["git", *argv], cwd=root,
                               capture_output=True, check=True)
    return completed.stdout


def _bind_path(digest, path: str, binding: bytes) -> None:
    digest.update(path.encode("utf-8", "surrogateescape"))
    digest.update(b"\0")
    digest.update(binding)
    digest.update(b"\0")


def _file_binding(root: Path, path: str) -> bytes:
    target = root / path
    if target.is_symlink():
        return b"symlink:" + target.readlink().as_posix().encode(
            "utf-8", "surrogateescape")
    if target.is_file():
        return hashlib.sha256(target.read_bytes()).digest()
    raise ValueError(
        f"prepared-source path is neither a regular file nor a symlink: "
        f"{path}; refusing to encode an unknown file type as missing")


def prepared_source_identity(root: Path) -> dict:
    """Canonical HEAD-bound identity of the uncommitted candidate."""
    root = Path(root).resolve()
    head = _git(root, "rev-parse", "HEAD").decode().strip()
    raw = _git(root, "status", "--porcelain=v1", "-z",
               "--untracked-files=all")
    entries = [item for item in raw.split(b"\0") if item]

    digest = hashlib.sha256()
    digest.update(b"prepared-source/v2\0")
    digest.update(head.encode())
    digest.update(b"\0")

    paths: list[str] = []
    renames_away: list[str] = []
    index = 0
    while index < len(entries):
        entry = entries[index]
        xy = entry[:2].decode()
        path_bytes = entry[3:]
        index += 1
        if "R" in xy or "C" in xy:
            # porcelain v1 -z: "<XY> <new>\0<old>\0" for rename/copy
            origin_bytes = entries[index]
            index += 1
            origin = origin_bytes.decode("utf-8", "surrogateescape")
            renames_away.append(origin)
        path = path_bytes.decode("utf-8", "surrogateescape")
        if xy == "D " or xy == " D" or xy == "DD":
            _bind_path(digest, path, b"deleted")
            paths.append(path)
        elif xy == "!!":
            continue  # ignored files never participate
        else:
            _bind_path(digest, path, _file_binding(root, path))
            paths.append(path)
    for origin in sorted(renames_away):
        _bind_path(digest, origin, b"renamed-away")
    return {"head": head,
            "prepared_source_sha256": digest.hexdigest(),
            "dirty_paths": sorted(paths),
            "renamed_away": sorted(renames_away)}


def runtime_tree_digest(root: Path) -> str:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "manage_plugin", Path(root).resolve() / "scripts" / "manage_plugin.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = module.tree_manifest(Path(root).resolve())
    return hashlib.sha256(json.dumps(
        manifest, ensure_ascii=True, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    args = parser.parse_args()
    root = Path(args.repo_root).resolve()
    identity = prepared_source_identity(root)
    identity["runtime_tree_sha256"] = runtime_tree_digest(root)
    print(json.dumps(identity, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
