"""Bounded Git source/commit identities; local read-only plumbing, no authority.

All paths round-trip strict UTF-8 Git bytes. Unsupported bytes and pathspecs
fail closed. This module never stages, commits, fetches, or pushes anything.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

MAX_FILES = 64
MAX_CANDIDATES = 128
SHA = re.compile(r"[0-9a-f]{40}")
REASONS = {
    "commit_result_missing": "The authorized commit has no uniquely correlated successful result or existing full readback.",
    "commit_failed": "The observed commit command failed; verify the commit result before this action.",
    "commit_scope_mismatch": "The commit's complete path/mode/blob scope differs from the frozen authorized source.",
    "commit_base_drift": "The commit parent or repository base changed from the authorized base.",
    "commit_authority_changed": "The commit observation belongs to a different work unit or authorization generation.",
    "commit_candidates_ambiguous": "Multiple existing commits match the frozen source; no unique commit can be associated.",
    "commit_scope_unresolved": "The authorized source scope is not ready or uniquely attributable to this task.",
    "commit_path_unsupported": "The Git path identity or pathspec cannot be represented and resolved without loss.",
    "commit_repository_mismatch": "The execution repository differs from the authorized repository.",
}


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def git(root: str, *args: str) -> bytes | None:
    try:
        p = subprocess.run(["git", "-C", root, *args], capture_output=True, timeout=5, check=False)
        return p.stdout if p.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def head(root: str) -> str | None:
    raw = git(root, "rev-parse", "--verify", "HEAD")
    value = raw.decode("ascii", "ignore").strip() if raw else ""
    return value if SHA.fullmatch(value) else None


def repository(root: str) -> str | None:
    raw = git(root, "rev-parse", "--show-toplevel")
    try:
        return str(Path(raw.removesuffix(b"\n").decode("utf-8")).resolve()) if raw else None
    except (UnicodeError, OSError):
        return None


def path_identity(raw: bytes) -> str:
    value = raw.decode("utf-8", "strict")
    if not value or value.encode("utf-8") != raw or "\0" in value:
        raise ValueError("unsupported Git path")
    return value


def input_path(root: str, value: str) -> str | None:
    """Map input spelling once; never rewrite a path from Git plumbing."""
    if not isinstance(value, str) or not value or any(c in value for c in "\0*?[]{}$`") or value.startswith(":"):
        return None
    try:
        value.encode("utf-8", "strict")
        candidates = [value]
        if "\\" in value:
            candidates.append(value.replace("\\", "/"))
        mapped = []
        for candidate in candidates:
            path = Path(candidate)
            if path.is_absolute():
                try:
                    path = path.relative_to(Path(root))
                except ValueError:
                    continue
            # Git plumbing identities always use forward slashes. On Windows,
            # this also collapses equivalent input spellings before the
            # ambiguity check; on POSIX a literal backslash remains literal.
            candidate = path.as_posix()
            parts = candidate.split("/")
            if any(p in {"", ".", ".."} for p in parts) or parts[0] == ".git":
                continue
            # Parent symlinks can escape the repository; a final symlink is
            # itself a legitimate Git object and is never followed for blobs.
            if any((Path(root).joinpath(*parts[:i])).is_symlink() for i in range(1, len(parts))):
                continue
            mapped.append(candidate)
        existing = [p for p in mapped if os.path.lexists(Path(root) / p) or git(root, "ls-files", "--error-unmatch", "--", p)]
        unique = list(dict.fromkeys(existing or mapped))
        return unique[0] if len(unique) == 1 else None
    except (UnicodeError, OSError, ValueError):
        return None


def tree(root: str, revision: str) -> dict[str, tuple[str, str]] | None:
    raw = git(root, "ls-tree", "-r", "-z", revision)
    if raw is None:
        return None
    result = {}
    try:
        for token in raw.split(b"\0"):
            if not token:
                continue
            meta, path = token.split(b"\t", 1)
            mode, kind, blob = meta.decode("ascii").split()
            if kind not in {"blob", "commit"} or not SHA.fullmatch(blob):
                return None
            result[path_identity(path)] = (mode, blob)
    except (UnicodeError, ValueError):
        return None
    return result


def index_tree(root: str) -> dict[str, tuple[str, str]] | None:
    raw = git(root, "ls-files", "--stage", "-z")
    if raw is None:
        return None
    result = {}
    try:
        for token in raw.split(b"\0"):
            if not token:
                continue
            meta, path = token.split(b"\t", 1)
            mode, blob, stage = meta.decode("ascii").split()
            if stage != "0" or not SHA.fullmatch(blob):
                return None
            result[path_identity(path)] = (mode, blob)
    except (UnicodeError, ValueError):
        return None
    return result


def worktree_object(root: str, path: str, tracked_mode: str | None = None) -> tuple[str, str] | None:
    absolute = Path(root) / path
    try:
        if absolute.is_symlink():
            content = os.fsencode(os.readlink(absolute))
            blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
            return "120000", blob
        if not absolute.exists():
            return None
        if not absolute.is_file():
            raise ValueError("unsupported source object")
        blob_raw = git(root, "hash-object", "--", path)
        blob = blob_raw.decode("ascii").strip() if blob_raw else ""
        if not SHA.fullmatch(blob):
            raise ValueError("unreadable source blob")
        mode = "100644" if os.name == "nt" else ("100755" if absolute.stat().st_mode & stat.S_IXUSR else "100644")
        if tracked_mode in {"100644", "100755"}:
            filemode = git(root, "config", "--get", "core.filemode")
            if filemode and filemode.strip() == b"false":
                mode = tracked_mode
        return mode, blob
    except (OSError, UnicodeError) as exc:
        raise ValueError("source read unavailable") from exc


def entry(path: str, obj: tuple[str, str] | None, origin: str) -> dict[str, Any]:
    return {"path": path, "status": "modified" if obj else "deleted", "mode": obj[0] if obj else None,
            "blob": obj[1] if obj else None, "origin": origin}


def identity(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(({k: e[k] for k in ("path", "status", "mode", "blob")} for e in entries), key=lambda e: e["path"].encode("utf-8"))


def projection(root: str, paths: list[str] | None = None, *, prefer_index: bool = True) -> dict[str, Any] | None:
    base = head(root)
    base_tree = tree(root, base) if base else {}
    index = index_tree(root)
    if base_tree is None or index is None:
        return None
    try:
        if paths is None:
            raw = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames")
            if raw is None:
                return None
            paths = [path_identity(t[3:]) for t in raw.split(b"\0") if t]
        if len(set(paths)) > MAX_FILES:
            return None
        entries = []
        for path in sorted(set(paths), key=lambda v: v.encode("utf-8")):
            path_identity(path.encode("utf-8"))
            parts = path.split("/")
            if path.startswith("/") or any(p in {"", ".", ".."} for p in parts) or parts[0] == ".git":
                return None
            if any((Path(root).joinpath(*parts[:i])).is_symlink() for i in range(1, len(parts))):
                return None
            staged = index.get(path) != base_tree.get(path)
            if staged and prefer_index:
                obj, origin = index.get(path), "staged"
            else:
                obj = worktree_object(root, path, (index.get(path) or (None, None))[0])
                origin = "unstaged" if path in base_tree else "untracked"
            if obj != base_tree.get(path):
                entries.append(entry(path, obj, origin))
        return {"base_head": base, "entries": entries, "projection_sha256": digest({"base_head": base, "entries": identity(entries)})}
    except (UnicodeError, ValueError, OSError):
        return None


def commit_changes(root: str, sha: str) -> tuple[str | None, list[dict[str, Any]]] | None:
    if not SHA.fullmatch(sha):
        return None
    raw = git(root, "rev-list", "--parents", "-n", "1", sha)
    if not raw:
        return None
    values = raw.decode("ascii", "ignore").split()
    if len(values) not in {1, 2} or values[0] != sha:
        return None  # merges never masquerade as one-base commits
    parent = values[1] if len(values) == 2 else None
    before = tree(root, parent) if parent else {}
    after = tree(root, sha)
    if before is None or after is None:
        return None
    paths = sorted(set(before) | set(after), key=lambda v: v.encode("utf-8"))
    changed = [entry(p, after.get(p), "commit") for p in paths if before.get(p) != after.get(p)]
    if len(changed) > MAX_FILES:
        return None
    return parent, identity(changed)


def candidates(root: str, base: str | None) -> list[str] | None:
    args = ["rev-list", "--all", "--reflog", f"--max-count={MAX_CANDIDATES + 1}"]
    if base:
        args += ["--not", base]
    raw = git(root, *args)
    if raw is None:
        return None
    values = raw.decode("ascii", "ignore").split()
    if len(values) > MAX_CANDIDATES or any(not SHA.fullmatch(v) for v in values):
        return None
    return sorted(set(values))


def match_candidates(root: str, prepared: dict[str, Any], allowed: list[str] | None = None) -> tuple[list[str], str]:
    values = candidates(root, prepared.get("base_head")) if allowed is None else allowed
    if values is None:
        return [], "commit_candidates_ambiguous"
    matches = []
    reason = "commit_result_missing"
    for sha in values:
        change = commit_changes(root, sha)
        if change is None:
            reason = "commit_path_unsupported"
            continue
        parent, entries = change
        if parent != prepared.get("base_head"):
            if reason == "commit_result_missing":
                reason = "commit_base_drift"
            continue
        if entries != identity(prepared["entries"]):
            reason = "commit_scope_mismatch"
            continue
        matches.append(sha)
    if len(matches) > 1:
        return matches, "commit_candidates_ambiguous"
    return matches, reason
