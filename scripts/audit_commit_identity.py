#!/usr/bin/env python3
"""Fail when candidate commits do not use a GitHub noreply identity."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

BASE_ENV = "CONTEXT_GUARD_IDENTITY_BASE"
HEAD_ENV = "CONTEXT_GUARD_IDENTITY_HEAD"
NOREPLY_EMAIL_RE = re.compile(
    r"\A(?:[^@\s<>]+@users\.noreply\.github\.com|noreply@github\.com)\Z",
    re.IGNORECASE,
)


class GitInspectionError(RuntimeError):
    """Raised without carrying potentially private Git output."""


def run_git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise GitInspectionError("Git could not inspect the candidate range")
    return result.stdout


def resolve_commit(root: Path, revision: str) -> str:
    raw = run_git(root, "rev-parse", "--verify", f"{revision}^{{commit}}")
    try:
        commit = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise GitInspectionError("Git returned an invalid commit identifier") from exc
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit):
        raise GitInspectionError("Git returned an invalid commit identifier")
    return commit.lower()


def is_zero_revision(revision: str) -> bool:
    return len(revision) >= 40 and set(revision) == {"0"}


def candidate_commits(root: Path, base: str, head: str) -> list[str]:
    head_commit = resolve_commit(root, head)
    if not base or is_zero_revision(base):
        return [head_commit]

    base_commit = resolve_commit(root, base)
    raw = run_git(root, "rev-list", "--reverse", f"{base_commit}..{head_commit}")
    try:
        commits = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GitInspectionError("Git returned an invalid candidate range") from exc
    if any(not re.fullmatch(r"[0-9a-fA-F]{40,64}", item) for item in commits):
        raise GitInspectionError("Git returned an invalid candidate range")
    return [item.lower() for item in commits]


def commit_identities(root: Path, commit: str) -> tuple[str, str] | None:
    raw = run_git(root, "show", "-s", "--format=%ae%x00%ce%x00", commit)
    fields = raw.split(b"\0")
    if len(fields) < 3:
        return None
    try:
        return fields[0].decode("utf-8"), fields[1].decode("utf-8")
    except UnicodeDecodeError:
        return None


def violations(root: Path, commits: list[str]) -> list[tuple[str, tuple[str, ...]]]:
    found: list[tuple[str, tuple[str, ...]]] = []
    for commit in commits:
        identities = commit_identities(root, commit)
        if identities is None:
            found.append((commit, ("metadata",)))
            continue
        invalid = tuple(
            role
            for role, email in zip(("author", "committer"), identities, strict=True)
            if NOREPLY_EMAIL_RE.fullmatch(email) is None
        )
        if invalid:
            found.append((commit, invalid))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", default=Path.cwd())
    parser.add_argument("--base", default=os.environ.get(BASE_ENV, ""))
    parser.add_argument("--head", default=os.environ.get(HEAD_ENV, "HEAD"))
    args = parser.parse_args()

    root = args.root.expanduser().resolve()
    base = args.base.strip()
    head = args.head.strip() or "HEAD"
    try:
        commits = candidate_commits(root, base, head)
        invalid = violations(root, commits)
    except GitInspectionError as exc:
        print(f"Commit-identity audit failed: {exc}.", file=sys.stderr)
        return 2

    if invalid:
        print(
            "Commit-identity audit failed: candidate commits must use GitHub "
            "noreply author and committer identities.",
            file=sys.stderr,
        )
        for commit, fields in invalid:
            print(f"  {commit[:12]}: invalid {', '.join(fields)} identity", file=sys.stderr)
        print("  Identity values are redacted.", file=sys.stderr)
        return 1

    print(f"Commit-identity audit passed: {len(commits)} candidate commit(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
