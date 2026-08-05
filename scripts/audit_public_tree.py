#!/usr/bin/env python3
"""Fail when the candidate public tree contains private or generated material."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "build", "dist", ".ruff_cache"}
GENERATED_NAMES = {".DS_Store", "Thumbs.db", "__pycache__", ".pytest_cache"}
SELF = "scripts/audit_public_tree.py"
FORBIDDEN_LITERALS = (
    "codex-sync",
    "lgr59",
    "@126.com",
    "GreenLv@users.noreply.github.com",
)
PATTERNS = {
    "macOS user-specific path": re.compile(r"/Users/[A-Za-z0-9._-]+/"),
    "Windows user-specific path": re.compile(
        r"[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\"
    ),
    "OpenAI-style API key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "GitHub token": re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b"),
    "bearer credential": re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{16,}\b", re.I),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "real-looking Codex session UUID": re.compile(
        r"\b019[a-f0-9]{5}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b",
        re.I,
    ),
}


def candidate_files(root: Path) -> list[Path]:
    if (root / ".git").is_dir():
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached"],
            check=False,
            capture_output=True,
        )
        if result.returncode == 0 and result.stdout:
            return [
                root / item.decode("utf-8")
                for item in result.stdout.split(b"\0")
                if item
            ]
    return [path for path in sorted(root.rglob("*")) if path.is_file()]


def findings(root: Path, extra_forbidden: list[str] | None = None) -> list[str]:
    issues: list[str] = []
    literals = FORBIDDEN_LITERALS + tuple(extra_forbidden or [])
    for path in candidate_files(root):
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if any(part in GENERATED_NAMES for part in relative.parts):
            issues.append(f"{relative}: generated/private filesystem artifact")
            continue
        if path.is_symlink():
            issues.append(f"{relative}: symlinks are not allowed in the public tree")
            continue
        if not path.is_file() or relative.as_posix() == SELF:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            issues.append(f"{relative}: unexpected binary file")
            continue
        for literal in literals:
            if literal and literal.casefold() in text.casefold():
                issues.append(f"{relative}: forbidden private literal")
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                issues.append(f"{relative}: {label}")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", default=Path.cwd())
    parser.add_argument("--forbid", action="append", default=[])
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    issues = findings(root, args.forbid)
    if issues:
        print("Public-tree audit failed:", file=sys.stderr)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        return 1
    print(f"Public-tree audit passed: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
