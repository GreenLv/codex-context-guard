#!/usr/bin/env python3
"""Select daily or full portability coverage, and verify its required jobs."""
from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
from pathlib import Path

from tools.validation.verify_required_jobs import evaluate

PYTHON_VERSIONS = ("3.10", "3.11", "3.12", "3.13", "3.14")
PLATFORMS = (("ubuntu", "Ubuntu"), ("macos", "macOS"), ("windows", "Windows"))
CI_LANES = tuple(
    (f"{os}_py{version.replace('.', '')}", f"{label} / Python {version}",
     f"{os}-latest", version)
    for os, label in PLATFORMS for version in PYTHON_VERSIONS
)
DAILY_FULL = {"ubuntu_py310", "ubuntu_py314", "macos_py312", "windows_py312"}
DAILY_FOCUSED = ("windows_platform_py310", "windows_platform_py314")
# These inputs can alter interpreter support, packaging or CI coverage itself.
FULL_PATHS = (
    ".github/**", ".codex-plugin/**", ".gitattributes", "pyproject.toml",
    "uv.lock", "requirements-lock.txt", "hooks/**", "scripts/manage_plugin.py",
    "scripts/run_context_guard.sh", "scripts/run-context-guard.ps1",
    "scripts/smoke_installed.py", "tools/validation/ci_policy.py",
    "tools/validation/run_windows_platform_suite.py", "tools/validation/validate_workflows.py",
    "docs/COMPATIBILITY.md", "docs/VERSIONING.md", "validation-map.json",
)
KNOWN_PATHS = ("*.md", "docs/**", "tests/**", "scripts/**", "tools/**", "assets/**",
               "skills/**", ".agents/**", ".gitignore", ".codexignore", "LICENSE")


def select_profile(request: str, paths: list[str]) -> str:
    if request not in {"auto", "daily", "full"}:
        raise ValueError("unknown CI profile")
    if request != "auto":
        return request
    if any(any(fnmatch.fnmatchcase(p, pattern) for pattern in FULL_PATHS)
           or not any(fnmatch.fnmatchcase(p, pattern) for pattern in KNOWN_PATHS)
           for p in paths):
        return "full"
    return "daily"


def required_jobs(profile: str, portable: bool) -> list[str]:
    if profile not in {"daily", "full"}:
        raise ValueError("resolved CI profile must be daily or full")
    lanes = [row[0] for row in CI_LANES if profile == "full" or row[0] in DAILY_FULL]
    if profile == "daily":
        lanes.extend(DAILY_FOCUSED)
    return ["classify", "static", *lanes, *(["portable_windows"] if portable else [])]


def verify(profile: str, portable: bool, needs: dict) -> dict:
    return evaluate(required_jobs(profile, portable), {k: v["result"] for k, v in needs.items()})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    select = sub.add_parser("select")
    select.add_argument("--profile", choices=("auto", "daily", "full"), default="auto")
    select.add_argument("--base", required=True)
    select.add_argument("--head", required=True)
    select.add_argument("--github-output", type=Path, required=True)
    summary = sub.add_parser("verify")
    summary.add_argument("--profile", required=True)
    summary.add_argument("--portable", choices=("true", "false"), required=True)
    summary.add_argument("--needs-json", required=True)
    args = parser.parse_args()
    if args.command == "select":
        # Include both sides of a rename/deletion; NUL-delimit unusual paths.
        paths = subprocess.check_output([
            "git", "diff", "--name-only", "--no-renames", "-z", args.base, args.head,
        ]).decode("utf-8").split("\0")
        profile = select_profile(args.profile, [p for p in paths if p])
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"profile={profile}\n")
        print(json.dumps({"profile": profile, "required": required_jobs(profile, False)}))
    else:
        print(json.dumps(verify(args.profile, args.portable == "true", json.loads(args.needs_json))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
