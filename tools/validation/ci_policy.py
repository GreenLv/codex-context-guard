#!/usr/bin/env python3
"""Select daily or full portability coverage, and verify its required jobs."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: conservative full fallback
    tomllib = None

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
    "uv.lock", "requirements-lock.txt", "hooks/**", "scripts/artifact_identity.py", "scripts/build_release_artifact.py",
    "scripts/run_context_guard.sh", "scripts/run-context-guard.ps1",
    "scripts/smoke_installed.py", "tools/validation/ci_policy.py",
    "tools/validation/run_windows_platform_suite.py", "tools/validation/validate_workflows.py",
    "docs/COMPATIBILITY.md", "docs/VERSIONING.md", "validation-map.json",
)
KNOWN_PATHS = ("*.md", "docs/**", "tests/**", "scripts/**", "tools/**", "assets/**",
               "skills/**", ".agents/**", ".gitignore", ".codexignore", "LICENSE")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _version_normalized(path: str, text: str) -> str | None:
    """Mask only this project's one version value; otherwise stay conservative."""
    if path == '.codex-plugin/plugin.json':
        try:
            data = json.loads(text, object_pairs_hook=_unique_pairs)
            if not isinstance(data, dict) or not isinstance(data.get('version'), str):
                return None
            data['version'] = '<version>'
            return json.dumps(data, sort_keys=True, separators=(',', ':'))
        except (ValueError, TypeError):
            return None
    if tomllib is None:
        return None
    try:
        tomllib.loads(text)
    except (ValueError, TypeError):
        return None
    if path == 'pyproject.toml':
        pattern = r'(?ms)(^\[project\]\s*\n(?:(?!\[).)*?^version\s*=\s*")[^"\n]+("\s*$)'
    elif path == 'uv.lock':
        pattern = r'(?m)(^name = "codex-context-guard"\nversion = ")[^"\n]+("$)'
    else:
        return None
    result, count = re.subn(pattern, r'\1<version>\2', text)
    return result if count == 1 else None


def version_only(path: str, before: str, after: str) -> bool:
    left, right = _version_normalized(path, before), _version_normalized(path, after)
    return left is not None and left == right and before != after


def manifest_only(before: str, after: str, paths: list[str], versions: set[str], read_blob) -> bool:
    """Allow only verified changed documentation/version entries, never code."""
    try:
        old = json.loads(before, object_pairs_hook=_unique_pairs)
        new = json.loads(after, object_pairs_hook=_unique_pairs)
        if (set(old) != {'schema', 'file_count', 'files'} or set(new) != set(old)
                or old['schema'] != 'cg-distribution-manifest/v1' or new['schema'] != old['schema']
                or not isinstance(old['files'], dict) or not isinstance(new['files'], dict)
                or type(old['file_count']) is not int or type(new['file_count']) is not int
                or old['file_count'] != len(old['files']) or new['file_count'] != len(new['files'])):
            return False
        changed = {p for p in set(old['files']) | set(new['files'])
                   if old['files'].get(p) != new['files'].get(p)}
        docs = {'README.md', 'README.zh-CN.md', 'CHANGELOG.md', 'CHANGELOG.zh-CN.md',
                'SECURITY.md', 'CONTRIBUTING.md'}
        if not changed or not changed <= set(paths):
            return False
        for path in changed:
            if not (path in versions or path in docs or (path.startswith('docs/') and path.endswith('.md'))):
                return False
            for rev, entries in (('base', old['files']), ('head', new['files'])):
                if path in entries and hashlib.sha256(read_blob(rev, path)).hexdigest() != entries[path]:
                    return False
        return True
    except (ValueError, TypeError, KeyError, subprocess.CalledProcessError):
        return False


def select_profile(request: str, paths: list[str], version_only_paths=()) -> str:
    if request not in {"auto", "daily", "full"}:
        raise ValueError("unknown CI profile")
    if any((any(fnmatch.fnmatchcase(p, pattern) for pattern in FULL_PATHS)
            and p not in version_only_paths)
           or not any(fnmatch.fnmatchcase(p, pattern) for pattern in KNOWN_PATHS)
           and p not in version_only_paths
           for p in paths):
        return "full"
    return "full" if request == "full" else "daily"


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
        paths = [p for p in paths if p]
        versions = set()
        for path in set(paths) & {'pyproject.toml', 'uv.lock', '.codex-plugin/plugin.json'}:
            try:
                before = subprocess.check_output(['git', 'show', f'{args.base}:{path}']).decode('utf-8')
                after = subprocess.check_output(['git', 'show', f'{args.head}:{path}']).decode('utf-8')
                if version_only(path, before, after):
                    versions.add(path)
            except (subprocess.CalledProcessError, UnicodeDecodeError):
                pass
        manifest = '.codex-plugin/distribution-manifest.json'
        if manifest in paths:
            def read_blob(revision, path):
                commit = args.base if revision == 'base' else args.head
                return subprocess.check_output(['git', 'show', f'{commit}:{path}'])
            try:
                if manifest_only(read_blob('base', manifest).decode('utf-8'),
                                 read_blob('head', manifest).decode('utf-8'), paths, versions, read_blob):
                    versions.add(manifest)
            except (subprocess.CalledProcessError, UnicodeDecodeError):
                pass
        profile = select_profile(args.profile, paths, versions)
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"profile={profile}\n")
        print(json.dumps({"profile": profile, "required": required_jobs(profile, False)}))
    else:
        print(json.dumps(verify(args.profile, args.portable == "true", json.loads(args.needs_json))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
