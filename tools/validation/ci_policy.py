#!/usr/bin/env python3
"""Select daily or full portability coverage, and verify its required jobs."""
from __future__ import annotations

import argparse
import ast
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
    "scripts/smoke_installed.py", "scripts/run_current_behavior_suite.py",
    "scripts/check_phase3_transition.py", "scripts/audit_commit_identity.py",
    "scripts/validate_public_repo.py", "scripts/audit_public_tree.py",
    "tools/validation/ci_policy.py",
    "tools/validation/select_validation.py", "tools/validation/run_selected_validation.py",
    "tools/validation/verify_required_jobs.py", "tools/validation/ci_reuse.py",
    "tools/validation/run_windows_platform_suite.py", "tools/validation/validate_workflows.py",
    "tools/validation/CI_POLICY.md", "tests/test_ci_policy.py", "tests/test_ci_reuse.py",
    "tests/test_validation_selection.py", "tests/test_selected_validation.py",
    "tests/test_required_jobs.py", "tests/test_public_contract.py",
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


# Curated ownership groups are deliberately explicit. In particular the native
# verifier suite uses dynamic imports that the static importer scan cannot see.
TEST_GROUPS = {
    "tests/test_daily_upgrade.py": ("tests.test_daily_upgrade", "tests.test_native_between_turns_acceptance", "tests.test_native_between_turns_acceptance_families"),
    "tests/test_native_between_turns_acceptance.py": ("tests.test_native_between_turns_acceptance", "tests.test_native_between_turns_acceptance_families"),
    "tests/test_native_between_turns_acceptance_families.py": ("tests.test_native_between_turns_acceptance_families",),
    "tests/test_native_between_turns_startup.py": ("tests.test_native_between_turns_startup",),
    "tests/test_native_state_capture.py": ("tests.test_native_state_capture",),
    "tests/test_private_upgrade_output.py": ("tests.test_private_upgrade_output",),
}
TEST_LANES = ("selected_ubuntu_py310", "selected_ubuntu_py314",
              "selected_macos_py312", "selected_windows_py312")


def test_modules_for_diff(root: Path, base: str, head: str) -> tuple[str, ...] | None:
    """Select only a complete, explicitly reviewed test-only change group.

    Both endpoints must be commits in this repository, base must be an
    ancestor, and the selected runner must execute the exact head checkout.
    Any unrecognised or non-modification path falls back to existing coverage.
    """
    from tools.validation import select_validation

    if not re.fullmatch(r"[0-9a-f]{40}", base) or not re.fullmatch(r"[0-9a-f]{40}", head) or base == head:
        return None
    try:
        def git(*args):
            return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)
        if git("rev-parse", "HEAD^{commit}").decode().strip() != head:
            return None
        git("merge-base", "--is-ancestor", base, head)
        # The selected tests import product and tool code as well as tests.
        # Bind every non-ignored checkout input to the stated exact head.
        git("diff", "--quiet", head, "--")
        if git("ls-files", "--others", "--exclude-standard"):
            return None
        raw = git("diff", "--name-status", "--no-renames", "-z", base, head, "--").decode("utf-8", "strict").split("\0")
        if raw[-1:] != [""]:
            return None
        items = raw[:-1]
        if not items or len(items) % 2:
            return None
        changes = list(zip(items[::2], items[1::2]))
        if any(status != "M" or path not in TEST_GROUPS for status, path in changes):
            return None
        # Read the exact parent map rather than accepting a candidate-supplied
        # map. Any policy/map/runner change also makes the diff ineligible.
        map_bytes = git("show", f"{base}:validation-map.json")
        map_path = root / "validation-map.json"
        if map_path.read_bytes() != map_bytes:
            return None
        mapping, digest = select_validation.load_map(map_path)
        plan = select_validation.classify(mapping, [path for _, path in changes],
                                          map_sha256=digest, base=base, head=head)
        if (plan["matched_rules"] != ["tests"] or plan["unknown_paths"]
                or set(plan["gates"]) != {"focused_tests", "repo_contract"}
                or set(plan["invalidates"]) != {"candidate_matrix"}):
            return None
        # Only test method bodies may change; module-level fixtures, shared
        # setup, imports, decorators and dynamic-loader calls remain identical.
        def signature(source):
            tree = ast.parse(source)
            dynamic = [ast.dump(node, include_attributes=False) for node in ast.walk(tree)
                       if isinstance(node, ast.Call) and (
                           isinstance(node.func, ast.Name) and node.func.id in ("__import__", "eval", "exec")
                           or isinstance(node.func, ast.Attribute) and node.func.attr in ("spec_from_file_location", "import_module"))]
            test_imports = [ast.dump(node, include_attributes=False) for node in ast.walk(tree)
                            if isinstance(node, ast.ImportFrom) and (node.level or (node.module or "").startswith("tests"))
                            or isinstance(node, ast.Import) and any(alias.name.startswith("tests") for alias in node.names)]
            test_names = [(cls.name, method.name) for cls in tree.body if isinstance(cls, ast.ClassDef)
                          for method in cls.body if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                          and method.name.startswith("test_") and not method.decorator_list]
            if len(test_names) != len(set(test_names)):
                raise ValueError("duplicate test methods")
            for cls in (item for item in tree.body if isinstance(item, ast.ClassDef)):
                cls.body = [method for method in cls.body if not (
                    isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith("test_")
                    and not method.decorator_list)]
            return (ast.dump(tree, include_attributes=False), dynamic, test_imports), set(test_names)
        for _, path in changes:
            old_mode = git("ls-tree", base, "--", path).split(None, 1)[0]
            new_mode = git("ls-tree", head, "--", path).split(None, 1)[0]
            if old_mode != b"100644" or new_mode != old_mode:
                return None
            old_sig, old_tests = signature(git("show", f"{base}:{path}").decode("utf-8", "strict"))
            new_sig, new_tests = signature(git("show", f"{head}:{path}").decode("utf-8", "strict"))
            if old_sig != new_sig or not old_tests or not old_tests <= new_tests:
                return None
        from tools.validation.run_selected_validation import focused_modules
        # Alternate both edge types to a fixed point. A static importer may
        # itself have registered dynamic importers, and vice versa.
        seeds = {path for _, path in changes}
        while True:
            for path in tuple(seeds):
                seeds.update(module.replace(".", "/") + ".py" for module in TEST_GROUPS.get(path, ()))
            selected = focused_modules(sorted(seeds), root)
            if not selected:
                return None
            expanded = {module.replace(".", "/") + ".py" for module in selected}
            if expanded <= seeds:
                return tuple(selected)
            seeds.update(expanded)
    except (OSError, UnicodeError, SyntaxError, ValueError, IndexError, subprocess.CalledProcessError):
        return None


def required_jobs(profile: str, portable: bool, reuse: bool = False) -> list[str]:
    if profile not in {"tests", "daily", "full"}:
        raise ValueError("resolved CI profile must be tests, daily or full")
    if profile == "tests":
        if portable or reuse:
            raise ValueError("test profile cannot consume artifact or full reuse")
        return ["classify", "static", "ci_reuse", *TEST_LANES]
    if reuse and profile != "full":
        raise ValueError("exact-commit reuse applies only to the full profile")
    if reuse:
        # A confirmed reuse consumes a prior full run on the exact commit;
        # the lanes it already passed stay exempt, and the summary still
        # demands the classification, the static gate and the reuse evidence
        # job of this run.
        return ["classify", "static", "ci_reuse"]
    lanes = [row[0] for row in CI_LANES if profile == "full" or row[0] in DAILY_FULL]
    if profile == "daily":
        lanes.extend(DAILY_FOCUSED)
    return ["classify", "static", *lanes, *(["portable_windows"] if portable else [])]


def verify(profile: str, portable: bool, needs: dict, reuse: bool = False) -> dict:
    required = required_jobs(profile, portable, reuse)
    observed = {k: v["result"] for k, v in needs.items()}
    if reuse or profile == "tests":
        # Reuse never widens what may fail: every other job of this run must
        # be a success or an unselected skip — a failed or cancelled job
        # anywhere still fails the summary.
        broken = sorted(job for job, result in observed.items()
                        if job not in required
                        and result in ("failure", "cancelled"))
        if broken:
            from tools.validation.verify_required_jobs import SummaryError
            raise SummaryError("required jobs did not pass: non_success=" + ",".join(broken))
    return evaluate(required, observed)


def verify_pr(profile: str, needs: dict) -> dict:
    if profile not in {"tests", "daily", "full"}:
        raise ValueError("unknown PR profile")
    observed = {key: value["result"] for key, value in needs.items()}
    required = ["classify", "selected_validation"] + (list(TEST_LANES) if profile == "tests" else [])
    broken = [job for job, result in observed.items() if job not in required and result in ("failure", "cancelled")]
    if broken:
        from tools.validation.verify_required_jobs import SummaryError
        raise SummaryError("unexpected PR job failed or was cancelled: " + ", ".join(sorted(broken)))
    return evaluate(required, observed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    select = sub.add_parser("select")
    select.add_argument("--profile", choices=("auto", "daily", "full"), default="auto")
    select.add_argument("--base", required=True)
    select.add_argument("--head", required=True)
    select.add_argument("--github-output", type=Path, required=True)
    pr = sub.add_parser("verify-pr")
    pr.add_argument("--profile", required=True)
    pr.add_argument("--needs-json", required=True)
    summary = sub.add_parser("verify")
    summary.add_argument("--profile", required=True)
    summary.add_argument("--portable", choices=("true", "false"), required=True)
    summary.add_argument("--needs-json", required=True)
    summary.add_argument("--reuse", choices=("true", "false"), default="false",
                         help="a ci_reuse receipt confirmed a prior full run on this exact commit")
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
        if args.profile == "auto" and profile == "daily" and test_modules_for_diff(Path.cwd(), args.base, args.head):
            profile = "tests"
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"profile={profile}\n")
            stream.write(f"base={args.base}\nhead={args.head}\n")
        print(json.dumps({"profile": profile, "required": required_jobs(profile, False)}))
    elif args.command == "verify-pr":
        print(json.dumps(verify_pr(args.profile, json.loads(args.needs_json))))
    else:
        print(json.dumps(verify(args.profile, args.portable == "true",
                                json.loads(args.needs_json),
                                reuse=args.reuse == "true")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
