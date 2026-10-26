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
import contextlib
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

MARKETPLACE = "codex-context-guard"
PLUGIN_NAME = "context-guard"
PLUGIN_ID = "context-guard@codex-context-guard"
MINIMUM_CODEX = (0, 146, 0)
IGNORED_TREE_NAMES = {
    ".DS_Store",
    ".codex",
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "Thumbs.db",
    "__pycache__",
    "build",
    "dist",
}
PLUGIN_TREE_ROOTS: set[str] | None = {".codex-plugin", "assets", "hooks", "scripts", "skills"}
# The staging artifact is built from an allowlist, never from a blacklist:
# only these roots and doc files may enter the distribution, and any other
# top-level repository entry (an `.env`, a private note, a scratch checkout)
# fails the build instead of being copied silently.
DISTRIBUTION_TREE_ROOTS = (".codex-plugin", "assets", "hooks", "scripts", "skills")
DISTRIBUTION_DOC_FILES = (
    ".codexignore",
    "CHANGELOG.md",
    "CHANGELOG.zh-CN.md",
    "LICENSE",
    "README.md",
    "README.zh-CN.md",
    "SECURITY.md",
    "pyproject.toml",
)
# The host reads this manifest when registering the marketplace directory, so
# it ships with the distribution; every other file under .agents is rejected.
DISTRIBUTION_NESTED_FILES = (".agents/plugins/marketplace.json",)
NON_DISTRIBUTION_TOP_LEVEL = {
    ".DS_Store",
    ".codex",
    ".git",
    ".gitattributes",
    ".github",
    ".gitignore",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "Thumbs.db",
    "__pycache__",
    "build",
    "contracts",
    "dist",
    "docs",
    "requirements-lock.txt",
    "tests",
    "tools",
    "uv.lock",
    "validation-map.json",
}
ARCHIVE_INDEX_NAME = "archive-index.json"
ARCHIVE_SCHEMA_VERSION = 1
PRESERVATION_ROOT_NAME = ".historical-cache-preservation"
PRESERVATION_INDEX_NAME = "preservation-index.json"
PRESERVATION_SCHEMA_VERSION = 1
SEMVER_RE = re.compile(
    r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2}(?:[-+][0-9A-Za-z.-]+)?"
)


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


def plugin_repository(root: Path) -> str | None:
    manifest_path = root / ".codex-plugin" / "plugin.json"
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if value.get("name") != PLUGIN_NAME:
        return None
    repository = value.get("repository")
    return repository if isinstance(repository, str) else None


def prior_managed_marketplace_root(
    value: str | Path, codex_home: Path, repo_root: Path
) -> bool:
    """Recognize a previous pinned checkout or its sanitized staging root."""
    supplied = Path(value).expanduser()
    if supplied.is_symlink():
        return False
    candidate = supplied.resolve()
    managed_parent = (
        codex_home.expanduser().resolve() / "upstreams" / PLUGIN_NAME
    )
    if candidate.parent != managed_parent or not candidate.is_dir():
        return False
    pinned_checkout = bool(
        re.fullmatch(r"[0-9a-f]{40}(?:\.marketplace)?", candidate.name)
        or candidate.name == f"{MARKETPLACE}.marketplace"
    )
    named_staging = bool(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.marketplace", candidate.name)
    )
    if not (pinned_checkout or named_staging):
        return False
    if named_staging and embedded_git_metadata(candidate) is not None:
        return False
    expected_repository = plugin_repository(repo_root)
    return bool(
        expected_repository
        and plugin_repository(candidate) == expected_repository
    )


DISTRIBUTION_MANIFEST_RELATIVE = ".codex-plugin/distribution-manifest.json"
DISTRIBUTION_SCAN_AREAS = tuple(DISTRIBUTION_TREE_ROOTS) + (".agents",)


def _reject_unsafe_distribution_entry(path: Path) -> None:
    """Links, reparse points and special files never enter the distribution."""
    if path.is_symlink():
        raise RuntimeError(f"unsafe link in distribution tree: {path}")
    info = path.lstat()
    if getattr(info, "st_reparse_tag", 0):
        raise RuntimeError(f"reparse point in distribution tree: {path}")
    if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode):
        return
    raise RuntimeError(f"unsupported entry type in distribution tree: {path}")


def _reject_unsafe_ancestors(source_root: Path, relative: str) -> None:
    """Every ancestor of a distribution file must be a real directory.

    A symbolic link or reparse point anywhere on the ancestor chain (for
    example ``.agents/plugins`` pointing outside the checkout) is rejected
    before any byte of the final entry is read.
    """
    parts = PurePosixPath(relative).parts
    for depth in range(1, len(parts)):
        ancestor = source_root.joinpath(*parts[:depth])
        _reject_unsafe_distribution_entry(ancestor)
    _reject_unsafe_distribution_entry(source_root / relative)


def _reject_unsafe_manifest_path(source_root: Path) -> None:
    """Reject a missing, linked, or oddly-anchored manifest before any read.

    The manifest and every one of its ancestors must be real on-disk
    directories/regular files inside the source; a symlink (including a
    link to an external manifest) or reparse ancestor is refused without
    reading a single byte.
    """
    path = source_root / DISTRIBUTION_MANIFEST_RELATIVE
    if not path.exists() and not path.is_symlink():
        raise RuntimeError(
            f"the reviewed distribution manifest is missing ({path}); the "
            "distribution set cannot be established without it. Regenerate "
            "it with `python scripts/manage_plugin.py "
            "--write-distribution-manifest` after review"
        )
    _reject_unsafe_ancestors(source_root, DISTRIBUTION_MANIFEST_RELATIVE)


def load_distribution_manifest(source_root: Path) -> dict:
    """Read the committed per-file release set; fail closed when unusable.

    Missing, malformed, symlinked, or externally anchored manifests are
    refused before their bytes are read; there is no structural fallback in
    the production builder.
    """
    path = source_root / DISTRIBUTION_MANIFEST_RELATIVE
    _reject_unsafe_manifest_path(source_root)
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"the reviewed distribution manifest is unreadable "
            f"({path}): {exc}; regenerate it with "
            "`python scripts/manage_plugin.py --write-distribution-manifest`"
        ) from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != (
        "cg-distribution-manifest/v1"
    ):
        raise RuntimeError(
            f"{path} does not carry schema cg-distribution-manifest/v1"
        )
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise RuntimeError(f"{path} lists no distribution files")
    for relative, digest in files.items():
        if not isinstance(relative, str) or not isinstance(digest, str):
            raise RuntimeError(f"{path} has a malformed entry: {relative!r}")
        if relative.endswith(("/",)) or "\\" in relative or ".." in relative.split("/"):
            raise RuntimeError(f"{path} has an unsafe path entry: {relative!r}")
    return manifest


def _expected_distribution(source_root: Path) -> dict[str, str]:
    """The exact reviewed set a source must stage, with digests.

    Strict only: a missing, corrupt, or linked manifest is refused by the
    loader; there is no fallback that could adopt unreviewed files.
    """
    manifest = load_distribution_manifest(source_root)
    return _checked_distribution_files(
        source_root, manifest, verify_hashes=True
    )


def _full_tree_digests(tree_root: Path) -> dict[str, str]:
    """Digest EVERY object present under a tree; nothing is ignored.

    This is the target side of the exact-set comparison, so any extra
    object — bytecode caches, private files, directory symlinks — makes the
    tree mismatch. Link entries are recorded as ``link:`` markers without
    reading through them; regular files and bytecode are hashed as data.
    Source-side development-cache exclusion does not apply here.
    """
    digests: dict[str, str] = {}
    if not tree_root.is_dir():
        return digests

    def record(relative: str, marker: str) -> None:
        if relative in digests:
            raise RuntimeError(f"duplicate object in tree: {relative}")
        digests[relative] = marker

    for current, dirnames, filenames in os.walk(tree_root):
        for name in sorted(dirnames):
            candidate = Path(current) / name
            relative = candidate.relative_to(tree_root).as_posix()
            if candidate.is_symlink():
                record(relative, "link:directory")
                dirnames.remove(name)
            else:
                info = candidate.lstat()
                if getattr(info, "st_reparse_tag", 0):
                    record(relative, "reparse:directory")
                    dirnames.remove(name)
        for name in sorted(filenames):
            candidate = Path(current) / name
            relative = candidate.relative_to(tree_root).as_posix()
            if candidate.is_symlink():
                record(relative, "link:file")
                continue
            info = candidate.lstat()
            if getattr(info, "st_reparse_tag", 0):
                record(relative, "reparse:file")
                continue
            if not stat.S_ISREG(info.st_mode):
                record(relative, f"special:{info.st_mode:o}")
                continue
            digests[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    return digests


def _checked_distribution_files(
    source_root: Path, manifest: dict, *, verify_hashes: bool
) -> dict[str, str]:
    """Resolve the manifest against the source and reject every deviation.

    Both directions are enforced: a listed file that is missing, unsafe or
    (optionally) hash-drifted fails, and any regular file found inside the
    distribution areas that the manifest does not list also fails, so
    untracked private files (``scripts/.env``) can never ride along.
    """
    listed: dict[str, str] = dict(manifest["files"])
    listed[DISTRIBUTION_MANIFEST_RELATIVE] = ""
    observed: set[str] = set()

    def note(relative: str, path: Path) -> None:
        if relative in observed:
            raise RuntimeError(f"duplicate distribution path: {relative}")
        if relative not in listed:
            raise RuntimeError(
                f"unreviewed file inside the distribution set: {relative}; "
                "add it to .codex-plugin/distribution-manifest.json via "
                "`--write-distribution-manifest` after review, or remove it"
            )
        _reject_unsafe_ancestors(source_root, relative)
        observed.add(relative)

    for top in DISTRIBUTION_SCAN_AREAS:
        area = source_root / top
        if not area.exists():
            continue
        _reject_unsafe_distribution_entry(area)
        for current, dirnames, filenames in os.walk(area):
            dirnames[:] = sorted(
                name for name in dirnames if name not in IGNORED_TREE_NAMES
            )
            for name in sorted(dirnames):
                _reject_unsafe_distribution_entry(Path(current) / name)
            for name in sorted(filenames):
                if name in IGNORED_TREE_NAMES or name.endswith((".pyc", ".pyo")):
                    continue
                candidate = Path(current) / name
                _reject_unsafe_distribution_entry(candidate)
                note(candidate.relative_to(source_root).as_posix(), candidate)
    for name in DISTRIBUTION_DOC_FILES:
        candidate = source_root / name
        if candidate.exists() or candidate.is_symlink():
            note(name, candidate)

    missing = sorted(set(listed) - observed)
    if missing:
        raise RuntimeError(
            "reviewed distribution files are missing from the source: "
            + ", ".join(missing[:5])
            + ("..." if len(missing) > 5 else "")
        )
    digests: dict[str, str] = {}
    for relative in sorted(observed):
        if relative == DISTRIBUTION_MANIFEST_RELATIVE:
            digests[relative] = hashlib.sha256(
                (source_root / relative).read_bytes()
            ).hexdigest()
            continue
        digest = hashlib.sha256(
            (source_root / relative).read_bytes()
        ).hexdigest()
        if verify_hashes and listed[relative] and digest != listed[relative]:
            raise RuntimeError(
                f"distribution file {relative} does not match its reviewed "
                "sha256 in .codex-plugin/distribution-manifest.json; review "
                "the change and regenerate the manifest"
            )
        digests[relative] = digest
    return digests


def distribution_manifest(root: Path) -> dict[str, str]:
    """Exact digest set of the reviewed distribution present at ``root``."""
    if not root.is_dir():
        return {}
    return _expected_distribution(root)


def _distribution_matches(source_root: Path, staged_root: Path) -> bool:
    """True when staged bytes equal the expected set exactly, both ways.

    The staged side is enumerated in full (no allowlist projection), so an
    extra file planted in an existing staging directory forces a rebuild
    instead of a no-op.
    """
    try:
        expected = _expected_distribution(source_root)
    except RuntimeError:
        return False
    return _full_tree_digests(staged_root) == expected


def build_distribution_tree(source_root: Path, destination: Path) -> None:
    """Materialize the reviewed distribution into a fresh destination."""
    expected = _expected_distribution(source_root)
    destination.mkdir(parents=True)
    for relative in sorted(expected):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / relative, target)
    copied = _full_tree_digests(destination)
    if copied != expected:
        raise RuntimeError(
            "distribution staging failed exact-set verification: "
            f"extra={sorted(set(copied) - set(expected))[:5]} "
            f"missing={sorted(set(expected) - set(copied))[:5]} "
            f"changed={[k for k in sorted(set(copied) & set(expected)) if copied[k] != expected[k]][:5]}"
        )


def write_distribution_manifest(source_root: Path) -> Path:
    """Regenerate the committed manifest from the current distribution set."""
    probe = source_root / DISTRIBUTION_MANIFEST_RELATIVE
    if probe.is_file():
        current = load_distribution_manifest(source_root)
        listed = set(current["files"])
    else:
        listed = set()
    observed: set[str] = set()

    def is_plain_object(candidate: Path) -> bool:
        """Area roots keep their canonical names (``.codex-plugin``); files
        inside must not be dot-prefixed, linked, reparse, or special."""
        try:
            _reject_unsafe_distribution_entry(candidate)
        except RuntimeError:
            return False
        return True

    def acceptable_file(candidate: Path) -> bool:
        if candidate.name.startswith(".") or candidate.name.startswith("~"):
            return False
        return is_plain_object(candidate)

    for top in DISTRIBUTION_SCAN_AREAS:
        area = source_root / top
        if not area.exists() or not is_plain_object(area):
            continue
        for current_dir, dirnames, filenames in os.walk(area):
            kept = []
            for name in sorted(dirnames):
                if name in IGNORED_TREE_NAMES:
                    continue
                if acceptable_file(Path(current_dir) / name):
                    kept.append(name)
            dirnames[:] = kept
            for name in sorted(filenames):
                if name in IGNORED_TREE_NAMES or name.endswith((".pyc", ".pyo")):
                    continue
                candidate = Path(current_dir) / name
                if acceptable_file(candidate):
                    observed.add(
                        candidate.relative_to(source_root).as_posix()
                    )
    for name in DISTRIBUTION_DOC_FILES:
        candidate = source_root / name
        # The doc list is itself the reviewed allowance: an explicitly listed
        # dotted name (``.codexignore``) is accepted as-is; the dot-prefix
        # exclusion applies to unlisted files inside the areas.
        if candidate.is_file() and is_plain_object(candidate):
            observed.add(name)
    # The manifest file is a distribution member but cannot enumerate itself:
    # dropping it here separates "the manifest file exists" from "a genuinely
    # new distribution file", so ordinary regeneration and digest updates of
    # already-listed files work while truly new files still require explicit
    # adoption.
    observed.discard(DISTRIBUTION_MANIFEST_RELATIVE)
    untracked = sorted(observed - listed)
    if untracked and probe.is_file():
        raise RuntimeError(
            "refusing to silently adopt new distribution files; review and "
            "re-run with --adopt-distribution-files to include: "
            + ", ".join(untracked[:10])
        )
    files = {}
    for relative in sorted(observed | listed):
        path = source_root / relative
        if not path.is_file():
            continue
        files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {
        "schema": "cg-distribution-manifest/v1",
        "description": (
            "Reviewed per-file release set; the installer refuses any "
            "distribution entry missing from or added to this list."
        ),
        "file_count": len(files),
        "files": dict(sorted(files.items())),
    }
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return probe


def marketplace_staging(
    codex_home: Path,
    repo_root: Path,
    *,
    keep_replaced_bytes: Path | None = None,
) -> Path:
    """Return a sanitized marketplace root for the Codex CLI to clone from.

    The Codex CLI materializes plugin caches from the registered marketplace
    directory without filtering, so registering the verified immutable Git
    checkout directly leaks its ``.git`` metadata into the live cache whenever
    the CLI refreshes the cache (the trusted-archive repair only runs under
    ``--apply``). Registering an on-disk copy of the exact distribution
    allowlist removes both that possibility and every other repository-only
    or private file. When ``keep_replaced_bytes`` names a path, the previous
    staged bytes are preserved there for installation-transaction rollback
    instead of being destroyed.
    """
    manifest_path = repo_root / DISTRIBUTION_MANIFEST_RELATIVE
    if not manifest_path.exists() and not manifest_path.is_symlink():
        # A source without any manifest cannot be silently downgraded to an
        # adopt-anything fallback. A git checkout whose tracked manifest is
        # absent is a deletion and fails closed; a foreign/non-git source
        # gets an explicit generated manifest (a visible artifact) before
        # the strict build, and the product repository always carries its
        # committed manifest so production install never bootstraps.
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch",
             DISTRIBUTION_MANIFEST_RELATIVE],
            cwd=repo_root, capture_output=True)
        if tracked.returncode == 0 or embedded_git_metadata(repo_root) is not None:
            raise RuntimeError(
                f"the reviewed distribution manifest is missing from a git "
                f"source ({manifest_path}); restore it from history or "
                "regenerate it with `--write-distribution-manifest` after "
                "review"
            )
        write_distribution_manifest(repo_root)
        print(
            "[BOOTSTRAP] generated reviewed distribution manifest for a "
            f"non-git source: {manifest_path}")
    staged = marketplace_staging_root(codex_home, repo_root)
    if staged.is_dir() and _distribution_matches(repo_root, staged):
        if embedded_git_metadata(staged) is None:
            return staged
    # A contaminated or drifted staging root is rebuilt from the reviewed
    # set, never accepted as a no-op: extra files in the staging directory
    # would otherwise be copied verbatim by the host.
    staged.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".marketplace-", dir=staged.parent))
    replaced_backup: Path | None = None
    try:
        filtered = temporary / "tree"
        build_distribution_tree(repo_root, filtered)
        if embedded_git_metadata(filtered) is not None:
            raise RuntimeError("sanitized marketplace staging still carries Git metadata")
        if staged.exists():
            replaced_backup = staged.with_name(f".{staged.name}.replaced-{os.getpid()}")
            if replaced_backup.exists():
                shutil.rmtree(replaced_backup)
            os.replace(staged, replaced_backup)
        os.replace(filtered, staged)
        if replaced_backup is not None and keep_replaced_bytes is not None:
            if keep_replaced_bytes.exists():
                shutil.rmtree(keep_replaced_bytes)
            os.replace(replaced_backup, keep_replaced_bytes)
            replaced_backup = None
    finally:
        if replaced_backup is not None and replaced_backup.exists() and staged.exists():
            shutil.rmtree(replaced_backup, ignore_errors=True)
        shutil.rmtree(temporary, ignore_errors=True)
    print(f"[OK] staged sanitized marketplace root: {staged}")
    return staged


def ensure_marketplace(
    codex: str,
    repo_root: Path,
    codex_home: Path,
    apply: bool,
    txn: dict | None = None,
) -> bool:
    staging = marketplace_staging_root(codex_home, repo_root)
    if txn is not None:
        txn["staging"] = staging
        txn.setdefault("stages", []).append("staging_resolved")
    keep_replaced_bytes = txn.get("staging_backup_slot") if txn else None
    entry = marketplace_entry(codex)
    if txn is not None:
        txn["prior_entry"] = entry
    if entry is not None:
        root = entry.get("root")
        source = entry.get("marketplaceSource", {}).get("source")
        known = {value for value in (root, source) if value}
        if any(same_path(value, staging) for value in known):
            if apply:
                marketplace_staging(
                    codex_home, repo_root, keep_replaced_bytes=keep_replaced_bytes
                )
            elif (
                not staging.is_dir()
                or not _distribution_matches(repo_root, staging)
                or embedded_git_metadata(staging) is not None
            ):
                raise RuntimeError(
                    f"marketplace {MARKETPLACE!r} points to a stale or missing "
                    "sanitized staging root; run --apply to refresh it"
                )
            print(f"[OK] marketplace {MARKETPLACE} points to {staging}")
            return False
        points_at_current_checkout = any(
            same_path(value, repo_root) for value in known
        )
        points_at_prior_managed_root = bool(known) and all(
            prior_managed_marketplace_root(
                value, codex_home, repo_root
            )
            for value in known
        )
        if points_at_current_checkout or points_at_prior_managed_root:
            if not apply:
                raise RuntimeError(
                    f"marketplace {MARKETPLACE!r} still points at a Git checkout "
                    "or prior managed staging root; "
                    "run --apply to repoint it at the sanitized staging root"
                )
            marketplace_staging(
                codex_home, repo_root, keep_replaced_bytes=keep_replaced_bytes
            )
            if txn is not None:
                txn.setdefault("stages", []).append("staging_replaced")
            run(codex, "plugin", "marketplace", "remove", MARKETPLACE)
            if txn is not None:
                # Recorded before the add attempt: a failure here is exactly
                # the state the rollback must restore (prior registration).
                txn["registration_removed"] = True
                txn.setdefault("stages", []).append("registration_removed")
            run(codex, "plugin", "marketplace", "add", str(staging), "--json")
            if txn is not None:
                txn["reregistered"] = True
                txn.setdefault("stages", []).append("registration_repointed")
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
    marketplace_staging(
        codex_home, repo_root, keep_replaced_bytes=keep_replaced_bytes
    )
    if txn is not None:
        txn.setdefault("stages", []).append("staging_created")
    run(codex, "plugin", "marketplace", "add", str(staging), "--json")
    if txn is not None:
        txn["registered_fresh"] = True
        txn.setdefault("stages", []).append("registration_added")
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


def full_file_manifest(root: Path) -> dict[str, str]:
    """Hash every regular file in a cache tree and reject unsafe entries."""
    if not root.is_dir():
        return {}
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part == ".git" for part in relative.parts):
            raise RuntimeError(f"embedded Git metadata in cache tree: {path}")
        if path.is_symlink():
            raise RuntimeError(f"unsafe symlink in cache tree: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RuntimeError(f"unsupported entry in cache tree: {path}")
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


def historical_preservation_root(archive_root: Path) -> Path:
    """Keep recovery data outside the Codex-owned live-cache hierarchy."""
    return archive_root.parent / PRESERVATION_ROOT_NAME


def _load_preservation_index(root: Path) -> dict[str, dict[str, str]]:
    index_path = root / PRESERVATION_INDEX_NAME
    try:
        value = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"historical cache preservation index is unreadable: {index_path}"
        ) from exc
    versions = value.get("versions") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != PRESERVATION_SCHEMA_VERSION
        or not isinstance(versions, dict)
        or not versions
    ):
        raise RuntimeError("historical cache preservation index is invalid")
    for version, manifest in versions.items():
        if (
            not isinstance(version, str)
            or not SEMVER_RE.fullmatch(version)
            or not isinstance(manifest, dict)
            or not manifest
        ):
            raise RuntimeError("historical cache preservation entry is invalid")
        if any(
            not isinstance(name, str)
            or Path(name).is_absolute()
            or ".." in Path(name).parts
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for name, digest in manifest.items()
        ):
            raise RuntimeError(
                f"historical cache preservation hashes are invalid for {version}"
            )
    return versions


def prepare_historical_cache_preservation(
    cache_root: Path, archive_root: Path, desired_version: str
) -> list[str]:
    """Preserve non-product live differences before Codex replaces the cache root."""
    preservation = historical_preservation_root(archive_root)
    if preservation.exists():
        raise RuntimeError(
            "historical cache preservation transaction is already pending"
        )
    trusted = _archive_index(archive_root)
    candidates: list[tuple[str, Path, dict[str, str]]] = []
    for version in sorted(trusted):
        if version == desired_version:
            continue
        live = cache_root / version
        archived = archive_root / version
        live_manifest = full_file_manifest(live)
        archived_manifest = full_file_manifest(archived)
        if live_manifest != archived_manifest:
            if tree_manifest(live) != trusted[version]:
                raise RuntimeError(
                    f"historical live cache {version} has untrusted product drift"
                )
            candidates.append((version, live, live_manifest))
    if not candidates:
        return []

    preservation.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{PRESERVATION_ROOT_NAME}.staged-",
            dir=preservation.parent,
        )
    )
    try:
        versions_root = temporary / "versions"
        manifests: dict[str, dict[str, str]] = {}
        for version, live, manifest in candidates:
            target = versions_root / version
            shutil.copytree(live, target)
            if full_file_manifest(target) != manifest:
                raise RuntimeError(
                    f"historical live cache {version} could not be preserved"
                )
            manifests[version] = manifest
        _atomic_json(
            temporary / PRESERVATION_INDEX_NAME,
            {
                "schema_version": PRESERVATION_SCHEMA_VERSION,
                "versions": manifests,
            },
        )
        os.replace(temporary, preservation)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
    return [version for version, _, _ in candidates]


def restore_historical_cache_preservation(
    cache_root: Path, archive_root: Path
) -> list[str]:
    """Restore and verify a completed preservation transaction."""
    preservation = historical_preservation_root(archive_root)
    if not preservation.exists():
        return []
    versions = _load_preservation_index(preservation)
    versions_root = preservation / "versions"
    for version, expected in sorted(versions.items()):
        preserved = versions_root / version
        if full_file_manifest(preserved) != expected:
            raise RuntimeError(
                f"historical cache preservation failed verification for {version}"
            )
    for version, expected in sorted(versions.items()):
        _replace_tree_atomically(versions_root / version, cache_root / version)
        if full_file_manifest(cache_root / version) != expected:
            raise RuntimeError(
                f"historical live cache {version} could not be restored"
            )
    shutil.rmtree(preservation)
    return sorted(versions)


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
                "or contains embedded Git metadata; if a fresh Codex task start "
                "pruned historical live caches, run scripts/manage_plugin.py "
                "--apply to restore this tree from its trusted archive"
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


@contextmanager
def _maybe_install_lock(cache_root: Path, enabled: bool) -> Iterator[None]:
    """Acquire the install lock, unless an outer transaction already holds it."""
    if enabled:
        with cache_install_lock(cache_root):
            yield
        return
    yield


def same_version_drift_preflight(
    codex: str, repo_root: Path, codex_home: Path
) -> bool:
    """Refuse an unresolvable same-version drift before any staged mutation.

    Returns True when the installed entry matches the desired version. A live
    cache that a trusted archive can restore to the exact source manifest
    keeps the healthy in-place repair path inside ensure_plugin; every other
    same-version difference raises the identical refusal here, before the
    marketplace staging or registration can change, so a rejected upgrade
    never leaves a mixed-identity installation.
    """
    source_root = source_plugin_root(repo_root)
    desired_version = source_plugin_version(source_root)
    cache_root = plugin_cache_root(codex_home)
    archive_root = cache_archive_root(codex_home)
    entry = plugin_entry(codex)
    if entry is None or entry.get("version") != desired_version:
        return False
    require_no_embedded_git_metadata(cache_root, archive_root, desired_version)
    if not tree_difference(source_root, cache_root / desired_version):
        return True
    versions = _archive_index(archive_root)
    if desired_version in versions and not tree_difference(
        source_root, archive_root / desired_version
    ):
        # ensure_plugin restores the live tree from this trusted archive and
        # re-checks parity afterwards; that repair path stays where it was.
        return True
    require_cache_parity(
        source_root,
        cache_root / desired_version,
        desired_version,
        same_version=True,
    )
    return True


def ensure_plugin(
    codex: str, repo_root: Path, codex_home: Path, apply: bool, *, lock: bool = True
) -> bool:
    source_root = source_plugin_root(repo_root)
    desired_version = source_plugin_version(source_root)
    cache_root = plugin_cache_root(codex_home)
    archive_root = cache_archive_root(codex_home)
    entry = plugin_entry(codex)
    was_installed = entry is not None

    preservation = historical_preservation_root(archive_root)
    if preservation.exists():
        if not apply:
            raise RuntimeError(
                "an interrupted historical cache preservation transaction is pending; "
                "run with --apply to restore it before continuing"
            )
        with _maybe_install_lock(cache_root, lock):
            restored = restore_historical_cache_preservation(cache_root, archive_root)
        if restored:
            print(
                "[OK] recovered interrupted historical cache preservation: "
                + ", ".join(restored)
            )
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
        with _maybe_install_lock(cache_root, lock):
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

    with _maybe_install_lock(cache_root, lock):
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
            preserved = prepare_historical_cache_preservation(
                cache_root, archive_root, desired_version
            )
            try:
                run(codex, "plugin", "add", PLUGIN_ID, "--json")
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
            finally:
                restored = restore_historical_cache_preservation(
                    cache_root, archive_root
                )
            if restored != preserved:
                raise RuntimeError(
                    "historical cache preservation restored an unexpected version set"
                )
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
            if restored:
                print(
                    "[OK] preserved historical live cache file tree(s): "
                    + ", ".join(restored)
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
    require_no_embedded_git_metadata(cache_root, archive_root, desired_version)
    if not entry.get("enabled"):
        raise RuntimeError(
            f"plugin {PLUGIN_ID!r} is installed but disabled; apply the shared config"
        )
    action = "updated" if was_installed else "installed"
    print(f"[OK] {action} plugin {PLUGIN_ID} {desired_version}")
    return not was_installed


def _rollback_install_transaction(
    codex: str, codex_home: Path, repo_root: Path, txn: dict
) -> list[str]:
    """Best-effort restore of the pre-transaction registration and staging.

    Runs under the same installation lock as the transaction itself. Returns
    human-readable notes for anything that could not be restored; an
    incomplete rollback is reported explicitly and never presented as a
    successful no-op. The recovery objects (previous staging bytes, prior
    registration source) are preserved whenever restoration fails so a
    later operator run can finish the repair.
    """
    notes: list[str] = []
    stages = list(txn.get("stages") or [])
    staging = txn.get("staging")
    backup = txn.get("staging_backup_slot")
    prior = txn.get("prior_entry")
    if stages:
        notes.append(f"stages completed before failure: {', '.join(stages)}")
    if isinstance(staging, Path) and isinstance(backup, Path) and backup.is_dir():
        try:
            if staging.exists():
                shutil.rmtree(staging)
            os.replace(backup, staging)
            notes.append(
                f"restored previous marketplace staging bytes at {staging}"
            )
        except OSError as exc:
            notes.append(
                f"INCOMPLETE: could not restore previous staging bytes "
                f"({backup} kept for recovery): {exc}"
            )
            return notes
    try:
        current = marketplace_entry(codex)
    except Exception:  # noqa: BLE001 - rollback keeps collecting notes
        current = "unknown"

    def prior_source() -> str | None:
        if not isinstance(prior, dict):
            return None
        for value in (prior.get("root"),
                      prior.get("marketplaceSource", {}).get("source")):
            if value:
                return str(value)
        return None

    def registration_matches(entry, expected: dict) -> bool:
        if not isinstance(entry, dict):
            return False
        expected_source = None
        for value in (expected.get("root"),
                      expected.get("marketplaceSource", {}).get("source")):
            if value:
                expected_source = value
                break
        current_source = None
        for value in (entry.get("root"),
                      entry.get("marketplaceSource", {}).get("source")):
            if value:
                current_source = value
                break
        return bool(expected_source and current_source
                    and same_path(current_source, expected_source))

    if isinstance(current, dict) and prior is not None and isinstance(prior, dict) \
            and registration_matches(current, prior):
        return notes
    if current is None:
        # The registration disappeared during this transaction.
        if txn.get("registration_removed") or txn.get("registered_fresh"):
            source = prior_source()
            if prior is not None and source:
                try:
                    run(codex, "plugin", "marketplace", "add", source, "--json")
                    notes.append(
                        f"restored prior marketplace registration at {source}"
                    )
                except RuntimeError as exc:
                    notes.append(
                        f"INCOMPLETE: prior marketplace registration at "
                        f"{source} could not be restored: {exc}"
                    )
            elif prior is not None:
                notes.append(
                    "INCOMPLETE: prior registration had no readable source; "
                    "restore it manually before the next install"
                )
            else:
                notes.append(
                    "INCOMPLETE: this run removed the only marketplace "
                    "registration and no prior registration exists to restore"
                )
    elif current == "unknown":
        notes.append(
            "INCOMPLETE: marketplace registration state is unreadable after "
            "the failure; run a read-only audit before the next install"
        )
    else:
        if prior is None:
            if txn.get("registered_fresh") or txn.get("reregistered"):
                try:
                    run(codex, "plugin", "marketplace", "remove", MARKETPLACE)
                    notes.append(
                        "removed the marketplace registration added by this "
                        "failed run"
                    )
                except RuntimeError as exc:
                    notes.append(
                        f"INCOMPLETE: marketplace registration added by this "
                        f"run could not be removed: {exc}"
                    )
        elif txn.get("reregistered") or txn.get("registered_fresh"):
            # The registration was repointed or replaced during this run and
            # still differs from the prior one: restore the prior source and
            # read the identity back; a failed restoration is an explicit
            # incomplete transaction, never a "verify manually" note.
            source = prior_source()
            if source:
                try:
                    try:
                        run(codex, "plugin", "marketplace", "remove", MARKETPLACE)
                    except RuntimeError:
                        pass
                    run(codex, "plugin", "marketplace", "add", source, "--json")
                    restored = marketplace_entry(codex)
                    if registration_matches(restored, prior):
                        notes.append(
                            f"restored prior marketplace registration at {source}"
                        )
                    else:
                        notes.append(
                            f"INCOMPLETE: prior marketplace registration "
                            f"restore could not be confirmed at {source}; "
                            "current registration differs"
                        )
                except RuntimeError as exc:
                    notes.append(
                        f"INCOMPLETE: prior marketplace registration at "
                        f"{source} could not be restored: {exc}"
                    )
            else:
                notes.append(
                    "INCOMPLETE: prior registration had no readable source; "
                    "restore it manually before the next install"
                )
    return notes


def _run_install_transaction(
    codex: str, repo_root: Path, codex_home: Path
) -> None:
    cache_root = plugin_cache_root(codex_home)
    staging_backup = (
        codex_home.expanduser().resolve()
        / "upstreams"
        / PLUGIN_NAME
        / f".{repo_root.name}.marketplace.txn-backup"
    )
    txn: dict = {"staging_backup_slot": staging_backup}
    with cache_install_lock(cache_root):
        try:
            ensure_marketplace(codex, repo_root, codex_home, apply=True, txn=txn)
            ensure_plugin(codex, repo_root, codex_home, apply=True, lock=False)
        except BaseException as exc:
            # Rollback runs while this transaction still holds the install
            # lock, so a concurrent installer cannot interleave with the
            # recovery or be overwritten by it.
            notes = _rollback_install_transaction(
                codex, codex_home, repo_root, txn
            )
            if notes:
                summary = "; ".join(notes)
                if isinstance(exc, RuntimeError):
                    raise RuntimeError(f"{exc}\n[transaction] {summary}") from exc
                print(f"[transaction] {summary}", file=sys.stderr)
            raise
        # Success cleanup also stays inside the lock: releasing the backup
        # only after the whole transaction committed.
        if staging_backup.exists():
            shutil.rmtree(staging_backup, ignore_errors=True)


INTERPRETER_CONF_RELATIVE = Path("context-guard") / "interpreter.conf"


def _reject_unsafe_binding_component(component: Path, label: str) -> None:
    """Refuse symlink/reparse/non-directory components before any write.

    The binding must live inside the selected HOME as real private state;
    a link anywhere on the conf chain could redirect writes outside the
    HOME or clobber an external object.
    """
    info = component.lstat()
    if component.is_symlink() or getattr(info, "st_reparse_tag", 0):
        raise RuntimeError(
            f"refusing to write the GUI interpreter binding through a link "
            f"or reparse point ({label}: {component}); remove the link and "
            "re-run --apply")
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(
            f"refusing to write the GUI interpreter binding: {label} "
            f"({component}) is not a real directory")


def prepare_gui_interpreter_binding(codex_home: Path) -> tuple[Path, str]:
    """Validate and create everything the binding needs, without writing it.

    Runs before the installation transaction so an unsafe binding location
    refuses the install instead of leaving a mixed state (installation done,
    binding impossible). Verifies the interpreter by executing it and
    returns the conf path plus the single-line content for the caller to
    write atomically afterwards.
    """
    if not codex_home.exists() and not codex_home.is_symlink():
        codex_home.mkdir(parents=True, exist_ok=True)
    if codex_home.is_symlink():
        raise RuntimeError(
            "refusing to bind the GUI interpreter through a symlinked "
            f"CODEX_HOME ({codex_home})")
    _reject_unsafe_binding_component(codex_home, "CODEX_HOME")
    private_dir = codex_home / INTERPRETER_CONF_RELATIVE.parent
    if private_dir.exists() or private_dir.is_symlink():
        _reject_unsafe_binding_component(private_dir, "context-guard data dir")
    else:
        private_dir.mkdir(mode=0o700)
    os.chmod(private_dir, 0o700)
    conf_path = codex_home / INTERPRETER_CONF_RELATIVE
    if conf_path.exists() or conf_path.is_symlink():
        info = conf_path.lstat()
        if conf_path.is_symlink() or getattr(info, "st_reparse_tag", 0):
            raise RuntimeError(
                f"refusing to overwrite the interpreter binding through a "
                f"link ({conf_path}); remove the link and re-run --apply")
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(
                f"refusing to write the interpreter binding: {conf_path} "
                "is not a regular file")
    interpreter = Path(sys.executable).resolve()
    if not interpreter.is_file():
        raise RuntimeError(
            f"cannot bind the GUI interpreter: {interpreter} is not a file")
    probe = subprocess.run(
        [str(interpreter), "-c",
         "import sys; raise SystemExit(sys.version_info < (3, 10))"],
        capture_output=True)
    if probe.returncode != 0:
        raise RuntimeError(
            f"cannot bind the GUI interpreter: {interpreter} does not "
            "provide Python 3.10+")
    content = f"{interpreter}\n"
    return conf_path, content


def write_gui_interpreter_binding(conf_path: Path, content: str) -> None:
    """Atomically publish the verified binding within its private directory.

    The write uses a same-directory temporary file with an exclusive create,
    fsync, and an atomic replace, so a crash never leaves a partial binding
    and no path component is ever followed out of the verified private
    directory. Failures clean up the temporary and propagate.
    """
    fd, temp_name = tempfile.mkstemp(
        dir=conf_path.parent, prefix=".interpreter.conf.")
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, conf_path)
    except BaseException:
        with contextlib.suppress(OSError):
            temp.unlink()
        raise


def bind_gui_interpreter(codex_home: Path) -> Path:
    """Prepare and publish the GUI interpreter binding for this HOME."""
    conf_path, content = prepare_gui_interpreter_binding(codex_home)
    write_gui_interpreter_binding(conf_path, content)
    print(f"[OK] bound GUI interpreter for this HOME: {content.strip()}")
    return conf_path


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
    parser.add_argument(
        "--write-distribution-manifest",
        action="store_true",
        help="regenerate .codex-plugin/distribution-manifest.json from the "
             "reviewed distribution set and exit",
    )
    parser.add_argument(
        "--adopt-distribution-files",
        action="store_true",
        help="with --write-distribution-manifest, adopt new files into the "
             "reviewed set after manual review instead of refusing",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.expanduser().resolve()
    codex_home = args.codex_home.expanduser().resolve()
    # Every Codex subprocess must use the same home that this script validates.
    # Otherwise --codex-home can inspect an isolated cache while plugin commands
    # silently mutate the caller's default ~/.codex installation.
    os.environ["CODEX_HOME"] = str(codex_home)
    try:
        if args.write_distribution_manifest:
            if args.adopt_distribution_files:
                probe = repo_root / DISTRIBUTION_MANIFEST_RELATIVE
                if probe.is_file():
                    probe.unlink()
            manifest_path = write_distribution_manifest(repo_root)
            print(f"[OK] wrote reviewed distribution manifest: {manifest_path}")
            return 0
        version = codex_version(args.codex)
        if version < MINIMUM_CODEX:
            minimum = ".".join(map(str, MINIMUM_CODEX))
            actual = ".".join(map(str, version))
            raise RuntimeError(
                f"Codex {actual} is below the Context Guard baseline {minimum}; upgrade first"
            )
        print(f"[OK] Codex version supports stable hooks: {'.'.join(map(str, version))}")
        if args.apply:
            # Same-version immutability is decided before the marketplace
            # staging or registration can change, so a rejected drift never
            # leaves a mixed-identity installation behind. The GUI
            # interpreter binding location is validated just as early: an
            # unsafe binding location refuses the install instead of
            # completing it and then failing to bind.
            same_version_drift_preflight(args.codex, repo_root, codex_home)
            conf_path, interpreter_line = prepare_gui_interpreter_binding(
                codex_home)
            _run_install_transaction(args.codex, repo_root, codex_home)
            write_gui_interpreter_binding(conf_path, interpreter_line)
            print(f"[OK] bound GUI interpreter for this HOME: {interpreter_line.strip()}")
        else:
            ensure_marketplace(args.codex, repo_root, codex_home, args.apply)
            ensure_plugin(args.codex, repo_root, codex_home, args.apply)
    except (OSError, RuntimeError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
