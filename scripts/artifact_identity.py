"""Read-only product byte identities; no installation or HOME mutation."""
from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

RUNTIME_ROOTS = (".codex-plugin", "assets", "hooks", "scripts", "skills")
IGNORED_TREE_NAMES = frozenset({".DS_Store", ".codex", ".git", ".pytest_cache", ".ruff_cache", ".venv", "Thumbs.db", "__pycache__", "build", "dist"})
DISTRIBUTION_MANIFEST_RELATIVE = ".codex-plugin/distribution-manifest.json"
DISTRIBUTION_EXTRA = (".agents/plugins/marketplace.json", ".codexignore", "LICENSE", "README.md", "README.zh-CN.md", "CHANGELOG.md", "CHANGELOG.zh-CN.md", "SECURITY.md", "CONTRIBUTING.md", "pyproject.toml")

def checked_metadata(path: Path):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_reparse_tag", 0)
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise RuntimeError("artifact links and reparse objects are refused")
    return info


def validate_roots(root: Path, *, distribution: bool = False) -> None:
    if not stat.S_ISDIR(checked_metadata(root).st_mode):
        raise RuntimeError("artifact root must be a real directory")
    names = (*RUNTIME_ROOTS, "docs", ".agents", ".agents/plugins") if distribution else RUNTIME_ROOTS
    for name in names:
        try:
            info = checked_metadata(root / name)
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("artifact area must be a real directory")


def safe_file(root: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or ".." in rel.parts or "\\" in relative:
        raise RuntimeError("invalid artifact path")
    current = root
    checked_metadata(root)
    for part in rel.parts:
        current = current / part
        checked_metadata(current)
    if not stat.S_ISREG(current.stat().st_mode):
        raise RuntimeError("artifact file must be regular")
    return current

def checked_walk(directory: Path, *, ignore_runtime: bool = False):
    """Enumerate one level at a time, rejecting reparse objects before descent.

    Do not replace this with a drained recursive glob: Python versions and
    Windows directory providers differ in which reparse directories they enter.
    Runtime exclusions apply before descent and retain the existing hash domain.
    """
    if not stat.S_ISDIR(checked_metadata(directory).st_mode):
        raise RuntimeError("artifact area must be a real directory")
    for path in sorted(directory.iterdir()):
        if ignore_runtime and (path.name in IGNORED_TREE_NAMES
                               or path.name.endswith((".pyc", ".pyo"))):
            continue
        info = checked_metadata(path)
        yield path, info
        if stat.S_ISDIR(info.st_mode):
            yield from checked_walk(path, ignore_runtime=ignore_runtime)


def tree_manifest(root: Path) -> dict[str, str]:
    root = Path(root)
    validate_roots(root)
    files = {}
    for name in RUNTIME_ROOTS:
        directory = root / name
        if not directory.exists():
            continue
        for path, info in checked_walk(directory, ignore_runtime=True):
            rel = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                continue
            files[rel] = hashlib.sha256(safe_file(root, rel).read_bytes()).hexdigest()
    if not files:
        raise RuntimeError("artifact runtime is empty")
    return files

def distribution_files(root: Path) -> dict[str, str]:
    validate_roots(root, distribution=True)
    files = tree_manifest(root)
    files.pop(DISTRIBUTION_MANIFEST_RELATIVE, None)
    docs = root / "docs"
    if docs.exists():
        for path, _info in checked_walk(docs):
            if path.match("*.md"):
                rel = path.relative_to(root).as_posix()
                files[rel] = hashlib.sha256(safe_file(root, rel).read_bytes()).hexdigest()
    for rel in DISTRIBUTION_EXTRA:
        if (root / rel).exists():
            files[rel] = hashlib.sha256(safe_file(root, rel).read_bytes()).hexdigest()
    return dict(sorted(files.items()))

def distribution_manifest(root: Path) -> dict[str, str]:
    path = safe_file(root, DISTRIBUTION_MANIFEST_RELATIVE)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    expected = manifest.get("files")
    actual = distribution_files(root)
    if (manifest.get("schema") != "cg-distribution-manifest/v1"
            or type(expected) is not dict or manifest.get("file_count") != len(expected)
            or expected != actual):
        raise RuntimeError("distribution differs from reviewed sha256 manifest")
    return {**actual, DISTRIBUTION_MANIFEST_RELATIVE: hashlib.sha256(path.read_bytes()).hexdigest()}


def compare_artifact(root: Path, installed: Path) -> None:
    expected = distribution_manifest(root)
    actual = {}
    validate_roots(installed, distribution=True)
    for path, info in checked_walk(installed):
        relative = path.relative_to(installed).as_posix()
        if stat.S_ISDIR(info.st_mode):
            continue
        actual[relative] = hashlib.sha256(safe_file(installed, relative).read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError("installed full release-file set or bytes differ")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare-to", type=Path, required=True,
                        help="Installed path saved from the first official plugin add --json")
    args = parser.parse_args()
    compare_artifact(Path(__file__).resolve().parents[1], args.compare_to)
    print("Exact release-file parity passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
