#!/usr/bin/env python3
"""Run portable exact-runtime acceptance and emit native-acceptance/v2 JSON."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import ntpath
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Sequence
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from functools import cache
from pathlib import Path
from typing import Any

HEX40 = re.compile(r"^[0-9a-f]{40}$")

HOST_BEHAVIOR_MODULE = "host_behavior"

POSIX_SNAPSHOT_CAPABLE = (
    all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW"))
    and os.listdir in os.supports_fd and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
)


class NativeRunError(RuntimeError):
    """Raised when portable native acceptance cannot establish its contract."""


def load_host_behavior():
    path = Path(__file__).resolve().parent / "host_behavior.py"
    spec = importlib.util.spec_from_file_location(HOST_BEHAVIOR_MODULE, path)
    if spec is None or spec.loader is None:
        raise NativeRunError("could not load the host_behavior profile module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_artifacts(root: Path):
    path = root / "scripts" / "artifact_identity.py"
    spec = importlib.util.spec_from_file_location("native_acceptance_artifact_identity", path)
    if spec is None or spec.loader is None:
        raise NativeRunError("could not load the repository plugin manager")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(root: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(args), cwd=root, env=env, text=True, capture_output=True, check=False
    )
    if result.returncode:
        detail = (result.stdout + result.stderr).strip()
        raise NativeRunError(f"command failed ({args[0]}): {detail[-1000:]}")
    return result


def resolve_executable(command: str) -> str:
    """Resolve platform launchers such as Windows ``codex.cmd`` exactly once."""
    resolved = shutil.which(command)
    if resolved is None:
        raise NativeRunError(f"executable not found: {command}")
    return resolved


def normalize_repository_url(raw: str) -> str:
    value = raw.strip()
    match = re.fullmatch(r"git@github\.com:([^/]+)/([^/]+?)(?:\.git)?", value)
    if match:
        return f"https://github.com/{match.group(1)}/{match.group(2)}.git"
    if value.startswith("https://") and "@" not in value.partition("//")[2].partition("/")[0]:
        return value
    raise NativeRunError("origin must be credential-free GitHub HTTPS or SSH")


def runtime_digest(manager: Any, root: Path) -> str:
    manifest = manager.tree_manifest(root)
    if not isinstance(manifest, dict) or not manifest:
        raise NativeRunError("runtime tree manifest is empty")
    return hashlib.sha256(
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def gate(gate_id: str, digest: str, *, passed: bool, note: str | None = None) -> dict[str, Any]:
    return {
        "id": gate_id,
        "required": True,
        "status": "passed" if passed else "failed",
        "subject": {"kind": "runtime_tree", "id": digest},
        "exit_code": 0 if passed else 1,
        "note": note,
        "evidence": {
            "mode": "executed",
            "source_result_sha256": None,
            "source_gate_id": None,
            "invalidation_reason": "runtime_tree_changed",
        },
    }


def verify_exact_source(root: Path, source_commit: str) -> None:
    if not HEX40.fullmatch(source_commit):
        raise NativeRunError("source commit must be a full lowercase SHA-1")
    head = run(root, "git", "rev-parse", "HEAD").stdout.strip()
    if head != source_commit:
        raise NativeRunError("source commit is not the exact checked-out HEAD")
    status = run(
        root, "git", "status", "--porcelain=v1", "--untracked-files=all"
    ).stdout.strip()
    if status:
        raise NativeRunError(
            "repository state must be clean, including staged, unstaged, and untracked files"
        )


def load_snapshot_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise NativeRunError("strict no-op snapshot reader unavailable")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


@cache
def load_snapshot_runtime():
    """Reuse the unchanged cross-platform no-follow opener, without running CLI."""
    return load_snapshot_module("native_snapshot_runtime",
        Path(__file__).resolve().parents[2] / "scripts" / "context_guard.py")


def open_snapshot_file(path: Path, *, dir_fd: int | None = None) -> int:
    if os.name == "nt":
        # CreateFileW OPEN_REPARSE_POINT plus handle attribute rejection.
        return load_snapshot_runtime()._open_windows_committed_state(path)
    if not hasattr(os, "O_NOFOLLOW"):
        raise NativeRunError("strict no-op snapshot no-follow reader unavailable")
    return os.open(path if dir_fd is None else path.name,
                   os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                   dir_fd=dir_fd)


@cache
def load_snapshot_windows():
    return load_snapshot_module("native_snapshot_windows",
        Path(__file__).resolve().with_name("incident_readonly_child.py"))


@contextmanager
def pinned_windows_directory(path: Path):
    """Retain the reviewed READ|WRITE (no DELETE sharing) directory handle."""
    backend = load_snapshot_windows()
    api, handle = backend.open_windows_handle(path, 0x20080)
    try:
        bound = backend.windows_handle_identity(api, handle)
        if (bound["kind"] != "directory" or bound["reparse_tag"]
                or bound != backend.windows_object_identity(path)):
            raise NativeRunError("strict no-op snapshot directory identity changed")
        yield
    finally:
        if not backend.close_windows_handle(api, handle)["return_value"]:
            raise NativeRunError("strict no-op snapshot directory close failed")


def windows_snapshot_ancestors(path: Path):
    # No guessed semantics for UNC, device namespaces, drive-relative or dot paths.
    if (len(path.drive) != 2 or not path.drive[0].isascii()
            or not path.drive[0].isalpha() or path.drive[1] != ":"
            or path.anchor != path.drive + "\\" or ".." in path.parts):
        raise NativeRunError("strict no-op snapshot root capability unavailable")
    return tuple(reversed(path.parents))


def installed_object_snapshot(codex_home: Path) -> dict[str, tuple[Any, ...]]:
    """Anchored full HOME-13 final-state equivalence, not absence of writes."""
    objects: dict[str, tuple[Any, ...]] = {}
    posix_bindings: list[tuple[int, str, int]] = []

    def identity(info):
        # Common path/handle fields; ctime is checked only within each provider.
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_size, info.st_mtime_ns)

    def validate(info):
        if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_reparse_tag", 0)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise NativeRunError("strict no-op snapshot refuses links and reparse objects")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise NativeRunError("strict no-op snapshot refuses special objects")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise NativeRunError("strict no-op snapshot refuses hard links")

    def read_file(path, before, parent_fd):
        descriptor = open_snapshot_file(path, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            validate(opened)
            if not stat.S_ISREG(opened.st_mode) or identity(before) != identity(opened):
                raise NativeRunError("strict no-op snapshot file identity changed")
            digest, size = hashlib.sha256(), 0
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
            finished = os.fstat(descriptor)
            if (identity(opened) != identity(finished)
                    or opened.st_ctime_ns != finished.st_ctime_ns
                    or size != finished.st_size):
                raise NativeRunError("strict no-op snapshot file changed during read")
        finally:
            os.close(descriptor)
        return ("file", before.st_mode, before.st_size, digest.hexdigest())

    def observe(path, parent_fd=None):
        name = path.name
        private_name = name.casefold()
        if (private_name in {
                "auth.json", ".auth.json", "auth.toml", "credentials", "credentials.json",
                "credentials.toml", "credentials.yaml", "credentials.yml", "credentials.ini", "token.json",
                "tokens.json", "oauth-token.json", "secrets.json", "secrets.toml",
                "secrets.yaml", "secrets.yml", ".netrc", "_netrc", ".env",
                "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".ssh", ".aws", ".azure",
                ".git-credentials", ".npmrc", ".pypirc", ".docker", ".kube",
            } or private_name.startswith(("auth.json.", ".env."))
                or private_name.endswith((".pem", ".p12", ".pfx", ".key"))):
            # This is refusal of the whole witness, never a hidden file exclusion.
            raise NativeRunError("strict no-op snapshot refuses credential material")
        before = (path.lstat() if parent_fd is None else
                  os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
        validate(before)
        relative = path.relative_to(codex_home).as_posix()
        if stat.S_ISDIR(before.st_mode):
            objects[relative] = ("directory", before.st_mode)
            with ExitStack() as held:
                if os.name == "nt":
                    held.enter_context(pinned_windows_directory(path))
                    if identity(before) != identity(path.lstat()):
                        raise NativeRunError("strict no-op snapshot directory identity changed")
                    children = sorted(path.iterdir())
                    directory_fd = None
                else:
                    directory_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                           dir_fd=parent_fd)
                    if path == codex_home:
                        # Retain HOME alongside its ancestors through final name revalidation.
                        ancestors.callback(os.close, directory_fd)
                        posix_bindings.append((parent_fd, name, directory_fd))
                    else:
                        held.callback(os.close, directory_fd)
                    if identity(before) != identity(os.fstat(directory_fd)):
                        raise NativeRunError("strict no-op snapshot directory identity changed")
                    children = [path / child for child in sorted(os.listdir(directory_fd))]
                for child in children:
                    if child.name in {".", ".."}:
                        raise NativeRunError("strict no-op snapshot child name invalid")
                    observe(child, directory_fd)
        else:
            objects[relative] = read_file(path, before, parent_fd)
        after = (path.lstat() if parent_fd is None else
                 os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
        if (identity(before) != identity(after)
                or before.st_ctime_ns != after.st_ctime_ns
                or getattr(after, "st_reparse_tag", 0)):
            raise NativeRunError("installed objects changed during strict no-op snapshot")

    try:
        with ExitStack() as ancestors:
            if os.name == "nt":
                for path in windows_snapshot_ancestors(codex_home):
                    ancestors.enter_context(pinned_windows_directory(path))
                observe(codex_home)
            else:
                if (not codex_home.is_absolute() or ".." in codex_home.parts
                        or not POSIX_SNAPSHOT_CAPABLE):
                    raise NativeRunError("strict no-op snapshot root capability unavailable")
                parent_fd = os.open(codex_home.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                ancestors.callback(os.close, parent_fd)
                for part in codex_home.parts[1:-1]:
                    before = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                    validate(before)
                    child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                       dir_fd=parent_fd)
                    ancestors.callback(os.close, child_fd)
                    if identity(before) != identity(os.fstat(child_fd)):
                        raise NativeRunError("strict no-op snapshot ancestor identity changed")
                    posix_bindings.append((parent_fd, part, child_fd))
                    parent_fd = child_fd
                observe(codex_home, parent_fd)
                # An anchored fd may outlive its original pathname. Prove the
                # entire currently named chain still selects those exact objects.
                for held_parent, name, held_child in posix_bindings:
                    current = os.stat(name, dir_fd=held_parent, follow_symlinks=False)
                    validate(current)
                    if (not stat.S_ISDIR(current.st_mode)
                            or identity(current) != identity(os.fstat(held_child))):
                        raise NativeRunError("strict no-op snapshot ancestor pathname changed")
    except (OSError, UnicodeError, ValueError):
        raise NativeRunError("strict no-op snapshot object unreadable") from None
    if not any(value[0] == "file" for value in objects.values()):
        raise NativeRunError("strict no-op snapshot contains no installed files")
    return objects


def inspect_installed_artifact(root: Path, source_commit: str, codex: str,
                        run_url: str | None, installed: Path | None = None) -> dict[str, Any]:
    """Inspect an explicitly supplied installed artifact; never install or repair it.

    The native install, second-operation no-op, old-cache preservation and trust
    gates remain pending. Artifact parity cannot close those obligations.
    """
    if installed is None:
        raise NativeRunError("official marketplace installation required; pass --installed-plugin-root for artifact checks only")
    artifacts = load_artifacts(root)
    digest = runtime_digest(artifacts, root)
    verify_exact_source(root, source_commit)
    artifacts.compare_artifact(root, installed)
    if artifacts.tree_manifest(installed) != artifacts.tree_manifest(root):
        raise NativeRunError("installed runtime tree differs from source")
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    run(root, sys.executable, "scripts/smoke_installed.py", "--plugin-root", str(installed), env=environment)
    return {
        "schema": "marketplace-artifact-inspection/v1", "status": "pending",
        "gate_profile": "installed_artifact_only", "source_commit": source_commit,
        "runtime_tree_sha256": digest,
        "gates": [gate("runtime_tree_parity", digest, passed=True),
                  gate("installed_lifecycle_smoke", digest, passed=True)],
        "pending_gates": ["official_marketplace_install", "strict_second_noop",
                          "old_cache_object_preservation", "normal_hook_trust",
                          "real_task_continuity", "gui_interpreter_discovery"],
        "run_url": run_url,
    }


OFFICIAL_PLUGIN = "context-guard@codex-context-guard-v016"


def _windows_safe_path_component(part: str) -> bool:
    if (not part or part in {".", ".."} or part != part.rstrip(" .")
            or any(ord(char) < 32 or ord(char) == 127
                   or 0xD800 <= ord(char) <= 0xDFFF
                   or char in '<>:"|?*' for char in part)):
        return False
    device = part.split(".", 1)[0].rstrip(" ").upper()
    return (device not in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"}
            and re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", device) is None)


def _windows_safe_absolute_unc(raw: Any) -> bool:
    """Validate only; UNC aliases are never normalized into an authority."""
    if not isinstance(raw, str) or not raw or len(raw) > 32767 or "/" in raw:
        return False
    if raw[:8].lower() == "\\\\?\\unc\\":
        tail = raw[8:]
    elif raw.startswith("\\\\") and not raw.startswith(("\\\\?\\", "\\\\.\\")):
        tail = raw[2:]
    else:
        return False
    parts = tail.split("\\")
    if parts[-1] == "":
        parts.pop()
    return len(parts) >= 2 and all(_windows_safe_path_component(part) for part in parts)


def _windows_local_absolute_key(raw: Any) -> str | None:
    """Lexical local-drive identity only; never query a JSON-supplied path.

    The supported spelling differences are separators, Windows case and one
    ordinary extended drive prefix. Controlled UNC uses a separate exact-match
    domain; device namespaces, traversal, ADS, reserved devices and ambiguous
    Win32 component spellings stay unsupported.
    This key is not samefile evidence or an object-identity claim.
    """
    if not isinstance(raw, str) or not raw or len(raw) > 32767:
        return None
    value = raw.replace("/", "\\")
    if value.startswith("\\\\?\\"):
        value = value[4:]
    if re.match(r"^[A-Za-z]:\\", value) is None:
        return None
    parts = value[3:].split("\\")
    if parts[-1] == "":
        parts.pop()  # a trailing separator does not change the directory
    if not all(_windows_safe_path_component(part) for part in parts):
        return None
    return ntpath.normcase(ntpath.normpath(value))


def _official_path_matches(raw: Any, expected: Path, *, windows: bool) -> bool:
    if not windows:
        return isinstance(raw, str) and raw == str(expected)
    # Preserve the old exact controlled UNC domain, including extended UNC.
    # Do not accept case/separator/prefix aliases even when Windows might.
    if isinstance(raw, str) and raw == str(expected) and _windows_safe_absolute_unc(raw):
        return True
    actual = _windows_local_absolute_key(raw)
    wanted = _windows_local_absolute_key(str(expected))
    return actual is not None and wanted is not None and actual == wanted


def official_identity(listed: dict[str, Any], added: dict[str, Any],
                      source: Path, home: Path, version: str) -> Path:
    """Bind one real list record to this run's saved official add response."""
    if not isinstance(listed, dict):
        raise NativeRunError("official list is not an object")
    entries = listed.get("installed")
    if not isinstance(entries, list):
        raise NativeRunError("official list has no installed array")
    matches = [entry for entry in entries if isinstance(entry, dict)
               and entry.get("pluginId") == OFFICIAL_PLUGIN]
    if len(matches) != 1:
        raise NativeRunError("official installed identity is missing or ambiguous")
    if not isinstance(added, dict):
        raise NativeRunError("official add is not an object")
    entry = matches[0]
    expected = {"pluginId": OFFICIAL_PLUGIN, "name": "context-guard",
                "marketplaceName": "codex-context-guard-v016", "version": version}
    if any(entry.get(k) != v or added.get(k) != v for k, v in expected.items()):
        raise NativeRunError("official installed identity differs")
    if entry.get("installed") is not True or entry.get("enabled") is not True:
        raise NativeRunError("official installed plugin is not enabled")
    windows = platform.system() == "Windows"
    source_record = entry.get("source")
    marketplace = entry.get("marketplaceSource")
    if (not isinstance(source_record, dict) or set(source_record) != {"source", "path"}
            or source_record["source"] != "local"
            or not _official_path_matches(source_record["path"], source, windows=windows)
            or not isinstance(marketplace, dict) or set(marketplace) != {"sourceType", "source"}
            or marketplace["sourceType"] != "local"
            or not _official_path_matches(marketplace["source"], source, windows=windows)):
        raise NativeRunError("official marketplace source differs")
    raw = added.get("installedPath")
    if not isinstance(raw, str):
        raise NativeRunError("official add has no installed path")
    cache = home / "plugins/cache/codex-context-guard-v016/context-guard"
    if windows:
        # Check untrusted JSON lexically, then return only a path constructed
        # from this run's trusted HOME. Existing parity/reparse checks consume
        # that trusted path, never the JSON spelling or a resolved alias.
        installed = next((cache / name for name in (version, "local")
                          if _official_path_matches(raw, cache / name, windows=True)), None)
        if installed is None or installed.is_symlink():
            raise NativeRunError("official installed path is outside the isolated cache")
    else:
        installed = Path(raw)
        if (not installed.is_absolute() or installed.parent != cache
                or installed.name not in {version, "local"} or installed.is_symlink()):
            raise NativeRunError("official installed path is outside the isolated cache")
    return installed


def exact_artifact_parity(installed: Path, files: dict[str, str]) -> None:
    snapshot = installed_object_snapshot(installed)
    actual = {path: value[3] for path, value in snapshot.items() if value[0] == "file"}
    if actual != files:
        raise NativeRunError("installed full release-file set or bytes differ")


def strict_cache_objects(root: Path) -> dict[str, tuple[Any, ...]]:
    """Extra object identity contract for the synthetic previous-cache fixture."""
    contents = installed_object_snapshot(root)
    objects = {}
    for name, value in contents.items():
        info = (root if name == "." else root / name).stat()
        if info.st_ino <= 0 or info.st_dev < 0:
            raise NativeRunError("previous-cache object identity capability unavailable")
        objects[name] = (value, info.st_dev, info.st_ino, info.st_ctime_ns)
    return objects


def documented_official_flow(root: Path, codex: str, home: Path, source: Path,
                              environment: dict[str, str], files: dict[str, str],
                              version: str, added: dict[str, Any] | None) -> tuple[dict[str, Any], Path]:
    listed = json.loads(run(root, codex, "plugin", "list", "--json", env=environment).stdout)
    if not isinstance(listed, dict):
        raise NativeRunError("official list is not an object")
    entries = listed.get("installed")
    if not isinstance(entries, list):
        raise NativeRunError("official list has no installed array")
    matches = [item for item in entries if isinstance(item, dict)
               and item.get("pluginId") == OFFICIAL_PLUGIN]
    if not matches:
        if added is not None:
            raise NativeRunError("previously installed plugin disappeared")
        run(root, codex, "plugin", "marketplace", "add", str(source), env=environment)
        added = json.loads(run(root, codex, "plugin", "add", OFFICIAL_PLUGIN,
                               "--json", env=environment).stdout)
        listed = json.loads(run(root, codex, "plugin", "list", "--json", env=environment).stdout)
    elif added is None:
        raise NativeRunError("unexpected preexisting plugin in fresh isolated HOME")
    installed = official_identity(listed, added, source, home, version)
    exact_artifact_parity(installed, files)
    return added, installed


def portable_acceptance(root: Path, source_commit: str, codex: str,
                        run_url: str | None, installed: Path | None = None,
                        release_zip: Path | None = None) -> dict[str, Any]:
    if installed is not None:
        return inspect_installed_artifact(root, source_commit, codex, run_url, installed)
    # This profile never accepts an operator HOME. Its only installation target
    # is created internally and discarded, with no old installer/cache repair.
    artifacts = load_artifacts(root)
    files = artifacts.distribution_manifest(root)
    digest = runtime_digest(artifacts, root)
    verify_exact_source(root, source_commit)
    version = json.loads((root / ".codex-plugin/plugin.json").read_text())["version"]
    started = timestamp()
    gates = [gate("source_identity", digest, passed=True)]
    status, cleanup = "failed", "passed"
    codex_version = "unavailable"
    artifact = None
    temporary = Path(tempfile.mkdtemp(prefix="ccg-official-marketplace-")).resolve()
    try:
        names = ("home", "os-home", "userprofile", "host-temp", "xdg-config", "xdg-data", "xdg-cache", "xdg-state")
        locations = {name: temporary / name for name in names}
        for path in locations.values():
            path.mkdir(mode=0o700)
        home = locations["home"]
        environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT") if key in os.environ}
        search = [str(Path(codex).parent), str(Path(sys.executable).parent)]
        node = shutil.which("node")
        if node:
            search.append(str(Path(node).parent))
        environment.update(PATH=os.pathsep.join([*search, os.defpath]),
            HOME=str(locations["os-home"]), CODEX_HOME=str(home), USERPROFILE=str(locations["userprofile"]),
            TMPDIR=str(locations["host-temp"]), TMP=str(locations["host-temp"]), TEMP=str(locations["host-temp"]),
            XDG_CONFIG_HOME=str(locations["xdg-config"]), XDG_DATA_HOME=str(locations["xdg-data"]),
            XDG_CACHE_HOME=str(locations["xdg-cache"]), XDG_STATE_HOME=str(locations["xdg-state"]),
            PYTHONDONTWRITEBYTECODE="1")
        codex_version = run(root, codex, "--version", env=environment).stdout.strip()
        archive_path = release_zip
        if archive_path is None:
            archive_path = temporary / "release.zip"
            run(root, sys.executable, "scripts/build_release_artifact.py", "--output", str(archive_path), env=environment)
        if archive_path.is_symlink() or not archive_path.is_file():
            raise NativeRunError("release ZIP must be a regular file")
        zip_bytes = archive_path.read_bytes()
        artifact = {"kind": "release_zip", "sha256": hashlib.sha256(zip_bytes).hexdigest(),
                    "size_bytes": len(zip_bytes), "file_count": len(files)}
        source = temporary / "release"
        source.mkdir()
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            if len(archive.namelist()) != len(files) or set(archive.namelist()) != set(files) or any(
                    hashlib.sha256(archive.read(name)).hexdigest() != files[name] for name in files):
                raise NativeRunError("release ZIP differs from reviewed source")
            archive.extractall(source)
        gates.append(gate("exact_release_zip", digest, passed=True))
        # A disclosed synthetic previous-version object fixture, never a daily
        # cache or proof of a resumed real task. It is only preservation evidence.
        old = home / "plugins/cache/codex-context-guard/context-guard/0.15.1"
        old.mkdir(parents=True)
        (old / "synthetic-preservation-control").write_bytes(b"synthetic previous cache object\n")
        old_before = strict_cache_objects(old)
        added, cache = documented_official_flow(root, codex, home, source, environment, files, version, None)
        gates.append(gate("isolated_install", digest, passed=True, note="official marketplace commands in internally created fresh HOME"))
        gates.append(gate("distribution_file_parity", digest, passed=True))
        if artifacts.tree_manifest(cache) != artifacts.tree_manifest(root):
            raise NativeRunError("installed runtime tree differs")
        gates.append(gate("runtime_tree_parity", digest, passed=True))
        run(root, sys.executable, "scripts/smoke_installed.py", "--plugin-root", str(cache), env=environment)
        gates.append(gate("installed_lifecycle_smoke", digest, passed=True))
        before = installed_object_snapshot(home)
        documented_official_flow(root, codex, home, source, environment, files, version, added)
        if installed_object_snapshot(home) != before:
            raise NativeRunError("second documented workflow changed final HOME paths, modes or file bytes")
        gates.append(gate("strict_second_noop", digest, passed=True,
                          note="documented status/identity/full-parity flow; final HOME state equality, not absence of writes or direct-add idempotence"))
        if strict_cache_objects(old) != old_before:
            raise NativeRunError("synthetic previous cache objects changed")
        gates.append(gate("old_cache_fixture_object_preservation", digest, passed=True,
                          note="synthetic previous cache only; no daily cache or real old-task continuity claim"))
        status = "passed"
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        gates.append(gate("official_marketplace_workflow", digest, passed=False,
                          note="official command, identity, artifact, no-op or preservation check failed; inspect local diagnostics"))
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
        if temporary.exists():
            cleanup, status = "failed", "failed"
    return {"schema": "native-acceptance/v2", "status": status,
        "product": "codex_context_guard", "gate_profile": "portable_runtime",
        "repository": {"url": normalize_repository_url(run(root, "git", "remote", "get-url", "origin").stdout), "commit": source_commit},
        "runtime_tree_sha256": digest, "artifact": artifact,
        "platform": {"os": {"Darwin": "macos", "Windows": "windows"}.get(platform.system(), "linux"),
                     "shell": "python-subprocess", "toolchain": {"python": platform.python_version(), "codex": codex_version}},
        "gates": gates, "cleanup": {"status": cleanup, "remaining_ids": [] if cleanup == "passed" else ["official_temporary_root"]},
        "run": {"started_at": started, "finished_at": timestamp(), "run_url": run_url},
        "limitations": ["local marketplace source retained only during this isolated gate; no long-term refresh/startup claim",
                        "direct repeated plugin add is not claimed idempotent", "no normal Hook trust or real old-task continuity established"],
        "unperformed_actions": ["commit", "push", "merge", "tag", "release", "public_promotion"]}


def build_argument_parser() -> argparse.ArgumentParser:
    return load_host_behavior().build_argument_parser()


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    parser.add_argument("--batch-manifest", type=Path,
                        help="Optional zero-model input manifest checked before acceptance execution")
    parser.add_argument("--commentary-replay-manifest", type=Path,
                        help="Immutable completed commentary run for zero-model replay")
    parser.add_argument("--commentary-control-replay-manifest", type=Path,
                        help="Immutable completed C2 control run for zero-model replay")
    parser.add_argument("--installed-plugin-root", type=Path, help="Existing officially installed artifact; this tool never installs")
    parser.add_argument("--release-zip", type=Path, help="Existing exact release ZIP; preserved without rebuild")
    args = parser.parse_args(argv)
    if not HEX40.fullmatch(args.source_commit):
        parser.error("source commit must be a full lowercase SHA-1")
    behavior = load_host_behavior()
    try:
        behavior.check_output_path(args.output, args.repo_root)
    except (OSError, behavior.HostBehaviorError) as exc:
        parser.error(str(exc))
    if args.batch_manifest is not None:
        try:
            path = Path(__file__).with_name("batch_preflight.py")
            spec = importlib.util.spec_from_file_location("batch_preflight", path)
            if spec is None or spec.loader is None:
                raise NativeRunError("batch preflight unavailable")
            batch = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(batch)
            manifest = batch.read_json(args.batch_manifest)
            check = batch.validate_batch(manifest)
            if check["status"] != "inputs_ready":
                raise NativeRunError("batch inputs failed: " + ",".join(check["errors"]))
            if manifest["source_commit"] != args.source_commit:
                raise NativeRunError("batch source identity mismatch")
            actual = runtime_digest(load_artifacts(args.repo_root.resolve()), args.repo_root.resolve())
            if manifest["runtime_tree_sha256"] != actual:
                raise NativeRunError("batch runtime identity mismatch")
        except (OSError, ValueError, NativeRunError, RuntimeError) as exc:
            parser.error(str(exc))
    if args.profile == "commentary_chain/v1":
        if args.commentary_replay_manifest is None:
            parser.error("commentary_chain/v1 requires --commentary-replay-manifest")
        try:
            root_path = str(Path(__file__).resolve().parents[2])
            if root_path not in sys.path:
                sys.path.insert(0, root_path)
            from tools.validation import commentary_native_profile
            if args.preflight:
                commentary_native_profile.preflight(args.commentary_replay_manifest,
                                                     args.source_commit)
                print("native_preflight=passed; input_checks_only; acceptance_not_written")
                return 0
            result = commentary_native_profile.replay(args.commentary_replay_manifest)
            if result["original_source_commit"] != args.source_commit:
                raise NativeRunError("commentary original source commit differs")
            behavior.write_result(args.output, result)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
            parser.error(str(exc))
        print(f"native_acceptance={result['status']}")
        return {"passed": 0, "failed": 1, "pending": 3}[result["status"]]
    if args.profile == "commentary_control_chain/v1":
        if args.commentary_control_replay_manifest is None:
            parser.error("commentary_control_chain/v1 requires --commentary-control-replay-manifest")
        try:
            root_path = str(Path(__file__).resolve().parents[2])
            if root_path not in sys.path:
                sys.path.insert(0, root_path)
            from tools.validation import commentary_control_native_profile
            if args.preflight:
                commentary_control_native_profile.preflight(
                    args.commentary_control_replay_manifest, args.source_commit)
                print("native_preflight=passed; input_checks_only; acceptance_not_written")
                return 0
            result = commentary_control_native_profile.replay(
                args.commentary_control_replay_manifest)
            if result["original_source_commit"] != args.source_commit:
                raise NativeRunError("C2 original source commit differs")
            behavior.write_result(args.output, result)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
            parser.error(str(exc))
        print(f"native_acceptance={result['status']}")
        return {"passed": 0, "failed": 1, "pending": 3}[result["status"]]
    if args.profile == "host_behavior":
        try:
            result = behavior.run_host_behavior(args)
            if args.preflight:
                print("native_preflight=" + ("failed" if result["status"] == "failed" else "passed")
                      + "; acceptance_not_written; capture_status=" + result["status"])
                return 1 if result["status"] == "failed" else 0
            behavior.write_result(args.output, result)
        except Exception as exc:  # noqa: BLE001 - surfaced through argparse
            parser.error(str(exc))
        print(f"native_acceptance={result['status']}")
        return {"passed": 0, "failed": 1, "pending": 3}[result["status"]]
    try:
        codex = resolve_executable(args.codex)
        root = args.repo_root.resolve()
        verify_exact_source(root, args.source_commit)
        normalize_repository_url(run(root, "git", "remote", "get-url", "origin").stdout)
        manager = load_artifacts(root)
        # Check reviewed source distribution bytes; this performs no installation.
        reviewed = manager.distribution_manifest(root)
        if args.installed_plugin_root is not None:
            manager.compare_artifact(root, args.installed_plugin_root)
        if args.release_zip is not None:
            if args.release_zip.is_symlink() or not args.release_zip.is_file():
                raise NativeRunError("release ZIP must be a regular file")
            with zipfile.ZipFile(io.BytesIO(args.release_zip.read_bytes())) as archive:
                if (len(archive.namelist()) != len(reviewed)
                        or set(archive.namelist()) != set(reviewed)
                        or any(hashlib.sha256(archive.read(name)).hexdigest() != reviewed[name] for name in reviewed)):
                    raise NativeRunError("release ZIP differs from reviewed source")
        runtime_digest(manager, root)
        # CLI execution belongs inside the internally isolated native HOME.
    except (NativeRunError, OSError, RuntimeError) as exc:
        parser.error(str(exc))
    if args.preflight:
        print("native_preflight=passed; input_checks_only; acceptance_not_run")
        return 0
    try:
        result = portable_acceptance(
            args.repo_root.resolve(), args.source_commit, codex, args.run_url, args.installed_plugin_root, args.release_zip
        )
    except (NativeRunError, OSError, RuntimeError) as exc:
        parser.error(str(exc))
    behavior.write_result(args.output, result)
    print(f"native_acceptance={result['status']}")
    return {"passed": 0, "failed": 1, "pending": 3}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
