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
COMMAND_TIMEOUT_SECONDS = 120

HOST_BEHAVIOR_MODULE = "host_behavior"

POSIX_SNAPSHOT_CAPABLE = (
    all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW"))
    and os.listdir in os.supports_fd and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
)


class NativeRunError(RuntimeError):
    """Raised when portable native acceptance cannot establish its contract."""


class ProcessCleanupUnknown(NativeRunError):
    """Owned process cleanup was not established; retain its temporary HOME."""


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


def load_process_tree():
    path = Path(__file__).resolve().parents[2] / 'scripts/cg_process_tree.py'
    spec = importlib.util.spec_from_file_location('native_process_tree', path)
    if spec is None or spec.loader is None:
        raise NativeRunError('owned process helper unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_natural_observer():
    path = Path(__file__).resolve().parent / 'perf_ab.py'
    spec = importlib.util.spec_from_file_location('native_natural_observer', path)
    if spec is None or spec.loader is None:
        raise NativeRunError('natural completion observer unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.observe_natural_completion


def run(root: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    module = load_process_tree()
    try:
        owner = module.OwnedProcess.spawn(list(args), cwd=root, env=env, text=True,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except BaseException as exc:
        cleanup = getattr(exc, 'cleanup', None)
        if not isinstance(cleanup, dict) or cleanup.get('cleanup_complete') is not True:
            raise ProcessCleanupUnknown('owned process startup cleanup not established') from exc
        raise NativeRunError('owned process startup failed') from exc
    error = None
    output = ('', '')
    try:
        output = owner.process.communicate(timeout=COMMAND_TIMEOUT_SECONDS)
    except BaseException as exc:
        error = exc
    natural = False
    if error is None:
        try:
            natural = load_natural_observer()(owner).get('no_running_members') is True
        except BaseException as exc:
            error = exc
    try:
        cleanup = owner.close(5)
    except BaseException as exc:
        raise ProcessCleanupUnknown(f'owned process cleanup failed: {type(exc).__name__}') from exc
    finally:
        for stream in (owner.process.stdout, owner.process.stderr):
            if stream is not None:
                stream.close()
    if (cleanup.get('owned_process_exited') is not True
            or cleanup.get('owned_tree_no_running_members') is not True
            or cleanup.get('process_group_cleanup_error') is not None):
        raise ProcessCleanupUnknown('owned process cleanup not established')
    if error:
        raise NativeRunError(f'command did not finish: {type(error).__name__}') from error
    if not natural:
        raise NativeRunError('owned process natural completion not established')
    result = subprocess.CompletedProcess(list(args), owner.process.returncode, *output)
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


# Future acceptance preparation only: the released 0.16.1 runtime validator
# remains unchanged. The next candidate must align its own validator and Hooks.
def marketplace_name_for_version(version: str) -> str:
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?", version)
    if match is None:
        raise NativeRunError("unsupported marketplace version")
    core = tuple(int(part) for part in match.groups())
    # Historical identity facts are not rewritten: the published 0.16.0 and
    # 0.16.1 packages declare the experimental marketplace, and every later
    # version uses the stable identity. Both transitions are separate
    # native scenarios (experimental->stable and stable->stable).
    if core in {(0, 16, 0), (0, 16, 1)}:
        return "codex-context-guard-v016"
    if core >= (0, 16, 2):
        return "codex-context-guard"
    raise NativeRunError("unsupported marketplace version")


def candidate_marketplace_name(source: Path, version: str) -> str:
    try:
        manifest = json.loads((source / ".agents/plugins/marketplace.json").read_text(encoding="utf-8"))
        expected = marketplace_name_for_version(version)
        if not isinstance(manifest, dict) or manifest.get("name") != expected:
            raise NativeRunError("candidate marketplace identity differs from version")
        return expected
    except (OSError, json.JSONDecodeError) as exc:
        raise NativeRunError("candidate marketplace manifest unavailable") from exc


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
    market = marketplace_name_for_version(version)
    plugin_id = f"context-guard@{market}"
    matches = [entry for entry in entries if isinstance(entry, dict)
               and entry.get("pluginId") == plugin_id]
    if len(matches) != 1:
        raise NativeRunError("official installed identity is missing or ambiguous")
    if not isinstance(added, dict):
        raise NativeRunError("official add is not an object")
    entry = matches[0]
    expected = {"pluginId": plugin_id, "name": "context-guard",
                "marketplaceName": market, "version": version}
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
    cache = home / "plugins" / "cache" / market / "context-guard"
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
    market = candidate_marketplace_name(source, version)
    plugin_id = f"context-guard@{market}"
    if added is None:
        # Caller owns a newly created HOME; the marketplace is not registered.
        if (environment.get('CODEX_HOME') != str(home) or
                any((home / path).exists() for path in ('config.toml', 'plugins/installed_plugins.json',
                    f'plugins/cache/{market}'))):
            raise NativeRunError('fresh isolated HOME precondition failed')
        run(root, codex, "plugin", "marketplace", "add", str(source), env=environment)
        added = json.loads(run(root, codex, "plugin", "add", plugin_id,
                               "--json", env=environment).stdout)
    listed = json.loads(run(root, codex, "plugin", "list", "--marketplace",
                            market, "--json", env=environment).stdout)
    if not isinstance(listed, dict):
        raise NativeRunError("official list is not an object")
    entries = listed.get("installed")
    if not isinstance(entries, list):
        raise NativeRunError("official list has no installed array")
    matches = [item for item in entries if isinstance(item, dict)
               and item.get("pluginId") == plugin_id]
    if not matches:
        raise NativeRunError("installed plugin disappeared")
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
    repository_url = normalize_repository_url(run(root, "git", "remote", "get-url", "origin").stdout)
    version = json.loads((root / ".codex-plugin/plugin.json").read_text())["version"]
    started = timestamp()
    gates = [gate("source_identity", digest, passed=True)]
    status, cleanup = "failed", "passed"
    retain_temporary = False
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
        market = candidate_marketplace_name(source, version)
        previous_market = ("codex-context-guard-v016" if market == "codex-context-guard"
                           else "codex-context-guard")
        old = home / "plugins" / "cache" / previous_market / "context-guard" / "0.15.1"
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
        retain_temporary = isinstance(exc, ProcessCleanupUnknown)
        print(f"[FAIL] {exc}", file=sys.stderr)
        gates.append(gate("official_marketplace_workflow", digest, passed=False,
                          note="official command, identity, artifact, no-op or preservation check failed; inspect local diagnostics"))
    finally:
        if not retain_temporary:
            shutil.rmtree(temporary, ignore_errors=True)
        if temporary.exists():
            cleanup, status = "failed", "failed"
    return {"schema": "native-acceptance/v2", "status": status,
        "product": "codex_context_guard", "gate_profile": "portable_runtime",
        "repository": {"url": repository_url, "commit": source_commit},
        "runtime_tree_sha256": digest, "artifact": artifact,
        "platform": {"os": {"Darwin": "macos", "Windows": "windows"}.get(platform.system(), "linux"),
                     "shell": "python-subprocess", "toolchain": {"python": platform.python_version(), "codex": codex_version}},
        "gates": gates, "cleanup": {"status": cleanup, "remaining_ids": [] if cleanup == "passed" else ["official_temporary_root"]},
        "run": {"started_at": started, "finished_at": timestamp(), "run_url": run_url},
        "limitations": ["local marketplace source retained only during this isolated gate; no long-term refresh/startup claim",
                        "direct repeated plugin add is not claimed idempotent", "no normal Hook trust or real old-task continuity established"],
        "unperformed_actions": ["commit", "push", "merge", "tag", "release", "public_promotion"]}


RETENTION_BATCH_SCHEMA = "cg-retention-native-batch/v3"
# The exact scenario set a consumer requires; a missing, renamed or extra
# scenario fails the batch instead of shrinking it.
RETENTION_BATCH_SCENARIOS = (
    "non_empty_backlog",
    "busy_lock_contention",
    "kept_ledger_readback",
    "transparent_resume_keeps_ledger",
    "explicit_restore_verified",
    "purge_complete",
    "purge_partial_resume",
    "crash_boundaries",
    "replacement_refusal",
    # v3 (0.17.0 R5, plan D1): every invocation is a fresh process.
    "fresh_process_discovery_within_capacity",
    "fresh_process_capacity_exceeded",
    "fresh_process_purge_progress",
)

# A fresh interpreter running the real maintenance entry under a modeled
# clock: each namespace/quarantine entry listed costs LIST ms, each entry
# listed inside an object being purged costs PURGE ms, each deadline check
# one microsecond. The order model lists names sorted (a stable adversarial
# order); costs are charged per yielded entry. Used where a deterministic
# budget is needed; the within-capacity scenario runs the real CLI instead.
_RETENTION_FRESH_DRIVER = r"""
import importlib.util, json, os, sys
from pathlib import Path
from unittest import mock
script, data_dir = sys.argv[1], Path(sys.argv[2])
budget, list_ms, purge_ms, future = (float(value) for value in sys.argv[3:7])
spec = importlib.util.spec_from_file_location("context_guard_fresh", script)
cg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cg)
clock = [1000.0]
def monotonic():
    clock[0] += 1e-6
    return clock[0]
namespace = data_dir / cg.V2_NAMESPACE
qdir = cg._retention_quarantine_dir(data_dir)
real_scandir = os.scandir
class Charged:
    def __init__(self, source, cost, names=None):
        self.source, self.cost = source, cost
        self.names = iter(names) if names is not None else None
    def __iter__(self):
        return self
    def __next__(self):
        entry = next(self.names) if self.names is not None else next(self.source)
        clock[0] += self.cost
        return entry
    def close(self):
        self.source.close()
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self.close()
        return False
def scandir(path):
    source = real_scandir(path)
    if isinstance(path, int):
        return Charged(source, purge_ms / 1000.0)
    target = Path(path)
    if target in (namespace, qdir):
        return Charged(source, list_ms / 1000.0, sorted(source, key=lambda e: e.name))
    if qdir in target.parents:
        return Charged(source, purge_ms / 1000.0)
    return source
patches = [mock.patch.object(cg.time, "monotonic", side_effect=monotonic),
           mock.patch.object(cg.os, "scandir", side_effect=scandir)]
if future:
    real_datetime = cg.dt.datetime
    moment = real_datetime.now(cg.dt.timezone.utc) + cg.dt.timedelta(days=future)
    class Future(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return moment if tz is not None else moment.replace(tzinfo=None)
    patches.append(mock.patch.object(cg.dt, "datetime", Future))
for patch in patches:
    patch.start()
start = clock[0]
report = cg.cleanup_old_sessions(data_dir, apply=True, deadline=start + budget / 1000.0)
print(json.dumps({"backlog": report.get("backlog"),
                  "scan_complete": report.get("scan_complete"),
                  "capacity_exceeded": report.get("capacity_exceeded"),
                  "purge": report.get("purge"),
                  "virtual_ms": round((clock[0] - start) * 1000.0, 4)}))
"""
_RETENTION_LEDGER_FIELDS = ("requirements", "acceptance_items", "work_units",
                            "open_items", "wait_conditions")


def retention_batch_capability() -> list[str]:
    """Native primitives the batch relies on; an empty list means usable."""
    missing = []
    try:
        import fcntl  # noqa: F401
    except ImportError:
        try:
            import msvcrt  # noqa: F401
        except ImportError:
            missing.append("file_lock")
    if not hasattr(os, "rename") or not hasattr(os, "scandir"):
        missing.append("filesystem")
    return missing


def check_retention_batch_inputs(repo_root: Path, source_commit: str, output: Path) -> None:
    """Everything a retention batch run needs, without running it.

    Expected identity (full SHA equal to the clean checked-out HEAD), native
    lock capability and a safe, new result location outside the source
    tree. Raises NativeRunError; writes nothing.
    """
    verify_exact_source(repo_root, source_commit)
    missing = retention_batch_capability()
    if missing:
        raise NativeRunError("retention batch capability missing: " + ",".join(missing))
    behavior = load_host_behavior()
    try:
        behavior.check_output_path(output, repo_root)
    except (OSError, behavior.HostBehaviorError) as exc:
        raise NativeRunError(str(exc)) from exc


def validate_retention_batch_result(
    result: Any, *, source_commit: str, runtime_tree_sha256: str,
) -> list[str]:
    """Consumer of a retention batch result: identity, the exact scenario
    set, and each scenario's own oracle facts. Returns the errors; an empty
    list is the only acceptance."""
    errors: list[str] = []
    if not isinstance(result, dict):
        return ["result is not an object"]
    if result.get("schema") != RETENTION_BATCH_SCHEMA:
        errors.append("schema")
    if result.get("source_commit") != source_commit:
        errors.append("source_commit")
    if result.get("runtime_tree_sha256") != runtime_tree_sha256:
        errors.append("runtime_tree_sha256")
    scenarios = result.get("scenarios")
    if not isinstance(scenarios, list):
        return errors + ["scenarios"]
    by_name = {}
    for row in scenarios:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            errors.append("scenario_row")
            continue
        if row["name"] in by_name:
            errors.append(f"duplicate:{row['name']}")
        by_name[row["name"]] = row
    if set(by_name) != set(RETENTION_BATCH_SCENARIOS):
        errors.append("scenario_set")
    for name in RETENTION_BATCH_SCENARIOS:
        row = by_name.get(name)
        if row is None:
            continue
        if row.get("status") != "passed":
            errors.append(f"failed:{name}")
        detail = row.get("detail")
        if not isinstance(detail, dict):
            errors.append(f"detail:{name}")
            continue
        checks = detail.get("checks")
        if (not isinstance(checks, dict) or not checks
                or any(value is not True for value in checks.values())):
            errors.append(f"checks:{name}")
    errors.extend(_validate_fresh_process_rows(by_name))
    kept = by_name.get("kept_ledger_readback", {}).get("detail", {})
    objects = kept.get("objects") if isinstance(kept, dict) else None
    if (not isinstance(objects, list) or len(objects) != 6
            or any(not isinstance(item, dict) or item.get("ledger_equal") is not True
                   or item.get("state_bytes_equal") is not True
                   or item.get("still_unfinished") is not True for item in objects)):
        errors.append("kept_ledger_objects")
    failed = [row for row in by_name.values() if row.get("status") != "passed"]
    expected_status = "passed" if not failed and not errors else "failed"
    if result.get("status") != expected_status and not errors:
        errors.append("status_inconsistent")
    if result.get("status") == "passed" and errors:
        errors.append("status_claims_pass")
    return errors


def _validate_fresh_process_rows(by_name: dict[str, Any]) -> list[str]:
    """Per-run facts of the v3 fresh-process scenarios, re-derived from the
    recorded runs rather than trusted from the scenario's own checks."""
    errors: list[str] = []

    def runs_of(name: str) -> list[dict[str, Any]] | None:
        detail = by_name.get(name, {}).get("detail")
        runs = detail.get("runs") if isinstance(detail, dict) else None
        if (not isinstance(runs, list) or not runs
                or not all(isinstance(run, dict) for run in runs)):
            return None
        return runs

    within = runs_of("fresh_process_discovery_within_capacity")
    if (within is None or len(within) > 6
            or any(run.get("capacity_exceeded") is not False for run in within)
            or by_name["fresh_process_discovery_within_capacity"]["detail"].get(
                "tail_reached_run") not in (1, 2, 3)
            or within[-1].get("scan_complete") is not True):
        errors.append("within_capacity_runs")
    beyond = runs_of("fresh_process_capacity_exceeded")
    if (beyond is None or len(beyond) < 6
            or any(run.get("backlog") is not True for run in beyond)
            or any(run.get("scan_complete") is not False for run in beyond)
            or any(run.get("capacity_exceeded") is not True for run in beyond[2:])
            or any(not isinstance(run.get("virtual_ms"), (int, float))
                   or run["virtual_ms"] > float(run.get("budget_ms", 0)) + 2.0
                   for run in beyond)):
        errors.append("capacity_exceeded_runs")
    purge = by_name.get("fresh_process_purge_progress", {}).get("detail", {})
    remaining = purge.get("remaining") if isinstance(purge, dict) else None
    if (not isinstance(remaining, list) or len(remaining) < 3
            or not all(type(value) is int for value in remaining)
            or remaining[-1] != 0 or remaining[0] < 19
            or any(later > earlier for earlier, later in zip(remaining, remaining[1:]))
            or any(a == b == c for a, b, c in zip(remaining, remaining[1:], remaining[2:])
                   if c)):
        errors.append("purge_progress_runs")
    return errors


def retention_native_batch(
    repo_root: Path, output: Path, *, source_commit: str | None = None,
) -> dict[str, Any]:
    """Versioned no-model retention acceptance batch (0.17.0 C01, R2).

    One shared contract for macOS and Windows. The batch builds an isolated
    synthetic data root, drives the real retention entry points, and judges
    every scenario by per-object oracles rather than counts: an eligible
    object held under a REAL lifecycle lock must stay and then be taken once
    released; every should-keep object is read back through the official
    reader with its saved ledger and exact state bytes; purge completes and
    resumes; each transaction crash boundary is settled; replaced or linked
    quarantine objects are refused. The result is bound to the expected
    source commit (equal to the clean HEAD) and runtime digest and written
    with exclusive creation. Platform-specific adversarial cases (junction/
    reparse, DACL, held handles, case/long paths) keep their dedicated
    native gates.
    """
    started = timestamp()
    repo_root = repo_root.resolve()
    digest = runtime_digest(load_artifacts(repo_root), repo_root)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_root,
                          capture_output=True, text=True, check=True).stdout.strip()
    expected = source_commit if source_commit is not None else head
    verify_exact_source(repo_root, expected)
    scenarios = run_retention_batch_scenarios(repo_root)
    return _finish_retention_batch(output, scenarios, expected, digest, started)


def run_retention_batch_scenarios(repo_root: Path) -> list[dict[str, Any]]:
    """The scenario family itself, without identity checks or output (the
    identity-bound entry is ``retention_native_batch``)."""
    import importlib.util
    import tempfile
    import time as _time
    from unittest import mock
    scenarios: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ccg-retention-batch-") as temp:
        work = Path(temp).resolve()
        data_dir = work / "private"
        data_dir.mkdir()
        saved_env = {key: os.environ.get(key) for key in (
            "CONTEXT_GUARD_DATA_DIR", "CODEX_HOME", "HOME", "USERPROFILE")}
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(data_dir)
        os.environ["CODEX_HOME"] = str(work / "codex-home")
        os.environ["HOME"] = str(work / "os-home")
        os.environ["USERPROFILE"] = str(work / "os-home")
        old_path = list(sys.path)
        sys.path.insert(0, str(repo_root / "scripts"))
        spec = importlib.util.spec_from_file_location(
            "context_guard_batch", repo_root / "scripts" / "context_guard.py")
        cg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cg)
        sessions = data_dir / "sessions-v2"
        qdir = cg._retention_quarantine_dir(data_dir)

        def payload(event, session, **extra):
            base = {"hook_event_name": event, "session_id": session,
                    "cwd": str(work), "turn_id": "t1"}
            base.update(extra)
            return base

        def home(name):
            return sessions / cg.safe_session_id(name)

        def make(name, *, ended_days_ago, finished=True):
            cg.dispatch(payload("UserPromptSubmit", name,
                                prompt="请先核对验收说明。"))
            state_path = home(name) / "state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if finished:
                for item in state.get("requirements", []):
                    item["status"] = "pass"
                for item in state.get("acceptance_items", []):
                    item["status"] = "pass"
                for unit in state.get("work_units", []):
                    unit["status"] = "completed"
                    unit["closed_at"] = cg.utc_now()
                state["open_items"] = []
                state["wait_conditions"] = []
            if ended_days_ago is not None:
                state["session"]["ended_at"] = (
                    cg.dt.datetime.now(cg.dt.timezone.utc)
                    - cg.dt.timedelta(days=ended_days_ago)
                ).isoformat().replace("+00:00", "Z")
            state["content_hash"] = cg.state_content_hash(state)
            state_path.write_text(json.dumps(state, ensure_ascii=False),
                                  encoding="utf-8")

        def records_for(name):
            return [(path, record) for path, record in cg._retention_iter_records(qdir)
                    if record.get("original_name") == cg.safe_session_id(name)]

        def ledger(state):
            return {field: state.get(field) for field in _RETENTION_LEDGER_FIELDS}

        def read_official(name):
            return cg.load_state(home(name), payload("SessionStart", name))

        def scenario(name, checks, **detail):
            scenarios.append({"name": name,
                              "status": "passed" if checks and all(checks.values())
                              else "failed",
                              "detail": dict(detail, checks=checks)})

        def future_clock(days):
            real = cg.dt.datetime
            moment = real.now(cg.dt.timezone.utc) + cg.dt.timedelta(days=days)

            class Future(real):
                @classmethod
                def now(cls, tz=None):
                    return moment if tz is not None else moment.replace(tzinfo=None)
            return mock.patch.object(cg.dt, "datetime", Future)

        def hold_lock(name):
            handle = open(cg.lifecycle_lock_path(home(name)), "a+b")
            if os.name == "nt":
                import msvcrt
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return handle

        def unlock(handle):
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                handle.close()

        def run_pass(**kwargs):
            return cg.cleanup_old_sessions(
                data_dir, apply=True, deadline=_time.monotonic() + 20.0, **kwargs)

        try:
            for index in range(6):
                make(f"eligible-{index:02d}", ended_days_ago=45)
                make(f"kept-{index:02d}", ended_days_ago=45, finished=False)
            make("busy-eligible", ended_days_ago=45)
            kept_before = {}
            for index in range(6):
                name = f"kept-{index:02d}"
                kept_before[name] = {
                    "bytes": (home(name) / "state.json").read_bytes(),
                    "ledger": ledger(read_official(name)),
                }
            cg.write_retention_policy(data_dir, enabled=True, quarantine_days=7)

            # Busy lock contention: an otherwise eligible object stays while a
            # real lifecycle lock is held, and is taken once it is released.
            handle = hold_lock("busy-eligible")
            try:
                first = run_pass()
                locked_kept = home("busy-eligible").is_dir()
                locked_reason = any(entry.get("name") == cg.safe_session_id("busy-eligible")
                                    and entry.get("reason") == "busy_lock"
                                    for entry in first["entries"])
            finally:
                unlock(handle)
            scenario("non_empty_backlog", {
                "quarantined_six": first["counts"]["quarantined"] == 6,
                "protected_seven": first["counts"]["protected"] == 7,
                "records_bound": all(len(records_for(f"eligible-{i:02d}")) == 1
                                     and records_for(f"eligible-{i:02d}")[0][1].get("tree")
                                     for i in range(6)),
            }, counts=first["counts"])
            second = run_pass()
            scenario("busy_lock_contention", {
                "locked_kept": locked_kept,
                "locked_reason_busy": locked_reason,
                "released_quarantined": not home("busy-eligible").exists()
                and len(records_for("busy-eligible")) == 1,
            }, second_counts=second["counts"])

            # Every should-keep object, through the official reader.
            objects = []
            for name, before in kept_before.items():
                state_path = home(name) / "state.json"
                exists = state_path.is_file()
                after_bytes = state_path.read_bytes() if exists else b""
                try:
                    state = read_official(name)
                    after_ledger = ledger(state)
                    unfinished = cg._retention_has_unfinished_work(state)
                except Exception:  # noqa: BLE001 - recorded as a failed oracle
                    after_ledger, unfinished = None, False
                objects.append({
                    "name": name,
                    "state_bytes_equal": exists and after_bytes == before["bytes"],
                    "ledger_equal": after_ledger == before["ledger"],
                    "still_unfinished": bool(unfinished),
                })
            scenario("kept_ledger_readback", {
                "all_objects": len(objects) == 6 and all(
                    item["state_bytes_equal"] and item["ledger_equal"]
                    and item["still_unfinished"] for item in objects),
            }, objects=objects)

            # Transparent resume restores the complete ledger.
            path, record = records_for("eligible-00")[0]
            before_state = json.loads(
                (qdir / record["quarantine_object"] / "state.json").read_text(encoding="utf-8"))
            cg.dispatch(payload("SessionStart", "eligible-00", source="resume"))
            resumed = json.loads((home("eligible-00") / "state.json").read_text(encoding="utf-8"))
            scenario("transparent_resume_keeps_ledger", {
                "ledger_equal": ledger(resumed) == ledger(before_state),
                "record_retired": not records_for("eligible-00"),
            })

            # Explicit restore verifies the content it moves back.
            path, record = records_for("eligible-01")[0]
            restored = cg.retention_restore(data_dir, cg.safe_session_id("eligible-01"))
            readback = read_official("eligible-01")
            path2, record2 = records_for("eligible-02")[0]
            (qdir / record2["quarantine_object"] / "state.json").unlink()
            damaged = cg.retention_restore(data_dir, cg.safe_session_id("eligible-02"))
            scenario("explicit_restore_verified", {
                "restored": restored.get("outcome") == "restored",
                "reader_reads_saved_ledger": readback.get("requirements") is not None,
                "damaged_refused": damaged.get("outcome") == "refused"
                and damaged.get("reason") == "content_mismatch",
                "damaged_kept_in_quarantine": (qdir / record2["quarantine_object"]).is_dir()
                and bool(records_for("eligible-02")),
            })

            # Replaced or linked quarantine objects are refused, not followed.
            outside = work / "outside-object"
            outside.mkdir()
            (outside / "keep.txt").write_text("outside", encoding="utf-8")
            path4, record4 = records_for("eligible-04")[0]
            target4 = qdir / record4["quarantine_object"]
            import shutil as _shutil
            _shutil.rmtree(target4)
            target4.mkdir()
            path5, record5 = records_for("eligible-05")[0]
            target5 = qdir / record5["quarantine_object"]
            _shutil.rmtree(target5)
            linked = True
            try:
                os.symlink(outside, target5, target_is_directory=True)
            except (OSError, NotImplementedError):
                linked = False
            # Purge after grace: tombstone, record retired, no restore, no
            # silent recreation.
            path, record = records_for("eligible-03")[0]
            target = qdir / record["quarantine_object"]
            with future_clock(8):
                purge = run_pass()
            recreate_refused = False
            try:
                cg.dispatch(payload("UserPromptSubmit", "eligible-03", prompt="继续"))
            except Exception:  # noqa: BLE001 - refusal is the expected outcome
                recreate_refused = True
            scenario("purge_complete", {
                "target_gone": not target.exists(),
                "tombstone": (qdir / (record["quarantine_object"] + ".tombstone.json")).is_file(),
                "record_retired": not records_for("eligible-03"),
                "restore_unavailable": cg.retention_restore(
                    data_dir, cg.safe_session_id("eligible-03")).get("outcome") != "restored",
                "recreation_refused": recreate_refused or not home("eligible-03").exists(),
            }, purge=purge.get("purge"))

            refused_pass = purge
            scenario("replacement_refusal", {
                "replaced_not_purged": target4.is_dir() and bool(records_for("eligible-04")),
                "replaced_restore_refused": cg.retention_restore(
                    data_dir, cg.safe_session_id("eligible-04")).get("outcome") != "restored",
                "outside_untouched": (outside / "keep.txt").is_file(),
                "link_refused": (not linked) or bool(records_for("eligible-05")),
            }, link_created=linked, purge=refused_pass.get("purge"))

            # Partial purge: never restorable, completed by the next pass.
            make("partial-purge", ended_days_ago=45)
            run_pass()
            path, record = records_for("partial-purge")[0]
            target = qdir / record["quarantine_object"]
            real_purge_tree = cg._retention_purge_tree

            def interrupted(tree, deadline):
                (tree / "state.json").unlink()
                return False
            with future_clock(8), mock.patch.object(cg, "_retention_purge_tree",
                                                    side_effect=interrupted):
                run_pass()
            state_after_partial = (records_for("partial-purge") or [(None, {})])[0][1].get("state")
            refused = cg.retention_restore(data_dir, cg.safe_session_id("partial-purge"))
            with future_clock(8):
                run_pass()
            scenario("purge_partial_resume", {
                "marked_purge_planned": state_after_partial == "purge_planned",
                "restore_refused": refused.get("outcome") != "restored",
                "completed_next_pass": not target.exists() and not records_for("partial-purge"),
                "real_tree_helper_restored": cg._retention_purge_tree is real_purge_tree,
            })

            # Crash boundaries of every transition.
            checks = {}
            make("crash-a", ended_days_ago=45)
            with mock.patch.object(cg.os, "rename", side_effect=OSError("crash")), \
                    mock.patch.object(cg.Path, "unlink", side_effect=OSError("crash")):
                run_pass()
            checks["planned_left_by_crash"] = any(
                record.get("state") == "planned" for _p, record in records_for("crash-a"))
            run_pass()
            checks["planned_settled"] = not any(
                record.get("state") == "planned" for _p, record in records_for("crash-a"))
            checks["planned_rolled_back_or_retaken"] = home("crash-a").is_dir() or [
                record.get("state") for _p, record in records_for("crash-a")] == ["quarantined"]
            make("crash-b", ended_days_ago=45)
            real_write = cg._retention_write_record

            def fail_commit(path, body):
                if body.get("state") == "quarantined":
                    raise OSError("crash after rename")
                return real_write(path, body)
            with mock.patch.object(cg, "_retention_write_record", side_effect=fail_commit):
                run_pass()
            checks["commit_lost_leaves_planned"] = any(
                record.get("state") == "planned" for _p, record in records_for("crash-b"))
            cg._retention_recover_records(qdir, cg.dt.datetime.now(cg.dt.timezone.utc))
            checks["commit_promoted"] = [record.get("state") for _p, record
                                         in records_for("crash-b")] == ["quarantined"]
            with mock.patch.object(cg.os, "rename", side_effect=OSError("crash")):
                cg.retention_restore(data_dir, cg.safe_session_id("crash-b"))
            checks["failed_restore_reverted"] = [record.get("state") for _p, record
                                                 in records_for("crash-b")] == ["quarantined"]
            path, record = records_for("crash-b")[0]

            def fail_tombstone(path, body):
                if body.get("schema") == cg.RETENTION_TOMBSTONE_SCHEMA:
                    raise OSError("disk full after data deletion")
                return real_write(path, body)
            with future_clock(8), mock.patch.object(
                    cg, "_retention_write_record", side_effect=fail_tombstone):
                run_pass()
            checks["tombstone_loss_keeps_purge_record"] = [
                r.get("state") for _p, r in records_for("crash-b")] == ["purge_planned"]
            with future_clock(8):
                run_pass()
            checks["tombstone_completed_next_pass"] = (
                not records_for("crash-b")
                and (qdir / (record["quarantine_object"] + ".tombstone.json")).is_file())
            scenario("crash_boundaries", checks)

            _retention_fresh_process_scenarios(
                cg, repo_root, work, payload, scenario, future_clock)

        except Exception as exc:  # noqa: BLE001 - retain failed scenario
            scenarios.append({"name": "batch_error", "status": "failed",
                              "detail": {"error": f"{type(exc).__name__}: {exc}"[:200],
                                         "checks": {"completed": False}}})
        finally:
            sys.path[:] = old_path
            for key, value in saved_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
    return scenarios


def _retention_fresh_process_scenarios(cg, repo_root: Path, work: Path, payload,
                                       scenario, future_clock) -> None:
    """v3 scenarios: every maintenance invocation is a NEW interpreter, the
    lifetime of the scheduled executor, each on its own synthetic root."""
    import time as _time
    script = repo_root / "scripts" / "context_guard.py"

    def make_in(root: Path, name: str, *, ended_days_ago=None, finished=True):
        previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(root)
        try:
            cg.dispatch(payload("UserPromptSubmit", name, prompt="请先核对验收说明。"))
        finally:
            if previous is None:
                os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
            else:
                os.environ["CONTEXT_GUARD_DATA_DIR"] = previous
        home = root / "sessions-v2" / cg.safe_session_id(name)
        state_path = home / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if finished:
            for group in ("requirements", "acceptance_items"):
                for item in state.get(group, []):
                    item["status"] = "pass"
            for unit in state.get("work_units", []):
                unit["status"] = "completed"
                unit["closed_at"] = cg.utc_now()
            state["open_items"] = []
            state["wait_conditions"] = []
        if ended_days_ago is not None:
            state["session"]["ended_at"] = (
                cg.dt.datetime.now(cg.dt.timezone.utc)
                - cg.dt.timedelta(days=ended_days_ago)
            ).isoformat().replace("+00:00", "Z")
        state["content_hash"] = cg.state_content_hash(state)
        state_path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
        return home

    def prefix_and_legacy_tail(root: Path, *, registered=None):
        for index in range(8):
            make_in(root, f"a-prefix-{index:02d}", finished=False)
        if registered:
            make_in(root, registered, ended_days_ago=45)
        cg.write_retention_policy(root, enabled=True, quarantine_days=1)
        before = cg._read_discovery_registry(root)
        tail = make_in(root, "z-legacy-tail", ended_days_ago=45)
        cg._compact_discovery_registry(root, before)  # an old runtime's creation
        return tail

    def modeled(root: Path, budget: float, *, list_ms=1.0, purge_ms=0.0, future=0.0):
        done = subprocess.run(
            [sys.executable, "-I", "-B", "-c", _RETENTION_FRESH_DRIVER, str(script),
             str(root), str(budget), str(list_ms), str(purge_ms), str(future)],
            capture_output=True, text=True, timeout=120, check=True)
        row = json.loads(done.stdout.strip().splitlines()[-1])
        row["budget_ms"] = budget
        return row

    # Within capacity, real executor and real clock: the scheduled command
    # line (`cleanup --data-dir <root> --apply --json`) in fresh processes.
    root = work / "fresh-within"
    (root / "sessions-v2").mkdir(parents=True)
    tail = prefix_and_legacy_tail(root)
    hint_lost = cg.safe_session_id("z-legacy-tail") not in cg._read_discovery_registry(root)
    runs, reached = [], None
    for index in range(6):
        done = subprocess.run(
            [sys.executable, "-B", str(script), "cleanup", "--data-dir", str(root),
             "--apply", "--json"], capture_output=True, text=True, timeout=120,
            check=True)
        report = json.loads(done.stdout)
        runs.append({"backlog": report.get("backlog"),
                     "scan_complete": report.get("scan_complete"),
                     "capacity_exceeded": report.get("capacity_exceeded")})
        if reached is None and not tail.exists():
            reached = index + 1
        if reached is not None and report.get("scan_complete"):
            break
        _time.sleep(0.01)
    scenario("fresh_process_discovery_within_capacity", {
        "tail_had_no_hint": hint_lost,
        "tail_reached_within_three": reached is not None and reached <= 3,
        "never_capacity_exceeded": all(run["capacity_exceeded"] is False for run in runs),
        "scan_completes": runs[-1]["scan_complete"] is True,
    }, runs=runs, tail_reached_run=reached)

    # Beyond capacity (modeled 1 ms per listed entry, 4 ms per invocation):
    # honest capacity report, registered eligible work still advances.
    root = work / "fresh-beyond"
    (root / "sessions-v2").mkdir(parents=True)
    tail = prefix_and_legacy_tail(root, registered="y-registered-eligible")
    registered = root / "sessions-v2" / cg.safe_session_id("y-registered-eligible")
    runs = [modeled(root, 4.0) for _ in range(8)]
    scenario("fresh_process_capacity_exceeded", {
        "backlog_every_run": all(run["backlog"] is True for run in runs),
        "never_scan_complete": all(run["scan_complete"] is False for run in runs),
        "capacity_reported": all(run["capacity_exceeded"] is True for run in runs[2:]),
        "registered_work_advanced": not registered.exists(),
        "tail_not_claimed": tail.exists(),
        "budget_respected": all(run["virtual_ms"] <= run["budget_ms"] + 2.0 for run in runs),
    }, runs=runs)

    # Purge of a registered quarantined object: 19 children at 1 ms per
    # listed child, 3 ms per invocation, each invocation a fresh process.
    root = work / "fresh-purge"
    (root / "sessions-v2").mkdir(parents=True)
    home = make_in(root, "purge-finite-wide", ended_days_ago=45)
    for index in range(16):
        (home / f"payload-{index:02d}").write_text("synthetic", encoding="utf-8")
    cg.write_retention_policy(root, enabled=True, quarantine_days=1)
    cg.cleanup_old_sessions(root, apply=True, deadline=_time.monotonic() + 20.0)
    qdir = cg._retention_quarantine_dir(root)
    records = [(path, record) for path, record in cg._retention_iter_records(qdir)]
    target = qdir / records[0][1]["quarantine_object"] if records else qdir / "missing"

    def remaining_entries() -> int:
        if not target.exists():
            return 0
        return sum(len(dirs) + len(files) for _d, dirs, files in os.walk(target))
    remaining = [remaining_entries()]
    runs = []
    while target.exists() and len(runs) < 20:
        runs.append(modeled(root, 3.0, purge_ms=1.0, future=2.0))
        remaining.append(remaining_entries())
    tombstone = bool(records) and (
        qdir / (records[0][1]["quarantine_object"] + ".tombstone.json")).is_file()
    scenario("fresh_process_purge_progress", {
        "one_bound_record": len(records) == 1,
        "never_regresses": all(b <= a for a, b in zip(remaining, remaining[1:])),
        "no_two_idle_runs": not any(a == b == c for a, b, c in zip(
            remaining, remaining[1:], remaining[2:]) if c),
        "finished": remaining[-1] == 0 and not target.exists(),
        "record_retired": bool(records) and not records[0][0].exists(),
        "tombstone_written": tombstone,
    }, remaining=remaining, runs=runs)


def _finish_retention_batch(output: Path, scenarios: list[dict[str, Any]],
                            expected: str, digest: str, started: str) -> dict[str, Any]:
    names = [row["name"] for row in scenarios]
    complete = sorted(names) == sorted(RETENTION_BATCH_SCENARIOS)
    failures = [row for row in scenarios if row["status"] != "passed"]
    result = {
        "schema": RETENTION_BATCH_SCHEMA,
        "status": "passed" if complete and not failures else "failed",
        "platform": {"Darwin": "macos", "Windows": "windows"}.get(
            platform.system(), "linux"),
        "source_commit": expected,
        "runtime_tree_sha256": digest,
        "scenarios": scenarios,
        "run": {"started_at": started, "finished_at": timestamp()},
        "limitations": [
            "no-model batch on a synthetic data root; crash boundaries are "
            "injected faults, not power loss",
            "junction/reparse, DACL, held handles and case/long paths keep "
            "their dedicated native gates",
            "no daily data, install, trust or scheduler registration touched",
        ],
        "unperformed_actions": ["commit", "push", "merge", "tag", "release"],
    }
    load_host_behavior().write_result(output, result)
    return result


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
    parser.add_argument(
        "--retention-batch", type=Path, metavar="OUTPUT",
        help="run the versioned no-model retention scenario batch and write "
             "the result; other acceptance gates are not executed")
    args = parser.parse_args(argv)
    if args.retention_batch is not None:
        # The batch shares the formal entry contract: the expected full source
        # commit must equal the clean HEAD, native capability and a new result
        # path outside the checkout are checked first, --preflight stops after
        # those checks without running a scenario or writing anything, and the
        # result is created exclusively and accepted only by its consumer.
        repo_root = (Path(args.repo_root) if args.repo_root else Path.cwd()).resolve()
        try:
            if not HEX40.fullmatch(args.source_commit or ""):
                raise NativeRunError("source commit must be a full lowercase SHA-1")
            check_retention_batch_inputs(repo_root, args.source_commit, args.retention_batch)
            if args.preflight:
                print("native_preflight=passed; input_checks_only; acceptance_not_written")
                return 0
            result = retention_native_batch(repo_root, args.retention_batch,
                                            source_commit=args.source_commit)
            errors = validate_retention_batch_result(
                result, source_commit=args.source_commit,
                runtime_tree_sha256=runtime_digest(load_artifacts(repo_root), repo_root))
        except (NativeRunError, OSError, RuntimeError) as exc:
            print(f"retention_batch=refused; {exc}", file=sys.stderr)
            return 2
        print(json.dumps({"status": result["status"],
                          "scenarios": len(result["scenarios"]),
                          "consumer_errors": errors}))
        return 0 if result["status"] == "passed" and not errors else 1
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
