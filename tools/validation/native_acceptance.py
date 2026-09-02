#!/usr/bin/env python3
"""Run portable exact-runtime acceptance and emit native-acceptance/v2 JSON."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HEX40 = re.compile(r"^[0-9a-f]{40}$")


class NativeRunError(RuntimeError):
    """Raised when portable native acceptance cannot establish its contract."""


def load_manager(root: Path):
    path = root / "scripts" / "manage_plugin.py"
    spec = importlib.util.spec_from_file_location("native_acceptance_manage_plugin", path)
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
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


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


def portable_acceptance(
    root: Path, source_commit: str, codex: str, run_url: str | None
) -> dict[str, Any]:
    manager = load_manager(root)
    digest = runtime_digest(manager, root)
    started = timestamp()
    gates: list[dict[str, Any]] = []
    temporary = Path(tempfile.mkdtemp(prefix="codex-context-guard-native-"))
    codex_home = temporary / "codex-home"
    codex_home.mkdir(parents=True)
    cleanup_status = "passed"
    remaining: list[str] = []
    environment = os.environ.copy()
    environment["CODEX_HOME"] = str(codex_home)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        codex_version = run(root, codex, "--version", env=environment).stdout.strip()
    except NativeRunError:
        codex_version = "unavailable"
    try:
        verify_exact_source(root, source_commit)
        gates.append(gate(
            "source_identity", digest, passed=True,
            note="exact clean commit checked before isolated runtime acceptance",
        ))

        manager_command = (
            sys.executable, "scripts/manage_plugin.py", "--repo-root", str(root),
            "--codex-home", str(codex_home), "--codex", codex,
        )
        run(root, *manager_command, "--apply", env=environment)
        gates.append(gate("isolated_install", digest, passed=True))
        run(root, *manager_command, env=environment)
        gates.append(gate("strict_second_noop", digest, passed=True))
        version = manager.source_plugin_version(root)
        installed = manager.plugin_cache_root(codex_home) / version
        if manager.tree_manifest(installed) != manager.tree_manifest(root):
            raise NativeRunError("installed runtime tree differs from repository runtime bytes")
        gates.append(gate("runtime_tree_parity", digest, passed=True))
        run(root, sys.executable, "scripts/smoke_installed.py", "--plugin-root", str(installed), env=environment)
        gates.append(gate("installed_lifecycle_smoke", digest, passed=True))
    except (OSError, UnicodeError, json.JSONDecodeError, NativeRunError, RuntimeError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        gates.append(gate(
            "portable_acceptance", digest, passed=False,
            note="portable gate failed; inspect the platform-local log",
        ))
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
        if temporary.exists():
            cleanup_status = "failed"
            remaining.append("portable_temporary_root")

    repository_url = normalize_repository_url(run(root, "git", "remote", "get-url", "origin").stdout)
    passed = all(item["status"] == "passed" for item in gates) and cleanup_status == "passed"
    return {
        "schema": "native-acceptance/v2",
        "status": "passed" if passed else "failed",
        "product": "codex_context_guard",
        "gate_profile": "portable_runtime",
        "repository": {"url": repository_url, "commit": source_commit},
        "runtime_tree_sha256": digest,
        "artifact": None,
        "platform": {
            "os": {"Darwin": "macos", "Windows": "windows"}.get(platform.system(), "linux"),
            "shell": "python-subprocess",
            "toolchain": {"python": platform.python_version(), "codex": codex_version},
        },
        "gates": gates,
        "cleanup": {"status": cleanup_status, "remaining_ids": remaining},
        "run": {"started_at": started, "finished_at": timestamp(), "run_url": run_url},
        "unperformed_actions": ["commit", "push", "merge", "tag", "release", "public_promotion"],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--run-url")
    args = parser.parse_args(argv)
    if not HEX40.fullmatch(args.source_commit):
        parser.error("source commit must be a full lowercase SHA-1")
    result = portable_acceptance(
        args.repo_root.resolve(), args.source_commit, args.codex, args.run_url
    )
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"native_acceptance={result['status']}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
