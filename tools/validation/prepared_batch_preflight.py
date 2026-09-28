#!/usr/bin/env python3
"""Prepared-batch preflight v1: input readiness for W-class local-process
batches over an UNCOMMITTED candidate.

This is NOT portable_runtime native acceptance and never claims to be: the
repository-native ``native_acceptance.py --profile portable_runtime`` keeps
its strict clean-commit contract untouched. This entry exists because an
uncommitted candidate cannot satisfy that contract without an unauthorized
commit, and W-class process batches still need a verifiable input gate.

Semantics (versioned; changes require a version bump and tests):
- binds the exact base HEAD (``--source-commit``) of the candidate's
  repository, the canonical prepared-source digest (v2 encoding from
  acceptance_identity.py), the runtime tree digest, and a driver manifest
  naming every batch script with its sha256;
- verifies every digest by RECOMPUTING from the working tree — a wrong
  HEAD, wrong digest, or missing driver input fails closed;
- checks the output storage: the ``--output`` receipt path must not exist
  (never overwrite) and its parent must be writable;
- checks local tooling only (python, git). It certifies input readiness
  only: no login, no host trust, no model, no native acceptance.

Exit codes: 0 preflight passed (receipt written); 1 verification failed;
2 usage error; 3 output/storage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

SCHEMA = "prepared-batch-preflight/v1"
DRIVER_MANIFEST_SCHEMA = "prepared-batch-drivers/v1"
HEX64 = "0123456789abcdef"
# The batch MUST ship exactly this driver set: the PowerShell entrypoint
# plus every per-case replay. A manifest naming fewer, more, or duplicated
# files fails closed — a swapped or trimmed manifest can never self-approve.
REQUIRED_DRIVER_PATHS = (
    "run-windows-acceptance.ps1",
    "w3_archive_043_replay.py",
    "w4_archive_044_replay.py",
    "w5_archive_045_replay.py",
    "w6_recovery_replay.py",
    "w7_feedback_chain_replay.py",
)


def _fail(code: int, message: str) -> None:
    print(f"prepared_batch_preflight=failed: {message}", file=sys.stderr)
    raise SystemExit(code)


def _load_identity_tool(repo_root: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "acceptance_identity",
        repo_root / "tools" / "validation" / "acceptance_identity.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _safe_package_path(package_root: Path, relative: str) -> Path:
    """Resolve one package-relative driver path; reject escape and absolute."""
    candidate = (package_root / relative).resolve()
    package_root = package_root.resolve()
    if candidate != package_root and package_root not in candidate.parents:
        raise ValueError(f"driver path escapes the package root: {relative}")
    return candidate


def validate_driver_manifest(manifest: dict, package_root: Path) -> list[dict]:
    """Validate schema, completeness, uniqueness and digests; return drivers.

    Every failure raises: an empty, schema-less, trimmed, duplicated or
    path-escaping manifest can never approve a batch.
    """
    if not isinstance(manifest, dict):
        raise ValueError("driver manifest must be a JSON object")
    if manifest.get("schema") != DRIVER_MANIFEST_SCHEMA:
        raise ValueError(
            f"driver manifest schema must be {DRIVER_MANIFEST_SCHEMA}")
    drivers = manifest.get("drivers")
    if not isinstance(drivers, list) or not drivers:
        raise ValueError("driver manifest drivers must be a non-empty list")
    seen: set[str] = set()
    by_path: dict[str, dict] = {}
    for driver in drivers:
        if not isinstance(driver, dict) or set(driver) != {"path", "sha256"}:
            raise ValueError(
                f"driver entry must contain exactly path and sha256: "
                f"{driver!r}")
        relative = driver["path"]
        if not isinstance(relative, str) or relative.startswith(("/", "\\"))                 or ":" in relative or ".." in Path(relative).parts:
            raise ValueError(f"driver path is not package-relative: "
                             f"{relative!r}")
        if relative in seen:
            raise ValueError(f"duplicate driver path: {relative}")
        if len(driver["sha256"]) != 64 or any(
                c not in HEX64 for c in driver["sha256"]):
            raise ValueError(f"driver sha256 invalid: {relative}")
        seen.add(relative)
        by_path[relative] = driver
    required = set(REQUIRED_DRIVER_PATHS)
    missing = sorted(required - seen)
    if missing:
        raise ValueError(f"driver manifest is missing required files: "
                         f"{missing}")
    extra = sorted(seen - required)
    if extra:
        raise ValueError(f"driver manifest names unknown files: {extra}")
    resolved = []
    for relative in sorted(by_path):
        driver = by_path[relative]
        path = _safe_package_path(package_root, relative)
        if not path.is_file():
            raise ValueError(f"driver file missing in package: {relative}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != driver["sha256"]:
            raise ValueError(
                f"driver sha256 mismatch for {relative}: recomputed "
                f"{digest} != manifest {driver['sha256']}")
        resolved.append({"path": relative, "sha256": digest})
    return resolved


def preflight(repo_root: Path, source_commit: str,
              prepared_sha256: str, runtime_sha256: str,
              driver_manifest: dict, output: Path,
              driver_package_root: Path) -> dict:
    checks: list[dict] = []
    problems: list[str] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})
        if not passed:
            problems.append(f"{name}: {detail}")

    identity_tool = _load_identity_tool(repo_root)
    identity = identity_tool.prepared_source_identity(repo_root)
    check("base_head", identity["head"] == source_commit,
          f"HEAD {identity['head']} vs requested {source_commit}")
    check("prepared_source_sha256",
          identity["prepared_source_sha256"] == prepared_sha256,
          "recomputed prepared-source digest "
          f"{identity['prepared_source_sha256']} vs requested "
          f"{prepared_sha256}")
    runtime = identity_tool.runtime_tree_digest(repo_root)
    check("runtime_tree_sha256", runtime == runtime_sha256,
          f"recomputed runtime digest {runtime} vs requested "
          f"{runtime_sha256}")

    drivers = validate_driver_manifest(driver_manifest, driver_package_root)
    check("driver_manifest", True,
          f"{len(drivers)} required drivers verified against the frozen "
          "package-relative manifest")
    for driver in drivers:
        check(f"driver:{driver['path']}", True,
              f"sha256 {driver['sha256']}")

    try:
        version = subprocess.run(
            [sys.executable, "--version"], capture_output=True,
            text=True, timeout=30).stdout.strip()
        check("python", bool(version), version)
    except OSError as exc:
        check("python", False, str(exc))
    git_version = subprocess.run(
        ["git", "--version"], capture_output=True, text=True, timeout=30
    ).stdout.strip()
    check("git", bool(git_version), git_version)

    if output.exists():
        _fail(3, f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    probe = output.parent / ".preflight-write-probe"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        check("output_storage", True, str(output.parent))
    except OSError as exc:
        check("output_storage", False, str(exc))

    receipt = {
        "schema": SCHEMA,
        "status": "inputs_ready" if not problems else "failed",
        "base_head": identity["head"],
        "prepared_source_sha256": identity["prepared_source_sha256"],
        "runtime_tree_sha256": runtime,
        "driver_manifest": {"schema": DRIVER_MANIFEST_SCHEMA,
                             "package_root": str(driver_package_root),
                             "drivers": drivers},
        "checks": checks,
        "problems": problems,
        "scope_note": ("W-class input readiness only: local process batch "
                       "over an uncommitted candidate. Not portable_runtime "
                       "native acceptance; no host trust, login or model."),
        "machine": {"system": platform.system(),
                    "python": sys.version.split()[0]},
    }
    output.write_text(json.dumps(receipt, indent=2, ensure_ascii=False),
                      encoding="utf-8")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--prepared-source-sha256", required=True)
    parser.add_argument("--runtime-tree-sha256", required=True)
    parser.add_argument("--driver-manifest", type=Path, required=True,
                        help="frozen JSON: {schema, drivers:[{path, sha256}]} "
                             "with package-relative paths")
    parser.add_argument("--driver-package-root", type=Path, required=True,
                        help="directory the package-relative paths resolve "
                             "against on THIS host")
    parser.add_argument("--expected-manifest-sha256",
                        help="frozen manifest digest from the delivery "
                             "envelope; a replaced manifest fails")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if len(args.source_commit) != 40 or any(
            c not in HEX64 for c in args.source_commit):
        _fail(2, "source commit must be a 40-char lowercase sha1")
    for label, value in (("prepared", args.prepared_source_sha256),
                         ("runtime", args.runtime_tree_sha256)):
        if len(value) != 64 or any(c not in HEX64 for c in value):
            _fail(2, f"{label} digest must be a 64-char lowercase sha256")
    if not args.driver_manifest.is_file():
        _fail(2, f"driver manifest missing: {args.driver_manifest}")
    manifest_sha256 = hashlib.sha256(
        args.driver_manifest.read_bytes()).hexdigest()
    if args.expected_manifest_sha256 and manifest_sha256 != \
            args.expected_manifest_sha256:
        _fail(2, f"driver manifest sha256 mismatch: recomputed "
                  f"{manifest_sha256} != expected "
                  f"{args.expected_manifest_sha256} (a replaced manifest "
                  "can never self-approve)")
    try:
        manifest = json.loads(
            args.driver_manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(2, f"driver manifest unreadable: {exc}")
    repo = args.repo_root.resolve()
    try:
        receipt = preflight(repo, args.source_commit,
                            args.prepared_source_sha256,
                            args.runtime_tree_sha256, manifest, args.output,
                            args.driver_package_root.resolve())
    except ValueError as exc:
        _fail(1, str(exc))
    except SystemExit:
        raise
    for problem in receipt.get("problems", []):
        print(f"prepared_batch_preflight=failed: {problem}", file=sys.stderr)
    print("prepared_batch_preflight="
          + ("passed" if receipt["status"] == "inputs_ready" else "failed"))
    return 0 if receipt["status"] == "inputs_ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
