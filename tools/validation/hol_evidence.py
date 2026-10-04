"""Bind retained HOL reports to public checkout bytes; never scan or submit.

The companion is repository-computed evidence, not a HOL component signature,
publisher certification, or proof of registry ingestion. Original reports are
never rewritten. Diagnostics contain fixed codes, not report bodies or paths.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

SARIF = "ai-plugin-scanner.sarif"
PAYLOAD = "hol-registry-payload.json"
COMPANION = "hol-evidence.json"
MAX_BYTES = 16 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
SEVERITIES = {"critical", "high", "medium", "low", "info"}


class EvidenceError(ValueError):
    pass


def safe_path(root: Path, name: str) -> Path:
    parts = PurePosixPath(name)
    if (not name or not parts.parts or "\\" in name or parts.is_absolute()
            or parts.as_posix() != name or any(p in {".", ".."} for p in parts.parts)):
        raise EvidenceError("unsafe_relative_path")
    path = root
    for part in parts.parts:
        path /= part
        if path.is_symlink():
            raise EvidenceError("symlink_rejected")
    if not path.resolve().is_relative_to(root):
        raise EvidenceError("path_escape")
    return path


def read_bytes(root: Path, name: str) -> bytes:
    path = safe_path(root, name)
    try:
        initial = path.lstat()
        if not stat.S_ISREG(initial.st_mode) or initial.st_size > MAX_BYTES:
            raise EvidenceError("non_regular_or_oversized")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
                raise EvidenceError("non_regular_or_oversized")
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
        disk = path.lstat()
        if (len(raw) > MAX_BYTES or stat.S_ISLNK(disk.st_mode)
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (disk.st_dev, disk.st_ino, disk.st_size, disk.st_mtime_ns)):
            raise EvidenceError("input_changed")
        return raw
    except FileNotFoundError as exc:
        raise EvidenceError("missing") from exc
    except OSError as exc:
        raise EvidenceError("unreadable") from exc


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                            check=False, timeout=30)
    if result.returncode:
        raise EvidenceError("git_check_failed")
    return result.stdout


def object_json(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise EvidenceError("duplicate_json_key")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               EvidenceError("invalid_json_constant")))
    except (ValueError, UnicodeError) as exc:
        raise EvidenceError("invalid_json") from exc
    if not isinstance(value, dict):
        raise EvidenceError("json_object_required")
    return value


def validate_report(name: str, value: dict, head: str, repository: str,
                    scanner_version: str) -> None:
    if name == SARIF:
        runs = value.get("runs")
        if value.get("version") != "2.1.0" or not isinstance(runs, list) or len(runs) != 1:
            raise EvidenceError("invalid_sarif")
        run = runs[0]
        if not isinstance(run, dict) or not isinstance(run.get("results"), list):
            raise EvidenceError("invalid_sarif")
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        if (not isinstance(driver, dict) or driver.get("name") != "plugin-scanner"
                or driver.get("version") != scanner_version):
            raise EvidenceError("sarif_scanner_mismatch")
        if not all(isinstance(result, dict) for result in run["results"]):
            raise EvidenceError("invalid_sarif")
    else:
        if value.get("sourceSha") != head:
            raise EvidenceError("payload_source_sha_mismatch")
        if value.get("sourceRepository") != repository:
            raise EvidenceError("payload_repository_mismatch")
        if value.get("scannerVersion") != scanner_version:
            raise EvidenceError("payload_scanner_mismatch")
        counts = value.get("findings")
        score = value.get("score")
        if (not isinstance(counts, dict) or set(counts) != SEVERITIES
                or any(type(v) is not int or v < 0 for v in counts.values())
                or type(score) is not int or not 0 <= score <= 100
                or value.get("grade") not in {"A", "B", "C", "D", "F"}):
            raise EvidenceError("invalid_payload")
        if score < 80 or counts["critical"] or counts["high"]:
            raise EvidenceError("payload_quality_gate_failed")


def collect(root: Path, expected_sha: str, repository: str,
            scanner_version: str, scanner_outcome: str) -> dict:
    record = {"schema": "hol-repository-evidence/v1",
              "evidence_owner": "repository",
              "registry_ingestion": "unverified",
              "publisher_certification": "unverified",
              "status": "failed", "diagnostics": [], "reports": {},
              "upload_paths": [COMPANION]}
    errors = record["diagnostics"]
    snapshots = {}
    if scanner_outcome != "success":
        errors.append("scanner_not_successful")
    try:
        if (not SHA.fullmatch(expected_sha) or not REPOSITORY.fullmatch(repository)
                or not VERSION.fullmatch(scanner_version)):
            raise EvidenceError("invalid_expected_identity")
        if root.is_symlink() or not root.is_dir():
            raise EvidenceError("unsafe_repository_root")
        root = root.resolve(strict=True)
        if Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() != root:
            raise EvidenceError("repository_root_mismatch")
        head = git(root, "rev-parse", "HEAD").decode().strip()
        if not SHA.fullmatch(head):
            raise EvidenceError("invalid_git_head")
        record["source_commit"] = head
        record["workflow_source_commit"] = expected_sha
        record["source_repository"] = repository
        record["scanner_version"] = scanner_version
        if head != expected_sha:
            errors.append("workflow_source_sha_mismatch")
        remote = git(root, "config", "--get", "remote.origin.url").decode().strip()
        if remote not in {f"https://github.com/{repository}",
                          f"https://github.com/{repository}.git",
                          f"git@github.com:{repository}.git"}:
            raise EvidenceError("checkout_repository_mismatch")
        git(root, "diff", "--quiet", "HEAD", "--")
        tracked = set(git(root, "ls-files", "-z").decode().split("\0"))
        raw = read_bytes(root, ".codex-plugin/plugin.json")
        snapshots[".codex-plugin/plugin.json"] = raw
        manifest = object_json(raw)
        version = manifest.get("version")
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            raise EvidenceError("invalid_manifest_version")
        record["manifest"] = {"path": ".codex-plugin/plugin.json", "version": version,
                              "sha256": digest(raw)}
        manager_path = safe_path(root, "scripts/manage_plugin.py")
        snapshots["scripts/manage_plugin.py"] = read_bytes(root, "scripts/manage_plugin.py")
        spec = importlib.util.spec_from_file_location("hol_runtime_manager", manager_path)
        if spec is None or spec.loader is None:
            raise EvidenceError("runtime_manager_unavailable")
        manager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(manager)
        tree = manager.tree_manifest(root)
        if not tree or not set(tree).issubset(tracked):
            raise EvidenceError("runtime_contains_untracked_files")
        record["runtime"] = {"algorithm": "manage_plugin.tree_manifest/canonical-json-sha256",
                             "file_count": len(tree), "sha256": digest(json.dumps(
                                 tree, ensure_ascii=True, sort_keys=True,
                                 separators=(",", ":")).encode())}
        locks = []
        for name in ("uv.lock", "requirements-lock.txt"):
            raw = read_bytes(root, name)
            if name not in tracked or not raw.strip():
                raise EvidenceError("invalid_source_lock")
            snapshots[name] = raw
            locks.append({"path": name, "bytes": len(raw), "sha256": digest(raw)})
        record["locks"] = locks
        for name in (SARIF, PAYLOAD):
            info = record["reports"][name] = {"status": "invalid"}
            try:
                if name in tracked:
                    raise EvidenceError("report_is_tracked")
                raw = read_bytes(root, name)
                snapshots[name] = raw
                info.update({"bytes": len(raw), "sha256": digest(raw)})
                validate_report(name, object_json(raw), head, repository, scanner_version)
                info["status"] = "validated"
                record["upload_paths"].append(name)
            except EvidenceError as exc:
                info["status"] = "missing" if str(exc) == "missing" else "invalid"
                errors.append(("sarif" if name == SARIF else "payload") + ":" + str(exc))
        if any(read_bytes(root, name) != raw for name, raw in snapshots.items()):
            raise EvidenceError("input_changed")
        if manager.tree_manifest(root) != tree or git(root, "rev-parse", "HEAD").decode().strip() != head:
            raise EvidenceError("source_changed")
        git(root, "diff", "--quiet", "HEAD", "--")
    except EvidenceError as exc:
        errors.append(str(exc))
        record["upload_paths"] = [COMPANION]
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        errors.append("collection_failed")
        record["upload_paths"] = [COMPANION]
    record["status"] = "passed" if not errors else "failed"
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-scanner-version", required=True)
    parser.add_argument("--scanner-outcome", required=True,
                        choices=("success", "failure", "cancelled", "skipped"))
    args = parser.parse_args(argv)
    record = collect(args.repo_root, args.expected_source_sha, args.expected_repository,
                     args.expected_scanner_version, args.scanner_outcome)
    try:
        if args.repo_root.is_symlink():
            raise EvidenceError("unsafe_repository_root")
        path = safe_path(args.repo_root.resolve(strict=True), COMPANION)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True, indent=2) + "\n")
    except (OSError, ValueError):
        print("hol_evidence: companion_output_rejected", file=sys.stderr)
        return 1
    print(f"companion_path={COMPANION}")
    for key, name in (("sarif_path", SARIF), ("payload_path", PAYLOAD)):
        if name in record["upload_paths"]:
            print(f"{key}={name}")
    print("hol_evidence: " + record["status"] + " "
          + ",".join(record["diagnostics"]), file=sys.stderr)
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
