#!/usr/bin/env python3
"""Audit one wrapped probe capture as bounded partial diagnostic facts.

The adapter recognizes one deliberately narrow scenario: a repository-owned
probe makes one exact commit and pushes it to a local bare repository.  A
marker in ``PostToolUse`` is necessary but never sufficient.  The adapter also
re-reads the Git commit, parent, tree, blob, worktree status and remote ref from
the live synthetic repositories before it emits any event record.

The captured Bash call runs a Python probe which performs Git internally.
It therefore cannot establish that commit or push itself crossed the host's
direct mutation gate.  The result deliberately emits no host-behavior event
bundle and cannot qualify any gate; it only separates the observed wrapper
pair from independently read Git facts.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

EXPERIMENT_SCHEMA = "context-guard-host-gate-experiment/v1"
MARKER_SCHEMA = "context-guard-host-gate-marker/v1"
OUTPUT_SCHEMA = "context-guard-host-gate-adapter/v1"
MARKER_PREFIX = "CG_HOST_GATE_MARKER_V1 "
MAX_EXPERIMENT_BYTES = 128 * 1024
MAX_MARKER_BYTES = 32 * 1024
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")

EXPERIMENT_KEYS = {
    "schema", "experiment_id", "created_at", "nonce", "scenario",
    "subject", "runtime", "command", "probe", "git", "expected_capture",
    "allowed_untracked",
}
SUBJECT_KEYS = {
    "source_commit", "prepared_source_sha256", "runtime_tree_sha256",
}
RUNTIME_KEYS = {"plugin_version", "capture_tool_sha256"}
COMMAND_KEYS = {"python", "probe_script", "experiment_path", "exact"}
PROBE_KEYS = {"probe_script_sha256", "adapter_sha256"}
GIT_KEYS = {
    "workspace_root", "worktree", "bare_remote", "branch", "target_path",
    "target_sha256", "initial_head", "commit_message",
}
CAPTURE_KEYS = {"pre_sequence", "post_sequence"}
MARKER_KEYS = {
    "schema", "experiment_sha256", "nonce", "scenario", "commit", "parent",
    "tree", "target_path", "target_blob_oid", "target_sha256", "remote_ref",
    "remote_commit",
}


class AdapterError(ValueError):
    """Raised when a capture or its independent readback is not admissible."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError(f"JSON object repeats key {key!r}")
        result[key] = value
    return result


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"{label} is not UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AdapterError(f"{label} must be a JSON object")
    return value


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AdapterError(f"{label} must contain exactly {sorted(keys)}")
    return value


def _string(value: Any, label: str, limit: int = 500) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or "\n" in value
        or "\r" in value
    ):
        raise AdapterError(f"{label} must be a bounded single-line string")
    return value


def _hex(value: Any, label: str, pattern: re.Pattern[str] = HEX64) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise AdapterError(f"{label} is invalid")
    return value


def _relative(value: Any, label: str) -> str:
    raw = _string(value, label, 300)
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or "\\" in raw:
        raise AdapterError(f"{label} must be a portable relative path")
    return raw


def _utc(value: Any, label: str) -> str:
    raw = _string(value, label, 80)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdapterError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise AdapterError(f"{label} must be UTC")
    return raw


def _private_file(path: Path, label: str, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise AdapterError(f"{label} must be a regular file")
    if path.stat().st_size > limit:
        raise AdapterError(f"{label} exceeds the bounded size")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise AdapterError(f"{label} is not owner-private")
    return path.read_bytes()


def _contained(root: Path, value: Any, label: str, *, directory: bool) -> Path:
    raw = Path(_string(value, label, 1000))
    if raw.is_symlink():
        raise AdapterError(f"{label} must not be a symlink")
    resolved = raw.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise AdapterError(f"{label} escapes workspace_root") from exc
    if directory and not resolved.is_dir():
        raise AdapterError(f"{label} must be a directory")
    if not directory and not resolved.is_file():
        raise AdapterError(f"{label} must be a file")
    return resolved


def load_experiment(
    path: Path, expected_sha256: str | None = None
) -> tuple[dict[str, Any], str]:
    raw = _private_file(path, "experiment manifest", MAX_EXPERIMENT_BYTES)
    observed_sha = sha256_bytes(raw)
    if expected_sha256 is not None and observed_sha != _hex(
        expected_sha256, "expected experiment SHA-256"
    ):
        raise AdapterError("experiment manifest SHA-256 changed")
    item = _json_object(raw, "experiment manifest")
    item = _exact(item, EXPERIMENT_KEYS, "experiment")
    if item["schema"] != EXPERIMENT_SCHEMA:
        raise AdapterError("experiment schema mismatch")
    _string(item["experiment_id"], "experiment_id", 128)
    _utc(item["created_at"], "created_at")
    if not isinstance(item["nonce"], str) or not NONCE.fullmatch(item["nonce"]):
        raise AdapterError("experiment nonce is invalid")
    if item["scenario"] != "commit_push":
        raise AdapterError("only the commit_push scenario is supported")
    subject = _exact(item["subject"], SUBJECT_KEYS, "subject")
    _hex(subject["source_commit"], "subject.source_commit", HEX40)
    _hex(subject["prepared_source_sha256"], "subject.prepared_source_sha256")
    _hex(subject["runtime_tree_sha256"], "subject.runtime_tree_sha256")
    runtime = _exact(item["runtime"], RUNTIME_KEYS, "runtime")
    _string(runtime["plugin_version"], "runtime.plugin_version", 80)
    _hex(runtime["capture_tool_sha256"], "runtime.capture_tool_sha256")
    command = _exact(item["command"], COMMAND_KEYS, "command")
    for key in COMMAND_KEYS:
        _string(command[key], f"command.{key}", 2000)
    probe = _exact(item["probe"], PROBE_KEYS, "probe")
    for key in PROBE_KEYS:
        _hex(probe[key], f"probe.{key}")
    git = _exact(item["git"], GIT_KEYS, "git")
    for key in ("workspace_root", "worktree", "bare_remote"):
        _string(git[key], f"git.{key}", 1000)
    if not isinstance(git["branch"], str) or not BRANCH.fullmatch(git["branch"]):
        raise AdapterError("git.branch is invalid")
    _relative(git["target_path"], "git.target_path")
    _hex(git["target_sha256"], "git.target_sha256")
    _hex(git["initial_head"], "git.initial_head", HEX40)
    _string(git["commit_message"], "git.commit_message", 200)
    capture = _exact(item["expected_capture"], CAPTURE_KEYS, "expected_capture")
    pre = capture["pre_sequence"]
    post = capture["post_sequence"]
    if (
        isinstance(pre, bool)
        or isinstance(post, bool)
        or not isinstance(pre, int)
        or not isinstance(post, int)
        or pre < 1
        or post != pre + 1
    ):
        raise AdapterError("expected capture must be one adjacent Pre/Post pair")
    if (
        not isinstance(item["allowed_untracked"], list)
        or not all(isinstance(x, str) for x in item["allowed_untracked"])
        or len(item["allowed_untracked"]) != len(set(item["allowed_untracked"]))
    ):
        raise AdapterError("allowed_untracked must be a unique string list")
    for index, value in enumerate(item["allowed_untracked"]):
        _relative(value, f"allowed_untracked[{index}]")
    return item, observed_sha


def expected_command(experiment: dict[str, Any]) -> str:
    command = experiment["command"]
    return shlex.join([
        command["python"], command["probe_script"], "commit-push",
        "--experiment", command["experiment_path"],
    ])


def validate_probe_bytes(experiment: dict[str, Any]) -> None:
    adapter = Path(__file__).resolve(strict=True)
    if sha256_bytes(adapter.read_bytes()) != experiment["probe"]["adapter_sha256"]:
        raise AdapterError("adapter bytes differ from frozen experiment")
    probe = Path(experiment["command"]["probe_script"])
    if probe.is_symlink() or not probe.is_file():
        raise AdapterError("probe script is missing or not regular")
    if sha256_bytes(probe.read_bytes()) != experiment["probe"]["probe_script_sha256"]:
        raise AdapterError("probe script bytes differ from frozen experiment")
    if experiment["command"]["exact"] != expected_command(experiment):
        raise AdapterError("frozen exact command does not match experiment paths")


def _load_sibling(name: str, filename: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AdapterError(f"could not load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_pair(
    capture_dir: Path,
    runtime_root: Path,
    experiment: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    host_capture = _load_sibling("host_gate_capture", "host_capture.py")
    try:
        report = host_capture.inspect_directory(capture_dir, runtime_root)
    except host_capture.CaptureError as exc:
        raise AdapterError(f"capture verification failed: {exc}") from exc
    if report["status"] != "observed":
        raise AdapterError("capture directory has no observed records")
    expected = experiment["expected_capture"]
    projections = {
        entry["sequence"]: entry for entry in report["entries"]
    }
    if expected["pre_sequence"] not in projections or expected["post_sequence"] not in projections:
        raise AdapterError("expected capture pair is missing")

    values: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for sequence in (expected["pre_sequence"], expected["post_sequence"]):
        meta_path = capture_dir / f"capture-{sequence:06d}.meta.json"
        raw_path = capture_dir / f"capture-{sequence:06d}.raw"
        meta = _json_object(meta_path.read_bytes(), "capture metadata")
        raw = _json_object(raw_path.read_bytes(), "capture raw payload")
        if meta["capture_tool_sha256"] != experiment["runtime"]["capture_tool_sha256"]:
            raise AdapterError("capture recorder bytes differ from experiment")
        if meta["runtime_tree_sha256"] != experiment["subject"]["runtime_tree_sha256"]:
            raise AdapterError("capture runtime differs from experiment")
        if meta["plugin_version"] != experiment["runtime"]["plugin_version"]:
            raise AdapterError("capture plugin version differs from experiment")
        values.append((meta, raw))
    (pre_meta, pre), (post_meta, post) = values
    if pre.get("hook_event_name") != "PreToolUse" or post.get("hook_event_name") != "PostToolUse":
        raise AdapterError("capture pair has wrong event roles")
    for field in ("session_id", "turn_id", "tool_use_id", "tool_name", "tool_input"):
        if pre.get(field) != post.get(field):
            raise AdapterError(f"capture pair {field} differs")
    if pre.get("tool_name") != "Bash":
        raise AdapterError("capture pair is not the Bash command surface")
    if pre.get("cwd") != experiment["git"]["worktree"] or post.get("cwd") != pre.get("cwd"):
        raise AdapterError("capture cwd differs from experiment worktree")
    if pre.get("tool_input") != {"command": experiment["command"]["exact"]}:
        raise AdapterError("captured command differs from frozen exact command")
    if not isinstance(post.get("tool_response"), str):
        raise AdapterError("PostToolUse response must be an observed string")
    return pre_meta, pre, post_meta, post


def decode_marker(response: str) -> dict[str, Any]:
    candidates = [
        line[len(MARKER_PREFIX):]
        for line in response.splitlines()
        if line.startswith(MARKER_PREFIX)
    ]
    if len(candidates) != 1:
        raise AdapterError("PostToolUse must contain exactly one bounded marker")
    token = candidates[0]
    if not token or len(token) > MAX_MARKER_BYTES * 2:
        raise AdapterError("marker token is empty or oversized")
    try:
        padding = "=" * (-len(token) % 4)
        raw = base64.b64decode(
            (token + padding).encode("ascii"), altchars=b"-_", validate=True
        )
    except (ValueError, UnicodeError) as exc:
        raise AdapterError("marker is not valid base64url") from exc
    if len(raw) > MAX_MARKER_BYTES:
        raise AdapterError("decoded marker is oversized")
    marker = _json_object(raw, "marker")
    marker = _exact(marker, MARKER_KEYS, "marker")
    if marker["schema"] != MARKER_SCHEMA:
        raise AdapterError("marker schema mismatch")
    for key in ("experiment_sha256", "target_sha256"):
        _hex(marker[key], f"marker.{key}")
    for key in ("commit", "parent", "tree", "target_blob_oid", "remote_commit"):
        _hex(marker[key], f"marker.{key}", HEX40)
    _relative(marker["target_path"], "marker.target_path")
    _string(marker["remote_ref"], "marker.remote_ref", 300)
    return marker


def encode_marker(marker: dict[str, Any]) -> str:
    raw = canonical(marker)
    if len(raw) > MAX_MARKER_BYTES:
        raise AdapterError("marker exceeds bounded size")
    return MARKER_PREFIX + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _git(cwd: Path, *args: str, git_dir: Path | None = None) -> bytes:
    command = ["git"]
    if git_dir is not None:
        command.extend(["--git-dir", str(git_dir)])
    command.extend(args)
    result = subprocess.run(command, cwd=cwd, capture_output=True, check=False)
    if result.returncode:
        raise AdapterError(
            f"independent Git readback failed for {args[0] if args else 'command'}"
        )
    return result.stdout


def _oid(value: bytes, label: str) -> str:
    text = value.decode("ascii", errors="strict").strip()
    return _hex(text, label, HEX40)


def git_readback(experiment: dict[str, Any]) -> dict[str, str]:
    git = experiment["git"]
    workspace = Path(git["workspace_root"])
    if workspace.is_symlink() or not workspace.is_dir():
        raise AdapterError("git.workspace_root must be a real directory")
    workspace = workspace.resolve(strict=True)
    worktree = _contained(workspace, git["worktree"], "git.worktree", directory=True)
    bare = _contained(workspace, git["bare_remote"], "git.bare_remote", directory=True)
    target = _relative(git["target_path"], "git.target_path")
    commit = _oid(_git(worktree, "rev-parse", "HEAD"), "readback commit")
    parent = _oid(_git(worktree, "rev-parse", "HEAD^"), "readback parent")
    tree = _oid(_git(worktree, "rev-parse", "HEAD^{tree}"), "readback tree")
    changed_raw = _git(
        worktree, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", "HEAD"
    )
    changed = [os.fsdecode(x) for x in changed_raw.split(b"\0") if x]
    if changed != [target]:
        raise AdapterError("commit changed paths differ from the exact target")
    ls_tree = _git(worktree, "ls-tree", "-z", "HEAD", "--", target)
    fields = ls_tree.rstrip(b"\0").split(None, 3)
    if len(fields) != 4 or fields[1] != b"blob":
        raise AdapterError("target is not one regular Git blob")
    blob_oid = _hex(fields[2].decode("ascii"), "target blob oid", HEX40)
    content = _git(worktree, "show", f"HEAD:{target}")
    target_sha = sha256_bytes(content)
    ref = f"refs/heads/{git['branch']}"
    remote_commit = _oid(
        _git(worktree, "rev-parse", ref, git_dir=bare), "remote commit"
    )
    status_raw = _git(worktree, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    dirty = [os.fsdecode(x) for x in status_raw.split(b"\0") if x]
    expected_dirty = sorted(f"?? {path}" for path in experiment["allowed_untracked"])
    if sorted(dirty) != expected_dirty:
        raise AdapterError("worktree status differs from frozen allowed_untracked")
    return {
        "commit": commit,
        "parent": parent,
        "tree": tree,
        "target_path": target,
        "target_blob_oid": blob_oid,
        "target_sha256": target_sha,
        "remote_ref": ref,
        "remote_commit": remote_commit,
    }


def _event(
    *, event_id: str, observed_at: str, sequence: int, session_id: str,
    scenario_id: str, event_type: str, subject_id: str,
    runtime_digest: str, plugin_version: str, producer: dict[str, str],
    pair_id: str | None = None, pair_role: str | None = None,
) -> str:
    item: dict[str, Any] = {
        "schema": "host-behavior-events/v2",
        "event_id": event_id,
        "observed_at": observed_at,
        "sequence": sequence,
        "session_id": session_id,
        "scenario_id": scenario_id,
        "event_type": event_type,
        "subject_id": subject_id,
        "producer": {
            "runtime_tree_sha256": runtime_digest,
            "plugin_version": plugin_version,
            **producer,
        },
    }
    if pair_id is not None:
        item["pair_id"] = pair_id
        item["pair_role"] = pair_role
    return canonical(item).decode("utf-8")


def adapt(
    *, experiment_path: Path, experiment_sha256: str,
    capture_dir: Path, runtime_root: Path,
) -> dict[str, Any]:
    experiment, observed_sha = load_experiment(experiment_path, experiment_sha256)
    validate_probe_bytes(experiment)
    pre_meta, pre, post_meta, post = _read_pair(
        capture_dir, runtime_root, experiment
    )
    marker = decode_marker(post["tool_response"])
    if marker["experiment_sha256"] != observed_sha:
        raise AdapterError("marker refers to different experiment bytes")
    if marker["nonce"] != experiment["nonce"] or marker["scenario"] != "commit_push":
        raise AdapterError("marker nonce or scenario differs from experiment")
    readback = git_readback(experiment)
    if {key: marker[key] for key in readback} != readback:
        raise AdapterError("marker facts differ from independent Git readback")
    if readback["parent"] != experiment["git"]["initial_head"]:
        raise AdapterError("commit parent differs from frozen initial head")
    if readback["target_sha256"] != experiment["git"]["target_sha256"]:
        raise AdapterError("committed blob differs from frozen target bytes")

    return {
        "schema": OUTPUT_SCHEMA,
        "status": "adapted_partial_gate_facts",
        "acceptance_authority": False,
        "guard_chain_qualified": False,
        "experiment_sha256": observed_sha,
        "adapter_sha256": experiment["probe"]["adapter_sha256"],
        "capture": {
            "pre_sequence": experiment["expected_capture"]["pre_sequence"],
            "post_sequence": experiment["expected_capture"]["post_sequence"],
            "pre_raw_sha256": pre_meta["raw_sha256"],
            "post_raw_sha256": post_meta["raw_sha256"],
        },
        "internal_git_facts": readback,
        "limitations": [
            "the captured command is a wrapper; commit and push occur inside the probe",
            "wrapper capture does not cross the direct Git mutation gates",
            "PostToolUse string content is never parsed as a generic exit code",
            "no host-behavior gate event or status is emitted",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment", type=Path, required=True)
    parser.add_argument("--experiment-sha256", required=True)
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _write_private_output(path: Path, payload: bytes) -> None:
    path.parent.resolve(strict=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("output write made no progress")
            view = view[count:]
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        os.fsync(fd)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = adapt(
            experiment_path=args.experiment,
            experiment_sha256=args.experiment_sha256,
            capture_dir=args.capture_dir,
            runtime_root=args.runtime_root,
        )
        _write_private_output(
            args.output,
            (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
    except (AdapterError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"host_gate_adapter_failed: {exc}", file=sys.stderr)
        return 2
    print("host_gate_adapter=adapted_partial_gate_facts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
