#!/usr/bin/env python3
"""Map reviewed immutable real-host evidence to three host-behavior gates.

This adapter owns no status decision.  It verifies raw Hook captures, a normal
Hook-trust readback, and independent Git objects/refs, then returns an in-memory
capture plus a receipt to ``host_behavior.Validator``.  Serializing the capture
does not preserve reviewed-mapping authority.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shlex
import stat
import subprocess
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_SCHEMA = "context-guard-reviewed-host-mapping/v1"
RECEIPT_SCHEMA = "context-guard-reviewed-host-mapping-receipt/v1"
CAPTURE_SCHEMA = "host-behavior-capture/v2"
EVENT_SCHEMA = "host-behavior-events/v2"
ORIGIN = "reviewed_mapping_v1"
MAPPED_GATES = ("hook_trust", "commit_event", "local_push_readback")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HASH_VALUE = re.compile(r"^sha256:[0-9a-f]{64}$")
REF_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
MAX_JSON_BYTES = 1024 * 1024


class MappingError(ValueError):
    """Raised when reviewed evidence cannot support the requested mapping."""


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
            raise MappingError(f"JSON object repeats key {key!r}")
        result[key] = value
    return result


def _read_json(path: Path, label: str, expected_sha256: str | None = None) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise MappingError(f"{label} must be a regular file")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise MappingError(f"{label} exceeds the bounded size")
    raw = path.read_bytes()
    if expected_sha256 is not None and sha256_bytes(raw) != _hex(expected_sha256, f"{label} SHA-256"):
        raise MappingError(f"{label} SHA-256 changed")
    try:
        item = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MappingError(f"{label} is not UTF-8 JSON: {exc}") from exc
    if not isinstance(item, dict):
        raise MappingError(f"{label} must be a JSON object")
    return item, raw


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise MappingError(f"{label} must contain exactly {sorted(keys)}")
    return value


def _string(value: Any, label: str, limit: int = 2000) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise MappingError(f"{label} must be a bounded non-empty string")
    return value


def _hex(value: Any, label: str, pattern: re.Pattern[str] = HEX64) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise MappingError(f"{label} is invalid")
    return value


def _relative(value: Any, label: str) -> str:
    raw = _string(value, label, 300)
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or "\\" in raw:
        raise MappingError(f"{label} must be a portable relative path")
    return raw


def _canonical_directory(value: Any, label: str) -> Path:
    raw = Path(_string(value, label))
    if not raw.is_absolute() or raw.is_symlink():
        raise MappingError(f"{label} must be a canonical absolute directory")
    resolved = raw.resolve(strict=True)
    if raw != resolved or not resolved.is_dir():
        raise MappingError(f"{label} must not use a path alias")
    return resolved


def _load_sibling(name: str, filename: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise MappingError(f"could not load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(cwd: Path, *args: str, git_dir: Path | None = None) -> bytes:
    command = ["git"]
    if git_dir is not None:
        command.extend(["--git-dir", str(git_dir)])
    command.extend(args)
    result = subprocess.run(command, cwd=cwd, capture_output=True, check=False)
    if result.returncode:
        raise MappingError(f"Git readback failed for {args[0]}")
    return result.stdout


def _direct_git(
    command: str,
    operation: str,
    remote: str | None = None,
    ref: str | None = None,
) -> list[str]:
    if any(token in command for token in ("\n", "\r", "`", "$(", ";", "&&", "||", "|")):
        raise MappingError(f"{operation} command is compound or substituted")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise MappingError(f"{operation} command is not parseable") from exc
    if operation == "commit":
        if len(tokens) != 4 or tokens[:3] != ["git", "commit", "-m"]:
            raise MappingError(
                "commit evidence must be exactly a direct git commit -m"
            )
        _string(tokens[3], "commit message", 200)
    elif operation == "push":
        remote_name = _string(remote, "push remote", 200)
        ref_name = _string(ref, "push ref", 200)
        if remote_name != "origin" or ref_name != "main":
            raise MappingError("reviewed push must target origin main")
        expected = [
            "git", "push", remote_name, f"HEAD:refs/heads/{ref_name}"
        ]
        if tokens != expected:
            raise MappingError("push evidence is not the frozen direct git push")
    else:
        raise MappingError("unsupported direct Git operation")
    return tokens


def _read_pair(
    capture_dir: Path,
    sequence_pair: list[int],
    exact_command: str,
    session_hash: str,
    runtime_root: Path,
    worktree: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if len(sequence_pair) != 2 or sequence_pair[1] != sequence_pair[0] + 1:
        raise MappingError("capture pair must name adjacent Pre/Post sequences")
    values: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for sequence in sequence_pair:
        meta, _ = _read_json(capture_dir / f"capture-{sequence:06d}.meta.json", "capture metadata")
        raw, raw_bytes = _read_json(capture_dir / f"capture-{sequence:06d}.raw", "capture raw payload", meta.get("raw_sha256"))
        if meta.get("raw_bytes") != len(raw_bytes) or meta.get("sequence") != sequence:
            raise MappingError("capture metadata length or sequence differs")
        values.append((meta, raw))
    (pre_meta, pre), (post_meta, post) = values
    if pre.get("hook_event_name") != "PreToolUse" or post.get("hook_event_name") != "PostToolUse":
        raise MappingError("capture pair has wrong Hook roles")
    for field in (
        "session_id", "turn_id", "tool_use_id", "tool_name", "tool_input", "cwd"
    ):
        if pre.get(field) != post.get(field):
            raise MappingError(f"capture pair {field} differs")
    if sha256_bytes(_string(pre.get("session_id"), "session id").encode()) != session_hash:
        raise MappingError("capture pair belongs to a different session")
    if pre.get("tool_name") != "Bash" or pre.get("tool_input") != {"command": exact_command}:
        raise MappingError("capture pair is not the frozen Bash command")
    raw_cwd = Path(_string(pre.get("cwd"), "capture cwd"))
    if (
        not raw_cwd.is_absolute()
        or raw_cwd.is_symlink()
        or raw_cwd.resolve(strict=True) != worktree
        or raw_cwd != worktree
    ):
        raise MappingError("capture cwd does not bind the canonical Git worktree")
    if not isinstance(post.get("tool_response"), str):
        raise MappingError("PostToolUse response is not an observed opaque string")
    runtime_digest, plugin_version, _ = _load_sibling("reviewed_mapping_capture", "host_capture.py").measure_runtime(runtime_root)
    for meta in (pre_meta, post_meta):
        if meta.get("runtime_tree_sha256") != runtime_digest or meta.get("plugin_version") != plugin_version:
            raise MappingError("capture pair runtime identity differs")
    return pre_meta, pre, post_meta, post


def _verify_windows_command(value: Any, expected: list[str]) -> None:
    # Match prepare_hooks PowerShell single-quoted argv bytes, not POSIX parsing.
    canonical_command = "& " + " ".join("'" + part.replace("'", "''") + "'" for part in expected)
    if _string(value, "Windows capture command") != canonical_command:
        raise MappingError("Windows capture command differs from exact argv")


def _time(value: Any, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(_string(value, label, 80).replace("Z", "+00:00"))
    except ValueError as exc:
        raise MappingError(f"{label} is not an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise MappingError(f"{label} has no timezone")
    return parsed


def _remote_refs(worktree: Path, remote: str) -> dict[str, str]:
    refs: dict[str, str] = {}
    for line in _git(worktree, "ls-remote", "--refs", remote).decode().splitlines():
        try:
            oid, ref_name = line.split("\t", 1)
        except ValueError as exc:
            raise MappingError("remote readback returned an invalid row") from exc
        if not HEX40.fullmatch(oid) or ref_name in refs:
            raise MappingError("remote readback returned invalid or duplicate refs")
        refs[ref_name] = oid
    return refs


def _verify_remote(worktree: Path, bare: Path, remote: str) -> dict[str, str]:
    if _git(bare, "rev-parse", "--is-bare-repository").decode().strip() != "true":
        raise MappingError("declared remote is not a bare Git repository")
    absolute_git_dir = Path(
        _git(bare, "rev-parse", "--absolute-git-dir").decode().strip()
    )
    if absolute_git_dir != bare:
        raise MappingError("declared bare Git identity differs")
    urls = _git(worktree, "remote", "get-url", "--push", "--all", remote).decode().splitlines()
    if len(urls) != 1:
        raise MappingError("push remote must resolve to exactly one URL")
    configured = Path(urls[0])
    try:
        configured_resolved = configured.resolve(strict=True)
    except OSError as exc:
        raise MappingError("push remote URL does not resolve") from exc
    if (
        not configured.is_absolute()
        or configured.is_symlink()
        or configured_resolved != bare
        or configured != bare
    ):
        raise MappingError("push remote does not resolve to the declared bare repository")
    return _remote_refs(worktree, remote)


def _hook_descriptors(config: dict[str, Any]) -> list[dict[str, Any]]:
    hooks = config.get("hooks")
    if not isinstance(hooks, dict):
        raise MappingError("Hook configuration has no hooks object")
    result: list[dict[str, Any]] = []
    for event_name, groups in hooks.items():
        if not isinstance(event_name, str) or not isinstance(groups, list):
            raise MappingError("Hook configuration event groups are invalid")
        normalized_event = event_name[:1].lower() + event_name[1:]
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                raise MappingError("Hook configuration group is invalid")
            for hook in group["hooks"]:
                if not isinstance(hook, dict):
                    raise MappingError("Hook configuration handler is invalid")
                result.append({
                    "eventName": normalized_event,
                    "handlerType": hook.get("type"),
                    "matcher": None if normalized_event in {"userPromptSubmit", "stop"} else group.get("matcher"),
                    "timeoutSec": hook.get("timeout"),
                    "additionalContextLimit": hook.get("additionalContextLimit"),
                })
    return result


def _trust(
    review: dict[str, Any],
    contract: dict[str, Any],
    plugin_version: str,
    runtime_digest: str,
    capture_dir: Path,
    collector_sha256: str,
) -> str:
    expected_count = contract.get("record_count")
    if expected_count not in {11, 16}:
        raise MappingError("unsupported exact Hook record count")
    capture_count = expected_count - 9
    capture_events = {"PreToolUse", "PostToolUse"}
    if expected_count == 16:
        capture_events |= {"UserPromptSubmit", "PreCompact", "SessionStart", "Stop", "SessionEnd"}
    if review.get("schema") != "context-guard-native-hook-review/v2" or review.get("status") != "trusted":
        raise MappingError("Hook review is not a trusted v2 review")
    if review.get("warnings") or review.get("errors") or review.get("trust_counts") != {"trusted": expected_count}:
        raise MappingError("Hook review warnings, errors, or counts differ")
    records = review.get("records")
    normalized = review.get("normalized_contract")
    if (
        not isinstance(records, list)
        or len(records) != expected_count
        or not isinstance(normalized, list)
        or len(normalized) != expected_count
    ):
        raise MappingError("Hook review does not contain the exact eleven-record contract")
    record_keys = {
        "key", "eventName", "handlerType", "matcher", "timeoutSec",
        "additionalContextLimit", "source", "pluginId", "currentHash",
        "enabled", "isManaged", "sourcePath", "trustStatus",
    }
    normalized_keys = record_keys - {"key", "sourcePath", "trustStatus"} | {
        "sourcePathClass"
    }
    if any(not isinstance(record, dict) or set(record) != record_keys for record in records):
        raise MappingError("Hook review record shape differs")
    if any(not isinstance(item, dict) or set(item) != normalized_keys for item in normalized):
        raise MappingError("normalized Hook contract shape differs")
    if any(
        record.get("trustStatus") != "trusted"
        or record.get("enabled") is not True
        or record.get("isManaged") is not False
        or not HASH_VALUE.fullmatch(record.get("currentHash") or "")
        for record in records
    ):
        raise MappingError("Hook review contains a disabled or non-trusted record")
    if len({record["key"] for record in records}) != expected_count or len(
        {record["currentHash"] for record in records}
    ) != expected_count:
        raise MappingError("Hook review repeats a key or current Hook hash")
    plugin = [record for record in records if record.get("pluginId") == "context-guard@codex-context-guard"]
    user = [record for record in records if record.get("source") == "user" and record.get("pluginId") is None]
    if len(plugin) != 9 or len(user) != capture_count:
        raise MappingError("Hook review does not contain nine product and two capture Hooks")
    if {record.get("eventName") for record in user} != {event[0].lower() + event[1:] for event in capture_events}:
        raise MappingError("capture Hook review has the wrong events")
    projected = []
    for record in records:
        item = {
            key: value
            for key, value in record.items()
            if key not in {"key", "sourcePath", "trustStatus"}
        }
        item["sourcePathClass"] = (
            f"plugin_{plugin_version.replace('.', '_')}"
            if record in plugin else "selected_home_hooks"
        )
        projected.append(item)
    if projected != normalized:
        raise MappingError("normalized Hook contract differs from reviewed records")
    contract = _exact(
        contract,
        {
            "schema", "plugin_version", "record_count", "plugin_record_count",
            "user_capture_record_count", "controlled_home", "records",
            "normalized_contract", "pretrust_requirement",
            "post_review_requirement",
        },
        "expected Hook contract",
    )
    if (
        contract["schema"]
        != "context-guard-p4-r5-recovery-expected-hooks/v1"
        or contract["plugin_version"] != plugin_version
        or contract["record_count"] != expected_count
        or contract["plugin_record_count"] != 9
        or contract["user_capture_record_count"] != capture_count
        or contract["records"]
        != [
            {key: value for key, value in record.items() if key != "trustStatus"}
            for record in records
        ]
        or contract["normalized_contract"] != normalized
        or not isinstance(contract["pretrust_requirement"], str)
        or not isinstance(contract["post_review_requirement"], str)
    ):
        raise MappingError("reviewed Hooks differ from the frozen expected contract")

    plugin_paths = {Path(record["sourcePath"]) for record in plugin}
    user_paths = {Path(record["sourcePath"]) for record in user}
    if len(plugin_paths) != 1 or len(user_paths) != 1:
        raise MappingError("Hook review source paths are not singular")
    plugin_config_path = next(iter(plugin_paths))
    user_config_path = next(iter(user_paths))
    for path, label in (
        (plugin_config_path, "product Hook source"),
        (user_config_path, "capture Hook source"),
    ):
        if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
            raise MappingError(f"{label} is not a canonical regular file")
        if not path.is_file():
            raise MappingError(f"{label} is not a regular file")
    if plugin_config_path.name != "hooks.json" or plugin_config_path.parent.name != "hooks":
        raise MappingError("product Hook source is outside a runtime hooks directory")
    installed_root = plugin_config_path.parents[1]
    measured, measured_version, _ = _load_sibling(
        "reviewed_mapping_trust_runtime", "host_capture.py"
    ).measure_runtime(installed_root)
    if measured != runtime_digest or measured_version != plugin_version:
        raise MappingError("reviewed product Hooks do not bind the inspected runtime")
    installed_collector = installed_root / "tools/validation/host_capture.py"
    if expected_count == 16:
        setup, _ = _read_json(user_config_path, "capture Hook configuration")
        recorder_tokens = shlex.split(setup["hooks"]["PreToolUse"][0]["hooks"][0]["command"], posix=True)
        if len(recorder_tokens) != 9:
            raise MappingError("capture recorder argv differs")
        installed_collector = Path(recorder_tokens[1])
        if not installed_collector.is_absolute() or installed_collector.resolve(strict=True) != installed_collector:
            raise MappingError("standalone recorder path is not canonical")
    if (
        installed_collector.is_symlink()
        or not installed_collector.is_file()
        or sha256_bytes(installed_collector.read_bytes()) != collector_sha256
    ):
        raise MappingError("capture Hook recorder bytes differ from the reviewed collector")

    selected_home = _canonical_directory(review.get("selected_home"), "selected home")
    if contract["controlled_home"] != str(selected_home):
        raise MappingError("expected Hook contract selected-home binding differs")
    if user_config_path != selected_home / "hooks.json":
        raise MappingError("capture Hook source differs from the selected home")
    plugin_config, _ = _read_json(plugin_config_path, "product Hook configuration")
    user_config, _ = _read_json(user_config_path, "capture Hook configuration")
    expected_plugin = _hook_descriptors(plugin_config)
    expected_user = _hook_descriptors(user_config)
    actual_plugin = [
        {key: record[key] for key in (
            "eventName", "handlerType", "matcher", "timeoutSec",
            "additionalContextLimit",
        )}
        for record in plugin
    ]
    actual_user = [
        {key: record[key] for key in (
            "eventName", "handlerType", "matcher", "timeoutSec",
            "additionalContextLimit",
        )}
        for record in user
    ]
    def key(item: dict[str, Any]) -> bytes:
        return canonical(item)
    if sorted(actual_plugin, key=key) != sorted(expected_plugin, key=key):
        raise MappingError("reviewed product Hook records differ from runtime hooks.json")
    if sorted(actual_user, key=key) != sorted(expected_user, key=key):
        raise MappingError("reviewed capture Hook records differ from selected hooks.json")

    if set(user_config) != {"description", "hooks"} or set(user_config["hooks"]) != capture_events:
        raise MappingError("selected capture Hook configuration shape differs")
    for event in sorted(capture_events):
        groups = user_config["hooks"][event]
        if (
            not isinstance(groups, list)
            or len(groups) != 1
            or groups[0].get("matcher") != ".*"
            or not isinstance(groups[0].get("hooks"), list)
            or len(groups[0]["hooks"]) != 1
        ):
            raise MappingError("selected capture Hook group differs")
        hook = groups[0]["hooks"][0]
        command = _string(hook.get("command"), "capture Hook command")
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError as exc:
            raise MappingError("capture Hook command is not parseable") from exc
        if not tokens:
            raise MappingError("capture Hook command is empty")
        expected = [
            tokens[0], str(installed_collector), "record",
            "--capture-dir", str(capture_dir),
            "--runtime-root", str(installed_root),
            "--expected-event", event,
        ]
        if expected_count == 16:
            expected = [tokens[0], str(installed_collector), "record", "--expected-event", event,
                        "--capture-dir", str(capture_dir), "--runtime-root", str(installed_root)]
            _verify_windows_command(hook.get("commandWindows"), expected)
        if (
            tokens != expected
            or hook.get("type") != "command"
            or hook.get("timeout") != (3 if expected_count == 16 else 10)
            or not Path(tokens[0]).is_file()
        ):
            raise MappingError("capture Hook command does not bind recorder/runtime/capture")
    return sha256_bytes(canonical(normalized))


def _event(sequence: int, observed_at: str, session_id: str, scenario: str, event_type: str, subject_id: str, producer: dict[str, Any], *, pair_id: str | None = None, pair_role: str | None = None) -> str:
    value: dict[str, Any] = {
        "schema": EVENT_SCHEMA,
        "event_id": f"reviewed-{sequence:04d}-{sha256_bytes((scenario + event_type + subject_id).encode())[:16]}",
        "observed_at": observed_at,
        "sequence": sequence,
        "session_id": session_id,
        "scenario_id": scenario,
        "event_type": event_type,
        "subject_id": subject_id,
        "producer": producer,
    }
    if pair_id is not None:
        value["pair_id"] = pair_id
        value["pair_role"] = pair_role
    return canonical(value).decode("utf-8")


def adapt(manifest_path: Path, runtime_root: Path, expected_manifest_sha256: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest, manifest_bytes = _read_json(manifest_path, "mapping manifest", expected_manifest_sha256)
    manifest = _exact(manifest, {"schema", "reviewed_at", "subject", "host", "session_id_sha256", "tools", "evidence", "git", "operations"}, "mapping manifest")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise MappingError("mapping manifest schema mismatch")
    subject = _exact(manifest["subject"], {"source_commit", "prepared_source_sha256", "runtime_tree_sha256", "plugin_version"}, "subject")
    _hex(subject["source_commit"], "source commit", HEX40)
    _hex(subject["prepared_source_sha256"], "prepared source")
    _hex(subject["runtime_tree_sha256"], "runtime tree")
    plugin_version = _string(subject["plugin_version"], "plugin version", 80)
    session_hash = _hex(manifest["session_id_sha256"], "session hash")
    tools = _exact(manifest["tools"], {"adapter_sha256", "capture_sha256", "validator_sha256"}, "tools")
    for field in tools:
        _hex(tools[field], f"tools.{field}")
    if tools["adapter_sha256"] != sha256_bytes(Path(__file__).read_bytes()):
        raise MappingError("adapter bytes differ from the reviewed manifest")
    capture_module = Path(__file__).with_name("host_capture.py")
    validator_module = Path(__file__).with_name("host_behavior.py")
    if tools["capture_sha256"] != sha256_bytes(capture_module.read_bytes()) or tools["validator_sha256"] != sha256_bytes(validator_module.read_bytes()):
        raise MappingError("collector or validator bytes differ from the reviewed manifest")
    runtime_root = _canonical_directory(str(runtime_root), "runtime root")
    measured_digest, measured_version, _ = _load_sibling(
        "reviewed_mapping_capture_identity", "host_capture.py"
    ).measure_runtime(runtime_root)
    if measured_digest != subject["runtime_tree_sha256"] or measured_version != plugin_version:
        raise MappingError("inspected runtime differs from the mapping subject")

    evidence = _exact(
        manifest["evidence"],
        {
            "capture_dir", "trust_review", "trust_review_sha256",
            "trust_contract", "trust_contract_sha256",
            "capture_report", "capture_report_sha256",
        },
        "evidence",
    )
    capture_dir = _canonical_directory(evidence["capture_dir"], "capture directory")
    if os.name != "nt" and stat.S_IMODE(capture_dir.stat().st_mode) & 0o077:
        raise MappingError("capture directory is not owner-private")

    git_spec = _exact(
        manifest["git"],
        {
            "worktree", "bare_remote", "target_path", "target_sha256",
            "initial_head", "final_head", "expected_refs",
        },
        "git",
    )
    worktree = _canonical_directory(git_spec["worktree"], "Git worktree")
    bare = _canonical_directory(git_spec["bare_remote"], "bare remote")
    target = _relative(git_spec["target_path"], "target path")
    target_sha = _hex(git_spec["target_sha256"], "target SHA-256")
    initial = _hex(git_spec["initial_head"], "initial head", HEX40)
    final = _hex(git_spec["final_head"], "final head", HEX40)
    expected_refs = git_spec["expected_refs"]
    if (
        not isinstance(expected_refs, dict)
        or not expected_refs
        or any(
            not isinstance(ref_name, str)
            or not ref_name.startswith("refs/heads/")
            or not REF_NAME.fullmatch(ref_name.removeprefix("refs/heads/"))
            or not HEX40.fullmatch(oid or "")
            for ref_name, oid in expected_refs.items()
        )
    ):
        raise MappingError("expected refs are invalid")

    operations = _exact(manifest["operations"], {"commit", "push"}, "operations")
    commit_spec = _exact(
        operations["commit"], {"capture_sequences", "command"},
        "commit operation",
    )
    push_spec = _exact(
        operations["push"],
        {"capture_sequences", "command", "remote", "ref"},
        "push operation",
    )
    commit_command = _string(commit_spec["command"], "commit command")
    push_command = _string(push_spec["command"], "push command")
    commit_tokens = _direct_git(commit_command, "commit")
    _direct_git(push_command, "push", push_spec["remote"], push_spec["ref"])

    capture_api = _load_sibling(
        "reviewed_mapping_capture_inspect", "host_capture.py"
    )
    try:
        capture_report_before = capture_api.inspect_directory(capture_dir, runtime_root)
    except capture_api.CaptureError as exc:
        raise MappingError(f"capture verification failed: {exc}") from exc
    report_path = Path(_string(evidence["capture_report"], "capture report path"))
    frozen_capture_report, _ = _read_json(
        report_path, "capture report", evidence["capture_report_sha256"]
    )
    if canonical(capture_report_before) != canonical(frozen_capture_report):
        raise MappingError("live capture differs from the frozen capture report")
    commit_pair = _read_pair(
        capture_dir, commit_spec["capture_sequences"], commit_command,
        session_hash, runtime_root, worktree,
    )
    push_pair = _read_pair(
        capture_dir, push_spec["capture_sequences"], push_command,
        session_hash, runtime_root, worktree,
    )
    session_id = commit_pair[1]["session_id"]
    if (
        push_pair[1]["session_id"] != session_id
        or commit_pair[2]["sequence"] >= push_pair[0]["sequence"]
    ):
        raise MappingError("commit and push captures lack one ordered session chain")
    try:
        capture_report_after = capture_api.inspect_directory(capture_dir, runtime_root)
    except capture_api.CaptureError as exc:
        raise MappingError(f"capture re-verification failed: {exc}") from exc
    if (
        canonical(capture_report_before) != canonical(capture_report_after)
        or canonical(capture_report_after) != canonical(frozen_capture_report)
    ):
        raise MappingError("capture evidence changed during mapping")
    capture_report = capture_report_after

    trust_path = Path(_string(evidence["trust_review"], "trust review path"))
    trust, trust_bytes = _read_json(
        trust_path, "trust review", evidence["trust_review_sha256"]
    )
    contract_path = Path(_string(evidence["trust_contract"], "trust contract path"))
    trust_contract, trust_contract_bytes = _read_json(
        contract_path, "trust contract", evidence["trust_contract_sha256"]
    )
    trust_subject = _trust(
        trust, trust_contract, plugin_version, measured_digest, capture_dir,
        tools["capture_sha256"],
    )

    if _git(worktree, "rev-parse", "--is-inside-work-tree").decode().strip() != "true":
        raise MappingError("capture cwd is not inside the reviewed Git worktree")
    top_level = Path(
        _git(worktree, "rev-parse", "--show-toplevel").decode().strip()
    )
    if top_level != worktree:
        raise MappingError("capture cwd does not identify the Git top level")
    head = _git(worktree, "rev-parse", "HEAD").decode().strip()
    parent = _git(worktree, "rev-parse", "HEAD^").decode().strip()
    changed = [os.fsdecode(x) for x in _git(worktree, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", "HEAD").split(b"\0") if x]
    blob = _git(worktree, "show", f"HEAD:{target}")
    dirty = _git(worktree, "status", "--porcelain=v1", "-z")
    actual_refs: dict[str, str] = {}
    for line in _git(worktree, "for-each-ref", "--format=%(objectname) %(refname)", git_dir=bare).decode().splitlines():
        oid, ref_name = line.split(" ", 1)
        actual_refs[ref_name] = oid
    if head != final or parent != initial or changed != [target] or sha256_bytes(blob) != target_sha or dirty:
        raise MappingError("independent commit/tree/blob/worktree readback differs")
    remote_refs = _verify_remote(worktree, bare, push_spec["remote"])
    if (
        actual_refs != expected_refs
        or remote_refs != actual_refs
        or actual_refs.get(f"refs/heads/{push_spec['ref']}") != final
    ):
        raise MappingError("independent local remote readback differs")

    branch = _git(worktree, "symbolic-ref", "--short", "HEAD").decode().strip()
    commit_data = _git(
        worktree, "show", "-s", "--format=%cI%x00%s", final
    ).decode().rstrip("\n").split("\0")
    if len(commit_data) != 2 or commit_data[1] != commit_tokens[3]:
        raise MappingError("commit subject does not bind the captured command")
    commit_time = _time(commit_data[0], "commit time")
    if not (
        _time(commit_pair[0]["captured_at"], "commit Pre capture time")
        < commit_time + timedelta(seconds=1)
        and commit_time <= _time(commit_pair[2]["captured_at"], "commit Post capture time")
    ):
        raise MappingError("commit time is outside its captured Pre/Post interval")
    commit_lines = commit_pair[3]["tool_response"].splitlines()
    commit_match = re.fullmatch(
        r"\[([^ ]+) ([0-9a-f]{7,40})\] (.+)",
        commit_lines[0] if commit_lines else "",
    )
    if (
        commit_match is None
        or commit_match.group(1) != branch
        or not final.startswith(commit_match.group(2))
        or commit_match.group(3) != commit_tokens[3]
        or len(commit_lines) < 2
        or not re.fullmatch(r" \d+ files? changed(?:, .+)?", commit_lines[1])
    ):
        raise MappingError("commit Post response does not bind the observed commit")

    push_lines = push_pair[3]["tool_response"].splitlines()
    if push_lines != [
        f"To {bare}",
        f" * [new branch]      HEAD -> {push_spec['ref']}",
    ]:
        raise MappingError("push Post response does not bind the resolved remote/ref")

    adapter_sha = tools["adapter_sha256"]
    producer = {"kind": "host_gate_adapter", "adapter_sha256": adapter_sha, "runtime_tree_sha256": measured_digest, "plugin_version": plugin_version}
    pair_seed = "|".join(str(commit_pair[1][key]) for key in ("session_id", "turn_id", "tool_use_id"))
    pair_id = "commit-" + sha256_bytes(pair_seed.encode())
    commit_subject = final
    push_subject = sha256_bytes((final + "|" + push_spec["remote"] + "|" + push_spec["ref"]).encode())
    trust_time = _string(manifest["reviewed_at"], "reviewed_at", 80)
    events = [
        _event(1, trust_time, session_id, "hook_trust", "hook_trust_reviewed", trust_subject, producer),
        _event(2, trust_time, session_id, "hook_trust", "hook_trust_granted", trust_subject, producer),
        _event(3, commit_pair[0]["captured_at"], session_id, "commit_event", "commit_requested", commit_subject, producer, pair_id=pair_id, pair_role="request"),
        _event(4, commit_pair[2]["captured_at"], session_id, "commit_event", "commit_observed", commit_subject, producer, pair_id=pair_id, pair_role="response"),
        _event(5, commit_pair[2]["captured_at"], session_id, "commit_event", "commit_readback_observed", commit_subject, producer),
        _event(6, push_pair[0]["captured_at"], session_id, "local_push_readback", "push_requested", push_subject, producer),
        _event(7, push_pair[2]["captured_at"], session_id, "local_push_readback", "push_readback_observed", push_subject, producer),
    ]
    bundle = {
        "schema": CAPTURE_SCHEMA,
        "origin": ORIGIN,
        "subject": {key: subject[key] for key in ("source_commit", "prepared_source_sha256", "runtime_tree_sha256")},
        "session_id": session_id,
        "plugin_version": plugin_version,
        "scenarios": list(MAPPED_GATES),
        "host": _exact(manifest["host"], {"os", "python", "codex"}, "host"),
        "events": events,
    }
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "adapter_sha256": adapter_sha,
        "collector_sha256": tools["capture_sha256"],
        "validator_sha256": tools["validator_sha256"],
        "runtime_tree_sha256": measured_digest,
        "mapped_gates": list(MAPPED_GATES),
        "capture_report_sha256": sha256_bytes(canonical(capture_report)),
        "trust_review_sha256": sha256_bytes(trust_bytes),
        "trust_contract_sha256": sha256_bytes(trust_contract_bytes),
        "raw_sha256": [commit_pair[0]["raw_sha256"], commit_pair[2]["raw_sha256"], push_pair[0]["raw_sha256"], push_pair[2]["raw_sha256"]],
        "git_readback_sha256": sha256_bytes(canonical({"head": head, "parent": parent, "changed": changed, "target_sha256": sha256_bytes(blob), "refs": actual_refs})),
    }
    return bundle, receipt
