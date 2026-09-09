#!/usr/bin/env python3
"""Map reviewed Hook/state witnesses to the three continuity gates.

This adapter is deliberately separate from the direct-Git adapter. It accepts
only a frozen manifest, genuine raw Hook capture files, state witnesses made by
``host_state_capture.py``, and one ordered session. It has no CLI that can
invent events or status; the caller must pass its in-memory receipt directly to
``host_behavior.Validator``.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA = "context-guard-reviewed-host-continuity/v1"
RECEIPT_SCHEMA = "context-guard-reviewed-host-continuity-receipt/v1"
CAPTURE_SCHEMA = "host-behavior-capture/v2"
EVENT_SCHEMA = "host-behavior-events/v2"
ORIGIN = "reviewed_mapping_v1"
MAPPED_GATES = ("continuity_wait", "compact_resume", "cleanup")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON = 4 * 1024 * 1024


class ContinuityMappingError(ValueError):
    pass


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContinuityMappingError(f"JSON object repeats key {key!r}")
        result[key] = value
    return result


def _read(path: Path, label: str, digest: str | None = None) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON:
        raise ContinuityMappingError(f"{label} must be a bounded regular file")
    raw = path.read_bytes()
    if digest is not None and _sha(raw) != _hex(digest, label + " SHA-256"):
        raise ContinuityMappingError(f"{label} SHA-256 changed")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContinuityMappingError(f"{label} is not UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ContinuityMappingError(f"{label} must be a JSON object")
    return value, raw


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ContinuityMappingError(f"{label} must contain exactly {sorted(keys)}")
    return value


def _string(value: Any, label: str, limit: int = 4000) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ContinuityMappingError(f"{label} must be a bounded non-empty string")
    return value


def _hex(value: Any, label: str, pattern: re.Pattern[str] = HEX64) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ContinuityMappingError(f"{label} is invalid")
    return value


def _time(value: Any, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(_string(value, label, 80).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContinuityMappingError(f"{label} is not an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise ContinuityMappingError(f"{label} has no timezone")
    return parsed


def _directory(value: Any, label: str) -> Path:
    path = Path(_string(value, label))
    if not path.is_absolute() or path.is_symlink():
        raise ContinuityMappingError(f"{label} must be a canonical absolute directory")
    resolved = path.resolve(strict=True)
    if path != resolved or not path.is_dir():
        raise ContinuityMappingError(f"{label} must not use an alias")
    return path


def _file(value: Any, label: str) -> Path:
    path = Path(_string(value, label))
    if not path.is_absolute() or path.is_symlink():
        raise ContinuityMappingError(f"{label} must be a canonical absolute file")
    resolved = path.resolve(strict=True)
    if path != resolved or not resolved.is_file():
        raise ContinuityMappingError(f"{label} must not use an alias")
    return path


def _module(name: str, filename: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ContinuityMappingError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _raw(capture_dir: Path, sequence: int, expected_event: str,
         session_hash: str, runtime_digest: str, plugin_version: str
         ) -> tuple[dict[str, Any], dict[str, Any]]:
    meta, _ = _read(capture_dir / f"capture-{sequence:06d}.meta.json", "capture metadata")
    payload, raw = _read(capture_dir / f"capture-{sequence:06d}.raw", "capture raw", meta.get("raw_sha256"))
    if (meta.get("sequence") != sequence or meta.get("raw_bytes") != len(raw)
            or meta.get("expected_event") != expected_event
            or payload.get("hook_event_name") != expected_event):
        raise ContinuityMappingError("capture metadata/event binding differs")
    if _sha(_string(payload.get("session_id"), "session id").encode()) != session_hash:
        raise ContinuityMappingError("capture belongs to a different session")
    if (meta.get("runtime_tree_sha256") != runtime_digest
            or meta.get("plugin_version") != plugin_version):
        raise ContinuityMappingError("capture belongs to a different runtime")
    return meta, payload


def _command_pair(capture_dir: Path, pair: Any, command: str, session_hash: str,
                  runtime_digest: str, plugin_version: str,
                  expected_output: Path, expected_sha256: str
                  ) -> tuple[dict[str, Any], dict[str, Any]]:
    if (not isinstance(pair, list) or len(pair) != 2
            or any(not isinstance(x, int) or isinstance(x, bool) for x in pair)
            or pair[0] >= pair[1]):
        raise ContinuityMappingError("witness command pair is invalid")
    pre_meta, pre = _raw(capture_dir, pair[0], "PreToolUse", session_hash,
                         runtime_digest, plugin_version)
    post_meta, post = _raw(capture_dir, pair[1], "PostToolUse", session_hash,
                           runtime_digest, plugin_version)
    for field in ("session_id", "turn_id", "tool_name", "tool_use_id", "tool_input"):
        if pre.get(field) != post.get(field):
            raise ContinuityMappingError(f"witness command {field} differs")
    if pre.get("tool_name") != "Bash" or pre.get("tool_input") != {"command": command}:
        raise ContinuityMappingError("witness command differs from the frozen direct command")
    response = post.get("tool_response")
    if not isinstance(response, str):
        raise ContinuityMappingError("witness command Post response is not text")
    try:
        result = json.loads(response.strip())
    except json.JSONDecodeError as exc:
        raise ContinuityMappingError("witness command Post response is not exact JSON") from exc
    if result != {"status": "captured", "output": str(expected_output),
                  "sha256": expected_sha256}:
        raise ContinuityMappingError("witness command Post response does not bind output bytes")
    return pre_meta, post_meta


def _state_witness(spec: dict[str, Any], tools: dict[str, str], subject: dict[str, Any],
                   session_hash: str, setup_hash: str) -> tuple[dict[str, Any], bytes]:
    item = _exact(spec, {"path", "sha256"}, "state witness spec")
    value, raw = _read(_file(item["path"], "state witness path"),
                       "state witness", item["sha256"])
    _exact(value, {"schema", "kind", "observed_at", "collector_sha256",
                   "runtime_tree_sha256", "plugin_version",
                   "capture_setup_sha256", "session_id_sha256",
                   "state_sha256", "facts"}, "state witness")
    if (value["schema"] != "context-guard-private-state-witness/v1"
            or value["kind"] != "state"
            or value["collector_sha256"] != tools["state_collector_sha256"]
            or value["runtime_tree_sha256"] != subject["runtime_tree_sha256"]
            or value["plugin_version"] != subject["plugin_version"]
            or value["capture_setup_sha256"] != setup_hash
            or value["session_id_sha256"] != session_hash):
        raise ContinuityMappingError("state witness provenance differs")
    _time(value["observed_at"], "state witness time")
    _hex(value["state_sha256"], "state witness state hash")
    return value, raw


def _inventory(spec: dict[str, Any], tools: dict[str, str], subject: dict[str, Any],
               setup_hash: str) -> tuple[dict[str, Any], bytes]:
    item = _exact(spec, {"path", "sha256"}, "inventory witness spec")
    value, raw = _read(_file(item["path"], "inventory witness path"),
                       "inventory witness", item["sha256"])
    _exact(value, {"schema", "kind", "observed_at", "collector_sha256",
                   "runtime_tree_sha256", "plugin_version",
                   "capture_setup_sha256", "facts"}, "inventory witness")
    if (value["schema"] != "context-guard-private-state-witness/v1"
            or value["kind"] != "inventory"
            or value["collector_sha256"] != tools["state_collector_sha256"]
            or value["runtime_tree_sha256"] != subject["runtime_tree_sha256"]
            or value["plugin_version"] != subject["plugin_version"]
            or value["capture_setup_sha256"] != setup_hash):
        raise ContinuityMappingError("inventory witness provenance differs")
    _time(value["observed_at"], "inventory witness time")
    facts = _exact(value["facts"], {"session_ids", "state_sha256", "ended_at"}, "inventory facts")
    if (not isinstance(facts["session_ids"], list)
            or len(facts["session_ids"]) != len(set(facts["session_ids"]))
            or facts["session_ids"] != sorted(facts["session_ids"])
            or not isinstance(facts["state_sha256"], dict)
            or not isinstance(facts["ended_at"], dict)
            or set(facts["state_sha256"]) != set(facts["session_ids"])
            or set(facts["ended_at"]) != set(facts["session_ids"])
            or any(not isinstance(item, str) or not item for item in facts["session_ids"])
            or any(not isinstance(state_hash, str) or not HEX64.fullmatch(state_hash)
                   for state_hash in facts["state_sha256"].values())
            or any(ended is not None and not isinstance(ended, str)
                   for ended in facts["ended_at"].values())):
        raise ContinuityMappingError("inventory ids/hashes differ")
    for ended in facts["ended_at"].values():
        if ended is not None:
            _time(ended, "inventory ended_at")
    return value, raw


def _event(sequence: int, at: str, session: str, scenario: str, kind: str,
           subject_id: str, producer: dict[str, Any], remaining: list[str] | None = None) -> str:
    value: dict[str, Any] = {
        "schema": EVENT_SCHEMA, "event_id": f"continuity-{sequence:04d}-" +
        _sha((scenario + kind + subject_id).encode())[:16], "observed_at": at,
        "sequence": sequence, "session_id": session, "scenario_id": scenario,
        "event_type": kind, "subject_id": subject_id, "producer": producer,
    }
    if remaining is not None:
        value["remaining_ids"] = remaining
    return _canonical(value).decode()


def _verify_setup(setup: dict[str, Any], capture_dir: Path,
                  runtime_root: Path) -> list[str]:
    if set(setup) != {"description", "hooks"} or not isinstance(setup["description"], str):
        raise ContinuityMappingError("capture setup shape differs")
    events = ["UserPromptSubmit", "PreToolUse", "PostToolUse", "PreCompact",
              "SessionStart", "Stop", "SessionEnd"]
    if list(setup.get("hooks", {})) != events:
        raise ContinuityMappingError("capture setup does not select the exact lifecycle events")
    collector = Path(__file__).with_name("host_capture.py").resolve(strict=True)
    for event in events:
        groups = setup["hooks"][event]
        if (not isinstance(groups, list) or len(groups) != 1
                or set(groups[0]) != {"matcher", "hooks"}
                or groups[0]["matcher"] != ".*"
                or not isinstance(groups[0]["hooks"], list)
                or len(groups[0]["hooks"]) != 1):
            raise ContinuityMappingError("capture setup Hook group differs")
        hook = groups[0]["hooks"][0]
        if (not isinstance(hook, dict)
                or set(hook) != {"type", "command", "commandWindows", "timeout"}
                or hook.get("type") != "command"
                or hook.get("timeout") != 3):
            raise ContinuityMappingError("capture setup Hook handler differs")
        try:
            tokens = shlex.split(_string(hook.get("command"), "capture command"), posix=True)
        except ValueError as exc:
            raise ContinuityMappingError("capture setup command is not parseable") from exc
        # A standalone recorder may live outside the installed runtime. Bind
        # its canonical path AND exact bytes to the pinned sibling recorder.
        if len(tokens) != 9:
            raise ContinuityMappingError("capture command argument count differs")
        actual_collector = _file(tokens[1], "capture recorder")
        if _sha(actual_collector.read_bytes()) != _sha(collector.read_bytes()):
            raise ContinuityMappingError("standalone recorder bytes differ")
        windows_command = "& " + " ".join("'" + part.replace("'", "''") + "'" for part in tokens)
        if _string(hook.get("commandWindows"), "Windows capture command") != windows_command:
            raise ContinuityMappingError("Windows capture command differs from exact argv")
        expected = [tokens[0], str(actual_collector), "record", "--expected-event", event,
                    "--capture-dir", str(capture_dir), "--runtime-root", str(runtime_root)]
        if tokens != expected or not Path(tokens[0]).is_file():
            raise ContinuityMappingError("capture setup command does not bind collector/runtime/directory")
    return events


def adapt(manifest_path: Path, runtime_root: Path,
          expected_manifest_sha256: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest, manifest_raw = _read(manifest_path, "continuity manifest", expected_manifest_sha256)
    _exact(manifest, {"schema", "subject", "host", "session_id_sha256", "tools",
                      "capture", "snapshots", "sequences", "markers", "cleanup"},
           "continuity manifest")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ContinuityMappingError("continuity manifest schema mismatch")
    subject = _exact(manifest["subject"], {"source_commit", "prepared_source_sha256",
                     "runtime_tree_sha256", "plugin_version"}, "subject")
    _hex(subject["source_commit"], "source commit", HEX40)
    for field in ("prepared_source_sha256", "runtime_tree_sha256"):
        _hex(subject[field], field)
    _string(subject["plugin_version"], "plugin version", 80)
    session_hash = _hex(manifest["session_id_sha256"], "session hash")
    tools = _exact(manifest["tools"], {"adapter_sha256", "capture_sha256",
                   "state_collector_sha256", "validator_sha256"}, "tools")
    identities = {"adapter_sha256": "host_continuity_mapping.py",
                  "capture_sha256": "host_capture.py",
                  "state_collector_sha256": "host_state_capture.py",
                  "validator_sha256": "host_behavior.py"}
    for field, filename in identities.items():
        if tools[field] != _sha(Path(__file__).with_name(filename).read_bytes()):
            raise ContinuityMappingError(f"{field} identity differs")
    runtime_root = _directory(str(runtime_root), "runtime root")
    capture_api = _module("continuity_capture", "host_capture.py")
    runtime_digest, version, _ = capture_api.measure_runtime(runtime_root)
    if runtime_digest != subject["runtime_tree_sha256"] or version != subject["plugin_version"]:
        raise ContinuityMappingError("inspected runtime differs from subject")
    capture = _exact(manifest["capture"], {"directory", "report", "report_sha256",
                     "setup", "setup_sha256", "trust_review",
                     "trust_review_sha256", "selected_home"}, "capture")
    capture_dir = _directory(capture["directory"], "capture directory")
    if os.name != "nt" and stat.S_IMODE(capture_dir.stat().st_mode) & 0o077:
        raise ContinuityMappingError("capture directory is not owner-private")
    report_path = _file(capture["report"], "capture report")
    frozen_report, _ = _read(report_path, "capture report", capture["report_sha256"])
    setup, setup_raw = _read(_file(capture["setup"], "capture setup"),
                             "capture setup", capture["setup_sha256"])
    expected_events = _verify_setup(setup, capture_dir, runtime_root)
    trust, trust_raw = _read(_file(capture["trust_review"], "trust review"),
                             "trust review", capture["trust_review_sha256"])
    records = trust.get("records")
    if (trust.get("schema") != "context-guard-native-hook-review/v2"
            or trust.get("status") != "trusted" or trust.get("warnings")
            or trust.get("errors") or trust.get("trust_counts") != {"trusted": 16}
            or trust.get("user_hooks_sha256") != _sha(setup_raw)
            or not isinstance(records, list) or len(records) != 16):
        raise ContinuityMappingError("capture Hooks lack one exact trusted review")
    user = [item for item in records if isinstance(item, dict)
            and item.get("source") == "user" and item.get("pluginId") is None]
    plugin = [item for item in records if isinstance(item, dict)
              and item.get("pluginId") == "context-guard@codex-context-guard"]
    expected_normalized = {event[:1].lower() + event[1:] for event in expected_events}
    record_keys = {"key", "eventName", "handlerType", "matcher", "timeoutSec",
                   "additionalContextLimit", "source", "pluginId", "currentHash",
                   "enabled", "isManaged", "sourcePath", "trustStatus"}
    selected_home = _directory(capture["selected_home"], "selected home")
    plugin_hooks = runtime_root / "hooks/hooks.json"
    if (len(user) != 7 or len(plugin) != 9
            or any(set(item) != record_keys for item in records)
            or {item.get("eventName") for item in user} != expected_normalized
            or any(item.get("trustStatus") != "trusted" or item.get("enabled") is not True
                   for item in records)
            or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", str(item.get("currentHash") or ""))
                   for item in records)
            or len({item.get("currentHash") for item in records}) != 16
            or {Path(item["sourcePath"]) for item in user} != {selected_home / "hooks.json"}
            or {Path(item["sourcePath"]) for item in plugin} != {plugin_hooks}):
        raise ContinuityMappingError("trusted Hook inventory differs from the lifecycle contract")
    before = capture_api.inspect_directory(capture_dir, runtime_root)
    if _canonical(before) != _canonical(frozen_report):
        raise ContinuityMappingError("live capture differs from frozen report")
    entries = before.get("entries")
    if (not isinstance(entries, list) or not entries
            or before.get("tool_pairing", {}).get("complete") is not True
            or {item.get("session_id_sha256") for item in entries} != {session_hash}
            or {item.get("runtime_tree_sha256") for item in entries} != {runtime_digest}
            or {item.get("plugin_version") for item in entries} != {version}):
        raise ContinuityMappingError("capture report has foreign or incomplete records")

    sequences = _exact(manifest["sequences"], {"wait", "compact", "cleanup",
                       "witnesses"}, "sequences")
    wait_seq = _exact(sequences["wait"], {"registered", "stopped", "released"}, "wait sequences")
    compact_seq = _exact(sequences["compact"], {"precompact", "resumed"}, "compact sequences")
    cleanup_seq = _exact(sequences["cleanup"], {"session_end"}, "cleanup sequences")
    witness_seq = _exact(sequences["witnesses"], {"wait_started", "wait_released",
                         "compact_resumed", "cleanup_before"}, "witness sequences")
    ordered = [wait_seq["registered"], wait_seq["stopped"], wait_seq["released"],
               compact_seq["precompact"], compact_seq["resumed"], cleanup_seq["session_end"]]
    if any(not isinstance(x, int) or isinstance(x, bool) or x < 1 for x in ordered) or ordered != sorted(set(ordered)):
        raise ContinuityMappingError("Hook sequence is not one strict causal order")
    reg_meta, registered = _raw(capture_dir, ordered[0], "UserPromptSubmit", session_hash, runtime_digest, version)
    stop_meta, stopped = _raw(capture_dir, ordered[1], "Stop", session_hash, runtime_digest, version)
    release_meta, released = _raw(capture_dir, ordered[2], "UserPromptSubmit", session_hash, runtime_digest, version)
    compact_meta, compacted = _raw(capture_dir, ordered[3], "PreCompact", session_hash, runtime_digest, version)
    resume_meta, resumed = _raw(capture_dir, ordered[4], "SessionStart", session_hash, runtime_digest, version)
    end_meta, ended = _raw(capture_dir, ordered[5], "SessionEnd", session_hash, runtime_digest, version)
    session_id = registered["session_id"]
    host = _exact(manifest["host"], {"os", "python", "codex"}, "host")
    if (host["os"] != platform.system() or host["python"] != platform.python_version()
            or not isinstance(host["codex"], str) or not host["codex"]
            or any(meta.get("host") != {"os": host["os"], "python": host["python"]}
                   for meta in (reg_meta, stop_meta, release_meta, compact_meta,
                                resume_meta, end_meta))):
        raise ContinuityMappingError("manifest and raw capture host identities differ")
    markers = _exact(manifest["markers"], {"wait_prompt_sha256", "release_prompt_sha256",
                     "stop_marker"}, "markers")
    wait_prompt_sha = _hex(markers["wait_prompt_sha256"], "wait prompt hash")
    release_prompt_sha = _hex(markers["release_prompt_sha256"], "release prompt hash")
    if (_sha(_string(registered.get("prompt"), "wait prompt").encode()) != wait_prompt_sha
            or _sha(_string(released.get("prompt"), "release prompt").encode()) != release_prompt_sha
            or _string(markers["stop_marker"], "stop marker", 200)
            not in _string(stopped.get("last_assistant_message"), "Stop reply")):
        raise ContinuityMappingError("wait trigger markers differ from raw Hooks")
    if compacted.get("trigger") not in {"manual", "auto"} or resumed.get("source") != "compact":
        raise ContinuityMappingError("compact/resume Hook roles differ")

    snapshots = _exact(manifest["snapshots"], {"wait_started", "wait_released",
                       "compact_resumed", "cleanup_before", "cleanup_after"}, "snapshots")
    setup_hash = _sha(setup_raw)
    report_hash = _sha(_canonical(frozen_report))
    wait_started, ws_raw = _state_witness(snapshots["wait_started"], tools, subject, session_hash, setup_hash)
    wait_released, wr_raw = _state_witness(snapshots["wait_released"], tools, subject, session_hash, setup_hash)
    compact_resumed, cr_raw = _state_witness(snapshots["compact_resumed"], tools, subject, session_hash, setup_hash)
    inv_before, ib_raw = _inventory(snapshots["cleanup_before"], tools, subject, setup_hash)
    inv_after, ia_raw = _inventory(snapshots["cleanup_after"], tools, subject, setup_hash)
    witness_pairs: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for name in ("wait_started", "wait_released", "compact_resumed", "cleanup_before"):
        operation = _exact(witness_seq[name], {"capture_sequences", "command"},
                           f"{name} witness operation")
        output = Path(_string(snapshots[name]["path"], f"{name} witness path"))
        witness_pairs[name] = _command_pair(
            capture_dir, operation["capture_sequences"],
            _string(operation["command"], f"{name} witness command"),
            session_hash, runtime_digest, version, output,
            snapshots[name]["sha256"],
        )
    wp = {name: operation for name, operation in witness_pairs.items()}
    causal_sequences = [
        wait_seq["stopped"], wp["wait_started"][0]["sequence"],
        wp["wait_started"][1]["sequence"], wait_seq["released"],
        wp["wait_released"][0]["sequence"], wp["wait_released"][1]["sequence"],
        compact_seq["precompact"], compact_seq["resumed"],
        wp["compact_resumed"][0]["sequence"], wp["compact_resumed"][1]["sequence"],
        wp["cleanup_before"][0]["sequence"], wp["cleanup_before"][1]["sequence"],
        cleanup_seq["session_end"],
    ]
    if causal_sequences != sorted(set(causal_sequences)):
        raise ContinuityMappingError("witness commands break lifecycle causality")
    witness_values = {"wait_started": wait_started, "wait_released": wait_released,
                      "compact_resumed": compact_resumed, "cleanup_before": inv_before}
    for name, value in witness_values.items():
        pre, post = witness_pairs[name]
        if not (_time(pre["captured_at"], f"{name} Pre time")
                <= _time(value["observed_at"], f"{name} observed time")
                <= _time(post["captured_at"], f"{name} Post time")):
            raise ContinuityMappingError(f"{name} witness time is outside its command pair")
    state_hashes = [value["state_sha256"] for value in
                    (wait_started, wait_released, compact_resumed)]
    if len(state_hashes) != len(set(state_hashes)):
        raise ContinuityMappingError("state witnesses replay the same state bytes")
    started_waits = wait_started.get("facts", {}).get("wait_conditions")
    released_waits = wait_released.get("facts", {}).get("wait_conditions")
    candidates = [x for x in started_waits or [] if isinstance(x, dict)
                  and x.get("status") == "waiting" and x.get("raised_prompt_sha256") == wait_prompt_sha]
    if len(candidates) != 1:
        raise ContinuityMappingError("waiting witness lacks one prompt-bound condition")
    condition_id = candidates[0].get("condition_id")
    closed = [x for x in released_waits or [] if isinstance(x, dict)
              and x.get("condition_id") == condition_id and x.get("status") == "released"
              and x.get("released_prompt_sha256") == release_prompt_sha
              and x.get("released_by_kind") == "root_user_confirmation"]
    if len(closed) != 1 or _time(wait_started["observed_at"], "wait observed") >= _time(wait_released["observed_at"], "release observed"):
        raise ContinuityMappingError("released witness does not causally close the wait")
    raw_times = [_time(meta["captured_at"], "Hook capture time") for meta in
                 (reg_meta, stop_meta, release_meta, compact_meta, resume_meta, end_meta)]
    if raw_times != sorted(raw_times) or len(set(raw_times)) != len(raw_times):
        raise ContinuityMappingError("Hook capture times are not strictly ordered")
    if not (raw_times[1] <= _time(wait_started["observed_at"], "wait observed")
            <= raw_times[2] <= _time(wait_released["observed_at"], "release observed")
            <= raw_times[3]):
        raise ContinuityMappingError("wait witnesses fall outside their Hook interval")
    compact_facts = compact_resumed.get("facts", {})
    compact_wait = [x for x in compact_facts.get("wait_conditions", [])
                    if isinstance(x, dict) and x.get("condition_id") == condition_id
                    and x.get("status") == "released"
                    and x.get("released_prompt_sha256") == release_prompt_sha]
    if (not isinstance(compact_facts.get("compaction_count"), int)
            or compact_facts["compaction_count"] < 1
            or compact_facts.get("pending_recovery_state") != "consumed"
            or compact_facts.get("pending_recovery_trigger") != "PreCompact"
            or compact_facts.get("pending_recovery_sequence") != compact_facts["compaction_count"]
            or compact_facts.get("recovery_trigger") != "SessionStart:compact"
            or not HEX64.fullmatch(str(compact_facts.get("recovery_state_hash") or ""))
            or len(compact_wait) != 1):
        raise ContinuityMappingError("compact witness lacks consumed recovery state")
    if not (raw_times[4] <= _time(compact_resumed["observed_at"], "compact witness")
            <= raw_times[5]):
        raise ContinuityMappingError("compact witness falls outside resume/end interval")
    cleanup_spec = _exact(manifest["cleanup"], {"expired_ids", "protected_ids"}, "cleanup")
    expired = cleanup_spec["expired_ids"]
    protected = cleanup_spec["protected_ids"]
    if (not isinstance(expired, list) or not expired or len(expired) != len(set(expired))
            or not isinstance(protected, list) or not protected
            or len(protected) != len(set(protected))
            or any(not isinstance(item, str) or not item for item in [*expired, *protected])
            or set(expired) & set(protected) or session_id not in protected):
        raise ContinuityMappingError("cleanup target/protected sets are invalid")
    before_ids = set(inv_before["facts"]["session_ids"])
    after_ids = set(inv_after["facts"]["session_ids"])
    expired_ids = set(expired)
    protected_ids = set(protected)
    if not expired_ids <= before_ids or not protected_ids <= before_ids:
        raise ContinuityMappingError("cleanup inventory loses its target/protected binding")
    if after_ids - before_ids:
        raise ContinuityMappingError("cleanup after inventory contains unexpected session ids")
    removed_ids = before_ids - after_ids
    if removed_ids != expired_ids:
        raise ContinuityMappingError("cleanup removed ids differ from the declared expired set")
    retained_ids = before_ids - expired_ids
    if protected_ids != retained_ids or not protected_ids <= after_ids:
        raise ContinuityMappingError("cleanup protected set does not cover every retained session")
    before_ended = inv_before["facts"]["ended_at"]
    after_ended = inv_after["facts"]["ended_at"]
    cutoff_seconds = 30 * 24 * 60 * 60
    before_time = _time(inv_before["observed_at"], "cleanup before")
    if any(before_ended[item] is None or
           (before_time - _time(before_ended[item], "expired ended_at")).total_seconds() <= cutoff_seconds
           for item in expired):
        raise ContinuityMappingError("cleanup target was not an observed expired ended session")
    if before_ended.get(session_id) is not None or after_ended.get(session_id) is None:
        raise ContinuityMappingError("current session end lifecycle is not observed")
    if (inv_before["facts"]["state_sha256"].get(session_id)
            == inv_after["facts"]["state_sha256"].get(session_id)):
        raise ContinuityMappingError("cleanup current session state did not change at SessionEnd")
    before_states = inv_before["facts"]["state_sha256"]
    after_states = inv_after["facts"]["state_sha256"]
    for item in retained_ids - {session_id}:
        if before_states[item] != after_states[item] or before_ended[item] != after_ended[item]:
            raise ContinuityMappingError("cleanup changed a retained non-current session")
    remaining = sorted(expired_ids & after_ids)
    if not (before_time <= _time(end_meta["captured_at"], "SessionEnd capture") <= _time(inv_after["observed_at"], "cleanup after")):
        raise ContinuityMappingError("SessionEnd is outside cleanup inventory interval")
    after = capture_api.inspect_directory(capture_dir, runtime_root)
    if _canonical(before) != _canonical(after):
        raise ContinuityMappingError("capture changed during mapping")

    producer = {"kind": "host_gate_adapter", "adapter_sha256": tools["adapter_sha256"],
                "runtime_tree_sha256": runtime_digest, "plugin_version": version}
    wait_subject = _sha((session_hash + "|" + str(condition_id)).encode())
    compact_subject = _sha((session_hash + "|" + compact_facts["recovery_packet_sha256"]).encode())
    cleanup_subject = _sha(_canonical({"expired": expired, "before": sorted(before_ids)}))
    events = [
        _event(1, reg_meta["captured_at"], session_id, "continuity_wait", "requirement_registered", wait_subject, producer),
        _event(2, wait_started["observed_at"], session_id, "continuity_wait", "wait_started", wait_subject, producer),
        _event(3, wait_released["observed_at"], session_id, "continuity_wait", "wait_released", wait_subject, producer),
        _event(4, compact_meta["captured_at"], session_id, "compact_resume", "compact_started", compact_subject, producer),
        _event(5, resume_meta["captured_at"], session_id, "compact_resume", "session_resumed", compact_subject, producer),
        _event(6, compact_resumed["observed_at"], session_id, "compact_resume", "recovery_page_shown", compact_subject, producer),
        _event(7, inv_after["observed_at"], session_id, "cleanup", "cleanup_observed", cleanup_subject, producer, remaining),
    ]
    bundle = {"schema": CAPTURE_SCHEMA, "origin": ORIGIN,
              "subject": {k: subject[k] for k in ("source_commit", "prepared_source_sha256", "runtime_tree_sha256")},
              "session_id": session_id, "plugin_version": version,
              "scenarios": list(MAPPED_GATES),
              "host": host,
              "events": events}
    raw_hashes = [m["raw_sha256"] for m in (reg_meta, stop_meta, release_meta,
                                             compact_meta, resume_meta, end_meta)]
    snapshot_hashes = [_sha(x) for x in (ws_raw, wr_raw, cr_raw, ib_raw, ia_raw)]
    receipt = {"schema": RECEIPT_SCHEMA, "manifest_sha256": _sha(manifest_raw),
               "adapter_sha256": tools["adapter_sha256"],
               "collector_sha256": tools["capture_sha256"],
               "state_collector_sha256": tools["state_collector_sha256"],
               "validator_sha256": tools["validator_sha256"],
               "runtime_tree_sha256": runtime_digest, "mapped_gates": list(MAPPED_GATES),
               "capture_report_sha256": report_hash,
               "trust_review_sha256": _sha(trust_raw), "raw_sha256": raw_hashes,
               "snapshot_sha256": snapshot_hashes}
    return bundle, receipt
