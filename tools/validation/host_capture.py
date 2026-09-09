#!/usr/bin/env python3
"""Capture genuine Codex command-hook input for private host-shape review.

This tool is a capture sink, not an acceptance producer.  A reviewed
``hooks.json`` command invokes ``record`` for one expected hook event.  The
command reads the exact stdin bytes supplied by Codex, checks the documented
event shape, measures the installed Context Guard runtime itself, and stores
an owner-private raw/meta pair.  ``inspect`` verifies those pairs and emits a
bounded private structural report.  Neither command emits host-behavior gate
records or a success claim.

The host supplies ``hook_event_name``, ``session_id``, and, for tool hooks,
``turn_id``, ``tool_name``, ``tool_use_id``, ``tool_input`` and (after the
tool) ``tool_response``.  Caller arguments may select the expected event and
private output directory; they cannot replace or supply those observed
fields.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, BinaryIO

CAPTURE_SCHEMA = "codex-hook-private-capture/v1"
REPORT_SCHEMA = "codex-hook-private-capture-report/v1"
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_METADATA_BYTES = 128 * 1024
READ_CHUNK = 65536
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SUPPORTED_EVENTS = frozenset({
    "UserPromptSubmit", "PreToolUse", "PostToolUse", "PreCompact",
    "SessionStart", "SubagentStart", "SubagentStop", "Stop", "SessionEnd",
})
TOOL_EVENTS = frozenset({"PreToolUse", "PostToolUse"})
COMMON_FIELDS = frozenset({
    "session_id", "transcript_path", "cwd", "hook_event_name", "model",
    "permission_mode", "turn_id", "tool_name", "tool_use_id", "tool_input",
    "tool_response", "prompt", "source", "trigger", "agent_id",
    "agent_type", "agent_transcript_path", "stop_hook_active",
    "last_assistant_message", "reason",
})


class CaptureError(ValueError):
    """Raised when input cannot be retained as a genuine-shape capture."""


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("write made no progress")
        view = view[count:]


def _read_bounded(stream: BinaryIO, limit: int) -> tuple[bytes, int, bool]:
    retained = bytearray()
    total = 0
    while True:
        chunk = stream.read(READ_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if len(retained) < limit:
            retained.extend(chunk[: limit - len(retained)])
    return bytes(retained), total, total > len(retained)


def _load_manager(runtime_root: Path) -> Any:
    path = runtime_root / "scripts" / "manage_plugin.py"
    if not path.is_file() or path.is_symlink():
        raise CaptureError("runtime root lacks a regular manage_plugin.py")
    spec = importlib.util.spec_from_file_location("host_capture_manager", path)
    if spec is None or spec.loader is None:
        raise CaptureError("could not load runtime manifest implementation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def measure_runtime(runtime_root: Path) -> tuple[str, str, int]:
    root = runtime_root.resolve(strict=True)
    manager = _load_manager(root)
    manifest = manager.tree_manifest(root)
    if not isinstance(manifest, dict) or not manifest:
        raise CaptureError("runtime manifest is empty")
    digest = _sha256(json.dumps(
        manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8"))
    plugin = json.loads((root / ".codex-plugin" / "plugin.json").read_text(
        encoding="utf-8"
    ))
    version = plugin.get("version") if isinstance(plugin, dict) else None
    if not isinstance(version, str) or not version:
        raise CaptureError("runtime plugin version is missing")
    return digest, version, len(manifest)


def validate_wire(raw: bytes, expected_event: str) -> dict[str, Any]:
    if expected_event not in SUPPORTED_EVENTS:
        raise CaptureError("unsupported expected event")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureError(f"hook stdin is not one UTF-8 JSON object: {exc}") from exc
    if not isinstance(payload, dict):
        raise CaptureError("hook stdin must be a JSON object")
    if payload.get("hook_event_name") != expected_event:
        raise CaptureError("observed hook_event_name does not match reviewed wiring")
    for field in ("session_id", "cwd"):
        if not isinstance(payload.get(field), str) or not payload[field]:
            raise CaptureError(f"observed hook payload lacks {field}")
    if expected_event in TOOL_EVENTS:
        for field in ("turn_id", "tool_name", "tool_use_id"):
            if not isinstance(payload.get(field), str) or not payload[field]:
                raise CaptureError(f"observed tool hook payload lacks {field}")
        if "tool_input" not in payload:
            raise CaptureError("observed tool hook payload lacks tool_input")
        if expected_event == "PostToolUse" and "tool_response" not in payload:
            raise CaptureError("observed PostToolUse payload lacks tool_response")
    present = sorted(COMMON_FIELDS.intersection(payload))
    unknown = sorted(set(payload) - COMMON_FIELDS)
    return {
        "observed_event": expected_event,
        "known_fields_present": present,
        "unknown_field_count": len(unknown),
        "unknown_field_names_sha256": _sha256(
            json.dumps(unknown, ensure_ascii=True, separators=(",", ":")).encode()
        ),
        "session_id_sha256": _sha256(payload["session_id"].encode("utf-8")),
        "turn_id_sha256": _sha256(str(payload.get("turn_id") or "").encode()),
        "tool_use_id_sha256": _sha256(
            str(payload.get("tool_use_id") or "").encode()
        ),
        "tool_input_sha256": _sha256(json.dumps(
            payload.get("tool_input"), ensure_ascii=True, sort_keys=True,
            separators=(",", ":"),
        ).encode()),
        "tool_name": payload.get("tool_name")
        if isinstance(payload.get("tool_name"), str) else None,
    }


def _private_directory(path: Path) -> Path:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise CaptureError("capture path must be a real directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(path, 0o700)
        if path.stat().st_mode & 0o077:
            raise CaptureError("capture directory is not owner-private")
    return path.resolve(strict=True)


def _require_owner_private(path: Path, label: str) -> None:
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise CaptureError(f"{label} is not owner-private")


def _validate_capture_time(value: Any) -> None:
    if not isinstance(value, str):
        raise CaptureError("capture timestamp is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise CaptureError("capture timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise CaptureError("capture timestamp is not UTC")


def _next_raw_path(directory: Path) -> tuple[int, Path, int]:
    for sequence in range(1, 1_000_001):
        path = directory / f"capture-{sequence:06d}.raw"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        return sequence, path, fd
    raise CaptureError("capture sequence exhausted")


def record_payload(
    raw: bytes,
    *,
    total_bytes: int,
    truncated: bool,
    expected_event: str,
    capture_dir: Path,
    runtime_root: Path,
) -> Path:
    if truncated or total_bytes != len(raw):
        raise CaptureError("oversized hook stdin is rejected; no partial evidence")
    wire = validate_wire(raw, expected_event)
    runtime_digest, plugin_version, runtime_files = measure_runtime(runtime_root)
    directory = _private_directory(capture_dir)
    sequence, raw_path, raw_fd = _next_raw_path(directory)
    try:
        _write_all(raw_fd, raw)
        if hasattr(os, "fchmod"):
            os.fchmod(raw_fd, 0o600)
        os.fsync(raw_fd)
    finally:
        os.close(raw_fd)
    meta = {
        "schema": CAPTURE_SCHEMA,
        "sequence": sequence,
        "captured_at": _utc_now(),
        "capture_kind": "codex_command_hook_stdin",
        "expected_event": expected_event,
        "raw_file": raw_path.name,
        "raw_bytes": len(raw),
        "raw_sha256": _sha256(raw),
        "capture_tool_sha256": _sha256(Path(__file__).read_bytes()),
        "runtime_tree_sha256": runtime_digest,
        "runtime_file_count": runtime_files,
        "plugin_version": plugin_version,
        "host": {
            "os": platform.system(),
            "python": platform.python_version(),
        },
        "wire": wire,
    }
    meta_path = raw_path.with_suffix(".meta.json")
    temp_path = directory / f".{meta_path.name}.{os.getpid()}.tmp"
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _write_all(fd, (json.dumps(meta, sort_keys=True) + "\n").encode())
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp_path, meta_path)
    return meta_path


def inspect_directory(capture_dir: Path, runtime_root: Path) -> dict[str, Any]:
    if capture_dir.is_symlink():
        raise CaptureError("capture path must be a real directory")
    directory = capture_dir.resolve(strict=True)
    if not directory.is_dir():
        raise CaptureError("capture path must be a real directory")
    _require_owner_private(directory, "capture directory")
    runtime_digest, plugin_version, runtime_files = measure_runtime(runtime_root)
    tool_digest = _sha256(Path(__file__).read_bytes())
    entries: list[dict[str, Any]] = []
    declared_raw: set[str] = set()
    seen_sequences: set[int] = set()
    seen_raw: set[str] = set()
    for meta_path in sorted(directory.glob("capture-*.meta.json")):
        if meta_path.is_symlink() or not meta_path.is_file():
            raise CaptureError("capture metadata is missing or not regular")
        _require_owner_private(meta_path, "capture metadata")
        if meta_path.stat().st_size > MAX_METADATA_BYTES:
            raise CaptureError("capture metadata exceeds the bounded size")
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CaptureError(f"capture metadata is unreadable: {exc}") from exc
        if not isinstance(meta, dict) or meta.get("schema") != CAPTURE_SCHEMA:
            raise CaptureError("capture metadata schema mismatch")
        if set(meta) != {
            "schema", "sequence", "captured_at", "capture_kind",
            "expected_event", "raw_file", "raw_bytes", "raw_sha256",
            "capture_tool_sha256", "runtime_tree_sha256", "runtime_file_count",
            "plugin_version", "host", "wire",
        }:
            raise CaptureError("capture metadata has missing or unknown fields")
        sequence = meta.get("sequence")
        if not isinstance(sequence, int) or sequence < 1 or sequence in seen_sequences:
            raise CaptureError("capture sequence is invalid or duplicated")
        if meta_path.name != f"capture-{sequence:06d}.meta.json":
            raise CaptureError("capture metadata filename does not match sequence")
        seen_sequences.add(sequence)
        raw_name = meta.get("raw_file")
        if not isinstance(raw_name, str) or Path(raw_name).name != raw_name:
            raise CaptureError("capture raw_file is not a local filename")
        if raw_name != f"capture-{sequence:06d}.raw":
            raise CaptureError("capture raw filename does not match sequence")
        raw_path = directory / raw_name
        declared_raw.add(raw_name)
        if raw_path.is_symlink() or not raw_path.is_file():
            raise CaptureError("capture raw payload is missing or not regular")
        _require_owner_private(raw_path, "capture raw payload")
        if raw_path.stat().st_size > MAX_CAPTURE_BYTES:
            raise CaptureError("capture raw payload exceeds the bounded size")
        raw = raw_path.read_bytes()
        raw_sha = _sha256(raw)
        if len(raw) != meta.get("raw_bytes") or raw_sha != meta.get("raw_sha256"):
            raise CaptureError("capture raw payload hash or length mismatch")
        if raw_sha in seen_raw:
            raise CaptureError("capture replays an earlier raw payload")
        seen_raw.add(raw_sha)
        wire = validate_wire(raw, str(meta.get("expected_event") or ""))
        if wire != meta.get("wire"):
            raise CaptureError("capture wire projection mismatch")
        if meta.get("capture_kind") != "codex_command_hook_stdin":
            raise CaptureError("capture kind is invalid")
        _validate_capture_time(meta.get("captured_at"))
        if meta.get("host") != {
            "os": platform.system(), "python": platform.python_version(),
        }:
            raise CaptureError("capture host identity differs from inspector")
        for digest_field in ("raw_sha256", "capture_tool_sha256",
                             "runtime_tree_sha256"):
            if not isinstance(meta.get(digest_field), str) or not HEX64.fullmatch(
                meta[digest_field]
            ):
                raise CaptureError(f"capture {digest_field} is invalid")
        if meta["capture_tool_sha256"] != tool_digest:
            raise CaptureError("capture was produced by different recorder bytes")
        if (
            meta["runtime_tree_sha256"] != runtime_digest
            or meta.get("plugin_version") != plugin_version
            or meta.get("runtime_file_count") != runtime_files
        ):
            raise CaptureError("capture runtime identity differs from inspected runtime")
        entries.append({
            "sequence": sequence,
            "captured_at": meta["captured_at"],
            "event": wire["observed_event"],
            "tool_name": wire["tool_name"],
            "known_fields_present": wire["known_fields_present"],
            "unknown_field_count": wire["unknown_field_count"],
            "raw_sha256": raw_sha,
            "runtime_tree_sha256": meta["runtime_tree_sha256"],
            "plugin_version": meta["plugin_version"],
            "session_id_sha256": wire["session_id_sha256"],
            "turn_id_sha256": wire["turn_id_sha256"],
            "tool_use_id_sha256": wire["tool_use_id_sha256"],
            "tool_input_sha256": wire["tool_input_sha256"],
        })
    raw_files = {path.name for path in directory.glob("capture-*.raw")}
    if raw_files != declared_raw:
        raise CaptureError("capture directory contains orphan raw or metadata files")
    pending_pre: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    paired = 0
    unmatched_post = 0
    for entry in sorted(entries, key=lambda item: item["sequence"]):
        if entry["event"] not in TOOL_EVENTS:
            continue
        key = (
            entry["session_id_sha256"], entry["turn_id_sha256"],
            entry["tool_use_id_sha256"], str(entry["tool_name"]),
        )
        if entry["event"] == "PreToolUse":
            if key in pending_pre:
                raise CaptureError("capture duplicates a PreToolUse identity")
            pending_pre[key] = entry
            continue
        pre = pending_pre.pop(key, None)
        if pre is None:
            unmatched_post += 1
            continue
        if pre["tool_input_sha256"] != entry["tool_input_sha256"]:
            raise CaptureError("Pre/PostToolUse tool_input differs for one tool_use_id")
        paired += 1
    return {
        "schema": REPORT_SCHEMA,
        "status": "observed" if entries else "pending",
        "scope": "private_hook_shape_probe",
        "acceptance_authority": False,
        "capture_count": len(entries),
        "entries": sorted(entries, key=lambda item: item["sequence"]),
        "tool_pairing": {
            "paired": paired,
            "unmatched_pre": len(pending_pre),
            "unmatched_post": unmatched_post,
            "complete": not pending_pre and not unmatched_post,
        },
        "limitations": [
            "records document Hook stdin shape only",
            "records do not establish trust method or any host_behavior gate",
            "raw payloads remain private and are not included in this report",
        ],
    }


def _powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def prepare_hooks(
    output: Path,
    *,
    python: Path,
    capture_dir: Path,
    runtime_root: Path,
    events: Sequence[str] = ("PreToolUse", "PostToolUse"),
) -> dict[str, Any]:
    python_path = python.resolve(strict=True)
    if not python_path.is_file():
        raise CaptureError("python entrypoint must be a regular file")
    tool_path = Path(__file__).resolve(strict=True)
    runtime_path = runtime_root.resolve(strict=True)
    _private_directory(capture_dir)
    runtime_digest, plugin_version, runtime_files = measure_runtime(runtime_path)

    def command(event: str) -> str:
        args = [
            str(python_path), str(tool_path), "record", "--expected-event", event,
            "--capture-dir", str(capture_dir.resolve()),
            "--runtime-root", str(runtime_path),
        ]
        return " ".join(shlex.quote(part) for part in args)

    def command_windows(event: str) -> str:
        args = [
            str(python_path), str(tool_path), "record", "--expected-event", event,
            "--capture-dir", str(capture_dir.resolve()),
            "--runtime-root", str(runtime_path),
        ]
        return "& " + " ".join(_powershell_quote(part) for part in args)

    selected_events = list(events)
    if (
        not selected_events
        or len(selected_events) != len(set(selected_events))
        or any(event not in SUPPORTED_EVENTS for event in selected_events)
    ):
        raise CaptureError("capture Hook event selection is invalid")
    config = {
        "description": (
            "Private Context Guard host-shape probe; records selected raw Hook "
            "stdin only after normal Codex hook review and trust."
        ),
        "hooks": {},
    }
    for event in selected_events:
        config["hooks"][event] = [{
            "matcher": ".*",
            "hooks": [{
                "type": "command",
                "command": command(event),
                "commandWindows": command_windows(event),
                "timeout": 3,
            }],
        }]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return {
        "schema": "codex-hook-private-capture-setup/v1",
        "hooks_file_sha256": _sha256(output.read_bytes()),
        "capture_tool_sha256": _sha256(tool_path.read_bytes()),
        "runtime_tree_sha256": runtime_digest,
        "runtime_file_count": runtime_files,
        "plugin_version": plugin_version,
        "events": selected_events,
        "requires_normal_hook_review_and_trust": True,
        "trust_bypass_used": False,
    }


def _positive_limit(value: str) -> int:
    parsed = int(value)
    if parsed < 1 or parsed > MAX_CAPTURE_BYTES:
        raise argparse.ArgumentTypeError(
            f"capture limit must be 1..{MAX_CAPTURE_BYTES}"
        )
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("record")
    record.add_argument("--expected-event", choices=sorted(SUPPORTED_EVENTS), required=True)
    record.add_argument("--capture-dir", type=Path, required=True)
    record.add_argument("--runtime-root", type=Path, required=True)
    record.add_argument("--max-bytes", type=_positive_limit, default=MAX_CAPTURE_BYTES)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--capture-dir", type=Path, required=True)
    inspect.add_argument("--runtime-root", type=Path, required=True)
    inspect.add_argument("--output", type=Path, required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--python", type=Path, required=True)
    prepare.add_argument("--capture-dir", type=Path, required=True)
    prepare.add_argument("--runtime-root", type=Path, required=True)
    prepare.add_argument(
        "--event", dest="events", choices=sorted(SUPPORTED_EVENTS),
        action="append", help="Hook event to capture; repeat as needed",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "record":
            raw, total, truncated = _read_bounded(sys.stdin.buffer, args.max_bytes)
            record_payload(
                raw, total_bytes=total, truncated=truncated,
                expected_event=args.expected_event,
                capture_dir=args.capture_dir, runtime_root=args.runtime_root,
            )
            # Tool hooks ignore plain stdout, but an empty JSON object is valid
            # and keeps the recorder inert across current Hook surfaces.
            print("{}")
            return 0
        if args.command == "prepare":
            setup = prepare_hooks(
                args.output, python=args.python, capture_dir=args.capture_dir,
                runtime_root=args.runtime_root,
                events=args.events or ("PreToolUse", "PostToolUse"),
            )
            print(json.dumps(setup, sort_keys=True))
            return 0
        report = inspect_directory(args.capture_dir, args.runtime_root)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"host_capture={report['status']}")
        return 0 if report["status"] == "observed" else 3
    except (CaptureError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"host_capture_failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
