#!/usr/bin/env python3
"""Create bounded private witnesses of Context Guard state and session IDs.

The witness is a collector, never a gate verdict. It validates state with the
installed runtime, measures that runtime, hashes all input bytes itself, and
writes a new owner-private file atomically. Raw prompts and recovery packet
text are excluded.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
from typing import Any, Sequence

SCHEMA = "context-guard-private-state-witness/v1"
HEX64 = __import__("re").compile(r"^[0-9a-f]{64}$")


class WitnessError(ValueError):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _regular(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise WitnessError(f"{label} must be a regular file")
    if path.stat().st_size > 4 * 1024 * 1024:
        raise WitnessError(f"{label} is too large")
    return path.read_bytes()


def _canonical_file(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise WitnessError(f"{label} must be a canonical absolute file")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise WitnessError(f"{label} must not use a path alias")
    return resolved


def _module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise WitnessError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _runtime(runtime_root: Path) -> tuple[Any, str, str]:
    root = runtime_root.resolve(strict=True)
    guard = _module(root / "scripts/context_guard.py", "state_witness_guard")
    capture = _module(Path(__file__).with_name("host_capture.py"), "state_witness_capture")
    digest, version, _ = capture.measure_runtime(root)
    return guard, digest, version


def _write(output: Path, value: dict[str, Any]) -> None:
    if output.exists() or output.is_symlink():
        raise WitnessError("witness output already exists")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(output.parent, 0o700)
        if stat.S_IMODE(output.parent.stat().st_mode) & 0o077:
            raise WitnessError("witness directory is not owner-private")
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n").encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("write made no progress")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def capture_state(state_path: Path, recovery_path: Path | None, output: Path,
                  runtime_root: Path, capture_setup_sha256: str) -> dict[str, Any]:
    if not HEX64.fullmatch(capture_setup_sha256):
        raise WitnessError("capture report SHA-256 is invalid")
    state_raw = _regular(_canonical_file(state_path, "state"), "state")
    state = json.loads(state_raw)
    recovery_raw: bytes | None = None
    recovery: dict[str, Any] = {}
    if recovery_path is not None:
        recovery_raw = _regular(_canonical_file(recovery_path, "recovery"), "recovery")
        parsed = json.loads(recovery_raw)
        if not isinstance(parsed, dict):
            raise WitnessError("recovery must be a JSON object")
        recovery = parsed
    guard, runtime_digest, version = _runtime(runtime_root)
    guard.validate_state_integrity(state)
    session_id = state.get("session", {}).get("id")
    if not isinstance(session_id, str) or not session_id:
        raise WitnessError("state session id is missing")
    if recovery and (not isinstance(recovery.get("state_hash"), str) or not HEX64.fullmatch(
        recovery["state_hash"]
    )):
        raise WitnessError("recovery state hash is invalid")
    packet = recovery.get("packet")
    if recovery and (not isinstance(packet, str) or recovery.get("packet_sha256") != _sha(packet.encode())):
        raise WitnessError("recovery packet hash differs")
    waits = []
    pending_recovery = state.get("pending", {}).get("recovery")
    if not isinstance(pending_recovery, dict):
        pending_recovery = {}
    prompt_hashes = {
        item.get("id"): item.get("sha256") for item in state.get("prompts", [])
        if isinstance(item, dict)
    }
    for item in state.get("wait_conditions", []):
        if not isinstance(item, dict):
            continue
        waits.append({
            "condition_id": item.get("condition_id"),
            "status": item.get("status"),
            "raised_prompt_sha256": prompt_hashes.get(item.get("raised_by_source")),
            "released_prompt_sha256": prompt_hashes.get(item.get("released_by_source")),
            "released_by_kind": item.get("released_by_kind"),
        })
    value = {
        "schema": SCHEMA, "kind": "state", "observed_at": _now(),
        "collector_sha256": _sha(Path(__file__).read_bytes()),
        "runtime_tree_sha256": runtime_digest, "plugin_version": version,
        "capture_setup_sha256": capture_setup_sha256,
        "session_id_sha256": _sha(session_id.encode()),
        "state_sha256": _sha(state_raw),
        "facts": {
            "content_hash": state.get("content_hash"),
            "wait_conditions": waits,
            "compaction_count": len(state.get("compactions", [])),
            "pending_recovery_state": pending_recovery.get("state"),
            "pending_recovery_trigger": pending_recovery.get("trigger"),
            "pending_recovery_sequence": pending_recovery.get("sequence"),
            "recovery_trigger": recovery.get("trigger"),
            "recovery_state_hash": recovery.get("state_hash"),
            "recovery_packet_sha256": recovery.get("packet_sha256"),
            "recovery_sha256": _sha(recovery_raw) if recovery_raw is not None else None,
        },
    }
    _write(output, value)
    return value


def capture_inventory(sessions: Path, output: Path, runtime_root: Path,
                      capture_setup_sha256: str) -> dict[str, Any]:
    if not HEX64.fullmatch(capture_setup_sha256):
        raise WitnessError("capture report SHA-256 is invalid")
    if sessions.is_symlink() or not sessions.resolve(strict=True).is_dir():
        raise WitnessError("sessions root must be a real directory")
    guard, runtime_digest, version = _runtime(runtime_root)
    ids: list[str] = []
    state_hashes: dict[str, str] = {}
    ended_at: dict[str, str | None] = {}
    for directory in sorted(sessions.iterdir()):
        if directory.is_symlink() or not directory.is_dir():
            continue
        path = directory / "state.json"
        try:
            raw = _regular(path, "session state")
            state = json.loads(raw)
            guard.validate_state_integrity(state)
        except Exception as exc:
            raise WitnessError(f"invalid session state {directory.name}: {exc}") from exc
        ids.append(directory.name)
        state_hashes[directory.name] = _sha(raw)
        ended = state.get("session", {}).get("ended_at")
        if ended is not None and not isinstance(ended, str):
            raise WitnessError(f"invalid ended_at in {directory.name}")
        ended_at[directory.name] = ended
    value = {
        "schema": SCHEMA, "kind": "inventory", "observed_at": _now(),
        "collector_sha256": _sha(Path(__file__).read_bytes()),
        "runtime_tree_sha256": runtime_digest, "plugin_version": version,
        "capture_setup_sha256": capture_setup_sha256,
        "facts": {"session_ids": ids, "state_sha256": state_hashes,
                  "ended_at": ended_at},
    }
    _write(output, value)
    return value


def capture_current(capture_dir: Path, sessions: Path, output: Path,
                    runtime_root: Path, capture_setup_sha256: str,
                    require_recovery: bool = False) -> dict[str, Any]:
    """Resolve the sole raw-captured session and witness its current state."""
    if capture_dir.is_symlink() or not capture_dir.resolve(strict=True).is_dir():
        raise WitnessError("capture directory must be a real directory")
    session_ids: set[str] = set()
    for path in sorted(capture_dir.glob("capture-*.raw")):
        raw = _regular(path, "Hook capture")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise WitnessError(f"Hook capture is invalid: {exc}") from exc
        session_id = payload.get("session_id") if isinstance(payload, dict) else None
        if not isinstance(session_id, str) or not session_id:
            raise WitnessError("Hook capture lacks session id")
        session_ids.add(session_id)
    if len(session_ids) != 1:
        raise WitnessError("current witness requires exactly one captured session")
    guard, _, _ = _runtime(runtime_root)
    session_id = next(iter(session_ids))
    directory = sessions.resolve(strict=True) / guard.safe_session_id(session_id)
    recovery = directory / "recovery.json"
    if require_recovery and not recovery.is_file():
        raise WitnessError("current witness requires a recovery file")
    return capture_state(directory / "state.json",
                         recovery if recovery.is_file() else None,
                         output, runtime_root, capture_setup_sha256)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    state = sub.add_parser("state")
    state.add_argument("--state", type=Path, required=True)
    state.add_argument("--recovery", type=Path)
    inv = sub.add_parser("inventory")
    inv.add_argument("--sessions", type=Path, required=True)
    current = sub.add_parser("current")
    current.add_argument("--capture-dir", type=Path, required=True)
    current.add_argument("--sessions", type=Path, required=True)
    current.add_argument("--require-recovery", action="store_true")
    for command in (state, inv, current):
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--runtime-root", type=Path, required=True)
        command.add_argument("--capture-setup-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "state":
            capture_state(args.state, args.recovery, args.output,
                                  args.runtime_root, args.capture_setup_sha256)
        elif args.command == "inventory":
            capture_inventory(args.sessions, args.output, args.runtime_root,
                                      args.capture_setup_sha256)
        else:
            capture_current(args.capture_dir, args.sessions, args.output,
                                    args.runtime_root, args.capture_setup_sha256,
                                    args.require_recovery)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}))
        return 2
    print(json.dumps({"status": "captured", "output": str(args.output.resolve()),
                      "sha256": _sha(args.output.read_bytes())},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
