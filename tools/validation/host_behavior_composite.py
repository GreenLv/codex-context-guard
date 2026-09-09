#!/usr/bin/env python3
"""Replay two independently pinned native captures and combine gate ownership.

Each child is replayed by its original adapter and Validator in an isolated
Python process. A stored result/receipt never replaces replay authority. No
Hook execution, installation, Git mutation, network, or model action is performed here.
The optional v2 manifest explicitly stages offline capture views at their original
canonical path and restores the original directory; v1 remains read-only.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA = "context-guard-host-composite-manifest/v1"
VIEW_MANIFEST_SCHEMA = "context-guard-host-composite-manifest/v2"
RESULT_SCHEMA = "host-behavior-composite/v1"
GATES = (
    "hook_trust",
    "continuity_wait",
    "compact_resume",
    "commit_event",
    "local_push_readback",
    "cleanup",
)
PARTITIONS = {
    "git_trust": ("hook_trust", "commit_event", "local_push_readback"),
    "continuity": ("continuity_wait", "compact_resume", "cleanup"),
}
ADAPTERS = {
    "git_trust": "host_raw_mapping.py",
    "continuity": "host_continuity_mapping.py",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_BYTES = 8 * 1024 * 1024


class CompositeError(ValueError):
    pass


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode()


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CompositeError("duplicate JSON key")
        result[key] = value
    return result


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise CompositeError(label + " shape differs")
    return value


def file(path: Any) -> Path:
    if not isinstance(path, str):
        raise CompositeError("file path must be a string")
    p = Path(path)
    if not p.is_absolute() or p.is_symlink() or not p.is_file() or p.resolve() != p:
        raise CompositeError("file must be canonical and regular")
    if p.stat().st_size > MAX_BYTES:
        raise CompositeError("file exceeds bounded size")
    return p


def read(path: Any, expected: Any) -> dict[str, Any]:
    if not isinstance(expected, str) or not HEX64.fullmatch(expected):
        raise CompositeError("expected SHA-256 is invalid")
    raw = file(path).read_bytes()
    if sha(raw) != expected:
        raise CompositeError("pinned file SHA-256 differs")
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise CompositeError("expected JSON object")
    return value


def normalize_platform(value: dict[str, Any]) -> dict[str, str]:
    exact(value, {"os", "shell", "toolchain"}, "platform")
    toolchain = exact(value["toolchain"], {"python", "codex"}, "toolchain")
    systems = {
        "Darwin": "macos",
        "macos": "macos",
        "Linux": "linux",
        "linux": "linux",
        "Windows": "windows",
        "windows": "windows",
    }
    system = systems.get(value["os"])
    codex = toolchain["codex"]
    if isinstance(codex, str) and codex.startswith("codex-cli "):
        codex = codex[len("codex-cli ") :]
    if (
        system is None
        or value["shell"] != "real-host-capture"
        or not isinstance(codex, str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", codex)
        or not isinstance(toolchain["python"], str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", toolchain["python"])
    ):
        raise CompositeError("platform identity is unsupported")
    return {"os": system, "python": toolchain["python"], "codex": codex}


def verify_manifest(path: Path, expected: str) -> dict[str, Any]:
    m = read(str(path), expected)
    keys = {"schema", "validator_sha256", "subject", "platform", "children"}
    if m.get("schema") == VIEW_MANIFEST_SCHEMA:
        keys.add("capture_views")
    exact(m, keys, "manifest")
    if m["schema"] not in {MANIFEST_SCHEMA, VIEW_MANIFEST_SCHEMA} or m["validator_sha256"] != sha(
        Path(__file__).read_bytes()
    ):
        raise CompositeError("composite validator identity differs")
    subject = exact(
        m["subject"],
        {
            "source_commit",
            "prepared_source_sha256",
            "runtime_tree_sha256",
            "plugin_version",
        },
        "subject",
    )
    if (
        not re.fullmatch(r"[0-9a-f]{40}", str(subject["source_commit"]))
        or any(
            not HEX64.fullmatch(str(subject[k]))
            for k in ("prepared_source_sha256", "runtime_tree_sha256")
        )
        or not re.fullmatch(r"\d+\.\d+\.\d+", str(subject["plugin_version"]))
    ):
        raise CompositeError("subject identity is invalid")
    exact(m["platform"], {"os", "python", "codex"}, "canonical platform")
    children = m["children"]
    if not isinstance(children, list) or len(children) != 2:
        raise CompositeError("exactly two children required")
    if {c.get("kind") for c in children if isinstance(c, dict)} != set(PARTITIONS):
        raise CompositeError("child partition differs")
    for c in children:
        exact(
            c,
            {
                "kind",
                "carrier_root",
                "runtime_root",
                "tool_sha256",
                "manifest",
                "manifest_sha256",
                "result",
                "result_sha256",
                "gates",
            },
            "child",
        )
        if c["gates"] != list(PARTITIONS[c["kind"]]):
            raise CompositeError("gate ownership must be the exact partition")
        check_child_files(c)
    if len({c["runtime_root"] for c in children}) != 1:
        raise CompositeError("children must replay against the same runtime root")
    if m["schema"] == VIEW_MANIFEST_SCHEMA:
        verify_capture_views(m)
    return m


def check_child_files(c: dict[str, Any]) -> None:
    root = Path(c["carrier_root"])
    runtime = Path(c["runtime_root"])
    for p in (root, runtime):
        if not p.is_absolute() or p.is_symlink() or not p.is_dir() or p.resolve() != p:
            raise CompositeError("carrier/runtime root must be canonical")
    pins = c["tool_sha256"]
    if not isinstance(pins, dict):
        raise CompositeError("tool pins missing")
    actual = {
        p.name: sha(file(str(p)).read_bytes())
        for p in (root / "tools/validation").glob("*.py")
    }
    if pins != actual or not {
        ADAPTERS[c["kind"]],
        "host_behavior.py",
        "host_capture.py",
    } <= set(pins):
        raise CompositeError("original child tool inventory changed")
    read(c["manifest"], c["manifest_sha256"])
    read(c["result"], c["result_sha256"])


def directory(value: Any) -> Path:
    if not isinstance(value, str):
        raise CompositeError("directory must be a string")
    p = Path(value)
    if not p.is_absolute() or p.is_symlink() or not p.is_dir() or p.resolve() != p:
        raise CompositeError("capture directory must be canonical")
    return p


def capture_inventory(path: Path) -> dict[str, str]:
    directory(str(path))
    result = {}
    total = 0
    for entry in path.iterdir():
        if not re.fullmatch(r"capture-[0-9]{6}\.(?:raw|meta\.json)", entry.name):
            raise CompositeError("capture view has an unexpected entry")
        regular = file(str(entry))
        if regular.stat().st_nlink != 1:
            raise CompositeError("capture view hard links are not allowed")
        raw = regular.read_bytes()
        total += len(raw)
        if len(result) >= 4096 or total > 64 * 1024 * 1024:
            raise CompositeError("capture view exceeds bounded inventory")
        result[entry.name] = sha(raw)
    if not result:
        raise CompositeError("capture view is empty")
    return result


def check_inventory(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or not value or len(value) > 4096:
        raise CompositeError("capture inventory is missing or oversized")
    if any(not isinstance(k, str) or not re.fullmatch(r"capture-[0-9]{6}\.(?:raw|meta\.json)", k)
           or not isinstance(v, str) or not HEX64.fullmatch(v) for k, v in value.items()):
        raise CompositeError("capture inventory entry differs")
    return value


def verify_capture_views(m: dict[str, Any]) -> None:
    views = exact(m["capture_views"], {"schema", "directory", "original_files", "children"}, "capture views")
    if views["schema"] != "offline-capture-views/v1":
        raise CompositeError("capture view schema differs")
    sink = directory(views["directory"])
    check_inventory(views["original_files"])
    snapshots = exact(views["children"], set(PARTITIONS), "capture view children")
    roots = [sink]
    for c in m["children"]:
        view = exact(snapshots[c["kind"]], {"archive_root", "files"}, "capture view")
        archive = directory(view["archive_root"])
        roots.append(archive)
        if capture_inventory(archive) != check_inventory(view["files"]):
            raise CompositeError("archive inventory differs from pinned bytes")
        original = read(c["manifest"], c["manifest_sha256"])
        recorded = (original.get("evidence", {}).get("capture_dir") if c["kind"] == "git_trust"
                    else original.get("capture", {}).get("directory"))
        if recorded != str(sink):
            raise CompositeError("capture view does not bind original manifest path")
    for index, root in enumerate(roots):
        for other in roots[index + 1:]:
            if root == other or root in other.parents or other in root.parents:
                raise CompositeError("capture view paths overlap")
    # The only movable directory is the declared capture sink, never a carrier
    # or runtime containing any pinned replay input.
    for c in m["children"]:
        for key in ("carrier_root", "runtime_root", "manifest", "result"):
            target = Path(c[key])
            if sink == target or sink in target.parents or target in sink.parents:
                raise CompositeError("capture sink overlaps replay inputs")


def rename_exclusive(source: Path, destination: Path) -> None:
    """Use native no-replace rename; an existence precheck alone is racy."""
    if os.name == "nt":
        os.rename(source, destination)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = libc.renamex_np
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        args = (os.fsencode(source), os.fsencode(destination), 4)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        rename = libc.renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        args = (-100, os.fsencode(source), -100, os.fsencode(destination), 1)  # RENAME_NOREPLACE
    else:
        raise CompositeError("exclusive directory rename is unsupported on this host")
    rename.restype = ctypes.c_int
    if rename(*args) != 0:
        code = ctypes.get_errno() or errno.EIO
        raise OSError(code, os.strerror(code), str(destination))


@contextmanager
def capture_view(m: dict[str, Any], kind: str):
    """Offline transaction; callers must stop all non-cooperating writers first.

    The exclusive lock coordinates replayers only. Raw recorders do not honor
    it. Any detected mutation rejects acceptance and preserves unexpected data.
    No original archive, manifest, result, or carrier is edited.
    """
    verify_capture_views(m)
    views = m["capture_views"]
    sink = directory(views["directory"])
    archive = directory(views["children"][kind]["archive_root"])
    expected = views["children"][kind]["files"]
    if capture_inventory(sink) != views["original_files"]:
        raise CompositeError("original live capture inventory changed")
    lock = sink.with_name(sink.name + ".offline-replay.lock")
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical({"schema": "offline-capture-replay-lock/v1", "pid": os.getpid()}))
    lock_bytes = lock.read_bytes()
    transaction = Path(tempfile.mkdtemp(prefix=".capture-replay-", dir=sink.parent)).resolve()
    backup = transaction / "original"
    staged = transaction / "staged"
    preserved = transaction / "replayed"
    switched = False
    restored = False
    receipt = {"schema": "offline-capture-view-replay/v1", "original_directory": str(sink),
               "archive_root": str(archive), "archive_files": expected,
               "original_files": views["original_files"], "transaction_directory": str(transaction),
               "mode": "temporary_canonical_path_switch", "restored": False,
               "writer_exclusion": "external_quiescence_required; lock_coordinates_replayers_only"}
    try:
        staged.mkdir(mode=0o700)
        for name, digest in expected.items():
            raw = file(str(archive / name)).read_bytes()
            if sha(raw) != digest:
                raise CompositeError("archive changed during staging")
            with (staged / name).open("xb") as stream:
                stream.write(raw)
            (staged / name).chmod(0o600)
        if capture_inventory(staged) != expected or capture_inventory(archive) != expected:
            raise CompositeError("staged archive differs")
        if capture_inventory(sink) != views["original_files"]:
            raise CompositeError("original capture changed before switch")
        rename_exclusive(sink, backup)
        # If a writer creates the sink in this interval, never overwrite it.
        if sink.exists() or sink.is_symlink():
            raise CompositeError("capture restore conflict; original preserved at " + str(backup))
        rename_exclusive(staged, sink)
        switched = True
        yield receipt
        if capture_inventory(sink) != expected or capture_inventory(archive) != expected:
            raise CompositeError("capture or archive changed during replay")
        if capture_inventory(backup) != views["original_files"]:
            raise CompositeError("preserved original capture changed")
    finally:
        if backup.exists():
            if capture_inventory(backup) != views["original_files"]:
                raise CompositeError("preserved original changed; recovery required at " + str(transaction))
            if switched:
                # Move, never delete, even a corrupt or unexpectedly replaced view.
                if preserved.exists() or preserved.is_symlink():
                    raise CompositeError("replay preservation conflict; recovery required at " + str(transaction))
                if sink.exists() or sink.is_symlink():
                    rename_exclusive(sink, preserved)
                else:
                    raise CompositeError("replay view disappeared; recovery required at " + str(transaction))
            elif sink.exists() or sink.is_symlink():
                raise CompositeError("restore refuses occupied capture path; recovery required at " + str(transaction))
            rename_exclusive(backup, sink)
            restored = capture_inventory(sink) == views["original_files"]
        else:
            restored = capture_inventory(sink) == views["original_files"]
        if not restored:
            raise CompositeError("capture restoration mismatch; recovery required at " + str(transaction))
        receipt["restored"] = True
        if file(str(lock)).read_bytes() != lock_bytes:
            raise CompositeError("replay lock changed; recovery required at " + str(transaction))
        lock.unlink()


def load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CompositeError("cannot load pinned child tool")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def replay_child(m: dict[str, Any], kind: str) -> dict[str, Any]:
    """Worker-only path: raw adapter and Validator are called together here."""
    c = next(c for c in m["children"] if c["kind"] == kind)
    check_child_files(c)
    root = Path(c["carrier_root"]) / "tools/validation"
    adapter = load(root / ADAPTERS[kind], "composite_original_adapter")
    validator = load(root / "host_behavior.py", "composite_original_validator")
    child_manifest = read(c["manifest"], c["manifest_sha256"])
    if child_manifest.get("subject") != m["subject"]:
        raise CompositeError("child manifest subject differs")
    bundle, receipt = adapter.adapt(
        Path(c["manifest"]), Path(c["runtime_root"]), c["manifest_sha256"]
    )
    result = validator.Validator(
        bundle["subject"], m["subject"]["plugin_version"]
    ).validate(bundle, reviewed_mapping=receipt)
    stored = read(c["result"], c["result_sha256"])
    if result != stored:
        raise CompositeError("fresh child result differs from original result")
    check_child_files(c)
    return {"result": result, "receipt_sha256": sha(canonical(receipt))}


def run_worker(path: Path, expected: str, kind: str) -> dict[str, Any]:
    command = [
        sys.executable,
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        "--manifest",
        str(path),
        "--sha256",
        expected,
        "--replay-child",
        kind,
    ]
    completed = subprocess.run(command, capture_output=True, timeout=90, check=False)
    if completed.returncode:
        raise CompositeError("fresh " + kind + " replay rejected")
    if len(completed.stdout) > MAX_BYTES:
        raise CompositeError("child replay output too large")
    value = json.loads(completed.stdout, object_pairs_hook=unique)
    return exact(value, {"result", "receipt_sha256"}, "fresh worker response")


def check_result(m: dict[str, Any], c: dict[str, Any], r: dict[str, Any]) -> None:
    expected_subject = {
        "kind": "prepared_host_behavior",
        **{
            k: m["subject"][k]
            for k in ("source_commit", "prepared_source_sha256", "runtime_tree_sha256")
        },
    }
    if (
        r.get("schema") != "native-acceptance/v2"
        or r.get("gate_profile") != "host_behavior"
        or r.get("product") != "codex_context_guard"
        or r.get("subject") != expected_subject
        or r.get("runtime_tree_sha256") != m["subject"]["runtime_tree_sha256"]
    ):
        raise CompositeError("child result subject/profile differs")
    if normalize_platform(r["platform"]) != m["platform"]:
        raise CompositeError("child platform differs")
    gates = r.get("gates")
    if (
        not isinstance(gates, list)
        or len(gates) != 6
        or {g.get("id") for g in gates} != set(GATES)
    ):
        raise CompositeError("child gate set differs")
    sessions = r.get("sessions")
    if (
        not isinstance(sessions, list)
        or len(sessions) != 1
        or set(sessions[0].get("scenarios", [])) != set(c["gates"])
    ):
        raise CompositeError("child session/gate ownership differs")
    for g in gates:
        if g["id"] in c["gates"]:
            if (
                g["status"] != "passed"
                or g["chain"] != "valid"
                or g["exit_code"] != 0
                or g["evidence"]["mode"] != "reviewed_raw_mapping"
            ):
                raise CompositeError("owned gate is not freshly verified")
        elif g["status"] != "pending" or g["chain"] != "absent":
            raise CompositeError("unowned child gate is not absent pending")
    if (
        r.get("status") != "pending"
        or r["visibility"]["host_passed_reachable"] is not False
    ):
        raise CompositeError("child bounded status changed")


def compose(path: Path, expected: str) -> dict[str, Any]:
    m = verify_manifest(path, expected)
    children = []
    gates = {}
    sessions = []
    for c in m["children"]:
        context = capture_view(m, c["kind"]) if m["schema"] == VIEW_MANIFEST_SCHEMA else nullcontext(None)
        with context as view_receipt:
            fresh = run_worker(path, expected, c["kind"])
        r = fresh["result"]
        # Never trust only subprocess JSON: require equality to the pinned original,
        # after fresh execution has independently produced it.
        if r != read(c["result"], c["result_sha256"]):
            raise CompositeError("worker result identity differs")
        check_result(m, c, r)
        sessions.extend(r["sessions"])
        for gate in r["gates"]:
            if gate["id"] not in c["gates"]:
                continue
            if gate["id"] in gates:
                raise CompositeError("duplicate gate owner")
            item = copy.deepcopy(gate)
            item["evidence"].update(
                mode="fresh_child_replay",
                source_result_sha256=c["result_sha256"],
                source_gate_id=gate["id"],
                invalidation_reason="child_inputs_changed",
            )
            gates[gate["id"]] = item
        child_manifest = read(c["manifest"], c["manifest_sha256"])
        children.append(
            {
                "kind": c["kind"],
                **({"capture_view_replay": view_receipt} if view_receipt is not None else {}),
                "manifest_sha256": c["manifest_sha256"],
                "result_sha256": c["result_sha256"],
                "tool_sha256": c["tool_sha256"],
                "fresh_receipt_sha256": fresh["receipt_sha256"],
                "gates": c["gates"],
                "sessions": r["sessions"],
                "platform_original": r["platform"],
                "original_validation": r["validation"],
                "capture_configuration": child_manifest.get(
                    "capture", child_manifest.get("evidence")
                ),
            }
        )
    if set(gates) != set(GATES) or len({s["session_id"] for s in sessions}) != len(
        sessions
    ):
        raise CompositeError("complete partition or independent sessions missing")
    verify_manifest(path, expected)
    if m["schema"] == VIEW_MANIFEST_SCHEMA and capture_inventory(directory(m["capture_views"]["directory"])) != m["capture_views"]["original_files"]:
        raise CompositeError("original capture changed after restoration")
    subject = {
        k: m["subject"][k]
        for k in ("source_commit", "prepared_source_sha256", "runtime_tree_sha256")
    }
    return {
        "schema": "native-acceptance/v2",
        "status": "passed",
        "product": "codex_context_guard",
        "gate_profile": "host_behavior",
        "subject": {"kind": "prepared_host_behavior", **subject},
        "repository": {"url": None, "commit": subject["source_commit"]},
        "runtime_tree_sha256": subject["runtime_tree_sha256"],
        "artifact": None,
        "platform": {
            "os": m["platform"]["os"],
            "shell": "real-host-capture",
            "toolchain": {k: m["platform"][k] for k in ("python", "codex")},
        },
        "sessions": sessions,
        "gates": [gates[g] for g in GATES],
        "validation": {
            "schema": RESULT_SCHEMA if m["schema"] == MANIFEST_SCHEMA else "host-behavior-composite/v2",
            "validator_sha256": m["validator_sha256"],
            "composite_manifest_sha256": expected,
            "children": children,
            "platform_alias_policy": "macos=Darwin; codex-cli prefix is formatting only",
            **({"executable_identity_scope": "version compatibility only; no shared executable byte identity is proved"}
               if m["schema"] == VIEW_MANIFEST_SCHEMA else {}),
        },
        "cleanup": {
            "status": "observed_facts_required",
            "remaining_ids": [],
            "note": "delegated to the independently replayed continuity child",
        },
        "visibility": {
            "full_result_is_public": False,
            "public_annex_sanitized": False,
            "host_passed_reachable": True,
        },
        "scope": {
            "macos_composite_only": m["platform"]["os"] == "macos",
            "whole_p4": "pending",
            "windows": "six_gates_composite" if m["platform"]["os"] == "windows" else "not_established",
            "p3": "not_established",
            "p5": "not_established",
        },
        "unperformed_actions": [
            "commit",
            "push",
            "merge",
            "tag",
            "release",
            "public_promotion",
        ],
        "capability_note": "Six gates across two separately pinned native captures; "
        "capture sessions, setups and tool versions remain distinct. "
        "Historical executable evidence is not strengthened by replay or version equality.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--replay-child", choices=tuple(PARTITIONS), help=argparse.SUPPRESS
    )
    args = parser.parse_args()
    try:
        if args.replay_child:
            result = replay_child(
                verify_manifest(args.manifest, args.sha256), args.replay_child
            )
            print(json.dumps(result, sort_keys=True))
        else:
            result = compose(args.manifest, args.sha256)
            if args.output is None:
                raise CompositeError("--output is required for a composite result")
            # Exclusive output prevents silently replacing any accepted evidence.
            raw = json.dumps(result, sort_keys=True, indent=2).encode() + b"\n"
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
            print(
                json.dumps(
                    {
                        "status": result["status"],
                        "output_sha256": sha(raw),
                        "scope": result["scope"],
                    }
                )
            )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
