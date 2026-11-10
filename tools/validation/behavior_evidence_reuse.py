#!/usr/bin/env python3
"""Behavior-evidence reuse by complete input identity (0.17.2 contract).

This tool is the executable consumer of the reuse declaration in
``docs/EVIDENCE_REUSE.md``: behavior results (unit/regression nodes) may be
reused for a new candidate only when EVERY input that affects them is
byte-identical. It evaluates a prior evidence record against the current
tree and answers, per node, ``reusable`` or ``stale`` with the changed
input named. It never relabels a stale result and never touches
artifact-exact gates (install, manifest parity, native acceptance,
performance, CI/HOL), which are never reusable across artifacts.

A record binds, per entry:

- ``code``: sha256 of every product file whose behavior the node exercises;
- ``tests``: sha256 of the test/judge file defining the node;
- ``runner``: sha256 of the runner file executing the nodes (and the
  runner's declared schema when it has one);
- ``environment``: exactly the python version, platform family and machine
  the result was observed on.

Caller shape, judge/decoder logic, fixtures and dependency facts are bound
by including the files that carry them in the appropriate group. An entry
is reusable iff every bound digest matches the current bytes and the
environment matches the current host. Anything else is ``stale`` with the
changed input named. Missing files make the entry stale (fail closed); a
record whose shape or binding is malformed is refused outright (exit 2),
never partially evaluated. Exit codes: 0 = established, 1 = stale entries,
2 = refused.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path

RECORD_SCHEMA = "cg-behavior-evidence/v1"
BINDING_KEYS = ("code", "tests", "runner")
ENVIRONMENT_KEYS = frozenset({"python", "platform_family", "machine"})
_HEX64 = set("0123456789abcdef")
_BACKSLASH = chr(92)


def file_digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def current_environment() -> dict[str, str]:
    return {
        "python": "{}.{}.{}".format(*sys.version_info[:3]),
        "platform_family": "windows" if sys.platform == "win32"
        else "macos" if sys.platform == "darwin" else "other",
        "machine": platform.machine(),
    }


def _validate_entry(entry, index: int) -> None:
    """Shape-check one entry; malformed records are refused outright
    (never partially evaluated)."""
    if not isinstance(entry, dict):
        raise ValueError(f"entry {index} must be an object")
    node = entry.get("node")
    if not isinstance(node, str) or not node:
        raise ValueError(f"entry {index} needs a node name")
    for group in BINDING_KEYS:
        bound = entry.get(group)
        if not isinstance(bound, dict) or not bound:
            raise ValueError(f"entry {node}: {group} binding missing or empty")
        for relative, digest in bound.items():
            if (not isinstance(relative, str) or not relative
                    or _BACKSLASH in relative or relative.startswith("/")
                    or ".." in Path(relative).parts):
                raise ValueError(f"entry {node}: unsafe path {relative!r}")
            if (not isinstance(digest, str) or len(digest) != 64
                    or not set(digest) <= _HEX64):
                raise ValueError(f"entry {node}: bad sha256 for {relative}")
    environment = entry.get("environment")
    if not isinstance(environment, dict) or set(environment) != ENVIRONMENT_KEYS:
        raise ValueError(
            f"entry {node}: environment must bind exactly "
            f"{sorted(ENVIRONMENT_KEYS)} (a missing environment never "
            "fails open)")


def _entry_verdict(entry: dict, root: Path, env: dict) -> dict:
    changed: list[str] = []
    for group in BINDING_KEYS:
        for relative, digest in sorted(entry[group].items()):
            actual = file_digest(root / relative)
            if actual is None:
                changed.append(f"{group}:{relative}:missing")
            elif actual != digest:
                changed.append(f"{group}:{relative}")
    for key in sorted(ENVIRONMENT_KEYS):
        if entry["environment"].get(key) != env.get(key):
            changed.append(f"environment:{key}")
    return {"node": entry["node"],
            "verdict": "stale" if changed else "reusable",
            "changed_inputs": changed}


def evaluate(record: dict, root: Path) -> dict:
    if (not isinstance(record, dict)
            or record.get("schema") != RECORD_SCHEMA
            or not isinstance(record.get("entries"), list)
            or set(record) != {"schema", "entries"}):
        raise ValueError(f"evidence record must be {RECORD_SCHEMA} with "
                         "exactly schema and entries")
    for index, entry in enumerate(record["entries"]):
        _validate_entry(entry, index)
    env = current_environment()
    entries = [_entry_verdict(entry, root, env) for entry in record["entries"]]
    reusable = [entry for entry in entries if entry["verdict"] == "reusable"]
    return {
        "schema": "cg-behavior-evidence-verdict/v1",
        "entries": entries,
        "reusable_count": len(reusable),
        "stale_count": len(entries) - len(reusable),
        "environment": env,
        # A partially reusable record is still "not_established": callers
        # re-run every stale node and may reuse only the fresh ones.
        "acceptance": "established" if entries
        and not (len(entries) - len(reusable)) else "not_established",
    }


def build_record(node_specs: list[dict], *, root: Path = Path(".")) -> dict:
    """Create a record from node specs naming their bound inputs."""
    entries = []
    for spec in node_specs:
        entry = {"node": spec["node"]}
        for group in BINDING_KEYS:
            files = spec.get(group) or []
            entry[group] = {relative: file_digest(root / relative)
                            for relative in files}
            missing = [rel for rel, digest in entry[group].items()
                       if digest is None]
            if missing:
                raise ValueError(f"bound file missing for {spec['node']}: {missing}")
        entry["environment"] = current_environment()
        entries.append(entry)
    return {"schema": RECORD_SCHEMA, "entries": entries}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True,
                        help="prior evidence record JSON")
    parser.add_argument("--root", type=Path, default=Path("."),
                        help="repository root the record is evaluated against")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()
    try:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"evidence record unreadable: {exc}", file=sys.stderr)
        return 2
    try:
        verdict = evaluate(record, args.root.resolve())
    except ValueError as exc:
        print(f"evidence record refused: {exc}", file=sys.stderr)
        return 2
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(verdict, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
    print(json.dumps({key: verdict[key] for key in
                      ("reusable_count", "stale_count", "acceptance")}))
    for entry in verdict["entries"]:
        if entry["verdict"] == "stale":
            print(f"STALE {entry['node']}: {', '.join(entry['changed_inputs'])}")
    return 0 if verdict["acceptance"] == "established" else 1


if __name__ == "__main__":
    raise SystemExit(main())
