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

RECORD_SCHEMA = "cg-behavior-evidence/v2"
RECEIPT_SCHEMA = "cg-behavior-execution-receipt/v1"
# The complete owner-declared input mapping per node (r1 repair 2): every
# group MUST be present (an empty dict is an explicit "none"), so a
# missing dependency or caller binding is a refusal, never a reuse.
BINDING_KEYS = ("code", "caller", "schema", "tests", "runner", "deps",
                "config")
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
    outcome = entry.get("outcome")
    if outcome not in ("executed_pass", "executed_fail"):
        raise ValueError(
            f"entry {node}: outcome must be a REAL observed "
            "executed_pass/executed_fail (a record without a real owner "
            "run behind it is never reusable)")
    result = entry.get("result")
    if (not isinstance(result, dict)
            or set(result) != {"exit_code", "observed_at",
                               "receipt_sha256", "receipt_node"}
            or not isinstance(result.get("exit_code"), int)
            or not isinstance(result.get("observed_at"), str)
            or not isinstance(result.get("receipt_sha256"), str)
            or len(result["receipt_sha256"]) != 64
            or not set(result["receipt_sha256"]) <= _HEX64
            or not isinstance(result.get("receipt_node"), str)
            or result["receipt_node"] != node):
        raise ValueError(
            f"entry {node}: result must bind the owner execution receipt "
            "(exit_code, observed_at, receipt_sha256, receipt_node)")
    for group in BINDING_KEYS:
        bound = entry.get(group)
        if not isinstance(bound, dict):
            raise ValueError(
                f"entry {node}: {group} binding missing (declare it, even "
                "as an empty dict for 'none')")
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


def _entry_verdict(entry: dict, root: Path, env: dict,
                   receipt: dict | None) -> dict:
    changed: list[str] = []
    if entry["outcome"] != "executed_pass":
        # A recorded failure (or a non-pass outcome) is never reusable:
        # the owner reruns the node.
        changed.append("outcome:not_executed_pass")
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
    if receipt is None:
        changed.append("owner_receipt:not_verified")
    else:
        result = entry["result"]
        receipt_nodes = {node.get("node"): node
                         for node in receipt.get("nodes") or []}
        bound = receipt_nodes.get(result["receipt_node"])
        if bound is None:
            changed.append("owner_receipt:node_absent")
        elif bound.get("outcome") != "passed":
            changed.append("owner_receipt:outcome_not_passed")
        elif bound.get("exit_code") != result["exit_code"]:
            changed.append("owner_receipt:exit_code_mismatch")
        else:
            bound_tests = ((bound.get("bindings") or {}).get("tests") or {})
            recorded_tests = entry.get("tests") or {}
            if recorded_tests and bound_tests and recorded_tests != bound_tests:
                changed.append("owner_receipt:test_binding_mismatch")
    return {"node": entry["node"],
            "verdict": "stale" if changed else "reusable",
            "changed_inputs": changed}


def evaluate(record: dict, root: Path,
             receipt: dict | None = None,
             receipt_sha256: str | None = None) -> dict:
    """Evaluate a reuse record against the current tree.

    ``receipt`` is the owner execution receipt the record was built from
    (with ``receipt_sha256`` = the receipt FILE's digest). Without a
    verified owner receipt EVERY entry is stale
    (``owner_receipt:not_verified``): a pass claim without a real owner
    run behind it is never established. With a receipt whose file digest
    differs from the record's binding, the record is refused outright.
    """
    if (not isinstance(record, dict)
            or record.get("schema") != RECORD_SCHEMA
            or not isinstance(record.get("entries"), list)
            or set(record) != {"schema", "entries", "source_receipt_sha256"}):
        raise ValueError(f"evidence record must be {RECORD_SCHEMA} with "
                         "schema, entries and source_receipt_sha256")
    for index, entry in enumerate(record["entries"]):
        _validate_entry(entry, index)
    if receipt is not None:
        if (not isinstance(receipt, dict) or receipt.get("schema") != RECEIPT_SCHEMA
                or receipt_sha256 is None
                or receipt_sha256 != record.get("source_receipt_sha256")):
            raise ValueError(
                "owner execution receipt refused: schema mismatch or the "
                "receipt file does not match the record's bound digest")
    env = current_environment()
    entries = [_entry_verdict(entry, root, env, receipt)
               for entry in record["entries"]]
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


def build_record_from_receipt(receipt_path: Path) -> dict:
    """THE only sanctioned producer of a reuse record.

    Converts an owner execution receipt (produced by a wired consumer,
    e.g. ``check_incident_coverage.py --execute --evidence-receipt``)
    into a reuse record. Every entry carries the node's REAL observed
    outcome and exit code plus the receipt file's digest, so a record
    without a real owner run behind it cannot exist. Nodes that did not
    actually pass are refused here: they never become reusable evidence
    and must be re-run by the owner instead.
    """
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"owner execution receipt unreadable: {exc}") from exc
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != RECEIPT_SCHEMA
            or not isinstance(receipt.get("nodes"), list)):
        raise ValueError(f"owner execution receipt must be {RECEIPT_SCHEMA}")
    entries = []
    for node in receipt["nodes"]:
        if not isinstance(node, dict):
            raise ValueError("receipt nodes must be objects")
        outcome = node.get("outcome")
        if outcome != "passed":
            raise ValueError(
                f"node {node.get('node')}: outcome {outcome!r} is not a "
                "pass -- re-run the node instead of recording it as "
                "reusable evidence")
        bindings = node.get("bindings") or {}
        missing = [group for group in BINDING_KEYS if group not in bindings]
        if missing:
            raise ValueError(
                f"node {node.get('node')}: owner input mapping incomplete, "
                f"missing groups: {', '.join(missing)}")
        entries.append({
            "node": node["node"],
            "outcome": "executed_pass",
            "result": {"exit_code": node.get("exit_code"),
                       "observed_at": receipt.get("produced_at"),
                       "receipt_sha256":
                           hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                       "receipt_node": node["node"]},
            **{group: dict(bindings.get(group) or {}) for group in BINDING_KEYS},
            "environment": dict(receipt.get("environment") or {}),
        })
    return {
        "schema": RECORD_SCHEMA,
        "entries": entries,
        "source_receipt_sha256":
            hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, default=None,
                        help="prior evidence record JSON (required for "
                             "evaluation; not for --build-from-receipt)")
    parser.add_argument("--owner-receipt", type=Path, default=None,
                        help="the owner execution receipt the record was "
                             "built from; without it no entry is reusable "
                             "(owner_receipt:not_verified)")
    parser.add_argument("--build-from-receipt", type=Path, default=None,
                        help="produce a reuse record from an owner "
                             "execution receipt (the only sanctioned "
                             "producer; requires --out-record)")
    parser.add_argument("--out-record", type=Path, default=None)
    parser.add_argument("--root", type=Path, default=Path("."),
                        help="repository root the record is evaluated against")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()
    if args.build_from_receipt is not None:
        try:
            record = build_record_from_receipt(args.build_from_receipt)
        except ValueError as exc:
            print(f"evidence record refused: {exc}", file=sys.stderr)
            return 2
        if args.out_record is None:
            print("--build-from-receipt requires --out-record",
                  file=sys.stderr)
            return 2
        args.out_record.parent.mkdir(parents=True, exist_ok=True)
        args.out_record.write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(f"record written: {args.out_record} "
              f"({len(record['entries'])} entries)")
        return 0
    if args.record is None:
        parser.error("--record is required for evaluation")
    try:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"evidence record unreadable: {exc}", file=sys.stderr)
        return 2
    receipt = None
    receipt_sha256 = None
    if args.owner_receipt is not None:
        try:
            receipt = json.loads(
                args.owner_receipt.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"owner execution receipt unreadable: {exc}",
                  file=sys.stderr)
            return 2
        receipt_sha256 = file_digest(args.owner_receipt)
    try:
        verdict = evaluate(record, args.root.resolve(), receipt,
                           receipt_sha256)
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
