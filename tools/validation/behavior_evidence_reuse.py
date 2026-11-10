#!/usr/bin/env python3
"""Reuse a completed historical-incident run with conservative input binding.

The coordinator must independently review the original execution and obtain its
report SHA-256 from that execution, and provide a reviewed environment identity.
The file hash does not authenticate the origin of a report.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

RECORD_SCHEMA = "cg-behavior-evidence/v3"
RECEIPT_SCHEMA = "cg-behavior-execution-receipt/v2"
REVIEWED_NODE = (
    "tests/test_incident_library_regression.py::DefaultPathAuthorizationCases::"
    "test_cgi_2026_009_017_026_default_path_allows_ordinary_business"
)
# This specific test was reviewed and observed without reading either log.
REVIEWED_NON_INPUTS = frozenset({"CHANGELOG.md", "CHANGELOG.zh-CN.md"})


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    return sha(path.read_bytes())


def source_inventory(root: Path) -> dict:
    """Bind every tracked file and HEAD, rejecting unexpected untracked files.

    This deliberately invalidates results on documentation-only changes too.
    Ignored and external inputs require the separate environment review.
    """
    root = root.resolve()

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(root), *args],
                                       stderr=subprocess.DEVNULL)

    untracked = git("ls-files", "--others", "--exclude-standard", "-z")
    if untracked:
        raise ValueError("untracked repository files require review")
    paths = git("ls-files", "--cached", "-z").split(b"\0")
    files = {}
    for raw in paths:
        if not raw:
            continue
        relative = os.fsdecode(raw)
        path = root / relative
        if (any(parent.is_symlink() for parent in (path, *path.parents)
                if parent != root and parent.is_relative_to(root))
                or not path.is_file() or not path.resolve().is_relative_to(root)):
            raise ValueError(f"tracked input missing or unsupported: {relative}")
        files[relative] = file_digest(path)
    if not files:
        raise ValueError("empty source inventory")
    return {"head": git("rev-parse", "HEAD").decode().strip(),
            "index_sha256": sha(git("ls-files", "--stage", "-z")),
            "status_sha256": sha(git("status", "--porcelain=v1",
                                     "--untracked-files=all", "-z")),
            "files": files}


def environment_fingerprint(environment_id: str) -> dict:
    if len(environment_id) != 64 or any(c not in "0123456789abcdef" for c in environment_id):
        raise ValueError("reviewed environment identity must be a SHA-256")
    distributions = sorted((d.metadata["Name"], d.version)
                           for d in importlib.metadata.distributions())
    if not any(name.lower() == "pytest" for name, _ in distributions if name):
        raise ValueError("pytest distribution is unavailable")
    return {
        "reviewed_external_inputs_sha256": environment_id,
        "python": sys.version,
        "python_executable_sha256": file_digest(Path(sys.executable)),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "installed_distributions_sha256": sha(json.dumps(distributions).encode()),
    }


def freeze_inputs(root: Path, environment_id: str) -> dict:
    return {"source": source_inventory(root),
            "environment": environment_fingerprint(environment_id)}


def _read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def reviewed_node_input_digest(files: dict) -> str:
    """Fingerprint the source bytes reviewed for the registered node."""
    inputs = {path: digest for path, digest in files.items()
              if path not in REVIEWED_NON_INPUTS}
    return sha(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode())


def _derive(receipt: dict, report: dict, root: Path, environment_id: str,
            report_digest: str, node: str | None = None,
            reviewed_node_sha256: str | None = None) -> dict:
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise ValueError("unsupported owner execution receipt")
    if receipt.get("report_sha256") != report_digest:
        raise ValueError("owner report digest mismatch")
    if (report.get("schema") != "incident-coverage-validation/v3"
            or report.get("valid") is not True or report.get("errors") not in (None, [])
            or report.get("release_gate", {}).get("closes_release_gate") is not True
            or report.get("release_gate", {}).get("consumer", {}).get("passed") is not True):
        raise ValueError("owner report is not a successful historical release gate")
    if receipt.get("candidate_binding") != report.get("candidate_binding"):
        raise ValueError("owner report and receipt subjects differ")
    if receipt.get("inputs_before") != receipt.get("inputs_after"):
        raise ValueError("inputs changed during original execution")
    original_inputs = receipt.get("inputs_after")
    current_inputs = freeze_inputs(root, environment_id)
    if node is None:
        if original_inputs != current_inputs:
            raise ValueError("source or reviewed environment changed")
    else:
        if node != REVIEWED_NODE:
            raise ValueError("node has no reviewed reuse scope")
        original_source = original_inputs["source"]["files"]
        current_source = current_inputs["source"]["files"]
        if reviewed_node_sha256 != reviewed_node_input_digest(original_source):
            raise ValueError("independent node-input review digest missing or mismatched")
        if (set(original_source) != set(current_source)
                or not REVIEWED_NON_INPUTS <= set(original_source)
                or original_inputs["environment"] != current_inputs["environment"]
                or any(original_source[path] != current_source[path]
                       for path in original_source if path not in REVIEWED_NON_INPUTS)):
            raise ValueError("reviewed node inputs or environment changed")

    # Re-derive the complete row/node set from the current authoritative
    # historical coverage table, rather than accepting the caller's list.
    sys.path.insert(0, str(root / "scripts"))
    import check_incident_coverage as incident  # noqa: PLC0415
    coverage = _read_json(root / "tests/fixtures/incidents/historical_case_coverage.json")
    rows = [row for row in coverage["cases"] + coverage["legacy"]
            if row.get("status") not in ("superseded", "legacy-superseded")]
    observed = report.get("execution_receipts")
    if not isinstance(observed, dict) or set(observed) != {row["id"] for row in rows}:
        raise ValueError("historical row inventory mismatch")
    nodes = []
    for row in rows:
        row_result = observed[row["id"]]
        expected = incident.locator_nodeids(str(row.get("test_locator") or ""))
        if not expected or row_result.get("executed") is not True or row_result.get("nodeids") != expected:
            raise ValueError(f"node inventory mismatch: {row['id']}")
        for key in ("results", "outcomes", "file_digests"):
            if not isinstance(row_result.get(key), dict) or set(row_result[key]) != set(expected):
                raise ValueError(f"node result inventory mismatch: {row['id']}")
        for node in expected:
            test_path = node.split("::")[0]
            digest = receipt["inputs_after"]["source"]["files"].get(test_path)
            code = row_result["results"][node]
            if (type(code) is not int or code != 0
                    or row_result["outcomes"][node] != "passed"
                    or digest is None or row_result["file_digests"][node] != digest):
                raise ValueError(f"node did not pass against its bound input: {node}")
            nodes.append({"row": row["id"], "node": node,
                          "exit_code": code, "test_sha256": digest})
    if receipt.get("nodes") != nodes:
        raise ValueError("owner report and receipt node inventory differ")
    if node is not None and not any(item["node"] == node for item in nodes):
        raise ValueError("reviewed node absent from owner report")
    return {"schema": RECORD_SCHEMA, "owner_report_sha256": report_digest,
            "inputs": receipt["inputs_after"], "nodes": nodes}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner-receipt", type=Path, required=True)
    parser.add_argument("--owner-receipt-sha256", required=True,
                        help="independently reviewed original receipt digest")
    parser.add_argument("--owner-report", type=Path, required=True)
    parser.add_argument("--owner-report-sha256", required=True,
                        help="independently reviewed original report digest")
    parser.add_argument("--environment-id", required=True,
                        help="reviewed external input identity (SHA-256)")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--build-from-receipt", action="store_true")
    parser.add_argument("--out-record", type=Path)
    parser.add_argument("--record", type=Path)
    parser.add_argument("--node", help="explicit reviewed node to reuse")
    parser.add_argument("--reviewed-node-inputs-sha256",
                        help="independent review digest for the node source inputs")
    args = parser.parse_args()
    try:
        if file_digest(args.owner_receipt) != args.owner_receipt_sha256:
            raise ValueError("independently supplied receipt digest mismatch")
        if file_digest(args.owner_report) != args.owner_report_sha256:
            raise ValueError("independently supplied report digest mismatch")
        derived = _derive(_read_json(args.owner_receipt), _read_json(args.owner_report),
                          args.root.resolve(), args.environment_id,
                          args.owner_report_sha256, args.node,
                          args.reviewed_node_inputs_sha256)
        if args.build_from_receipt:
            if (args.out_record is None or args.record is not None or args.node is not None
                    or args.reviewed_node_inputs_sha256 is not None):
                raise ValueError("build requires --out-record and no --record or --node")
            with args.out_record.open("x", encoding="utf-8") as output:
                json.dump(derived, output, indent=2)
                output.write("\n")
            print(f"record written ({len(derived['nodes'])} nodes)")
        else:
            if (args.record is None or args.out_record is not None
                    or (args.node is None and args.reviewed_node_inputs_sha256 is not None)):
                raise ValueError("evaluation requires --record and no --out-record")
            if _read_json(args.record) != derived:
                raise ValueError("record differs from complete owner evidence")
            count = 1 if args.node else len(derived["nodes"])
            print(json.dumps({"acceptance": "established", "nodes": count}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        print(f"evidence not established: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
