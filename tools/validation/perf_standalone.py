#!/usr/bin/env python3
"""Standalone absolute-budget measurement for cells without a defined A/B.

Some 0.17.0 cells have no meaningful baseline ratio (the published baseline
has no retention worker; it fails the large-record oracle by design). Their
budgets are registered in the scoped performance contract before
measurement. This runner executes exactly the predeclared number of
attempts of one such cell on the candidate tree, reads the budgets from the
contract (never from the command line), retains every failure without
replacement, and accepts only when every attempt passed its semantic oracle
and the median and p95 elapsed are within budget. Output is created
exclusively.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.validation import perf_ab  # noqa: E402

STANDALONE = {
    "retention_maintenance": ("retention_worker", perf_ab.run_retention_attempt),
    "terminal_read_large": ("repair_r1_addendum.new_cells.terminal_read_large",
                            perf_ab.run_terminal_read_attempt),
}


def contract_budgets(contract: dict, cell: str) -> tuple[dict, int]:
    node: object = contract
    for part in STANDALONE[cell][0].split("."):
        if not isinstance(node, dict) or part not in node:
            raise ValueError(f"contract has no registered budget for {cell}")
        node = node[part]
    budgets = node.get("budgets") if isinstance(node, dict) else None
    if (not isinstance(budgets, dict) or set(budgets) != {
            "median_elapsed_seconds", "p95_elapsed_seconds", "per_attempt_timeout_seconds"}
            or any(type(v) not in (int, float) or v <= 0 for v in budgets.values())):
        raise ValueError(f"registered budgets for {cell} are incomplete")
    samples = node.get("samples", contract.get("attempts"))
    if type(samples) is not int or samples < 20:
        raise ValueError("standalone cells need at least 20 predeclared samples")
    return budgets, samples


def nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, -(-len(ordered) * percentile // 100) - 1))
    return ordered[int(index)]


def measure(candidate: Path, cell: str, contract_path: Path) -> dict:
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    budgets, samples = contract_budgets(contract, cell)
    runner = STANDALONE[cell][1]
    rows = []
    for index in range(samples):
        with tempfile.TemporaryDirectory(prefix=f"cg-standalone-{cell}-") as home:
            data_dir = Path(home) / "private"
            data_dir.mkdir()
            row = dict(runner(candidate, data_dir), index=index)
        if row.get("elapsed", 0) > budgets["per_attempt_timeout_seconds"]:
            row.update(outcome_class="timeout", assertion="per_attempt_timeout")
        rows.append(row)
    passed = [row for row in rows if row.get("outcome_class") == "completed"
              and row.get("assertion") == "ok"]
    elapsed = [row["elapsed"] for row in passed]
    median = round(statistics.median(elapsed), 4) if elapsed else None
    p95 = round(nearest_rank(elapsed, 95), 4) if elapsed else None
    accepted = (len(passed) == samples and median is not None
                and median <= budgets["median_elapsed_seconds"]
                and p95 <= budgets["p95_elapsed_seconds"])
    return {
        "schema": "perf-standalone/v1", "cell": cell, "samples": samples,
        "completed": len(passed), "failures": samples - len(passed),
        "failure_details": [row for row in rows if row not in passed],
        "median_elapsed": median, "p95_elapsed": p95, "budgets": budgets,
        "contract_sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "cell_driver_sha256": hashlib.sha256(Path(perf_ab.__file__).read_bytes()).hexdigest(),
        "candidate_tree": str(candidate),
        "platform": {"system": platform.system(), "python": platform.python_version()},
        "rows": rows, "accepted": accepted,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--cell", choices=sorted(STANDALONE), required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.out.exists() or args.out.is_symlink():
        parser.error(f"refusing to overwrite existing result {args.out}")
    try:
        report = measure(args.candidate.resolve(), args.cell, args.contract)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    descriptor = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({key: report[key] for key in (
        "cell", "samples", "completed", "median_elapsed", "p95_elapsed", "accepted")}))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
