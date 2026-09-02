#!/usr/bin/env python3
"""Fail closed over the required job IDs selected for one CI run."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
RESULTS = {"success", "failure", "cancelled", "skipped"}


class SummaryError(ValueError):
    """Raised when required CI evidence is missing or non-successful."""


def evaluate(required: Any, observed: Any) -> dict[str, list[str]]:
    if not isinstance(required, list) or len(required) > 128:
        raise SummaryError("required must be a bounded list")
    if any(not isinstance(item, str) or not IDENTIFIER.fullmatch(item) for item in required):
        raise SummaryError("required contains an invalid job ID")
    if len(required) != len(set(required)):
        raise SummaryError("required contains duplicate job IDs")
    if not isinstance(observed, dict) or len(observed) > 256:
        raise SummaryError("observed must be a bounded object")
    for job, result in observed.items():
        if not isinstance(job, str) or not IDENTIFIER.fullmatch(job):
            raise SummaryError("observed contains an invalid job ID")
        if result not in RESULTS:
            raise SummaryError(f"observed result for {job} is invalid")
    missing = sorted(set(required) - set(observed))
    non_success = sorted(job for job in required if observed.get(job) in RESULTS - {"success"})
    if missing or non_success:
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if non_success:
            details.append("non_success=" + ",".join(non_success))
        raise SummaryError("required jobs did not pass: " + " ".join(details))
    return {"required": sorted(required), "passed": sorted(required)}


def read_json(path: Path, label: str) -> Any:
    try:
        raw = path.read_bytes()
        if len(raw) > 1024 * 1024:
            raise SummaryError(f"{label} exceeds 1 MiB")
        return json.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SummaryError(f"cannot read {label}: {exc}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--required", type=Path, required=True)
    parser.add_argument("--observed", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = evaluate(read_json(args.required, "required"), read_json(args.observed, "observed"))
    except SummaryError as exc:
        print(f"required_summary=failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"valid": True, **summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
