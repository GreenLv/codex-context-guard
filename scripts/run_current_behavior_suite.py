#!/usr/bin/env python3
"""Run the Context Guard current-behavior suite (Phase 3 matrix).

Discovery is DYNAMIC closed-world: every ``tests/test_*.py`` module found
on disk is collected, and exactly one module is excluded by name —
``tests/test_context_guard_012_baseline.py``, the byte-frozen Phase-1
historical baseline. That file pins 0.11.x defect behavior and 0.12 target
gaps with ``@unittest.expectedFailure``; after the Phase 3 implementation
it necessarily reports inverted defect pins and unexpected successes (the
documented test-lifecycle conflict), so it is audited separately by
``check_phase3_transition.py``, never silently skipped here.

Because discovery is dynamic, a module added in a later phase (for example
``tests/test_context_guard_phase4.py``) is collected automatically; a
module that fails to import or to load is reported as an error and fails
the runner. Every module's raw result is propagated: any failure or error
in a current module fails this runner (original exit codes, no masking).
"""

from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
EXCLUDED_HISTORICAL_BASELINE = "test_context_guard_012_baseline"


def discover_current_modules(tests_dir: Path | None = None) -> list[str]:
    """Closed-world discovery over ``test_*.py`` minus the frozen baseline.

    ``tests_dir`` defaults to the repository's tests directory; passing an
    explicit directory lets harnesses (and the census negative controls)
    exercise the discovery against an independent, disposable tree without
    ever writing into the source checkout.
    """
    directory = Path(tests_dir) if tests_dir is not None else TESTS_DIR
    module_names = sorted(
        path.stem
        for path in directory.glob("test_*.py")
        if path.is_file() and path.stem != EXCLUDED_HISTORICAL_BASELINE
    )
    if not module_names:
        raise RuntimeError(
            f"current-behavior discovery found no modules under {directory}"
        )
    return module_names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", type=Path, default=None, help="write the matrix JSON here"
    )
    args = parser.parse_args()

    sys.path.insert(0, str(ROOT))
    module_names = discover_current_modules()
    if EXCLUDED_HISTORICAL_BASELINE in module_names:
        print(f"! exclusion leaked into discovery: {EXCLUDED_HISTORICAL_BASELINE}")
        return 1

    loader = unittest.TestLoader()
    matrix = []
    aggregate_failures: list[str] = []
    for module_name in module_names:
        try:
            module = __import__(f"tests.{module_name}", fromlist=[module_name])
            suite = loader.loadTestsFromModule(module)
        except Exception as exc:  # noqa: BLE001 - report and fail, never mask
            matrix.append(
                {
                    "module": module_name,
                    "tests": 0,
                    "failures": 1,
                    "errors": 1,
                    "skipped": 0,
                    "note": f"import/load failed: {type(exc).__name__}: {exc}",
                }
            )
            aggregate_failures.append(f"{module_name}: import/load failed ({exc})")
            continue
        result = unittest.TextTestRunner(verbosity=0, stream=sys.stderr).run(suite)
        matrix.append(
            {
                "module": module_name,
                "tests": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
            }
        )
        for test, _ in result.failures:
            aggregate_failures.append(f"{module_name}: FAIL {test.id()}")
        for test, _ in result.errors:
            aggregate_failures.append(f"{module_name}: ERROR {test.id()}")

    total = {
        "excluded_historical_baseline": EXCLUDED_HISTORICAL_BASELINE,
        "discovered_modules": module_names,
        "modules": matrix,
        "tests": sum(item["tests"] for item in matrix),
        "failures": sum(item["failures"] for item in matrix),
        "errors": sum(item["errors"] for item in matrix),
        "skipped": sum(item["skipped"] for item in matrix),
    }
    if args.json:
        args.json.write_text(
            json.dumps(total, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    print(
        json.dumps(
            {
                "suite": "context-guard-current-behavior",
                "excluded_historical_baseline": EXCLUDED_HISTORICAL_BASELINE,
                "discovered_modules": len(module_names),
                "tests": total["tests"],
                "failures": total["failures"],
                "errors": total["errors"],
                "skipped": total["skipped"],
            },
            ensure_ascii=False,
        )
    )
    for failure in aggregate_failures:
        print("!", failure)
    return 1 if aggregate_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
