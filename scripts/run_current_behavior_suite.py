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
the runner. Explicitly retired retention-deletion nodes remain visible as named skips,
with their original source and prior expected-failure status recorded. No
manifest entry removes tests from discovery. Every module's raw result is propagated: any failure or error
in a current module fails this runner (original exit codes, no masking).
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
EXCLUDED_HISTORICAL_BASELINE = "test_context_guard_012_baseline"


def console_failure_summary(failure: str) -> str:
    """Keep failed test IDs printable on Windows' legacy console encoding."""
    return failure.encode("ascii", "backslashreplace").decode("ascii")


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



RETIRED_RETENTION_PREFIX = "Retired retention deletion;"
RETIRED_RETENTION_BASELINE = "1178b1426254654cff4ab84d1dd2dff33c6de3d6"


def load_retired_retention_tests(path: Path | None = None) -> dict[str, dict]:
    """Verify explicit historical skips against retained methods, never filter."""
    path = path or TESTS_DIR / "retired_retention_cleanup.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("schema") != "retired-retention-tests/v1":
        raise ValueError("invalid retired-retention manifest")
    result = {}
    sources = {}
    fields = {"node", "source_commit", "original_source_sha256",
              "previous_expected_failure", "reason", "replacement"}
    for row in record.get("tests", []):
        if set(row) != fields:
            raise ValueError("invalid retired test metadata fields")
        if (row["source_commit"] != RETIRED_RETENTION_BASELINE
                or not isinstance(row["reason"], str) or not row["reason"]
                or not isinstance(row["replacement"], str) or not row["replacement"]):
            raise ValueError("retired test baseline or explanation mismatch")
        node = row["node"]
        parts = node.split(".")
        if (len(parts) != 4 or parts[0] != "tests"
                or not parts[1].startswith("test_")
                or not all(part.isidentifier() for part in parts)):
            raise ValueError("invalid retired test node")
        if node in result or type(row["previous_expected_failure"]) is not bool:
            raise ValueError("duplicate or invalid retired test")
        _, module, class_name, method_name = parts
        if module not in sources:
            text = (TESTS_DIR / (module + ".py")).read_text(encoding="utf-8")
            sources[module] = (text.splitlines(keepends=True), ast.parse(text))
        lines, tree = sources[module]
        cls = next((item for item in tree.body
                    if isinstance(item, ast.ClassDef) and item.name == class_name), None)
        method = next((item for item in cls.body
                       if isinstance(item, ast.FunctionDef) and item.name == method_name), None) if cls else None
        if method is None:
            raise ValueError("retired test method unavailable")
        start = min([method.lineno] + [item.lineno for item in method.decorator_list])
        retained = lines[start - 1:method.end_lineno]
        marker = '    @unittest.skip("Retired retention deletion;'
        if sum(line.startswith(marker) for line in retained) != 1:
            raise ValueError("retired test lacks its explicit retirement decorator")
        original = "".join(line for line in retained if not line.startswith(marker))
        if hashlib.sha256(original.encode()).hexdigest() != row["original_source_sha256"]:
            raise ValueError("retired test source digest mismatch")
        previous_xfail = any(isinstance(item, ast.Attribute) and item.attr == "expectedFailure"
                             for item in method.decorator_list)
        if previous_xfail != row["previous_expected_failure"]:
            raise ValueError("retired test expected-failure mismatch")
        result[node] = row
    return result


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

    retired = load_retired_retention_tests()
    observed_retired: set[str] = set()
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
                    "expected_failures": 0,
                    "unexpected_successes": 1,
                    "skipped": 0,
                    "note": f"import/load failed: {type(exc).__name__}: {exc}",
                }
            )
            aggregate_failures.append(f"{module_name}: import/load failed ({exc})")
            continue
        result = unittest.TextTestRunner(verbosity=0, stream=sys.stderr).run(suite)
        module_retired = [test.id() for test, reason in result.skipped
                          if reason.startswith(RETIRED_RETENTION_PREFIX)]
        observed_retired.update(module_retired)
        matrix.append(
            {
                "module": module_name,
                "retired_tests": module_retired,
                "platform_skipped": len(result.skipped) - len(module_retired),
                "tests": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "expected_failures": len(result.expectedFailures),
                "unexpected_successes": len(result.unexpectedSuccesses),
                "skipped": len(result.skipped),
            }
        )
        for test, _ in result.failures:
            aggregate_failures.append(f"{module_name}: FAIL {test.id()}")
        for test, _ in result.errors:
            aggregate_failures.append(f"{module_name}: ERROR {test.id()}")
        # A test marked expectedFailure that actually passes is a broken
        # pin: the suite must fail on it exactly like unittest does,
        # instead of silently folding it into the pass column.
        for test in result.unexpectedSuccesses:
            aggregate_failures.append(
                f"{module_name}: UNEXPECTED SUCCESS {test.id()}")

    if observed_retired != set(retired):
        aggregate_failures.append("retired retention manifest does not match explicit skipped nodes")
    retirement_report = [
        {"node": node, "previous_expected_failure": row["previous_expected_failure"],
         "reason": row["reason"]}
        for node, row in sorted(retired.items())
    ]
    total = {
        "retired_tests": retirement_report,
        "retired_test_count": len(retirement_report),
        "platform_skipped": sum(item.get("platform_skipped", item["skipped"]) for item in matrix),
        "retired_expected_failures": sum(row["previous_expected_failure"] for row in retired.values()),
        "excluded_historical_baseline": EXCLUDED_HISTORICAL_BASELINE,
        "discovered_modules": module_names,
        "modules": matrix,
        "tests": sum(item["tests"] for item in matrix),
        "failures": sum(item["failures"] for item in matrix),
        "errors": sum(item["errors"] for item in matrix),
        "expected_failures": sum(item["expected_failures"] for item in matrix),
        "unexpected_successes": sum(
            item["unexpected_successes"] for item in matrix
        ),
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
                "retired_tests": retirement_report,
                "retired_test_count": total["retired_test_count"],
                "platform_skipped": total["platform_skipped"],
                "retired_expected_failures": total["retired_expected_failures"],
                "excluded_historical_baseline": EXCLUDED_HISTORICAL_BASELINE,
                "discovered_modules": len(module_names),
                "tests": total["tests"],
                "failures": total["failures"],
                "errors": total["errors"],
                "expected_failures": total["expected_failures"],
                "unexpected_successes": total["unexpected_successes"],
                "skipped": total["skipped"],
            },
            ensure_ascii=False,
        )
    )
    for failure in aggregate_failures:
        print("!", console_failure_summary(failure))
    return 1 if aggregate_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
