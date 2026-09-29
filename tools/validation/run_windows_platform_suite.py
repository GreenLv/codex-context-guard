#!/usr/bin/env python3
"""Bounded platform regression suite; never a substitute for full behavior tests.

Covers path canonicalization/quoting and historical Windows incidents, terminal
wire encodings, Hook subprocess invocation, unusual filenames and installer
cache/no-op/integrity behavior. Live-host trust remains separate acceptance.
"""
from __future__ import annotations

import sys
import unittest

MODULES = (
    "tests.test_current_action_grounding",
    "tests.test_incident_library_regression",
    "tests.test_host_terminal_wire",
    "tests.test_stop_performance",
    "tests.test_acceptance_identity",
    "tests.test_manage_plugin",
)


def run(modules: tuple[str, ...] = MODULES) -> int:
    if not modules:
        raise ValueError("platform suite must not be empty")
    # Like the full runner, load/run modules separately to retain test isolation.
    passed = True
    total = 0
    for module in modules:
        suite = unittest.defaultTestLoader.loadTestsFromName(module)
        count = suite.countTestCases()
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        total += result.testsRun
        passed = passed and count > 0 and result.wasSuccessful() and result.testsRun > len(result.skipped)
    print(f"platform_tests={total}; status={'passed' if passed else 'failed'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(run())
