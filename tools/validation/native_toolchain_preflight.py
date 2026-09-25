#!/usr/bin/env python3
"""Exercise the synthetic native toolchain before spending model/interaction budget.

Runs repository-owned positive and negative controls in a real Git checkout.
No Codex process, credentials, network or native acceptance is requested.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Classes, not modules: avoid collecting TestCase helpers imported by a module.
CHECKS = (
    "tests.test_cg142_batch_preflight.BatchPreflightTests",
    "tests.test_candidate_namespace.NamespaceTests",
    "tests.test_commentary_runner_protocol.CausalTests",
    "tests.test_commentary_control_live.C2ControllerTests",
    "tests.test_commentary_native_profile.CommentaryNativeProfileTests",
    "tests.test_commentary_control_native_profile.CommentaryControlNativeProfileTests",
)
WINDOWS_ONLY = frozenset({
    "tests.test_candidate_namespace.NamespaceTests.test_windows_real_idle_rejects_other_held_file_before_manager_lock",
    "tests.test_candidate_namespace.NamespaceTests.test_windows_real_idle_scan_with_manager_lock_sequence",
})
EXIT_CODES = {"synthetic_checks_passed": 0, "failed": 1, "coverage_incomplete": 3}
UNKNOWN = ("authentication", "live_hook_trust", "effective_child_permissions",
           "live_model_lifecycle", "other_host_behavior")


def input_identity(root: Path) -> str:
    """Bind disk bytes (including uncommitted inputs), not just a commit label."""
    top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                         capture_output=True, check=True).stdout.decode().strip()
    if Path(top).resolve() != root.resolve():
        raise ValueError("requires_repository_root")
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
         "--exclude-standard", "--", "scripts", "tests", "tools", "hooks",
         "skills", "assets", ".codex-plugin", ".gitattributes", "pyproject.toml", "uv.lock"], capture_output=True, check=True,
    ).stdout
    tree = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"],
                          capture_output=True, check=False)
    if tree.returncode:
        raise ValueError("requires_committed_fixture_baseline")
    digest = hashlib.sha256(tree.stdout.strip() + b"\0")
    for raw in sorted(set(listing.split(b"\0")) - {b""}):
        relative = raw.decode("utf-8")
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("input_missing_or_linked")
        digest.update(raw + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def evaluate(root: Path, *, checks=CHECKS) -> dict:
    before = input_identity(root)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(checks)
    expected = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=0, stream=sys.stderr).run(suite)
    after = input_identity(root)
    host = platform.system()
    skipped = [test.id() for test, _ in result.skipped]
    allowed_skips = WINDOWS_ONLY if host != "Windows" else frozenset()
    unexpected_skips = sorted(set(skipped) - allowed_skips)
    completed = (expected > 0 and result.testsRun == expected and result.wasSuccessful()
                 and before == after)
    status = "failed"
    if completed:
        status = ("coverage_incomplete" if unexpected_skips or len(skipped) == expected
                  else "synthetic_checks_passed")
    return {
        "status": status,
        "toolkit_sha256": before,
        "inputs_unchanged": before == after,
        "host": host, "python": platform.python_version(),
        "checks": list(checks), "tests": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors),
        "skipped": skipped, "unexpected_skips": unexpected_skips,
        "skip_details": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
        "model_requests": 0, "native_acceptance": "not_run", "unknown": list(UNKNOWN),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="New receipt outside the source tree; never overwrites an earlier run")
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents or output.exists():
        parser.error("output must be a new path outside the source tree")
    sys.path.insert(0, str(ROOT))
    try:
        # Reserve the destination before tests; interrupted attempts never contain a PASS.
        with output.open("x", encoding="utf-8") as stream:
            result = evaluate(ROOT)
            json.dump(result, stream, indent=2)
            stream.write("\n")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("native_toolchain_preflight=failed; " + type(exc).__name__)
        return 2
    print("native_toolchain_preflight=" + result["status"] + "; native_acceptance_not_run")
    return EXIT_CODES[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
