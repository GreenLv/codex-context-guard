"""Dedicated private zero-model source controls, not native acceptance."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


CHECKS = (
    "tests.test_native_code_mode_command.CodeModeObservationTests",
    "tests.test_incident_host_full_code_mode.SharedDualViewTests",
    "tests.test_incident_host_full_code_mode.WindowsCodeModePureTests",
    "tests.test_incident_host_full_code_mode.WindowsCodeModeFullTests",
)


@contextlib.contextmanager
def private_environment():
    """Install and verify all private roots before importing product/tests."""
    keys = (
        "HOME",
        "USERPROFILE",
        "CODEX_HOME",
        "CONTEXT_GUARD_DATA_DIR",
        "CTX",
        "DATA",
        "TMPDIR",
        "TMP",
        "TEMP",
        "PLUGIN_DATA",
        "CLAUDE_PLUGIN_DATA",
        "PLUGIN_ROOT",
        "CG_CODE_MODE_VERIFICATION_ROOT",
        "PYTHONDONTWRITEBYTECODE",
    )
    previous = {key: os.environ.get(key) for key in keys}
    old_tempdir = tempfile.tempdir
    old_bytecode = sys.dont_write_bytecode
    with tempfile.TemporaryDirectory(prefix="cg-code-mode-private-") as directory:
        private = Path(directory).resolve()
        try:
            values = {
                "HOME": private / "home",
                "USERPROFILE": private / "home",
                "CODEX_HOME": private / "codex",
                "CONTEXT_GUARD_DATA_DIR": private / "data",
                "CTX": private / "data",
                "DATA": private / "data",
                "TMPDIR": private / "tmp",
                "TMP": private / "tmp",
                "TEMP": private / "tmp",
            }
            for path in set(values.values()):
                path.mkdir(mode=0o700)
            os.environ.update({key: str(path) for key, path in values.items()})
            for key in ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT"):
                os.environ.pop(key, None)
            os.environ["CG_CODE_MODE_VERIFICATION_ROOT"] = str(private)
            os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
            sys.dont_write_bytecode = True
            tempfile.tempdir = None
            for key in values:
                path = Path(os.environ[key]).resolve()
                if not path.is_relative_to(private) or path.is_symlink():
                    raise ValueError("private verification root escaped")
            if Path(os.environ["CONTEXT_GUARD_DATA_DIR"]).resolve() != private / "data":
                raise ValueError("explicit private data root missing")
            yield private
        finally:
            tempfile.tempdir = old_tempdir
            sys.dont_write_bytecode = old_bytecode
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def evaluate():
    private = Path(os.environ["CG_CODE_MODE_VERIFICATION_ROOT"]).resolve()
    # Product import occurs only after the dedicated environment is installed.
    from scripts import context_guard as cg

    if (
        cg.data_root().resolve() != private / "data"
        or not Path.home().resolve().is_relative_to(private)
    ):
        raise ValueError("effective private root assertion failed before tests")
    source_preflight = importlib.import_module(
        "tools.validation.native_toolchain_preflight"
    )
    before = source_preflight.input_identity(ROOT)
    suite = unittest.defaultTestLoader.loadTestsFromNames(CHECKS)
    expected = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if cg.data_root().resolve() != private / "data":
        raise ValueError("effective private root changed after tests")
    after = source_preflight.input_identity(ROOT)
    status = (
        "failed"
        if not expected
        or not result.wasSuccessful()
        or before != after
        or result.testsRun != expected
        else "coverage_incomplete"
        if result.skipped
        else "synthetic_checks_passed"
    )
    return {
        "schema": "incident-code-mode-preflight/v1",
        "profile": "incident_host/v2-full-code-mode",
        "status": status,
        "checks": list(CHECKS),
        "toolkit_sha256": before,
        "producer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "inputs_unchanged": before == after,
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": [{"test": t.id(), "reason": reason} for t, reason in result.skipped],
        "private_roots_verified_before_product_import_and_writes": True,
        "model_requests": 0,
        "native_acceptance": "not_run",
        "unknown": [
            "native_windows",
            "live_hook_trust",
            "effective_ACL",
            "model_lifecycle",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    path = args.output.resolve()
    if path == ROOT or ROOT in path.parents or path.exists():
        parser.error("new output outside source required")
    if "scripts.context_guard" in sys.modules:
        raise ValueError("dedicated preflight requires product-unimported process")
    with private_environment():
        with path.open("x", encoding="utf-8") as stream:
            if os.name != "nt":
                path.chmod(0o600)
            result = evaluate()
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
    print(
        "incident_code_mode_preflight="
        + result["status"]
        + "; native_acceptance=not_run"
    )
    return {"synthetic_checks_passed": 0, "failed": 1, "coverage_incomplete": 3}[
        result["status"]
    ]


if __name__ == "__main__":
    sys.exit(main())
