"""Fixed-node Windows CI diagnosis; never full or native acceptance.

Runs the original strict ACL test. Only failed operation structure is emitted;
raw descriptors, SID values, absolute paths and exception messages stay private.
"""
from __future__ import annotations

import json
import os
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

from tools.validation import incident_readonly_child as child

NODE = ("tests.test_incident_acl_family.WindowsACLMechanismTests."
        "test_original_inherited_and_protected_controls_restore")
OWNED_NAMES = {".", "nested", "nested/lock"}


def failure_structure(root, record, expected):
    """Project a failed exact comparison without weakening or editing it."""
    aliases = {record["sid"]: "actor"}

    def contract(value):
        if value is None:
            return None
        parsed = child.descriptor_contract(value)
        aces = []
        for index, value in enumerate(parsed["aces"]):
            raw = bytes.fromhex(value)
            entry = {"order": index, "type": raw[0], "flags": raw[1],
                     "size": len(raw)}
            if len(raw) >= 8:
                entry["mask"] = struct.unpack_from("<I", raw, 4)[0]
            try:
                sid = child.ace_sid(raw)
            except ValueError:
                entry["principal"] = "unsupported-shape"
            else:
                if sid not in aliases:
                    aliases[sid] = f"principal-{len(aliases):03d}"
                entry["principal"] = aliases[sid]
            aces.append(entry)
        return {key: parsed[key] for key in
                ("descriptor_revision", "dacl_revision", "dacl_control")} | {"aces": aces}

    def name(path):
        try:
            relative = Path(path).relative_to(root).as_posix()
        except ValueError:
            return "outside-owned-fixture"
        return relative if relative in OWNED_NAMES else "other-owned-object"

    operation = record["operations"][-1]
    if not isinstance(expected, dict):
        raise ValueError("exact comparison target unavailable")
    native = operation.get("native_result")
    safe_native = None
    if isinstance(native, dict):
        safe_native = {key: value for key, value in native.items()
                       if key in {"security_information", "return_value", "winerror"}
                       and type(value) is int}
        safe_native["api"] = (native.get("api") if native.get("api") in
                              {"SetFileSecurityW", "SetNamedSecurityInfoW"} else "unknown")
    return {
        "scope": "fixed-node CI diagnosis, original exact oracle retained",
        "phase": operation["phase"] if operation["phase"] in {"grant", "deny"} else "other",
        "object": name(root / operation["path"]),
        "native_result": safe_native,
        "before": contract(operation.get("before")),
        "planned": contract(operation.get("planned")),
        "actual": contract(operation.get("actual")),
        "unexpected_objects": [
            {"object": name(root / relative),
             "expected": contract(expected.get(str(root / relative))),
             "actual": contract(value)}
            for relative, value in sorted(operation.get("unexpected_objects", {}).items())],
    }


def run():
    if os.name != "nt":
        print(json.dumps({"status": "unsupported", "required_platform": "Windows"}))
        return 2
    original = child.apply_acl_change
    reports = []

    def observed(*args, **kwargs):
        try:
            return original(*args, **kwargs)
        except BaseException:
            # Diagnostics cannot swallow, replace or retry the original error.
            try:
                expected = kwargs["expected"] if "expected" in kwargs else args[6]
                report = failure_structure(args[0], args[1], expected)
            except Exception:
                report = {"scope": "fixed-node CI diagnosis", "structure": "unavailable"}
            reports.append(report)
            raise

    suite = unittest.defaultTestLoader.loadTestsFromName(NODE)
    count = suite.countTestCases()
    result = unittest.TestResult()
    # The original fixture prints its retained private path; keep those messages
    # out of public logs. The structure projection is the only diagnostic output.
    import contextlib
    import io
    output = sys.stdout
    with mock.patch.object(child, "apply_acl_change", observed):
        with contextlib.redirect_stdout(io.StringIO()):
            suite.run(result)
    for report in reports:
        print("ACL_STRUCTURE=" + json.dumps(report, sort_keys=True), file=output)
    passed = (count == result.testsRun == 1
              and result.wasSuccessful() and not result.skipped)
    print(json.dumps({"scope": "fixed-node CI diagnosis", "node": NODE,
                      "python": list(sys.version_info[:3]), "tests": result.testsRun,
                      "failures": len(result.failures), "errors": len(result.errors),
                      "skipped": len(result.skipped), "status": "passed" if passed else "failed"}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(run())
