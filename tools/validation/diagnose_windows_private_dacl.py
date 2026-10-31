"""Opt-in synthetic Windows DACL observation; no caller-selected filesystem path.

This is a diagnostic, not acceptance or a permission repair. It applies the
unchanged product contract only to a newly created disposable directory. Output
contains no paths, account names, raw SIDs, raw SDDL or exception messages.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import tempfile
from pathlib import Path


def descriptor_shape(value, user_sid):
    if value is None:
        return {"readable": False}
    if not isinstance(value, str):
        return {"readable": False, "invalid_type": True}
    match = re.fullmatch(r"D:([A-Z]*)(.*)", value)
    if match is None:
        return {"readable": True, "dacl_only": False}
    controls, body = match.groups()
    aces = re.findall(r"\(([^()]*)\)", body)
    result = {"readable": True, "dacl_only": True,
              "protected": "P" in controls, "auto_inherited": "AI" in controls,
              "auto_inherit_requested": "AR" in controls,
              "recognized_controls": controls in {"", "P", "PAI", "AIP"},
              "ace_count": len(aces), "aces": []}
    for ace in aces:
        fields = ace.split(";")
        if len(fields) != 6:
            result["aces"].append({"six_fields": False})
            continue
        kind, flags, rights, object_guid, inherited_guid, trustee = fields
        category = {user_sid: "current_user", "S-1-5-18": "system",
                    "SY": "system", "S-1-5-32-544": "administrators",
                    "BA": "administrators"}.get(trustee, "other")
        # SDDL aliases are public constants, never account names. Only expose
        # the bounded aliases relevant to this diagnosis; all others stay other.
        if trustee in {"LA", "LG", "DA", "DU", "WD", "AU", "OW", "CO"}:
            category = "alias_" + trustee
        result["aces"].append({
            "type": kind if kind in {"A", "D", "OA", "OD"} else "other",
            "flags": flags if flags in {"", "OICI", "CIOI", "OICIID", "CI", "OI"}
            else "other",
            "rights": rights if rights in {"FA", "GA", "FR", "FW", "FX"}
            or re.fullmatch(r"0x[0-9a-fA-F]{1,8}", rights) else "other",
            "has_object_guid": bool(object_guid),
            "has_inherited_guid": bool(inherited_guid), "trustee": category,
        })
    return result


def observe(runtime, directory):
    report = {"diagnostic": "synthetic_windows_private_dacl/v1",
              "native_acceptance": False}
    stage = "expected"
    try:
        user_sid = runtime._windows_current_user_sid()
        expected = runtime._windows_expected_sddl(is_directory=True)
        report["expected"] = descriptor_shape(expected, user_sid)
        stage = "query_before"
        before = runtime._windows_query_dacl_sddl(directory)
        report["before"] = descriptor_shape(before, user_sid)
        stage = "apply"
        runtime._windows_apply_protected_dacl(directory, expected)
        report["apply_succeeded"] = True
        stage = "query_after"
        after = runtime._windows_query_dacl_sddl(directory)
        report["after"] = descriptor_shape(after, user_sid)
        report["contract_matches"] = runtime._windows_private_directory_dacl_matches(
            after, expected)
    except OSError as exc:
        report["error"] = {"stage": stage, "type": type(exc).__name__,
                           "winerror": getattr(exc, "winerror", None),
                           "errno": exc.errno}
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    if os.name != "nt":
        print(json.dumps({"diagnostic": "synthetic_windows_private_dacl/v1",
                          "status": "unsupported_platform"}))
        return 2
    source = Path(__file__).resolve().parents[2] / "scripts" / "context_guard.py"
    spec = importlib.util.spec_from_file_location("cg_dacl_diagnostic", source)
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    with tempfile.TemporaryDirectory(prefix="cg-dacl-diagnostic-") as temporary:
        directory = Path(temporary) / ".locks"
        directory.mkdir()
        report = observe(runtime, directory)
    report["runtime_source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    print(json.dumps(report, sort_keys=True))
    return 0 if report.get("contract_matches") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
