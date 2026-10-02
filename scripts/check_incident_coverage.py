#!/usr/bin/env python3
"""Validate the historical incident per-case coverage table (schema v3).

The frozen index pins every library record's identity (id, title, family,
runtime, status, successor lineage, record digest). Validation is record by
record: a forged id, a swapped title, a fabricated successor or a mismatched
lineage fails even when counts match. Test locators must resolve to a real
file, a real class and a method that actually belongs to that class. With
``--execute``, every active row's first locator runs through pytest and its
exit status becomes an execution receipt that must pass.

Import ``validate_coverage`` for adversarial self-checks (see
tests/test_incident_coverage_negative_controls.py).
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

VERDICTS = {"executed_pass", "executed_fail", "not_applicable", "analogue_only",
            "pending"}
PASSING = {"executed_pass"}
# Closed platform/source result vocabulary and the applicability rules that
# bind it to verdicts. Anything else is rejected; no failed/not_run/unknown
# platform cell can coexist with executed_pass.
PLATFORM_RESULTS = {"passed", "failed", "not_run", "pending",
                    "environment_unavailable", "not_required"}
SOURCE_RESULTS = {"passed", "failed", "not_run", "pending",
                  "environment_unavailable"}
# Windows applicability is FROZEN from the library contract: only these case
# ids are legitimately Windows-not-required. A pending-Windows row can never
# waive itself into not_required; edits here require independent review.
WINDOWS_NOT_REQUIRED_FROZEN: set[str] | None = None  # loaded from index


def _windows_required(rid: str) -> bool:
    waived = WINDOWS_NOT_REQUIRED_FROZEN
    return not (waived is not None and rid in waived)


def _check_result_alignment(rid, row, errors):
    for field, allowed in (("source_result", SOURCE_RESULTS),
                           ("macos_result", PLATFORM_RESULTS),
                           ("windows_result", PLATFORM_RESULTS)):
        if row.get(field) not in allowed:
            errors.append(f"{rid}: {field}={row.get(field)!r} outside the "
                          f"closed vocabulary {sorted(allowed)}")
    verdict = row.get("final_verdict")
    not_passed = [f for f in ("source_result", "macos_result", "windows_result")
                  if row.get(f) in {"failed", "not_run", "unknown",
                                    "environment_unavailable"}]
    if verdict == "executed_pass" and not_passed:
        errors.append(
            f"{rid}: executed_pass cannot coexist with {not_passed}")
    if verdict == "executed_pass":
        if row.get("source_result") != "passed":
            errors.append(f"{rid}: executed_pass requires source passed")
        if row.get("macos_result") != "passed":
            errors.append(f"{rid}: executed_pass requires macos passed")
        if row.get("windows_result") not in {"passed", "not_required"}:
            errors.append(
                f"{rid}: executed_pass requires windows passed or not_required")
        if (row.get("windows_result") == "not_required"
                and _windows_required(rid)):
            errors.append(
                f"{rid}: windows not_required is not in the frozen "
                "applicability waiver; the row cannot waive itself")
    if verdict == "analogue_only" and row.get("source_result") != "passed":
        errors.append(f"{rid}: analogue_only still requires source passed")
    if verdict == "pending":
        if not any(row.get(f) in {"failed", "not_run", "pending",
                                   "environment_unavailable"}
                   for f in ("source_result", "macos_result", "windows_result")):
            errors.append(
                f"{rid}: pending verdict needs at least one unpassed platform")
REQUIRED_ACTIVE_FIELDS = (
    "current_contract", "trigger", "positive", "negative", "test_locator",
    "source_result", "macos_result", "windows_result", "final_verdict",
    "owner", "missing_evidence",
)


def class_method_index(root: Path, file_path: Path):
    """Map class name -> set of method names for one test file."""
    tree = ast.parse(file_path.read_text(encoding="utf-8"))
    classes: dict[str, set[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            methods = {child.name for child in node.body
                       if isinstance(child, (ast.FunctionDef,
                                             ast.AsyncFunctionDef))}
            classes[node.name] = methods
    return classes


def resolve_locator(root: Path, locator: str, errors: list[str]) -> None:
    """Every locator segment must resolve to a real file, class and method.

    A leading ``path.py::Class::method`` sets the current file; later
    ``Class::method`` or ``::Class::method`` segments inherit it. The method
    must be owned by the named class.
    """
    current_file: Path | None = None
    current_classes: dict[str, set[str]] = {}
    last_owner: str | None = None
    for statement in locator.split(";"):
        for part in statement.split(" and "):
            part = part.strip()
            if not part:
                continue
            class_elided = part.startswith("::")
            segments = [seg for seg in part.split("::") if seg.strip()]
            if not segments:
                continue
            file_token = segments[0].split()[0] if " " in segments[0] else segments[0]
            if file_token.endswith(".py"):
                segments[0] = file_token
                current_file = root / file_token.removeprefix("./")
                if not current_file.is_file():
                    errors.append(f"locator file missing: {part}")
                    current_file = None
                    current_classes = {}
                    continue
                current_classes = class_method_index(root, current_file)
                segments = segments[1:]
            if current_file is None:
                errors.append(f"locator segment without a resolvable file: {part}")
                continue
            if not segments:
                continue
            if class_elided and last_owner:
                owner, method = last_owner, segments[0].split("(")[0].strip()
            else:
                owner = segments[0].split("(")[0].strip()
                method = (segments[1].split("(")[0].strip()
                          if len(segments) > 1 else None)
                last_owner = owner
            if owner and owner not in current_classes:
                errors.append(
                    f"class {owner} not found in {current_file.name}")
                continue
            if method and method not in current_classes[owner]:
                errors.append(
                    f"method {method} not owned by class {owner} "
                    f"in {current_file.name}")


def validate_coverage(index: dict, coverage: dict) -> list[str]:
    errors: list[str] = []
    if coverage.get("schema") != "incident-case-coverage/v2":
        errors.append("coverage schema is not incident-case-coverage/v2")
    if coverage.get("library_commit") != index.get("library_commit"):
        errors.append("coverage library commit differs from the frozen index")
    registry = index["case_registry"]["records"]
    legacy = index["legacy_source"]["records"]

    case_rows = coverage.get("cases", [])
    legacy_rows = coverage.get("legacy", [])
    case_ids = [row.get("id") for row in case_rows]
    legacy_ids = [row.get("id") for row in legacy_rows]
    for label, values in (("cases", case_ids), ("legacy", legacy_ids)):
        duplicates = {v for v in values if values.count(v) > 1}
        if duplicates:
            errors.append(f"{label}: duplicate ids {sorted(duplicates)}")
    if set(case_ids) != set(registry):
        errors.append("case id set differs from the frozen registry: "
                      f"missing={sorted(set(registry)-set(case_ids))} "
                      f"extra={sorted(set(case_ids)-set(registry))}")
    if set(legacy_ids) != set(legacy):
        errors.append("legacy id set differs from the frozen legacy lineage")
    if len(case_rows) != index["case_registry"]["raw_record_count"]:
        errors.append("case row count differs from the frozen registry")
    if len(legacy_rows) != index["legacy_source"]["raw_record_count"]:
        errors.append("legacy row count differs from the frozen lineage")

    for row in case_rows:
        rid = row.get("id")
        pin = registry.get(rid)
        if pin is None:
            continue
        for field in ("title", "family", "runtime"):
            if row.get(field) != pin.get(field):
                errors.append(
                    f"{rid}: {field} differs from the frozen library record "
                    f"({row.get(field)!r} != {pin.get(field)!r})")
        if row.get("status") != pin.get("status"):
            errors.append(f"{rid}: status differs from the frozen library")
        if pin.get("status") == "superseded":
            if row.get("successor") != pin.get("successor"):
                errors.append(
                    f"{rid}: successor {row.get('successor')!r} is not the "
                    f"library's real successor {pin.get('successor')!r}")
            continue
        if row.get("successor"):
            errors.append(f"{rid}: active row must not claim a successor")
    for row in legacy_rows:
        lid = row.get("id")
        pin = legacy.get(lid)
        if pin is None:
            continue
        if row.get("status") != pin.get("status"):
            errors.append(f"{lid}: legacy status differs from the frozen lineage")
        if pin.get("status") == "legacy-superseded":
            if row.get("successor") != pin.get("successor"):
                errors.append(
                    f"{lid}: legacy successor is not the registry's real one")
    return errors


def validate_rows(rows: list, root: Path, errors: list[str],
                  exceptions: dict | None = None) -> dict[str, int]:
    verdicts: dict[str, int] = {}
    for row in rows:
        rid = row.get("id", "<unknown>")
        status = row.get("status")
        if status in ("superseded", "legacy-superseded"):
            continue
        for field in REQUIRED_ACTIVE_FIELDS:
            if field not in row:
                errors.append(f"{rid}: missing field {field}")
        for field in ("current_contract", "trigger", "positive", "negative",
                      "test_locator"):
            if not str(row.get(field) or "").strip():
                errors.append(f"{rid}: empty {field}")
        verdict = row.get("final_verdict")
        if verdict not in VERDICTS:
            errors.append(f"{rid}: verdict not in vocabulary: {verdict}")
        else:
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
        _check_result_alignment(rid, row, errors)
        if verdict == "pending":
            if not row.get("missing_evidence"):
                errors.append(f"{rid}: pending without missing_evidence")
            if "coordinator" not in str(row.get("owner") or ""):
                errors.append(f"{rid}: pending without coordinator owner")
        if verdict == "not_applicable":
            errors.append(f"{rid}: not_applicable requires a reviewed product "
                          "boundary; batch exclusions are not accepted here")
        missing = " ".join(str(item) for item in (row.get("missing_evidence") or []))
        if "incomplete-exception:" in missing:
            _check_incomplete_exception(rid, missing, exceptions, errors, root)
        resolve_locator(root, str(row.get("test_locator") or ""), errors)
    return verdicts


INCOMPLETE_EXCEPTION_MARKER = "incomplete-exception:"


def _check_incomplete_exception(rid: str, missing: str,
                                exceptions: dict | None,
                                errors: list[str],
                                root: Path) -> None:
    """A row citing an incomplete-case exception must reference a reviewed
    entry with the required fields; the exception stays pending, never a
    pass, and its retained generic boundary must really resolve."""
    entry_id = None
    for token in missing.split():
        if token.startswith(INCOMPLETE_EXCEPTION_MARKER):
            entry_id = token[len(INCOMPLETE_EXCEPTION_MARKER):]
            break
    entries = {item.get("id"): item
               for item in ((exceptions or {}).get("exceptions") or [])
               if isinstance(item, dict)}
    entry = entries.get(entry_id)
    if entry is None:
        errors.append(
            f"{rid}: incomplete-exception reference {entry_id!r} has no "
            "reviewed entry in the exceptions fixture")
        return
    for field in ("kind", "missing", "sources_checked",
                  "why_no_faithful_oracle", "retained_generic_boundary",
                  "counts_as"):
        if not entry.get(field):
            errors.append(
                f"{rid}: exception {entry_id} is missing field {field}")
    if entry.get("coordinator_review") != "required":
        errors.append(
            f"{rid}: exception {entry_id} must require coordinator review")
    if "pass" in str(entry.get("counts_as", "")).lower() \
            and "never" not in str(entry.get("counts_as", "")).lower():
        errors.append(
            f"{rid}: exception {entry_id} must not count as a pass")
    boundary = entry.get("retained_generic_boundary") or {}
    locator = str(boundary.get("test_locator") or "")
    if locator:
        resolve_locator(root, locator, errors)


def locator_nodeids(locator: str) -> list[str]:
    """Expand a locator into every file::Class::method nodeid it names.

    Both ';' and ' and ' separate REQUIRED entries; class-elided '::method'
    inherits the current file and class. Non-test tool references (e.g. a
    benchmark CLI line) are skipped for execution but must still resolve
    structurally via resolve_locator.
    """
    nodeids: list[str] = []
    current_file = None
    last_owner = None
    for statement in locator.split(";"):
        for part in statement.split(" and "):
            part = part.strip()
            if not part:
                continue
            class_elided = part.startswith("::")
            segments = [seg for seg in part.split("::") if seg.strip()]
            if not segments:
                continue
            file_token = segments[0].split()[0] if " " in segments[0] else segments[0]
            if file_token.endswith(".py"):
                current_file = file_token
                segments = segments[1:]
                last_owner = None
            if current_file is None or not segments:
                continue
            if class_elided and last_owner:
                owner, method = last_owner, segments[0].split("(")[0].strip()
            else:
                owner = segments[0].split("(")[0].strip()
                method = (segments[1].split("(")[0].strip()
                          if len(segments) > 1 else None)
                last_owner = owner
            if method:
                nodeids.append(f"{current_file}::{owner}::{method}")
    return nodeids


def execute_receipts(root: Path, rows: list, errors: list[str]) -> dict:
    """Run EVERY required nodeid per active row; aggregate per row.

    Receipts are cached per nodeid (dedup allowed across rows, omission
    forbidden) and each receipt binds the exact test-file bytes it ran.
    """
    import hashlib

    cache: dict[str, dict] = {}
    receipts = {}
    for row in rows:
        if row.get("status") in ("superseded", "legacy-superseded"):
            continue
        nodeids = locator_nodeids(str(row.get("test_locator") or ""))
        if not nodeids:
            receipts[row["id"]] = {"executed": False,
                                   "reason": "no in-repo test nodeid"}
            errors.append(f"{row['id']}: no executable in-repo nodeid")
            continue
        row_receipt = {"executed": True, "nodeids": nodeids,
                       "results": {}, "file_digests": {}}
        for nodeid in nodeids:
            record = cache.get(nodeid)
            if record is None:
                file_path = root / nodeid.split("::")[0]
                digest = (hashlib.sha256(file_path.read_bytes()).hexdigest()
                          if file_path.is_file() else None)
                import tempfile

                with tempfile.TemporaryDirectory(prefix="cg-receipt-") as tmp:
                    junit = Path(tmp) / "report.xml"
                    completed = subprocess.run(
                        [sys.executable, "-m", "pytest", "-q", nodeid,
                         "--no-header", f"--junitxml={junit}"],
                        cwd=root, capture_output=True, text=True, timeout=900)
                    outcome = _pytest_node_outcome(nodeid, completed, junit)
                record = {"returncode": completed.returncode,
                          "outcome": outcome,
                          "file_sha256": digest,
                          "tail": (completed.stdout.strip().splitlines()[-1:]
                                   or [""])}
                cache[nodeid] = record
            row_receipt["results"][nodeid] = record["returncode"]
            row_receipt["outcomes"] = row_receipt.get("outcomes", {})
            row_receipt["outcomes"][nodeid] = record["outcome"]
            row_receipt["file_digests"][nodeid] = record["file_sha256"]
            # A required nodeid must actually PASS. A skip, xfail, or zero
            # collection exits 0 but is NOT an executed assertion.
            if record["outcome"] != "passed":
                errors.append(
                    f"{row['id']}: required nodeid not passed "
                    f"({record['outcome']}): {nodeid}")
        receipts[row["id"]] = row_receipt
    return receipts


def _pytest_node_outcome(nodeid: str, completed, junit: Path) -> str:
    """Classify one required nodeid from a machine-readable JUnit XML report.

    The nodeid must actually pass: the report binds the exact
    classname+name, any failure/error/skip child fails it, and a nonzero
    subprocess exit fails the whole node even when the XML is ambiguous
    (setup/teardown errors included).
    """
    if completed.returncode != 0:
        # A nonzero exit with a passed-looking XML (e.g. teardown error)
        # is a failure of the required node, never a pass.
        if junit.is_file():
            try:
                root = ET.parse(junit).getroot()
            except ET.ParseError:
                return "failed"
            if _junit_node_passed(root, nodeid) and not _junit_has_bad_child(
                    root, nodeid):
                return "error"  # pass surface but process failed: teardown
        return "failed"
    if not junit.is_file():
        return "not_collected"
    try:
        root = ET.parse(junit).getroot()
    except ET.ParseError:
        return "failed"
    if not _junit_has_node(root, nodeid):
        return "not_collected"
    if _junit_has_bad_child(root, nodeid):
        child = _junit_bad_child(root, nodeid)
        return {"failure": "failed", "error": "error",
                "skipped": "skipped"}.get(child, "failed")
    return "passed"


def _junit_matches(case, nodeid: str) -> bool:
    file_path = nodeid.split("::")[0].replace(".py", "").replace("/", ".")
    parts = nodeid.split("::")
    classname = case.get("classname", "")
    name = case.get("name", "")
    want_name = parts[-1]
    if len(parts) == 3:
        want_class = parts[1]
        return (name == want_name
                and (classname == f"{file_path}.{want_class}"
                     or classname.endswith(f".{want_class}")
                     or classname == want_class))
    return name == want_name and (classname == file_path
                                   or classname.endswith(file_path))


def _junit_cases(root, nodeid: str):
    return [case for case in root.iter("testcase")
            if _junit_matches(case, nodeid)]


def _junit_has_node(root, nodeid: str) -> bool:
    return bool(_junit_cases(root, nodeid))


def _junit_bad_child(root, nodeid: str) -> str | None:
    for case in _junit_cases(root, nodeid):
        for child in case:
            if child.tag in {"failure", "error", "skipped"}:
                return child.tag
    return None


def _junit_has_bad_child(root, nodeid: str) -> bool:
    return _junit_bad_child(root, nodeid) is not None


def _junit_node_passed(root, nodeid: str) -> bool:
    return (_junit_has_node(root, nodeid)
            and not _junit_has_bad_child(root, nodeid))


def prepared_source_identity(root: Path) -> dict:
    """Canonical prepared-source identity; delegates to the ONE shared
    implementation in tools/validation/acceptance_identity.py (v2: HEAD
    bound, --untracked-files=all, explicit delete/rename/symlink bindings,
    unknown file types rejected)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "acceptance_identity",
        root / "tools" / "validation" / "acceptance_identity.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.prepared_source_identity(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--index",
                        default="tests/fixtures/incidents/library_case_index.json")
    parser.add_argument("--coverage",
                        default="tests/fixtures/incidents/historical_case_coverage.json")
    parser.add_argument(
        "--exceptions",
        default="tests/fixtures/incidents/incomplete_case_exceptions.json",
        help="reviewed incomplete-case exception entries; a coverage row "
             "citing incomplete-exception:<id> must match an entry here")
    parser.add_argument("--execute", action="store_true",
                        help="run each active row's first in-repo locator and "
                             "require a passing execution receipt")
    parser.add_argument("--report")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    index = json.loads((root / args.index).read_text(encoding="utf-8"))
    coverage = json.loads((root / args.coverage).read_text(encoding="utf-8"))
    exceptions_path = root / args.exceptions
    exceptions = (json.loads(exceptions_path.read_text(encoding="utf-8"))
                  if exceptions_path.is_file() else None)
    global WINDOWS_NOT_REQUIRED_FROZEN
    WINDOWS_NOT_REQUIRED_FROZEN = set(
        index.get("windows_not_required_case_ids") or set())
    errors = validate_coverage(index, coverage)
    rows = coverage.get("cases", []) + coverage.get("legacy", [])
    verdicts = validate_rows(rows, root, errors, exceptions)
    receipts = execute_receipts(root, rows, errors) if args.execute else None
    expected = (index["case_registry"]["active_case_count"]
                + index["legacy_source"]["active_case_count"])
    adjudicated = sum(verdicts.values())
    if adjudicated != expected:
        errors.append(f"adjudicated rows {adjudicated} != active denominator "
                      f"{expected}")
    if receipts:
        for rid, receipt in receipts.items():
            for nodeid, digest in (receipt.get("file_digests") or {}).items():
                file_path = root / nodeid.split("::")[0]
                current = (hashlib.sha256(file_path.read_bytes()).hexdigest()
                           if file_path.is_file() else None)
                if digest != current:
                    errors.append(
                        f"{rid}: stale receipt for {nodeid} (file bytes "
                        "changed after execution)")

    identity = prepared_source_identity(root)
    summary = {
        "schema": "incident-coverage-validation/v3",
        "library_commit": index.get("library_commit"),
        "candidate_binding": identity,
        "denominator": {"registry": index["case_registry"],
                         "legacy": index["legacy_source"],
                         "active_total": expected},
        "adjudicated": adjudicated, "verdicts": verdicts,
        "superseded_attributed": len(rows) - adjudicated,
        "incomplete_exceptions": sorted(
            {token[len(INCOMPLETE_EXCEPTION_MARKER):]
             for row in rows
             for token in " ".join(str(x) for x in (row.get("missing_evidence") or [])).split()
             if token.startswith(INCOMPLETE_EXCEPTION_MARKER)}),
        "execution_receipts": receipts,
        "errors": errors, "valid": not errors,
    }
    print(json.dumps(summary, indent=2, default=str))
    if args.report:
        Path(args.report).write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
