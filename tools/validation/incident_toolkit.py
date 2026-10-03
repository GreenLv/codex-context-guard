#!/usr/bin/env python3
"""Incident-scenario native-acceptance toolkit for CG-0151 (zero model).

Reusable runner/capture/mapper/oracle chain for the two reproduced
incidents (CGI-20261002 pause/resume, CGI-20261003 checkpoint-status).
The bundled input manifest (incident_scenarios.json) pins synthetic,
sanitized scenario inputs and desired oracle verdicts. ``capture`` runs a
scenario against a product checkout in a temporary private tree the
product's own P0Harness owns; ``map`` projects a capture bundle onto
oracle rows deterministically; ``judge`` compares rows against the
manifest. ``preflight`` proves toolchain readiness (manifest identity,
positive capture, negative fixture that must fail the oracle) and output
storage without performing any host, model or Hook-trust work.

Zero-model boundary: every artifact here is a synthetic source/toolchain
receipt. It never substitutes for native two-platform incident
acceptance, which stays a coordinator-owned gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

TOOLKIT_ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = TOOLKIT_ROOT / "incident_scenarios.json"
CAPTURE_SCHEMA = "cg-incident-capture/v1"
MAPPING_SCHEMA = "cg-incident-mapping/v1"
VERDICT_SCHEMA = "cg-incident-verdict/v1"
PREFLIGHT_SCHEMA = "cg-incident-toolkit-preflight/v1"
SCENARIO_IDS = ("pause-resume-v1", "checkpoint-status-v1")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest() -> dict:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest.get("schema") != "cg-incident-scenarios/v1":
        raise ValueError("incident scenario manifest has an unsupported schema")
    for scenario in manifest["scenarios"]:
        if scenario["id"] not in SCENARIO_IDS:
            raise ValueError(f"unknown scenario id {scenario['id']!r}")
    return manifest


def load_product_module(product_root: Path):
    product = product_root.resolve()
    sys.path.insert(0, str(product))
    sys.path.insert(0, str(product / "scripts"))
    module = __import__("tests.test_cg122_p0_counterexamples",
                        fromlist=["P0Harness", "cg"])
    return product, module


def spell_command(argv: list[str], *, windows: bool) -> str:
    """Platform adapter: one exact invocation per supported shell family.

    POSIX uses the shared shell_join form; Windows uses the single leading
    PowerShell call operator with the same token order.
    """
    from scripts.context_guard import shell_join  # noqa: PLC0415 (tool path)
    body = shell_join(argv)
    return f"& {body}" if windows else body


# ---------------------------------------------------------------------------
# Scenario runners (zero model): each returns a capture bundle dict.
# ---------------------------------------------------------------------------

def capture_pause_resume(product_root: Path) -> dict:
    product, module = load_product_module(product_root)
    harness = module.P0Harness()
    harness.setUp()
    events: list[dict] = []
    try:
        harness.activate()
        events.append({"event": "UserPromptSubmit", "kind": "activation"})
        harness.prompt("请检查并修复示例文档，然后运行测试验证。")
        harness.prompt("暂停")
        harness.dispatch("Stop", last_assistant_message="已暂停，改动已保留。")
        paused = harness.state()
        events.append({"event": "Stop", "kind": "pause_boundary",
                       "unit_status": paused["work_units"][-1]["status"],
                       "waiting": _waiting_count(paused)})
        harness.prompt("请继续执行")
        resumed = harness.state()
        events.append({"event": "UserPromptSubmit", "kind": "polite_resume",
                       "unit_status": resumed["work_units"][-1]["status"],
                       "waiting": _waiting_count(resumed),
                       "released_with_provenance": _released_provenance(resumed)})
        # Negative control: a typed wait is not released by a bare resume.
        harness.prompt("等我发来标记 ALPHA-73 再继续分析。")
        harness.dispatch("Stop", last_assistant_message="等待指定标记。")
        harness.prompt("请继续执行")
        typed = harness.state()
        events.append({"event": "UserPromptSubmit", "kind": "resume_over_typed_wait",
                       "waiting": _waiting_count(typed),
                       "typed_waiting": _typed_waiting(typed)})
        # Negative control: a negation of the resume action keeps waiting.
        harness.prompt("现在不要继续。")
        negated = harness.state()
        events.append({"event": "UserPromptSubmit", "kind": "negated_resume",
                       "waiting": _waiting_count(negated)})
    finally:
        harness.doCleanups()
    return _bundle("pause-resume-v1", events)


def capture_checkpoint_status(product_root: Path, *, windows: bool = False) -> dict:
    product, module = load_product_module(product_root)
    harness = module.P0Harness()
    harness.setUp()
    events: list[dict] = []
    try:
        harness.activate()
        harness.prompt("请核对示例诊断结果。")
        state = harness.state()
        turn = state["completion_attempt"]["turn_id"]
        script = product / "scripts" / "context_guard.py"
        for kind, options in (("legal_commands_query", ["--commands"]),
                              ("unknown_option_guard", ["--unknown-status-option"]),
                              ("missing_value_guard", ["--item", "--commands"])):
            argv = [sys.executable, str(script), "checkpoint-status",
                    "--data-dir", str(harness.root / "private"),
                    "--session-id", "p0", "--turn-id", turn,
                    "--token", "p0token", *options]
            completed = subprocess.run(argv, capture_output=True, check=False)
            spelling = spell_command(argv, windows=windows)
            payload = {"tool_name": "shell", "turn_id": turn,
                       "tool_input": {"command": spelling},
                       "tool_response": {"exit_code": completed.returncode}}
            output = harness.dispatch("PostToolUse", **payload)
            events.append({
                "event": "PostToolUse", "kind": kind,
                "cli_exit_code": completed.returncode,
                "spelling_family": "powershell" if windows else "posix",
                "posttool_blocked": output.get("decision") == "block",
            })
    finally:
        harness.doCleanups()
    return _bundle("checkpoint-status-v1", events)


def _waiting_count(state: dict) -> int:
    return sum(1 for row in state.get("wait_conditions", [])
               if row.get("status") == "waiting")


def _released_provenance(state: dict) -> bool:
    return any(row.get("status") == "released"
               and row.get("released_by_source")
               for row in state.get("wait_conditions", []))


def _typed_waiting(state: dict) -> bool:
    return any(row.get("status") == "waiting"
               and row.get("subject_sha256")
               for row in state.get("wait_conditions", []))


def _bundle(scenario_id: str, events: list[dict]) -> dict:
    return {
        "schema": CAPTURE_SCHEMA,
        "scenario_id": scenario_id,
        "captured_at": utc_now(),
        "platform_family": ("windows" if sys.platform == "win32"
                            else "posix" if sys.platform != "win32" else "unknown"),
        "execution_boundary": "zero-model synthetic source dispatch; not native acceptance",
        "events": events,
    }


# ---------------------------------------------------------------------------
# Mapper: capture bundle -> oracle rows (deterministic, no model).
# ---------------------------------------------------------------------------

def map_capture(capture: dict) -> dict:
    if capture.get("schema") != CAPTURE_SCHEMA:
        raise ValueError("capture bundle has an unsupported schema")
    by_kind = {event["kind"]: event for event in capture["events"]}
    rows: list[dict] = []
    if capture["scenario_id"] == "pause-resume-v1":
        pause = by_kind["pause_boundary"]
        resume = by_kind["polite_resume"]
        typed = by_kind["resume_over_typed_wait"]
        negated = by_kind["negated_resume"]
        rows.append({
            "id": "pause_parks_unit_with_unique_wait",
            "observed": pause["unit_status"] == "awaiting_user"
            and pause["waiting"] == 1,
        })
        rows.append({
            "id": "polite_resume_releases_with_provenance",
            "observed": resume["unit_status"] == "active"
            and resume["waiting"] == 0
            and resume["released_with_provenance"],
        })
        rows.append({
            "id": "typed_wait_survives_bare_resume",
            "observed": typed["waiting"] >= 1 and typed["typed_waiting"],
        })
        rows.append({
            "id": "negated_resume_keeps_waiting",
            "observed": negated["waiting"] >= 1,
        })
    elif capture["scenario_id"] == "checkpoint-status-v1":
        legal = by_kind["legal_commands_query"]
        unknown = by_kind["unknown_option_guard"]
        missing = by_kind["missing_value_guard"]
        rows.append({
            "id": "legal_query_not_blocked",
            "observed": legal["cli_exit_code"] == 0
            and not legal["posttool_blocked"],
        })
        rows.append({
            "id": "unknown_option_blocked",
            "observed": unknown["cli_exit_code"] == 2
            and unknown["posttool_blocked"],
        })
        rows.append({
            "id": "missing_value_blocked_on_both_surfaces",
            "observed": missing["cli_exit_code"] == 2
            and missing["posttool_blocked"],
        })
    else:
        raise ValueError(f"unknown scenario {capture['scenario_id']!r}")
    return {
        "schema": MAPPING_SCHEMA,
        "scenario_id": capture["scenario_id"],
        "capture_sha256": hashlib.sha256(json.dumps(
            capture, sort_keys=True, ensure_ascii=True).encode()).hexdigest(),
        "platform_family": capture["platform_family"],
        "rows": rows,
    }


# ---------------------------------------------------------------------------
# Oracle: mapped rows vs the manifest's desired verdicts.
# ---------------------------------------------------------------------------

def judge(mapping: dict, manifest: dict) -> dict:
    scenario = next(item for item in manifest["scenarios"]
                    if item["id"] == mapping["scenario_id"])
    desired = {row["id"]: row["desired"] for row in scenario["oracle_rows"]}
    rows = []
    for row in mapping["rows"]:
        expected = desired.get(row["id"])
        if expected is None:
            raise ValueError(f"unmapped oracle row {row['id']!r}")
        rows.append({"id": row["id"], "observed": row["observed"],
                     "desired": expected, "passed": row["observed"] == expected})
    return {
        "schema": VERDICT_SCHEMA,
        "scenario_id": mapping["scenario_id"],
        "capture_sha256": mapping["capture_sha256"],
        "platform_family": mapping["platform_family"],
        "rows": rows,
        "passed_count": sum(row["passed"] for row in rows),
        "failed_count": sum(not row["passed"] for row in rows),
    }


# ---------------------------------------------------------------------------
# Preflight: toolchain readiness, zero model, no acceptance evidence.
# ---------------------------------------------------------------------------

def preflight(output: Path) -> int:
    manifest = load_manifest()
    receipt = {
        "schema": PREFLIGHT_SCHEMA,
        "checked_at": utc_now(),
        "manifest_sha256": sha256_file(MANIFEST_PATH),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "boundary": "input and toolchain checks only; no native, host, model "
                    "or Hook-trust acceptance is performed or claimed",
        "checks": [],
    }

    def check(name: str, passed: bool, detail: str) -> bool:
        receipt["checks"].append({"check": name, "passed": bool(passed),
                                  "detail": detail})
        return bool(passed)

    ok = check("manifest_identity", True,
               f"{len(manifest['scenarios'])} scenarios pinned")
    output.parent.mkdir(parents=True, exist_ok=True)
    ok = check("output_storage_writable", ok and _writable(output),
               str(output.parent))
    with tempfile.TemporaryDirectory() as tmp:
        product_root = Path(tmp) / "product"
        product_root.symlink_to(Path(__file__).resolve().parents[2],
                                target_is_directory=True)
        positive_capture = capture_pause_resume(product_root)
        positive = map_capture(positive_capture)
        verdict = judge(positive, manifest)
        ok = check("pause_resume_positive_fixture",
                   verdict["failed_count"] == 0,
                   f"{verdict['passed_count']}/{len(verdict['rows'])} rows") and ok
        # Negative fixture: an inverted capture must fail the oracle.
        negative_capture = json.loads(json.dumps(positive_capture))
        negative_capture["events"] = [event for event in negative_capture["events"]
                                      if event["kind"] != "polite_resume"]
        negative_capture["events"].append({"event": "UserPromptSubmit",
                                           "kind": "polite_resume",
                                           "unit_status": "awaiting_user",
                                           "waiting": 1,
                                           "released_with_provenance": False})
        negative_verdict = judge(map_capture(negative_capture), manifest)
        ok = check("pause_resume_negative_fixture_detected",
                   negative_verdict["failed_count"] > 0,
                   f"{negative_verdict['failed_count']} inverted row(s) caught") and ok
        status_positive = map_capture(capture_checkpoint_status(product_root))
        status_verdict = judge(status_positive, manifest)
        ok = check("checkpoint_status_positive_fixture",
                   status_verdict["failed_count"] == 0,
                   f"{status_verdict['passed_count']}/{len(status_verdict['rows'])} rows") and ok
        # Platform adapter: the PowerShell spelling parses on this host too.
        from scripts.context_guard import (  # noqa: PLC0415
            private_control_command_tokens,
        )
        argv = [sys.executable, "context_guard.py", "checkpoint-status",
                "--data-dir", "/tmp/x", "--session-id", "p0",
                "--turn-id", "t1", "--token", "p0token", "--commands"]
        tokens = private_control_command_tokens(spell_command(argv, windows=True),
                                                windows=True)
        ok = check("powershell_spelling_adapter",
                   tokens is not None and tokens[2] == "checkpoint-status",
                   "leading call operator parsed") and ok
    receipt["preflight_passed"] = ok
    output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")
    return 0 if ok else 1


def _writable(output: Path) -> bool:
    try:
        probe = output.parent / ".preflight-probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-root", type=Path,
                        help="product checkout used by capture runs")
    parser.add_argument("--scenario", choices=SCENARIO_IDS,
                        help="capture one scenario without judging")
    parser.add_argument("--windows-spelling", action="store_true",
                        help="checkpoint-status capture uses the PowerShell "
                             "call-operator spelling")
    parser.add_argument("--capture-output", type=Path,
                        help="write the capture bundle here")
    parser.add_argument("--preflight", type=Path,
                        help="run the zero-model toolchain preflight and "
                             "write the receipt here")
    args = parser.parse_args()
    if args.preflight is not None:
        return preflight(args.preflight)
    if args.scenario is None:
        parser.error("either --preflight or --scenario is required")
    if args.product_root is None:
        parser.error("--product-root is required for --scenario")
    capture = (capture_pause_resume(args.product_root)
               if args.scenario == "pause-resume-v1"
               else capture_checkpoint_status(
                   args.product_root,
                   windows=args.windows_spelling))
    if args.capture_output is None:
        print(json.dumps(capture, ensure_ascii=False, indent=2))
        return 0
    args.capture_output.parent.mkdir(parents=True, exist_ok=True)
    args.capture_output.write_text(
        json.dumps(capture, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
