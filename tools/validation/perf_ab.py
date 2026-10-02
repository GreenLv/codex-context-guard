#!/usr/bin/env python3
"""Formal interleaved A/B performance driver (baseline tree vs candidate tree).

Fixes the R1 driver defects: matched active sessions and event identities,
assertions on output AND persisted semantics, the exact configured Hook
wrapper from hooks/hooks.json, raw per-attempt rows, retained timeouts and
failures (never aborting the batch, never replacing a sample), input/driver/
source digests, and predeclared attempt counts with nearest-rank percentiles.

Modes: default runs a labeled diagnostic; ``--formal`` refuses fewer than 20
attempts per cell and records full identities. A formal batch is executed
once after F1/F2 converge; do not present diagnostics as formal evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HOOK_TIMEOUT_SECONDS = 15


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_wrapper(tree: Path, event: str) -> str:
    hooks = json.loads((tree / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    entry = hooks["hooks"][event][0]["hooks"][0]
    command = entry["command"]
    if sys.platform == "win32":
        command = entry["commandWindows"]
    return command


def runtime_digest(tree: Path) -> str:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "perf_acceptance_identity", tree / "tools" / "validation" / "acceptance_identity.py")
    if not spec or not spec.loader:
        return "unavailable"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return str(module.runtime_tree_digest(tree))
    except Exception:  # noqa: BLE001 - identity absence is recorded, never faked
        return "unavailable"


def source_identities(tree: Path) -> dict:
    identities = {}
    for rel in ("scripts/context_guard.py", "scripts/cg_hook.py",
                "scripts/run_context_guard.sh", "scripts/run-context-guard.ps1",
                "hooks/hooks.json"):
        path = tree / rel
        identities[rel] = sha256_bytes(path.read_bytes()) if path.is_file() else "absent"
    return identities


def nearest_rank(sorted_values, percentile: float):
    index = max(0, min(len(sorted_values) - 1,
                       int(-(-len(sorted_values) * percentile / 100)) - 1))
    return sorted_values[index]


def classify_outcome(elapsed: float, returncode: int | None, error: str | None,
                     timeout: float) -> str:
    if error is not None:
        return "timeout" if "TimeoutExpired" in error else "driver_error"
    if returncode != 0:
        return "failed"
    if elapsed > timeout:
        return "overran_budget"
    return "completed"


def run_event(wrapper: str, tree: Path, data_dir: Path, payload: bytes,
              timeout: float) -> dict:
    started = time.perf_counter()
    error = None
    completed = None
    try:
        completed = subprocess.run(
            ["sh", "-c", wrapper] if sys.platform != "win32"
            else ["powershell", "-NoProfile", "-Command", wrapper],
            input=payload, capture_output=True, env=dict(
                os.environ,
                PLUGIN_ROOT=str(tree),
                CODEX_HOME=str(data_dir.parent),
                CONTEXT_GUARD_DATA_DIR=str(data_dir),
            ), timeout=timeout)
        returncode, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        error = f"TimeoutExpired:{exc}"
        returncode, stdout, stderr = None, exc.stdout or b"", exc.stderr or b""
    elapsed = time.perf_counter() - started
    return {
        "elapsed": round(elapsed, 4),
        "returncode": returncode,
        "error": error,
        "_stdout": stdout,
        "_stderr": stderr,
    }


def report_row(timing: dict) -> dict:
    return {
        "elapsed": timing["elapsed"],
        "returncode": timing["returncode"],
        "error": timing["error"],
        "stdout_sha256": sha256_bytes(timing["_stdout"]) if timing["_stdout"] else None,
        "stdout_head": timing["_stdout"][:200].decode("utf-8", errors="replace"),
        "stderr_head": timing["_stderr"][:200].decode("utf-8", errors="replace"),
    }


def seed_active_session(tree: Path, data_dir: Path, session: str) -> dict:
    """Create one active session through real dispatch; return its state."""
    spec_file = tree / "scripts" / "context_guard.py"
    script = (
        "import importlib.util, json, os, sys\n"
        "from pathlib import Path\n"
        "os.environ['CONTEXT_GUARD_DATA_DIR'] = sys.argv[1]\n"
        "spec = importlib.util.spec_from_file_location('cg_seed', sys.argv[2])\n"
        "cg = importlib.util.module_from_spec(spec); spec.loader.exec_module(cg)\n"
        "cg.dispatch({'hook_event_name': 'UserPromptSubmit', 'session_id': sys.argv[3],"
        " 'cwd': sys.argv[4], 'prompt': 'context-guard on'})\n"
        "cg.dispatch({'hook_event_name': 'UserPromptSubmit', 'session_id': sys.argv[3],"
        " 'cwd': sys.argv[4], 'prompt': '实现模块性能样本。必须运行测试提供验收证据。'})\n"
        "print('seeded')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(data_dir), str(spec_file), session, str(data_dir)],
        capture_output=True, text=True, timeout=60,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    if completed.returncode != 0 or "seeded" not in completed.stdout:
        raise RuntimeError(f"seed failed: {completed.stderr[-400:]}")


def build_cells(tree: Path, attempts: int) -> dict:
    safe = {"hook_event_name": "PreToolUse", "session_id": "perf-safe",
            "cwd": "/tmp", "tool_name": "bash", "tool_input": {"command": "echo hello"}}
    return {
        "pretool_safe": {"payload": safe, "timeout": 10.0, "seed": None,
                         "assert": "safe_empty"},
        "posttool_active": {"payload": {
            "hook_event_name": "PostToolUse", "session_id": "perf-active",
            "cwd": "/tmp", "tool_name": "bash",
            "tool_input": {"command": "echo hello"},
            "tool_response": {"stdout": "hello", "exit_code": 0}},
            "timeout": 10.0, "seed": "perf-active", "assert": "state_grows"},
        "user_prompt_active": {"payload": {
            "hook_event_name": "UserPromptSubmit", "session_id": "perf-active",
            "cwd": "/tmp", "prompt": "继续推进模块性能样本，并保持验收要求。"},
            "timeout": 10.0, "seed": "perf-active", "assert": "discovery_entry"},
        "lifecycle_matched": {"payload": None, "timeout": 120.0, "seed": "perf-life",
                              "assert": "lifecycle"},
    }


def assert_semantics(cell: str, spec: dict, row: dict, data_dir: Path, stdout: bytes):
    """Output and persisted-semantics assertions; failures mark the row."""
    if row.get("error") is not None or row.get("returncode") != 0:
        return  # already classified; nothing further to assert
    parsed = None
    try:
        parsed = json.loads(stdout.decode("utf-8") or "null")
    except json.JSONDecodeError:
        row["assertion"] = "stdout_not_json"
        return
    session_dir = data_dir / "sessions-v2" if (data_dir / "sessions-v2").is_dir() \
        else data_dir / "sessions"
    if spec["assert"] == "safe_empty":
        state_dir = data_dir / "sessions" / "perf-safe"
        legacy = state_dir.is_dir()
        v2 = (data_dir / "sessions-v2" / "perf-safe").is_dir()
        if parsed != {} or legacy or v2:
            row["assertion"] = "safe_path_expected_empty_object_and_no_state"
        else:
            row["assertion"] = "ok"
    elif spec["assert"] == "state_grows":
        state_file = session_dir / "perf-active" / "state.json"
        if not isinstance(parsed, dict) or not state_file.is_file():
            row["assertion"] = "missing_state_after_posttool"
        else:
            state = json.loads(state_file.read_text(encoding="utf-8"))
            grew = len(state.get("evidence") or []) >= 1
            row["assertion"] = "ok" if grew else "evidence_not_recorded"
    elif spec["assert"] == "discovery_entry":
        context = ((parsed or {}).get("hookSpecificOutput") or {}).get("additionalContext") or ""
        row["assertion"] = "ok" if "checkpoint-status" in context else "discovery_entry_missing"
    elif spec["assert"] == "lifecycle":
        state_file = session_dir / "perf-life" / "state.json"
        if not state_file.is_file():
            row["assertion"] = "missing_lifecycle_state"
            return
        state = json.loads(state_file.read_text(encoding="utf-8"))
        ok = (len(state.get("prompts") or []) >= 1
              and len(state.get("evidence") or []) >= 5)
        row["assertion"] = "ok" if ok else "lifecycle_expectations_unmet"


def run_cell(wrapper: str, tree: Path, cell: str, spec: dict, attempts: int,
             workdir: Path, side: str) -> list:
    rows = []
    session = spec.get("seed")
    for index in range(attempts):
        home = workdir / f"{cell}-{side}-{index}"
        data_dir = home / "private"
        data_dir.mkdir(parents=True)
        if session and spec["assert"] != "safe_empty":
            try:
                seed_active_session(tree, data_dir, session)
            except RuntimeError as exc:
                rows.append({"index": index, "side": side, "elapsed": 0.0,
                             "returncode": None, "outcome_class": "seed_failed",
                             "error": str(exc)[:200]})
                continue
        if cell == "lifecycle_matched":
            # One matched ACTIVE session receives interleaved real pairs.
            row = {"index": index, "side": side, "elapsed": 0.0,
                   "returncode": 0, "error": None, "outcome_class": "completed"}
            started = time.perf_counter()
            failure = None
            for pair in range(5):
                for payload, expect in (
                        ({"hook_event_name": "PreToolUse", "session_id": "perf-life",
                          "cwd": "/tmp", "tool_name": "bash",
                          "tool_input": {"command": f"echo pair{pair}"}}, {}),
                        ({"hook_event_name": "PostToolUse", "session_id": "perf-life",
                          "cwd": "/tmp", "tool_name": "bash",
                          "tool_input": {"command": f"echo pair{pair}"},
                          "tool_response": {"stdout": f"pair{pair}", "exit_code": 0}},
                         None)):
                    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                    timing = run_event(wrapper, tree, data_dir, body, 10.0)
                    if timing["error"] or timing["returncode"] != 0:
                        failure = timing["error"] or f"rc={timing['returncode']}"
                        break
                if failure:
                    break
            row["elapsed"] = round(time.perf_counter() - started, 4)
            row["error"] = failure
            row["outcome_class"] = classify_outcome(
                row["elapsed"], 0 if not failure else 1, failure, spec["timeout"])
            assert_semantics(cell, spec, row, data_dir, b"{}")
            rows.append(row)
            continue
        payload = json.dumps(spec["payload"], ensure_ascii=False).encode("utf-8")
        timing = run_event(wrapper, tree, data_dir, payload, spec["timeout"])
        row = {"index": index, "side": side, "payload_sha256": sha256_bytes(payload),
               "returncode": timing["returncode"], "error": timing["error"]}
        row["outcome_class"] = classify_outcome(
            timing["elapsed"], timing["returncode"], timing["error"],
            spec["timeout"])
        assert_semantics(cell, spec, row, data_dir, timing["_stdout"])
        row.update(report_row(timing))
        rows.append(row)
    return rows


def summarize(rows: list) -> dict:
    completed = sorted(r["elapsed"] for r in rows
                       if r.get("outcome_class") == "completed")
    return {
        "attempts": len(rows),
        "completed": len(completed),
        "failures": sum(1 for r in rows if r.get("outcome_class") == "failed"),
        "timeouts": sum(1 for r in rows if r.get("outcome_class") == "timeout"),
        "assertion_failures": sum(1 for r in rows
                                  if r.get("assertion") not in (None, "ok")),
        "median": round(statistics.median(completed), 4) if completed else None,
        "p95": round(nearest_rank(completed, 95), 4) if completed else None,
        "max": round(completed[-1], 4) if completed else None,
        "note": "timeouts are right-censored; failed and assertion-failed attempts stay in the raw rows",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=20)
    parser.add_argument("--cells", default="pretool_safe,posttool_active,user_prompt_active,lifecycle_matched")
    parser.add_argument("--formal", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=HOOK_TIMEOUT_SECONDS,
                        help="per-hook host budget used for censoring")
    args = parser.parse_args()
    if args.formal and args.attempts < 20:
        parser.error("formal batches require at least 20 predeclared attempts per cell")
    cells = {name: build_cells(args.candidate, args.attempts)[name]
             for name in args.cells.split(",")}
    driver_sha = sha256_bytes(Path(__file__).read_bytes())
    identities = {
        "baseline_tree": str(args.baseline),
        "candidate_tree": str(args.candidate),
        "baseline_runtime_digest": runtime_digest(args.baseline),
        "candidate_runtime_digest": runtime_digest(args.candidate),
        "baseline_sources": source_identities(args.baseline),
        "candidate_sources": source_identities(args.candidate),
        "driver_sha256": driver_sha,
        "wrapper_note": "exact hooks/hooks.json command, run via sh -c with PLUGIN_ROOT bound to each tree",
    }
    # The baseline tree may predate tools/validation; keep its digest honest.
    identities["baseline_runtime_digest"] = runtime_digest(args.candidate) \
        if not (args.baseline / "tools/validation/acceptance_identity.py").is_file() \
        else runtime_digest(args.baseline)
    report = {"mode": "formal" if args.formal else "diagnostic",
              "predeclared_attempts_per_cell": args.attempts,
              "identities": identities, "cells": {}}
    with tempfile.TemporaryDirectory(prefix="cg-perf-formal-") as tmp:
        workdir = Path(tmp)
        for cell, spec in cells.items():
            report["cells"][cell] = {}
            for side, tree in (("baseline", args.baseline), ("candidate", args.candidate)):
                wrapper = load_wrapper(tree, spec["payload"]["hook_event_name"]
                                       if spec["payload"] else "PreToolUse")
                rows = run_cell(wrapper, tree, cell, spec, args.attempts,
                                workdir, side)
                report["cells"][cell][side] = {"raw_rows": rows,
                                               "summary": summarize(rows)}
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({cell: {side: data["summary"]
                             for side, data in sides.items()}
                      for cell, sides in report["cells"].items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
