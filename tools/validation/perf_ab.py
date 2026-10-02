#!/usr/bin/env python3
"""Formal interleaved A/B performance driver (baseline tree vs candidate tree).

Cell union (this driver + existing runners; one driver does NOT implement the
whole matrix): this driver owns the per-event production cells (pretool_safe,
posttool_active, user_prompt_active, precompact_active, session_start_resume,
subagent_start, subagent_events, session_end, lifecycle_matched 100-event matched cell,
memory_stop) and delegates the Stop S1 wall-clock cell to each tree's own
tools/validation/benchmark_stop.py runner (each runtime is judged by its own
oracle). Memory uses an in-process tracemalloc cell.

Guarantees (R2): predeclared attempt counts with a recorded interleaved
order; raw per-attempt rows with input/driver/source/runtime identities;
timeouts, child failures and semantic assertion failures retained without
replacement and excluded from success-conditioned latency statistics; the
exact configured Hook wrapper from hooks/hooks.json (or an explicit override
for negative tests, which can never be formal); nearest-rank percentiles via
ceil(n*p/100)-1; incremental result persistence after every started attempt
with partial output preserved and existing results never overwritten; exit
status nonzero when any attempt fails, times out, or violates its semantic
oracle; baseline identity computed with the same versioned hasher, recorded
as unavailable otherwise (formal refuses unavailable identities).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_EVENT_TIMEOUT = 10.0
LIFECYCLE_PAIRS = 50  # planned 100-event matched cell


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_wrapper(tree: Path, event: str) -> str:
    hooks = json.loads((tree / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    entry = hooks["hooks"][event][0]["hooks"][0]
    return entry["commandWindows"] if sys.platform == "win32" else entry["command"]


def tree_digest(tree: Path, hasher_module) -> str:
    try:
        return str(hasher_module.runtime_tree_digest(tree))
    except Exception:  # noqa: BLE001 - recorded as unavailable, never substituted
        return "unavailable"


def load_hasher(tree: Path):
    """Load ONE explicitly versioned hasher (the candidate's) used for both
    trees, so baseline and candidate digests are comparable."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "perf_acceptance_identity",
        tree / "tools" / "validation" / "acceptance_identity.py")
    if not spec or not spec.loader:
        return None
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except (OSError, ImportError):
        return None
    return module


def source_identities(tree: Path) -> dict:
    identities = {}
    for rel in ("scripts/context_guard.py", "scripts/cg_hook.py",
                "scripts/run_context_guard.sh", "scripts/run-context-guard.ps1",
                "hooks/hooks.json", "tools/validation/stop_performance_fixture.py",
                "tools/validation/benchmark_stop.py",
                "tools/validation/acceptance_identity.py"):
        path = tree / rel
        identities[rel] = sha256_bytes(path.read_bytes()) if path.is_file() else "absent"
    return identities


def nearest_rank(values, percentile: float):
    """Nearest-rank percentile on a pre-sorted list: ceil(n*p/100)-1."""
    if not values:
        return None
    index = max(0, math.ceil(len(values) * percentile / 100) - 1)
    return values[min(index, len(values) - 1)]


def classify_outcome(elapsed: float, returncode: int | None, error: str | None,
                     timeout: float) -> str:
    del timeout  # censoring bound is applied by the caller's budget
    if error is not None:
        return "timeout" if error.startswith("TimeoutExpired") else "driver_error"
    if returncode != 0:
        return "failed"
    return "completed"


def run_event(wrapper: str, tree: Path, data_dir: Path, payload: bytes,
              timeout: float) -> dict:
    started = time.perf_counter()
    error = None
    returncode, stdout, stderr = None, b"", b""
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
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
    elapsed = time.perf_counter() - started
    return {"elapsed": round(elapsed, 4), "returncode": returncode,
            "error": error, "_stdout": stdout, "_stderr": stderr}


def report_row(timing: dict) -> dict:
    return {
        "elapsed": timing["elapsed"],
        "returncode": timing["returncode"],
        "error": timing["error"],
        "stdout_sha256": sha256_bytes(timing["_stdout"]) if timing["_stdout"] else None,
        "stdout_head": timing["_stdout"][:200].decode("utf-8", errors="replace"),
        "stderr_head": timing["_stderr"][:200].decode("utf-8", errors="replace"),
    }


def seed_active_session(tree: Path, data_dir: Path, session: str) -> None:
    spec_file = tree / "scripts" / "context_guard.py"
    script = (
        "import importlib.util, os, sys\n"
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
        [sys.executable, "-c", script, str(data_dir), str(spec_file), session,
         str(data_dir)],
        capture_output=True, text=True, timeout=60,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    if completed.returncode != 0 or "seeded" not in completed.stdout:
        raise RuntimeError(f"seed failed: {completed.stderr[-400:]}")


ACTIVE = "perf-active"


def payload_state_dir(data_dir: Path, session: str) -> Path:
    v2 = data_dir / "sessions-v2" / session
    return v2 if v2.is_dir() else data_dir / "sessions" / session


def check_semantics(cell: str, row: dict, data_dir: Path, stdout: bytes,
                    expect: dict | None = None) -> None:
    """Per-event output AND persisted-semantics oracle; sets row['assertion']."""
    if row.get("error") is not None or row.get("returncode") != 0:
        row["assertion"] = "skipped_event_failed"
        return
    try:
        parsed = json.loads(stdout.decode("utf-8") or "null")
    except json.JSONDecodeError:
        row["assertion"] = "stdout_not_json"
        return
    session = (expect or {}).get("session")
    state_file = payload_state_dir(data_dir, session) / "state.json" if session else None
    if cell == "pretool_safe":
        row["assertion"] = "ok" if parsed == {} else "expected_empty_object"
        return
    if cell == "lifecycle_matched":
        kind = (expect or {}).get("kind")
        if kind != "post":
            row["assertion"] = "ok" if parsed == {} else "pre_expected_empty"
        else:
            try:
                state = json.loads(state_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, TypeError):
                row["assertion"] = "lifecycle_state_missing"
                return
            expected_count = (expect or {}).get("evidence_after")
            count = len(state.get("evidence") or [])
            evidence = (state.get("evidence") or [{}])[-1]
            command = (expect or {}).get("command")
            pair = (expect or {}).get("pair")
            summary = evidence.get("summary", "")
            associated = (evidence.get("id") == f"E{pair + 1:04d}"
                          and evidence.get("outcome") == "success"
                          and evidence.get("tool") == "bash"
                          and f"input={json.dumps({'command': command}, sort_keys=True)};" in summary
                          and f'"stdout": {json.dumps(command)}' in summary
                          and evidence.get("core_result_seq", 0)
                          == evidence.get("core_call_seq", 0) + 1)
            row["assertion"] = ("ok" if count == expected_count and associated
                                else "lifecycle_evidence_association_failed")
        return
    if not isinstance(parsed, dict) or (state_file is not None and not state_file.is_file()):
        row["assertion"] = "missing_or_invalid_output_or_state"
        return
    if cell == "user_prompt_active":
        context = (parsed.get("hookSpecificOutput") or {}).get("additionalContext") or ""
        row["assertion"] = ("ok" if "checkpoint-status" in context
                            else "discovery_entry_missing")
    elif cell == "posttool_active":
        if state_file is None:
            row["assertion"] = "session_unspecified"
            return
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            row["assertion"] = "state_unreadable"
            return
        row["assertion"] = "ok" if state.get("evidence") else "evidence_not_recorded"
    elif cell == "precompact_active":
        if session is None:
            row["assertion"] = "session_unspecified"
            return
        row["assertion"] = ("ok" if parsed.get("continue") is True
                            and (payload_state_dir(data_dir, session)
                                 / "recovery.json").is_file()
                            else "precompact_expectations_unmet")
    elif cell == "session_start_resume":
        context = (parsed.get("hookSpecificOutput") or {}).get("additionalContext") or ""
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            row["assertion"] = "state_unreadable"
            return
        consumed = ((state.get("pending") or {}).get("recovery") or {}).get("state")
        row["assertion"] = ("ok" if "checkpoint-status" in context
                            and consumed == "consumed"
                            else "session_start_expectations_unmet")
    elif cell in {"subagent_start", "subagent_events"}:
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            row["assertion"] = "state_unreadable"
            return
        agents = state.get("agents") or []
        expected_status = "running" if cell == "subagent_start" else "stopped"
        complete = any(a.get("status") == expected_status
                       and a.get("agent_id") == "perf-agent"
                       for a in agents if isinstance(a, dict))
        row["assertion"] = "ok" if complete else "subagent_record_incomplete"
    elif cell == "session_end":
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            row["assertion"] = "state_unreadable"
            return
        row["assertion"] = ("ok" if state.get("session", {}).get("ended_at")
                            else "ended_at_missing")
    else:
        row["assertion"] = "ok"


def cell_specs() -> dict:
    post = {"hook_event_name": "PostToolUse", "session_id": ACTIVE, "cwd": "/tmp",
            "tool_name": "bash", "tool_input": {"command": "echo hello"},
            "tool_response": {"stdout": "hello", "exit_code": 0}}
    return {
        "pretool_safe": {
            "event": "PreToolUse", "seed": None, "timeout": DEFAULT_EVENT_TIMEOUT,
            "payload": {"hook_event_name": "PreToolUse", "session_id": "perf-safe",
                        "cwd": "/tmp", "tool_name": "bash",
                        "tool_input": {"command": "echo hello"}},
        },
        "posttool_active": {"event": "PostToolUse", "seed": ACTIVE,
                            "timeout": DEFAULT_EVENT_TIMEOUT, "payload": post,
                            "session": ACTIVE},
        "user_prompt_active": {"event": "UserPromptSubmit", "seed": ACTIVE,
                               "timeout": DEFAULT_EVENT_TIMEOUT,
                               "payload": {"hook_event_name": "UserPromptSubmit",
                                           "session_id": ACTIVE, "cwd": "/tmp",
                                           "prompt": "继续推进模块性能样本，并保持验收要求。"},
                               "session": ACTIVE},
        "precompact_active": {"event": "PreCompact", "seed": ACTIVE,
                              "timeout": 15.0,
                              "payload": {"hook_event_name": "PreCompact",
                                          "session_id": ACTIVE, "cwd": "/tmp",
                                          "trigger": "manual"},
                              "session": ACTIVE},
        "session_start_resume": {"event": "SessionStart", "seed": "precompact-seq",
                                 "timeout": DEFAULT_EVENT_TIMEOUT,
                                 "payload": {"hook_event_name": "SessionStart",
                                             "session_id": "precompact-seq",
                                             "cwd": "/tmp", "source": "compact"},
                                 "session": "precompact-seq",
                                 "seed_events": [
                                     {"hook_event_name": "UserPromptSubmit",
                                      "session_id": "precompact-seq", "cwd": "/tmp",
                                      "prompt": "context-guard on"},
                                     {"hook_event_name": "UserPromptSubmit",
                                      "session_id": "precompact-seq", "cwd": "/tmp",
                                      "prompt": "实现恢复样本。必须运行测试提供验收证据。"},
                                     {"hook_event_name": "PreCompact",
                                      "session_id": "precompact-seq", "cwd": "/tmp",
                                      "trigger": "manual"},
                                 ]},
        "subagent_start": {"event": "SubagentStart", "seed": ACTIVE,
                           "timeout": DEFAULT_EVENT_TIMEOUT,
                           "payload": {"hook_event_name": "SubagentStart",
                                       "session_id": ACTIVE, "cwd": "/tmp",
                                       "agent_id": "perf-agent", "agent_type": "worker"},
                           "session": ACTIVE},
        "subagent_events": {"event": "SubagentStop", "seed": ACTIVE,
                            "timeout": DEFAULT_EVENT_TIMEOUT,
                            "payload": {"hook_event_name": "SubagentStop",
                                        "session_id": ACTIVE, "cwd": "/tmp",
                                        "agent_id": "perf-agent",
                                        "agent_type": "worker",
                                        "last_assistant_message": "子任务完成样本。"},
                            "session": ACTIVE,
                            "seed_events_extra": [
                                {"hook_event_name": "SubagentStart",
                                 "session_id": ACTIVE, "cwd": "/tmp",
                                 "agent_id": "perf-agent", "agent_type": "worker"},
                            ]},
        "session_end": {"event": "SessionEnd", "seed": "perf-end",
                        "timeout": 3.0,
                        "payload": {"hook_event_name": "SessionEnd",
                                    "session_id": "perf-end", "cwd": "/tmp"},
                        "session": "perf-end"},
        "lifecycle_matched": {"event": "PreToolUse", "seed": "perf-life",
                              "timeout": 120.0, "payload": None,
                              "session": "perf-life"},
        "memory_stop": {"event": "Stop", "timeout": 10.0},
        "stop_s1": {"event": "Stop", "timeout": 120.0},
    }


def run_standard_attempt(wrapper: str, tree: Path, cell: str, spec: dict,
                         data_dir: Path, timeout: float) -> dict:
    payload = json.dumps(spec["payload"], ensure_ascii=False).encode("utf-8")
    timing = run_event(wrapper, tree, data_dir, payload, timeout)
    row = {"event": cell, "payload_sha256": sha256_bytes(payload),
           "returncode": timing["returncode"], "error": timing["error"],
           "outcome_class": classify_outcome(timing["elapsed"],
                                             timing["returncode"],
                                             timing["error"], timeout)}
    check_semantics(cell, row, data_dir, timing["_stdout"],
                    {"session": spec.get("session")})
    row.update(report_row(timing))
    return row


def run_lifecycle_attempt(wrapper: str, tree: Path, data_dir: Path,
                          timeout: float, *, wrapper_override: bool = False) -> dict:
    """One 100-event matched cell: ONE active session receives 50 matched
    Pre/Post pairs with the same tool identity per pair; every event's
    timing/output/expect is recorded and asserted."""
    events = []
    failure = None
    started = time.perf_counter()
    for pair in range(LIFECYCLE_PAIRS):
        command = f"echo pair-{pair}"
        for kind, payload, expect in (
            ("pre", {"hook_event_name": "PreToolUse", "session_id": "perf-life",
                     "cwd": "/tmp", "tool_name": "bash",
                     "tool_input": {"command": command}}, {}),
            ("post", {"hook_event_name": "PostToolUse", "session_id": "perf-life",
                      "cwd": "/tmp", "tool_name": "bash",
                      "tool_input": {"command": command},
                      "tool_response": {"stdout": command, "exit_code": 0}},
             {"session": "perf-life", "kind": "post", "evidence_after": pair + 1,
              "pair": pair, "command": command}),
        ):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            event_wrapper = wrapper if wrapper_override else load_wrapper(tree, payload["hook_event_name"])
            timing = run_event(event_wrapper, tree, data_dir, body, timeout)
            row = {"pair": pair, "kind": kind, "tool_command": command,
                   "wrapper_sha256": sha256_bytes(event_wrapper.encode()),
                   "payload_sha256": sha256_bytes(body),
                   "returncode": timing["returncode"], "error": timing["error"]}
            check_semantics("lifecycle_matched", row, data_dir,
                            timing["_stdout"], expect)
            row.update(report_row(timing))
            events.append(row)
            if row["error"] is not None or row["returncode"] != 0 \
                    or row.get("assertion") != "ok":
                failure = row.get("error") or row.get("assertion") \
                    or f"rc={row['returncode']}"
                break
        if failure:
            break
    elapsed = round(time.perf_counter() - started, 4)
    bad = [e for e in events if e.get("assertion") != "ok"]
    return {"elapsed": elapsed, "events": events,
            "pairs_completed": len(events) // 2,
            "outcome_class": "completed" if not failure else "failed",
            "error": failure,
            "assertion": "ok" if not bad else f"{len(bad)}_event_assertions_failed"}


def run_memory_attempt(tree: Path, data_dir: Path) -> dict:
    """Measure Stop allocation with an exact stdout/ledger/turn/integrity oracle."""
    import importlib.util

    started = time.perf_counter()
    old_path = list(sys.path)
    old_env = os.environ.get("CONTEXT_GUARD_DATA_DIR")
    names = ("stop_performance_fixture", "context_guard", "benchmark_stop")
    old_modules = {name: sys.modules.get(name) for name in names}
    try:
        sys.path[:0] = [str(tree / "tools" / "validation"), str(tree / "scripts")]
        for name in names:
            sys.modules.pop(name, None)
        spec = importlib.util.spec_from_file_location(
            "stop_performance_fixture", tree / "tools/validation/stop_performance_fixture.py")
        fx = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fx)
        cg = fx.load_runtime()
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(data_dir)
        built = fx.build_session(cg, str(data_dir), "S1")
        before = json.loads((built["session_dir"] / "state.json").read_text())
        tracemalloc.start()
        decision = cg.dispatch(built["stop_event"])
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        state = json.loads((built["session_dir"] / "state.json").read_text())
        final = (state.get("decision_log") or [{}])[-1]
        ok = (decision == {} and state.get("integrity", {}).get("status") == "ok"
              and len(state.get("decision_log") or []) > len(before.get("decision_log") or [])
              and final.get("turn_id") == built["stop_event"].get("turn_id")
              and final.get("outcome") == "silent_end_owner_ambiguous")
        return {"elapsed": round(time.perf_counter() - started, 4),
                "peak_bytes": peak, "fixture": built["counters"],
                "payload_sha256": sha256_bytes(json.dumps(built["stop_event"],
                                                       sort_keys=True).encode()),
                "outcome_class": "completed" if ok else "failed",
                "assertion": "ok" if ok else "memory_semantics_failed", "error": None}
    except Exception as exc:  # noqa: BLE001 - retain failed attempt
        return {"elapsed": round(time.perf_counter() - started, 4),
                "outcome_class": "failed", "assertion": "memory_cell_error",
                "error": f"{type(exc).__name__}: {exc}"[:200]}
    finally:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        sys.path[:] = old_path
        for name, value in old_modules.items():
            sys.modules.pop(name, None)
            if value is not None:
                sys.modules[name] = value
        if old_env is None:
            os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
        else:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = old_env


def run_stop_cell(tree: Path, attempts: int, out_dir: Path) -> dict:
    """Invoke the supported process/S1 runner and validate its terminal schema."""
    runner = tree / "tools/validation/benchmark_stop.py"
    result_path = out_dir / "stop-result.json"
    started = time.perf_counter()
    completed = subprocess.run(
        [sys.executable, str(runner), "--mode", "process", "--shape", "S1",
         "--samples", str(attempts), "--json", str(result_path)],
        capture_output=True, text=True, timeout=1800, cwd=str(tree))
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        s1 = payload["S1"]
        ok = (completed.returncode == 0 and s1["verdict"] == "passed"
              and s1["mode"] == "process" and s1["shape"] == "S1"
              and s1["samples"] == attempts and len(s1["times"]) == attempts
              and all(isinstance(x, (float, int)) and x >= 0 for x in s1["times"])
              and isinstance(s1["fixture"], dict) and isinstance(s1["stats"], dict))
    except (OSError, ValueError, KeyError, TypeError):
        s1, ok = {}, False
    return {"elapsed": round(time.perf_counter() - started, 4),
            "stop_wall": s1.get("times", [None])[0], "fixture": s1.get("fixture"),
            "runner": "benchmark_stop.py --mode process --shape S1",
            "returncode": completed.returncode,
            "outcome_class": "completed" if ok else "failed",
            "assertion": "ok" if ok else "stop_runner_schema_or_semantics_failed",
            "error": None if ok else completed.stderr[-400:],
            "runner_result": s1}


def write_report(path: Path, report: dict) -> None:
    tmp = path.with_name(path.name + ".partial")
    tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=20)
    parser.add_argument("--cells", default="pretool_safe,posttool_active,"
                        "user_prompt_active,precompact_active,session_start_resume,"
                        "subagent_start,subagent_events,session_end,lifecycle_matched,memory_stop,"
                        "stop_s1")
    parser.add_argument("--formal", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=None,
                        help="optional tighter timeout; declared event deadlines remain upper bounds")
    parser.add_argument("--wrapper-override", default=None,
                        help="negative-testing only: replace every cell's wrapper; "
                             "refused together with --formal")
    args = parser.parse_args()
    if args.formal and args.attempts < 20:
        parser.error("formal batches require at least 20 predeclared attempts per cell")
    if args.formal and args.wrapper_override:
        parser.error("wrapper overrides are negative-testing only and cannot be formal")
    if args.out.exists():
        parser.error(f"refusing to overwrite existing result {args.out}")

    hasher = load_hasher(args.candidate)
    baseline_digest = tree_digest(args.baseline, hasher) if hasher else "unavailable"
    candidate_digest = tree_digest(args.candidate, hasher) if hasher else "unavailable"
    identities = {
        "hasher": "candidate's tools/validation/acceptance_identity.py computes both trees",
        "baseline_tree": str(args.baseline),
        "candidate_tree": str(args.candidate),
        "baseline_runtime_digest": baseline_digest,
        "candidate_runtime_digest": candidate_digest,
        "baseline_sources": source_identities(args.baseline),
        "candidate_sources": source_identities(args.candidate),
        "driver_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "wrapper_note": "exact hooks/hooks.json command per event via sh -c, "
                        "PLUGIN_ROOT bound per tree",
        "cell_union": "perf_ab event/lifecycle/memory cells + benchmark_stop Stop cells",
    }
    if args.formal and "unavailable" in (baseline_digest, candidate_digest):
        parser.error("formal batches require computable runtime identities for both trees")

    selected = args.cells.split(",")
    if args.attempts <= 0 or (args.timeout is not None and
                              (args.timeout <= 0 or not math.isfinite(args.timeout))):
        parser.error("attempts and timeout must be positive and finite")
    if not all(selected) or len(set(selected)) != len(selected) or set(selected) - set(cell_specs()):
        parser.error("unknown, empty or duplicate cell selection")
    if args.formal and set(selected) != set(cell_specs()):
        parser.error("formal batches require the full registered cell profile")

    report = {"mode": "formal" if args.formal else "diagnostic",
              "predeclared_attempts_per_cell": args.attempts,
              "identities": identities, "accepted": None, "cells": {},
              "acceptance_scope": "cell execution and semantic oracles; comparison targets and host/model acceptance are separate"}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_report(args.out, report)

    def persist() -> None:
        write_report(args.out, report)

    failures = 0
    try:
        cells = {name: cell_specs()[name] for name in selected}
        schedule = ["baseline", "candidate"] * args.attempts
        report["planned_cells"] = list(cells)
        for cell, spec in cells.items():
            report["cells"][cell] = {
                "sides": {"baseline": {"raw_rows": []}, "candidate": {"raw_rows": []}},
                "interleaved_schedule": list(schedule),
            }
            sides = report["cells"][cell]["sides"]
            side_index = {"baseline": 0, "candidate": 0}
            for side in schedule:
                tree = args.baseline if side == "baseline" else args.candidate
                index = side_index[side]
                side_index[side] += 1
                row = {"index": index, "side": side, "outcome_class": "started",
                       "error": None, "assertion": None}
                sides[side]["raw_rows"].append(row)
                persist()  # before wrapper loading, directory creation, seeding or execution
                home = None
                try:
                    home = Path(tempfile.mkdtemp(prefix=f"cg-perf-{cell}-{side}-"))
                    data_dir = home / "private"
                    data_dir.mkdir()
                    budget = spec["timeout"] if args.timeout is None else min(args.timeout, spec["timeout"])
                    wrapper = args.wrapper_override or load_wrapper(tree, spec["event"])
                    if spec.get("seed"):
                        try:
                            seed_active_session(tree, data_dir, spec["seed"])
                            for pre in (spec.get("seed_events_extra", [])
                                        + spec.get("seed_events", [])):
                                seed_wrapper = args.wrapper_override or load_wrapper(tree, pre["hook_event_name"])
                                timing = run_event(seed_wrapper, tree, data_dir,
                                                   json.dumps(pre, ensure_ascii=False).encode(), budget)
                                if timing["error"] or timing["returncode"] != 0:
                                    raise RuntimeError("seed event failed")
                        except Exception as exc:  # noqa: BLE001 - retain seed failure
                            row.update(outcome_class="seed_failed", error=str(exc)[:200])
                            continue
                    if cell == "lifecycle_matched":
                        result = run_lifecycle_attempt(wrapper, tree, data_dir,
                                                       min(budget, 10.0),
                                                       wrapper_override=bool(args.wrapper_override))
                    elif cell == "memory_stop":
                        result = run_memory_attempt(tree, data_dir)
                    elif cell == "stop_s1":
                        result = run_stop_cell(tree, 1, home)
                    else:
                        result = run_standard_attempt(wrapper, tree, cell, spec, data_dir, budget)
                    row.update(result)
                    row["host_deadline"] = budget
                except Exception as exc:  # noqa: BLE001 - record, continue
                    row.update(outcome_class="driver_error", error=f"{type(exc).__name__}: {exc}"[:200])
                finally:
                    if home is not None:
                        shutil.rmtree(home)
                    if row.get("outcome_class") != "completed" or row.get("assertion") != "ok":
                        failures += 1
                    persist()
        coverage = set(report["cells"]) == set(selected)
        for cell, celldata in report["cells"].items():
            for side, data in celldata["sides"].items():
                rows = data["raw_rows"]
                exact = ([r["index"] for r in rows] == list(range(args.attempts))
                         and all(r["side"] == side and r["outcome_class"] != "started" for r in rows))
                coverage = coverage and exact
                good = sorted((r["stop_wall"] if cell == "stop_s1" else r["elapsed"])
                              for r in rows if r.get("outcome_class") == "completed"
                              and r.get("assertion") == "ok")
                data["summary"] = {
                    "attempts": len(rows), "completed_and_asserted": len(good),
                    "failed": sum(r.get("outcome_class") == "failed" for r in rows),
                    "timeouts": sum(r.get("outcome_class") == "timeout" for r in rows),
                    "driver_errors": sum(r.get("outcome_class") == "driver_error" for r in rows),
                    "seed_failures": sum(r.get("outcome_class") == "seed_failed" for r in rows),
                    "assertion_failures": sum(r.get("assertion") not in (None, "ok") for r in rows),
                    "success_median": round(statistics.median(good), 4) if good else None,
                    "success_p95": round(nearest_rank(good, 95), 4) if good else None,
                    "success_max": round(good[-1], 4) if good else None,
                    "peak_bytes": [r["peak_bytes"] for r in rows if "peak_bytes" in r],
                    "note": "success-conditioned latency; all failed/censored rows retained",
                }
        report["coverage_complete"] = coverage
        report["accepted"] = coverage and failures == 0
        report["full_profile"] = set(selected) == set(cell_specs())
        report["blocking_failures"] = failures + int(not coverage)
        persist()
    except BaseException as exc:  # preserve interrupted started rows
        report["accepted"] = False
        report["blocking_failures"] = failures + 1
        report["driver_failure"] = f"{type(exc).__name__}: {exc}"[:400]
        persist()
        return 1
    print(json.dumps({"accepted": report["accepted"]}))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
