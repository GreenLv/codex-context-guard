#!/usr/bin/env python3
"""Formal interleaved A/B performance driver (baseline tree vs candidate tree).

Cell union (this driver + existing runners; one driver does NOT implement the
whole matrix): this driver owns the per-event production cells (pretool_safe,
posttool_active, user_prompt_active, precompact_active, session_start_resume,
subagent_events, session_end, lifecycle_matched 100-event matched cell,
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
                "hooks/hooks.json"):
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
            row["assertion"] = ("ok" if count == expected_count else
                                f"evidence_count_{count}_expected_{expected_count}")
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
    elif cell == "subagent_events":
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            row["assertion"] = "state_unreadable"
            return
        agents = state.get("agents") or []
        complete = any(a.get("status") == "stopped"
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
                          timeout: float) -> dict:
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
             {"session": "perf-life", "kind": "post", "evidence_after": pair + 1}),
        ):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            timing = run_event(wrapper, tree, data_dir, body, timeout)
            row = {"pair": pair, "kind": kind, "tool_command": command,
                   "wrapper_bound": wrapper[:40],
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
    """In-process tracemalloc peak of one S1 Stop dispatch (fixture from the
    measured tree itself)."""
    started = time.perf_counter()
    try:
        sys.path.insert(0, str(tree / "tools" / "validation"))
        sys.path.insert(0, str(tree / "scripts"))
        for stale in [m for m in list(sys.modules)
                      if m in ("stop_performance_fixture", "context_guard")]:
            del sys.modules[stale]
        import context_guard as cg  # noqa: E402
        import stop_performance_fixture as fx  # noqa: E402
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(data_dir)
        built = fx.build_session(fx.load_runtime(), str(data_dir), "S1")
        tracemalloc.start()
        decision = cg.dispatch(built["stop_event"])
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return {"elapsed": round(time.perf_counter() - started, 4),
                "peak_bytes": peak,
                "decision_type": type(decision).__name__,
                "outcome_class": "completed", "assertion": "ok", "error": None}
    except Exception as exc:  # noqa: BLE001 - recorded, batch continues
        return {"elapsed": round(time.perf_counter() - started, 4),
                "outcome_class": "failed", "assertion": "memory_cell_error",
                "error": f"{type(exc).__name__}: {exc}"[:200]}


def run_stop_cell(tree: Path, attempts: int, out_dir: Path) -> dict:
    """Delegate the Stop wall-clock cell to the tree's own benchmark runner
    (each runtime judged by its own oracle)."""
    runner = tree / "tools" / "validation" / "benchmark_stop.py"
    result_path = out_dir / f"stop-{hashlib.sha256(str(tree).encode()).hexdigest()[:10]}.json"
    if not runner.is_file():
        return {"delegated": False, "verdict": "runner_absent",
                "summary": {"attempts": 0, "failures": 1}}
    completed = subprocess.run(
        [sys.executable, str(runner), "--mode", "process", "--shape", "S1",
         "--samples", str(attempts), "--json", str(result_path)],
        capture_output=True, text=True, timeout=1800, cwd=str(tree))
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {"verdict": "report_missing", "stderr": completed.stderr[-400:]}
    s1 = payload.get("S1", payload)
    return {"delegated": True,
            "runner": "benchmark_stop.py --mode process --shape S1",
            "exit_code": completed.returncode, "samples": attempts,
            "verdict": s1.get("verdict"), "stats": s1.get("stats"),
            "result_ref": result_path.name}


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
                        "subagent_events,session_end,lifecycle_matched,memory_stop,"
                        "stop_s1")
    parser.add_argument("--formal", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=DEFAULT_EVENT_TIMEOUT,
                        help="per-event host budget used by every event call")
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

    report = {"mode": "formal" if args.formal else "diagnostic",
              "predeclared_attempts_per_cell": args.attempts,
              "identities": identities, "accepted": None, "cells": {}}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_report(args.out, report)

    def persist() -> None:
        write_report(args.out, report)

    failures = 0
    try:
        cells = {name: spec for name, spec in cell_specs().items()
                 if name in set(args.cells.split(","))}
        schedule = ["baseline", "candidate"] * args.attempts
        for cell, spec in cells.items():
            report["cells"][cell] = {
                "sides": {"baseline": {"raw_rows": []},
                          "candidate": {"raw_rows": []}},
                "interleaved_schedule": list(schedule),
            }
            sides = report["cells"][cell]["sides"]
            if cell == "stop_s1":
                for side, tree in (("baseline", args.baseline),
                                   ("candidate", args.candidate)):
                    sides[side] = run_stop_cell(tree, args.attempts, args.out.parent)
                    if sides[side].get("verdict") != "passed":
                        failures += 1
                    persist()
                continue
            side_index = {"baseline": 0, "candidate": 0}
            for side in schedule:
                tree = args.baseline if side == "baseline" else args.candidate
                wrapper = args.wrapper_override or load_wrapper(tree, spec["event"])
                home = Path(tempfile.mkdtemp(prefix=f"cg-perf-{cell}-{side}-"))
                data_dir = home / "private"
                data_dir.mkdir(parents=True)
                index = side_index[side]
                side_index[side] += 1
                try:
                    if spec.get("seed"):
                        try:
                            seed_active_session(tree, data_dir, spec["seed"])
                            for extra in spec.get("seed_events_extra", []) or []:
                                body = json.dumps(extra, ensure_ascii=False).encode("utf-8")
                                run_event(wrapper, tree, data_dir, body, args.timeout)
                            for pre in spec.get("seed_events", []) or []:
                                body = json.dumps(pre, ensure_ascii=False).encode("utf-8")
                                run_event(wrapper, tree, data_dir, body, args.timeout)
                        except RuntimeError as exc:
                            sides[side]["raw_rows"].append(
                                {"index": index, "side": side,
                                 "outcome_class": "seed_failed",
                                 "error": str(exc)[:200]})
                            failures += 1
                            persist()
                            continue
                    if cell == "lifecycle_matched":
                        row = run_lifecycle_attempt(wrapper, tree, data_dir,
                                                    args.timeout)
                        row.update({"index": index, "side": side})
                        if row["outcome_class"] != "completed" \
                                or row["assertion"] != "ok":
                            failures += 1
                        sides[side]["raw_rows"].append(row)
                    elif cell == "memory_stop":
                        row = run_memory_attempt(tree, data_dir)
                        row.update({"index": index, "side": side})
                        if row["outcome_class"] != "completed":
                            failures += 1
                        sides[side]["raw_rows"].append(row)
                    else:
                        row = run_standard_attempt(wrapper, tree, cell, spec,
                                                   data_dir, args.timeout)
                        row.update({"index": index, "side": side})
                        if row["outcome_class"] != "completed" \
                                or row.get("assertion") != "ok":
                            failures += 1
                        sides[side]["raw_rows"].append(row)
                except Exception as exc:  # noqa: BLE001 - record and continue
                    sides[side]["raw_rows"].append(
                        {"index": index, "side": side,
                         "outcome_class": "driver_error",
                         "error": f"{type(exc).__name__}: {exc}"[:200]})
                    failures += 1
                persist()
        for cell, celldata in report["cells"].items():
            for side, data in celldata["sides"].items():
                rows = data.get("raw_rows") or []
                if cell == "stop_s1":
                    data["summary"] = {"verdict": data.get("verdict"),
                                       "stats": data.get("stats")}
                    continue
                good = sorted(r["elapsed"] for r in rows
                              if r.get("outcome_class") == "completed"
                              and r.get("assertion") == "ok")
                data["summary"] = {
                    "attempts": len(rows),
                    "completed_and_asserted": len(good),
                    "failed": sum(1 for r in rows
                                  if r.get("outcome_class") == "failed"),
                    "timeouts": sum(1 for r in rows
                                    if r.get("outcome_class") == "timeout"),
                    "driver_errors": sum(1 for r in rows
                                         if r.get("outcome_class") == "driver_error"),
                    "seed_failures": sum(1 for r in rows
                                         if r.get("outcome_class") == "seed_failed"),
                    "assertion_failures": sum(1 for r in rows if r.get("assertion")
                                              not in (None, "ok")),
                    "success_median": round(statistics.median(good), 4) if good else None,
                    "success_p95": round(nearest_rank(good, 95), 4) if good else None,
                    "success_max": round(good[-1], 4) if good else None,
                    "note": "latency statistics condition on completed attempts with "
                            "passing semantics; failed/censored attempts stay in "
                            "raw_rows and block acceptance",
                }
        report["accepted"] = failures == 0
        report["blocking_failures"] = failures
        persist()
    except Exception as exc:  # noqa: BLE001 - persist partial then fail
        report["accepted"] = False
        report["blocking_failures"] = failures + 1
        report["driver_failure"] = f"{type(exc).__name__}: {exc}"[:400]
        persist()
        print(json.dumps({"accepted": False,
                          "driver_failure": report["driver_failure"]}))
        return 1
    print(json.dumps({"accepted": report["accepted"]}))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
