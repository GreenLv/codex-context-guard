#!/usr/bin/env python3
"""Full-Stop benchmark: deterministic work counts and wall-clock samples.

Modes
-----
count    In-process dispatch over a freshly built fixture, capturing the
         event-scoped EvaluationContext counters. Verifies the deterministic
         work thresholds (scope constructions, prompt-record reads, fragment
         constructions, basis evaluations) that CI can assert without a
         wall-clock dependency.
process  Full hook subprocess timing: every sample starts a new Python
         process and replays the final Stop over a fresh fixture clone.
         Reports median/p95/max (nearest-rank) against the declared gates.

Exit codes: 0 passed, 1 failed, 3 environment_unavailable. A shape whose
fixture cannot be built or timed is environment_unavailable, never a pass.

Standard library only; no network, no model, no host trust.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools" / "validation"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import stop_performance_fixture as fixture  # noqa: E402

# Semantic oracle for every process/pretool shape: the exact hook stdout and
# the persisted final decision (outcome bound to the replayed turn) that a
# correct candidate must produce. Measured on the candidate and pinned; a
# blocked, fail-closed or empty-ledger run can never pass a timing gate.
DEFAULT_PROCESS_ORACLE = {"stdout": {},
                           "outcome": "silent_end_owner_ambiguous"}
PROCESS_ORACLE = {}  # all shapes share the measured neutral-reply oracle

# Count-mode gates assert these keys EXIST: a counter that never fired is a
# broken instrument, not a zero.
REQUIRED_COUNTER_KEYS = ("scope_computed", "prompt_record_read",
                          "fragments_computed", "basis_evaluated",
                          "consumption_recheck_read")


# Deterministic work-count gates for an ordinary state-semantic-modification
# free Stop (plan section 6.4). B is the number of stable phases actually
# opened by writes on the exercised path; P the distinct prompt records.
# fragments_computed counts DISTINCT source texts parsed (each exactly once);
# the bound scales with roots plus scoped items, never with I×C repetition.
COUNT_GATES: dict[str, dict[str, Any]] = {
    "S1": {
        "max_scope_computed": 4,
        "max_prompt_record_read": 60,
        "max_fragments_computed": 260,
        "max_basis_evaluated": 2600,
        "max_action_sources_computed": 200,
    },
    "S4": {
        "max_scope_computed": 4,
        "max_prompt_record_read": 60,
        "max_fragments_computed": 740,
        "max_basis_evaluated": 7400,
        "max_action_sources_computed": 200,
    },
}
WALL_GATES: dict[str, dict[str, float]] = {
    "S1": {"median": 2.0, "p95": 3.0, "max": 5.0},
    "S4": {"p95": 8.0, "max": 10.0},
    "S0": {"median_regression_max": None},
}


def _percentile_nearest(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(round(percentile / 100.0 * len(ordered)))))
    return ordered[rank - 1]


def run_count_mode(shape: str, workdir: Path) -> dict[str, Any]:
    import context_guard as cg

    captured: dict[str, int] = {}

    original_cls = cg.EvaluationContext

    class CountingContext(original_cls):  # type: ignore[misc, valid-type]
        def __init__(self, state, session_dir, **kwargs: Any) -> None:
            kwargs["counters"] = captured
            super().__init__(state, session_dir, **kwargs)

    cg.EvaluationContext = CountingContext
    try:
        root = str(workdir / f"count-{shape}")
        import os

        os.environ["CONTEXT_GUARD_DATA_DIR"] = root
        built = fixture.build_session(cg, root, shape)
        started = time.perf_counter()
        result = cg.dispatch(built["stop_event"])
        wall = time.perf_counter() - started
    finally:
        cg.EvaluationContext = original_cls
    gates = COUNT_GATES.get(shape)
    verdict = "passed"
    failures = []
    for key in REQUIRED_COUNTER_KEYS:
        if key not in captured:
            verdict = "failed"
            failures.append(f"missing counter {key}")
    if gates:
        for gate_name, bound in gates.items():
            observed = captured.get(gate_name.replace("max_", ""), 0)
            if observed > bound:
                verdict = "failed"
                failures.append(f"{gate_name}={observed}>{bound}")
    return {
        "mode": "count", "shape": shape, "verdict": verdict,
        "failures": failures, "wall_seconds": round(wall, 4),
        "result": result, "counters": dict(sorted(captured.items())),
        "fixture": built["counters"],
        "fixture_integrity": built["state_integrity"],
    }


# Full-process timing: each sample invokes the real hook CLI
# ``scripts/context_guard.py hook`` with the event on stdin. The parent
# measures the whole subprocess (interpreter start, runtime import, lock,
# dispatch, save); paths travel as argv, never inside code literals.


def _classify_subprocess_failure(stderr: str) -> str:
    # Only interpreter/environment facts are environment_unavailable; a
    # syntax error in the candidate tree is a candidate failure.
    environment_markers = ("ModuleNotFoundError", "ImportError",
                           "FileNotFoundError", "PermissionError",
                           "OSError")
    if any(marker in stderr for marker in environment_markers):
        return "environment_unavailable"
    return "failed"


def _run_hook_cli(data_dir: str, event: dict) -> dict:
    """One full hook process; returns timing and verification facts."""
    started = time.perf_counter()
    completed = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "context_guard.py"),
         "hook"],
        input=json.dumps(event), capture_output=True, text=True, timeout=120,
        env={**os.environ, "CONTEXT_GUARD_DATA_DIR": data_dir,
             "PYTHONDONTWRITEBYTECODE": "1"}, cwd=str(REPO_ROOT))
    wall = time.perf_counter() - started
    record = {"wall": wall, "returncode": completed.returncode,
              "stderr": completed.stderr[-2000:]}
    if completed.returncode != 0:
        record["classification"] = _classify_subprocess_failure(
            completed.stderr)
        return record
    try:
        record["stdout_json"] = json.loads(completed.stdout or "null")
    except json.JSONDecodeError:
        record["classification"] = "failed"
        record["stderr"] = "hook stdout is not valid JSON: " + completed.stdout[:500]
        return record
    # Persisted-fact verification against THIS clone's data dir (the parent
    # process env points elsewhere): state intact, no residual lock, the
    # decision ledger grew, and the final decision binds this event's turn
    # with the expected outcome.
    session_dir = (Path(data_dir) / "sessions-v2" / str(event.get("session_id")))
    if not session_dir.is_dir():
        session_dir = Path(data_dir) / "sessions" / str(event.get("session_id"))
    state_path = session_dir / "state.json"
    if not state_path.is_file():
        record["classification"] = "failed"
        record["stderr"] = "no persisted state after hook"
        return record
    state = json.loads(state_path.read_text(encoding="utf-8"))
    record["decision_log_len"] = len(state.get("decision_log") or [])
    record["integrity"] = state.get("integrity", {}).get("status")
    # Lock-release oracle: protocol 2 keeps a stable lock FILE, so the check
    # is functional — a second process must be able to acquire the kernel
    # lock immediately. A held lock means the hook leaked ownership.
    import importlib.util as _ilu

    _spec = _ilu.spec_from_file_location(
        "benchmark_context_guard",
        REPO_ROOT / "scripts" / "context_guard.py")
    _cg = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_cg)
    try:
        with _cg.session_lock(session_dir, timeout=2.0):
            record["lock_released"] = True
    except TimeoutError:
        record["lock_released"] = False
    if record["integrity"] != "ok" or not record["lock_released"]:
        record["classification"] = "failed"
        return record
    final_decision = (state.get("decision_log") or [{}])[-1]
    record["final_outcome"] = final_decision.get("outcome")
    record["final_turn"] = final_decision.get("turn_id")
    record["classification"] = "completed"
    return record


def run_process_mode(shape: str, samples: int, workdir: Path) -> dict[str, Any]:
    import os

    import context_guard as cg  # noqa: F401 - runtime presence check

    base = workdir / f"process-{shape}-gold"
    gold_root = str(base)
    os.environ["CONTEXT_GUARD_DATA_DIR"] = gold_root
    built = fixture.build_session(fixture.load_runtime(), gold_root, shape)
    fixture_info = built["counters"]
    session_dir = built["session_dir"]
    baseline_decisions = len(
        (json.loads((session_dir / "state.json").read_text(encoding="utf-8"))
         ).get("decision_log") or [])
    times: list[float] = []
    outputs = []
    problems = []
    for index in range(samples):
        clone_root = str(workdir / f"process-{shape}-run{index}")
        shutil.copytree(gold_root, clone_root)
        record = _run_hook_cli(clone_root, built["stop_event"])
        shutil.rmtree(clone_root, ignore_errors=True)
        if record["classification"] != "completed":
            return {
                "mode": "process", "shape": shape,
                "verdict": record["classification"],
                "error": record.get("stderr"), "fixture": fixture_info,
            }
        if record["decision_log_len"] <= baseline_decisions:
            problems.append(f"sample {index}: decision log did not grow")
        # Semantic oracle, asserted HERE at the runner level: even a
        # perfectly fast sample fails if its business result is wrong.
        oracle = PROCESS_ORACLE.get(shape, DEFAULT_PROCESS_ORACLE)
        if record.get("stdout_json") != oracle["stdout"]:
            problems.append(
                f"sample {index}: stdout {record.get('stdout_json')!r} "
                f"differs from oracle {oracle['stdout']!r}")
        if (record.get("final_outcome") != oracle["outcome"]
                or record.get("final_turn") != built["stop_event"].get("turn_id")):
            problems.append(
                f"sample {index}: decision outcome/turn "
                f"({record.get('final_outcome')!r}/"
                f"{record.get('final_turn')!r}) differs from oracle "
                f"{oracle['outcome']!r}/{built['stop_event'].get('turn_id')!r}")
        times.append(record["wall"])
        outputs.append(json.dumps(record.get("stdout_json"), sort_keys=True))
    if problems:
        return {"mode": "process", "shape": shape, "verdict": "failed",
                "problems": problems, "fixture": fixture_info}
    stats = {
        "median": round(statistics.median(times), 4),
        "p95": round(_percentile_nearest(times, 95), 4),
        "max": round(max(times), 4),
        "min": round(min(times), 4),
    }
    gates = WALL_GATES.get(shape, {})
    verdict = "passed"
    failures = []
    for name, bound in gates.items():
        if bound is None or name not in stats:
            continue
        if stats[name] > bound:
            verdict = "failed"
            failures.append(f"{name}={stats[name]}>{bound}")
    if len(set(outputs)) != 1:
        verdict = "failed"
        failures.append("hook outputs differ across samples")
    return {
        "mode": "process", "shape": shape, "verdict": verdict,
        "failures": failures, "samples": samples,
        "times": [round(value, 4) for value in times], "stats": stats,
        "fixture": fixture_info,
        "decisions_before": baseline_decisions,
        "machine": {
            "system": platform.system(), "release": platform.release(),
            "python": sys.version.split()[0], "machine": platform.machine(),
        },
    }


def run_pretool_mode(samples: int, workdir: Path) -> dict[str, Any]:
    """Cold-start samples of one ordinary PreToolUse over a built session.

    The historical 50 ms Phase-2 threshold is a retired contract; this mode
    records the current whole-process distribution (interpreter, import,
    dispatch) through the real hook CLI and asserts only the active
    hook-timeout margin (10 s), never the old number.
    """
    import os

    import context_guard as cg  # noqa: F401

    base = workdir / "pretool-gold"
    gold_root = str(base)
    os.environ["CONTEXT_GUARD_DATA_DIR"] = gold_root
    built = fixture.build_session(fixture.load_runtime(), gold_root, "S0")
    event = dict(hook_event_name="PreToolUse", tool_name="shell",
                 tool_input={"command": "echo cold-start"},
                 session_id=built["session_id"], cwd=gold_root,
                 turn_id="t-cold")
    times: list[float] = []
    outputs = []
    for index in range(samples):
        clone = str(workdir / f"pretool-run{index}")
        shutil.copytree(gold_root, clone)
        record = _run_hook_cli(clone, event)
        shutil.rmtree(clone, ignore_errors=True)
        if record["classification"] != "completed":
            return {"mode": "pretool", "verdict": record["classification"],
                    "error": record.get("stderr")}
        times.append(record["wall"])
        outputs.append(record.get("stdout_json"))
        if record.get("stdout_json") != {}:
            return {"mode": "pretool", "verdict": "failed",
                    "error": "ordinary PreToolUse must stay silently "
                             f"allowed (empty JSON), got {record.get('stdout_json')!r}"}
    if any(value != {} for value in outputs):
        return {"mode": "pretool", "verdict": "failed",
                "error": "ordinary PreToolUse must stay silently allowed "
                         "(empty JSON), got a decision instead"}
    stats = {"median": round(statistics.median(times), 4),
             "p95": round(_percentile_nearest(times, 95), 4),
             "max": round(max(times), 4)}
    verdict = "passed" if stats["max"] < 10.0 else "failed"
    return {"mode": "pretool", "verdict": verdict, "samples": samples,
            "stats": stats, "times": [round(v, 4) for v in times],
            "note": ("ordinary PreToolUse cold start via the real hook CLI; "
                      "the historical 50 ms Phase-2 threshold is a retired "
                      "contract and is not a gate here")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("count", "process", "pretool"), required=True)
    parser.add_argument("--shape", default="S1")
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--json", dest="json_out", help="write the result JSON here")
    parser.add_argument("--list-gates", action="store_true")
    args = parser.parse_args()
    if args.list_gates:
        print(json.dumps({"count": COUNT_GATES, "wall": WALL_GATES}, indent=2))
        return 0
    workdir = Path(tempfile.mkdtemp(prefix="cg-benchmark-"))
    try:
        if args.mode == "count":
            report = run_count_mode(args.shape, workdir)
        elif args.mode == "pretool":
            report = run_pretool_mode(args.samples, workdir)
        else:
            shapes = [item.strip() for item in args.shape.split(",") if item.strip()]
            report = {shape: run_process_mode(shape, args.samples, workdir)
                      for shape in shapes}
            medians = {shape: value.get("stats", {}).get("median")
                       for shape, value in report.items()}
            if "S2" in medians and "S4" in medians and all(medians.values()):
                ratio = medians["S4"] / medians["S2"]
                report["s2_to_s4_median_ratio"] = round(ratio, 4)
                report["ratio_gate"] = ("passed" if ratio <= 2.8 else "failed")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    text = json.dumps(report, ensure_ascii=False, indent=2, default=str)
    print(text)
    if args.json_out:
        target = Path(args.json_out)
        if target.exists():
            print(f"refusing to overwrite existing result file {target}; "
                  "pass a new timestamped path", file=sys.stderr)
            return 3
        target.write_text(text, encoding="utf-8")
    verdicts = ([value["verdict"] for value in report.values()
                 if isinstance(value, dict) and "verdict" in value]
                if args.mode == "process" and not isinstance(
                    report.get("verdict"), str) else [report["verdict"]])
    if args.mode == "process" and report.get("ratio_gate") == "failed":
        return 1
    if any(value == "failed" for value in verdicts):
        return 1
    if any(value == "environment_unavailable" for value in verdicts):
        return 3
    return 0 if all(value == "passed" for value in verdicts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
