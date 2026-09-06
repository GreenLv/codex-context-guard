#!/usr/bin/env python3
"""Layered 0.11.x baseline benchmark for the Context Guard 0.12 evolution plan.

Phase 0 exit gate: at least 300 classification calls across 10 task
categories, a safe/mutation confusion matrix, visible-prompt counts, extra
control-command counts, false allow/deny/continuation/duplicate-interruption
metrics, message-length distributions, and layered latency (interpreter
startup, module import, classification, state read, full hook path) with
p50/p95. This harness only measures; it never changes product behavior and
it does not treat its own output as a p95 acceptance result.

Usage:
    python3 tests/benchmark_context_guard_012.py --output REPORT.json

The report path is caller-provided so no machine-specific path is embedded
here. Synthetic fixtures only; no network, no private data. Expected 0.11.x
defects are reported as metrics, not harness failures; only infrastructure
errors (crashes, unreadable state) fail the run.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "context_guard.py"

SYNTHETIC_THREAD_ID = "aa11bb33-c0de-4d5e-8f90-1234567890ab"

# (category, expected_outcome, command) — expected_outcome is the plan's
# ground truth: "allow" for read-only/text/simulation commands, "deny" for
# real unauthorized release/remote mutations.
CLASSIFICATION_TABLE: list[tuple[str, str, str]] = [
    ("text_echo", "allow", "echo git tag v1.2.3"),
    ("text_echo", "allow", 'printf "%s\\n" "git push origin main"'),
    ("text_echo", "allow", "echo npm publish --dry-run"),
    ("text_echo", "allow", "echo 'gh release create v1.2.3 --notes x'"),
    ("search_read", "allow", "rg -n npm publish README.md"),
    ("search_read", "allow", 'rg -n "npm publish" README.md'),
    ("search_read", "allow", "grep -rn git tag docs/"),
    ("search_read", "allow", "rg -n 'gh release create' CHANGELOG.md"),
    ("dry_run_simulation", "allow", "npm publish --dry-run"),
    ("dry_run_simulation", "allow", "git push --dry-run origin main"),
    ("dry_run_simulation", "allow", "gh release create v1.2.3 --dry-run"),
    ("dry_run_simulation", "allow", "cargo publish --dry-run"),
    ("read_only_git", "allow", "git status --porcelain"),
    ("read_only_git", "allow", "git log --oneline -5"),
    ("read_only_git", "allow", "git tag -l"),
    ("read_only_git", "allow", "git diff --check"),
    ("local_file_tools", "allow", "python3 -m compileall -q scripts"),
    ("local_file_tools", "allow", "ls -la scripts"),
    ("local_file_tools", "allow", "cat README.md"),
    ("local_file_tools", "allow", "wc -l scripts/context_guard.py"),
    ("test_build_local", "allow", "python3 -m unittest discover -s tests -p 'test_*.py'"),
    ("test_build_local", "allow", "ruff check ."),
    ("test_build_local", "allow", "python3 scripts/context_guard.py self-test"),
    ("test_build_local", "allow", "cargo build --offline"),
    ("quoted_split_negative", "allow", 'rg -n "npm" publish README.md'),
    ("quoted_split_negative", "allow", "echo \"npm\" publish"),
    ("quoted_split_negative", "allow", 'grep "git" tag docs/x.md'),
    ("quoted_split_negative", "allow", "echo git 'tag' v1.2.3"),
    ("release_tag_real", "deny", "git tag v1.2.3"),
    ("release_tag_real", "deny", "git tag v0.11.1"),
    ("release_push_real", "deny", "git push origin main"),
    ("release_push_real", "deny", "git push origin v1.2.3"),
    ("release_push_real", "deny", "git push --tags"),
    ("release_gh_release", "deny", "gh release create v1.2.3 --notes x"),
    ("release_gh_release", "deny", "gh release edit v1.2.3 --notes y"),
    ("registry_publish_real", "deny", "npm publish"),
    ("registry_publish_real", "deny", "cargo publish"),
    ("registry_publish_real", "deny", "twine upload dist/*"),
    ("wrapper_execution", "deny", "bash -c 'git tag v1.2.3'"),
    ("wrapper_execution", "deny", "sh -c 'npm publish'"),
    ("wrapper_execution", "deny", 'pwsh -Command "git tag v1.2.3"'),
    ("wrapper_execution", "deny", 'powershell -Command "npm publish"'),
    ("compound_mutation", "deny", "git tag v1.2.3 && git push origin v1.2.3"),
    ("compound_mutation", "deny", "npm publish && git push origin main"),
    ("compound_mutation", "deny", "bash -c 'git push origin main' ; npm publish"),
    ("compound_mutation", "deny", "git tag v1.2.3 || echo retry-needed"),
]

# Wrapper/compound probes exercise the deny side; they are reported
# separately from the core allow/deny categories.
WRAPPER_COMPOUND_CATEGORIES = {"wrapper_execution", "compound_mutation"}


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1)))
    return ordered[index]


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "p50_ms": round(percentile(values, 50), 3),
        "p95_ms": round(percentile(values, 95), 3),
        "mean_ms": round(statistics.fmean(values), 3),
        "min_ms": round(min(values), 3),
        "max_ms": round(max(values), 3),
    }


def load_runtime() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location("context_guard_benchmark", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load runtime: {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_subprocess_ms(args: list[str], *, env: dict[str, str], stdin_text: str | None = None) -> tuple[float, subprocess.CompletedProcess[str]]:
    start = time.perf_counter()
    completed = subprocess.run(
        args,
        input=stdin_text,
        text=True,
        capture_output=True,
        env=env,
        timeout=60,
        check=False,
    )
    return (time.perf_counter() - start) * 1000, completed


def measure_process_startup(env: dict[str, str], rounds: int) -> list[float]:
    samples = []
    for _ in range(rounds):
        milliseconds, completed = run_subprocess_ms(
            [sys.executable, "-c", "pass"], env=env
        )
        if completed.returncode != 0:
            raise RuntimeError("bare interpreter startup failed")
        samples.append(milliseconds)
    return samples


def measure_module_import(env: dict[str, str], rounds: int) -> list[float]:
    samples = []
    for _ in range(rounds):
        milliseconds, completed = run_subprocess_ms(
            [
                sys.executable,
                "-c",
                "import importlib.util,sys;spec=importlib.util.spec_from_file_location('cg',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)",
                str(MODULE_PATH),
            ],
            env=env,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"module import failed: {completed.stderr[:200]}")
        samples.append(milliseconds)
    return samples


def measure_full_hook_path(
    env: dict[str, str], data_dir: Path, rounds_per_event: int
) -> tuple[dict[str, list[float]], dict[str, int]]:
    events = [
        (
            "UserPromptSubmit",
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "bench-session",
                "cwd": str(data_dir / "project"),
                "turn_id": "turn-bench-1",
                "prompt": "请修复 scripts/example.py 中的问题并运行测试",
            },
        ),
        (
            "PreToolUse",
            {
                "hook_event_name": "PreToolUse",
                "session_id": "bench-session",
                "cwd": str(data_dir / "project"),
                "turn_id": "turn-bench-1",
                "tool_name": "shell",
                "tool_input": {"command": "python3 -m unittest discover -s tests"},
            },
        ),
        (
            "PostToolUse",
            {
                "hook_event_name": "PostToolUse",
                "session_id": "bench-session",
                "cwd": str(data_dir / "project"),
                "turn_id": "turn-bench-1",
                "tool_name": "shell",
                "tool_input": {"command": "python3 -m unittest discover -s tests"},
                "tool_response": {"exit_code": 0, "output": "OK"},
            },
        ),
        (
            "Stop",
            {
                "hook_event_name": "Stop",
                "session_id": "bench-session",
                "cwd": str(data_dir / "project"),
                "turn_id": "turn-bench-1",
                "last_assistant_message": "任务已完成,全部检查通过。",
            },
        ),
    ]
    timings: dict[str, list[float]] = {}
    visible: dict[str, int] = {}
    for event, payload in events:
        samples = []
        count_visible = 0
        for _ in range(rounds_per_event):
            milliseconds, completed = run_subprocess_ms(
                [sys.executable, str(MODULE_PATH), "hook"],
                env=env,
                stdin_text=json.dumps(payload),
            )
            if completed.returncode != 0:
                raise RuntimeError(f"hook path failed for {event}: {completed.stderr[:200]}")
            if completed.stdout.strip() and completed.stdout.strip() != "{}":
                count_visible += 1
            samples.append(milliseconds)
        timings[event] = samples
        visible[event] = count_visible
    return timings, visible


def count_visible_output(result: dict[str, Any]) -> bool:
    if not isinstance(result, dict) or not result:
        return False
    if result.get("decision") == "block":
        return True
    specific = result.get("hookSpecificOutput")
    if isinstance(specific, dict):
        if specific.get("additionalContext"):
            return True
        if specific.get("permissionDecisionReason"):
            return True
    if result.get("stopReason") or result.get("systemMessage"):
        return True
    return False


def classify_table(cg: Any, rounds: int) -> dict[str, Any]:
    per_call: dict[str, list[float]] = {}
    rows = []
    for category, expected, command in CLASSIFICATION_TABLE:
        payload = {
            "tool_name": "shell",
            "tool_input": {"command": command},
            "cwd": os.getcwd(),
        }
        action = None
        for _ in range(rounds):
            start = time.perf_counter()
            try:
                action = cg.classify_pre_tool_action(payload)
            except Exception as exc:  # noqa: BLE001 - benchmark reports, not hides
                raise RuntimeError(f"classifier raised on {command!r}: {exc}") from exc
            per_call.setdefault(category, []).append((time.perf_counter() - start) * 1000)
        rows.append(
            {
                "category": category,
                "command": command,
                "expected": expected,
                "flagged": action is not None,
                "tier": action.get("tier") if action else None,
                "semantic_action_id": action.get("semantic_action_id") if action else None,
            }
        )
    # Wrapper/compound categories exercise the deny side too; they are
    # positive-control probes and are reported separately from the core
    # allow/deny category matrix. Every cell below partitions core rows only,
    # so the cells always sum to the row/call totals; the harness fails
    # closed on any partition mismatch instead of reporting inconsistent
    # matrices.
    wrapper_rows = [row for row in rows if row["category"] in WRAPPER_COMPOUND_CATEGORIES]
    core_rows = [row for row in rows if row["category"] not in WRAPPER_COMPOUND_CATEGORIES]
    core_calls = len(core_rows) * rounds
    case_totals = {
        "cases": len(core_rows),
        "true_allow": sum(
            1 for row in core_rows if row["expected"] == "allow" and not row["flagged"]
        ),
        "false_allow": sum(
            1 for row in core_rows if row["expected"] == "deny" and not row["flagged"]
        ),
        "true_deny": sum(
            1 for row in core_rows if row["expected"] == "deny" and row["flagged"]
        ),
        "false_deny": sum(
            1 for row in core_rows if row["expected"] == "allow" and row["flagged"]
        ),
    }
    if (
        sum(value for key, value in case_totals.items() if key != "cases")
        != case_totals["cases"]
    ):
        raise RuntimeError("case_matrix cells do not partition the core cases")
    call_matrix = {
        "calls": core_calls,
        "expected_allow_flagged": rounds
        * sum(1 for row in core_rows if row["expected"] == "allow" and row["flagged"]),
        "expected_allow_clear": rounds
        * sum(1 for row in core_rows if row["expected"] == "allow" and not row["flagged"]),
        "expected_deny_flagged": rounds
        * sum(1 for row in core_rows if row["expected"] == "deny" and row["flagged"]),
        "expected_deny_clear": rounds
        * sum(1 for row in core_rows if row["expected"] == "deny" and not row["flagged"]),
    }
    if (
        sum(value for key, value in call_matrix.items() if key != "calls")
        != call_matrix["calls"]
    ):
        raise RuntimeError("call_matrix cells do not partition the classification calls")
    return {
        "classification_calls": core_calls,
        "categories": len({row["category"] for row in core_rows}),
        "case_matrix_core_categories": case_totals,
        "call_matrix_core_categories": call_matrix,
        "wrapper_compound_probes": {
            "cases": len(wrapper_rows),
            "calls": len(wrapper_rows) * rounds,
            "flagged_cases": sum(1 for row in wrapper_rows if row["flagged"]),
        },
        "per_category_false_deny": {
            category: sum(
                1
                for row in core_rows
                if row["category"] == category and row["expected"] == "allow" and row["flagged"]
            )
            for category in sorted({row["category"] for row in core_rows})
        },
        "classification_ms_by_category": {
            category: summarize(values) for category, values in per_call.items()
        },
        "rows": rows,
    }


def measure_state_read_ms(cg: Any, data_dir: Path, rounds: int) -> list[float]:
    session_dir = data_dir / "sessions" / "bench-session"
    samples = []
    for _ in range(rounds):
        start = time.perf_counter()
        try:
            cg.load_state(session_dir, {"session_id": "bench-session"})
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"state read failed: {exc}") from exc
        samples.append((time.perf_counter() - start) * 1000)
    return samples


def synthetic_turn_protocol(
    cg: Any, data_dir: Path
) -> dict[str, Any]:
    """Drive one synthetic terminal turn the way the observed sessions did.

    A plain completion claim is not gated by 0.11.x; the visible-continuation
    cascade enters through staged checkpoint/disposition controls. This
    reproduces the documented T3 chain: deferred, then user_wait, then
    external_wait, against a reply the lexical observer reads as an external
    wait. Counts visible blocks, duplicate interruptions, and the extra
    private control commands the injected continuations demand.
    """
    from unittest import mock

    # Isolated session: the long hook-path loop above accumulates 100+ turns
    # on its own session and may trigger a prompt-ledger rebuild that drops
    # the private completion attempt. The terminal-chain replay must depend
    # only on its own dispatches, never on that cross-layer state.
    session = "bench-turn"
    project = data_dir / "project"
    project.mkdir(parents=True, exist_ok=True)
    activating_prompt = (
        "请修复 scripts/example.py:必须修复函数崩溃、必须更新 README、"
        "必须补充回归测试,并运行完整测试套件验证后汇报。"
    )
    external_wait_reply = "修改已交付上游流水线,当前等待外部 CI 结果,暂无法继续。"
    visible_prompts = 0
    hook_enters = 0
    extra_control_commands = 0

    def dispatch(event: str, **extra: Any) -> dict[str, Any]:
        nonlocal hook_enters
        hook_enters += 1
        payload = {
            "hook_event_name": event,
            "session_id": session,
            "cwd": str(project),
            "turn_id": "turn-1",
        }
        payload.update(extra)
        return cg.dispatch(payload)

    def observe(result: dict[str, Any]) -> None:
        nonlocal visible_prompts
        if count_visible_output(result):
            visible_prompts += 1

    def stage(disposition: str) -> None:
        nonlocal extra_control_commands
        extra_control_commands += 1
        cg.stage_private_disposition(
            data_dir, session, "turn-1", "bench-token", disposition, replace=True
        )

    with mock.patch.object(cg.secrets, "token_urlsafe", return_value="bench-token"):
        observe(dispatch("UserPromptSubmit", prompt=activating_prompt))
        observe(
            dispatch(
                "PostToolUse",
                tool_name="shell",
                tool_input={"command": "python3 -m unittest discover -s tests"},
                tool_response={"exit_code": 0, "output": "OK"},
            )
        )
        attempts = []
        for disposition in ("deferred", "user_wait", "external_wait"):
            stage(disposition)
            result = dispatch("Stop", last_assistant_message=external_wait_reply)
            observe(result)
            attempts.append(result)
    blocks = [item for item in attempts if item.get("decision") == "block"]
    lengths = [len(item["reason"]) for item in blocks if isinstance(item.get("reason"), str)]
    additional = [
        len(item["hookSpecificOutput"]["additionalContext"])
        for item in attempts
        if isinstance(item.get("hookSpecificOutput"), dict)
        and isinstance(item["hookSpecificOutput"].get("additionalContext"), str)
    ]
    return {
        "stop_calls": len(attempts),
        "visible_blocks": len(blocks),
        "duplicate_interruptions": max(0, len(blocks) - 1),
        "extra_control_commands": extra_control_commands,
        "hook_enters_for_turn": hook_enters,
        "visible_prompts_total": visible_prompts,
        "block_reason_lengths": lengths,
        "additional_context_lengths": additional,
        "chain": ["deferred", "user_wait", "external_wait"],
    }


def status_message_events() -> dict[str, list[str]]:
    """Parse the persisted Hook configuration for visibility facts.

    The event set carrying a persistent ``statusMessage`` is read from
    ``hooks/hooks.json`` instead of being assumed, so the report reflects
    the actual configuration bytes.
    """
    config = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    events: dict[str, list[str]] = {}
    for event, matchers in config.get("hooks", {}).items():
        messages = [
            str(hook["statusMessage"])
            for matcher in matchers
            for hook in matcher.get("hooks", [])
            if isinstance(hook, dict) and hook.get("statusMessage")
        ]
        if messages:
            events[event] = sorted(set(messages))
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rounds", type=int, default=30, help="classification repeats per command")
    parser.add_argument("--subprocess-rounds", type=int, default=100)
    parser.add_argument("--state-read-rounds", type=int, default=100)
    args = parser.parse_args()

    started = time.perf_counter()
    cg = load_runtime()
    with tempfile.TemporaryDirectory(prefix="cg-benchmark-") as tmp:
        data_dir = Path(tmp) / "private"
        # In-process dispatch resolves the data root from os.environ too, so
        # the real default data root must never be reachable from here.
        previous_data_dir = os.environ.get("CONTEXT_GUARD_DATA_DIR")
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(data_dir)
        env = os.environ.copy()
        env["CONTEXT_GUARD_DATA_DIR"] = str(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        # Prepare a real session so the state-read layer and full hook path
        # operate on persisted state, not an empty directory.
        (data_dir / "project").mkdir(parents=True, exist_ok=True)
        prep = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "bench-session",
            "cwd": str(data_dir / "project"),
            "turn_id": "turn-bench-1",
            "prompt": "请修复 scripts/example.py 中的问题并运行测试",
        }
        prepared, error = run_subprocess_ms(
            [sys.executable, str(MODULE_PATH), "hook"],
            env=env,
            stdin_text=json.dumps(prep),
        )
        if error.returncode != 0:
            raise RuntimeError("session preparation hook failed")

        classification = classify_table(cg, args.rounds)
        if classification["classification_calls"] < 300 or classification["categories"] < 10:
            raise RuntimeError("classification table does not meet the 300-call/10-category gate")
        startup = measure_process_startup(env, args.subprocess_rounds)
        imports = measure_module_import(env, args.subprocess_rounds)
        hook_timings, hook_visible = measure_full_hook_path(
            env, data_dir, args.subprocess_rounds
        )
        state_read = measure_state_read_ms(cg, data_dir, args.state_read_rounds)
        turn_protocol = synthetic_turn_protocol(cg, data_dir)
        status_events = status_message_events()

    if previous_data_dir is None:
        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
    else:
        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous_data_dir

    report = {
        "benchmark_schema": "context-guard-baseline-benchmark/v1",
        "target_version": "0.11.1-candidate",
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "elapsed_seconds": round(time.perf_counter() - started, 1),
        "layers": {
            "interpreter_startup": summarize(startup),
            "module_import": summarize(imports),
            "state_read": summarize(state_read),
            "full_hook_path_by_event": {
                event: summarize(values) for event, values in hook_timings.items()
            },
            "classification": {
                category: values
                for category, values in classification[
                    "classification_ms_by_category"
                ].items()
            },
        },
        "classification": {
            key: value
            for key, value in classification.items()
            if key != "classification_ms_by_category"
        },
        "visibility": {
            "hooks_json_status_message_events": status_events,
            "full_hook_path_visible_outputs_by_event": hook_visible,
            "synthetic_turn": turn_protocol,
        },
        "gate_notes": [
            "case_matrix counts each deterministic table row once; call_matrix counts every timed invocation",
            "case_matrix expected allow/deny versus classifier flag, core categories only",
            "false_deny on allow rows is the plan's UX-06/UX-07 defect surface",
            "wrapper/compound probes are deny-side positive controls reported separately",
            "layered timing is a same-machine directional baseline, not a p95 acceptance result",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "classification_calls": classification["classification_calls"],
                "categories": classification["categories"],
                "case_matrix": classification["case_matrix_core_categories"],
                "call_matrix": classification["call_matrix_core_categories"],
                "status_message_events": status_events,
                "false_continuation_candidates": turn_protocol["duplicate_interruptions"],
                "extra_control_commands": turn_protocol["extra_control_commands"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"benchmark infrastructure error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
