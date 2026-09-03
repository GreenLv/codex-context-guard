#!/usr/bin/env python3
"""Run an isolated installed Context Guard lifecycle smoke test."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def run(
    command: list[str],
    *,
    environment: dict[str, str],
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        env=environment,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {shlex.join(command)}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result


def hook(
    runtime: Path,
    environment: dict[str, str],
    payload: dict[str, Any],
) -> dict[str, Any]:
    result = run(
        [sys.executable, str(runtime), "hook"],
        environment=environment,
        input_text=json.dumps(payload, ensure_ascii=True),
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("hook output must be a JSON object")
    if value.get("systemMessage") and payload["hook_event_name"] not in {
        "Stop",
        "SubagentStop",
    }:
        raise RuntimeError(f"unexpected hook warning: {value['systemMessage']}")
    return value


def context_text(value: dict[str, Any]) -> str:
    output = value.get("hookSpecificOutput")
    if not isinstance(output, dict):
        return ""
    return str(output.get("additionalContext") or "")


def option_from_command_context(context: str, option: str) -> str:
    for line in context.splitlines():
        if " checkpoint-status " not in f" {line} ":
            continue
        tokens = shlex.split(line)
        if option in tokens:
            index = tokens.index(option)
            if index + 1 < len(tokens):
                return tokens[index + 1]
        prefix = option + "="
        for token in tokens:
            if token.startswith(prefix):
                return token[len(prefix) :]
    raise RuntimeError(f"could not find {option} in private command context")


def load_runtime_module(runtime: Path) -> Any:
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location("context_guard_smoke", runtime)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot import {runtime}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.dont_write_bytecode = previous


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    source_manifest = json.loads(
        (repo_root / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    version = str(source_manifest["version"])
    configured_home = os.environ.get("CODEX_HOME")
    codex_home = (
        Path(configured_home).expanduser() if configured_home else Path.home() / ".codex"
    )
    default_root = (
        codex_home
        / "plugins"
        / "cache"
        / "codex-context-guard"
        / "context-guard"
        / version
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-root", type=Path, default=default_root)
    args = parser.parse_args()
    plugin_root = args.plugin_root.expanduser().resolve()
    runtime = plugin_root / "scripts" / "context_guard.py"
    if not runtime.is_file():
        raise RuntimeError(f"installed runtime not found: {runtime}")

    with tempfile.TemporaryDirectory(prefix="context-guard-smoke-") as temporary:
        root = Path(temporary)
        project = root / "project"
        project.mkdir()
        private = root / "private"
        environment = os.environ.copy()
        environment["CONTEXT_GUARD_DATA_DIR"] = str(private)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        session_id = "installed-smoke-session"

        def payload(event: str, turn_id: str, **extra: Any) -> dict[str, Any]:
            value: dict[str, Any] = {
                "hook_event_name": event,
                "session_id": session_id,
                "turn_id": turn_id,
                "cwd": str(project),
                "permission_mode": "plan",
            }
            value.update(extra)
            return value

        root_prompt = hook(
            runtime,
            environment,
            payload(
                "UserPromptSubmit",
                "turn-root",
                prompt=(
                    "实现隔离生命周期 smoke。必须保护根需求，必须恢复计划，"
                    "必须记录 subagent 结果并验证完成门禁。"
                ),
            ),
        )
        root_context = context_text(root_prompt)
        if "Context Guard is active" not in root_context:
            raise RuntimeError("complex root prompt did not activate protection")

        pre_tool = hook(
            runtime,
            environment,
            payload(
                "PreToolUse",
                "turn-root",
                tool_name="exec_command",
                tool_use_id="release-tool-without-ticket",
                tool_input={"cmd": "git tag v9.9.9"},
            ),
        )
        pre_tool_output = pre_tool.get("hookSpecificOutput", {})
        if (
            pre_tool_output.get("permissionDecision") != "deny"
            or "action-ticket/v1"
            not in str(pre_tool_output.get("permissionDecisionReason") or "")
        ):
            raise RuntimeError("PreToolUse did not fail closed without an action ticket")

        hook(
            runtime,
            environment,
            payload(
                "PostToolUse",
                "turn-root",
                tool_name="update_plan",
                tool_use_id="plan-tool",
                tool_input={
                    "explanation": "Installed lifecycle smoke.",
                    "plan": [
                        {"step": "Prepare", "status": "completed"},
                        {"step": "Verify lifecycle", "status": "in_progress"},
                    ],
                },
                tool_response={"success": True},
            ),
        )
        started = hook(
            runtime,
            environment,
            payload(
                "SubagentStart",
                "turn-agent",
                agent_id="agent-smoke",
                agent_type="explorer",
            ),
        )
        contract = context_text(started)
        if "root user's requirements remain authoritative" not in contract:
            raise RuntimeError("SubagentStart did not inject the authority boundary")
        hook(
            runtime,
            environment,
            payload(
                "UserPromptSubmit",
                "turn-agent",
                prompt=(
                    "<codex_delegation><task>Inspect the isolated smoke state."
                    "</task></codex_delegation>"
                ),
            ),
        )
        hook(
            runtime,
            environment,
            payload(
                "PostToolUse",
                "turn-root",
                tool_name="unknown-text-regression",
                tool_input={"command": "synthetic unstructured outcome"},
                tool_response="SMOKE_PASS",
            ),
        )
        hook(
            runtime,
            environment,
            payload(
                "PostToolUse",
                "turn-root",
                tool_name="weak-marker-regression",
                tool_input={"command": "synthetic mixed outcome"},
                tool_response=(
                    "PASS\nTraceback (most recent call last):\nRuntimeError: broken"
                ),
            ),
        )
        hook(
            runtime,
            environment,
            payload(
                "PostToolUse",
                "turn-root",
                tool_name="Bash",
                tool_input={"command": "synthetic warning verification"},
                tool_response=(
                    "Script completed\nOutput:\nWarning: Operation not permitted"
                ),
            ),
        )
        hook(
            runtime,
            environment,
            payload(
                "PostToolUse",
                "turn-root",
                tool_name="view_image",
                tool_input={"path": str(project / "synthetic.png")},
                tool_response={
                    "image_url": "data:image/png;base64," + ("A" * 5000),
                    "detail": "original",
                },
            ),
        )
        hook(
            runtime,
            environment,
            payload(
                "SubagentStop",
                "turn-agent",
                agent_id="agent-smoke",
                agent_type="explorer",
                agent_transcript_path=str(root / "not-read.jsonl"),
                last_assistant_message="\n".join(
                    [
                        "Outcome: inspected the isolated state.",
                        "Evidence: synthetic lifecycle events were observed.",
                        "Validation: no workspace mutation occurred.",
                        "Limitations: this is a synthetic boundary smoke.",
                        "Next: parent should complete the private checkpoint.",
                    ]
                ),
            ),
        )
        root_token = option_from_command_context(root_context, "--token")
        root_common = [
            "--data-dir",
            str(private),
            "--session-id",
            session_id,
            "--turn-id",
            "turn-root",
            f"--token={root_token}",
        ]
        disposition_arguments = [
            sys.executable,
            str(runtime),
            "stage-disposition",
            *root_common,
            "--disposition",
            "user_wait",
        ]
        staged_disposition = run(disposition_arguments, environment=environment)
        hook(
            runtime,
            environment,
            payload(
                "PostToolUse",
                "turn-root",
                tool_name="Bash",
                tool_input={"command": shlex.join(disposition_arguments)},
                tool_response=staged_disposition.stdout,
            ),
        )
        yielded = hook(
            runtime,
            environment,
            payload(
                "Stop",
                "turn-root",
                last_assistant_message=(
                    "Please configure the required account publisher, then respond."
                ),
            ),
        )
        if yielded:
            raise RuntimeError(
                f"Stop did not accept the staged user_wait disposition: {yielded}"
            )
        waiting_state = json.loads(
            (
                private / "sessions" / session_id / "state.json"
            ).read_text(encoding="utf-8")
        )
        waiting_attempt = waiting_state.get("completion_attempt")
        if isinstance(waiting_attempt, dict) and waiting_attempt.get("staged_control"):
            raise RuntimeError("Stop did not consume the user_wait disposition")
        if not waiting_state.get("open_items"):
            raise RuntimeError("user_wait disposition incorrectly completed the task")

        resumed_turn = hook(
            runtime,
            environment,
            payload(
                "UserPromptSubmit",
                "turn-resume",
                prompt=(
                    "用户动作已经完成；继续 lifecycle smoke，并恢复后完成证据验收。"
                ),
            ),
        )
        if "stage-disposition" not in context_text(resumed_turn):
            raise RuntimeError("new turn did not receive the disposition protocol")
        compact = hook(
            runtime,
            environment,
            payload("PreCompact", "turn-resume", trigger="manual"),
        )
        if compact.get("continue") is not True:
            raise RuntimeError("PreCompact did not continue after saving recovery")
        restored = hook(
            runtime,
            environment,
            payload("SessionStart", "turn-after-compact", source="compact"),
        )
        restored_context = context_text(restored)
        for expected in (
            "Latest Codex plan mirror",
            "Bounded subagent coordination state",
            "checkpoint-status",
            "stage-disposition",
        ):
            if expected not in restored_context:
                raise RuntimeError(f"recovery context is missing {expected!r}")

        token = option_from_command_context(restored_context, "--token")
        common = [
            "--data-dir",
            str(private),
            "--session-id",
            session_id,
            "--turn-id",
            "turn-after-compact",
            f"--token={token}",
        ]
        status = run(
            [sys.executable, str(runtime), "checkpoint-status", *common],
            environment=environment,
        )
        snapshot = json.loads(status.stdout)
        warning_evidence = next(
            item
            for item in snapshot["recent_successful_evidence"]
            if item["tool"] == "Bash"
        )
        visual_evidence = next(
            (
                item
                for item in snapshot["recent_successful_evidence"]
                if item["tool"] == "view_image"
            ),
            None,
        )
        if visual_evidence is None:
            raise RuntimeError("structured view_image result was not successful evidence")
        if any(
            item["tool"] == "weak-marker-regression"
            for item in snapshot["recent_successful_evidence"]
        ):
            raise RuntimeError("weak PASS marker overrode a traceback failure")
        if any(
            item["tool"] == "unknown-text-regression"
            for item in snapshot["recent_successful_evidence"]
        ):
            raise RuntimeError("unstructured SMOKE_PASS was treated as success")
        evidence_id = warning_evidence["id"]
        stage_arguments = [
            sys.executable,
            str(runtime),
            "stage-checkpoint",
            *common,
        ]
        stage_arguments.extend(
            argument
            for item_id in (
                [
                    item["id"]
                    for item in snapshot["items"]
                    if item["id"].startswith("R")
                ]
                + [
                    item_id
                    for item_id in snapshot["ancestor_constraint_ids"]
                    if item_id.startswith("R")
                ]
            )
            for argument in ("--requirement", f"{item_id}={evidence_id}")
        )
        stage_arguments.extend(
            argument
            for item_id in (
                [
                    item["id"]
                    for item in snapshot["items"]
                    if item["id"].startswith("A")
                ]
                + [
                    item_id
                    for item_id in snapshot["ancestor_constraint_ids"]
                    if item_id.startswith("A")
                ]
            )
            for argument in ("--acceptance", f"{item_id}={evidence_id}")
        )
        staged = run(stage_arguments, environment=environment)
        hook(
            runtime,
            environment,
            payload(
                "PostToolUse",
                "turn-after-compact",
                tool_name="Bash",
                tool_input={"command": shlex.join(stage_arguments)},
                tool_response=staged.stdout,
            ),
        )
        stopped = hook(
            runtime,
            environment,
            payload(
                "Stop",
                "turn-after-compact",
                last_assistant_message="Installed lifecycle smoke is verified and complete.",
            ),
        )
        if stopped:
            raise RuntimeError(f"Stop did not accept the staged checkpoint: {stopped}")

        state_path = private / "sessions" / session_id / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        module = load_runtime_module(runtime)
        module.validate_state_integrity(state)
        expected_schema = int(getattr(module, "SCHEMA_VERSION", 0))
        serialized = json.dumps(state, ensure_ascii=False)
        assertions = {
            "current_schema": state.get("schema_version") == expected_schema,
            "proof_protocol": getattr(module, "PROOF_PROTOCOL_VERSION", None)
            == "1.0.0",
            "root_and_resume_requirements": len(state.get("requirements", [])) == 2,
            "delegated_prompt": any(
                item.get("authority") == "delegated"
                for item in state.get("prompts", [])
            ),
            "plan_mirrored": bool(
                state.get("work_state", {}).get("plan_snapshot", {}).get("steps")
            ),
            "agent_stopped": any(
                item.get("status") == "stopped"
                and item.get("result_envelope", {}).get("complete") is True
                for item in state.get("agents", [])
            ),
            "unstructured_text_unknown": any(
                item.get("tool") == "unknown-text-regression"
                and item.get("outcome") == "unknown"
                and item.get("outcome_basis") == "weak_success_marker"
                for item in state.get("evidence", [])
            ),
            "binary_removed": "base64,AAAA" not in serialized,
            "checkpoint_complete": state.get("completion_checkpoint", {}).get("status")
            == "complete",
            "checkpoint_control_consumed": state.get("completion_attempt") is None,
            "disposition_consumed": "user_wait"
            in json.dumps(state.get("decision_log", []), ensure_ascii=False),
            "no_open_items": not state.get("open_items"),
            "all_items_pass": all(
                item.get("status") == "pass"
                for item in state.get("requirements", [])
                + state.get("acceptance_items", [])
            ),
        }
        if expected_schema >= 7:
            assertions["execution_dormant"] = bool(
                module.execution_state_is_dormant(state.get("execution"))
            )
            assertions["no_execution_tickets"] = not state.get("execution", {}).get(
                "action_tickets"
            )
        failed = [name for name, passed in assertions.items() if not passed]
        if failed:
            raise RuntimeError("smoke assertions failed: " + ", ".join(failed))

    print(
        "SMOKE_PASS context-guard installed lifecycle: "
        f"schema{expected_schema}/proof-1.0.0, private disposition consumption, plan mirror, delegated "
        "authority, bounded agent result, unknown-text exclusion, binary "
        "omission, pre-action denial, compaction recovery, and private completion gate"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
