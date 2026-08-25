#!/usr/bin/env python3
"""Unit and synthetic hook regression tests for Context Guard."""

from __future__ import annotations

import base64
import concurrent.futures
import datetime as dt
import hashlib
import importlib.util
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)


class ContextGuardTests(unittest.TestCase):
    DISPOSITION_REASONS: ClassVar[dict[str, str]] = {
        "continue": "assistant_work_remains",
        "user_wait": "user_action_required",
        "external_wait": "external_dependency",
        "deferred": "denied_or_out_of_scope",
    }

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.turn_index = 0
        self.current_turn = "turn-0"
        self.environment = mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.root / "private")}
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def payload(self, event: str, session: str = "session-a", **extra: object) -> dict:
        result = {
            "hook_event_name": event,
            "session_id": session,
            "cwd": str(self.project),
        }
        if event in {
            "UserPromptSubmit",
            "PostToolUse",
            "PreCompact",
            "SubagentStart",
            "SubagentStop",
            "Stop",
        }:
            result["turn_id"] = self.current_turn
        result.update(extra)
        return result

    def state(self, session: str = "session-a") -> dict:
        path = self.root / "private" / "sessions" / session / "state.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def execution_manifest(self, plan_sha256: str | None = None) -> dict:
        sources = [
            {
                "id": "source-skill",
                "kind": "skill_contract",
                "origin_id": "skill-publisher",
                "revision": 1,
                "sha256": "1" * 64,
            }
        ]
        if plan_sha256 is not None:
            sources.append(
                {
                    "id": "source-plan",
                    "kind": "plan_snapshot",
                    "origin_id": "codex-plan",
                    "revision": 1,
                    "sha256": plan_sha256,
                }
            )
        return {
            "protocol_version": cg.EXECUTION_PROTOCOL_VERSION,
            "contract_id": "contract-phase3",
            "revision": 1,
            "instruction_sources": sources,
            "phases": [
                {"id": "phase-write", "depends_on": []},
                {"id": "phase-readback", "depends_on": ["phase-write"]},
            ],
            "gates": [{"id": "gate-authorization", "depends_on": []}],
            "authorization_candidates": [
                {
                    "id": "candidate-deterministic",
                    "prompt_id": "P0001",
                    "prompt_sha256": "2" * 64,
                    "semantic_action_id": "publish",
                    "canonical_target_id": "target-test",
                    "write_surface_id": "external-api",
                    "binding": "deterministic",
                },
                {
                    "id": "candidate-natural",
                    "prompt_id": "P0001",
                    "prompt_sha256": "3" * 64,
                    "semantic_action_id": "publish",
                    "canonical_target_id": "target-heuristic",
                    "write_surface_id": "external-api",
                    "binding": "natural_language",
                },
            ],
            "coverage_manifest": {
                "host_lock": None,
                "adapters": [],
                "uncovered_write_surfaces": [
                    {"id": "surface-ui", "reason_code": "no-native-hook", "status": "uncovered"}
                ],
                "unclassified_high_risk_policy": "deny_when_active",
                "non_active_contract_policy": "completion_only",
                "stale_conflicted_policy": "deny_covered_high_risk",
                "pre_tool_output_policy": "allow_deny_only",
            },
        }

    def prompt(self, text: str, session: str = "session-a") -> dict:
        self.turn_index += 1
        self.current_turn = f"turn-{self.turn_index}"
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="test-token"):
            return cg.dispatch(
                self.payload("UserPromptSubmit", session=session, prompt=text)
            )

    def test_find_latest_state_ignores_empty_session_directory(self) -> None:
        empty = self.root / "private" / "sessions" / "empty"
        empty.mkdir(parents=True)
        self.assertIsNone(cg.find_latest_state(self.root / "private"))

    def test_find_latest_state_prefers_persisted_state_over_empty_sibling(
        self,
    ) -> None:
        self.prompt("simple prompt", session="session-a")
        empty = self.root / "private" / "sessions" / "newer-empty"
        empty.mkdir(parents=True)
        latest = cg.find_latest_state(self.root / "private")
        self.assertIsNotNone(latest)
        assert latest is not None
        self.assertEqual(latest[0].name, "session-a")

    def test_status_cli_handles_only_empty_session_directories(self) -> None:
        empty = self.root / "private" / "sessions" / "empty"
        empty.mkdir(parents=True)
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "status"],
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "Context Guard has no local session state.",
        )
        self.assertEqual(result.stderr, "")

    def record_tool(
        self,
        *,
        session: str = "session-a",
        tool: str = "Bash",
        response: dict | None = None,
    ) -> str:
        cg.dispatch(
            self.payload(
                "PostToolUse",
                session=session,
                tool_name=tool,
                tool_input={"command": "synthetic verification"},
                tool_response=response or {"exit_code": 0, "output": "PASS"},
            )
        )
        return self.state(session)["evidence"][-1]["id"]

    def stage_all(self, evidence_id: str, session: str = "session-a") -> dict:
        state = self.state(session)
        requirements = [
            f"{item['id']}={evidence_id}"
            for item in state["requirements"]
            if item["status"] not in {"pass", "superseded"}
        ]
        acceptance = [
            f"{item['id']}={evidence_id}"
            for item in state["acceptance_items"]
            if item["status"] not in {"pass", "superseded"}
        ]
        return cg.stage_private_checkpoint(
            self.root / "private",
            session,
            self.current_turn,
            "test-token",
            requirements,
            acceptance,
        )

    def private_command_common(
        self,
        *,
        session: str = "session-a",
        turn_id: str | None = None,
        token: str = "test-token",
        data_dir: Path | None = None,
    ) -> list[str]:
        return [
            "--data-dir",
            str(data_dir or self.root / "private"),
            "--session-id",
            session,
            "--turn-id",
            turn_id or self.current_turn,
            f"--token={token}",
        ]

    def run_private_stage(
        self,
        arguments: list[str],
        *,
        session: str = "session-a",
        turn_id: str | None = None,
        tool_response: object | None = None,
        command: str | None = None,
        tool_name: str = "Bash",
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        staged = subprocess.run(
            arguments,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=15,
            check=False,
        )
        if staged.returncode != 0:
            return staged, {}
        response = (
            tool_response
            if tool_response is not None
            else {"exit_code": 0, "output": staged.stdout}
        )
        hook_result = cg.dispatch(
            self.payload(
                "PostToolUse",
                session=session,
                turn_id=turn_id or self.current_turn,
                tool_name=tool_name,
                tool_input={"command": command or cg.shell_join(arguments)},
                tool_response=response,
            )
        )
        return staged, hook_result

    def stage_disposition(
        self,
        disposition: str,
        *,
        session: str = "session-a",
        turn_id: str | None = None,
        token: str = "test-token",
        replace: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-disposition",
            *self.private_command_common(
                session=session,
                turn_id=turn_id,
                token=token,
            ),
            "--disposition",
            disposition,
        ]
        if replace:
            arguments.append("--replace")
        return self.run_private_stage(
            arguments,
            session=session,
            turn_id=turn_id,
        )

    def stage_checkpoint_cli(
        self,
        evidence_id: str,
        *,
        session: str = "session-a",
        replace: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        state = self.state(session)
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-checkpoint",
            *self.private_command_common(session=session),
        ]
        for item in state["requirements"]:
            if item["status"] not in {"pass", "superseded"}:
                arguments.extend(
                    ["--requirement", f"{item['id']}={evidence_id}"]
                )
        for item in state["acceptance_items"]:
            if item["status"] not in {"pass", "superseded"}:
                arguments.extend(
                    ["--acceptance", f"{item['id']}={evidence_id}"]
                )
        if replace:
            arguments.append("--replace")
        return self.run_private_stage(arguments, session=session)

    def write_successor_input(
        self,
        *,
        current_step_reads: list[dict] | None = None,
        audit_only_files: list[dict] | None = None,
    ) -> Path:
        path = (
            self.project
            / ".codex"
            / "context-guard"
            / cg.SUCCESSOR_INPUT_FILENAME
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "current_status": "Implementation checkpoint is verified.",
                    "exact_next_action": "Run the next bounded verification step.",
                    "authorization": {
                        "granted": [
                            {
                                "text": "Modify only files required by R001.",
                                "source_ids": ["R001"],
                            }
                        ],
                        "consumed": [],
                        "pending": [],
                        "forbidden": [
                            {
                                "text": "Do not broaden the task.",
                                "source_ids": ["R001"],
                            }
                        ],
                    },
                    "current_step_reads": current_step_reads or [],
                    "audit_only_files": audit_only_files or [],
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def test_simple_prompt_is_journaled_without_activation(self) -> None:
        self.prompt("把这句话翻译成英文。")
        state = self.state()
        self.assertFalse(state["mode"]["active"])
        self.assertEqual(len(state["prompts"]), 1)
        self.assertEqual(len(state["requirements"]), 1)

    def test_complex_prompt_activates_and_preserves_hash_and_acceptance(self) -> None:
        text = "\n".join(
            [
                "请实现跨平台插件并完成测试：",
                "- 必须保存原始需求",
                "- 必须验证压缩后恢复",
                "- 不得提交密钥",
                "- 完成 doctor 和 smoke test",
                "请修改 Python、JSON、TOML 和安装脚本，并逐项验收。",
            ]
        )
        result = self.prompt(text)
        state = self.state()
        self.assertTrue(state["mode"]["active"])
        self.assertGreaterEqual(len(state["acceptance_items"]), 3)
        activation = result["hookSpecificOutput"]["additionalContext"]
        self.assertIn("requirement R001", activation)
        self.assertIn("A001", activation)
        self.assertIn("checkpoint-status", activation)
        self.assertIn("stage-checkpoint", activation)
        self.assertIn("stage-disposition", activation)
        self.assertNotIn("<!--", activation)
        attempt = state["completion_attempt"]
        self.assertEqual(
            set(attempt),
            {
                "protocol_version",
                "turn_id",
                "token_sha256",
                "created_at",
                "staged_at",
                "staged_control",
            },
        )
        self.assertEqual(attempt["turn_id"], self.current_turn)
        self.assertEqual(attempt["token_sha256"], cg.sha256_text("test-token"))
        self.assertTrue(attempt["created_at"])
        self.assertIsNone(attempt["staged_at"])
        self.assertIsNone(attempt["staged_control"])
        metadata = state["prompts"][0]
        self.assertEqual(
            metadata["sha256"], hashlib.sha256(text.encode("utf-8")).hexdigest()
        )
        raw = json.loads(
            (
                self.root
                / "private"
                / "sessions"
                / "session-a"
                / metadata["file"]
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(raw["text"], text)

    def test_later_revision_records_supersession(self) -> None:
        self.prompt("实现旧方案并验证。")
        self.prompt("取消旧方案，改为实现新方案并测试。")
        state = self.state()
        self.assertEqual(state["supersedes"][0]["old_id"], "R001")
        self.assertEqual(state["supersedes"][0]["new_id"], "R002")
        self.assertEqual(state["requirements"][0]["status"], "superseded")

    def test_negated_supersession_preserves_existing_requirement(self) -> None:
        for revision in (
            "不要取消 R001；继续保留原要求。",
            "Do not replace R001; keep the original requirement.",
            "Do not ever cancel R001; use the original approach instead.",
            "不要取消 R001；改为继续保留原要求。",
        ):
            with self.subTest(revision=revision):
                session = "session-" + hashlib.sha256(
                    revision.encode("utf-8")
                ).hexdigest()[:8]
                self.prompt("实现旧方案并验证。", session=session)
                self.prompt(revision, session=session)
                state = self.state(session)
                self.assertEqual(state["supersedes"], [])
                self.assertEqual(state["requirements"][0]["status"], "pending")

    def test_ambiguous_explicit_supersession_targets_fail_closed(self) -> None:
        self.prompt("实现方案一并验证。")
        self.prompt("补充方案二并测试。")
        self.prompt("取消 R001 或 R002，改用新方案。")
        state = self.state()
        self.assertEqual(state["supersedes"], [])
        self.assertEqual(
            [item["status"] for item in state["requirements"][:2]],
            ["pending", "pending"],
        )

    def test_goal_prompt_activates_without_private_goal_state(self) -> None:
        self.prompt("/goal 完成这个长期任务")
        state = self.state()
        self.assertTrue(state["mode"]["active"])
        self.assertIn("goal", state["mode"]["activation_reasons"])

    def test_precompact_snapshot_and_immediate_restore(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存初始边界，必须验证压缩恢复，必须运行全部测试。"
        )
        result = cg.dispatch(
            self.payload("PreCompact", trigger="manual", transcript_path="/diagnostic")
        )
        self.assertTrue(result["continue"])
        session_dir = self.root / "private" / "sessions" / "session-a"
        self.assertTrue((session_dir / "recovery.json").exists())
        restored = cg.dispatch(self.payload("SessionStart", source="compact"))
        packet = restored["hookSpecificOutput"]["additionalContext"]
        self.assertIn("CONTEXT-GUARD RECOVERY PACKET", packet)
        self.assertIn("R001", packet)
        self.assertIn("checkpoint-status", packet)
        self.assertIn("stage-checkpoint", packet)
        self.assertIn("stage-disposition", packet)
        self.assertNotIn("<!--", packet)
        self.assertLessEqual(len(packet), cg.RECOVERY_CHAR_LIMIT)

    def test_session_start_without_turn_id_uses_latest_transcript_turn(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存初始边界，必须验证压缩恢复，必须运行全部测试。"
        )
        transcript = self.root / "session.jsonl"
        transcript.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "type": "turn_context",
                            "payload": {"turn_id": "turn-before-compact"},
                        }
                    ),
                    "{malformed",
                    json.dumps(
                        {
                            "type": "turn_context",
                            "payload": {"turn_id": "turn-after-compact"},
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        state = self.state()
        state["completion_attempt"] = None
        state["session"]["transcript_path"] = str(transcript)
        cg.save_state(session_dir, state)

        with mock.patch.object(
            cg.secrets, "token_urlsafe", return_value="resume-token"
        ):
            restored = cg.dispatch(self.payload("SessionStart", source="compact"))

        packet = restored["hookSpecificOutput"]["additionalContext"]
        self.assertIn("--turn-id turn-after-compact", packet)
        self.assertEqual(
            self.state()["completion_attempt"]["turn_id"],
            "turn-after-compact",
        )

    def test_transcript_resolved_turn_accepts_post_compact_checkpoint(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        transcript = self.root / "session.jsonl"
        transcript.write_text(
            json.dumps(
                {
                    "type": "turn_context",
                    "payload": {"turn_id": "turn-after-compact"},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        state = self.state()
        state["completion_attempt"] = None
        state["session"]["transcript_path"] = str(transcript)
        cg.save_state(session_dir, state)
        with mock.patch.object(
            cg.secrets, "token_urlsafe", return_value="test-token"
        ):
            cg.dispatch(self.payload("SessionStart", source="compact"))

        self.current_turn = "turn-after-compact"
        evidence_id = self.record_tool()
        receipt = self.stage_all(evidence_id)
        self.assertRegex(receipt["checkpoint_sha256"], r"^[0-9a-f]{64}$")

    def test_snapshot_write_failure_blocks_compaction_only(self) -> None:
        self.prompt("$context-guard")
        with mock.patch.object(cg, "atomic_write_text", side_effect=OSError("disk full")):
            result = cg.safe_dispatch(self.payload("PreCompact", trigger="auto"))
        self.assertFalse(result["continue"])
        self.assertIn("disk full", result["systemMessage"])

    def test_manual_off_skips_recovery_but_keeps_prompt_journaling(self) -> None:
        self.prompt("$context-guard")
        self.prompt("context-guard off")
        result = cg.dispatch(self.payload("PreCompact", trigger="manual"))
        self.assertTrue(result["continue"])
        session_dir = self.root / "private" / "sessions" / "session-a"
        self.assertFalse((session_dir / "recovery.json").exists())
        state = self.state()
        self.assertFalse(state["mode"]["active"])
        self.assertTrue(state["mode"]["manual_off"])
        self.assertEqual(len(state["prompts"]), 2)

    def test_diagnose_control_is_hash_only_and_does_not_add_requirement(self) -> None:
        self.prompt("$context-guard")
        before = len(self.state()["requirements"])

        result = self.prompt("context-guard diagnose")

        context = result["hookSpecificOutput"]["additionalContext"]
        self.assertIn(cg.CLASSIFIER_VERSION, context)
        self.assertIn("no Stop decisions", context)
        self.assertEqual(len(self.state()["requirements"]), before)

    def test_stop_is_bounded_and_fails_closed_after_two_retries(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        first = cg.dispatch(
            self.payload("Stop", last_assistant_message="任务已经完成。")
        )
        self.assertEqual(first["decision"], "block")
        self.assertIn(cg.INTERNAL_CONTINUATION_PREFIX, first["reason"])
        self.assertIn("requirements=R001", first["reason"])
        self.assertIn("acceptance=A001", first["reason"])
        self.prompt(first["reason"])
        second = cg.dispatch(
            self.payload("Stop", last_assistant_message="任务已经完成。")
        )
        self.assertEqual(second["decision"], "block")
        self.assertEqual(self.state()["continuation_attempts"], 2)
        self.prompt(second["reason"])
        terminal = cg.dispatch(
            self.payload("Stop", last_assistant_message="任务已经完成。")
        )
        self.assertFalse(terminal["continue"])
        self.assertIn("stopped an unverified completion", terminal["stopReason"])
        self.assertEqual(len(self.state()["requirements"]), 1)

    def test_new_user_turn_resets_bounded_completion_gate(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        first = cg.dispatch(
            self.payload("Stop", last_assistant_message="任务已经完成。")
        )
        self.assertEqual(first["decision"], "block")
        self.assertEqual(self.state()["continuation_attempts"], 1)
        self.prompt("继续处理缺失项并重新验收。")
        self.assertEqual(self.state()["continuation_attempts"], 0)
        next_attempt = cg.dispatch(
            self.payload("Stop", last_assistant_message="任务已经完成。")
        )
        self.assertEqual(next_attempt["decision"], "block")
        self.assertEqual(self.state()["continuation_attempts"], 1)

    def test_protocol_default_yield_preserves_pending_but_completion_claim_gates(
        self,
    ) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        for message in (
            "核心代码已写完；剩余测试稍后继续。",
            "The local commit passed; I will continue the remaining work later.",
            "当前仍有代理可执行事项，但本轮先报告进度。",
        ):
            with self.subTest(message=message):
                self.assertEqual(
                    cg.dispatch(
                        self.payload("Stop", last_assistant_message=message)
                    ),
                    {},
                )
                state = self.state()
                self.assertEqual(state["continuation_attempts"], 0)
                self.assertTrue(state["open_items"])
                self.assertIsNone(state["completion_checkpoint"])

        completed = cg.dispatch(
            self.payload(
                "Stop",
                last_assistant_message="The entire requested task is complete.",
            )
        )
        self.assertEqual(completed["decision"], "block")
        self.assertEqual(self.state()["continuation_attempts"], 1)

    def test_protocol_dispositions_drive_stop_without_marking_waits_complete(
        self,
    ) -> None:
        cases = (
            ("user_wait", "请完成账号选择后告诉我。"),
            ("external_wait", "The PR is awaiting external review."),
            ("deferred", "Push and CI are outside this turn's scope."),
            ("continue", "I still have work to perform."),
        )
        for disposition, message in cases:
            with self.subTest(disposition=disposition):
                session = f"session-{disposition}"
                self.prompt(
                    "$context-guard\n完成复杂任务并保留所有未完成需求。",
                    session=session,
                )
                staged, hook_result = self.stage_disposition(
                    disposition,
                    session=session,
                )
                self.assertEqual(staged.returncode, 0, staged.stderr)
                self.assertIn("privately staged", json.dumps(hook_result))
                result = cg.dispatch(
                    self.payload(
                        "Stop",
                        session=session,
                        last_assistant_message=message,
                    )
                )
                self.assertEqual(result, {})
                state = self.state(session)
                self.assertTrue(state["open_items"])
                self.assertIsNone(state["completion_checkpoint"])
                attempt = state.get("completion_attempt")
                self.assertTrue(
                    attempt is None or attempt.get("staged_control") is None
                )
                if disposition == "continue":
                    self.assertEqual(
                        state["decision_log"][-1]["reason_codes"][0],
                        "protocol_continue_advisory",
                    )

    def test_private_disposition_api_derives_fixed_reason(self) -> None:
        for disposition, reason in self.DISPOSITION_REASONS.items():
            with self.subTest(disposition=disposition):
                session = f"session-api-{disposition}"
                self.prompt(
                    "$context-guard\n保留未完成需求并验证私有 disposition API。",
                    session=session,
                )
                cg.stage_private_disposition(
                    self.root / "private",
                    session,
                    self.current_turn,
                    "test-token",
                    disposition,
                    replace=False,
                )
                self.assertEqual(
                    self.state(session)["completion_attempt"]["staged_control"],
                    {
                        "kind": "disposition",
                        "disposition": disposition,
                        "reason": reason,
                    },
                )

    def test_explicit_persistence_gates_default_yield_and_conflicting_deferral(
        self,
    ) -> None:
        for session, prompt in (
            (
                "session-persist-en",
                "$context-guard\nDo not stop until the entire task is complete.",
            ),
            (
                "session-persist-zh",
                "$context-guard\n不要停，持续执行直到整个任务完成。",
            ),
        ):
            with self.subTest(prompt=prompt):
                self.prompt(prompt, session=session)
                result = cg.dispatch(
                    self.payload(
                        "Stop",
                        session=session,
                        last_assistant_message="Progress is recorded; work remains.",
                    )
                )
                self.assertEqual(result["decision"], "block")

        session = "session-persist-deferred"
        self.prompt(
            "$context-guard\nDo not stop until implementation, push, and CI finish.",
            session=session,
        )
        staged, _ = self.stage_disposition("deferred", session=session)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        result = cg.dispatch(
            self.payload(
                "Stop",
                session=session,
                last_assistant_message="Push and CI are deferred.",
            )
        )
        self.assertEqual(result["decision"], "block")

        session = "session-persist-user-wait"
        self.prompt(
            "$context-guard\nDo not stop until completion, but ask me for required login steps.",
            session=session,
        )
        staged, _ = self.stage_disposition("user_wait", session=session)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertEqual(
            cg.dispatch(
                self.payload(
                    "Stop",
                    session=session,
                    last_assistant_message="Please finish the required login step.",
                )
            ),
            {},
        )

    def test_persistence_deferred_is_bound_to_the_denied_action(self) -> None:
        prompt = (
            "$context-guard\nDo not stop until the local implementation is complete. "
            "Do not publish."
        )
        cases = (
            (
                "denied-publish-action",
                "Publishing is deferred to a later phase.",
                True,
            ),
            (
                "authorized-implementation-action",
                "I will implement the remaining local change later.",
                False,
            ),
            (
                "unidentified-deferred-action",
                "Implementation is deferred.",
                False,
            ),
            (
                "completed-denied-action-does-not-cover-other-deferral",
                "Publishing is complete; implementation is deferred.",
                False,
            ),
        )
        for label, reply, should_yield in cases:
            with self.subTest(label=label):
                session = f"session-persist-bound-{label}"
                self.prompt(prompt, session=session)
                staged, _ = self.stage_disposition("deferred", session=session)
                self.assertEqual(staged.returncode, 0, staged.stderr)
                result = cg.dispatch(
                    self.payload(
                        "Stop",
                        session=session,
                        last_assistant_message=reply,
                    )
                )
                if should_yield:
                    self.assertEqual(result, {})
                    self.assertEqual(
                        self.state(session)["decision_log"][-1]["outcome"],
                        "allow_out_of_scope_deferred",
                    )
                else:
                    self.assertEqual(result["decision"], "block")
                    self.assertEqual(
                        self.state(session)["continuation_attempts"], 1
                    )

    def test_service_stop_negation_is_not_agent_persistence(self) -> None:
        cases = (
            (
                "$context-guard\nDo not stop the server while checking logs.",
                "Log inspection is still in progress; this turn reports current status.",
            ),
            (
                "$context-guard\n检查日志时不要停止服务。",
                "日志检查尚未结束；本轮先报告当前状态。",
            ),
        )
        for index, (prompt, reply) in enumerate(cases):
            with self.subTest(prompt=prompt):
                session = f"session-service-negation-{index}"
                self.prompt(prompt, session=session)
                self.assertEqual(
                    cg.dispatch(
                        self.payload(
                            "Stop",
                            session=session,
                            last_assistant_message=reply,
                        )
                    ),
                    {},
                )
                self.assertEqual(
                    self.state(session)["continuation_attempts"], 0
                )
                self.assertTrue(self.state(session)["open_items"])

    def test_staged_control_is_exclusive_idempotent_and_replaceable(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()

        first, _ = self.stage_disposition("user_wait")
        self.assertEqual(first.returncode, 0, first.stderr)
        first_attempt = self.state()["completion_attempt"]
        first_control = first_attempt["staged_control"]
        first_staged_at = first_attempt["staged_at"]
        self.assertIsNotNone(first_staged_at)
        self.assertEqual(
            first_control,
            {
                "kind": "disposition",
                "disposition": "user_wait",
                "reason": "user_action_required",
            },
        )

        repeated, _ = self.stage_disposition("user_wait")
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(
            self.state()["completion_attempt"]["staged_control"],
            first_control,
        )
        self.assertEqual(
            self.state()["completion_attempt"]["staged_at"],
            first_staged_at,
        )

        conflict, _ = self.stage_disposition("external_wait")
        self.assertNotEqual(conflict.returncode, 0)
        self.assertEqual(
            self.state()["completion_attempt"]["staged_control"],
            first_control,
        )

        replaced, _ = self.stage_disposition("external_wait", replace=True)
        self.assertEqual(replaced.returncode, 0, replaced.stderr)
        self.assertEqual(
            self.state()["completion_attempt"]["staged_control"],
            {
                "kind": "disposition",
                "disposition": "external_wait",
                "reason": "external_dependency",
            },
        )
        self.assertNotEqual(
            self.state()["completion_attempt"]["staged_at"],
            first_staged_at,
        )

        checkpoint_conflict, _ = self.stage_checkpoint_cli(evidence_id)
        self.assertNotEqual(checkpoint_conflict.returncode, 0)
        checkpoint, _ = self.stage_checkpoint_cli(evidence_id, replace=True)
        self.assertEqual(checkpoint.returncode, 0, checkpoint.stderr)
        self.assertEqual(
            self.state()["completion_attempt"]["staged_control"]["kind"],
            "checkpoint",
        )
        checkpoint_attempt = self.state()["completion_attempt"]
        checkpoint_control = checkpoint_attempt["staged_control"]
        checkpoint_staged_at = checkpoint_attempt["staged_at"]
        repeated_checkpoint, _ = self.stage_checkpoint_cli(evidence_id)
        self.assertEqual(
            repeated_checkpoint.returncode,
            0,
            repeated_checkpoint.stderr,
        )
        self.assertEqual(
            self.state()["completion_attempt"]["staged_control"],
            checkpoint_control,
        )
        self.assertEqual(
            self.state()["completion_attempt"]["staged_at"],
            checkpoint_staged_at,
        )

        disposition_conflict, _ = self.stage_disposition("user_wait")
        self.assertNotEqual(disposition_conflict.returncode, 0)
        disposition, _ = self.stage_disposition("user_wait", replace=True)
        self.assertEqual(disposition.returncode, 0, disposition.stderr)
        self.assertEqual(
            self.state()["completion_attempt"]["staged_control"]["kind"],
            "disposition",
        )

    def test_10000_generated_control_transitions_obey_one_way_safety_lattice(
        self,
    ) -> None:
        rng = random.Random(602)
        dispositions = tuple(self.DISPOSITION_REASONS)
        attempt: dict[str, object] = {
            "staged_control": None,
            "staged_at": None,
        }
        conflicts = 0
        replacements = 0
        for _ in range(10_000):
            if rng.randrange(13) == 0:
                attempt["staged_control"] = None
                attempt["staged_at"] = None
            control = cg.disposition_control(rng.choice(dispositions))
            replace = rng.randrange(4) == 0
            existing = attempt["staged_control"]
            try:
                idempotent = cg.stage_control(
                    attempt,
                    control,
                    replace=replace,
                )
            except ValueError:
                conflicts += 1
                self.assertIsNotNone(existing)
                self.assertNotEqual(
                    cg.canonical_json(existing),
                    cg.canonical_json(control),
                )
                self.assertFalse(replace)
            else:
                if existing is not None and cg.canonical_json(
                    existing
                ) == cg.canonical_json(control):
                    self.assertTrue(idempotent)
                else:
                    self.assertFalse(idempotent)
                    if existing is not None:
                        replacements += 1
                    self.assertEqual(attempt["staged_control"], control)

            staged = attempt["staged_control"]
            declared = (
                str(staged["disposition"])
                if isinstance(staged, dict)
                else None
            )
            whole_completion = bool(rng.getrandbits(1))
            explicit_persistence = bool(rng.getrandbits(1))
            persistence_allows_deferred = bool(
                declared == "deferred" and rng.getrandbits(1)
            )
            policy = cg.terminal_stop_policy(
                whole_completion=whole_completion,
                explicit_persistence=explicit_persistence,
                persistence_allows_deferred=persistence_allows_deferred,
                declared_disposition=declared,
            )
            if whole_completion:
                self.assertEqual(policy, "gate_completion_claim")
            elif (
                explicit_persistence
                and not persistence_allows_deferred
                and declared not in {"user_wait", "external_wait"}
            ):
                self.assertEqual(policy, "gate_explicit_persistence")
            else:
                self.assertTrue(policy.startswith("yield_"), policy)
                if declared == "continue":
                    self.assertEqual(policy, "yield_continue_advisory")

        self.assertGreater(conflicts, 1_000)
        self.assertGreater(replacements, 100)

    def test_staged_wait_cannot_hide_uncheckpointed_whole_completion(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        staged, _ = self.stage_disposition("user_wait")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        result = cg.dispatch(
            self.payload("Stop", last_assistant_message="整个任务已经全部完成。")
        )
        self.assertEqual(result["decision"], "block")
        self.assertIsNone(self.state()["completion_checkpoint"])

    def test_staged_deferred_cannot_hide_direct_whole_completion(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        staged, _ = self.stage_disposition("deferred")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        result = cg.dispatch(
            self.payload("Stop", last_assistant_message="The task is complete.")
        )
        self.assertEqual(result["decision"], "block")
        self.assertEqual(
            self.state()["decision_log"][-1]["outcome"],
            "gate_completion_claim",
        )
        self.assertIsNone(self.state()["completion_checkpoint"])

    def test_private_checkpoint_passes_without_reply_metadata(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        snapshot = cg.checkpoint_status(
            self.root / "private",
            "session-a",
            self.current_turn,
            "test-token",
        )
        self.assertEqual(
            snapshot["recent_successful_evidence"][-1]["id"], evidence_id
        )
        receipt = self.stage_all(evidence_id)
        self.assertRegex(receipt["checkpoint_sha256"], r"^[0-9a-f]{64}$")
        message = "已修复并推送，验证结果均符合要求。"
        self.assertNotIn("context-guard", message)
        self.assertEqual(
            cg.dispatch(self.payload("Stop", last_assistant_message=message)), {}
        )
        final = self.state()
        self.assertTrue(
            all(item["status"] == "pass" for item in final["requirements"])
        )
        self.assertEqual(
            final["completion_checkpoint"]["turn_id"], self.current_turn
        )
        self.assertIsNone(final["completion_attempt"])
        self.assertEqual(final["open_items"], [])

    def test_completion_without_tracked_items_needs_no_checkpoint(self) -> None:
        self.prompt("context-guard on")
        result = cg.dispatch(
            self.payload(
                "Stop",
                last_assistant_message="The requested verification is complete.",
            )
        )
        self.assertNotIn("decision", result)
        self.assertIsNone(self.state()["completion_checkpoint"])

    def test_legacy_inline_checkpoint_is_rejected(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        checkpoint = {
            "status": "complete",
            "requirements": {"R001": {"status": "pass", "evidence": [evidence_id]}},
            "acceptance": {"A001": {"status": "pass", "evidence": [evidence_id]}},
            "open_items": [],
        }
        message = (
            "任务已完成。\n<!-- context-guard-checkpoint\n"
            + json.dumps(checkpoint, ensure_ascii=False)
            + "\n-->"
        )
        result = cg.dispatch(self.payload("Stop", last_assistant_message=message))
        self.assertEqual(result["decision"], "block")
        self.assertIn("legacy inline checkpoint", result["reason"])
        self.assertEqual(self.state()["requirements"][0]["status"], "pending")

    def test_private_checkpoint_commands_are_rejected_from_user_reply(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        self.stage_all(evidence_id)
        result = cg.dispatch(
            self.payload(
                "Stop",
                last_assistant_message=(
                    "任务已经完成。内部命令为 stage-checkpoint --requirement "
                    f"R001={evidence_id}"
                ),
            )
        )
        self.assertEqual(result["decision"], "block")
        self.assertIn("private checkpoint metadata", result["reason"])
        self.assertIsNone(self.state()["completion_checkpoint"])

    def test_stop_privacy_classifier_separates_explanation_control_and_ambiguity(
        self,
    ) -> None:
        explanatory = (
            "文档只说明 `checkpoint-status`、STAGE-CHECKPOINT 和 register-proof；"
            "另见 /tmp/stage-checkpoint.log、https://example.test/checkpoint-status "
            "与 tests/stage-checkpoint-fixture.json；CONTEXT_GUARD_DATA_DIR "
            "只是变量名称。"
        )
        self.assertEqual(
            cg.classify_private_metadata(explanatory),
            ("explanatory_reference", ["bare_control_reference"]),
        )
        sensitive_cases = (
            "stage-checkpoint --requirement R001=E0001",
            "`checkpoint-status`：--token redacted-token",
            "The private argument was --token redacted-token.",
            "CONTEXT_GUARD_DATA_DIR=/private/example checkpoint-status",
            '{"token":"redacted"}',
            '{"command":"stage-checkpoint","token":"redacted","turn_id":"turn-a"}',
        )
        for text in sensitive_cases:
            with self.subTest(text=text):
                category, reasons = cg.classify_private_metadata(text)
                self.assertEqual(category, "sensitive_control")
                self.assertTrue(reasons)
        category, reasons = cg.classify_private_metadata(
            "The fragment ends with stage-disposition --disposition"
        )
        self.assertEqual(category, "ambiguous_control_fragment")
        self.assertEqual(reasons, ["incomplete_control_invocation"])

        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        self.stage_all(evidence_id)
        result = cg.dispatch(
            self.payload(
                "Stop",
                last_assistant_message=(
                    "任务已经完成。故障说明仅提到 checkpoint-status 与 "
                    "stage-checkpoint 两个命令名称。"
                ),
            )
        )
        self.assertEqual(result, {})
        self.assertTrue(
            all(item["status"] == "pass" for item in self.state()["requirements"])
        )

    def test_failed_or_unknown_evidence_cannot_be_staged(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        failed = self.record_tool(response={"exit_code": 1, "output": "FAIL"})
        with self.assertRaisesRegex(ValueError, "non-success evidence"):
            self.stage_all(failed)
        unknown = self.record_tool(
            response={"output": "Verification could not be completed"}
        )
        with self.assertRaisesRegex(ValueError, "outcome=unknown"):
            self.stage_all(unknown)
        with self.assertRaisesRegex(ValueError, "unknown evidence"):
            self.stage_all("E9999")
        self.assertIsNone(
            self.state()["completion_attempt"]["staged_control"]
        )

    def test_private_checkpoint_is_bound_to_turn_and_token(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        first_turn = self.current_turn
        self.prompt("继续验证另一个步骤。")
        with self.assertRaisesRegex(RuntimeError, "different turn"):
            cg.checkpoint_status(
                self.root / "private",
                "session-a",
                first_turn,
                "test-token",
            )
        with self.assertRaisesRegex(RuntimeError, "invalid private completion token"):
            cg.checkpoint_status(
                self.root / "private",
                "session-a",
                self.current_turn,
                "wrong-token",
            )

    def test_invalid_staged_checkpoint_does_not_mutate_state(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        session_dir = self.root / "private" / "sessions" / "session-a"
        state = self.state()
        state["completion_attempt"]["staged_control"] = {
            "kind": "checkpoint",
            "checkpoint": {
                "status": "complete",
                "requirements": {
                    "R001": {"status": "pass", "evidence": [evidence_id]}
                },
                "acceptance": {},
                "open_items": [],
            },
        }
        cg.save_state(session_dir, state)
        result = cg.dispatch(
            self.payload("Stop", last_assistant_message="任务已经完成。")
        )
        self.assertEqual(result["decision"], "block")
        final = self.state()
        self.assertEqual(final["requirements"][0]["status"], "pending")
        self.assertIsNone(final["completion_checkpoint"])

    def test_corrupt_staged_checkpoint_fails_closed(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        state = self.state()
        state["completion_attempt"]["staged_control"] = {
            "kind": "checkpoint",
            "checkpoint": "corrupt",
        }
        cg.save_state(session_dir, state)
        result = cg.dispatch(
            self.payload("Stop", last_assistant_message="任务已经完成。")
        )
        self.assertEqual(result["decision"], "block")
        self.assertIn("invalid staged private", result["reason"])
        self.assertIsNone(self.state()["completion_checkpoint"])

    def test_only_high_confidence_whole_task_completion_phrases_are_detected(
        self,
    ) -> None:
        for message in (
            "整个任务已全部完成，所有要求与验收项均已满足。",
            "All requested work is complete and every requirement is satisfied.",
            "The entire task is finished with all acceptance criteria met.",
        ):
            with self.subTest(message=message):
                self.assertTrue(cg.claims_whole_completion(message))
        for local_milestone in (
            "已修复并推送。",
            "处理好了，可以交付。",
            "29 项回归测试全量通过。",
            "Fixed, verified, and pushed.",
            "All regression tests passed.",
        ):
            with self.subTest(local_milestone=local_milestone):
                self.assertFalse(cg.claims_whole_completion(local_milestone))

    def test_examples_hypotheticals_and_attributed_quotes_are_not_completion_claims(
        self,
    ) -> None:
        examples = (
            "A team may call the task complete after unit tests alone.",
            'The docs say "the task is complete" only after validation.',
            "Calling the task complete after unit tests alone would be unsafe.",
            "Example:\n> The task is complete.",
            "示例里写着“整个任务已全部完成”，但那只是反例。",
            "假设有人宣称整个任务已全部完成，我们仍应检查证据。",
        )
        for message in examples:
            with self.subTest(message=message):
                self.assertFalse(cg.claims_whole_completion(message))

        direct_claims = (
            "The task is complete.",
            "> The task is complete.",
            "I can confirm the task is complete.",
            "I consider the task complete.",
            "整个任务已全部完成，所有要求均已满足。",
        )
        for message in direct_claims:
            with self.subTest(message=message):
                self.assertTrue(cg.claims_whole_completion(message))

    def test_real_session_blog_example_does_not_trigger_completion_gate(self) -> None:
        self.prompt(
            "$context-guard\n继续查看补充材料并给出建议，但不要修改仓库或博客。"
        )
        staged, _ = self.stage_disposition("deferred")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        message = (
            "看完补充材料后，我会调整上一轮的判断：保留“1M 上下文”这个热点，"
            "但不把文章写成 Codex 新闻或配置教程。\n\n"
            "> A European SaaS team asks an agent to migrate its authentication "
            "service. After a long run or handoff, the agent may call the task "
            "complete after unit tests alone.\n\n"
            "本轮没有修改仓库、文章或平台内容。"
        )
        observed = cg.classify_stop_decision(
            message,
            "继续查看补充材料并给出建议，但不要修改仓库或博客。",
        )
        self.assertEqual(observed["outcome"], "allow_external_wait")
        self.assertEqual(observed["actions"], [])
        self.assertFalse(cg.claims_whole_completion(message))
        self.assertEqual(
            cg.dispatch(self.payload("Stop", last_assistant_message=message)),
            {},
        )
        decision = self.state()["decision_log"][-1]
        self.assertEqual(decision["observed_outcome"], "allow_external_wait")
        self.assertEqual(decision["outcome"], "allow_out_of_scope_deferred")
        self.assertEqual(self.state()["continuation_attempts"], 0)

    def test_classifier_22_whole_completion_plurals_questions_and_attribution(
        self,
    ) -> None:
        claims = (
            "All tasks are complete.",
            "The tasks are complete.",
            "All items are complete.",
            "Every requirement is done.",
            "All requirements are satisfied.",
            "We report the task is complete.",
            "I report that the task is complete.",
            "As I said, the task is complete.",
            "任务都完成了。",
        )
        for message in claims:
            with self.subTest(message=message):
                self.assertTrue(cg.claims_whole_completion(message))
        non_claims = (
            "Do I consider the task complete? No, it is not.",
            (
                "I asked myself whether I consider the task complete, "
                "and the answer is no."
            ),
            "The task is complete?",
            "他说整个任务已全部完成。",
            "我们假设整个任务已全部完成。",
            "The team reported the task is complete.",
        )
        for message in non_claims:
            with self.subTest(message=message):
                self.assertFalse(cg.claims_whole_completion(message))

    def test_future_action_binding_ignores_negated_topical_mentions(self) -> None:
        prompt = "继续完成修复，配置运行时并修改仓库。"
        topical = (
            "我会调整上一轮的判断：保留 1M 热点，"
            "但不把文章写成 Codex 新闻或配置教程。"
        )
        topical_decision = cg.classify_stop_decision(topical, prompt)
        self.assertEqual(topical_decision["outcome"], "allow_neutral")
        self.assertEqual(topical_decision["actions"], [])

        actionable = "我会继续配置运行时并修改仓库。"
        actionable_decision = cg.classify_stop_decision(actionable, prompt)
        self.assertEqual(
            actionable_decision["outcome"], "gate_authorized_remaining_work"
        )
        self.assertTrue(
            any(
                action["category"] == "artifact_work"
                and action["authorization"] == "authorized"
                for action in actionable_decision["actions"]
            )
        )

        for contrastive in (
            "I won't publish, but I will configure the runtime.",
            "我不会发布，但我会继续配置运行时。",
        ):
            with self.subTest(contrastive=contrastive):
                contrastive_decision = cg.classify_stop_decision(
                    contrastive, prompt
                )
                self.assertTrue(
                    any(
                        action["category"] == "artifact_work"
                        for action in contrastive_decision["actions"]
                    )
                )

        for documentation_action in (
            "I will review documentation.",
            "I will configure documentation.",
            "我会配置文档。",
        ):
            with self.subTest(documentation_action=documentation_action):
                documentation_decision = cg.classify_stop_decision(
                    documentation_action, prompt
                )
                self.assertTrue(
                    any(
                        action["owner"] == "assistant"
                        for action in documentation_decision["actions"]
                    )
                )

    def test_explicit_incomplete_report_defaults_to_safe_yield(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        result = cg.dispatch(
            self.payload(
                "Stop",
                last_assistant_message="任务尚未完成，因为外部服务被阻塞。",
            )
        )
        self.assertEqual(result, {})
        implemented_but_remaining = cg.dispatch(
            self.payload(
                "Stop",
                last_assistant_message="Core code is implemented; remaining tests still need work.",
            )
        )
        self.assertEqual(implemented_but_remaining, {})
        self.assertEqual(self.state()["continuation_attempts"], 0)
        self.assertTrue(self.state()["open_items"])

    def test_partial_milestone_reports_do_not_trigger_continuations(self) -> None:
        self.prompt(
            "实现完整论文处理系统。必须导入论文并完成 PDF 阶段，"
            "必须执行测试并提供验收证据。"
        )
        messages = (
            "已推进到首个写入确认门；尚未导入论文。14 项回归测试全量通过。",
            "Pilot 阶段已通过，但整个任务尚未结束；下一批等待确认。",
            "当前不能宣告整个任务完成：pilot 已审计通过。",
            "Formal metadata 审计通过；整体任务仍待 PDF 阶段。15 项回归均通过。",
            "已处理 BLADE；原始任务尚未全部完成，剩余 PDF 等待批次确认。",
        )
        for message in messages:
            with self.subTest(message=message):
                result = cg.dispatch(
                    self.payload("Stop", last_assistant_message=message)
                )
                self.assertFalse(cg.claims_whole_completion(message))
                self.assertEqual(result, {})
        self.assertEqual(self.state()["continuation_attempts"], 0)

    def test_user_decision_gated_reports_do_not_trigger_continuations(self) -> None:
        self.prompt(
            "实现并发布开源项目。必须先让用户验收，得到明确授权后才能公开。"
        )
        messages = (
            (
                "这些技术检查我已经完成。你主要需要确认这个项目是否可以公开。"
                "如果四项都接受，请回复“验收通过，可以公开”。"
            ),
            (
                "当前无法继续安全执行，因为下一步会创建公开 GitHub 仓库，"
                "必须先得到你的明确授权。请回复“验收通过，可以公开”。"
            ),
            (
                "当前仍在等待你的验收决定，没有新的可执行事项。"
                "请回复“验收通过，可以公开”。"
            ),
            "Local validation is complete; waiting for your approval before publication.",
            "The candidate is ready, but I cannot proceed without user authorization.",
        )
        for message in messages:
            with self.subTest(message=message):
                self.assertFalse(cg.claims_completion(message))
                self.assertEqual(
                    cg.dispatch(
                        self.payload("Stop", last_assistant_message=message)
                    ),
                    {},
                )
        self.assertEqual(self.state()["continuation_attempts"], 0)

    def test_explicit_user_action_handoffs_do_not_trigger_continuations(self) -> None:
        self.prompt(
            "$context-guard\n完成跨平台发布计划。必须先让用户处理账号登录、配置和审批。"
        )
        messages = (
            (
                "两仓库的发布准备已完成，但尚未发布正式版本。"
                "目前被 GitHub 登录失效阻塞。请先运行 gh auth login，"
                "完成后回复“已登录”。"
            ),
            (
                "Context Guard 已正式发布。只有账号登录、2FA 和 Pending "
                "Publisher 确认必须由你操作。"
            ),
            (
                "TestPyPI 上传与安装测试已通过。请添加正式 Publisher，"
                "配置后告诉我“PyPI publisher 配好了”。"
            ),
            (
                "构建与包检查已通过。现在正式 PyPI 发布正等待你批准。"
                "批准后回复“已批准”。"
            ),
            (
                "正式 PyPI 已全部完成。下一步需要你这样做：在 Chrome 打开"
                " Marketplace 提交页，登录后回复我。"
            ),
            (
                "Local checks are complete, but I need you to log in to GitHub "
                "and reply when ready."
            ),
            (
                "Build and package verification passed; waiting for the user to "
                "approve the production deployment."
            ),
            (
                "TestPyPI is verified. Please configure the PyPI publisher, then "
                "respond."
            ),
        )
        for message in messages:
            with self.subTest(message=message):
                self.assertFalse(cg.claims_completion(message))
                self.assertEqual(
                    cg.dispatch(
                        self.payload("Stop", last_assistant_message=message)
                    ),
                    {},
                )
        self.assertEqual(self.state()["continuation_attempts"], 0)

    def test_user_handoff_and_assistant_future_are_owner_separated(self) -> None:
        broad_prompt = "完成完整认证计划，继续测试、提交并推送。"
        allowed = (
            (
                "Mac 当前锁定。请先手动解锁 Mac 和登录钥匙串，然后回复“已解锁”。",
                "allow_user_handoff",
            ),
            (
                "Git 和 CLI 已验证。请确认是否重新登录 GitHub Desktop。",
                "allow_user_handoff",
            ),
            (
                "请先解锁钥匙串，完成后我会继续提交并推送。",
                "allow_user_handoff",
            ),
            (
                "Please unlock the keychain; once you confirm, I will continue tests and push.",
                "allow_user_handoff",
            ),
        )
        for reply, expected in allowed:
            with self.subTest(reply=reply):
                decision = cg.classify_stop_decision(reply, broad_prompt)
                self.assertEqual(decision["outcome"], expected)
                self.assertTrue(
                    any(action["owner"] == "user" for action in decision["actions"])
                )

        gated = (
            "请先解锁钥匙串；我会在等待期间继续修改仓库并推送。",
            "请先登录 GitHub Desktop，同时我会继续运行测试。",
            "请先确认 GitHub Desktop 登录。我会继续提交并推送。",
            "Please sign in to GitHub Desktop; meanwhile I will continue tests and push.",
        )
        for reply in gated:
            with self.subTest(reply=reply):
                decision = cg.classify_stop_decision(reply, broad_prompt)
                self.assertEqual(
                    decision["outcome"], "gate_authorized_remaining_work"
                )
                self.assertTrue(
                    any(
                        action["owner"] == "assistant"
                        and action["authorization"] == "authorized"
                        for action in decision["actions"]
                    )
                )

    def test_classifier_diagnostics_cover_cross_sentence_and_abbreviation_blind_spots(
        self,
    ) -> None:
        cases = (
            (
                "继续完成 H.O.L. 所有权验证。",
                "请点击账号。完成后告诉我；随后我会继续 H.O.L. 所有权验证。",
                "allow_user_handoff",
            ),
            (
                "Continue the H.O.L. ownership check after sign-in.",
                (
                    "Please choose the account. When that's done, tell me; afterwards "
                    "I'll continue the H.O.L. ownership check."
                ),
                "allow_user_handoff",
            ),
            (
                "完成目录发布，但等待外部审核。",
                (
                    "PR #351 remains under external review; H.O.L., CI, and promotion "
                    "are paused—no repository work is running."
                ),
                "allow_external_wait",
            ),
            (
                "只审查并本地提交；不要推送或运行 CI/CD。",
                "本地提交已完成——push、CI/CD 与 v0.7.0 发布留待后续阶段。",
                "allow_out_of_scope_deferred",
            ),
        )
        punctuation_variants = {
            ";": ("；", "。", "—"),
            "；": (";", "。", "—"),
            "——": (";", "；", "。"),
            "H.O.L.": ("HOL", "H.O.L", "H-O-L"),
            "CI/CD": ("CI", "C.I.", "CI + CD"),
        }
        for prompt, reply, expected in cases:
            variants = {reply}
            for needle, replacements in punctuation_variants.items():
                if needle not in reply:
                    continue
                variants.update(reply.replace(needle, value) for value in replacements)
            for variant in sorted(variants):
                with self.subTest(expected=expected, reply=variant):
                    decision = cg.classify_stop_decision(variant, prompt)
                    self.assertEqual(decision["outcome"], expected)

    def test_mixed_handoff_respects_bounded_action_authority(self) -> None:
        reply = "请先解锁钥匙串；我会在等待期间继续修改仓库并推送。"
        cases = (
            (
                "只审查登录问题，不要修改仓库或推送。",
                "allow_out_of_scope_deferred",
            ),
            (
                "继续完成全部认证修复，修改仓库并推送。",
                "gate_authorized_remaining_work",
            ),
        )
        for prompt, expected in cases:
            with self.subTest(prompt=prompt):
                self.assertEqual(
                    cg.classify_stop_decision(reply, prompt)["outcome"], expected
                )

    def test_external_review_and_policy_hold_reports_do_not_trigger(self) -> None:
        self.prompt(
            "$context-guard\n完成发布计划，但遵守用户暂停推广和等待外部审核的决定。"
        )
        messages = (
            (
                "已处理并恢复当前状态：OpenAI Case 12876647 已记录为正式结论，"
                "暂不走官方 Hook 插件投稿，不提交 skills-only 降级版。两个 "
                "Showcase、HOL PR #351、Awesome Codex CLI PR #185 均保持"
                "‘已提交、等待审核’。推广仍按你的要求暂停。没有重复发布，"
                "也没有修改两个项目仓库。"
            ),
            (
                "本轮状态同步已完成：申请已提交，仍待第三方审核；发布继续暂停，"
                "没有新的仓库修改。"
            ),
            (
                "Status synchronization is complete. The PR remains pending "
                "external review; promotion is on hold and no repository changes "
                "were made."
            ),
            (
                "Local verification passed. The submission is awaiting platform "
                "selection, and publishing is currently paused."
            ),
        )
        for message in messages:
            with self.subTest(message=message):
                self.assertTrue(cg.reports_non_completion(message))
                self.assertFalse(cg.claims_completion(message))
                self.assertEqual(
                    cg.dispatch(
                        self.payload("Stop", last_assistant_message=message)
                    ),
                    {},
                )
        self.assertEqual(self.state()["continuation_attempts"], 0)

    def test_status_wording_keeps_assistant_followups_diagnostic_only(self) -> None:
        messages = (
            "状态已更新并验证通过。接下来我会提交 PR、更新博客并继续推广。",
            "PR 已提交。接下来我会检查审核日志、发布版本并修改仓库。",
            "Status is verified. Next I will publish and update the repository.",
        )
        for message in messages:
            with self.subTest(message=message):
                prompt = "$context-guard\n完成仍由代理负责的发布和仓库更新。"
                self.prompt(prompt)
                self.assertFalse(cg.reports_non_completion(message))
                self.assertTrue(
                    cg.classify_stop_decision(message, prompt)["outcome"].startswith(
                        "gate_"
                    )
                )
                self.assertFalse(cg.claims_completion(message))
                result = cg.dispatch(
                    self.payload("Stop", last_assistant_message=message)
                )
                self.assertEqual(result, {})
                self.assertEqual(self.state()["continuation_attempts"], 0)
                self.assertTrue(self.state()["open_items"])

    def test_actionable_remaining_work_without_disposition_safely_yields(self) -> None:
        prompt = "$context-guard\n完成完整推广计划。必须提交目录、更新博客并发布社区帖子。"
        self.prompt(prompt)
        message = (
            "Marketplace 这一项已完成并验证通过。整体推广计划仍有 HOL 审核、"
            "Showcase、博客及社区发帖等后续项。"
        )
        self.assertTrue(
            cg.classify_stop_decision(message, prompt)["outcome"].startswith(
                "gate_"
            )
        )
        self.assertFalse(cg.claims_completion(message))
        result = cg.dispatch(
            self.payload("Stop", last_assistant_message=message)
        )
        self.assertEqual(result, {})
        self.assertEqual(self.state()["continuation_attempts"], 0)
        self.assertTrue(self.state()["open_items"])

    def test_bounded_turn_can_defer_a_later_phase_without_continuation(self) -> None:
        cases = (
            (
                "$context-guard\nreview一下两个仓库的改动，没问题就提交",
                (
                    "两个仓库已审查并分别完成本地提交，未推送。验证均通过。"
                    "下一阶段仍需创建 PRIVATE 远程仓库、推送并运行 CI。"
                ),
            ),
            (
                "$context-guard\nReview both repositories and commit them if clean.",
                (
                    "Both repositories are reviewed, verified, and committed locally. "
                    "The next phase still requires creating the private remote, "
                    "pushing, and running CI."
                ),
            ),
            (
                "$context-guard\n只审查并本地提交，不要推送或运行 CI。",
                (
                    "两个仓库已审查并分别完成本地提交，未推送。验证均通过。"
                    "下一阶段仍需创建 PRIVATE 远程仓库、推送并运行 CI。"
                ),
            ),
            (
                "$context-guard\nReview and commit locally; do not push or run CI.",
                (
                    "Both repositories are reviewed, verified, and committed locally. "
                    "The next phase still requires creating the private remote, "
                    "pushing, and running CI."
                ),
            ),
        )
        for prompt, message in cases:
            with self.subTest(prompt=prompt):
                self.prompt(prompt)
                self.assertTrue(cg.reports_non_completion(message, prompt))
                self.assertFalse(cg.claims_completion(message, prompt))
                self.assertEqual(
                    cg.dispatch(
                        self.payload("Stop", last_assistant_message=message)
                    ),
                    {},
                )
        self.assertEqual(self.state()["continuation_attempts"], 0)

    def test_broad_execution_prompt_without_persistence_defaults_to_safe_yield(
        self,
    ) -> None:
        cases = (
            (
                "$context-guard\n继续执行完整发布计划，创建远端、推送并等待 CI。",
                (
                    "两个仓库已审查并分别完成本地提交，未推送。"
                    "验证均通过。下一阶段仍需创建 PRIVATE 远程仓库、"
                    "推送并运行 CI。"
                ),
            ),
            (
                "$context-guard\nContinue the whole release plan, push, and run CI.",
                (
                    "Both repositories are reviewed, verified, and committed locally. "
                    "The next phase still requires creating the private remote, "
                    "pushing, and running CI."
                ),
            ),
            (
                "$context-guard\nReview the local checkpoint only. "
                + ("bounded scope detail " * 70)
                + "\nThen push and run CI.",
                (
                    "Both repositories are reviewed, verified, and committed locally. "
                    "The next phase still requires creating the private remote, "
                    "pushing, and running CI."
                ),
            ),
            (
                "$context-guard\n不要跳过推送，继续执行完整发布计划。",
                (
                    "两个仓库已审查并分别完成本地提交，未推送。"
                    "验证均通过。下一阶段仍需创建 PRIVATE 远程仓库、"
                    "推送并运行 CI。"
                ),
            ),
        )
        for prompt, message in cases:
            with self.subTest(prompt=prompt):
                self.prompt(prompt)
                self.assertFalse(cg.reports_non_completion(message, prompt))
                self.assertEqual(
                    cg.classify_stop_decision(message, prompt)["outcome"],
                    "gate_authorized_remaining_work",
                )
                self.assertFalse(cg.claims_completion(message, prompt))
                result = cg.dispatch(
                    self.payload("Stop", last_assistant_message=message)
                )
                self.assertEqual(result, {})
                self.assertEqual(self.state()["continuation_attempts"], 0)
                self.assertTrue(self.state()["open_items"])

    def test_structured_boundary_classifier_covers_regression_session_cases(self) -> None:
        cases = (
            (
                "只审查并本地提交，不要创建远端仓库、推送或运行 CI。",
                "本地审查已完成并验证通过；远端创建、推送与 CI 留待下一轮。",
                "allow_out_of_scope_deferred",
            ),
            (
                "只审查并本地提交。",
                "本地提交已完成；推送和 CI 将在后续单独处理。",
                "allow_out_of_scope_deferred",
            ),
            (
                "Review and commit locally.",
                "Local commit is complete; push and CI are deferred to a later turn.",
                "allow_out_of_scope_deferred",
            ),
            (
                "暂不推送，也不跑 CI。",
                "本地验证已完成；推送和 CI 将在后续单独处理。",
                "allow_out_of_scope_deferred",
            ),
            (
                "No push or CI.",
                "Local validation is complete; push and CI are deferred to a later turn.",
                "allow_out_of_scope_deferred",
            ),
            (
                "提交 PR 并处理后续审查意见。",
                "PR 已提交；下一阶段仍需处理审查意见。",
                "gate_authorized_remaining_work",
            ),
            (
                "完成发布并等待外部审核。",
                "PR仍待外部审核；与此同时我接下来会修改仓库并发布博客。验证已通过。",
                "gate_authorized_remaining_work",
            ),
        )
        for prompt, reply, expected in cases:
            with self.subTest(prompt=prompt):
                decision = cg.classify_stop_decision(reply, prompt)
                self.assertEqual(decision["outcome"], expected)
        mixed = cg.classify_stop_decision(cases[-1][1], cases[-1][0])
        self.assertIn("mixed_external_and_assistant_work", mixed["reason_codes"])

    def test_boundary_classifier_is_scope_metamorphic_and_handles_double_negation(self) -> None:
        reply = "本地验证已完成；推送和 CI 将在后续单独处理。"
        cases = (
            ("只做本地检查。", "allow_out_of_scope_deferred"),
            ("暂不推送，也不跑 CI。", "allow_out_of_scope_deferred"),
            ("继续执行完整发布计划，推送并运行 CI。", "gate_authorized_remaining_work"),
            ("不要跳过推送，继续执行完整发布计划。", "gate_authorized_remaining_work"),
        )
        for prompt, expected in cases:
            with self.subTest(prompt=prompt):
                self.assertEqual(
                    cg.classify_stop_decision(reply, prompt)["outcome"], expected
                )

    def test_decision_log_is_bounded_hash_only_and_diagnosable(self) -> None:
        secret_prompt = "$context-guard\n完成复杂任务，token=private-prompt-value。"
        secret_reply = "验证已通过，private-reply-value；下一阶段仍需运行测试。"
        self.prompt(secret_prompt)
        for _ in range(cg.DECISION_LOG_LIMIT + 5):
            cg.dispatch(self.payload("Stop", last_assistant_message=secret_reply))
            state = self.state()
            state["continuation_attempts"] = 0
            cg.save_state(
                self.root / "private" / "sessions" / "session-a", state
            )
        state = self.state()
        self.assertEqual(len(state["decision_log"]), cg.DECISION_LOG_LIMIT)
        serialized = json.dumps(state["decision_log"], ensure_ascii=False)
        self.assertNotIn("private-prompt-value", serialized)
        self.assertNotIn("private-reply-value", serialized)
        latest = state["decision_log"][-1]
        self.assertEqual(latest["prompt_sha256"], cg.sha256_text(secret_prompt))
        self.assertEqual(latest["reply_sha256"], cg.sha256_text(secret_reply))
        self.assertEqual(latest["classifier_version"], cg.CLASSIFIER_VERSION)
        self.assertIn("classifier=", cg.status_context(state))

        result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "diagnose", "--limit", "2"],
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        diagnosed = json.loads(result.stdout)
        self.assertEqual(len(diagnosed["decisions"]), 2)
        self.assertNotIn("private-reply-value", result.stdout)

    def test_tampered_full_prompt_record_fails_closed(self) -> None:
        prompt = (
            "$context-guard\nReview the local checkpoint only. "
            + ("bounded scope detail " * 70)
            + "\nThen push and run CI."
        )
        message = (
            "Both repositories are reviewed, verified, and committed locally. "
            "The next phase still requires creating the private remote, "
            "pushing, and running CI."
        )
        self.prompt(prompt)
        session_dir = self.root / "private" / "sessions" / "session-a"
        record_path = session_dir / "prompts" / "P0001.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["text"] = "$context-guard\nReview the local checkpoint only."
        record_path.write_text(json.dumps(record), encoding="utf-8")

        self.assertEqual(cg.latest_requirement_text(session_dir, self.state()), "")
        result = cg.dispatch(self.payload("Stop", last_assistant_message=message))
        self.assertFalse(result["continue"])
        self.assertIn("prompt boundary", result["stopReason"])
        self.assertEqual(
            self.state()["decision_log"][-1]["outcome"],
            "fail_closed_integrity",
        )

    def test_assistant_owned_followups_remain_diagnostic_without_disposition(
        self,
    ) -> None:
        messages = (
            "全部检查已通过。接下来需要打开页面并继续配置。",
            "配置完成后通知用户，然后继续处理发布。测试已通过。",
            "All tests passed. Next I need to open the page and continue configuration.",
            "All tests passed. After configuration, I will notify the user and continue.",
        )
        for message in messages:
            with self.subTest(message=message):
                prompt = "$context-guard\n继续完成仍由代理负责的发布工作。"
                self.prompt(prompt)
                self.assertTrue(
                    cg.classify_stop_decision(message, prompt)["outcome"].startswith(
                        "gate_"
                    )
                )
                self.assertFalse(cg.claims_completion(message))
                result = cg.dispatch(
                    self.payload("Stop", last_assistant_message=message)
                )
                self.assertEqual(result, {})
                self.assertEqual(self.state()["continuation_attempts"], 0)
                self.assertTrue(self.state()["open_items"])

    def test_synthetic_forgotten_boundary_cannot_complete(self) -> None:
        self.prompt(
            "\n".join(
                [
                    "处理合成报销任务：",
                    "- 必须填写每条行程路线",
                    "- 必须填写事由",
                    "- 必须执行零静默错误验证",
                    "- 缺失字段时不得宣称完成",
                ]
            )
        )
        result = cg.dispatch(
            self.payload("Stop", last_assistant_message="全部完成。")
        )
        self.assertEqual(result["decision"], "block")
        for item in self.state()["acceptance_items"]:
            self.assertIn(item["id"], result["reason"])

    def test_redacted_export_is_project_bounded(self) -> None:
        secret = "sk-" + "1234567890abcdefghijkl"
        self.prompt(
            "实现复杂插件，必须验证 token="
            + secret
            + " 且 URL https://example.test/path?token=visible-secret&benign=value。"
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        state = self.state()
        target = cg.export_handoff(session_dir, state, "handoff/CONTEXT_HANDOFF.md")
        content = target.read_text(encoding="utf-8")
        self.assertNotIn(secret, content)
        self.assertNotIn("visible-secret", content)
        self.assertNotIn("benign=value", content)
        self.assertIn("https://example.test/path?[QUERY_REDACTED]", content)
        self.assertIn("[REDACTED]", content)
        raw = next((session_dir / "prompts").glob("*.json")).read_text(encoding="utf-8")
        self.assertIn(secret, raw)
        quoted = cg.export_handoff(
            session_dir, state, '"handoff with spaces/CONTEXT_HANDOFF.md"'
        )
        self.assertTrue(quoted.exists())
        with self.assertRaises(ValueError):
            cg.export_handoff(session_dir, state, "../outside.md")

    def test_successor_pack_is_bounded_hash_verified_and_non_authorizing(self) -> None:
        self.prompt(
            "实现复杂插件，必须保留权限边界，必须验证交接清单，且不得自动创建新任务。"
        )
        current = self.project / "current.py"
        current.write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")
        historical = self.project / "history.log"
        historical.write_text("verified historical evidence\n", encoding="utf-8")
        self.write_successor_input(
            current_step_reads=[
                {
                    "path": "current.py",
                    "purpose": "Continue the current implementation.",
                    "read_mode": "lines",
                    "line_ranges": [[2, 3]],
                }
            ],
            audit_only_files=[
                {
                    "path": "history.log",
                    "purpose": "Hash-only historical verification.",
                }
            ],
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        state = self.state()

        output = cg.export_successor_pack(
            session_dir, state, "handoff/successor-001"
        )

        manifest = json.loads(
            (output / cg.SUCCESSOR_MANIFEST_FILENAME).read_text(encoding="utf-8")
        )
        handoff = (output / cg.SUCCESSOR_HANDOFF_FILENAME).read_text(
            encoding="utf-8"
        )
        self.assertFalse(manifest["authority"]["grants_new_authority"])
        self.assertTrue(manifest["authority"]["requirements_remain_authoritative"])
        self.assertEqual(manifest["current_step_reads"][0]["path"], "current.py")
        self.assertEqual(
            manifest["current_step_reads"][0]["sha256"],
            hashlib.sha256(current.read_bytes()).hexdigest(),
        )
        self.assertEqual(manifest["audit_only_files"][0]["path"], "history.log")
        self.assertEqual(manifest["budgets"]["targeted_lines"], 2)
        self.assertEqual(
            manifest["handoff"]["sha256"],
            hashlib.sha256(handoff.encode("utf-8")).hexdigest(),
        )
        self.assertNotIn(state["session"]["id"], handoff)
        self.assertIn("grants no new permission", handoff)

    def test_successor_pack_rejects_path_escape_and_overwrite(self) -> None:
        self.prompt(
            "实现复杂插件。必须验证交接路径，必须防止覆盖，且不得扩大权限。"
        )
        outside = self.root / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        self.write_successor_input(
            current_step_reads=[
                {
                    "path": "../outside.txt",
                    "purpose": "Invalid escape.",
                    "read_mode": "full",
                }
            ]
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        state = self.state()
        with self.assertRaisesRegex(ValueError, "inside the current project"):
            cg.export_successor_pack(session_dir, state, "handoff/escape")

        current = self.project / "current.txt"
        current.write_text("current\n", encoding="utf-8")
        self.write_successor_input(
            current_step_reads=[
                {
                    "path": "current.txt",
                    "purpose": "Valid current file.",
                    "read_mode": "full",
                }
            ]
        )
        first = cg.export_successor_pack(session_dir, state, "handoff/stable")
        self.assertTrue(first.is_dir())
        with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
            cg.export_successor_pack(session_dir, state, "handoff/stable")

    def test_successor_pack_requires_explicit_input_and_does_not_create_task(self) -> None:
        self.prompt(
            "实现复杂插件。必须显式准备交接输入，且不得自动创建或退役任务。"
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        with self.assertRaisesRegex(ValueError, "missing successor input"):
            cg.export_successor_pack(session_dir, self.state())

    def test_successor_pack_rejects_symlinked_input(self) -> None:
        self.prompt(
            "实现复杂插件。必须限制交接输入范围，必须验证文件身份，且不得扩大权限。"
        )
        input_path = self.write_successor_input()
        outside = self.root / "outside-successor-input.json"
        input_path.replace(outside)
        try:
            input_path.symlink_to(outside)
        except OSError:
            self.skipTest("symlinks unavailable")
        session_dir = self.root / "private" / "sessions" / "session-a"

        with self.assertRaisesRegex(ValueError, "must not be a symlink"):
            cg.export_successor_pack(session_dir, self.state())

        input_path.unlink()
        outside.replace(input_path)
        outside_parent = self.root / "outside-input-parent"
        input_path.parent.replace(outside_parent)
        input_path.parent.symlink_to(outside_parent, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "stay inside the current project"):
            cg.export_successor_pack(session_dir, self.state())

    def test_successor_pack_checks_budget_before_hashing(self) -> None:
        self.prompt(
            "实现复杂插件。必须在读取大文件前检查预算，必须验证边界，且不得静默放行。"
        )
        current = self.project / "large-current.bin"
        current.write_bytes(b"x" * 32)
        self.write_successor_input(
            current_step_reads=[
                {
                    "path": "large-current.bin",
                    "purpose": "Must be rejected before hashing.",
                    "read_mode": "full",
                }
            ]
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        with (
            mock.patch.object(cg, "MAX_SUCCESSOR_FULL_READ_BYTES", 16),
            mock.patch.object(cg, "inspect_regular_file") as inspect,
            self.assertRaisesRegex(ValueError, "full-read byte budget"),
        ):
            cg.export_successor_pack(session_dir, self.state())
        inspect.assert_not_called()

    def test_successor_pack_rejects_failed_authorization_evidence(self) -> None:
        self.prompt(
            "实现复杂插件。必须验证权限来源，必须拒绝失败证据，且不得扩大权限。"
        )
        failed_id = self.record_tool(response={"exit_code": 1, "output": "FAIL"})
        input_path = self.write_successor_input()
        data = json.loads(input_path.read_text(encoding="utf-8"))
        data["authorization"]["consumed"] = [
            {
                "text": "A failed operation must not establish consumed authority.",
                "source_ids": [failed_id],
            }
        ]
        input_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        session_dir = self.root / "private" / "sessions" / "session-a"

        with self.assertRaisesRegex(ValueError, "unknown IDs"):
            cg.export_successor_pack(session_dir, self.state())

    def test_cleanup_removes_only_old_ended_session(self) -> None:
        old_dir = self.root / "private" / "sessions" / "old-session"
        old_dir.mkdir(parents=True)
        old = cg.new_state(self.payload("SessionEnd", session="old-session"))
        old["session"]["ended_at"] = (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=31)
        ).isoformat()
        cg.save_state(old_dir, old)
        active_dir = self.root / "private" / "sessions" / "active-session"
        active_dir.mkdir()
        active = cg.new_state(self.payload("UserPromptSubmit", session="active-session"))
        cg.save_state(active_dir, active)
        removed = cg.cleanup_old_sessions(self.root / "private", current=active_dir)
        self.assertEqual(removed, 1)
        self.assertFalse(old_dir.exists())
        self.assertTrue(active_dir.exists())

    def test_session_end_archives_state_and_writes_recovery(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存初始边界，必须执行测试，必须提供验收证据。"
        )
        result = cg.dispatch(self.payload("SessionEnd", reason="other"))
        self.assertEqual(result, {})
        state = self.state()
        self.assertIsNotNone(state["session"]["ended_at"])
        session_dir = self.root / "private" / "sessions" / "session-a"
        recovery = json.loads(
            (session_dir / "recovery.json").read_text(encoding="utf-8")
        )
        self.assertEqual(recovery["trigger"], "SessionEnd")

    def test_concurrent_turns_are_serialized(self) -> None:
        def write(index: int) -> None:
            self.prompt(
                f"并发需求 {index}：实现步骤并验证结果。",
                session="concurrent-session",
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(write, range(20)))
        state = self.state("concurrent-session")
        self.assertEqual(len(state["prompts"]), 20)
        self.assertEqual(
            len({item["id"] for item in state["prompts"]}), 20
        )

    def test_session_lock_treats_windows_access_denied_as_contention(self) -> None:
        session_dir = self.root / "private" / "sessions" / "lock-session"
        session_dir.mkdir(parents=True)
        lock_path = session_dir / ".lock"
        lock_path.write_text("other holder", encoding="ascii")
        real_open = os.open
        open_calls = 0

        def transient_open(path: str, flags: int, mode: int) -> int:
            nonlocal open_calls
            open_calls += 1
            if open_calls == 1:
                raise PermissionError(13, "simulated Windows lock contention", path)
            return real_open(path, flags, mode)

        def release_other_holder(_: float) -> None:
            lock_path.unlink()

        with (
            mock.patch.object(cg.os, "open", side_effect=transient_open),
            mock.patch.object(cg.time, "sleep", side_effect=release_other_holder),
            cg.session_lock(session_dir),
        ):
            self.assertTrue(lock_path.exists())

        self.assertGreaterEqual(open_calls, 2)
        self.assertFalse(lock_path.exists())

    def test_session_lock_retries_windows_access_denied_after_holder_exits(self) -> None:
        session_dir = self.root / "private" / "sessions" / "lock-race-session"
        session_dir.mkdir(parents=True)
        lock_path = session_dir / ".lock"
        real_open = os.open
        open_calls = 0

        def transient_open(path: str, flags: int, mode: int) -> int:
            nonlocal open_calls
            open_calls += 1
            if open_calls == 1:
                raise PermissionError(13, "simulated vanished Windows holder", path)
            return real_open(path, flags, mode)

        with (
            mock.patch.object(cg.os, "name", "nt"),
            mock.patch.object(cg.os, "open", side_effect=transient_open),
            cg.session_lock(session_dir),
        ):
            self.assertTrue(lock_path.exists())

        self.assertGreaterEqual(open_calls, 2)
        self.assertFalse(lock_path.exists())

    def test_session_lock_rejects_unrelated_posix_permission_error(self) -> None:
        session_dir = self.root / "private" / "sessions" / "lock-error-session"
        session_dir.mkdir(parents=True)

        with (
            mock.patch.object(cg.os, "name", "posix"),
            mock.patch.object(
                cg.os,
                "open",
                side_effect=PermissionError(13, "simulated permission failure"),
            ),
            self.assertRaises(PermissionError),
        ):
            with cg.session_lock(session_dir):
                self.fail("unrelated POSIX permission errors must not be retried")

    def test_v1_state_migrates_without_trusting_legacy_evidence(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        self.record_tool()
        session_dir = self.root / "private" / "sessions" / "session-a"
        legacy = self.state()
        legacy["schema_version"] = 1
        legacy.pop("evidence_sequence")
        legacy.pop("completion_attempt")
        legacy["requirements"][0]["status"] = "pass"
        legacy["requirements"][0]["evidence"] = ["unverified legacy text"]
        legacy["content_hash"] = cg.state_content_hash(legacy)
        cg.atomic_write_json(session_dir / "state.json", legacy)

        self.prompt("继续验证迁移后的私有状态。")

        migrated = self.state()
        self.assertEqual(cg.SCHEMA_VERSION, 7)
        self.assertEqual(migrated["schema_version"], cg.SCHEMA_VERSION)
        self.assertEqual(migrated["evidence_sequence"], 1)
        self.assertEqual(migrated["work_state"], {"plan_snapshot": None})
        self.assertEqual(migrated["agents"], [])
        self.assertEqual(migrated["decision_log"], [])
        self.assertEqual(migrated["requirements"][0]["status"], "pending")
        self.assertEqual(migrated["requirements"][0]["evidence"], [])
        self.assertEqual(migrated["integrity"]["status"], "ok")

    def test_v2_state_migrates_with_verified_content_hash(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        self.record_tool()
        session_dir = self.root / "private" / "sessions" / "session-a"
        legacy = self.state()
        legacy["schema_version"] = 2
        legacy.pop("work_state")
        legacy.pop("agents")
        legacy.pop("integrity")
        legacy["completion_attempt"] = {
            "turn_id": "legacy-turn",
            "token_sha256": cg.sha256_text("legacy-token"),
            "created_at": cg.utc_now(),
            "staged_at": cg.utc_now(),
            "staged_checkpoint": {"status": "complete"},
        }
        legacy["content_hash"] = cg.state_content_hash(legacy)
        cg.atomic_write_json(session_dir / "state.json", legacy)

        self.prompt("继续验证从 0.2.1 状态迁移后的任务。")

        migrated = self.state()
        self.assertEqual(migrated["schema_version"], cg.SCHEMA_VERSION)
        self.assertEqual(migrated["integrity"]["status"], "ok")
        self.assertEqual(migrated["evidence_sequence"], 1)
        self.assertEqual(len(migrated["evidence"]), 1)
        self.assertEqual(migrated["work_state"], {"plan_snapshot": None})
        self.assertEqual(migrated["agents"], [])
        self.assertEqual(migrated["decision_log"], [])
        self.assertEqual(
            migrated["completion_attempt"]["turn_id"], self.current_turn
        )
        self.assertEqual(
            migrated["completion_attempt"]["token_sha256"],
            cg.sha256_text("test-token"),
        )
        self.assertIsNone(
            migrated["completion_attempt"].get("staged_control")
        )

    def test_v3_state_migrates_to_hash_only_decision_schema(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        legacy = self.state()
        legacy["schema_version"] = 3
        legacy.pop("decision_log")
        legacy["open_items"] = []
        legacy["completion_attempt"] = {
            "turn_id": "legacy-turn",
            "token_sha256": cg.sha256_text("legacy-token"),
            "created_at": cg.utc_now(),
            "staged_at": cg.utc_now(),
            "staged_checkpoint": {"status": "complete"},
        }
        legacy["content_hash"] = cg.state_content_hash(legacy)
        cg.atomic_write_json(session_dir / "state.json", legacy)

        self.prompt("继续验证从 0.4.x 状态迁移后的任务。")

        migrated = self.state()
        self.assertEqual(migrated["schema_version"], cg.SCHEMA_VERSION)
        self.assertEqual(migrated["decision_log"], [])
        self.assertEqual(migrated["integrity"]["status"], "ok")
        self.assertEqual(migrated["open_items"], cg.open_item_ids(migrated))
        self.assertEqual(
            migrated["completion_attempt"]["turn_id"], self.current_turn
        )
        self.assertEqual(
            migrated["completion_attempt"]["token_sha256"],
            cg.sha256_text("test-token"),
        )
        self.assertIsNone(
            migrated["completion_attempt"].get("staged_control")
        )

    def test_v4_state_integrity_migrates_to_schema7_and_invalidates_control(
        self,
    ) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        legacy = self.state()
        legacy["schema_version"] = 4
        legacy["completion_attempt"] = {
            "turn_id": "legacy-turn",
            "token_sha256": cg.sha256_text("legacy-token"),
            "created_at": cg.utc_now(),
            "staged_at": cg.utc_now(),
            "staged_checkpoint": {"status": "complete"},
        }
        legacy["content_hash"] = cg.state_content_hash(legacy)
        cg.atomic_write_json(session_dir / "state.json", legacy)

        migrated = cg.load_state(
            session_dir,
            self.payload("SessionStart", source="resume"),
        )

        self.assertEqual(migrated["schema_version"], 7)
        self.assertEqual(migrated["integrity"]["status"], "ok")
        self.assertIsNone(migrated["completion_attempt"])
        self.assertEqual(migrated["requirements"][0]["status"], "pending")
        self.assertFalse(list(session_dir.glob("state.corrupt.*.json")))
        with self.assertRaisesRegex(RuntimeError, "completion attempt"):
            cg.checkpoint_status(
                self.root / "private",
                "session-a",
                "legacy-turn",
                "legacy-token",
            )

        self.prompt("继续迁移后的任务，并建立新的 turn-bound control。")
        current = self.state()
        self.assertEqual(current["completion_attempt"]["turn_id"], self.current_turn)
        self.assertEqual(
            current["completion_attempt"]["token_sha256"],
            cg.sha256_text("test-token"),
        )
        self.assertIsNone(current["completion_attempt"]["staged_control"])

    def test_schema5_migrates_to_schema7_and_invalidates_only_inflight_control(
        self,
    ) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        session_dir = self.root / "private" / "sessions" / "session-a"
        previous = self.state()
        previous["completion_attempt"]["protocol_version"] = "1.0.0"
        previous["completion_attempt"]["staged_control"] = (
            cg.disposition_control("continue")
        )
        previous["completion_attempt"]["staged_at"] = cg.utc_now()
        previous["content_hash"] = cg.state_content_hash(previous)
        cg.atomic_write_json(session_dir / "state.json", previous)

        migrated = cg.load_state(
            session_dir,
            self.payload("SessionStart", source="resume"),
        )

        self.assertEqual(migrated["schema_version"], 7)
        self.assertEqual(migrated["integrity"]["status"], "ok")
        self.assertIsNone(migrated["completion_attempt"])
        self.assertEqual(migrated["evidence"][-1]["id"], evidence_id)
        self.assertEqual(migrated["requirements"][0]["status"], "pending")
        self.assertFalse(list(session_dir.glob("state.corrupt.*.json")))

        self.prompt("继续协议升级后的任务，并建立新的 turn-bound control。")
        current = self.state()
        self.assertEqual(
            current["completion_attempt"]["protocol_version"],
            cg.STOP_PROTOCOL_VERSION,
        )
        self.assertIsNone(current["completion_attempt"]["staged_control"])

    def test_schema6_migrates_losslessly_to_dormant_schema7(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        session_dir = self.root / "private" / "sessions" / "session-a"
        current = self.state()
        schema6 = cg.project_state_to_schema6(current)
        original_requirements = json.loads(json.dumps(schema6["requirements"]))
        original_evidence = json.loads(json.dumps(schema6["evidence"]))
        original_assets = json.loads(json.dumps(schema6["assets"]))
        original_proofs = json.loads(json.dumps(schema6["proofs"]))
        cg.atomic_write_json(session_dir / "state.json", schema6)

        migrated = cg.load_state(
            session_dir,
            self.payload("SessionStart", source="resume"),
        )

        self.assertEqual(migrated["schema_version"], 7)
        self.assertEqual(migrated["requirements"], original_requirements)
        self.assertEqual(migrated["evidence"], original_evidence)
        self.assertEqual(migrated["assets"], original_assets)
        self.assertEqual(migrated["proofs"], original_proofs)
        self.assertEqual(migrated["evidence"][-1]["id"], evidence_id)
        self.assertTrue(cg.execution_state_is_dormant(migrated["execution"]))
        self.assertIsNone(migrated["completion_attempt"])

    def test_schema7_dormant_projection_round_trips_to_schema6(self) -> None:
        self.prompt("实现复杂系统并测试。")
        current = self.state()

        projected = cg.project_state_to_schema6(current)

        self.assertEqual(projected["schema_version"], 6)
        self.assertNotIn("execution", projected)
        cg.validate_state_integrity(projected)
        self.assertEqual(projected["requirements"], current["requirements"])
        self.assertEqual(projected["evidence"], current["evidence"])
        self.assertEqual(projected["assets"], current["assets"])
        self.assertEqual(projected["proofs"], current["proofs"])

    def test_execution_contract_and_phase_transitions_are_bounded(self) -> None:
        execution = cg.dormant_execution_state()

        cg.transition_execution_contract(
            execution,
            "candidate",
            revision=1,
            contract_id="contract-1",
        )
        execution["contract"]["phases"].append(
            {
                "id": "phase-1",
                "state": "pending",
                "depends_on": [],
                "evidence_ids": [],
                "resolution_sha256": None,
            }
        )
        execution["contract"]["canonical_sha256"] = cg.contract_content_hash(
            execution["contract"]
        )
        cg.transition_execution_phase(execution, "phases", "phase-1", "passed")
        adoption = {
            "prompt_id": "P0001",
            "prompt_sha256": "a" * 64,
            "contract_sha256": execution["contract"]["canonical_sha256"],
            "revision": 1,
            "adopted_at": "2026-08-24T00:00:00Z",
        }
        cg.transition_execution_contract(execution, "active", adoption=adoption)

        self.assertEqual(execution["contract"]["state"], "active")
        self.assertEqual(execution["contract"]["phases"][0]["state"], "passed")
        cg.validate_execution_state(execution)
        with self.assertRaisesRegex(ValueError, "active -> candidate"):
            cg.transition_execution_contract(execution, "candidate", revision=2, contract_id="contract-2")
        with self.assertRaisesRegex(ValueError, "passed -> pending"):
            cg.transition_execution_phase(execution, "phases", "phase-1", "pending")
        cg.transition_execution_phase(execution, "phases", "phase-1", "stale")
        with self.assertRaises(cg.StateIntegrityError):
            cg.transition_execution_phase(execution, "phases", "phase-1", "pending")
        cg.transition_execution_phase(
            execution,
            "phases",
            "phase-1",
            "pending",
            resolution_sha256="c" * 64,
        )

    def test_execution_state_rejects_raw_paths_text_and_oversize_values(self) -> None:
        cases: list[dict] = []
        raw_text = cg.dormant_execution_state()
        raw_text["coverage_manifest"]["content"] = "copied Skill body"
        cases.append(raw_text)
        raw_path = cg.dormant_execution_state()
        raw_path["coverage_manifest"]["uncovered_write_surfaces"] = [
            {"id": "surface-1", "reason_code": "/workspace/private/target", "status": "uncovered"}
        ]
        cases.append(raw_path)
        oversized = cg.dormant_execution_state()
        oversized["coverage_manifest"]["uncovered_write_surfaces"] = [
            {"id": "surface-1", "reason_code": "x" * 513, "status": "uncovered"}
        ]
        cases.append(oversized)
        deep = cg.dormant_execution_state()
        nested: dict[str, object] = {}
        cursor = nested
        for index in range(10):
            child: dict[str, object] = {}
            cursor[f"level_{index}"] = child
            cursor = child
        deep["coverage_manifest"]["host_lock"] = nested
        cases.append(deep)

        for case in cases:
            with self.subTest(case=cases.index(case)):
                with self.assertRaises(cg.StateIntegrityError):
                    cg.validate_execution_state(case)

    def test_execution_state_rejects_duplicate_ticket_namespace_and_lossy_rollback(self) -> None:
        self.prompt("实现复杂系统并测试。")
        state = self.state()
        execution = state["execution"]
        cg.transition_execution_contract(
            execution,
            "candidate",
            revision=1,
            contract_id="contract-1",
        )
        ticket = {
            "id": "ticket-1",
            "session_id": "session-a",
            "turn_id": "turn-1",
            "actor_id": "root",
            "tool_use_id": "tool-1",
            "contract_revision": 1,
            "semantic_action_id": "write-file",
            "canonical_target_id": "target-1",
            "write_surface_id": "workspace",
            "input_sha256": "b" * 64,
            "state": "reserved",
            "reserved_at": "2026-08-24T00:00:00Z",
            "expires_at": "2026-08-24T00:01:00Z",
            "settled_at": None,
        }
        execution["action_tickets"] = [ticket, {**ticket, "id": "ticket-2"}]
        execution["contract"]["canonical_sha256"] = cg.contract_content_hash(
            execution["contract"]
        )

        with self.assertRaisesRegex(cg.StateIntegrityError, "ticket identity"):
            cg.validate_execution_state(execution)
        execution["action_tickets"] = []
        state["content_hash"] = cg.state_content_hash(state)
        with self.assertRaisesRegex(ValueError, "non-dormant"):
            cg.project_state_to_schema6(state)

    def test_execution_ticket_expiry_is_unsettled_and_terminal(self) -> None:
        execution = cg.dormant_execution_state()
        cg.transition_execution_contract(
            execution,
            "candidate",
            revision=1,
            contract_id="contract-1",
        )
        execution["action_tickets"] = [
            {
                "id": "ticket-1",
                "session_id": "session-a",
                "turn_id": "turn-1",
                "actor_id": "root",
                "tool_use_id": "tool-1",
                "contract_revision": 1,
                "semantic_action_id": "write-file",
                "canonical_target_id": "target-1",
                "write_surface_id": "workspace",
                "input_sha256": "b" * 64,
                "state": "reserved",
                "reserved_at": "2026-08-24T00:00:00Z",
                "expires_at": "2026-08-24T00:01:00Z",
                "settled_at": None,
            }
        ]

        expired = cg.expire_execution_tickets(
            execution,
            observed_at="2026-08-24T00:02:00Z",
        )

        self.assertEqual(expired, ["ticket-1"])
        self.assertEqual(execution["action_tickets"][0]["state"], "expired_unsettled")
        with self.assertRaisesRegex(ValueError, "expired_unsettled -> consumed"):
            cg.transition_execution_ticket(
                execution,
                "ticket-1",
                "consumed",
                settled_at="2026-08-24T00:03:00Z",
            )

    def test_phase2_pre_tool_output_schema_rejects_ask_and_updated_input(self) -> None:
        allow = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        }
        deny = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "contract gate blocked",
            }
        }
        cg.validate_pre_tool_decision(allow)
        cg.validate_pre_tool_decision(deny)

        invalid = [
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                }
            },
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": {"command": "changed"},
                }
            },
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "blocked",
                    "updatedInput": {},
                }
            },
        ]
        for decision in invalid:
            with self.subTest(decision=decision):
                with self.assertRaises(ValueError):
                    cg.validate_pre_tool_decision(decision)

    def test_schema7_normal_lifecycle_creates_no_execution_ticket(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        state = self.state()

        self.assertEqual(state["schema_version"], 7)
        self.assertEqual(state["execution"]["contract"]["state"], "absent")
        self.assertEqual(state["execution"]["action_tickets"], [])
        self.assertEqual(state["execution"]["denials"], [])
        self.assertIn(evidence_id, {item["id"] for item in state["evidence"]})

    def test_phase3_explicit_manifest_adoption_activates_only_deterministic_bindings(self) -> None:
        self.prompt("Implement the bounded Phase 3 test plan. Must verify every step.")
        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="update_plan",
                tool_input={
                    "plan": [{"step": "bounded step", "status": "in_progress"}],
                    "explanation": "phase 3",
                },
                tool_response="Plan updated",
                tool_use_id="plan-1",
            )
        )
        plan_sha256 = self.state()["work_state"]["plan_snapshot"]["semantic_sha256"]
        manifest = self.project / "execution-contract.json"
        manifest.write_text(
            json.dumps(self.execution_manifest(plan_sha256)), encoding="utf-8"
        )

        result = self.prompt("context-guard adopt execution-contract.json")
        state = self.state()
        execution = state["execution"]

        self.assertIn("adopted explicitly", result["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(execution["contract"]["state"], "active")
        self.assertEqual(cg.execution_contract_mode(execution), "active_contract")
        candidates = {item["id"]: item for item in execution["contract"]["authorization_candidates"]}
        self.assertEqual(candidates["candidate-deterministic"]["state"], "active")
        self.assertIsNotNone(candidates["candidate-deterministic"]["activation"])
        self.assertEqual(candidates["candidate-natural"]["state"], "candidate")
        self.assertIsNone(candidates["candidate-natural"]["activation"])
        self.assertEqual(execution["action_tickets"], [])
        self.assertEqual(execution["denials"], [])
        self.assertEqual(len(state["requirements"]), 1)
        self.assertNotIn(str(self.project), cg.canonical_json(execution))

    def test_phase3_manifest_or_policy_presence_never_implicitly_adopts(self) -> None:
        (self.project / "execution-contract.json").write_text(
            json.dumps(self.execution_manifest()), encoding="utf-8"
        )

        self.prompt(
            "The Skill and AGENTS mention execution-contract.json; inspect them without adopting."
        )
        execution = self.state()["execution"]

        self.assertEqual(execution["contract"]["state"], "absent")
        self.assertEqual(cg.execution_contract_mode(execution), "completion_only")
        self.assertEqual(execution["action_tickets"], [])
        self.assertEqual(execution["denials"], [])

    def test_phase3_adoption_conflict_keeps_every_candidate_non_authoritative(self) -> None:
        manifest = self.project / "execution-contract.json"
        manifest.write_text(
            json.dumps(self.execution_manifest("4" * 64)), encoding="utf-8"
        )

        result = self.prompt("context-guard adopt execution-contract.json")
        execution = self.state()["execution"]

        self.assertIn("recorded as conflicted", result["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(execution["contract"]["state"], "conflicted")
        self.assertEqual(cg.execution_contract_mode(execution), "completion_only")
        self.assertTrue(
            all(
                item["state"] == "candidate" and item["activation"] is None
                for item in execution["contract"]["authorization_candidates"]
            )
        )

    def test_phase3_plan_drift_is_soft_persisted_and_recovered(self) -> None:
        self.prompt("Implement the bounded Phase 3 test plan. Must verify every step.")
        initial_plan = {
            "plan": [{"step": "bounded step", "status": "in_progress"}],
            "explanation": "phase 3",
        }
        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="update_plan",
                tool_input=initial_plan,
                tool_response="Plan updated",
                tool_use_id="plan-1",
            )
        )
        manifest = self.project / "execution-contract.json"
        manifest.write_text(
            json.dumps(
                self.execution_manifest(
                    self.state()["work_state"]["plan_snapshot"]["semantic_sha256"]
                )
            ),
            encoding="utf-8",
        )
        self.prompt("context-guard adopt execution-contract.json")

        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="update_plan",
                tool_input={
                    "plan": [{"step": "silently changed step", "status": "in_progress"}],
                    "explanation": "phase 3",
                },
                tool_response="Plan updated",
                tool_use_id="plan-2",
            )
        )
        state = self.state()
        execution = state["execution"]

        self.assertEqual(execution["contract"]["state"], "stale")
        self.assertEqual(cg.execution_contract_mode(execution), "completion_only")
        self.assertEqual(len(execution["drift"]), 1)
        self.assertEqual(execution["drift"][0]["state"], "detected")
        self.assertEqual(execution["action_tickets"], [])
        packet = cg.recovery_packet(
            self.root / "private" / "sessions" / "session-a", state
        )
        self.assertIn("Execution contract recovery state", packet)
        self.assertIn("drift-1", packet)
        self.assertIn("phase-write", packet)
        self.assertNotIn("silently changed step", cg.diagnose_context(state))

    def test_phase3_identical_semantic_plan_does_not_drift_on_new_receipt(self) -> None:
        self.prompt("Implement the bounded Phase 3 test plan. Must verify every step.")
        plan_input = {
            "plan": [{"step": "bounded step", "status": "in_progress"}],
            "explanation": "phase 3",
        }
        for tool_use_id in ("plan-1",):
            cg.dispatch(
                self.payload(
                    "PostToolUse",
                    tool_name="update_plan",
                    tool_input=plan_input,
                    tool_response="Plan updated",
                    tool_use_id=tool_use_id,
                )
            )
        manifest = self.project / "execution-contract.json"
        manifest.write_text(
            json.dumps(
                self.execution_manifest(
                    self.state()["work_state"]["plan_snapshot"]["semantic_sha256"]
                )
            ),
            encoding="utf-8",
        )
        self.prompt("context-guard adopt execution-contract.json")
        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="update_plan",
                tool_input=plan_input,
                tool_response="Plan updated",
                tool_use_id="plan-2",
            )
        )

        execution = self.state()["execution"]
        self.assertEqual(execution["contract"]["state"], "active")
        self.assertEqual(execution["drift"], [])

    def test_phase3_adoption_rejects_out_of_project_manifest(self) -> None:
        external = self.root / "outside.json"
        external.write_text(json.dumps(self.execution_manifest()), encoding="utf-8")

        result = self.prompt("context-guard adopt ../outside.json")

        self.assertIn("must stay inside the project", result["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self.state()["execution"]["contract"]["state"], "absent")

    def test_phase3_every_non_active_contract_state_is_completion_only(self) -> None:
        for contract_state in (
            "absent",
            "candidate",
            "inactive",
            "rejected",
            "superseded",
        ):
            with self.subTest(contract_state=contract_state):
                execution = cg.dormant_execution_state()
                if contract_state != "absent":
                    cg.transition_execution_contract(
                        execution,
                        "candidate",
                        revision=1,
                        contract_id="contract-1",
                    )
                    if contract_state != "candidate":
                        cg.transition_execution_contract(execution, contract_state)
                self.assertEqual(cg.execution_contract_mode(execution), "completion_only")
                self.assertEqual(execution["action_tickets"], [])
                self.assertEqual(execution["denials"], [])

    def test_phase3_adoption_rejects_duplicate_raw_and_oversize_manifests(self) -> None:
        duplicate = self.execution_manifest()
        duplicate["instruction_sources"].append(
            dict(duplicate["instruction_sources"][0])
        )
        raw_path = self.execution_manifest()
        raw_path["instruction_sources"][0]["origin_id"] = str(self.project / "private")
        cases = {
            "duplicate.json": json.dumps(duplicate),
            "raw-path.json": json.dumps(raw_path),
            "oversize.json": json.dumps(self.execution_manifest()) + (" " * 65536),
        }

        for name, content in cases.items():
            with self.subTest(name=name):
                (self.project / name).write_text(content, encoding="utf-8")
                result = self.prompt(f"context-guard adopt {name}")
                context = result["hookSpecificOutput"]["additionalContext"]
                self.assertTrue(
                    any(
                        marker in context
                        for marker in (
                            "invalid",
                            "exceeds 64 KiB",
                            "must not retain raw machine paths",
                        )
                    ),
                    context,
                )
                self.assertEqual(
                    self.state()["execution"]["contract"]["state"], "absent"
                )

    def test_invalid_schema7_execution_ledger_recovers_from_prompts(self) -> None:
        original = "实现复杂系统。必须保留原始需求，必须验证 schema 7 损坏恢复。"
        self.prompt(original)
        session_dir = self.root / "private" / "sessions" / "session-a"
        invalid = self.state()
        invalid["execution"]["coverage_manifest"]["content"] = "copied private contract"
        invalid["content_hash"] = cg.state_content_hash(invalid)
        cg.atomic_write_json(session_dir / "state.json", invalid)

        restored = cg.dispatch(self.payload("SessionStart", source="resume"))

        self.assertIn(
            "recovered_from_prompts",
            restored["hookSpecificOutput"]["additionalContext"],
        )
        rebuilt = self.state()
        self.assertEqual(rebuilt["schema_version"], 7)
        self.assertTrue(cg.execution_state_is_dormant(rebuilt["execution"]))
        self.assertIn(original, rebuilt["requirements"][0]["text"])

    def test_natural_language_authorization_candidate_cannot_activate(self) -> None:
        execution = cg.dormant_execution_state()
        cg.transition_execution_contract(
            execution,
            "candidate",
            revision=1,
            contract_id="contract-1",
        )
        execution["contract"]["authorization_candidates"] = [
            {
                "id": "candidate-1",
                "prompt_id": "P0001",
                "prompt_sha256": "d" * 64,
                "semantic_action_id": "publish",
                "canonical_target_id": "target-1",
                "write_surface_id": "external-api",
                "binding": "natural_language",
                "state": "active",
                "activation": {
                    "prompt_id": "P0002",
                    "prompt_sha256": "e" * 64,
                    "activated_at": "2026-08-24T00:00:00Z",
                },
            }
        ]
        execution["contract"]["canonical_sha256"] = cg.contract_content_hash(
            execution["contract"]
        )

        with self.assertRaisesRegex(cg.StateIntegrityError, "deterministic"):
            cg.validate_execution_state(execution)

    def test_current_schema_load_and_save_normalize_stale_open_items(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        stale = self.state()
        stale["open_items"] = []
        stale["content_hash"] = cg.state_content_hash(stale)
        cg.atomic_write_json(session_dir / "state.json", stale)

        loaded = cg.load_state(
            session_dir,
            self.payload("SessionStart", source="resume"),
        )

        self.assertEqual(loaded["integrity"]["status"], "ok")
        self.assertEqual(loaded["open_items"], cg.open_item_ids(loaded))
        self.assertTrue(loaded["open_items"])
        cg.save_state(session_dir, loaded)
        persisted = self.state()
        self.assertEqual(persisted["open_items"], cg.open_item_ids(persisted))

    def test_tampered_state_recovers_from_immutable_prompts(self) -> None:
        original = "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        self.prompt(original)
        session_dir = self.root / "private" / "sessions" / "session-a"
        tampered = self.state()
        tampered["requirements"][0]["text"] = "silently weakened requirement"
        cg.atomic_write_json(session_dir / "state.json", tampered)

        restored = cg.dispatch(self.payload("SessionStart", source="resume"))

        packet = restored["hookSpecificOutput"]["additionalContext"]
        self.assertIn("recovered_from_prompts", packet)
        rebuilt = self.state()
        self.assertEqual(rebuilt["integrity"]["status"], "recovered_from_prompts")
        self.assertIn(original, rebuilt["requirements"][0]["text"])
        self.assertEqual(rebuilt["requirements"][0]["status"], "pending")
        self.assertTrue(list(session_dir.glob("state.corrupt.*.json")))

    def test_prompt_authority_metadata_is_bound_to_record_hash(self) -> None:
        self.prompt(
            "实现复杂系统。必须保护用户权限，必须验证提示来源，且不得静默降权。"
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        prompt_path = next((session_dir / "prompts").glob("*.json"))
        record = json.loads(prompt_path.read_text(encoding="utf-8"))
        record["origin"] = "subagent_delegation"
        cg.atomic_write_json(prompt_path, record)
        with self.assertRaisesRegex(cg.StateIntegrityError, "record hash mismatch"):
            cg.prompt_records_from_disk(session_dir)

    def test_truncated_state_recovers_without_losing_prompt_boundaries(self) -> None:
        self.prompt(
            "实现复杂系统。必须保留初始边界，必须运行测试，且不得扩大范围。"
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        (session_dir / "state.json").write_text("{", encoding="utf-8")

        cg.dispatch(self.payload("PreCompact", trigger="manual"))

        rebuilt = self.state()
        self.assertEqual(rebuilt["integrity"]["status"], "recovered_from_prompts")
        self.assertEqual(len(rebuilt["requirements"]), 1)
        self.assertIn("不得扩大范围", rebuilt["requirements"][0]["text"])
        self.assertTrue((session_dir / "recovery.json").is_file())

    def test_missing_state_recovers_from_existing_prompt_ledger(self) -> None:
        original = "实现复杂系统。必须保留原始边界，必须验证缺失状态恢复，且不得静默重置。"
        self.prompt(original)
        session_dir = self.root / "private" / "sessions" / "session-a"
        (session_dir / "state.json").unlink()

        restored = cg.dispatch(self.payload("SessionStart", source="resume"))

        self.assertIn(
            "recovered_from_prompts",
            restored["hookSpecificOutput"]["additionalContext"],
        )
        rebuilt = self.state()
        self.assertEqual(rebuilt["integrity"]["status"], "recovered_from_prompts")
        self.assertIn(original, rebuilt["requirements"][0]["text"])

    def test_unrecoverable_state_integrity_blocks_compaction_and_completion(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        prompt_path = next((session_dir / "prompts").glob("*.json"))
        (session_dir / "state.json").write_text("{", encoding="utf-8")
        prompt_path.write_text("{}", encoding="utf-8")

        compact = cg.safe_dispatch(self.payload("PreCompact", trigger="auto"))
        self.assertFalse(compact["continue"])
        self.assertIn("integrity", compact["systemMessage"].lower())
        stopped = cg.dispatch(
            self.payload("Stop", last_assistant_message="任务已经完成。")
        )
        self.assertFalse(stopped["continue"])
        self.assertIn("could not be reconstructed", stopped["stopReason"])

    def test_failed_integrity_retries_after_prompt_ledger_repair(self) -> None:
        original = "实现复杂系统。必须保留初始需求，必须允许修复后恢复，且不得静默放行。"
        self.prompt(original)
        session_dir = self.root / "private" / "sessions" / "session-a"
        prompt_path = next((session_dir / "prompts").glob("*.json"))
        prompt_record = prompt_path.read_text(encoding="utf-8")
        prompt_path.write_text("{}", encoding="utf-8")
        failed = cg.rebuild_state_from_prompts(
            session_dir,
            self.payload("SessionStart", source="resume"),
            issue="synthetic corruption",
            backup_file=None,
        )
        cg.save_state(session_dir, failed)
        self.assertEqual(self.state()["integrity"]["status"], "failed")
        prompt_path.write_text(prompt_record, encoding="utf-8")

        restored = cg.dispatch(self.payload("SessionStart", source="resume"))

        self.assertIn(
            "recovered_from_prompts",
            restored["hookSpecificOutput"]["additionalContext"],
        )
        rebuilt = self.state()
        self.assertEqual(rebuilt["integrity"]["status"], "recovered_from_prompts")
        self.assertIn(original, rebuilt["requirements"][0]["text"])

    def test_unknown_state_schema_recovers_from_prompts(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存边界，必须测试恢复，且不得静默放行。"
        )
        session_dir = self.root / "private" / "sessions" / "session-a"
        unsupported = self.state()
        unsupported["schema_version"] = 999
        unsupported["content_hash"] = cg.state_content_hash(unsupported)
        cg.atomic_write_json(session_dir / "state.json", unsupported)

        self.prompt("继续验证恢复后的任务。")

        rebuilt = self.state()
        self.assertEqual(rebuilt["schema_version"], cg.SCHEMA_VERSION)
        self.assertEqual(rebuilt["integrity"]["status"], "recovered_from_prompts")
        self.assertEqual(len(rebuilt["requirements"]), 2)

    def test_evidence_ids_remain_unique_after_retention_limit(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        with mock.patch.object(cg, "EVIDENCE_LIMIT", 2):
            self.record_tool()
            self.record_tool()
            self.record_tool()
        state = self.state()
        self.assertEqual([item["id"] for item in state["evidence"]], ["E0002", "E0003"])
        self.assertEqual(state["evidence_sequence"], 3)

    def test_referenced_evidence_survives_retention(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        first_evidence = self.record_tool()
        self.stage_all(first_evidence)
        self.assertEqual(
            cg.dispatch(
                self.payload("Stop", last_assistant_message="第一阶段已经完成。")
            ),
            {},
        )
        self.prompt("继续实现第二阶段，并完成测试和验收。")
        with mock.patch.object(cg, "EVIDENCE_LIMIT", 2):
            self.record_tool()
            self.record_tool()
            latest_evidence = self.record_tool()
        self.assertIn(
            first_evidence,
            {item["id"] for item in self.state()["evidence"]},
        )
        self.stage_all(latest_evidence)
        self.assertEqual(
            cg.dispatch(
                self.payload("Stop", last_assistant_message="第二阶段已完成。")
            ),
            {},
        )

    def test_stop_hook_exception_fails_closed(self) -> None:
        with mock.patch.object(cg, "dispatch", side_effect=RuntimeError("broken")):
            result = cg.safe_dispatch(
                self.payload("Stop", last_assistant_message="任务已经完成。")
            )
        self.assertFalse(result["continue"])
        self.assertIn("private validation failed", result["stopReason"])

    def test_private_checkpoint_cli_roundtrip(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        common = [
            "--data-dir",
            str(self.root / "private"),
            "--session-id",
            "session-a",
            "--turn-id",
            self.current_turn,
            "--token",
            "test-token",
        ]
        status = subprocess.run(
            [sys.executable, str(MODULE_PATH), "checkpoint-status", *common],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(
            json.loads(status.stdout)["recent_successful_evidence"][-1]["id"],
            evidence_id,
        )
        state = self.state()
        stage_arguments = [sys.executable, str(MODULE_PATH), "stage-checkpoint", *common]
        for item in state["requirements"]:
            stage_arguments.extend(
                ["--requirement", f"{item['id']}={evidence_id}"]
            )
        for item in state["acceptance_items"]:
            stage_arguments.extend(
                ["--acceptance", f"{item['id']}={evidence_id}"]
            )
        staged = subprocess.run(
            stage_arguments,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertIn(cg.STAGE_REQUEST_MARKER, staged.stdout)
        hook_result = cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="Bash",
                tool_input={"command": cg.shell_join(stage_arguments)},
                tool_response={"exit_code": 0, "output": staged.stdout},
            )
        )
        self.assertIn("privately staged", json.dumps(hook_result))
        self.assertEqual(
            self.state()["completion_attempt"]["staged_control"]["kind"],
            "checkpoint",
        )

    def test_private_stage_cli_real_wire_receipts_are_stageable(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        state = self.state()
        checkpoint_arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-checkpoint",
            *self.private_command_common(),
        ]
        for item in state["requirements"]:
            if item["status"] not in {"pass", "superseded"}:
                checkpoint_arguments.extend(
                    ["--requirement", f"{item['id']}={evidence_id}"]
                )
        for item in state["acceptance_items"]:
            if item["status"] not in {"pass", "superseded"}:
                checkpoint_arguments.extend(
                    ["--acceptance", f"{item['id']}={evidence_id}"]
                )

        checkpoint = subprocess.run(
            checkpoint_arguments,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=15,
            check=False,
        )
        self.assertEqual(checkpoint.returncode, 0, checkpoint.stderr)
        checkpoint_lines = checkpoint.stdout.splitlines()
        self.assertEqual(len(checkpoint_lines), 2)
        checkpoint_marker, checkpoint_sha256 = checkpoint_lines[0].split(" ", 1)
        self.assertEqual(checkpoint_marker, cg.STAGE_REQUEST_MARKER)
        self.assertEqual(len(checkpoint_sha256), 64)
        int(checkpoint_sha256, 16)
        self.assertEqual(checkpoint_lines[-1], "Script completed")
        self.assertEqual(checkpoint.stderr, "")
        before_checkpoint = self.state()
        checkpoint_result = cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="Bash",
                tool_input={"command": cg.shell_join(checkpoint_arguments)},
                tool_response=checkpoint.stdout,
            )
        )
        self.assertIn("privately staged", json.dumps(checkpoint_result))
        after_checkpoint = self.state()
        self.assertEqual(
            after_checkpoint["completion_attempt"]["staged_control"]["kind"],
            "checkpoint",
        )
        self.assertEqual(
            after_checkpoint["evidence_sequence"],
            before_checkpoint["evidence_sequence"],
        )
        self.assertEqual(
            len(after_checkpoint["evidence"]),
            len(before_checkpoint["evidence"]),
        )

        self.prompt("继续检查当前协议状态，并等待用户操作。")
        disposition_arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-disposition",
            *self.private_command_common(),
            "--disposition",
            "user_wait",
        ]
        disposition = subprocess.run(
            disposition_arguments,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=15,
            check=False,
        )
        self.assertEqual(disposition.returncode, 0, disposition.stderr)
        disposition_lines = disposition.stdout.splitlines()
        self.assertEqual(len(disposition_lines), 2)
        disposition_marker, disposition_sha256 = disposition_lines[0].split(
            " ", 1
        )
        self.assertEqual(disposition_marker, cg.DISPOSITION_REQUEST_MARKER)
        self.assertEqual(len(disposition_sha256), 64)
        int(disposition_sha256, 16)
        self.assertEqual(disposition_lines[-1], "Script completed")
        self.assertEqual(disposition.stderr, "")
        before_disposition = self.state()
        disposition_result = cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="Bash",
                tool_input={"command": cg.shell_join(disposition_arguments)},
                tool_response=disposition.stdout,
            )
        )
        self.assertIn("privately staged", json.dumps(disposition_result))
        after_disposition = self.state()
        self.assertEqual(
            after_disposition["completion_attempt"]["staged_control"]["kind"],
            "disposition",
        )
        self.assertEqual(
            after_disposition["evidence_sequence"],
            before_disposition["evidence_sequence"],
        )
        self.assertEqual(
            len(after_disposition["evidence"]),
            len(before_disposition["evidence"]),
        )

    def test_private_stage_raw_marker_without_success_line_is_rejected(
        self,
    ) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-disposition",
            *self.private_command_common(),
            "--disposition",
            "user_wait",
        ]
        precheck = subprocess.run(
            arguments,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=15,
            check=False,
        )
        self.assertEqual(precheck.returncode, 0, precheck.stderr)
        marker_only = precheck.stdout.splitlines()[0] + "\n"
        before = self.state()
        result = cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="Bash",
                tool_input={"command": cg.shell_join(arguments)},
                tool_response=marker_only,
            )
        )
        self.assertEqual(result["decision"], "block")
        after = self.state()
        self.assertIsNone(after["completion_attempt"]["staged_control"])
        self.assertEqual(after["evidence_sequence"], before["evidence_sequence"])
        self.assertEqual(len(after["evidence"]), len(before["evidence"]))

    def test_private_stage_failure_signals_override_success_receipt(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-disposition",
            *self.private_command_common(),
            "--disposition",
            "user_wait",
        ]
        precheck = subprocess.run(
            arguments,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=15,
            check=False,
        )
        self.assertEqual(precheck.returncode, 0, precheck.stderr)
        receipt = precheck.stdout
        cases = (
            ("exit-1", {"exit_code": 1, "output": receipt}),
            ("is-error", {"isError": True, "output": receipt}),
            ("success-false", {"success": False, "output": receipt}),
            (
                "traceback",
                receipt
                + "Traceback (most recent call last):\n"
                + "RuntimeError: broken\n",
            ),
            ("script-failed", receipt + "Script failed\n"),
            ("fatal", receipt + "fatal: broken\n"),
        )
        for label, response in cases:
            with self.subTest(label=label):
                before = self.state()
                result = cg.dispatch(
                    self.payload(
                        "PostToolUse",
                        tool_name="Bash",
                        tool_input={"command": cg.shell_join(arguments)},
                        tool_response=response,
                    )
                )
                self.assertEqual(result["decision"], "block")
                after = self.state()
                self.assertIsNone(
                    after["completion_attempt"]["staged_control"]
                )
                self.assertEqual(
                    after["evidence_sequence"], before["evidence_sequence"]
                )
                self.assertEqual(len(after["evidence"]), len(before["evidence"]))

    def test_private_checkpoint_token_may_start_with_dash(self) -> None:
        self.turn_index += 1
        self.current_turn = f"turn-{self.turn_index}"
        with mock.patch.object(
            cg.secrets, "token_urlsafe", return_value="-leading-token"
        ):
            submitted = cg.dispatch(
                self.payload(
                    "UserPromptSubmit",
                    prompt=(
                        "实现复杂系统。必须保护需求，必须验证随机 token，"
                        "必须提供验收证据。"
                    ),
                )
            )
        context = submitted["hookSpecificOutput"]["additionalContext"]
        self.assertIn("--token=-leading-token", context)
        evidence_id = self.record_tool()
        common = [
            "--data-dir",
            str(self.root / "private"),
            "--session-id",
            "session-a",
            "--turn-id",
            self.current_turn,
            "--token=-leading-token",
        ]
        status = subprocess.run(
            [sys.executable, str(MODULE_PATH), "checkpoint-status", *common],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        state = self.state()
        stage_arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-checkpoint",
            *common,
        ]
        for item in state["requirements"]:
            stage_arguments.extend(
                ["--requirement", f"{item['id']}={evidence_id}"]
            )
        for item in state["acceptance_items"]:
            stage_arguments.extend(
                ["--acceptance", f"{item['id']}={evidence_id}"]
            )
        staged = subprocess.run(
            stage_arguments,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(staged.returncode, 0, staged.stderr)
        hook_result = cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="Bash",
                tool_input={"command": cg.shell_join(stage_arguments)},
                tool_response={"exit_code": 0, "output": staged.stdout},
            )
        )
        self.assertIn("privately staged", json.dumps(hook_result))

    def test_stage_request_marker_in_unrelated_output_is_ignored(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        result = cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="Bash",
                tool_input={"command": "rg CONTEXT_GUARD_STAGE_REQUEST source.py"},
                tool_response=cg.STAGE_REQUEST_MARKER,
            )
        )
        self.assertEqual(result, {})
        self.assertIsNone(
            self.state()["completion_attempt"]["staged_control"]
        )

    def test_stage_disposition_rejects_wrong_private_boundaries_and_complete(
        self,
    ) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        base = [sys.executable, str(MODULE_PATH), "stage-disposition"]
        mismatched_control_value = self.id()
        cases = (
            (
                "wrong-turn",
                self.private_command_common(turn_id="turn-other"),
                ["--disposition", "user_wait"],
            ),
            (
                "wrong-token",
                self.private_command_common(token=mismatched_control_value),
                ["--disposition", "user_wait"],
            ),
            (
                "wrong-session",
                self.private_command_common(session="session-other"),
                ["--disposition", "user_wait"],
            ),
            (
                "wrong-data-dir",
                self.private_command_common(data_dir=self.root / "other-private"),
                ["--disposition", "user_wait"],
            ),
            (
                "complete-is-not-a-disposition",
                self.private_command_common(),
                ["--disposition", "complete"],
            ),
            (
                "reason-option-is-forbidden",
                self.private_command_common(),
                ["--disposition", "user_wait", "--reason", "external_dependency"],
            ),
        )
        for label, common, tail in cases:
            with self.subTest(label=label):
                result = subprocess.run(
                    [*base, *common, *tail],
                    text=True,
                    capture_output=True,
                    env=os.environ.copy(),
                    timeout=15,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(cg.DISPOSITION_REQUEST_MARKER, result.stdout)
                self.assertNotIn("Script completed", result.stdout)
                self.assertIsNone(
                    self.state()["completion_attempt"]["staged_control"]
                )

    def test_post_tool_stage_rejects_forged_marker_failed_command_and_shell_tail(
        self,
    ) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-disposition",
            *self.private_command_common(),
            "--disposition",
            "user_wait",
        ]
        precheck = subprocess.run(
            arguments,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=15,
            check=False,
        )
        self.assertEqual(precheck.returncode, 0, precheck.stderr)

        cases = (
            (
                "failed-command",
                cg.shell_join(arguments),
                {"exit_code": 1, "output": precheck.stdout},
            ),
            (
                "extra-shell-segment",
                cg.shell_join(arguments) + "; echo injected",
                {"exit_code": 0, "output": precheck.stdout},
            ),
            (
                "wrong-script-path",
                cg.shell_join(
                    [
                        sys.executable,
                        str(self.root / "context_guard.py"),
                        *arguments[2:],
                    ]
                ),
                {"exit_code": 0, "output": precheck.stdout},
            ),
            (
                "marker-only-unrelated-command",
                "rg CONTEXT_GUARD_STAGE_REQUEST source.py",
                {"exit_code": 0, "output": precheck.stdout},
            ),
            (
                "string-failure-after-authoritative-success-marker",
                cg.shell_join(arguments),
                (
                    precheck.stdout
                    + "Script completed\n"
                    + "Traceback (most recent call last):\n"
                    + "RuntimeError: broken\n"
                ),
            ),
        )
        for label, command, response in cases:
            with self.subTest(label=label):
                result = cg.dispatch(
                    self.payload(
                        "PostToolUse",
                        tool_name="Bash",
                        tool_input={"command": command},
                        tool_response=response,
                    )
                )
                self.assertNotIn("privately staged", json.dumps(result))
                self.assertIsNone(
                    self.state()["completion_attempt"]["staged_control"]
                )

    def test_private_control_shell_tails_never_create_success_evidence(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        state = self.state()
        checkpoint_arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-checkpoint",
            *self.private_command_common(),
        ]
        for item in state["requirements"]:
            if item["status"] not in {"pass", "superseded"}:
                checkpoint_arguments.extend(
                    ["--requirement", f"{item['id']}={evidence_id}"]
                )
        for item in state["acceptance_items"]:
            if item["status"] not in {"pass", "superseded"}:
                checkpoint_arguments.extend(
                    ["--acceptance", f"{item['id']}={evidence_id}"]
                )
        commands = (
            [
                sys.executable,
                str(MODULE_PATH),
                "checkpoint-status",
                *self.private_command_common(),
            ],
            checkpoint_arguments,
            [
                sys.executable,
                str(MODULE_PATH),
                "stage-disposition",
                *self.private_command_common(),
                "--disposition",
                "user_wait",
            ],
        )
        for arguments in commands:
            with self.subTest(private_command=arguments[2]):
                before = self.state()
                evidence_count = len(before["evidence"])
                evidence_sequence = before["evidence_sequence"]
                result = cg.dispatch(
                    self.payload(
                        "PostToolUse",
                        tool_name="Bash",
                        tool_input={
                            "command": cg.shell_join(arguments) + "; echo injected"
                        },
                        tool_response={"exit_code": 0, "output": "injected"},
                    )
                )
                self.assertNotIn("privately staged", json.dumps(result))
                current = self.state()
                self.assertEqual(len(current["evidence"]), evidence_count)
                self.assertEqual(current["evidence_sequence"], evidence_sequence)

    def test_checkpoint_status_wrapped_shell_segments_never_create_evidence(
        self,
    ) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "checkpoint-status",
            *self.private_command_common(),
        ]
        exact_command = cg.shell_join(arguments)
        commands = (
            "echo injected; " + exact_command,
            "echo injected && " + exact_command,
            "echo injected | " + exact_command,
            exact_command + " | echo injected",
        )
        for command in commands:
            with self.subTest(command=command):
                before = self.state()
                evidence_count = len(before["evidence"])
                evidence_sequence = before["evidence_sequence"]
                result = cg.dispatch(
                    self.payload(
                        "PostToolUse",
                        tool_name="Bash",
                        tool_input={"command": command},
                        tool_response={"exit_code": 0, "output": "injected"},
                    )
                )
                self.assertNotIn("privately staged", json.dumps(result))
                current = self.state()
                self.assertEqual(len(current["evidence"]), evidence_count)
                self.assertEqual(current["evidence_sequence"], evidence_sequence)

    def test_quoted_control_search_patterns_are_not_command_intent(self) -> None:
        searches = (
            "rg -n 'stage-disposition|checkpoint-status' source.py",
            'rg -n "stage-disposition;checkpoint-status" source.py',
            "grep -E 'stage-disposition\\|checkpoint-status' source.py",
            "rg -n 'stage-disposition && checkpoint-status' source.py",
        )
        for command in searches:
            with self.subTest(command=command):
                self.assertFalse(
                    cg.private_control_command_intent(
                        {
                            "tool_name": "Bash",
                            "tool_input": {"command": command},
                        }
                    )
                )

        wrapped_search_or_text = (
            "rg -n stage-disposition source.py | sed -n '1p'",
            'rg -n "$(stage-disposition)" source.py',
            "rg -n stage-disposition source.py; echo injected",
            "sed -n '/register-proof/p' source.py",
            "printf '%s\\n' register-proof",
            "python -c \"print('register-proof')\"",
        )
        for command in wrapped_search_or_text:
            with self.subTest(command=command):
                self.assertFalse(
                    cg.private_control_command_intent(
                        {
                            "tool_name": "Bash",
                            "tool_input": {"command": command},
                        }
                    )
                )

    def test_control_names_in_regular_shell_text_remain_successful_evidence(self) -> None:
        self.prompt("$context-guard\nAudit the current behavior.")
        commands = (
            "rg -n 'input_asset_inspection|register-proof|obligation_id' source.py",
            "grep -E 'checkpoint-status|stage-checkpoint' source.py",
            "sed -n '/register-proof/p' source.py",
            "python /tmp/unrelated.py register-proof",
        )
        for command in commands:
            with self.subTest(command=command):
                result = cg.dispatch(
                    self.payload(
                        "PostToolUse",
                        tool_name="Bash",
                        tool_input={"command": command},
                        tool_response={"exit_code": 0, "output": "match"},
                    )
                )
                self.assertNotEqual(result.get("decision"), "block")
                self.assertEqual(self.state()["evidence"][-1]["outcome"], "success")
        malformed_runtime = cg.shell_join(
            [sys.executable, str(MODULE_PATH), "register-proof", "--bad-option"]
        )
        self.assertTrue(
            cg.private_control_command_intent(
                {"tool_name": "Bash", "tool_input": {"command": malformed_runtime}}
            )
        )

        private_command_name = "stage" + "-" + "disposition"
        status_command_name = "checkpoint" + "-" + "status"
        patch_text = (
            "*** Begin Patch\n"
            f"+Document {private_command_name}|{status_command_name} "
            "without execution.\n"
            "*** End Patch"
        )
        self.assertFalse(
            cg.private_control_command_intent(
                {
                    "tool_name": "apply_patch",
                    "tool_input": {"command": patch_text},
                }
            )
        )

    def test_non_shell_control_text_is_regular_evidence(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        before = len(self.state()["evidence"])
        result = cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="apply_patch",
                tool_input={
                    "patch": (
                        "*** Begin Patch\n"
                        "+Document stage-disposition and checkpoint-status.\n"
                        "*** End Patch"
                    )
                },
                tool_response={"success": True, "output": "Done"},
            )
        )
        self.assertEqual(result, {})
        current = self.state()
        self.assertEqual(len(current["evidence"]), before + 1)
        self.assertEqual(current["evidence"][-1]["tool"], "apply_patch")

    def test_exec_command_tool_name_accepts_exact_private_stage(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-disposition",
            *self.private_command_common(),
            "--disposition",
            "user_wait",
        ]
        staged, hook_result = self.run_private_stage(
            arguments,
            tool_name="exec_command",
        )
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertNotEqual(hook_result.get("decision"), "block")
        control = self.state()["completion_attempt"]["staged_control"]
        self.assertEqual(control["disposition"], "user_wait")

    def test_private_control_commands_are_not_evidence_and_tokens_are_redacted(
        self,
    ) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
        )
        evidence_id = self.record_tool()
        before = self.state()
        evidence_count = len(before["evidence"])
        evidence_sequence = before["evidence_sequence"]

        staged, _ = self.stage_disposition("user_wait")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        after_disposition = self.state()
        self.assertEqual(len(after_disposition["evidence"]), evidence_count)
        self.assertEqual(after_disposition["evidence_sequence"], evidence_sequence)

        checkpoint, _ = self.stage_checkpoint_cli(evidence_id, replace=True)
        self.assertEqual(checkpoint.returncode, 0, checkpoint.stderr)
        after_checkpoint = self.state()
        self.assertEqual(len(after_checkpoint["evidence"]), evidence_count)
        self.assertEqual(after_checkpoint["evidence_sequence"], evidence_sequence)
        self.assertNotIn("test-token", json.dumps(after_checkpoint))

        for command in (
            "verify --token secret-space",
            "verify --token=secret-equals",
        ):
            cg.dispatch(
                self.payload(
                    "PostToolUse",
                    tool_name="Bash",
                    tool_input={"command": command},
                    tool_response={"exit_code": 0, "output": "PASS"},
                )
            )
        state = self.state()
        serialized = json.dumps(state, ensure_ascii=False)
        self.assertNotIn("secret-space", serialized)
        self.assertNotIn("secret-equals", serialized)

        session_dir = self.root / "private" / "sessions" / "session-a"
        exported = cg.export_handoff(
            session_dir,
            state,
            str(self.project / "handoff.md"),
        )
        handoff = exported.read_text(encoding="utf-8")
        self.assertNotIn("secret-space", handoff)
        self.assertNotIn("secret-equals", handoff)

    def test_staged_continue_is_advisory_unless_prompt_requires_persistence(
        self,
    ) -> None:
        self.prompt(
            "$context-guard\n继续处理获批论文，并保留所有未完成项目。"
        )
        staged, _ = self.stage_disposition("continue")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        result = cg.dispatch(
            self.payload(
                "Stop",
                last_assistant_message=(
                    "获批批次仍有若干条目待处理。请先在当前浏览器中"
                    "完成必要登录，然后告诉我。"
                ),
            )
        )
        self.assertEqual(result, {})
        latest = self.state()["decision_log"][-1]
        self.assertEqual(latest["declared_disposition"], "continue")
        self.assertEqual(latest["observed_outcome"], "allow_user_handoff")
        self.assertEqual(latest["outcome"], "allow_neutral")
        self.assertIn("protocol_continue_advisory", latest["reason_codes"])
        self.assertEqual(self.state()["continuation_attempts"], 0)

        session = "session-continue-persistence"
        self.prompt(
            "$context-guard\nDo not stop until the entire task is complete.",
            session=session,
        )
        staged, _ = self.stage_disposition("continue", session=session)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        blocked = cg.dispatch(
            self.payload(
                "Stop",
                session=session,
                last_assistant_message="Progress is recorded; work remains.",
            )
        )
        self.assertEqual(blocked["decision"], "block")
        self.assertIn(
            "explicit_user_persistence",
            self.state(session)["decision_log"][-1]["reason_codes"],
        )

    def test_anonymized_historical_terminal_replays_never_loop_on_continue(
        self,
    ) -> None:
        messages = (
            "本地整理和验证已完成；其余条目需要你先完成登录，然后告诉我。",
            "Local validation passed; the remaining upload needs your approval.",
            "The submission is recorded and now awaits an external review.",
            "本地提交已准备好；远端推送与 CI 不在本阶段授权范围内。",
            "I can continue after you provide the required account selection.",
            "Remaining items are recorded. This is the terminal handoff for this turn.",
        )
        for index, message in enumerate(messages):
            session = f"historical-terminal-{index}"
            self.prompt(
                "$context-guard\n处理合成批次并保留所有未完成要求。",
                session=session,
            )
            staged, _ = self.stage_disposition("continue", session=session)
            self.assertEqual(staged.returncode, 0, staged.stderr)
            result = cg.dispatch(
                self.payload(
                    "Stop",
                    session=session,
                    last_assistant_message=message,
                )
            )
            self.assertEqual(result, {}, message)
            current = self.state(session)
            self.assertEqual(current["continuation_attempts"], 0)
            self.assertTrue(current["open_items"])
            latest = current["decision_log"][-1]
            self.assertEqual(latest["declared_disposition"], "continue")
            self.assertEqual(latest["outcome"], "allow_neutral")
            self.assertIn(
                "protocol_continue_advisory",
                latest["reason_codes"],
            )

    def test_realistic_string_tool_failures_are_not_success_evidence(self) -> None:
        for response in (
            "fatal: not a git repository",
            "[FAIL] Operation not permitted",
            "Traceback (most recent call last):\nRuntimeError: broken",
        ):
            with self.subTest(response=response):
                self.assertEqual(
                    cg.tool_outcome({"tool_response": response}),
                    "failed",
                )
        self.assertEqual(
            cg.tool_outcome({"tool_response": "SMOKE_PASS"}),
            "unknown",
        )
        self.assertEqual(
            cg.tool_outcome_details(
                {"tool_response": "Verification could not be completed"}
            ),
            ("unknown", "unstructured_text"),
        )
        self.assertEqual(
            cg.tool_outcome_details({"tool_response": "Script completed."}),
            ("unknown", "unstructured_text"),
        )

    def test_prompt_subjects_reject_prose_slashes_and_preserve_real_locators(
        self,
    ) -> None:
        thread_uri = "codex://threads/01a01503-a631-7681-92cb-cac150d2b94a"
        prose = (
            f"接续{thread_uri}的任务；覆盖原始字节/哈希场景、newline；"
            "不修改公共/macOS规则或运行时应用。"
        )
        self.assertEqual(
            cg.prompt_subjects(prose),
            [
                {
                    "id": f"subject:{cg.sha256_text(thread_uri)[:20]}",
                    "kind": "url",
                    "display": thread_uri,
                    "locator_sha256": cg.sha256_text(thread_uri),
                }
            ],
        )
        locators = cg.prompt_subjects(
            "核验 /tmp/context-guard/result.json 和 https://example.test/report。"
        )
        self.assertEqual([item["kind"] for item in locators], ["path", "url"])
        self.assertFalse(cg.UI_SURFACE_RE.search("使用官方入口完成运行时应用。"))
        self.assertTrue(cg.UI_SURFACE_RE.search("在应用界面中核验可见结果。"))

    def test_view_image_data_url_is_structured_success(self) -> None:
        response = {"image_url": "data:image/png;base64,AAAA", "detail": "original"}
        self.assertEqual(
            cg.tool_outcome_details(
                {"tool_name": "view_image", "tool_response": response}
            ),
            ("success", "structured_visual_result"),
        )
        self.assertEqual(
            cg.tool_outcome_details(
                {"tool_name": "other_tool", "tool_response": response}
            ),
            ("unknown", "unstructured_text"),
        )
        content_response = {
            "content": [
                {
                    "type": "input_image",
                    "image_url": "data:image/png;base64,BBBB",
                }
            ]
        }
        for tool_name, visual_response in (
            ("view_image", content_response),
            ("functions.view_image", content_response["content"]),
        ):
            with self.subTest(tool_name=tool_name):
                self.assertEqual(
                    cg.tool_outcome_details(
                        {"tool_name": tool_name, "tool_response": visual_response}
                    ),
                    ("success", "structured_visual_result"),
                )
        for tool_name, visual_response in (
            ("fake_view_image", content_response),
            ("other_image_tool", content_response),
            ("view_image", {"nested": content_response}),
        ):
            with self.subTest(tool_name=tool_name, visual_response=visual_response):
                self.assertEqual(
                    cg.tool_outcome_details(
                        {"tool_name": tool_name, "tool_response": visual_response}
                    )[0],
                    "unknown",
                )
        self.assertEqual(cg.evidence_capabilities("other_image_tool"), ["artifact"])
        self.assertEqual(
            cg.tool_outcome_details(
                {
                    "tool_name": "view_image",
                    "tool_response": {
                        "content": content_response["content"],
                        "error": "render failed",
                    },
                }
            ),
            ("failed", "structured_error"),
        )
        self.assertEqual(
            cg.tool_outcome_details(
                {
                    "tool_name": "view_image",
                    "tool_response": content_response["content"]
                    + [{"type": "text", "text": "Script failed"}],
                }
            ),
            ("failed", "failure_marker"),
        )

    def test_real_view_image_receipt_binds_asset_but_not_visual_fact(self) -> None:
        image = self.write_png("visual-receipt.png", 21, 34)
        encoded = base64.b64encode(image.read_bytes()).decode("ascii")
        self.turn_index += 1
        self.current_turn = f"turn-{self.turn_index}"
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="test-token"):
            cg.dispatch(
                self.payload(
                    "UserPromptSubmit",
                    prompt="$context-guard\n请检查这张截图并报告可见事实，不要修改。",
                    local_images=[str(image)],
                )
            )
        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="functions.view_image",
                tool_input={"path": str(image)},
                tool_response=[
                    {
                        "type": "input_image",
                        "image_url": f"data:image/png;base64,{encoded}",
                    }
                ],
            )
        )
        state = self.state()
        evidence = state["evidence"][-1]
        asset_id = state["assets"][0]["id"]
        self.assertEqual(evidence["outcome"], "success")
        self.assertEqual(evidence["outcome_basis"], "structured_visual_result")
        self.assertIn("visual", evidence["capabilities"])
        self.assertEqual(evidence["asset_ids"], [asset_id])
        self.assertEqual(state["proofs"], [])
        obligation = state["requirements"][0]["verification_contract"]["obligations"][0]
        proof = cg.normalize_proof_manifest(
            state,
            {
                "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                "item_id": "R001",
                "obligation_id": obligation["id"],
                "evidence_ids": [evidence["id"]],
                "surface": "visual",
                "subject_ids": [asset_id],
                "visual_facts": [
                    {"asset_id": asset_id, "text": "The image has a visible frame."}
                ],
            },
        )
        self.assertEqual(proof["evidence_ids"], [evidence["id"]])

    def test_explicit_success_status_wins_over_warning_text(self) -> None:
        warning = "Script completed\nOutput:\nWarning: Operation not permitted"
        self.assertEqual(
            cg.tool_outcome_details({"tool_response": warning}),
            ("success", "authoritative_success_marker"),
        )
        self.assertEqual(
            cg.tool_outcome_details(
                {
                    "tool_response": {
                        "exit_code": 0,
                        "output": "Warning: Operation not permitted",
                    }
                }
            ),
            ("success", "structured_exit_code"),
        )
        self.assertEqual(
            cg.tool_outcome_details(
                {
                    "tool_response": {
                        "exit_code": 2,
                        "output": "Script completed",
                    }
                }
            ),
            ("failed", "structured_exit_code"),
        )
        self.assertEqual(
            cg.tool_outcome_details(
                {"tool_response": {"exit_code": 0.5, "output": "PASS"}}
            ),
            ("failed", "invalid_exit_code"),
        )

    def test_weak_success_marker_does_not_override_failure(self) -> None:
        for response in (
            "PASS\nTraceback (most recent call last):\nRuntimeError: broken",
            "Script completed with errors\nPASS",
            "Script completed\nTraceback (most recent call last):\nRuntimeError: broken",
        ):
            with self.subTest(response=response):
                self.assertEqual(
                    cg.tool_outcome_details({"tool_response": response}),
                    ("failed", "failure_marker"),
                )

    def test_binary_tool_result_is_replaced_with_bounded_metadata(self) -> None:
        self.prompt(
            "实现复杂系统。必须保护上下文，必须运行测试，必须提供验收证据。"
        )
        data_url = "data:image/png;base64," + ("A" * 6000)
        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="view_image",
                tool_input={"path": "/tmp/example.png"},
                tool_response={"image_url": data_url, "detail": "original"},
            )
        )
        evidence = self.state()["evidence"][-1]
        self.assertIn("[binary omitted: type=image/png", evidence["summary"])
        self.assertIn("sha256=", evidence["summary"])
        self.assertNotIn("base64,AAAA", evidence["summary"])
        self.assertLess(len(evidence["summary"]), 1800)
        self.assertEqual(evidence["origin"], "runtime_unattributed")
        self.assertEqual(evidence["outcome"], "success")
        self.assertEqual(evidence["outcome_basis"], "structured_visual_result")

        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="image-block",
                tool_input={"path": "/tmp/example-2.png"},
                tool_response={
                    "type": "image",
                    "mimeType": "image/png",
                    "data": "B" * 6000,
                },
            )
        )
        binary_block = self.state()["evidence"][-1]["summary"]
        self.assertIn("[binary omitted: type=base64", binary_block)
        self.assertNotIn("BBBBBBBB", binary_block)

        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="text-block",
                tool_input={"command": "return long text data"},
                tool_response={"type": "text", "data": "A" * 700},
            )
        )
        text_block = self.state()["evidence"][-1]["summary"]
        self.assertNotIn("[binary omitted", text_block)
        self.assertIn("AAAAAAAA", text_block)

    def test_successful_update_plan_is_mirrored_and_failed_update_is_ignored(
        self,
    ) -> None:
        self.prompt(
            "实现复杂系统。必须保护当前计划，必须验证恢复，必须运行测试。"
        )
        initial_plan = {
            "explanation": "First bounded plan.",
            "plan": [
                {"step": "Inspect", "status": "completed"},
                {"step": "Implement", "status": "in_progress"},
                {"step": "Verify", "status": "pending"},
            ],
        }
        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="update_plan",
                tool_use_id="tool-plan-1",
                tool_input=initial_plan,
                tool_response={"success": True},
            )
        )
        snapshot = self.state()["work_state"]["plan_snapshot"]
        self.assertEqual(snapshot["steps"], initial_plan["plan"])
        first_hash = snapshot["sha256"]
        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="functions.update_plan",
                tool_use_id="tool-plan-2",
                tool_input={
                    "plan": [{"step": "Incorrect overwrite", "status": "completed"}]
                },
                tool_response={"exit_code": 1, "output": "Script failed"},
            )
        )
        self.assertEqual(
            self.state()["work_state"]["plan_snapshot"]["sha256"], first_hash
        )
        packet = cg.recovery_packet(
            self.root / "private" / "sessions" / "session-a",
            self.state(),
        )
        self.assertIn("Latest Codex plan mirror", packet)
        self.assertIn("[in_progress] Implement", packet)
        self.assertIn("E0002 [failed]", packet)

    def test_real_update_plan_receipt_survives_compact_resume_with_health(self) -> None:
        self.prompt(
            "实现复杂系统。必须保护当前计划，必须验证恢复，必须运行测试。"
        )
        real_plan = {
            "explanation": "Real first-party receipt.",
            "plan": [
                {"step": "Inspect", "status": "completed"},
                {"step": "Implement", "status": "in_progress"},
                {"step": "Verify", "status": "pending"},
            ],
        }
        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="functions.update_plan",
                tool_use_id="tool-real-plan",
                tool_input=real_plan,
                tool_response="Plan updated",
            )
        )
        state = self.state()
        snapshot_hash = state["work_state"]["plan_snapshot"]["sha256"]
        self.assertEqual(state["evidence"][-1]["outcome"], "success")
        self.assertEqual(
            state["evidence"][-1]["outcome_basis"], "first_party_plan_receipt"
        )
        self.assertEqual(cg.plan_mirror_health(state), "healthy")
        self.assertIn("plan_mirror=healthy", cg.status_context(state))
        self.assertIn("plan mirror healthy", cg.diagnose_context(state))

        cg.dispatch(self.payload("PreCompact", trigger="manual"))
        cg.dispatch(self.payload("SessionStart", source="resume"))
        resumed = self.state()
        self.assertEqual(
            resumed["work_state"]["plan_snapshot"]["sha256"], snapshot_hash
        )
        self.assertEqual(cg.plan_mirror_health(resumed), "healthy")

        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="update_plan",
                tool_use_id="tool-unknown-plan",
                tool_input={
                    "plan": [{"step": "Do not overwrite", "status": "completed"}]
                },
                tool_response="Plan may have been updated",
            )
        )
        self.assertEqual(
            self.state()["work_state"]["plan_snapshot"]["sha256"], snapshot_hash
        )

        missing = cg.new_state(self.payload("UserPromptSubmit"))
        self.assertEqual(cg.plan_mirror_health(missing), "missing")
        missing["work_state"]["plan_snapshot"] = {
            "steps": [{"step": "Tampered", "status": "completed"}],
            "sha256": "0" * 64,
        }
        self.assertEqual(cg.plan_mirror_health(missing), "degraded")

    def test_phase1_redacted_incident_fixture_event_order_is_frozen(self) -> None:
        fixtures = {
            "original_task": [
                {"event": "UserPromptSubmit"},
                {
                    "event": "PostToolUse",
                    "tool": "functions.update_plan",
                    "response": "Plan updated",
                    "baseline_outcome": "unknown",
                    "candidate_outcome": "success",
                },
                {"event": "PreCompact"},
                {"event": "SessionStart"},
            ],
            "review_task": [
                {"event": "UserPromptSubmit", "asset": "redacted-image"},
                {
                    "event": "PostToolUse",
                    "tool": "functions.view_image",
                    "response": [
                        {
                            "type": "input_image",
                            "image_url": "data:image/png;base64,AAAA",
                        }
                    ],
                    "baseline_outcome": "unknown",
                    "candidate_outcome": "success",
                },
                {"event": "Stop"},
            ],
            "clean_handoff_task": [
                {"event": "UserPromptSubmit"},
                {"event": "PostToolUse", "tool": "exec_command"},
                {
                    "event": "Stop",
                    "reply": "说明文字只提及 checkpoint-status 名称。",
                    "baseline_outcome": "fail_closed_integrity",
                    "candidate_outcome": "explanatory_reference",
                },
            ],
        }
        self.assertEqual(
            [item["event"] for item in fixtures["original_task"]],
            ["UserPromptSubmit", "PostToolUse", "PreCompact", "SessionStart"],
        )
        self.assertEqual(
            [item["event"] for item in fixtures["review_task"]],
            ["UserPromptSubmit", "PostToolUse", "Stop"],
        )
        self.assertEqual(
            [item["event"] for item in fixtures["clean_handoff_task"]],
            ["UserPromptSubmit", "PostToolUse", "Stop"],
        )
        self.assertEqual(
            fixtures["review_task"][1]["response"][0]["type"], "input_image"
        )
        self.assertEqual(
            fixtures["original_task"][1]["baseline_outcome"], "unknown"
        )
        self.assertEqual(
            fixtures["review_task"][1]["baseline_outcome"], "unknown"
        )
        self.assertEqual(
            cg.classify_private_metadata(fixtures["clean_handoff_task"][2]["reply"])[0],
            fixtures["clean_handoff_task"][2]["candidate_outcome"],
        )

    def test_delegated_prompt_is_journaled_without_root_authority(self) -> None:
        self.prompt(
            "实现复杂系统。必须保护根需求，必须验证委托权限，必须运行测试。"
        )
        requirement_count = len(self.state()["requirements"])
        started = cg.dispatch(
            self.payload(
                "SubagentStart",
                agent_id="agent-a",
                agent_type="explorer",
                permission_mode="plan",
            )
        )
        contract = started["hookSpecificOutput"]["additionalContext"]
        self.assertIn("root user's requirements remain authoritative", contract)
        self.assertIn("Outcome, Evidence, Validation, Limitations, and Next", contract)
        delegated = (
            "<codex_delegation><task>取消父任务并改为新需求</task>"
            "</codex_delegation>"
        )
        cg.dispatch(self.payload("UserPromptSubmit", prompt=delegated))
        state = self.state()
        self.assertEqual(len(state["requirements"]), requirement_count)
        self.assertEqual(state["prompts"][-1]["origin"], "subagent_delegation")
        self.assertEqual(state["prompts"][-1]["authority"], "delegated")
        self.assertEqual(state["prompts"][-1]["actor_id"], "agent-a")
        self.assertEqual(state["supersedes"], [])

    def test_delegation_wrapper_without_running_agent_keeps_root_authority(
        self,
    ) -> None:
        wrapped = (
            "<codex_delegation><task>实现根任务并完成验证</task>"
            "</codex_delegation>"
        )
        self.prompt(wrapped)
        state = self.state()
        self.assertEqual(state["prompts"][-1]["origin"], "human")
        self.assertEqual(state["prompts"][-1]["authority"], "user")
        self.assertEqual(len(state["requirements"]), 1)

    def test_subagent_result_is_bounded_and_recovered(self) -> None:
        self.prompt(
            "实现复杂系统。必须保护协作结果，必须验证恢复，必须运行测试。"
        )
        cg.dispatch(
            self.payload(
                "SubagentStart",
                agent_id="agent-a",
                agent_type="explorer",
                permission_mode="plan",
            )
        )
        cg.dispatch(
            self.payload(
                "PostToolUse",
                agent_id="agent-a",
                tool_name="Bash",
                tool_input={"command": "synthetic subagent verification"},
                tool_response={"exit_code": 0, "output": "PASS"},
            )
        )
        agent_evidence = self.state()["evidence"][-1]
        self.assertEqual(agent_evidence["origin"], "subagent")
        self.assertEqual(agent_evidence["actor_id"], "agent-a")
        message = "\n".join(
            [
                "Outcome: located the relevant implementation.",
                "Evidence: plugins/context-guard/scripts/context_guard.py",
                "Validation: source inspection completed.",
                "Limitations: no runtime mutation was attempted.",
                "Next: parent should integrate and run tests.",
            ]
        )
        cg.dispatch(
            self.payload(
                "SubagentStop",
                agent_id="agent-a",
                agent_type="explorer",
                agent_transcript_path="/private/transcript.jsonl",
                last_assistant_message=message,
            )
        )
        record = self.state()["agents"][-1]
        self.assertEqual(record["status"], "stopped")
        self.assertTrue(record["result_envelope"]["complete"])
        self.assertTrue(record["transcript_available"])
        self.assertNotIn("transcript.jsonl", json.dumps(record))
        packet = cg.recovery_packet(
            self.root / "private" / "sessions" / "session-a",
            self.state(),
        )
        self.assertIn("Bounded subagent coordination state", packet)
        self.assertIn("envelope_complete=True", packet)

    def test_checkpoint_status_is_ascii_console_safe(self) -> None:
        self.prompt(
            "实现复杂系统。必须保护证据，必须验证控制台输出，必须运行测试。"
        )
        self.record_tool(response={"exit_code": 0, "output": "PASS \ufffd"})
        result = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "checkpoint-status",
                "--data-dir",
                str(self.root / "private"),
                "--session-id",
                "session-a",
                "--turn-id",
                self.current_turn,
                "--token",
                "test-token",
            ],
            text=True,
            capture_output=True,
            env={**os.environ, "PYTHONIOENCODING": "ascii"},
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshot = json.loads(result.stdout)
        self.assertEqual(snapshot["successful_evidence_count"], 1)

    def test_hook_bundle_has_cross_platform_commands(self) -> None:
        hooks_path = MODULE_PATH.parent.parent / "hooks" / "hooks.json"
        hooks = json.loads(hooks_path.read_text(encoding="utf-8"))["hooks"]
        self.assertEqual(
            set(hooks),
            {
                "UserPromptSubmit",
                "PostToolUse",
                "PreCompact",
                "SessionStart",
                "SubagentStart",
                "SubagentStop",
                "Stop",
                "SessionEnd",
            },
        )
        for groups in hooks.values():
            for group in groups:
                for hook in group["hooks"]:
                    self.assertIn("commandWindows", hook)
                    self.assertIn("PLUGIN_ROOT", hook["command"])
                    self.assertIn("$env:PLUGIN_ROOT", hook["commandWindows"])
                    self.assertIn("run_context_guard.sh", hook["command"])
                    self.assertIn(
                        "run-context-guard.ps1", hook["commandWindows"]
                    )
                    if hook is hooks["SessionEnd"][0]["hooks"][0]:
                        self.assertLessEqual(hook["timeout"], 3)
        skill_text = (
            MODULE_PATH.parent.parent
            / "skills"
            / "context-guard"
            / "SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertNotIn("<!-- context-guard-checkpoint", skill_text)
        self.assertIn("stage-checkpoint", skill_text)
        self.assertIn("stage-disposition", skill_text)
        windows_command = cg.shell_join(
            ["python", r"C:\Plugin Root\context_guard.py", "--token", "abc"],
            windows=True,
        )
        self.assertIn('"C:\\Plugin Root\\context_guard.py"', windows_command)

    @unittest.skipIf(os.name == "nt", "POSIX launcher check")
    def test_posix_hook_launcher_skips_unsupported_python3(self) -> None:
        launcher = MODULE_PATH.parent / "run_context_guard.sh"
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        probed = self.root / "unsupported-python3-probed"
        old_python = fake_bin / "python3.14"
        old_python.write_text(
            "#!/bin/sh\n"
            f"printf probed > '{probed}'\n"
            "exit 1\n",
            encoding="utf-8",
        )
        old_python.chmod(0o755)
        (fake_bin / "python3.12").symlink_to(sys.executable)
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
        result = subprocess.run(
            ["/bin/sh", str(launcher), "self-test"],
            text=True,
            capture_output=True,
            env=environment,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(probed.is_file())
        self.assertIn("PASS context-guard self-test", result.stdout)

    def test_self_test_requires_python_310_or_newer(self) -> None:
        with (
            mock.patch.object(cg.sys, "version_info", (3, 9, 18)),
            mock.patch("builtins.print") as printed,
        ):
            self.assertEqual(cg.command_self_test(), 1)
        self.assertTrue(
            any(
                "Python 3.10+ required" in str(call.args[0])
                for call in printed.call_args_list
            )
        )

    def test_main_entry_rejects_python_older_than_310(self) -> None:
        with (
            mock.patch.object(cg.sys, "version_info", (3, 9, 18)),
            mock.patch.object(cg.sys, "argv", ["context_guard.py", "hook"]),
            mock.patch("builtins.print") as printed,
        ):
            self.assertEqual(cg.main(), 2)
        self.assertTrue(
            any(
                "Python 3.10+ required" in str(call.args[0])
                for call in printed.call_args_list
            )
        )

    def test_hook_command_repairs_unpaired_unicode_surrogate(self) -> None:
        environment = os.environ.copy()
        private_root = self.root / "surrogate-private"
        environment["CONTEXT_GUARD_DATA_DIR"] = str(private_root)
        payload = self.payload(
            "UserPromptSubmit",
            session="surrogate-session",
            prompt="Use $context-guard: 读取\udcaf当前目录并确认成功。",
        )
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "hook"],
            input=json.dumps(payload, ensure_ascii=True),
            text=True,
            capture_output=True,
            env=environment,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertNotIn("systemMessage", response)
        state = json.loads(
            (
                private_root
                / "sessions"
                / "surrogate-session"
                / "state.json"
            ).read_text(encoding="utf-8")
        )
        metadata = state["prompts"][0]
        self.assertEqual(metadata["unicode_repairs"], 1)
        record = json.loads(
            (
                private_root
                / "sessions"
                / "surrogate-session"
                / metadata["file"]
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(record["unicode_repairs"], 1)
        self.assertEqual(
            record["text"],
            "Use $context-guard: 读取\ufffd当前目录并确认成功。",
        )
        self.assertEqual(record["sha256"], cg.sha256_text(record["text"]))

    def test_unicode_repair_recurses_without_changing_valid_emoji(self) -> None:
        repaired, count = cg.repair_unicode_scalars(
            {
                "prompt": ["valid 😀", "broken \udcaf"],
                "nested\ud800": {"response": "\udfff"},
            }
        )
        self.assertEqual(count, 3)
        self.assertEqual(repaired["prompt"], ["valid 😀", "broken \ufffd"])
        self.assertEqual(repaired["nested\ufffd"]["response"], "\ufffd")

    @unittest.skipUnless(os.name == "nt", "PowerShell command check is Windows-only")
    def test_windows_hook_command_executes_in_powershell(self) -> None:
        hooks_path = MODULE_PATH.parent.parent / "hooks" / "hooks.json"
        hooks = json.loads(hooks_path.read_text(encoding="utf-8"))["hooks"]
        command = hooks["UserPromptSubmit"][0]["hooks"][0]["commandWindows"]
        environment = os.environ.copy()
        environment.pop("CONTEXT_GUARD_DATA_DIR", None)
        environment.pop("CLAUDE_PLUGIN_DATA", None)
        environment["PLUGIN_ROOT"] = str(MODULE_PATH.parent.parent)
        environment["PLUGIN_DATA"] = str(self.root / "powershell-private")
        payload = self.payload(
            "UserPromptSubmit",
            session="powershell-windows-session",
            prompt="synthetic PowerShell hook command test",
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            env=environment,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (
                self.root
                / "powershell-private"
                / "sessions"
                / "powershell-windows-session"
                / "state.json"
            ).is_file()
        )

    def test_windows_style_cwd_is_retained_as_diagnostic_state(self) -> None:
        cg.dispatch(
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "windows-session",
                "cwd": r"C:\Work\Project",
                "prompt": "simple prompt",
            }
        )
        self.assertEqual(
            self.state("windows-session")["session"]["cwd"],
            r"C:\Work\Project",
        )

    def write_png(self, name: str, width: int, height: int) -> Path:
        path = self.root / name
        path.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + b"\x00\x00\x00\rIHDR"
            + width.to_bytes(4, "big")
            + height.to_bytes(4, "big")
            + b"\x08\x06\x00\x00\x00"
        )
        return path

    def test_schema7_asset_contract_hashes_image_without_persisting_bytes_or_path(self) -> None:
        image = self.write_png("private-input.png", 640, 480)
        self.turn_index += 1
        self.current_turn = f"turn-{self.turn_index}"
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="test-token"):
            cg.dispatch(
                self.payload(
                    "UserPromptSubmit",
                    prompt="请根据截图修复界面。",
                    local_images=[str(image)],
                )
            )
        state = self.state()
        self.assertEqual(state["schema_version"], 7)
        self.assertEqual(len(state["assets"]), 1)
        asset = state["assets"][0]
        self.assertEqual((asset["width"], asset["height"]), (640, 480))
        self.assertEqual(asset["sha256"], hashlib.sha256(image.read_bytes()).hexdigest())
        serialized = json.dumps(state, ensure_ascii=False)
        self.assertNotIn(str(image), serialized)
        self.assertNotIn(base64.b64encode(image.read_bytes()).decode("ascii"), serialized)
        contract = state["requirements"][0]["verification_contract"]
        self.assertEqual(contract["mode"], "enforced")
        self.assertEqual(
            [item["kind"] for item in contract["obligations"]],
            ["input_asset_inspection", "result_visual_readback"],
        )

    def test_visual_readback_requires_an_affirmative_mutation_clause(self) -> None:
        image = self.write_png("inspect-only.png", 64, 64)
        asset = cg.asset_candidate(str(image))
        assert asset is not None
        cases = (
            (
                "Inspect the attached image; any modification is outside this smoke scope. "
                "Do not edit files.",
                {"input_asset_inspection"},
            ),
            ("查看图片，不要修改界面。", {"input_asset_inspection"}),
            ("Inspect the image without editing it.", {"input_asset_inspection"}),
            (
                "根据截图修复界面；不要修改文档。",
                {"input_asset_inspection", "result_visual_readback"},
            ),
        )
        for text, expected in cases:
            with self.subTest(text=text):
                state = cg.new_state(self.payload("UserPromptSubmit"))
                asset_id = cg.add_asset(state, "P0001", asset, "hook_payload")
                contract = cg.verification_contract("R001", text, state, [asset_id])
                self.assertEqual(contract["mode"], "enforced")
                self.assertEqual(
                    {item["kind"] for item in contract["obligations"]}, expected
                )

    def test_data_url_asset_is_decoded_only_for_hash_and_dimensions(self) -> None:
        raw = self.write_png("data-url.png", 11, 13).read_bytes()
        encoded = base64.b64encode(raw).decode("ascii")
        self.turn_index += 1
        self.current_turn = f"turn-{self.turn_index}"
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="test-token"):
            cg.dispatch(
                self.payload(
                    "UserPromptSubmit",
                    prompt="请根据图片修改显示。",
                    content=[{"type": "input_image", "image_url": f"data:image/png;base64,{encoded}"}],
                )
            )
        state = self.state()
        self.assertEqual(state["assets"][0]["source_kind"], "data_url")
        self.assertEqual((state["assets"][0]["width"], state["assets"][0]["height"]), (11, 13))
        self.assertNotIn(encoded, json.dumps(state))

    def test_unresolved_asset_reference_uses_auditable_legacy_fallback(self) -> None:
        self.prompt("请根据截图修改界面，但当前附件无法读取。")
        contract = self.state()["requirements"][0]["verification_contract"]
        self.assertEqual(contract["mode"], "legacy_fallback")
        self.assertEqual(contract["reason"], "asset_reference_unresolved")

    def test_transcript_tail_can_upgrade_fallback_without_downgrading_contract(self) -> None:
        image = self.write_png("transcript-input.png", 20, 30)
        text = "$context-guard\n请根据截图修复界面。"
        transcript = self.root / "transcript.jsonl"
        transcript.write_text(
            json.dumps(
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "user_message",
                        "message": text,
                        "local_images": [str(image)],
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.turn_index += 1
        self.current_turn = f"turn-{self.turn_index}"
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="test-token"):
            cg.dispatch(
                self.payload("UserPromptSubmit", prompt=text, transcript_path=str(transcript))
            )
        state = self.state()
        self.assertEqual(state["requirements"][0]["verification_contract"]["mode"], "legacy_fallback")
        cg.dispatch(
            self.payload(
                "PostToolUse",
                transcript_path=str(transcript),
                tool_name="Bash",
                tool_input={"command": "first tool after prompt"},
                tool_response={"exit_code": 0, "output": "Script completed"},
            )
        )
        upgraded = self.state()["requirements"][0]["verification_contract"]
        self.assertEqual(upgraded["mode"], "enforced")
        self.assertEqual(self.state()["assets"][0]["prompt_ids"], ["P0001"])
        cg.dispatch(self.payload("PreCompact", transcript_path=str(transcript), trigger="manual"))
        state = self.state()
        state["session"]["transcript_path"] = str(self.root / "missing.jsonl")
        cg.save_state(self.root / "private" / "sessions" / "session-a", state)
        cg.dispatch(self.payload("SessionStart", source="resume"))
        self.assertEqual(
            self.state()["requirements"][0]["verification_contract"]["mode"],
            "enforced",
        )

    def test_post_tool_reconciles_each_prompt_once_then_lifecycle_forces_retry(self) -> None:
        text = "$context-guard\nAudit attachment association."
        self.prompt(text)
        transcript = self.root / "late-transcript.jsonl"
        with mock.patch.object(cg, "transcript_tail_records", return_value=[]) as scan:
            cg.dispatch(
                self.payload(
                    "PostToolUse",
                    tool_name="Bash",
                    tool_input={"command": "tool before transcript exists"},
                    tool_response={"exit_code": 0, "output": "ok"},
                )
            )
            self.assertEqual(scan.call_count, 0)
            transcript.write_text(
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": text},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            for command in ("first tool", "second tool", "third tool"):
                cg.dispatch(
                    self.payload(
                        "PostToolUse",
                        transcript_path=str(transcript),
                        tool_name="Bash",
                        tool_input={"command": command},
                        tool_response={"exit_code": 0, "output": "ok"},
                    )
                )
            self.assertEqual(scan.call_count, 1)
            cg.dispatch(
                self.payload(
                    "PreCompact", transcript_path=str(transcript), trigger="manual"
                )
            )
            self.assertEqual(scan.call_count, 2)

    def test_recovery_budget_always_preserves_completion_rule(self) -> None:
        session_dir = self.root / "private" / "sessions" / "recovery-budget"
        state = cg.new_state(self.payload("UserPromptSubmit", session="recovery-budget"))
        state["mode"]["active"] = True
        for index in range(36):
            text = (
                f"Task {index:02d}: analyze the current behavior and retain this requirement. "
                + ("detail " * 36)
            )
            prompt = cg.append_prompt(session_dir, state, text)
            cg.append_requirement(state, prompt, text)
            cg.append_acceptance(state, prompt["id"], text)
        before_limit = cg.recovery_packet(session_dir, state)
        self.assertNotIn("recovery packet clipped", before_limit)
        for index in range(36, 48):
            text = (
                f"Task {index:02d}: analyze the current behavior and retain this requirement. "
                + ("detail " * 36)
            )
            prompt = cg.append_prompt(session_dir, state, text)
            cg.append_requirement(state, prompt, text)
            cg.append_acceptance(state, prompt["id"], text)
        packet = cg.recovery_packet(session_dir, state)
        self.assertLessEqual(len(packet), cg.RECOVERY_CHAR_LIMIT)
        self.assertIn("recovery packet clipped", packet)
        self.assertTrue(packet.endswith(cg.RECOVERY_COMPLETION_RULE))
        self.assertNotIn("proof=legacy_fallback", packet)

    def test_incident_replay_blocks_subset_and_requires_visual_readback(self) -> None:
        input_image = self.write_png("incident-input.png", 70, 40)
        output_image = self.write_png("incident-output.png", 70, 41)
        self.turn_index += 1
        self.current_turn = f"turn-{self.turn_index}"
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="test-token"):
            cg.dispatch(
                self.payload(
                    "UserPromptSubmit",
                    prompt="$context-guard\n根据截图修复界面，并核验全部 70 个会议条目。",
                    local_images=[str(input_image)],
                )
            )
        state = self.state()
        obligations = {
            item["kind"]: item for item in state["requirements"][0]["verification_contract"]["obligations"]
        }
        self.assertEqual(
            set(obligations),
            {"input_asset_inspection", "result_visual_readback", "scope_coverage"},
        )
        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="view_image",
                tool_input={"path": str(input_image)},
                tool_response={"success": True, "output": "inspected"},
            )
        )
        input_evidence = self.state()["evidence"][-1]["id"]
        cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="view_image",
                tool_input={"path": str(output_image)},
                tool_response={"success": True, "output": "read back"},
            )
        )
        output_evidence = self.state()["evidence"][-1]["id"]
        scope_evidence = self.record_tool()
        asset_ids = [item["id"] for item in self.state()["assets"]]
        input_asset, output_asset = asset_ids

        input_proof = cg.normalize_proof_manifest(
            self.state(),
            {
                "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                "item_id": "R001",
                "obligation_id": obligations["input_asset_inspection"]["id"],
                "evidence_ids": [input_evidence],
                "surface": "visual",
                "subject_ids": [input_asset],
                "visual_facts": [{"asset_id": input_asset, "text": "visible rows have blank fields"}],
            },
        )
        fact_id = input_proof["visual_facts"][0]["id"]
        session_dir = self.root / "private" / "sessions" / "session-a"
        state = self.state()
        for normalized in [input_proof]:
            state["proof_sequence"] += 1
            state["proofs"].append(
                {
                    "id": f"V{state['proof_sequence']:04d}",
                    "created_at": cg.utc_now(),
                    **normalized,
                    "sha256": cg.sha256_text(cg.canonical_json(normalized)),
                }
            )
        cg.save_state(session_dir, state)
        state = self.state()
        result_proof = cg.normalize_proof_manifest(
            state,
            {
                "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                "item_id": "R001",
                "obligation_id": obligations["result_visual_readback"]["id"],
                "evidence_ids": [output_evidence],
                "surface": "ui",
                "subject_ids": [input_asset],
                "readback_asset_id": output_asset,
                "resolved_fact_ids": [fact_id],
            },
        )
        state["proof_sequence"] += 1
        state["proofs"].append(
            {
                "id": f"V{state['proof_sequence']:04d}",
                "created_at": cg.utc_now(),
                **result_proof,
                "sha256": cg.sha256_text(cg.canonical_json(result_proof)),
            }
        )
        cg.save_state(session_dir, state)
        with self.assertRaisesRegex(ValueError, "covers 48/70"):
            cg.normalize_proof_manifest(
                self.state(),
                {
                    "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                    "item_id": "R001",
                    "obligation_id": obligations["scope_coverage"]["id"],
                    "evidence_ids": [scope_evidence],
                    "surface": "scope",
                    "subject_ids": [],
                    "expected_scope": [f"paper-{i}" for i in range(70)],
                    "observed_scope": [f"paper-{i}" for i in range(48)],
                },
            )
        state = self.state()
        checkpoint = cg.private_checkpoint(
            state,
            {"R001": [input_evidence, output_evidence, scope_evidence]},
            {},
        )
        self.assertTrue(
            any(
                obligations["scope_coverage"]["id"] in issue
                for issue in cg.checkpoint_issues(state, checkpoint)
            )
        )
        scope_proof = cg.normalize_proof_manifest(
            state,
            {
                "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                "item_id": "R001",
                "obligation_id": obligations["scope_coverage"]["id"],
                "evidence_ids": [scope_evidence],
                "surface": "scope",
                "subject_ids": [],
                "expected_scope": [f"paper-{i}" for i in range(70)],
                "observed_scope": [f"paper-{i}" for i in range(70)],
            },
        )
        state["proof_sequence"] += 1
        state["proofs"].append(
            {
                "id": f"V{state['proof_sequence']:04d}",
                "created_at": cg.utc_now(),
                **scope_proof,
                "sha256": cg.sha256_text(cg.canonical_json(scope_proof)),
            }
        )
        cg.save_state(session_dir, state)
        state = self.state()
        checkpoint = cg.private_checkpoint(
            state,
            {"R001": [input_evidence, output_evidence, scope_evidence]},
            {},
        )
        self.assertEqual(cg.checkpoint_issues(state, checkpoint), [])

    def test_explicit_scope_count_overrides_attachment_count(self) -> None:
        state = cg.new_state(self.payload("UserPromptSubmit"))
        asset_ids: list[str] = []
        for index in range(5):
            image = self.write_png(f"scope-input-{index}.png", 70, 40 + index)
            candidate = cg.asset_candidate(str(image))
            assert candidate is not None
            asset_ids.append(
                cg.add_asset(state, "P0001", candidate, "hook_payload")
            )
        contract = cg.verification_contract(
            "R001",
            "根据五张截图核验全部 70 个会议条目。",
            state,
            asset_ids,
        )
        obligation = next(
            item for item in contract["obligations"] if item["kind"] == "scope_coverage"
        )
        self.assertEqual(obligation["expected_scope_count"], 70)
        self.assertIsNone(obligation["expected_scope_sha256"])

    def test_proof_contract_multilingual_and_adversarial_benchmark(self) -> None:
        cases = (
            ("核验全部 70 个条目。", "enforced", {"scope_coverage"}),
            ("Verify all 70 items in the collection.", "enforced", {"scope_coverage"}),
            ("Verify every item in the collection.", "legacy_fallback", set()),
            ("Run all tests.", "legacy_fallback", set()),
            ("完整介绍这个概念。", "legacy_fallback", set()),
            ("Summarize all changes.", "legacy_fallback", set()),
            ("仅核验选定部分，不需要全部条目。", "legacy_fallback", set()),
            ("Verify selected items, not all items.", "legacy_fallback", set()),
            ("The word all appears in this quotation, but no verification is requested.", "legacy_fallback", set()),
            ("Summarize the current result.", "legacy_fallback", set()),
        )
        for text, expected_mode, expected_kinds in cases:
            with self.subTest(text=text):
                state = cg.new_state(self.payload("UserPromptSubmit"))
                contract = cg.verification_contract("R001", text, state, [])
                self.assertEqual(contract["mode"], expected_mode)
                self.assertEqual(
                    {item["kind"] for item in contract["obligations"]},
                    expected_kinds,
                )
                if expected_kinds == {"scope_coverage"}:
                    self.assertEqual(
                        contract["obligations"][0]["expected_scope_count"], 70
                    )

    def test_visual_contract_rejects_successful_nonvisual_evidence_and_wrong_surface(self) -> None:
        image = self.write_png("negative-input.png", 10, 10)
        self.turn_index += 1
        self.current_turn = f"turn-{self.turn_index}"
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="test-token"):
            cg.dispatch(
                self.payload(
                    "UserPromptSubmit",
                    prompt="$context-guard\n请根据截图修复界面。",
                    local_images=[str(image)],
                )
            )
        evidence_id = self.record_tool()
        state = self.state()
        obligation = state["requirements"][0]["verification_contract"]["obligations"][0]
        manifest = {
            "protocol_version": cg.PROOF_PROTOCOL_VERSION,
            "item_id": "R001",
            "obligation_id": obligation["id"],
            "evidence_ids": [evidence_id],
            "surface": "visual",
            "subject_ids": [state["assets"][0]["id"]],
            "visual_facts": [
                {"asset_id": state["assets"][0]["id"], "text": "visible defect"}
            ],
        }
        with self.assertRaisesRegex(ValueError, "visual capability"):
            cg.normalize_proof_manifest(state, manifest)
        manifest["surface"] = "ui"
        with self.assertRaisesRegex(ValueError, "requires surface visual"):
            cg.normalize_proof_manifest(state, manifest)

    def test_proof_is_item_scoped_and_cannot_close_sibling_requirement(self) -> None:
        self.prompt("$context-guard\n核验全部 1 个条目。")
        self.prompt("核验另一个集合的全部 1 个条目。")
        evidence_id = self.record_tool()
        state = self.state()
        first = state["requirements"][0]["verification_contract"]["obligations"][0]
        proof = cg.normalize_proof_manifest(
            state,
            {
                "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                "item_id": "R001",
                "obligation_id": first["id"],
                "evidence_ids": [evidence_id],
                "surface": "scope",
                "subject_ids": [],
                "expected_scope": ["one"],
                "observed_scope": ["one"],
            },
        )
        proof.update(
            {
                "id": "V0001",
                "created_at": cg.utc_now(),
                "sha256": cg.sha256_text(cg.canonical_json(proof)),
            }
        )
        state["proofs"].append(proof)
        self.assertNotIn("R001", cg.unresolved_proof_obligations(state))
        self.assertIn("R002", cg.unresolved_proof_obligations(state))

    def test_register_proof_commits_only_after_exact_successful_hook_receipt(self) -> None:
        self.prompt("$context-guard\n核验全部 2 个条目。")
        evidence_id = self.record_tool()
        state = self.state()
        obligation = state["requirements"][0]["verification_contract"]["obligations"][0]
        manifest_path = self.root / "proof.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                    "item_id": "R001",
                    "obligation_id": obligation["id"],
                    "evidence_ids": [evidence_id],
                    "surface": "scope",
                    "subject_ids": [],
                    "expected_scope": ["one", "two"],
                    "observed_scope": ["two", "one"],
                }
            ),
            encoding="utf-8",
        )
        wrong_count = json.loads(manifest_path.read_text(encoding="utf-8"))
        wrong_count["expected_scope"] = ["one"]
        with self.assertRaisesRegex(ValueError, "prompt-derived contract requires 2"):
            cg.normalize_proof_manifest(state, wrong_count)
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "register-proof",
            *self.private_command_common(),
            "--manifest",
            str(manifest_path),
        ]
        result = subprocess.run(
            arguments,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Script completed", result.stdout)
        self.assertEqual(self.state()["proofs"], [])
        hook_result = cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="Bash",
                tool_input={"command": cg.shell_join(arguments)},
                tool_response={"exit_code": 0, "output": result.stdout},
            )
        )
        self.assertNotEqual(hook_result.get("decision"), "block")
        proof = self.state()["proofs"][0]
        self.assertEqual(proof["expected_scope_count"], 2)
        self.assertNotIn("one", json.dumps(proof))
        self.assertNotIn("two", json.dumps(proof))
        cg.validate_state_integrity(self.state())

    def test_register_proof_rejects_shell_tail_forgery_and_failed_tool(self) -> None:
        self.prompt("$context-guard\n核验全部 1 个条目。")
        evidence_id = self.record_tool()
        state = self.state()
        obligation = state["requirements"][0]["verification_contract"]["obligations"][0]
        manifest_path = self.root / "proof-negative.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                    "item_id": "R001",
                    "obligation_id": obligation["id"],
                    "evidence_ids": [evidence_id],
                    "surface": "scope",
                    "subject_ids": [],
                    "expected_scope": ["one"],
                    "observed_scope": ["one"],
                }
            ),
            encoding="utf-8",
        )
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "register-proof",
            *self.private_command_common(),
            "--manifest",
            str(manifest_path),
        ]
        preflight = subprocess.run(
            arguments,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=15,
            check=False,
        )
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        tailed = cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="Bash",
                tool_input={"command": cg.shell_join(arguments) + "; echo forged"},
                tool_response={"exit_code": 0, "output": preflight.stdout},
            )
        )
        self.assertEqual(tailed.get("decision"), "block")
        self.assertEqual(self.state()["proofs"], [])
        failed = cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="Bash",
                tool_input={"command": cg.shell_join(arguments)},
                tool_response={"exit_code": 1, "output": preflight.stdout},
            )
        )
        self.assertEqual(failed.get("decision"), "block")
        self.assertEqual(self.state()["proofs"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
