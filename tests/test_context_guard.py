#!/usr/bin/env python3
"""Unit and synthetic hook regression tests for Context Guard."""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)


class ContextGuardTests(unittest.TestCase):
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
        self.assertNotIn("<!--", activation)
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
            self.state()["completion_attempt"]["staged_checkpoint"]
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
        state["completion_attempt"]["staged_checkpoint"] = {
            "status": "complete",
            "requirements": {
                "R001": {"status": "pass", "evidence": [evidence_id]}
            },
            "acceptance": {},
            "open_items": [],
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
        state["completion_attempt"]["staged_checkpoint"] = "corrupt"
        cg.save_state(session_dir, state)
        result = cg.dispatch(
            self.payload("Stop", last_assistant_message="任务已经完成。")
        )
        self.assertEqual(result["decision"], "block")
        self.assertIn("invalid staged private checkpoint", result["reason"])
        self.assertIsNone(self.state()["completion_checkpoint"])

    def test_common_completion_phrases_are_detected(self) -> None:
        for message in (
            "已修复并推送。",
            "处理好了，可以交付。",
            "29 项回归测试全量通过。",
            "修好了，可以使用了。",
            "Fixed, verified, and pushed.",
            "All regression tests passed.",
        ):
            with self.subTest(message=message):
                self.assertTrue(cg.claims_completion(message))

    def test_explicit_incomplete_report_does_not_loop(self) -> None:
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

    def test_partial_milestone_reports_do_not_trigger_continuations(self) -> None:
        self.prompt(
            "实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。"
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
                self.assertFalse(cg.claims_completion(message))
                self.assertEqual(
                    cg.dispatch(
                        self.payload("Stop", last_assistant_message=message)
                    ),
                    {},
                )
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
        self.assertEqual(migrated["schema_version"], 3)
        self.assertEqual(migrated["evidence_sequence"], 1)
        self.assertEqual(migrated["work_state"], {"plan_snapshot": None})
        self.assertEqual(migrated["agents"], [])
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
        legacy["content_hash"] = cg.state_content_hash(legacy)
        cg.atomic_write_json(session_dir / "state.json", legacy)

        self.prompt("继续验证从 0.2.1 状态迁移后的任务。")

        migrated = self.state()
        self.assertEqual(migrated["schema_version"], 3)
        self.assertEqual(migrated["integrity"]["status"], "ok")
        self.assertEqual(migrated["evidence_sequence"], 1)
        self.assertEqual(len(migrated["evidence"]), 1)
        self.assertEqual(migrated["work_state"], {"plan_snapshot": None})
        self.assertEqual(migrated["agents"], [])

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
                tool_response=staged.stdout,
            )
        )
        self.assertIn("privately staged", json.dumps(hook_result))
        self.assertIsNotNone(
            self.state()["completion_attempt"]["staged_checkpoint"]
        )

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
                tool_response=staged.stdout,
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
            self.state()["completion_attempt"]["staged_checkpoint"]
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
                "Evidence: scripts/context_guard.py",
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
        windows_command = cg.shell_join(
            ["python", r"C:\Plugin Root\context_guard.py", "--token", "abc"],
            windows=True,
        )
        self.assertIn('"C:\\Plugin Root\\context_guard.py"', windows_command)

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
        windows_cwd = "C:\\" + "Users\\Research\\Project"
        cg.dispatch(
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "windows-session",
                "cwd": windows_cwd,
                "prompt": "simple prompt",
            }
        )
        self.assertEqual(
            self.state("windows-session")["session"]["cwd"],
            windows_cwd,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
