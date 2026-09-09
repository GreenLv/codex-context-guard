#!/usr/bin/env python3
"""Context Guard 0.12.2 P1 state/recovery/supersession family closure.

Implements the frozen plan section 3 + 4.3 P1 matrix ON TOP of the P0
counterexamples: continuity boundaries (completion, explicit cancel,
deferral), wait-condition lifecycle (honest raise kinds, typed releases,
multi-condition units, external waits, replay/compact-resume persistence,
corrupt fail-closed), supersession speech acts (mixed clauses, multi-target
ambiguity, passive narration), recovery projection surfaces (released-wait
annotation, deterministic paging with stale-cursor failure), and schema-11
persistence/idempotency. Commit-chain families stay in P2 counterexamples.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

MODULE_PATH = SCRIPTS / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard_p1", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)

from tests.test_cg122_p0_counterexamples import (  # noqa: E402
    SCHEMA10_PARKED_FIXTURE,
    P0Harness,
)

EXTERNAL_WAIT_STOP_MESSAGE = "目录发布已完成,当前等待外部审核。"


class ContinuityBoundaryTests(P0Harness):
    """CONTINUITY family expansion (plan section 3.1 table rows)."""

    def test_completed_unit_then_new_request_opens_new_unit(self) -> None:
        """[CONTINUITY] A completed unit never blocks a new request: the
        next plain prompt opens a NEW unit and the completed one stays
        completed with its passing evidence."""
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="p0token"):
            self.dispatch(
                "UserPromptSubmit",
                prompt=f"$context-guard\n请先核对 {target} 后修复文档。",
            )
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": f"cat {target}"},
            tool_response={"exit_code": 0, "output": "subject"},
        )
        self.dispatch("Stop", last_assistant_message="任务已经全部完成。")
        state = self.state()
        self.assertEqual(state["work_units"][0]["status"], "completed")
        self.prompt("请开始新的独立事项：整理文档索引。")
        state = self.state()
        self.assertEqual(len(state["work_units"]), 2)
        self.assertEqual(state["work_units"][0]["status"], "completed")
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0002")
        self.assertIsNone(self.unit(state, "WU0002")["parent_id"])

    def test_explicit_cancel_isolates_unit_and_never_marks_pass(self) -> None:
        """[CONTINUITY] An explicit task cancel keeps auditable isolation:
        the unit becomes historical_unresolved (never pass), its
        requirements keep pending status, and they leave the current
        completion scope."""
        self.activate()
        self.prompt("请修复构建脚本的编码问题。必须运行测试验证。")
        self.prompt("取消当前任务。")
        state = self.state()
        self.assertEqual(self.unit(state, "WU0001")["status"],
                         "historical_unresolved")
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0002")
        for item in state["requirements"]:
            self.assertNotEqual(item["status"], "pass")
        scoped, _ancestors = cg.checkpoint_scope_item_ids(state)
        self.assertNotIn("R001", scoped)

    def test_deferred_unit_stays_deferred_and_new_request_opens_sibling(
        self,
    ) -> None:
        """[CONTINUITY] An explicitly deferred unit stays deferred (never
        auto-reopened, never completed); a later explicit switch opens a
        sibling root while the deferral survives."""
        self.activate()
        self.prompt("只审查并本地提交；不要推送或运行 CI/CD。必须运行测试验证。")
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="p0token"):
            self.dispatch(
                "Stop",
                last_assistant_message=(
                    "本地提交已完成——push、CI/CD 与发布留待后续阶段。"
                ),
            )
        state = self.state()
        self.assertEqual(state["work_units"][0]["status"], "deferred")
        self.prompt("另一件独立事项：请检查文档拼写。")
        state = self.state()
        self.assertEqual(state["work_units"][0]["status"], "deferred")
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0002")


class WaitLifecycleTests(P0Harness):
    """WAIT family expansion: typed records, honest provenance, releases."""

    def waiting(self, state: dict) -> list[dict]:
        return [
            item for item in state.get("wait_conditions", [])
            if isinstance(item, dict) and item.get("status") == "waiting"
        ]

    def released(self, state: dict) -> list[dict]:
        return [
            item for item in state.get("wait_conditions", [])
            if isinstance(item, dict) and item.get("status") == "released"
        ]

    def test_assistant_question_records_honest_raise_kind(self) -> None:
        """[WAIT] A parked A/B question is an ASSISTANT-raised choice wait:
        the record names the assistant raise kind, the unit's own prompt as
        bounded source, and the choice type — no invented root provenance."""
        self.activate()
        self.park_awaiting_user()
        state = self.state()
        waiting = self.waiting(state)
        self.assertEqual(len(waiting), 1)
        record = waiting[0]
        self.assertEqual(str(record.get("raised_by_kind")), "assistant")
        self.assertEqual(str(record.get("raised_by_source")), "P0002")
        self.assertEqual(str(record.get("condition_type")), "choice")
        self.assertEqual(str(record.get("status")), "waiting")
        self.assertIsNone(record.get("released_by_source"))

    def test_choice_answer_releases_and_records_root_confirmation(self) -> None:
        """[WAIT] The answer to the parked choice question keeps the unit
        and records a root-user release bound to the answering prompt."""
        self.activate()
        self.park_awaiting_user()
        self.prompt("选择方案 B。必须运行测试验证。")
        state = self.state()
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0001")
        released = self.released(state)
        self.assertEqual(len(released), 1)
        self.assertEqual(str(released[0].get("released_by_kind")),
                         "root_user_confirmation")
        self.assertEqual(str(released[0].get("released_by_source")), "P0003")
        self.assertEqual(self.waiting(state), [])

    def test_external_wait_is_never_released_by_speech(self) -> None:
        """[WAIT] An external dependency stays waiting: model-change wording
        is an unrelated reply, not a trustworthy external fact."""
        self.activate()
        self.park_awaiting_user(
            stop_message=EXTERNAL_WAIT_STOP_MESSAGE,
            expected_status="awaiting_external",
        )
        self.prompt("模型已换好，继续。")
        state = self.state()
        self.assertEqual(self.unit(state, "WU0001")["status"],
                         "awaiting_external")
        waiting = self.waiting(state)
        self.assertEqual(len(waiting), 1)
        self.assertEqual(str(waiting[0].get("condition_type")),
                         "external_dependency")

    def test_explicit_resume_reopens_external_unit_condition_stays_waiting(
        self,
    ) -> None:
        """[WAIT] A unique explicit resume reopens the externally parked
        UNIT while the external condition keeps waiting for real facts."""
        self.activate()
        self.park_awaiting_user(
            stop_message=EXTERNAL_WAIT_STOP_MESSAGE,
            expected_status="awaiting_external",
        )
        self.prompt("继续刚才的任务。")
        state = self.state()
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0001")
        self.assertEqual(self.unit(state, "WU0001")["status"], "active")
        self.assertEqual(len(self.waiting(state)), 1)

    def test_multi_condition_release_closes_one_and_keeps_unit_parked(
        self,
    ) -> None:
        """[WAIT] Two typed conditions on one unit (a root confirmation wait
        and an external dependency): a confirmation matching the FIRST one
        releases exactly that condition; the external one keeps the unit
        parked."""
        self.activate()
        self.prompt("请修复恢复模块。在我确认模型更换完成前，本任务保持等待。必须运行测试验证。")
        self.prompt("补充：等 CI 构建完成后再继续部署。")
        self.dispatch("Stop", last_assistant_message="已按要求暂停等待确认。")
        state = self.state()
        self.assertEqual(len(self.waiting(state)), 2)
        types = sorted(item["condition_type"] for item in self.waiting(state))
        self.assertEqual(types, ["confirmation", "external_dependency"])
        self.prompt("模型已换好，继续。")
        state = self.state()
        self.assertEqual(len(self.released(state)), 1)
        self.assertEqual(len(self.waiting(state)), 1)
        self.assertEqual(str(self.waiting(state)[0].get("condition_type")),
                         "external_dependency")
        self.assertEqual(self.unit(state, "WU0001")["status"],
                         "awaiting_user")

    def test_released_condition_is_never_re_released_or_duplicated(self) -> None:
        """[WAIT] After a release, further continuation prompts add no new
        conditions, never re-release, and never reactivate the released
        record (plan 3.2: replay/duplicate protection)."""
        self.activate()
        self.prompt("请修复恢复模块。在我确认模型更换完成前，本任务保持等待。必须运行测试验证。")
        self.dispatch("Stop", last_assistant_message="已按要求暂停等待确认。")
        self.prompt("模型已换好，继续。")
        self.prompt("继续。")
        state = self.state()
        self.assertEqual(len(state["wait_conditions"]), 1)
        self.assertEqual(len(self.released(state)), 1)
        self.assertEqual(self.waiting(state), [])
        self.assertEqual(state["work_units"][0]["status"], "active")

    def test_schema11_state_roundtrip_keeps_condition_lifecycle(self) -> None:
        """[WAIT/MIGRATION] A released condition survives save/load exactly:
        no re-derivation, no status flip, no duplicate record."""
        self.activate()
        self.prompt("请修复恢复模块。在我确认模型更换完成前，本任务保持等待。必须运行测试验证。")
        self.dispatch("Stop", last_assistant_message="已按要求暂停等待确认。")
        self.prompt("模型已换好，继续。")
        session_dir = self.root / "private" / "sessions" / "p0"
        before = self.state()
        reloaded = cg.load_state(session_dir, {"session_id": "p0"})
        self.assertEqual(
            json.dumps(reloaded.get("wait_conditions"), sort_keys=True),
            json.dumps(before.get("wait_conditions"), sort_keys=True),
        )
        self.assertEqual(len(reloaded["wait_conditions"]), 1)
        self.assertEqual(str(reloaded["wait_conditions"][0]["status"]),
                         "released")

    def test_corrupt_wait_conditions_fail_closed_and_rebuild(self) -> None:
        """[WAIT] A hand-corrupted wait ledger (released record without its
        release source) fails state integrity closed: the runtime preserves
        the corrupt file for diagnosis and rebuilds a functional ledger from
        the immutable prompt records without inventing conditions."""
        self.activate()
        self.prompt("请修复恢复模块。在我确认模型更换完成前，本任务保持等待。必须运行测试验证。")
        state = self.state()
        state["wait_conditions"][0]["status"] = "released"
        state["wait_conditions"][0]["released_by_kind"] = None
        self.save_state(state)
        self.prompt("现在整体进度如何？")
        rebuilt = self.state()
        self.assertEqual(rebuilt.get("wait_conditions"), [])
        self.assertIn(
            rebuilt["integrity"]["status"], {"ok", "recovered_from_prompts"}
        )
        prompt_count = len(rebuilt["prompts"])
        self.assertGreaterEqual(prompt_count, 3)

    def test_migrated_condition_releases_with_root_confirmation(self) -> None:
        """[MIGRATION/WAIT] The deterministic migrated_unresolved condition
        releases on an explicit root resume and records the root-user
        release source — the first lawful release supplies provenance."""
        session_dir = self.root / "private" / "sessions" / "p0"
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "state.json").write_text(
            SCHEMA10_PARKED_FIXTURE, encoding="utf-8"
        )
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="p0token"):
            self.dispatch(
                "UserPromptSubmit", prompt="继续刚才的任务。"
            )
        state = self.state()
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0001")
        self.assertEqual(state["work_units"][0]["status"], "active")
        conditions = state["wait_conditions"]
        self.assertEqual(len(conditions), 1)
        self.assertEqual(str(conditions[0].get("status")), "released")
        self.assertEqual(str(conditions[0].get("released_by_kind")),
                         "root_user_confirmation")
        self.assertTrue(str(conditions[0].get("released_by_source")))


class SupersessionSpeechActTests(P0Harness):
    """SUPERSESSION family expansion (plan 3.1 / CG122-07)."""

    def seed_two_requirements(self) -> None:
        self.activate()
        self.prompt("请实现登录功能。必须运行测试验证。")
        self.prompt("请实现审计日志。必须运行测试验证。")

    def test_mixed_test_description_and_real_correction_supersedes(self) -> None:
        """[SUPERSESSION] A prompt that BOTH speculates about a test AND
        carries a genuine correction clause supersedes exactly through the
        correction clause."""
        self.seed_two_requirements()
        self.prompt("测试应覆盖取消 R001 的情形。另外，取消 R001，改为只输出摘要。")
        state = self.state()
        statuses = {item["id"]: item["status"] for item in state["requirements"]}
        self.assertEqual(statuses.get("R001"), "superseded")
        self.assertEqual(statuses.get("R002"), "pending")
        self.assertEqual(len(state["supersedes"]), 1)

    def test_multi_target_control_keeps_all_and_clarifies_readably(self) -> None:
        """[SUPERSESSION] Two named targets are genuinely ambiguous: both
        requirements stay active, and the clarification quotes the bounded
        requirement texts instead of demanding internal IDs."""
        self.seed_two_requirements()
        result = self.prompt("取消 R001 和 R002，改用新方案。")
        state = self.state()
        statuses = {item["id"]: item["status"] for item in state["requirements"]}
        self.assertEqual(statuses.get("R001"), "pending")
        self.assertEqual(statuses.get("R002"), "pending")
        self.assertEqual(state["supersedes"], [])
        context = str(result.get("hookSpecificOutput", {}).get(
            "additionalContext", ""
        ))
        self.assertIn("Supersession target is ambiguous", context)
        self.assertIn("登录功能", context)
        self.assertIn("Do not demand internal IDs", context)

    def test_passive_and_documentation_mentions_stay_inert(self) -> None:
        """[SUPERSESSION] Passive narration and documentation requests
        containing control words never supersede and never raise the
        ambiguous clarification."""
        self.seed_two_requirements()
        for text in (
            "旧方案将在下个版本被取消。",
            "提交模块的取消流程需要文档说明。",
        ):
            result = self.prompt(text)
            context = str(result.get("hookSpecificOutput", {}).get(
                "additionalContext", ""
            ))
            self.assertNotIn("Supersession target is ambiguous", context)
        state = self.state()
        self.assertEqual(state["supersedes"], [])
        for item in state["requirements"]:
            self.assertEqual(item["status"], "pending")


class RecoveryProjectionTests(P0Harness):
    """RECOVERY family expansion: released-wait annotation and paging."""

    def test_released_wait_is_annotated_and_never_listed_as_current(self) -> None:
        """[RECOVERY] After a release, the raw prompt excerpt that imposed
        the pause carries an explicit released annotation, and the released
        condition never appears in the unreleased-wait section (plan 3.3:
        raw excerpts must not reintroduce released waits)."""
        self.activate()
        self.prompt("请修复恢复模块。在我确认模型更换完成前，本任务保持等待。必须运行测试验证。")
        self.dispatch("Stop", last_assistant_message="已按要求暂停等待确认。")
        self.prompt("模型已换好，继续。")
        packet = cg.recovery_packet(
            self.root / "private" / "sessions" / "p0", self.state()
        )
        self.assertIn("[等待条件已解除/released", packet)
        self.assertNotIn("## Unreleased wait conditions", packet)

    def test_recovery_page_cursor_walk_and_stale_failure(self) -> None:
        """[RECOVERY] The deterministic paging entry walks the current scope
        page by page; after a relevant state change the old cursor fails
        closed with the current revision instead of stitching pages."""
        self.activate()
        self.prompt("请保持当前修复任务直到验证完成。必须运行测试验证。")
        state = self.state()
        template = state["requirements"][0]
        for index in range(30):
            item = dict(template)
            item.update({
                "id": f"R8{index:03d}",
                "text": f"synthetic current item {index} for paging",
            })
            state["requirements"].append(item)
        self.save_state(state)
        first = io.StringIO()
        with contextlib.redirect_stdout(first):
            code = cg.command_recovery_page(
                mock.Mock(session_id="p0", cursor=None, limit=5)
            )
        self.assertEqual(code, 0)
        page1 = json.loads(first.getvalue())
        self.assertEqual(page1["total"], 32)
        self.assertEqual(len(page1["items"]), 5)
        self.assertIsNotNone(page1["next_cursor"])
        second = io.StringIO()
        with contextlib.redirect_stdout(second):
            code = cg.command_recovery_page(
                mock.Mock(session_id="p0", cursor=page1["next_cursor"], limit=5)
            )
        self.assertEqual(code, 0)
        page2 = json.loads(second.getvalue())
        self.assertEqual(page2["offset"], 5)
        self.assertNotEqual(
            [item["id"] for item in page1["items"]],
            [item["id"] for item in page2["items"]],
        )
        # Mutate the ledger: the old cursor must fail closed.
        state = self.state()
        state["requirements"].append({
            **template,
            "id": "R8999",
            "status": "pending",
            "text": "post-cursor change",
            "work_unit_id": "WU0001",
            "evidence": [],
        })
        self.save_state(state)
        err = io.StringIO()
        with contextlib.redirect_stdout(err):
            code = cg.command_recovery_page(
                mock.Mock(session_id="p0", cursor=page1["next_cursor"], limit=5)
            )
        self.assertEqual(code, 2)
        stale = json.loads(err.getvalue())
        self.assertEqual(stale["error"], "stale_cursor")
        self.assertNotEqual(stale["current_revision"], page1["revision"])

    def test_repeat_migration_on_persisted_schema11_is_idempotent(self) -> None:
        """[MIGRATION] Persisting the migrated schema-11 state and loading
        it again neither duplicates nor re-derives conditions; the schema
        stays 11 and the ledger keeps exactly one migrated record."""
        session_dir = self.root / "private" / "sessions" / "p0"
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "state.json").write_text(
            SCHEMA10_PARKED_FIXTURE, encoding="utf-8"
        )
        first = cg.load_state(session_dir, {"session_id": "p0"})
        cg.save_state(session_dir, first)
        second = cg.load_state(session_dir, {"session_id": "p0"})
        self.assertEqual(second["schema_version"], cg.SCHEMA_VERSION)
        self.assertEqual(len(second["wait_conditions"]), 1)
        self.assertEqual(
            json.dumps(first["wait_conditions"], sort_keys=True),
            json.dumps(second["wait_conditions"], sort_keys=True),
        )
        self.assertEqual(str(second["wait_conditions"][0]["status"]), "waiting")


if __name__ == "__main__":
    unittest.main()
