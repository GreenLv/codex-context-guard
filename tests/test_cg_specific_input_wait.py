"""Root-sourced waits distinguish supplied input from permission to continue."""
from __future__ import annotations

import base64
import json
from unittest import mock

from tests.test_cg122_p0_counterexamples import SCHEMA10_PARKED_FIXTURE, P0Harness, cg


class SpecificInputWaitTests(P0Harness):
    def waiting(self):
        return [row for row in self.state()["wait_conditions"]
                if row["status"] == "waiting"]

    def test_exact_marker_arrives_after_bare_resume_and_wrong_marker(self):
        self.activate()
        self.prompt("等我发来标记 ALPHA-73 再继续分析。")
        self.dispatch("Stop", last_assistant_message="按要求等待标记。")
        old_stop = self.state()["decision_log"][-1]
        self.assertEqual(len(self.waiting()), 1)

        self.prompt("继续。")
        self.assertEqual(len(self.waiting()), 1)
        self.assertEqual(self.state()["work_units"][0]["status"], "awaiting_user")
        self.prompt("标记 BETA-91 已发来，继续。")
        self.assertEqual(len(self.waiting()), 1)

        # The exact root input itself is evidence; a formulaic completion
        # declaration is not required when the named marker is supplied.
        self.prompt("标记 ALPHA-73")
        state = self.state()
        self.assertEqual(self.waiting(), [])
        self.assertEqual(state["wait_conditions"][0]["released_by_source"],
                         state["prompts"][-1]["id"])
        self.assertEqual(state["work_units"][0]["status"], "active")
        self.assertEqual(state["decision_log"][0], old_stop)

    def test_direct_bare_markers_are_not_fixed_wording_templates(self):
        cases = (
            ("请等待我随后明确发送 READY_Q7 才继续。", "READY_Q7"),
            ("Wait until I provide ACK-42 before continuing.", "ACK-42"),
            ("等我发来 YES 再继续分析。", "YES"),
            ("等我发来 READY 再继续分析。", "READY"),
            ("等我发来 ACK-DONE 再继续分析。", "ACK-DONE"),
        )
        for index, (root, marker) in enumerate(cases):
            session = f"marker-{index}"
            with self.subTest(root=root):
                self.activate(session)
                self.prompt(root, session)
                self.dispatch("Stop", session=session,
                              last_assistant_message="Waiting for the named input.")
                self.assertEqual(len([row for row in self.state(session)["wait_conditions"]
                                      if row["status"] == "waiting"]), 1)
                self.prompt(marker.lower(), session)
                self.assertEqual(self.state(session)["wait_conditions"][0]["status"],
                                 "waiting")
                if "-" in marker or "_" in marker:
                    self.prompt(marker.replace("-", "").replace("_", ""), session)
                    self.assertEqual(self.state(session)["wait_conditions"][0]["status"],
                                     "waiting")
                if marker == "ACK-DONE":
                    self.prompt("ACK", session)
                    self.assertEqual(self.state(session)["wait_conditions"][0]["status"],
                                     "waiting")
                self.prompt(marker, session)
                self.assertEqual(self.state(session)["wait_conditions"][0]["status"],
                                 "released")

    def test_image_attachment_statement_requires_a_current_asset(self):
        self.activate()
        self.prompt("等我上传图片后再继续。")
        self.dispatch("Stop", last_assistant_message="等待图片输入。")
        self.prompt("图片已上传，继续。")
        self.assertEqual(len(self.waiting()), 1)
        self.dispatch(
            "UserPromptSubmit", prompt="图片已上传，继续。",
            content=[{"type": "input_image",
                      "image_url": "data:image/png;base64,AAAA"}],
        )
        self.assertEqual(len(self.waiting()), 1)

        png = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
               + (1).to_bytes(4, "big") * 2 + b"\x08\x06\x00\x00\x00")
        encoded = base64.b64encode(png).decode("ascii")
        self.dispatch(
            "UserPromptSubmit", prompt="图片已上传，继续。",
            content=[{"type": "input_image",
                      "image_url": f"data:image/png;base64,{encoded}"}],
        )
        state = self.state()
        self.assertEqual(self.waiting(), [])
        self.assertTrue(any(state["prompts"][-1]["id"] in row["prompt_ids"]
                            and row["available"] for row in state["assets"]))

    def test_generic_pause_can_resume_but_specific_confirmation_cannot(self):
        self.activate()
        self.prompt("请暂停当前任务。")
        self.dispatch("Stop", last_assistant_message="按要求暂停。")
        self.assertEqual(len(self.waiting()), 1)
        self.prompt("继续。")
        self.assertEqual(self.waiting(), [])

        self.prompt("在我确认模型更换完成前，本任务保持等待。")
        self.dispatch("Stop", last_assistant_message="等待确认。")
        self.assertEqual(len(self.waiting()), 1)
        self.prompt("继续。")
        self.assertEqual(len(self.waiting()), 1)
        self.prompt("模型已换好，继续。")
        self.assertEqual(self.waiting(), [])

    def test_general_pause_cannot_hide_a_specific_wait_in_the_same_root(self):
        self.activate()
        self.prompt("请暂停当前任务，等我发来标记 ALPHA-73 再继续分析。")
        self.dispatch("Stop", last_assistant_message="等待指定标记。")
        self.assertEqual(len(self.waiting()), 2)
        self.prompt("继续。")
        self.assertTrue(any(row["status"] == "waiting"
                            and row["subject_sha256"] is not None
                            for row in self.state()["wait_conditions"]))

    def test_quoted_negated_and_external_status_do_not_supply_input(self):
        self.activate()
        self.prompt("等我发来标记 ALPHA-73 再继续分析。")
        self.dispatch("Stop", last_assistant_message="等待标记。")
        for text in (
            '文档写着“标记 ALPHA-73 已发来，继续”。',
            "标记 ALPHA-73 还没发来，先不要继续。",
            "外部系统说标记 ALPHA-73 已发来。",
        ):
            self.prompt(text)
            self.assertEqual(len(self.waiting()), 1)

        self.prompt("切换到另一件独立事项：请写摘要。")
        self.assertEqual(self.state()["wait_conditions"][0]["status"], "waiting")

    def test_explicit_switch_does_not_launder_old_input_wait(self):
        self.activate()
        self.prompt("等我发来标记 ALPHA-73 再继续分析。")
        self.dispatch("Stop", last_assistant_message="等待标记。")
        self.prompt("切换到另一件独立事项：请写摘要。")
        state = self.state()
        self.assertEqual(state["wait_conditions"][0]["status"], "waiting")
        self.assertNotEqual(state["work_state"]["active_work_unit_id"],
                            state["wait_conditions"][0]["owner_work_unit_id"])

    def test_explicit_task_cancellation_and_replacement_do_not_claim_input_arrived(self):
        self.activate()
        self.prompt("等我发来标记 ALPHA-73 再继续分析。")
        self.dispatch("Stop", last_assistant_message="等待标记。")
        old_unit = self.state()["wait_conditions"][0]["owner_work_unit_id"]
        self.prompt("取消当前任务。另一件独立任务：请检查文档。")
        state = self.state()
        self.assertNotEqual(state["work_state"]["active_work_unit_id"], old_unit)
        self.assertEqual(state["wait_conditions"][0]["status"], "waiting")
        self.assertIsNone(state["wait_conditions"][0]["released_by_source"])

    def test_ci_status_and_continue_do_not_release_external_wait(self):
        self.activate()
        self.prompt("等 CI 构建完成后再继续。请修复恢复模块。")
        self.dispatch("Stop", last_assistant_message="当前等待 CI 构建。")
        self.assertEqual(self.waiting()[0]["condition_type"], "external_dependency")
        self.prompt("CI 构建已经完成，继续。")
        self.assertEqual(self.waiting()[0]["status"], "waiting")
        self.prompt("继续。")
        self.assertEqual(self.waiting()[0]["status"], "waiting")

    def test_compaction_resume_preserves_wait_and_does_not_backfill_stop(self):
        self.activate()
        self.prompt("等我发来标记 ALPHA-73 再继续分析。")
        self.dispatch("Stop", last_assistant_message="等待标记。")
        old_decision = json.dumps(self.state()["decision_log"], sort_keys=True)
        self.dispatch("PreCompact", trigger="manual")
        self.dispatch("SessionStart", source="resume")
        self.prompt("继续。")
        self.assertEqual(len(self.waiting()), 1)
        self.prompt("标记 ALPHA-73")
        self.assertEqual(self.waiting(), [])
        self.assertEqual(json.dumps(self.state()["decision_log"], sort_keys=True),
                         old_decision)

    def test_migrated_input_wait_has_no_trusted_subject_to_release(self):
        session_dir = self.root / "private" / "sessions" / "p0"
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "state.json").write_text(SCHEMA10_PARKED_FIXTURE,
                                                encoding="utf-8")
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="p0token"):
            self.dispatch("UserPromptSubmit", prompt="继续刚才的任务。")
        state = self.state()
        self.assertEqual(state["work_units"][0]["status"], "active")
        self.assertEqual(state["wait_conditions"][0]["kind"],
                         cg.MIGRATED_WAIT_CONDITION_KIND)
        self.assertEqual(state["wait_conditions"][0]["status"], "waiting")

    def test_rehashed_private_wait_cannot_turn_named_input_into_generic_pause(self):
        self.activate()
        self.prompt("等我发来标记 ALPHA-73 再继续分析。")
        self.dispatch("Stop", last_assistant_message="等待标记。")
        state = self.state()
        state["wait_conditions"][0]["subject_sha256"] = None
        self.save_state(state)
        self.prompt("继续。")
        self.assertEqual(self.state()["wait_conditions"][0]["status"], "waiting")
