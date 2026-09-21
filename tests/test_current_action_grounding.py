"""Frozen production-entry matrix for current-action grounding.

These cases encode source, scope, predicate, owner, readiness and as-of
boundaries before the implementation repair.  They intentionally exercise the
real UserPromptSubmit/PostToolUse/Stop persistence path instead of a prose-only
classifier helper.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import context_guard as cg


class CurrentActionGroundingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cg-current-grounding-")
        self.root = Path(self.temp.name).resolve()
        self.data = self.root / "private"
        self.previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(self.data)
        self.session = "current-grounding"
        self.turn = 0
        self.submit("context-guard on")

    def tearDown(self) -> None:
        if self.previous is None:
            os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
        else:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = self.previous
        self.temp.cleanup()

    def event(self, kind: str, **values):
        return {"hook_event_name": kind, "session_id": self.session,
                "cwd": str(self.root), "turn_id": f"t{self.turn}", **values}

    def submit(self, prompt: str) -> None:
        self.turn += 1
        cg.dispatch(self.event("UserPromptSubmit", prompt=prompt))

    def stop(self, reply: str):
        return cg.dispatch(self.event("Stop", last_assistant_message=reply))

    def state(self):
        return cg.load_state(self.data / "sessions" / self.session, self.event("Stop"))

    def host(self, command: str, output: str = "", code: int = 0) -> None:
        cg.dispatch(self.event(
            "PostToolUse", tool_name="Bash", tool_use_id=f"tool-{self.turn}",
            tool_input={"command": command},
            tool_response={"exit_code": code, "output": output},
        ))

    def test_future_observation_closes_information_without_execution_catalog(self):
        suite = self.root / "future_suite.py"
        suite.write_text("def test_future(): assert True\n", encoding="utf-8")
        self.submit(
            f'今后再观察 "{suite}" 的测试速度是否需要优化；'
            "本轮只解释这个未来观察，不运行测试。"
        )
        self.stop("本轮不运行 future_suite.py；以后用相同输入比较多次耗时。")
        state = self.state()
        current = [row for row in state["requirements"]
                   if row["prompt_id"] == state["prompts"][-1]["id"]]
        self.assertEqual([row["status"] for row in current], ["pending", "answered"])
        self.assertIsNone(current[0].get("information_source_span"))
        self.assertIsNotNone(current[1].get("information_source_span"))
        self.assertFalse(any(op.get("operation") == "test_verify"
                             for op in state["pending"]["operations"]))
        self.submit("继续。")
        resumed = self.state()
        self.assertFalse(resumed["root_controls"])

    def test_current_unrun_test_remains_sourced_ready_and_resume_selectable(self):
        suite = self.root / "current_suite.py"
        suite.write_text("def test_current(): assert True\n", encoding="utf-8")
        self.submit(f"继续执行，运行 {suite} 的测试。")
        self.host(f"test -f '{suite}'")
        self.stop("测试尚未运行。")
        decision = self.state()["decision_log"][-1]
        action = next(row for row in decision["actions"]
                      if row.get("basis_requirement_id"))
        self.assertEqual(action["category"], "test_verify")
        self.assertEqual(action["actionability"], "current_ready")
        self.assertIsInstance(action["basis_as_of"], int)
        self.submit("继续。")
        items = self.state()["root_controls"][-1]["items"]
        self.assertEqual([row["action"] for row in items], ["test_verify"])

    def test_direct_test_object_needs_no_repeated_test_noun(self):
        cases = (
            ("现在运行 {target} 并报告退出状态。", "还有测试没有运行。"),
            ("Run {target} and report the exit status.", "The test has not yet run."),
        )
        for index, (root, reply) in enumerate(cases):
            with self.subTest(index=index):
                self.session = f"current-grounding-direct-{index}"
                self.turn = 0
                self.submit("context-guard on")
                suite = self.root / f"test_direct_{index}.py"
                suite.write_text("def test_case(): assert True\n", encoding="utf-8")
                self.submit(root.format(target=suite))
                self.host(f"test -f '{suite}'")
                self.stop(reply)
                actions = [row for row in self.state()["decision_log"][-1]["actions"]
                           if row.get("basis_requirement_id")]
                self.assertEqual(len(actions), 1)
                self.assertEqual(actions[0]["category"], "test_verify")
                self.assertEqual(actions[0]["actionability"], "current_ready")

    def test_explicit_deliberative_question_never_uses_status_object_exception(self):
        questions = (
            "Should we run {target} and report its status",
            "Is it necessary to run {target} and report status",
        )
        for index, question in enumerate(questions):
            with self.subTest(index=index):
                self.session = f"current-grounding-question-{index}"
                self.turn = 0
                self.submit("context-guard on")
                suite = self.root / f"test_question_{index}.py"
                suite.write_text("def test_case(): assert True\n", encoding="utf-8")
                self.submit(question.format(target=suite))
                self.host(f"test -f '{suite}'")
                self.stop("This asks whether the test should be run; it does not direct a run.")
                state = self.state()
                self.assertEqual(cg._action_source_clauses(question.format(target=suite)), [])
                self.assertFalse(any(
                    row.get("actionability") == "current_ready"
                    for row in state["decision_log"][-1]["actions"]
                ))
                self.submit("Continue.")
                self.assertFalse(self.state()["root_controls"])

    def test_completed_test_is_not_reintroduced_by_pending_legacy_row(self):
        suite = self.root / "done_suite.py"
        suite.write_text("def test_done(): assert True\n", encoding="utf-8")
        command = f"pytest '{suite}'"
        self.submit(f"现在运行 `{command}` 并报告退出状态。")
        self.host(command, "1 passed\n")
        self.stop("测试退出码 0，1 passed。")
        state = self.state()
        requirement = state["requirements"][-1]
        requirement["status"] = "pending"  # legacy residue, effect stays trusted
        cg.save_state(self.data / "sessions" / self.session, state)
        self.submit("继续。")
        self.assertFalse(self.state()["root_controls"])

    def test_mixed_current_test_excludes_future_observation(self):
        current = self.root / "current_suite.py"
        future = self.root / "future_suite.py"
        current.write_text("def test_current(): assert True\n", encoding="utf-8")
        future.write_text("def test_future(): assert True\n", encoding="utf-8")
        self.submit(
            f"先运行 {current} 的测试并回读结果。"
            f"长期速度优化以后再观察 '{future}'，这一轮只说明观察方法。"
        )
        self.host(f"test -f '{current}'")
        self.stop("当前测试还未运行；长期速度只在以后观察。")
        actions = [row for row in self.state()["decision_log"][-1]["actions"]
                   if row.get("basis_requirement_id")]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["category"], "test_verify")

    def test_two_current_tests_survive_beside_one_future_observation(self):
        for name in ("alpha.py", "beta.py", "gamma.py"):
            (self.root / name).write_text("def test_case(): assert True\n", encoding="utf-8")
        self.submit(
            f"现在分别运行 {self.root / 'alpha.py'} 和 {self.root / 'beta.py'} 的测试；"
            f"{self.root / 'gamma.py'} 的长期收益留到下季度观察。"
        )
        self.host(f"test -f '{self.root / 'alpha.py'}'")
        self.host(f"test -f '{self.root / 'beta.py'}'")
        self.stop("alpha.py 和 beta.py 的测试均尚未运行；gamma.py 留待季度观察。")
        actions = [row for row in self.state()["decision_log"][-1]["actions"]
                   if row.get("basis_requirement_id")]
        self.assertEqual(len(actions), 2)
        self.assertEqual({row["category"] for row in actions}, {"test_verify"})
        self.assertEqual(len({row["basis_requirement_id"] for row in actions}), 2)

    def test_conditioned_test_waits_while_information_closes_then_new_root_runs(self):
        suite = self.root / "sample_test.py"
        suite.write_text("def test_sample(): assert True\n", encoding="utf-8")
        self.submit(f"收到样本后运行 {suite}；先解释采用的判定方法。")
        self.stop("判定时比较同一输入的实际退出状态；样本尚未收到。")
        before = self.state()["decision_log"][-1].copy()
        self.assertFalse(any(row.get("actionability") == "current_ready"
                             for row in before["actions"]))
        conditioned = next(row for row in before["core_projections"]
                           if row.get("root_condition"))
        self.assertEqual(conditioned["root_condition"]["kind"], "predicate")
        self.assertIn("pending", conditioned["conditions"].values())
        waiting_child = next(dict(row, execution_kind="test_verify")
                             for row in self.state()["requirements"]
                             if str(suite) in row["text"]
                             and row.get("information_source_span") is None)
        self.assertEqual(cg._root_control_item_action(waiting_child), "test_verify")
        stale_future_child = dict(waiting_child)
        stale_future_child["text"] = f"改天再运行 {suite}"
        self.assertIsNone(cg._root_control_item_action(stale_future_child))
        readback = self.root / "sample.txt"
        readback.write_text("sample\n", encoding="utf-8")
        waiting_readback = {
            "text": f"收到样本后使用宿主 Bash 调用 `cat '{readback}'` 完整回读",
            "execution_kind": "state_readback",
        }
        self.assertEqual(cg._action_clause_time_state(
            waiting_readback["text"], "state_readback"), "waiting")
        self.assertEqual(cg._root_control_item_action(waiting_readback), "state_readback")
        self.submit(f"样本已发来；现在运行 {suite}。")
        self.host(f"test -f '{suite}'")
        self.stop("当前样本测试尚未运行。")
        state = self.state()
        self.assertEqual(state["decision_log"][-2], before)
        self.assertTrue(any(row.get("category") == "test_verify"
                            and row.get("actionability") == "current_ready"
                            for row in state["decision_log"][-1]["actions"]))

    def test_implicit_future_explanation_needs_no_fixed_turn_wording(self):
        self.submit("测试耗时的长期改进留到季度回顾。讲讲到时候如何比较。")
        self.stop("届时固定输入与环境，比较多轮耗时分布。")
        state = self.state()
        current = [row for row in state["requirements"]
                   if row["prompt_id"] == state["prompts"][-1]["id"]]
        self.assertTrue(any(row["status"] == "answered" for row in current))
        self.submit("接着来。")
        self.assertFalse(self.state()["root_controls"])

    def test_unsupported_visual_proof_gap_creates_no_execution_authority(self):
        self.submit("判断既有截图中图标是否清晰。")
        self.stop("当前没有受支持的可信视觉证据，无法认证清晰度。")
        actions = self.state()["decision_log"][-1]["actions"]
        self.assertFalse(any(row.get("actionability") == "current_ready"
                             or row.get("category") == "generic_work"
                             for row in actions))

    def test_plain_visualizations_locator_is_artifact_but_real_image_is_visual(self):
        target = self.root / "visualizations" / "config.txt"
        target.parent.mkdir()
        target.write_text("mode=off\n", encoding="utf-8")
        self.submit(f"请修改 '{target}'，然后回读内容。")
        ordinary = self.state()["requirements"][-1]
        self.assertNotIn("visual", ordinary["requestedSurface"])
        self.submit("请检查这张图片的视觉内容，并说明图例。")
        visual = self.state()["requirements"][-1]
        self.assertIn("visual", visual["requestedSurface"])

    def test_reported_wait_and_old_generic_text_never_become_current_actions(self):
        self.submit("解释报告里“等待日志”的含义，不需要我提供日志。")
        self.stop("报告中的等待指尚未收集日志。")
        self.submit("旧记录写着“下一步运行 test_later.py”，那只是计划来源；本轮仅核对已有结果。")
        self.stop("旧记录没有提供当前执行来源；现有证据仍不足。")
        state = self.state()
        self.assertEqual(state["wait_conditions"], [])
        self.assertFalse(any(row.get("actionability") == "current_ready"
                             for row in state["decision_log"][-1]["actions"]))

    def test_grounded_user_wait_survives_while_reported_wait_does_not(self):
        self.submit("在我确认日志收集完成前，本任务保持等待。")
        self.stop("正在等待用户确认日志收集完成。")
        state = self.state()
        self.assertTrue(state["wait_conditions"])
        self.assertTrue(any(row.get("raised_by_kind") == "root_user"
                            for row in state["wait_conditions"]))

    def test_user_supplied_input_wait_is_a_sourced_releasable_fact(self):
        cases = (
            ("等我发来实际日志再分析，收到之前保持等待。", "实际日志已发来。"),
            ("Wait until I send the actual logs, then analyze them.",
             "The actual logs are ready."),
        )
        for index, (root, release) in enumerate(cases):
            with self.subTest(index=index):
                self.session = f"current-grounding-wait-{index}"
                self.turn = 0
                self.submit("context-guard on")
                self.submit(root)
                state = self.state()
                prompt_id = state["prompts"][-1]["id"]
                waits = [row for row in state["wait_conditions"]
                         if row.get("raised_by_source") == prompt_id]
                self.assertEqual(len(waits), 1)
                self.assertEqual(waits[0]["raised_by_kind"], "root_user")
                self.assertEqual(waits[0]["condition_type"], "input")
                self.assertTrue(waits[0]["source_clause_sha256"])
                self.assertTrue(cg.release_matches_condition(waits[0], release))
                self.submit(release)
                released = next(row for row in self.state()["wait_conditions"]
                                if row["condition_id"] == waits[0]["condition_id"])
                self.assertEqual(released["status"], "released")
                self.assertEqual(released["released_by_kind"], "root_user_confirmation")
                self.assertEqual(released["released_by_source"],
                                 self.state()["prompts"][-1]["id"])

    def test_input_wait_subjects_preserve_lexical_qian_prefix_and_release_independently(self):
        self.submit("等我发来前台日志再分析。等我发来前序输出再分析。")
        self.stop("按要求等待两份输入。")
        waiting = self.state()["wait_conditions"]
        self.assertEqual(len(waiting), 2)
        self.assertTrue(all(row["condition_type"] == "input" for row in waiting))
        self.assertEqual(
            [row["subject_sha256"] for row in waiting],
            [cg.sha256_text("前台日志"), cg.sha256_text("前序输出")],
        )

        self.submit("前台日志已发来，继续。")
        self.assertEqual(
            [row["status"] for row in self.state()["wait_conditions"]],
            ["released", "waiting"],
        )
        self.submit("前序输出已发来，继续。")
        self.assertEqual(
            [row["status"] for row in self.state()["wait_conditions"]],
            ["released", "released"],
        )

    def test_temporal_qian_boundary_is_removed_from_wait_subject(self):
        self.assertEqual(cg.wait_subject("等我确认服务状态前暂停"), "服务状态")
        self.submit("在我确认服务配置完成前，本任务保持等待。")
        self.stop("按要求暂停，等待确认。")
        waiting = self.state()["wait_conditions"]
        self.assertEqual(len(waiting), 1)
        self.assertEqual(waiting[0]["subject_sha256"], cg.sha256_text("服务配置"))

        self.submit("服务配置已确认，继续。")
        self.assertEqual(self.state()["wait_conditions"][0]["status"], "released")

    def test_qian_inside_subject_is_not_deferred_release_syntax(self):
        self.submit("等我发来服务前台日志再分析。")
        self.stop("按要求等待输入。")
        waiting = self.state()["wait_conditions"]
        self.assertEqual(len(waiting), 1)
        self.assertEqual(
            waiting[0]["subject_sha256"], cg.sha256_text("服务前台日志")
        )

        self.submit("服务前台日志已发来，继续。")
        self.assertEqual(self.state()["wait_conditions"][0]["status"], "released")

    def test_persisted_legacy_generic_action_cannot_migrate_into_resume(self):
        self.submit("解释当前记录里的状态字段。")
        self.stop("该字段表示记录仍待核验。")
        state = self.state()
        state["decision_log"].append({
            "created_at": "legacy",
            "turn_id": "legacy",
            "protocol_version": cg.STOP_PROTOCOL_VERSION,
            "decision_source": "legacy_migration",
            "declared_disposition": "unknown",
            "observed_outcome": "allow_neutral",
            "classifier_version": "legacy",
            "outcome": "allow_neutral",
            "reason_codes": [],
            "prompt_sha256": cg.sha256_text("legacy"),
            "reply_sha256": cg.sha256_text("legacy"),
            "actions": [{"category": "generic_work", "owner": "assistant",
                         "actionability": "current_ready",
                         "basis_requirement_id": None, "basis_as_of": None}],
            "core_projections": [],
        })
        cg.save_state(self.data / "sessions" / self.session, state)
        self.submit("继续。")
        self.stop("旧记录没有当前来源，因此没有可恢复的执行动作。")
        recovered = self.state()
        self.assertFalse(recovered["root_controls"])
        self.assertFalse(any(row.get("category") == "generic_work"
                             and row.get("actionability") == "current_ready"
                             for row in recovered["decision_log"][-1]["actions"]))

    def test_later_authorization_is_current_only_at_its_own_watermark(self):
        suite = self.root / "future_suite.py"
        suite.write_text("def test_future(): assert True\n", encoding="utf-8")
        self.submit(f"改天再运行 {suite} 的测试；今天只解释安排，不运行测试。")
        self.stop("今天不运行；以后在相同输入下比较结果。")
        before = self.state()["decision_log"][-1].copy()
        self.submit(f"现在授权运行 {suite} 的测试。")
        self.host(f"test -f {suite}")
        self.stop("测试尚未运行。")
        state = self.state()
        self.assertEqual(state["decision_log"][-2], before)
        action = next(row for row in state["decision_log"][-1]["actions"]
                      if row.get("basis_requirement_id"))
        self.assertEqual(action["actionability"], "current_ready")
        self.assertGreater(action["basis_as_of"], before["core_projections"][-1]["as_of"]
                           if before["core_projections"] else 0)

    def test_current_assessment_is_not_downgraded_to_future_observation(self):
        sample = self.root / "sample.json"
        sample.write_text("{}\n", encoding="utf-8")
        self.submit("不要只谈将来收益；现在测量当前样本并报告实际数值。")
        self.host(f"test -f {sample}")
        self.stop("当前测量尚未进行，不能报告数值。")
        state = self.state()
        action = next(row for row in state["decision_log"][-1]["actions"]
                      if row.get("basis_requirement_id"))
        self.assertEqual(action["category"], "measure_current_effect")
        self.assertEqual(action["actionability"], "current_ready")

    def test_observed_edit_without_required_readback_is_insufficient_not_rerun(self):
        target = self.root / "config.txt"
        target.write_text("mode=off\n", encoding="utf-8")
        command = f"cat '{target}'"
        self.submit(
            f"请修改 {target}，把它改为 mode=on；"
            f"然后用宿主 Bash 调用 `{command}` 完整回读并报告。"
        )
        patch = (f"*** Begin Patch\n*** Update File: {target}\n@@\n"
                 "-mode=off\n+mode=on\n*** End Patch\n")
        target.write_text("mode=on\n", encoding="utf-8")
        cg.dispatch(self.event(
            "PostToolUse", tool_name="apply_patch", tool_use_id="edit-only",
            tool_input={"command": patch},
            tool_response="Success. Updated the following files:\nM config.txt\n",
        ))
        self.host(f"test -f '{target}'")
        self.stop("编辑效果已观察，但独立回读尚未执行，证据不足以认证完成。")
        actions = self.state()["decision_log"][-1]["actions"]
        self.assertTrue(any(row.get("category") == "state_readback"
                            and row.get("actionability") == "current_ready"
                            for row in actions))
        self.assertFalse(any(row.get("category") == "local_edit"
                             and row.get("actionability") == "current_ready"
                             for row in actions))
        self.assertFalse(any(row.get("category") == "generic_work" for row in actions))


if __name__ == "__main__":
    unittest.main()
