"""0.17.0 F01: planning-only prompts never inherit a stamped mutation.

The historical case CGI-20261105-codex-plan-only-edit-obligation showed that
another actor's completed work, attributed advice and bare negation were read
as this turn's own local_edit request. These regressions cover the whole
clause-action family through the single production interpretation
(``_clause_action_is_current``), the enforced contract, the prompt action
scope, and a real dispatcher lifecycle with cold readback.
"""

from tests import test_context_guard_phase3 as phase3

cg = phase3.cg


class ClauseActionContextTests(phase3.Phase3TestCase):
    """Table-driven closure of the planning/action-scope family."""

    TARGET = "/work/reference.pptx"

    def edit_obligation(self, text: str) -> bool:
        contract = cg.verification_contract("R001", text, {}, [])
        return "local_edit" in [
            obligation.get("operation") for obligation in contract["obligations"]
        ]

    def assert_family(self, rows):
        for text, expected in rows:
            with self.subTest(text=text):
                self.assertEqual(self.edit_obligation(text), expected)

    def test_planning_only_history_and_advice_never_stamp_local_edit(self):
        self.assert_family([
            # Other actor's completed work (original repro).
            (f"同事修改完了 {self.TARGET}。请规划内容逻辑和大纲，本轮不执行具体修改。", False),
            (f"同事修改了 {self.TARGET}。", False),
            (f"有人删除了 /work/a.txt，请检查现状。", False),
            (f"A colleague already modified {self.TARGET}. Plan the outline this turn.", False),
            (f"{self.TARGET} was modified by a teammate. Please plan the outline.", False),
            # Attributed advice and suggestions.
            (f"已有修改建议，参考 {self.TARGET}；本轮只组织内容逻辑和大纲，不执行具体修改。", False),
            (f"同事建议修改 {self.TARGET}，请只给大纲。", False),
            # Historical self completion.
            (f"我已经修改了 {self.TARGET}，请验证结果。", False),
            # Bare and strong negation, Chinese and English.
            (f"参考 {self.TARGET}，只给大纲，不修改文件。", False),
            (f"参考 {self.TARGET}，只给大纲，不要修改文件。", False),
            (f"参考 /work/a.txt，只给大纲，do not modify files.", False),
            (f"The file {self.TARGET} will not be modified this turn; plan the outline.", False),
            (f"尚未提交任何改动。请给出 {self.TARGET} 的大纲。", False),
            (f"没修改过 {self.TARGET}，请先读它再给大纲。", False),
            # Planning object and stated future intent.
            ("请规划修改大纲。", False),
            (f"我打算修改 {self.TARGET}，请先等确认。", False),
        ])

    def test_current_directives_keep_their_obligations(self):
        self.assert_family([
            (f"请修改 {self.TARGET}。", True),
            (f"请更新 {self.TARGET}。", True),
            (f"请实现 {self.TARGET} 中描述的功能。", True),
            # Delegation from another actor is this turn's own work.
            (f"同事让我修改 {self.TARGET}。", True),
            # Mixed planning plus a current directive.
            (f"先规划大纲，然后修改 /work/a.txt。", True),
            (f"请规划大纲，然后修改 {self.TARGET}。", True),
            # An intent word with other content before it is a plan
            # reference, not future intent.
            (f"按计划修改 {self.TARGET}。", True),
        ])

    def test_contract_mode_matches_operation_stamp(self):
        contract = cg.verification_contract(
            "R001",
            f"同事修改完了 {self.TARGET}。请规划内容逻辑和大纲，本轮不执行具体修改。",
            {}, [])
        self.assertEqual(contract["mode"], "enforced")
        self.assertEqual(contract["clause_operation"], "unspecified")
        self.assertEqual(contract["clause_derivation_version"], cg.CLAUSE_DERIVATION_VERSION)
        for obligation in contract["obligations"]:
            self.assertNotEqual(obligation.get("operation"), "local_edit")

    def test_prompt_action_scope_authorizes_only_current_actions(self):
        scope = cg.prompt_action_scope(
            f"同事修改完了 {self.TARGET}。请规划内容逻辑和大纲，本轮不执行具体修改。")
        self.assertNotIn("local_edit", scope["authorized"])
        self.assertIn("local_edit", scope["denied"])
        real = cg.prompt_action_scope(f"请修改 {self.TARGET}。")
        self.assertIn("local_edit", real["authorized"])


class PlanningOnlyLifecycleTests(phase3.Phase3TestCase):
    """UserPromptSubmit -> real-shape PostToolUse -> Stop -> cold readback."""

    def build_planning_turn(self):
        target = self.project / "reference.pptx"
        target.write_text("outline-source", encoding="utf-8")
        self.prompt(
            f"$context-guard\n同事修改完了 {target}。请规划内容逻辑和大纲，"
            "本轮不执行具体修改。",
            turn="t1",
        )
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": f"cat {target}"},
            tool_response={"exit_code": 0, "output": "outline-source"},
        )
        return target

    def test_planning_only_turn_stops_without_edit_gate(self):
        self.build_planning_turn()
        result = self.dispatch(
            "Stop", turn="t1", last_assistant_message="大纲已经规划完成。"
        )
        # Same shape as the explicit-prohibition control: a silent stop with
        # the unspecified readback kept explicitly pending - never an edit
        # gate demanding mutation evidence.
        self.assertEqual(result, {})
        state = self.state()
        requirement = state["requirements"][0]
        self.assertEqual(requirement["operation"], "unspecified")
        self.assertEqual(requirement["status"], "pending")
        self.assertEqual(state["work_units"][0]["status"], "active")
        self.assertIsNone(state.get("completion_checkpoint"))
        self.assertNotIn("local_edit", [
            item.get("clause_operation") for item in state["requirements"]
        ])
        self.assertNotIn(
            "local_edit",
            [o.get("operation") for o in
             requirement["verification_contract"]["obligations"]],
        )

    def test_real_edit_turn_still_demands_evidence(self):
        target = self.project / "reference.pptx"
        target.write_text("subject", encoding="utf-8")
        self.prompt(f"$context-guard\n请修改 {target}。", turn="t1")
        result = self.dispatch(
            "Stop", turn="t1", last_assistant_message="任务已经全部完成。"
        )
        # Without real edit evidence the completion claim cannot close.
        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(self.state()["work_units"][0]["status"], "active")

    def test_planning_state_survives_cold_readback(self):
        self.build_planning_turn()
        self.dispatch("Stop", turn="t1", last_assistant_message="大纲已经规划完成。")
        self.dispatch("PreCompact", turn="t1")
        self.dispatch("SessionStart", turn="t1", source="resume")
        state = self.state()
        self.assertEqual(state["work_units"][0]["status"], "active")
        self.assertEqual(state["requirements"][0]["operation"], "unspecified")
        self.assertEqual(state["requirements"][0]["status"], "pending")
