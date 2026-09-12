"""Information-delivery closure: a delivered answer is a delivery, not debt.

Regression family for the phantom-obligation defect: a root request whose
deliverable *is* the reply was recorded as a pending execution obligation, so
it survived the delivered answer, was re-injected by every later recovery
packet as a current requirement, and silently disabled the ordinary
auto-completion path for the whole work unit.

The fix extends the existing ``answered`` delivery closure from the strict
interrogative shape it was frozen with to its imperative counterpart, while
keeping every producing operation on the evidence path. These tests fail on
the pre-fix code: the information-request items below stayed ``pending``.

Boundaries pinned here:

* both phrasings of one request close on delivery;
* a producing operation, an explicit run/execute command, a visual mutation,
  and an unresolved asset reference never close this way;
* a noun-phrase mention of an operation ("实现的核心逻辑") is not an action;
* the migration reconstruction keeps its frozen interrogative-only shape;
* prose questions no longer become pending acceptance criteria, while real
  normative criteria still do.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "context_guard.py"

INFORMATION_REQUEST = "帮我讲一下这个仓库的主要内容，以及实现的核心逻辑"
ANSWER = "主要内容与核心逻辑如下……"


class InformationDeliveryHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.data_dir = Path(tempfile.mkdtemp())
        patcher = mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.data_dir / "private")}
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        spec = importlib.util.spec_from_file_location("cg_information_delivery", ENTRY)
        self.cg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.cg)

    def payload(self, event, *, turn="t1", **kwargs):
        payload = {
            "hook_event_name": event,
            "session_id": "information-delivery-suite",
            "cwd": str(self.data_dir),
            "turn_id": turn,
        }
        payload.update(kwargs)
        return payload

    def session_dir(self) -> Path:
        return self.data_dir / "private" / "sessions" / "information-delivery-suite"

    def state(self):
        return self.cg.load_state(self.session_dir(), self.payload("Stop"))

    def answer(self, prompt: str, *, reply: str = ANSWER, turn: str = "t1"):
        """One complete question/answer turn; returns the requirement record."""
        self.cg.dispatch(self.payload("UserPromptSubmit", turn=turn, prompt=prompt))
        self.cg.dispatch(
            self.payload("Stop", turn=turn, last_assistant_message=reply)
        )
        return self.state()["requirements"][-1]


class DeliveredInformationRequestTests(InformationDeliveryHarness):
    def test_imperative_information_request_closes_on_delivery(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        item = self.answer(INFORMATION_REQUEST)
        self.assertEqual(item["status"], "answered")
        self.assertEqual(item["answer_state"], "answered")

    def test_operation_noun_phrase_is_not_an_action(self) -> None:
        """'实现的核心逻辑' names work; it does not request work."""
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for prompt in ("讲一下实现的核心逻辑", "说明一下它的目录结构",
                       "帮我看看有没有漏洞", "介绍一下它的测试怎么跑"):
            with self.subTest(prompt=prompt):
                item = self.answer(prompt)
                self.assertEqual(item["status"], "answered")

    def test_english_information_request_closes_on_delivery(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        item = self.answer("please explain the recovery packet")
        self.assertEqual(item["status"], "answered")

    def test_closed_request_never_replays_after_compaction(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.answer(INFORMATION_REQUEST)
        self.cg.dispatch(
            self.payload("UserPromptSubmit", turn="t2", prompt="那测试怎么跑？")
        )
        self.cg.dispatch(self.payload("PreCompact", turn="t2"))
        resumed = self.cg.dispatch(
            self.payload("SessionStart", source="compact", turn="t2")
        )
        packet = json.dumps(resumed, ensure_ascii=False)
        self.assertNotIn("主要内容，以及实现的核心逻辑", packet)
        projection = self.cg.current_scope_projection(self.state())
        self.assertNotIn("R001", projection["current_item_ids"])

    def test_pending_actions_keep_the_information_request_open(self) -> None:
        """Delivery alone never closes a reply that promises more work."""
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        item = self.answer(INFORMATION_REQUEST, reply="我会继续核实这个问题。")
        self.assertEqual(item["status"], "pending")


class EvidencePathIsPreservedTests(InformationDeliveryHarness):
    """Execution obligations must not be closed by a delivered reply."""

    def test_producing_and_run_requests_stay_pending(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for prompt in (
            "实现 scripts/foo.py 里的新功能",
            "修复 scripts/foo.py 的空指针",
            "把 README 的版本号改成 0.13.5 并提交",
            "帮我跑一下测试并总结结果",
            "运行测试验证并汇报",
            "修改图片并展示修改后的效果图",
            "暂时不要提交或推送",
        ):
            with self.subTest(prompt=prompt):
                item = self.answer(prompt)
                self.assertEqual(item["status"], "pending")

    def test_migration_reconstruction_keeps_frozen_shape(self) -> None:
        """The historical path stays interrogative-only."""
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        state = self.state()
        legacy = {"status": "pending", "text": INFORMATION_REQUEST,
                  "verification_contract": {"mode": "legacy_fallback"}}
        question = {"status": "pending", "text": "这个仓库是做什么的？",
                    "verification_contract": {"mode": "legacy_fallback"}}
        self.assertFalse(
            self.cg._delivable_question(legacy, state, allow_information_request=False)
        )
        self.assertTrue(
            self.cg._delivable_question(question, state, allow_information_request=False)
        )
        self.assertTrue(self.cg._delivable_question(legacy, state))

    def test_mixed_requests_and_unknown_commands_never_close_on_delivery(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for prompt in (
            "你继续执行，然后总结结果",
            "按你的计划执行，然后说明结果",
            "执行 pytest 并总结结果",
            "运行 python scripts/check.py 并解释结果",
            "Explain the code and run pytest",
            "Please list the files and execute pytest",
            "介绍这个仓库，然后清理临时目录",
            "列出全部文件并删除临时文件",
            "Explain the project and frobnicate the workspace",
            "总结一下核心逻辑，最好画个流程图",
        ):
            with self.subTest(prompt=prompt):
                self.assertEqual(self.answer(prompt)["status"], "pending")

    def test_executable_names_in_how_to_questions_are_not_commands(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for prompt in ("How do I run pytest?", "说明如何运行 pytest", "介绍一下它的测试怎么跑"):
            with self.subTest(prompt=prompt):
                self.assertEqual(self.answer(prompt)["status"], "answered")


class WholeRequestGrammarTests(InformationDeliveryHarness):
    def assert_delivery(self, prompt, expected, *, turn="t1"):
        item = self.answer(prompt, reply="说明如下。", turn=turn)
        self.assertEqual(item["status"], expected, prompt)
        self.cg.dispatch(self.payload("PreCompact", turn=turn))
        self.cg.dispatch(self.payload("SessionStart", source="compact", turn=turn))
        current = self.cg.current_scope_projection(self.state())["current_item_ids"]
        self.assertEqual(item["id"] in current, expected == "pending", prompt)

    def test_unknown_execution_tails_survive_delivery_and_recovery(self):
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        # Vary syntax and unknown operations, not just a growing verb blacklist.
        cases = [
            "列出文件后删除临时文件", "介绍一下项目后清理临时目录",
            "Explain the project before deleting temporary files",
            "Explain the project & frobnicate the workspace",
        ]
        for connector in (" and ", " then ", " & ", " before ", " / ", " plus ", " "):
            for action in ("frobnicate the workspace", "sanitize the files", "delete the cache"):
                cases.append("Explain the project" + connector + action)
        for index, prompt in enumerate(cases):
            with self.subTest(prompt=prompt):
                self.assert_delivery(prompt, "pending", turn=f"mixed-{index}")

    def test_how_to_and_operation_topics_close_without_execution(self):
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        cases = (
            "如何发布版本？", "说明如何修改代码", "Explain how to configure the application",
            "介绍一下部署流程", "如何运行 pytest？", "说明如何执行 pytest",
            "Explain how to run pytest", "Explain how to modify the code",
            "说明如何修改代码，并说明如何运行测试", "Explain the code and describe the files",
        )
        for index, prompt in enumerate(cases):
            with self.subTest(prompt=prompt):
                self.assert_delivery(prompt, "answered", turn=f"how-{index}")

    def test_how_to_scope_does_not_absorb_a_second_action(self):
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for index, prompt in enumerate((
            "说明如何修改代码后删除文件", "说明如何运行测试并执行脚本",
            "Explain how to configure the application and execute pytest",
            "Explain how to run pytest & sanitize the workspace",
            "Explain the code and validate all tests", "请说明结果并验证全部测试",
        )):
            with self.subTest(prompt=prompt):
                self.assert_delivery(prompt, "pending", turn=f"escape-{index}")

    def test_unknown_topics_are_not_silently_classified_as_information(self):
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for index, prompt in enumerate((
            "Explain the project frobnicate", "介绍项目顺便整理文件",
            "Explain the unusually complicated custom machinery",
            "Explain `project` erase files", "Explain the code and frobnicate",
        )):
            with self.subTest(prompt=prompt):
                self.assert_delivery(prompt, "pending", turn=f"unknown-{index}")

    def test_basic_questions_keep_their_delivery_path(self):
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for index, prompt in enumerate((
            "How does the plugin work?", "Where is the config file?",
            "What does the plugin do?", "配置文件在哪里？", "这个插件怎么工作？",
            "When does the script run?", "Which version supports Windows?",
            "哪个版本支持 Windows？", "能否说明这个项目？", "Can you explain the code?",
            "What is the hook?", "How does the hook work?",
            "When does the hook run?", "Where is the configuration?",
        )):
            with self.subTest(prompt=prompt):
                self.assert_delivery(prompt, "answered", turn=f"basic-{index}")

    def test_determiners_do_not_require_a_per_subject_vocabulary_patch(self):
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for index, (determiner, subject) in enumerate(
            (d, s) for d in ("the", "a", "this", "its")
            for s in ("hook", "configuration", "scheduler", "frobnicator")
        ):
            self.assert_delivery(f"Explain {determiner} {subject}", "answered", turn=f"noun-{index}")
            self.assert_delivery(f"Explain {determiner} {subject} delete files", "pending", turn=f"tail-{index}")

    def test_actual_how_to_steps_are_not_unfinished_assistant_actions(self):
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        cases = (
            ("如何发布版本？", "先运行测试，然后创建标签并发布版本。"),
            ("如何发布版本？", "你需要先运行测试，然后发布版本。"),
            ("说明如何修改代码", "修改步骤是：打开文件，修改函数，然后运行测试。"),
            ("Explain how to publish the version", "First run the tests, then create the tag and publish the version"),
        )
        for index, (prompt, reply) in enumerate(cases):
            with self.subTest(prompt=prompt, reply=reply):
                turn = f"recipe-{index}"
                item = self.answer(prompt, reply=reply, turn=turn)
                self.assertEqual(item["status"], "answered")
                self.cg.dispatch(self.payload("PreCompact", turn=turn))
                self.cg.dispatch(self.payload("SessionStart", source="compact", turn=turn))
                self.assertNotIn(item["id"], self.cg.current_scope_projection(self.state())["current_item_ids"])

    def test_tutorial_with_a_promise_or_handoff_stays_pending(self):
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for index, reply in enumerate((
            "先运行测试，然后发布版本。我会继续核实这个问题。",
            "先运行测试，然后发布版本。仍未完成。",
            "需要你登录后告诉我，我会继续。",
            "我会运行测试，然后发布版本。",
            "First run the tests. I will continue checking the answer.",
            "我还没回答完，下一步会运行测试。", "请先提供配置文件，我再解释。",
            "等待维护者回复后我再说明。", "I need to run tests before I can answer.",
        )):
            with self.subTest(reply=reply):
                self.assertEqual(self.answer("如何发布版本？", reply=reply, turn=f"promise-{index}")["status"], "pending")

    def test_delivery_does_not_override_enforced_or_asset_contracts(self):
        state = {"acceptance_items": []}
        for contract in (
            {"mode": "enforced"},
            {"mode": "legacy_fallback", "reason": "asset_reference_unresolved"},
        ):
            item = {"text": "Explain the code", "status": "pending", "verification_contract": contract}
            self.assertFalse(self.cg._delivable_question(item, state))

    def test_normative_requirements_do_not_become_delivered_answers(self):
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for index, prompt in enumerate((
            "请说明结果并确保测试通过", "Explain the code; tests must pass",
            "请验证全部测试，可以吗？", "Explain the code and do not modify the files",
        )):
            with self.subTest(prompt=prompt):
                self.assert_delivery(prompt, "pending", turn=f"normative-{index}")


class AcceptanceExtractionTests(InformationDeliveryHarness):
    def test_casual_questions_do_not_become_acceptance_items(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for prompt in ("那测试怎么跑？", "这段代码有没有测试覆盖？",
                       "帮我确认一下这个说法对不对"):
            with self.subTest(prompt=prompt):
                self.cg.dispatch(
                    self.payload("UserPromptSubmit", turn="t9", prompt=prompt)
                )
                self.assertEqual(self.state()["acceptance_items"], [])

    def test_normative_criteria_are_still_captured(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(
            self.payload(
                "UserPromptSubmit",
                turn="t9",
                prompt="测试必须覆盖 Windows 路径\n不要修改上线日期",
            )
        )
        texts = [item["text"] for item in self.state()["acceptance_items"]]
        self.assertIn("测试必须覆盖 Windows 路径", texts)

    def test_polite_and_interrogative_acceptance_requests_are_preserved(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for prompt in ("请验证所有测试通过", "请确保测试全部通过，可以吗？",
                       "帮我验证全部测试", "Can you run the tests?",
                       "请说明结果并验证全部测试"):
            with self.subTest(prompt=prompt):
                self.assertIn(prompt, self.cg.extract_acceptance(prompt))
                self.assertEqual(self.answer(prompt)["status"], "pending")


class ExecutionResumeTests(InformationDeliveryHarness):
    def test_compact_resume_preserves_request_and_corrects_unfinished_action(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        for index, prompt in enumerate(("你继续执行", "按你的计划执行", "Proceed with the plan")):
            turn = f"resume-{index}"
            self.cg.dispatch(self.payload("UserPromptSubmit", turn=turn, prompt=prompt))
            self.cg.dispatch(self.payload("PreCompact", turn=turn))
            packet = self.cg.dispatch(self.payload("SessionStart", source="compact", turn=turn))
            self.assertIn(prompt, json.dumps(packet, ensure_ascii=False))
            reply = "下一步应该修改模块并运行测试。此次只做了核查。"
            first = self.cg.dispatch(self.payload("Stop", turn=turn, last_assistant_message=reply))
            self.assertEqual(first.get("decision"), "block")
            second = self.cg.dispatch(self.payload("Stop", turn=turn, last_assistant_message=reply))
            self.assertEqual(second, {})
            self.assertEqual(self.state()["requirements"][-1]["status"], "pending")

    def test_real_wait_and_informational_answers_do_not_trigger_resume_correction(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        cases = (
            ("按你的计划执行", "需要你登录后告诉我，我会继续。"),
            ("你继续执行", "已提交审核，等待维护者回复。"),
            ("解释一下原理", "下一步应该修改模块并运行测试。"),
            ("解释一下“继续执行”的含义", "下一步应该修改模块并运行测试。"),
            ("如果测试失败，你继续执行", "下一步应该修改模块并运行测试。"),
        )
        for index, (prompt, reply) in enumerate(cases):
            turn = f"wait-{index}"
            self.cg.dispatch(self.payload("UserPromptSubmit", turn=turn, prompt=prompt))
            result = self.cg.dispatch(self.payload("Stop", turn=turn, last_assistant_message=reply))
            self.assertEqual(result, {}, (prompt, reply))


class UncertifiedClaimDiagnosticTests(InformationDeliveryHarness):
    def test_uncertified_claim_records_its_reason(self) -> None:
        """A silent end over pending items must stay diagnosable."""
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(
            self.payload("UserPromptSubmit", turn="t1",
                         prompt="修复 scripts/foo.py 的空指针")
        )
        self.cg.dispatch(
            self.payload("Stop", turn="t1",
                         last_assistant_message="任务已完成，所有要求均已满足。")
        )
        decision = self.state()["decision_log"][-1]
        self.assertIn(
            "completion_claim_uncertified_pending_items", decision["reason_codes"]
        )


if __name__ == "__main__":
    unittest.main()
