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
from unittest import mock

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

    def host(
        self, command: str, output: str = "", code: int = 0,
        *, shell: str | None = None,
    ) -> None:
        tool_input = {"command": command}
        if shell is not None:
            tool_input["shell"] = shell
        cg.dispatch(self.event(
            "PostToolUse", tool_name="Bash", tool_use_id=f"tool-{self.turn}",
            tool_input=tool_input,
            tool_response={"exit_code": code, "output": output},
        ))

    def ready_file(self, target: Path) -> None:
        if os.name == "nt":
            escaped = str(target).replace("'", "''")
            self.host(
                f"Test-Path -LiteralPath '{escaped}' -PathType Leaf",
                "True\r\n", shell="powershell",
            )
        else:
            self.host(f"test -f '{target}'")

    def test_exact_marker_wait_releases_only_on_named_user_input(self):
        suite = self.root / "suite.py"
        suite.write_text("def test_case(): assert True\n", encoding="utf-8")
        self.submit(
            f'只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行 "{suite}" 的测试。'
        )
        waiting = self.state()["wait_conditions"]
        self.assertEqual(len(waiting), 1)
        self.assertEqual(waiting[0]["condition_type"], "exact_input")
        self.assertEqual(waiting[0]["subject_sha256"],
                         cg.sha256_text("CG142-CONFIRM-17"))
        self.submit("继续。")
        self.assertEqual(self.state()["wait_conditions"][0]["status"], "waiting")
        for wrong in (
            "CG142-CONFIRM-18", "cg142-CONFIRM-17", "CG142-CONFIRM-17 ",
            "CG142-CONFIRM-170", '"CG142-CONFIRM-17"',
            "`CG142-CONFIRM-17`",
        ):
            self.submit(wrong)
            self.assertEqual(self.state()["wait_conditions"][0]["status"],
                             "waiting", wrong)
        self.submit("CG142-CONFIRM-17")
        self.assertEqual(self.state()["wait_conditions"][0]["status"], "released")

    def test_exact_marker_english_equivalent_and_false_source_frames(self):
        suite = self.root / "suite.py"
        suite.write_text("def test_case(): assert True\n", encoding="utf-8")
        for index, prompt in enumerate((
            f'Only after I send exactly CG142-CONFIRM-17 may you run "{suite}".',
            f'只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行 "{suite}" 的测试。',
        )):
            self.session = f"exact-marker-{index}"
            self.turn = 0
            self.submit("context-guard on")
            self.submit(prompt)
            waiting = self.state()["wait_conditions"]
            self.assertEqual(len(waiting), 1)
            self.assertEqual(waiting[0]["condition_type"], "exact_input")
            self.submit("CG142-CONFIRM-17")
            self.assertEqual(self.state()["wait_conditions"][0]["status"], "released")
        for index, frame in enumerate((
            f'测试规格：只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行 "{suite}"。',
            f'例如只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行 "{suite}"。',
            f'不要把只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行 "{suite}" 当成授权。',
            f'"只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行 {suite}"',
        )):
            self.session = f"exact-marker-negative-{index}"
            self.turn = 0
            self.submit("context-guard on")
            self.submit(frame)
            self.assertFalse(self.state()["wait_conditions"], frame)

    def test_same_exact_marker_for_two_targets_is_ambiguous(self):
        first = self.root / "first.py"
        second = self.root / "second.py"
        for path in (first, second):
            path.write_text("def test_case(): assert True\n", encoding="utf-8")
        self.submit(
            f'只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行 "{first}" 的测试。'
            f'只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行 "{second}" 的测试。'
        )
        waiting = self.state()["wait_conditions"]
        self.assertEqual(len(waiting), 2)
        self.assertNotEqual(waiting[0]["source_clause_sha256"],
                            waiting[1]["source_clause_sha256"])
        self.submit("CG142-CONFIRM-17")
        self.assertEqual([row["status"] for row in self.state()["wait_conditions"]],
                         ["waiting", "waiting"])

    def test_exact_marker_release_does_not_satisfy_future_observation(self):
        suite = self.root / "suite.py"
        suite.write_text("def test_case(): assert True\n", encoding="utf-8")
        future = self.root / "future-observation.json"
        self.submit(
            f'只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行 "{suite}" 的测试。'
            f'今后再观察 "{future}" 的性能变化；当前文件不存在。'
        )
        original = self.state()["requirements"][-1]
        clauses = original["clause_metadata"]["clauses"]
        main = next(row for row in clauses if row["operation"] == "test_verify")
        later = next(row for row in clauses if future.name in row["clause"])
        self.assertNotEqual(main["subjectId"], later["subjectId"])
        self.assertFalse(future.exists())
        self.submit("CG142-CONFIRM-17")
        state = self.state()
        self.assertEqual(state["wait_conditions"][0]["status"], "released")
        self.assertFalse(future.exists())
        self.assertEqual(state["requirements"][1]["status"], "pending")

    def test_generic_pause_and_exact_marker_remain_separate_without_target_proof(self):
        suite = self.root / "suite.py"
        suite.write_text("def test_case(): assert True\n", encoding="utf-8")
        self.submit(
            f'请先暂停运行 "{suite}" 的测试；'
            '只有我在后续消息中原样发送 CG142-CONFIRM-17 才可继续运行该测试。'
        )
        waiting = self.state()["wait_conditions"]
        self.assertEqual(len(waiting), 2)
        self.assertEqual([row["condition_type"] for row in waiting],
                         ["confirmation", "exact_input"])
        self.submit("CG142-CONFIRM-17")
        self.assertEqual([row["status"] for row in self.state()["wait_conditions"]],
                         ["waiting", "released"])

    def test_exact_marker_keeps_second_source_after_rejected_first(self):
        first = "只有我原样发送 BAD 才可运行测试，测试必须包含负例。"
        second = "只有我原样发送 GOOD 才可运行 suite.py。"
        self.assertEqual(cg.root_pause_clauses(first + second),
                         [second.rstrip("。")])
        self.submit(first + second)
        waits = self.state()["wait_conditions"]
        self.assertEqual(len(waits), 1)
        self.assertEqual(waits[0]["condition_type"], "exact_input")
        self.assertEqual(waits[0]["source_clause_sha256"],
                         cg.sha256_text(second.rstrip("。")))
        self.assertEqual(waits[0]["subject_sha256"], cg.sha256_text("GOOD"))

    def test_two_english_exact_markers_keep_distinct_sentence_sources(self):
        first = "Only after I send exactly BAD may you run suite.py."
        second = "Only after I send exactly GOOD may you run other.py."
        self.assertEqual(cg.root_pause_clauses(first + " " + second),
                         [first.rstrip("."), second.rstrip(".")])
        self.submit(first + " " + second)
        waits = self.state()["wait_conditions"]
        self.assertEqual(len(waits), 2)
        self.assertEqual([w["source_clause_sha256"] for w in waits],
                         [cg.sha256_text(first.rstrip(".")),
                          cg.sha256_text(second.rstrip("."))])
        self.assertEqual([w["subject_sha256"] for w in waits],
                         [cg.sha256_text("BAD"), cg.sha256_text("GOOD")])

    def test_exact_marker_state_requires_root_source_and_subject(self):
        self.submit("只有我原样发送 READY 才可运行测试。")
        for field in ("subject_sha256", "source_clause_sha256"):
            damaged = self.state()
            damaged["wait_conditions"][0][field] = None
            with self.assertRaises(cg.StateIntegrityError):
                cg.validate_state_integrity(damaged)

    def test_multiline_source_frames_do_not_create_waits(self):
        fenced = "```text\n只有我原样发送 BAD 才可运行 suite.py。\n请先暂停当前任务。\n```"
        self.assertEqual(cg.root_pause_clauses(fenced), [])
        self.assertEqual(cg.root_pause_clauses(
            fenced + "\n只有我原样发送 GOOD 才可运行 other.py。"
        ), ["只有我原样发送 GOOD 才可运行 other.py"])
        self.assertEqual(cg.root_pause_clauses(
            "> 只有我原样发送 BAD 才可运行 suite.py。\n"
            "只有我原样发送 GOOD 才可运行 other.py。"
        ), ["只有我原样发送 GOOD 才可运行 other.py"])
        self.assertEqual(cg.root_pause_clauses(
            "```text\n请先暂停当前任务。\n```\n请先暂停当前任务。"
        ), ["请先暂停当前任务"])

    def test_quoted_path_with_spaces_keeps_exact_source_and_current_action(self):
        suite = self.root / "suite space" / "test now.py"
        suite.parent.mkdir()
        suite.write_text("def test_current(): assert True\n", encoding="utf-8")
        prompt = f'现在运行 "{suite}" 并报告退出状态。'
        self.submit(prompt)
        self.ready_file(suite)
        self.stop("当前测试尚未运行。")

        decision = self.state()["decision_log"][-1]
        projection = next(row for row in decision["core_projections"]
                          if row["predicate"] == "test_run_completed")
        self.assertEqual(
            projection["source_sha256"],
            cg.sha256_text(prompt),
        )
        self.assertTrue(any(
            row.get("category") == "test_verify"
            and row.get("actionability") == "current_ready"
            for row in decision["actions"]
        ))

    def test_windows_quoted_drive_paths_bind_whole_subject_not_prefix(self):
        for quote, target in (
            ('"', r"D:\work\tests\test_now.py"),
            ("'", r"C:\work dir\tests\test now.py"),
        ):
            with self.subTest(quote=quote, target=target):
                prompt = f"Run {quote}{target}{quote} and report its status."
                locators, ambiguous = cg.root_absolute_locator_mentions(prompt)
                self.assertFalse(ambiguous)
                self.assertEqual(locators, {target})
                subjects = cg.prompt_subjects(prompt)
                self.assertEqual(
                    [row["locator_sha256"] for row in subjects],
                    [cg.sha256_text(target)],
                )
                self.assertEqual(subjects[0]["display"], target.rsplit("\\", 1)[-1])

        unquoted = r"Run C:\work dir\tests\test now.py and report its status."
        self.assertEqual(cg.root_absolute_locator_mentions(unquoted), (set(), True))

    def test_windows_native_test_path_requires_true_exact_leaf_result(self):
        target = r"D:\work dir\tests\test now.py"
        state = {
            "session": {"cwd": r"D:\work dir"},
            "work_state": {"active_work_unit_id": "w"},
            "work_units": [{"id": "w", "prompt_id": "P0001"}],
            "requirements": [{"work_unit_id": "w", "prompt_id": "P0001"}],
        }
        command = f"Test-Path -LiteralPath '{target}' -PathType Leaf"

        def payload(
            output: str, *, shell: str | None = "powershell",
            command_text: str = command,
        ) -> dict:
            tool_input = {"command": command_text}
            if shell is not None:
                tool_input["shell"] = shell
            return {
                "tool_name": "exec_command",
                "tool_input": tool_input,
                "tool_response": {"exit_code": 0, "output": output},
                "turn_id": "turn",
            }

        with mock.patch.object(cg, "_verified_windows_target", return_value=target):
            for quoted in (f"'{target}'", f'"{target}"'):
                with self.subTest(quoted=quoted):
                    observed = cg.core_shell_observation(
                        state, payload(
                            "True\r\n", shell="pwsh.exe",
                            command_text=f"Test-Path -LiteralPath {quoted} -PathType Leaf",
                        ), "success", "structured_exit_code",
                    )
                    self.assertIsNotNone(observed)
                    self.assertEqual(observed["predicate"], "file_exists")
                    self.assertEqual(observed["target"], target)
            for candidate in (
                payload("False\r\n"),
                payload("True\r\n", shell="bash"),
                payload("True\r\n", shell="cmd"),
                payload("True\r\n", shell="fish"),
                payload("True\r\n", shell=None),
                payload("True\r\n", command_text=command.replace("-LiteralPath", "-Path")),
            ):
                with self.subTest(candidate=candidate):
                    self.assertIsNone(cg.core_shell_observation(
                        state, candidate, "success", "structured_exit_code",
                    ))
            host_ps = {"type": "command", "shell": "pwsh.exe"}
            observed = cg.core_shell_observation(
                state, payload("True\r\n", shell=None), "success",
                "host_transcript_exit_code", host_ps,
            )
            self.assertIsNotNone(observed)
            self.assertEqual(observed["host_shell"], "pwsh.exe")
            for declared, terminal in (
                ("cmd", host_ps),
                ("bash", host_ps),
                ("powershell", {"type": "command", "shell": "cmd.exe"}),
                (None, {"type": "command", "shell": "zsh"}),
            ):
                with self.subTest(declared=declared, terminal=terminal):
                    self.assertIsNone(cg.core_shell_observation(
                        state, payload("True\r\n", shell=declared), "success",
                        "host_transcript_exit_code", terminal,
                    ))

    def test_posix_future_path_does_not_borrow_current_readiness(self):
        current = self.root / "current suite.py"
        future = self.root / "future suite.py"
        current.write_text("def test_current(): assert True\n", encoding="utf-8")
        future.write_text("def test_future(): assert True\n", encoding="utf-8")
        self.submit(
            f'现在运行 "{current}" 的测试；'
            f'以后再观察 "{future}" 的测试长期耗时。'
        )
        self.ready_file(current)
        self.stop("当前测试尚未运行；长期耗时留待以后观察。")
        actions = [row for row in self.state()["decision_log"][-1]["actions"]
                   if row.get("basis_requirement_id")]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["category"], "test_verify")

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
        self.submit(f'继续执行，运行 "{suite}" 的测试。')
        self.ready_file(suite)
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
            ('现在运行 "{target}" 并报告退出状态。', "还有测试没有运行。"),
            ('Run "{target}" and report the exit status.', "The test has not yet run."),
        )
        for index, (root, reply) in enumerate(cases):
            with self.subTest(index=index):
                self.session = f"current-grounding-direct-{index}"
                self.turn = 0
                self.submit("context-guard on")
                suite = self.root / f"test_direct_{index}.py"
                suite.write_text("def test_case(): assert True\n", encoding="utf-8")
                self.submit(root.format(target=suite))
                self.ready_file(suite)
                self.stop(reply)
                actions = [row for row in self.state()["decision_log"][-1]["actions"]
                           if row.get("basis_requirement_id")]
                self.assertEqual(len(actions), 1)
                self.assertEqual(actions[0]["category"], "test_verify")
                self.assertEqual(actions[0]["actionability"], "current_ready")

    def test_explicit_deliberative_question_never_uses_status_object_exception(self):
        questions = (
            'Should we run "{target}" and report its status',
            'Is it necessary to run "{target}" and report status',
        )
        for index, question in enumerate(questions):
            with self.subTest(index=index):
                self.session = f"current-grounding-question-{index}"
                self.turn = 0
                self.submit("context-guard on")
                suite = self.root / f"test_question_{index}.py"
                suite.write_text("def test_case(): assert True\n", encoding="utf-8")
                self.submit(question.format(target=suite))
                self.ready_file(suite)
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
            f'先运行 "{current}" 的测试并回读结果。'
            f"长期速度优化以后再观察 '{future}'，这一轮只说明观察方法。"
        )
        self.ready_file(current)
        self.stop("当前测试还未运行；长期速度只在以后观察。")
        actions = [row for row in self.state()["decision_log"][-1]["actions"]
                   if row.get("basis_requirement_id")]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["category"], "test_verify")

    def test_two_current_tests_survive_beside_one_future_observation(self):
        for name in ("alpha.py", "beta.py", "gamma.py"):
            (self.root / name).write_text("def test_case(): assert True\n", encoding="utf-8")
        self.submit(
            f'现在分别运行 "{self.root / "alpha.py"}" 和 "{self.root / "beta.py"}" 的测试；'
            f'"{self.root / "gamma.py"}" 的长期收益留到下季度观察。'
        )
        self.ready_file(self.root / "alpha.py")
        self.ready_file(self.root / "beta.py")
        self.stop("alpha.py 和 beta.py 的测试均尚未运行；gamma.py 留待季度观察。")
        actions = [row for row in self.state()["decision_log"][-1]["actions"]
                   if row.get("basis_requirement_id")]
        self.assertEqual(len(actions), 2)
        self.assertEqual({row["category"] for row in actions}, {"test_verify"})
        self.assertEqual(len({row["basis_requirement_id"] for row in actions}), 2)

    def test_conditioned_test_waits_while_information_closes_then_new_root_runs(self):
        suite = self.root / "sample_test.py"
        suite.write_text("def test_sample(): assert True\n", encoding="utf-8")
        self.submit(f'收到样本后运行 "{suite}"；先解释采用的判定方法。')
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
        self.submit(f'样本已发来；现在运行 "{suite}"。')
        self.ready_file(suite)
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
        self.submit(f'现在授权运行 "{suite}" 的测试。')
        self.ready_file(suite)
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
        self.ready_file(sample)
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
        self.ready_file(target)
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
