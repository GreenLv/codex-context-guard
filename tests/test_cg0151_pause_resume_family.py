"""CGI-20261002 pause/resume family regression (CG-0151 D1).

Each SPEC W-matrix row is driven through the real Hook dispatch chain the
same way the canonical incident reproducer does: root prompts write v2
state, Stop parks the unit, the resume prompt must release only the
source-verified unique ordinary pause, and every refusal control keeps the
ledger waiting. Parser helpers are asserted only as supporting evidence;
every row's verdict comes from dispatch, persisted state and Stop output.
"""
from __future__ import annotations

from unittest import mock

from tests.test_cg122_p0_counterexamples import SCHEMA10_PARKED_FIXTURE, P0Harness, cg


class PauseResumeFamilyTests(P0Harness):
    def activate_session(self, session: str = "p0") -> None:
        self.activate(session)

    def waiting(self, session: str = "p0") -> list[dict]:
        return [row for row in self.state(session)["wait_conditions"]
                if row["status"] == "waiting"]

    def park_with_pause(self, pause_text: str, session: str = "p0",
                        task: str = "请检查并修复示例文档，然后运行测试验证。") -> dict:
        self.activate_session(session)
        self.prompt(task, session)
        self.prompt(pause_text, session)
        stop_output = self.dispatch("Stop", session=session,
                                    last_assistant_message="已暂停，改动已保留。")
        self.assertEqual(stop_output, {})
        state = self.state(session)
        self.assertEqual(state["work_units"][-1]["status"], "awaiting_user")
        return state

    def assert_released_unique_wait(self, session: str = "p0") -> dict:
        state = self.state(session)
        self.assertEqual([row for row in state["wait_conditions"]
                          if row["status"] == "waiting"], [])
        record = state["wait_conditions"][-1]
        self.assertEqual(record["status"], "released")
        self.assertEqual(record["released_by_source"], state["prompts"][-1]["id"])
        return state

    # -- W01: bare pause, bare resume ------------------------------------
    def test_w01_bare_pause_resumes_with_unique_release(self):
        self.park_with_pause("暂停")
        self.prompt("继续")
        state = self.assert_released_unique_wait()
        self.assertEqual(state["work_units"][-1]["status"], "active")
        self.assertEqual(state["wait_conditions"][0]["subject_sha256"], None)
        stop_output = self.dispatch("Stop", last_assistant_message="继续执行任务。")
        self.assertEqual(stop_output, {})

    # -- W02: polite suffix pause with follow-up tool note ---------------
    def test_w02_polite_pause_suffix_does_not_create_named_object(self):
        state = self.park_with_pause("暂停一下，我重启下测试工具。")
        self.assertEqual(len(state["wait_conditions"]), 1)
        self.assertEqual(state["wait_conditions"][0]["condition_type"],
                         "confirmation")
        self.assertEqual(state["wait_conditions"][0]["subject_sha256"], None)
        self.prompt("继续")
        state = self.assert_released_unique_wait()
        self.assertEqual(state["work_units"][-1]["status"], "active")

    # -- W03: polite and task-referencing resume wording ------------------
    def test_w03_polite_resume_wordings_release_generic_pause(self):
        for index, resume in enumerate(("请继续执行", "你继续", "恢复刚才任务")):
            session = f"w03-{index}"
            with self.subTest(resume=resume):
                self.park_with_pause("暂停", session)
                self.prompt(resume, session)
                state = self.assert_released_unique_wait(session)
                self.assertEqual(state["work_units"][-1]["status"], "active")

    # -- W04: old-object negation must not veto the current resume -------
    def test_w04_negated_old_object_does_not_block_current_resume(self):
        self.park_with_pause("暂停")
        self.prompt("旧测试通道不可用了，换了个新的，你继续")
        state = self.assert_released_unique_wait()
        self.assertEqual(state["work_units"][-1]["status"], "active")

    # -- W05: mid-sentence directive after a replacement note ------------
    def test_w05_mid_sentence_resume_directive_releases_generic_pause(self):
        self.park_with_pause("暂停")
        self.prompt("换好了，请继续执行")
        state = self.assert_released_unique_wait()
        self.assertEqual(state["work_units"][-1]["status"], "active")

    # -- W06: English contract parity ------------------------------------
    def test_w06_english_pause_resume_parity(self):
        self.park_with_pause("Pause for a moment.")
        self.prompt("please continue.")
        state = self.assert_released_unique_wait()
        self.assertEqual(state["work_units"][-1]["status"], "active")

        self.park_with_pause("pause", session="w06b")
        self.prompt("resume the previous task", session="w06b")
        state = self.assert_released_unique_wait("w06b")
        self.assertEqual(state["work_units"][-1]["status"], "active")

    # -- W07: negated resume directives keep waiting ----------------------
    def test_w07_negated_resume_directives_do_not_release(self):
        for index, resume in enumerate(("现在不要继续。", "条件未好，暂时别继续")):
            session = f"w07-{index}"
            with self.subTest(resume=resume):
                self.park_with_pause("暂停", session)
                self.prompt(resume, session)
                state = self.state(session)
                self.assertEqual(len(self.waiting(session)), 1)
                self.assertEqual(state["wait_conditions"][0]["status"], "waiting")
                self.assertIsNone(state["wait_conditions"][0]["released_by_source"])
                self.assertEqual(state["work_units"][-1]["status"], "awaiting_user")

    # -- W08: quotes, questions, third-party and embedded words ----------
    def test_w08_non_authoritative_resume_mentions_do_not_release(self):
        for index, resume in enumerate((
            '文档写着“继续”。',
            "tests/test_x.py 中的 continue 语句要保留",
            "能否继续？",
            "让子代理继续处理",
        )):
            session = f"w08-{index}"
            with self.subTest(resume=resume):
                self.park_with_pause("暂停", session)
                self.prompt(resume, session)
                state = self.state(session)
                self.assertEqual(len(self.waiting(session)), 1)
                self.assertEqual(state["wait_conditions"][0]["status"], "waiting")
                self.assertEqual(state["work_units"][-1]["status"], "awaiting_user")

    # -- W09: typed waits are not released by a generalized resume -------
    def test_w09_exact_marker_wait_keeps_generic_resume_blocked(self):
        self.activate_session()
        self.prompt("请检查并修复示例文档。等我发来标记 ALPHA-73 再继续分析。")
        self.prompt("暂停")
        self.dispatch("Stop", last_assistant_message="等待标记。")
        self.assertEqual(len(self.waiting()), 2)
        self.prompt("请继续执行")
        self.assertEqual(len(self.waiting()), 2)
        self.assertTrue(all(row["status"] == "waiting"
                            for row in self.state()["wait_conditions"]))
        self.prompt("标记 ALPHA-73")
        state = self.state()
        input_rows = [row for row in state["wait_conditions"]
                      if row["condition_type"] == "input"]
        self.assertEqual([row["status"] for row in input_rows], ["released"])
        self.assertEqual([row["status"] for row in self.waiting()], ["waiting"])

    # -- W10: ambiguous generic/named pairs are not guessed --------------
    def test_w10_two_generic_pauses_keep_bare_resume_ambiguous(self):
        self.park_with_pause("暂停")
        self.prompt("暂停一下")
        self.assertEqual(len(self.waiting()), 2)
        self.prompt("继续")
        state = self.state()
        self.assertEqual(len(self.waiting()), 2)
        self.assertEqual(state["work_units"][-1]["status"], "awaiting_user")

        self.park_with_pause("暂停", session="w10b")
        self.prompt("等我发来标记 BETA-09 再继续分析。", session="w10b")
        self.assertEqual(len(self.waiting("w10b")), 2)
        self.prompt("继续", session="w10b")
        self.assertEqual(len(self.waiting("w10b")), 2)

    # -- W11: external dependency survives the generic release -----------
    def test_w11_external_dependency_survives_generic_resume(self):
        self.activate_session()
        self.prompt("请检查并修复示例文档。")
        self.prompt("暂停，等 CI 流水线完成后再说")
        self.dispatch("Stop", last_assistant_message="已暂停，等待 CI。")
        state = self.state()
        self.assertEqual(len(self.waiting()), 2)
        types = sorted(row["condition_type"] for row in self.waiting())
        self.assertEqual(types, ["confirmation", "external_dependency"])
        self.prompt("继续")
        state = self.state()
        by_type = {row["condition_type"]: row for row in state["wait_conditions"]}
        self.assertEqual(by_type["confirmation"]["status"], "released")
        self.assertEqual(by_type["external_dependency"]["status"], "waiting")
        self.assertNotEqual(state["work_units"][-1]["status"], "active")

    # -- W12: unverifiable or changed sources fail closed -----------------
    def test_w12_changed_or_missing_source_stays_fail_closed(self):
        self.park_with_pause("暂停")
        state = self.state()
        condition = state["wait_conditions"][0]
        condition["source_clause_sha256"] = cg.sha256_text("伪造子句")
        self.save_state(state)
        self.prompt("继续")
        state = self.state()
        self.assertEqual(state["wait_conditions"][0]["status"], "waiting")
        self.assertIsNone(state["wait_conditions"][0]["released_by_source"])
        self.assertEqual(state["work_units"][-1]["status"], "awaiting_user")

        self.park_with_pause("暂停", session="w12b")
        source_id = self.state("w12b")["wait_conditions"][0]["raised_by_source"]
        prompt_dir = self.root / "private" / "sessions-v2" / "w12b" / "prompts"
        record = next(item for item in prompt_dir.iterdir()
                      if source_id in item.name and item.is_file())
        record.unlink()
        self.prompt("继续", session="w12b")
        state = self.state("w12b")
        self.assertEqual(state["wait_conditions"][0]["status"], "waiting")
        self.assertIsNone(state["wait_conditions"][0]["released_by_source"])
        self.assertEqual(state["work_units"][-1]["status"], "awaiting_user")

    # -- W13: persistence across reload keeps the release and pending work
    def test_w13_reload_preserves_release_and_pending_requirements(self):
        self.park_with_pause("暂停")
        pending_before = [item["id"] for item in self.state()["requirements"]
                          if item["status"] == "pending"]
        self.assertTrue(pending_before)
        self.prompt("请继续执行")
        self.assert_released_unique_wait()
        self.dispatch("PreCompact", trigger="manual")
        self.dispatch("SessionStart", source="resume")
        state = self.state()
        self.assertEqual(state["wait_conditions"][0]["status"], "released")
        self.assertEqual(state["work_units"][-1]["status"], "active")
        pending_after = [item["id"] for item in state["requirements"]
                         if item["status"] == "pending"]
        self.assertTrue(set(pending_before) <= set(pending_after))
        first = self.dispatch("Stop", last_assistant_message="任务仍在进行。")
        second = self.dispatch("Stop", last_assistant_message="任务仍在进行。")
        self.assertEqual(first, {})
        self.assertEqual(second, {})

    # -- W14: 0.15.0 misclassified v2 pause recovers with history ---------
    def test_w14_misclassified_v2_pause_recovers_with_verified_source(self):
        self.park_with_pause("暂停一下，我重启下测试工具。")
        state = self.state()
        condition = state["wait_conditions"][0]
        # Shape the ledger the way 0.15.0 wrote it: a subject-bound
        # confirmation object derived from the polite suffix.
        condition["subject_sha256"] = cg.sha256_text(cg.wait_subject("暂停一下"))
        self.save_state(state)
        self.assertEqual(self.waiting()[0]["status"], "waiting")
        old_released_fields = (state["wait_conditions"][0]["released_at"],
                               state["wait_conditions"][0]["released_by_source"])
        self.prompt("请继续执行")
        state = self.state()
        self.assertEqual(state["wait_conditions"][0]["status"], "released")
        self.assertNotEqual((state["wait_conditions"][0]["released_at"],
                             state["wait_conditions"][0]["released_by_source"]),
                            old_released_fields)
        self.assertEqual(state["wait_conditions"][0]["released_by_source"],
                         state["prompts"][-1]["id"])
        self.assertEqual(state["work_units"][-1]["status"], "active")

    def test_w14b_misclassified_pause_without_verifiable_source_stays(self):
        self.park_with_pause("暂停一下，我重启下测试工具。")
        state = self.state()
        condition = state["wait_conditions"][0]
        condition["subject_sha256"] = cg.sha256_text(cg.wait_subject("暂停一下"))
        self.save_state(state)
        source_id = condition["raised_by_source"]
        prompt_dir = self.root / "private" / "sessions-v2" / "p0" / "prompts"
        record = next(item for item in prompt_dir.iterdir()
                      if source_id in item.name and item.is_file())
        record.unlink()
        self.prompt("请继续执行")
        state = self.state()
        self.assertEqual(state["wait_conditions"][0]["status"], "waiting")
        self.assertIsNone(state["wait_conditions"][0]["released_by_source"])
        self.assertEqual(state["work_units"][-1]["status"], "awaiting_user")

    def test_w14c_migrated_legacy_wait_bytes_stay_unchanged(self):
        session_dir = self.root / "private" / "sessions-v2" / "p0"
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "state.json").write_text(SCHEMA10_PARKED_FIXTURE,
                                                encoding="utf-8")
        with mock.patch.object(cg.secrets, "token_urlsafe",
                               return_value="p0token"):
            self.dispatch("UserPromptSubmit", prompt="请继续执行")
        state = self.state()
        self.assertEqual(state["wait_conditions"][0]["kind"],
                         cg.MIGRATED_WAIT_CONDITION_KIND)
        self.assertEqual(state["wait_conditions"][0]["status"], "waiting")
        self.assertIsNone(state["wait_conditions"][0]["released_by_source"])

    # -- W15: repeated cycles, mixed validity, switch/cancel -------------
    def test_w15_repeat_pause_resume_cycles_without_duplicate_todos(self):
        self.park_with_pause("暂停")
        cycles = ("先暂停", "请暂停当前任务", "暂停一下")
        for cycle in range(3):
            self.prompt("请继续执行")
            self.assert_released_unique_wait()
            self.assertEqual(len(self.state()["work_units"]), 1)
            self.prompt(cycles[cycle])
            self.assertEqual(len(self.waiting()), 1)
        state = self.state()
        self.assertEqual(len(state["work_units"]), 1)
        # The journal stays append-only one-per-root-prompt (the activation
        # control prompt raises no requirement); the resume and re-pause
        # cycles duplicate neither units nor waiting conditions.
        bound = [item.get("prompt_id") for item in state["requirements"]]
        self.assertEqual(len(bound), len(set(bound)))
        self.assertEqual(len(self.waiting()), 1)
        self.dispatch("Stop", last_assistant_message="再次暂停。")
        self.assertEqual(self.state()["work_units"][-1]["status"],
                         "awaiting_user")

        # The same pause bytes raise no duplicate todo (idempotent source-
        # clause identity), and the resume does not duplicate requirements.
        self.prompt("请继续执行")
        self.assert_released_unique_wait()
        self.prompt("先暂停")
        self.assertEqual(self.waiting(), [])

    def test_w15b_long_text_valid_directive_with_invalid_description(self):
        self.park_with_pause("暂停")
        self.prompt(
            "下面的示例对话里出现过“继续”这个词，仅作为引用保留。"
            "如果测试失败请报告日志。现在你继续"
        )
        state = self.state()
        self.assertEqual(state["wait_conditions"][0]["status"], "released")
        self.assertEqual(state["work_units"][-1]["status"], "active")

    def test_w15c_cancelled_unit_does_not_revive_on_later_resume(self):
        self.park_with_pause("暂停")
        self.prompt("取消当前任务")
        state = self.state()
        cancelled = next(item for item in state["work_units"]
                         if item["status"] == "historical_unresolved")
        self.prompt("继续")
        state = self.state()
        still = next(item for item in state["work_units"]
                     if item["id"] == cancelled["id"])
        self.assertEqual(still["status"], "historical_unresolved")
        self.assertNotEqual(state["work_state"]["active_work_unit_id"],
                            cancelled["id"])
