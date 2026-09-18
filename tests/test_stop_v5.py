"""Paired production Stop replays for current-action provenance."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import context_guard as cg
from cg_codex_core_adapter import project_current_action


class StopV5Tests(unittest.TestCase):
    def test_text_only_owner_roles_do_not_create_current_readiness(self):
        prompt = "请运行本轮测试。"
        cases = (
            ("本轮测试还未运行，我会继续。", "assistant", "allow_neutral"),
            ("请先登录 GitHub Desktop，完成后告诉我。", "user", "allow_user_handoff"),
            ("PR 正在等待外部审核。", "external", "allow_external_wait"),
        )
        for reply, role, expected in cases:
            with self.subTest(role=role):
                decision = cg.classify_stop_decision(reply, prompt)
                self.assertEqual(decision["outcome"], expected)
                self.assertTrue(any(a["owner"] == role for a in decision["actions"]))
                self.assertFalse(any(a.get("authorization") == "authorized"
                                     for a in decision["actions"]))
                self.assertEqual(decision["interpretation"]["remaining_action_owner"],
                                 "unknown")

    def test_delivered_explanation_and_verified_edit_share_complete_root_coverage(self):
        def observed(_cg, event, cwd):
            target = Path(cwd) / "src/queue.ts"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("before\n", encoding="utf-8")
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                              tool_input={"cmd": f"cat {target}"},
                              tool_response={"exit_code": 0, "output": "before\n"}))
            target.write_text("after\n", encoding="utf-8")
            cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                              tool_input={"patch": f"*** Begin Patch\n*** Update File: {target}\n@@\n-before\n+after\n*** End Patch\n"},
                              tool_response={"success": True}))
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                              tool_input={"cmd": f"cat {target}"},
                              tool_response={"exit_code": 0, "output": "after\n"}))
        result, decision, state = self.replay(
            "先说明原因，再修正 src/queue.ts 并核对文件内容。",
            "原因已说明，文件已修正并回读。", preparation=observed, include_state=True)
        self.assertEqual(result, {})
        self.assertTrue(any(r.get("information_source_span") is not None and
                            r["status"] == "answered" for r in state["requirements"]))
        mixed = [r for r in decision["core_projections"]
                 if r["predicate"] == "information_and_edit"]
        self.assertEqual(len(mixed), 1)
        self.assertEqual(mixed[0]["predicate_state"], "satisfied")
        self.assertTrue(mixed[0]["certifiable"])
        self.assertEqual(mixed[0]["unknown_coverage_count"], 0)

    def test_exact_edit_with_reported_other_path_and_prohibition(self):
        def observed(_cg, event, cwd):
            target = Path(cwd) / "packages/api/src/request.ts"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("before\n", encoding="utf-8")
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                              tool_input={"cmd": f"cat {target}"},
                              tool_response={"exit_code": 0, "output": "before\n"}))
            target.write_text("after\n", encoding="utf-8")
            cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                              tool_input={"patch": f"*** Begin Patch\n*** Update File: {target}\n@@\n-before\n+after\n*** End Patch\n"},
                              tool_response={"success": True}))
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                              tool_input={"cmd": f"cat {target}"},
                              tool_response={"exit_code": 0, "output": "after\n"}))
        root = ("请只修改 packages/api/src/request.ts。错误日志还提到了 "
                "packages/web/src/request.ts，但本轮不要动后者。")
        result, decision = self.replay(root, "API 文件已修改并核对。", preparation=observed)
        self.assertEqual(result, {})
        rows = [r for r in decision["core_projections"]
                if r["predicate"] == "edit_with_prohibition"]
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["certifiable"])
        self.assertEqual(rows[0]["violating_host_event_ids"], [])
        _, mere_claim = self.replay(root, "API 已修改，web 文件也改了。", preparation=observed)
        claimed_rows = [r for r in mere_claim["core_projections"]
                        if r["predicate"] == "edit_with_prohibition"]
        self.assertEqual(len(claimed_rows), 1)
        self.assertTrue(claimed_rows[0]["certifiable"])

        def observed_with_forbidden_edit(_cg, event, cwd):
            observed(_cg, event, cwd)
            forbidden = Path(cwd) / "packages/web/src/request.ts"
            forbidden.parent.mkdir(parents=True, exist_ok=True)
            forbidden.write_text("before\n", encoding="utf-8")
            forbidden.write_text("after\n", encoding="utf-8")
            cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                              tool_input={"patch": f"*** Begin Patch\n*** Update File: {forbidden}\n@@\n-before\n+after\n*** End Patch\n"},
                              tool_response={"success": True}))
        _, forbidden_effect = self.replay(root, "API 文件已修改并核对。",
                                          preparation=observed_with_forbidden_edit)
        forbidden_rows = [r for r in forbidden_effect["core_projections"]
                          if r["predicate"] == "edit_with_prohibition"]
        self.assertEqual(len(forbidden_rows), 1)
        self.assertEqual(forbidden_rows[0]["constraint_state"], "constraint_violated")
        self.assertFalse(forbidden_rows[0]["certifiable"])
        self.assertTrue(forbidden_rows[0]["violating_host_event_ids"])
        for operation in ("Add", "Delete"):
            with self.subTest(operation=operation):
                def observed_with_other_mutation(_cg, event, cwd):
                    observed(_cg, event, cwd)
                    forbidden = Path(cwd) / "packages/web/src/request.ts"
                    forbidden.parent.mkdir(parents=True, exist_ok=True)
                    if operation == "Add":
                        forbidden.write_text("created\n", encoding="utf-8")
                        patch = f"*** Begin Patch\n*** Add File: {forbidden}\n+created\n*** End Patch\n"
                    else:
                        forbidden.write_text("old\n", encoding="utf-8")
                        forbidden.unlink()
                        patch = f"*** Begin Patch\n*** Delete File: {forbidden}\n*** End Patch\n"
                    cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                                      tool_input={"patch": patch},
                                      tool_response={"success": True}))
                _, mutation = self.replay(root, "API 文件已修改并核对。",
                                          preparation=observed_with_other_mutation)
                row = next(r for r in mutation["core_projections"]
                           if r["predicate"] == "edit_with_prohibition")
                self.assertEqual(row["constraint_state"], "constraint_violated")
                self.assertFalse(row["certifiable"])
                self.assertTrue(row["violating_host_event_ids"])

        def observed_with_unknown_shell(_cg, event, cwd):
            observed(_cg, event, cwd)
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                              tool_input={"cmd": "printf changed > packages/web/src/request.ts"},
                              tool_response={"exit_code": 0, "output": ""}))
        _, unknown_effect = self.replay(root, "API 文件已修改并核对。",
                                        preparation=observed_with_unknown_shell)
        row = next(r for r in unknown_effect["core_projections"]
                   if r["predicate"] == "edit_with_prohibition")
        self.assertFalse(row["certifiable"])
        self.assertTrue(row["unattributed_host_event_ids"])
        def observed_with_alias_edit(_cg, event, cwd):
            observed(_cg, event, cwd)
            outside = Path(cwd) / "outside.ts"
            outside.write_text("before\n", encoding="utf-8")
            forbidden = Path(cwd) / "packages/web/src/request.ts"
            forbidden.parent.mkdir(parents=True, exist_ok=True)
            forbidden.symlink_to(outside)
            outside.write_text("after\n", encoding="utf-8")
            cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                              tool_input={"patch": f"*** Begin Patch\n*** Update File: {forbidden}\n@@\n-before\n+after\n*** End Patch\n"},
                              tool_response={"success": True}))
        _, alias_effect = self.replay(root, "API 文件已修改并核对。",
                                      preparation=observed_with_alias_edit)
        alias_row = next(r for r in alias_effect["core_projections"]
                         if r["predicate"] == "edit_with_prohibition")
        self.assertFalse(alias_row["certifiable"])
        self.assertEqual(alias_row["violating_host_event_ids"], [])
        # An extra unresolved positive request must remain open even when the
        # exact edit and prohibition are otherwise identical.
        _, unresolved = self.replay(root + " 同时完成未命名的迁移。",
                                    "API 文件已修改并核对。", preparation=observed)
        self.assertFalse(any(r["certifiable"] for r in unresolved["core_projections"]))
        competing = ("请只修改 packages/api/src/request.ts。日志还提到了 "
                     "packages/web/src/request.ts 与 packages/mobile/src/request.ts，"
                     "但本轮不要动后者。")
        _, ambiguous = self.replay(competing, "API 文件已修改并核对。",
                                   preparation=observed)
        self.assertFalse(any(r["certifiable"] for r in ambiguous["core_projections"]))

    def test_existing_root_speech_act_keeps_information_questions_out_of_edit_basis(self):
        with tempfile.TemporaryDirectory(prefix="core-question-role-") as tmp:
            selected = Path(tmp) / "parser.py"
            selected.write_text("before\n", encoding="utf-8")
            def readback(_cg, event, _cwd):
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"cat {selected}"},
                                  tool_response={"exit_code": 0, "output": "before\n"}))
            for root in (
                "修复解析器是否会影响性能？",
                "修改 src/a.ts 会导致什么后果？",
            ):
                with self.subTest(root=root):
                    result, decision = self.replay(root, "这是影响分析。", preparation=readback)
                    self.assertEqual(result, {})
                    self.assertEqual(decision["actions"], [])
                    self.assertEqual(decision["core_projections"], [])

    def replay(self, root: str, final: str, *, preparation=None, include_state=False):
        with tempfile.TemporaryDirectory(prefix="stop-v5-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(kind, turn="turn", **fields):
                    return dict(hook_event_name=kind, session_id="synthetic-v5",
                                cwd=tmp, turn_id=turn, **fields)
                cg.dispatch(event("UserPromptSubmit", "control", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", prompt=root))
                if preparation:
                    preparation(cg, event, tmp)
                result = cg.dispatch(event("Stop", last_assistant_message=final))
                state = cg.load_state(Path(tmp) / "private/sessions/synthetic-v5", event("Stop"))
                if include_state:
                    return result, state["decision_log"][-1], state
                return result, state["decision_log"][-1]
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_future_observation_and_specific_unrun_test(self):
        cases = [
            ("按既定计划执行本轮修复。",
             "本轮修复和回归验证已完成。实际收益仍需后续使用观察。改动保持未提交。", False),
            ("按既定计划执行本轮修复。",
             "本轮修改已完成，长期稳定性尚待真实使用检验。", False),
            ("按既定计划执行本轮修复并运行测试。",
             "本地修改已完成。我接下来需要运行测试。", False),
            ("按既定计划执行本轮修复并运行测试。",
             "本地修改已完成。测试尚未运行。", False),
        ]
        for root, final, blocked in cases:
            with self.subTest(final=final):
                result, decision = self.replay(root, final)
                self.assertEqual(result.get("decision") == "block", blocked)
                self.assertEqual(decision["protocol_version"], "5.0.0")
                self.assertNotIn("explicit_user_persistence", decision["reason_codes"])
                self.assertFalse(any(a["category"] == "generic_work" and
                                     a.get("actionability") == "current_ready"
                                     for a in decision["actions"]))
                self.assertTrue(all("authorization" not in a for a in decision["actions"]))

    def test_reply_wait_does_not_register_external_operation(self):
        _, decision, state = self.replay("查看本轮材料并说明结果。",
                                         "外部审核还在继续，后续等结果。",
                                         include_state=True)
        self.assertNotEqual(decision["outcome"], "silent_yield_preserve_pending")
        self.assertEqual(state["wait_conditions"], [])

    def test_host_goal_adoption_reports_unavailable_without_creating_work(self):
        with tempfile.TemporaryDirectory(prefix="core-goal-capability-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(prompt):
                    return dict(hook_event_name="UserPromptSubmit", session_id="goal-capability-v5",
                                cwd=tmp, turn_id="turn", prompt=prompt)
                cg.dispatch(event("context-guard on"))
                response = cg.dispatch(event("context-guard goal-adopt"))
                self.assertIn("capability_unavailable", str(response))
                state = cg.load_state(Path(tmp) / "private/sessions/goal-capability-v5",
                                      event("context-guard status"))
                self.assertEqual(state["requirements"], [])
                self.assertIn("goal_host_completion=capability_unavailable",
                              cg.status_context(state))
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_mixed_information_delivers_only_its_utf8_span(self):
        root = "请解释方案并修改文件 /tmp/cg-mixed-A.py。未知条件保持原样。"
        result, _, state = self.replay(
            root, "方案的做法是先检查，再修改；文件仍待处理。", include_state=True)
        self.assertEqual(result, {})
        current = [i for i in state["requirements"] if i.get("prompt_id") == state["prompts"][-1]["id"]]
        self.assertGreaterEqual(len(current), 2)
        parent = next(i for i in current if "information_source_span" not in i)
        child = next(i for i in current if "information_source_span" in i)
        self.assertEqual(parent["status"], "pending")
        self.assertEqual(child["status"], "answered")
        start, end = child["information_source_span"]
        self.assertEqual(root.encode("utf-8")[start:end].decode("utf-8"), child["text"])
        self.assertIn("未知条件保持原样", parent["text"])

    def test_explain_install_restart_is_delivery_not_tool_intent(self):
        cases = (
            ("请解释如何重启宿主。", "先保存状态，再由操作者重启宿主。"),
            ("Explain how to install the plugin.", "The installer copies a validated package."),
        )
        for root, final in cases:
            with self.subTest(root=root):
                result, decision, state = self.replay(root, final, include_state=True)
                self.assertEqual(result, {})
                self.assertEqual(state["requirements"][-1]["status"], "answered")
                self.assertEqual(decision["core_projections"], [])
        for command in ("请安装插件。", "Restart the host."):
            with self.subTest(command=command):
                _, _, state = self.replay(command, "操作尚未执行。", include_state=True)
                self.assertEqual(state["requirements"][-1]["status"], "pending")

    def test_information_with_execution_prohibition_delivers_information_only(self):
        cases = (
            ("解释安装流程，不执行安装。", "安装流程是先校验包，再由操作者启动安装。"),
            ("说明重启步骤，但不要重启宿主。", "步骤是保存状态并由操作者重启。"),
            ("说明数据同步机制，不执行同步。", "机制先比较版本，再传输差异。"),
            ("Explain the installation steps, but do not install the plugin.",
             "The steps are to verify the package and then install it."),
            ("Describe the data synchronization workflow, but do not run it.",
             "The workflow compares versions and then transfers differences."),
        )
        for root, final in cases:
            with self.subTest(root=root):
                result, decision, state = self.replay(root, final, include_state=True)
                self.assertEqual(result, {})
                current = [i for i in state["requirements"]
                           if i.get("prompt_id") == state["prompts"][-1]["id"]]
                self.assertTrue(any(i["status"] == "answered" and
                                    i.get("information_source_span") is not None
                                    for i in current))
                self.assertTrue(any(i["status"] == "pending" for i in current))
                self.assertFalse(any(a.get("actionability") == "current_ready"
                                     for a in decision["actions"]))

    def test_trusted_preflight_makes_unrun_test_actionable(self):
        with tempfile.TemporaryDirectory(prefix="core-input-") as tmp:
            suite = Path(tmp) / "suite.py"
            suite.write_text("def test_ok(): assert True\n", encoding="utf-8")
            def preparation(_cg, event, _cwd):
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"test -f {suite}"},
                                  tool_response={"exit_code": 0, "output": ""}))
            root = f"继续执行，运行 {suite} 的测试。"
            result, decision = self.replay(root, "测试尚未运行。", preparation=preparation)
            self.assertEqual(result.get("decision"), "block")
            self.assertIn("resume_with_actionable_work", decision["reason_codes"])
            self.assertNotIn("explicit_user_persistence", decision["reason_codes"])

    def test_one_test_fact_cannot_close_a_combined_edit_and_test(self):
        with tempfile.TemporaryDirectory(prefix="core-combined-") as tmp:
            suite = Path(tmp) / "suite.py"
            suite.write_text("def test_ok(): assert True\n", encoding="utf-8")
            def observed(_cg, event, _cwd):
                for command in (f"test -f {suite}", f"pytest {suite}"):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": command},
                                      tool_response={"exit_code": 0, "output": "1 passed"}))
            root = f"请修改 {suite}，并运行 {suite} 的测试。"
            _, decision, state = self.replay(
                root, "测试通过，但修改尚未完成。",
                preparation=observed, include_state=True)
            aggregate = next(row for row in decision["core_projections"]
                             if row["predicate"] == "edit_and_test")
            self.assertFalse(aggregate["certifiable"])
            self.assertEqual(aggregate["predicate_state"], "insufficient")
            self.assertTrue(any(i.get("execution_kind") == "local_edit"
                                and i["status"] == "pending"
                                for i in state["requirements"]))

    def test_combined_edit_and_test_have_distinct_sourced_children(self):
        with tempfile.TemporaryDirectory(prefix="core-combined-positive-") as tmp:
            suite = Path(tmp) / "suite.py"
            suite.write_text("before\n", encoding="utf-8")
            patch = (f"*** Begin Patch\n*** Update File: {suite}\n@@\n"
                     "-before\n+after\n*** End Patch\n")
            def observed(_cg, event, _cwd):
                for cmd, output in ((f"cat {suite}", "before\n"),
                                    (f"test -f {suite}", "")):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": cmd},
                                      tool_response={"exit_code": 0, "output": output}))
                suite.write_text("after\n", encoding="utf-8")
                cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                                  tool_input={"patch": patch},
                                  tool_response={"success": True}))
                for cmd, output in ((f"cat {suite}", "after\n"),
                                    (f"pytest {suite}", "1 passed")):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": cmd},
                                      tool_response={"exit_code": 0, "output": output}))
            _, decision, state = self.replay(
                f"请修改 {suite}，并运行 {suite} 的测试。", "修改和测试已完成。",
                preparation=observed, include_state=True)
            current = [i for i in state["requirements"]
                       if i.get("prompt_id") == state["prompts"][-1]["id"]]
            children = [i for i in current if i.get("execution_source_span") is not None]
            self.assertEqual({i["execution_kind"] for i in children},
                             {"local_edit", "test_verify"})
            self.assertEqual(len(decision["core_projections"]), 3)
            self.assertTrue(all(row["predicate_state"] == "satisfied"
                                for row in decision["core_projections"]))
            aggregate = next(row for row in decision["core_projections"]
                             if row["predicate"] == "edit_and_test")
            self.assertTrue(aggregate["certifiable"])
            self.assertEqual(aggregate["unknown_coverage_count"], 0)

    def test_later_commit_push_synthetic_host_lineage_reuses_sourced_repo(self):
        """Structured Hook replay only: this test never runs Git commands."""
        with tempfile.TemporaryDirectory(prefix="core-git-replay-") as tmp:
            root = Path(tmp)
            repo_a, repo_b = root / "A", root / "B"
            repo_a.mkdir()
            repo_b.mkdir()
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(root / "private")
            try:
                def event(kind, **fields):
                    return dict(hook_event_name=kind, session_id="git-replay-v5",
                                cwd=str(repo_a), turn_id="turn", **fields)
                def observed(command, output):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": f"git -C {repo_b} {command}"},
                                      tool_response={"exit_code": 0, "output": output}))
                cg.dispatch(event("UserPromptSubmit", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", prompt=f"请在 {repo_b} 仓库工作。"))
                cg.dispatch(event("UserPromptSubmit", prompt="提交改动，并推送 origin main。"))
                old, new = "a" * 40, "b" * 40
                observed("rev-parse --show-toplevel", str(repo_b) + "\n")
                observed("show -s --format=%H%n%P%n%T HEAD", f"{old}\n\n{'1' * 40}\n")
                observed("commit -m change", "[main bbbbbbb] change\n")
                observed("show -s --format=%H%n%P%n%T HEAD",
                         f"{new}\n{old}\n{'2' * 40}\n")
                observed("symbolic-ref --short HEAD", "main\n")
                observed("push origin main", "To local fixture\n")
                observed("ls-remote origin refs/heads/main", f"{new}\trefs/heads/main\n")
                cg.dispatch(event("Stop", last_assistant_message="提交并推送完成。"))
                state = cg.load_state(root / "private/sessions/git-replay-v5", event("Stop"))
                rows = state["decision_log"][-1]["core_projections"]
                self.assertEqual({row["predicate"] for row in rows},
                                 {"commit_verified", "push_verified", "commit_and_push"})
                self.assertTrue(all(row["predicate_state"] == "satisfied" for row in rows))
                aggregate = next(row for row in rows if row["predicate"] == "commit_and_push")
                self.assertTrue(aggregate["certifiable"])
                git_facts = [e["core_observation"] for e in state["evidence"]
                             if isinstance(e.get("core_observation"), dict)
                             and isinstance(e["core_observation"].get("git"), dict)]
                self.assertIn({"oid": new, "parent": old, "tree": "2" * 40},
                              [f["git"] for f in git_facts])
                self.assertIn({"oid": new, "remote": "origin", "refspec": "main"},
                              [f["git"] for f in git_facts])
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_git_target_requires_unique_prior_root_and_current_host_selection(self):
        for mode in ("wrong_target", "ambiguous_prior", "stale_selection", "reply_only"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="core-git-negative-") as tmp:
                root = Path(tmp)
                repo_a, repo_b, repo_c = (root / name for name in ("A", "B", "C"))
                for repo in (repo_a, repo_b, repo_c):
                    repo.mkdir()
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(root / "private")
                try:
                    def event(kind, **fields):
                        return dict(hook_event_name=kind, session_id="git-negative-v5",
                                    cwd=str(repo_a), turn_id="turn", **fields)
                    def selected(target):
                        cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                          tool_input={"cmd": f"git -C {target} rev-parse --show-toplevel"},
                                          tool_response={"exit_code": 0, "output": str(target) + "\n"}))
                    cg.dispatch(event("UserPromptSubmit", prompt="context-guard on"))
                    first = (f"请在 {repo_b} 与 {repo_c} 仓库工作。" if mode == "ambiguous_prior"
                             else f"请在 {repo_b} 仓库工作。")
                    cg.dispatch(event("UserPromptSubmit", prompt=first))
                    if mode == "stale_selection":
                        selected(repo_b)
                    cg.dispatch(event("UserPromptSubmit", prompt="提交改动，并推送 origin main。"))
                    if mode not in {"stale_selection", "reply_only"}:
                        selected(repo_c if mode == "wrong_target" else repo_b)
                    cg.dispatch(event("Stop", last_assistant_message=f"将在 {repo_b} 提交并推送。"))
                    state = cg.load_state(root / "private/sessions/git-negative-v5", event("Stop"))
                    self.assertEqual(state["decision_log"][-1]["core_projections"], [])
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_git_readback_does_not_certify_wrong_parent_tree_branch_or_remote(self):
        """No Git effect: adversarial structured Hook captures only."""
        for defect in ("parent", "tree", "branch", "remote", "no_commit", "no_push"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory(prefix="core-git-effect-") as tmp:
                root, repo = Path(tmp), Path(tmp) / "B"
                repo.mkdir()
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(root / "private")
                try:
                    def event(kind, **fields):
                        return dict(hook_event_name=kind, session_id="git-effect-v5",
                                    cwd=str(root), turn_id="turn", **fields)
                    def observed(command, output):
                        cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                          tool_input={"cmd": f"git -C {repo} {command}"},
                                          tool_response={"exit_code": 0, "output": output}))
                    cg.dispatch(event("UserPromptSubmit", prompt="context-guard on"))
                    cg.dispatch(event("UserPromptSubmit", prompt=f"请在 {repo} 仓库工作。"))
                    cg.dispatch(event("UserPromptSubmit", prompt="提交改动，并推送 origin main。"))
                    old, new = "a" * 40, "b" * 40
                    observed("rev-parse --show-toplevel", str(repo) + "\n")
                    observed("show -s --format=%H%n%P%n%T HEAD", f"{old}\n\n{'1' * 40}\n")
                    if defect != "no_commit":
                        observed("commit -m change", "[main bbbbbbb] change\n")
                    parent = "c" * 40 if defect == "parent" else old
                    tree = "1" * 40 if defect == "tree" else "2" * 40
                    observed("show -s --format=%H%n%P%n%T HEAD", f"{new}\n{parent}\n{tree}\n")
                    observed("symbolic-ref --short HEAD", "dev\n" if defect == "branch" else "main\n")
                    if defect != "no_push":
                        observed("push origin main", "To local fixture\n")
                    remote = "c" * 40 if defect == "remote" else new
                    observed("ls-remote origin refs/heads/main", f"{remote}\trefs/heads/main\n")
                    cg.dispatch(event("Stop", last_assistant_message="已完成。"))
                    state = cg.load_state(root / "private/sessions/git-effect-v5", event("Stop"))
                    aggregates = [row for row in state["decision_log"][-1]["core_projections"]
                                  if row["predicate"] == "commit_and_push"]
                    self.assertFalse(aggregates and aggregates[0]["certifiable"])
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_successful_test_projection_is_persisted_at_stop(self):
        with tempfile.TemporaryDirectory(prefix="core-success-") as tmp:
            suite = Path(tmp) / "suite.py"
            suite.write_text("def test_ok(): assert True\n", encoding="utf-8")
            def observed(_cg, event, _cwd):
                for command in (f"test -f {suite}", f"pytest {suite}"):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": command},
                                      tool_response={"exit_code": 0, "output": "1 passed"}))
            _, decision, state = self.replay(
                f"继续执行，运行 {suite} 的测试。", "测试通过。",
                preparation=observed, include_state=True)
            rows = decision["core_projections"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["predicate_state"], "satisfied")
            self.assertTrue(rows[0]["certifiable"])
            self.assertEqual(rows[0]["unknown_coverage_count"], 0)
            # The shared projection does not self-apply a whole-work checkpoint.
            self.assertEqual(state["requirements"][-1]["status"], "pending")

    def test_edit_needs_structured_patch_and_changed_readback(self):
        with tempfile.TemporaryDirectory(prefix="core-edit-") as tmp:
            target = Path(tmp) / "module.py"
            target.write_text("before\n", encoding="utf-8")
            patch = (f"*** Begin Patch\n*** Update File: {target}\n@@\n"
                     "-before\n+after\n*** End Patch\n")

            def observed(_cg, event, _cwd):
                def readback(content):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": f"cat {target}"},
                                      tool_response={"exit_code": 0, "output": content}))
                readback("before\n")
                target.write_text("after\n", encoding="utf-8")
                cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                                  tool_input={"patch": patch},
                                  tool_response={"success": True}))
                readback("after\n")

            _, decision, state = self.replay(
                f"请修改 {target}。", "修改已完成。", preparation=observed,
                include_state=True)
            self.assertEqual(len(decision["core_projections"]), 1)
            self.assertEqual(decision["core_projections"][0]["predicate_state"], "satisfied")
            self.assertTrue(decision["core_projections"][0]["certifiable"])
            self.assertEqual(state["requirements"][-1]["status"], "pending")

            for root in (f"请修改 {target}，写入指定内容。",
                         f"请修改 {target}，不要覆盖已有内容。"):
                with self.subTest(root=root):
                    _, constrained = self.replay(root, "修改已完成。", preparation=observed)
                    self.assertFalse(any(row["certifiable"]
                                         for row in constrained["core_projections"]))
                    self.assertTrue(all(row["unknown_coverage_count"] > 0
                                        for row in constrained["core_projections"]))

    def test_edit_is_not_proven_by_patch_or_exit_zero_alone(self):
        with tempfile.TemporaryDirectory(prefix="core-edit-negative-") as tmp:
            target = Path(tmp) / "module.py"
            target.write_text("before\n", encoding="utf-8")
            patch = (f"*** Begin Patch\n*** Update File: {target}\n@@\n"
                     "-before\n+after\n*** End Patch\n")
            def observed(_cg, event, _cwd):
                for content in ("before\n", "before\n"):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": f"cat {target}"},
                                      tool_response={"exit_code": 0, "output": content}))
                    if content == "before\n":
                        cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                                          tool_input={"patch": patch},
                                          tool_response={"success": True}))
                        break
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"cat {target}"},
                                  tool_response={"exit_code": 0, "output": "before\n"}))
            _, decision = self.replay(f"请修改 {target}。", "修改已完成。",
                                      preparation=observed)
            self.assertNotEqual(decision["core_projections"][0]["predicate_state"], "satisfied")
            self.assertFalse(decision["core_projections"][0]["certifiable"])

    def test_windows_drive_locator_has_lexical_provenance_without_native_claim(self):
        target = r"C:\Repo\suite.py"
        def observed(_cg, event, _cwd):
            for command in (f"test -f '{target}'", f"pytest '{target}'"):
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": command},
                                  tool_response={"exit_code": 0, "output": "1 passed"}))
        _, decision, _ = self.replay(
            f"继续执行，运行 {target} 的测试。", "测试通过。",
            preparation=observed, include_state=True)
        self.assertEqual(decision["core_projections"][0]["predicate_state"], "satisfied")
        self.assertTrue(decision["core_projections"][0]["certifiable"])
        for unsupported in (r"\\server\share\suite.py", r"C:\Repo\CON\suite.py"):
            with self.subTest(unsupported=unsupported):
                _, decision, _ = self.replay(
                    f"继续执行，运行 {unsupported} 的测试。", "测试尚未运行。",
                    preparation=observed, include_state=True)
                self.assertEqual(decision["core_projections"], [])

    def test_current_effect_is_due_only_from_root_scope_and_host_selection(self):
        with tempfile.TemporaryDirectory(prefix="core-eval-") as tmp:
            selected = Path(tmp) / "benchmark.py"
            selected.write_text("def measure(): return 1\n", encoding="utf-8")
            def ready(_cg, event, _cwd):
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"test -f {selected}"},
                                  tool_response={"exit_code": 0, "output": ""}))
            cases = (
                ("现在评估这次修改的效果并给出结果。", "修改完成，效果以后观察。", True),
                ("立刻测量本次改动的吞吐收益。", "已改动；吞吐收益有待评估。", False),
                ("检查这批改动并给出结论。", "这项检查尚未完成。", False),
                ("解释‘现在评估这次修改的效果’这句话。", "未来可以再观察效果。", False),
                ("不要现在评估这次修改的效果。", "效果以后观察。", False),
            )
            for root, final, expected_block in cases:
                with self.subTest(root=root):
                    result, decision = self.replay(root, final, preparation=ready)
                    self.assertEqual(result.get("decision") == "block", expected_block)
                    if expected_block:
                        self.assertIn("current_due_action_omitted", decision["reason_codes"])
                        self.assertEqual(decision["actions"][0]["actionability"],
                                         "current_ready")
            result, _ = self.replay(cases[0][0], cases[0][1])
            self.assertEqual(result, {})

    def test_root_time_and_antecedent_keep_review_deferred(self):
        with tempfile.TemporaryDirectory(prefix="core-condition-") as tmp:
            selected = Path(tmp) / "benchmark.py"
            selected.write_text("def measure(): return 1\n", encoding="utf-8")
            def ready(_cg, event, _cwd):
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"test -f {selected}"},
                                  tool_response={"exit_code": 0, "output": ""}))
            cases = (
                ("下周评估这次修改的效果。", "predicate"),
                ("收到外部审批后评估这次修改的效果。", "external_dependency"),
                ("外部审核通过后评估这次修改的效果。", "external_dependency"),
                ("After the external approval, evaluate this change.", "external_dependency"),
                ("Next month evaluate this change.", "predicate"),
            )
            for root, kind in cases:
                with self.subTest(root=root):
                    result, decision = self.replay(root, "修改完成，评估尚未进行。",
                                                   preparation=ready)
                    self.assertEqual(result, {})
                    self.assertNotIn("current_due_action_omitted", decision["reason_codes"])
                    self.assertFalse(any(a.get("actionability") == "current_ready"
                                         for a in decision["actions"]))
                    self.assertFalse(any(w.get("external_source_sha256")
                                         for w in decision.get("wait_conditions", [])))
                    self.assertEqual(len(decision["core_projections"]), 1)
                    self.assertIn("pending", decision["core_projections"][0]["conditions"].values())
                    self.assertEqual(decision["core_projections"][0]["root_condition"]["kind"], kind)
            result, decision = self.replay("现在评估这次修改的效果。",
                                           "评估尚未进行。", preparation=ready)
            self.assertEqual(result, {})
            self.assertNotIn("current_due_action_omitted", decision["reason_codes"])
            self.assertEqual(decision["actions"][0]["actionability"], "current_ready")

    def test_event_sequence_survives_same_timestamp_and_clock_rollback(self):
        with tempfile.TemporaryDirectory(prefix="stop-v5-seq-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(kind, turn="turn", **fields):
                    return dict(hook_event_name=kind, session_id="sequence-v5",
                                cwd=tmp, turn_id=turn, **fields)
                suite = Path(tmp) / "suite.py"
                suite.write_text("def test_ok(): assert True\n", encoding="utf-8")
                cg.dispatch(event("UserPromptSubmit", "control", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", prompt=f"继续执行，运行 {suite} 的测试。"))
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"test -f {suite}"},
                                  tool_response={"exit_code": 0, "output": ""}))
                directory = Path(tmp) / "private/sessions/sequence-v5"
                state = cg.load_state(directory, event("Stop"))
                item = state["requirements"][-1]
                root = next(p for p in state["prompts"] if p["id"] == item["prompt_id"])
                record = cg.read_prompt_record(directory, root)
                self.assertIsNotNone(record)
                obs = next(e for e in state["evidence"] if e.get("core_observation"))
                self.assertLess(record["core_event_seq"], obs["core_call_seq"])
                self.assertLess(obs["core_call_seq"], obs["core_result_seq"])
                for root_time, host_time in (("same", "same"), ("later", "earlier")):
                    with self.subTest(root_time=root_time, host_time=host_time):
                        record["created_at"] = root_time
                        obs["created_at"] = host_time
                        projection = project_current_action(
                            state, {root["id"]: record}, item=item,
                            action="test_verify", target=str(suite), turn="turn",
                            root_scope=record["text"].rstrip("。"))
                        self.assertEqual(projection["as_of"], state["core_event_sequence"])
                        self.assertEqual(projection["current_actions"][0]["target"], str(suite))
                prior = cg.dispatch(event("Stop", last_assistant_message="测试尚未运行。"))
                prior_state = cg.load_state(directory, event("Stop"))
                prior_decision = dict(prior_state["decision_log"][-1])
                prior_watermark = prior_state["core_event_sequence"]
                self.assertEqual(prior.get("decision"), "block")
                cg.dispatch(event("UserPromptSubmit", "later", prompt="接下来再安装工具。"))
                latest = cg.load_state(directory, event("Stop", "later"))
                self.assertEqual(latest["decision_log"][-1], prior_decision)
                self.assertGreater(latest["core_event_sequence"], prior_watermark)
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_late_prior_turn_result_cannot_violate_later_root(self):
        with tempfile.TemporaryDirectory(prefix="stop-v5-late-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(kind, turn="prior", **fields):
                    return dict(hook_event_name=kind, session_id="late-v5",
                                cwd=tmp, turn_id=turn, **fields)
                web = Path(tmp) / "packages/web/src/request.ts"
                api = Path(tmp) / "packages/api/src/request.ts"
                for target in (web, api):
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("old\n", encoding="utf-8")
                cg.dispatch(event("UserPromptSubmit", "control", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", prompt="修复本轮文件。"))
                web_patch = f"*** Begin Patch\n*** Update File: {web}\n@@\n-old\n+new\n*** End Patch\n"
                cg.dispatch(event("PreToolUse", tool_name="apply_patch",
                                  tool_use_id="earlier-call", tool_input={"patch": web_patch}))
                web.write_text("new\n", encoding="utf-8")
                root = ("请只修改 packages/api/src/request.ts。错误日志还提到了 "
                        "packages/web/src/request.ts，但本轮不要动后者。")
                cg.dispatch(event("UserPromptSubmit", "current", prompt=root))
                cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                                  tool_use_id="earlier-call", tool_input={"patch": web_patch},
                                  tool_response={"success": True}))
                cg.dispatch(event("PostToolUse", "current", tool_name="exec_command",
                                  tool_input={"cmd": f"cat {api}"},
                                  tool_response={"exit_code": 0, "output": "old\n"}))
                api.write_text("new\n", encoding="utf-8")
                api_patch = f"*** Begin Patch\n*** Update File: {api}\n@@\n-old\n+new\n*** End Patch\n"
                cg.dispatch(event("PostToolUse", "current", tool_name="apply_patch",
                                  tool_input={"patch": api_patch},
                                  tool_response={"success": True}))
                cg.dispatch(event("PostToolUse", "current", tool_name="exec_command",
                                  tool_input={"cmd": f"cat {api}"},
                                  tool_response={"exit_code": 0, "output": "new\n"}))
                cg.dispatch(event("Stop", "current", last_assistant_message="API 文件已修改并回读。"))
                directory = Path(tmp) / "private/sessions/late-v5"
                state = cg.load_state(directory, event("Stop", "current"))
                rows = [r for r in state["decision_log"][-1]["core_projections"]
                        if r["predicate"] == "edit_with_prohibition"]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["constraint_state"], "constraint_unresolved")
                self.assertEqual(rows[0]["crossing_host_event_ids"], ["E0001"])
                self.assertEqual(rows[0]["violating_host_event_ids"], [])
                origin = next(p for p in state["prompts"] if p.get("turn_id") == "prior")
                record = cg.read_prompt_record(directory, origin)
                self.assertEqual(record["turn_id"], "prior")
                self.assertEqual(record["record_sha256"], cg.prompt_record_hash(record))
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_missing_or_competing_prompt_turn_does_not_bind_host_origin(self):
        state = {
            "work_state": {"active_work_unit_id": "WU0001"},
            "requirements": [
                {"prompt_id": "P0001", "work_unit_id": "WU0001"},
                {"prompt_id": "P0002", "work_unit_id": "WU0001"},
            ],
            "prompts": [
                {"id": "P0001", "core_event_seq": 1},  # schema-12 legacy root
                {"id": "P0002", "core_event_seq": 2, "turn_id": "current"},
            ],
        }
        self.assertIsNone(cg.core_host_origin_prompt(state, {"turn_id": "prior"}))
        self.assertEqual(cg.core_host_origin_prompt(state, {"turn_id": "current"}), "P0002")
        state["prompts"][0]["turn_id"] = "current"
        self.assertIsNone(cg.core_host_origin_prompt(state, {"turn_id": "current"}))
        self.assertIsNone(cg.core_host_origin_prompt(state, {}))


if __name__ == "__main__":
    unittest.main()
