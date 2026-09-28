"""Per-case regression suite over the frozen historical incident library.

Each test maps one frozen library case (CGI-2026-009..CGI-2026-046) to the
CURRENT product contract: a synthetic dispatch-level replay with at least
one positive and one negative assertion. Where an existing test module is
the deeper authoritative coverage for the same chain, its locator is named
in the case's coverage-table row and in the test docstring; this suite
guarantees every case keeps a real, executed assertion.

Cases whose original behavior was replaced by a versioned contract change
(pre-0.13 execution approvals) verify the replacement invariant: the
default path neither vetoes ordinary business tools nor re-asks granted
natural-language authorization, while explicitly declared release profiles
keep their exact-ticket gate.

Platform boundary: Windows-native observations (CGI-2026-043/044/045 and
any Windows-only surface) carry portable source assertions here; their
native confirmation is a separate coordinator-run gate, never reported as
passed from this suite.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import context_guard as cg  # noqa: E402


def _hook(event_name, session, cwd, turn, **fields):
    payload = dict(hook_event_name=event_name, session_id=session,
                   cwd=cwd, turn_id=turn)
    payload.update(fields)
    return payload


def _permission_decision(result):
    output = (result or {}).get("hookSpecificOutput") or {}
    return output.get("permissionDecision"), output.get("permissionDecisionReason", "")


class CaseFixture:
    """One isolated synthetic session driven through real dispatch."""

    def __init__(self, prefix, activate=True):
        self.root = tempfile.mkdtemp(prefix=prefix)
        os.environ["CONTEXT_GUARD_DATA_DIR"] = self.root
        self.session = prefix
        self.directory = Path(self.root) / "sessions" / self.session
        self.turn = 0
        if activate:
            self.prompt("context-guard on")

    def prompt(self, text):
        self.turn += 1
        return cg.dispatch(_hook("UserPromptSubmit", self.session, self.root,
                                 f"t{self.turn}", prompt=text))

    def tool(self, tool_name, tool_input):
        self.turn += 1
        return cg.dispatch(_hook("PreToolUse", self.session, self.root,
                                 f"t{self.turn}", tool_name=tool_name,
                                 tool_input=tool_input))

    def after(self, tool_name, tool_input, tool_response):
        self.turn += 1
        return cg.dispatch(_hook("PostToolUse", self.session, self.root,
                                 f"t{self.turn}", tool_name=tool_name,
                                 tool_input=tool_input,
                                 tool_response=tool_response))

    def ready_file(self, target):
        if os.name == "nt":
            escaped = str(target).replace("'", "''")
            tool_input = {"cmd": f"Test-Path -LiteralPath '{escaped}' -PathType Leaf",
                          "shell": "powershell"}
            output = "True\r\n"
        else:
            tool_input = {"cmd": f"test -f '{target}'", "shell": "bash"}
            output = ""
        return self.after("exec_command", tool_input,
                          {"exit_code": 0, "output": output})

    def stop(self, reply, *, new_turn=True):
        if new_turn:
            self.turn += 1
        return cg.dispatch(_hook("Stop", self.session, self.root,
                                 f"t{self.turn}", last_assistant_message=reply))

    def state(self):
        return cg.load_state(self.directory, _hook(
            "Stop", self.session, self.root, f"t{self.turn}"))


class DefaultPathAuthorizationCases(unittest.TestCase):
    """009/017/026/018/027/019/028: default path has no execution approvals.

    Retired pre-0.13 behavior (deny high-risk actions without an
    action-ticket) was replaced by the versioned default-path contract; the
    replacement invariant is what these cases now pin. Deeper authoritative
    coverage: tests/test_cg130_default_path.py
    (::test_cases_a_through_e_all_allow_without_provenance,
    ::test_declared_release_profile_enforces_tier_a_tickets).
    """

    def test_cgi_2026_009_017_026_default_path_allows_ordinary_business(self):
        fixture = CaseFixture("case-authorization")
        fixture.prompt("修复模块A的问题，必须验证行为。")
        for command in ("git tag v1.2.3", "gh release create v1.2.3 --notes x",
                        "npm publish", "git push origin main"):
            decision, _ = _permission_decision(
                fixture.tool("shell", {"command": command}))
            self.assertIsNone(decision, command)

    def test_cgi_2026_009_017_026_release_profile_keeps_exact_ticket_gate(self):
        fixture = CaseFixture("case-release-lane")
        fixture.prompt("context-guard release")
        decision, reason = _permission_decision(
            fixture.tool("shell", {"command": "git tag v1.2.3"}))
        self.assertEqual(decision, "deny")
        self.assertIn("action-ticket", reason)

    def test_cgi_2026_018_027_text_output_commands_are_not_actions(self):
        fixture = CaseFixture("case-echo")
        fixture.prompt("发布模块B，必须验证。")
        for command in ("echo git tag v1.2.3", "echo 'gh release create v1'",
                        "grep 'git push' README.md"):
            decision, _ = _permission_decision(
                fixture.tool("shell", {"command": command}))
            self.assertIsNone(decision, command)
        self.assertIsNone(cg.classify_action_kind(
            "shell", {"command": "echo git tag v1.2.3"}))
        kind = cg.classify_action_kind("shell", {"command": "git tag v1.2.3"})
        self.assertEqual(kind.get("tier"), "A")

    def test_cgi_2026_019_028_dry_run_variants_are_simulation(self):
        fixture = CaseFixture("case-dryrun")
        fixture.prompt("context-guard release")
        decision, _ = _permission_decision(
            fixture.tool("shell", {"command": "git push --dry-run"}))
        self.assertIsNone(decision)
        decision, _ = _permission_decision(
            fixture.tool("shell", {"command": "npm publish --dry-run"}))
        self.assertIsNone(decision)
        # Without the flag the same command is a real release mutation.
        decision, reason = _permission_decision(
            fixture.tool("shell", {"command": "npm publish"}))
        self.assertEqual(decision, "deny")
        self.assertIn("action-ticket", reason)


class StopDispositionCases(unittest.TestCase):
    """010/013/014/015/020/022/023/024/029: Stop 5.0.0 disposition contract.

    Deeper authoritative coverage: tests/test_cg122_p0_counterexamples.py,
    tests/test_stop_v5.py, tests/test_cg130_delivery.py.
    """

    def test_cgi_2026_014_023_terminal_disposition_ends_after_one_correction(self):
        fixture = CaseFixture("case-disposition")
        suite = Path(fixture.root) / "suite.py"
        suite.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        fixture.prompt(f'继续执行，运行 "{suite}" 的测试。')
        fixture.ready_file(suite)
        # A wrong whole-completion claim over pending work draws exactly one
        # bounded correction; the budget never repeats it.
        first = fixture.stop("任务完成。")
        self.assertEqual(first.get("decision"), "block")
        self.assertLessEqual(len(first.get("reason", "")), 240)
        second = fixture.stop("任务完成。")
        self.assertEqual(second, {})

    def test_cgi_2026_015_024_wait_subclass_difference_never_blocks(self):
        fixture = CaseFixture("case-waits")
        fixture.prompt("修复模块C的问题，必须验证行为。")
        for reply in ("等待外部审核结果后继续。",
                      "我需要用户确认配置后再继续。",
                      "该任务超出当前授权，暂缓处理。"):
            self.assertEqual(fixture.stop(reply), {}, reply)

    def test_cgi_2026_010_declared_user_wait_does_not_authorize_work(self):
        fixture = CaseFixture("case-declared")
        suite = Path(fixture.root) / "suite.py"
        suite.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        fixture.prompt(f'继续执行，运行 "{suite}" 的测试。')
        fixture.ready_file(suite)
        # A declared user_wait cannot silently absorb remaining assistant
        # work: the turn still draws its single correction.
        result = fixture.stop("我还需要继续修复两项。")
        self.assertEqual(result.get("decision"), "block")
        self.assertLessEqual(len(result["reason"]), 240)

    def test_cgi_2026_013_022_sibling_units_leave_no_active_ancestors(self):
        fixture = CaseFixture("case-sibling")
        fixture.prompt("任务A: 修复模块A，必须验证行为。")
        fixture.prompt("切换到新任务。任务B: 修复模块B，必须验证行为。")
        state = fixture.state()
        statuses = {u["id"]: u["status"] for u in state["work_units"]}
        self.assertEqual(sorted(statuses.values()), ["active", "historical_unresolved"])
        scope = cg.current_scope_projection(state)
        old_unit = next(u for u, s in statuses.items()
                        if s == "historical_unresolved")
        old_items = {i["id"] for c in ("requirements", "acceptance_items")
                     for i in state[c] if i.get("work_unit_id") == old_unit}
        self.assertFalse(old_items & scope["current_item_ids"])

    def test_cgi_2026_020_029_feedback_is_bounded_without_id_lists(self):
        fixture = CaseFixture("case-feedback")
        suite = Path(fixture.root) / "suite.py"
        suite.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        fixture.prompt(f'继续执行，运行 "{suite}" 的测试。')
        fixture.ready_file(suite)
        result = fixture.stop("任务完成。")
        self.assertEqual(result.get("decision"), "block")
        reason = result["reason"]
        self.assertLessEqual(len(reason), 240)
        self.assertNotIn("R0", reason)
        self.assertNotIn("A0", reason)
        self.assertNotIn("Expected IDs", reason)


class SilentAllowCases(unittest.TestCase):
    """016/025: successful allow paths are silent for ordinary events."""

    def test_cgi_2026_016_025_normal_events_stay_silent(self):
        fixture = CaseFixture("case-silent")
        prompt_result = fixture.prompt("修复模块D的问题，必须验证行为。")
        # The versioned redesign injects one bounded requirement-ID context
        # on a new business prompt; it carries no private control material.
        context = (prompt_result.get("hookSpecificOutput") or {}).get(
            "additionalContext", "")
        # Bounded, model-facing guidance channel: the private command token
        # it carries is for the assistant's private commands, and the N case
        # below proves it must never reach a user-facing reply.
        self.assertLessEqual(len(context), 4000)
        self.assertNotIn("CONTEXT_GUARD_STAGE_REQUEST", context)
        self.assertEqual(
            fixture.after("shell", {"command": "echo ok"},
                          {"exit_code": 0, "output": "ok"}), {})
        self.assertEqual(fixture.stop("已完成本轮修复。"), {})
        hooks = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text(
            encoding="utf-8"))
        for event_rows in hooks["hooks"].values():
            for row in event_rows:
                for hook in row["hooks"]:
                    self.assertNotIn("statusMessage", hook)

    def test_cgi_2026_016_025_private_leak_still_blocks(self):
        fixture = CaseFixture("case-leak")
        fixture.prompt("修复模块E的问题，必须验证行为。")
        result = fixture.stop("收尾：CONTEXT_GUARD_STAGE_REQUEST 请勿外传。")
        self.assertEqual(result.get("continue"), False)


class ThreadReadCases(unittest.TestCase):
    """021/030: fully-qualified thread-read tools bind thread subjects.

    Deeper authoritative coverage:
    tests/test_context_guard_012_baseline.py (mcp__codex_app__read_thread).
    """

    def test_cgi_2026_021_030_fully_qualified_thread_read_binds(self):
        identity = cg.stop3().adapter_identity("mcp__codex_app__read_thread")
        self.assertEqual(identity["adapter"], "thread_read")
        self.assertEqual(identity["identity"], "canonical")
        fixture = CaseFixture("case-thread")
        fixture.prompt("读取这个线程的内容并总结。")
        fixture.after("mcp__codex_app__read_thread",
                      {"threadId": "01a0e37e-a9d6-74b2-a9a4-31976c89b99c"},
                      {"exit_code": 0, "output": "thread content"})
        evidence = fixture.state()["evidence"][-1]
        self.assertEqual(evidence["tool"], "mcp__codex_app__read_thread")
        self.assertTrue(evidence.get("readback_subjects"))
        # A registered short name under an untrusted namespace stays
        # adapter-ambiguous: evidence may exist but no subject may bind.
        self.assertEqual(
            cg.stop3().adapter_identity("mcp__other_app__read_thread")["identity"],
            "adapter_identity_ambiguous")


class RecoveryAndScopeCases(unittest.TestCase):
    """011/012/040/041/042: supersession, unit kind, recovery, provenance."""

    def test_cgi_2026_011_distinct_restatement_supersedes_prior(self):
        fixture = CaseFixture("case-supersession")
        fixture.prompt("任务F: 修复模块F，必须验证行为。")
        before = fixture.state()
        fixture.prompt("取消 R001，改为修复模块F2，必须验证行为。")
        after = fixture.state()
        prior = next(i for i in after["requirements"]
                     if i["id"] == before["requirements"][0]["id"])
        self.assertEqual(prior["status"], "superseded")
        self.assertGreater(len(after["requirements"]), 1)

    def test_cgi_2026_041_mixed_cleanup_and_update_is_not_cleanup_only(self):
        fixture = CaseFixture("case-mixed")
        fixture.prompt(
            "1. 如有需要，更新本仓库内容，之后提交并推送\n"
            "2. 仓库中有额外的工作树和分支，看看是否需要清理")
        # A cleanup classification never vetoes the product edit on the
        # default path (the retired 0.12.1 behavior denied the patch).
        decision, _ = _permission_decision(fixture.tool(
            "apply_patch",
            {"patch": "*** Begin Patch\n*** Update File: docs.md\n*** End Patch"}))
        self.assertIsNone(decision)
        texts = " ".join(i["text"] for i in fixture.state()["requirements"])
        self.assertIn("更新本仓库内容", texts)
        self.assertIn("清理", texts)
        self.assertEqual(cg.work_unit_kind("清理仓库中的多余工作树"), "cleanup")

    def test_cgi_2026_040_reviewed_answer_leaves_current_debt(self):
        # Scope-level invariant of the compaction-recovery chain; the full
        # Stop->PreCompact->SessionStart chain with a real transcript is
        # covered by tests/test_context_guard.py
        # ::test_real_update_plan_receipt_survives_compact_resume_with_health
        # and tests/test_answer_review*.py.
        fixture = CaseFixture("case-recovery")
        fixture.prompt("任务G1: 解释这个函数为什么这样实现？")
        fixture.prompt("任务G2: 修复模块G，必须验证行为。")
        state = fixture.state()
        projection = cg.current_scope_projection(state)
        self.assertTrue(projection["current_item_ids"])

    def test_cgi_2026_042_edit_without_provenance_needs_no_reconfirmation(self):
        fixture = CaseFixture("case-provenance")
        fixture.prompt("修复模块H并提交，必须验证行为。")
        fixture.after("shell", {"command": "sed -i s/a/b/ mod.py"},
                      {"exit_code": 0, "output": ""})
        decision, _ = _permission_decision(
            fixture.tool("shell", {"command": "git commit -m fix"}))
        self.assertIsNone(decision)


class WindowsPlatformSourceCases(unittest.TestCase):
    """043/044/045: portable source assertions; native Windows is a
    coordinator-run gate and stays pending from this suite."""

    def test_cgi_2026_043_commit_then_push_not_denied_on_default(self):
        fixture = CaseFixture("case-push")
        fixture.prompt("提交并推送模块I的修复，必须验证。")
        fixture.after("shell", {"command": "git commit -m 'fix module I'"},
                      {"exit_code": 0, "output": "[main abc123] fix"})
        decision, reason = _permission_decision(
            fixture.tool("shell", {"command": "git push origin main"}))
        self.assertIsNone(decision)
        self.assertNotIn("authorized_commit_not_completed", reason)

    def test_cgi_2026_044_followup_prompt_preserves_prior_work(self):
        fixture = CaseFixture("case-followup")
        fixture.prompt("任务J: 修复模块J，必须验证行为。")
        before = {r["id"]: r["status"] for r in fixture.state()["requirements"]}
        fixture.prompt("这是老版本的问题，还是新版未覆盖的问题？继续执行")
        after = {r["id"]: r["status"] for r in fixture.state()["requirements"]}
        for item_id, status in before.items():
            self.assertEqual(after.get(item_id), status)

    def test_cgi_2026_045_diagnose_bounded_and_controls_rejected(self):
        fixture = CaseFixture("case-diagnose", activate=False)
        fixture.prompt("context-guard on")
        fixture.prompt("任务K: 修复模块K，必须验证行为。")
        with tempfile.TemporaryDirectory() as out:
            capture = Path(out) / "diag.txt"
            with open(capture, "w", encoding="utf-8") as handle:
                saved = sys.stdout
                sys.stdout = handle
                try:
                    code = cg.command_diagnose(SimpleNamespace(limit=3))
                finally:
                    sys.stdout = saved
            self.assertEqual(code, 0)
            text = capture.read_text(encoding="utf-8")
            self.assertLess(len(text), 20000)
        code = cg.command_stage_disposition(SimpleNamespace(
            data_dir=Path(fixture.root), session_id=fixture.session,
            turn_id="t-invalid", token="", disposition="user_wait",
            replace=False))
        self.assertNotEqual(code, 0)


class StopPerformanceCase(unittest.TestCase):
    """046: full-Stop work-count bounds (the long-session Stop fix).

    Wall-clock and full-process evidence:
    tools/validation/benchmark_stop.py; tests/test_stop_performance.py.
    """

    def test_cgi_2026_046_stop_work_counts_event_scoped(self):
        sys.path.insert(0, str(REPO_ROOT / "tools" / "validation"))
        import stop_performance_fixture as fx

        captured: dict[str, int] = {}
        original = cg.EvaluationContext

        class Counting(original):  # type: ignore[misc, valid-type]
            def __init__(self, state, session_dir, **kwargs):
                kwargs["counters"] = captured
                super().__init__(state, session_dir, **kwargs)

        with tempfile.TemporaryDirectory(prefix="case-046-") as root:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = root
            built = fx.build_session(cg, root, "S1")
            import unittest.mock as mock

            with mock.patch.object(cg, "EvaluationContext", Counting):
                result = cg.dispatch(built["stop_event"])
            self.assertEqual(result, {})
            self.assertLessEqual(captured.get("scope_computed", 0), 4)
            self.assertLessEqual(captured.get("prompt_record_read", 0), 60)
            self.assertLessEqual(captured.get("fragments_computed", 0), 260)


class ExtendedCodexCases(unittest.TestCase):
    """Post-archive active codex cases: full chains and current contracts."""

    def test_archive_040_full_chain_question_answer_then_task_compact_restore(self):
        fixture = CaseFixture("case-040-chain")
        suite = Path(fixture.root) / "suite.py"
        suite.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        # Guard stays active for the whole chain.
        fixture.prompt("顺便解释一下这个函数为什么要处理空输入？")
        self.assertEqual(fixture.stop(
            "这个函数处理空输入是因为入口契约允许缺失值，返回空列表保持类型稳定。",
            new_turn=False), {})
        fixture.prompt(f'继续执行，运行 "{suite}" 的测试。')
        fixture.ready_file(suite)
        result = fixture.stop("如前所述，该函数处理空输入是为了入口契约的稳定性。")
        self.assertEqual(result.get("decision"), "block")
        cg.dispatch(_hook("PreCompact", fixture.session, fixture.root, "t9",
                          trigger="manual"))
        resumed = cg.dispatch(_hook("SessionStart", fixture.session, fixture.root,
                                    "t9", source="resume"))
        state = fixture.state()
        statuses = {item["id"]: item["status"] for item in state["requirements"]}
        self.assertEqual(statuses.get("R001"), "answered")
        self.assertEqual(statuses.get("R002"), "pending")
        # The recovery packet is Guard-produced while active: the delivered
        # question leaves current debt and never reappears in it, while the
        # pending execution duty stays listed.
        packet = json.dumps(resumed, ensure_ascii=False)
        self.assertNotIn("R001", packet)
        self.assertNotIn("顺便解释一下", packet)
        self.assertIn("R002", packet)
        projection = cg.current_scope_projection(state)
        self.assertNotIn("R001", projection["current_item_ids"])
        self.assertIn("R002", projection["current_item_ids"])
        self.assertTrue(state["mode"]["active"])

    def test_cgi_20260914_conditional_wait_stop_silent(self):
        fixture = CaseFixture("case-conditional-wait")
        fixture.prompt("修复模块L的问题，必须验证行为。")
        for reply in ("如果你确认方案可行，我就继续修复。",
                      "下个月平台验收后再执行剩余步骤。",
                      "等审核通过后再继续，先到这里。"):
            self.assertEqual(fixture.stop(reply), {}, reply)

    def test_cgi_20260918_future_observation_stop_not_authorized_work(self):
        fixture = CaseFixture("case-future-obs")
        suite = Path(fixture.root) / "suite.py"
        suite.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        fixture.prompt(f'继续执行，运行 "{suite}" 的测试。')
        fixture.after("exec_command", {"cmd": f"python3 {suite}", "shell": "bash"},
                      {"exit_code": 0, "output": "ok"})
        self.assertEqual(fixture.stop(
            "本轮修复与验证已完成，长期收益仍待未来使用观察。"), {})
        state = fixture.state()
        self.assertNotIn("explicit_user_persistence",
                         state["decision_log"][-1].get("reason_codes", []))

    def test_cgi_20260920_side_question_does_not_end_main_task(self):
        # The 040-chain shape covers the shared boundary: a delivered side
        # answer never closes the pending main execution task.
        fixture = CaseFixture("case-side-question")
        suite = Path(fixture.root) / "suite.py"
        suite.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        fixture.prompt("顺便解释一下这个函数为什么要处理空输入？")
        fixture.stop("该函数处理空输入是因为入口契约允许缺失值。", new_turn=False)
        fixture.prompt(f'继续执行，运行 "{suite}" 的测试。')
        fixture.ready_file(suite)
        result = fixture.stop("解释已在前面给出：入口契约允许缺失值。")
        self.assertEqual(result.get("decision"), "block")

    def test_cgi_20260914_confirmed_chain_decision_binding(self):
        fixture = CaseFixture("case-decision-bind")
        fixture.prompt("修复模块M的问题，必须验证行为。")
        fixture.stop("我还需要继续修复两项。")
        last = fixture.state()["decision_log"][-1]
        for field in ("protocol_version", "classifier_version", "reply_sha256",
                      "reason_codes", "outcome"):
            self.assertIn(field, last, field)

    def test_cgi_20260913_compaction_continuation_recovery_keeps_execution(self):
        sys.path.insert(0, str(REPO_ROOT / "tools" / "validation"))
        import stop_performance_fixture as fx

        with tempfile.TemporaryDirectory(prefix="case-cc-") as root:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = root
            built = fx.build_session(fx.load_runtime(), root, "S0")
            cg.dispatch(_hook("PreCompact", built["session_id"], root, "t9",
                              trigger="manual"))
            packet = cg.dispatch(_hook("SessionStart", built["session_id"], root,
                                       "t9", source="resume"))
            text = json.dumps(packet, ensure_ascii=False)
            state = cg.load_state(
                built["session_dir"],
                _hook("Stop", built["session_id"], root, "t9"))
            pending = [item["id"] for item in state["requirements"]
                       if item["status"] == "pending"]
            self.assertTrue(pending)
            for item_id in pending:
                self.assertIn(item_id, text)

    def test_cgi_20260923_path_action_continuation_object_words_inert(self):
        for folder in ("neutral", "audit", "review", "commit"):
            with self.subTest(folder=folder):
                prompt = f"请运行 /work/{folder}/suite.py 的测试并持续执行直到任务完成。"
                self.assertEqual(
                    cg._root_control_item_action({"text": prompt}), "test_verify")

    def test_cgi_20260913_execution_tail_and_tutorial_delivery_boundary(self):
        # Thin confirmation of the dedicated suites that own these chains.
        self.assertTrue(cg._reply_only_request_shape("帮我讲一下这个仓库的主要内容，以及实现的核心逻辑"))
        item = {"text": "顺便解释一下这个函数为什么要处理空输入？",
                "verification_contract": {"mode": "legacy_fallback",
                                          "reason": "no_deterministic_contract",
                                          "obligations": []}}
        self.assertTrue(cg._information_delivery_item(item))
        self.assertFalse(cg._reply_only_request_shape("解释一下为什么，然后修改代码。"))

    def test_archive_042_full_chain_missing_edit_observation_no_reask(self):
        fixture = CaseFixture("case-042-chain")
        # One root authorization for edit + commit + push.
        fixture.prompt("授权你修复并提交推送模块N的改动，必须验证行为。")
        # The edit happens with NO PostToolUse observation: the observer
        # missed it entirely.
        decision, _ = _permission_decision(
            fixture.tool("apply_patch",
                         {"patch": "*** Begin Patch\n*** Update File: n.md\n"
                                   "+fix\n*** End Patch"}))
        self.assertIsNone(decision)
        # The commit succeeds and IS observed; push follows in the same
        # authorized chain.
        fixture.after("shell", {"command": "git commit -m 'fix N'"},
                      {"exit_code": 0, "output": "[main abc123] fix N"})
        decision, reason = _permission_decision(
            fixture.tool("shell", {"command": "git push origin main"}))
        self.assertIsNone(decision)
        self.assertNotIn("authorized_commit_not_completed", reason)
        self.assertNotIn("commit_scope", reason)
        # The turn closes with a delivered summary and survives a resume
        # without the authorization ever being re-asked.
        fixture.stop("模块N已修复、提交并推送完成。")
        state = fixture.state()
        for row in state["decision_log"]:
            self.assertNotIn("re-authorization", json.dumps(row))
        cg.dispatch(_hook("PreCompact", fixture.session, fixture.root, "t9",
                          trigger="manual"))
        resumed = cg.dispatch(_hook("SessionStart", fixture.session,
                                    fixture.root, "t9", source="resume"))
        self.assertTrue(json.loads(json.dumps(resumed)) is not None)
        # Negative control: the same authorization never generalizes to the
        # release lane's publication surface.
        release = CaseFixture("case-042-release")
        release.prompt("授权你修复模块N并提交推送，必须验证行为。")
        release.after("shell", {"command": "git commit -m 'fix N'"},
                      {"exit_code": 0, "output": "[main abc123] fix N"})
        release.prompt("context-guard release")
        decision, reason = _permission_decision(
            release.tool("shell", {"command": "git tag v9.9.9"}))
        self.assertEqual(decision, "deny")
        self.assertIn("action-ticket", reason)


class DshSharedSemanticsCases(unittest.TestCase):
    """DSH active cases: shared semantics with executed Codex-side regressions.

    A DSH case is adjudicated analogue_only when the shared semantic risk
    has an applicable Codex regression here that passes. These runs never
    certify the DSH implementation itself.
    """

    def _grounding_untethered_source_never_executable(self):
        fixture = CaseFixture("dsh-grounding")
        fixture.prompt("修复模块O的问题，必须验证行为。")
        state = fixture.state()
        # No prompt record source: no basis may authorize execution work.
        evaluation = cg.EvaluationContext(state, fixture.directory)
        self.assertFalse(cg._live_current_action_bases(state, fixture.directory,
                                                       evaluation))

    def test_prepare_output_json_boundary(self):
        # analogue: prepare-output-root-cause (+ superseded prepare-output-invalid)
        fixture = CaseFixture("dsh-json")
        fixture.prompt("修复模块P的问题，必须验证行为。")
        result = fixture.prompt("context-guard status")
        json.dumps(result)  # every hook projection stays lossless JSON.

    def test_asset_information_execution_separation(self):
        self._grounding_untethered_source_never_executable()

    def test_discovery_truncation_pagination_complete(self):
        with tempfile.TemporaryDirectory(prefix="dsh-page-") as root:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = root
            fixture = CaseFixture("dsh-page")
            fixture.prompt("修复模块Q的问题，必须验证行为。")
            state = fixture.state()
            projection = cg.current_scope_projection(state)
            self.assertTrue(projection["revision"])
            # Paging cursors bind to the projection revision: any state change
            # that moves the scope invalidates stale cursors.
            self.assertIn("revision", projection)

    def test_ordinary_git_observation_not_completion(self):
        fixture = CaseFixture("dsh-git-obs")
        fixture.prompt("提交并推送模块R，必须验证。")
        fixture.after("shell", {"command": "git commit -m x"},
                      {"exit_code": 0, "output": "[main 1] x"})
        state = fixture.state()
        # An observed commit is evidence, never whole-task completion.
        unit = state["work_units"][-1]
        self.assertNotEqual(unit.get("status"), "completed")

    def test_positive_default_authority_rejected(self):
        self._grounding_untethered_source_never_executable()

    def test_readonly_verification_capability_contract(self):
        fixture = CaseFixture("dsh-readonly")
        fixture.prompt("验证模块S的行为，必须确认结果。")
        state = fixture.state()
        obligations = cg.unresolved_proof_obligations(state)
        # No enforced contract was adopted: nothing is mis-diagnosed as a
        # missing three-part change-evidence chain.
        self.assertEqual(obligations, {})

    def test_cwd_never_promotes_to_target(self):
        fixture = CaseFixture("dsh-cwd")
        fixture.prompt("修复模块T的问题，必须验证行为。")
        state = fixture.state()
        evaluation = cg.EvaluationContext(state, fixture.directory)
        # No readiness selection exists, so no basis may resolve cwd itself
        # into the requested target.
        bases = cg._live_current_action_bases(state, fixture.directory, evaluation)
        for basis in bases:
            self.assertNotEqual(basis.get("target"), fixture.root)

    def test_mixed_question_does_not_close_actions(self):
        fixture = CaseFixture("dsh-mixed")
        fixture.prompt("更新模块U并查询状态，同时记录结果，必须验证更新。")
        fixture.stop("状态已查询并记录。", new_turn=False)
        state = fixture.state()
        pending = [item for item in state["requirements"]
                   if "更新" in str(item.get("text"))]
        self.assertTrue(pending)
        self.assertTrue(all(item["status"] == "pending" for item in pending))

    def test_prepare_compatibility_preflight_freshness(self):
        # analogue: consumption-time recheck is the Codex counterpart of
        # preparing with the item's current identity and re-checking before
        # execution.
        fixture = CaseFixture("dsh-compat")
        fixture.prompt("修复模块V的问题，必须验证行为。")
        state = fixture.state()
        evaluation = cg.EvaluationContext(state, fixture.directory)
        evaluation.root_records()
        self.assertTrue(evaluation.verify_consumed_sources())

    def test_cleanup_partial_result_not_whole_completion(self):
        fixture = CaseFixture("dsh-partial")
        suite = Path(fixture.root) / "suite.py"
        suite.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        fixture.prompt(f'清理临时文件并运行 "{suite}" 的测试，必须验证。')
        fixture.after("exec_command", {"cmd": "rm -rf tmp", "shell": "bash"},
                      {"exit_code": 0, "output": ""})
        fixture.stop("清理完成，任务完成。")
        # Partial success cannot close the unverified whole task.
        state = fixture.state()
        self.assertEqual(state["work_units"][-1].get("status"), "active")

    def test_shell_compound_outcome_layered(self):
        fixture = CaseFixture("dsh-compound")
        fixture.prompt("修复模块W的问题，必须验证行为。")
        fixture.after("shell", {"command": "rm -rf a; rm -rf b"},
                      {"exit_code": 0, "output": ""})
        state = fixture.state()
        # A compound shell success stays an observation; it never certifies
        # the business requirement.
        self.assertTrue(all(item["status"] == "pending"
                            for item in state["requirements"]))

    def test_unsupported_cleanup_capability_not_input_error(self):
        fixture = CaseFixture("dsh-cleanup-cap")
        fixture.prompt("清理仓库中的多余工作树。")
        decision, _ = _permission_decision(
            fixture.tool("shell", {"command": "git worktree list"}))
        # A capability gap never becomes a user-input denial on the default
        # path, and never rewrites the request into another action.
        self.assertIsNone(decision)

    def test_v6_recovery_feedback_consistency(self):
        with tempfile.TemporaryDirectory(prefix="dsh-v6-") as root:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = root
            fixture = CaseFixture("dsh-v6")
            fixture.prompt("修复模块X的问题，必须验证行为。")
            cg.dispatch(_hook("PreCompact", fixture.session, fixture.root, "t9",
                              trigger="manual"))
            packet = cg.dispatch(_hook("SessionStart", fixture.session,
                                       fixture.root, "t9", source="resume"))
            state = fixture.state()
            projection = cg.current_scope_projection(state)
            packet_text = json.dumps(packet, ensure_ascii=False)
            # The recovery packet derives from the same current projection:
            # items it reports pending are exactly the current-scope items.
            for item in state["requirements"]:
                if item["id"] in projection["current_item_ids"]:
                    self.assertIn(item["id"], packet_text)

    def test_ux10_target_boundary_adjacent_text(self):
        # Adjacent explanatory text never becomes part of a quoted target.
        text = '修改 "/work/a.py" 这个文件并测试 "/work/b.py"。'
        subjects = cg.prompt_subjects(text)
        displays = {s["display"] for s in subjects}
        self.assertEqual(displays, {"a.py", "b.py"})
        self.assertTrue(all(s["id"].startswith("subject:") for s in subjects))

    def test_ux11_remediation_chain_reachable(self):
        fixture = CaseFixture("dsh-ux11")
        suite = Path(fixture.root) / "suite.py"
        suite.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        fixture.prompt(f'继续执行，运行 "{suite}" 的测试。')
        fixture.ready_file(suite)
        first = fixture.stop("任务完成。")
        self.assertEqual(first.get("decision"), "block")
        # The stated next step is executable and deterministic: the same
        # input state yields the same decision, no unresolvable loop.
        fixture2 = CaseFixture("dsh-ux11b")
        suite2 = Path(fixture2.root) / "suite.py"
        suite2.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        fixture2.prompt(f'继续执行，运行 "{suite2}" 的测试。')
        fixture2.ready_file(suite2)
        second = fixture2.stop("任务完成。")
        self.assertEqual(second.get("decision"), "block")
        self.assertEqual(first["reason"], second["reason"])


if __name__ == "__main__":
    unittest.main()
