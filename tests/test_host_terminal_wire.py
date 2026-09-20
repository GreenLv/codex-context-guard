"""Real-shape Host terminal records paired with string PostToolUse responses."""

import hashlib
import json
import os
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import context_guard as cg


class HostTerminalWireTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cg-host-wire-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(strict=True)
        self.home = self.root / "home"
        self.transcript = self.home / "sessions/2026/09/20/rollout-fixture.jsonl"
        self.transcript.parent.mkdir(parents=True)
        self.cwd = self.root / "work"
        self.cwd.mkdir()
        self.cwd = self.cwd.resolve(strict=True)
        self.session_id = "host-wire-fixture"
        self.turn_id = "turn-current"
        self.rows = [self.record("session_meta", {
            "id": self.session_id, "session_id": self.session_id})]
        self.write_rows()
        patch = mock.patch.dict(os.environ, {
            "CODEX_HOME": str(self.home),
            "CONTEXT_GUARD_DATA_DIR": str(self.root / "private"),
        })
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def record(kind, payload):
        return {"type": kind, "payload": payload}

    def write_rows(self):
        self.transcript.write_bytes(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in self.rows).encode("utf-8")
        )

    @staticmethod
    def write_file(path, content):
        # The claimed Host content/stdout uses exact UTF-8 bytes. Text-mode
        # writes would silently turn LF into CRLF on Windows.
        path.write_bytes(content.encode("utf-8"))

    @staticmethod
    def root_target(path):
        # A quoted drive locator binds the entire Windows source token.
        return f'"{path}"' if os.name == "nt" else str(path)

    def event(self, kind, **extra):
        return {"hook_event_name": kind, "session_id": self.session_id,
                "turn_id": self.turn_id, "cwd": str(self.cwd),
                "transcript_path": str(self.transcript), **extra}

    def start(self, root):
        cg.dispatch(self.event("UserPromptSubmit", prompt="context-guard on"))
        cg.dispatch(self.event("UserPromptSubmit", prompt=root))

    def completed(self, call_id, item, *, turn=None, thread=None):
        self.rows.append(self.record("event_msg", {
            "type": "item_completed", "thread_id": thread or self.session_id,
            "turn_id": turn or self.turn_id, "item": {"id": call_id, **item},
        }))
        self.write_rows()

    def command(self, call_id, command, *, code=0, stdout="", response="done", **overrides):
        invocation = (["pwsh.exe", "-Command", command] if os.name == "nt"
                      else ["/bin/zsh", "-lc", command])
        item = {"type": "CommandExecution", "status": "completed" if code == 0 else "failed",
                "exit_code": code, "command": invocation,
                "parsed_cmd": [{"type": "unknown", "cmd": command}],
                "cwd": self.cwd.as_uri(), "stdout": stdout}
        item.update(overrides)
        self.completed(call_id, item)
        cg.dispatch(self.event("PostToolUse", tool_name="Bash", tool_use_id=call_id,
                               tool_input={"command": command}, tool_response=response))

    def readback(self, call_id, target, stdout):
        if os.name == "nt":
            self.assertNotIn("'", str(target))
            command = ("[System.Console]::Write([System.IO.File]::ReadAllText("
                       f"'{target}'))")
        else:
            command = f"cat {shlex.quote(str(target))}"
        self.command(call_id, command, stdout=stdout)

    def patch(self, call_id, target, before, after, *, response="patch applied",
              status="completed"):
        source = (f"*** Begin Patch\n*** Update File: {target.name}\n@@\n"
                  f"-{before.rstrip()}\n+{after.rstrip()}\n*** End Patch\n")
        self.write_file(target, after)
        self.completed(call_id, {"type": "FileChange", "status": status,
                                 "changes": {str(target): {"type": "update",
                                                           "unified_diff": f"@@ -1 +1 @@\n-{before.rstrip()}\n+{after.rstrip()}\n",
                                                           "move_path": None}},
                                 "stdout": "", "stderr": ""})
        cg.dispatch(self.event("PostToolUse", tool_name="apply_patch", tool_use_id=call_id,
                               tool_input={"command": source}, tool_response=response))

    def state(self):
        return cg.load_state(self.root / "private/sessions" / self.session_id,
                             self.event("Stop"))

    def test_real_wire_edit_test_readback_can_close_combined_root(self):
        target = self.cwd / "module.py"
        before = "def test_value(): assert False\n"
        after = "def test_value(): assert True\n"
        self.write_file(target, before)
        locator = self.root_target(target)
        root = f"请修改 {locator}，并运行 {locator} 的测试。"
        self.start(root)
        self.readback("read-before", target, before)
        self.patch("patch", target, before, after)
        self.readback("read-after", target, after)
        self.command("focused-test", f"pytest {target}", stdout="1 passed\n")
        result = cg.dispatch(self.event("Stop", last_assistant_message="修改和测试已完成。"))
        decision = self.state()["decision_log"][-1]
        aggregate = next(row for row in decision["core_projections"]
                         if row["predicate"] == "edit_and_test")
        self.assertEqual(result, {})
        self.assertTrue(aggregate["certifiable"])
        self.assertEqual(aggregate["unknown_coverage_count"], 0)
        self.assertEqual({e.get("outcome_basis") for e in self.state()["evidence"]},
                         {"host_transcript_exit_code", "host_transcript_file_change"})

    def test_real_wire_update_then_independent_readback_needs_no_pre_read(self):
        target = self.cwd / "module.py"
        before = "before\n"
        after = "after\n"
        self.write_file(target, before)
        self.start(f"请修改 {self.root_target(target)}，并核对改动后的文件。")
        self.patch("patch", target, before, after)
        self.readback("read-after", target, after)
        cg.dispatch(self.event("Stop", last_assistant_message="文件已经修改并核对。"))
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["predicate_state"], "satisfied")
        self.assertEqual(rows[0]["unknown_coverage_count"], 0)
        self.assertTrue(rows[0]["certifiable"])

    def test_direct_quoted_filesystem_object_with_space_can_close(self):
        target = self.cwd / "A File.ts"
        self.write_file(target, "before\n")
        self.start(f'请修改 "{target}"，并核对改动后的文件。')
        self.patch("quoted-patch", target, "before\n", "after\n")
        self.readback("quoted-read", target, "after\n")
        cg.dispatch(self.event("Stop", last_assistant_message="已修改并核对文件。"))
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target_sha256"],
                         hashlib.sha256(str(target).encode()).hexdigest())
        self.assertTrue(rows[0]["certifiable"])

    def test_quoted_same_file_edit_and_test_remain_distinct(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        locator = f'"{target}"'
        self.start(f"请修改 {locator}，并运行 {locator} 的测试。")
        self.patch("quoted-patch", target, "before\n", "after\n")
        self.readback("quoted-read", target, "after\n")
        self.command("quoted-test", f"pytest {locator}", stdout="1 passed\n")
        cg.dispatch(self.event("Stop", last_assistant_message="修改和测试已完成。"))
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertEqual({row["predicate"] for row in rows},
                         {"state_matches", "test_passed", "edit_and_test"})
        self.assertTrue(all(row["predicate_state"] == "satisfied" for row in rows))
        self.assertTrue(next(row for row in rows
                             if row["predicate"] == "edit_and_test")["certifiable"])

    def test_quoted_statement_report_and_negation_do_not_become_edit(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        for index, root in enumerate((
            f'"修改 {target}。"',
            f'日志写着："修改 {target}。"',
            f'不要修改 "{target}"。',
        )):
            with self.subTest(root=root):
                with mock.patch.object(self, "session_id", f"quoted-negative-{index}"):
                    self.rows = [self.record("session_meta", {
                        "id": self.session_id, "session_id": self.session_id})]
                    self.write_rows()
                    self.start(root)
                    self.command("ready", f"test -f {shlex.quote(str(target))}")
                    cg.dispatch(self.event("Stop", last_assistant_message="文件尚未修改。"))
                    decision = self.state()["decision_log"][-1]
                    self.assertFalse(any(a.get("category") == "local_edit"
                                         and a.get("actionability") == "current_ready"
                                         for a in decision["actions"]))
                    self.assertEqual(decision["core_projections"], [])

    def test_frozen_projection_does_not_reread_later_disk_bytes(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {self.root_target(target)}，并核对改动后的文件。")
        self.patch("patch", target, "before\n", "after\n")
        self.readback("read-after", target, "after\n")
        state = self.state()
        session_dir = self.root / "private/sessions" / self.session_id
        before_projection = cg.current_core_projections(state, session_dir)
        self.assertTrue(before_projection[0]["certifiable"])
        # No new Host event or event watermark: a later filesystem change is
        # outside this immutable as-of projection. A fresh observed readback
        # would need its own event and could then invalidate the old result.
        self.write_file(target, "changed-without-host-event\n")
        after_projection = cg.current_core_projections(state, session_dir)
        self.assertEqual(after_projection, before_projection)

    def test_prior_root_edit_and_readback_do_not_close_new_root_edit(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        locator = self.root_target(target)
        self.start(f"请修改 {locator}，并核对改动后的文件。")
        self.patch("first-patch", target, "before\n", "after\n")
        self.readback("first-read", target, "after\n")
        cg.dispatch(self.event("UserPromptSubmit", prompt=f"请修改 {locator}，并核对改动后的文件。"))
        state = self.state()
        session_dir = self.root / "private/sessions" / self.session_id
        roots = {p["id"]: cg.read_prompt_record(session_dir, p)
                 for p in state["prompts"] if p.get("origin", "human") == "human"}
        from cg_codex_core_adapter import project_current_action
        item = state["requirements"][-1]
        self.assertIn(item["id"], cg.current_scope_projection(state)["scoped_item_ids"])
        root = roots[item["prompt_id"]]
        projection = project_current_action(
            state, roots, item=item, action="local_edit", target=str(target),
            turn=self.turn_id, root_scope=root["text"])
        self.assertNotEqual(projection["predicates"].get(item["id"]), "satisfied")

    def test_real_wire_update_without_current_readback_is_evidence_insufficient(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {self.root_target(target)}，并核对改动后的文件。")
        self.patch("patch", target, "before\n", "after\n")
        cg.dispatch(self.event("UserPromptSubmit", prompt="继续。"))
        cg.dispatch(self.event("Stop", last_assistant_message="修改已经执行，状态尚未核验。"))
        decision = self.state()["decision_log"][-1]
        self.assertFalse(any(a.get("category") == "local_edit"
                             and a.get("actionability") == "current_ready"
                             for a in decision["actions"]))
        self.assertFalse(any(row["certifiable"] for row in decision["core_projections"]))

    def test_real_wire_later_update_invalidates_prior_edit_readback(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {self.root_target(target)}，并核对改动后的文件。")
        self.patch("patch-one", target, "before\n", "after\n")
        self.readback("read-after-one", target, "after\n")
        self.patch("patch-two", target, "after\n", "changed-again\n")
        cg.dispatch(self.event("Stop", last_assistant_message="之前已核对。"))
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertTrue(rows)
        self.assertFalse(any(row["certifiable"] for row in rows))

    def test_real_wire_wrong_target_readback_does_not_close_edit(self):
        target = self.cwd / "module.py"
        other = self.cwd / "other.py"
        self.write_file(target, "before\n")
        self.write_file(other, "other\n")
        self.start(f"请修改 {self.root_target(target)}，并核对改动后的文件。")
        self.patch("patch", target, "before\n", "after\n")
        self.readback("wrong-read", other, "other\n")
        cg.dispatch(self.event("Stop", last_assistant_message="已经核对。"))
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertFalse(any(row["certifiable"] for row in rows))

    def test_mixed_root_unknown_does_not_reopen_observed_edit_on_resume(self):
        target = self.cwd / "suite.py"
        self.write_file(target, "before\n")
        locator = self.root_target(target)
        self.start(
            f"请只修复 {locator} 中多余的一行。"
            f"请把编辑、测试和回读分成独立宿主调用：编辑 {locator}，"
            f"运行 pytest {locator}，再回读 {locator}。"
            "长期收益留待以后观察，不作为本轮任务。"
        )
        self.patch("patch", target, "before\n", "after\n")
        self.command("test", f"pytest {target}", stdout="1 passed\n")
        self.readback("read-after", target, "after\n")
        cg.dispatch(self.event("Stop", last_assistant_message="本轮工具已执行。"))
        cg.dispatch(self.event("UserPromptSubmit", prompt="继续。"))
        cg.dispatch(self.event("Stop", last_assistant_message="当前结果已报告。"))
        decision = self.state()["decision_log"][-1]
        self.assertFalse(any(a.get("category") == "local_edit"
                             and a.get("actionability") == "current_ready"
                             for a in decision["actions"]))
        self.assertFalse(any(row["certifiable"] for row in decision["core_projections"]))

    def test_unperformed_ready_edit_remains_a_concrete_action(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {self.root_target(target)}。")
        self.readback("read-before", target, "before\n")
        cg.dispatch(self.event("UserPromptSubmit", prompt="继续。"))
        cg.dispatch(self.event("Stop", last_assistant_message="尚未修改文件。"))
        self.assertTrue(any(a.get("category") == "local_edit"
                            and a.get("actionability") == "current_ready"
                            for a in self.state()["decision_log"][-1]["actions"]))

    def test_observed_edit_with_conflicting_poststate_is_not_ready_reedit(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {self.root_target(target)}。")
        self.patch("patch", target, "before\n", "after\n")
        # The later independent readback is truthful but no longer names the
        # postimage attached to the verified FileChange. It cannot certify a
        # change or turn the missing proof into permission to redo the edit.
        self.write_file(target, "changed-outside-host\n")
        self.readback("changed-read", target, "changed-outside-host\n")
        cg.dispatch(self.event("UserPromptSubmit", prompt="继续。"))
        cg.dispatch(self.event("Stop", last_assistant_message="修改后的状态仍需核验。"))
        decision = self.state()["decision_log"][-1]
        self.assertFalse(any(a.get("category") == "local_edit"
                             and a.get("actionability") == "current_ready"
                             for a in decision["actions"]))
        self.assertFalse(any(row["certifiable"] for row in decision["core_projections"]))

    def test_failed_host_edit_and_truncated_readback_never_close(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {self.root_target(target)}，并核对改动后的文件。")
        self.patch("failed-patch", target, "before\n", "after\n", status="failed")
        self.readback("after-failure", target, "after\n")
        cg.dispatch(self.event("Stop", last_assistant_message="状态仍不确定。"))
        self.assertFalse(any(row["certifiable"] for row in
                             self.state()["decision_log"][-1]["core_projections"]))

        self.patch("successful-patch", target, "after\n", "new-content\n")
        self.command("truncated-read", f"cat {target}", stdout="new-content")
        cg.dispatch(self.event("Stop", last_assistant_message="回读不完整。"))
        self.assertFalse(any(row["certifiable"] for row in
                             self.state()["decision_log"][-1]["core_projections"]))

    def test_later_readback_never_backfills_earlier_stop(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {self.root_target(target)}，并核对改动后的文件。")
        self.patch("patch", target, "before\n", "after\n")
        cg.dispatch(self.event("Stop", last_assistant_message="等待核验。"))
        earlier = json.loads(json.dumps(self.state()["decision_log"][-1]))
        self.assertFalse(any(row["certifiable"] for row in earlier["core_projections"]))
        self.readback("later-read", target, "after\n")
        cg.dispatch(self.event("Stop", last_assistant_message="文件已经核对。"))
        decisions = self.state()["decision_log"]
        self.assertEqual(decisions[-2], earlier)
        self.assertTrue(any(row["certifiable"] for row in decisions[-1]["core_projections"]))

    def test_combined_edit_readback_cannot_hide_failed_focused_test(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        locator = self.root_target(target)
        self.start(f"请修改 {locator}，并运行 {locator} 的测试。")
        self.patch("patch", target, "before\n", "after\n")
        self.readback("read-after", target, "after\n")
        self.command("failed-test", f"pytest {target}", code=1, stdout="1 failed\n")
        cg.dispatch(self.event("Stop", last_assistant_message="测试未通过。"))
        aggregate = next(row for row in self.state()["decision_log"][-1]["core_projections"]
                         if row["predicate"] == "edit_and_test")
        self.assertFalse(aggregate["certifiable"])

    def test_foreign_turn_file_change_cannot_supply_edit_state(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {self.root_target(target)}，并核对改动后的文件。")
        patch = (f"*** Begin Patch\n*** Update File: {target.name}\n@@\n"
                 "-before\n+after\n*** End Patch\n")
        self.write_file(target, "after\n")
        self.completed("foreign-patch", {"type": "FileChange", "status": "completed",
                                        "changes": {str(target): {
                                            "type": "update", "unified_diff": "@@ -1 +1 @@\n-before\n+after\n",
                                            "move_path": None}}}, turn="prior-turn")
        cg.dispatch(self.event("PostToolUse", tool_name="apply_patch",
                               tool_use_id="foreign-patch", tool_input={"command": patch},
                               tool_response="patch applied"))
        self.readback("read-after", target, "after\n")
        cg.dispatch(self.event("Stop", last_assistant_message="文件已经核对。"))
        self.assertFalse(any(row["certifiable"] for row in
                             self.state()["decision_log"][-1]["core_projections"]))

    def test_failed_edit_with_ready_target_remains_current_action(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {self.root_target(target)}。")
        self.readback("read-before", target, "before\n")
        patch = (f"*** Begin Patch\n*** Update File: {target.name}\n@@\n"
                 "-before\n+after\n*** End Patch\n")
        self.completed("failed-patch", {"type": "FileChange", "status": "failed",
                                        "changes": {str(target): {
                                            "type": "update", "unified_diff": "@@ -1 +1 @@\n-before\n+after\n",
                                            "move_path": None}}})
        cg.dispatch(self.event("PostToolUse", tool_name="apply_patch",
                               tool_use_id="failed-patch", tool_input={"command": patch},
                               tool_response="failed"))
        cg.dispatch(self.event("UserPromptSubmit", prompt="继续。"))
        cg.dispatch(self.event("Stop", last_assistant_message="编辑失败，尚未完成。"))
        self.assertTrue(any(a.get("category") == "local_edit"
                            and a.get("actionability") == "current_ready"
                            for a in self.state()["decision_log"][-1]["actions"]))

    def test_unrun_selected_focused_test_remains_current_action(self):
        target = self.cwd / "suite.py"
        self.write_file(target, "def test_ok(): assert True\n")
        self.start(f"请运行 {self.root_target(target)} 的测试。")
        self.readback("selected-file", target, "def test_ok(): assert True\n")
        cg.dispatch(self.event("UserPromptSubmit", prompt="继续。"))
        cg.dispatch(self.event("Stop", last_assistant_message="测试尚未运行。"))
        self.assertTrue(any(a.get("category") == "test_verify"
                            and a.get("actionability") == "current_ready"
                            for a in self.state()["decision_log"][-1]["actions"]))

    def test_combined_root_stays_open_without_test_and_future_note_is_not_work(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        locator = self.root_target(target)
        self.start(f"请修改 {locator}，并运行 {locator} 的测试。")
        self.readback("before", target, "before\n")
        self.patch("patch", target, "before\n", "after\n")
        self.readback("after", target, "after\n")
        cg.dispatch(self.event("Stop", last_assistant_message=
                               "修改完成，测试尚未运行。实际收益还要以后观察。"))
        decision = self.state()["decision_log"][-1]
        aggregate = next(row for row in decision["core_projections"]
                         if row["predicate"] == "edit_and_test")
        self.assertFalse(aggregate["certifiable"])
        self.assertFalse(any(action.get("category") == "generic_work"
                             and action.get("actionability") == "current_ready"
                             for action in decision["actions"]))
        cg.dispatch(self.event("UserPromptSubmit", prompt="继续。"))
        cg.dispatch(self.event("Stop", last_assistant_message="测试仍未运行。"))
        self.assertNotIn("explicit_user_persistence",
                         self.state()["decision_log"][-1]["reason_codes"])

    def test_failed_post_and_missing_terminal_never_create_success(self):
        target = self.cwd / "suite.py"
        self.write_file(target, "def test_ok(): assert True\n")
        self.start(f"请运行 {target} 的测试。")
        self.command("failed", f"pytest {target}", code=1,
                     stdout="1 passed", response="Success")
        cg.dispatch(self.event("PostToolUse", tool_name="Bash", tool_use_id="missing",
                               tool_input={"command": f"pytest {target}"},
                               tool_response="Tests passed"))
        evidence = self.state()["evidence"][-2:]
        self.assertEqual([e["outcome"] for e in evidence], ["failed", "unknown"])
        self.assertFalse(any(e.get("core_observation", {}).get("outcome") == "success"
                             for e in evidence))

    def test_powershell_host_invocation_shape_needs_exact_script_and_arity(self):
        target = self.cwd / "suite.py"
        self.write_file(target, "def test_ok(): assert True\n")
        command = f"pytest {target}"
        self.start(f"请运行 {target} 的测试。")
        for label, invocation, expected in (
            ("exact", ["pwsh.exe", "-Command", command], "success"),
            ("wrong-script", ["pwsh.exe", "-Command", "other"], "unknown"),
            ("extra-option", ["pwsh.exe", "-NoProfile", "-Command", command], "unknown"),
        ):
            with self.subTest(label=label):
                call_id = f"ps-{label}"
                self.completed(call_id, {"type": "CommandExecution", "status": "completed",
                                         "exit_code": 0, "command": invocation,
                                         "parsed_cmd": [{"type": "unknown", "cmd": command}],
                                         "cwd": self.cwd.as_uri(), "stdout": "1 passed"})
                cg.dispatch(self.event("PostToolUse", tool_name="Bash", tool_use_id=call_id,
                                       tool_input={"command": command}, tool_response="done"))
                self.assertEqual(self.state()["evidence"][-1]["outcome"], expected)

    def test_powershell_literal_readback_needs_host_shell_and_identical_bytes(self):
        raw_target = r"C:\Work\module.txt"
        command = (
            "[System.Console]::Write([System.IO.File]::ReadAllText("
            f"'{raw_target}'))"
        )
        suite = self.cwd / "suite.py"
        self.write_file(suite, "def test_ok(): assert True\n")
        local_file = self.cwd / "module.txt"
        local_file.write_bytes(b"line\n")
        self.start(f"请运行 {suite} 的测试。")
        cases = (
            ("lf", command, "pwsh.exe", "line\n", b"line\n", True),
            ("crlf", command, "pwsh.exe", "line\r\n", b"line\r\n", True),
            ("unicode", command, "pwsh.exe", "中文😀\n", "中文😀\n".encode(), True),
            ("bom", command, "pwsh.exe", "line\n", b"\xef\xbb\xbfline\n", False),
            ("cat-normalized", f"cat {raw_target}", "pwsh.exe", "line\r\n", b"line\n", False),
            ("wrong-shell", command, "bash", "line\n", b"line\n", False),
            ("wrong-target", command.replace("module.txt", "other.txt"),
             "pwsh.exe", "line\n", b"line\n", False),
            ("relative-target", command.replace(raw_target, "module.txt"),
             "pwsh.exe", "line\n", b"line\n", False),
            ("posix-target", command.replace(raw_target, str(local_file)),
             "pwsh.exe", "line\n", b"line\n", False),
            ("variable", command.replace(f"'{raw_target}'", "$path"),
             "pwsh.exe", "line\n", b"line\n", False),
            ("extra-operation", command + "; Write-Output done",
             "pwsh.exe", "line\n", b"line\n", False),
            ("trailing-output", command + " extra",
             "pwsh.exe", "line\n", b"line\n", False),
        )
        for label, script, shell, stdout, current_bytes, accepted in cases:
            with self.subTest(label=label):
                call_id = f"ps-read-{label}"
                self.completed(call_id, {
                    "type": "CommandExecution", "status": "completed", "exit_code": 0,
                    "command": [shell, "-Command" if shell != "bash" else "-lc", script],
                    "parsed_cmd": [{"type": "unknown", "cmd": script}],
                    "cwd": self.cwd.as_uri(), "stdout": stdout,
                })
                with (mock.patch.object(cg, "_verified_windows_target",
                                        side_effect=lambda path: path if path == raw_target else None),
                      mock.patch.object(cg, "_stable_host_file_bytes",
                                        return_value=current_bytes)):
                    cg.dispatch(self.event(
                        "PostToolUse", tool_name="Bash", tool_use_id=call_id,
                        tool_input={"command": script, "shell": "pwsh"},
                        tool_response="text result is not proof",
                    ))
                evidence = self.state()["evidence"][-1]
                self.assertEqual("core_observation" in evidence, accepted)
                if accepted:
                    self.assertEqual(evidence["core_observation"]["predicate"],
                                     "content_hash")
        with mock.patch.object(cg, "_verified_windows_target", return_value=raw_target):
            cg.dispatch(self.event(
                "PostToolUse", tool_name="Bash", tool_use_id="ps-no-host",
                tool_input={"command": command, "shell": "pwsh"},
                tool_response={"exit_code": 0, "output": "line\n"},
            ))
        self.assertNotIn("core_observation", self.state()["evidence"][-1])

    @unittest.skipUnless(os.name == "nt", "physical drive-path binding is Windows-native")
    def test_powershell_literal_readback_binds_real_windows_file(self):
        target = self.cwd / "module.txt"
        target.write_bytes(b"line\n")
        command = (
            "[System.Console]::Write([System.IO.File]::ReadAllText("
            f"'{target}'))"
        )
        self.start(f"请修改 {target} 并回读内容。")
        self.completed("ps-native", {
            "type": "CommandExecution", "status": "completed", "exit_code": 0,
            "command": ["pwsh.exe", "-Command", command],
            "parsed_cmd": [{"type": "unknown", "cmd": command}],
            "cwd": self.cwd.as_uri(), "stdout": "line\n",
        })
        cg.dispatch(self.event("PostToolUse", tool_name="Bash", tool_use_id="ps-native",
                               tool_input={"command": command}, tool_response="line\n"))
        self.assertEqual(self.state()["evidence"][-1]["core_observation"]["predicate"],
                         "content_hash")

    def test_foreign_conflicting_or_unsafe_transcript_is_unknown(self):
        target = self.cwd / "suite.py"
        self.write_file(target, "def test_ok(): assert True\n")
        command = f"pytest {target}"
        self.start(f"请运行 {target} 的测试。")
        item = {"type": "CommandExecution", "status": "completed", "exit_code": 0,
                "command": ["/bin/zsh", "-lc", command],
                "parsed_cmd": [{"type": "unknown", "cmd": command}],
                "cwd": self.cwd.as_uri(), "stdout": "1 passed"}
        cases = [
            ("other-turn", {"turn": "foreign-turn"}),
            ("other-session", {"thread": "foreign-session"}),
            ("other-command", {"item": {**item, "command": ["/bin/zsh", "-lc", "other"]}}),
            ("other-cwd", {"item": {**item, "cwd": self.root.as_uri()}}),
            ("duplicate", {"duplicate": True}),
        ]
        for index, (label, defect) in enumerate(cases):
            with self.subTest(label=label):
                call_id = f"bad-{index}"
                current = defect.get("item", item)
                self.completed(call_id, current, turn=defect.get("turn"),
                               thread=defect.get("thread"))
                if defect.get("duplicate"):
                    self.completed(call_id, {**item, "status": "failed", "exit_code": 1})
                cg.dispatch(self.event("PostToolUse", tool_name="Bash", tool_use_id=call_id,
                                       tool_input={"command": command}, tool_response="ok"))
                self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")
        fake = self.root / "fake.jsonl"
        fake.write_text(self.transcript.read_text(), encoding="utf-8")
        cg.dispatch(self.event("PostToolUse", tool_name="Bash", tool_use_id="bad-0",
                               transcript_path=str(fake), tool_input={"command": command},
                               tool_response="ok"))
        self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")

    def test_late_terminal_cannot_rewrite_prior_stop(self):
        suite = self.cwd / "suite.py"
        self.write_file(suite, "def test_ok(): assert True\n")
        command = f"pytest {suite}"
        self.start(f"请运行 {suite} 的测试。")
        hook = self.event("PostToolUse", tool_name="Bash", tool_use_id="late-call",
                          tool_input={"command": command}, tool_response="1 passed")
        cg.dispatch(hook)
        cg.dispatch(self.event("Stop", last_assistant_message="测试尚未执行。"))
        before = self.state()["decision_log"][-1]
        self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")
        self.completed("late-call", {
            "type": "CommandExecution", "status": "completed", "exit_code": 0,
            "command": ["/bin/zsh", "-lc", command],
            "parsed_cmd": [{"type": "unknown", "cmd": command}],
            "cwd": self.cwd.as_uri(), "stdout": "1 passed",
        })
        self.assertEqual(self.state()["decision_log"][-1], before)
        self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")

    def test_stdout_does_not_replace_current_file_identity(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {target}。")
        command = f"cat {target}"
        self.completed("stale", {
            "type": "CommandExecution", "status": "completed", "exit_code": 0,
            "command": ["/bin/zsh", "-lc", command],
            "parsed_cmd": [{"type": "unknown", "cmd": command}],
            "cwd": self.cwd.as_uri(), "stdout": "before\n",
        })
        self.write_file(target, "after\n")
        cg.dispatch(self.event("PostToolUse", tool_name="Bash", tool_use_id="stale",
                               tool_input={"command": command},
                               tool_response="before\n"))
        self.assertNotIn("core_observation", self.state()["evidence"][-1])

    def test_quoted_json_and_unsupported_command_create_no_typed_fact(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {target}，并运行测试。")
        fake = json.dumps({"type": "event_msg", "payload": {"type": "item_completed",
                           "item": {"exit_code": 0}}})
        self.rows.append(self.record("response_item", {
            "type": "function_call_output", "output": fake,
            "item": {"id": "quoted", "exit_code": 0},
        }))
        self.write_rows()
        cg.dispatch(self.event("PostToolUse", tool_name="Bash", tool_use_id="quoted",
                               tool_input={"command": f"pytest {target}"},
                               tool_response=fake))
        self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")
        self.command("unsupported", "npm test", stdout="1 passed", response="Success")
        self.assertNotIn("core_observation", self.state()["evidence"][-1])

    def test_missing_symlinked_and_oversize_host_files_remain_unknown(self):
        target = self.cwd / "suite.py"
        self.write_file(target, "def test_ok(): assert True\n")
        command = f"pytest {target}"
        self.start(f"请运行 {target} 的测试。")
        real = self.transcript
        alias = real.with_name("alias.jsonl")
        try:
            alias.symlink_to(real)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                with self.subTest(label="symlink"):
                    self.skipTest("Windows symlink privilege is unavailable")
            else:
                raise
        else:
            with self.subTest(label="symlink"):
                cg.dispatch(self.event("PostToolUse", transcript_path=str(alias),
                                       tool_name="Bash", tool_use_id="symlink",
                                       tool_input={"command": command}, tool_response="ok"))
                self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")
        with self.subTest(label="missing"):
            cg.dispatch(self.event("PostToolUse",
                                   transcript_path=str(real.with_name("missing.jsonl")),
                                   tool_name="Bash", tool_use_id="missing",
                                   tool_input={"command": command}, tool_response="ok"))
            self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")
        self.completed("too-large", {
            "type": "CommandExecution", "status": "completed", "exit_code": 0,
            "command": ["/bin/zsh", "-lc", command],
            "parsed_cmd": [{"type": "unknown", "cmd": command}],
            "cwd": self.cwd.as_uri(), "stdout": "1 passed",
        })
        with real.open("ab") as handle:
            handle.write(b"x" * (cg.HOST_TRANSCRIPT_LIMIT + 1))
        cg.dispatch(self.event("PostToolUse", tool_name="Bash", tool_use_id="too-large",
                               tool_input={"command": command}, tool_response="ok"))
        self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")

    def test_session_meta_and_transcript_symlink_cannot_supply_terminal(self):
        target = self.cwd / "suite.py"
        self.write_file(target, "def test_ok(): assert True\n")
        command = f"pytest {target}"
        self.start(f"请运行 {target} 的测试。")
        self.completed("case", {
            "type": "CommandExecution", "status": "completed", "exit_code": 0,
            "command": ["/bin/zsh", "-lc", command],
            "parsed_cmd": [{"type": "unknown", "cmd": command}],
            "cwd": self.cwd.as_uri(), "stdout": "1 passed",
        })
        self.rows[0]["payload"]["id"] = "other-session"
        self.write_rows()
        hook = self.event("PostToolUse", tool_name="Bash", tool_use_id="case",
                          tool_input={"command": command}, tool_response="ok")
        cg.dispatch(hook)
        self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")
        self.rows[0]["payload"]["id"] = self.session_id
        self.write_rows()
        real = self.transcript.with_name("original.jsonl")
        self.transcript.rename(real)
        with self.subTest(label="symlinked transcript"):
            try:
                self.transcript.symlink_to(real)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows symlink privilege is unavailable")
                raise
            cg.dispatch(hook)
            self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")

    def test_file_change_requires_single_exact_change_and_current_content(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        self.start(f"请修改 {target}。")
        patch = ("*** Begin Patch\n*** Update File: module.py\n@@\n"
                 "-before\n+after\n*** End Patch\n")
        for label, source, changes in (
            ("wrong-content", patch, {str(target): {"type": "update", "unified_diff": "@@ -1 +1 @@\n-before\n+other\n"}}),
            ("wrong-target", patch, {str(self.cwd / "other.py"): {"type": "update", "unified_diff": "@@ -1 +1 @@\n-before\n+after\n"}}),
            ("extra-operation", patch.replace("*** End Patch", "*** Add File: other.py\n+x\n*** End Patch"),
             {str(target): {"type": "update", "unified_diff": "@@ -1 +1 @@\n-before\n+after\n"}}),
        ):
            with self.subTest(label=label):
                self.write_file(target, "after\n")
                self.completed(label, {"type": "FileChange", "status": "completed",
                                       "changes": changes, "stdout": "", "stderr": ""})
                cg.dispatch(self.event("PostToolUse", tool_name="apply_patch",
                                       tool_use_id=label, tool_input={"command": source},
                                       tool_response="Success"))
                self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")
                self.assertNotIn("core_observation", self.state()["evidence"][-1])

    def test_host_add_shape_is_one_effect_not_content_certification(self):
        target = self.cwd / "new.txt"
        self.start(f"请创建 {self.root_target(target)}。")
        patch = "*** Begin Patch\n*** Add File: new.txt\n+new\n*** End Patch\n"
        self.write_file(target, "new\n")
        self.completed("add", {"type": "FileChange", "status": "completed",
                               "changes": {str(target): {"type": "add", "content": "new\n"}},
                               "stdout": "", "stderr": ""})
        cg.dispatch(self.event("PostToolUse", tool_name="apply_patch",
                               tool_use_id="add", tool_input={"command": patch},
                               tool_response="Success"))
        evidence = self.state()["evidence"][-1]
        self.assertEqual(evidence["outcome_basis"], "host_transcript_file_change")
        self.assertEqual(evidence["core_observation"]["predicate"], "mutation_applied")
        cg.dispatch(self.event("Stop", last_assistant_message="文件已经创建。"))
        self.assertFalse(any(row["certifiable"]
                             for row in self.state()["decision_log"][-1]["core_projections"]))

    def test_host_add_content_must_match_file_bytes_without_newline_conversion(self):
        target = self.cwd / "new.txt"
        self.start(f"请创建 {self.root_target(target)}。")
        patch = "*** Begin Patch\n*** Add File: new.txt\n+new\n*** End Patch\n"
        target.write_bytes(b"new\r\n")
        self.completed("add-mismatch", {
            "type": "FileChange", "status": "completed",
            "changes": {str(target): {"type": "add", "content": "new\n"}},
            "stdout": "", "stderr": "",
        })
        cg.dispatch(self.event("PostToolUse", tool_name="apply_patch",
                               tool_use_id="add-mismatch", tool_input={"command": patch},
                               tool_response="Success"))
        evidence = self.state()["evidence"][-1]
        self.assertEqual(evidence["outcome_basis"], "host_terminal_unavailable")
        self.assertNotIn("core_observation", evidence)

    @unittest.skipUnless(os.name == "nt", "drive-token boundary is Windows-native")
    def test_windows_root_requires_complete_path_token(self):
        target = self.cwd / "module.py"
        vague = f"请修改 {target} 并运行测试。"
        exact = f"请修改 {self.root_target(target)}，并运行测试。"
        self.assertEqual(cg.root_absolute_locator_mentions(vague), (set(), True))
        self.assertEqual(cg.root_absolute_locator_mentions(exact), ({str(target)}, False))

    def test_unobserved_native_delete_shape_remains_unavailable(self):
        target = self.cwd / "old.txt"
        self.start(f"请删除 {target}。")
        patch = "*** Begin Patch\n*** Delete File: old.txt\n*** End Patch\n"
        self.completed("delete", {"type": "FileChange", "status": "completed",
                                  "changes": {str(target): {"type": "delete"}}})
        cg.dispatch(self.event("PostToolUse", tool_name="apply_patch",
                               tool_use_id="delete", tool_input={"command": patch},
                               tool_response="Success"))
        self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")

    def test_hardlinked_readback_cannot_claim_unique_file_subject(self):
        target = self.cwd / "module.py"
        self.write_file(target, "before\n")
        os.link(target, self.cwd / "alias.py")
        self.start(f"请核对 {target} 的内容。")
        self.command("hardlink", f"cat {target}", stdout="before\n")
        self.assertNotIn("core_observation", self.state()["evidence"][-1])

    def test_inactive_ordinary_post_does_not_scan_transcript(self):
        with mock.patch.object(cg, "host_terminal_result") as scan:
            result = cg.dispatch(self.event("PostToolUse", tool_name="Bash",
                                            tool_use_id="inactive",
                                            tool_input={"command": "pytest suite.py"},
                                            tool_response="1 passed"))
        self.assertEqual(result, {})
        scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
