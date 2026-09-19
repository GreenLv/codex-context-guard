"""Real-shape Host terminal records paired with string PostToolUse responses."""

import json
import os
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
        self.transcript.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in self.rows),
            encoding="utf-8",
        )

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
        item = {"type": "CommandExecution", "status": "completed" if code == 0 else "failed",
                "exit_code": code, "command": ["/bin/zsh", "-lc", command],
                "parsed_cmd": [{"type": "unknown", "cmd": command}],
                "cwd": self.cwd.as_uri(), "stdout": stdout}
        item.update(overrides)
        self.completed(call_id, item)
        cg.dispatch(self.event("PostToolUse", tool_name="Bash", tool_use_id=call_id,
                               tool_input={"command": command}, tool_response=response))

    def patch(self, call_id, target, before, after, *, response="patch applied"):
        source = (f"*** Begin Patch\n*** Update File: {target.name}\n@@\n"
                  f"-{before.rstrip()}\n+{after.rstrip()}\n*** End Patch\n")
        target.write_text(after, encoding="utf-8")
        self.completed(call_id, {"type": "FileChange", "status": "completed",
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
        target.write_text(before, encoding="utf-8")
        root = f"请修改 {target}，并运行 {target} 的测试。"
        self.start(root)
        self.command("read-before", f"cat {target}", stdout=before)
        self.patch("patch", target, before, after)
        self.command("read-after", f"cat {target}", stdout=after)
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

    def test_combined_root_stays_open_without_test_and_future_note_is_not_work(self):
        target = self.cwd / "module.py"
        target.write_text("before\n", encoding="utf-8")
        self.start(f"请修改 {target}，并运行 {target} 的测试。")
        self.command("before", f"cat {target}", stdout="before\n")
        self.patch("patch", target, "before\n", "after\n")
        self.command("after", f"cat {target}", stdout="after\n")
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
        target.write_text("def test_ok(): assert True\n", encoding="utf-8")
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
        target.write_text("def test_ok(): assert True\n", encoding="utf-8")
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

    def test_foreign_conflicting_or_unsafe_transcript_is_unknown(self):
        target = self.cwd / "suite.py"
        target.write_text("def test_ok(): assert True\n", encoding="utf-8")
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
        suite.write_text("def test_ok(): assert True\n", encoding="utf-8")
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
        target.write_text("before\n", encoding="utf-8")
        self.start(f"请修改 {target}。")
        command = f"cat {target}"
        self.completed("stale", {
            "type": "CommandExecution", "status": "completed", "exit_code": 0,
            "command": ["/bin/zsh", "-lc", command],
            "parsed_cmd": [{"type": "unknown", "cmd": command}],
            "cwd": self.cwd.as_uri(), "stdout": "before\n",
        })
        target.write_text("after\n", encoding="utf-8")
        cg.dispatch(self.event("PostToolUse", tool_name="Bash", tool_use_id="stale",
                               tool_input={"command": command},
                               tool_response="before\n"))
        self.assertNotIn("core_observation", self.state()["evidence"][-1])

    def test_quoted_json_and_unsupported_command_create_no_typed_fact(self):
        target = self.cwd / "module.py"
        target.write_text("before\n", encoding="utf-8")
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
        target.write_text("def test_ok(): assert True\n", encoding="utf-8")
        command = f"pytest {target}"
        self.start(f"请运行 {target} 的测试。")
        real = self.transcript
        alias = real.with_name("alias.jsonl")
        alias.symlink_to(real)
        for label, path in (("symlink", alias), ("missing", real.with_name("missing.jsonl"))):
            with self.subTest(label=label):
                cg.dispatch(self.event("PostToolUse", transcript_path=str(path),
                                       tool_name="Bash", tool_use_id=label,
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
        target.write_text("def test_ok(): assert True\n", encoding="utf-8")
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
        self.transcript.symlink_to(real)
        cg.dispatch(hook)
        self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")

    def test_file_change_requires_single_exact_change_and_current_content(self):
        target = self.cwd / "module.py"
        target.write_text("before\n", encoding="utf-8")
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
                target.write_text("after\n", encoding="utf-8")
                self.completed(label, {"type": "FileChange", "status": "completed",
                                       "changes": changes, "stdout": "", "stderr": ""})
                cg.dispatch(self.event("PostToolUse", tool_name="apply_patch",
                                       tool_use_id=label, tool_input={"command": source},
                                       tool_response="Success"))
                self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")
                self.assertNotIn("core_observation", self.state()["evidence"][-1])

    def test_host_add_shape_is_one_effect_not_content_certification(self):
        target = self.cwd / "new.txt"
        self.start(f"请创建 {target}。")
        patch = "*** Begin Patch\n*** Add File: new.txt\n+new\n*** End Patch\n"
        target.write_text("new\n", encoding="utf-8")
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
        target.write_text("before\n", encoding="utf-8")
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
