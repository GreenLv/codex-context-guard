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

    @staticmethod
    def readback_command(target):
        if os.name == "nt":
            if "'" in str(target):
                raise ValueError("fixture target is not one literal PowerShell argument")
            return ("[System.Console]::Write([System.IO.File]::ReadAllText("
                    f"'{target}'))")
        return f"cat {shlex.quote(str(target))}"

    def readback(self, call_id, target, stdout):
        self.command(call_id, self.readback_command(target), stdout=stdout)

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

    @unittest.skipIf(os.name == "nt", "POSIX Host parsed-command display shape")
    def test_host_cat_display_may_remove_only_ordinary_posix_quoting(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "mode=on\n")
        self.start(f"请修改 {target}，并核对改动后的文件。")
        command = f"cat '{target}'"
        display = f"cat {target}"
        self.command("quoted-cat", command, stdout="mode=on\n",
                     response="mode=on\n",
                     parsed_cmd=[{"type": "read", "cmd": display,
                                  "name": target.name, "path": str(target)}])
        fact = self.state()["evidence"][-1]
        self.assertEqual(fact["outcome_basis"], "host_transcript_exit_code")
        self.assertEqual(fact["core_observation"]["predicate"], "content_hash")

    @unittest.skipIf(os.name == "nt", "POSIX Host parsed-command display shape")
    def test_host_display_cannot_shrink_compound_redirect_or_wrong_target(self):
        target = self.cwd / "config.txt"
        other = self.cwd / "other.txt"
        self.write_file(target, "mode=on\n")
        self.write_file(other, "else\n")
        self.start(f"请修改 {target}，并核对改动后的文件。")
        for index, (command, display) in enumerate((
            (f"cat '{target}'; echo done", f"cat {target}"),
            (f"cat '{target}' > {other}", f"cat {target}"),
            (f"cat '{target}'", f"cat {other}"),
        )):
            with self.subTest(index=index):
                self.command(f"display-{index}", command, stdout="mode=on\n",
                             response="mode=on\n",
                             parsed_cmd=[{"type": "read", "cmd": display}])
                self.assertEqual(self.state()["evidence"][-1]["outcome"], "unknown")

    def test_host_display_does_not_guess_windows_whitespace_argv(self):
        command = r"cat 'C:\Work Space\config.txt'"
        display = r"cat C:\Work Space\config.txt"
        self.assertFalse(cg._host_parsed_display_matches(command, display, "pwsh.exe"))

    @unittest.skipIf(os.name == "nt", "POSIX Host parsed-command display shape")
    def test_quoted_cat_host_failure_remains_failed(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "mode=on\n")
        self.start(f"请核对 {target} 的内容。")
        command = f"cat '{target}'"
        self.command("failed-quoted-cat", command, code=1, stdout="",
                     response="cat failed",
                     parsed_cmd=[{"type": "read", "cmd": f"cat {target}"}])
        fact = self.state()["evidence"][-1]
        self.assertEqual(fact["outcome"], "failed")
        self.assertNotIn("core_observation", fact)

    def test_direct_backtick_pytest_object_binds_current_test(self):
        suite = self.cwd / "current_suite.py"
        self.write_file(suite, "def test_current(): assert True\n")
        command = f"pytest '{suite}'"
        self.start(f"现在通过宿主 Bash 单独运行 `{command}`，并根据本次真实退出结果报告测试。")
        self.command("current-test", command, stdout="1 passed\n", response="1 passed\n")
        cg.dispatch(self.event("Stop", last_assistant_message="本次测试退出码 0，1 passed。"))
        evidence = self.state()["evidence"][-1]
        self.assertEqual(evidence["core_observation"]["predicate"], "test_passed")
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertTrue(any(row["predicate"] == "test_run_completed"
                            and row["predicate_state"] == "satisfied" for row in rows))

    def test_direct_backtick_cat_object_binds_independent_current_readback(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "mode=on\n")
        command = self.readback_command(target)
        shell = "PowerShell" if os.name == "nt" else "Bash"
        self.start(f"请用宿主 {shell} 调用 `{command}` 完整回读该文件。")
        self.readback("single-read", target, "mode=on\n")
        cg.dispatch(self.event("Stop", last_assistant_message="已回读文件。"))
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertTrue(any(row["predicate"] == "readback_complete"
                            and row["predicate_state"] == "satisfied" for row in rows))

    def test_powershell_byte_readback_object_requires_one_direct_literal_operation(self):
        target = r"C:\Work Space\config.txt"
        command = ("[System.Console]::Write([System.IO.File]::ReadAllText("
                   f"'{target}'))")
        direct = f"请用宿主 PowerShell 调用 `{command}` 完整回读该文件。"
        self.assertEqual(cg._direct_shell_command_object(direct),
                         ("state_readback", target, f"`{command}`"))
        for source in (
            f"请用宿主 Bash 调用 `{command}` 完整回读该文件。",
            f"请用宿主 PowerShell 调用 `{command}; echo done` 完整回读该文件。",
            f"请用宿主 PowerShell 调用 `{command.replace(target, '$target')}` 完整回读该文件。",
            f"请用宿主 PowerShell 调用 `{command.replace(target, 'config.txt')}` 完整回读该文件。",
            f"请用宿主 PowerShell 调用 `cat '{target}'` 完整回读该文件。",
            f"不要调用 `{command}`。",
            f"文档写着：请调用 `{command}` 完整回读。",
            f"“请调用 `{command}` 完整回读。”",
        ):
            with self.subTest(source=source):
                self.assertIsNone(cg._direct_shell_command_object(source))

    @unittest.skipUnless(os.name == "nt", "PowerShell cat byte semantics")
    def test_powershell_cat_does_not_prove_exact_lf_readback(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "mode=on\n")
        command = f"cat '{target}'"
        self.start(f"请用宿主 PowerShell 调用 `{command}` 完整回读该文件。")
        self.command("ps-cat", command, stdout="mode=on\r\n", response="mode=on\r\n")
        self.assertNotIn("core_observation", self.state()["evidence"][-1])

    @unittest.skipUnless(os.name == "nt", "Windows shell attribution")
    def test_explicit_bash_cat_is_not_fulfilled_by_powershell_readback(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "mode=on\n")
        self.start(f"请用宿主 Bash 调用 `cat '{target}'` 完整回读该文件。")
        self.readback("different-shell-read", target, "mode=on\n")
        cg.dispatch(self.event("Stop", last_assistant_message="已完整回读。"))
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertFalse(any(row["predicate"] == "readback_complete"
                             and row["certifiable"] for row in rows))

    def test_tilde_inside_absolute_filename_remains_a_literal_host_target(self):
        directory = self.cwd / "RUNNER~1"
        directory.mkdir()
        self.cwd = directory.resolve(strict=True)
        target = self.cwd / "config.txt"
        self.write_file(target, "mode=off\n")
        target = target.resolve(strict=True)
        command = f"cat '{target}'"
        self.assertEqual(cg._direct_shell_command_object(
            f"请调用 `{command}` 完整回读该文件。"),
            ("state_readback", str(target), f"`{command}`"))
        if os.name != "nt":
            self.assertTrue(cg._host_parsed_display_matches(
                command, f"cat {target}", "zsh"))
        self.start(f"请修改 {self.root_target(target)}，并核对改动后的文件。")
        self.patch("tilde-edit", target, "mode=off\n", "mode=on\n")
        self.readback("tilde-read", target, "mode=on\n")
        cg.dispatch(self.event("Stop", last_assistant_message="已修改并核对文件。"))
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["certifiable"])
        self.assertEqual(rows[0]["predicate_state"], "satisfied")

    def test_home_tilde_and_command_control_stay_unattributed(self):
        self.assertIsNone(cg._direct_shell_command_object(
            "请调用 `cat ~/config.txt` 完整回读该文件。"))
        self.assertIsNone(cg._direct_shell_command_object(
            "请调用 `cat '/tmp/RUNNER~1/config.txt'; echo done` 完整回读。"))
        self.assertFalse(cg._host_parsed_display_matches(
            "cat '~/config.txt'", "cat ~/config.txt", "zsh"))
        self.start("请核对当前文件内容。")
        self.command("home-expansion", "cat ~/config.txt", stdout="mode=on\n",
                     response="mode=on\n")
        self.assertNotIn("core_observation", self.state()["evidence"][-1])

    def test_single_same_root_file_referent_binds_later_direct_edit(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "mode=off\n")
        command = self.readback_command(target)
        shell = "PowerShell" if os.name == "nt" else "Bash"
        root = (f'已知 "{target}" 的原内容恰好为 mode=off 加一个换行。'
                '请用宿主文件编辑工具直接把它改为恰好 mode=on 加一个换行，无需编辑前读取；'
                f"然后用独立的宿主 {shell} 调用 `{command}` 完整回读该文件，并根据真实回读报告实际内容。")
        self.start(root)
        self.patch("anaphoric-edit", target, "mode=off\n", "mode=on\n")
        self.readback("anaphoric-read", target, "mode=on\n")
        cg.dispatch(self.event("Stop", last_assistant_message="已修改并回读：mode=on 加一个换行。"))
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertTrue(any(row["predicate"] == "state_matches"
                            and row["predicate_state"] == "satisfied" for row in rows))
        observed = [e["core_observation"] for e in self.state()["evidence"]
                    if isinstance(e.get("core_observation"), dict)]
        self.assertEqual([e["predicate"] for e in observed], ["edit_applied", "content_hash"])
        aggregate = next(row for row in rows if row["predicate"] == "edit_readback_and_report")
        self.assertEqual(aggregate["predicate_state"], "satisfied")
        self.assertTrue(aggregate["certifiable"])
        self.assertEqual(aggregate["unknown_coverage_count"], 0)

    def test_same_root_replacement_requires_exact_postimage_and_independent_readback(self):
        target = self.cwd / "config.txt"
        command = self.readback_command(target)
        root = (f'已知 "{target}"。请把它改为恰好 mode=on 加一个换行；'
                f"然后调用 `{command}` 完整回读并报告。")
        for index, actual in enumerate(("mode=off\n", "mode=on", "mode=on\n")):
            with self.subTest(actual=actual):
                self.session_id = f"postimage-{index}"
                self.rows = [self.record("session_meta", {
                    "id": self.session_id, "session_id": self.session_id})]
                self.write_rows()
                self.write_file(target, "old\n")
                self.start(root)
                self.patch(f"postimage-edit-{index}", target, "old\n", actual)
                self.readback(f"postimage-read-{index}", target, actual)
                basis = cg._current_action_basis(
                    self.state(), "local_edit", "", self.root / "private/sessions" / self.session_id,
                    include_satisfied=True, include_unready=True)
                self.assertIsNotNone(basis)
                self.assertEqual(basis["predicate_state"],
                                 "satisfied" if actual == "mode=on\n" else "insufficient")

    def test_later_edit_invalidates_prior_matching_readback(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "old\n")
        self.start(f'已知 "{target}"。请把它改为恰好 mode=on 加一个换行。')
        self.patch("first-edit", target, "old\n", "mode=on\n")
        self.readback("first-read", target, "mode=on\n")
        session_dir = self.root / "private/sessions" / self.session_id
        first = cg._current_action_basis(self.state(), "local_edit", "", session_dir,
                                         include_satisfied=True)
        self.assertEqual(first["predicate_state"], "satisfied")
        self.patch("later-edit", target, "mode=on\n", "changed\n")
        later = cg._current_action_basis(self.state(), "local_edit", "", session_dir,
                                         include_satisfied=True, include_unready=True)
        self.assertEqual(later["predicate_state"], "insufficient")
        self.assertGreater(later["as_of"], first["as_of"])

    def test_report_clause_does_not_erase_independent_current_review_or_extra_action(self):
        target = self.cwd / "current_suite.py"
        other = self.cwd / "other.txt"
        self.write_file(target, "def test_current(): assert True\n")
        self.write_file(other, "untouched\n")
        self.start("现在评估这次修改的效果并报告结果。")
        self.command("review-ready", f"test -f {target}", response="")
        session_dir = self.root / "private/sessions" / self.session_id
        review = cg._current_action_basis(self.state(), "local_review", "", session_dir,
                                          include_unready=True)
        self.assertIsNotNone(review)
        self.assertEqual(review["action"], "evaluate_current_effect")
        self.session_id = "mixed-extra-action"
        self.rows = [self.record("session_meta", {
            "id": self.session_id, "session_id": self.session_id})]
        self.write_rows()
        command = f"pytest '{target}'"
        self.start(f"请运行 `{command}`，并根据结果报告并检查文件 {other}。")
        self.command("test-only", command, stdout="1 passed\n", response="1 passed\n")
        test = cg._current_action_basis(
            self.state(), "test_verify", "", self.root / "private/sessions" / self.session_id,
            include_satisfied=True)
        self.assertIsNotNone(test)
        self.assertFalse(test["core_projection"]["certifiable"])
        self.assertTrue(test["core_projection"]["unknown_coverage"])

    def test_anaphoric_edit_does_not_promote_report_or_question(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "off\n")
        roots = (
            f'日志写着：“已知 "{target}"。请把它改为 mode=on。”',
            f'已知 "{target}"。不要把它改为 mode=on。',
            f'如果将来需要处理 "{target}"，再把它改为 mode=on；本轮只解释。',
            "请把它改为 mode=on。",
        )
        for index, root in enumerate(roots):
            with self.subTest(index=index):
                self.session_id = f"referent-negative-{index}"
                self.rows = [self.record("session_meta", {
                    "id": self.session_id, "session_id": self.session_id})]
                self.write_rows()
                self.start(root)
                self.patch(f"negative-edit-{index}", target, "off\n", "mode=on\n")
                self.assertIsNone(cg._current_action_basis(
                    self.state(), "local_edit", "", self.root / "private/sessions" / self.session_id,
                    include_satisfied=True))

    def test_anaphoric_edit_does_not_choose_between_two_same_root_objects(self):
        first, second = self.cwd / "A.txt", self.cwd / "B.txt"
        self.write_file(first, "off\n")
        self.write_file(second, "off\n")
        self.start(f'已知 "{first}" 和 "{second}"。请把它改为 on。')
        self.patch("ambiguous-edit", first, "off\n", "on\n")
        self.assertIsNone(cg._current_action_basis(
            self.state(), "local_edit", "", self.root / "private/sessions" / self.session_id,
            include_satisfied=True))
        self.session_id = "ambiguous-english"
        self.rows = [self.record("session_meta", {
            "id": self.session_id, "session_id": self.session_id})]
        self.write_rows()
        self.start(f'Both "{first}" and "{second}" were mode=off. '
                   'Update it to mode=on plus newline and read it back.')
        self.patch("ambiguous-english-edit", first, "on\n", "mode=on\n")
        self.assertIsNone(cg._current_action_basis(
            self.state(), "local_edit", "", self.root / "private/sessions" / self.session_id,
            include_satisfied=True))

    def test_same_root_referent_and_readback_synonyms_close_from_real_host_facts(self):
        target = self.cwd / "config.txt"
        command = self.readback_command(target)
        roots = (
            f'已知 "{target}" 当前是 mode=off 后跟换行。现在请将该文件内容更新为 mode=on 后跟换行，'
            f"随后单独执行 `{command}` 核对，并据实告知内容。",
            f'这个文件 "{target}" 原为 mode=off 加换行。请修成 mode=on 加换行，'
            f"再通过独立的 `{command}` 读取它并说明读到的内容。",
            f'The file "{target}" currently says mode=off followed by a newline. '
            f"Change it to mode=on followed by a newline, then read it with a separate `{command}` call and report the actual bytes.",
            f'Please edit "{target}" to mode=on plus newline, then run '
            f"`{command}` separately and report what it returned.",
        )
        for index, root in enumerate(roots):
            with self.subTest(index=index):
                self.session_id = f"synonym-{index}"
                self.rows = [self.record("session_meta", {
                    "id": self.session_id, "session_id": self.session_id})]
                self.write_rows()
                self.write_file(target, "mode=off\n")
                self.start(root)
                self.patch(f"synonym-edit-{index}", target, "mode=off\n", "mode=on\n")
                self.readback(f"synonym-read-{index}", target, "mode=on\n")
                cg.dispatch(self.event("Stop", last_assistant_message="已回读：mode=on 加一个换行。"))
                rows = self.state()["decision_log"][-1]["core_projections"]
                aggregate = next(r for r in rows if r["predicate"] == "edit_readback_and_report")
                self.assertTrue(aggregate["certifiable"])
                self.assertEqual(aggregate["unknown_coverage_count"], 0)

    def test_exact_edit_delivery_does_not_claim_unreported_or_extra_work(self):
        target = self.cwd / "config.txt"
        other = self.cwd / "other.txt"
        roots = (
            (f'已知 "{target}"。请把它改为恰好 mode=on 加一个换行；'
             f"然后运行 `cat '{target}'` 完整回读并报告。", False),
            (f'已知 "{target}"。请把它改为恰好 mode=on 加一个换行；'
             f"然后运行 `cat '{target}'` 完整回读并报告并修复 {other}。", True),
        )
        for index, (root, extra_action) in enumerate(roots):
            with self.subTest(index=index):
                self.session_id = f"unreported-{index}"
                self.rows = [self.record("session_meta", {
                    "id": self.session_id, "session_id": self.session_id})]
                self.write_rows()
                self.write_file(target, "old\n")
                self.write_file(other, "untouched\n")
                self.start(root)
                self.patch(f"unreported-edit-{index}", target, "old\n", "mode=on\n")
                self.command(f"unreported-read-{index}", f"cat '{target}'",
                             stdout="mode=on\n", response="mode=on\n",
                             parsed_cmd=[{"type": "read", "cmd": f"cat {target}",
                                          "name": target.name, "path": str(target)}])
                reply = ("已回读：mode=on 加一个换行。" if extra_action
                         else "已完成操作。")
                cg.dispatch(self.event("Stop", last_assistant_message=reply))
                rows = self.state()["decision_log"][-1]["core_projections"]
                self.assertFalse(any(r["predicate"] == "edit_readback_and_report"
                                     and r["certifiable"] for r in rows))

    def test_quoted_target_bytes_are_not_an_actual_readback_report(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "old\n")
        self.start(f'已知 "{target}" 的原内容恰好为 mode=off 加一个换行。'
                   '请把它改为恰好 mode=on 加一个换行；'
                   f"然后调用 `cat '{target}'` 完整回读并报告内容。")
        self.patch("edit", target, "old\n", "mode=on\n")
        self.command("read", f"cat '{target}'", stdout="mode=on\n",
                     parsed_cmd=[{"type": "read", "cmd": f"cat {target}",
                                  "name": target.name, "path": str(target)}])
        cg.dispatch(self.event("Stop", last_assistant_message=(
            "说明文字里出现 mode=on 加一个换行；实际文件内容我未核验。")))
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertFalse(any(r["predicate"] == "edit_readback_and_report"
                             and r["certifiable"] for r in rows))

    def test_actual_current_file_report_requires_one_attributed_complete_value(self):
        target = self.cwd / "config.txt"
        root = (f'已知 "{target}" 的原内容恰好为 mode=off 加一个换行。'
                '请把它改为恰好 mode=on 加一个换行；'
                f"然后调用 `cat '{target}'` 完整回读并报告内容。")
        actual_model_shape = ("已完成修改。独立 Bash `cat` 完整回读结果为：\n\n"
                              "```text\nmode=on\n```\n\n"
                              "实际文件内容恰好为 `mode=on` 加一个换行。")
        cases = (
            (actual_model_shape, True),
            ("我核对了本次 config.txt 的完整回读：文件内容是 mode=on，末尾有一个换行。", True),
            ("已独立回读当前文件，读到 mode=on 加一个换行。", True),
            ("已独立回读当前文件，读到 mode=on 加一个换行。以后可以观察另一个文件的变化。", True),
            ("以后可以观察另一个文件的变化。\n已独立回读当前文件，读到 mode=on 加一个换行。", True),
            ("已独立回读当前文件，读到 mode=on 加一个换行。另一个文件的内容是 mode=off 加一个换行。", True),
            ("已独立回读当前文件，读到 mode=off 加一个换行。另一个文件的内容是 mode=on 加一个换行。", False),
            ("已回读当前文件。\n\n以下是说明文档的示例：\n```text\nmode=on\n```", False),
            ("已回读当前文件。\n\n另一个文件的内容：\n```text\nmode=on\n```", False),
            ("已回读当前文件：以下是说明文档的示例：\n```text\nmode=on\n```", False),
            ("已回读当前文件，另一个文件的内容是 mode=on 加一个换行。", False),
            ("已回读另一个文件，其中有 mode=on 加一个换行。", False),
            ("已回读说明文档，示例写着 mode=on 加一个换行。", False),
            ("实际回读 config.txt 得到 mode=off 加一个换行。", False),
            ("用户原话是‘请报告 mode=on 加一个换行’；我尚未说明实际读到什么。", False),
            ("测试输出中包含 mode=on 加一个换行。", False),
            ("实际回读当前文件：\n```text\nmode=onX\n```\n实际文件内容是 mode=on 加一个换行。", False),
            ("实际回读当前文件：\n```text\nmode=on```\n实际文件内容是 mode=on 加一个换行。", False),
            ("我实际回读当前文件得到 mode=on 加一个换行。再次说明：实际内容是 mode=off 加一个换行。", False),
            ("稍后我会回读并报告 mode=on 加一个换行。", False),
            ("mode=on 加一个换行。", False),
            ("另一个文件的实际内容是 mode=on 加一个换行。", False),
            ("日志引述：‘我已回读当前文件，读到 mode=on 加一个换行。’", False),
        )
        for index, (final, expected) in enumerate(cases):
            with self.subTest(index=index):
                self.session_id = f"report-attribution-{index}"
                self.rows = [self.record("session_meta", {
                    "id": self.session_id, "session_id": self.session_id})]
                self.write_rows()
                self.write_file(target, "mode=off\n")
                self.start(root)
                self.patch(f"edit-{index}", target, "mode=off\n", "mode=on\n")
                self.readback(f"read-{index}", target, "mode=on\n")
                cg.dispatch(self.event("Stop", last_assistant_message=final))
                rows = self.state()["decision_log"][-1]["core_projections"]
                certified = any(row["predicate"] == "edit_readback_and_report"
                                and row["certifiable"] for row in rows)
                self.assertEqual(certified, expected)

    def test_exact_edit_readback_report_completion_survives_reload(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "mode=off\n")
        command = (self.readback_command(target) if os.name == "nt"
                   else f"cat '{target}'")
        self.start(f'已知 "{target}" 的原内容恰好为 mode=off 加一个换行。'
                   '请把它改为恰好 mode=on 加一个换行；'
                   f"然后调用 `{command}` 完整回读并报告内容。")
        self.patch("edit", target, "mode=off\n", "mode=on\n")
        if os.name == "nt":
            self.readback("read", target, "mode=on\n")
        else:
            self.command("read", command, stdout="mode=on\n")
        final = (("已完成修改。独立 Bash `cat` 完整回读结果为：\n\n"
                  "```text\nmode=on\n```\n\n"
                  "实际文件内容恰好为 `mode=on` 加一个换行。")
                 if os.name != "nt" else
                 ("已完成修改。实际文件内容恰好为 `mode=on` 加一个换行。"
                  "我实际回读当前文件得到 mode=on 加一个换行。"))
        self.assertEqual(cg.dispatch(self.event("Stop", last_assistant_message=final)), {})
        state = self.state()
        aggregate = next(row for row in state["decision_log"][-1]["core_projections"]
                         if row["predicate"] == "edit_readback_and_report")
        self.assertTrue(aggregate["certifiable"])
        item = next(row for row in state["requirements"]
                    if row["id"] == aggregate["requirement_id"])
        self.assertEqual(item["status"], "pass")
        self.assertTrue(state["proofs"])
        self.assertEqual(item["completion_basis"]["host_evidence_ids"], ["E0001", "E0002"])
        self.assertEqual(state["open_items"], [])
        self.assertEqual(state["response_delivery"]["records"][-1]["resolution"], "verified")
        self.assertFalse(cg.current_scope_projection(state)["current_item_ids"])
        cg.validate_state_integrity(state)
        self.assertEqual(self.state()["requirements"], state["requirements"])
        cg.dispatch(self.event("Stop", last_assistant_message=final))
        reloaded = self.state()
        self.assertEqual(reloaded["requirements"], state["requirements"])
        self.assertEqual(reloaded["open_items"], [])
        for change in ("missing_host", "wrong_delivery", "wrong_core",
                       "evicted_delivery", "evicted_core", "enforced_contract"):
            with self.subTest(change=change):
                altered = json.loads(json.dumps(state))
                item = altered["requirements"][0]
                if change == "missing_host":
                    item["completion_basis"]["host_evidence_ids"] = ["E0999", "E0002"]
                elif change == "wrong_delivery":
                    item["completion_basis"]["delivery_sha256"] = "0" * 64
                elif change == "wrong_core":
                    item["completion_basis"]["core_sha256"] = "0" * 64
                elif change == "evicted_delivery":
                    altered["response_delivery"]["records"] = []
                    altered["response_delivery"]["sequence"] = 513
                elif change == "evicted_core":
                    altered["decision_log"] = []
                else:
                    altered["proofs"] = []
                altered["content_hash"] = cg.state_content_hash(altered)
                with self.assertRaises(cg.StateIntegrityError):
                    cg.validate_state_integrity(altered)
        # Normal bounded diagnostics may rotate repeatedly. They must not
        # evict the source-bound ordinary result that still closes this item.
        for index in range(cg.delivery().MAX_DELIVERY_RECORDS + 4):
            self.turn_id = f"later-turn-{index}"
            cg.dispatch(self.event("Stop", last_assistant_message="后续说明已交付。"))
        retained = self.state()
        self.assertEqual(retained["requirements"], state["requirements"])
        self.assertEqual(retained["open_items"], [])
        self.assertTrue(any(record["delivery_sha256"] == item["completion_basis"]["delivery_sha256"]
                            for record in retained["response_delivery"]["records"]))
        self.assertEqual(len(retained["response_delivery"]["records"]),
                         cg.delivery().MAX_DELIVERY_RECORDS + 1)
        self.assertTrue(any(
            row.get("core_projection") == aggregate["core_projection"]
            for decision in retained["decision_log"]
            for row in decision.get("core_projections", [])))
        cg.validate_state_integrity(retained)

    def test_seventeen_distinct_ordinary_results_keep_their_completion_sources(self):
        # The retention policy is per completed source, not a second quota on
        # how many independent, already-verified work items a session may hold.
        state = {"requirements": [], "acceptance_items": [],
                 "decision_log": [], "response_delivery": {"records": []}}
        for index in range(17):
            digest = hashlib.sha256(f"delivery-{index}".encode()).hexdigest()
            core = {"index": index}
            state["requirements"].append({
                "status": "pass", "completion_basis": {
                    "delivery_sha256": digest,
                    "core_sha256": cg.sha256_text(cg.canonical_json(core))}})
            state["decision_log"].append({"core_projections": [{
                "delivery_sha256": digest, "core_projection": core}]})
            state["response_delivery"]["records"].append({"delivery_sha256": digest})
        for index in range(40):
            cg.append_decision_log(state, {}, f"later-{index}")
            state["response_delivery"]["records"].append({
                "delivery_sha256": hashlib.sha256(f"later-{index}".encode()).hexdigest()})
            cg._trim_response_delivery(state)
        self.assertEqual(len(cg._ordinary_completion_pins(state)), 17)
        self.assertTrue(all(any(row.get("core_projection") == {"index": index}
                                for decision in state["decision_log"]
                                for row in decision.get("core_projections", []))
                            for index in range(17)))
        self.assertEqual(len(state["response_delivery"]["records"]), 57)

    def test_current_test_and_actual_result_report_close_together(self):
        suite = self.cwd / "current_suite.py"
        self.write_file(suite, "def test_current(): assert True\n")
        command = f"pytest '{suite}'"
        root = (f"现在通过宿主 Bash 单独运行 `{command}`，"
                "并根据本次真实退出结果报告测试。")
        cases = (
            (0, "1 passed\n", "测试成功。\n- 退出码 0\n- 收集测试 1\n- 通过 1\n- 耗时0.00s", True),
            (0, "1 passed\n", "测试成功。\n- 退出码：`0`\n- 收集测试：`1`\n- 通过：`1`\n- 耗时：`0.00s`", True),
            (1, "1 failed\n", "测试失败。退出码 1，失败 1。", True),
            (1, "1 failed\n", "测试成功。\n- 退出码 0\n- 通过 1", False),
            (0, "1 passed\n", "测试成功。\n- 退出码 0\n- 通过 2", False),
            (0, "1 passed\n", "稍后报告本次测试结果。", False),
            (0, "1 passed\n", "另一个测试套件成功。退出码 0，通过 1。", False),
            (0, "1 passed\n", "执行情况另述。\n> 测试成功。退出码 0，通过 1。", False),
            (0, "1 passed\n", "测试成功。退出码 0，通过 1。Future test speed may warrant observation.", True),
            (0, "1 passed\n", "Future test speed may warrant observation.\n测试成功。退出码 0，通过 1。", True),
            (0, "1 passed\n", "测试成功。退出码 0，通过 1。另一个测试套件未来可能需要观察。", True),
            (0, "1 passed\n", "测试成功。退出码 0，通过 2。另一个测试套件未来可能需要观察。", False),
        )
        for index, (code, stdout, final, expected) in enumerate(cases):
            with self.subTest(index=index):
                self.session_id = f"test-report-{index}"
                self.rows = [self.record("session_meta", {
                    "id": self.session_id, "session_id": self.session_id})]
                self.write_rows()
                self.start(root)
                self.command(f"test-{index}", command, code=code, stdout=stdout)
                cg.dispatch(self.event("Stop", last_assistant_message=final))
                rows = self.state()["decision_log"][-1]["core_projections"]
                certified = any(row["predicate"] == "test_and_report"
                                and row["certifiable"] for row in rows)
                self.assertEqual(certified, expected)
                statuses = {item["id"]: item["status"] for item in
                            self.state()["requirements"] + self.state()["acceptance_items"]}
                self.assertEqual(set(statuses.values()), {"pass" if expected else "pending"})
                if expected:
                    self.assertEqual(self.state()["open_items"], [])
                    self.assertEqual(self.state()["response_delivery"]["records"][-1]["resolution"],
                                     "verified")
                    saved = self.state()
                    chosen = {item["id"]: list(item["evidence"])
                              for item in saved["requirements"] + saved["acceptance_items"]}
                    checkpoint = cg.private_checkpoint(
                        saved,
                        {key: value for key, value in chosen.items() if key.startswith("R")},
                        {key: value for key, value in chosen.items() if key.startswith("A")},
                    )
                    self.assertEqual(cg.checkpoint_issues(saved, checkpoint), [])

    def test_test_input_path_does_not_invent_artifact_readback_proof(self):
        suite = self.cwd / "suite.py"
        self.write_file(suite, "def test_current(): assert True\n")
        cases = (
            (f"请运行 `pytest '{suite}'` 并报告结果。", False),
            (f"请运行 `pytest '{suite}'`；并读取 {suite} 的完整内容。", True),
            (f"日志写着：请运行 `pytest '{suite}'`。", False),
        )
        for index, (root, explicit_read) in enumerate(cases):
            with self.subTest(index=index):
                self.session_id = f"test-proof-source-{index}"
                self.rows = [self.record("session_meta", {
                    "id": self.session_id, "session_id": self.session_id})]
                self.write_rows()
                self.start(root)
                obligations = [obligation for item in self.state()["requirements"]
                               for obligation in item["verification_contract"]["obligations"]]
                self.assertEqual(any(obligation["kind"] == "subject_readback"
                                     for obligation in obligations), explicit_read)

    def test_coordinated_test_and_read_keep_only_readback_subject(self):
        suite = self.cwd / "suite.py"
        other = self.cwd / "other.py"
        self.write_file(suite, "def test_current(): assert True\n")
        self.write_file(other, "other\n")
        cases = (
            (f"读取 {suite} 的完整文件内容并运行 pytest {suite} 验证。", suite),
            (f"运行 pytest {suite} 并读取 {suite} 的完整文件内容。", suite),
            (f"运行 pytest {suite} 并读取 {other} 的完整文件内容。", other),
            (f"运行 pytest {suite}，然后读取该文件的完整内容。", suite),
            (f"运行 pytest {suite}。", None),
            (f"请运行 `pytest {suite} 并读取 {other}`。", None),
            (f"Run pytest {suite} and read the complete contents of {other}.", other),
            (f"Read the complete contents of {other} and run pytest {suite}.", other),
            (f"Run pytest {suite}. Then read {other} in full.", other),
            (f"Run pytest {suite}.", None),
            (f"Run `pytest {suite} and read {other}`.", None),
        )
        for root, expected in cases:
            with self.subTest(root=root):
                contract = cg.verification_contract("R001", root, {"assets": []}, [])
                readbacks = [obligation for obligation in contract["obligations"]
                             if obligation["kind"] == "subject_readback"]
                if expected is None:
                    self.assertEqual(readbacks, [])
                else:
                    self.assertEqual(len(readbacks), 1)
                    self.assertEqual(readbacks[0]["subject_ids"],
                                     [cg.prompt_subjects(str(expected))[0]["id"]])
                self.assertFalse(any(obligation["kind"] == "scope_coverage"
                                     for obligation in contract["obligations"]))

    def test_file_readback_quantity_does_not_swallow_separate_proof(self):
        path = "/work/a.txt"
        roots = (
            (f"Read the complete contents of {path}.", True),
            (f"读取 {path} 的完整文件内容。", True),
            (f"然后调用 `cat '{path}'` 完整回读并报告内容。", True),
            (f"然后调用 `cat '{path}'` 完整回读并检查项目所有文件。", False),
            (f"Read the complete contents of {path} and check all files in this project.", False),
            (f"Read the complete contents of {path}; check all files in this project.", False),
            (f"读取 {path} 的完整文件内容并检查项目所有文件。", False),
            (f"读取 {path} 的完整文件内容；检查项目所有文件。", False),
            (f"Read the complete contents of {path} and prove all generated artifacts "
             "meet the unspecified acceptance criteria.", False),
            (f"Read the complete contents of {path}; prove all generated artifacts "
             "meet the unspecified acceptance criteria.", False),
            (f"读取 {path} 的完整文件内容，并证明所有生成制品符合尚未提供的验收标准。", False),
            (f"Run pytest /work/suite.py and read the complete contents of {path}.", True),
        )
        for root, readback_only in roots:
            with self.subTest(root=root):
                contract = cg.verification_contract("R001", root, {"assets": []}, [])
                if not readback_only:
                    self.assertEqual((contract["mode"], contract["reason"]),
                                     ("legacy_fallback", "scope_not_constructible"))
                    continue
                self.assertEqual(contract["mode"], "enforced")
                self.assertEqual([item["kind"] for item in contract["obligations"]],
                                 ["subject_readback"])
                self.assertEqual(contract["obligations"][0]["subject_ids"],
                                 [cg.prompt_subjects(path)[0]["id"]])

    def test_explicit_pass_target_does_not_accept_terminal_failed_run(self):
        suite = self.cwd / "current_suite.py"
        self.write_file(suite, "def test_current(): assert False\n")
        command = f"pytest '{suite}'"
        self.start(f"请运行 `{command}` 并确保测试通过。")
        self.command("failing-test", command, code=1, stdout="1 failed\n")
        cg.dispatch(self.event("Stop", last_assistant_message="测试失败。退出码 1，失败 1。"))
        basis = cg._current_action_basis(
            self.state(), "test_verify", "", self.root / "private/sessions" / self.session_id,
            include_satisfied=True, include_unready=True)
        self.assertIsNotNone(basis)
        self.assertEqual(basis["predicate"], "test_passed")
        self.assertNotEqual(basis["predicate_state"], "satisfied")
        self.assertFalse(any(row.get("certifiable") for row in
                             self.state()["decision_log"][-1]["core_projections"]))

    def test_single_prior_object_cannot_be_the_latter_one(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "old\n")
        self.start(f'已知 "{target}"。请把后者改为恰好 mode=on 加一个换行。')
        self.patch("edit", target, "old\n", "mode=on\n")
        self.command("read", f"cat '{target}'", stdout="mode=on\n",
                     parsed_cmd=[{"type": "read", "cmd": f"cat {target}",
                                  "name": target.name, "path": str(target)}])
        self.assertIsNone(cg._current_action_basis(
            self.state(), "local_edit", "", self.root / "private/sessions" / self.session_id,
            include_satisfied=True))

    def test_context_clause_with_preservation_rule_remains_uninterpreted(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "old\n")
        self.start(f'已知 "{target}" 且需要保留所有注释。'
                   '请把它改为恰好 mode=on 加一个换行；'
                   f"然后运行 `cat '{target}'` 完整回读并报告内容。")
        self.patch("edit", target, "old\n", "mode=on\n")
        self.command("read", f"cat '{target}'", stdout="mode=on\n",
                     parsed_cmd=[{"type": "read", "cmd": f"cat {target}",
                                  "name": target.name, "path": str(target)}])
        cg.dispatch(self.event("Stop", last_assistant_message="已回读：mode=on 加一个换行。"))
        rows = self.state()["decision_log"][-1]["core_projections"]
        self.assertFalse(any(r["predicate"] == "edit_readback_and_report"
                             and r["certifiable"] for r in rows))

    def test_anaphoric_edit_does_not_borrow_prior_root_object(self):
        target = self.cwd / "config.txt"
        self.write_file(target, "off\n")
        self.start(f'已知 "{target}"。')
        self.turn_id = "later-turn"
        cg.dispatch(self.event("UserPromptSubmit", prompt="请把它改为 on。"))
        self.patch("cross-root-edit", target, "off\n", "on\n")
        self.assertIsNone(cg._current_action_basis(
            self.state(), "local_edit", "", self.root / "private/sessions" / self.session_id,
            include_satisfied=True))

    def test_backtick_test_object_is_not_authority_when_quoted_or_negated(self):
        suite = self.cwd / "current_suite.py"
        self.write_file(suite, "def test_current(): assert True\n")
        command = f"pytest '{suite}'"
        roots = (
            f"今后观察 `{command}` 是否变慢；本轮只解释，不运行。",
            f"日志写着：`{command}`，但我没有要求现在运行。",
            f"不要运行 `{command}`。",
            f"`请运行 {command}。`",
        )
        for index, root in enumerate(roots):
            with self.subTest(index=index):
                self.session_id = f"quote-neg-{index}"
                self.rows = [self.record("session_meta", {
                    "id": self.session_id, "session_id": self.session_id})]
                self.write_rows()
                self.start(root)
                self.assertIsNone(cg._current_action_basis(
                    self.state(), "test_verify", "", self.root / "private/sessions" / self.session_id,
                    include_satisfied=True))

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
                         {"state_matches", "test_run_completed", "edit_and_test"})
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

    def test_combined_edit_readback_preserves_honest_failed_test_result(self):
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
        self.assertTrue(aggregate["certifiable"])
        self.assertEqual(aggregate["predicate_state"], "satisfied")

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
