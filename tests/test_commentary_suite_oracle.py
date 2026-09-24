"""Exact suite proof from official-looking RPC records, without a model."""

import copy
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

from tools.validation import commentary_suite_oracle as oracle
from tools.validation.commentary_live_controller import Controller


class SuiteOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        cwd = Path(self.temp.name)
        script = cwd / "suite.py"
        script.write_bytes((
            "import unittest\n\nVALUES = tuple(range(-64, 64))\n\n"
            "class SquareFixture(unittest.TestCase):\n"
            "    def test_squared_rows(self):\n"
            "        rows = [value * value for value in VALUES]\n"
            "        self.assertEqual(len(rows), 128)\n"
            "        self.assertEqual(rows[0], 4096)\n"
            "        self.assertEqual(rows[-1], 3969)\n"
            "        self.assertEqual(sum(rows), 174784)\n\n"
            "if __name__ == \"__main__\":\n"
            "    unittest.main()\n").encode("utf-8"))
        if os.name == "nt":
            python = sys.executable
            self.action = f"& '{python}' '{script}'"
            doubled_action = self.action.replace("\\", "\\\\")
            self.outer = f'"C:\\\\Synthetic\\\\pwsh.exe" -Command "{doubled_action}"'
            platform = "windows"
        else:
            python = "python3"
            self.action = f"python3 '{script}'"
            self.outer = f"/bin/zsh -lc \"{self.action}\""
            platform = "posix"
        self.plan = {
            "cwd": str(cwd), "root_prompt": f"请运行 {script} 的测试并持续执行直到任务完成。",
            "main_requirement_text": f"请运行 {script} 的测试并持续执行直到任务完成。",
            "values": list(range(-64, 64)), "hook_source": "/installed/hooks.json",
            "suite_oracle": {"path": str(script), "sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
                             "platform": platform, "allowed_python": [python],
                             "allowed_outer_commands": [self.outer]},
        }
        item = {"type": "commandExecution", "id": "suite-call", "command": self.outer,
                "commandActions": [{"type": "unknown", "command": self.action}],
                "cwd": str(cwd), "status": "inProgress", "exitCode": None,
                "aggregatedOutput": None}
        completed = {**item, "status": "completed", "exitCode": 0,
                     "aggregatedOutput": ".\n" + "-" * 70 + "\nRan 1 test in 0.001s\n\nOK\n"}
        self.rows = [
            self.row("item/completed", {"item": {"type": "dynamicToolCall", "id": "business",
                                               "namespace": "cg_commentary_acceptance",
                                               "tool": "business", "status": "completed",
                                               "success": True}}),
            self.row("item/started", {"item": item}),
            self.row("item/completed", {"item": completed}),
            self.row("hook/completed", {"run": {
                "eventName": "postToolUse", "sourcePath": self.plan["hook_source"],
                "id": "post-tool-use:10:/installed/hooks.json:suite-call", "status": "completed",
                "statusMessage": None, "source": "plugin", "handlerType": "command",
                "executionMode": "sync", "scope": "turn"}}),
            self.row("turn/completed", {"turn": {"id": "turn", "status": "completed", "error": None}}),
        ]

    @staticmethod
    def row(method, params):
        return {"direction": "receive", "raw": {"method": method, "params": {
            "threadId": "thread", "turnId": "turn", **params}}}

    def test_exact_suite_with_terminal_and_hook(self):
        evidence = oracle.verify_suite(self.rows, self.plan, "thread", "turn", "business")
        self.assertEqual(evidence["exit_code"], 0)
        self.assertEqual(evidence["item_id"], "suite-call")
        self.assertEqual(evidence["path_sha256"], self.plan["suite_oracle"]["sha256"])

    def test_wrong_target_failed_output_early_final_and_duplicate_are_rejected(self):
        for change in (
            lambda rows: rows[2]["raw"]["params"]["item"].update(exitCode=1),
            lambda rows: rows[2]["raw"]["params"]["item"].update(aggregatedOutput="OK\n"),
            lambda rows: rows[2]["raw"]["params"].update(turnId="other"),
            lambda rows: rows[2]["raw"]["params"]["item"].update(cwd="/foreign"),
            lambda rows: rows[3]["raw"]["params"]["run"].update(status="failed"),
            lambda rows: rows[3]["raw"]["params"].update(threadId="foreign"),
            lambda rows: rows[3]["raw"]["params"].update(turnId="foreign"),
            lambda rows: rows[0]["raw"]["params"]["item"].update(success=False),
            lambda rows: rows[0]["raw"]["params"]["item"].update(tool="ready"),
            lambda rows: rows[0]["raw"]["params"]["item"].update(namespace="foreign"),
            lambda rows: rows.insert(1, copy.deepcopy(rows[0])),
            lambda rows: rows.insert(4, copy.deepcopy(rows[3])),
            lambda rows: rows[2]["raw"]["params"]["item"].update(
                command="/bin/zsh -lc 'echo fake'"),
            lambda rows: rows[2]["raw"]["params"]["item"]["commandActions"][0].update(
                command=self.action + " ; true"),
            lambda rows: rows.insert(1, rows.pop(4)),
            lambda rows: rows.append(copy.deepcopy(rows[2])),
        ):
            rows = copy.deepcopy(self.rows)
            change(rows)
            with self.subTest(change=change), self.assertRaises(oracle.SuiteEvidenceError):
                oracle.verify_suite(rows, self.plan, "thread", "turn", "business")
        rows = copy.deepcopy(self.rows)
        other = Path(self.temp.name).parent / "elsewhere" / "suite.py"
        foreign_action = (f"& '{sys.executable}' '{other}'" if os.name == "nt"
                          else f"python3 '{other}'")
        for index in (1, 2):
            rows[index]["raw"]["params"]["item"]["commandActions"][0]["command"] = foreign_action
        with self.assertRaisesRegex(oracle.SuiteEvidenceError, "foreign_same_name_suite"):
            oracle.verify_suite(rows, self.plan, "thread", "turn", "business")

    def test_source_and_shell_argv_are_frozen(self):
        self.assertEqual(oracle._action_argv("& 'C:\\Python\\python.exe' 'C:\\work\\suite.py'",
                                              "windows"),
                         ["C:\\Python\\python.exe", "C:\\work\\suite.py"])
        self.assertIsNone(oracle._action_argv("& 'C:\\Python\\python.exe' 'C:\\work\\suite.py'; whoami",
                                               "windows"))
        self.assertIsNone(oracle._action_argv("'C:\\Python\\python.exe' 'C:\\work\\suite.py'",
                                               "windows"))
        self.assertIsNone(oracle._action_argv("& C:\\Python\\python.exe C:\\work\\suite.py",
                                               "windows"))
        for unsafe in ("& 'C:\\Python\\python.exe' \"$env:TEMP\\suite.py\"",
                       "& 'C:\\Python\\python.exe' 'C:\\work\\suite.py`whoami'",
                       "& 'C:\\Python\\python.exe' \"$(whoami)\\suite.py\""):
            with self.subTest(unsafe=unsafe):
                self.assertIsNone(oracle._action_argv(unsafe, "windows"))
        self.assertEqual(
            oracle._action_argv("python3 '/synthetic suite/suite.py'", "posix"),
            ["python3", "/synthetic suite/suite.py"])
        with self.assertRaisesRegex(oracle.SuiteEvidenceError, "suite_not_bound_to_main_work"):
            oracle.validate_suite_plan({**self.plan, "values": [1, 2]})
        Path(self.plan["suite_oracle"]["path"]).write_text("changed")
        with self.assertRaisesRegex(oracle.SuiteEvidenceError, "suite_source_changed"):
            oracle.validate_suite_plan(self.plan)

    def test_windows_outer_is_one_literal_shell_and_one_plain_action(self):
        body = r"& 'C:\\Python\\python.exe' 'C:\\work\\suite.py'"
        outer = '"C:\\\\Tools\\\\pwsh.exe" -Command "' + body + '"'
        parsed = oracle._windows_outer_argv(outer)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], r"C:\Tools\pwsh.exe")
        self.assertEqual([oracle._windows_literal_path(x) for x in parsed[1]],
                         [r"C:\Python\python.exe", r"C:\work\suite.py"])
        self.assertTrue(oracle._windows_outer_matches(
            outer, r"C:\work\suite.py", [r"C:\Python\python.exe"]))
        self.assertFalse(oracle._windows_outer_matches(
            outer, r"C:\other\suite.py", [r"C:\Python\python.exe"]))
        self.assertFalse(oracle._windows_outer_matches(
            outer, r"C:\work\suite.py", [r"C:\Other\python.exe"]))
        for bad in (
            outer + "; whoami",
            outer.replace(" -Command ", " -NoProfile -Command "),
            outer.replace("pwsh.exe", "other.exe"),
            outer.replace("suite.py'", "suite.py'; whoami"),
            outer.replace("C:\\\\work", "C:\\\\work\\\\..\\\\elsewhere"),
            outer.replace("& '", "'", 1),
        ):
            with self.subTest(bad=bad):
                parsed = oracle._windows_outer_argv(bad)
                if parsed is not None:
                    self.assertIsNone(oracle._windows_literal_path(parsed[1][1]))

    def controller(self, phase="awaiting_suite"):
        controller = Controller({**self.plan, "question_client_id": "question"}, object())
        controller.thread, controller.turn = "thread", "turn"
        controller.phase = phase
        controller.business_reply_sent = True
        return controller

    def approval(self):
        item = self.rows[1]["raw"]["params"]["item"]
        return {"id": 3, "method": "item/commandExecution/requestApproval", "params": {
            "threadId": "thread", "turnId": "turn", "itemId": item["id"],
            "startedAtMs": 100, "kind": "command", "environmentId": "local",
            "command": item["command"], "commandActions": copy.deepcopy(item["commandActions"]),
            "cwd": item["cwd"], "availableDecisions": [
                "accept", {"acceptWithExecpolicyAmendment": {
                    "execpolicy_amendment": ["unselected"]}}, "cancel"],
            "proposedExecpolicyAmendment": ["unselected"],
        }}

    def test_exact_suite_approval_is_single_use_and_not_terminal_proof(self):
        for phase in ("awaiting_auto_compaction", "awaiting_compaction_evidence",
                      "awaiting_cold_recovery", "awaiting_suite"):
            controller = self.controller(phase)
            self.assertEqual(controller.ingest(self.rows[1]["raw"]), [])
            self.assertEqual(controller.ingest(self.approval()),
                             [{"id": 3, "result": {"decision": "accept"}}])
            with self.assertRaisesRegex(ValueError, "unreviewed_server_request"):
                controller.ingest(self.approval())
        with self.assertRaises(oracle.SuiteEvidenceError):
            oracle.verify_suite(self.rows[:2], self.plan, "thread", "turn", "business")

    def test_suite_approval_rejects_early_or_unbound_requests(self):
        with self.assertRaisesRegex(ValueError, "unreviewed_server_request"):
            self.controller().ingest(self.approval())
        for change in (
            lambda p: p.update(threadId="foreign"),
            lambda p: p.update(turnId="foreign"),
            lambda p: p.update(itemId="foreign"),
            lambda p: p.update(command="pwsh -NoProfile -Command 'other'"),
            lambda p: p.update(cwd="/foreign"),
            lambda p: p["commandActions"][0].update(command="other"),
            lambda p: p.update(kind="writeStdin"),
            lambda p: p.update(environmentId="remote"),
            lambda p: p.update(additionalPermissions={"fs": "all"}),
            lambda p: p.update(networkApprovalContext={"host": "example.test"}),
            lambda p: p.update(proposedNetworkPolicyAmendments=["allow"]),
            lambda p: p.update(approvalId="bridge"),
            lambda p: p.update(availableDecisions=["cancel"]),
            lambda p: p.update(startedAtMs="100"),
            lambda p: p.update(unknownFutureAuthority=True),
        ):
            controller = self.controller()
            controller.ingest(self.rows[1]["raw"])
            request = self.approval()
            change(request["params"])
            with self.subTest(change=change), self.assertRaises(ValueError):
                controller.ingest(request)
            self.assertFalse(controller.suite_approval_sent)
        controller = self.controller()
        extra = copy.deepcopy(self.rows[1]["raw"])
        extra["params"]["item"]["commandActions"][0]["command"] += "; whoami"
        with self.assertRaises(oracle.SuiteEvidenceError):
            controller.ingest(extra)
        controller = self.controller()
        controller.ingest(self.rows[1]["raw"])
        with self.assertRaisesRegex(ValueError, "unreviewed_command_start"):
            controller.ingest(self.rows[1]["raw"])

    def test_suite_change_or_completed_item_blocks_late_approval(self):
        controller = self.controller()
        controller.ingest(self.rows[1]["raw"])
        Path(self.plan["suite_oracle"]["path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(oracle.SuiteEvidenceError, "suite_source_changed"):
            controller.ingest(self.approval())
        self.assertFalse(controller.suite_approval_sent)

        controller = self.controller()
        controller.suite_item_started = copy.deepcopy(self.rows[1]["raw"]["params"]["item"])
        controller.ingest(self.rows[2]["raw"])
        with self.assertRaisesRegex(ValueError, "unreviewed_server_request"):
            controller.ingest(self.approval())
        self.assertFalse(controller.suite_approval_sent)


if __name__ == "__main__":
    unittest.main()
