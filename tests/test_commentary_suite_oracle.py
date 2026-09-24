"""Exact suite proof from official-looking RPC records, without a model."""

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.validation import commentary_suite_oracle as oracle


class SuiteOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        cwd = Path(self.temp.name)
        script = cwd / "suite.py"
        script.write_text(
            "import unittest\n\nVALUES = tuple(range(-64, 64))\n\n"
            "class SquareFixture(unittest.TestCase):\n"
            "    def test_squared_rows(self):\n"
            "        rows = [value * value for value in VALUES]\n"
            "        self.assertEqual(len(rows), 128)\n"
            "        self.assertEqual(rows[0], 4096)\n"
            "        self.assertEqual(rows[-1], 3969)\n"
            "        self.assertEqual(sum(rows), 174784)\n\n"
            "if __name__ == \"__main__\":\n"
            "    unittest.main()\n")
        self.action = f"python3 {script}"
        self.outer = f"/bin/zsh -lc '{self.action}'"
        self.plan = {
            "cwd": str(cwd), "root_prompt": f"请运行 {script} 的测试并持续执行直到任务完成。",
            "main_requirement_text": f"请运行 {script} 的测试并持续执行直到任务完成。",
            "values": list(range(-64, 64)), "hook_source": "/installed/hooks.json",
            "suite_oracle": {"path": str(script), "sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
                             "platform": "posix", "allowed_python": ["python3"],
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
        for index in (1, 2):
            rows[index]["raw"]["params"]["item"]["commandActions"][0]["command"] = f"python3 {other}"
        with self.assertRaisesRegex(oracle.SuiteEvidenceError, "foreign_same_name_suite"):
            oracle.verify_suite(rows, self.plan, "thread", "turn", "business")

    def test_source_and_shell_argv_are_frozen(self):
        self.assertEqual(oracle._action_argv("& 'C:\\Python\\python.exe' 'C:\\work\\suite.py'",
                                              "windows"),
                         ["C:\\Python\\python.exe", "C:\\work\\suite.py"])
        self.assertIsNone(oracle._action_argv("& 'C:\\Python\\python.exe' 'C:\\work\\suite.py'; whoami",
                                               "windows"))
        for unsafe in ("& 'C:\\Python\\python.exe' \"$env:TEMP\\suite.py\"",
                       "& 'C:\\Python\\python.exe' 'C:\\work\\suite.py`whoami'",
                       "& 'C:\\Python\\python.exe' \"$(whoami)\\suite.py\""):
            with self.subTest(unsafe=unsafe):
                self.assertIsNone(oracle._action_argv(unsafe, "windows"))
        self.assertEqual(oracle._action_argv(self.action, "posix"),
                         ["python3", self.plan["suite_oracle"]["path"]])
        with self.assertRaisesRegex(oracle.SuiteEvidenceError, "suite_not_bound_to_main_work"):
            oracle.validate_suite_plan({**self.plan, "values": [1, 2]})
        Path(self.plan["suite_oracle"]["path"]).write_text("changed")
        with self.assertRaisesRegex(oracle.SuiteEvidenceError, "suite_source_changed"):
            oracle.validate_suite_plan(self.plan)


if __name__ == "__main__":
    unittest.main()
