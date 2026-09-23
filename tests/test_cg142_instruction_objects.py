"""Object renaming must not change instruction or continuation semantics."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import context_guard as cg
from cg_instruction import fragments, instruction_text


class InstructionObjectTests(unittest.TestCase):
    def test_lossless_unicode_source_mapping(self):
        text = '请测试 "./研究/并提交 audit 空间.py"，不要发布。🙂'
        parts = fragments(text)
        self.assertEqual("".join(part.text for part in parts), text)
        for part in parts:
            self.assertEqual(text[part.start:part.end], part.text)
            self.assertEqual(text.encode("utf-8")[part.byte_start:part.byte_end].decode("utf-8"),
                             part.text)
        self.assertEqual(len(instruction_text(text)), len(text))
        self.assertNotIn("audit", instruction_text(text))
        self.assertIn("不要发布", instruction_text(text))

    def test_quoted_and_code_actions_are_data(self):
        for suffix in ('“commit and release”', '`audit review push`',
                       '\n```\ncommit and release\n```', '\n> commit and release'):
            with self.subTest(suffix=suffix):
                text = "Test /work/suite.py. " + suffix
                self.assertEqual(cg.prompt_action_scope(text)["authorized"], {"test_verify"})

    def test_object_punctuation_does_not_split_real_actions(self):
        text = '修改 "/work/并且, test/review.py" 并测试 "/work/并且, test/review.py"。'
        clauses = cg._action_source_clauses(text)
        self.assertEqual(len(clauses), 1)
        self.assertIn('"/work/并且, test/review.py"', clauses[0])

    def test_action_catalog_ignores_object_words(self):
        for word in ("neutral", "audit", "review", "commit", "push", "release", "edit", "test"):
            for locator in (f"/work/{word}/suite.py", f'"/work/空间 {word}/suite.py"',
                            f"`/work/{word}/suite.py`", f"./{word}/suite.py",
                            f'"C:\\work\\{word}\\suite.py"', f"\\\\server\\{word}\\suite.py"):
                with self.subTest(locator=locator):
                    prompt = f"请运行 {locator} 的测试并持续执行直到任务完成。"
                    self.assertEqual(cg._root_control_item_action({"text": prompt}), "test_verify")
                    self.assertEqual(cg.prompt_action_scope(prompt)["authorized"], {"test_verify"})

    def test_real_second_action_is_not_hidden(self):
        for prompt in ("请测试 /work/audit/suite.py 并提交修改。",
                       "Test ./commit/suite.py and review the results."):
            self.assertIsNone(cg._root_control_item_action({"text": prompt}))
        self.assertEqual(cg.prompt_action_scope("不要提交代码 /work/test/file.py。")['denied'],
                         {"local_commit"})

    def test_invalid_windows_object_never_becomes_its_valid_prefix(self):
        for char in ("?", "*", "|", "\x01"):
            locator = "D:\\work\\review" + char + "bad.py"
            with self.subTest(char=repr(char)):
                canonical, reason = cg.canonical_windows_locator(locator)
                self.assertIsNone(canonical)
                self.assertIn(reason, cg.UNSUPPORTED_REASON_TOKENS)
                self.assertTrue(cg.unsupported_subject(reason, locator).startswith("codex:unsupported/"))

    def test_object_words_do_not_supply_time_or_polarity(self):
        for folder in ("after", "review", "不要", "以后", "never", "when", "下个月"):
            prompt = f'请运行 "/work/{folder}/suite.py" 的测试。'
            self.assertEqual(cg._action_clause_time_state(prompt, "test_verify"), "current")
            self.assertEqual(cg.prompt_action_scope(prompt)["authorized"], {"test_verify"})
        self.assertEqual(cg._action_clause_time_state(
            '收到 "TEST-READY" 后运行 "/work/neutral/suite.py" 的测试。', "test_verify"), "waiting")

    def test_production_side_question_and_compaction(self):
        for folder in ("neutral", "audit", "review", "commit", "test", "push", "release", "edit"):
            for compact in (False, True):
                with self.subTest(folder=folder, compact=compact), tempfile.TemporaryDirectory() as base:
                    root = Path(base).resolve() / folder
                    root.mkdir()
                    target = root / "suite.py"
                    target.write_text("def test_ok(): assert True\n", encoding="utf-8")
                    with patch.dict(os.environ, {"CONTEXT_GUARD_DATA_DIR": str(root / "private")}):
                        def event(kind, turn="t2", **kw):
                            return dict(hook_event_name=kind, session_id="objects", cwd=str(root),
                                        turn_id=turn, **kw)
                        cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                        cg.dispatch(event("UserPromptSubmit", "t1", prompt=
                                          f'请运行 "{target}" 的测试并持续执行直到任务完成。'))
                        command = (f"Test-Path -LiteralPath '{target}' -PathType Leaf" if os.name == "nt"
                                   else f"test -f '{target}'")
                        cg.dispatch(event("PostToolUse", "t1", tool_name="Bash",
                                          tool_input={"command": command, **(
                                              {"shell": "powershell"} if os.name == "nt" else {})},
                                          tool_response={"exit_code": 0,
                                                         "output": "True\r\n" if os.name == "nt" else ""}))
                        cg.dispatch(event("UserPromptSubmit", prompt="顺便解释一下这个函数为什么要处理空输入？"))
                        if compact:
                            cg.dispatch(event("PreCompact"))
                            cg.dispatch(event("SessionStart", source="compact"))
                        result = cg.dispatch(event("Stop", last_assistant_message="空输入需要返回默认结果。"))
                        self.assertEqual(result.get("decision"), "block")


if __name__ == "__main__":
    unittest.main()
