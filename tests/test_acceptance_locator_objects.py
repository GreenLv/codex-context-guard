"""Locator words never create acceptance duties or activation (0.16.1 DEV-01).

Synthetic data only. A path, URL or filename is an object of the request; a
directory named ``test``, ``verify`` or ``验收`` states no checkable rule. The
classification view masks only complete locators. Item text, prompt hashes
and source spans keep the unchanged original line, and real obligations
stated in prose (including the governed ``run test_*.py`` form) survive.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import context_guard as cg  # noqa: E402
from cg_instruction import locator_masked_text  # noqa: E402

LOCATOR_WORDS = ("test", "tests", "verify", "accept", "acceptance", "must",
                 "validate", "测试", "验收", "验证", "必须")


class ExtractAcceptanceLocatorTests(unittest.TestCase):
    def test_minimal_counterexample_matches_its_neutral_twin(self):
        self.assertEqual(cg.extract_acceptance("打开 /work/items/a.txt"), [])
        self.assertEqual(cg.extract_acceptance("打开 /work/test/a.txt"), [])

    def test_locator_word_families_never_create_items(self):
        templates = (
            "打开 /work/{w}/a.txt", "读取 /work/{w}/目录 中的内容",
            "Open /tmp/{w}/report.txt", "read ./{w}/notes.md",
            "read ../{w}/x/y", "look at ~/{w}/notes.txt",
            "打开 C:\\work\\{w}\\a.txt", "打开 D:/work/{w}/a.txt",
            "打开 \\\\server\\share\\{w}\\a.txt", "read docs/{w}/guide.md",
            "看看 https://example.com/{w}/page", "打开 {w}_notes.md",
            '打开 "/work/my {w} dir/a.txt"', "打开 `/work/{w}/a.txt`",
            "Open “C:\\Program Files\\{w}\\a.txt”",
            "参考 [说明](/work/{w}/a.md)",
        )
        for word in LOCATOR_WORDS:
            for template in templates:
                text = template.format(w=word)
                with self.subTest(text=text):
                    self.assertEqual(cg.extract_acceptance(text), [])

    def test_multiple_and_long_locators_create_no_items(self):
        long_tmp = "/private/var/folders/xy/" + "/".join(
            ["isolated-tests", "verify-acceptance", "必须-验收", "must-validate"] * 12)
        self.assertGreater(len(long_tmp), 300)
        for text in (
            "读取 /work/test/a.txt\n读取 /work/verify/b.txt",
            "比较 /work/test/a.txt 与 C:\\verify\\b.txt 以及 /验收/c.md",
            f"请先核对 {long_tmp}/project/spec.txt 后修复文档。",
            f"- 打开 {long_tmp}/a.txt\n- 打开 {long_tmp}/b.txt\n- 打开 {long_tmp}/c.txt",
        ):
            with self.subTest(text=text[:60]):
                self.assertEqual(cg.extract_acceptance(text), [])

    def test_bare_document_and_media_filenames_are_objects(self):
        # The authority lexer intentionally recognizes a narrower file domain.
        # Acceptance classification must cover other ordinary file types too,
        # without changing that lexer's authority or locator-verification scope.
        for word in LOCATOR_WORDS:
            for extension in ("pdf", "docx", "xlsx", "pptx", "png", "jpg",
                              "csv", "log", "zip", "tar.gz"):
                for wrapper in ("{}", "[说明]({})", "({})", "<{}>"):
                    text = "打开 " + wrapper.format(f"{word}.{extension}")
                    with self.subTest(text=text):
                        self.assertEqual(cg.extract_acceptance(text), [])
                        self.assertEqual(cg.score_complexity(text)[0],
                                         cg.score_complexity(text.replace(word, "items"))[0])

    def test_locator_first_quoted_prose_keeps_its_real_obligation(self):
        for quoted in ('"/work/a.txt must verify output"',
                       "“/work/a.txt 必须验证输出”",
                       "`/work/a.txt must verify output`",
                       "「C:\\work\\a.pdf 必须测试输出」"):
            text = f"请保留 {quoted} 这一条要求"
            with self.subTest(text=text):
                self.assertEqual(cg.extract_acceptance(text), [text])

    def test_slash_separated_prose_is_not_a_complete_locator(self):
        for text in ("请验证/测试/实现这个模块", "必须验证/测试/验收",
                     "请实现/安装/部署这个模块"):
            with self.subTest(text=text):
                if "验证" in text:
                    self.assertEqual(cg.extract_acceptance(text), [text])
                self.assertNotEqual(locator_masked_text(text).strip(), "")
                self.assertGreater(cg.score_complexity(text)[0], 0)
        for text in ("打开 ./验证/测试/实现", "打开 docs/verify/build",
                     "打开 中文/测试/说明.pdf"):
            with self.subTest(text=text):
                self.assertEqual(cg.extract_acceptance(text), [])

    def test_file_wrappers_do_not_hide_labels_or_adjacent_prose(self):
        for text in ("打开 [必须验证](test.md)", "打开 [必须验证](test.pdf)",
                     "打开 test.pdf后验证结果", "打开 test.csv 后验证结果",
                     "必须验证 test.png 的输出", "运行 test_case.py"):
            with self.subTest(text=text):
                self.assertEqual(cg.extract_acceptance(text), [text])

    def test_real_obligations_survive_with_the_complete_original_line(self):
        for text in (
            "必须运行测试并验证输出 /work/test/a.txt",
            "请测试模块 /work/items/a.py",
            "You must verify /work/items/out.txt before reporting.",
            "运行 /work/test_case.py",
            "运行 test_case.py",
            "Run tests/test_case.py",
            "执行 C:\\work\\verify\\test_api.py",
            "请验证/测试这个模块",
            "do not edit /work/test/a.txt",
            "打开 /work/a.txt后验证结果",
            '确认 "must verify output" 这一条已经写入',
        ):
            with self.subTest(text=text):
                self.assertEqual(cg.extract_acceptance(text), [text])

    def test_locator_words_cannot_turn_an_inquiry_into_a_duty(self):
        # "must" inside the path is not a normative constraint.
        self.assertEqual(cg.extract_acceptance("确认一下 /work/must/a.txt 对不对"), [])
        self.assertEqual(cg.extract_acceptance("确认一下 /work/items/a.txt 对不对"), [])

    def test_masked_view_preserves_every_position(self):
        for text in ("打开 /work/test/a.txt 后验证", "打开 C:\\验收\\测试.md\n下一行",
                     "参考 [说明](/work/test/a.md)", "运行 test_case.py"):
            with self.subTest(text=text):
                view = locator_masked_text(text)
                self.assertEqual(len(view), len(text))
                self.assertEqual([i for i, c in enumerate(text) if c == "\n"],
                                 [i for i, c in enumerate(view) if c == "\n"])
                self.assertNotIn("test", view.replace("后验证", ""))

    def test_locator_words_do_not_raise_activation_score(self):
        neutral, _ = cg.score_complexity("打开 /work/items/a.txt")
        for word in LOCATOR_WORDS:
            text = f"打开 /work/{word}/测试/验证/a.txt"
            with self.subTest(text=text):
                self.assertEqual(cg.score_complexity(text)[0], neutral)
        score, reasons = cg.score_complexity("必须实现并验证 /work/items/a.txt")
        self.assertIn("implementation", reasons)
        self.assertIn("hard_constraints", reasons)
        self.assertIn("artifacts", reasons)
        self.assertGreaterEqual(score, 4)


class LocatorHookLifecycleTests(unittest.TestCase):
    """UserPromptSubmit -> Stop -> SessionStart(resume) on the real dispatcher."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve(strict=True)
        self.project = base / "isolated-tests" / "verify-acceptance" / "必须验收" / "project"
        self.project.mkdir(parents=True)
        self.data = base / "private"
        patcher = mock.patch.dict(os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.data)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def dispatch(self, session, event, turn, **fields):
        return cg.dispatch(dict(hook_event_name=event, session_id=session,
                                cwd=str(self.project), turn_id=turn, **fields))

    def state(self, session):
        path = self.data / "sessions-v2" / session / "state.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_path_words_do_not_add_items_or_activate(self):
        first = self.project / "test" / "a.txt"
        second = self.project / "verify" / "b.txt"
        prompt = f"读取 {first}\n读取 {second}"
        self.dispatch("paths", "UserPromptSubmit", "t1", prompt=prompt)
        state = self.state("paths")
        self.assertEqual(state["acceptance_items"], [])
        self.assertFalse(state["mode"]["active"])
        self.assertEqual(self.dispatch("paths", "Stop", "t1",
                                       last_assistant_message="done"), {})

    def test_real_duty_with_long_path_is_kept_through_stop_and_resume(self):
        target = self.project / "test" / "output.txt"
        prompt = f"$context-guard\n必须验证 {target} 的输出"
        self.dispatch("duty", "UserPromptSubmit", "t1", prompt=prompt)
        state = self.state("duty")
        self.assertEqual([row["text"] for row in state["acceptance_items"]],
                         [f"必须验证 {target} 的输出"])
        record = state["prompts"][-1]
        self.assertEqual(record["sha256"], cg.sha256_text(prompt))
        item_id = state["acceptance_items"][0]["id"]
        self.dispatch("duty", "Stop", "t1", last_assistant_message="完成了。")
        stopped = self.state("duty")
        self.assertEqual(stopped["acceptance_items"][0]["status"], "pending")
        self.assertIn(item_id, stopped["open_items"])
        self.dispatch("duty", "SessionStart", "t2", source="resume")
        resumed = self.state("duty")
        self.assertEqual([row["text"] for row in resumed["acceptance_items"]],
                         [f"必须验证 {target} 的输出"])
        self.assertEqual(resumed["acceptance_items"][0]["status"], "pending")
        self.assertIn(item_id, resumed["open_items"])

    def test_existing_path_derived_item_is_retained_not_rewritten(self):
        # A state written by 0.16.0 holds the extra item. The narrower
        # extractor is a subset, so integrity holds; the item is kept as
        # recorded (no migration, no silent closure).
        legacy = cg.extract_acceptance

        def old_extract(text):
            items = legacy(text)
            for line in text.splitlines():
                if "/test/" in line.replace("\\", "/") and line.strip() not in items:
                    items.append(line.strip())
            return items

        for path in ("/work/test/a.txt", r"C:\work\test\a.txt"):
            with self.subTest(path=path):
                line = f"打开 {path}"
                self.assertEqual(old_extract(line), [line])

        prompt = f"$context-guard\n打开 {self.project / 'test' / 'a.txt'}"
        with mock.patch.object(cg, "extract_acceptance", old_extract):
            self.dispatch("legacy", "UserPromptSubmit", "t1", prompt=prompt)
        before = self.state("legacy")["acceptance_items"]
        self.assertEqual(len(before), 1)
        self.dispatch("legacy", "SessionStart", "t2", source="resume")
        after = self.state("legacy")
        self.assertEqual(after["acceptance_items"], before)
        self.assertNotIn("integrity_error", json.dumps(after.get("integrity", {})))


class LongTemporaryDirectoryReplayTests(unittest.TestCase):
    """Replay the three original tests under a keyword-rich long TMPDIR.

    0.16.0 failed exactly these with a long temporary root; the fix must not
    rely on a short neutral TMPDIR or on weakened assertions.
    """

    ORIGINAL_TESTS = (
        "tests.test_context_guard_phase3.OrdinaryTerminalCompletionTests."
        "test_ambiguous_evidence_keeps_the_unit_open_and_pending",
        "tests.test_cg122_stop_subject.StopSubjectTests."
        "test_ambiguous_evidence_keeps_the_unit_open_and_pending",
        "tests.test_stop_v5.StopV5Tests."
        "test_exact_cancel_uses_sourced_target_and_wrong_target_stays_pending",
    )

    def test_original_assertions_pass_under_long_keyword_tmpdir(self):
        with tempfile.TemporaryDirectory() as raw:
            long_tmp = Path(raw).joinpath(
                "isolated-tests", "verify-acceptance-must-validate",
                "release-test-review", "x" * 40)
            long_tmp.mkdir(parents=True)
            env = dict(os.environ, TMPDIR=str(long_tmp), TMP=str(long_tmp),
                       TEMP=str(long_tmp), PYTHONDONTWRITEBYTECODE="1")
            env.pop("CONTEXT_GUARD_DATA_DIR", None)
            completed = subprocess.run(
                [sys.executable, "-m", "unittest", *self.ORIGINAL_TESTS],
                cwd=ROOT, env=env, capture_output=True, text=True, timeout=600)
            self.assertEqual(completed.returncode, 0, completed.stderr[-4000:])
            self.assertIn("Ran 3 tests", completed.stderr)


if __name__ == "__main__":
    unittest.main()
