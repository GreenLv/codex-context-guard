"""Event-scoped evaluation-context reuse, invalidation and safety tests.

Mapped to plan items T01–T06, T13, T14, T16, T17, T19: pure-projection reuse
inside one stable state phase, explicit invalidation at every write boundary,
content-keyed lexical identity, caller-isolation of cached values, distinct
semantic keys, bounded memory, and no reuse across events.
"""

import copy
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import context_guard as cg  # noqa: E402

from tools.validation import stop_performance_fixture as fx  # noqa: E402


class EvaluationContextTests(unittest.TestCase):
    def setUp(self):
        self._previous_data_dir = os.environ.get("CONTEXT_GUARD_DATA_DIR")
        self.root = tempfile.mkdtemp(prefix="cg-ctx-tests-")
        os.environ["CONTEXT_GUARD_DATA_DIR"] = self.root
        self.built = fx.build_session(fx.load_runtime(), self.root, "S0")
        self.session_dir = self.built["session_dir"]
        self.state = cg.load_state(
            self.session_dir, dict(hook_event_name="Stop",
                                   session_id=self.built["session_id"],
                                   cwd=self.root, turn_id="t1"))

    def tearDown(self):
        if self._previous_data_dir is None:
            os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
        else:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = self._previous_data_dir

    def context(self, counters=None, **kwargs):
        return cg.EvaluationContext(self.state, self.session_dir,
                                    counters=counters, **kwargs)

    def test_t01_repeated_pure_projections_reuse_and_match(self):
        counters = {}
        evaluation = self.context(counters)
        first = cg.current_feedback_view(self.state, self.session_dir, evaluation)
        snapshot = copy.deepcopy(self.state)
        second = cg.current_feedback_view(self.state, self.session_dir, evaluation)
        self.assertEqual(first, second)
        self.assertEqual(self.state, snapshot)
        self.assertEqual(counters.get("scope_computed"), 1)

    def test_t02_inplace_state_change_requires_new_phase(self):
        counters = {}
        evaluation = self.context(counters)
        before = cg.current_scope_projection(self.state, _context=evaluation)
        self.assertTrue(before["scoped_item_ids"])
        for unit in self.state["work_units"]:
            unit["status"] = "historical_unresolved"
        self.state["work_state"]["active_work_unit_id"] = None
        stale = cg.current_scope_projection(self.state, _context=evaluation)
        self.assertEqual(stale, before)  # phase memo still serves the old view
        evaluation.new_phase("state_mutated")
        after = cg.current_scope_projection(self.state, _context=evaluation)
        self.assertNotEqual(after["revision"], before["revision"])
        self.assertEqual(counters.get("scope_computed"), 2)

    def test_t03_same_length_root_change_detected_by_identity(self):
        counters = {}
        evaluation = self.context(counters)
        roots = evaluation.root_records()
        prompt_id, record = next(iter(roots.items()))
        metadata = next(p for p in self.state["prompts"] if str(p.get("id")) == prompt_id)
        path = self.session_dir / metadata["file"]
        text = record["text"]
        swapped = ("A" if text[0] != "A" else "B") + text[1:]
        self.assertEqual(len(swapped.encode("utf-8")), len(text.encode("utf-8")))
        original_stat = path.stat()
        payload = {"id": record["id"], "text": swapped,
                   "sha256": cg.sha256_text(swapped),
                   "core_event_seq": record["core_event_seq"],
                   "turn_id": record["turn_id"]}
        path.write_text(cg.canonical_json(payload), encoding="utf-8")
        os.utime(path, (original_stat.st_atime, original_stat.st_mtime))
        self.assertEqual(len(evaluation.root_records()), len(roots))
        self.assertFalse(evaluation.verify_consumed_sources())
        fresh = cg.EvaluationContext(self.state, self.session_dir)
        # The rewritten record fails whole-record validation: same length and
        # disguised mtime do not restore the original byte identity.
        self.assertIsNone(fresh.root_records().get(prompt_id))

    def test_t04_deleted_record_fails_consumption_recheck(self):
        evaluation = self.context()
        roots = evaluation.root_records()
        prompt_id = next(iter(roots))
        metadata = next(p for p in self.state["prompts"] if str(p.get("id")) == prompt_id)
        (self.session_dir / metadata["file"]).unlink()
        self.assertFalse(evaluation.verify_consumed_sources())

    def test_t05_control_catalog_still_validates_directory(self):
        root = tempfile.mkdtemp(prefix="cg-ctx-ct-")
        os.environ["CONTEXT_GUARD_DATA_DIR"] = root
        built = fx.build_session(fx.load_runtime(), root, "CT")
        state = cg.load_state(
            built["session_dir"], dict(hook_event_name="Stop",
                                       session_id=built["session_id"],
                                       cwd=root, turn_id="t1"))
        if not state.get("root_controls"):
            self.skipTest("CT fixture without a control catalog")
        controls = cg.current_root_control_projection(state, built["session_dir"])
        self.assertIsNotNone(controls)
        # A rogue record newer than the state watermark must invalidate the
        # catalog: the survivor-only view cannot prove completeness.
        records = cg.prompt_records_from_disk(built["session_dir"])
        latest = max(r.get("core_event_seq", 0) for r in records)
        rogue = copy.deepcopy(records[-1])
        rogue["id"] = "P9999"
        rogue["core_event_seq"] = latest + 1
        rogue["sha256"] = cg.sha256_text(rogue["text"])
        (built["session_dir"] / "prompts" / "P9999.json").write_text(
            cg.canonical_json(rogue), encoding="utf-8")
        state["prompts"].append({"id": "P9999", "file": "prompts/P9999.json",
                                 "origin": "human", "sha256": rogue["sha256"],
                                 "core_event_seq": rogue["core_event_seq"]})
        fresh = cg.EvaluationContext(state, built["session_dir"])
        self.assertIsNone(cg.current_root_control_projection(
            state, built["session_dir"], fresh))

    def test_t13_fresh_contexts_do_not_share_state_views(self):
        first = self.context()
        second = self.context()
        self.assertIsNot(first.scope(), second.scope())

    def test_t14_cached_basis_copy_isolated_from_caller(self):
        # A live test_verify basis: executable root plus a real suite file.
        # Expand Windows TEMP aliases before constructing the observed target.
        root = str(Path(tempfile.mkdtemp(prefix="cg-ctx-t14-")).resolve())
        os.environ["CONTEXT_GUARD_DATA_DIR"] = root
        suite = Path(root) / "suite.py"
        suite.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        session = "ctx-t14"

        def event(kind, turn, **fields):
            return dict(hook_event_name=kind, session_id=session, cwd=root,
                        turn_id=turn, **fields)

        cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
        cg.dispatch(event("UserPromptSubmit", "t1",
                          prompt=f'继续执行，运行 "{suite}" 的测试。'))
        if os.name == "nt":
            escaped = str(suite).replace("'", "''")
            command = f"Test-Path -LiteralPath '{escaped}' -PathType Leaf"
            shell, output = "powershell", "True\r\n"
        else:
            command = f"test -f '{suite}'"
            shell, output = "bash", ""
        cg.dispatch(event("PostToolUse", "t1", tool_name="exec_command",
                          tool_input={"cmd": command, "shell": shell},
                          tool_response={"exit_code": 0, "output": output}))
        directory = Path(root) / "sessions" / session
        state = cg.load_state(directory, event("Stop", "t1"))
        evaluation = cg.EvaluationContext(state, directory)
        bases = cg._live_current_action_bases(state, directory, evaluation)
        self.assertTrue(bases, "expected a live test_verify basis")
        category, item_id = bases[0]["action"], bases[0]["requirement_id"]
        again = cg._current_action_basis(
            state, category, "", directory, allowed_item_ids={item_id},
            _context=evaluation)
        self.assertIsNotNone(again)
        again["target"] = "polluted"
        again["core_projection"]["predicates"] = {}
        third = cg._current_action_basis(
            state, category, "", directory, allowed_item_ids={item_id},
            _context=evaluation)
        self.assertNotEqual(third.get("target"), "polluted")
        self.assertNotEqual(third["core_projection"]["predicates"], {})

    def test_t16_lexical_views_equal_module_functions(self):
        samples = [
            "修改 `src/模块.py` 后运行 test_suite.py，再核对“报告.md”。",
            "```bash\ngit tag v1.2.3\n``` 之外的 git 不是动作。",
            '路径 "C:\\work\\suite.py" 与 /posix/path.txt 相邻。README.md 与报告md 相邻。',
            "Don't stop: it's fine. 引用「日語.txt」 encore.",
            "运行 tests/ 目录的测试。分别检查 a.py 和 b.py。",
        ]
        evaluation = self.context()
        for text in samples:
            self.assertEqual(evaluation.fragments_of(text), cg.fragments(text))
            self.assertEqual(
                evaluation.instruction_view(text), cg.instruction_text(text))
            self.assertEqual(
                evaluation.instruction_view(text, preserve_newlines=False),
                cg.instruction_text(text, preserve_newlines=False))
            for category, pattern in cg.ACTION_PATTERNS:
                self.assertEqual(
                    [m.span() for m in evaluation.action_matches_of(pattern, text)],
                    [m.span() for m in cg.action_matches(pattern, text)])
                self.assertEqual(
                    [m.group(0) for m in evaluation.action_matches_of(pattern, text)],
                    [m.group(0) for m in cg.action_matches(pattern, text)])

    def test_t17_semantic_flags_keep_distinct_keys(self):
        evaluation = self.context()
        scoped = evaluation.scope()["scoped_item_ids"]
        item_id = sorted(scoped)[0]
        seen_keys = set()
        for flags in (dict(include_satisfied=False, include_unready=False,
                           include_controlled=False),
                      dict(include_satisfied=True, include_unready=False,
                           include_controlled=False),
                      dict(include_satisfied=False, include_unready=True,
                           include_controlled=False),
                      dict(include_satisfied=False, include_unready=False,
                           include_controlled=True),
                      dict(include_satisfied=True, include_unready=True,
                           include_controlled=True)):
            key = evaluation.basis_key(
                "local_review", "", allowed_item_ids={item_id}, **flags)
            seen_keys.add(key)
        self.assertEqual(len(seen_keys), 5)

    def test_t19_budget_fallback_stays_correct_and_bounded(self):
        counters = {}
        evaluation = self.context(counters=counters, text_budget_bytes=1)
        text = "修改 src/a.py 并运行 tests/test_a.py，必须验证结果。"
        first = evaluation.fragments_of(text)
        second = evaluation.fragments_of(text)
        self.assertEqual(first, second)
        self.assertEqual(counters.get("fragments_computed"), 2)
        self.assertEqual(len(evaluation._parsed), 0)


if __name__ == "__main__":
    unittest.main()
