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
        directory = Path(root) / "sessions-v2" / session
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

    def test_t20_total_budget_covers_search_and_clause_memos(self):
        """CGN-02 regression: old code retained 14KB under a 1-byte budget."""
        pattern = dict(cg.ACTION_PATTERNS)["local_edit"]
        text = "修改 src/component.py 并运行完整验证套件，必须提供回执。" * 200
        evaluation = self.context(text_budget_bytes=1)
        evaluation.action_matches_of(pattern, text)
        evaluation.action_source_clauses_of(text)
        evaluation.reply_clauses_of(text)
        self.assertEqual(len(evaluation._searches), 0)
        self.assertEqual(len(evaluation._source_clauses), 0)
        self.assertEqual(len(evaluation._reply_clause_memo), 0)
        self.assertEqual(evaluation._memo_bytes, 0)
        # Results stay correct while uncached: recomputation matches direct
        # computation, and the decision surface is unchanged.
        self.assertEqual(
            [(m.span(), m.group(0))
             for m in evaluation.action_matches_of(pattern, text)],
            [(m.span(), m.group(0))
             for m in cg.action_matches(pattern, text)],
        )

    def test_t21_total_budget_admits_and_accounts_within_limit(self):
        pattern = dict(cg.ACTION_PATTERNS)["local_edit"]
        text = "修改 src/a.py 并运行测试。"
        evaluation = self.context(text_budget_bytes=1_000_000)
        evaluation.action_matches_of(pattern, text)
        evaluation.action_source_clauses_of(text)
        self.assertEqual(len(evaluation._searches), 1)
        self.assertEqual(len(evaluation._source_clauses), 1)
        self.assertGreater(evaluation._memo_bytes, 0)
        self.assertLessEqual(evaluation._memo_bytes, 1_000_000)

    def test_t22_huge_single_input_is_never_retained(self):
        pattern = dict(cg.ACTION_PATTERNS)["local_edit"]
        huge = "必须 " * 400_000  # ~3.2MB text
        evaluation = self.context(text_budget_bytes=1_000_000)
        evaluation.action_matches_of(pattern, huge)
        self.assertEqual(len(evaluation._searches), 0)
        self.assertLessEqual(evaluation._memo_bytes, 1_000_000)

    def test_t23_budget_exhaustion_keeps_decisions_identical(self):
        small = self.context(text_budget_bytes=64)
        large = self.context()
        self.assertEqual(
            cg.current_feedback_view(self.state, self.session_dir, small),
            cg.current_feedback_view(self.state, self.session_dir, large),
        )

    # -- CGR-M1: keys, containers, and derived views are part of the budget.

    def test_m1_long_key_empty_value_is_charged_and_refused(self):
        """Coordinator probe CGR-M1-source: a 100KB source retained under an
        empty result charged zero bytes. Now the key is accounted and the
        entry is refused under a tiny budget; the direct result is equal."""
        text = "a" * 100_000
        refused = self.context(text_budget_bytes=1)
        result = refused.action_sources_of(text, "not_a_known_action", None)
        self.assertEqual(refused._action_sources, {})
        self.assertEqual(refused._memo_bytes, 0)
        admitted = self.context()
        self.assertEqual(list(admitted.action_sources_of(text, "not_a_known_action", None)),
                         list(result))

    def test_m1_negative_basis_long_key_is_charged_and_refused(self):
        """Coordinator probe CGR-M1-basis: a negative basis result retained a
        100KB clause inside its key for 64 charged bytes."""
        clause = "b" * 100_000
        evaluation = self.context(text_budget_bytes=64)
        key = evaluation.basis_key(
            "local_review", clause, include_satisfied=True,
            include_unready=True, include_controlled=True,
            allowed_item_ids=None,
        )
        evaluation.store_basis(key, None)
        self.assertEqual(evaluation._bases, {})
        self.assertEqual(evaluation._memo_bytes, 0)
        self.assertIs(evaluation.cached_basis(key), cg._MEMO_MISS)

    def test_m1_many_small_entries_stay_within_budget(self):
        pattern = dict(cg.ACTION_PATTERNS)["local_edit"]
        evaluation = self.context(text_budget_bytes=4_096)
        for index in range(50):
            evaluation.action_matches_of(pattern, f"修改 src/file{index}.py 并运行测试。")
        self.assertLessEqual(evaluation._memo_bytes, 4_096)
        self.assertGreater(len(evaluation._searches), 0)

    def test_m1_derived_view_growth_is_reserved_up_front(self):
        text = "修改 src/view.py 并运行测试，必须验证结果。" * 4
        evaluation = self.context(text_budget_bytes=1_000_000)
        evaluation.parsed(text)
        base_charge = evaluation._memo_bytes
        self.assertGreaterEqual(base_charge, len(text.encode("utf-8")) * 3)
        # Building both derived views must not grow the accounted footprint
        # beyond the up-front reserve.
        evaluation.parsed(text).instruction_view(preserve_newlines=True)
        evaluation.parsed(text).instruction_view(preserve_newlines=False)
        self.assertEqual(evaluation._memo_bytes, base_charge)

    def test_m1_multilingual_strings_count_utf8_bytes(self):
        text = "必须验证模块示例的结果。" * 20  # CJK: 3 bytes per char
        evaluation = self.context(text_budget_bytes=1_000_000)
        evaluation.reply_clauses_of(text)
        expected_text_bytes = len(text.encode("utf-8"))
        self.assertGreater(evaluation._memo_bytes, expected_text_bytes)
        self.assertLessEqual(evaluation._memo_bytes, 1_000_000)

    def test_m1_phase_release_returns_charged_bytes(self):
        pattern = dict(cg.ACTION_PATTERNS)["local_edit"]
        text = "修改 src/phase.py 并运行测试。"
        evaluation = self.context(text_budget_bytes=1_000_000)
        evaluation.parsed(text)
        lexical_charge = evaluation._memo_bytes
        evaluation.store_basis(
            evaluation.basis_key("local_review", text, include_satisfied=False,
                                 include_unready=False, include_controlled=False,
                                 allowed_item_ids=None),
            None,
        )
        evaluation.action_matches_of(pattern, text)
        evaluation.action_sources_of(text, "local_edit", None)
        self.assertGreater(evaluation._memo_bytes, lexical_charge)
        mixed_charge = evaluation._memo_bytes
        evaluation.new_phase("state_mutated")
        # Phase-bound families (bases, action_sources) release exactly;
        # content-keyed lexical families persist within the event.
        self.assertLess(evaluation._memo_bytes, mixed_charge)
        self.assertGreaterEqual(evaluation._memo_bytes, lexical_charge)

    def test_m1_mixed_families_small_budget_match_unbudgeted(self):
        pattern = dict(cg.ACTION_PATTERNS)["local_edit"]
        texts = ["修改 src/mix.py 并运行完整测试。", "审查模块并核对回执。",
                 "继续执行并报告结果。"]
        small = self.context(text_budget_bytes=2_048)
        large = self.context()
        for text in texts * 3:
            small.parsed(text)
            large.parsed(text)
            small.action_matches_of(pattern, text)
            large.action_matches_of(pattern, text)
            small.action_source_clauses_of(text)
            large.action_source_clauses_of(text)
            key = small.basis_key("local_review", text, include_satisfied=True,
                                  include_unready=False, include_controlled=False,
                                  allowed_item_ids=None)
            small.store_basis(key, None)
            large.store_basis(key, None)
            self.assertEqual(list(small.action_sources_of(text, "local_edit", None)),
                             list(large.action_sources_of(text, "local_edit", None)))
        self.assertLessEqual(small._memo_bytes, 2_048)
        # The unbudgeted context admitted everything; the small one refused
        # at least one family, yet computed identical results throughout.
        self.assertGreater(large._memo_bytes, small._memo_bytes)
        self.assertEqual(
            cg.current_feedback_view(self.state, self.session_dir, small),
            cg.current_feedback_view(self.state, self.session_dir, large),
        )

    def test_m1_default_budget_equals_explicit_default(self):
        default_ctx = self.context()
        explicit = self.context(text_budget_bytes=cg.EvaluationContext._TEXT_BUDGET_BYTES)
        self.assertEqual(default_ctx._memo_bytes, explicit._memo_bytes)

    # -- CGR-R2: unknown shapes refuse admission instead of a fixed guess.

    def test_r2_wide_dict_with_late_large_value_is_refused(self):
        """Coordinator probe memo_wide: a 1MB value after entry 64 charged
        1,778 bytes. The unvisited suffix is now unknown -> refused."""
        payload = {f"k{i}": "x" for i in range(64)}
        payload["late"] = "y" * 1_000_000
        evaluation = self.context(text_budget_bytes=4_096)
        key = evaluation.basis_key("local_review", "clause", include_satisfied=False,
                                   include_unready=False, include_controlled=False,
                                   allowed_item_ids=None)
        evaluation.store_basis(key, payload)
        self.assertEqual(evaluation._bases, {})
        self.assertEqual(evaluation._memo_bytes, 0)
        self.assertIs(evaluation.cached_basis(key), cg._MEMO_MISS)

    def test_r2_deep_nesting_is_refused(self):
        """Coordinator probe memo_deep: eight nested dicts around a 1MB
        value charged 274 bytes. Beyond the depth limit is unknown."""
        node = {"value": "z" * 1_000_000}
        for _ in range(8):
            node = {"child": node}
        evaluation = self.context(text_budget_bytes=4_096)
        key = evaluation.basis_key("local_review", "clause", include_satisfied=False,
                                   include_unready=False, include_controlled=False,
                                   allowed_item_ids=None)
        evaluation.store_basis(key, node)
        self.assertEqual(evaluation._bases, {})
        self.assertEqual(evaluation._memo_bytes, 0)

    def test_r2_cycles_and_unsupported_types_are_refused(self):
        evaluation = self.context(text_budget_bytes=1_000_000)
        cycle = ["payload"]
        cycle.append(cycle)
        key = evaluation.basis_key("local_review", "c", include_satisfied=False,
                                   include_unready=False, include_controlled=False,
                                   allowed_item_ids=None)
        evaluation.store_basis(key, {"loop": cycle})
        self.assertEqual(evaluation._bases, {})
        evaluation.store_basis(key, {"opaque": object()})
        self.assertEqual(evaluation._bases, {})
        self.assertIsNone(cg._bounded_size_estimate(cycle))
        self.assertIsNone(cg._bounded_size_estimate({"o": object()}))

    def test_r2_measured_prefixes_still_admit(self):
        evaluation = self.context(text_budget_bytes=1_000_000)
        key = evaluation.basis_key("local_review", "clause", include_satisfied=False,
                                   include_unready=False, include_controlled=False,
                                   allowed_item_ids=None)
        value = {f"k{i}": "v" * 10 for i in range(30)}
        evaluation.store_basis(key, value)
        self.assertIsNot(evaluation.cached_basis(key), cg._MEMO_MISS)
        expected = cg._bounded_size_estimate(key) \
            + cg._bounded_size_estimate(dict(value)) \
            + cg.EvaluationContext._ENTRY_OVERHEAD
        self.assertEqual(evaluation._memo_bytes, expected)

    def test_r2_repeated_key_replacement_does_not_accumulate(self):
        evaluation = self.context(text_budget_bytes=1_000_000)
        key = evaluation.basis_key("local_review", "clause", include_satisfied=False,
                                   include_unready=False, include_controlled=False,
                                   allowed_item_ids=None)
        evaluation.store_basis(key, {"a": "x" * 100})
        first = evaluation._memo_bytes
        evaluation.store_basis(key, {"a": "y" * 300})
        second = evaluation._memo_bytes
        # The old charge was refunded before the new one was added.
        self.assertEqual(
            second - first,
            cg._bounded_size_estimate({"a": "y" * 300})
            - cg._bounded_size_estimate({"a": "x" * 100}),
        )
        evaluation.new_phase("state_mutated")
        self.assertEqual(evaluation._memo_bytes, 0)

    def test_r2_retained_memo_values_are_immutable_snapshots(self):
        pattern = dict(cg.ACTION_PATTERNS)["local_edit"]
        text = "修改 src/imm.py 并运行测试。"
        evaluation = self.context()
        clauses = evaluation.action_source_clauses_of(text)
        sources = evaluation.action_sources_of(text, "local_edit", None)
        matches = evaluation.action_matches_of(pattern, text)
        for retained in (clauses, sources, matches):
            self.assertIsInstance(retained, tuple)
        basis_key = evaluation.basis_key("local_review", text, include_satisfied=False,
                                         include_unready=False, include_controlled=False,
                                         allowed_item_ids=None)
        produced = {"rows": [1, 2, 3]}
        evaluation.store_basis(basis_key, produced)
        produced["rows"].append(4)  # producer mutation after admission
        cached = evaluation.cached_basis(basis_key)
        self.assertEqual(cached["rows"], [1, 2, 3])
        cached["rows"].append(5)  # reader mutation stays isolated
        self.assertEqual(evaluation.cached_basis(basis_key)["rows"], [1, 2, 3])

    def test_r2_disk_projection_has_finite_cap(self):
        evaluation = self.context()
        records = evaluation.disk_prompt_records()
        measured = cg._bounded_size_estimate(records)
        if measured is not None and measured <= cg.EvaluationContext._PROJECTION_BUDGET_BYTES:
            self.assertIs(evaluation.disk_prompt_records(), records)
        else:
            # Over cap or unmeasurable: not cached, recomputed per access,
            # same content.
            self.assertIsNone(evaluation._disk_records)
            self.assertEqual(evaluation.disk_prompt_records(), records)

    def test_r3_deep_basis_never_copies_before_refusal(self):
        from unittest.mock import patch
        value = {}
        for _ in range(1200):
            value = {"child": value}
        evaluation = self.context(text_budget_bytes=1)
        with patch("copy.deepcopy", side_effect=AssertionError("copy before admission")):
            evaluation.store_basis(("deep",), value)
        self.assertEqual(evaluation._bases, {})
        self.assertEqual(evaluation._memo_bytes, 0)

    def test_r3_prompt_projection_routes_share_aggregate_budget(self):
        from unittest.mock import patch
        evaluation = self.context(text_budget_bytes=0)
        evaluation.state["prompts"] = [{"id": f"p{i}", "origin": "human"} for i in range(10)]
        record = {"text": "x" * 1000, "sha256": "s", "record_sha256": "r"}
        cost = cg._bounded_size_estimate(("p0", record))
        evaluation._PROJECTION_BUDGET_BYTES = cost * 2
        with patch.object(cg, "read_prompt_record", return_value=record):
            roots = evaluation.root_records()
            prompts = evaluation.prompt_records()
            self.assertEqual(len(roots), 10)
            self.assertEqual(len(prompts), 10)
            self.assertEqual(len(evaluation._prompt_record_memo), 2)
            self.assertIsNone(evaluation._root_records)
            self.assertIsNone(evaluation._prompt_records)
            self.assertEqual(len(evaluation._consumed), 10)
            self.assertTrue(evaluation.verify_consumed_sources())
        self.assertLessEqual(evaluation._projection_bytes, evaluation._PROJECTION_BUDGET_BYTES)
        evaluation.new_phase("reset")
        self.assertEqual(evaluation._projection_bytes, 0)
        self.assertEqual(len(evaluation._consumed), 10)

    def test_r3_one_megabyte_root_probe_not_retained(self):
        from unittest.mock import patch
        evaluation = self.context(text_budget_bytes=0)
        evaluation.state["prompts"] = [{"id": "p1", "origin": "human"}]
        evaluation._PROJECTION_BUDGET_BYTES = 1
        with patch.object(cg, "read_prompt_record", return_value={"text": "x" * 1_000_000}):
            self.assertEqual(len(evaluation.root_records()["p1"]["text"]), 1_000_000)
        self.assertEqual(evaluation._prompt_record_memo, {})
        self.assertIsNone(evaluation._root_records)
        self.assertEqual(evaluation._projection_bytes, 0)

    def test_r3_large_integer_cannot_hide_outside_budget(self):
        value = {"n": 1 << 1_000_000}
        evaluation = self.context(text_budget_bytes=1024)
        evaluation.store_basis(("large-int",), value)
        self.assertEqual(evaluation._bases, {})
        self.assertGreater(cg._bounded_size_estimate(value), 1024)

    def test_r3_custom_container_copy_is_never_entered(self):
        class Unsupported(dict):
            def __deepcopy__(self, memo):
                raise AssertionError("custom copy must never be entered")
        evaluation = self.context(text_budget_bytes=1_000_000)
        evaluation.store_basis(("custom",), Unsupported(x=1))
        self.assertEqual(evaluation._bases, {})
        self.assertIsNone(cg._bounded_size_estimate(Unsupported(x=1)))


if __name__ == "__main__":
    unittest.main()
