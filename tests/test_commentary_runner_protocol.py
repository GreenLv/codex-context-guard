"""Offline source-contract counterexamples; never native acceptance."""

import unittest

from tests import test_commentary_runner as fixture

runner = fixture.runner


class CausalTests(unittest.TestCase):
    setUp = fixture.CommentaryRunnerTests.setUp
    response = staticmethod(fixture.CommentaryRunnerTests.response)
    event = staticmethod(fixture.CommentaryRunnerTests.event)
    item = fixture.CommentaryRunnerTests.item
    message = fixture.CommentaryRunnerTests.message
    hook = fixture.CommentaryRunnerTests.hook
    events = fixture.CommentaryRunnerTests.events
    run_capture = fixture.CommentaryRunnerTests.run_capture

    def test_ack_proves_only_enqueued_input(self):
        result, _, _ = self.run_capture()
        edge = next(
            e for e in result["causal_edges"] if e.get("method") == "turn/steer"
        )
        self.assertEqual(edge["meaning"], "input_enqueued_for_turn")
        self.assertIn(
            "question_to_model_response_source_boundary",
            result["unproven_observations"],
        )

    def test_hook_fields_are_raw_diagnostics_and_cannot_prove_resume(self):
        for start, end in ((107, 107), (109, 1), (None, None), (999999999, 999999999)):
            events = self.events()
            events[13][1]["params"]["run"].update(
                startedAt=start,
                completedAt=end,
                durationMs=1,
                emittedAtMs=109999,
                source="compact",
            )
            result, _, _ = self.run_capture(events)
            self.assertEqual(result["full_chain"], "unknown")
            self.assertIn(
                "compaction_to_true_session_start_trigger",
                result["unproven_observations"],
            )

    def test_missing_precompact_or_compaction_never_gets_backfilled(self):
        for index in (10, 11, 12):
            events = self.events()
            events.pop(index)
            result, _, _ = self.run_capture(events)
            self.assertEqual(result["native_acceptance"], "not_established")
            self.assertEqual(result["full_chain"], "unknown")

    def test_final_before_compaction_stops(self):
        events = self.events()
        events[6][1]["params"]["item"]["phase"] = "final_answer"
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["reason"], "final_before_active_compact_chain")

    def test_hook_identity_revisions_fail_and_source_change_is_not_ignored(self):
        for field, value in (("startedAt", 1), ("sourcePath", "/foreign")):
            events = self.events()
            duplicate = self.hook("preCompact", "h1")
            duplicate["params"]["run"][field] = value
            events.insert(12, (7.95, duplicate))
            result, _, _ = self.run_capture(events)
            self.assertEqual(result["reason"], "conflicting_hook_identity")

    def test_native_collection_blocked_before_process_or_output(self):
        from unittest.mock import Mock

        factory = Mock()
        path = self.root / "results" / "blocked"
        with self.assertRaisesRegex(ValueError, "native_source_contract_incomplete"):
            runner.collect(self.plan, path, factory)
        factory.assert_not_called()
        self.assertFalse(path.exists())

    def test_old_versions_cannot_be_recertified(self):
        for version in range(1, 6):
            self.plan["schema"] = "cg-commentary-runner/v" + str(version)
            with self.assertRaisesRegex(ValueError, "unsupported_plan"):
                runner.checked_plan(self.plan)

    def test_conflicting_ack_cannot_leave_enqueued_input_edge(self):
        events = self.events()
        events[4] = (4, self.response(4, {"turnId": "foreign"}))
        result, _, _ = self.run_capture(events)
        self.assertFalse(
            any(e.get("method") == "turn/steer" for e in result["causal_edges"])
        )

    def test_unrecognized_item_cannot_acquire_supported_lifecycle_edge(self):
        events = self.events()
        for index in (5, 6):
            events[index][1]["params"]["item"]["type"] = "inventedItem"
        result, _, _ = self.run_capture(events)
        self.assertFalse(any(e.get("item_id") == "m1" for e in result["causal_edges"]))
