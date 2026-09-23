"""Offline source-contract counterexamples; never native acceptance."""

import copy
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

    def test_matched_items_prove_only_their_own_lifecycle(self):
        result, fake, _ = self.run_capture()
        edges = result["causal_edges"]
        local = [e for e in edges if e["kind"] == "same_item_lifecycle"]
        self.assertEqual({e["item_id"] for e in local}, {"m1", "continue", "compact"})
        self.assertTrue(all(e["from"] != e["to"] for e in edges))
        self.assertEqual(result["full_chain"], "unknown")
        self.assertIn("independent_semantic_review", result["unproven_observations"])
        self.assertNotIn("thread/compact/start", [r["method"] for r in fake.sent])

    def test_old_delayed_message_and_reversed_wall_fields_never_create_answer_edge(
        self,
    ):
        for start, end in ((1, 2), (99999999, 1), (104500, 105000)):
            with self.subTest(start=start, end=end):
                events = self.events()
                events[5][1]["params"]["startedAtMs"] = start
                events[6][1]["params"]["completedAtMs"] = end
                result, _, _ = self.run_capture(events)
                self.assertEqual(result["full_chain"], "unknown")
                self.assertEqual(result["answer_coverage"], "unknown")
                self.assertTrue(
                    all(
                        e["kind"] in {"rpc_request_response", "same_item_lifecycle"}
                        for e in result["causal_edges"]
                    )
                )

    def test_reordered_transport_preserves_only_identity_edges(self):
        original, _, _ = self.run_capture()
        events = self.events()
        first, second = events[5][1], events[6][1]
        events[5] = (4.5, second)
        events[6] = (5, first)
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["causal_edges"], original["causal_edges"])
        self.assertEqual(result["full_chain"], "unknown")

    def test_missing_start_and_foreign_item_cannot_supply_pair(self):
        for mutation in ("missing", "other_id"):
            events = self.events()
            if mutation == "missing":
                events.pop(5)
            else:
                events[5][1]["params"]["item"]["id"] = "other"
            result, _, _ = self.run_capture(events)
            self.assertFalse(
                any(e.get("item_id") == "m1" for e in result["causal_edges"])
            )
            self.assertEqual(result["full_chain"], "unknown")

    def test_duplicate_is_idempotent_but_revision_is_conflict(self):
        original, _, _ = self.run_capture()
        events = self.events()
        events.insert(7, copy.deepcopy(events[6]))
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["causal_edges"], original["causal_edges"])
        events[7][1]["params"]["item"]["text"] = "changed"
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["reason"], "conflicting_item_lifecycle")

    def test_source_order_claim_cannot_create_edge(self):
        events = self.events()
        events[6][1]["params"]["sourceOrdinal"] = 100
        events[6][1]["params"]["afterQuestion"] = True
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["full_chain"], "unknown")
        self.assertIn(
            "question_to_model_response_source_boundary",
            result["unproven_observations"],
        )

    def test_command_identity_cannot_change(self):
        for field, value in (
            ("command", "python other.py"),
            ("cwd", "/elsewhere"),
            ("type", "agentMessage"),
        ):
            events = self.events()
            events[8][1]["params"]["item"][field] = value
            result, _, _ = self.run_capture(events)
            self.assertEqual(result["status"], "failed")

    def test_nonzero_command_does_not_prove_business_success(self):
        events = self.events()
        events[8][1]["params"]["item"]["exitCode"] = 1
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["full_chain"], "unknown")
        self.assertFalse(
            any(e["kind"] == "business_success" for e in result["causal_edges"])
        )
