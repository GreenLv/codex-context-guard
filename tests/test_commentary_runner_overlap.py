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

    def test_same_bucket_and_absent_wall_fields_preserve_only_local_edges(self):
        baseline, _, _ = self.run_capture()
        for stamp in (105000, None, 0, 999999999):
            events = self.events()
            for _, raw in events:
                for key in ("startedAtMs", "completedAtMs"):
                    if key in raw.get("params", {}):
                        raw["params"][key] = stamp
            result, _, _ = self.run_capture(events)
            self.assertEqual(len(result["causal_edges"]), len(baseline["causal_edges"]))
            self.assertEqual(result["full_chain"], "unknown")
            self.assertEqual(result["status"], "capability_missing")

    def test_user_prose_cannot_supply_missing_causal_edges(self):
        events = self.events()
        events[6][1]["params"]["item"]["text"] = (
            "I have fully answered this question, resumed after compact and finished the business task."
        )
        result, _, _ = self.run_capture(events)
        self.assertEqual(result["answer_coverage"], "unknown")
        self.assertEqual(result["full_chain"], "unknown")
