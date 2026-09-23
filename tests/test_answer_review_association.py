"""Missing causal association is not a message ordering failure."""

import copy
import unittest

from tests import test_answer_review as reviews

cg = reviews.cg


class AssociationDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.product = reviews.ConsumerTests()
        self.product.setUp()
        self.addCleanup(self.product.doCleanups)

    def test_empty_bound_catalog_has_accurate_diagnostic(self):
        p = self.product
        source = cg.answer_review_source(p.directory, p.state)
        source["messages"] = []
        with self.assertRaisesRegex(ValueError, "^no_source_bound_commentary$"):
            cg.answer_review_request(p.directory, p.state, p.item, source=source)

    def test_actual_overlap_keeps_order_diagnostic(self):
        p = self.product
        source = cg.answer_review_source(p.directory, p.state)
        second = copy.deepcopy(source["messages"][0])
        second["message_id"] = "second"
        source["messages"].append(second)
        with self.assertRaisesRegex(ValueError, "^ambiguous_message_order$"):
            cg.answer_review_request(p.directory, p.state, p.item, source=source)

    def test_same_turn_main_and_question_remain_unbound_without_source(self):
        p = self.product
        cg.dispatch(p.host.event("UserPromptSubmit", prompt="请运行 /work/suite.py 的测试。"))
        state = p.host.state()
        before = copy.deepcopy(state)
        with self.assertRaisesRegex(ValueError, "^no_source_bound_commentary$"):
            cg.answer_review_request(p.directory, state, p.item)
        self.assertEqual(state, before)
