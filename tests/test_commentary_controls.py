"""Adversarial zero-model checks for the bounded native control oracle."""

import tempfile
import unittest
from pathlib import Path

from tools.validation.commentary_controls import (
    ControlError,
    ControlOracle,
    ControlPending,
    c2_root_sources,
    c2_wait_status,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
C2_MAIN = "只有 CG142-CONFIRM-17 才可调用 business。"
C2_FUTURE = "只有 future-observation.json 存在后才分析。"
C2_PROMPT = C2_MAIN + C2_FUTURE


def c2_sources():
    main_end = len(C2_MAIN.encode("utf-8"))
    return {"prompt": C2_PROMPT, "main_span": [0, main_end],
            "future_span": [main_end, len(C2_PROMPT.encode("utf-8"))]}


def projection(*, main_current, product_digest=DIGEST_B):
    current = ["R002"]
    if main_current:
        current.append("R001")
    return {"current_item_ids": current,
            "answer_reviews": {"R002": {"coverage": "partial"}},
            "requirements_sha256": DIGEST_A,
            "product_projection_sha256": product_digest}


class CommentaryControlOracleTests(unittest.TestCase):
    def test_c1_requires_real_partial_then_business_auto_compact_and_cold(self):
        oracle = ControlOracle("C1", started_ns=1)
        oracle.c1_partial(
            now_ns=2, question_message_id="user-2", answer_message_id="answer-1",
            answer_text="第一问是 49。", reviewer_verdict="partial",
            question_id="R002", main_id="R001", projection=projection(main_current=True),
        )
        oracle.c1_business(now_ns=3, call_id="business-1", nonce="fresh",
                           expected_nonce="fresh", rows_verified=128,
                           suite_succeeded=True, projection=projection(main_current=True))
        oracle.c1_compaction(now_ns=4, trigger="auto", completed_item_id="compact-1",
                             matching_hook_item_id="compact-1",
                             projection=projection(main_current=True))
        oracle.c1_cold(now_ns=5, projection=projection(main_current=True))
        self.assertEqual(oracle.stage, "passed")
        self.assertEqual((oracle.review_count, oracle.business_count), (1, 1))

    def test_c1_unknown_full_answer_and_false_compact_do_not_pass(self):
        for verdict, text in (("complete", "第一问是 49。"),
                              ("partial", "49，121。"),
                              ("partial", "149 是结果。")):
            with self.subTest(verdict=verdict, text=text):
                oracle = ControlOracle("C1", started_ns=1)
                with self.assertRaises(ControlError):
                    oracle.c1_partial(
                        now_ns=2, question_message_id="u", answer_message_id="a",
                        answer_text=text, reviewer_verdict=verdict,
                        question_id="R002", main_id="R001",
                        projection=projection(main_current=True),
                    )
        for trigger, hook in (("manual", "compact"), ("auto", "foreign")):
            oracle = ControlOracle("C1", started_ns=1)
            oracle.c1_partial(now_ns=2, question_message_id="u", answer_message_id="a",
                              answer_text="第一问是 49。", reviewer_verdict="partial", question_id="R002",
                              main_id="R001", projection=projection(main_current=True))
            oracle.c1_business(now_ns=3, call_id="b", nonce="fresh",
                               expected_nonce="fresh", rows_verified=128,
                               suite_succeeded=True, projection=projection(main_current=True))
            with self.subTest(trigger=trigger, hook=hook), self.assertRaises(ControlError):
                oracle.c1_compaction(
                    now_ns=4, trigger=trigger, completed_item_id="compact",
                    matching_hook_item_id=hook,
                    projection=projection(main_current=True),
                )
        unknown = ControlOracle("C1", started_ns=1)
        with self.assertRaises(ControlPending):
            unknown.c1_partial(
                now_ns=2, question_message_id="u", answer_message_id="a",
                answer_text="第一问是 49。", reviewer_verdict="unknown", question_id="R002",
                main_id="R001", projection=projection(main_current=True),
            )
        self.assertEqual(unknown.stage, "pending")

    def test_c1_preserves_partial_product_and_nonextending_deadline(self):
        oracle = ControlOracle("C1", started_ns=1)
        with self.assertRaisesRegex(ControlError, "whole_session_deadline"):
            oracle.c1_partial(
                now_ns=oracle.deadline_ns + 1, question_message_id="u",
                answer_message_id="a", answer_text="第一问是 49。", reviewer_verdict="partial",
                question_id="R002", main_id="R001", projection=projection(main_current=True),
            )
        other = ControlOracle("C1", started_ns=1)
        with self.assertRaisesRegex(ControlError, "product_projection_mismatch"):
            other.c1_partial(
                now_ns=2, question_message_id="u", answer_message_id="a",
                answer_text="第一问是 49。", reviewer_verdict="partial", question_id="R002",
                main_id="R001", projection=projection(main_current=False),
            )

    def test_c1_clock_rejects_before_start_and_backward_events(self):
        early = ControlOracle("C1", started_ns=10)
        with self.assertRaisesRegex(ControlError, "whole_session_deadline"):
            early.c1_partial(
                now_ns=9, question_message_id="u", answer_message_id="a",
                answer_text="第一问是 49。", reviewer_verdict="partial",
                question_id="R002", main_id="R001", projection=projection(main_current=True),
            )
        self.assertEqual(early.stage, "failed")
        backward = ControlOracle("C1", started_ns=10)
        backward.c1_partial(
            now_ns=20, question_message_id="u", answer_message_id="a",
            answer_text="第一问是 49。", reviewer_verdict="partial",
            question_id="R002", main_id="R001", projection=projection(main_current=True),
        )
        with self.assertRaisesRegex(ControlError, "whole_session_deadline"):
            backward.c1_business(now_ns=19, call_id="b", nonce="fresh",
                                 expected_nonce="fresh", rows_verified=128,
                                 suite_succeeded=True,
                                 projection=projection(main_current=True))

    def test_c1_compact_keeps_real_main_status_after_business(self):
        oracle = ControlOracle("C1", started_ns=1)
        oracle.c1_partial(
            now_ns=2, question_message_id="u", answer_message_id="a",
            answer_text="第一问是 49。", reviewer_verdict="partial",
            question_id="R002", main_id="R001", projection=projection(main_current=True),
        )
        oracle.c1_business(now_ns=3, call_id="b", nonce="fresh",
                           expected_nonce="fresh", rows_verified=128,
                           suite_succeeded=True, projection=projection(main_current=False))
        oracle.c1_compaction(now_ns=4, trigger="auto", completed_item_id="compact",
                             matching_hook_item_id="compact",
                             projection=projection(main_current=False))
        oracle.c1_cold(now_ns=5, projection=projection(main_current=False))
        self.assertEqual(oracle.stage, "passed")

    def test_c2_general_resume_cannot_release_but_exact_confirmation_does(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "future-observation.json"
            negative = ControlOracle("C2", started_ns=1, future_path=path)
            negative.c2_root(now_ns=2, message_id="root", main_id="R001",
                             future_id="R002", main_wait="CG142-CONFIRM-17",
                             future_wait=str(path), business_requests=0,
                             wait_id="WC0001", wait_status="waiting", **c2_sources())
            with self.assertRaises(ControlError):
                negative.c2_general_resume(
                    now_ns=3, message_id="general", text="继续；请只报告现在能确认的状态。",
                    business_requests=1, main_wait="CG142-CONFIRM-17",
                    future_wait=str(path), wait_id="WC0001", wait_status="waiting",
                )
            self.assertEqual(negative.stage, "failed")
            oracle = ControlOracle("C2", started_ns=1, future_path=path)
            oracle.c2_root(now_ns=2, message_id="root", main_id="R001",
                           future_id="R002", main_wait="CG142-CONFIRM-17",
                           future_wait=str(path), business_requests=0,
                           wait_id="WC0001", wait_status="waiting", **c2_sources())
            oracle.c2_general_resume(
                now_ns=3, message_id="general", text="继续；请只报告现在能确认的状态。",
                business_requests=0, main_wait="CG142-CONFIRM-17", future_wait=str(path),
                wait_id="WC0001", wait_status="waiting",
            )
            wrong_confirmation = ControlOracle("C2", started_ns=1, future_path=path)
            wrong_confirmation.c2_root(now_ns=2, message_id="root", main_id="R001",
                                       future_id="R002", main_wait="CG142-CONFIRM-17",
                                       future_wait=str(path), business_requests=0,
                                       wait_id="WC0001", wait_status="waiting",
                                       **c2_sources())
            wrong_confirmation.c2_general_resume(
                now_ns=3, message_id="general", text="继续；请只报告现在能确认的状态。",
                business_requests=0, main_wait="CG142-CONFIRM-17", future_wait=str(path),
                wait_id="WC0001", wait_status="waiting",
            )
            with self.assertRaises(ControlError):
                wrong_confirmation.c2_confirmation(now_ns=4, message_id="almost",
                                                   text="继续", future_wait=str(path),
                                                   business_requests=0, wait_id="WC0001",
                                                   wait_status="waiting")
            oracle.c2_confirmation(now_ns=4, message_id="exact",
                                   text="CG142-CONFIRM-17", future_wait=str(path),
                                   business_requests=0, wait_id="WC0001",
                                   wait_status="released")
            oracle.c2_business(now_ns=5, call_id="business-1", nonce="fresh",
                               expected_nonce="fresh", succeeded=True,
                               future_wait=str(path), business_requests=1)
            self.assertEqual((oracle.stage, oracle.business_count, oracle.review_count),
                             ("passed", 1, 0))
            with self.assertRaises(ControlError):
                oracle.c2_business(now_ns=6, call_id="business-2", nonce="fresh",
                                   expected_nonce="fresh", succeeded=True,
                                   future_wait=str(path), business_requests=2)

    def test_c2_future_file_or_missing_release_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "future-observation.json"
            oracle = ControlOracle("C2", started_ns=1, future_path=path)
            oracle.c2_root(now_ns=2, message_id="root", main_id="R001",
                           future_id="R002", main_wait="CG142-CONFIRM-17",
                           future_wait=str(path), business_requests=0,
                           wait_id="WC0001", wait_status="waiting", **c2_sources())
            oracle.c2_general_resume(
                now_ns=3, message_id="general", text="继续；请只报告现在能确认的状态。",
                business_requests=0, main_wait="CG142-CONFIRM-17", future_wait=str(path),
                wait_id="WC0001", wait_status="waiting",
            )
            oracle.c2_confirmation(now_ns=4, message_id="exact",
                                   text="CG142-CONFIRM-17", future_wait=str(path),
                                   business_requests=0, wait_id="WC0001",
                                   wait_status="released")
            self.assertNotEqual(oracle.stage, "passed")
            with self.assertRaisesRegex(ControlError, "release_or_future_wait"):
                oracle.c2_business(now_ns=5, call_id="business", nonce="fresh",
                                   expected_nonce="fresh", succeeded=False,
                                   future_wait=str(path), business_requests=1)
            other = ControlOracle("C2", started_ns=1, future_path=path)
            path.write_text("{}")
            with self.assertRaisesRegex(ControlError, "future_observation_present"):
                other.c2_root(now_ns=2, message_id="root", main_id="R001",
                              future_id="R002", main_wait="CG142-CONFIRM-17",
                              future_wait=str(path), business_requests=0,
                              wait_id="WC0001", wait_status="waiting", **c2_sources())

    def test_c2_rejects_overlapping_or_unbound_source_spans(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "future-observation.json"
            for changed in (
                {"main_span": [0, 1]},
                {"future_span": [0, len(C2_MAIN.encode("utf-8"))]},
                {"main_span": [1, 2]},
            ):
                with self.subTest(changed=changed):
                    oracle = ControlOracle("C2", started_ns=1, future_path=path)
                    source = {**c2_sources(), **changed}
                    with self.assertRaises(ControlError):
                        oracle.c2_root(
                            now_ns=2, message_id="root", main_id="R001",
                            future_id="R002", main_wait="CG142-CONFIRM-17",
                            future_wait=str(path), business_requests=0,
                            wait_id="WC0001", wait_status="waiting", **source,
                        )
                    self.assertEqual(oracle.stage, "failed")

    def test_c2_sources_bind_real_product_clauses_and_token_wait(self):
        from tests.test_current_action_grounding import CurrentActionGroundingTests

        host = CurrentActionGroundingTests()
        host.setUp()
        self.addCleanup(host.tearDown)
        suite = host.root / "suite.py"
        suite.write_text("def test_case(): assert True\n", encoding="utf-8")
        future = host.root / "future-observation.json"
        prompt = (
            f'只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行 "{suite}" 的测试。'
            f'今后再观察 "{future}" 的性能变化；当前文件不存在。'
        )
        host.submit(prompt)
        source = c2_root_sources(host.state(), prompt, future)
        self.assertNotEqual(source["main_id"], source["future_id"])
        self.assertEqual(c2_wait_status(host.state(), source["wait_id"]), "waiting")
        host.submit("继续；请只报告现在能确认的状态。")
        self.assertEqual(c2_wait_status(host.state(), source["wait_id"]), "waiting")
        host.submit("CG142-CONFIRM-17")
        self.assertEqual(c2_wait_status(host.state(), source["wait_id"]), "released")


if __name__ == "__main__":
    unittest.main()
