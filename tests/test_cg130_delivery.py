"""0.13 failure-family suite: response delivery versus completion.

Covers the frozen plan section 4.5 contract (CG130-01 family, matrix rows
T05/T06/T07):

* canonical ``response-delivery/v1`` vectors — domain-separated digest,
  UTF-8-byte requirement ordering, strict typing, closed-world validation;
* the question/answer lifecycle: a delivered natural answer closes the
  question as ``answered`` WITHOUT a checkpoint, later questions stay
  current, and compaction recovery never re-injects the delivered question;
* delivered is NOT verified: a promise reply keeps execution obligations
  open; unknown reply sources record ``delivery_unknown`` and never close
  anything; a Guard-blocked candidate reply is not delivered while the
  corrected reply within the same turn is, with no unbounded ledger growth.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "context_guard.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


delivery = _load("cg_delivery_module", ROOT / "scripts" / "cg_delivery.py")


class CanonicalVectorTests(unittest.TestCase):
    """Frozen response-delivery/v1 canonicalization vectors (plan 4.5)."""

    def test_known_digest_vector_is_stable(self) -> None:
        projection = delivery.canonical_projection(
            session_id="session-A",
            turn_id="turn-1",
            work_unit_id="WU0001",
            requirement_ids=["R002", "R001", "R002"],
            source="stop_final_reply",
            reply_sha256="a" * 64,
            delivery="delivered",
        )
        # UTF-8 byte order, deduplicated.
        self.assertEqual(projection["requirement_ids"], ["R001", "R002"])
        digest = delivery.delivery_digest(projection)
        # Domain separation: the domain prefix and NUL are part of the
        # preimage; the manual recomputation is the fixed golden vector.
        manual = __import__("hashlib").sha256(
            b"context-guard/response-delivery/v1\x00"
            + json.dumps(
                projection, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        ).hexdigest()
        self.assertEqual(digest, manual)
        self.assertEqual(digest, delivery.delivery_digest(projection))

    def test_unicode_is_preserved_not_escaped(self) -> None:
        projection = delivery.canonical_projection(
            session_id="会话-01",
            turn_id="turn-1",
            work_unit_id=None,
            requirement_ids=["R001"],
            source="stop_final_reply",
            reply_sha256="b" * 64,
            delivery="delivered",
        )
        raw = delivery.canonical_json_bytes(projection)
        self.assertIn("会话-01".encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)

    def test_floats_and_non_string_keys_are_rejected(self) -> None:
        with self.assertRaises(delivery.DeliveryValueError):
            delivery.canonical_json_bytes({"score": 0.5})
        with self.assertRaises(delivery.DeliveryValueError):
            delivery.canonical_json_bytes({1: "x"})

    def test_closed_world_record_validation(self) -> None:
        projection = delivery.canonical_projection(
            session_id="s", turn_id="t", work_unit_id=None,
            requirement_ids=[], source="migration_reconstruction",
            reply_sha256="c" * 64, delivery="delivered",
        )
        record = delivery.build_record(
            projection, resolution="open", sequence=1, recorded_at="2026-09-10T00:00:00Z"
        )
        delivery.validate_record(record)
        delivery.validate_ledger(
            {"schema": delivery.DELIVERY_SCHEMA, "sequence": 1, "records": [record]}
        )
        # Extra keys are refused, not ignored.
        tainted = dict(record)
        tainted["note"] = "extra"
        with self.assertRaises(delivery.DeliveryValueError):
            delivery.validate_record(tainted)
        # Delivered without a digest is refused; unknown with one is refused.
        with self.assertRaises(delivery.DeliveryValueError):
            delivery.canonical_projection(
                session_id="s", turn_id="t", work_unit_id=None,
                requirement_ids=[], source="stop_final_reply",
                reply_sha256=None, delivery="delivered",
            )
        with self.assertRaises(delivery.DeliveryValueError):
            delivery.canonical_projection(
                session_id="s", turn_id="t", work_unit_id=None,
                requirement_ids=[], source="stop_final_reply",
                reply_sha256="d" * 64, delivery="delivery_unknown",
            )

    def test_idempotency_key_follows_association_and_reply(self) -> None:
        base = dict(
            session_id="s", turn_id="t", work_unit_id="WU0001",
            requirement_ids=["R001"], source="stop_final_reply",
        )
        first = delivery.canonical_projection(
            reply_sha256="e" * 64, delivery="delivered", **base
        )
        replay = delivery.canonical_projection(
            reply_sha256="e" * 64, delivery="delivered", **base
        )
        corrected = delivery.canonical_projection(
            reply_sha256="f" * 64, delivery="delivered", **base
        )
        self.assertEqual(
            delivery.idempotency_key(first), delivery.idempotency_key(replay)
        )
        self.assertNotEqual(
            delivery.idempotency_key(first), delivery.idempotency_key(corrected)
        )


class DeliveryLifecycleHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.data_dir = Path(tempfile.mkdtemp())
        patcher = mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.data_dir / "private")}
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        spec = importlib.util.spec_from_file_location("cg_del_lifecycle", ENTRY)
        self.cg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.cg)

    def payload(self, event, *, turn="t1", **kwargs):
        payload = {
            "hook_event_name": event,
            "session_id": "delivery-suite",
            "cwd": str(self.data_dir),
            "turn_id": turn,
        }
        payload.update(kwargs)
        return payload

    def state(self):
        return self.cg.load_state(
            self.data_dir / "private" / "sessions" / "delivery-suite",
            self.payload("Stop"),
        )

    def ledger(self):
        return self.state()["response_delivery"]


class QuestionAnswerLifecycleTests(DeliveryLifecycleHarness):
    """T05: A answered, B current, recovery never replays the old question."""

    QUESTION_A = "Context Guard 是这个插件的名称吗？"
    ANSWER_A = "是的，Context Guard 是这个插件的名称。"
    QUESTION_B = "这个插件的恢复包里有什么内容？"

    def test_delivered_answer_closes_question_and_survives_compaction(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(
            self.payload("UserPromptSubmit", prompt=self.QUESTION_A, turn="t1")
        )
        result = self.cg.dispatch(
            self.payload(
                "Stop", turn="t1", last_assistant_message=self.ANSWER_A
            )
        )
        self.assertEqual(result, {})
        state = self.state()
        self.assertEqual(state["requirements"][0]["status"], "answered")
        records = state["response_delivery"]["records"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["delivery"], "delivered")
        self.assertEqual(records[0]["source"], "stop_final_reply")
        self.assertEqual(records[0]["resolution"], "not_applicable")
        self.assertEqual(records[0]["requirement_ids"], ["R001"])
        # Audit retains the delivered answer's digest binding, never the text.
        self.assertNotIn(self.ANSWER_A, json.dumps(records))

        # Question B arrives, then a real compaction and resume.
        self.cg.dispatch(
            self.payload("UserPromptSubmit", prompt=self.QUESTION_B, turn="t2")
        )
        self.cg.dispatch(self.payload("PreCompact", turn="t2"))
        resumed = self.cg.dispatch(
            self.payload("SessionStart", source="compact", turn="t2")
        )
        packet = json.dumps(resumed, ensure_ascii=False)
        self.assertNotIn("是这个插件的名称吗", packet)
        self.assertIn("恢复包里有什么内容", packet)
        projection = self.cg.current_scope_projection(self.state())
        self.assertNotIn("R001", projection["current_item_ids"])
        self.assertIn("R002", projection["current_item_ids"])

    def test_repeated_stop_replay_does_not_grow_the_ledger(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(
            self.payload("UserPromptSubmit", prompt=self.QUESTION_A, turn="t1")
        )
        for _ in range(3):
            self.cg.dispatch(
                self.payload("Stop", turn="t1", last_assistant_message=self.ANSWER_A)
            )
        self.assertEqual(len(self.ledger()["records"]), 1)

    def test_unknown_reply_source_records_delivery_unknown(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(
            self.payload("UserPromptSubmit", prompt=self.QUESTION_A, turn="t1")
        )
        self.cg.dispatch(self.payload("Stop", turn="t1"))
        records = self.ledger()["records"]
        self.assertEqual(records[-1]["delivery"], "delivery_unknown")
        self.assertIsNone(records[-1]["reply_sha256"])
        # Nothing was closed: the obligation view is unchanged.
        self.assertEqual(self.state()["requirements"][0]["status"], "pending")


class DeliveredIsNotVerifiedTests(DeliveryLifecycleHarness):
    """T06: a promise reply keeps known execution obligations open."""

    def test_promise_reply_never_passes_execution_obligations(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(
            self.payload(
                "UserPromptSubmit",
                prompt="修复登录缺陷并运行测试验证。",
                turn="t1",
            )
        )
        self.cg.dispatch(
            self.payload(
                "Stop",
                turn="t1",
                last_assistant_message="我会处理这个缺陷，稍后继续。",
            )
        )
        state = self.state()
        self.assertEqual(state["requirements"][0]["status"], "pending")
        records = state["response_delivery"]["records"]
        self.assertEqual(records[-1]["delivery"], "delivered")
        # Delivered but NOT verified: no item silently became pass.
        self.assertNotEqual(records[-1]["resolution"], "verified")
        for collection in ("requirements", "acceptance_items"):
            for item in state[collection]:
                self.assertNotEqual(item["status"], "pass")

    def test_blocked_candidate_is_not_delivered_corrected_reply_is(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(
            self.payload(
                "UserPromptSubmit",
                prompt=(
                    "请修复模块、修复文档、修复测试三件事。必须逐项落实。"
                    "必须运行测试验证。不要停止,一直推进直到完成。"
                ),
                turn="t1",
            )
        )
        blocked = self.cg.dispatch(
            self.payload(
                "Stop",
                turn="t1",
                last_assistant_message="我会继续修复模块和文档,并运行测试。",
            )
        )
        # Persistence + remaining authorized assistant work draws the
        # single visible correction: the candidate reply is NOT delivered.
        self.assertEqual(blocked.get("decision"), "block")
        deliveries = [
            record
            for record in self.ledger()["records"]
            if record["delivery"] == "delivered"
        ]
        self.assertEqual(deliveries, [])
        # The corrected same-turn reply IS delivered (event order kept).
        self.cg.dispatch(
            self.payload(
                "Stop",
                turn="t1",
                last_assistant_message="模块已修复,文档与测试仍在进行。",
            )
        )
        records = self.ledger()["records"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[-1]["delivery"], "delivered")
        self.assertEqual(records[-1]["resolution"], "open")


if __name__ == "__main__":
    unittest.main()
