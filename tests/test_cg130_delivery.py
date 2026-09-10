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

    def test_persisted_identity_must_be_strict_and_canonical(self) -> None:
        inputs = dict(session_id="s", turn_id="t", work_unit_id="WU1",
                      requirement_ids=["R001", "R002"], source="stop_final_reply",
                      reply_sha256="a" * 64, delivery="delivered")
        for field in ("session_id", "turn_id", "work_unit_id"):
            for value in (True, 1, 1.5, [], {}, "\ud800"):
                with self.subTest(field=field, value=repr(value)):
                    with self.assertRaises(delivery.DeliveryValueError):
                        delivery.canonical_projection(**{**inputs, field: value})
        projection = delivery.canonical_projection(**inputs)
        record = delivery.build_record(projection, resolution="open", sequence=1,
                                       recorded_at="2026-09-10T00:00:00Z")
        for field, value in (("version", "wrong"), ("session_id", True),
                             ("requirement_ids", ["R002", "R001"]),
                             ("requirement_ids", ["R001", "R001", "R002"])):
            with self.subTest(field=field, value=value):
                with self.assertRaises(delivery.DeliveryValueError):
                    delivery.validate_record({**record, field: value})
        for ids in (["\ud800"], ["R" * 201], ["R\n1"]):
            with self.assertRaises(delivery.DeliveryValueError):
                delivery.canonical_projection(**{**inputs, "requirement_ids": ids})
        for ledger in (
            {"schema": delivery.DELIVERY_SCHEMA, "sequence": 0, "records": [record]},
            {"schema": delivery.DELIVERY_SCHEMA, "sequence": 1, "records": [record], "extra": True},
        ):
            with self.assertRaises(delivery.DeliveryValueError):
                delivery.validate_ledger(ledger)

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

    def test_scope_update_does_not_force_reauthorization_or_offer_self(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(self.payload("UserPromptSubmit", turn="t0",
            prompt="暂时不要提交或推送。稍后收到代号再创建待办文件。"))
        self.cg.dispatch(self.payload("UserPromptSubmit", turn="t1", prompt=self.QUESTION_A))
        self.cg.dispatch(self.payload("Stop", turn="t1", last_assistant_message=self.ANSWER_A))
        self.cg.dispatch(self.payload("UserPromptSubmit", turn="t2",
            prompt="现在只列出尚未完成事项，不改文件。"))
        result = self.cg.dispatch(self.payload("UserPromptSubmit", turn="t3", prompt=
            "更新操作范围：允许一次本地提交，以及只向临时本机 bare remote 的 main 做一次普通推送；"
            "这替代此前对应的提交和推送禁令。请更新 sample.txt、提交并推送；其他限制继续有效。"))
        context = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("Ask the root user which existing", context)
        self.assertNotIn("“更新操作范围", context)
        self.assertNotIn("“" + self.QUESTION_A, context)
        state = self.state()
        self.assertEqual(state["requirements"][0]["status"], "pending")
        self.assertEqual(state["supersedes"], [])

    def test_answer_with_inherited_wait_closes_only_question(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(self.payload("UserPromptSubmit", turn="t0", prompt=
            "请修复恢复模块。在我确认模型更换完成前，本任务保持等待。必须运行测试验证。不要推送。"))
        self.cg.dispatch(self.payload("Stop", turn="t0", last_assistant_message="已按要求暂停等待确认。"))
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt=self.QUESTION_A, turn="t1"))
        before = self.state()
        self.assertTrue(self.cg.current_scope_projection(before)["waiting_conditions"])
        for reply in ("我会继续核实这个问题。", "仍未完成。", "是的，但仍需核实后半部分。"):
            self.cg.dispatch(self.payload("Stop", turn="t1", last_assistant_message=reply))
            question = next(i for i in self.state()["requirements"] if i["text"] == self.QUESTION_A)
            self.assertEqual(question["status"], "pending")
        self.assertEqual(self.cg.dispatch(self.payload("Stop", turn="t1",
            last_assistant_message=self.ANSWER_A)), {})
        after = self.state()
        question = next(i for i in after["requirements"] if i["text"] == self.QUESTION_A)
        self.assertEqual(question["status"], "answered")
        self.assertEqual(after["wait_conditions"], before["wait_conditions"])
        self.assertEqual(after["requirements"][0]["status"], "pending")
        self.assertNotEqual(self.ledger()["records"][-1]["resolution"], "verified")
        self.cg.dispatch(self.payload("PreCompact", turn="t1"))
        packet = json.dumps(self.cg.dispatch(self.payload("SessionStart", source="compact", turn="t1")), ensure_ascii=False)
        self.assertNotIn(self.QUESTION_A, packet)
        self.assertIn("修复恢复模块", packet)

    def test_delayed_or_unbound_stop_cannot_answer_a_new_question(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt=self.QUESTION_A, turn="t1"))
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt=self.QUESTION_B, turn="t2"))
        for turn in ("t1", None):
            self.cg.dispatch(self.payload("Stop", turn=turn, last_assistant_message=self.ANSWER_A))
            current = [item for item in self.state()["requirements"] if item["text"] == self.QUESTION_B]
            self.assertEqual(current[0]["status"], "pending")
            record = self.ledger()["records"][-1]
            self.assertEqual(record["delivery"], "delivery_unknown")
            self.assertEqual(record["requirement_ids"], [])
        self.cg.dispatch(self.payload("Stop", turn="t2", last_assistant_message="恢复包包含需求和验收条件。"))
        current = [item for item in self.state()["requirements"] if item["text"] == self.QUESTION_B]
        self.assertEqual(current[0]["status"], "answered")

    def test_subagent_and_malformed_reply_sources_remain_unknown(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt=self.QUESTION_A, turn="t1"))
        for extra in ({"agent_id": "child-1"}, {"response": 7},
                      {"response": "different reply"}):
            self.cg.dispatch(self.payload("Stop", turn="t1",
                last_assistant_message=self.ANSWER_A, **extra))
            question = next(i for i in self.state()["requirements"] if i["text"] == self.QUESTION_A)
            self.assertEqual(question["status"], "pending")
            self.assertEqual(self.ledger()["records"][-1]["delivery"], "delivery_unknown")

    def test_promise_or_explicit_remaining_answer_does_not_close_question(self) -> None:
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt="context-guard on"))
        self.cg.dispatch(self.payload("UserPromptSubmit", prompt=self.QUESTION_A, turn="t1"))
        for reply in ("我会继续核实这个问题。", "是的，但仍需核实后半部分。"):
            self.cg.dispatch(self.payload("Stop", turn="t1", last_assistant_message=reply))
            question = next(i for i in self.state()["requirements"] if i["text"] == self.QUESTION_A)
            self.assertEqual(question["status"], "pending")
            self.assertEqual(self.ledger()["records"][-1]["delivery"], "delivered")

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
