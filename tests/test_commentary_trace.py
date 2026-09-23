import copy
import json
import unittest

from tools.validation.commentary_trace import Unknown, reduce_pair


class PairTests(unittest.TestCase):
    def setUp(self):
        self.question = "Why retain the prior result?"
        self.answer = "Its unchanged inputs allow reuse."
        self.user = {
            "method": "item/completed",
            "params": {
                "threadId": "t",
                "turnId": "u",
                "item": {
                    "type": "userMessage",
                    "id": "user1",
                    "clientId": "client1",
                    "content": [{"type": "text", "text": self.question}],
                },
            },
        }
        self.commentary = {
            "method": "item/completed",
            "params": {
                "threadId": "t",
                "turnId": "u",
                "item": {
                    "type": "agentMessage",
                    "id": "a1",
                    "phase": "commentary",
                    "text": self.answer,
                },
            },
        }

        def ref(n, k):
            return {
                "raw_payload_id": f"raw_payload:{n}",
                "kind": {"type": k},
                "path": f"payloads/{n}.json",
            }

        self.start = {
            "schema_version": 1,
            "seq": 3,
            "wall_time_unix_ms": 100,
            "rollout_id": "r",
            "thread_id": "t",
            "codex_turn_id": "u",
            "payload": {
                "type": "inference_started",
                "inference_call_id": "c",
                "thread_id": "t",
                "codex_turn_id": "u",
                "request_payload": ref(1, "inference_request"),
            },
        }
        self.done = {
            "schema_version": 1,
            "seq": 4,
            "wall_time_unix_ms": 1,
            "rollout_id": "r",
            "thread_id": "t",
            "codex_turn_id": "u",
            "payload": {
                "type": "inference_completed",
                "inference_call_id": "c",
                "response_id": "res",
                "response_payload": ref(2, "inference_response"),
            },
        }
        self.req = {
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": self.question}],
                }
            ]
        }
        self.res = {
            "response_id": "res",
            "output_items": [
                {
                    "type": "message",
                    "role": "assistant",
                    "id": "a1",
                    "phase": "commentary",
                    "content": [{"type": "output_text", "text": self.answer}],
                }
            ],
        }

    def run_pair(self):
        return reduce_pair(
            [self.done, self.user, self.start],
            {
                "payloads/1.json": json.dumps(self.req).encode(),
                "payloads/2.json": json.dumps(self.res).encode(),
            },
            thread="t",
            turn="u",
            client_id="client1",
            question=self.question,
            commentary=self.commentary,
        )

    def test_pair_not_semantic_or_native_acceptance(self):
        r = self.run_pair()
        self.assertEqual(r["pair"]["inference_call_id"], "c")
        self.assertEqual(r["native_acceptance"], "not_established")
        self.assertFalse(r["core_closure"])

    def test_official_empty_text_elements(self):
        self.user["params"]["item"]["content"][0]["text_elements"] = []
        self.assertFalse(self.run_pair()["core_closure"])

    def test_nonempty_text_elements_unsupported(self):
        self.user["params"]["item"]["content"][0]["text_elements"] = [
            {"byteRange": {"start": 0, "end": 2}}
        ]
        with self.assertRaises(Unknown):
            self.run_pair()

    def test_steer_client_id_mismatch(self):
        self.user["params"]["item"]["clientId"] = "foreign"
        with self.assertRaises(Unknown):
            self.run_pair()

    def test_same_text_distinct_user_cannot_borrow_consumed_input(self):
        for field, value in (("clientId", "second-client"), ("id", "second-user")):
            other = copy.deepcopy(self.user)
            other["params"]["item"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                Unknown, "ambiguous_same_text_user_source|conflicting_user_event"
            ):
                reduce_pair(
                    [self.user, other, self.start, self.done],
                    {"payloads/1.json": json.dumps(self.req).encode(),
                     "payloads/2.json": json.dumps(self.res).encode()},
                    thread="t", turn="u", client_id="client1",
                    question=self.question, commentary=self.commentary,
                )

    def test_same_text_prior_turn_and_empty_text_elements_remain_ambiguous(self):
        old = copy.deepcopy(self.user)
        old["params"]["turnId"] = "old-turn"
        old["params"]["item"].update(id="old-user", clientId="old-client")
        old["params"]["item"]["content"][0]["text_elements"] = []
        with self.assertRaisesRegex(Unknown, "ambiguous_same_text_user_source"):
            reduce_pair(
                [old, self.user, self.start, self.done],
                {"payloads/1.json": json.dumps(self.req).encode(),
                 "payloads/2.json": json.dumps(self.res).encode()},
                thread="t", turn="u", client_id="client1",
                question=self.question, commentary=self.commentary,
            )

    def test_incremental_ancestor_only_unknown(self):
        self.req = {"previous_response_id": "older", "input": []}
        with self.assertRaises(Unknown):
            self.run_pair()

    def test_quoted_question_not_user_input(self):
        self.req["input"][0]["role"] = "assistant"
        with self.assertRaises(Unknown):
            self.run_pair()

    def test_foreign_turn(self):
        self.done["codex_turn_id"] = "other"
        with self.assertRaises(Unknown):
            self.run_pair()

    def test_wrong_response_identity(self):
        self.res["response_id"] = "other"
        with self.assertRaises(Unknown):
            self.run_pair()

    def test_same_text_wrong_item(self):
        self.res["output_items"][0]["id"] = "other"
        with self.assertRaises(Unknown):
            self.run_pair()

    def test_final_phase_not_commentary(self):
        self.res["output_items"][0]["phase"] = "final_answer"
        with self.assertRaises(Unknown):
            self.run_pair()

    def test_traversal_and_missing_payload(self):
        for path in [
            "../1.json",
            "payloads/0.json",
            "payloads/999.json",
            "payloads/1.json/../../secret",
        ]:
            with self.subTest(path=path):
                self.start["payload"]["request_payload"]["path"] = path
                with self.assertRaises(Unknown):
                    self.run_pair()

    def test_conflicting_duplicate_rejected(self):
        bad = copy.deepcopy(self.start)
        bad["payload"]["thread_id"] = "other"
        with self.assertRaises(Unknown):
            reduce_pair(
                [self.user, self.start, bad, self.done],
                {},
                thread="t",
                turn="u",
                client_id="client1",
                question=self.question,
                commentary=self.commentary,
            )


if __name__ == "__main__":
    unittest.main()


class SnapshotTests(unittest.TestCase):
    def test_strict_json_domains(self):
        from tools.validation import commentary_trace as t

        for raw in (
            b'{"x":1,"x":2}',
            b'{"x":NaN}',
            b'{"x":1e999}',
            b'"\\ud800"',
            b"[" * 40 + b"0" + b"]" * 40,
        ):
            with self.assertRaises(t.Unknown):
                t.decode(raw)
        self.assertEqual(t.decode(b'{"x":0.25}'), {"x": 0.25})

    def test_cold_snapshot_paths_sequences_and_conflicts(self):
        import tempfile
        from pathlib import Path

        from tools.validation import commentary_trace as t

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / "payloads").mkdir()
            (root / "payloads/1.json").write_bytes(b'{"input":[]}')
            row = {
                "schema_version": 1,
                "seq": 1,
                "rollout_id": "r",
                "payload": {
                    "type": "inference_started",
                    "request_payload": {
                        "path": "payloads/1.json",
                        "kind": {"type": "inference_request"},
                        "raw_payload_id": "raw_payload:1",
                    },
                },
            }
            raw = json.dumps(row).encode() + b"\n"
            log = root / "events.jsonl"
            log.write_bytes(raw)
            events, payloads, hashes = t.load_snapshot(root, log.name)
            self.assertEqual(len(events), 1)
            self.assertEqual(payloads["payloads/1.json"], b'{"input":[]}')
            self.assertEqual(len(hashes), 2)
            for bad in (raw[:-1], raw + raw):
                log.write_bytes(bad)
                with self.assertRaises(t.Unknown):
                    t.load_snapshot(root, log.name)
            log.write_bytes(raw)
            for path in ("../secret.json", "payloads/01.json", "/tmp/secret.json"):
                with self.assertRaises(t.Unknown):
                    t.stable_read(root, path)
            (root / "payloads/1.json").unlink()
            try:
                (root / "payloads/1.json").symlink_to(log)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(t.Unknown):
                t.load_snapshot(root, log.name)
