import copy
import json
import unittest

from tools.validation.commentary_fixture import Unknown, marker, pair


class HookPairTests(unittest.TestCase):
    def setUp(self):
        self.value = {
            "session_id": "t",
            "hook_event_name": "SessionStart",
            "source": "compact",
        }
        self.cid = "a" * 32
        self.raw = json.dumps(self.value).encode()
        self.notification = {
            "method": "hook/completed",
            "params": {
                "threadId": "t",
                "turnId": "u",
                "run": {
                    "id": "run1",
                    "eventName": "sessionStart",
                    "status": "completed",
                    "handlerType": "command",
                    "executionMode": "sync",
                    "sourcePath": "/fixture/hooks.json",
                    "entries": [
                        {"kind": "warning", "text": marker(self.raw, self.cid)}
                    ],
                },
            },
        }

    def check(self, event="SessionStart"):
        return pair(
            self.raw,
            self.cid,
            self.notification,
            thread="t",
            turn="u",
            source_path="/fixture/hooks.json",
            event=event,
        )

    def test_pair_does_not_establish_trust_or_native(self):
        r = self.check()
        self.assertEqual(r["trust"], "not_established")
        self.assertEqual(r["native_acceptance"], "not_established")

    def test_identical_input_distinct_invocation(self):
        self.cid = "b" * 32
        with self.assertRaises(Unknown):
            self.check()

    def test_mutated_raw(self):
        self.raw += b" "
        with self.assertRaises(Unknown):
            self.check()

    def test_startup_resume_rejected(self):
        for source in ["startup", "resume"]:
            self.value["source"] = source
            self.raw = json.dumps(self.value).encode()
            self.notification["params"]["run"]["entries"][0]["text"] = marker(
                self.raw, self.cid
            )
            with self.assertRaises(Unknown):
                self.check()

    def test_absent_turn_cannot_use_raw_source(self):
        self.notification["params"]["turnId"] = None
        with self.assertRaises(Unknown):
            self.check()

    def test_context_echo_not_warning(self):
        self.notification["params"]["run"]["entries"][0]["kind"] = "context"
        with self.assertRaises(Unknown):
            self.check()

    def test_extra_control_effect_rejected(self):
        self.notification["params"]["run"]["entries"].append(
            {"kind": "stop", "text": "stop"}
        )
        with self.assertRaises(Unknown):
            self.check()

    def test_foreign_source_rejected(self):
        self.notification["params"]["run"]["sourcePath"] = "/other/hooks.json"
        with self.assertRaises(Unknown):
            self.check()

    def test_precompact_requires_actual_auto_and_turn(self):
        self.value = {
            "session_id": "t",
            "turn_id": "u",
            "hook_event_name": "PreCompact",
            "trigger": "auto",
        }
        self.raw = json.dumps(self.value).encode()
        self.notification["params"]["run"]["eventName"] = "preCompact"
        self.notification["params"]["run"]["entries"][0]["text"] = marker(
            self.raw, self.cid
        )
        self.assertEqual(self.check("PreCompact")["event"], "PreCompact")
        for field, v in [("trigger", "manual"), ("turn_id", "foreign")]:
            value = copy.deepcopy(self.value)
            value[field] = v
            self.raw = json.dumps(value).encode()
            self.notification["params"]["run"]["entries"][0]["text"] = marker(
                self.raw, self.cid
            )
            with self.assertRaises(Unknown):
                self.check("PreCompact")


if __name__ == "__main__":
    unittest.main()


class FixtureBoundaries(unittest.TestCase):
    def test_run_capture_bijection_and_exact_repeat(self):
        from tools.validation import commentary_fixture as f

        h = HookPairTests()
        h.setUp()
        pairs = f.HookPairs()
        scope = dict(
            thread="t",
            turn="u",
            source_path="/fixture/hooks.json",
            event="SessionStart",
        )
        first = pairs.observe(h.raw, h.cid, h.notification, **scope)
        self.assertEqual(first, pairs.observe(h.raw, h.cid, h.notification, **scope))
        other = copy.deepcopy(h.notification)
        other["params"]["run"]["id"] = "other"
        with self.assertRaisesRegex(f.Unknown, "replayed"):
            pairs.observe(h.raw, h.cid, other, **scope)
        other = copy.deepcopy(h.notification)
        cid = "b" * 32
        other["params"]["run"]["entries"][0]["text"] = f.marker(h.raw, cid)
        with self.assertRaisesRegex(f.Unknown, "run_rebound"):
            pairs.observe(h.raw, cid, other, **scope)

    def test_effective_config_requires_matching_supported_values(self):
        from tools.validation import commentary_fixture as f

        config = {
            "model_auto_compact_token_limit": 4096,
            "model_auto_compact_token_limit_scope": "body_after_prefix",
        }
        self.assertEqual(config, f.effective_config(config, dict(config)))
        for value in (
            {},
            {**config, "model_auto_compact_token_limit": True},
            {**config, "model_auto_compact_token_limit_scope": "total"},
            {**config, "model_auto_compact_token_limit": 2048},
        ):
            with self.subTest(value=value), self.assertRaises(f.Unknown):
                f.effective_config(config, value)

    def test_frozen_threshold_and_all_trigger_outcomes(self):
        from tools.validation import commentary_fixture as f

        self.assertEqual(
            f.threshold_basis(
                limit=4096, fallback_buffer=0, before_business=1024, after_business=5000
            )["effective_threshold"],
            4096,
        )
        for before, after in [(4096, 5000), (1024, 4095), (5000, 1024)]:
            with self.assertRaises(f.Unknown):
                f.threshold_basis(
                    limit=4096,
                    fallback_buffer=0,
                    before_business=before,
                    after_business=after,
                )
        h = HookPairTests()
        h.setUp()
        post = {"raw": h.raw, "capture_id": h.cid, "notification": h.notification}
        raw = json.dumps(
            {
                "session_id": "t",
                "turn_id": "u",
                "hook_event_name": "PreCompact",
                "trigger": "auto",
            }
        ).encode()
        notification = copy.deepcopy(h.notification)
        notification["params"]["run"].update(
            id="pre-run",
            eventName="preCompact",
            entries=[{"kind": "warning", "text": f.marker(raw, "b" * 32)}],
        )
        pre = {"raw": raw, "capture_id": "b" * 32, "notification": notification}
        result = {"schema": "cg-business-result/v1", "nonce": "fixture"}
        invocation = {
            "type": "function_call",
            "call_id": "business-call",
            "name": "fixture_business",
            "arguments": "{}",
        }
        request = {
            "input": [
                invocation,
                {
                    "type": "function_call_output",
                    "call_id": "business-call",
                    "output": f.canonical(result).decode(),
                },
            ]
        }
        args = dict(
            request=request,
            business_result=result,
            invocation=invocation,
            thread="t",
            turn="u",
            source_path="/fixture/hooks.json",
        )
        self.assertTrue(f.compact_outcome([pre, post], **args)["paired_hook_shapes"])
        list_output = copy.deepcopy(request)
        list_output["input"][-1]["output"] = [{
            "type": "input_text", "text": f.canonical(result).decode(),
        }]
        self.assertTrue(f.compact_outcome(
            [pre, post], **{**args, "request": list_output}
        )["paired_hook_shapes"])
        list_output["input"][-1]["output"].append({
            "type": "input_text", "text": "extra",
        })
        with self.assertRaises(f.Unknown):
            f.compact_outcome([pre, post], **{**args, "request": list_output})
        for captures in (
            [],
            [pre],
            [pre, pre, post],
            [{"event": "PreCompact"}, {"event": "SessionStart"}],
        ):
            with self.assertRaises(f.Unknown):
                f.compact_outcome(captures, **args)
        for change in ("wrong_call", "missing_invocation", "early", "duplicate"):
            altered = copy.deepcopy(request)
            if change == "wrong_call":
                altered["input"][-1]["call_id"] = "unrelated-call"
            elif change == "missing_invocation":
                altered["input"] = altered["input"][1:]
            elif change == "early":
                altered["input"] = []
            else:
                altered["input"].append(altered["input"][-1])
            with self.subTest(change=change), self.assertRaises(f.Unknown):
                f.compact_outcome([pre, post], **{**args, "request": altered})
        foreign = copy.deepcopy(post)
        foreign["notification"]["params"]["turnId"] = "foreign"
        with self.assertRaises(f.Unknown):
            f.compact_outcome([pre, foreign], **args)

    def test_fresh_challenge_real_result_and_independent_oracle(self):
        import tempfile
        from pathlib import Path

        from tools.validation import commentary_fixture as f

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "challenge.json"
            challenge = f.issue_challenge(
                path,
                {"inference_call_id": "c", "response_id": "r", "commentary_id": "a"},
            )
            with self.assertRaises(FileExistsError):
                f.issue_challenge(
                    path,
                    {
                        "inference_call_id": "c",
                        "response_id": "r",
                        "commentary_id": "a",
                    },
                )
            values = [-3, 0, 2]
            output, report = f.business_result(values, challenge)
            self.assertEqual([9, 0, 4], [r["square"] for r in output["rows"]])
            self.assertEqual(
                f.verify_business(values, challenge, output)["rows_verified"], 3
            )
            self.assertLess(len(report.encode()), 65536)
            bad = copy.deepcopy(output)
            bad["rows"][0]["square"] = 8
            with self.assertRaises(f.Unknown):
                f.verify_business(values, challenge, bad)
            bad = {**output, "nonce": "0" * 64}
            with self.assertRaises(f.Unknown):
                f.verify_business(values, challenge, bad)
            for report in ("forged", output["validation_report"][:-1], "x" * 65537):
                bad = {**output, "validation_report": report}
                with self.assertRaises(f.Unknown):
                    f.verify_business(values, challenge, bad)
            for data in ([], [True], list(range(257)), [1000001]):
                with self.assertRaises(f.Unknown):
                    f.verify_business(data, challenge, output)
            for data in ([], [True], list(range(257)), [1000001]):
                with self.assertRaises(f.Unknown):
                    f.business_result(data, challenge)


class ProductReviewProjectionTests(unittest.TestCase):
    def test_partial_postbusiness_allows_main_to_leave_current_but_cold_hashes_bind(self):
        import tempfile
        from pathlib import Path

        from tools.validation import commentary_fixture as f

        class Runtime:
            @staticmethod
            def current_scope_projection(_state, **_kwargs):
                return {"answer_reviews": {"q": {"coverage": "partial"}},
                        "current_item_ids": {"q"}}

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "session"
            directory.mkdir()
            state = {"session": {"id": "session"},
                     "requirements": [{"id": "q"}, {"id": "main"}]}
            with self.assertRaisesRegex(f.Unknown, "review_not_consumed_or_main_lost"):
                f.product_review_checkpoint(
                    Runtime, state, session_dir=directory, codex_home=temporary,
                    question_id="q", main_ids=["main"],
                    expected_coverage="partial",
                )
            after = f.product_review_checkpoint(
                Runtime, state, session_dir=directory, codex_home=temporary,
                question_id="q", main_ids=["main"], expected_coverage="partial",
                expected_main_current=None,
            )
            self.assertEqual(after["question_id"], "q")

    def test_partial_review_stays_current_through_compact_and_cold_load(self):
        from tests import test_answer_review as base
        from tools.validation import commentary_fixture as f

        fixture = base.ConsumerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        host = fixture.host
        host.turn_id = "business-turn"
        base.cg.dispatch(host.event(
            "UserPromptSubmit", prompt="请运行 /work/suite.py 的测试并持续执行直到完成。",
        ))
        main = host.state()["requirements"][-1]["id"]
        question = fixture.item["id"]
        fixture.collect("partial")
        def check():
            return f.product_review_checkpoint(
                base.cg, host.state(), session_dir=fixture.directory,
                codex_home=host.home, question_id=question, main_ids=[main],
                expected_coverage="partial",
            )
        first = check()
        with self.assertRaises(f.Unknown):
            f.product_review_checkpoint(
                base.cg, host.state(), session_dir=fixture.directory,
                codex_home=host.home, question_id=question, main_ids=[main],
            )
        for event, extra in (("PreCompact", {}), ("SessionStart", {"source": "compact"})):
            base.cg.dispatch(host.event(event, **extra))
            self.assertEqual(check(), first)

    def test_real_receipt_consumer_preserves_main_through_hooks(self):
        from tests import test_answer_review as base
        from tools.validation import commentary_fixture as f

        fixture = base.ConsumerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        host = fixture.host
        # Add a real business root; an answer score must not close it.
        host.turn_id = "business-turn"
        base.cg.dispatch(
            host.event(
                "UserPromptSubmit",
                prompt="请运行 /work/suite.py 的测试并持续执行直到完成。",
            )
        )
        state = host.state()
        main = state["requirements"][-1]["id"]
        question = fixture.item["id"]
        with self.assertRaises(f.Unknown):
            f.product_review_checkpoint(
                base.cg, state, session_dir=fixture.directory,
                codex_home=host.home,
                question_id=question, main_ids=[main]
            )
        fixture.collect()  # invokes the production collector with a synthetic model boundary
        checkpoint = f.product_review_checkpoint(
            base.cg, host.state(), session_dir=fixture.directory,
            codex_home=host.home,
            question_id=question, main_ids=[main]
        )
        for event, extra in [
            ("PreCompact", {}),
            ("SessionStart", {"source": "compact"}),
        ]:
            base.cg.dispatch(host.event(event, **extra))
            after = f.product_review_checkpoint(
                base.cg, host.state(), session_dir=fixture.directory,
                codex_home=host.home,
                question_id=question, main_ids=[main]
            )
            self.assertEqual(
                after["requirements_sha256"], checkpoint["requirements_sha256"]
            )
        import subprocess
        import sys
        from pathlib import Path

        script = """
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / 'scripts'))
import context_guard as cg
from tools.validation.commentary_fixture import product_review_checkpoint
args = json.load(sys.stdin)
state = cg.load_state(Path(args['directory']), args['payload'])
print(json.dumps(product_review_checkpoint(cg, state,
    session_dir=Path(args['directory']),
    codex_home=Path(args['home']),
    question_id=args['question'], main_ids=args['main'])))
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            input=json.dumps(
                {
                    "directory": str(fixture.directory),
                    "home": str(host.home),
                    "payload": host.event("Stop"),
                    "question": question,
                    "main": [main],
                }
            ),
            text=True,
            capture_output=True,
            timeout=15,
            cwd=Path(__file__).resolve().parents[1],
            check=True,
        )
        cold = json.loads(result.stdout)
        self.assertEqual(cold["requirements_sha256"], checkpoint["requirements_sha256"])
        self.assertEqual(cold["main_ids"], [main])


class BusinessCommandTests(unittest.TestCase):
    def test_actual_file_output_and_exclusive_second_run(self):
        import subprocess
        import sys
        import tempfile
        from pathlib import Path

        from tools.validation import commentary_fixture as f

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            values = list(range(256))
            (root / "input.json").write_bytes(f.canonical(values))
            challenge = f.issue_challenge(
                root / "challenge.json",
                {"inference_call_id": "c", "response_id": "r", "commentary_id": "a"},
            )
            command = [
                sys.executable,
                "-m",
                "tools.validation.commentary_fixture",
                "--input",
                str(root / "input.json"),
                "--challenge",
                str(root / "challenge.json"),
                "--output",
                str(root / "result.json"),
            ]
            result = subprocess.run(
                command, capture_output=True, check=True, timeout=10
            )
            raw = (root / "result.json").read_bytes()
            self.assertEqual(result.stdout.rstrip(b"\r\n"), raw)
            self.assertLessEqual(len(raw), 65536)
            self.assertEqual(
                f.verify_business(values, challenge, json.loads(raw))["rows_verified"],
                256,
            )
            again = subprocess.run(command, capture_output=True, timeout=10)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual((root / "result.json").read_bytes(), raw)
