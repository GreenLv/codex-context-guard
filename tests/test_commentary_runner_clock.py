"""Wall slew/steps cannot become causal evidence or reset monotonic deadlines."""

import hashlib
import json
import unittest
from unittest.mock import patch

from tests import test_commentary_runner as fixture

runner = fixture.runner


class ClockContractTests(unittest.TestCase):
    setUp = fixture.CommentaryRunnerTests.setUp
    response = staticmethod(fixture.CommentaryRunnerTests.response)
    event = staticmethod(fixture.CommentaryRunnerTests.event)
    item = fixture.CommentaryRunnerTests.item
    message = fixture.CommentaryRunnerTests.message
    hook = fixture.CommentaryRunnerTests.hook
    events = fixture.CommentaryRunnerTests.events

    def capture(self, wall):
        clock = fixture.Clock()
        fake = fixture.Fake(self.events(), clock, self.plan)
        path = (
            self.root
            / "results"
            / ("clock-" + str(len(list((self.root / "results").iterdir()))))
        )
        result = runner.collect(
            self.plan,
            path,
            lambda *_: fake,
            offline=True,
            clock=clock,
            wall=lambda: wall(clock()),
            wall_resolution_ns=1001,
            mono_resolution_ns=42,
        )
        with patch.object(
            runner.time, "time_ns", side_effect=AssertionError("no replay clock")
        ):
            checked = runner.validate(path, path / "validated.json")
        self.assertEqual(checked["status"], result["status"])
        return result, path

    def test_ns_samples_keep_exact_values_without_accuracy_bounds(self):
        samples = iter([10000000000000001, 10000000000000009])
        sample = runner.clock_sample(lambda: next(samples), lambda: 555, 1001, 42)
        self.assertEqual(
            sample,
            {
                "mono_before_ns": 10000000000000001,
                "mono_after_ns": 10000000000000009,
                "wall_ns": 555,
                "wall_resolution_ns": 1001,
                "mono_resolution_ns": 42,
            },
        )
        self.assertNotIn("wall_ns_range", sample)

    def test_slew_and_forward_backward_steps_preserve_dag_and_deadline(self):
        baseline, _ = self.capture(lambda m: 100000000000 + m)
        for wall in (
            lambda m: 100000000000 + m + m // 100000,
            lambda m: 100000000000 + m + (1000000000 if m > 4000000000 else 0),
            lambda m: 100000000000 + m - (1000000000 if m > 4000000000 else 0),
            lambda m: 100000000000 + m // 2,
        ):
            result, _ = self.capture(wall)
            self.assertEqual(result["causal_edges"], baseline["causal_edges"])
            self.assertEqual(result["deadline_ns"], baseline["deadline_ns"])
            self.assertEqual(result["as_of_elapsed_ns"], baseline["as_of_elapsed_ns"])
            self.assertEqual(result["reason"], "causal_chain_not_proven")
            self.assertNotEqual(
                result["clock_diagnostics"], baseline["clock_diagnostics"]
            )

    def test_malformed_or_reversed_monotonic_is_rejected(self):
        first = runner.clock_sample(lambda: 100, lambda: 1000, 1)
        for changed in (
            {},
            {**first, "mono_before_ns": 99},
            {**first, "mono_after_ns": True},
        ):
            machine = runner.Machine(self.plan, first)
            machine.observe_clock(changed)
            self.assertEqual(machine.reason, "clock_sample_missing_or_invalid")

    def test_float_clock_is_rejected_instead_of_inventing_ns_precision(self):
        with self.assertRaises(ValueError):
            runner.clock_sample(lambda: 0.1, lambda: 1, 1)

    def test_replay_rejects_missing_samples_and_elapsed_tampering(self):
        for mutation in ("missing", "elapsed"):
            _, path = self.capture(lambda m: 100000000000 + m)
            rows = [
                json.loads(line)
                for line in (path / "rpc.jsonl").read_text().splitlines()
            ]
            row = next(r for r in rows if r["direction"] == "receive")
            if mutation == "missing":
                del row["clock"]
            else:
                row["clock"]["mono_after_ns"] += 1
            raw = "".join(json.dumps(r) + "\n" for r in rows).encode()
            (path / "rpc.jsonl").write_bytes(raw)
            result = json.loads((path / "result.json").read_text())
            result["journal_sha256"] = hashlib.sha256(raw).hexdigest()
            (path / "result.json").write_text(json.dumps(result))
            with self.assertRaisesRegex(ValueError, "clock_elapsed_mismatch"):
                runner.validate(path, path / "recheck.json")

    def test_replay_cannot_promote_unknown_to_full_chain(self):
        _, path = self.capture(lambda m: 100000000000 + m)
        result = json.loads((path / "result.json").read_text())
        result["full_chain"] = "complete"
        (path / "result.json").write_text(json.dumps(result))
        with self.assertRaises(ValueError):
            runner.validate(path, path / "recheck.json")

    def test_send_write_completion_is_retained_and_deadline_not_extended(self):
        clock = fixture.Clock()
        fake = fixture.Fake(self.events(), clock, self.plan)
        original = fake.send

        def delayed(raw, timeout):
            if raw.get("method") == "turn/steer":
                clock.value += 0.2
            original(raw, timeout)

        fake.send = delayed
        path = self.root / "results" / "slow-write"
        result = runner.collect(
            self.plan,
            path,
            lambda *_: fake,
            offline=True,
            clock=clock,
            wall=lambda: 100000000000 + clock(),
        )
        rows = [
            json.loads(line) for line in (path / "rpc.jsonl").read_text().splitlines()
        ]
        pair = [r for r in rows if r["raw"].get("method") == "turn/steer"]
        self.assertEqual([r["direction"] for r in pair], ["send", "send_complete"])
        self.assertEqual(pair[1]["elapsed_ns"] - pair[0]["elapsed_ns"], 200000000)
        self.assertEqual(result["deadline_ns"], 22000000000)
        runner.validate(path, path / "validated.json")
