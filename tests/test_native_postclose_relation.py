"""Synthetic-only predicate tests; no real state, model, child or network."""

import copy
import hashlib
import json
import unittest

from tools.validation import state_relation as p


def sealed(value):
    out = copy.deepcopy(value)
    out.pop("content_hash", None)
    out["content_hash"] = hashlib.sha256(p.canonical(out)).hexdigest()
    return out


def raw(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


class Tests(unittest.TestCase):
    def setUp(self):
        self.before = sealed(
            {
                "schema_version": 13,
                "session": {
                    "id": "thread_1",
                    "ended_at": None,
                    "updated_at": "2026-11-15T14:00:00.000001Z",
                },
                "requirements": [
                    {"id": "r1", "status": "pending", "work_unit_id": "u1"}
                ],
                "acceptance_items": [{"id": "a1", "status": "pending"}],
                "root_controls": [{"kind": "persist", "items": ["r1"]}],
                "prompts": [{"turn_id": "turn1"}, {"turn_id": "turn2"}],
                "mode": {"active": True},
                "scope": {"current": ["r1"], "ancestor": []},
            }
        )
        self.after = copy.deepcopy(self.before)
        self.after["session"]["ended_at"] = "2026-11-15T14:00:05.000001Z"
        self.after["session"]["updated_at"] = "2026-11-15T14:00:05.000010Z"
        self.after = sealed(self.after)
        self.checks = []

    def validate(self, state):
        self.checks.append(state["session"]["id"])
        if state.get("schema_version") != 13:
            raise ValueError("synthetic invalid")

    def call(self, before=None, after=None, **kw):
        old = raw(self.before if before is None else before)
        now = raw(self.after if after is None else after)
        options = {
            "recorded_pre_sha": hashlib.sha256(old).hexdigest(),
            "stable_current_sha": hashlib.sha256(now).hexdigest(),
            "recorded_root": "/synthetic/root",
            "current_root": "/synthetic/root",
            "thread": "thread_1",
            "observed_at": "2026-11-15T14:00:06Z",
            "validate_state": self.validate,
        }
        options.update(kw)
        return p.relation(old, now, **options)

    def test_exact_raw_default_and_two_full_integrity_calls(self):
        result = self.call(after=self.before)
        self.assertEqual(result["relation"], "exact_raw_match")
        self.assertEqual(self.checks, ["thread_1", "thread_1"])

    def test_only_end_metadata_passes_without_claiming_attribution(self):
        result = self.call()
        self.assertEqual(result["relation"], "session_end_metadata_consistent")
        self.assertNotIn("SessionEnd_observed", result)

    def test_wrong_preimage_or_current_hash_rejected(self):
        for option in (
            {"recorded_pre_sha": "0" * 64},
            {"stable_current_sha": "0" * 64},
        ):
            with self.subTest(option=option), self.assertRaises(p.Refused):
                self.call(**option)

    def test_root_or_thread_identity_mismatch_rejected(self):
        for option in ({"current_root": "/synthetic/other"}, {"thread": "thread_2"}):
            with self.subTest(option=option), self.assertRaises(p.Refused):
                self.call(**option)

    def test_changed_business_authority_scope_pending_turns_or_extra_key_rejected(self):
        edits = [
            lambda s: s["requirements"][0].update(status="completed"),
            lambda s: s["acceptance_items"][0].update(status="passed"),
            lambda s: s["root_controls"][0].update(kind="cancel"),
            lambda s: s["scope"]["ancestor"].append("constraint"),
            lambda s: s["prompts"].append({"turn_id": "extra"}),
            lambda s: s["mode"].update(active=1),
            lambda s: s.update(extra="new"),
        ]
        for edit in edits:
            changed = copy.deepcopy(self.after)
            edit(changed)
            with self.subTest(change=edit), self.assertRaises(p.Refused):
                self.call(after=sealed(changed))

    def test_invalid_content_hash_and_runtime_integrity_rejected(self):
        bad = copy.deepcopy(self.after)
        bad["content_hash"] = "0" * 64
        with self.assertRaises(p.Refused):
            self.call(after=bad)
        with self.assertRaises(p.Refused):
            self.call(
                validate_state=lambda _: (_ for _ in ()).throw(ValueError("private"))
            )

    def test_time_order_future_malformed_or_existing_end_rejected(self):
        cases = [
            ("ended_at", "2026-11-15T13:59:59Z"),
            ("updated_at", "2026-11-15T14:00:04Z"),
            ("updated_at", "2026-11-15T14:00:07Z"),
            ("ended_at", "invalid"),
            ("ended_at", None),
        ]
        for key, value in cases:
            changed = copy.deepcopy(self.after)
            changed["session"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(p.Refused):
                self.call(after=sealed(changed))
        old = copy.deepcopy(self.before)
        old["session"]["ended_at"] = "2026-11-15T13:59:00Z"
        with self.assertRaises(p.Refused):
            self.call(before=sealed(old))

    def test_duplicate_keys_nonfinite_and_invalid_utf8_rejected(self):
        for value in (
            b'{"session":{},"session":{}}',
            b'{"session":{},"v":NaN}',
            b"\xff",
        ):
            with self.subTest(value=value), self.assertRaises(p.Refused):
                p.state_from_bytes(value)

    def test_validator_cannot_modify_comparison_inputs(self):
        def mutator(value):
            value["requirements"][0]["status"] = "tampered"

        self.assertEqual(
            self.call(validate_state=mutator)["relation"],
            "session_end_metadata_consistent",
        )
        self.assertEqual(self.before["requirements"][0]["status"], "pending")


if __name__ == "__main__":
    unittest.main()
