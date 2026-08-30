#!/usr/bin/env python3
"""Regression tests for the digest v3 reference encoder and its fixture gate.

Positive coverage replays every frozen golden vector through the encoder and
the ``--check`` gate command. Negative coverage pins the fail-closed edges the
semantic compatibility plan freezes for v3: semantic-key sorting, the two
collision layers, Unicode and length boundaries, duplicate collection members,
closed enums, camelCase rejection, the evidenceFact role matrix, and the
binding state-closure rules.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENCODER = ROOT / "scripts" / "reference_digest_encoder.py"
CASES = ROOT / "tests" / "fixtures" / "conformance" / "digest_v3" / "cases.json"
EXPECTED = ROOT / "tests" / "fixtures" / "conformance" / "digest_v3" / "expected.json"

SPEC = importlib.util.spec_from_file_location("reference_digest_encoder", ENCODER)
enc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(enc)

DigestError = enc.DigestError
field = enc.field
typed_token = enc.typed_token

TEST_ALLOWLIST = frozenset({"aa", "b", "symbol", "accent", "long_key_" + "a" * 56})


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class GoldenVectorTests(unittest.TestCase):
    """Every frozen vector must be reproduced from machine-readable inputs."""

    def test_all_29_vectors_reproduce_expected_digests(self) -> None:
        cases = json.loads(CASES.read_text(encoding="utf-8"))
        expected = json.loads(EXPECTED.read_text(encoding="utf-8"))["expected"]
        self.assertEqual(len(cases["vectors"]), 29)
        self.assertEqual(set(expected), {v["id"] for v in cases["vectors"]})
        results = enc.compute_all(cases["vectors"])
        self.assertEqual(results, expected)

    def test_check_gate_command_passes(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ENCODER), "--check", str(CASES)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_check_gate_fails_on_tampered_expected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            shutil.copy(CASES, workdir / "cases.json")
            expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
            first_id = sorted(expected["expected"])[0]
            expected["expected"][first_id] = "0" * 64
            (workdir / "expected.json").write_text(
                json.dumps(expected, indent=2) + "\n", encoding="utf-8"
            )
            proc = subprocess.run(
                [sys.executable, str(ENCODER), "--check", str(workdir / "cases.json")],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(first_id, proc.stderr)

    def test_check_gate_fails_on_tampered_case_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            cases = json.loads(CASES.read_text(encoding="utf-8"))
            for vector in cases["vectors"]:
                if vector["id"] == "SESSION_A":
                    vector["input"]["agentPreset"] = "tampered-preset"
            shutil.copy(EXPECTED, workdir / "expected.json")
            (workdir / "cases.json").write_text(
                json.dumps(cases, indent=2) + "\n", encoding="utf-8"
            )
            proc = subprocess.run(
                [sys.executable, str(ENCODER), "--check", str(workdir / "cases.json")],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("SESSION_A", proc.stderr)

    def test_write_is_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            shutil.copy(CASES, workdir / "cases.json")
            for _ in range(2):
                proc = subprocess.run(
                    [sys.executable, str(ENCODER), "--write", str(workdir / "cases.json")],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(
                (workdir / "expected.json").read_bytes(),
                EXPECTED.read_bytes(),
            )

    def test_present_zero_value_differs_from_absent(self) -> None:
        base = {"version": 0, "id": "s", "createdAt": 1}
        absent = enc.session_ref_digest(base)
        present_zero = enc.session_ref_digest({**base, "seedLength": 0})
        self.assertNotEqual(absent, present_zero)

    def test_session_vectors_cover_absent_optional_fields(self) -> None:
        # Session B (all optionals absent) must encode: presence is decided
        # before any stringification of the missing values.
        digest = enc.session_ref_digest(
            {"version": 0, "id": "synthetic-session-0001", "createdAt": 1700000000000}
        )
        expected = json.loads(EXPECTED.read_text(encoding="utf-8"))["expected"]
        self.assertEqual(digest, expected["SESSION_B"])


class SortingTests(unittest.TestCase):
    """Canonical maps sort by semantic key bytes, never by encoded bytes."""

    def test_multi_entry_map_uses_semantic_key_order(self) -> None:
        params = {"b": {"k": "s", "v": "1"}, "aa": {"k": "s", "v": "1"}}
        payload = enc.pred_params_bytes(params, TEST_ALLOWLIST)
        aa_field = field("aa", typed_token({"k": "s", "v": "1"}))
        b_field = field("b", typed_token({"k": "s", "v": "1"}))
        semantic_order = b"ccg.predParams.v3\n" + aa_field + b_field
        # Encoded-field order would sort the u32BE lengths first and put the
        # shorter key "b" ahead of "aa"; that construction must not match.
        encoded_order = b"ccg.predParams.v3\n" + b_field + aa_field
        self.assertEqual(payload, semantic_order)
        self.assertNotEqual(payload, encoded_order)
        self.assertNotEqual(sha256(payload), sha256(encoded_order))

    def test_binding_rows_sort_by_semantic_key(self) -> None:
        row_a = {
            "item": "i",
            "semanticAction": "test",
            "requestedTarget": {
                "remote": {"k": "s", "v": "origin"},
                "branch": {"k": "s", "v": "main"},
            },
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {},
            "predId": "p",
            "predVersion": 1,
            "predParamsKind": "inline",
            "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
            "effectEvidenceId": "e1",
        }
        row_b = {
            **row_a,
            "requestedTarget": {
                "branch": {"k": "s", "v": "main"},
                "remote": {"k": "s", "v": "origin"},
            },
        }
        self.assertEqual(
            enc.binding_record_digest(row_a, enc.PRODUCT_KEY_VOCABULARY),
            enc.binding_record_digest(row_b, enc.PRODUCT_KEY_VOCABULARY),
        )

    def test_evidence_sha256_is_insertion_order_invariant(self) -> None:
        cases = json.loads(CASES.read_text(encoding="utf-8"))
        vectors = {v["id"]: v for v in cases["vectors"]}
        forward = enc.compute_all(cases["vectors"])
        reshuffled = [v for v in cases["vectors"]]
        pull_index = next(
            i for i, v in enumerate(reshuffled) if v["id"] == "ESH_PULL"
        )
        facts = reshuffled[pull_index]["input"]["facts"]
        reshuffled[pull_index]["input"]["facts"] = list(reversed(facts))
        backward = enc.compute_all(reshuffled)
        self.assertEqual(forward["ESH_PULL"], backward["ESH_PULL"])
        self.assertEqual(forward["BD_PULL"], backward["BD_PULL"])
        self.assertIsNotNone(vectors)

    def test_host_lock_capability_rows_are_order_invariant(self) -> None:
        manifest = {
            "manifestVersion": 1,
            "supportedGoalVersions": ["0.1.1-rc.1", "0.1.1-rc.2"],
            "capabilities": [
                {"name": "supported_action", "value": {"k": "s", "v": "pull"}},
                {"name": "goal_disarm_readback", "value": {"k": "s", "v": "required"}},
                {"name": "supported_action", "value": {"k": "s", "v": "push"}},
            ],
            "packages": [
                {"name": "@deepseek-ai/cordis", "version": "4.0.1", "integrity": "sha512-synthetic-cordis"},
                {"name": "@deepseek-ai/dsh-agent", "version": "0.1.1-rc.2", "integrity": "sha512-synthetic-agent"},
                {"name": "@deepseek-ai/dsh-goal", "version": "0.1.1-rc.2", "integrity": "sha512-synthetic-goal"},
            ],
        }
        expected = json.loads(EXPECTED.read_text(encoding="utf-8"))["expected"]
        self.assertEqual(enc.host_lock_digest(manifest), expected["HOST_D"])


class CollisionTests(unittest.TestCase):
    """Two collision layers: raw field primitive and manifest grammar."""

    def test_raw_field_length_prefix_prevents_concatenation_collision(self) -> None:
        left = field("malicious\x00name", b"s:z")
        right = field("a", b"s:x") + field("b", b"s:z")
        self.assertNotEqual(left, right)

    def test_raw_field_accepts_long_names_up_to_limit(self) -> None:
        field("n" * 256, b"s:v")
        with self.assertRaises(DigestError):
            field("n" * 257, b"s:v")

    def test_manifest_layer_rejects_grammar_violating_names(self) -> None:
        with self.assertRaises(DigestError):
            enc.pred_params_bytes(
                {"maliciousName": {"k": "s", "v": "z"}}, TEST_ALLOWLIST
            )
        with self.assertRaises(DigestError):
            enc.pred_params_bytes(
                {"expectedOutcome": {"k": "s", "v": "success"}},
                enc.PRODUCT_KEY_VOCABULARY,
            )
        with self.assertRaises(DigestError):
            enc.pred_params_bytes(
                {"upstreamOid": {"k": "x", "v": "ab" * 32}},
                enc.PRODUCT_KEY_VOCABULARY,
            )

    def test_camel_case_tuple_keys_are_rejected_before_hashing(self) -> None:
        fact = {
            "id": "e1",
            "outcome": "success",
            "method": "shell",
            "surfaces": ["artifact"],
            "semanticAction": "test",
            "evidenceRole": "effect",
            "resolvedTarget": {"scopeId": {"k": "s", "v": "x"}},
            "observedState": {},
            "parseStatus": "supported",
        }
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest(fact)

    def test_vocabulary_outside_tuple_keys_are_rejected_before_hashing(self) -> None:
        # Grammar-valid snake_case is not enough: tuple keys must come from
        # the frozen canonical vocabulary (or the declared test allowlist).
        fact = {
            "id": "e1",
            "outcome": "success",
            "method": "shell",
            "surfaces": ["artifact"],
            "semanticAction": "test",
            "evidenceRole": "effect",
            "resolvedTarget": {"custom_key": {"k": "s", "v": "x"}},
            "observedState": {},
            "parseStatus": "supported",
        }
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest(fact)
        allowed = enc.evidence_fact_digest(fact, frozenset({"custom_key"}))
        self.assertEqual(len(allowed), 64)
        binding = {
            "item": "i",
            "semanticAction": "test",
            "requestedTarget": {"custom_key": {"k": "s", "v": "x"}},
            "resolvedTarget": {"scope": {"k": "s", "v": "x"}},
            "observedState": {},
            "predId": "p",
            "predVersion": 1,
            "predParamsKind": "inline",
            "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
            "effectEvidenceId": "e1",
        }
        with self.assertRaises(DigestError):
            enc.binding_record_digest(binding, enc.PRODUCT_KEY_VOCABULARY)
        self.assertEqual(
            len(enc.binding_record_digest(binding, frozenset({"custom_key", "scope"}))), 64
        )


class UnicodeAndBoundaryTests(unittest.TestCase):
    def test_lone_surrogate_fails_closed(self) -> None:
        with self.assertRaises(DigestError):
            enc.pred_params_bytes(
                {"accent": {"k": "s", "v": "\ud800"}}, frozenset({"accent"})
            )

    def test_nfc_and_nfd_values_produce_different_digests(self) -> None:
        expected = json.loads(EXPECTED.read_text(encoding="utf-8"))["expected"]
        nfc = enc.pred_params_bytes(
            {"accent": {"k": "s", "v": "é"}}, frozenset({"accent"})
        )
        nfd = enc.pred_params_bytes(
            {"accent": {"k": "s", "v": "é"}}, frozenset({"accent"})
        )
        self.assertNotEqual(nfc, nfd)
        self.assertEqual(sha256(nfc), expected["U2"])
        self.assertEqual(sha256(nfd), expected["U3"])

    def test_astral_scalar_is_encoded_as_utf8(self) -> None:
        payload = enc.pred_params_bytes(
            {"symbol": {"k": "s", "v": "𝄞"}}, frozenset({"symbol"})
        )
        self.assertIn("𝄞".encode("utf-8"), payload)

    def test_value_length_boundary(self) -> None:
        # The per-value limit binds at the raw field layer: 4096 token bytes
        # are accepted, 4097 are rejected before the u32BE is written.
        field("k", b"s:" + b"a" * 4094)
        with self.assertRaises(DigestError):
            field("k", b"s:" + b"a" * 4095)

    def test_pred_params_total_length_boundary(self) -> None:
        # separator(18) + field overhead 4+6+1+4 + token bytes = total.
        fits = enc.pred_params_bytes(
            {"accent": {"k": "s", "v": "a" * 4061}}, frozenset({"accent"})
        )
        self.assertEqual(len(fits), 4096)
        with self.assertRaises(DigestError):
            enc.pred_params_bytes(
                {"accent": {"k": "s", "v": "a" * 4062}}, frozenset({"accent"})
            )

    def test_semantic_key_length_boundary(self) -> None:
        long_key = "long_key_" + "a" * 55  # exactly 64 bytes
        enc.pred_params_bytes(
            {long_key: {"k": "s", "v": "v"}}, frozenset({long_key})
        )
        with self.assertRaises(DigestError):
            enc.pred_params_bytes(
                {long_key + "a": {"k": "s", "v": "v"}}, frozenset({long_key + "a"})
            )

    def test_package_name_grammar_and_length(self) -> None:
        base = {
            "manifestVersion": 1,
            "supportedGoalVersions": ["1.0.0"],
            "capabilities": [],
        }
        ok = {**base, "packages": [{"name": "@" + "a" * 127, "version": "1", "integrity": None}]}
        enc.host_lock_digest(ok)
        bad = {**base, "packages": [{"name": "@" + "a" * 128, "version": "1", "integrity": None}]}
        with self.assertRaises(DigestError):
            enc.host_lock_digest(bad)
        upper = {**base, "packages": [{"name": "@Scope/Thing", "version": "1", "integrity": None}]}
        with self.assertRaises(DigestError):
            enc.host_lock_digest(upper)

    def test_field_count_limit(self) -> None:
        names = [f"p{i:03d}" for i in range(129)]
        params = {name: {"k": "i", "v": 1} for name in names}
        with self.assertRaises(DigestError):
            enc.pred_params_bytes(params, frozenset(names))


class DuplicateAndEnumTests(unittest.TestCase):
    def test_duplicate_pred_params_names_fail_closed(self) -> None:
        # JSON objects cannot carry duplicate keys once parsed; the canonical
        # input contract therefore rejects duplicates at the raw collection
        # layer, which encode_set/encode_map_rows enforce for list-shaped
        # inputs. Exercise the underlying helper directly.
        with self.assertRaises(DigestError):
            enc.encode_map_rows([("aa", b"s:1"), ("aa", b"s:2")])

    def test_duplicate_capability_rows_fail_closed(self) -> None:
        manifest = {
            "manifestVersion": 1,
            "supportedGoalVersions": ["1.0.0"],
            "capabilities": [
                {"name": "goal_disarm_readback", "value": {"k": "s", "v": "required"}},
                {"name": "goal_disarm_readback", "value": {"k": "s", "v": "required"}},
            ],
            "packages": [],
        }
        with self.assertRaises(DigestError):
            enc.host_lock_digest(manifest)

    def test_duplicate_supported_goal_versions_fail_closed(self) -> None:
        manifest = {
            "manifestVersion": 1,
            "supportedGoalVersions": ["1.0.0", "1.0.0"],
            "capabilities": [],
            "packages": [],
        }
        with self.assertRaises(DigestError):
            enc.host_lock_digest(manifest)

    def test_duplicate_item_action_bindings_fail_closed(self) -> None:
        row = {
            "item": "i",
            "semanticAction": "test",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "predId": "p",
            "predVersion": 1,
            "predParamsKind": "inline",
            "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
        }
        with self.assertRaises(DigestError):
            enc.binding_digest([row, dict(row)], enc.PRODUCT_KEY_VOCABULARY)

    def test_duplicate_evidence_ids_fail_closed(self) -> None:
        fact = {
            "id": "e1",
            "outcome": "success",
            "method": "shell",
            "surfaces": ["artifact"],
            "semanticAction": "test",
            "evidenceRole": "effect",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {},
            "parseStatus": "supported",
        }
        with self.assertRaises(DigestError):
            enc.evidence_sha256_digest([fact, dict(fact)])

    def test_duplicate_state_evidence_ids_fail_closed(self) -> None:
        binding = {
            "item": "i",
            "semanticAction": "pull",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {"post_head_oid": {"k": "x", "v": "ab" * 32}},
            "predId": "p",
            "predVersion": 1,
            "predParamsKind": "inline",
            "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
            "effectEvidenceId": "e1",
            "stateEvidenceIds": ["e2", "e2"],
        }
        with self.assertRaises(DigestError):
            enc.binding_record_digest(binding, enc.PRODUCT_KEY_VOCABULARY)

    def test_surface_cardinality_and_enum_fail_closed(self) -> None:
        base = {
            "id": "e1",
            "outcome": "success",
            "method": "shell",
            "semanticAction": "test",
            "evidenceRole": "effect",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {},
            "parseStatus": "supported",
        }
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest({**base, "surfaces": ["artifact", "ui"]})
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest({**base, "surfaces": []})
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest({**base, "surfaces": ["ntfs"]})

    def test_unknown_outcome_and_role_fail_closed(self) -> None:
        base = {
            "id": "e1",
            "method": "shell",
            "surfaces": ["artifact"],
            "semanticAction": "test",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {},
            "parseStatus": "supported",
        }
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest({**base, "outcome": "probably-fine"})
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest({**base, "outcome": "success", "evidenceRole": "observer"})

    def test_invalid_digest_and_enum_tokens_fail_closed(self) -> None:
        with self.assertRaises(DigestError):
            typed_token({"k": "x", "v": "ABCDEF"})
        with self.assertRaises(DigestError):
            typed_token({"k": "x", "v": "abc"})  # odd length
        with self.assertRaises(DigestError):
            typed_token({"k": "e", "v": "Not An Enum"})
        with self.assertRaises(DigestError):
            typed_token({"k": "q", "v": "x"})


class RoleMatrixAndClosureTests(unittest.TestCase):
    @staticmethod
    def _fact(fid: str, role: str, observed: dict) -> dict:
        return {
            "id": fid,
            "outcome": "success",
            "method": "git",
            "operations": ["run"],
            "executables": ["git"],
            "subjects": ["repo"],
            "surfaces": ["artifact"],
            "semanticAction": "pull",
            "evidenceRole": role,
            "resolvedTarget": {
                "remote": {"k": "s", "v": "origin"},
                "repository": {"k": "s", "v": "repo"},
                "refspec": {"k": "s", "v": "main"},
            },
            "observedState": observed,
            "parseStatus": "supported",
        }

    def _binding(self, resolution_id: str, effect_id: str, state_ids: list[str]) -> dict:
        return {
            "item": "i",
            "semanticAction": "pull",
            "resolvedTarget": {
                "remote": {"k": "s", "v": "origin"},
                "repository": {"k": "s", "v": "repo"},
                "refspec": {"k": "s", "v": "main"},
            },
            "observedState": {"post_head_oid": {"k": "x", "v": "ab" * 32}},
            "predId": "pred.pull.ff",
            "predVersion": 1,
            "predParamsKind": "inline",
            "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
            "resolutionEvidenceId": resolution_id,
            "effectEvidenceId": effect_id,
            "stateEvidenceIds": state_ids,
        }

    def test_closed_pull_chain_passes(self) -> None:
        resolution = self._fact("res", "resolution", {})
        effect = self._fact("eff", "effect", {})
        state = self._fact("st", "state", {"post_head_oid": {"k": "x", "v": "ab" * 32}})
        binding = self._binding("res", "eff", ["st"])
        enc.binding_state_closure(binding, resolution, effect, [state], [resolution, effect, state])

    def test_effect_must_not_carry_observed_state(self) -> None:
        resolution = self._fact("res", "resolution", {})
        effect = self._fact("eff", "effect", {"post_head_oid": {"k": "x", "v": "ab" * 32}})
        state = self._fact("st", "state", {"post_head_oid": {"k": "x", "v": "ab" * 32}})
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest(effect)
        binding = self._binding("res", "eff", ["st"])
        with self.assertRaises(DigestError):
            enc.binding_state_closure(binding, resolution, effect, [state])

    def test_state_fact_requires_observed_state(self) -> None:
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest(self._fact("st", "state", {}))

    def test_binding_res_must_match_facts_byte_for_byte(self) -> None:
        resolution = self._fact("res", "resolution", {})
        effect = self._fact("eff", "effect", {})
        state = self._fact("st", "state", {"post_head_oid": {"k": "x", "v": "ab" * 32}})
        binding = self._binding("res", "eff", ["st"])
        binding["resolvedTarget"]["refspec"] = {"k": "s", "v": "feature"}
        with self.assertRaises(DigestError):
            enc.binding_state_closure(binding, resolution, effect, [state])

    def test_observed_state_key_intersection_fails_closed(self) -> None:
        resolution = self._fact("res", "resolution", {})
        effect = self._fact("eff", "effect", {})
        state_a = self._fact("st1", "state", {"post_head_oid": {"k": "x", "v": "ab" * 32}})
        state_b = self._fact("st2", "state", {"post_head_oid": {"k": "x", "v": "cd" * 32}})
        binding = self._binding("res", "eff", ["st1", "st2"])
        with self.assertRaises(DigestError):
            enc.binding_state_closure(binding, resolution, effect, [state_a, state_b])

    def test_duplicate_state_fact_ids_fail_closed_without_evidence_set(self) -> None:
        resolution = self._fact("res", "resolution", {})
        effect = self._fact("eff", "effect", {})
        state_a = self._fact(
            "st", "state", {"post_head_oid": {"k": "x", "v": "ab" * 32}}
        )
        state_b = self._fact(
            "st", "state", {"health": {"k": "s", "v": "healthy"}}
        )
        binding = self._binding("res", "eff", ["st"])
        binding["observedState"]["health"] = {"k": "s", "v": "healthy"}
        with self.assertRaisesRegex(DigestError, "duplicate state fact id"):
            enc.binding_state_closure(binding, resolution, effect, [state_a, state_b])

    def test_binding_obs_must_equal_state_union(self) -> None:
        resolution = self._fact("res", "resolution", {})
        effect = self._fact("eff", "effect", {})
        state = self._fact("st", "state", {"post_head_oid": {"k": "x", "v": "ab" * 32}})
        binding = self._binding("res", "eff", ["st"])
        binding["observedState"]["tracking_ref_oid"] = {"k": "x", "v": "cd" * 32}
        with self.assertRaises(DigestError):
            enc.binding_state_closure(binding, resolution, effect, [state])

    def test_cross_paired_evidence_ids_fail_closed(self) -> None:
        resolution = self._fact("res", "resolution", {})
        effect = self._fact("eff", "effect", {})
        state = self._fact("st", "state", {"post_head_oid": {"k": "x", "v": "ab" * 32}})
        # Resolution and effect ids swapped: the resolution evidence no longer
        # pairs with the binding's resolvedTarget derivation.
        binding = self._binding("eff", "res", ["st"])
        with self.assertRaises(DigestError):
            enc.binding_state_closure(binding, resolution, effect, [state])

    def test_missing_evidence_id_from_set_fails_closed(self) -> None:
        resolution = self._fact("res", "resolution", {})
        effect = self._fact("eff", "effect", {})
        state = self._fact("st", "state", {"post_head_oid": {"k": "x", "v": "ab" * 32}})
        binding = self._binding("res", "eff", ["st"])
        with self.assertRaises(DigestError):
            enc.binding_state_closure(binding, resolution, effect, [state], [resolution, effect])

    def test_resolved_target_mismatch_across_facts_fails_closed(self) -> None:
        resolution = self._fact("res", "resolution", {})
        effect = self._fact("eff", "effect", {})
        state = self._fact("st", "state", {"post_head_oid": {"k": "x", "v": "ab" * 32}})
        state["resolvedTarget"]["pull_mode"] = {"k": "s", "v": "ff-only"}
        binding = self._binding("res", "eff", ["st"])
        with self.assertRaises(DigestError):
            enc.binding_state_closure(binding, resolution, effect, [state])


class AdversarialContractTests(unittest.TestCase):
    """Closed-manifest and fail-closed attacks mirrored in the DSH suite."""

    def test_unknown_fields_rejected_in_every_manifest(self) -> None:
        digest_or_none = "ab" * 32
        cases = [
            (
                lambda: enc.session_ref_digest(
                    {"version": 0, "id": "s", "createdAt": 1, "evil": "x"}
                ),
                lambda: enc.session_ref_digest({"version": 0, "id": "s", "createdAt": 1}),
            ),
            (
                lambda: enc.host_lock_digest(
                    {
                        "manifestVersion": 1,
                        "supportedGoalVersions": ["1.0.0"],
                        "evil": "x",
                    }
                ),
                lambda: enc.host_lock_digest(
                    {"manifestVersion": 1, "supportedGoalVersions": ["1.0.0"]}
                ),
            ),
            (
                lambda: enc.host_lock_digest(
                    {
                        "manifestVersion": 1,
                        "supportedGoalVersions": ["1.0.0"],
                        "capabilities": [{"name": "cap", "value": "v", "evil": "x"}],
                    }
                ),
                None,
            ),
            (
                lambda: enc.host_lock_digest(
                    {
                        "manifestVersion": 1,
                        "supportedGoalVersions": ["1.0.0"],
                        "packages": [
                            {"name": "pkg-a", "version": "1.0.0", "integrity": None, "evil": "x"}
                        ],
                    }
                ),
                None,
            ),
            (
                lambda: enc.evidence_fact_digest(
                    {
                        "id": "e1",
                        "outcome": "success",
                        "method": "shell",
                        "surfaces": ["artifact"],
                        "semanticAction": "test",
                        "evidenceRole": "effect",
                        "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
                        "observedState": {},
                        "parseStatus": "supported",
                        "evil": "x",
                    }
                ),
                None,
            ),
            (
                lambda: enc.binding_record_digest(
                    {
                        "item": "i",
                        "semanticAction": "test",
                        "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
                        "predId": "p",
                        "predVersion": 1,
                        "predParamsKind": "inline",
                        "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
                        "effectEvidenceId": "e1",
                        "evil": "x",
                    },
                    enc.PRODUCT_KEY_VOCABULARY,
                ),
                None,
            ),
            (
                lambda: enc.certification_digest(
                    {
                        "stopProtocolVersion": "2.0.0",
                        "certificateVersion": "1",
                        "epoch": 0,
                        "sessionRefDigest": digest_or_none,
                        "hostLockDigest": digest_or_none,
                        "contractRevision": 1,
                        "contractSha256": digest_or_none,
                        "openDigest": digest_or_none,
                        "evidenceSha256": digest_or_none,
                        "bindingDigest": digest_or_none,
                        "evil": "x",
                    }
                ),
                None,
            ),
            (
                lambda: enc.certification_digest(
                    {
                        "stopProtocolVersion": "2.0.0",
                        "certificateVersion": "1",
                        "epoch": 0,
                        "sessionRefDigest": digest_or_none,
                        "hostLockDigest": digest_or_none,
                        "contractRevision": 1,
                        "contractSha256": digest_or_none,
                        "openDigest": digest_or_none,
                        "evidenceSha256": digest_or_none,
                        "bindingDigest": digest_or_none,
                        "goalRef": {"id": "g", "revision": 1, "evil": "x"},
                    }
                ),
                None,
            ),
        ]
        for attack, baseline in cases:
            with self.assertRaises(DigestError):
                attack()
            if baseline is not None:
                baseline()

    def test_unsupported_parse_status_requires_reason_code(self) -> None:
        fact = {
            "id": "e1",
            "outcome": "success",
            "method": "shell",
            "surfaces": ["artifact"],
            "semanticAction": "test",
            "evidenceRole": "effect",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {},
            "parseStatus": "malformed_quote",
        }
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest(fact)
        fact["reasonCode"] = "quote unterminated"
        self.assertEqual(len(enc.evidence_fact_digest(fact)), 64)

    def test_session_header_field_types_fail_closed(self) -> None:
        with self.assertRaises(DigestError):
            enc.session_ref_digest(
                {"version": 0, "id": "s", "createdAt": 1, "seedLength": "42"}
            )
        with self.assertRaises(DigestError):
            enc.session_ref_digest({"version": 0, "id": "s", "createdAt": "1"})
        with self.assertRaises(DigestError):
            enc.session_ref_digest({"version": 0, "id": "s", "createdAt": 1, "agentPreset": 7})

    def test_package_row_value_types_fail_closed(self) -> None:
        manifest = {
            "manifestVersion": 1,
            "supportedGoalVersions": ["1.0.0"],
            "packages": [{"name": "pkg-a", "version": 1, "integrity": None}],
        }
        with self.assertRaises(DigestError):
            enc.host_lock_digest(manifest)

    def test_evidence_fact_field_count_boundary_is_exact(self) -> None:
        def fact_with_subjects(count: int) -> dict:
            return {
                "id": "e1",
                "outcome": "success",
                "method": "shell",
                "subjects": [f"subject-{i:04d}" for i in range(count)],
                "surfaces": ["artifact"],
                "semanticAction": "test",
                "evidenceRole": "state",
                "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
                "observedState": {"post_digest": {"k": "s", "v": "d"}},
                "parseStatus": "supported",
            }

        # 10 fixed fields (incl. absent reasonCode/adapter rows) + 1 res + 1 obs
        # + subject rows = 128 exactly.
        self.assertEqual(len(enc.evidence_fact_digest(fact_with_subjects(116))), 64)
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest(fact_with_subjects(117))

    def test_closure_binds_fact_content_not_just_ids(self) -> None:
        helpers = RoleMatrixAndClosureTests
        resolution = helpers._fact("res", "resolution", {})
        effect = helpers._fact("eff", "effect", {})
        state = helpers._fact("st", "state", {"post_head_oid": {"k": "x", "v": "ab" * 32}})
        binding = helpers()._binding("res", "eff", ["st"])
        # Same ID, different content than what evidenceSha256 hashed.
        impostor = helpers._fact("st", "state", {"post_head_oid": {"k": "x", "v": "cd" * 32}})
        with self.assertRaises(DigestError):
            enc.binding_state_closure(
                binding, resolution, effect, [impostor], [resolution, effect, state]
            )
        duplicate_set = [resolution, effect, state, dict(state)]
        with self.assertRaises(DigestError):
            enc.binding_state_closure(
                binding, resolution, effect, [state], duplicate_set
            )
        enc.binding_state_closure(
            binding, resolution, effect, [state], [resolution, effect, state]
        )


    def test_binding_branch_is_closed(self) -> None:
        inline = {
            "item": "i",
            "semanticAction": "test",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "predId": "p",
            "predVersion": 1,
            "predParamsKind": "inline",
            "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
            "effectEvidenceId": "e1",
        }
        manifest = {
            **inline,
            "predParamsKind": "manifest",
            "predParamsRef": "cmd-manifest-0001",
            "predParamsManifest": {"scope": {"k": "s", "v": "worktree"}},
        }
        del manifest["predParams"]
        # An inline record must not tolerate manifest-branch fields, and vice
        # versa: extra branch fields are rejected, not silently ignored.
        with self.assertRaises(DigestError):
            enc.binding_record_digest({**inline, "predParamsRef": "cmd-manifest-0001"}, enc.PRODUCT_KEY_VOCABULARY)
        with self.assertRaises(DigestError):
            enc.binding_record_digest({**inline, "predParamsManifest": {}}, enc.PRODUCT_KEY_VOCABULARY)
        with self.assertRaises(DigestError):
            enc.binding_record_digest({**manifest, "predParams": {"expected_outcome": {"k": "e", "v": "success"}}}, enc.PRODUCT_KEY_VOCABULARY)
        self.assertEqual(len(enc.binding_record_digest(inline, enc.PRODUCT_KEY_VOCABULARY)), 64)
        self.assertEqual(len(enc.binding_record_digest(manifest, enc.PRODUCT_KEY_VOCABULARY)), 64)

    def test_typed_wrapper_rejects_extra_fields(self) -> None:
        with self.assertRaises(DigestError):
            typed_token({"k": "s", "v": "x", "evil": 1})
        with self.assertRaises(DigestError):
            typed_token({"k": "s"})
        self.assertEqual(typed_token({"k": "s", "v": "x"}), b"s:x")

    def test_string_domains_fail_closed(self) -> None:
        with self.assertRaises(DigestError):
            enc.host_lock_digest(
                {"manifestVersion": 1, "supportedGoalVersions": [1]}
            )
        fact = {
            "id": "e1",
            "outcome": "success",
            "method": "shell",
            "operations": [1],
            "surfaces": ["artifact"],
            "semanticAction": "test",
            "evidenceRole": "effect",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {},
            "parseStatus": "supported",
        }
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest(fact)
        for opt_name, bad in (("reasonCode", 7), ("adapterId", 7), ("adapterVersion", 7)):
            mutated = dict(fact, operations=["run"])
            mutated[opt_name] = bad
            with self.assertRaises(DigestError):
                enc.evidence_fact_digest(mutated)
        # Strings stay accepted.
        ok = dict(fact, operations=["run"], reasonCode="rc", adapterId="a", adapterVersion="1.0.0")
        self.assertEqual(len(enc.evidence_fact_digest(ok)), 64)

    def test_reason_code_null_with_unsupported_parse_status_fails_closed(self) -> None:
        fact = {
            "id": "e1",
            "outcome": "success",
            "method": "shell",
            "surfaces": ["artifact"],
            "semanticAction": "test",
            "evidenceRole": "effect",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {},
            "parseStatus": "malformed_quote",
            "reasonCode": None,
        }
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest(fact)

    def test_integer_domain_is_frozen_to_safe_integers(self) -> None:
        self.assertEqual(typed_token(2**53 - 1), b"i:9007199254740991")
        with self.assertRaises(DigestError):
            typed_token(2**53)
        with self.assertRaises(DigestError):
            typed_token(-(2**53))
        with self.assertRaises(DigestError):
            enc.session_ref_digest({"version": 0, "id": "s", "createdAt": 2**53})

    def _boundary_binding(self, state_id_count: int) -> dict:
        vocabulary = sorted(enc.PRODUCT_KEY_VOCABULARY)
        filler = {key: {"k": "s", "v": "x"} for key in vocabulary}
        return {
            "item": "i",
            "semanticAction": "test",
            "requestedTarget": dict(filler),
            "resolvedTarget": dict(filler),
            "observedState": dict(filler),
            "predId": "p",
            "predVersion": 1,
            "predParamsKind": "inline",
            "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
            "effectEvidenceId": "e1",
            "stateEvidenceIds": [f"s{i:03d}" for i in range(state_id_count)],
        }

    def test_binding_field_count_boundary_is_exact(self) -> None:
        # 9 fixed fields (incl. absent resolutionEvidenceId) + 28 req + 28 res
        # + 28 obs + N state rows.
        self.assertEqual(len(enc.binding_record_digest(self._boundary_binding(35), enc.PRODUCT_KEY_VOCABULARY)), 64)
        with self.assertRaises(DigestError):
            enc.binding_record_digest(self._boundary_binding(36), enc.PRODUCT_KEY_VOCABULARY)

    def test_binding_sort_uses_tuple_order_with_nul_items(self) -> None:
        allowlist = enc.PRODUCT_KEY_VOCABULARY

        def record(item: str, action: str) -> dict:
            return {
                "item": item,
                "semanticAction": action,
                "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
                "predId": "p",
                "predVersion": 1,
                "predParamsKind": "inline",
                "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
                "effectEvidenceId": "e1",
            }

        first = record("a", "z")
        second = record("a\x00", "b")
        d_first = enc.binding_record_digest(first, allowlist)
        d_second = enc.binding_record_digest(second, allowlist)
        digest = enc.binding_digest([first, second], allowlist)
        # Frozen tuple order: "a" < "a\x00".
        tuple_ordered = sha256(
            b"ccg.bindingDigest.v3\n"
            + field("binding", ("x:" + d_first).encode())
            + field("binding", ("x:" + d_second).encode())
        )
        concat_ordered = sha256(
            b"ccg.bindingDigest.v3\n"
            + field("binding", ("x:" + d_second).encode())
            + field("binding", ("x:" + d_first).encode())
        )
        self.assertEqual(digest, tuple_ordered)
        self.assertNotEqual(digest, concat_ordered)


    def test_binding_evidence_ids_must_be_strings(self) -> None:
        base = {
            "item": "i",
            "semanticAction": "test",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "predId": "p",
            "predVersion": 1,
            "predParamsKind": "inline",
            "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
            "effectEvidenceId": "e1",
        }
        with self.assertRaises(DigestError):
            enc.binding_record_digest({**base, "resolutionEvidenceId": 7}, enc.PRODUCT_KEY_VOCABULARY)
        with self.assertRaises(DigestError):
            enc.binding_record_digest(
                {**base, "stateEvidenceIds": [7]}, enc.PRODUCT_KEY_VOCABULARY
            )
        with self.assertRaises(DigestError):
            enc.binding_record_digest(
                {**base, "stateEvidenceIds": [True]}, enc.PRODUCT_KEY_VOCABULARY
            )
        ok = {**base, "resolutionEvidenceId": "res-1", "stateEvidenceIds": ["st-1"]}
        self.assertEqual(len(enc.binding_record_digest(ok, enc.PRODUCT_KEY_VOCABULARY)), 64)

    def test_null_collections_and_non_string_names_fail_closed(self) -> None:
        manifest = {
            "manifestVersion": 1,
            "supportedGoalVersions": ["1.0.0"],
            "capabilities": None,
        }
        with self.assertRaises(DigestError):
            enc.host_lock_digest(manifest)
        with self.assertRaises(DigestError):
            enc.host_lock_digest({**manifest, "capabilities": [], "packages": None})
        with self.assertRaises(DigestError):
            enc.host_lock_digest(
                {
                    "manifestVersion": 1,
                    "supportedGoalVersions": ["1.0.0"],
                    "capabilities": [{"name": 7, "value": "v"}],
                }
            )
        fact = {
            "id": "e1",
            "outcome": "success",
            "method": "shell",
            "operations": None,
            "surfaces": ["artifact"],
            "semanticAction": "test",
            "evidenceRole": "effect",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {},
            "parseStatus": "supported",
        }
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest(fact)
        binding = {
            "item": "i",
            "semanticAction": "test",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "predId": "p",
            "predVersion": 1,
            "predParamsKind": "inline",
            "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
            "effectEvidenceId": "e1",
            "stateEvidenceIds": None,
        }
        with self.assertRaises(DigestError):
            enc.binding_record_digest(binding, enc.PRODUCT_KEY_VOCABULARY)
        with self.assertRaises(DigestError):
            enc.binding_record_digest({**binding, "predParams": []}, enc.PRODUCT_KEY_VOCABULARY)
        manifest_binding = {
            **binding,
            "predParamsKind": "manifest",
            "predParamsRef": "cmd-manifest-0001",
            "predParamsManifest": [],
        }
        del manifest_binding["predParams"]
        with self.assertRaises(DigestError):
            enc.binding_record_digest(manifest_binding, enc.PRODUCT_KEY_VOCABULARY)
        with self.assertRaises(DigestError):
            enc._resolve_allowlist(["scope", 7])
        with self.assertRaises(DigestError):
            enc._resolve_allowlist("product-v2")

    def test_explicit_null_key_allowlist_maps_to_product(self) -> None:
        self.assertEqual(enc._resolve_allowlist(None), enc._resolve_allowlist("product"))
        self.assertEqual(
            enc._resolve_allowlist(None), enc.PRODUCT_KEY_VOCABULARY
        )
        params = {"scope": {"k": "s", "v": "worktree"}}
        self.assertEqual(
            enc.pred_params_digest(params, enc._resolve_allowlist(None)),
            enc.pred_params_digest(params, enc._resolve_allowlist("product")),
        )

    def test_regex_anchors_reject_trailing_newlines(self) -> None:
        # Python '$' matches before a final newline; the grammar checks use
        # fullmatch so grammar tokens with trailing newlines fail closed,
        # matching the TypeScript mirror.
        with self.assertRaises(DigestError):
            typed_token({"k": "e", "v": "ok\n"})
        with self.assertRaises(DigestError):
            typed_token({"k": "x", "v": "ab\n"})
        with self.assertRaises(DigestError):
            enc.host_lock_digest(
                {
                    "manifestVersion": 1,
                    "supportedGoalVersions": ["1.0.0"],
                    "capabilities": [{"name": "cap\n", "value": "v"}],
                }
            )
        with self.assertRaises(DigestError):
            enc.host_lock_digest(
                {
                    "manifestVersion": 1,
                    "supportedGoalVersions": ["1.0.0"],
                    "packages": [{"name": "pkg\n", "version": "1.0.0"}],
                }
            )
        fact = {
            "id": "e1",
            "outcome": "success",
            "method": "shell",
            "surfaces": ["artifact"],
            "semanticAction": "test",
            "evidenceRole": "effect",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {},
            "parseStatus": "supported\n",
            "reasonCode": "rc",
        }
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest(fact)
        keyed = dict(fact, parseStatus="supported")
        keyed["resolvedTarget"] = {"scope\n": {"k": "s", "v": "s"}}
        with self.assertRaises(DigestError):
            enc.evidence_fact_digest(keyed)

    def test_integral_json_numbers_normalize_to_integer_tokens(self) -> None:
        # Frozen rule: finite, safe, numerically integral JSON numbers
        # normalize to integer tokens (matching the TS mirror and the shared
        # schema's integer semantics).
        self.assertEqual(typed_token(1.0), b"i:1")
        self.assertEqual(typed_token(1e0), b"i:1")
        self.assertEqual(typed_token({"k": "i", "v": 1.0}), b"i:1")
        self.assertEqual(typed_token(-(2**53 - 1)), b"i:-9007199254740991")
        with self.assertRaises(DigestError):
            typed_token(1.5)
        with self.assertRaises(DigestError):
            typed_token(float(2**53))
        with self.assertRaises(DigestError):
            typed_token(float("nan"))
        with self.assertRaises(DigestError):
            typed_token(float("inf"))
        base = {"version": 0, "id": "s", "createdAt": 1}
        self.assertEqual(
            enc.session_ref_digest({**base, "seedLength": 1.0}),
            enc.session_ref_digest({**base, "seedLength": 1}),
        )
        cert = {
            "stopProtocolVersion": "2.0.0",
            "certificateVersion": "1",
            "epoch": 0,
            "sessionRefDigest": "ab" * 32,
            "hostLockDigest": "ab" * 32,
            "contractRevision": 1,
            "contractSha256": "cd" * 32,
            "openDigest": "01" * 32,
            "evidenceSha256": "02" * 32,
            "bindingDigest": "03" * 32,
        }
        self.assertEqual(
            enc.certification_digest({**cert, "epoch": 3.0}),
            enc.certification_digest({**cert, "epoch": 3}),
        )

    def test_certificate_version_fields_must_be_strings(self) -> None:
        base = {
            "stopProtocolVersion": "2.0.0",
            "certificateVersion": "1",
            "epoch": 0,
            "sessionRefDigest": "ab" * 32,
            "hostLockDigest": "ab" * 32,
            "contractRevision": 1,
            "contractSha256": "cd" * 32,
            "openDigest": "01" * 32,
            "evidenceSha256": "02" * 32,
            "bindingDigest": "03" * 32,
        }
        with self.assertRaises(DigestError):
            enc.certification_digest({**base, "stopProtocolVersion": 2})
        with self.assertRaises(DigestError):
            enc.certification_digest({**base, "certificateVersion": {"k": "s", "v": "1"}})
        # Explicit null goalRef is the shared no-Goal representation.
        self.assertEqual(
            enc.certification_digest(base),
            enc.certification_digest({**base, "goalRef": None}),
        )


class PredicateDigestTests(unittest.TestCase):
    def test_digest_is_recomputed_from_payload_not_copied(self) -> None:
        params = {"expected_outcome": {"k": "e", "v": "success"}, "min_matches": {"k": "i", "v": 1}}
        payload = enc.pred_params_bytes(params, enc.PRODUCT_KEY_VOCABULARY)
        self.assertEqual(enc.pred_params_digest(params, enc.PRODUCT_KEY_VOCABULARY), sha256(payload))
        tampered = {"expected_outcome": {"k": "e", "v": "success"}, "min_matches": {"k": "i", "v": 2}}
        self.assertNotEqual(
            enc.pred_params_digest(tampered, enc.PRODUCT_KEY_VOCABULARY),
            sha256(payload),
        )

    def test_manifest_binding_carries_recomputed_digest(self) -> None:
        record = {
            "item": "i",
            "semanticAction": "pull",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {},
            "predId": "p",
            "predVersion": 1,
            "predParamsKind": "manifest",
            "predParamsRef": "git-manifest-0001",
            "predParamsManifest": {"scope": {"k": "s", "v": "worktree"}},
            "effectEvidenceId": "e1",
        }
        payload = enc.binding_record_bytes(record, enc.PRODUCT_KEY_VOCABULARY)
        expected_digest = sha256(
            enc.pred_params_bytes(
                {"scope": {"k": "s", "v": "worktree"}}, enc.PRODUCT_KEY_VOCABULARY
            )
        )
        self.assertIn(b"git-manifest-0001", payload)
        self.assertIn(("x:" + expected_digest).encode(), payload)

    def test_inline_binding_embeds_raw_payload_bytes(self) -> None:
        record = {
            "item": "i",
            "semanticAction": "test",
            "resolvedTarget": {"scope": {"k": "s", "v": "s"}},
            "observedState": {},
            "predId": "p",
            "predVersion": 1,
            "predParamsKind": "inline",
            "predParams": {"expected_outcome": {"k": "e", "v": "success"}},
            "effectEvidenceId": "e1",
        }
        payload = enc.binding_record_bytes(record, enc.PRODUCT_KEY_VOCABULARY)
        inner = enc.pred_params_bytes(
            {"expected_outcome": {"k": "e", "v": "success"}}, enc.PRODUCT_KEY_VOCABULARY
        )
        self.assertIn(inner, payload)

    def test_goal_ref_fields_are_pairwise_present_or_absent(self) -> None:
        base = {
            "stopProtocolVersion": "2.0.0",
            "certificateVersion": "1",
            "epoch": 0,
            "sessionRefDigest": "ab" * 32,
            "hostLockDigest": "cd" * 32,
            "contractRevision": 1,
            "contractSha256": "ef" * 32,
            "openDigest": "01" * 32,
            "evidenceSha256": "02" * 32,
            "bindingDigest": "03" * 32,
        }
        without_goal = enc.certification_digest(base)
        with_goal = enc.certification_digest(
            {**base, "goalRef": {"id": "goal-1", "revision": 2}}
        )
        self.assertNotEqual(without_goal, with_goal)

    def test_locator_digest_is_domain_separated_and_distinct(self) -> None:
        expected = json.loads(EXPECTED.read_text(encoding="utf-8"))["expected"]
        self.assertEqual(enc.locator_digest("\\\\server\\share\\x"), expected["L1"])
        self.assertEqual(enc.locator_digest("C:\\repo\\CON"), expected["L2"])
        self.assertEqual(enc.locator_digest("\\\\server2\\share\\y"), expected["L3"])
        # Same reason (unc), different locator: no identity collapse.
        self.assertNotEqual(expected["L1"], expected["L3"])


if __name__ == "__main__":
    unittest.main()
