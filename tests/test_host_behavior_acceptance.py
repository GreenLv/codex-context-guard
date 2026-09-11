"""Host-behavior acceptance profile: collector/validator regressions (r2).

Every fixture in this module is synthetic and labeled as such. These are
validator/parser unit tests only; they never count as native or actual-host
evidence. Host ``passed`` is unreachable in this source: no supported
accepted raw-to-gate mapping exists yet, so any capture at best stays pending with
its parser chain validity recorded separately.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
HOST_SCRIPT = ROOT / "tools" / "validation" / "host_behavior.py"
NATIVE_SCRIPT = ROOT / "tools" / "validation" / "native_acceptance.py"

_SPEC = importlib.util.spec_from_file_location("host_behavior", HOST_SCRIPT)
assert _SPEC and _SPEC.loader
HB = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(HB)

_NATIVE_SPEC = importlib.util.spec_from_file_location(
    "native_acceptance_entry", NATIVE_SCRIPT
)
assert _NATIVE_SPEC and _NATIVE_SPEC.loader
NATIVE = importlib.util.module_from_spec(_NATIVE_SPEC)
_NATIVE_SPEC.loader.exec_module(NATIVE)

SOURCE_COMMIT = "a" * 40
PREPARED_SOURCE = "b" * 64
RUNTIME_DIGEST = "c" * 64
SESSION = "sess-synthetic"
OTHER_SESSION = "sess-other"
PLUGIN_VERSION = "0.12.4"

DECLARED = {
    "source_commit": SOURCE_COMMIT,
    "prepared_source_sha256": PREPARED_SOURCE,
    "runtime_tree_sha256": RUNTIME_DIGEST,
}
SCENARIOS = [
    "hook_trust",
    "continuity_wait",
    "compact_resume",
    "commit_event",
    "local_push_readback",
    "cleanup",
]


def producer(**overrides) -> dict:
    base = {
        "kind": "codex_hook",
        "hook_event": "PreToolUse",
        "runtime_tree_sha256": RUNTIME_DIGEST,
        "plugin_version": PLUGIN_VERSION,
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def make_record(
    event_type: str,
    scenario: str,
    sequence: int,
    *,
    event_id: str | None = None,
    session: str = SESSION,
    subject: str = "fact-1",
    prod: dict | None = None,
    pair_id: str | None = None,
    pair_role: str | None = None,
    remaining_ids: list | None = None,
    synthetic: bool = False,
) -> dict:
    record = {
        "schema": "host-behavior-events/v2",
        "event_id": event_id or f"ev-{sequence:04d}",
        "observed_at": f"2026-09-07T10:00:{sequence % 60:02d}.000000Z",
        "sequence": sequence,
        "session_id": session,
        "scenario_id": scenario,
        "event_type": event_type,
        "subject_id": subject,
        "producer": prod or producer(),
    }
    if pair_id is not None:
        record["pair_id"] = pair_id
    if pair_role is not None:
        record["pair_role"] = pair_role
    if remaining_ids is not None:
        record["remaining_ids"] = remaining_ids
    if synthetic:
        record["synthetic"] = True
    return record


def raw_lines(records: list[dict]) -> list[str]:
    return [json.dumps(record, sort_keys=True) for record in records]


def full_records() -> list[dict]:
    records: list[dict] = []
    plans = (
        ("hook_trust", "hook_trust", ["hook_trust_reviewed", "hook_trust_granted"]),
        (
            "continuity_wait",
            "continuity_wait",
            ["requirement_registered", "wait_started", "wait_released"],
        ),
        (
            "compact_resume",
            "compact_resume",
            ["compact_started", "session_resumed", "recovery_page_shown"],
        ),
        (
            "local_push_readback",
            "local_push_readback",
            ["push_requested", "push_readback_observed"],
        ),
    )
    for scenario, subject, types in plans:
        for event_type in types:
            records.append(
                make_record(event_type, scenario, len(records) + 1, subject=subject)
            )
    records.append(
        make_record(
            "commit_requested", "commit_event", len(records) + 1,
            subject="commit-1", pair_id="pair-1", pair_role="request",
        )
    )
    records.append(
        make_record(
            "commit_observed", "commit_event", len(records) + 1,
            subject="commit-1", pair_id="pair-1", pair_role="response",
        )
    )
    records.append(
        make_record(
            "commit_readback_observed", "commit_event", len(records) + 1,
            subject="commit-1",
        )
    )
    records.append(
        make_record(
            "cleanup_observed", "cleanup", len(records) + 1,
            subject="temp-root-1", remaining_ids=[],
        )
    )
    return records


def capture(records: list[dict], *, origin: str = "synthetic", **overrides) -> dict:
    bundle = {
        "schema": "host-behavior-capture/v2",
        "origin": origin,
        "subject": dict(DECLARED),
        "session_id": SESSION,
        "plugin_version": PLUGIN_VERSION,
        "scenarios": list(SCENARIOS),
        "host": {"os": "macos", "python": "3.12.2", "codex": "0.153.4"},
        "events": raw_lines(records),
    }
    bundle.update(overrides)
    return bundle


def validate_capture(bundle: dict, declared: dict | None = None):
    return HB.Validator(dict(declared or DECLARED), PLUGIN_VERSION).validate(bundle)


def gates_by_id(result: dict) -> dict:
    return {gate["id"]: gate for gate in result["gates"]}


class CollectorTests(unittest.TestCase):
    def test_collector_binds_digest_to_raw_bytes(self) -> None:
        records = full_records()
        lines = raw_lines(records)
        normalized = HB.Collector().collect_raw(lines)
        for line, record in zip(lines, normalized):
            self.assertEqual(
                record["payload_sha256"],
                hashlib.sha256(line.encode("utf-8")).hexdigest(),
            )
        self.assertEqual(len(normalized), len(records))

    def test_collector_rejects_malformed_raw_lines(self) -> None:
        collector = HB.Collector()
        with self.assertRaises(HB.HostBehaviorError):
            collector.collect_raw(["{not json"])
        bad_time = make_record("hook_trust_reviewed", "hook_trust", 1)
        bad_time["observed_at"] = "not-a-timestamp"
        with self.assertRaises(HB.HostBehaviorError):
            collector.collect_raw(raw_lines([bad_time]))
        bad_producer = make_record(
            "hook_trust_reviewed", "hook_trust", 2,
            prod=producer(hook_event=None),
        )
        with self.assertRaises(HB.HostBehaviorError):
            collector.collect_raw(raw_lines([bad_producer]))

    def test_collector_rejects_caller_claimed_digest_fields(self) -> None:
        collector = HB.Collector()
        forged = make_record("hook_trust_reviewed", "hook_trust", 1)
        forged["payload_sha256"] = "d" * 64
        with self.assertRaises(HB.HostBehaviorError):
            collector.collect_raw(raw_lines([forged]))

    def test_collector_records_carry_no_status_authority(self) -> None:
        normalized = HB.Collector().collect_raw(raw_lines(full_records()))
        self.assertFalse(any("status" in record for record in normalized))


class OriginTests(unittest.TestCase):
    def test_unmarked_legacy_dict_never_passes(self) -> None:
        legacy = {
            "schema": "host-behavior-capture/v1",
            "session_id": SESSION,
            "scenarios": SCENARIOS,
            "cleanup": {"status": "passed", "remaining_ids": []},
            "host": {"os": "macos", "python": "3.12.2", "codex": "0.153.4"},
            "events": [],
        }
        result = validate_capture(legacy)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(
            gates_by_id(result)["hook_trust"]["evidence"]["mode"],
            "unverified_origin",
        )
        self.assertFalse(result["visibility"]["host_passed_reachable"])

    def test_external_normalized_bundle_never_passes(self) -> None:
        result = validate_capture(capture(full_records(), origin="external_normalized"))
        self.assertEqual(result["status"], "pending")
        self.assertTrue(
            all(
                gate["status"] == "pending"
                and gate["chain"] == "valid"
                and gate["evidence"]["mode"] == "unverified_origin"
                for gate in result["gates"]
            )
        )

    def test_collector_origin_valid_chains_stay_pending(self) -> None:
        result = validate_capture(capture(full_records(), origin="collector_v1"))
        self.assertEqual(result["status"], "pending")
        self.assertTrue(
            all(
                gate["status"] == "pending" and gate["chain"] == "valid"
                for gate in result["gates"]
            )
        )
        self.assertIn("live", result["capability_note"])

    def test_synthetic_marker_forces_pending_fixture_mode(self) -> None:
        records = [
            dict(record, synthetic=True) for record in full_records()
        ]
        result = validate_capture(capture(records, origin="collector_v1"))
        self.assertEqual(result["status"], "pending")
        self.assertEqual(
            gates_by_id(result)["hook_trust"]["evidence"]["mode"],
            "synthetic_unit_fixture",
        )


class ContradictionTests(unittest.TestCase):
    def contradiction(self, mutate) -> dict:
        records = full_records()
        mutate(records)
        for origin in ("synthetic", "external_normalized", "collector_v1"):
            result = validate_capture(capture(records, origin=origin))
            with self.subTest(origin=origin):
                self.assertEqual(result["status"], "failed")
        return validate_capture(capture(records, origin="collector_v1"))

    def test_reversed_pair_roles_fail(self) -> None:
        def mutate(records: list[dict]) -> None:
            for record in records:
                if record["event_type"] == "commit_requested":
                    record["pair_role"] = "response"
                elif record["event_type"] == "commit_observed":
                    record["pair_role"] = "request"

        result = self.contradiction(mutate)
        self.assertEqual(gates_by_id(result)["commit_event"]["chain"], "contradicted")

    def test_duplicate_event_ids_fail(self) -> None:
        def mutate(records: list[dict]) -> None:
            records[1]["event_id"] = records[0]["event_id"]

        result = self.contradiction(mutate)
        self.assertEqual(result["status"], "failed")

    def test_replayed_identical_raw_event_fails(self) -> None:
        def mutate(records: list[dict]) -> None:
            records.append(copy.deepcopy(records[0]))

        result = self.contradiction(mutate)
        self.assertEqual(result["status"], "failed")

    def test_subject_id_mismatch_fails(self) -> None:
        def mutate(records: list[dict]) -> None:
            for record in records:
                if record["event_type"] == "wait_released":
                    record["subject_id"] = "fact-2"

        result = self.contradiction(mutate)
        self.assertEqual(
            gates_by_id(result)["continuity_wait"]["chain"], "contradicted"
        )

    def test_producer_version_mismatch_fails(self) -> None:
        def mutate(records: list[dict]) -> None:
            records[0]["producer"]["plugin_version"] = "0.0.0"

        result = self.contradiction(mutate)
        self.assertEqual(result["status"], "failed")

    def test_foreign_runtime_producer_fails(self) -> None:
        def mutate(records: list[dict]) -> None:
            records[3]["producer"]["runtime_tree_sha256"] = "e" * 64

        result = self.contradiction(mutate)
        self.assertEqual(result["status"], "failed")

    def test_foreign_session_fails(self) -> None:
        def mutate(records: list[dict]) -> None:
            records[0] = make_record(
                records[0]["event_type"],
                records[0]["scenario_id"],
                records[0]["sequence"],
                session=OTHER_SESSION,
            )

        result = self.contradiction(mutate)
        self.assertEqual(result["status"], "failed")

    def test_cross_scenario_contamination_fails_gate(self) -> None:
        def mutate(records: list[dict]) -> None:
            records.append(
                make_record("wait_released", "hook_trust", 900, subject="fact-1")
            )

        result = self.contradiction(mutate)
        self.assertEqual(gates_by_id(result)["hook_trust"]["chain"], "contradicted")

    def test_sequence_regression_fails(self) -> None:
        def mutate(records: list[dict]) -> None:
            records[4]["sequence"] = -5

        result = self.contradiction(mutate)
        self.assertEqual(result["status"], "failed")

    def test_declared_subject_mismatch_fails(self) -> None:
        for field, value in (
            ("runtime_tree_sha256", "f" * 64),
            ("prepared_source_sha256", "0" * 64),
            ("source_commit", "b" * 40),
        ):
            with self.subTest(field=field):
                declared = {**DECLARED, field: value}
                result = validate_capture(capture(full_records()), declared)
                self.assertEqual(result["status"], "failed")

    def test_capture_plugin_version_mismatch_fails(self) -> None:
        result = validate_capture(
            capture(full_records(), plugin_version="9.9.9")
        )
        self.assertEqual(result["status"], "failed")


class IncompleteTests(unittest.TestCase):
    def test_missing_final_readback_is_pending_not_failed(self) -> None:
        records = [
            record
            for record in full_records()
            if record["event_type"] != "commit_readback_observed"
        ]
        result = validate_capture(capture(records, origin="collector_v1"))
        gate = gates_by_id(result)["commit_event"]
        self.assertEqual(gate["chain"], "incomplete")
        self.assertEqual(gate["status"], "pending")
        self.assertEqual(result["status"], "pending")

    def test_empty_capture_is_pending(self) -> None:
        result = validate_capture(capture([], origin="collector_v1"))
        self.assertEqual(result["status"], "pending")
        self.assertEqual(gates_by_id(result)["cleanup"]["chain"], "absent")

    def test_missing_subject_id_is_pending_not_failed(self) -> None:
        records = full_records()
        for record in records:
            if record["event_type"] == "wait_released":
                del record["subject_id"]
        result = validate_capture(capture(records, origin="collector_v1"))
        gate = gates_by_id(result)["continuity_wait"]
        self.assertEqual(gate["status"], "pending")
        self.assertNotEqual(gate["chain"], "contradicted")

    def test_unverified_producer_kind_is_pending_not_failed(self) -> None:
        records = full_records()
        for record in records:
            if record["scenario_id"] == "hook_trust":
                record["producer"] = producer(
                    kind="model_summary", hook_event=None
                )
        result = validate_capture(capture(records, origin="collector_v1"))
        gate = gates_by_id(result)["hook_trust"]
        self.assertEqual(gate["status"], "pending")
        self.assertEqual(gate["evidence"]["mode"], "unverified_producer")


class CapabilityRecordTests(unittest.TestCase):
    def test_capability_record_is_pending_and_reaches_no_pass(self) -> None:
        result = HB.capability_record(DECLARED, PLUGIN_VERSION, "no_host_entry")
        self.assertEqual(result["status"], "pending")
        self.assertTrue(all(gate["chain"] == "absent" for gate in result["gates"]))
        self.assertFalse(result["visibility"]["host_passed_reachable"])
        self.assertIn("no_host_entry", result["capability_note"])

    def test_capability_record_binds_declared_identity(self) -> None:
        result = HB.capability_record(DECLARED, PLUGIN_VERSION, "no_host_entry")
        self.assertEqual(
            result["subject"],
            {
                "kind": "prepared_host_behavior",
                "source_commit": SOURCE_COMMIT,
                "prepared_source_sha256": PREPARED_SOURCE,
                "runtime_tree_sha256": RUNTIME_DIGEST,
            },
        )


class AnnexTests(unittest.TestCase):
    def test_annex_sanitizes_attacker_controlled_strings(self) -> None:
        records = full_records()
        for record in records:
            if record["scenario_id"] == "hook_trust":
                record["scenario_id"] = f"/private/synthetic-user/{SESSION}"
        result = validate_capture(capture(records, origin="collector_v1"))
        annex = result["public_annex"]
        serialized = json.dumps(annex)
        self.assertNotIn("/private/synthetic-user/", serialized)
        self.assertNotIn(SESSION, serialized)
        by_type = {redacted["event_type"]: redacted for redacted in annex["events"]}
        self.assertEqual(by_type["hook_trust_reviewed"]["scenario_id"], "[redacted]")
        self.assertEqual(by_type["wait_released"]["scenario_id"], "continuity_wait")

    def test_private_looking_lowercase_tokens_are_redacted(self) -> None:
        """r3: harmless-looking identifiers are not an allowlist; enums are."""
        records = full_records()
        for record in records:
            if record["scenario_id"] == "hook_trust":
                record["scenario_id"] = "private_customer_alice"
                record["event_type"] = "private_customer_alice"
        bundle = capture(records, origin="collector_v1")
        bundle["scenarios"] = SCENARIOS + ["private_customer_alice"]
        result = validate_capture(bundle)
        annex = result["public_annex"]
        serialized = json.dumps(annex)
        self.assertNotIn("private_customer_alice", serialized)
        self.assertTrue(result["visibility"]["public_annex_sanitized"])

    def test_annex_keeps_only_protocol_enum_labels(self) -> None:
        result = validate_capture(capture(full_records(), origin="collector_v1"))
        annex = result["public_annex"]
        for redacted in annex["events"]:
            self.assertIn(redacted["event_type"], HB._PUBLIC_EVENT_TYPES)
            self.assertIn(redacted["scenario_id"], HB._PUBLIC_SCENARIOS)
            self.assertEqual(
                set(redacted), {"event_type", "scenario_id", "payload_sha256"}
            )

    def test_annex_keeps_only_allowlisted_facts(self) -> None:
        result = validate_capture(capture(full_records(), origin="collector_v1"))
        annex = result["public_annex"]
        for redacted in annex["events"]:
            self.assertEqual(
                set(redacted), {"event_type", "scenario_id", "payload_sha256"}
            )

    def test_result_marks_full_document_private(self) -> None:
        result = validate_capture(capture(full_records(), origin="collector_v1"))
        self.assertFalse(result["visibility"]["full_result_is_public"])
        self.assertTrue(result["visibility"]["public_annex_sanitized"])
        self.assertEqual(result["sessions"][0]["session_id"], SESSION)


class PrecedenceTests(unittest.TestCase):
    """r3: contradictory observed facts override every pending reason."""

    def test_role_contradiction_overrides_unverified_producer(self) -> None:
        records = full_records()
        for record in records:
            if record["event_type"] == "commit_requested":
                record["pair_role"] = "response"
                record["producer"] = producer(
                    kind="model_summary", hook_event=None
                )
            elif record["event_type"] == "commit_observed":
                record["pair_role"] = "request"
                record["producer"] = producer(
                    kind="model_summary", hook_event=None
                )
        result = validate_capture(capture(records, origin="collector_v1"))
        gate = gates_by_id(result)["commit_event"]
        self.assertEqual(gate["chain"], "contradicted")
        self.assertEqual(gate["status"], "failed")
        self.assertEqual(result["status"], "failed")

    def test_role_contradiction_overrides_missing_subject(self) -> None:
        records = full_records()
        for record in records:
            if record["event_type"] in {"commit_requested", "commit_observed"}:
                record["pair_role"] = (
                    "response" if record["event_type"] == "commit_requested"
                    else "request"
                )
                del record["subject_id"]
        result = validate_capture(capture(records, origin="collector_v1"))
        gate = gates_by_id(result)["commit_event"]
        self.assertEqual(gate["chain"], "contradicted")
        self.assertEqual(result["status"], "failed")

    def test_cleanup_fact_contradiction_overrides_missing_subject(self) -> None:
        records = full_records()
        for record in records:
            if record["event_type"] == "cleanup_observed":
                record["remaining_ids"] = ["stray-dir"]
                del record["subject_id"]
        result = validate_capture(capture(records, origin="collector_v1"))
        gate = gates_by_id(result)["cleanup"]
        self.assertEqual(gate["chain"], "contradicted")
        self.assertEqual(result["status"], "failed")


class CleanupFactTests(unittest.TestCase):
    def test_complete_cleanup_positive_with_explicit_empty_list(self) -> None:
        """r3: a genuinely complete parser cleanup positive states its facts."""
        result = validate_capture(capture(full_records(), origin="collector_v1"))
        gate = gates_by_id(result)["cleanup"]
        self.assertEqual(gate["chain"], "valid")
        self.assertEqual(gate["status"], "pending")

    def test_cleanup_without_remaining_ids_is_incomplete(self) -> None:
        """r3: omitted observed facts must not imply an empty list."""
        records = [
            record
            for record in full_records()
            if record["event_type"] != "cleanup_observed"
        ]
        records.append(
            make_record(
                "cleanup_observed", "cleanup", len(records) + 1,
                subject="temp-root-1",
            )
        )
        result = validate_capture(capture(records, origin="collector_v1"))
        gate = gates_by_id(result)["cleanup"]
        self.assertEqual(gate["chain"], "incomplete")
        self.assertEqual(gate["status"], "pending")
        self.assertEqual(gate["evidence"]["mode"], "missing_cleanup_facts")

    def test_handwritten_cleanup_field_is_ignored(self) -> None:
        bundle = capture([], origin="collector_v1")
        bundle["cleanup"] = {"status": "passed", "remaining_ids": []}
        result = validate_capture(bundle)
        self.assertEqual(gates_by_id(result)["cleanup"]["chain"], "absent")
        self.assertEqual(gates_by_id(result)["cleanup"]["status"], "pending")

    def test_observed_remaining_ids_fail_cleanup(self) -> None:
        records = [
            record
            for record in full_records()
            if record["event_type"] != "cleanup_observed"
        ]
        records.append(
            make_record(
                "cleanup_observed", "cleanup", len(records) + 1,
                subject="temp-root-1", remaining_ids=["stray-dir"],
            )
        )
        result = validate_capture(capture(records, origin="collector_v1"))
        gate = gates_by_id(result)["cleanup"]
        self.assertEqual(gate["chain"], "contradicted")
        self.assertEqual(result["status"], "failed")


class ResultContractTests(unittest.TestCase):
    def test_default_plugin_version_tracks_manifest(self) -> None:
        manifest = json.loads(
            (ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
        )
        self.assertEqual(HB.PLUGIN_VERSION_DEFAULT, manifest["version"])

    def test_result_kinds_validate_against_v2_schema(self) -> None:
        schema = json.loads(
            (ROOT / "tools" / "validation" / "native-acceptance-v2.schema.json")
            .read_text(encoding="utf-8")
        )
        samples = [
            ("capability", HB.capability_record(DECLARED, PLUGIN_VERSION, "r")),
            (
                "validated_capture",
                validate_capture(capture(full_records(), origin="collector_v1")),
            ),
            (
                "contradicted",
                validate_capture(
                    capture(
                        [
                            make_record(
                                "commit_requested", "commit_event", 1,
                                subject="commit-1",
                                pair_id="pair-1", pair_role="request",
                            ),
                            make_record(
                                "commit_requested", "commit_event", 2,
                                subject="commit-1",
                                pair_id="pair-1", pair_role="request",
                            ),
                        ],
                        origin="collector_v1",
                    )
                ),
            ),
        ]
        for label, sample in samples:
            with self.subTest(sample=label):
                self.assertTrue(_SchemaChecker.matches(schema, sample))


class _SchemaChecker:
    """Minimal structural check against the bundled v2 JSON schema subset."""

    @staticmethod
    def matches(node: dict, value) -> bool:
        kinds = node.get("type")
        if isinstance(kinds, str):
            kinds = [kinds]
        if kinds:
            checks = {
                "object": lambda v: isinstance(v, dict),
                "array": lambda v: isinstance(v, list),
                "string": lambda v: isinstance(v, str),
                "boolean": lambda v: isinstance(v, bool),
                "null": lambda v: v is None,
                "integer": lambda v: isinstance(v, int)
                and not isinstance(v, bool),
            }
            if not any(checks[kind](value) for kind in kinds):
                return False
        if "enum" in node and value not in node["enum"]:
            return False
        if "const" in node and value != node["const"]:
            return False
        if isinstance(value, dict):
            properties = node.get("properties", {})
            for key, sub in properties.items():
                if key in value and not _SchemaChecker.matches(sub, value[key]):
                    return False
            for key in node.get("required", []):
                if key not in value:
                    return False
            if node.get("additionalProperties") is False:
                if not set(value) <= set(properties):
                    return False
        if isinstance(value, list) and "items" in node:
            if not all(
                _SchemaChecker.matches(node["items"], item) for item in value
            ):
                return False
        return True


class CliTests(unittest.TestCase):
    def base_args(self, output: Path) -> list[str]:
        return [
            sys.executable,
            "tools/validation/native_acceptance.py",
            "--source-commit", SOURCE_COMMIT,
            "--output", str(output),
            "--profile", "host_behavior",
            "--prepared-source-sha256", PREPARED_SOURCE,
            "--runtime-tree-sha256", RUNTIME_DIGEST,
            "--plugin-version", PLUGIN_VERSION,
        ]

    def test_default_profile_is_portable_runtime(self) -> None:
        parser = NATIVE.build_argument_parser()
        args = parser.parse_args(
            ["--source-commit", SOURCE_COMMIT, "--output", "out.json"]
        )
        self.assertEqual(args.profile, "portable_runtime")

    def test_capability_record_cli_exit_is_pending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            completed = subprocess.run(
                self.base_args(output) + ["--capability-reason", "no_host_entry"],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(completed.returncode, 3, completed.stderr)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "pending")
            self.assertEqual(result["gate_profile"], "host_behavior")

    def test_external_bundle_cli_is_pending_not_passed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle_path = Path(directory) / "bundle.json"
            bundle_path.write_text(
                json.dumps(capture(full_records(), origin="external_normalized")),
                encoding="utf-8",
            )
            output = Path(directory) / "result.json"
            completed = subprocess.run(
                self.base_args(output) + ["--events-bundle", str(bundle_path)],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(completed.returncode, 3, completed.stderr)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "pending")
            self.assertFalse(result["visibility"]["host_passed_reachable"])

    def test_contradicted_bundle_cli_fails(self) -> None:
        records = full_records()
        records[1]["event_id"] = records[0]["event_id"]
        with tempfile.TemporaryDirectory() as directory:
            bundle_path = Path(directory) / "bundle.json"
            bundle_path.write_text(
                json.dumps(capture(records, origin="collector_v1")),
                encoding="utf-8",
            )
            output = Path(directory) / "result.json"
            completed = subprocess.run(
                self.base_args(output) + ["--events-bundle", str(bundle_path)],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "failed")

    def test_malformed_bundle_record_is_rejected(self) -> None:
        broken = make_record("hook_trust_reviewed", "hook_trust", 1)
        del broken["sequence"]
        with tempfile.TemporaryDirectory() as directory:
            bundle_path = Path(directory) / "bundle.json"
            bundle_path.write_text(
                json.dumps(capture([broken], origin="collector_v1")),
                encoding="utf-8",
            )
            completed = subprocess.run(
                self.base_args(Path(directory) / "result.json")
                + ["--events-bundle", str(bundle_path)],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("sequence", completed.stderr)

    def test_missing_declared_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [
                    sys.executable,
                    "tools/validation/native_acceptance.py",
                    "--source-commit", SOURCE_COMMIT,
                    "--output", str(Path(directory) / "result.json"),
                    "--profile", "host_behavior",
                ],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("runtime-tree-sha256", completed.stderr)

    def test_portable_profile_rejects_missing_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [
                    sys.executable,
                    "tools/validation/native_acceptance.py",
                    "--source-commit", SOURCE_COMMIT,
                    "--output", str(Path(directory) / "result.json"),
                ],
                cwd=ROOT, capture_output=True, text=True,
                env={"PATH": "/nonexistent"},
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((Path(directory) / "result.json").exists())


class PurityTests(unittest.TestCase):
    def test_validator_does_not_mutate_capture(self) -> None:
        bundle = capture(full_records(), origin="collector_v1")
        frozen = copy.deepcopy(bundle)
        validate_capture(bundle)
        self.assertEqual(bundle, frozen)

    def test_host_behavior_module_does_not_import_product_runtime(self) -> None:
        import ast

        tree = ast.parse(HOST_SCRIPT.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        self.assertTrue(imported)
        for banned in (
            "context_guard",
            "cg_hook",
            "cg_actions",
            "cg_protocol",
            "cg_codex_adapter",
            "manage_plugin",
        ):
            for module_name in imported:
                self.assertNotIn(banned, module_name)


if __name__ == "__main__":
    unittest.main()
