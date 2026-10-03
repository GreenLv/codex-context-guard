"""CG-0151 incident-native toolkit regression (review F6).

The toolkit's capture/mapper/oracle chain must be deterministic, bound to
the frozen scenario manifest, and its preflight must catch an inverted
capture. These tests prove the zero-model toolchain only; native host
acceptance stays a coordinator-owned gate.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

spec = __import__("importlib").util.spec_from_file_location(
    "incident_toolkit", ROOT / "tools" / "validation" / "incident_toolkit.py")
toolkit = __import__("importlib").util.module_from_spec(spec)
sys.modules["incident_toolkit"] = toolkit
spec.loader.exec_module(toolkit)


class IncidentToolkitTests(unittest.TestCase):
    def test_manifest_identity_and_oracle_coverage(self):
        manifest = toolkit.load_manifest()
        self.assertEqual(manifest["schema"], "cg-incident-scenarios/v1")
        ids = [scenario["id"] for scenario in manifest["scenarios"]]
        self.assertEqual(sorted(ids), sorted(toolkit.SCENARIO_IDS))
        for scenario in manifest["scenarios"]:
            self.assertTrue(scenario["oracle_rows"])
            for row in scenario["oracle_rows"]:
                self.assertIn(row["desired"], (True, False))
                self.assertNotIn("prompt", json.dumps(row))
        self.assertEqual(
            manifest["incidents"]["pause-resume-v1"],
            "CGI-20261002-codex-pause-resume-wait-stall")
        self.assertEqual(
            manifest["incidents"]["checkpoint-status-v1"],
            "CGI-20261003-codex-checkpoint-status-posttool-rejection")

    def test_pause_resume_capture_maps_and_judges_green(self):
        capture = toolkit.capture_pause_resume(ROOT)
        self.assertEqual(capture["schema"], toolkit.CAPTURE_SCHEMA)
        self.assertEqual(capture["scenario_id"], "pause-resume-v1")
        self.assertIn("not native acceptance", capture["execution_boundary"])
        mapping = toolkit.map_capture(capture)
        self.assertEqual(mapping["capture_sha256"], hashlib.sha256(
            json.dumps(capture, sort_keys=True,
                       ensure_ascii=True).encode()).hexdigest())
        verdict = toolkit.judge(mapping, toolkit.load_manifest())
        self.assertEqual(verdict["failed_count"], 0)
        self.assertEqual(verdict["passed_count"], len(verdict["rows"]))

    def test_inverted_capture_fails_the_oracle(self):
        capture = toolkit.capture_pause_resume(ROOT)
        capture["events"] = [event for event in capture["events"]
                             if event["kind"] != "negated_resume"]
        capture["events"].append({"event": "UserPromptSubmit",
                                  "kind": "negated_resume", "waiting": 0})
        verdict = toolkit.judge(toolkit.map_capture(capture),
                                toolkit.load_manifest())
        self.assertEqual(verdict["failed_count"], 1)
        self.assertIn("negated_resume_keeps_waiting",
                      {row["id"] for row in verdict["rows"] if not row["passed"]})

    def test_checkpoint_status_capture_maps_and_judges_green(self):
        capture = toolkit.capture_checkpoint_status(ROOT)
        self.assertEqual(capture["scenario_id"], "checkpoint-status-v1")
        verdict = toolkit.judge(toolkit.map_capture(capture),
                                toolkit.load_manifest())
        self.assertEqual(verdict["failed_count"], 0)
        kinds = [event["kind"] for event in capture["events"]]
        self.assertIn("missing_value_guard", kinds)
        self.assertIn("legal_commands_query", kinds)

    def test_mapper_rejects_foreign_schemas_and_unknown_rows(self):
        with self.assertRaises(ValueError):
            toolkit.map_capture({"schema": "other/v1", "events": []})
        mapping = {
            "schema": toolkit.MAPPING_SCHEMA,
            "scenario_id": "pause-resume-v1",
            "capture_sha256": "0" * 64,
            "platform_family": "posix",
            "rows": [{"id": "not-in-manifest", "observed": True}],
        }
        with self.assertRaises(ValueError):
            toolkit.judge(mapping, toolkit.load_manifest())

    def test_preflight_receipt_green_and_deterministic_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "preflight.json"
            result = subprocess.run(
                [sys.executable,
                 str(ROOT / "tools" / "validation" / "incident_toolkit.py"),
                 "--preflight", str(output)],
                capture_output=True, text=True, check=False,
                cwd=ROOT,
            )
            self.assertEqual(result.returncode, 0, result.stderr[-800:])
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema"], toolkit.PREFLIGHT_SCHEMA)
            self.assertTrue(receipt["preflight_passed"])
            self.assertEqual(receipt["manifest_sha256"],
                             toolkit.sha256_file(toolkit.MANIFEST_PATH))
            self.assertIn("no native", receipt["boundary"])
            names = [check["check"] for check in receipt["checks"]]
            self.assertIn("pause_resume_negative_fixture_detected", names)
            self.assertIn("checkpoint_status_positive_fixture", names)
            self.assertIn("powershell_spelling_adapter", names)



    # -- R2 incident-oracle family matrix ---------------------------------
    def _base_mapping(self, scenario):
        rows = [{"id": row["id"], "observed": row["desired"]}
                for row in scenario["oracle_rows"]]
        return {"schema": toolkit.MAPPING_SCHEMA,
                "scenario_id": scenario["id"], "capture_sha256": "a" * 64,
                "platform_family": "posix", "rows": rows}

    def test_r2_judge_oracle_matrix(self):
        manifest = toolkit.load_manifest()
        for scenario in manifest["scenarios"]:
            full = self._base_mapping(scenario)
            verdict = toolkit.judge(full, manifest)
            self.assertEqual(verdict["failed_count"], 0, scenario["id"])
            variants = {}
            empty = dict(full, rows=[])
            variants["empty"] = (empty, None)
            one = dict(full, rows=full["rows"][:1])
            variants["one-row-only"] = (one, None)
            dup = dict(full, rows=[full["rows"][0], full["rows"][0]])
            variants["duplicate-first-row"] = (dup, None)
            unknown = dict(full, rows=full["rows"]
                           + [{"id": "not-in-manifest", "observed": True}])
            variants["unknown-row"] = (unknown, None)
            nonbool = dict(full, rows=[dict(full["rows"][0],
                                            observed="yes")]
                           + full["rows"][1:])
            variants["non-boolean-observed"] = (nonbool, None)
            extra_key = dict(full, rows=[dict(full["rows"][0], extra=1)]
                             + full["rows"][1:])
            variants["malformed-row"] = (extra_key, None)
            wrong_schema = dict(full, schema="cg-incident-mapping/v0")
            variants["unsupported-schema"] = (wrong_schema, None)
            bad_digest = dict(full, capture_sha256="nope")
            variants["bad-capture-digest"] = (bad_digest, None)
            unknown_scenario = dict(full, scenario_id="other-v9")
            variants["unknown-scenario"] = (unknown_scenario, None)
            for label, (mapping, _) in variants.items():
                with self.subTest(scenario=scenario["id"], case=label):
                    with self.assertRaises(ValueError):
                        toolkit.judge(mapping, manifest)
            # Behavior inversion still produces a verdict with a failing
            # row (a real observation, not a structural rejection).
            inverted = dict(full,
                            rows=[dict(row, observed=not row["observed"])
                                  for row in full["rows"]])
            inverted_verdict = toolkit.judge(inverted, manifest)
            self.assertEqual(inverted_verdict["failed_count"],
                             len(inverted["rows"]))

    def test_r2_mapper_structural_matrix(self):
        for scenario_id, extra in (("pause-resume-v1", "activation"),
                                   ("checkpoint-status-v1", None)):
            capture = (toolkit.capture_pause_resume(ROOT)
                       if scenario_id == "pause-resume-v1"
                       else toolkit.capture_checkpoint_status(ROOT))
            self.assertEqual(capture["scenario_id"], scenario_id)
            required = toolkit.REQUIRED_EVENT_KINDS[scenario_id]
            def without(kind):
                trimmed = dict(capture,
                               events=[event for event in capture["events"]
                                       if event["kind"] != kind])
                return trimmed
            def duplicated(kind):
                event = next(event for event in capture["events"]
                             if event["kind"] == kind)
                return dict(capture,
                            events=capture["events"] + [dict(event)])
            variants = {
                "missing-required-event": without(required[0]),
                "duplicate-event": duplicated(required[0]),
                "unknown-event-kind": dict(
                    capture, events=capture["events"]
                    + [{"kind": "mystery", "event": "X"}]),
                "malformed-event": dict(capture, events=capture["events"] + ["junk"]),
                "events-not-a-list": dict(capture, events={"kind": "x"}),
                "unsupported-schema": dict(capture, schema="cg-incident-capture/v0"),
            }
            for label, mutated in variants.items():
                with self.subTest(scenario=scenario_id, case=label):
                    with self.assertRaises(ValueError):
                        toolkit.map_capture(mutated)
            if extra:
                with self.subTest(scenario=scenario_id, case="extra-kind-ok"):
                    allowed = dict(capture, events=capture["events"])
                    toolkit.map_capture(allowed)  # activation kind is legal

    # -- R2 result-storage family matrix ----------------------------------
    def test_r2_preflight_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "receipt.json"
            sentinel = b"previous immutable receipt\n"
            output.write_bytes(sentinel)
            exit_code = toolkit.preflight(output)
            self.assertEqual(exit_code, toolkit.EXIT_OUTPUT_NOT_CREATED)
            self.assertEqual(output.read_bytes(), sentinel)
            self.assertNotIn(".cg-toolkit-probe-",
                             [item.name for item in Path(tmp).iterdir()])

    def test_r2_preflight_race_creation_reports_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "receipt.json"
            real_open = os.open
            def racing_open(path, flags, *rest, **keywords):
                if Path(os.fsdecode(path)) == output:
                    raise FileExistsError(17, "File exists", str(path))
                return real_open(path, flags, *rest, **keywords)
            with mock.patch.object(os, "open", side_effect=racing_open):
                exit_code = toolkit.preflight(output)
            self.assertEqual(exit_code, toolkit.EXIT_OUTPUT_NOT_CREATED)
            self.assertFalse(output.exists())

    def test_r2_preflight_unwritable_directory_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "receipt.json"
            real_open = os.open
            refusing_dir = Path(tmp) / "locked"
            refusing_dir.mkdir()
            refusing_dir.chmod(0o500)
            try:
                def blocked_open(path, flags, *rest, **keywords):
                    if Path(os.fsdecode(path)).parent == refusing_dir:
                        raise PermissionError(13, "Permission denied",
                                              str(path))
                    return real_open(path, flags, *rest, **keywords)
                with mock.patch.object(os, "open", side_effect=blocked_open):
                    exit_code = toolkit.preflight(
                        refusing_dir / "receipt.json")
                self.assertEqual(exit_code, toolkit.EXIT_OUTPUT_NOT_CREATED)
                self.assertEqual(list(refusing_dir.iterdir()), [])
                self.assertFalse(output.exists())
            finally:
                refusing_dir.chmod(0o700)

    def test_r2_capture_cli_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "capture.json"
            sentinel = b"previous capture bytes\n"
            output.write_bytes(sentinel)
            result = subprocess.run(
                [sys.executable,
                 str(ROOT / "tools" / "validation" / "incident_toolkit.py"),
                 "--scenario", "pause-resume-v1", "--product-root", str(ROOT),
                 "--capture-output", str(output)],
                capture_output=True, text=True, check=False, cwd=ROOT)
            self.assertEqual(result.returncode,
                             toolkit.EXIT_OUTPUT_NOT_CREATED)
            self.assertEqual(output.read_bytes(), sentinel)

    def test_r2_preflight_needs_no_symlink_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "receipt.json"
            def refusing_symlink(self_path, target, *args, **kwargs):
                raise OSError("symlink capability unavailable")
            with mock.patch.object(Path, "symlink_to", refusing_symlink):
                exit_code = toolkit.preflight(output)
            self.assertEqual(exit_code, toolkit.EXIT_OK)
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(receipt["preflight_passed"])


if __name__ == "__main__":
    unittest.main()
