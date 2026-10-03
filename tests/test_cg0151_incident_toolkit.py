"""CG-0151 incident-native toolkit regression (review F6).

The toolkit's capture/mapper/oracle chain must be deterministic, bound to
the frozen scenario manifest, and its preflight must catch an inverted
capture. These tests prove the zero-model toolchain only; native host
acceptance stays a coordinator-owned gate.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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
        self.assertEqual(verdict["rows"][-1]["id"], "negated_resume_keeps_waiting")

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


if __name__ == "__main__":
    unittest.main()
