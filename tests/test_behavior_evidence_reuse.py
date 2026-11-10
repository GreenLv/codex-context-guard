"""Historical evidence reuse binds the complete owner run and inputs."""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_incident_coverage as incident  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "behavior_evidence_reuse", ROOT / "tools/validation/behavior_evidence_reuse.py")
reuse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reuse)


class OwnerRunTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / "repository"
        self.root.mkdir()
        for path in ("tests/fixtures/incidents", "assets", "scripts", "tools/validation"):
            (self.root / path).mkdir(parents=True)
        (self.root / ".gitignore").write_text(
            "__pycache__/\n.pytest_cache/\n", encoding="utf-8")
        shutil.copyfile(ROOT / "scripts/check_incident_coverage.py",
                        self.root / "scripts/check_incident_coverage.py")
        shutil.copyfile(ROOT / "tools/validation/behavior_evidence_reuse.py",
                        self.root / "tools/validation/behavior_evidence_reuse.py")
        index = {"case_registry": {"active_case_count": 1},
                 "legacy_source": {"active_case_count": 0}}
        (self.root / "tests/fixtures/incidents/library_case_index.json").write_text(
            json.dumps(index), encoding="utf-8")
        for name in ("CHANGELOG.md", "CHANGELOG.zh-CN.md"):
            (self.root / name).write_text("original notes\n", encoding="utf-8")
        self.test_file = self.root / "tests/test_incident_library_regression.py"
        self.test_file.write_text(
            "import unittest\nclass DefaultPathAuthorizationCases(unittest.TestCase):\n"
            "    def test_cgi_2026_009_017_026_default_path_allows_ordinary_business(self):\n"
            "        self.assertTrue(True)\n", encoding="utf-8")
        (self.root / "assets/input.json").write_text('{"value": 1}\n', encoding="utf-8")
        self.node = reuse.REVIEWED_NODE
        self.row = {"id": "case-one", "status": "active", "test_locator": self.node}
        coverage = {"cases": [self.row], "legacy": []}
        (self.root / "tests/fixtures/incidents/historical_case_coverage.json").write_text(
            json.dumps(coverage), encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Test",
                        "-c", "user.email=test@users.noreply.github.com",
                        "commit", "-qm", "fixture"], check=True)
        self.environment_id = "a" * 64
        before = reuse.freeze_inputs(self.root, self.environment_id)
        errors = []
        executions = incident.execute_receipts(self.root, [self.row], errors)
        self.assertEqual(errors, [])
        self.assertEqual(executions["case-one"]["outcomes"][self.node], "passed")
        after = reuse.freeze_inputs(self.root, self.environment_id)
        identity = {"head": before["source"]["head"], "prepared_source_sha256": "b" * 64}
        self.identity = identity
        self.report = {"schema": "incident-coverage-validation/v3", "valid": True,
                       "candidate_binding": identity,
                       "release_gate": {"closes_release_gate": True, "consumer": {"passed": True}},
                       "execution_receipts": executions}
        self.report_path = self.base / "owner-report.json"
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")
        self.report_sha = reuse.file_digest(self.report_path)
        self.receipt = incident.build_execution_receipt(
            [self.row], executions, identity, before, after, self.report_sha)
        self.record = self.derive()
        self.reviewed_node_sha = reuse.reviewed_node_input_digest(
            before["source"]["files"])
        self.receipt_path = self.base / "owner-receipt.json"
        self.receipt_path.write_text(json.dumps(self.receipt), encoding="utf-8")
        self.receipt_sha = reuse.file_digest(self.receipt_path)
        self.record_path = self.base / "record.json"

    def cli(self, *extra):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/validation/behavior_evidence_reuse.py"),
             "--owner-receipt", str(self.receipt_path),
             "--owner-receipt-sha256", self.receipt_sha,
             "--owner-report", str(self.report_path),
             "--owner-report-sha256", self.report_sha,
             "--environment-id", self.environment_id, "--root", str(self.root),
             *extra], text=True, capture_output=True)


    def derive(self):
        return reuse._derive(self.receipt, self.report, self.root,
                             self.environment_id, self.report_sha)

    def test_producer_main_emits_bound_report_after_actual_test(self):
        report = self.base / "main-report.json"
        receipt = self.base / "main-receipt.json"
        args = ["checker", str(self.root), "--execute", "--release-gate",
                "--report", str(report), "--evidence-receipt", str(receipt),
                "--evidence-environment-id", self.environment_id]
        stdout, stderr = io.StringIO(), io.StringIO()
        with (mock.patch.object(sys, "argv", args),
              mock.patch.object(incident, "validate_coverage", return_value=[]),
              mock.patch.object(incident, "validate_rows", return_value={"executed_pass": 1}),
              mock.patch.object(incident, "prepared_source_identity", return_value=self.identity),
              contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
            self.assertEqual(incident.main(), 0, stderr.getvalue())
        report_sha = reuse.file_digest(report)
        receipt_sha = reuse.file_digest(receipt)
        self.assertIn("owner_report_sha256=" + report_sha, stderr.getvalue())
        self.assertIn("owner_receipt_sha256=" + receipt_sha, stderr.getvalue())
        derived = reuse._derive(json.loads(receipt.read_text()),
                                json.loads(report.read_text()), self.root,
                                self.environment_id, report_sha)
        self.assertEqual([item["node"] for item in derived["nodes"]], [self.node])

    def test_cli_build_readback_and_tampering(self):
        result = self.cli("--build-from-receipt", "--out-record", str(self.record_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.cli("--record", str(self.record_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(self.record_path.read_text())
        record["inputs"]["source"]["files"] = {}
        self.record_path.write_text(json.dumps(record), encoding="utf-8")
        result = self.cli("--record", str(self.record_path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("record differs", result.stderr)
        self.receipt_path.write_text("{}", encoding="utf-8")
        result = self.cli("--record", str(self.record_path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("receipt digest mismatch", result.stderr)

    def test_real_owner_run_establishes_complete_node(self):
        self.assertEqual([node["node"] for node in self.record["nodes"]], [self.node])
        self.assertEqual(self.record["nodes"][0]["exit_code"], 0)

    def test_reviewed_node_allows_only_changelog_changes_across_commits(self):
        self.record_path.write_text(json.dumps(self.record), encoding="utf-8")
        (self.root / "CHANGELOG.md").write_text("revised notes\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "CHANGELOG.md"], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Test",
                        "-c", "user.email=test@users.noreply.github.com", "commit",
                        "-qm", "revise notes"], check=True)
        with self.assertRaisesRegex(ValueError, "source or reviewed environment changed"):
            self.derive()
        with self.assertRaisesRegex(ValueError, "node-input review digest"):
            reuse._derive(self.receipt, self.report, self.root,
                          self.environment_id, self.report_sha, self.node)
        reviewed = reuse._derive(self.receipt, self.report, self.root,
                                 self.environment_id, self.report_sha, self.node,
                                 self.reviewed_node_sha)
        self.assertEqual(reviewed, self.record)
        self.assertEqual(self.cli("--record", str(self.record_path)).returncode, 1)
        scoped = self.cli("--record", str(self.record_path), "--node", self.node,
                          "--reviewed-node-inputs-sha256", self.reviewed_node_sha)
        self.assertEqual(scoped.returncode, 0, scoped.stderr)
        self.assertEqual(json.loads(scoped.stdout)["nodes"], 1)
        (self.root / "assets/input.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "reviewed node inputs"):
            reuse._derive(self.receipt, self.report, self.root,
                          self.environment_id, self.report_sha, self.node,
                                 self.reviewed_node_sha)
        with self.assertRaisesRegex(ValueError, "no reviewed reuse scope"):
            reuse._derive(self.receipt, self.report, self.root,
                          self.environment_id, self.report_sha, "unknown-node",
                          self.reviewed_node_sha)

    def test_changed_unrelated_tracked_input_invalidates_conservatively(self):
        (self.root / "assets/input.json").write_text('{}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source or reviewed environment changed"):
            self.derive()

    def test_untracked_input_is_unknown(self):
        (self.root / "tests/conftest.py").write_text("# new input\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "untracked"):
            self.derive()

    def test_tracked_symlink_and_index_changes_are_unknown(self):
        subprocess.run(["git", "-C", str(self.root), "rm", "--cached", "-q",
                        "assets/input.json"], check=True)
        with self.assertRaisesRegex(ValueError, "untracked"):
            self.derive()
        subprocess.run(["git", "-C", str(self.root), "add", "assets/input.json"],
                       check=True)
        asset = self.root / "assets/input.json"
        asset.unlink()
        try:
            asset.symlink_to(self.test_file)
        except OSError as exc:
            self.skipTest(f"symlink unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.derive()

    def test_producer_refuses_receipt_without_full_release_run(self):
        output = self.base / "not-produced.json"
        args = ["checker", str(self.root), "--evidence-receipt", str(output)]
        with mock.patch.object(sys, "argv", args), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(incident.main(), 2)
        self.assertFalse(output.exists())

    def test_fake_missing_or_failing_nodes_do_not_derive(self):
        self.receipt["nodes"][0]["node"] = "tests/test_incident_library_regression.py::DefaultPathAuthorizationCases::test_fake"
        with self.assertRaisesRegex(ValueError, "node inventory differ"):
            self.derive()
        self.receipt["nodes"][0]["node"] = self.node
        self.report["execution_receipts"]["case-one"]["outcomes"][self.node] = "failed"
        with self.assertRaisesRegex(ValueError, "did not pass"):
            self.derive()

    def test_incomplete_receipt_and_changed_report_digest_refused(self):
        self.receipt["nodes"] = []
        with self.assertRaisesRegex(ValueError, "node inventory differ"):
            self.derive()
        self.receipt["report_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "report digest mismatch"):
            self.derive()

    def test_changes_during_owner_run_and_unknown_environment_refused(self):
        self.receipt["inputs_before"] = copy.deepcopy(self.receipt["inputs_after"])
        self.receipt["inputs_before"]["source"]["files"].pop("assets/input.json")
        with self.assertRaisesRegex(ValueError, "during original execution"):
            self.derive()
        with self.assertRaisesRegex(ValueError, "environment identity"):
            reuse.environment_fingerprint("unknown")

    def test_record_tampering_does_not_equal_derivation(self):
        tampered = copy.deepcopy(self.record)
        tampered["inputs"]["source"]["files"] = {}
        self.assertNotEqual(tampered, self.derive())


if __name__ == "__main__":
    unittest.main()
