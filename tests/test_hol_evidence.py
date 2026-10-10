from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "hol_evidence", ROOT / "tools/validation/hol_evidence.py")
assert SPEC and SPEC.loader
HE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HE)
REPOSITORY = "example/context-guard"
SCANNER = "3.27.1"


class HolEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts/manage_plugin.py",
                        self.root / "scripts/manage_plugin.py")
        (self.root / ".codex-plugin").mkdir()
        (self.root / ".codex-plugin/plugin.json").write_text(
            json.dumps({"version": "0.15.1", "private_unrequested": "DO_NOT_EXPORT"}))
        (self.root / "uv.lock").write_text("version = 1\n")
        (self.root / "requirements-lock.txt").write_text("plugin-scanner==3.0.157\n")
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@users.noreply.github.com")
        self.git("remote", "add", "origin", f"https://github.com/{REPOSITORY}.git")
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.payload = {"sourceSha": self.head, "sourceRepository": REPOSITORY,
                        "scannerVersion": SCANNER, "score": 95, "grade": "A",
                        "findings": dict.fromkeys(HE.SEVERITIES, 0),
                        "description": "DO_NOT_EXPORT", "publisher_verified": True}
        self.sarif = {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "plugin-scanner", "version": SCANNER}},
            "results": []}]}
        self.write_reports()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args],
                                       stderr=subprocess.DEVNULL).decode()

    def write_reports(self):
        (self.root / HE.PAYLOAD).write_text(json.dumps(self.payload))
        (self.root / HE.SARIF).write_text(json.dumps(self.sarif))

    def collect(self, **kwargs):
        return HE.collect(self.root, kwargs.get("sha", self.head),
                          kwargs.get("repository", REPOSITORY),
                          kwargs.get("version", SCANNER), kwargs.get("outcome", "success"))

    def test_positive_binds_actual_bytes_without_exporting_report_content(self):
        before = {name: (self.root / name).read_bytes() for name in (HE.SARIF, HE.PAYLOAD)}
        record = self.collect()
        self.assertEqual(record["status"], "passed")
        self.assertEqual(record["source_commit"], self.head)
        self.assertEqual(record["manifest"]["sha256"], HE.digest(
            (self.root / ".codex-plugin/plugin.json").read_bytes()))
        self.assertEqual(record["runtime"]["file_count"], 2)
        self.assertEqual([x["path"] for x in record["locks"]],
                         ["uv.lock", "requirements-lock.txt"])
        self.assertEqual(set(record["upload_paths"]), {HE.COMPANION, HE.SARIF, HE.PAYLOAD})
        serialized = json.dumps(record)
        for forbidden in ("DO_NOT_EXPORT", str(self.root), "publisher_verified"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(record["publisher_certification"], "unverified")
        self.assertEqual(record["registry_ingestion"], "unverified")
        for name, raw in before.items():
            self.assertEqual((self.root / name).read_bytes(), raw)

    def test_payload_subject_and_scanner_mismatches_are_not_repaired(self):
        for field, value, error in (
            ("sourceSha", "a" * 40, "payload_source_sha_mismatch"),
            ("sourceRepository", "other/repository", "payload_repository_mismatch"),
            ("scannerVersion", "3.0.157", "payload_scanner_mismatch")):
            with self.subTest(field=field):
                original = self.payload[field]
                self.payload[field] = value
                self.write_reports()
                raw = (self.root / HE.PAYLOAD).read_bytes()
                result = self.collect()
                self.assertEqual(result["status"], "failed")
                self.assertIn("payload:" + error, result["diagnostics"])
                self.assertNotIn(HE.PAYLOAD, result["upload_paths"])
                self.assertEqual((self.root / HE.PAYLOAD).read_bytes(), raw)
                self.payload[field] = original

    def test_workflow_merge_sha_is_preserved_as_mismatch(self):
        result = self.collect(sha="b" * 40)
        self.assertEqual(result["workflow_source_commit"], "b" * 40)
        self.assertEqual(result["source_commit"], self.head)
        self.assertIn("workflow_source_sha_mismatch", result["diagnostics"])
        self.assertEqual(result["status"], "failed")

    def test_previous_scanner_reports_cannot_satisfy_upgraded_identity(self):
        self.payload["scannerVersion"] = "3.12.1"
        self.sarif["runs"][0]["tool"]["driver"]["version"] = "3.12.1"
        self.write_reports()
        before = {name: (self.root / name).read_bytes()
                  for name in (HE.SARIF, HE.PAYLOAD)}
        result = self.collect()
        self.assertEqual(result["status"], "failed")
        for error in ("payload:payload_scanner_mismatch", "sarif:sarif_scanner_mismatch"):
            self.assertIn(error, result["diagnostics"])
        self.assertEqual(result["upload_paths"], [HE.COMPANION])
        for name, raw in before.items():
            self.assertEqual((self.root / name).read_bytes(), raw)

    def test_scanner_failure_cannot_be_promoted_by_valid_reports(self):
        for outcome in ("failure", "cancelled", "skipped"):
            with self.subTest(outcome=outcome):
                result = self.collect(outcome=outcome)
                self.assertEqual(result["status"], "failed")
                self.assertIn("scanner_not_successful", result["diagnostics"])

    def test_missing_and_malformed_reports_are_explicit_and_not_synthesized(self):
        (self.root / HE.PAYLOAD).unlink()
        (self.root / HE.SARIF).write_bytes(b"DO_NOT_EXPORT invalid")
        result = self.collect()
        self.assertIn("payload:missing", result["diagnostics"])
        self.assertIn("sarif:invalid_json", result["diagnostics"])
        self.assertEqual(result["upload_paths"], [HE.COMPANION])
        self.assertFalse((self.root / HE.PAYLOAD).exists())
        self.assertNotIn("DO_NOT_EXPORT", json.dumps(result))

    def test_nested_sarif_shapes_and_version_are_checked(self):
        for sarif in ({"version": "2.1.0", "runs": [None]},
                      {"version": "2.1.0", "runs": [{"results": [], "tool": []}]},
                      {"version": "2.1.0", "runs": []}):
            with self.subTest(sarif=sarif):
                (self.root / HE.SARIF).write_text(json.dumps(sarif))
                self.assertEqual(self.collect()["status"], "failed")
        self.sarif["runs"][0]["tool"]["driver"]["version"] = "3.0.157"
        self.write_reports()
        self.assertIn("sarif:sarif_scanner_mismatch", self.collect()["diagnostics"])

    def test_payload_quality_shape_and_existing_quality_gate(self):
        for changes in ({"score": True}, {"score": 79}, {"findings": {"high": 0}},
                        {"findings": {**self.payload["findings"], "high": 1}},
                        {"findings": {**self.payload["findings"], "info": -1}}):
            with self.subTest(changes=changes):
                value = {**self.payload, **changes}
                (self.root / HE.PAYLOAD).write_text(json.dumps(value))
                self.assertEqual(self.collect()["status"], "failed")

    def test_duplicate_keys_constants_and_non_objects_rejected(self):
        for raw in (b'{"score":95,"score":100}', b'{"score":NaN}', b'[]', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(HE.EvidenceError):
                HE.object_json(raw)

    def test_oversized_and_non_regular_files_rejected_without_opening(self):
        with mock.patch.object(HE, "MAX_BYTES", 8):
            with self.assertRaisesRegex(HE.EvidenceError, "non_regular_or_oversized"):
                HE.read_bytes(self.root, HE.PAYLOAD)
        with self.assertRaisesRegex(HE.EvidenceError, "non_regular_or_oversized"):
            HE.read_bytes(self.root, "scripts")
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.root / "fifo")
            with self.assertRaisesRegex(HE.EvidenceError, "non_regular_or_oversized"):
                HE.read_bytes(self.root, "fifo")

    def test_tracked_reports_cannot_be_relabelled_as_scan_output(self):
        self.git("add", HE.PAYLOAD)
        self.git("commit", "-qm", "track fabricated report")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.payload["sourceSha"] = self.head
        self.write_reports()
        self.assertEqual(self.collect()["status"], "failed")

    def test_empty_tracked_lock_is_not_accepted(self):
        (self.root / "uv.lock").write_bytes(b"")
        self.git("add", "uv.lock")
        self.git("commit", "-qm", "empty lock")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.payload["sourceSha"] = self.head
        self.write_reports()
        self.assertIn("invalid_source_lock", self.collect()["diagnostics"])

    def test_source_lock_missing_and_dirty_checkout_fail(self):
        (self.root / "uv.lock").unlink()
        self.assertEqual(self.collect()["status"], "failed")
        (self.root / "uv.lock").write_text("version = 1\n")
        (self.root / ".codex-plugin/plugin.json").write_text('{"version":"0.15.2"}')
        self.assertEqual(self.collect()["status"], "failed")

    def test_untracked_runtime_is_not_bound_to_git_commit(self):
        (self.root / "scripts/untracked.py").write_text("private = True\n")
        result = self.collect()
        self.assertIn("runtime_contains_untracked_files", result["diagnostics"])
        self.assertEqual(result["upload_paths"], [HE.COMPANION])

    def test_remote_repository_mismatch_and_credential_url_are_redacted(self):
        self.git("remote", "set-url", "origin", "https://SECRET@github.com/other/repo.git")
        result = self.collect()
        self.assertIn("checkout_repository_mismatch", result["diagnostics"])
        self.assertNotIn("SECRET", json.dumps(result))

    def test_relative_paths_reject_escape_absolute_backslash_and_aliases(self):
        for path in (".", "../private", "/private", "nested/../../private", "a\\b", "./uv.lock", "a//b"):
            with self.subTest(path=path), self.assertRaises(HE.EvidenceError):
                HE.safe_path(self.root, path)

    def test_symlink_reports_and_parent_paths_rejected(self):
        original = self.root / HE.PAYLOAD
        original.unlink()
        try:
            original.symlink_to(self.root / HE.SARIF)
            (self.root / "linked").symlink_to(self.root, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable on this host")
        result = self.collect()
        self.assertIn("payload:symlink_rejected", result["diagnostics"])
        self.assertNotIn(HE.PAYLOAD, result["upload_paths"])
        with self.assertRaises(HE.EvidenceError):
            HE.safe_path(self.root, "linked/uv.lock")

    def test_changed_report_drops_upload_authority(self):
        original = HE.read_bytes
        calls = 0
        def changing(root, name):
            nonlocal calls
            raw = original(root, name)
            if name == HE.PAYLOAD:
                calls += 1
                if calls == 2:
                    return raw + b" "
            return raw
        with mock.patch.object(HE, "read_bytes", side_effect=changing):
            result = self.collect()
        self.assertIn("input_changed", result["diagnostics"])
        self.assertEqual(result["upload_paths"], [HE.COMPANION])

    def test_cli_failure_writes_only_diagnostic_companion_and_returns_nonzero(self):
        (self.root / HE.PAYLOAD).unlink()
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["--repo-root", str(self.root), "--expected-source-sha", self.head,
                "--expected-repository", REPOSITORY, "--expected-scanner-version", SCANNER,
                "--scanner-outcome", "success"]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = HE.main(argv)
        self.assertEqual(code, 1)
        self.assertIn("companion_path=" + HE.COMPANION, stdout.getvalue())
        self.assertNotIn("payload_path=", stdout.getvalue())
        self.assertIn("payload:missing", stderr.getvalue())
        record = json.loads((self.root / HE.COMPANION).read_text())
        self.assertEqual(record["status"], "failed")
        raw = (self.root / HE.COMPANION).read_bytes()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(HE.main(argv), 1)
        self.assertEqual((self.root / HE.COMPANION).read_bytes(), raw)

    def test_cli_success_emits_only_three_exact_relative_outputs(self):
        stdout = io.StringIO()
        argv = ["--repo-root", str(self.root), "--expected-source-sha", self.head,
                "--expected-repository", REPOSITORY, "--expected-scanner-version", SCANNER,
                "--scanner-outcome", "success"]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(HE.main(argv), 0)
        self.assertEqual(stdout.getvalue().splitlines(), [
            "companion_path=" + HE.COMPANION, "sarif_path=" + HE.SARIF,
            "payload_path=" + HE.PAYLOAD])

    def test_companion_symlink_does_not_overwrite_target_or_emit_upload_output(self):
        target = self.root / "private-target"
        target.write_bytes(b"preserve unrelated bytes")
        try:
            (self.root / HE.COMPANION).symlink_to(target)
        except OSError:
            self.skipTest("symlink creation unavailable on this host")
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["--repo-root", str(self.root), "--expected-source-sha", self.head,
                "--expected-repository", REPOSITORY, "--expected-scanner-version", SCANNER,
                "--scanner-outcome", "success"]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(HE.main(argv), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("companion_output_rejected", stderr.getvalue())
        self.assertEqual(target.read_bytes(), b"preserve unrelated bytes")


if __name__ == "__main__":
    unittest.main()
