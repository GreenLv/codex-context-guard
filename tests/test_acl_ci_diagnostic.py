"""Privacy and failure propagation for the fixed CI diagnostic, not native proof."""
import base64
import copy
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.validation import acl_ci_diagnostic as diagnostic
from tools.validation import incident_readonly_child as child


class ACLDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "fixture"
        self.actor = "S-1-5-21-101-202-303-404"
        self.other = "S-1-5-21-505-606-707-808"

    def descriptor(self, entries, control=0x8404):
        aces = b"".join(struct.pack("<BBHI", kind, flags,
                                   8 + len(child.sid_bytes(sid)), mask) + child.sid_bytes(sid)
                        for kind, flags, mask, sid in entries)
        acl = struct.pack("<BBHHH", 2, 0, 8 + len(aces), len(entries), 0) + aces
        header = struct.pack("<BBHIIII", 1, 0, control, 0, 0, 0, 20)
        return base64.b64encode(header + acl).decode("ascii")

    def record(self):
        before = self.descriptor([(0, 16, 0x120089, self.other)])
        planned = self.descriptor([(1, 0, 0x10116, self.actor), (0, 16, 0x120089, self.other)])
        actual = self.descriptor([(0, 16, 0x120089, self.other), (1, 0, 0x10116, self.actor)])
        return {"sid": self.actor, "original_dacls": {str(self.root / "nested"): before},
                "operations": [{"phase": "deny", "path": "nested/lock",
                                "before": before, "planned": planned, "actual": actual,
                                "native_result": {"api": "SetNamedSecurityInfoW",
                                                  "security_information": 4,
                                                  "return_value": 0, "winerror": 0},
                                "unexpected_objects": {"nested": actual}}]}

    def test_safe_structure_retains_order_masks_flags_and_cross_object_aliases(self):
        record = self.record()
        original = copy.deepcopy(record)
        report = diagnostic.failure_structure(self.root, record, record["original_dacls"])
        self.assertEqual(record, original)
        self.assertEqual(report["object"], "nested/lock")
        self.assertEqual(report["planned"]["dacl_control"], 0x404)
        self.assertEqual([ace["principal"] for ace in report["planned"]["aces"]],
                         ["actor", "principal-001"])
        self.assertEqual([ace["principal"] for ace in report["actual"]["aces"]],
                         ["principal-001", "actor"])
        self.assertEqual(report["actual"]["aces"][0]["flags"], 16)
        self.assertEqual(report["actual"]["aces"][1]["mask"], 0x10116)
        self.assertEqual(report["unexpected_objects"][0]["actual"], report["actual"])
        serialized = json.dumps(report)
        for forbidden in (self.actor, self.other, str(self.root),
                          record["operations"][0]["planned"], "S-1-"):
            self.assertNotIn(forbidden, serialized)

    def test_unexpected_object_uses_current_comparison_target_after_prior_deny(self):
        record = self.record()
        op = record["operations"][0]
        record["granted_dacls"] = dict(record["original_dacls"])
        expected = {str(self.root / "nested"): op["actual"]}
        original = copy.deepcopy((record, expected))
        report = diagnostic.failure_structure(self.root, record, expected)
        unexpected = report["unexpected_objects"][0]
        self.assertEqual(unexpected["expected"], unexpected["actual"])
        self.assertNotEqual(unexpected["expected"], report["before"])
        self.assertEqual((record, expected), original)
        with self.assertRaisesRegex(ValueError, "exact comparison target unavailable"):
            diagnostic.failure_structure(self.root, record, None)

    def test_unrecognized_paths_and_native_strings_cannot_leak(self):
        record = self.record()
        op = record["operations"][0]
        op["path"] = str(self.root.parent / "private-name")
        op["native_result"]["private_message"] = "private-value"
        op["native_result"]["winerror"] = "private-value"
        report = diagnostic.failure_structure(self.root, record, record["original_dacls"])
        self.assertEqual(report["object"], "outside-owned-fixture")
        self.assertNotIn("private-value", json.dumps(report))
        self.assertNotIn("private-name", json.dumps(report))

    def test_original_exception_is_retained_and_diagnostic_never_turns_it_into_pass(self):
        record = self.record()
        failure = ValueError("private-original-exception")
        caught = []
        expected = {str(self.root / "nested"): record["operations"][0]["actual"]}

        class FixedSuite:
            def countTestCases(self):
                return 1

            def run(suite, result):
                result.testsRun = 1
                try:
                    child.apply_acl_change(self.root, record, self.root / "nested/lock",
                                           None, None, "deny", expected)
                except ValueError as exc:
                    caught.append(exc)
                    result.errors.append((None, "private-traceback"))

        stream = io.StringIO()
        with mock.patch.object(diagnostic, "os", SimpleNamespace(name="nt")), \
                mock.patch.object(child, "apply_acl_change", side_effect=failure), \
                mock.patch.object(unittest.defaultTestLoader, "loadTestsFromName", return_value=FixedSuite()), \
                mock.patch("sys.stdout", stream):
            self.assertEqual(diagnostic.run(), 1)
        self.assertEqual(caught, [failure])
        self.assertIn('"status": "failed"', stream.getvalue())
        self.assertEqual(stream.getvalue().count("ACL_STRUCTURE="), 1)
        line = next(line for line in stream.getvalue().splitlines()
                    if line.startswith("ACL_STRUCTURE="))
        report = json.loads(line.removeprefix("ACL_STRUCTURE="))
        self.assertNotIn("structure", report)
        unexpected = report["unexpected_objects"][0]
        self.assertEqual(unexpected["expected"], unexpected["actual"])
        self.assertNotEqual(unexpected["expected"], report["before"])
        for private in ("private-original-exception", "private-traceback", self.actor, str(self.root)):
            self.assertNotIn(private, stream.getvalue())

    def test_workflow_is_bounded_manual_read_only_and_fixed_to_two_failed_versions(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/windows-acl-diagnostic.yml").read_text(encoding="utf-8")
        self.assertIn("\n  workflow_dispatch:", workflow)
        self.assertIn("branches: [codex/0.15.1-hook-repair]", workflow)
        self.assertIn("    paths:\n", workflow)
        self.assertNotIn("branches: [main]", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn('python: ["3.10", "3.11"]', workflow)
        self.assertIn("timeout-minutes: 10", workflow)
        self.assertIn("python -B -m tools.validation.acl_ci_diagnostic", workflow)
        for forbidden in ("continue-on-error", "pull_request:", "secrets.", "upload-artifact"):
            self.assertNotIn(forbidden, workflow)
