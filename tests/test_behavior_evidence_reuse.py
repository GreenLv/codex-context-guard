"""0.17.2 r1 evidence-reuse contract: records bind REAL owner-executed
results; a pass claim without a real owner run behind it is never
established, and a recorded failure/unknown node is refused."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools" / "validation"
SPEC = importlib.util.spec_from_file_location(
    "behavior_evidence_reuse", TOOLS / "behavior_evidence_reuse.py")
assert SPEC is not None and SPEC.loader is not None
reuse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reuse)


def sha(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReceiptFixture(unittest.TestCase):
    """A minimal owner receipt bound to REAL files in a scratch root."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "scripts" / "product.py").write_text("a = 1\n",
                                                          encoding="utf-8")
        (self.root / "tests" / "test_product.py").write_text("b = 2\n",
                                                             encoding="utf-8")
        (self.root / "scripts" / "runner.py").write_text("c = 3\n",
                                                         encoding="utf-8")
        self.receipt_path = self.root / "receipt.json"

    def write_receipt(self, *, outcome="passed", exit_code=0, node=None):
        node = node or "tests/test_product.py::TestX::test_one"
        receipt = {
            "schema": reuse.RECEIPT_SCHEMA,
            "produced_by": "check_incident_coverage",
            "produced_at": "2026-11-11T00:00:00Z",
            "candidate_binding": {"head": "0" * 40},
            "environment": dict(reuse.current_environment()),
            "nodes": [{
                "node": node,
                "row": "CGI-X",
                "outcome": outcome,
                "exit_code": exit_code,
                "test_file_sha256": sha(self.root / "tests" / "test_product.py"),
                "bindings": {
                    "code": {"scripts/product.py":
                             sha(self.root / "scripts" / "product.py")},
                    "caller": {"scripts/runner.py":
                               sha(self.root / "scripts" / "runner.py")},
                    "schema": {},
                    "tests": {"tests/test_product.py":
                              sha(self.root / "tests" / "test_product.py")},
                    "runner": {"scripts/runner.py":
                               sha(self.root / "scripts" / "runner.py")},
                    "deps": {},
                    "config": {},
                },
            }],
        }
        self.receipt_path.write_text(json.dumps(receipt) + "\n",
                                     encoding="utf-8")
        return receipt

    def build(self, **kwargs):
        self.write_receipt(**kwargs)
        return reuse.build_record_from_receipt(self.receipt_path)

    def call_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-B", str(TOOLS / "behavior_evidence_reuse.py"),
             *args], text=True, capture_output=True, timeout=60)


class ReceiptBindingTests(ReceiptFixture):
    def test_real_passed_run_reuses_with_verified_owner_receipt(self):
        record = self.build()
        self.assertEqual(record["source_receipt_sha256"],
                         sha(self.receipt_path))
        verdict = reuse.evaluate(record, self.root, receipt=self.write_receipt(),
                                 receipt_sha256=sha(self.receipt_path))
        self.assertEqual(verdict["reusable_count"], 1)
        self.assertEqual(verdict["acceptance"], "established")
        self.assertEqual(verdict["entries"][0]["changed_inputs"], [])

    def test_without_owner_receipt_nothing_is_established(self):
        # The r1 counterexample: a record whose entries claim a pass with
        # arbitrary node names and files must NEVER evaluate as
        # established on its own.
        record = self.build()
        verdict = reuse.evaluate(record, self.root)
        self.assertEqual(verdict["acceptance"], "not_established")
        self.assertEqual(verdict["entries"][0]["changed_inputs"],
                         ["owner_receipt:not_verified"])
        self.assertEqual(verdict["stale_count"], 1)

    def test_tampered_receipt_digest_is_refused(self):
        record = self.build()
        other = self.root / "other.json"
        other.write_text(json.dumps(self.write_receipt()), encoding="utf-8")
        # Same content re-serialized under a different name: the record's
        # bound digest does not match the presented receipt file.
        with self.assertRaisesRegex(ValueError, "receipt"):
            reuse.evaluate(record, self.root,
                           receipt=json.loads(other.read_text()),
                           receipt_sha256=sha(other))

    def test_failed_node_is_refused_at_build_time(self):
        self.write_receipt(outcome="failed", exit_code=1)
        with self.assertRaisesRegex(ValueError, "re-run the node"):
            reuse.build_record_from_receipt(self.receipt_path)

    def test_changed_code_or_environment_is_stale(self):
        record = self.build()
        bound_receipt = json.loads(self.receipt_path.read_text())
        bound_sha = sha(self.receipt_path)
        (self.root / "scripts" / "product.py").write_text("a = 2\n",
                                                          encoding="utf-8")
        verdict = reuse.evaluate(record, self.root, receipt=bound_receipt,
                                 receipt_sha256=bound_sha)
        self.assertEqual(verdict["entries"][0]["changed_inputs"],
                         ["code:scripts/product.py"])
        self.assertEqual(verdict["acceptance"], "not_established")

    def test_incomplete_owner_mapping_is_refused(self):
        record = self.build()
        del record["entries"][0]["deps"]
        with self.assertRaisesRegex(ValueError, "deps binding missing"):
            reuse.evaluate(record, self.root, receipt=self.write_receipt(),
                           receipt_sha256=sha(self.receipt_path))

    def test_tampered_node_claim_is_refused_not_staled(self):
        # A record edited to claim a node the owner receipt never ran is
        # REFUSED outright (the receipt-node binding must equal the node),
        # never partially evaluated.
        record = self.build()
        bound_receipt = json.loads(self.receipt_path.read_text())
        bound_sha = sha(self.receipt_path)
        record["entries"][0]["result"]["receipt_node"] = \
            "tests/test_product.py::TestX::test_never_ran"
        with self.assertRaisesRegex(ValueError, "result must bind"):
            reuse.evaluate(record, self.root, receipt=bound_receipt,
                           receipt_sha256=bound_sha)

    def test_record_schema_refuses_legacy_shape(self):
        record = self.build()
        record["schema"] = "cg-behavior-evidence/v1"
        with self.assertRaisesRegex(ValueError, "v2"):
            reuse.evaluate(record, self.root, receipt=self.write_receipt(),
                           receipt_sha256=sha(self.receipt_path))

    def test_cli_build_evaluate_and_refusals(self):
        self.write_receipt()
        out = self.root / "record.json"
        proc = self.call_cli("--build-from-receipt", str(self.receipt_path),
                             "--out-record", str(out))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # Evaluation without the owner receipt: not established, exit 1.
        proc = self.call_cli("--record", str(out), "--root", str(self.root))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("owner_receipt:not_verified", proc.stdout)
        # With the owner receipt: established, exit 0.
        proc = self.call_cli("--record", str(out), "--root", str(self.root),
                             "--owner-receipt", str(self.receipt_path))
        self.assertEqual(proc.returncode, 0)
        verdict = json.loads(proc.stdout)
        self.assertEqual(verdict["acceptance"], "established")
        # A failed node in the receipt: build refused, exit 2.
        self.write_receipt(outcome="failed", exit_code=1)
        proc = self.call_cli("--build-from-receipt", str(self.receipt_path),
                             "--out-record", str(self.root / "bad.json"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("re-run the node", proc.stderr)


if __name__ == "__main__":
    unittest.main()
