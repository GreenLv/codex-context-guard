import tempfile
import unittest
from pathlib import Path

from tools.validation.acceptance_evidence import (
    STAGES,
    evidence_index,
    payload_identity,
    transfer_state,
)


class AcceptanceEvidenceTests(unittest.TestCase):
    def test_transfer_is_ordered_idempotent_and_does_not_grant_acceptance(self):
        payload = payload_identity({"fixture.json": b"{}", "oracle.py": b"pass\n"})
        events = [dict(request_id="r1", stage=stage, payload=payload) for stage in STAGES]
        self.assertEqual(transfer_state(events[:1], "r1", payload)["status"], "accepted")
        self.assertFalse(transfer_state(events[:1], "r1", payload)["execution_reported"])
        full = transfer_state([events[0], *events], "r1", payload)
        self.assertEqual(full["status"], "completed")
        self.assertEqual(full["acceptance"], "not_established")
        for bad in (events[1:], list(reversed(events)),
                    [dict(events[0], payload=dict(payload, byte_count=0))],
                    [dict(events[0], request_id="wrong")],
                    [dict(events[0], status="active_writer_conflict")]):
            self.assertEqual(transfer_state(bad, "r1", payload)["status"], "unknown")

    def test_payload_identity_binds_names_counts_and_bytes(self):
        original = payload_identity({"a": b"one", "b": b"two"})
        self.assertEqual(original, payload_identity({"b": b"two", "a": b"one"}))
        self.assertNotEqual(original, payload_identity({"a": b"two", "b": b"one"}))

    def test_evidence_index_rejects_derived_trust_stale_candidate_and_bad_digest(self):
        import hashlib

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "receipt.json"
            source.write_bytes(b"{}")
            subject = {"commit": "a" * 40, "runtime_sha256": "b" * 64}
            base = dict(gate="hook_trust", subject=subject, provenance="host_observed",
                        as_of="2026-09-23T00:00:00Z", source=str(source),
                        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
            for bad in (dict(base, provenance="derived"), dict(base, subject={}),
                        dict(base, source_sha256="0" * 64), dict(base, source="missing")):
                result = evidence_index([bad], subject, {"hook_trust", "model"})
                self.assertEqual(result["missing"], ["hook_trust", "model"])
                self.assertTrue(result["rejected"])
            result = evidence_index([base], subject, {"hook_trust", "model"})
            self.assertEqual(result["acceptance"], "not_established")
            self.assertEqual(result["missing"], ["model"])


if __name__ == "__main__":
    unittest.main()
