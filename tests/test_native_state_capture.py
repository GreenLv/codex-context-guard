"""Exact private capture and failure handling for native result v3."""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.validation import native_between_turns_acceptance as bt


class FullStateCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.data = self.root / "data"
        self.output = self.root / "output"
        self.output.mkdir()
        self.thread = "controlled-thread"
        self.live = self.data / "sessions-v2" / self.thread / "state.json"
        self.live.parent.mkdir(parents=True)
        self.state = {
            "session": {"id": self.thread, "ended_at": None},
            "requirements": [],
        }
        self.raw = (
            json.dumps(self.state, ensure_ascii=False, indent=2) + "\n"
        ).encode()
        self.live.write_bytes(self.raw)
        self.snap = {
            "root": str(self.data),
            "sha256": hashlib.sha256(self.raw).hexdigest(),
            "state": self.state,
            "scope": {"current": [], "ancestor": [], "waiting": 0},
        }
        self.ctx = {"output": self.output}

    def capture(self):
        return bt.capture_full_state(
            self.ctx, self.snap, self.thread, self.output / "capture.json"
        )

    def test_exact_raw_bytes_saved_exclusively_and_private(self):
        self.assertEqual(self.capture(), self.snap["sha256"])
        self.assertEqual((self.output / "capture.json").read_bytes(), self.raw)
        self.assertEqual(self.live.read_bytes(), self.raw)
        if os.name != "nt":
            self.assertEqual(
                (self.output / "capture.json").stat().st_mode & 0o777, 0o600
            )
        with self.assertRaises(FileExistsError):
            self.capture()

    def test_drift_between_validated_snapshot_and_read_refuses(self):
        self.live.write_bytes(self.raw + b" ")
        with self.assertRaises(bt.Refused):
            self.capture()
        self.assertFalse((self.output / "capture.json").exists())

    def test_projected_state_type_change_refuses(self):
        self.snap["state"] = {
            "session": {"id": self.thread, "ended_at": False},
            "requirements": [],
        }
        with self.assertRaises(bt.Refused):
            self.capture()

    def test_full_state_thread_identity_mismatch_refuses(self):
        self.state["session"]["id"] = "other-thread"
        self.raw = json.dumps(self.state).encode()
        self.live.write_bytes(self.raw)
        self.snap["sha256"] = hashlib.sha256(self.raw).hexdigest()
        with self.assertRaises(bt.Refused):
            self.capture()

    def test_ambiguous_session_namespace_refuses(self):
        other = self.data / "sessions" / self.thread / "state.json"
        other.parent.mkdir(parents=True)
        other.write_bytes(self.raw)
        with self.assertRaises(bt.Refused):
            self.capture()

    def test_capture_cannot_escape_private_result_directory(self):
        with self.assertRaises(bt.Refused):
            bt.capture_full_state(
                self.ctx, self.snap, self.thread, self.root / "escape.json"
            )

    def test_linked_live_input_refuses(self):
        linked = self.root / "linked.json"
        try:
            os.link(self.live, linked)
        except OSError:
            self.skipTest("hardlink unavailable")
        with self.assertRaises(bt.Refused):
            self.capture()

    def test_post_close_snapshot_is_bound_to_capture_and_observation(self):
        with (
            mock.patch.object(bt, "snapshot", return_value=self.snap),
            mock.patch.object(
                bt, "project", return_value={"sha256": self.snap["sha256"]}
            ),
        ):
            bt.capture_post_close(self.ctx, self.thread)
        saved = json.loads((self.output / "post-close.json").read_bytes())
        self.assertEqual(saved["schema"], bt.STATE_CAPTURE)
        self.assertEqual(saved["snapshot"]["sha256"], self.snap["sha256"])
        self.assertEqual(
            (self.output / "post-close-full-state.json").read_bytes(), self.raw
        )
        self.assertTrue(saved["observed_at_utc"].endswith("Z"))


class V3CaptureConsumerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name).resolve()
        self.ctx = {"output": self.output}
        self.state = {
            "session": {
                "id": "controlled",
                "ended_at": "2020-01-01T00:00:01Z",
                "updated_at": "2020-01-01T00:00:02Z",
            },
            "pending": ["keep"],
        }
        self.pre = {
            "session": {
                "id": "controlled",
                "ended_at": None,
                "updated_at": "2020-01-01T00:00:00Z",
            },
            "pending": ["keep"],
        }
        self.put("old-after-full-state.json", self.pre)
        self.put("post-close-full-state.json", self.state)
        self.current = {
            "root": "controlled-data",
            "sha256": bt.sha(self.output / "post-close-full-state.json"),
            "state": self.state,
            "scope": {"current": ["keep"], "ancestor": [], "waiting": 0},
        }
        self.projected = {
            "root": self.current["root"],
            "sha256": self.current["sha256"],
            "scope": self.current["scope"],
        }
        self.put(
            "old-after.json",
            {
                "root": self.current["root"],
                "sha256": bt.sha(self.output / "old-after-full-state.json"),
            },
        )
        self.post = {
            "schema": bt.STATE_CAPTURE,
            "observed_at_utc": "2020-01-01T00:00:03Z",
            "snapshot": self.projected,
        }
        self.put("post-close.json", self.post)
        self.saved = {
            "schema": bt.REPORT,
            "subject": {"state_capture": bt.STATE_CAPTURE},
            "gates": {"old_model": {"thread": "controlled"}},
        }
        self.bind()

    def put(self, name, value):
        (self.output / name).write_text(json.dumps(value))

    def bind(self):
        self.saved["evidence"] = {
            name: bt.sha(self.output / name)
            for name in bt.CAPTURE_EVIDENCE | {"old-after.json"}
        }
        self.put("result.json", self.saved)

    def verify(self, **kwargs):
        from tools.validation import shared_verify

        with (
            mock.patch.object(bt, "snapshot", **kwargs)
            if kwargs
            else mock.patch.object(bt, "snapshot", return_value=self.current),
            mock.patch.object(bt, "project", return_value=self.projected),
            mock.patch.object(
                shared_verify,
                "verify_core",
                return_value={"relation": "synthetic-only"},
            ) as core,
        ):
            result = bt.independent_verify(self.ctx, {}, self.output)
            return result, core

    def test_v3_binds_fixed_captures_before_all_shared_gates(self):
        result, core = self.verify()
        self.assertEqual(result["relation"], "synthetic-only")
        self.assertEqual(
            core.call_args.kwargs["preimage_path"],
            self.output / "old-after-full-state.json",
        )
        self.assertEqual(
            core.call_args.kwargs["extra_required_evidence"], bt.CAPTURE_EVIDENCE
        )

    def test_v3_contract_missing_or_legacy_schema_refuses(self):
        for change in ({"schema": "cg-between-turn-native-result/v2"}, {"subject": {}}):
            original = dict(self.saved)
            self.saved.update(change)
            self.bind()
            with self.assertRaises(bt.Refused):
                self.verify()
            self.saved = original

    def test_unbound_or_changed_capture_refuses(self):
        for name in bt.CAPTURE_EVIDENCE:
            original = (self.output / name).read_bytes()
            (self.output / name).write_bytes(original + b" ")
            with self.assertRaises(bt.Refused):
                self.verify()
            (self.output / name).write_bytes(original)

    def test_preimage_digest_mismatch_refuses_even_with_rehashed_evidence(self):
        self.put("old-after-full-state.json", {"other": "state"})
        self.bind()
        with self.assertRaises(bt.Refused):
            self.verify()

    def test_post_capture_time_shape_or_projection_refuses(self):
        for key, value in (
            ("observed_at_utc", "2999-01-01T00:00:00Z"),
            ("observed_at_utc", "2019-01-01T00:00:00Z"),
            ("observed_at_utc", "2020-01-01T00:00:03+01:00"),
            ("snapshot", {"root": "elsewhere"}),
            ("extra", True),
        ):
            original = dict(self.post)
            self.post[key] = value
            self.put("post-close.json", self.post)
            self.bind()
            with self.assertRaises(bt.Refused):
                self.verify()
            self.post = original

    def test_final_live_drift_refuses_after_shared_gates(self):
        changed = dict(self.current, sha256="0" * 64)
        with self.assertRaises(bt.Refused):
            self.verify(side_effect=[self.current, changed])


if __name__ == "__main__":
    unittest.main()
