from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "validation" / "host_capture.py"
SPEC = importlib.util.spec_from_file_location("host_capture", MODULE_PATH)
assert SPEC and SPEC.loader
HC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HC)


def payload(event: str = "PreToolUse", **updates) -> bytes:
    item = {
        "session_id": "thr-live-shape-1",
        "transcript_path": None,
        "cwd": "/tmp/synthetic-host-capture",
        "hook_event_name": event,
        "model": "test-model",
        "permission_mode": "dontAsk",
        "turn_id": "turn-live-shape-1",
    }
    if event in HC.TOOL_EVENTS:
        item.update({
            "tool_name": "Bash",
            "tool_use_id": "call-live-shape-1",
            "tool_input": {"command": "git status --short"},
        })
    if event == "PostToolUse":
        item["tool_response"] = {"exit_code": 0, "output": ""}
    item.update(updates)
    return json.dumps(item, separators=(",", ":")).encode()


class WireValidationTests(unittest.TestCase):
    def test_pre_and_post_require_documented_tool_fields(self) -> None:
        for event in ("PreToolUse", "PostToolUse"):
            with self.subTest(event=event):
                result = HC.validate_wire(payload(event), event)
                self.assertEqual(result["observed_event"], event)
                self.assertEqual(result["tool_name"], "Bash")
                self.assertIn("tool_use_id", result["known_fields_present"])

    def test_wiring_event_mismatch_rejected(self) -> None:
        with self.assertRaisesRegex(HC.CaptureError, "does not match"):
            HC.validate_wire(payload("PostToolUse"), "PreToolUse")

    def test_missing_tool_use_id_rejected(self) -> None:
        raw = json.loads(payload())
        del raw["tool_use_id"]
        with self.assertRaisesRegex(HC.CaptureError, "tool_use_id"):
            HC.validate_wire(json.dumps(raw).encode(), "PreToolUse")

    def test_post_requires_actual_tool_response_field(self) -> None:
        raw = json.loads(payload("PostToolUse"))
        del raw["tool_response"]
        with self.assertRaisesRegex(HC.CaptureError, "tool_response"):
            HC.validate_wire(json.dumps(raw).encode(), "PostToolUse")

    def test_non_json_and_non_object_rejected(self) -> None:
        for raw in (b"not-json", b"[]", b"\xff"):
            with self.subTest(raw=raw):
                with self.assertRaises(HC.CaptureError):
                    HC.validate_wire(raw, "PreToolUse")

    def test_unknown_names_are_counted_but_never_echoed(self) -> None:
        result = HC.validate_wire(payload(private_customer_key="secret"), "PreToolUse")
        self.assertEqual(result["unknown_field_count"], 1)
        self.assertNotIn("private_customer_key", json.dumps(result))
        self.assertNotIn("secret", json.dumps(result))


class CaptureRecordTests(unittest.TestCase):
    def record(self, directory: Path, raw: bytes | None = None) -> Path:
        raw = raw or payload()
        return HC.record_payload(
            raw, total_bytes=len(raw), truncated=False,
            expected_event="PreToolUse", capture_dir=directory,
            runtime_root=ROOT,
        )

    def test_record_measures_runtime_and_owner_private_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            meta_path = self.record(directory)
            meta = json.loads(meta_path.read_text())
            expected, version, count = HC.measure_runtime(ROOT)
            self.assertEqual(meta["runtime_tree_sha256"], expected)
            self.assertEqual(meta["plugin_version"], version)
            self.assertEqual(meta["runtime_file_count"], count)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(meta_path.stat().st_mode), 0o600)
                self.assertEqual(
                    stat.S_IMODE((directory / meta["raw_file"]).stat().st_mode), 0o600
                )

    def test_two_records_receive_unique_monotonic_sequences(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            first = self.record(directory, payload(tool_use_id="call-1"))
            second = self.record(directory, payload(tool_use_id="call-2"))
            self.assertEqual(json.loads(first.read_text())["sequence"], 1)
            self.assertEqual(json.loads(second.read_text())["sequence"], 2)

    def test_partial_or_oversized_payload_is_never_evidence(self) -> None:
        raw = payload()
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(HC.CaptureError, "partial evidence"):
                HC.record_payload(
                    raw[:20], total_bytes=len(raw), truncated=True,
                    expected_event="PreToolUse", capture_dir=Path(temp),
                    runtime_root=ROOT,
                )

    def test_runtime_root_without_manager_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(HC.CaptureError, "manage_plugin"):
                HC.record_payload(
                    payload(), total_bytes=len(payload()), truncated=False,
                    expected_event="PreToolUse", capture_dir=Path(temp) / "capture",
                    runtime_root=Path(temp),
                )


class InspectionTests(unittest.TestCase):
    def record(self, directory: Path, raw: bytes | None = None) -> Path:
        raw = raw or payload()
        return HC.record_payload(
            raw, total_bytes=len(raw), truncated=False,
            expected_event="PreToolUse", capture_dir=directory,
            runtime_root=ROOT,
        )

    def test_inspect_verifies_raw_projection_and_stays_non_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            self.record(directory)
            report = HC.inspect_directory(directory, ROOT)
            self.assertEqual(report["status"], "observed")
            self.assertFalse(report["acceptance_authority"])
            self.assertEqual(report["capture_count"], 1)
            self.assertEqual(report["entries"][0]["tool_name"], "Bash")
            self.assertNotIn("git status", json.dumps(report))
            self.assertNotIn("thr-live", json.dumps(report))

    def test_raw_tamper_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            meta_path = self.record(directory)
            meta = json.loads(meta_path.read_text())
            (directory / meta["raw_file"]).write_bytes(b"{}")
            with self.assertRaisesRegex(HC.CaptureError, "hash or length"):
                HC.inspect_directory(directory, ROOT)

    def test_metadata_unknown_field_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            meta_path = self.record(directory)
            meta = json.loads(meta_path.read_text())
            meta["claimed_success"] = True
            meta_path.write_text(json.dumps(meta))
            with self.assertRaisesRegex(HC.CaptureError, "unknown fields"):
                HC.inspect_directory(directory, ROOT)

    def test_metadata_value_tamper_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            meta_path = self.record(directory)
            meta = json.loads(meta_path.read_text())
            meta["capture_kind"] = "claimed_host_acceptance"
            meta_path.write_text(json.dumps(meta))
            with self.assertRaisesRegex(HC.CaptureError, "kind is invalid"):
                HC.inspect_directory(directory, ROOT)

    def test_oversized_metadata_rejected_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            meta_path = self.record(directory)
            meta_path.write_bytes(b" " * (HC.MAX_METADATA_BYTES + 1))
            with self.assertRaisesRegex(HC.CaptureError, "bounded size"):
                HC.inspect_directory(directory, ROOT)

    @unittest.skipIf(os.name == "nt", "POSIX permission semantics")
    def test_non_private_capture_file_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            meta_path = self.record(directory)
            meta_path.chmod(0o644)
            with self.assertRaisesRegex(HC.CaptureError, "not owner-private"):
                HC.inspect_directory(directory, ROOT)

    def test_replayed_raw_payload_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            self.record(directory)
            self.record(directory)
            with self.assertRaisesRegex(HC.CaptureError, "replays"):
                HC.inspect_directory(directory, ROOT)

    def test_orphan_raw_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            directory.mkdir(mode=0o700)
            raw_path = directory / "capture-000001.raw"
            raw_path.write_bytes(payload())
            raw_path.chmod(0o600)
            with self.assertRaisesRegex(HC.CaptureError, "orphan"):
                HC.inspect_directory(directory, ROOT)

    def test_empty_directory_is_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            report = HC.inspect_directory(Path(temp), ROOT)
            self.assertEqual(report["status"], "pending")
            self.assertEqual(report["capture_count"], 0)

    def test_pre_post_pair_requires_same_observed_identity_and_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            pre = payload("PreToolUse")
            HC.record_payload(
                pre, total_bytes=len(pre), truncated=False,
                expected_event="PreToolUse", capture_dir=directory,
                runtime_root=ROOT,
            )
            post = payload("PostToolUse")
            HC.record_payload(
                post, total_bytes=len(post), truncated=False,
                expected_event="PostToolUse", capture_dir=directory,
                runtime_root=ROOT,
            )
            pairing = HC.inspect_directory(directory, ROOT)["tool_pairing"]
            self.assertEqual(pairing["paired"], 1)
            self.assertTrue(pairing["complete"])

    def test_pre_post_pair_rejects_changed_tool_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            pre = payload("PreToolUse")
            HC.record_payload(
                pre, total_bytes=len(pre), truncated=False,
                expected_event="PreToolUse", capture_dir=directory,
                runtime_root=ROOT,
            )
            post = payload(
                "PostToolUse", tool_input={"command": "different command"}
            )
            HC.record_payload(
                post, total_bytes=len(post), truncated=False,
                expected_event="PostToolUse", capture_dir=directory,
                runtime_root=ROOT,
            )
            with self.assertRaisesRegex(HC.CaptureError, "tool_input differs"):
                HC.inspect_directory(directory, ROOT)

    def test_unmatched_post_is_visible_not_reordered_into_a_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            post = payload("PostToolUse")
            HC.record_payload(
                post, total_bytes=len(post), truncated=False,
                expected_event="PostToolUse", capture_dir=directory,
                runtime_root=ROOT,
            )
            pairing = HC.inspect_directory(directory, ROOT)["tool_pairing"]
            self.assertEqual(pairing["unmatched_post"], 1)
            self.assertFalse(pairing["complete"])


class CliTests(unittest.TestCase):
    def test_record_and_inspect_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "capture"
            recorded = subprocess.run(
                [sys.executable, str(MODULE_PATH), "record",
                 "--expected-event", "PreToolUse",
                 "--capture-dir", str(directory),
                 "--runtime-root", str(ROOT)],
                input=payload(), capture_output=True, check=False,
            )
            self.assertEqual(recorded.returncode, 0, recorded.stderr)
            self.assertEqual(recorded.stdout.strip(), b"{}")
            output = Path(temp) / "report.json"
            inspected = subprocess.run(
                 [sys.executable, str(MODULE_PATH), "inspect",
                 "--capture-dir", str(directory), "--runtime-root", str(ROOT),
                 "--output", str(output)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            self.assertEqual(json.loads(output.read_text())["status"], "observed")

    def test_empty_inspect_returns_pending_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.json"
            result = subprocess.run(
                [sys.executable, str(MODULE_PATH), "inspect",
                 "--capture-dir", temp, "--runtime-root", str(ROOT),
                 "--output", str(output)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 3)

    def test_prepare_emits_reviewable_two_event_hook_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "scratch" / ".codex" / "hooks.json"
            capture_dir = Path(temp) / "capture"
            setup = HC.prepare_hooks(
                output, python=Path(sys.executable), capture_dir=capture_dir,
                runtime_root=ROOT,
            )
            config = json.loads(output.read_text())
            self.assertEqual(set(config["hooks"]), {"PreToolUse", "PostToolUse"})
            for event, groups in config["hooks"].items():
                hook = groups[0]["hooks"][0]
                self.assertIn(f"--expected-event {event}", hook["command"])
                self.assertIn(f"--expected-event' '{event}", hook["commandWindows"])
                self.assertNotIn("bypass", hook["command"].lower())
            self.assertTrue(setup["requires_normal_hook_review_and_trust"])
            self.assertFalse(setup["trust_bypass_used"])


if __name__ == "__main__":
    unittest.main()
