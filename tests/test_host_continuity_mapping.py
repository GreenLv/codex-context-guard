"""Offline regressions for the reviewed continuity mapping contract.

The fixture uses synthetic Hook-shaped input. Passing here proves parser
reachability only; it is not native-host evidence.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import platform
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CAPTURE = load("continuity_capture_test", ROOT / "tools/validation/host_capture.py")
STATE = load("continuity_state_test", ROOT / "tools/validation/host_state_capture.py")
MAPPING = load("continuity_mapping_test", ROOT / "tools/validation/host_continuity_mapping.py")
BEHAVIOR = load("continuity_behavior_test", ROOT / "tools/validation/host_behavior.py")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.capture = self.root / "capture"
        self.report = self.root / "report.json"
        self.session = "synthetic-continuity-session"
        self.wait_prompt = "Pause now and wait for CG_WAIT_RELEASE_47."
        self.release_prompt = "Resume CG_WAIT_RELEASE_47."
        self.stop_marker = "WAITING_FOR:CG_WAIT_RELEASE_47"
        self.expired = "expired-session-hash"
        self.protected = self.session
        self._captures()
        self._manifest()

    def payload(self, event: str, command: str | None = None,
                response: str | None = None) -> dict[str, object]:
        value: dict[str, object] = {
            "hook_event_name": event, "session_id": self.session,
            "cwd": str(self.root),
        }
        if event == "UserPromptSubmit":
            value["prompt"] = self.wait_prompt
        elif event == "Stop":
            value["last_assistant_message"] = self.stop_marker
        elif event == "PreCompact":
            value["trigger"] = "manual"
        elif event == "SessionStart":
            value["source"] = "compact"
        elif event == "SessionEnd":
            value["reason"] = "user_exit"
        elif event in {"PreToolUse", "PostToolUse"}:
            assert command is not None
            value.update({"turn_id": "turn-" + hashlib.sha256(command.encode()).hexdigest()[:8],
                          "tool_name": "Bash", "tool_use_id": "tool-" + hashlib.sha256(command.encode()).hexdigest()[:8],
                          "tool_input": {"command": command}})
            if event == "PostToolUse":
                value["tool_response"] = response
        return value

    def _captures(self) -> None:
        self.setup = self.root / "hooks.json"
        CAPTURE.prepare_hooks(
            self.setup, python=Path(os.sys.executable), capture_dir=self.capture,
            runtime_root=ROOT,
            events=("UserPromptSubmit", "PreToolUse", "PostToolUse", "PreCompact",
                    "SessionStart", "Stop", "SessionEnd"),
        )
        self.setup_hash = sha(self.setup)
        self._snapshots()
        self.commands = {name: f"witness {name}" for name in
                         ("wait_started", "wait_released", "compact_resumed", "cleanup_before")}
        layout: list[tuple[str, str | None, str | None]] = [
            ("UserPromptSubmit", None, None), ("Stop", None, None),
            ("PreToolUse", "wait_started", None), ("PostToolUse", "wait_started", "wait_started"),
            ("UserPromptSubmit", None, None),
            ("PreToolUse", "wait_released", None), ("PostToolUse", "wait_released", "wait_released"),
            ("PreCompact", None, None), ("SessionStart", None, None),
            ("PreToolUse", "compact_resumed", None), ("PostToolUse", "compact_resumed", "compact_resumed"),
            ("PreToolUse", "cleanup_before", None), ("PostToolUse", "cleanup_before", "cleanup_before"),
            ("SessionEnd", None, None),
        ]
        for index, (event, command_name, response_name) in enumerate(layout, 1):
            command = self.commands[command_name] if command_name else None
            response = None
            if response_name:
                path = self.paths[response_name]
                response = json.dumps({"status": "captured", "output": str(path),
                                       "sha256": sha(path)}, sort_keys=True)
            payload = self.payload(event, command, response)
            if index == 5:
                payload["prompt"] = self.release_prompt
            raw = json.dumps(payload, sort_keys=True).encode()
            CAPTURE.record_payload(raw, total_bytes=len(raw), truncated=False,
                                   expected_event=event, capture_dir=self.capture,
                                   runtime_root=ROOT)
            meta = self.capture / f"capture-{index:06d}.meta.json"
            item = json.loads(meta.read_text())
            item["captured_at"] = f"2026-09-09T00:00:{index:02d}+00:00"
            meta.write_text(json.dumps(item, sort_keys=True))
            meta.chmod(0o600)
        report = CAPTURE.inspect_directory(self.capture, ROOT)
        self.report.write_text(json.dumps(report, sort_keys=True))
        self.report.chmod(0o600)
        user_events = ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PreCompact",
                       "SessionStart", "Stop", "SessionEnd")
        records = []
        self.home = self.root / "home"
        self.home.mkdir()
        for index, event in enumerate(user_events):
            records.append({"key": f"user-{index}", "source": "user", "pluginId": None,
                            "eventName": event[:1].lower() + event[1:],
                            "handlerType": "command", "matcher": ".*",
                            "timeoutSec": 10, "additionalContextLimit": None,
                            "trustStatus": "trusted", "enabled": True,
                            "isManaged": False, "sourcePath": str(self.home / "hooks.json"),
                            "currentHash": "sha256:" + f"{index + 1:064x}"})
        for index in range(9):
            records.append({"key": f"plugin-{index}", "source": "plugin",
                            "pluginId": "context-guard@codex-context-guard",
                            "eventName": f"plugin{index}", "trustStatus": "trusted",
                            "handlerType": "command", "matcher": None,
                            "timeoutSec": 10, "additionalContextLimit": None,
                            "enabled": True, "isManaged": False,
                            "sourcePath": str(ROOT / "hooks/hooks.json"),
                            "currentHash": "sha256:" + f"{index + 100:064x}"})
        self.trust = self.root / "trust-review.json"
        self.trust.write_text(json.dumps({
            "schema": "context-guard-native-hook-review/v2", "status": "trusted",
            "records": records, "trust_counts": {"trusted": 16},
            "warnings": [], "errors": [], "user_hooks_sha256": self.setup_hash,
        }, sort_keys=True))
        self.trust.chmod(0o600)

    def witness(self, name: str, time: int, facts: dict[str, object]) -> Path:
        runtime, version, _ = CAPTURE.measure_runtime(ROOT)
        path = self.root / f"{name}.json"
        value = {
            "schema": STATE.SCHEMA, "kind": "state",
            "observed_at": f"2026-09-09T00:00:{time:02d}+00:00",
            "collector_sha256": sha(ROOT / "tools/validation/host_state_capture.py"),
            "runtime_tree_sha256": runtime, "plugin_version": version,
            "capture_setup_sha256": self.setup_hash,
            "session_id_sha256": hashlib.sha256(self.session.encode()).hexdigest(),
            "state_sha256": hashlib.sha256(name.encode()).hexdigest(), "facts": facts,
        }
        path.write_text(json.dumps(value, sort_keys=True) + "\n")
        path.chmod(0o600)
        return path

    def inventory(self, name: str, time: int, ids: list[str]) -> Path:
        runtime, version, _ = CAPTURE.measure_runtime(ROOT)
        path = self.root / f"{name}.json"
        value = {
            "schema": STATE.SCHEMA, "kind": "inventory",
            "observed_at": f"2026-09-09T00:00:{time:02d}+00:00",
            "collector_sha256": sha(ROOT / "tools/validation/host_state_capture.py"),
            "runtime_tree_sha256": runtime, "plugin_version": version,
            "capture_setup_sha256": self.setup_hash,
            "facts": {"session_ids": ids,
                      "state_sha256": {i: hashlib.sha256((name + i).encode()).hexdigest()
                                       for i in ids},
                      "ended_at": {i: ("2026-08-01T00:00:00+00:00" if i == self.expired
                                       else ("2026-09-09T00:00:06+00:00" if name == "cleanup-after" else None))
                                   for i in ids}},
        }
        path.write_text(json.dumps(value, sort_keys=True) + "\n")
        path.chmod(0o600)
        return path

    def _snapshots(self) -> None:
        condition = "WC0001"
        common = {"content_hash": "c" * 64, "compaction_count": 0,
                  "pending_recovery_state": None, "pending_recovery_trigger": None,
                  "pending_recovery_sequence": None, "recovery_trigger": "Stop",
                  "recovery_state_hash": "c" * 64,
                  "recovery_packet_sha256": "f" * 64,
                  "recovery_sha256": "1" * 64}
        wait = dict(common)
        wait["wait_conditions"] = [{"condition_id": condition, "status": "waiting",
            "raised_prompt_sha256": hashlib.sha256(self.wait_prompt.encode()).hexdigest(),
            "released_prompt_sha256": None, "released_by_kind": None}]
        released = dict(common)
        released["wait_conditions"] = [{"condition_id": condition, "status": "released",
            "raised_prompt_sha256": hashlib.sha256(self.wait_prompt.encode()).hexdigest(),
            "released_prompt_sha256": hashlib.sha256(self.release_prompt.encode()).hexdigest(),
            "released_by_kind": "root_user_confirmation"}]
        compact = dict(released)
        compact.update({"compaction_count": 1, "pending_recovery_state": "consumed",
                        "pending_recovery_trigger": "PreCompact",
                        "pending_recovery_sequence": 1,
                        "recovery_trigger": "SessionStart:compact"})
        self.paths = {
            "wait_started": self.witness("wait-started", 3, wait),
            "wait_released": self.witness("wait-released", 6, released),
            "compact_resumed": self.witness("compact-resumed", 10, compact),
            "cleanup_before": self.inventory("cleanup-before", 12,
                                              [self.expired, self.protected]),
            "cleanup_after": self.inventory("cleanup-after", 15, [self.protected]),
        }

    def _manifest(self) -> None:
        runtime, version, _ = CAPTURE.measure_runtime(ROOT)
        value = {
            "schema": MAPPING.MANIFEST_SCHEMA,
            "subject": {"source_commit": "a" * 40,
                        "prepared_source_sha256": "b" * 64,
                        "runtime_tree_sha256": runtime, "plugin_version": version},
            "host": {"os": platform.system(), "python": platform.python_version(),
                     "codex": "test"},
            "session_id_sha256": hashlib.sha256(self.session.encode()).hexdigest(),
            "tools": {"adapter_sha256": sha(ROOT / "tools/validation/host_continuity_mapping.py"),
                      "capture_sha256": sha(ROOT / "tools/validation/host_capture.py"),
                      "state_collector_sha256": sha(ROOT / "tools/validation/host_state_capture.py"),
                      "validator_sha256": sha(ROOT / "tools/validation/host_behavior.py")},
            "capture": {"directory": str(self.capture), "report": str(self.report),
                        "report_sha256": sha(self.report), "setup": str(self.setup),
                        "setup_sha256": sha(self.setup),
                        "trust_review": str(self.trust),
                        "trust_review_sha256": sha(self.trust),
                        "selected_home": str(self.home)},
            "snapshots": {name: {"path": str(path), "sha256": sha(path)}
                          for name, path in self.paths.items()},
            "sequences": {"wait": {"registered": 1, "stopped": 2, "released": 5},
                          "compact": {"precompact": 8, "resumed": 9},
                          "cleanup": {"session_end": 14},
                          "witnesses": {
                              "wait_started": {"capture_sequences": [3, 4], "command": self.commands["wait_started"]},
                              "wait_released": {"capture_sequences": [6, 7], "command": self.commands["wait_released"]},
                              "compact_resumed": {"capture_sequences": [10, 11], "command": self.commands["compact_resumed"]},
                              "cleanup_before": {"capture_sequences": [12, 13], "command": self.commands["cleanup_before"]},
                          }},
            "markers": {"wait_prompt_sha256": hashlib.sha256(self.wait_prompt.encode()).hexdigest(),
                        "release_prompt_sha256": hashlib.sha256(self.release_prompt.encode()).hexdigest(),
                        "stop_marker": self.stop_marker},
            "cleanup": {"expired_ids": [self.expired], "protected_ids": [self.protected]},
        }
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps(value, sort_keys=True))
        self.manifest.chmod(0o600)

    def adapt(self):
        return MAPPING.adapt(self.manifest, ROOT, sha(self.manifest))

    def mutate_manifest(self, fn) -> None:
        value = json.loads(self.manifest.read_text())
        fn(value)
        self.manifest.write_text(json.dumps(value, sort_keys=True))

    def mutate_snapshot(self, name: str, fn) -> None:
        path = self.paths[name]
        value = json.loads(path.read_text())
        fn(value)
        path.write_text(json.dumps(value, sort_keys=True) + "\n")
        self.mutate_manifest(lambda m: m["snapshots"][name].update({"sha256": sha(path)}))
        post_sequences = {"wait_started": 4, "wait_released": 7,
                          "compact_resumed": 11, "cleanup_before": 13}
        if name in post_sequences:
            sequence = post_sequences[name]
            raw_path = self.capture / f"capture-{sequence:06d}.raw"
            payload = json.loads(raw_path.read_text())
            payload["tool_response"] = json.dumps({
                "status": "captured", "output": str(path), "sha256": sha(path)
            }, sort_keys=True)
            raw = json.dumps(payload, sort_keys=True).encode()
            raw_path.write_bytes(raw)
            raw_path.chmod(0o600)
            meta_path = self.capture / f"capture-{sequence:06d}.meta.json"
            meta = json.loads(meta_path.read_text())
            meta["raw_sha256"] = hashlib.sha256(raw).hexdigest()
            meta["raw_bytes"] = len(raw)
            meta_path.write_text(json.dumps(meta, sort_keys=True))
            meta_path.chmod(0o600)
            report = CAPTURE.inspect_directory(self.capture, ROOT)
            self.report.write_text(json.dumps(report, sort_keys=True))
            self.report.chmod(0o600)
            self.mutate_manifest(lambda m: m["capture"].update(
                {"report_sha256": sha(self.report)}))


class ContinuityMappingTests(unittest.TestCase):
    def fixture(self, temp: str) -> Fixture:
        return Fixture(Path(temp))

    def test_in_memory_receipt_maps_only_remaining_three_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            bundle, receipt = fixture.adapt()
            result = BEHAVIOR.Validator(bundle["subject"], "0.12.4").validate(
                bundle, reviewed_mapping=receipt)
            gates = {g["id"]: g["status"] for g in result["gates"]}
            self.assertEqual({g for g, s in gates.items() if s == "passed"},
                             set(MAPPING.MAPPED_GATES))
            self.assertEqual(result["status"], "pending")
            self.assertFalse(result["visibility"]["host_passed_reachable"])

    def test_serialized_bundle_has_no_acceptance_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            bundle, _ = fixture.adapt()
            result = BEHAVIOR.Validator(bundle["subject"], "0.12.4").validate(
                json.loads(json.dumps(bundle)))
            self.assertTrue(all(g["status"] == "pending" for g in result["gates"]))

    def test_cross_session_and_reordered_hooks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            payload = {"hook_event_name": "UserPromptSubmit", "session_id": "foreign",
                       "cwd": str(fixture.root), "prompt": "foreign"}
            raw = json.dumps(payload, sort_keys=True).encode()
            CAPTURE.record_payload(raw, total_bytes=len(raw), truncated=False,
                                   expected_event="UserPromptSubmit",
                                   capture_dir=fixture.capture, runtime_root=ROOT)
            report = CAPTURE.inspect_directory(fixture.capture, ROOT)
            fixture.report.write_text(json.dumps(report, sort_keys=True))
            fixture.report.chmod(0o600)
            fixture.mutate_manifest(lambda m: m["capture"].update(
                {"report_sha256": sha(fixture.report)}))
            with self.assertRaisesRegex(Exception, "foreign|session"):
                fixture.adapt()
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            fixture.mutate_manifest(lambda m: m["sequences"]["compact"].update(
                {"precompact": 5, "resumed": 4}))
            with self.assertRaisesRegex(MAPPING.ContinuityMappingError, "causal order"):
                fixture.adapt()

    def test_witness_command_cannot_be_rebound_by_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            fixture.mutate_manifest(lambda m: m["sequences"]["witnesses"][
                "wait_started"].update({"command": "witness something-else"}))
            with self.assertRaisesRegex(MAPPING.ContinuityMappingError,
                                        "frozen direct command"):
                fixture.adapt()

    def test_forged_wait_marker_and_release_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            fixture.mutate_manifest(lambda m: m["markers"].update({"stop_marker": "forged"}))
            with self.assertRaisesRegex(MAPPING.ContinuityMappingError, "markers"):
                fixture.adapt()
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            fixture.mutate_snapshot("wait_released", lambda s: s["facts"]["wait_conditions"][0].update(
                {"released_prompt_sha256": "0" * 64}))
            with self.assertRaisesRegex(MAPPING.ContinuityMappingError, "causally close"):
                fixture.adapt()

    def test_incomplete_compaction_or_recovery_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            fixture.mutate_snapshot("compact_resumed", lambda s: s["facts"].update(
                {"pending_recovery_state": "ready"}))
            with self.assertRaisesRegex(MAPPING.ContinuityMappingError, "compact witness"):
                fixture.adapt()

    def test_untrusted_lifecycle_capture_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            trust = json.loads(fixture.trust.read_text())
            trust["records"][0]["trustStatus"] = "untrusted"
            fixture.trust.write_text(json.dumps(trust, sort_keys=True))
            fixture.mutate_manifest(lambda m: m["capture"].update(
                {"trust_review_sha256": sha(fixture.trust)}))
            with self.assertRaisesRegex(MAPPING.ContinuityMappingError, "trusted"):
                fixture.adapt()

    def test_cleanup_remaining_target_or_lost_protected_id_is_rejected(self) -> None:
        for ids in (["expired-session-hash", "synthetic-continuity-session"], []):
            with self.subTest(ids=ids), tempfile.TemporaryDirectory() as temp:
                fixture = self.fixture(temp)
                fixture.mutate_snapshot("cleanup_after", lambda s, ids=ids: s["facts"].update(
                    {"session_ids": ids, "state_sha256": {i: "e" * 64 for i in ids},
                     "ended_at": {i: ("2026-08-01T00:00:00+00:00" if i == fixture.expired else "2026-09-09T00:00:06+00:00") for i in ids}}))
                with self.assertRaisesRegex(MAPPING.ContinuityMappingError, "cleanup"):
                    fixture.adapt()

    def test_cleanup_rejects_undeclared_removed_sessions(self) -> None:
        cases = (("unexpired-other", None),
                 ("undeclared-expired", "2026-08-01T00:00:00+00:00"))
        for session_id, ended_at in cases:
            with self.subTest(session_id=session_id), tempfile.TemporaryDirectory() as temp:
                fixture = self.fixture(temp)
                fixture.mutate_snapshot("cleanup_before", lambda s: (
                    s["facts"]["session_ids"].append(session_id),
                    s["facts"]["session_ids"].sort(),
                    s["facts"]["state_sha256"].update({session_id: "a" * 64}),
                    s["facts"]["ended_at"].update({session_id: ended_at}),
                ))
                with self.assertRaisesRegex(MAPPING.ContinuityMappingError,
                                            "removed ids|protected set"):
                    fixture.adapt()

    def test_cleanup_rejects_protected_set_tampering_and_duplicates(self) -> None:
        for case, mutate in enumerate((
            lambda m: m["cleanup"].update({"protected_ids": []}),
            lambda m: m["cleanup"].update({"protected_ids":
                                            [m["cleanup"]["protected_ids"][0]] * 2}),
            lambda m: m["cleanup"].update({"protected_ids":
                                            [m["cleanup"]["protected_ids"][0], "other"]}),
        )):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                fixture = self.fixture(temp)
                fixture.mutate_manifest(mutate)
                with self.assertRaisesRegex(MAPPING.ContinuityMappingError, "cleanup"):
                    fixture.adapt()

    def test_cleanup_rejects_retained_state_or_lifecycle_drift(self) -> None:
        for field, value in (("state_sha256", "d" * 64),
                             ("ended_at", "2026-09-01T00:00:00+00:00")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                fixture = self.fixture(temp)
                retained = "retained-ended-session"
                ended = "2026-09-08T00:00:00+00:00"
                for name in ("cleanup_before", "cleanup_after"):
                    fixture.mutate_snapshot(name, lambda s, name=name: (
                        s["facts"]["session_ids"].append(retained),
                        s["facts"]["session_ids"].sort(),
                        s["facts"]["state_sha256"].update({retained: "c" * 64}),
                        s["facts"]["ended_at"].update({retained: ended}),
                    ))
                fixture.mutate_manifest(lambda m: m["cleanup"]["protected_ids"].append(retained))
                fixture.mutate_snapshot("cleanup_after", lambda s: s["facts"][field].update(
                    {retained: value}))
                with self.assertRaisesRegex(MAPPING.ContinuityMappingError,
                                            "retained non-current"):
                    fixture.adapt()

    def test_cleanup_rejects_extra_after_or_invalid_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            fixture.mutate_snapshot("cleanup_after", lambda s: (
                s["facts"]["session_ids"].append("after-only"),
                s["facts"]["session_ids"].sort(),
                s["facts"]["state_sha256"].update({"after-only": "a" * 64}),
                s["facts"]["ended_at"].update({"after-only": None}),
            ))
            with self.assertRaisesRegex(MAPPING.ContinuityMappingError, "unexpected"):
                fixture.adapt()
        for mutate in (
            lambda s: s["facts"]["session_ids"].append(s["facts"]["session_ids"][0]),
            lambda s: s["facts"]["state_sha256"].update(
                {s["facts"]["session_ids"][0]: "invalid"}),
            lambda s: s["facts"]["ended_at"].update(
                {s["facts"]["session_ids"][0]: 123}),
        ):
            with tempfile.TemporaryDirectory() as temp:
                fixture = self.fixture(temp)
                fixture.mutate_snapshot("cleanup_before", mutate)
                with self.assertRaisesRegex(MAPPING.ContinuityMappingError,
                                            "inventory ids/hashes"):
                    fixture.adapt()

    def test_receipt_cannot_expand_gate_set_or_replay_changed_validator(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            bundle, receipt = fixture.adapt()
            forged = copy.deepcopy(receipt)
            forged["mapped_gates"] = list(BEHAVIOR.REQUIRED_GATES)
            with self.assertRaisesRegex(BEHAVIOR.HostBehaviorError, "remaining-gate set"):
                BEHAVIOR.Validator(bundle["subject"], "0.12.4").validate(bundle, reviewed_mapping=forged)
            forged = copy.deepcopy(receipt)
            forged["validator_sha256"] = "0" * 64
            with self.assertRaisesRegex(BEHAVIOR.HostBehaviorError, "validator identity"):
                BEHAVIOR.Validator(bundle["subject"], "0.12.4").validate(bundle, reviewed_mapping=forged)

    def test_capture_setup_can_select_the_exact_lifecycle_event_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "hooks.json"
            events = ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PreCompact",
                      "SessionStart", "Stop", "SessionEnd")
            setup = CAPTURE.prepare_hooks(output, python=Path(os.sys.executable),
                                          capture_dir=root / "capture",
                                          runtime_root=ROOT, events=events)
            hooks = json.loads(output.read_text())["hooks"]
            self.assertEqual(list(hooks), list(events))
            self.assertEqual(setup["events"], list(events))
            self.assertTrue(setup["requires_normal_hook_review_and_trust"])
            self.assertFalse(setup["trust_bypass_used"])

    def test_state_collector_validates_runtime_state_and_omits_raw_packet(self) -> None:
        guard = load("continuity_state_guard", ROOT / "scripts/context_guard.py")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            session_dir = root / "sessions" / "state-session"
            session_dir.mkdir(parents=True)
            state = guard.new_state({"session_id": "state-session", "cwd": str(root)})
            state["mode"]["active"] = True
            guard.save_state(session_dir, state)
            guard.write_recovery(session_dir, state, "test")
            setup_hash = "a" * 64
            output = root / "witness" / "state.json"
            value = STATE.capture_state(session_dir / "state.json",
                                        session_dir / "recovery.json", output,
                                        ROOT, setup_hash)
            self.assertEqual(value["kind"], "state")
            self.assertNotIn("CONTEXT-GUARD RECOVERY PACKET", json.dumps(value))
            inventory = root / "witness" / "inventory.json"
            observed = STATE.capture_inventory(root / "sessions", inventory,
                                               ROOT, setup_hash)
            self.assertEqual(observed["facts"]["session_ids"], ["state-session"])
            self.assertIsNone(observed["facts"]["ended_at"]["state-session"])

    def test_production_dispatch_and_exact_collector_sequence_reaches_all_three_gates(self) -> None:
        guard = load("continuity_production_guard", ROOT / "scripts/context_guard.py")
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(Path(temp) / "private"),
                         "PYTHONDONTWRITEBYTECODE": "1"}, clear=False,
        ):
            fixture = self.fixture(temp)
            for path in fixture.capture.iterdir():
                path.unlink()
            for path in fixture.paths.values():
                path.unlink()
            workspace = fixture.root / "workspace"
            workspace.mkdir()
            sessions = fixture.root / "private" / "sessions"
            expired_dir = sessions / fixture.expired
            expired = guard.new_state({"session_id": fixture.expired, "cwd": str(workspace)})
            expired["session"]["ended_at"] = "2026-07-01T00:00:00+00:00"
            guard.save_state(expired_dir, expired)
            sequence = 0

            def event(name: str, **extra: object) -> tuple[int, dict[str, object]]:
                nonlocal sequence
                sequence += 1
                payload: dict[str, object] = {
                    "hook_event_name": name, "session_id": fixture.session,
                    "cwd": str(workspace), "turn_id": f"turn-{sequence}",
                    "tool_use_id": f"tool-{sequence}",
                }
                payload.update(extra)
                raw = json.dumps(payload, sort_keys=True).encode()
                CAPTURE.record_payload(raw, total_bytes=len(raw), truncated=False,
                                       expected_event=name, capture_dir=fixture.capture,
                                       runtime_root=ROOT)
                result = guard.dispatch(payload)
                return sequence, result

            def command(output: Path, mode: str, require_recovery: bool = False) -> str:
                args = [sys.executable, str(ROOT / "tools/validation/host_state_capture.py"), mode]
                if mode == "current":
                    args += ["--capture-dir", str(fixture.capture), "--sessions", str(sessions)]
                else:
                    args += ["--sessions", str(sessions)]
                args += ["--output", str(output), "--runtime-root", str(ROOT),
                         "--capture-setup-sha256", fixture.setup_hash]
                if require_recovery:
                    args.append("--require-recovery")
                return " ".join(shlex.quote(item) for item in args)

            def run_witness(name: str, mode: str = "current",
                            require_recovery: bool = False) -> tuple[int, int]:
                output = fixture.root / f"{name.replace('_', '-')}.json"
                cmd = command(output, mode, require_recovery)
                turn_id = f"witness-turn-{name}"
                tool_use_id = f"witness-tool-{name}"
                pre, decision = event("PreToolUse", tool_name="Bash",
                                      turn_id=turn_id, tool_use_id=tool_use_id,
                                      tool_input={"command": cmd})
                self.assertNotEqual((decision.get("hookSpecificOutput") or {}).get(
                    "permissionDecision"), "deny")
                completed = subprocess.run(shlex.split(cmd), shell=False, cwd=workspace, text=True,
                                           capture_output=True, check=True)
                post, _ = event("PostToolUse", tool_name="Bash",
                                turn_id=turn_id, tool_use_id=tool_use_id,
                                tool_input={"command": cmd},
                                tool_response=completed.stdout.strip())
                fixture.paths[name] = output
                fixture.commands[name] = cmd
                return pre, post

            fixture.wait_prompt = (
                "请使用 $context-guard 保持当前工作单元暂停，直到我明确输入"
                "“CG_CONTINUITY_RELEASE_47”。本轮不要调用工具；最后一行必须是 "
                "WAITING_FOR:CG_CONTINUITY_RELEASE_47。"
            )
            wait_registered, _ = event("UserPromptSubmit", prompt=fixture.wait_prompt)
            stopped, _ = event("Stop", last_assistant_message=
                               "WAITING_FOR:CG_CONTINUITY_RELEASE_47")
            event("UserPromptSubmit", prompt="仅执行状态采集；不要输入释放词。")
            wait_pair = run_witness("wait_started")
            release_cmd = command(fixture.root / "wait-released.json", "current")
            fixture.release_prompt = (
                "继续 CG_CONTINUITY_RELEASE_47。仅执行这一条命令记录释放后的状态："
                + release_cmd
            )
            released, _ = event("UserPromptSubmit", prompt=fixture.release_prompt)
            release_pair = run_witness("wait_released")
            precompact, _ = event("PreCompact", trigger="manual")
            resumed, _ = event("SessionStart", source="compact")
            event("UserPromptSubmit", prompt="仅执行 compact 状态采集。")
            compact_pair = run_witness("compact_resumed", require_recovery=True)
            event("UserPromptSubmit", prompt="仅执行 SessionEnd 前会话清单采集。")
            cleanup_pair = run_witness("cleanup_before", mode="inventory")
            session_end, _ = event("SessionEnd", reason="user_exit")
            cleanup_after = fixture.root / "cleanup-after.json"
            STATE.capture_inventory(sessions, cleanup_after, ROOT, fixture.setup_hash)
            fixture.paths["cleanup_after"] = cleanup_after
            report = CAPTURE.inspect_directory(fixture.capture, ROOT)
            fixture.report.write_text(json.dumps(report, sort_keys=True))
            manifest = json.loads(fixture.manifest.read_text())
            manifest["capture"]["report_sha256"] = sha(fixture.report)
            manifest["snapshots"] = {name: {"path": str(path), "sha256": sha(path)}
                                     for name, path in fixture.paths.items()}
            manifest["sequences"] = {
                "wait": {"registered": wait_registered, "stopped": stopped,
                         "released": released},
                "compact": {"precompact": precompact, "resumed": resumed},
                "cleanup": {"session_end": session_end},
                "witnesses": {
                    "wait_started": {"capture_sequences": list(wait_pair),
                                     "command": fixture.commands["wait_started"]},
                    "wait_released": {"capture_sequences": list(release_pair),
                                      "command": fixture.commands["wait_released"]},
                    "compact_resumed": {"capture_sequences": list(compact_pair),
                                        "command": fixture.commands["compact_resumed"]},
                    "cleanup_before": {"capture_sequences": list(cleanup_pair),
                                       "command": fixture.commands["cleanup_before"]},
                },
            }
            manifest["markers"] = {
                "wait_prompt_sha256": hashlib.sha256(fixture.wait_prompt.encode()).hexdigest(),
                "release_prompt_sha256": hashlib.sha256(fixture.release_prompt.encode()).hexdigest(),
                "stop_marker": "WAITING_FOR:CG_CONTINUITY_RELEASE_47",
            }
            fixture.manifest.write_text(json.dumps(manifest, sort_keys=True))
            bundle, receipt = fixture.adapt()
            result = BEHAVIOR.Validator(bundle["subject"], "0.12.4").validate(
                bundle, reviewed_mapping=receipt)
            gate_status = {gate["id"]: gate["status"] for gate in result["gates"]}
            self.assertEqual({gate: gate_status[gate]
                              for gate in MAPPING.MAPPED_GATES},
                             {gate: "passed" for gate in MAPPING.MAPPED_GATES})




class WindowsCommandCanonicalTests(unittest.TestCase):
    def test_generated_command_and_noncanonical_expressions(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            setup = json.loads(fixture.setup.read_bytes())
            self.assertTrue(MAPPING._verify_setup(setup, fixture.capture, ROOT))
            original = setup["hooks"]["PreToolUse"][0]["hooks"][0]["commandWindows"]
            variants = ["'&'" + original[1:], '"&"' + original[1:],
                        original + "; Write-Output injected", original.replace("& ", "&  ", 1)]
            for command in variants:
                with self.subTest(command=command):
                    altered = copy.deepcopy(setup)
                    altered["hooks"]["PreToolUse"][0]["hooks"][0]["commandWindows"] = command
                    with self.assertRaises(MAPPING.ContinuityMappingError):
                        MAPPING._verify_setup(altered, fixture.capture, ROOT)


class StateWriterByteTests(unittest.TestCase):
    def test_binary_open_flag_and_exact_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "state.json"
            original_open = os.open
            seen = []
            binary_flag = getattr(os, "O_BINARY", 0x8000)
            def open_binary(path, flags, mode):
                seen.append(flags)
                return original_open(path, flags if os.name == "nt" else flags & ~binary_flag, mode)
            with mock.patch.object(STATE.os, "O_BINARY", binary_flag, create=True), mock.patch.object(STATE.os, "open", side_effect=open_binary):
                STATE._write(output, {"value": "line"})
            self.assertTrue(seen[0] & binary_flag)
            self.assertEqual(output.read_bytes(), b'{"value": "line"}\n')

    def test_cli_hashes_actual_written_bytes(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "state.json"
            actual = b'{"written": true}\r\n'
            def capture(*args):
                output.write_bytes(actual)
                return {"different_return_value": True}
            stream = io.StringIO()
            with mock.patch.object(STATE, "capture_inventory", side_effect=capture), contextlib.redirect_stdout(stream):
                status = STATE.main(["inventory", "--sessions", temp, "--output", str(output),
                                     "--runtime-root", str(ROOT), "--capture-setup-sha256", "a" * 64])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(stream.getvalue())["sha256"], hashlib.sha256(actual).hexdigest())


if __name__ == "__main__":
    unittest.main()
