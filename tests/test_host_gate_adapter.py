#!/usr/bin/env python3
"""Regression tests for the bounded private Hook-to-host-gate adapter."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ADAPTER = load("host_gate_adapter_test", ROOT / "tools/validation/host_gate_adapter.py")
CAPTURE = load("host_capture_for_adapter_test", ROOT / "tools/validation/host_capture.py")
PROBE_PATH = ROOT / "tools/validation/host_gate_probe.py"
ADAPTER_PATH = ROOT / "tools/validation/host_gate_adapter.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, text=True, capture_output=True, check=True
    )
    return result.stdout.strip()


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.worktree = root / "worktree"
        self.remote = root / "remote.git"
        self.capture_dir = root / "capture"
        self.experiment_path = root / "experiment.json"
        self.target = "gate-target.txt"
        self.target_bytes = b"candidate gate target\n"
        self.command = ""
        self.manifest: dict = {}
        self._prepare_git()
        self._write_experiment()

    def _prepare_git(self) -> None:
        self.worktree.mkdir()
        run_git(self.worktree, "init", "-q", "-b", "main")
        (self.worktree / self.target).write_bytes(b"initial\n")
        run_git(self.worktree, "add", "--", self.target)
        run_git(
            self.worktree,
            "-c", "user.name=Context Guard Fixture",
            "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit", "-q", "--no-gpg-sign", "-m", "initial fixture",
        )
        self.initial_head = run_git(self.worktree, "rev-parse", "HEAD")
        run_git(self.root, "init", "-q", "--bare", str(self.remote))
        (self.worktree / self.target).write_bytes(self.target_bytes)

    def _write_experiment(self, **updates) -> None:
        runtime_digest, version, _ = CAPTURE.measure_runtime(ROOT)
        python = os.fsdecode(Path(os.sys.executable).resolve())
        command = ADAPTER.shlex.join([
            python, str(PROBE_PATH), "commit-push", "--experiment",
            str(self.experiment_path),
        ])
        manifest = {
            "schema": ADAPTER.EXPERIMENT_SCHEMA,
            "experiment_id": "adapter-regression-1",
            "created_at": "2026-09-08T00:00:00+00:00",
            "nonce": "adapter_regression_nonce_1234",
            "scenario": "commit_push",
            "subject": {
                "source_commit": run_git(ROOT, "rev-parse", "HEAD"),
                "prepared_source_sha256": "b" * 64,
                "runtime_tree_sha256": runtime_digest,
            },
            "runtime": {
                "plugin_version": version,
                "capture_tool_sha256": sha256(
                    ROOT / "tools/validation/host_capture.py"
                ),
            },
            "command": {
                "python": python,
                "probe_script": str(PROBE_PATH),
                "experiment_path": str(self.experiment_path),
                "exact": command,
            },
            "probe": {
                "probe_script_sha256": sha256(PROBE_PATH),
                "adapter_sha256": sha256(ADAPTER_PATH),
            },
            "git": {
                "workspace_root": str(self.root),
                "worktree": str(self.worktree),
                "bare_remote": str(self.remote),
                "branch": "main",
                "target_path": self.target,
                "target_sha256": hashlib.sha256(self.target_bytes).hexdigest(),
                "initial_head": self.initial_head,
                "commit_message": "exact host gate fixture",
            },
            "expected_capture": {"pre_sequence": 1, "post_sequence": 2},
            "allowed_untracked": [],
        }
        for key, value in updates.items():
            manifest[key] = value
        self.manifest = manifest
        self.command = command
        self.experiment_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.experiment_path.chmod(0o600)

    @property
    def experiment_sha(self) -> str:
        return sha256(self.experiment_path)

    def run_probe(self) -> str:
        return load(
            f"host_gate_probe_{id(self)}", PROBE_PATH
        ).run(self.experiment_path)

    def payload(self, event: str, response: str | None = None, **updates) -> bytes:
        value = {
            "hook_event_name": event,
            "session_id": "sess-adapter-regression",
            "turn_id": "turn-adapter-regression",
            "cwd": str(self.worktree),
            "tool_name": "Bash",
            "tool_use_id": "inner-bash-tool-use-id",
            "tool_input": {"command": self.command},
        }
        if event == "PostToolUse":
            value["tool_response"] = response if response is not None else ""
        value.update(updates)
        return json.dumps(value, sort_keys=True).encode()

    def record_pair(
        self,
        marker: str,
        *,
        pre_updates: dict | None = None,
        post_updates: dict | None = None,
        response: str | None = None,
    ) -> None:
        pre = self.payload("PreToolUse", **(pre_updates or {}))
        CAPTURE.record_payload(
            pre, total_bytes=len(pre), truncated=False,
            expected_event="PreToolUse", capture_dir=self.capture_dir,
            runtime_root=ROOT,
        )
        post = self.payload(
            "PostToolUse",
            response=(
                response
                if response is not None
                else f"Chunk ID: outer-exec-id\nProcess exited with code 0\n{marker}"
            ),
            **(post_updates or {}),
        )
        CAPTURE.record_payload(
            post, total_bytes=len(post), truncated=False,
            expected_event="PostToolUse", capture_dir=self.capture_dir,
            runtime_root=ROOT,
        )

    def adapt(self) -> dict:
        return ADAPTER.adapt(
            experiment_path=self.experiment_path,
            experiment_sha256=self.experiment_sha,
            capture_dir=self.capture_dir,
            runtime_root=ROOT,
        )


class HostGateAdapterTests(unittest.TestCase):
    def fixture(self, temp: str) -> Fixture:
        return Fixture(Path(temp))

    def test_wrapped_probe_is_partial_and_cannot_emit_host_gate_chains(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            marker = fixture.run_probe()
            fixture.record_pair(marker)
            result = fixture.adapt()
            self.assertFalse(result["acceptance_authority"])
            self.assertFalse(result["guard_chain_qualified"])
            readback = result["internal_git_facts"]
            self.assertEqual(readback["parent"], fixture.initial_head)
            self.assertEqual(readback["remote_commit"], readback["commit"])
            self.assertNotIn("host_behavior_bundle", result)

    def test_marker_is_required_unique_and_exact(self) -> None:
        cases = ("", "warning: command may have worked")
        for response in cases:
            with self.subTest(response=response), tempfile.TemporaryDirectory() as temp:
                fixture = self.fixture(temp)
                marker = fixture.run_probe()
                fixture.record_pair(marker, response=response)
                with self.assertRaisesRegex(ADAPTER.AdapterError, "exactly one"):
                    fixture.adapt()
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            marker = fixture.run_probe()
            fixture.record_pair(marker, response=f"{marker}\n{marker}")
            with self.assertRaisesRegex(ADAPTER.AdapterError, "exactly one"):
                fixture.adapt()

    def test_forged_marker_and_generic_exit_text_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            marker = fixture.run_probe()
            decoded = ADAPTER.decode_marker(marker)
            decoded["nonce"] = "different_nonce_123456"
            fixture.record_pair(
                ADAPTER.encode_marker(decoded),
                response=(
                    "Process exited with code 0\n"
                    + ADAPTER.encode_marker(decoded)
                ),
            )
            with self.assertRaisesRegex(ADAPTER.AdapterError, "nonce"):
                fixture.adapt()

    def test_wrong_command_or_pair_identity_is_rejected(self) -> None:
        for changed, message in (
            ({"tool_input": {"command": "wrong command"}}, "tool_input"),
            ({"tool_use_id": "different-inner-id"}, "tool_use_id"),
            ({"turn_id": "different-turn"}, "turn_id"),
            ({"session_id": "different-session"}, "session_id"),
        ):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temp:
                fixture = self.fixture(temp)
                marker = fixture.run_probe()
                fixture.record_pair(marker, post_updates=changed)
                with self.assertRaisesRegex(Exception, message):
                    fixture.adapt()

    def test_frozen_probe_adapter_runtime_and_metadata_drift_are_rejected(self) -> None:
        byte_mutations = (
            ("probe", "probe_script_sha256", "0" * 64, "probe script bytes"),
            ("probe", "adapter_sha256", "0" * 64, "adapter bytes"),
        )
        for group, key, value, message in byte_mutations:
            with self.subTest(group=group, key=key), tempfile.TemporaryDirectory() as temp:
                fixture = self.fixture(temp)
                manifest = copy.deepcopy(fixture.manifest)
                manifest[group][key] = value
                fixture.experiment_path.write_text(json.dumps(manifest), encoding="utf-8")
                fixture.experiment_path.chmod(0o600)
                with self.assertRaisesRegex(ADAPTER.AdapterError, message):
                    ADAPTER.adapt(
                        experiment_path=fixture.experiment_path,
                        experiment_sha256=fixture.experiment_sha,
                        capture_dir=fixture.capture_dir,
                        runtime_root=ROOT,
                    )

        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            marker = fixture.run_probe()
            fixture.record_pair(marker)
            manifest = copy.deepcopy(fixture.manifest)
            manifest["subject"]["runtime_tree_sha256"] = "0" * 64
            fixture.experiment_path.write_text(json.dumps(manifest), encoding="utf-8")
            fixture.experiment_path.chmod(0o600)
            with self.assertRaisesRegex(ADAPTER.AdapterError, "runtime differs"):
                fixture.adapt()

        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            marker = fixture.run_probe()
            fixture.record_pair(marker)
            meta_path = fixture.capture_dir / "capture-000001.meta.json"
            meta = json.loads(meta_path.read_text())
            meta["capture_kind"] = "claimed-success"
            meta_path.write_text(json.dumps(meta))
            with self.assertRaisesRegex(Exception, "kind"):
                fixture.adapt()

    def test_live_repository_drift_and_marker_readback_conflicts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            marker = fixture.run_probe()
            fixture.record_pair(marker)
            run_git(fixture.worktree, "reset", "-q", "--hard", fixture.initial_head)
            with self.assertRaisesRegex(ADAPTER.AdapterError, "changed paths|readback"):
                fixture.adapt()

        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            marker = fixture.run_probe()
            decoded = ADAPTER.decode_marker(marker)
            decoded["remote_commit"] = fixture.initial_head
            fixture.record_pair(ADAPTER.encode_marker(decoded))
            with self.assertRaisesRegex(ADAPTER.AdapterError, "marker facts"):
                fixture.adapt()

    def test_unexpected_status_and_missing_remote_ref_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            marker = fixture.run_probe()
            fixture.record_pair(marker)
            (fixture.worktree / "unexpected.txt").write_text("dirty\n")
            with self.assertRaisesRegex(ADAPTER.AdapterError, "allowed_untracked"):
                fixture.adapt()

        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            marker = fixture.run_probe()
            fixture.record_pair(marker)
            run_git(
                fixture.worktree, "--git-dir", str(fixture.remote),
                "update-ref", "-d", "refs/heads/main",
            )
            with self.assertRaisesRegex(ADAPTER.AdapterError, "readback failed"):
                fixture.adapt()

    def test_replayed_capture_and_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            marker = fixture.run_probe()
            fixture.record_pair(marker)
            raw = (fixture.capture_dir / "capture-000001.raw").read_bytes()
            CAPTURE.record_payload(
                raw, total_bytes=len(raw), truncated=False,
                expected_event="PreToolUse", capture_dir=fixture.capture_dir,
                runtime_root=ROOT,
            )
            with self.assertRaisesRegex(ADAPTER.AdapterError, "replays"):
                fixture.adapt()

        duplicate = b'{"schema":"a","schema":"b"}'
        with self.assertRaisesRegex(ADAPTER.AdapterError, "repeats key"):
            ADAPTER._json_object(duplicate, "fixture")

    def test_cli_writes_owner_private_output_and_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            marker = fixture.run_probe()
            fixture.record_pair(marker)
            output = Path(temp) / "result.json"
            argv = [
                "--experiment", str(fixture.experiment_path),
                "--experiment-sha256", fixture.experiment_sha,
                "--capture-dir", str(fixture.capture_dir),
                "--runtime-root", str(ROOT),
                "--output", str(output),
            ]
            self.assertEqual(ADAPTER.main(argv), 0)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            original = output.read_bytes()
            self.assertEqual(ADAPTER.main(argv), 2)
            self.assertEqual(output.read_bytes(), original)

    def test_probe_failure_prints_no_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            run_git(fixture.worktree, "add", "--", fixture.target)
            result = subprocess.run(
                [os.sys.executable, str(PROBE_PATH), "commit-push", "--experiment",
                 str(fixture.experiment_path)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(ADAPTER.MARKER_PREFIX, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
