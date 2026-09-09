"""Reviewed raw-to-gate mapping regressions.

Fixtures create actual local Git objects and raw Hook capture files, but they
are synthetic parser tests and never count as native host evidence.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
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


CAPTURE = load("reviewed_mapping_capture_test", ROOT / "tools/validation/host_capture.py")
MAPPING = load("reviewed_mapping_test", ROOT / "tools/validation/host_raw_mapping.py")
BEHAVIOR = load("reviewed_mapping_behavior_test", ROOT / "tools/validation/host_behavior.py")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(cwd: Path, *args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, text=True, capture_output=True, check=True,
        env=env,
    )
    return result.stdout.strip()


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.repo = self.root / "repo"
        self.remote = self.root / "remote.git"
        self.capture = self.root / "capture"
        self.capture_report = self.root / "capture-report.json"
        self.home = self.root / "home"
        self.trust = self.root / "trust.json"
        self.contract = self.root / "trust-contract.json"
        self.manifest = self.root / "manifest.json"
        self.session = "synthetic-reviewed-mapping-session"
        self.commit_command = "git commit -m 'reviewed mapping fixture'"
        self.push_command = "git push origin HEAD:refs/heads/main"
        self._git_fixture()
        self._captures()
        self._trust_review()
        self._manifest()

    def _git_fixture(self) -> None:
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "core.autocrlf", "false")
        (self.repo / "owned.txt").write_bytes(b"v1\n")
        git(self.repo, "add", "owned.txt")
        git(
            self.repo, "-c", "user.name=Context Guard Fixture", "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit", "-q", "--no-gpg-sign", "-m", "initial",
        )
        self.initial = git(self.repo, "rev-parse", "HEAD")
        git(self.root, "init", "-q", "--bare", str(self.remote))
        git(self.repo, "remote", "add", "origin", str(self.remote))
        (self.repo / "owned.txt").write_bytes(b"v2\n")
        git(self.repo, "add", "owned.txt")
        commit_env = os.environ.copy()
        commit_env.update({
            "GIT_AUTHOR_DATE": "2026-09-09T00:00:02+00:00",
            "GIT_COMMITTER_DATE": "2026-09-09T00:00:02+00:00",
        })
        git(
            self.repo, "-c", "user.name=Context Guard Fixture", "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit", "-q", "--no-gpg-sign", "-m", "reviewed mapping fixture",
            env=commit_env,
        )
        self.final = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "push", "origin", "HEAD:refs/heads/main")

    def payload(self, event: str, command: str, response: str | None = None) -> bytes:
        value = {
            "hook_event_name": event,
            "session_id": self.session,
            "turn_id": "turn-reviewed-git-chain",
            "cwd": str(self.repo),
            "tool_name": "Bash",
            "tool_use_id": f"tool-{command.split()[1]}",
            "tool_input": {"command": command},
        }
        if event == "PostToolUse":
            value["tool_response"] = response or "opaque host response"
        return json.dumps(value, sort_keys=True).encode()

    def _captures(self) -> None:
        responses = {
            self.commit_command: (
                f"[main {self.final[:7]}] reviewed mapping fixture\n"
                " 1 file changed, 1 insertion(+), 1 deletion(-)\n"
            ),
            self.push_command: (
                f"To {self.remote}\n"
                " * [new branch]      HEAD -> main\n"
            ),
        }
        for command in (self.commit_command, self.push_command):
            for event in ("PreToolUse", "PostToolUse"):
                raw = self.payload(
                    event, command,
                    responses[command] if event == "PostToolUse" else None,
                )
                CAPTURE.record_payload(
                    raw,
                    total_bytes=len(raw),
                    truncated=False,
                    expected_event=event,
                    capture_dir=self.capture,
                    runtime_root=ROOT,
                )
        for sequence, timestamp in enumerate((
            "2026-09-09T00:00:01+00:00",
            "2026-09-09T00:00:03+00:00",
            "2026-09-09T00:00:04+00:00",
            "2026-09-09T00:00:05+00:00",
        ), 1):
            meta = self.capture / f"capture-{sequence:06d}.meta.json"
            item = json.loads(meta.read_text())
            item["captured_at"] = timestamp
            meta.write_text(json.dumps(item, sort_keys=True))
            meta.chmod(0o600)
        self.refresh_capture_report(update_manifest=False)

    def refresh_capture_report(self, *, update_manifest: bool = True) -> None:
        report = CAPTURE.inspect_directory(self.capture, ROOT)
        self.capture_report.write_text(json.dumps(report, sort_keys=True))
        self.capture_report.chmod(0o600)
        if update_manifest:
            self.mutate_manifest(
                lambda item: item["evidence"].update(
                    {"capture_report_sha256": sha(self.capture_report)}
                )
            )

    def _trust_review(self) -> None:
        self.home.mkdir()
        def capture_command(event: str) -> str:
            return shlex.join((
                sys.executable,
                str(ROOT / "tools/validation/host_capture.py"),
                "record", "--capture-dir", str(self.capture),
                "--runtime-root", str(ROOT), "--expected-event", event,
            ))
        user_config = {
            "description": "Synthetic reviewed mapping fixture.",
            "hooks": {
                event: [{
                    "matcher": ".*",
                    "hooks": [{
                        "type": "command", "command": capture_command(event),
                        "timeout": 10,
                    }],
                }]
                for event in ("PreToolUse", "PostToolUse")
            },
        }
        user_path = self.home / "hooks.json"
        user_path.write_text(json.dumps(user_config, sort_keys=True))

        def records_from(
            config: dict[str, object], source: str, plugin_id: str | None,
            source_path: Path,
        ) -> list[dict[str, object]]:
            result = []
            for index, descriptor in enumerate(MAPPING._hook_descriptors(config)):
                hook_hash = "sha256:" + hashlib.sha256(
                    json.dumps(
                        [source, plugin_id, index, descriptor], sort_keys=True
                    ).encode()
                ).hexdigest()
                result.append({
                    "key": f"{source_path}:{descriptor['eventName']}:{index}",
                    **descriptor,
                    "source": source,
                    "pluginId": plugin_id,
                    "currentHash": hook_hash,
                    "enabled": True,
                    "isManaged": False,
                    "sourcePath": str(source_path),
                    "trustStatus": "trusted",
                })
            return result

        plugin_path = ROOT / "hooks/hooks.json"
        plugin_config = json.loads(plugin_path.read_text())
        records = records_from(
            plugin_config, "plugin", "context-guard@codex-context-guard",
            plugin_path,
        ) + records_from(user_config, "user", None, user_path)
        records.sort(key=lambda item: str(item["key"]))
        normalized = []
        for record in records:
            item = {
                key: value for key, value in record.items()
                if key not in {"key", "sourcePath", "trustStatus"}
            }
            item["sourcePathClass"] = (
                "plugin_0_12_4" if record["source"] == "plugin"
                else "selected_home_hooks"
            )
            normalized.append(item)
        self.trust.write_text(json.dumps({
            "schema": "context-guard-native-hook-review/v2",
            "status": "trusted", "selected_home": str(self.home),
            "records": records,
            "normalized_contract": normalized,
            "trust_counts": {"trusted": 11}, "warnings": [], "errors": [],
        }))
        self.trust.chmod(0o600)
        contract = {
            "schema": "context-guard-p4-r5-recovery-expected-hooks/v1",
            "plugin_version": "0.12.4",
            "record_count": 11,
            "plugin_record_count": 9,
            "user_capture_record_count": 2,
            "controlled_home": str(self.home),
            "records": [
                {key: value for key, value in record.items() if key != "trustStatus"}
                for record in records
            ],
            "normalized_contract": normalized,
            "pretrust_requirement": "capture Hooks require review",
            "post_review_requirement": "all exact Hooks trusted",
        }
        self.contract.write_text(json.dumps(contract, sort_keys=True))
        self.contract.chmod(0o600)

    def _manifest(self) -> None:
        runtime, version, _ = CAPTURE.measure_runtime(ROOT)
        value = {
            "schema": MAPPING.MANIFEST_SCHEMA,
            "reviewed_at": "2026-09-09T00:00:00+00:00",
            "subject": {
                "source_commit": "a" * 40,
                "prepared_source_sha256": "b" * 64,
                "runtime_tree_sha256": runtime,
                "plugin_version": version,
            },
            "host": {"os": "test", "python": "3.12", "codex": "test"},
            "session_id_sha256": hashlib.sha256(self.session.encode()).hexdigest(),
            "tools": {
                "adapter_sha256": sha(ROOT / "tools/validation/host_raw_mapping.py"),
                "capture_sha256": sha(ROOT / "tools/validation/host_capture.py"),
                "validator_sha256": sha(ROOT / "tools/validation/host_behavior.py"),
            },
            "evidence": {
                "capture_dir": str(self.capture), "trust_review": str(self.trust),
                "trust_review_sha256": sha(self.trust),
                "trust_contract": str(self.contract),
                "trust_contract_sha256": sha(self.contract),
                "capture_report": str(self.capture_report),
                "capture_report_sha256": sha(self.capture_report),
            },
            "git": {
                "worktree": str(self.repo), "bare_remote": str(self.remote),
                "target_path": "owned.txt",
                "target_sha256": hashlib.sha256(b"v2\n").hexdigest(),
                "initial_head": self.initial, "final_head": self.final,
                "expected_refs": {"refs/heads/main": self.final},
            },
            "operations": {
                "commit": {"capture_sequences": [1, 2], "command": self.commit_command},
                "push": {"capture_sequences": [3, 4], "command": self.push_command,
                         "remote": "origin", "ref": "main"},
            },
        }
        self.manifest.write_text(json.dumps(value, sort_keys=True))
        self.manifest.chmod(0o600)

    def adapt(self):
        return MAPPING.adapt(self.manifest, ROOT, sha(self.manifest))

    def mutate_manifest(self, mutate) -> None:
        item = json.loads(self.manifest.read_text())
        mutate(item)
        self.manifest.write_text(json.dumps(item, sort_keys=True))

    def mutate_raw(self, sequence: int, mutate) -> None:
        path = self.capture / f"capture-{sequence:06d}.raw"
        item = json.loads(path.read_text())
        mutate(item)
        raw = json.dumps(item, sort_keys=True).encode()
        path.write_bytes(raw)
        meta = self.capture / f"capture-{sequence:06d}.meta.json"
        data = json.loads(meta.read_text())
        data["raw_sha256"] = hashlib.sha256(raw).hexdigest()
        data["raw_bytes"] = len(raw)
        meta.write_text(json.dumps(data, sort_keys=True))
        path.chmod(0o600)
        meta.chmod(0o600)

    def refresh_trust_hash(self) -> None:
        self.mutate_manifest(
            lambda item: item["evidence"].update(
                {"trust_review_sha256": sha(self.trust)}
            )
        )


class ReviewedRawMappingTests(unittest.TestCase):
    def fixture(self, temp: str) -> Fixture:
        return Fixture(Path(temp))

    def test_reviewed_mapping_passes_only_three_observed_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            bundle, receipt = fixture.adapt()
            declared = dict(bundle["subject"])
            result = BEHAVIOR.Validator(declared, "0.12.4").validate(
                bundle, reviewed_mapping=receipt
            )
            gates = {gate["id"]: gate for gate in result["gates"]}
            self.assertEqual(result["status"], "pending")
            self.assertFalse(result["visibility"]["host_passed_reachable"])
            self.assertEqual(
                {name for name, gate in gates.items() if gate["status"] == "passed"},
                {"hook_trust", "commit_event", "local_push_readback"},
            )
            self.assertEqual(
                {name for name, gate in gates.items() if gate["status"] == "pending"},
                {"continuity_wait", "compact_resume", "cleanup"},
            )
            self.assertEqual(result["subject"]["runtime_tree_sha256"], receipt["runtime_tree_sha256"])
            self.assertNotEqual(
                result["validation"]["validator_sha256"],
                result["subject"]["runtime_tree_sha256"],
            )

    def test_serialized_reviewed_origin_has_no_acceptance_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            bundle, _ = fixture.adapt()
            result = BEHAVIOR.Validator(bundle["subject"], "0.12.4").validate(
                json.loads(json.dumps(bundle))
            )
            self.assertTrue(all(gate["status"] == "pending" for gate in result["gates"]))
            self.assertFalse(result["visibility"]["host_passed_reachable"])

    def test_raw_capture_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            path = fixture.capture / "capture-000001.raw"
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(MAPPING.MappingError, "capture verification"):
                fixture.adapt()

    def test_manifest_drift_and_validator_identity_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            before = sha(fixture.manifest)
            item = json.loads(fixture.manifest.read_text())
            item["reviewed_at"] = "2026-09-09T00:00:01+00:00"
            fixture.manifest.write_text(json.dumps(item, sort_keys=True))
            with self.assertRaisesRegex(MAPPING.MappingError, "SHA-256 changed"):
                MAPPING.adapt(fixture.manifest, ROOT, before)
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            item = json.loads(fixture.manifest.read_text())
            item["tools"]["validator_sha256"] = "0" * 64
            fixture.manifest.write_text(json.dumps(item, sort_keys=True))
            with self.assertRaisesRegex(MAPPING.MappingError, "validator bytes"):
                fixture.adapt()

    def test_wrong_pair_session_or_missing_post_is_rejected(self) -> None:
        for mutation, message in (
            ("session", "capture verification"),
            ("missing", "capture verification"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                fixture = self.fixture(temp)
                if mutation == "session":
                    path = fixture.capture / "capture-000002.raw"
                    item = json.loads(path.read_text())
                    item["session_id"] = "foreign"
                    raw = json.dumps(item, sort_keys=True).encode()
                    path.write_bytes(raw)
                    meta = fixture.capture / "capture-000002.meta.json"
                    data = json.loads(meta.read_text())
                    data["raw_sha256"] = hashlib.sha256(raw).hexdigest()
                    data["raw_bytes"] = len(raw)
                    meta.write_text(json.dumps(data, sort_keys=True))
                else:
                    (fixture.capture / "capture-000002.raw").unlink()
                with self.assertRaisesRegex(Exception, message):
                    fixture.adapt()

    def test_compound_command_and_generic_success_text_have_no_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            item = json.loads(fixture.manifest.read_text())
            item["operations"]["commit"]["command"] += "; echo ok"
            fixture.manifest.write_text(json.dumps(item, sort_keys=True))
            with self.assertRaisesRegex(MAPPING.MappingError, "compound"):
                fixture.adapt()
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            subprocess.run(
                ["git", "--git-dir", str(fixture.remote), "update-ref", "-d", "refs/heads/main"],
                check=True,
            )
            with self.assertRaisesRegex(MAPPING.MappingError, "remote readback"):
                fixture.adapt()

    def test_untrusted_hook_or_git_blob_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            trust = json.loads(fixture.trust.read_text())
            trust["records"][0]["trustStatus"] = "modified"
            fixture.trust.write_text(json.dumps(trust))
            manifest = json.loads(fixture.manifest.read_text())
            manifest["evidence"]["trust_review_sha256"] = sha(fixture.trust)
            fixture.manifest.write_text(json.dumps(manifest, sort_keys=True))
            with self.assertRaisesRegex(MAPPING.MappingError, "non-trusted"):
                fixture.adapt()
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            (fixture.repo / "owned.txt").write_text("drift\n")
            with self.assertRaisesRegex(MAPPING.MappingError, "worktree readback"):
                fixture.adapt()

    def test_receipt_replay_with_changed_validator_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            bundle, receipt = fixture.adapt()
            forged = copy.deepcopy(receipt)
            forged["validator_sha256"] = "0" * 64
            with self.assertRaisesRegex(BEHAVIOR.HostBehaviorError, "validator identity"):
                BEHAVIOR.Validator(bundle["subject"], "0.12.4").validate(
                    bundle, reviewed_mapping=forged
                )

    def test_receipt_cannot_expand_the_accepted_gate_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            bundle, receipt = fixture.adapt()
            forged = copy.deepcopy(receipt)
            forged["mapped_gates"] = list(BEHAVIOR.REQUIRED_GATES)
            bundle["scenarios"] = list(BEHAVIOR.REQUIRED_GATES)
            with self.assertRaisesRegex(
                BEHAVIOR.HostBehaviorError, "accepted three-gate set"
            ):
                BEHAVIOR.Validator(bundle["subject"], "0.12.4").validate(
                    bundle, reviewed_mapping=forged
                )

    def test_capture_cwd_cannot_be_rebound_to_a_different_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            other = fixture.root / "different-repo"
            shutil.copytree(fixture.repo, other)
            fixture.mutate_manifest(
                lambda item: item["git"].update({"worktree": str(other)})
            )
            with self.assertRaisesRegex(MAPPING.MappingError, "capture cwd"):
                fixture.adapt()

    def test_worktree_path_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            alias = fixture.root / "repo-alias"
            try:
                alias.symlink_to(fixture.repo, target_is_directory=True)
            except OSError as exc:
                if getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows symbolic-link privilege unavailable")
                raise
            fixture.mutate_manifest(
                lambda item: item["git"].update({"worktree": str(alias)})
            )
            with self.assertRaisesRegex(MAPPING.MappingError, "canonical|alias"):
                fixture.adapt()

    def test_push_remote_must_resolve_to_the_reviewed_bare_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            wrong = fixture.root / "wrong.git"
            git(fixture.repo, "remote", "set-url", "origin", str(wrong))
            with self.assertRaisesRegex(MAPPING.MappingError, "remote URL"):
                fixture.adapt()
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            clone = fixture.root / "same-objects.git"
            git(fixture.root, "clone", "-q", "--bare", str(fixture.remote), str(clone))
            git(fixture.repo, "remote", "set-url", "origin", str(clone))
            with self.assertRaisesRegex(MAPPING.MappingError, "declared bare"):
                fixture.adapt()

    def test_wrong_remote_or_ref_cannot_be_selected_by_manifest(self) -> None:
        for field, value in (("remote", "backup"), ("ref", "reauth")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                fixture = self.fixture(temp)
                fixture.mutate_manifest(
                    lambda item, field=field, value=value: item["operations"][
                        "push"
                    ].update({field: value})
                )
                with self.assertRaisesRegex(MAPPING.MappingError, "origin main"):
                    fixture.adapt()

    def test_failed_or_dry_run_commit_cannot_borrow_existing_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            fixture.mutate_raw(
                2,
                lambda item: item.update(
                    {"tool_response": "nothing to commit, working tree clean\n"}
                ),
            )
            fixture.refresh_capture_report()
            with self.assertRaisesRegex(MAPPING.MappingError, "commit Post"):
                fixture.adapt()
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            fixture.mutate_manifest(
                lambda item: item["operations"]["commit"].update(
                    {"command": "git commit --dry-run -m 'reviewed mapping fixture'"}
                )
            )
            with self.assertRaisesRegex(MAPPING.MappingError, "exactly"):
                fixture.adapt()

    def test_existing_commit_outside_capture_interval_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            for sequence, timestamp in (
                (1, "2026-09-09T00:00:10+00:00"),
                (2, "2026-09-09T00:00:11+00:00"),
            ):
                meta = fixture.capture / f"capture-{sequence:06d}.meta.json"
                item = json.loads(meta.read_text())
                item["captured_at"] = timestamp
                meta.write_text(json.dumps(item, sort_keys=True))
            fixture.refresh_capture_report()
            with self.assertRaisesRegex(MAPPING.MappingError, "outside"):
                fixture.adapt()

    def test_push_response_must_name_the_resolved_remote_and_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            fixture.mutate_raw(
                4,
                lambda item: item.update(
                    {"tool_response": "To /tmp/other.git\n"
                     " * [new branch]      HEAD -> main\n"}
                ),
            )
            fixture.refresh_capture_report()
            with self.assertRaisesRegex(MAPPING.MappingError, "push Post"):
                fixture.adapt()

    def test_trust_records_bind_normalized_and_actual_hook_definitions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            trust = json.loads(fixture.trust.read_text())
            trust["normalized_contract"][0]["matcher"] = "drift"
            fixture.trust.write_text(json.dumps(trust, sort_keys=True))
            fixture.refresh_trust_hash()
            with self.assertRaisesRegex(MAPPING.MappingError, "normalized"):
                fixture.adapt()
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            hooks = json.loads((fixture.home / "hooks.json").read_text())
            hooks["hooks"]["PreToolUse"][0]["matcher"] = "drift"
            (fixture.home / "hooks.json").write_text(json.dumps(hooks, sort_keys=True))
            with self.assertRaisesRegex(MAPPING.MappingError, "selected hooks.json"):
                fixture.adapt()
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            hooks = json.loads((fixture.home / "hooks.json").read_text())
            hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"] += " --extra"
            (fixture.home / "hooks.json").write_text(json.dumps(hooks, sort_keys=True))
            with self.assertRaisesRegex(MAPPING.MappingError, "does not bind recorder"):
                fixture.adapt()
        with tempfile.TemporaryDirectory() as temp:
            fixture = self.fixture(temp)
            trust = json.loads(fixture.trust.read_text())
            trust["records"][0]["currentHash"] = "sha256:" + "0" * 64
            trust["normalized_contract"][0]["currentHash"] = "sha256:" + "0" * 64
            fixture.trust.write_text(json.dumps(trust, sort_keys=True))
            fixture.refresh_trust_hash()
            with self.assertRaisesRegex(MAPPING.MappingError, "frozen expected"):
                fixture.adapt()




class CommitTimestampQuantizationTests(unittest.TestCase):
    def test_strict_one_second_quantization_boundary(self):
        from datetime import datetime, timedelta
        for offset, accepted in ((0.999999, True), (1.0, False)):
            with self.subTest(offset=offset), tempfile.TemporaryDirectory() as temp:
                fixture = Fixture(Path(temp))
                commit_time = datetime.fromisoformat(git(fixture.repo, "show", "-s", "--format=%cI"))
                path = fixture.capture / "capture-000001.meta.json"
                value = json.loads(path.read_bytes())
                value["captured_at"] = (commit_time + timedelta(seconds=offset)).isoformat()
                path.write_text(json.dumps(value))
                fixture.refresh_capture_report()
                if accepted:
                    fixture.adapt()
                else:
                    with self.assertRaisesRegex(MAPPING.MappingError, "outside"):
                        fixture.adapt()

    def test_fixture_remote_alias_remains_rejected(self):
        with self.assertRaises(MAPPING.MappingError):
            MAPPING._direct_git("git push fixture HEAD:refs/heads/main", "push", "fixture", "main")


class WindowsCaptureCommandTests(unittest.TestCase):
    def test_generated_command_is_required(self):
        with tempfile.TemporaryDirectory(prefix="capture ' quoted ") as temp:
            root = Path(temp)
            output = root / "hooks.json"
            CAPTURE.prepare_hooks(output, python=Path(sys.executable),
                                  capture_dir=root / "captures", runtime_root=ROOT)
            hook = json.loads(output.read_bytes())["hooks"]["PreToolUse"][0]["hooks"][0]
            expected = shlex.split(hook["command"])
            command = hook["commandWindows"]
            MAPPING._verify_windows_command(command, expected)
            for altered in ("'&'" + command[1:], '"&"' + command[1:],
                            command + "; Write-Output injected",
                            command.replace("& ", "&  ", 1)):
                with self.subTest(command=altered), self.assertRaises(MAPPING.MappingError):
                    MAPPING._verify_windows_command(altered, expected)


if __name__ == "__main__":
    unittest.main()
