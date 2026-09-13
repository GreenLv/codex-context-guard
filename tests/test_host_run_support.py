"""Regression tests for pinned native-host run bookkeeping."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE = Path(__file__).parents[1] / "tools" / "validation" / "host_run_support.py"
ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("host_run_support", MODULE)
assert SPEC and SPEC.loader
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


class HostRunSupportTests(unittest.TestCase):
    def test_local_git_fixture_is_bound_and_resume_preserves_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            item = {"runtime": {"sha256": "a" * 64}}
            args = argparse.Namespace(run_dir=root)
            RUN.fixture_git(args, item)
            fixture = root / "git" / "fixture"
            draft = json.loads((fixture / "commands.draft.json").read_text(encoding="utf-8"))
            self.assertFalse(draft["reviewed"])
            self.assertEqual(draft["runtime_tree_sha256"], "a" * 64)
            self.assertEqual((fixture / "work" / "artifact.txt").read_bytes(), b"candidate\n")
            with self.assertRaisesRegex(RUN.RunError, "already exists"):
                RUN.fixture_git(args, item)

    def test_runtime_newline_preflight_rejects_crlf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = root / "hook.ps1"
            text.write_bytes(b"first\r\nsecond\r\n")
            with self.assertRaisesRegex(RUN.RunError, "CRLF checkout conversion"):
                RUN.check_runtime_newlines(root, {"hook.ps1": "digest"})
            text.write_bytes(b"first\nsecond\n")
            RUN.check_runtime_newlines(root, {"hook.ps1": "digest"})

    def test_stage_resume_and_trust_review_are_bound_to_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = root / "run.json"
            item = {"schema": RUN.SCHEMA, "runtime": {"sha256": "a" * 64},
                    "stages": {"prepared": {"status": "passed"},
                               "login": {"status": "passed"}}}
            RUN.write_new(journal, item)
            proof = root / "trust.json"
            proof.write_text(json.dumps({"status": "trusted", "errors": [],
                                         "warnings": []}), encoding="utf-8")
            args = argparse.Namespace(stage="trust", proof=proof, reviewed=False,
                                      run_dir=root)
            with self.assertRaisesRegex(RUN.RunError, "operator review"):
                RUN.advance(args, item)
            self.assertNotIn("trust", item["stages"])
            args.reviewed = True
            RUN.advance(args, item)
            self.assertTrue(item["stages"]["trust"]["operator_reviewed"])
            RUN.advance(args, item)
            proof.write_text('{"status":"failed"}', encoding="utf-8")
            with self.assertRaisesRegex(RUN.RunError, "different evidence"):
                RUN.advance(args, item)
            self.assertEqual(json.loads(journal.read_text())["stages"]["trust"]["status"], "passed")

    def test_validation_rejects_old_runtime_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            item = {"runtime": {"sha256": "a" * 64},
                    "stages": {stage: {"status": "passed"}
                               for stage in RUN.STAGES[:5]}}
            proof = root / "result.json"
            proof.write_text(json.dumps({"status": "passed",
                                         "runtime_tree_sha256": "b" * 64}), encoding="utf-8")
            args = argparse.Namespace(stage="validation", proof=proof,
                                      reviewed=False, run_dir=root)
            with self.assertRaisesRegex(RUN.RunError, "pinned runtime"):
                RUN.advance(args, item)

    def test_mapping_stage_rejects_draft_and_cross_runtime_subject(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            item = {"runtime": {"sha256": "a" * 64, "plugin_version": "0.13.8"},
                    "stages": {stage: {"status": "passed"}
                               for stage in RUN.STAGES[:4]}}
            proof = root / "mapping.json"
            args = argparse.Namespace(stage="mapping", proof=proof,
                                      reviewed=False, run_dir=root)
            proof.write_text(json.dumps({"schema": "context-guard-host-mapping-draft/v1",
                                         "reviewed": False}), encoding="utf-8")
            with self.assertRaisesRegex(RUN.RunError, "reviewed manifest"):
                RUN.advance(args, item)
            proof.write_text(json.dumps({
                "schema": "context-guard-reviewed-host-mapping/v1",
                "reviewed_at": "2026-09-13T00:00:00Z",
                "subject": {"runtime_tree_sha256": "b" * 64,
                            "plugin_version": "0.13.8"}}), encoding="utf-8")
            with self.assertRaisesRegex(RUN.RunError, "pinned runtime"):
                RUN.advance(args, item)

    def test_continuity_draft_binds_generated_commands_without_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = argparse.Namespace(run_dir=root, scenario="continuity")
            item = {"runtime": RUN.runtime_identity(ROOT),
                    "toolchain": {"python": {"path": sys.executable}}}
            RUN.draft(args, item)
            folder = root / "continuity"
            mapping = json.loads((folder / "mapping.draft.json").read_text(encoding="utf-8"))
            commands = json.loads((folder / "commands.draft.json").read_text(encoding="utf-8"))
            self.assertFalse(mapping["reviewed"])
            self.assertFalse(commands["reviewed"])
            self.assertEqual(mapping["command_draft_sha256"], RUN.sha(folder / "commands.draft.json"))
            self.assertEqual(commands["runtime_tree_sha256"], item["runtime"]["sha256"])
            with self.assertRaisesRegex(RUN.RunError, "already exists"):
                RUN.draft(args, item)

    def test_launch_environment_prioritizes_pinned_interpreters(self) -> None:
        item = {"codex_home": "C:/isolated", "toolchain": {
            "python": {"path": "C:/pinned/python.exe"},
            "shell": {"path": "C:/shell/pwsh.exe"}}}
        env = RUN.launch_environment(item)
        self.assertEqual(env["CODEX_HOME"], "C:/isolated")
        self.assertEqual(env["PATH"].split(RUN.os.pathsep)[:2],
                         ["C:\\pinned", "C:\\shell"] if RUN.os.name == "nt"
                         else ["C:/pinned", "C:/shell"])
        self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")

    def test_detects_executable_drift_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            tool = root / "codex.exe"
            tool.write_bytes(b"old")
            pinned = {"path": str(tool), "sha256": RUN.sha(tool), "version": "codex 1"}
            journal = {"schema": RUN.SCHEMA, "codex_home": str(home),
                       "toolchain": {name: pinned for name in ("codex", "python", "shell")},
                       "runtime": {"root": str(root), "sha256": "a" * 64},
                       "stages": {"prepared": {"status": "passed"}}}
            run_dir = root / "run"
            RUN.write_new(run_dir / "run.json", journal)
            tool.write_bytes(b"new")
            args = argparse.Namespace(run_dir=run_dir, codex_home=home)
            with mock.patch.object(RUN, "version", return_value="codex 1"):
                with self.assertRaisesRegex(RUN.RunError, "codex executable drifted"):
                    RUN.load_and_verify(args)

    def test_redacted_bundle_rejects_byte_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = root / "private-result.json"
            result.write_text(json.dumps({
                "status": "pending", "gate_profile": "host_behavior",
                "runtime_tree_sha256": "a" * 64,
                "gates": [{"id": "cleanup", "status": "pending",
                           "private_prompt": "must not export"}],
                "cleanup": {"status": "observed_facts_required", "remaining_ids": ["private-session-id"]},
            }), encoding="utf-8")
            pinned = {"sha256": "b" * 64, "version": "v"}
            item = {"runtime": {"sha256": "a" * 64, "plugin_version": "0.13.8"},
                    "toolchain": {name: pinned for name in ("codex", "python", "shell")},
                    "stages": {"prepared": {"status": "passed"}}}
            out = root / "bundle"
            RUN.bundle(argparse.Namespace(result=result, bundle_dir=out), item)
            RUN.verify_bundle(out)
            summary = (out / "summary.json").read_text(encoding="utf-8")
            self.assertNotIn("must not export", summary)
            self.assertNotIn("private-session-id", summary)
            self.assertIn('"remaining_count": null', summary)
            extra = out / "private.txt"
            extra.write_bytes(b"must not export")
            with self.assertRaisesRegex(RUN.RunError, "unexpected"):
                RUN.verify_bundle(out)
            extra.unlink()
            (out / "summary.json").write_bytes(b"changed")
            with self.assertRaisesRegex(RUN.RunError, "digest"):
                RUN.verify_bundle(out)

    def test_bundle_rejects_private_gate_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = root / "result.json"
            result.write_text(json.dumps({
                "status": "pending", "gate_profile": "host_behavior",
                "runtime_tree_sha256": "a" * 64,
                "gates": [{"id": "private prompt", "status": "pending"}],
                "cleanup": {"status": "pending", "remaining_ids": []},
            }), encoding="utf-8")
            pinned = {"sha256": "b" * 64, "version": "v"}
            item = {"runtime": {"sha256": "a" * 64, "plugin_version": "0.13.8"},
                    "toolchain": {name: pinned for name in ("codex", "python", "shell")},
                    "stages": {"prepared": {"status": "passed"}}}
            with self.assertRaisesRegex(RUN.RunError, "gate fields"):
                RUN.bundle(argparse.Namespace(result=result, bundle_dir=root / "bundle"), item)


if __name__ == "__main__":
    unittest.main()
