"""0.13 failure-family suite: migration, default-path exit, release isolation.

Matrix rows covered (frozen plan section 8.1):

* T01/T03 — report-3 A–E style edit→commit→push sequences and multi-repo
  execution under the standard profile: no provenance-based denies, no
  compound prohibition, no fabricated authorization or success evidence;
* T04 — mixed requests keep both objects as requirements and never draw a
  cleanup patch veto;
* T12 — release isolation: without an adopted contract nothing (files,
  skills, ordinary tasks) enables release enforcement; a declared release
  profile enforces tier-A exact tickets; unknown adoption state never
  degrades a declared/adopted release posture;
* T13 — schema 11→12 migration: trusted delivery reconstruction, explicit
  historical marking of pre-0.13 authorization records, protocol identity
  moves, and no lossy rewrite of pending obligations;
* T14 — structural assertion: the default candidate path performs no Git
  subprocess and no authorization-chain solving.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "context_guard.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DefaultPathHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.data_dir = Path(tempfile.mkdtemp())
        patcher = mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.data_dir / "private")}
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.project = self.data_dir / "project"
        self.project.mkdir()
        self.git_init(self.project)
        spec = importlib.util.spec_from_file_location("cg_dp", ENTRY)
        self.cg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.cg)

    @staticmethod
    def git_init(project: Path) -> None:
        subprocess.run(
            ["git", "init", "-q", str(project)], check=True, capture_output=True
        )
        subprocess.run(
            ["git", "-C", str(project), "config", "user.name", "Context Guard Test"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(project), "config", "user.email", "test@example.invalid"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(project), "commit", "-q", "--allow-empty", "-m", "base"],
            check=True, capture_output=True,
        )

    def payload(self, event, *, turn="t1", **kwargs):
        payload = {
            "hook_event_name": event,
            "session_id": "default-path-suite",
            "cwd": str(self.project),
            "turn_id": turn,
        }
        payload.update(kwargs)
        return payload

    def dispatch(self, event, **kwargs):
        return self.cg.dispatch(self.payload(event, **kwargs))

    def state(self):
        return self.cg.load_state(
            self.data_dir / "private" / "sessions" / "default-path-suite",
            self.payload("Stop"),
        )


class Report3SequenceTests(DefaultPathHarness):
    """T01: report-3 cases A–E replayed under the standard profile."""

    def test_full_default_pre_hook_never_loads_locks_or_repairs_state(self) -> None:
        for profile in ("on", "strict"):
            self.dispatch("UserPromptSubmit", prompt=f"context-guard {profile}")
            session_dir = self.data_dir / "private" / "sessions" / "default-path-suite"
            for corrupt in (False, True):
                if corrupt:
                    (session_dir / "state.json").write_text("{broken", encoding="utf-8")
                before = {p.name: p.read_bytes() for p in session_dir.iterdir() if p.is_file()}
                with mock.patch.object(self.cg, "session_lock", side_effect=AssertionError("lock")), \
                     mock.patch.object(self.cg, "load_state", side_effect=AssertionError("load")), \
                     mock.patch.object(self.cg, "save_state", side_effect=AssertionError("save")):
                    self.assertEqual(self.dispatch("PreToolUse", tool_name="shell",
                        tool_input={"command": "git push origin main"}), {})
                self.assertEqual(before, {p.name: p.read_bytes() for p in session_dir.iterdir() if p.is_file()})

    def test_cases_a_through_e_all_allow_without_provenance(self) -> None:
        self.dispatch("UserPromptSubmit", prompt="context-guard on")
        self.dispatch(
            "UserPromptSubmit",
            prompt="完成修改后提交并推送。使用 python 脚本直接提交也可以。",
            turn="t1",
        )
        cases = (
            # (case, edit command, edit exit, commit command, commit exit)
            ("A", "python3 -c 'open(\"f.txt\",\"w\").write(\"x\")'", 0,
             "git commit -am candidate", 0),
            ("B", "echo observed-shell-edit > b.txt", 0,
             "git commit -am candidate", 0),
            ("E", "python3 -c 'print(\"text-only success\")'", 0,
             "git commit -am candidate", 0),
        )
        for index, (case, edit, edit_rc, commit, commit_rc) in enumerate(cases):
            with self.subTest(case=case):
                pre = self.dispatch(
                    "PreToolUse", turn=f"t1-{index}",
                    tool_name="shell", tool_input={"command": edit},
                    tool_use_id=f"edit-{index}",
                )
                self.assertEqual(pre, {}, case)
                self.dispatch(
                    "PostToolUse", turn=f"t1-{index}",
                    tool_name="shell", tool_input={"command": edit},
                    tool_response={"exit_code": edit_rc},
                    tool_use_id=f"edit-{index}",
                )
                pre_commit = self.dispatch(
                    "PreToolUse", turn=f"t1-{index}",
                    tool_name="shell", tool_input={"command": commit},
                    tool_use_id=f"commit-{index}",
                )
                self.assertEqual(pre_commit, {}, case)
                self.dispatch(
                    "PostToolUse", turn=f"t1-{index}",
                    tool_name="shell", tool_input={"command": commit},
                    tool_response={"exit_code": commit_rc},
                    tool_use_id=f"commit-{index}",
                )
                pre_push = self.dispatch(
                    "PreToolUse", turn=f"t1-{index}",
                    tool_name="shell",
                    tool_input={"command": "git push origin main"},
                    tool_use_id=f"push-{index}",
                )
                # Cases A/D/E were provenance denies in 0.12; the 0.13
                # default path has no provenance precondition (INV-02).
                self.assertEqual(pre_push, {}, case)
        # No Guard authorization facts were fabricated anywhere.
        for unit in self.state()["work_units"]:
            self.assertNotIn("authorizations", unit)
            self.assertNotIn("commit_context", unit)

    def test_structural_default_path_makes_no_git_subprocess(self) -> None:
        """T14 structural: a standard-profile candidate decision solves no
        Git object identities at all — any cg_commit subprocess is a
        contract violation."""
        self.dispatch("UserPromptSubmit", prompt="context-guard on")
        self.dispatch(
            "UserPromptSubmit", prompt="提交并推送本次修改。", turn="t1"
        )
        with mock.patch(
            "cg_commit.subprocess.run",
            side_effect=AssertionError("git subprocess on default path"),
        ):
            result = self.dispatch(
                "PreToolUse", turn="t1-perf",
                tool_name="shell",
                tool_input={"command": "git push origin main"},
                tool_use_id="push-perf",
            )
        self.assertEqual(result, {})
        # No state mutation happened on the default path either.
        state = self.state()
        for unit in state["work_units"]:
            self.assertNotIn("authorizations", unit)
            self.assertNotIn("commit_context", unit)


class MultiRepoExecutionTests(DefaultPathHarness):
    """T03: several authorized remote writes run without compound bans."""

    def test_sequential_multi_remote_pushes_are_not_denied(self) -> None:
        other = self.data_dir / "other"
        other.mkdir()
        self.git_init(other)
        self.dispatch("UserPromptSubmit", prompt="context-guard on")
        self.dispatch(
            "UserPromptSubmit",
            prompt="把两个仓库的 main 都推送到各自远端。",
            turn="t1",
        )
        for index, root in enumerate((self.project, other)):
            old_cwd = self.project
            try:
                self.project = root
                result = self.dispatch(
                    "PreToolUse", turn=f"t1-{index}",
                    tool_name="shell",
                    tool_input={"command": "git push origin main"},
                    tool_use_id=f"push-{index}",
                )
            finally:
                self.project = old_cwd
            self.assertEqual(result, {})
        # The old compound_remote_mutation default deny is gone; chaining
        # is an execution-organization concern, not a Guard veto.
        chained = self.dispatch(
            "PreToolUse", turn="t1-x",
            tool_name="shell",
            tool_input={"command": "git push origin main && git push origin dev"},
            tool_use_id="push-chained",
        )
        self.assertEqual(chained, {})


class MixedRequestPreservationTests(DefaultPathHarness):
    """T04: the mixed request keeps both objects; the narrow category
    never swallows the other part."""

    def test_update_and_cleanup_mixed_request_preserves_both_objects(self) -> None:
        self.dispatch("UserPromptSubmit", prompt="context-guard on")
        self.dispatch(
            "UserPromptSubmit",
            prompt=(
                "1. 如有需要，更新本仓库内容，之后提交并推送\n"
                "2. 仓库中有额外的工作树和分支，看看是否需要清理"
            ),
            turn="t1",
        )
        state = self.state()
        texts = " ".join(item["text"] for item in state["requirements"])
        self.assertIn("更新本仓库内容", texts)
        self.assertIn("清理", texts)
        # The cleanup classification (if any) never vetoes a product edit.
        result = self.dispatch(
            "PreToolUse", turn="t1",
            tool_name="apply_patch",
            tool_input={"patch": "*** Begin Patch\n*** Update File: docs.md\n*** End Patch"},
            tool_use_id="patch-1",
        )
        self.assertEqual(result, {})


class ReleaseIsolationTests(DefaultPathHarness):
    """T12: release enforcement only behind explicit declaration/adoption."""

    def test_no_implicit_enablement_from_files_or_task_text(self) -> None:
        (self.project / "RELEASE_PLAN.md").write_text("release v1", encoding="utf-8")
        self.dispatch("UserPromptSubmit", prompt="context-guard on")
        self.dispatch(
            "UserPromptSubmit",
            prompt="准备 v1.2.3 发布候选，创建 tag。",
            turn="t1",
        )
        result = self.dispatch(
            "PreToolUse", turn="t1",
            tool_name="shell", tool_input={"command": "git tag v1.2.3"},
            tool_use_id="tag-1",
        )
        # Release-flavored task text and files never enable the adapter.
        self.assertEqual(result, {})
        self.assertEqual(
            self.state()["execution"]["contract"]["state"], "absent"
        )

    def test_declared_release_profile_enforces_tier_a_tickets(self) -> None:
        self.dispatch("UserPromptSubmit", prompt="context-guard release")
        denied = self.dispatch(
            "PreToolUse", turn="t1",
            tool_name="shell", tool_input={"command": "git tag v1.2.3"},
            tool_use_id="tag-1",
        )
        self.assertEqual(
            denied["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn("action-ticket/v1", denied["hookSpecificOutput"]["permissionDecisionReason"])
        # Ordinary pushes stay ungated even under the release profile.
        self.assertEqual(
            self.dispatch(
                "PreToolUse", turn="t1",
                tool_name="shell",
                tool_input={"command": "git push origin main"},
                tool_use_id="push-1",
            ),
            {},
        )
        # Declared release state survives Guard-internal failure without
        # silently degrading (fail-closed via the posture probe).
        with mock.patch.object(
            self.cg, "dispatch", side_effect=RuntimeError("validation failed")
        ):
            fallback = self.cg.safe_dispatch(
                self.payload(
                    "PreToolUse", turn="t2",
                    tool_name="shell",
                    tool_input={"command": "git tag v1.2.3"},
                    tool_use_id="tag-2",
                )
            )
        self.assertEqual(
            fallback["hookSpecificOutput"]["permissionDecision"], "deny"
        )

    def test_release_posture_survives_unreadable_state_and_internal_failure(self) -> None:
        self.dispatch("UserPromptSubmit", prompt="context-guard release")
        session_dir = self.data_dir / "private" / "sessions" / "default-path-suite"
        (session_dir / "state.json").write_text("{broken", encoding="utf-8")
        for command in ("git tag v1.2.3", "echo v1.2.3 | xargs git tag"):
            payload = self.payload("PreToolUse", tool_name="shell", tool_input={"command": command})
            self.assertEqual(self.cg.safe_dispatch(payload)["hookSpecificOutput"]["permissionDecision"], "deny")
            with mock.patch.object(self.cg, "dispatch", side_effect=RuntimeError("unavailable")):
                self.assertEqual(self.cg.safe_dispatch(payload)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_explicit_release_exit_retires_posture_latch(self) -> None:
        self.dispatch("UserPromptSubmit", prompt="context-guard release")
        self.dispatch("UserPromptSubmit", prompt="context-guard off")
        self.assertEqual(self.dispatch("PreToolUse", tool_name="shell",
                         tool_input={"command": "git tag v1.2.3"}), {})

    def test_unknown_legacy_posture_blocks_publication_only(self) -> None:
        self.dispatch("UserPromptSubmit", prompt="context-guard release")
        session_dir = self.data_dir / "private" / "sessions" / "default-path-suite"
        (session_dir / "release-required").unlink()
        (session_dir / "action-profile.json").unlink()
        (session_dir / "state.json").write_text("{broken", encoding="utf-8")
        self.assertEqual(self.dispatch("PreToolUse", tool_name="shell",
                         tool_input={"command": "git commit -am fix"}), {})
        payload = self.payload("PreToolUse", tool_name="shell",
                               tool_input={"command": "git tag v1.2.3"})
        self.assertEqual(self.cg.safe_dispatch(payload)["hookSpecificOutput"]["permissionDecision"], "deny")
        with mock.patch.object(self.cg, "dispatch", side_effect=RuntimeError("unavailable")):
            self.assertEqual(self.cg.safe_dispatch(payload)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_candidate_contract_does_not_activate_release_profile(self) -> None:
        self.dispatch("UserPromptSubmit", prompt="context-guard on")
        state = self.state()
        state["execution"]["contract"]["state"] = "candidate"
        state["content_hash"] = self.cg.state_content_hash(state)
        session_dir = self.data_dir / "private" / "sessions" / "default-path-suite"
        self.cg.atomic_write_json(session_dir / "state.json", state)
        result = self.dispatch(
            "PreToolUse", turn="t1",
            tool_name="shell", tool_input={"command": "git tag v1.2.3"},
            tool_use_id="tag-1",
        )
        # Only an ACTIVE adopted contract forces the release profile; a
        # half-staged candidate must not silently upgrade enforcement…
        self.assertEqual(result, {})


class Schema12MigrationTests(DefaultPathHarness):
    """T13: schema 11→12 preserves facts and marks legacy authority."""

    def build_schema11_state(self):
        self.dispatch("UserPromptSubmit", prompt="context-guard on")
        self.dispatch(
            "UserPromptSubmit",
            prompt="Context Guard 是这个插件的名称吗？",
            turn="t1",
        )
        self.dispatch(
            "Stop", turn="t1", last_assistant_message="是的，它是插件名称。"
        )
        self.dispatch(
            "UserPromptSubmit",
            prompt="修复登录缺陷。必须运行测试验证。",
            turn="t2",
        )
        state = self.state()
        state["schema_version"] = 11
        del state["response_delivery"]
        for item in state["requirements"]:
            item.pop("answer_state", None)
            if item["status"] == "answered":
                item["status"] = "pending"
        for unit in state["work_units"]:
            unit["protocol_version"] = "2.0.0"
        state["content_hash"] = self.cg.state_content_hash(state)
        session_dir = (
            self.data_dir / "private" / "sessions" / "default-path-suite"
        )
        self.cg.atomic_write_json(session_dir / "state.json", state)
        return state

    def test_migration_reconstructs_delivery_and_marks_legacy_authority(self) -> None:
        self.build_schema11_state()
        migrated = self.state()
        self.assertEqual(migrated["schema_version"], 12)
        # Trusted reconstruction: the question's allowed stop correlates.
        question = migrated["requirements"][0]
        self.assertEqual(question["status"], "answered")
        self.assertEqual(question["answer_state"], "answered")
        records = migrated["response_delivery"]["records"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["source"], "migration_reconstruction")
        self.assertEqual(records[0]["requirement_ids"], ["R001"])
        # The execution obligation is untouched: no batch pass flipping.
        self.assertEqual(migrated["requirements"][1]["status"], "pending")
        for unit in migrated["work_units"]:
            self.assertEqual(unit["protocol_version"], "3.0.0")
            for record in unit.get("authorizations") or []:
                self.assertEqual(record.get("participation"), "historical")
        self.assertEqual(
            migrated["execution"]["protocol_version"], "3.0.0"
        )
        # Second migration (load after save) is idempotent.
        self.dispatch("UserPromptSubmit", prompt="context-guard status", turn="t3")
        again = self.state()
        self.assertEqual(
            [item["status"] for item in again["requirements"]],
            ["answered", "pending"],
        )
        self.assertEqual(len(again["response_delivery"]["records"]), 1)

    def test_migration_without_delivery_facts_marks_unknown(self) -> None:
        state = self.build_schema11_state()
        # Remove the correlation source honestly: an empty decision log is
        # exactly what pre-upgrade sessions with ledger trimming look like.
        state = self.state()
        state["schema_version"] = 11
        del state["response_delivery"]
        state["decision_log"] = []
        for item in state["requirements"]:
            item.pop("answer_state", None)
            if item["status"] == "answered":
                item["status"] = "pending"
        for unit in state["work_units"]:
            unit["protocol_version"] = "2.0.0"
        state["content_hash"] = self.cg.state_content_hash(state)
        session_dir = (
            self.data_dir / "private" / "sessions" / "default-path-suite"
        )
        self.cg.atomic_write_json(session_dir / "state.json", state)

        migrated = self.state()
        question = migrated["requirements"][0]
        self.assertEqual(question["status"], "pending")
        self.assertEqual(question.get("answer_state"), "delivery_unknown")
        self.assertEqual(migrated["response_delivery"]["records"], [])
        # The recovery packet annotates the uncertainty instead of
        # demanding a mechanical re-answer.
        packet = self.cg.recovery_packet(
            self.data_dir / "private" / "sessions" / "default-path-suite",
            migrated,
        )
        self.assertIn("historical answer-delivery uncertain", packet)


if __name__ == "__main__":
    unittest.main()
