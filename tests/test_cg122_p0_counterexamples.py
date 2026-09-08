#!/usr/bin/env python3
"""Context Guard 0.12.2 P0 counterexamples (frozen plan 1.0, sections 2/3/6).

Revision r2 (coordinator review repairs; same baseline 5dcbcf27…): explicit
owned-path commit authorizations, causal Pre/real-exec/Post hook pairs that
share ``tool_use_id``/``turn_id`` and execute exactly the payload command,
matching wait/stop conditions with separately verified release facts, a
frozen synthetic schema-10 fixture (digest-pinned) for the 10→11 migration
oracle, a true staged+unstaged two-content case, existing-commit ambiguity
negatives with factual-reason assertions, and a POSIX invalid-byte path
fail-closed test. Revision r1 evidence (21 failures) is preserved unchanged
in the coordination record; this revision supersedes its oracle defects.

Synthetic product regressions for the known planning-round counterexamples
CG122-01/02/03/04/07 and the section-6.1 failure-family matrix. Each
counterexample asserts the DESIRED post-fix contract, so it fails on the
0.12.1 baseline with a contract assertion (never an import error or an
incidental exception). Guard tests already hold on the baseline and pin the
boundaries a P1/P2 fix must not break.

Family cells that stay pending and are deliberately NOT replayed here:

* Hook-payload event shapes (``functions.exec -> exec_command``): the frozen
  plan (section 4.2) requires the real-host probe before shapes are pinned;
  the Hook layer is unprobed this round, and synthetic dispatch in this
  module is NOT exact-host evidence.
* Native Windows path/separator identity and case-collision cells run on the
  platform that owns those identities. POSIX invalid-byte plumbing IS
  covered below (``git update-index`` plants an undecodable index path).
* MIGRATION current-schema (schema-11) persistence/round-trip and
  lossy-downgrade refusal need the schema-11 writer (P1) and an installed
  candidate; the r1 "already migrated" fixture was withdrawn as invalid
  schema-11 preservation evidence.

All fixtures are synthetic: no private paths, session ids, prompts, or
consumed-version bytes appear in this module.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

MODULE_PATH = SCRIPTS / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard_p0", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)

AWAIT_USER_STOP_MESSAGE = "需要你先在方案 A 与方案 B 之间做出选择。"
MODEL_WAIT_STOP_MESSAGE = "需要你先把运行模型更换为 5.3，更换完成后告诉我。"
NOT_VERIFIABLY_COMPLETED = "not verifiably completed"

# Factual-reason vocabulary for denial diagnostics (plan section 4.2: the
# runtime must distinguish scope mismatch, base/parent drift, and ambiguity
# instead of claiming the commit never completed). Until P1/P2 freeze a
# reason enum, the oracle accepts any of these factual markers and always
# rejects the generic non-completion claim; a frozen enum replaces this set.
SCOPE_REASON_MARKERS = ("scope", "extra", "beyond", "mismatch", "范围", "额外", "超出", "不符")
PARENT_REASON_MARKERS = ("parent", "base", "drift", "moved", "漂移", "基线", "移动")
AMBIGUITY_REASON_MARKERS = (
    "ambiguous", "multiple", "candidate", "unique", "歧义", "多个", "唯一", "候选",
)

# Frozen synthetic schema-10 fixture (valid awaiting_user state, WU0001,
# schema_version=10, synthetic cwd/session/prompt texts). The content_hash
# field is the exact schema-10 digest of these bytes; the fixture is
# validated as the SOURCE version before every migration run so the oracle
# keeps testing 10→11 after P1 ships schema 11.
SCHEMA10_PARKED_FIXTURE = (
    '{"acceptance_items": [{"evidence": [], "id": "A001", "prompt_id": "P0002", '
    '"status": "pending", "text": "请修复恢复模块。必须运行测试验证。", '
    '"verification_contract": {"mode": "legacy_fallback", "obligations": [], '
    '"protocol_version": "1.0.0", "reason": "no_deterministic_contract"}, '
    '"work_unit_id": "WU0001"}], "adapter_manifest": {"adapters": {"file_read": '
    '"2.0.0", "shell_read": "1.0.0", "thread_read": "2.0.0", "visual_read": '
    '"1.0.0"}, "version": "2.0.0"}, "agents": [], "asset_sequence": 0, '
    '"assets": [], "classifier_metadata": {"clause_derivation_version": '
    '"1.0.0", "fail_closed": true, "version": "3.2.1"}, "compactions": [], '
    '"completion_attempt": {"created_at": "2026-09-07T07:57:12.718103Z", '
    '"protocol_version": "3.0.0", "staged_at": null, "staged_control": null, '
    '"token_sha256": '
    '"1a7674eb4ee78df7e1ac439a93c3fa8e3c945784d4dec9fd8e3011738b2f1d62", '
    '"turn_id": "t2"}, "completion_checkpoint": null, "content_hash": '
    '"1498967e325e71c21937bf5aea6e55d099fdd77c0b1303c054cb938e9fd93e57", '
    '"continuation_attempts": 0, "decision_log": [{"actions": '
    '[{"authorization": "user_only", "category": "user_action", "owner": '
    '"user"}], "classifier_version": "3.2.1", "created_at": '
    '"2026-09-07T07:57:12.719616Z", "decision_source": "stop3_structured", '
    '"declared_disposition": null, "observed_outcome": "allow_user_handoff", '
    '"outcome": "silent_yield_preserve_pending", "prompt_sha256": '
    '"3173e16f3044b8d783992148e224a69a861d89707ecadd162a5355860f6195c8", '
    '"protocol_version": "3.0.0", "reason_codes": '
    '["remaining_action_owned_by_user", "protocol_waiting_boundary"], '
    '"reply_sha256": '
    '"e8fe9703d212c16eadad4d00c98fba59d3d6fce8addfe640acf906c085762619", '
    '"turn_id": "t3"}], "evidence": [], "evidence_sequence": 0, "execution": '
    '{"action_tickets": [], "contract": {"adoption": null, '
    '"authorization_candidates": [], "canonical_sha256": null, "contract_id": '
    'null, "gates": [], "phases": [], "revision": 0, "state": "absent", '
    '"supersedes_revision": null}, "coverage_manifest": {"adapters": [], '
    '"host_lock": null, "non_active_contract_policy": "completion_only", '
    '"pre_tool_output_policy": "allow_deny_only", "stale_conflicted_policy": '
    '"deny_covered_high_risk", "unclassified_high_risk_policy": '
    '"deny_when_active", "uncovered_write_surfaces": []}, "delegations": [], '
    '"denials": [], "drift": [], "instruction_sources": [], '
    '"protocol_version": "2.0.0", "unified_exec_sessions": []}, "integrity": '
    '{"backup_file": null, "issue": null, "recovered_at": null, "status": '
    '"ok"}, "mode": {"activation_reasons": ["explicit", "implementation", '
    '"hard_constraints"], "active": true, "complexity_score": 4, '
    '"manual_off": false, "profile": null}, "open_items": ["R001", "A001"], '
    '"pending": {"clear_token": null, "operations": [{"operation": '
    '"test_verify", "requestedSurface": "artifact", "state": "pending", '
    '"subjectId": null}], "recovery": null}, "prompt_journal": {"entries": '
    '[{"authority": "user", "id": "P0001", "origin": "human", "record_sha256": '
    '"6159918a29e44191cc42f6dccd5eeeecea65955fea89d24ce3aea099e959f8ac", '
    '"sha256": '
    '"15a456dd119b43c1f4d9917c0e76ff132d76cf4bc9b0047d2a6e1971712ed314"}, '
    '{"authority": "user", "id": "P0002", "origin": "human", "record_sha256": '
    '"438d7d0011616190b7a44d0914db765be673af114183d1910878c2c1faf72465", '
    '"sha256": '
    '"3173e16f3044b8d783992148e224a69a861d89707ecadd162a5355860f6195c8"}], '
    '"version": 1}, "prompts": [{"actor_id": null, "authority": "user", '
    '"chars": 16, "created_at": "2026-09-07T07:57:12.714624Z", "file": '
    '"prompts/P0001.json", "id": "P0001", "origin": "human", "record_sha256": '
    '"6159918a29e44191cc42f6dccd5eeeecea65955fea89d24ce3aea099e959f8ac", '
    '"sha256": '
    '"15a456dd119b43c1f4d9917c0e76ff132d76cf4bc9b0047d2a6e1971712ed314", '
    '"unicode_repairs": 0}, {"actor_id": null, "authority": "user", "chars": '
    '17, "created_at": "2026-09-07T07:57:12.716425Z", "file": '
    '"prompts/P0002.json", "id": "P0002", "origin": "human", "record_sha256": '
    '"438d7d0011616190b7a44d0914db765be673af114183d1910878c2c1faf72465", '
    '"sha256": '
    '"3173e16f3044b8d783992148e224a69a861d89707ecadd162a5355860f6195c8", '
    '"unicode_repairs": 0}], "proof_sequence": 0, "proofs": [], '
    '"requirements": [{"clause_metadata": {"clauses": [{"clause": "请修复恢复'
    '模块", "operation": "unspecified", "requestedSurface": "artifact", '
    '"subjectId": []}, {"clause": "必须运行测试验证", "operation": '
    '"test_verify", "requestedSurface": "artifact", "subjectId": []}], '
    '"version": "1.0.0"}, "evidence": [], "id": "R001", "operation": '
    '"unspecified", "prompt_id": "P0002", "requestedSurface": ["artifact"], '
    '"sha256": '
    '"3173e16f3044b8d783992148e224a69a861d89707ecadd162a5355860f6195c8", '
    '"status": "pending", "subjectId": [], "text": "请修复恢复模块。必须运行'
    '测试验证。", "verification_contract": {"mode": "legacy_fallback", '
    '"obligations": [], "protocol_version": "1.0.0", "reason": '
    '"no_deterministic_contract"}, "work_unit_id": "WU0001"}], '
    '"schema_version": 10, "session": {"asset_reconciliation": '
    '{"pending_prompt_ids": ["P0001", "P0002"], "post_tool_attempted_prompt_ids": '
    '[]}, "created_at": "2026-09-07T07:57:12.714285Z", "cwd": '
    '"/synthetic/cg122-p0/project", "ended_at": null, "id": "probe", "model": '
    'null, "permission_mode": null, "transcript_path": null, "updated_at": '
    '"2026-09-07T07:57:12.719640Z"}, "supersedes": [], "work_state": '
    '{"active_work_unit_id": "WU0001", "plan_snapshot": null, '
    '"unit_activity_seq": 1}, "work_unit_sequence": 1, "work_units": '
    '[{"closed_at": "2026-09-07T07:57:12.719601Z", "created_at": '
    '"2026-09-07T07:57:12.716968Z", "id": "WU0001", "kind": "implementation", '
    '"last_active_seq": 1, "parent_id": null, "prompt_id": "P0002", '
    '"protocol_version": "2.0.0", "scope_sha256": '
    '"e807789837c14c4d29b464e9e718170c689fc27a929684034a27cf151d2ce5b1", '
    '"status": "awaiting_user"}]}'
)


class P0Harness(unittest.TestCase):
    """Temp-state harness dispatching hooks exactly like the host.

    Causal tool execution: :meth:`causal_command` issues ``PreToolUse``
    BEFORE the real command, executes exactly the payload command string in
    the project worktree, then issues ``PostToolUse`` with the SAME
    ``tool_use_id`` and ``turn_id``. Plain :meth:`write` performs a file
    change OUTSIDE any hook event and represents unattributed worktree dirt
    (never task work).
    """

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        environment = mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.root / "private")}
        )
        environment.start()
        self.addCleanup(environment.stop)
        self.addCleanup(self.temp.cleanup)
        self.turn_counter = 0
        subprocess.run(
            ["git", "init", "-q", str(self.project)], check=True, capture_output=True
        )
        # The session branch is part of the authorization identity: every
        # commit/push oracle in this module names `main`, so the sandbox
        # pins the unborn branch instead of inheriting the host's
        # init.defaultBranch (master on stock Windows, main on many POSIX
        # hosts). A host-default branch would bind a different push ref
        # than the statement and command spell, which is material drift.
        subprocess.run(
            ["git", "-C", str(self.project), "symbolic-ref", "HEAD",
             "refs/heads/main"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.project), "config", "user.name", "P0 Synthetic"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.project), "config", "user.email",
             "p0@example.invalid"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.project), "commit", "-q", "--allow-empty",
             "-m", "base"],
            check=True, capture_output=True,
        )

    def dispatch(self, event: str, session: str = "p0", turn_id: str | None = None,
                 tool_use_id: str | None = None, **extra: object) -> dict:
        if turn_id is None:
            self.turn_counter += 1
            turn_id = f"t{self.turn_counter}"
        if tool_use_id is None:
            tool_use_id = f"tool-{self.turn_counter}"
        payload = {
            "hook_event_name": event,
            "session_id": session,
            "cwd": str(self.project),
            "turn_id": turn_id,
            "tool_use_id": tool_use_id,
        }
        payload.update(extra)
        return cg.dispatch(payload)

    def prompt(self, text: str, session: str = "p0") -> dict:
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="p0token"):
            return self.dispatch("UserPromptSubmit", session=session, prompt=text)

    def activate(self, session: str = "p0") -> None:
        self.prompt("context-guard on", session=session)
        self.assertTrue(self.state(session)["mode"]["active"])

    def state(self, session: str = "p0") -> dict:
        path = self.root / "private" / "sessions" / session / "state.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def save_state(self, state: dict, session: str = "p0") -> None:
        state["content_hash"] = cg.state_content_hash(state)
        cg.save_state(self.root / "private" / "sessions" / session, state)

    def unit(self, state: dict, unit_id: str) -> dict:
        return next(
            item for item in state["work_units"] if item["id"] == unit_id
        )

    def park_awaiting_user(self, stop_message: str = AWAIT_USER_STOP_MESSAGE,
                           session: str = "p0",
                           expected_status: str = "awaiting_user") -> None:
        """Drive one real task into a parked waiting boundary."""
        self.prompt("请修复恢复模块。必须运行测试验证。", session=session)
        self.dispatch("Stop", session=session, last_assistant_message=stop_message)
        self.assertEqual(
            self.state(session)["work_units"][0]["status"], expected_status
        )

    def decision(self, command: str, session: str = "p0") -> tuple[str, str]:
        result = self.dispatch(
            "PreToolUse",
            session=session,
            tool_name="shell",
            tool_input={"command": command},
        )
        output = result.get("hookSpecificOutput")
        if not output:
            return "allow", ""
        return (
            str(output.get("permissionDecision")),
            str(output.get("permissionDecisionReason") or ""),
        )

    def causal_command(self, command: str, session: str = "p0") -> tuple[dict, int | None, dict | None]:
        """Pre -> exact real execution -> Post with shared tool/turn ids."""
        self.turn_counter += 1
        turn_id = f"t{self.turn_counter}"
        tool_use_id = f"exec-{self.turn_counter}"
        pre = self.dispatch(
            "PreToolUse", session=session, turn_id=turn_id, tool_use_id=tool_use_id,
            tool_name="shell", tool_input={"command": command},
        )
        pre_output = pre.get("hookSpecificOutput") or {}
        if str(pre_output.get("permissionDecision")) == "deny":
            return pre, None, None
        completed = subprocess.run(
            command, shell=True, cwd=str(self.project), capture_output=True, text=True
        )
        post = self.dispatch(
            "PostToolUse", session=session, turn_id=turn_id, tool_use_id=tool_use_id,
            tool_name="shell", tool_input={"command": command},
            tool_response={"exit_code": completed.returncode},
        )
        return pre, completed.returncode, post

    @staticmethod
    def shell_write_command(name: str, content: str) -> str:
        """Return one real, parser-visible file write for the host shell."""
        rendered = content.replace("\\n", "\n")
        if os.name == "nt":
            ps_name = "'" + name.replace("'", "''") + "'"
            encoded = base64.b64encode(rendered.encode("utf-8")).decode("ascii")
            # Set-Content stays on the runtime's recognized write-form
            # allowlist (local_source_effect), and -Encoding Byte emits
            # exactly the stated UTF-8 bytes: the PS5.1 text-encoding
            # default would prepend a BOM and silently change the frozen
            # blob identity relative to the unattributed writer and to
            # POSIX content bytes.
            return (
                'powershell.exe -NoLogo -NoProfile -NonInteractive -Command '
                f'"Set-Content -LiteralPath {ps_name} '
                f"-Value ([Byte[]][Convert]::FromBase64String('{encoded}')) "
                '-NoNewline -Encoding Byte"'
            )
        return f"printf %s {shlex.quote(rendered)} > {shlex.quote(name)}"

    @staticmethod
    def shell_join(args: list[str]) -> str:
        """Quote one argv vector for the shell that ``shell=True`` selects."""
        return subprocess.list2cmdline(args) if os.name == "nt" else shlex.join(args)

    def task_edit(self, name: str, content: str, session: str = "p0") -> None:
        """Attributable task work: change a file through a causal shell pair."""
        command = self.shell_write_command(name, content)
        _pre, exit_code, _post = self.causal_command(command, session=session)
        self.assertIsNotNone(exit_code, "task_edit write was denied")
        self.assertEqual(exit_code, 0)

    def git(self, *args: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.project), *args], check=True, capture_output=True
        )

    def git_out(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.project), *args], check=True,
            capture_output=True, text=True,
        ).stdout.strip()

    def write(self, name: str, content: str) -> None:
        """Unattributed worktree change OUTSIDE any hook event."""
        (self.project / name).write_text(content, encoding="utf-8")

    def authorize_commit_push(self, statement: str =
                              "提交并推送 origin 的 main 分支。",
                              session: str = "p0") -> None:
        self.prompt(statement, session=session)

    def frozen_scope_paths(self, session: str = "p0") -> list[str]:
        state = self.state(session)
        unit_id = state["work_state"]["active_work_unit_id"]
        unit = self.unit(state, unit_id)
        paths: list[str] = []
        for record in unit.get("authorizations") or []:
            if not isinstance(record, dict) or record.get("state") != "active":
                continue
            prepared = record.get("prepared_source")
            if isinstance(prepared, dict):
                paths.extend(
                    str(entry.get("path"))
                    for entry in prepared.get("entries") or []
                    if isinstance(entry, dict)
                )
        return paths

    def commit_and_post(self, args: list[str], session: str = "p0") -> None:
        """Causally execute one exact commit command (Pre -> git -> Post)."""
        command = self.shell_join(args)
        _pre, exit_code, _post = self.causal_command(command, session=session)
        self.assertIsNotNone(exit_code, f"commit denied: {command}")
        self.assertEqual(exit_code, 0, f"commit failed: {command}")

    def assert_factual_reason(self, reason: str, markers: tuple[str, ...]) -> None:
        """A typed factual diagnostic, rather than any nonempty sentence."""
        expected = {
            SCOPE_REASON_MARKERS: "commit_scope_mismatch",
            PARENT_REASON_MARKERS: "commit_base_drift",
            AMBIGUITY_REASON_MARKERS: "commit_candidates_ambiguous",
        }[markers]
        self.assertTrue(reason.startswith(expected + ":"), reason)

    def prepare_owned_change(self, session: str = "p0") -> None:
        """Track owned.txt in the base commit, then change it as task work."""
        self.write("owned.txt", "v1\n")
        self.git("add", "owned.txt")
        self.git("commit", "-q", "-m", "track owned")
        self.prompt("请修复 owned.txt 并验证结果。", session=session)
        self.task_edit("owned.txt", "v2\\n", session=session)


class ContinuityCounterexampleTests(P0Harness):
    """CG122-01 + CONTINUITY family (plan sections 2.2, 3.1, 6.1).

    Failure condition on the 0.12.1 baseline: ``append_work_unit`` turns the
    active unit into ``historical_unresolved`` on ANY non-control,
    non-resume prompt, so an ordinary supplement opens a sibling root and
    the original constraints exit the current completion scope
    (``checkpoint_scope_item_ids`` keeps only active-descendant items).
    """

    def test_supplement_keeps_unit_id_and_completion_scope(self) -> None:
        """[CG122-01 counterexample] "只审查、不要修改" followed by the
        supplement "重点关注恢复逻辑" must stay ONE work unit: the unit id
        is retained, the unit stays active, and the original requirement
        remains inside the current completion scope."""
        self.activate()
        self.prompt("只审查 docs 恢复模块，不要修改任何文件。")
        self.assertEqual(self.state()["work_state"]["active_work_unit_id"], "WU0001")
        self.prompt("重点关注恢复逻辑的异常分支。")
        state = self.state()
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0001")
        self.assertEqual(self.unit(state, "WU0001")["status"], "active")
        scoped, _ancestors = cg.checkpoint_scope_item_ids(state)
        requirement_ids = {
            item["id"] for item in state["requirements"]
        }
        self.assertIn("R001", requirement_ids & scoped)

    def test_explicit_topic_switch_still_creates_isolated_sibling(self) -> None:
        """[CONTINUITY guard] An explicit switch to an independent task must
        keep sibling-root isolation: the old unit is isolated and the new
        unit is active. This pins the boundary so the CG122-01 fix does not
        collapse explicit switches into the original unit."""
        self.activate()
        self.prompt("请修复构建脚本的编码问题。必须运行测试验证。")
        self.prompt("切换到独立任务：请整理文档目录的索引。")
        state = self.state()
        self.assertEqual(self.unit(state, "WU0001")["status"],
                         "historical_unresolved")
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0002")
        self.assertIsNone(self.unit(state, "WU0002")["parent_id"])

    def test_old_remote_authorization_not_extended_to_new_task(self) -> None:
        """[CONTINUITY guard] A push authorization recorded in task A must
        not authorize a push issued inside a different, later task (plan
        section 3.1: sibling units never inherit remote-write authority)."""
        self.activate()
        self.prepare_owned_change()
        self.authorize_commit_push()
        self.prompt("切换到独立任务：请整理文档目录的索引。")
        decision, _reason = self.decision("git push origin main")
        self.assertEqual(decision, "deny")


class WaitCounterexampleTests(P0Harness):
    """CG122-02 + WAIT family (plan sections 2.2, 3.2, 6.1).

    Failure condition on the 0.12.1 baseline: ``append_work_unit`` treats
    the unit's ``awaiting_user`` status as "the next prompt is the answer",
    so progress questions, explicit topic switches, negated replies, and
    quoted/tool text all reactivate the parked unit; and no independent
    wait-condition record exists, so a valid release leaves no auditable
    condition id, owner, raise source, release source, or release type.

    The release test uses a MATCHING pause condition imposed by the ROOT
    USER through normal prompt capture, and the release wording matches
    that exact condition; the model-replacement confirmation is
    user-confirmation evidence, never model-detection proof. The A/B
    answer scenario keeps its own separate guard with the assistant's
    honest raise kind.
    """

    def test_progress_question_does_not_reactivate_parked_unit(self) -> None:
        """[CG122-02 counterexample] A progress question during a user wait
        must keep the unit parked (plan section 3.2: waiting tasks may answer
        status questions and remain waiting)."""
        self.activate()
        self.park_awaiting_user()
        self.prompt("现在整体进度如何？")
        state = self.state()
        self.assertEqual(self.unit(state, "WU0001")["status"], "awaiting_user")

    def test_explicit_switch_during_wait_parks_old_and_opens_new(self) -> None:
        """[CG122-02 counterexample] An explicit switch to an independent
        task during a user wait must leave the old unit waiting and open a
        new sibling unit; it must not silently resume the parked unit."""
        self.activate()
        self.park_awaiting_user()
        self.prompt("另一件独立事项：请检查文档拼写。")
        state = self.state()
        self.assertEqual(self.unit(state, "WU0001")["status"], "awaiting_user")
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0002")

    def test_unmet_condition_reply_does_not_release_model_wait(self) -> None:
        """[CG122-02 counterexample] With a model-replacement pause, "还没
        换好" reports the condition unmet and must not release the wait."""
        self.activate()
        self.park_awaiting_user(stop_message=MODEL_WAIT_STOP_MESSAGE)
        self.prompt("还没换好，先这样。")
        state = self.state()
        self.assertEqual(self.unit(state, "WU0001")["status"], "awaiting_user")

    def test_quoted_release_text_does_not_release_model_wait(self) -> None:
        """[WAIT family] Release wording inside quoted material is content,
        not a root-user release; the parked unit must stay waiting."""
        self.activate()
        self.park_awaiting_user(stop_message=MODEL_WAIT_STOP_MESSAGE)
        self.prompt('把"模型已换好，继续"这句写进公告文档。')
        state = self.state()
        self.assertEqual(self.unit(state, "WU0001")["status"], "awaiting_user")

    def test_valid_user_release_records_each_wait_fact(self) -> None:
        """[CG122-02 counterexample] The ROOT USER imposes the matching
        one-shot pause and the persistent restriction through normal prompt
        capture; a later matching root confirmation releases exactly that
        condition, and the release is recorded as an independent
        wait-condition fact. Owner, raise source, release source, and
        release kind are verified separately; surviving business
        requirements and the persistent restriction are verified separately
        from the condition. The confirmation is user-confirmation evidence,
        never model-detection proof."""
        self.activate()
        self.prompt("任务约束：在整个任务期间不要修改 docs 目录。")
        self.prompt("请修复恢复模块。在我确认模型更换完成前，本任务保持等待。必须运行测试验证。")
        state = self.state()
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0001")
        waiting = [
            item for item in state.get("wait_conditions", [])
            if isinstance(item, dict) and item.get("status") == "waiting"
        ]
        self.assertEqual(len(waiting), 1, "the root pause must capture one condition")
        self.assertEqual(str(waiting[0].get("raised_by_kind")), "root_user")
        self.assertEqual(str(waiting[0].get("raised_by_source")), "P0003")
        self.dispatch(
            "Stop",
            last_assistant_message="已按要求暂停，等待你确认模型更换完成后再继续。",
        )
        self.assertEqual(
            self.state()["work_units"][0]["status"], "awaiting_user"
        )
        still_waiting = [
            item for item in self.state().get("wait_conditions", [])
            if isinstance(item, dict) and item.get("status") == "waiting"
        ]
        self.assertEqual(len(still_waiting), 1,
                         "the handoff must not duplicate the root pause")
        self.prompt("模型已换好，继续。")
        state = self.state()
        self.assertEqual(self.unit(state, "WU0001")["status"], "active")
        conditions = state.get("wait_conditions")
        self.assertIsInstance(conditions, list, "wait-condition records missing")
        owned = [
            item for item in conditions
            if isinstance(item, dict)
            and str(item.get("owner_work_unit_id", "")) == "WU0001"
        ]
        self.assertEqual(len(owned), 1, "exactly one condition for WU0001")
        record = owned[0]
        self.assertTrue(record.get("condition_id"), "condition id missing")
        self.assertEqual(
            str(record.get("raised_by_kind", "")), "root_user",
            "raise source kind must be the root user",
        )
        self.assertEqual(
            str(record.get("raised_by_source", "")), "P0003",
            "raise source must be the prompt that imposed the pause",
        )
        self.assertIn(
            str(record.get("status", "")).lower(),
            {"released", "resolved", "closed"},
            "released condition must be marked released",
        )
        release_kind = str(record.get("released_by_kind", "")).lower()
        self.assertIn(
            release_kind, {"root_user_confirmation", "user_confirmation"},
            "release kind must be a root-user confirmation, not model detection",
        )
        self.assertNotIn("model", release_kind)
        self.assertEqual(
            str(record.get("released_by_source", "")), "P0004",
            "release source must reference the actual release prompt",
        )
        statuses = {
            item["id"]: item["status"] for item in state["requirements"]
        }
        restriction_ids = [
            item["id"] for item in state["requirements"]
            if "不要修改 docs" in str(item.get("text", ""))
        ]
        self.assertTrue(restriction_ids, "persistent restriction must be captured")
        for requirement_id in restriction_ids:
            self.assertEqual(statuses.get(requirement_id), "pending",
                             "persistent restriction must survive the release")
        business_ids = [
            item["id"] for item in state["requirements"]
            if "修复恢复模块" in str(item.get("text", ""))
        ]
        for requirement_id in business_ids:
            self.assertEqual(statuses.get(requirement_id), "pending",
                             "business requirement must survive the release")

    def test_answer_to_parked_question_still_reopens_same_unit(self) -> None:
        """[WAIT guard] A genuine answer to the parked A/B question keeps the
        same unit id and reactivates it (plan section 3.1: supplementary
        answers preserve the original requirement)."""
        self.activate()
        self.park_awaiting_user()
        self.prompt("选择方案 B。必须运行测试验证。")
        state = self.state()
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0001")
        self.assertEqual(self.unit(state, "WU0001")["status"], "active")


class SupersessionCounterexampleTests(P0Harness):
    """CG122-07 + SUPERSESSION family (plan sections 2.2, 3.1, 6.1).

    Failure condition on the 0.12.1 baseline:
    ``has_positive_supersession_intent`` keys on control words
    (替代/取消/cancel/replace/...), so product descriptions and test
    instructions are treated as supersession statements; a test enumeration
    naming an existing requirement ID even supersedes that requirement, and
    description sentences raise the ambiguous-target clarification.
    """

    def seed_two_requirements(self) -> None:
        self.activate()
        self.prompt("请修复恢复模块。必须运行测试验证。")
        self.prompt("请修复提交模块。必须运行测试验证。")

    def test_product_description_does_not_raise_supersession_clarification(
        self,
    ) -> None:
        """[CG122-07 counterexample] The product description sentence
        "恢复包仍列出完成、被替代和历史要求" must not be parsed as a
        supersession attempt: no ambiguous-target clarification and no
        supersession record."""
        self.seed_two_requirements()
        result = self.prompt("恢复包仍列出完成、被替代和历史要求。请继续完善说明文档。")
        context = str(result.get("hookSpecificOutput", {}).get(
            "additionalContext", ""
        ))
        self.assertNotIn("Supersession target is ambiguous", context)
        state = self.state()
        self.assertEqual(state["supersedes"], [])

    def test_test_enumeration_does_not_supersede_named_requirement(self) -> None:
        """[CG122-07 counterexample] "测试应覆盖取消 R001 的情形" is a test
        instruction; R001 must stay active and no supersession record may be
        created."""
        self.seed_two_requirements()
        self.prompt("测试应覆盖取消 R001 的情形。")
        state = self.state()
        superseded_ids = [
            item["id"] for item in state["requirements"]
            if item["status"] == "superseded"
        ]
        self.assertEqual(superseded_ids, [])
        self.assertEqual(state["supersedes"], [])

    def test_english_test_instruction_does_not_supersede(self) -> None:
        """[CG122-07 counterexample] "Implement a regression test for cancel
        R001." is a test instruction, not a current-root supersession."""
        self.seed_two_requirements()
        self.prompt("Implement a regression test for cancel R001.")
        state = self.state()
        superseded_ids = [
            item["id"] for item in state["requirements"]
            if item["status"] == "superseded"
        ]
        self.assertEqual(superseded_ids, [])
        self.assertEqual(state["supersedes"], [])

    def test_explicit_cancellation_supersedes_exactly_the_named_target(
        self,
    ) -> None:
        """[SUPERSESSION guard] A real root-user correction with one unique
        target must still supersede exactly that requirement."""
        self.seed_two_requirements()
        self.prompt("取消 R001，改为只输出摘要。")
        state = self.state()
        self.assertEqual(
            [item["status"] for item in state["requirements"] if item["id"] == "R001"],
            ["superseded"],
        )
        self.assertEqual(len(state["supersedes"]), 1)

    def test_negated_cancellation_leaves_requirement_active(self) -> None:
        """[SUPERSESSION guard] "不要取消 R001" must neither supersede nor
        raise the ambiguous clarification."""
        self.seed_two_requirements()
        result = self.prompt("不要取消 R001，保持原要求。")
        context = str(result.get("hookSpecificOutput", {}).get(
            "additionalContext", ""
        ))
        state = self.state()
        self.assertEqual(
            [item["status"] for item in state["requirements"] if item["id"] == "R001"],
            ["pending"],
        )
        self.assertEqual(state["supersedes"], [])
        self.assertNotIn("Supersession target is ambiguous", context)

    def test_permission_boundary_correction_retry_is_not_supersession(self) -> None:
        """[CG122-07 native counterexample] A permission-boundary correction
        describes how to retry the same authorized calls. The noun modifier
        ``修正`` must not be treated as a request to replace a requirement."""
        self.seed_two_requirements()
        result = self.prompt(
            "继续同一个 CG_R4 原生验收工作单元。CG_R4_PERMISSION_RETRY："
            "上一轮第一条调用由宿主以 `.git/index.lock: Operation not permitted` 阻止，"
            "工具退出码为 128，且没有产生源文件、索引、HEAD 或远端 ref 变化。"
            "P0005/R004 已有的合成仓库授权、文件、目标、命令顺序和停止规则全部保持原样；"
            "本消息只允许对该三步序列进行一次宿主权限边界修正重试，"
            "不新增或扩大任何 Git 行为授权。按照 P0005 所列三步从第一条重新开始。"
        )
        context = str(result.get("hookSpecificOutput", {}).get(
            "additionalContext", ""
        ))
        state = self.state()
        self.assertEqual(state["supersedes"], [])
        self.assertNotIn("Supersession target is ambiguous", context)

    def test_correction_that_names_requirement_remains_supersession(self) -> None:
        """[SUPERSESSION guard] Contextual ``修正`` with one exact requirement
        target remains an authoritative correction."""
        self.seed_two_requirements()
        self.prompt("修正 R001：该要求现在只需要输出摘要。")
        state = self.state()
        self.assertEqual(
            [item["status"] for item in state["requirements"]
             if item["id"] == "R001"],
            ["superseded"],
        )
        self.assertEqual(state["supersedes"][-1]["old_id"], "R001")

    def test_correction_with_exact_target_before_verb_supersedes(self) -> None:
        """[SUPERSESSION grammar] A 将-object-修正 control act keeps the
        exact requirement target that appears before the verb."""
        self.seed_two_requirements()
        self.prompt("将 R001 修正为只输出摘要。")
        state = self.state()
        self.assertEqual(
            [item["status"] for item in state["requirements"]
             if item["id"] == "R001"],
            ["superseded"],
        )
        self.assertEqual(state["supersedes"][-1]["old_id"], "R001")

    def test_correction_with_bare_exact_target_before_verb_supersedes(self) -> None:
        """[SUPERSESSION grammar] An exact ID before 修正 is authoritative
        even when the optional 将/把 marker is omitted."""
        self.seed_two_requirements()
        self.prompt("R001 修正为只输出摘要。")
        state = self.state()
        self.assertEqual(state["supersedes"][-1]["old_id"], "R001")

    def test_correction_with_previous_target_before_verb_uses_latest(self) -> None:
        """[SUPERSESSION grammar] A qualified previous-requirement object
        before 修正 resolves through the existing unique-previous rule."""
        self.seed_two_requirements()
        self.prompt("将上一条要求修正为只输出摘要。")
        state = self.state()
        self.assertEqual(state["supersedes"][-1]["old_id"], "R002")

    def test_correction_plan_without_unique_target_clarifies(self) -> None:
        """[SUPERSESSION fail-closed] 修正计划 is a real control shape, but
        two live requirements make its target ambiguous."""
        self.seed_two_requirements()
        result = self.prompt("修正计划：只输出摘要。")
        context = str(result.get("hookSpecificOutput", {}).get(
            "additionalContext", ""
        ))
        self.assertEqual(self.state()["supersedes"], [])
        self.assertIn("Supersession target is ambiguous", context)

    def test_correction_current_requirement_without_unique_id_clarifies(
        self,
    ) -> None:
        """[SUPERSESSION fail-closed] A direct requirement-like object keeps
        an unresolvable correction visible instead of silently preserving it."""
        self.seed_two_requirements()
        result = self.prompt("修正当前要求：只输出摘要。")
        context = str(result.get("hookSpecificOutput", {}).get(
            "additionalContext", ""
        ))
        self.assertEqual(self.state()["supersedes"], [])
        self.assertIn("Supersession target is ambiguous", context)

    def test_negated_target_before_correction_is_not_supersession(self) -> None:
        """[SUPERSESSION authority] Negation applies to the complete
        target-before-verb correction phrase."""
        self.seed_two_requirements()
        result = self.prompt("不要将 R001 修正为只输出摘要。")
        context = str(result.get("hookSpecificOutput", {}).get(
            "additionalContext", ""
        ))
        self.assertEqual(self.state()["supersedes"], [])
        self.assertNotIn("Supersession target is ambiguous", context)

    def test_quoted_target_before_correction_is_not_authoritative(self) -> None:
        """[SUPERSESSION authority] A quoted target-before-verb example is
        content rather than root control speech."""
        self.seed_two_requirements()
        result = self.prompt('记录用户示例：“将 R001 修正为只输出摘要。”')
        context = str(result.get("hookSpecificOutput", {}).get(
            "additionalContext", ""
        ))
        self.assertEqual(self.state()["supersedes"], [])
        self.assertNotIn("Supersession target is ambiguous", context)

    def test_correction_test_instruction_is_not_authoritative(self) -> None:
        """[SUPERSESSION authority] A regression instruction that mentions
        the correction grammar does not alter the live requirement."""
        self.seed_two_requirements()
        result = self.prompt("测试应覆盖将 R001 修正为只输出摘要的场景。")
        context = str(result.get("hookSpecificOutput", {}).get(
            "additionalContext", ""
        ))
        self.assertEqual(self.state()["supersedes"], [])
        self.assertNotIn("Supersession target is ambiguous", context)

    def test_named_target_does_not_capture_operational_correction_object(
        self,
    ) -> None:
        """[SUPERSESSION grammar] A requirement ID elsewhere in the clause
        cannot turn a later permission-boundary noun modifier into the
        predicate that supersedes that requirement."""
        prompts = (
            "对 R001 进行权限边界修正重试。",
            "R001 仅进行权限边界修正重试。",
            "将 R001 保持不变仅进行权限边界修正重试。",
            "对上一条要求执行权限边界修正重试。",
            "将 R001 的权限边界修正重试重新执行一次。",
            "权限边界修正计划：只重试原三步。",
            "执行权限边界修正方案：只重试原三步。",
        )
        for text in prompts:
            with self.subTest(text=text):
                self.tearDown()
                self.setUp()
                self.seed_two_requirements()
                result = self.prompt(text)
                context = str(result.get("hookSpecificOutput", {}).get(
                    "additionalContext", ""
                ))
                self.assertEqual(self.state()["supersedes"], [])
                self.assertNotIn("Supersession target is ambiguous", context)

    def test_bounded_target_before_correction_predicates_remain_authoritative(
        self,
    ) -> None:
        """[SUPERSESSION grammar] Constraining the predicate gap preserves
        direct, modified and 进行一次 correction control acts."""
        prompts = (
            "将 R001 重新修正为只输出摘要。",
            "对 R001 进行修正：现在只输出摘要。",
            "R001 需要修正为只输出摘要。",
        )
        for text in prompts:
            with self.subTest(text=text):
                self.tearDown()
                self.setUp()
                self.seed_two_requirements()
                self.prompt(text)
                state = self.state()
                self.assertEqual(state["supersedes"][-1]["old_id"], "R001")

    def test_modified_direct_correction_without_unique_target_clarifies(
        self,
    ) -> None:
        """[SUPERSESSION fail-closed] Polite and temporal markers do not
        hide a direct but ambiguous correction control act."""
        self.seed_two_requirements()
        result = self.prompt("请立即修正计划：只输出摘要。")
        context = str(result.get("hookSpecificOutput", {}).get(
            "additionalContext", ""
        ))
        self.assertEqual(self.state()["supersedes"], [])
        self.assertIn("Supersession target is ambiguous", context)

    def test_direct_correction_punctuation_and_authority_matrix(self) -> None:
        """[SUPERSESSION grammar] Sentence and clause endings preserve a
        direct ambiguous control act, while the same target words inside an
        operational noun, negation, quotation or test frame stay inert."""
        cases = (
            ("请修正计划。", "clarify"),
            ("修正计划，只输出摘要。", "clarify"),
            ("修正要求，只输出摘要。", "clarify"),
            ("现在修正方案；只保留摘要。", "clarify"),
            ("修正需求\n只输出摘要。", "clarify"),
            ("请修正当前要求。", "clarify"),
            ("麻烦修正计划。", "clarify"),
            ("请你修正要求。", "clarify"),
            ("请帮我修正方案。", "clarify"),
            ("随后修正需求。", "clarify"),
            ("请修正 R001。", "R001"),
            ("将 R001 修正为摘要。", "R001"),
            ("权限边界修正计划。", "none"),
            ("请执行权限边界修正计划，只重试原三步。", "none"),
            ("R001 的权限边界修正计划：只重试原三步。", "none"),
            ("不要修正计划。", "none"),
            ("请不要修正计划。", "none"),
            ("麻烦执行权限边界修正计划。", "none"),
            ('记录用户示例：“请修正计划。”', "none"),
            ("测试应覆盖请修正计划的场景。", "none"),
        )
        for text, expected in cases:
            with self.subTest(text=text, expected=expected):
                self.tearDown()
                self.setUp()
                self.seed_two_requirements()
                result = self.prompt(text)
                context = str(result.get("hookSpecificOutput", {}).get(
                    "additionalContext", ""
                ))
                state = self.state()
                if expected == "R001":
                    self.assertEqual(state["supersedes"][-1]["old_id"], "R001")
                    self.assertNotIn("Supersession target is ambiguous", context)
                elif expected == "clarify":
                    self.assertEqual(state["supersedes"], [])
                    self.assertIn("Supersession target is ambiguous", context)
                else:
                    self.assertEqual(state["supersedes"], [])
                    self.assertNotIn("Supersession target is ambiguous", context)

    def test_quoted_cancellation_is_not_authoritative(self) -> None:
        """[SUPERSESSION guard] A cancellation inside a quoted span is
        stripped before authority parsing and must not supersede."""
        self.seed_two_requirements()
        self.prompt('记录用户示例："取消 R001，改为只输出摘要"。')
        state = self.state()
        self.assertEqual(
            [item["status"] for item in state["requirements"] if item["id"] == "R001"],
            ["pending"],
        )


class RecoveryCounterexampleTests(P0Harness):
    """CG122-03 + RECOVERY family (plan sections 2.2, 3.3, 6.1).

    Failure condition on the 0.12.1 baseline: ``recovery_packet`` renders
    every requirement/acceptance item regardless of status or applicability
    (``format_items`` has no status filter and no scope projection), so 100
    synthetic historical items push the current requirement out of the
    15,000-character budget; only the completion rule survives clipping.
    """

    HISTORY_MARKER = "历史项"

    HISTORY_FILLER = (
        "已被替代的旧任务条目，内容为占位说明文字，用于撑大恢复包体积的合成"
        "历史负载。该条目描述一个早已结束的修复轮次，其验证证据早已归档，"
        "不属于当前未完成集合，也不应作为当前完成检查的约束出现。"
        "补充说明：恢复投影应只保留当前适用范围，历史隔离项仅作有界说明。"
    )

    def build_state_with_history(self, current_text: str) -> tuple[Path, dict]:
        session_dir = self.root / "private" / "sessions" / "p0"
        self.activate()
        self.prompt("请保持当前修复任务直到验证完成。必须运行测试验证。")
        state = self.state()
        history: list[dict] = []
        for index in range(1, 101):
            history.append({
                "id": f"R9{index:03d}",
                "status": "pending",
                "text": f"{self.HISTORY_MARKER}{index}: {self.HISTORY_FILLER}",
                "work_unit_id": "WU0001",
                "evidence": [],
            })
        state["work_units"][0]["status"] = "historical_unresolved"
        state["work_units"].append({
            "id": "WU0002",
            "protocol_version": cg.WORK_UNIT_PROTOCOL_VERSION,
            "prompt_id": state["prompts"][-1]["id"],
            "parent_id": None,
            "kind": "general",
            "status": "active",
            "created_at": "2026-09-07T00:00:00Z",
            "closed_at": None,
            "last_active_seq": 2,
            "scope_sha256": "0" * 64,
        })
        for item in state["requirements"]:
            item["work_unit_id"] = "WU0001"
        state["work_state"]["active_work_unit_id"] = "WU0002"
        state["work_unit_sequence"] = 2
        state["work_state"]["unit_activity_seq"] = 2
        current = {
            "id": "R900",
            "status": "pending",
            "text": current_text,
            "work_unit_id": "WU0002",
            "evidence": [],
        }
        state["requirements"] = history + [current]
        state["requirements_sequence"] = 900
        self.save_state(state)
        return session_dir, state

    def test_historical_volume_cannot_displace_the_current_requirement(
        self,
    ) -> None:
        """[CG122-03 counterexample] 100 synthetic historical items must not
        push the current requirement out of the recovery packet; the packet
        must keep current information inside the budget."""
        marker = "CURRENT-UNIQUE-MARKER-7f3a 当前要求必须保留"
        session_dir, _state = self.build_state_with_history(
            "同步修复提交链投影。" + marker
        )
        packet = cg.recovery_packet(session_dir, self.state())
        self.assertIn(marker, packet)

    def test_bilingual_current_items_survive_historical_volume(self) -> None:
        """[RECOVERY family] The current-requirement survival contract holds
        for English current text over Chinese history."""
        english_marker = "ENGLISH-CURRENT-MARKER-91d0 keep this visible"
        session_dir, _state = self.build_state_with_history(
            f"同步修复提交链投影。{english_marker}"
        )
        packet = cg.recovery_packet(session_dir, self.state())
        self.assertIn(english_marker, packet)

    def test_completed_and_superseded_items_leave_current_sections(self) -> None:
        """[CG122-03 family] Completed, superseded, and isolated historical
        items must not be listed as current obligations in the recovery
        packet's requirement section (plan section 3.3)."""
        session_dir, state = self.build_state_with_history(
            "同步修复提交链投影。CURRENT-ONLY-MARKER-2c8e"
        )
        mutated = self.state()
        mutated["requirements"][0]["status"] = "pass"
        mutated["requirements"][1]["status"] = "superseded"
        self.save_state(mutated)
        packet = cg.recovery_packet(session_dir, mutated)
        self.assertNotIn("R9001 [pass]", packet)
        self.assertNotIn("R9002 [superseded]", packet)
        self.assertNotIn("R9001 [pending]", packet)

    def test_budget_overflow_still_keeps_rules_and_current_reason(self) -> None:
        """[RECOVERY family] When the packet exceeds the budget, the clip
        marker and the completion rule must survive; and the CURRENT
        requirement must not be the casualty of historical volume."""
        marker = "OVERFLOW-CURRENT-MARKER-5b7d"
        session_dir, _state = self.build_state_with_history(
            f"同步修复提交链投影。{marker}"
        )
        packet = cg.recovery_packet(session_dir, self.state())
        self.assertIn(cg.RECOVERY_COMPLETION_RULE, packet)
        self.assertIn(marker, packet)


class CommitChainCounterexampleTests(P0Harness):
    """CG122-04 + COMMIT/COMMIT-NEG/CHAIN families (plan sections 2.2,
    2.3, 4.1, 4.2, 6.1).

    Failure conditions on the 0.12.1 baseline: the authorization freezes the
    WHOLE dirty-tree projection (``prepared_source_identity`` covers staged,
    unstaged, and untracked paths, attributable or not), and
    ``advance_commit_transitions`` requires the produced commit's tree delta
    to equal that projection exactly; an unrelated file makes a legal,
    authorized commit unverifiable, unattributed dirt is silently frozen
    into scope, and every denial then claims the commit "has not verifiably
    completed" instead of naming the actual condition. The commit path here
    always runs as a causal Pre/exact-exec/Post pair with shared ids; the
    missing-result scenarios below are explicitly unpaired or unexecuted.
    """

    def test_explicit_owned_scope_survives_unrelated_untracked_file(
        self,
    ) -> None:
        """[CG122-04 counterexample] With an explicit root-user authorization
        naming owned.txt, an unrelated untracked other.txt stays outside the
        frozen scope: a commit of exactly owned.txt advances the expectation
        so the following push is allowed (plan section 4.1: the explicit
        root-user file set wins; the executor must not need a clean tree)."""
        self.activate()
        self.prepare_owned_change()
        self.write("other.txt", "unrelated\n")
        self.authorize_commit_push("提交 owned.txt 的修改并推送 origin main。")
        self.assertIn("owned.txt", self.frozen_scope_paths())
        self.commit_and_post(
            ["git", "commit", "-q", "-m", "update owned", "--", "owned.txt"]
        )
        decision, reason = self.decision("git push origin main")
        self.assertEqual((decision, reason), ("allow", ""))

    def test_unattributed_change_is_not_silently_frozen_into_scope(
        self,
    ) -> None:
        """[CG122-04 provenance guard] Without an explicit file list, the
        frozen scope may only contain uniquely attributable task changes
        (plan section 4.1); ghost.txt was written outside every hook event
        and must be excluded or asked about, never silently frozen. On the
        baseline the whole-tree projection includes it."""
        self.activate()
        self.prepare_owned_change()
        self.write("ghost.txt", "unattributed dirt\n")
        self.authorize_commit_push()
        scope = self.frozen_scope_paths()
        self.assertIn("owned.txt", scope)
        self.assertNotIn("ghost.txt", scope)

    def test_unpaired_missing_result_never_advances_expectation(self) -> None:
        """[COMMIT-NEG guard, missing-result scenario] A PostToolUse success
        with NO matching PreToolUse and no real commit object is an
        uncorrelated, missing-result call: it must never advance the
        expectation, and the push stays denied. Synthetic dispatch is not
        exact-host evidence; this pins only the missing-result outcome."""
        self.activate()
        self.prepare_owned_change()
        self.authorize_commit_push()
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": "git commit -q -m never ran"},
            tool_response={"exit_code": 0},
        )
        decision, reason = self.decision("git push origin main")
        self.assertEqual(decision, "deny")
        self.assertTrue(reason.startswith("commit_result_missing:"), reason)

    def test_forged_sha_text_never_advances_expectation(self) -> None:
        """[COMMIT-NEG guard, missing-result scenario] A tool response that
        merely displays a commit SHA (no causal Pre pairing, no verifiable
        commit correspondence) is not commit evidence; the expectation stays
        pending."""
        self.activate()
        self.prepare_owned_change()
        self.authorize_commit_push()
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": "git rev-parse HEAD"},
            tool_response={"exit_code": 0, "output": "a" * 40},
        )
        decision, _reason = self.decision("git push origin main")
        self.assertEqual(decision, "deny")

    def test_extra_object_beyond_explicit_scope_denies_with_factual_reason(
        self,
    ) -> None:
        """[CG122-04 counterexample] A commit that carries an extra object
        beyond the explicitly frozen owned.txt scope must be denied with a
        reason naming the scope mismatch, not the generic non-completion
        claim."""
        self.activate()
        self.prepare_owned_change()
        self.authorize_commit_push("提交 owned.txt 的修改并推送 origin main。")
        self.task_edit("extra.txt", "beyond scope\\n")
        self.git("add", "extra.txt")
        self.commit_and_post(["git", "commit", "-q", "-m", "owned plus extra"])
        decision, reason = self.decision("git push origin main")
        self.assertEqual(decision, "deny")
        self.assert_factual_reason(reason, SCOPE_REASON_MARKERS)

    def test_base_head_drift_denies_with_factual_reason(self) -> None:
        """[COMMIT-NEG counterexample] When another commit lands between the
        authorization and the authorized commit (parent drift), the push
        must be denied with a drift-specific reason, not the generic
        non-completion claim."""
        self.activate()
        self.prepare_owned_change()
        self.authorize_commit_push("提交 owned.txt 的修改并推送 origin main。")
        self.task_edit("parallel.txt", "parallel\\n")
        self.git("add", "parallel.txt")
        self.git("commit", "-q", "-m", "parallel head movement")
        self.commit_and_post(
            ["git", "commit", "-q", "-m", "update owned", "--", "owned.txt"]
        )
        decision, reason = self.decision("git push origin main")
        self.assertEqual(decision, "deny")
        self.assert_factual_reason(reason, PARENT_REASON_MARKERS)

    def test_existing_commit_reconciled_when_unique_and_corresponding(
        self,
    ) -> None:
        """[CG122-04/CHAIN counterexample] When exactly one existing commit
        verifiably corresponds to the current authorization (repository,
        parent, full frozen contents, current generation, trusted readback)
        but its completion event was NEVER observed (no Pre/Post hook pair),
        deterministic reconciliation must associate it so the following push
        is allowed (plan section 4.2; the recorded 0.12.0 incidents). The
        readback may stay internal; this oracle pins the observable
        outcome."""
        self.activate()
        self.prepare_owned_change()
        self.authorize_commit_push("提交 owned.txt 的修改并推送 origin main。")
        # The authorized commit runs with NO hook observation at all.
        self.git("commit", "-q", "-m", "update owned", "--", "owned.txt")
        decision, reason = self.decision("git push origin main")
        self.assertEqual((decision, reason), ("allow", ""))

    def test_existing_commit_ambiguity_denies_with_factual_reason(
        self,
    ) -> None:
        """[CHAIN counterexample] Two existing candidate commits with the
        same parent and the same frozen-scope delta are ambiguous; none may
        be auto-associated, and the denial must name the ambiguity rather
        than claim non-completion (plan section 4.2: only a UNIQUE candidate
        object may associate)."""
        self.activate()
        self.prepare_owned_change()
        self.authorize_commit_push("提交 owned.txt 的修改并推送 origin main。")
        base = self.git_out("rev-parse", "HEAD")
        self.git("checkout", "-q", "-b", "candidate-a")
        self.git("commit", "-q", "-m", "candidate a", "--", "owned.txt")
        candidate_a = self.git_out("rev-parse", "HEAD")
        self.git("checkout", "-q", "main")
        self.write("owned.txt", "v2\n")
        self.git("commit", "-q", "-m", "candidate b", "--", "owned.txt")
        candidate_b = self.git_out("rev-parse", "HEAD")
        # Fixture sanity: two distinct commits, identical parent and delta.
        self.assertNotEqual(candidate_a, candidate_b)
        self.assertEqual(self.git_out("rev-parse", f"{candidate_a}~1"), base)
        self.assertEqual(self.git_out("rev-parse", f"{candidate_b}~1"), base)
        self.assertEqual(self.git_out("rev-parse", f"{candidate_a}^{{tree}}"), self.git_out("rev-parse", f"{candidate_b}^{{tree}}"))
        decision, reason = self.decision("git push origin main")
        self.assertEqual(decision, "deny")
        self.assert_factual_reason(reason, AMBIGUITY_REASON_MARKERS)

    def test_cross_unit_replay_of_old_authorization_denied(self) -> None:
        """[COMMIT-NEG guard] An authorization recorded in an earlier work
        unit cannot be replayed to authorize a push issued from a later
        unit, even when the repository state still matches."""
        self.activate()
        self.prepare_owned_change()
        self.authorize_commit_push()
        self.prompt("切换到独立任务：请整理文档目录的索引。")
        decision, _reason = self.decision("git push origin main")
        self.assertEqual(decision, "deny")

    def test_staged_content_drift_beyond_frozen_blob_denies(self) -> None:
        """[COMMIT family counterexample] After owned.txt v2 was frozen, the
        executor stages and commits different content (v3): the committed
        blob differs from every frozen object, so the push must be denied
        with a reason naming the content mismatch, not non-completion."""
        self.activate()
        self.prepare_owned_change()
        self.authorize_commit_push("提交 owned.txt 的修改并推送 origin main。")
        self.task_edit("owned.txt", "v3-drifted\\n")
        self.git("add", "owned.txt")
        self.commit_and_post(["git", "commit", "-q", "-m", "commit drifted blob"])
        decision, reason = self.decision("git push origin main")
        self.assertEqual(decision, "deny")
        self.assert_factual_reason(reason, SCOPE_REASON_MARKERS)

    def test_staged_blob_committed_exactly_survives_unstaged_worktree_drift(
        self,
    ) -> None:
        """[COMMIT family counterexample] True two-content case: the staged
        candidate blob (v2) is frozen and committed EXACTLY, while a later,
        unstaged worktree edit (v3) exists. The exact authorized blob
        correspondence stays valid (plan section 4.1 freezes path/status/
        mode/blob of the prepared candidate; worktree drift beyond the
        frozen set does not retroactively invalidate the exact commit). On
        the baseline the projection overwrites the frozen blob with the
        unstaged one, so the exact commit can never advance."""
        self.activate()
        self.write("owned.txt", "v1\n")
        self.git("add", "owned.txt")
        self.git("commit", "-q", "-m", "track owned")
        self.write("owned.txt", "v2\n")
        self.git("add", "owned.txt")
        self.write("owned.txt", "v3-unstaged\n")
        index_blob = self.git_out("rev-parse", ":owned.txt")
        worktree_blob = self.git_out("hash-object", "owned.txt")
        self.assertNotEqual(index_blob, worktree_blob,
                            "fixture must hold two distinct contents")
        self.authorize_commit_push("提交已暂存的 owned.txt 修改并推送 origin main。")
        self.commit_and_post(["git", "commit", "-q", "-m", "commit staged blob"])
        committed_blob = self.git_out("rev-parse", "HEAD:owned.txt")
        self.assertEqual(committed_blob, index_blob,
                         "fixture must commit exactly the staged blob")
        decision, reason = self.decision("git push origin main")
        self.assertEqual((decision, reason), ("allow", ""))

    @unittest.skipIf(os.name == "nt", "POSIX newline filename fixture")
    def test_newline_path_identity_survives_the_commit_chain(self) -> None:
        """[COMMIT family counterexample] A path containing a newline is one
        exact Git path identity: the prepared projection and the commit
        delta must agree on its bytes (NUL-delimited plumbing), so the
        authorized commit advances and the push is allowed. The commit runs
        through shlex quoting so the newline stays inside one path token."""
        self.activate()
        self.write("owned.txt", "v1\n")
        self.git("add", "owned.txt")
        self.git("commit", "-q", "-m", "track owned")
        newline_name = "weird\nname.txt"
        (self.project / newline_name).write_text("v2\n", encoding="utf-8")
        self.git("add", newline_name)
        self.git("commit", "-q", "-m", "track weird")
        self.prompt("请修复该文件并验证结果。")
        self.task_edit(newline_name, "v3\\n")
        self.authorize_commit_push("提交并推送 origin 的 main 分支。")
        self.commit_and_post(
            ["git", "commit", "-q", "-m", "update weird", "--", newline_name]
        )
        decision, reason = self.decision("git push origin main")
        self.assertEqual((decision, reason), ("allow", ""))

    def test_non_ascii_path_keeps_exact_byte_identity(self) -> None:
        """[CG122-04 family counterexample] A non-ASCII path is one exact
        byte identity. On the baseline the projection reads exact bytes via
        NUL-delimited plumbing, but the commit-delta reader parses quoted
        ``diff-tree`` text, so non-ASCII paths come back as octal-escape
        look-alikes and the authorized commit can never advance; the legal
        push is denied with the generic not-completed reason (plan section
        4.1: reversible byte identity, no normalization)."""
        self.activate()
        self.write("owned.txt", "v1\n")
        self.git("add", "owned.txt")
        self.git("commit", "-q", "-m", "track owned")
        unicode_name = "説明書-说明-café.txt"
        (self.project / unicode_name).write_text("v2\n", encoding="utf-8")
        self.git("add", unicode_name)
        self.git("commit", "-q", "-m", "track unicode")
        self.prompt("请修复该文件并验证结果。")
        self.task_edit(unicode_name, "v3\\n")
        self.authorize_commit_push("提交并推送 origin 的 main 分支。")
        self.commit_and_post(
            ["git", "commit", "-q", "-m", "update unicode", "--", unicode_name]
        )
        decision, reason = self.decision("git push origin main")
        self.assertEqual((decision, reason), ("allow", ""))

    @unittest.skipIf(os.name == "nt", "POSIX invalid-byte path fixture")
    def test_invalid_utf8_path_fails_closed_deterministically(self) -> None:
        """[COMMIT family counterexample, POSIX plumbing] An index path with
        bytes that cannot be decoded losslessly must fail the prepared
        projection closed (plan section 4.1: explicit fail-closed, never a
        silent lossy replacement and never a crashed hook). On the baseline
        the strict text decoding of ``git ls-files``/``diff-index`` output
        lets a raw ``UnicodeDecodeError`` escape the runtime helper."""
        self.activate()
        blob = subprocess.run(
            ["git", "-C", str(self.project), "hash-object", "-w", "--stdin"],
            input="blob\n", check=True, capture_output=True, text=True,
        ).stdout.strip()
        raw_name = os.fsdecode(b"bad\xffname.txt")
        subprocess.run(
            ["git", "-C", str(self.project), "update-index", "--add",
             "--cacheinfo", f"100644,{blob},{raw_name}"],
            check=True, capture_output=True,
        )
        try:
            result = cg.prepared_source_identity(str(self.project))
            raised: BaseException | None = None
        except Exception as exc:  # noqa: BLE001 - the defect IS the escape
            result, raised = None, exc
        self.assertIsNone(
            raised,
            f"projection must fail closed, not raise {type(raised).__name__}",
        )
        self.assertIsNone(result, "undecodable path must reject the projection")


class MigrationCounterexampleTests(P0Harness):
    """MIGRATION family: schema 10 -> 11 wait-condition contract (plan
    sections 3.2, 4.3, 6.1).

    Failure condition on the 0.12.1 baseline: schema 10 records only the
    work-unit ``awaiting_user`` status; there is no wait-condition record,
    so no raise source, condition id, release source, or release type can be
    verified, and schema-10 states cannot express the deterministic
    ``migrated_unresolved`` condition required by plan section 4.3.

    The source fixture is a frozen synthetic valid schema-10 state (digest
    pinned in-module) validated as the source version before each run, so
    the oracle keeps exercising 10→11 after P1 ships schema 11. Current-
    schema persistence (round-trip, no re-derivation) and lossy-downgrade
    refusal need the schema-11 writer and are P1 scope, not old-source
    counterexamples.
    """

    EXPECTED_FIXTURE_SHA256 = "31f46de7a507219e347d938a418848df26d5be3fa26f7b9036cc5ee8e1e79429"

    def load_frozen_schema10_fixture(self) -> tuple[Path, dict]:
        fixture = json.loads(SCHEMA10_PARKED_FIXTURE)
        session_dir = self.root / "private" / "sessions" / "p0"
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "state.json").write_text(
            SCHEMA10_PARKED_FIXTURE, encoding="utf-8"
        )
        # The frozen bytes must validate as the SOURCE version first.
        cg.validate_state_integrity(fixture)
        self.assertEqual(fixture["schema_version"], 10)
        self.assertEqual(
            hashlib.sha256(SCHEMA10_PARKED_FIXTURE.encode("utf-8")).hexdigest(),
            self.EXPECTED_FIXTURE_SHA256,
        )
        return session_dir, fixture

    def migrated_conditions(self, loaded: dict) -> list[dict]:
        return [
            item for item in loaded.get("wait_conditions") or []
            if isinstance(item, dict)
            and str(item.get("owner_work_unit_id", "")) == "WU0001"
        ]

    def test_frozen_schema10_fixture_migrates_one_deterministic_condition(
        self,
    ) -> None:
        """[MIGRATION counterexample] A schema-10 ``awaiting_user`` unit must
        migrate deterministically into exactly ONE ``migrated_unresolved``
        wait condition owned by the original work-unit id, with ``waiting``
        status and an empty/null release source (restricted-nullable raise
        provenance per plan section 4.3)."""
        session_dir, _fixture = self.load_frozen_schema10_fixture()
        loaded = cg.load_state(session_dir, {"session_id": "p0"})
        migrated = self.migrated_conditions(loaded)
        self.assertEqual(len(migrated), 1, "exactly one migrated condition")
        record = migrated[0]
        self.assertEqual(str(record.get("kind", "")), "migrated_unresolved")
        self.assertEqual(str(record.get("status", "")), "waiting")
        self.assertTrue(record.get("condition_id"), "condition id missing")
        self.assertFalse(
            record.get("released_by_source"),
            "first load must not invent a release source",
        )

    def test_repeated_migration_is_deterministic_and_non_duplicative(
        self,
    ) -> None:
        """[MIGRATION counterexample] Re-loading the same schema-10 state
        must derive the same deterministic condition id and never append a
        duplicate condition."""
        session_dir, _fixture = self.load_frozen_schema10_fixture()
        first = cg.load_state(session_dir, {"session_id": "p0"})
        second = cg.load_state(session_dir, {"session_id": "p0"})
        first_records = self.migrated_conditions(first)
        second_records = self.migrated_conditions(second)
        self.assertTrue(first_records, "migration must derive the condition")
        first_ids = sorted(str(item.get("condition_id")) for item in first_records)
        second_ids = sorted(str(item.get("condition_id")) for item in second_records)
        self.assertEqual(first_ids, second_ids)
        self.assertEqual(len(second_ids), len(set(second_ids)))


class CompletionGateGuardTests(P0Harness):
    """COMPLETION family anchors (plan section 6.1).

    These already hold on the 0.12.1 baseline; they pin the completion gate
    so the P1 state/recovery refactor cannot silently weaken it. The setup
    mirrors the established deterministic single-read task: one verifiable
    requirement and no acceptance clauses.
    """

    def single_read_task_without_evidence(self) -> None:
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="p0token"):
            self.dispatch(
                "UserPromptSubmit",
                prompt=f"$context-guard\n请先核对 {target} 后修复文档。",
            )

    def test_whole_completion_claim_without_evidence_is_blocked_once(
        self,
    ) -> None:
        """[COMPLETION guard] A whole-completion reply with a pending
        deterministic requirement and no captured evidence yields exactly one
        bounded Stop correction and leaves the unit active."""
        self.single_read_task_without_evidence()
        result = self.dispatch(
            "Stop", last_assistant_message="任务已经全部完成。"
        )
        self.assertEqual(result.get("decision"), "block")
        self.assertLessEqual(len(str(result.get("reason", ""))), 240)
        self.assertNotRegex(str(result.get("reason", "")), r"\b(?:WU|R|A|E)\d{3,}\b")
        self.assertEqual(self.state()["work_units"][0]["status"], "active")

    def test_second_correction_is_silent_and_preserves_pending(self) -> None:
        """[COMPLETION guard] The per-turn interruption budget is one: a
        second whole-completion claim in the same turn ends silently with
        pending work preserved."""
        self.single_read_task_without_evidence()
        self.dispatch("Stop", last_assistant_message="任务已经全部完成。")
        second = self.dispatch(
            "Stop", last_assistant_message="任务已经全部完成。"
        )
        self.assertEqual(second, {})
        state = self.state()
        self.assertEqual(state["work_units"][0]["status"], "active")


if __name__ == "__main__":
    unittest.main()
