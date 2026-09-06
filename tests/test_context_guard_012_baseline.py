#!/usr/bin/env python3
"""Context Guard 0.12 Phase 1 baseline tests (sanitized, table-driven).

These tests pin the 0.11.x baseline described by the frozen 0.12 evolution
plan and its Phase 0 private incidents (CGI-2026-013..021, families UX-01
through UX-09). They contain only synthetic data: no real thread ids, no
prompts or transcripts from any private session, no private paths, and no
credentials.

Expectation protocol
--------------------

* Tests asserting the plan's 0.12 target behavior that the 0.11.x baseline
  is known to fail are marked ``@unittest.expectedFailure``. They document
  the defect; an "unexpected success" on this baseline means the baseline
  drifted and fails the run.
* Tests without the marker must pass on this baseline. A failure there is a
  test-infrastructure or regression problem, never an accepted defect.

This file intentionally implements no product fixes: no Stop-regex changes,
no keyword additions, no classifier edits (Phase 2+ scope).
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard_012_baseline", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)

# Row-level fixture results, reported separately from the unittest
# decorator expectedFailures in the __main__ summary.
ROW_LEVEL_REPORT: list[dict] = []

# Synthetic uuid: must never be a real Codex session id and must not match
# the repository audit pattern for real-looking session uuids.
THREAD_ID = "aa11bb33-c0de-4d5e-8f90-1234567890ab"
THREAD_URI = f"codex://threads/{THREAD_ID}"

# Prompts below avoid full-scope vocabulary (全部/所有/完整/…) so the enforced
# subject-readback contract is constructible without a scope cardinality.
ACTIVATING_PROMPT = "请修复模块、修复文档、修复测试三件事。必须逐项落实。必须运行测试验证。"
THREAD_PROMPT = (
    f"请先读取 {THREAD_URI} 中的决定,再修复对应脚本。必须逐条落实其中决定。"
    "必须运行测试验证。必须更新 README 文件。"
)
EXTERNAL_WAIT_REPLY = "目录发布已完成,当前等待外部审核。"


class BaselineTestCase(unittest.TestCase):
    """Shared temp-state harness; dispatches hooks exactly like the host."""

    ux_family: ClassVar[str | None] = None

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.environment = mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.root / "private")}
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def dispatch(
        self, event: str, turn: str = "turn-1", session: str = "baseline", **extra: object
    ) -> dict:
        payload = {
            "hook_event_name": event,
            "session_id": session,
            "cwd": str(self.project),
            "turn_id": turn,
        }
        payload.update(extra)
        return cg.dispatch(payload)

    def state(self, session: str = "baseline") -> dict:
        path = self.root / "private" / "sessions" / session / "state.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def prompt_activated(self, text: str) -> dict:
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="baseline"):
            self.dispatch("UserPromptSubmit", prompt=text)
        state = self.state()
        self.assertTrue(state["mode"]["active"], "prompt failed to activate guard")
        self.assertTrue(
            state.get("completion_attempt"), "no private completion attempt"
        )
        return state

    def evidence_id(self, state: dict) -> str:
        return f"E{state['evidence_sequence']:04d}"

    def stage_disposition(
        self,
        disposition: str,
        token: str = "baseline",
        turn: str = "turn-1",
        session: str = "baseline",
    ) -> dict:
        return cg.stage_private_disposition(
            self.root / "private",
            session,
            turn,
            token,
            disposition,
            replace=True,
        )

    def stage_checkpoint_with_latest_evidence(self, token: str = "baseline") -> dict:
        state = self.state()
        evidence = self.evidence_id(state)
        requirements = [
            f"{item['id']}={evidence}"
            for item in state["requirements"]
            if item["status"] not in {"pass", "superseded"}
        ]
        acceptance = [
            f"{item['id']}={evidence}"
            for item in state["acceptance_items"]
            if item["status"] not in {"pass", "superseded"}
        ]
        return cg.stage_private_checkpoint(
            self.root / "private",
            "baseline",
            "turn-1",
            token,
            requirements,
            acceptance,
        )


    def canonical_reason_input_identity(self, state: dict) -> str:
        """Hash the canonical reason-code inputs: the enforced contracts
        (obligations) plus the ORDER-INDEPENDENT evidence field set, bound
        to the derivation/adapter versions that define their meaning. The
        reason code must be a function of exactly this identity."""
        contracts = [
            {
                "item_id": item["id"],
                "mode": item["verification_contract"]["mode"],
                "obligations": item["verification_contract"]["obligations"],
            }
            for item in state["requirements"] + state["acceptance_items"]
            if isinstance(item.get("verification_contract"), dict)
        ]
        evidence = sorted(
            (
                {
                    "id": entry.get("id"),
                    "outcome": entry.get("outcome"),
                    "subject_ids": sorted(entry.get("subject_ids", [])),
                    "readback_subjects": sorted(entry.get("readback_subjects", [])),
                    "capabilities": sorted(entry.get("capabilities", [])),
                }
                for entry in state.get("evidence", [])
            ),
            key=lambda entry: str(entry["id"]),
        )
        identity = {
            "clause_derivation_version": cg.CLAUSE_DERIVATION_VERSION,
            "adapter_manifest_version": cg.ADAPTER_MANIFEST_VERSION,
            "stop_protocol_version": cg.STOP_PROTOCOL_VERSION,
            "contracts": contracts,
            "evidence": evidence,
        }
        return hashlib.sha256(
            json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class ExecutablePositionBaselineTests(BaselineTestCase):
    """UX-06 / CGI-2026-018: command words outside an executable position."""

    ux_family = "UX-06"

    PLAN_TABLE_TEXT_POSITION = [
        "echo git tag v1.2.3",
        "echo git push origin main",
        "rg -n npm publish README.md",
        'printf "%s\\n" "git push origin main"',
        'rg -n "npm" publish README.md',
        "echo 'gh release create v1.2.3 --notes x'",
    ]

    @unittest.expectedFailure
    def test_plan_false_positive_table_is_classified_as_action(self) -> None:
        """UX-06 baseline defect (documented_only): text-position command
        words are classified as real tier-A/B actions; the 0.12 target is
        no action for every row."""
        for command in self.PLAN_TABLE_TEXT_POSITION:
            action = cg.classify_pre_tool_action(
                {"tool_name": "shell", "tool_input": {"command": command}}
            )
            self.assertIsNone(action, f"false positive on {command!r}")

    def test_quoted_phrase_argument_stays_inert(self) -> None:
        """Baseline behavior that is already correct and must survive 0.12."""
        action = cg.classify_pre_tool_action(
            {
                "tool_name": "shell",
                "tool_input": {"command": 'rg -n "npm publish" README.md'},
            }
        )
        self.assertIsNone(action)

    def test_real_executable_positions_still_detected(self) -> None:
        """Positive controls: real executable positions must keep gating."""
        detected = [
            "git tag v1.2.3",
            "bash -c 'git tag v1.2.3'",
            'pwsh -Command "git tag v1.2.3"',
            'powershell -Command "npm publish"',
            "git tag v1.2.3 && git push origin v1.2.3",
        ]
        for command in detected:
            action = cg.classify_pre_tool_action(
                {"tool_name": "shell", "tool_input": {"command": command}}
            )
            self.assertIsNotNone(action, f"expected detection for {command!r}")
            self.assertEqual(action["tier"], "A", command)

    def test_read_only_git_forms_stay_inert(self) -> None:
        for command in ("git tag -l", "git status --porcelain", "gh release view v1.2.3"):
            action = cg.classify_pre_tool_action(
                {"tool_name": "shell", "tool_input": {"command": command}}
            )
            self.assertIsNone(action, command)


class SimulationBaselineTests(BaselineTestCase):
    """UX-07 / CGI-2026-019: no-side-effect variants classified as real."""

    ux_family = "UX-07"

    @unittest.expectedFailure
    def test_dry_run_variants_are_treated_as_real_mutations(self) -> None:
        """UX-07 baseline defect (documented_only): --dry-run variants are
        classified as tier-A/B real mutations; 0.12 target is a simulation
        class that never consumes authorization."""
        for command in ("npm publish --dry-run", "git push --dry-run origin main"):
            action = cg.classify_pre_tool_action(
                {"tool_name": "shell", "tool_input": {"command": command}}
            )
            self.assertIsNone(action, f"dry-run misclassified: {command!r}")

    def test_real_publish_still_detected(self) -> None:
        action = cg.classify_pre_tool_action(
            {"tool_name": "shell", "tool_input": {"command": "npm publish"}}
        )
        self.assertIsNotNone(action)
        self.assertEqual(action["semantic_action_id"], "registry_npm_publish")


class PolicyScopeBaselineTests(BaselineTestCase):
    """UX-05 / CGI-2026-017: release machinery active without adoption."""

    ux_family = "UX-05"

    def test_unticketed_tag_denied_without_any_adopted_contract(self) -> None:
        """Baseline observable: the action-ticket requirement fires even when
        no release contract was ever adopted. (Security behavior retained by
        0.12; the 0.12 change is that explicit root-user authorization in the
        current work unit must be sufficient under the standard profile.)"""
        self.prompt_activated(ACTIVATING_PROMPT)
        result = self.dispatch(
            "PreToolUse",
            tool_name="shell",
            tool_input={"command": "git tag v9.9.9"},
        )
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    @unittest.expectedFailure
    def test_root_user_authorized_tag_still_requires_ticket(self) -> None:
        """UX-05 baseline defect (documented_only): an explicit root-user
        instruction in the current work unit does not satisfy the default
        core; only an action-ticket/v1 does. 0.12 target: allow under the
        standard profile."""
        self.prompt_activated(
            "请为本仓库创建标签 v9.9.9。必须只打这一个 tag,必须运行测试验证。"
        )
        result = self.dispatch(
            "PreToolUse",
            tool_name="shell",
            tool_input={"command": "git tag v9.9.9"},
        )
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "allow"
        )


class AdapterBindingBaselineTests(BaselineTestCase):
    """UX-09 / CGI-2026-021: thread-read adapter identity and readback."""

    ux_family = "UX-09"

    def test_alias_set_contains_only_the_short_name(self) -> None:
        """Root-cause pin: the fully qualified event name is not member of
        the alias set, so a real MCP thread read never matches."""
        self.assertIn("read_thread", cg.THREAD_READ_TOOL_ALIASES)
        self.assertNotIn(
            cg.normalized_tool_name("mcp__codex_app__read_thread"),
            cg.THREAD_READ_TOOL_ALIASES,
        )

    def test_qualified_thread_read_binds_no_subject(self) -> None:
        """Defect pin: a successful fully qualified thread read leaves the
        thread subject unbound anywhere in the evidence record."""
        self.prompt_activated(THREAD_PROMPT)
        self.dispatch(
            "PostToolUse",
            tool_name="mcp__codex_app__read_thread",
            tool_input={"threadId": THREAD_ID},
            tool_response={"exit_code": 0, "output": "thread content"},
        )
        evidence = self.state()["evidence"][-1]
        self.assertEqual(evidence["tool"], "mcp__codex_app__read_thread")
        self.assertNotIn(
            cg.thread_subject_item(THREAD_URI)["id"],
            evidence["subject_ids"],
        )
        self.assertEqual(evidence["readback_subjects"], [])

    def test_thread_readback_obligation_cannot_close(self) -> None:
        """Defect pin (E2E): the enforced subject-readback obligation on the
        read thread can never be satisfied, so the private checkpoint is
        rejected and the turn cannot complete cleanly. The rejection names
        the obligation and a stable, structured diagnostic (INV-11)."""
        self.prompt_activated(THREAD_PROMPT)
        self.dispatch(
            "PostToolUse",
            tool_name="mcp__codex_app__read_thread",
            tool_input={"threadId": THREAD_ID},
            tool_response={"exit_code": 0, "output": "thread content"},
        )
        state = self.state()
        contract = state["requirements"][0]["verification_contract"]
        self.assertEqual(contract["mode"], "enforced")
        obligation_ids = [item["id"] for item in contract["obligations"]]
        self.assertEqual(
            [item["kind"] for item in contract["obligations"]],
            ["subject_readback"],
        )
        with self.assertRaises(ValueError) as caught:
            self.stage_checkpoint_with_latest_evidence()
        self.assertIn("unresolved proof obligations", str(caught.exception))
        self.assertIn(obligation_ids[0], str(caught.exception))
        diagnostic = cg.obligation_binding_diagnostic(
            state, "R001", obligation_ids[0]
        )
        self.assertIn("subject_binding=missing", diagnostic)
        self.assertEqual(
            diagnostic,
            cg.obligation_binding_diagnostic(state, "R001", obligation_ids[0]),
        )

    @unittest.expectedFailure
    def test_read_adapter_binds_thread_id_from_structured_input(self) -> None:
        """UX-09 baseline defect, target behavior (documented_only): the
        registered thread-read adapter must bind the thread subject from the
        bounded ``threadId`` input field. 0.11.x has no thread branch in the
        readback derivation, so even the short name binds nothing."""
        bound = cg.read_input_subject_ids("read_thread", {"threadId": THREAD_ID})
        self.assertEqual(
            bound, [cg.thread_subject_item(THREAD_URI)["id"]]
        )

    @unittest.expectedFailure
    def test_qualified_name_binds_readback_subject(self) -> None:
        """UX-09 baseline defect, target behavior (documented_only): the
        fully qualified adapter name must be normalized onto the registered
        adapter and bind the same subject from its input."""
        self.prompt_activated(THREAD_PROMPT)
        self.dispatch(
            "PostToolUse",
            tool_name="mcp__codex_app__read_thread",
            tool_input={"threadId": THREAD_ID},
            tool_response={"exit_code": 0, "output": "thread content"},
        )
        evidence = self.state()["evidence"][-1]
        self.assertIn(
            cg.thread_subject_item(THREAD_URI)["id"],
            evidence["readback_subjects"],
        )

    def test_response_echo_never_binds_thread_subject(self) -> None:
        """Negative control that is already correct and must survive 0.12:
        a thread URI echoed by any other tool stays inert."""
        self.prompt_activated(THREAD_PROMPT)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": f"echo {THREAD_URI}"},
            tool_response={"exit_code": 0, "output": THREAD_URI},
        )
        evidence = self.state()["evidence"][-1]
        self.assertNotIn(
            cg.thread_subject_item(THREAD_URI)["id"],
            evidence["subject_ids"],
        )
        self.assertEqual(evidence["readback_subjects"], [])


class StopCascadeBaselineTests(BaselineTestCase):
    """UX-02/UX-03/UX-08: disposition validation cascade and feedback scope."""

    ux_family = "UX-02/03/08"

    def start_turn(self) -> None:
        self.prompt_activated(ACTIVATING_PROMPT)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": "python3 -m unittest"},
            tool_response={"exit_code": 0, "output": "OK"},
        )

    def stop(self, reply: str) -> dict:
        return self.dispatch("Stop", last_assistant_message=reply)

    def test_subclass_disposition_differences_cause_visible_blocks(self) -> None:
        """Defect pins (UX-03/UX-08): a declared user_wait against an
        externally-observed boundary blocks visibly, twice, and each block
        carries every requirement/acceptance id in one long message."""
        self.start_turn()
        self.stage_disposition("deferred")
        first = self.stop(EXTERNAL_WAIT_REPLY)
        self.assertEqual(first.get("decision"), "block")
        self.stage_disposition("user_wait")
        second = self.stop(EXTERNAL_WAIT_REPLY)
        self.assertEqual(second.get("decision"), "block")
        reason = second["reason"]
        self.assertIn("Expected IDs", reason)
        state = self.state()
        for item in state["requirements"] + state["acceptance_items"]:
            self.assertIn(item["id"], reason)
        self.assertGreater(len(reason), 240)

    def test_correction_chain_closes_with_matching_disposition(self) -> None:
        """INV-11 reachability pin: the correction the hook demands can
        actually close the turn — staging the matching external_wait after
        the mismatches ends silently."""
        self.start_turn()
        self.stage_disposition("deferred")
        self.assertEqual(self.stop(EXTERNAL_WAIT_REPLY).get("decision"), "block")
        self.stage_disposition("user_wait")
        self.assertEqual(self.stop(EXTERNAL_WAIT_REPLY).get("decision"), "block")
        self.stage_disposition("external_wait")
        self.assertEqual(self.stop(EXTERNAL_WAIT_REPLY), {})

    def test_repeated_mismatch_exhausts_budget_with_hard_stop(self) -> None:
        """Baseline pin (UX-02): the retry chain ends in a protocol-level
        hard stop after two corrections; the turn still cannot end quietly."""
        self.start_turn()
        self.stage_disposition("deferred")
        self.assertEqual(self.stop(EXTERNAL_WAIT_REPLY).get("decision"), "block")
        self.stage_disposition("user_wait")
        self.assertEqual(self.stop(EXTERNAL_WAIT_REPLY).get("decision"), "block")
        self.stage_disposition("user_wait")
        third = self.stop(EXTERNAL_WAIT_REPLY)
        self.assertFalse(third.get("continue", True))
        self.assertIn("two correction attempts", third.get("stopReason", ""))

    @unittest.expectedFailure
    def test_correction_budget_is_one_visible_block(self) -> None:
        """UX-02/UX-03 baseline defect, 0.12 target (documented_only): at
        most one visible correction per turn; sub-class disposition
        differences never continue the turn."""
        self.start_turn()
        blocks = 0
        for disposition in ("deferred", "user_wait", "external_wait"):
            self.stage_disposition(disposition)
            result = self.stop(EXTERNAL_WAIT_REPLY)
            if result.get("decision") == "block":
                blocks += 1
        self.assertLessEqual(blocks, 1)

    @unittest.expectedFailure
    def test_disposition_comparator_treats_waits_equivalently(self) -> None:
        """UX-03 baseline defect, 0.12 target (documented_only): a declared
        wait whose only difference is the sub-class must match the observed
        boundary instead of failing the disposition check."""
        self.assertTrue(
            cg.disposition_matches_observed("user_wait", "allow_external_wait")
        )

    def test_plain_completion_claim_is_not_gated(self) -> None:
        """Baseline pin: without a staged control, a whole-completion claim
        over open items ends silently. Documented so the 0.12 Stop 3.0 work
        starts from the real baseline, not an assumed one."""
        self.start_turn()
        self.assertEqual(self.stop("全部修复已经完成。"), {})


class WorkUnitLifecycleBaselineTests(BaselineTestCase):
    """UX-01 / CGI-2026-013: per-prompt parent chains never close."""

    ux_family = "UX-01"

    def test_each_prompt_chains_a_child_unit(self) -> None:
        """Defect pin: every non-control prompt becomes a child of the
        still-active previous unit and nothing ever closes."""
        for index in range(1, 5):
            self.dispatch(
                "UserPromptSubmit",
                turn=f"turn-{index}",
                prompt=f"请处理第 {index} 项修复任务。必须逐项落实。必须运行测试验证。",
            )
        state = self.state()
        units = state["work_units"]
        self.assertEqual(len(units), 4)
        self.assertEqual(units[1]["parent_id"], units[0]["id"])
        self.assertEqual(units[3]["parent_id"], units[2]["id"])
        self.assertTrue(all(unit["status"] == "active" for unit in units))

    @unittest.expectedFailure
    def test_new_independent_request_starts_a_sibling_root(self) -> None:
        """UX-01 baseline defect, 0.12 target (documented_only): a new
        independent request creates a sibling/root unit instead of chaining
        behind the previous active one."""
        self.dispatch(
            "UserPromptSubmit",
            turn="turn-1",
            prompt="请修复模块。必须逐项落实。必须运行测试验证。",
        )
        self.dispatch(
            "UserPromptSubmit",
            turn="turn-2",
            prompt="新的独立请求:请检查文档拼写。必须运行测试验证。",
        )
        units = self.state()["work_units"]
        self.assertEqual(units[1]["parent_id"], None)

    def test_replay_over_120_turns_keeps_units_active(self) -> None:
        """100+ turn replay: the ledger replays without error and every unit
        stays active on the baseline (defect context for UX-01)."""
        for index in range(1, 121):
            self.dispatch(
                "UserPromptSubmit",
                turn=f"turn-{index}",
                prompt=f"批量任务第 {index} 步:请修复对应条目。必须运行测试验证。",
            )
        state = self.state()
        self.assertEqual(len(state["work_units"]), 120)
        self.assertTrue(
            all(unit["status"] == "active" for unit in state["work_units"])
        )
        self.assertEqual(
            state["work_state"]["active_work_unit_id"], "WU0120"
        )


class WaitingOwnerFactTableTests(BaselineTestCase):
    """CGR1-P2-D / CGR2-P2-A: structured waiting-owner outcomes."""

    ux_family = "INV-waiting-owner"

    FACT_TABLE = [
        (
            ACTIVATING_PROMPT,
            "我会继续修复模块和文档,并运行测试。",
            "gate_authorized_remaining_work",
        ),
        (
            ACTIVATING_PROMPT,
            "需要你先在方案 A 与方案 B 之间做出选择。",
            "allow_user_handoff",
        ),
        (
            ACTIVATING_PROMPT,
            "目录发布已完成,当前等待外部审核。",
            "allow_external_wait",
        ),
        # The deferred class is prompt-relative: the reply's remaining work
        # must be the work the authoritative prompt denied (pair proven in
        # the repository's disposition suite).
        (
            "只审查并本地提交,不要推送或运行 CI。",
            "Local commit is complete; push and CI are deferred to a later turn.",
            "allow_out_of_scope_deferred",
        ),
        (ACTIVATING_PROMPT, "状态不太确定。", "allow_neutral"),
    ]

    def test_structured_fact_table_is_stable(self) -> None:
        for prompt, reply, expected in self.FACT_TABLE:
            observed = cg.classify_stop_decision(reply, prompt)
            self.assertEqual(
                observed["outcome"],
                expected,
                f"unstable ownership classification for {reply!r}",
            )

    def test_assistant_owner_with_persistence_gates_once(self) -> None:
        policy = cg.terminal_stop_policy(
            explicit_persistence=True,
            persistence_allows_deferred=False,
            declared_disposition=None,
        )
        self.assertEqual(policy, "gate_explicit_persistence")

    def test_subagent_stop_never_continues_the_root_turn(self) -> None:
        """Pin: SubagentStop records a bounded result and returns no
        continuation and no developer text."""
        self.prompt_activated(ACTIVATING_PROMPT)
        result = self.dispatch(
            "SubagentStop",
            agent_id="synthetic-agent-1",
            last_assistant_message="子任务已完成一部分。",
        )
        self.assertEqual(result, {})
        record = self.state()["agents"][-1]
        self.assertEqual(record["status"], "stopped")
        self.assertIn("子任务", record["result_summary"])


class SchemaMigrationBaselineTests(BaselineTestCase):
    """CGR1-P2-C: schema 9 today, schema 10 migration contract."""

    ux_family = "INV-migration"

    def test_schema9_pending_items_survive_resume_without_auto_pass(self) -> None:
        self.prompt_activated(ACTIVATING_PROMPT)
        reloaded = cg.load_state(
            self.root / "private" / "sessions" / "baseline",
            {"session_id": "baseline"},
        )
        statuses = [item["status"] for item in reloaded["requirements"]]
        self.assertEqual(statuses, ["pending"])
        self.assertEqual(reloaded["schema_version"], cg.SCHEMA_VERSION)

    def test_unknown_future_schema_fails_closed_without_marking_pass(self) -> None:
        """Pin: a state written by a newer schema must fail closed; it must
        never be silently converted with pending items marked pass."""
        self.prompt_activated(ACTIVATING_PROMPT)
        state_path = (
            self.root / "private" / "sessions" / "baseline" / "state.json"
        )
        future = json.loads(state_path.read_text(encoding="utf-8"))
        future["schema_version"] = cg.SCHEMA_VERSION + 1
        state_path.write_text(json.dumps(future), encoding="utf-8")
        reloaded = cg.load_state(
            self.root / "private" / "sessions" / "baseline",
            {"session_id": "baseline"},
        )
        integrity = reloaded["integrity"]
        if integrity["status"] == "recovered_from_prompts":
            statuses = [item["status"] for item in reloaded["requirements"]]
            self.assertEqual(statuses, ["pending"])
        else:
            self.assertEqual(integrity["status"], "failed")
        for item in reloaded["requirements"]:
            self.assertNotEqual(item["status"], "pass")

    @unittest.expectedFailure
    def test_schema_version_is_10_with_migration(self) -> None:
        """0.12 target (documented_only): the runtime implements schema 10
        with a 9→10 live migration that isolates historical chains and never
        marks pending items pass."""
        self.assertEqual(cg.SCHEMA_VERSION, 10)


class EvidenceUniquenessBaselineTests(BaselineTestCase):
    """CGR1-P2-B: non-unique evidence must not be auto-selected."""

    ux_family = "INV-evidence-uniqueness"

    def build_two_identical_reads(self) -> Path:
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        prompt = (
            f"请先核对 {target} 后修复文档。必须读取该文件内容并运行测试验证。"
            "必须更新 README 文件。"
        )
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="baseline"):
            self.dispatch("UserPromptSubmit", prompt=prompt)
        for _ in range(2):
            self.dispatch(
                "PostToolUse",
                tool_name="shell",
                tool_input={"command": f"cat {target}"},
                tool_response={"exit_code": 0, "output": "subject"},
            )
        return target

    def test_derivation_is_deterministic_for_a_fixed_order(self) -> None:
        """INV-11 pin: the same ledger state always yields the same derived
        proofs and diagnostics."""
        self.build_two_identical_reads()
        state = self.state()
        first = cg.derive_ordinary_proofs(state)
        second = cg.derive_ordinary_proofs(state)
        self.assertEqual(
            [(item["obligation_id"], item["evidence_ids"]) for item in first],
            [(item["obligation_id"], item["evidence_ids"]) for item in second],
        )

    @unittest.expectedFailure
    def test_non_unique_evidence_is_not_auto_selected(self) -> None:
        """CGR1-P2-B baseline defect, 0.12 target (documented_only): two
        equally valid candidate readings must leave the obligation pending
        (evidence_ambiguous); 0.11.x picks whichever comes first in ledger
        order, so a permutation flips the selection."""
        self.build_two_identical_reads()
        state = self.state()
        permuted = json.loads(json.dumps(state))
        permuted["evidence"] = list(reversed(permuted["evidence"]))
        forward = cg.derive_ordinary_proofs(state)
        backward = cg.derive_ordinary_proofs(permuted)
        self.assertEqual(forward, [])
        self.assertEqual(backward, [])


class MatcherDeterminismTests(BaselineTestCase):
    """INV-11 conformance on the Codex surface: verdict determinism under
    event-order permutation, repeated execution, and concurrent reads, plus
    one reachable positive per rejection hint. (DSH UX-10/UX-11 are the
    sibling failure family on the TypeScript surface; they are not claimed
    here.)"""

    ux_family = "INV-matcher-determinism"

    def build_reads(self) -> None:
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        prompt = (
            f"请先核对 {target} 后修复文档。必须读取该文件内容并运行测试验证。"
            "必须更新 README 文件。"
        )
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="baseline"):
            self.dispatch("UserPromptSubmit", prompt=prompt)
        for _ in range(2):
            self.dispatch(
                "PostToolUse",
                tool_name="shell",
                tool_input={"command": f"cat {target}"},
                tool_response={"exit_code": 0, "output": "subject"},
            )

    def test_verdict_stable_under_permutation_repeat_and_concurrency(self) -> None:
        """The matched/rejected verdict per obligation id must be identical
        across ledger permutation, repeated evaluation, and concurrent
        reads, and the verdict domain is the canonical reason-code input
        identity (order-independent item/evidence-set field set plus the
        derivation, adapter, and protocol versions). Selection differences
        are covered by the non-unique-evidence defect test."""
        self.build_reads()
        state = self.state()
        permuted = json.loads(json.dumps(state))
        permuted["evidence"] = list(reversed(permuted["evidence"]))
        self.assertEqual(
            self.canonical_reason_input_identity(state),
            self.canonical_reason_input_identity(permuted),
            "canonical input identity is not order-independent",
        )

        def verdict(proofs: list[dict]) -> list[str]:
            return sorted(str(item["obligation_id"]) for item in proofs)

        repeated = [cg.derive_ordinary_proofs(state) for _ in range(3)]
        permuted_results = [cg.derive_ordinary_proofs(permuted) for _ in range(3)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            concurrent_results = list(
                pool.map(
                    lambda _: cg.derive_ordinary_proofs(state),
                    range(8),
                )
            )
        for label, results in (
            ("repeat", repeated),
            ("permutation-repeat", permuted_results),
            ("concurrent", concurrent_results),
        ):
            self.assertEqual(
                len({json.dumps(verdict(item), sort_keys=True) for item in results}),
                1,
                f"{label} verdicts diverged",
            )
        self.assertEqual(
            json.dumps(verdict(repeated[0]), sort_keys=True),
            json.dumps(verdict(permuted_results[0]), sort_keys=True),
            "verdict differs between ledger orders",
        )

    def test_control_request_digest_invariant_under_key_permutation(self) -> None:
        control = {
            "kind": "disposition",
            "disposition": "external_wait",
            "reason": "external_dependency",
        }
        reordered = dict(reversed(list(control.items())))
        self.assertEqual(
            cg.control_request_sha256("baseline", "turn-1", control, replace=True),
            cg.control_request_sha256("baseline", "turn-1", reordered, replace=True),
        )

    def test_missing_evidence_hint_has_reachable_positive(self) -> None:
        """INV-11: staging with a missing scoped item is rejected with a
        hint that names the item, and completing exactly what the hint names
        closes the turn silently."""
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        prompt = (
            f"请先核对 {target} 后修复文档。必须读取该文件内容并运行测试验证。"
            "必须更新 README 文件。"
        )
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="baseline"):
            self.dispatch("UserPromptSubmit", prompt=prompt)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": f"cat {target}"},
            tool_response={"exit_code": 0, "output": "subject"},
        )
        state = self.state()
        evidence = self.evidence_id(state)
        missing = [f"{item['id']}={evidence}" for item in state["requirements"]]
        with self.assertRaises(ValueError) as caught:
            cg.stage_private_checkpoint(
                self.root / "private",
                "baseline",
                "turn-1",
                "baseline",
                missing,
                [],
            )
        self.assertIn("is missing", str(caught.exception))
        # Reachable positive: supply exactly the missing acceptance mapping.
        acceptance = [
            f"{item['id']}={evidence}"
            for item in self.state()["acceptance_items"]
            if item["status"] not in {"pass", "superseded"}
        ]
        cg.stage_private_checkpoint(
            self.root / "private",
            "baseline",
            "turn-1",
            "baseline",
            missing,
            acceptance,
        )
        self.assertEqual(
            self.dispatch("Stop", last_assistant_message=EXTERNAL_WAIT_REPLY),
            {},
        )


PERSISTENCE_PROMPT = (
    "请修复模块、修复文档、修复测试三件事。必须逐项落实。必须运行测试验证。"
    "不要停止,一直推进直到完成。"
)
ASSISTANT_ACTIONABLE_REPLY = "我会继续修复模块和文档,并运行测试。"


class ReasonCodeFixtureTests(BaselineTestCase):
    """Canonical input -> result fixtures for the reason-code surface.

    ux_family: INV-matcher-determinism.

    Two strictly separated layers:

    * ``legacy_observation`` rows pin the CURRENT 0.11.x behavior with
      literal frozen results (lexical/legacy observation; a drift fails the
      run and the row must be re-frozen deliberately). Production
      ``derive_ordinary_proofs`` returns proof lists only — it has no
      structured reason code — so no legacy row claims one.
    * ``test_production_structured_matcher_api`` is the 0.12 target: a pure
      production matcher API that, for the same canonical item, binding, and
      projection, returns the full normalized result (outcome, reason_code,
      obligation, selected-evidence identity); non-unique evidence must
      yield evidence_ambiguous/pending/no selection. Expected to fail today
      because the API does not exist.
    """

    ux_family = "INV-matcher-determinism"

    STATE_VERSION = {
        "schema": cg.SCHEMA_VERSION,
        "stop_protocol": cg.STOP_PROTOCOL_VERSION,
        "clause_derivation": cg.CLAUSE_DERIVATION_VERSION,
        "adapter_manifest": cg.ADAPTER_MANIFEST_VERSION,
    }

    def build_spec_reads(self) -> tuple[dict, dict, dict]:
        """Persist one unique cat read, then build duplicate-read and
        permuted in-memory views for the ambiguity rows."""
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        prompt = (
            f"请先核对 {target} 后修复文档。必须读取该文件内容并运行测试验证。"
            "必须更新 README 文件。"
        )
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="baseline"):
            self.dispatch("UserPromptSubmit", prompt=prompt)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": f"cat {target}"},
            tool_response={"exit_code": 0, "output": "subject"},
        )
        unique = self.state()
        duplicated = json.loads(json.dumps(unique))
        second = dict(duplicated["evidence"][-1])
        second["id"] = "E0002"
        duplicated["evidence"].append(second)
        permuted = json.loads(json.dumps(duplicated))
        permuted["evidence"] = list(reversed(permuted["evidence"]))
        return unique, duplicated, permuted

    def canonical_projection(self, state: dict, item_id: str) -> dict:
        """The raw projection handed to the future production matcher:
        enforced contract of one item plus the evidence set in the ledger's
        RAW insertion order. This helper deliberately does NOT sort — the
        production API owns canonicalization, and flattening the order here
        would erase the very variation the permutation rows exercise."""
        item = next(
            entry
            for entry in state["requirements"] + state["acceptance_items"]
            if entry["id"] == item_id
        )
        return {
            "item": {
                "id": item["id"],
                "verification_contract": item["verification_contract"],
            },
            "evidence": list(state.get("evidence", [])),
            "versions": {
                "clause_derivation": cg.CLAUSE_DERIVATION_VERSION,
                "adapter_manifest": cg.ADAPTER_MANIFEST_VERSION,
                "stop_protocol": cg.STOP_PROTOCOL_VERSION,
                "schema": cg.SCHEMA_VERSION,
            },
        }

    def test_legacy_observations_match_frozen_results(self) -> None:
        unique, duplicated, permuted = self.build_spec_reads()
        identity_unique = self.canonical_reason_input_identity(unique)
        identity_forward = self.canonical_reason_input_identity(duplicated)
        identity_permuted = self.canonical_reason_input_identity(permuted)
        forward = cg.derive_ordinary_proofs(duplicated)
        backward = cg.derive_ordinary_proofs(permuted)
        selection_forward = sorted(
            evidence for item in forward for evidence in item["evidence_ids"]
        )
        selection_permuted = sorted(
            evidence for item in backward for evidence in item["evidence_ids"]
        )
        rows = [
            {
                "name": "canonical_identity_is_order_independent",
                "input": {
                    "identity_duplicated": identity_forward,
                    "identity_permuted": identity_permuted,
                    "state_version": self.STATE_VERSION,
                },
                "frozen_result": {"identities_equal": True},
                "check": lambda: self.assertEqual(
                    identity_forward, identity_permuted
                ),
            },
            {
                "name": "fulfillment_stable_under_permutation_legacy",
                "input": {"identity": identity_forward, "state_version": self.STATE_VERSION},
                "frozen_result": {
                    "outcome": "fulfilled_legacy_selection",
                    "obligation": sorted(
                        str(item["obligation_id"]) for item in forward
                    ),
                },
                "check": lambda: self.assertEqual(
                    sorted(str(item["obligation_id"]) for item in backward),
                    sorted(str(item["obligation_id"]) for item in forward),
                ),
            },
            {
                "name": "selection_order_dependent_legacy",
                "input": {"identity": identity_forward, "state_version": self.STATE_VERSION},
                "frozen_result": {
                    "selected_evidence_forward": selection_forward,
                    "selected_evidence_permuted": selection_permuted,
                },
                "check": lambda: self.assertEqual(
                    selection_forward, ["E0001", "E0001"]
                )
                or self.assertEqual(
                    selection_permuted, ["E0002", "E0002"]
                ),
            },
            {
                "name": "missing_acceptance_error_text_and_reachable_positive_legacy",
                "input": {"identity": identity_unique, "state_version": self.STATE_VERSION},
                "frozen_result": {"error_text_contains": "A001 is missing"},
                "check": lambda: self._assert_missing_acceptance_hint(
                    unique, identity_unique
                ),
            },
        ]
        for row in rows:
            with self.subTest(row=row["name"], observation_class="legacy_observation"):
                row["check"]()
            ROW_LEVEL_REPORT.append(
                {
                    "suite": "reason_code",
                    "row": row["name"],
                    "observation_class": "legacy_observation",
                    "input": row["input"],
                    "frozen_result": row["frozen_result"],
                    "status": "pinned_on_baseline",
                }
            )

    def _assert_missing_acceptance_hint(self, unique_state: dict, identity: str) -> None:
        """The identity argument must be the canonical identity of the exact
        state this row evaluates — assert it, then pin the legacy error text
        and its reachable positive."""
        self.assertEqual(
            identity,
            self.canonical_reason_input_identity(unique_state),
            "fixture identity does not match the evaluated state",
        )
        evidence = f"E{unique_state['evidence_sequence']:04d}"
        with self.assertRaises(ValueError) as caught:
            cg.stage_private_checkpoint(
                self.root / "private",
                "baseline",
                "turn-1",
                "baseline",
                [f"{item['id']}={evidence}" for item in unique_state["requirements"]],
                [],
            )
        self.assertIn("A001 is missing", str(caught.exception))
        acceptance = [
            f"{item['id']}={evidence}"
            for item in self.state()["acceptance_items"]
            if item["status"] not in {"pass", "superseded"}
        ]
        cg.stage_private_checkpoint(
            self.root / "private",
            "baseline",
            "turn-1",
            "baseline",
            [f"{item['id']}={evidence}" for item in unique_state["requirements"]],
            acceptance,
        )
        self.assertEqual(
            self.dispatch("Stop", last_assistant_message=EXTERNAL_WAIT_REPLY),
            {},
        )

    @unittest.expectedFailure
    def test_production_structured_matcher_api(self) -> None:
        """0.12 target (absent today): the production matcher must
        canonicalize order internally. The two RAW inputs below genuinely
        differ in evidence insertion order and binding evidenceIds order
        (asserted first); after canonicalization the full normalized result
        must be identical across repeat, permutation, and 8 concurrent
        reads, and non-unique evidence must produce evidence_ambiguous /
        pending / no selection."""
        _, duplicated, permuted = self.build_spec_reads()
        raw_order_duplicated = [e["id"] for e in duplicated["evidence"]]
        raw_order_permuted = [e["id"] for e in permuted["evidence"]]
        # The raw input sequences must genuinely differ BEFORE canonicalization.
        self.assertEqual(raw_order_duplicated, ["E0001", "E0002"])
        self.assertEqual(raw_order_permuted, ["E0002", "E0001"])
        self.assertNotEqual(raw_order_duplicated, raw_order_permuted)

        projection = self.canonical_projection(duplicated, "R001")
        permuted_projection = self.canonical_projection(permuted, "R001")
        binding = {"itemId": "R001", "evidenceIds": ["E0001", "E0002"]}
        permuted_binding = {"itemId": "R001", "evidenceIds": ["E0002", "E0001"]}
        # The helper must not have flattened the variation either.
        self.assertNotEqual(
            [e["id"] for e in projection["evidence"]],
            [e["id"] for e in permuted_projection["evidence"]],
        )
        self.assertNotEqual(binding["evidenceIds"], permuted_binding["evidenceIds"])

        expected_pending = {
            "outcome": "pending",
            "reason_code": "evidence_ambiguous",
            "obligation": "O-R001-001",
            "selected_evidence": [],
        }
        results = []
        for _ in range(3):
            results.append(cg.evaluate_reason("R001", binding, projection))
        results.append(
            cg.evaluate_reason("R001", permuted_binding, permuted_projection)
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results.extend(
                pool.map(
                    lambda _: cg.evaluate_reason("R001", binding, projection),
                    range(8),
                )
            )
        normalized = [
            json.dumps(result, ensure_ascii=False, sort_keys=True)
            for result in results
        ]
        self.assertEqual(len(set(normalized)), 1)
        self.assertEqual(results[0], expected_pending)

    def test_permutation_sensitivity_negative_control(self) -> None:
        """Negative control: a deliberately order-sensitive fake matcher
        yields DIFFERENT normalized results on the two raw orders, proving
        the permutation assertions above would actually catch an
        order-sensitive production implementation."""
        _, duplicated, permuted = self.build_spec_reads()
        projection = self.canonical_projection(duplicated, "R001")
        permuted_projection = self.canonical_projection(permuted, "R001")

        def order_sensitive_evaluate(projection: dict) -> dict:
            first = projection["evidence"][0]["id"]
            return {"selected_evidence": [first], "reason_code": "fake_first_fit"}

        result_forward = order_sensitive_evaluate(projection)
        result_permuted = order_sensitive_evaluate(permuted_projection)
        self.assertNotEqual(
            json.dumps(result_forward, sort_keys=True),
            json.dumps(result_permuted, sort_keys=True),
        )
        ROW_LEVEL_REPORT.append(
            {
                "suite": "reason_code",
                "row": "permutation_sensitivity_negative_control",
                "observation_class": "harness_control",
                "input": {"raw_orders": ["E0001,E0002", "E0002,E0001"]},
                "frozen_result": {"fake_outputs_differ": True},
                "status": "control_passed",
            }
        )


class WaitingOwnerStructuredTests(BaselineTestCase):
    """CGR1-P2-D / CGR2-P2-A structured contrasts (not lexical-only): the
    owner ladder, the three assistant-owner terminals, and the two silent
    pending controls demanded by the frozen plan."""

    ux_family = "INV-waiting-owner-structured"

    def test_structured_facts_rank_assistant_above_user_and_external(self) -> None:
        combined = (
            "我会继续修复模块和文档,并运行测试。"
            "之后需要你确认方案,同时等待外部审核结果。"
        )
        observed = cg.classify_stop_decision(combined, ACTIVATING_PROMPT)
        self.assertEqual(observed["outcome"], "gate_authorized_remaining_work")
        owners = [action["category"] for action in observed["actions"]]
        self.assertIn("test_verify", owners)
        self.assertIn("user_action", owners)
        self.assertIn("external_wait", owners)
        user_first = cg.classify_stop_decision(
            "需要你先确认方案,同时等待外部审核结果。", ACTIVATING_PROMPT
        )
        user_last = cg.classify_stop_decision(
            "等待外部审核结果,之后也需要你确认方案。", ACTIVATING_PROMPT
        )
        self.assertEqual(user_first["outcome"], "allow_user_handoff")
        self.assertEqual(user_last["outcome"], "allow_user_handoff")

    @unittest.expectedFailure
    def test_assistant_owner_terminal_persistent_completion_gates(self) -> None:
        """Terminal (a): user demands persistence, assistant work remains,
        no staged control — the hook corrects once in the target protocol;
        on 0.11.x it corrects on every Stop until the two-strike budget."""
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="baseline"):
            self.dispatch("UserPromptSubmit", prompt=PERSISTENCE_PROMPT)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": "python3 -m unittest"},
            tool_response={"exit_code": 0, "output": "OK"},
        )
        blocks = 0
        for _ in range(3):
            result = self.dispatch(
                "Stop", last_assistant_message=ASSISTANT_ACTIONABLE_REPLY
            )
            if result.get("decision") == "block":
                blocks += 1
        self.assertGreaterEqual(blocks, 1)
        self.assertLessEqual(blocks, 1)

    def test_assistant_owner_terminal_false_completion_claim(self) -> None:
        """Terminal (b): the reply asserts whole completion while structured
        facts show authorized assistant work — the ownership facts outrank
        the completion wording and the correction names remaining work."""
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="baseline"):
            self.dispatch("UserPromptSubmit", prompt=PERSISTENCE_PROMPT)
        claim = "我会继续修复模块和文档,并运行测试。此外任务已经全部完成。"
        observed = cg.classify_stop_decision(claim, PERSISTENCE_PROMPT)
        self.assertEqual(observed["outcome"], "gate_authorized_remaining_work")
        result = self.dispatch("Stop", last_assistant_message=claim)
        self.assertEqual(result.get("decision"), "block")
        self.assertIn("Continue the authorized work", result["reason"])

    def test_assistant_owner_terminal_explicit_partial_ends_silently(self) -> None:
        """Terminal (c): explicit partial/neutral reply, assistant actions
        remain, no persistence demand, no completion claim — the turn must
        end silently with assistant_pending_actions recorded as diagnostic."""
        self.prompt_activated(ACTIVATING_PROMPT)
        self.assertEqual(
            self.dispatch("Stop", last_assistant_message=ASSISTANT_ACTIONABLE_REPLY),
            {},
        )

    def test_declared_waiting_user_with_structured_assistant_facts(self) -> None:
        """Silent-pending control 1 (0.12 target): the agent's copy declares
        waiting_user but the structured facts show an executable assistant
        action, no persistence demand, and no whole-completion claim. The
        sub-class mismatch must not continue the turn. 0.11.x blocks."""
        self.prompt_activated(ACTIVATING_PROMPT)
        self.stage_disposition("user_wait")
        result = self.dispatch(
            "Stop",
            last_assistant_message=(
                "我会继续修复模块和文档;如需调整优先级请告诉我。"
            ),
        )
        self.assertEqual(result, {})

    def test_ambiguous_reply_without_terminal_claim_stays_silent(self) -> None:
        """Silent-pending control 2: ambiguous wording, no explicit terminal
        claim, no staged control — silent end, no disposition retry chain."""
        self.prompt_activated(ACTIVATING_PROMPT)
        self.assertEqual(
            self.dispatch("Stop", last_assistant_message="状态不太确定。"),
            {},
        )

    def test_unknown_owner_defaults_to_yield(self) -> None:
        self.assertEqual(
            cg.terminal_stop_policy(
                explicit_persistence=False,
                persistence_allows_deferred=False,
                declared_disposition=None,
            ),
            "yield_default",
        )


# Schema 9 -> 10 migration fixtures (frozen plan section 4.2). These encode
# the 0.12 target migration contract as data: historical active parent chains
# become historical_unresolved, pending items never become pass, the current
# prompt starts a new root unit, and explicit resume only reopens a unique
# waiting candidate (ties stay pending without clock or similarity guesses).
MIGRATION_FIXTURE_CHAIN = {
    "name": "historical_parent_chain_isolated",
    "schema9_state": {
        "schema_version": 9,
        "work_unit_sequence": 3,
        "work_units": [
            {"id": "WU0001", "parent_id": None, "status": "active", "kind": "general"},
            {"id": "WU0002", "parent_id": "WU0001", "status": "active", "kind": "general"},
            {"id": "WU0003", "parent_id": "WU0002", "status": "active", "kind": "general"},
        ],
        "work_state": {"active_work_unit_id": "WU0003"},
        "requirements": [
            {"id": "R001", "work_unit_id": "WU0001", "status": "pending"},
            {"id": "R002", "work_unit_id": "WU0002", "status": "pending"},
            {"id": "R003", "work_unit_id": "WU0003", "status": "pending"},
        ],
        "acceptance_items": [],
    },
    "expected": {
        "historical_unresolved": ["WU0001", "WU0002"],
        "active_root": "WU0003",
        "statuses_stay_pending": ["R001", "R002", "R003"],
        "no_status_becomes_pass": True,
    },
}
MIGRATION_FIXTURE_UNIQUE_WAITING = {
    "name": "unique_waiting_candidate_resume",
    "schema9_state": {
        "schema_version": 9,
        "work_unit_sequence": 7,
        "work_units": [
            {"id": "WU0003", "parent_id": None, "status": "awaiting_user", "last_active_seq": 3, "kind": "general"},
            {"id": "WU0007", "parent_id": None, "status": "awaiting_user", "last_active_seq": 7, "kind": "general"},
        ],
        "work_state": {"active_work_unit_id": "WU0007"},
        "requirements": [],
        "acceptance_items": [],
    },
    "expected": {
        "resume_reopens": ["WU0007"],
        "stays_pending": ["WU0003"],
    },
}
MIGRATION_FIXTURE_TIE = {
    "name": "waiting_candidate_tie_stays_pending",
    "schema9_state": {
        "schema_version": 9,
        "work_unit_sequence": 7,
        "work_units": [
            {"id": "WU0004", "parent_id": None, "status": "awaiting_external", "last_active_seq": 5, "kind": "general"},
            {"id": "WU0006", "parent_id": None, "status": "awaiting_user", "kind": "general"},
        ],
        "work_state": {"active_work_unit_id": "WU0004"},
        "requirements": [],
        "acceptance_items": [],
    },
    "expected": {
        "resume_reopens": [],
        "requires_explicit_selection": ["WU0004", "WU0006"],
    },
}
MIGRATION_FIXTURES = [
    MIGRATION_FIXTURE_CHAIN,
    MIGRATION_FIXTURE_UNIQUE_WAITING,
    MIGRATION_FIXTURE_TIE,
]


# Frozen owner-ladder fixtures. The structured facts, expected owner,
# expected outcome, mode, and the observed 0.11.x behavior are LITERALS
# frozen by hand from isolated-session probes; nothing in the fixture rows
# is derived from classify_stop_decision at runtime. The lexical E2E
# observation is a separate test that only compares against the frozen
# "observed_0_11_x" values (drift alarm), never against the plan target.
OWNER_GOAL_PROMPT = "/goal 请修复模块、修复文档、修复测试三件事。必须逐项落实。必须运行测试验证。"
OWNER_PERSISTENCE_PROMPT = (
    "请修复模块、修复文档、修复测试三件事。必须逐项落实。必须运行测试验证。"
    "不要停止,一直推进直到完成。"
)
OWNER_DEFERRED_PROMPT = "只审查并本地提交,不要推送或运行 CI。必须逐项落实。必须运行测试验证。"
OWNER_DEFERRED_REPLY = (
    "Local commit is complete; push and CI are deferred to a later turn."
)


def _facts(claim: bool, persist: bool, auth: bool, user: bool, ext: bool, deferred: bool) -> dict:
    return {
        "whole_completion_claim": claim,
        "explicit_persistence": persist,
        "authorized_assistant_actions_available": auth,
        "missing_user_only_input_or_approval": user,
        "registered_external_operation": ext,
        "deferred_by_scope_or_authority": deferred,
    }


OWNER_LADDER_FIXTURES = [
    {
        "name": "assistant_partial_no_persistence",
        "prompt_label": "activating",
        "reply_label": "assistant_actionable",
        "declared": None,
        "facts": _facts(False, False, True, False, False, False),
        "expected_owner": "assistant",
        "expected_outcome": "silent_end_assistant_pending_actions",
        "mode": "passing_pin",
        "observed_0_11_x": "silent_end",
    },
    {
        "name": "assistant_persistence_budget",
        "prompt_label": "persistence",
        "reply_label": "assistant_actionable",
        "declared": None,
        "facts": _facts(False, True, True, False, False, False),
        "expected_owner": "assistant",
        "expected_outcome": "single_bounded_correction",
        "mode": "expected_failure",
        "observed_0_11_x": "hard_stop_after_budget",
    },
    {
        "name": "assistant_declared_user_wait_mismatch",
        "prompt_label": "activating",
        "reply_label": "assistant_actionable",
        "declared": "user_wait",
        "facts": _facts(False, False, True, False, False, False),
        "expected_owner": "assistant",
        "expected_outcome": "silent_end_assistant_pending_actions",
        "mode": "expected_failure",
        "observed_0_11_x": "hard_stop_after_budget",
    },
    {
        "name": "user_missing_input",
        "prompt_label": "activating",
        "reply_label": "user_choice_needed",
        "declared": "user_wait",
        "facts": _facts(False, False, False, True, False, False),
        "expected_owner": "user",
        "expected_outcome": "silent_yield_preserve_pending",
        "mode": "passing_pin",
        "observed_0_11_x": "silent_end",
    },
    {
        "name": "external_registered_operation",
        "prompt_label": "activating",
        "reply_label": "external_wait",
        "declared": "external_wait",
        "facts": _facts(False, False, False, False, True, False),
        "expected_owner": "external",
        "expected_outcome": "silent_yield_preserve_pending",
        "mode": "passing_pin",
        "observed_0_11_x": "silent_end",
    },
    {
        "name": "external_declared_deferred_subclass",
        "prompt_label": "activating",
        "reply_label": "external_wait",
        "declared": "deferred",
        "facts": _facts(False, False, False, False, True, False),
        "expected_owner": "external",
        "expected_outcome": "silent_yield_preserve_pending",
        "mode": "expected_failure",
        "observed_0_11_x": "hard_stop_after_budget",
    },
    {
        "name": "deferred_by_scope",
        "prompt_label": "deferred_scope",
        "reply_label": "deferred_en",
        "declared": "deferred",
        "facts": _facts(False, False, False, False, False, True),
        "expected_owner": "deferred",
        "expected_outcome": "silent_yield_preserve_pending",
        "mode": "passing_pin",
        "observed_0_11_x": "silent_end",
    },
    {
        "name": "unknown_ambiguous",
        "prompt_label": "activating",
        "reply_label": "ambiguous",
        "declared": None,
        "facts": _facts(False, False, False, False, False, False),
        "expected_owner": "unknown",
        "expected_outcome": "silent_end_owner_ambiguous",
        "mode": "passing_pin",
        "observed_0_11_x": "silent_end",
    },
    {
        "name": "whole_claim_persistence",
        "prompt_label": "persistence",
        "reply_label": "completion_claim_with_assistant_work",
        "declared": None,
        "facts": _facts(True, True, True, False, False, False),
        "expected_owner": "assistant",
        "expected_outcome": "single_bounded_correction",
        "mode": "expected_failure",
        "observed_0_11_x": "hard_stop_after_budget",
    },
    {
        "name": "whole_claim_no_persistence_no_obligations",
        "prompt_label": "activating",
        "reply_label": "completion_claim_with_assistant_work",
        "declared": None,
        "facts": _facts(True, False, True, False, False, False),
        "expected_owner": "assistant",
        "expected_outcome": "silent_end_assistant_pending_actions",
        "mode": "passing_pin",
        "observed_0_11_x": "silent_end",
    },
    {
        "name": "goal_prompt_assistant",
        "prompt_label": "goal_prefix",
        "reply_label": "assistant_actionable",
        "declared": None,
        "facts": _facts(False, False, True, False, False, False),
        "expected_owner": "assistant",
        "expected_outcome": "silent_end_assistant_pending_actions",
        "mode": "passing_pin",
        "observed_0_11_x": "silent_end",
    },
]

OWNER_PROMPT_LABELS = {
    "activating": ACTIVATING_PROMPT,
    "persistence": OWNER_PERSISTENCE_PROMPT,
    "deferred_scope": OWNER_DEFERRED_PROMPT,
    "goal_prefix": OWNER_GOAL_PROMPT,
}
OWNER_REPLY_LABELS = {
    "assistant_actionable": "我会继续修复模块和文档,并运行测试。",
    "user_choice_needed": "需要你先在方案 A 与方案 B 之间做出选择。",
    "external_wait": "目录发布已完成,当前等待外部审核。",
    "deferred_en": OWNER_DEFERRED_REPLY,
    "ambiguous": "状态不太确定。",
    "completion_claim_with_assistant_work": (
        "我会继续修复模块和文档,并运行测试。此外任务已经全部完成。"
    ),
}


class OwnerLadderFixtureTests(BaselineTestCase):
    """Frozen structured waiting-owner fixtures plus the lexical E2E
    observation, strictly separated.

    ux_family: INV-waiting-owner-structured.

    * The generated ``test_target_<row>`` methods are the 0.12 target:
      one independent countable expectedFailure per fixture row, each
      driving the future pure production API
      (resolve_waiting_owner / plan_waiting_outcome) against the frozen
      structured facts, expected owner, and expected outcome.
    * ``test_owner_rows_isolated_sessions_lexical_observation`` drives the
      real hook per row in an ISOLATED session and pins only the frozen
      observed 0.11.x behavior (drift alarm). It never asserts plan target
      semantics and never feeds the structured fixtures.
    """

    ux_family = "INV-waiting-owner-structured"

    @unittest.expectedFailure
    def _assert_owner_fixture_row(self, row: dict) -> None:
        """One independent, countable 0.12 target case per fixture row:
        the future production API must map the frozen structured facts to
        the frozen owner and outcome. On 0.11.x every row fails with
        AttributeError (API absent) and stays an individually visible
        expected failure. A CONFORMING implementation — one that satisfies
        the frozen row — makes that row an unexpected success, prompting
        removal/rewrite of the xfail; a partially correct or wrong
        implementation still fails as an expected failure."""
        resolved_owner = cg.resolve_waiting_owner(row["facts"])
        self.assertEqual(resolved_owner, row["expected_owner"], row["name"])
        resolved_outcome = cg.plan_waiting_outcome(
            row["facts"], row["declared"], interruption_index=1
        )
        self.assertEqual(resolved_outcome, row["expected_outcome"], row["name"])

    def test_owner_rows_isolated_sessions_lexical_observation(self) -> None:
        for index, row in enumerate(OWNER_LADDER_FIXTURES):
            session = f"owner-{row['name']}"
            prompt = OWNER_PROMPT_LABELS[row["prompt_label"]]
            reply = OWNER_REPLY_LABELS[row["reply_label"]]
            turn = "t1"
            with mock.patch.object(cg.secrets, "token_urlsafe", return_value="baseline"):
                self.dispatch("UserPromptSubmit", turn=turn, session=session, prompt=prompt)
            self.dispatch(
                "PostToolUse",
                turn=turn,
                session=session,
                tool_name="shell",
                tool_input={"command": "python3 -m unittest"},
                tool_response={"exit_code": 0, "output": "OK"},
            )
            if row["declared"] is not None:
                self.stage_disposition(row["declared"], turn=turn, session=session)
            blocks = 0
            hard_stop = False
            for _ in range(3):
                result = self.dispatch(
                    "Stop", turn=turn, session=session, last_assistant_message=reply
                )
                if result.get("decision") == "block":
                    blocks += 1
                    continue
                if not result.get("continue", True):
                    hard_stop = True
                break
            if hard_stop:
                actual = "hard_stop_after_budget"
            elif blocks == 0:
                actual = "silent_end"
            elif blocks == 1:
                actual = "single_bounded_correction"
            else:
                actual = "repeated_continuation"
            with self.subTest(row=row["name"]):
                self.assertEqual(
                    actual,
                    row["observed_0_11_x"],
                    "observed baseline behavior drifted from the frozen "
                    "lexical observation; re-freeze the row deliberately",
                )
            ROW_LEVEL_REPORT.append(
                {
                    "suite": "owner_ladder",
                    "row": row["name"],
                    "observation_class": "lexical_e2e_observation",
                    "input": {
                        "prompt_label": row["prompt_label"],
                        "reply_label": row["reply_label"],
                        "declared_disposition": row["declared"],
                        "session": session,
                    },
                    "frozen_result": {"observed_0_11_x": row["observed_0_11_x"]},
                    "status": "pinned_on_baseline",
                }
            )



def _make_owner_target_test(row: dict):
    @unittest.expectedFailure
    def test_case(self: "OwnerLadderFixtureTests") -> None:
        self._assert_owner_fixture_row(row)
    test_case.__doc__ = (
        f"0.12 target row '{row['name']}': the future production API must "
        f"resolve the frozen facts to owner={row['expected_owner']} and "
        f"outcome={row['expected_outcome']}."
    )
    return test_case


for _row in OWNER_LADDER_FIXTURES:
    setattr(
        OwnerLadderFixtureTests,
        f"test_target_{_row['name']}",
        _make_owner_target_test(_row),
    )


class SchemaMigrationTargetTests(BaselineTestCase):
    """CGR1-P2-C: the schema 9 -> 10 target migration contract, expressed as
    fixtures the 0.12 implementation must satisfy. The fixture well-formedness
    test runs on this baseline; the migration run itself is a documented
    expected failure because 0.11.x has no schema 10."""

    ux_family = "INV-migration-fixture"

    def test_migration_fixtures_are_well_formed(self) -> None:
        for fixture in MIGRATION_FIXTURES:
            state = fixture["schema9_state"]
            self.assertEqual(state["schema_version"], 9)
            for unit in state["work_units"]:
                self.assertIn(unit["status"], {"active", "awaiting_user", "awaiting_external"})
            expected = fixture["expected"]

            def flat(value: object) -> list[object]:
                if isinstance(value, dict):
                    return [leaf for child in value.values() for leaf in flat(child)]
                if isinstance(value, list):
                    return [leaf for child in value for leaf in flat(child)]
                return [value]

            self.assertNotIn("pass", flat(expected))
            for status_map in expected.get("statuses_stay_pending", []):
                self.assertIn(status_map, {item["id"] for item in state["requirements"]})

    def test_unknown_schema10_state_fails_closed_on_fixture_chain(self) -> None:
        """Pin: a state stamped by a future schema 10 must fail closed on
        0.11.x and must never surface with pending items marked pass."""
        future = json.loads(json.dumps(MIGRATION_FIXTURE_CHAIN["schema9_state"]))
        future["schema_version"] = 10
        session_dir = self.root / "private" / "sessions" / "baseline"
        prompts_dir = session_dir / "prompts"
        prompts_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "state.json").write_text(json.dumps(future), encoding="utf-8")
        reloaded = cg.load_state(session_dir, {"session_id": "baseline"})
        for item in reloaded["requirements"]:
            self.assertNotEqual(item["status"], "pass")
        self.assertIn(reloaded["integrity"]["status"], {"failed", "recovered_from_prompts"})

    @unittest.expectedFailure
    def test_schema10_migration_isolates_chain_without_marking_pass(self) -> None:
        """0.12 target (documented_only): running the schema-9 chain fixture
        through the schema-10 migration isolates historical units, keeps the
        current root, and never marks a pending item pass."""
        migrated = cg.migrate_state(
            json.loads(json.dumps(MIGRATION_FIXTURE_CHAIN["schema9_state"])),
            {"session_id": "baseline"},
        )
        expected = MIGRATION_FIXTURE_CHAIN["expected"]
        units = {unit["id"]: unit for unit in migrated["work_units"]}
        for unit_id in expected["historical_unresolved"]:
            self.assertEqual(units[unit_id]["status"], "historical_unresolved")
        self.assertNotEqual(units[expected["active_root"]]["status"], "historical_unresolved")
        for item in migrated["requirements"]:
            self.assertNotEqual(item["status"], "pass")

    @unittest.expectedFailure
    def test_schema10_resume_policy_unique_and_tie(self) -> None:
        """0.12 target (documented_only): explicit resume reopens only a
        unique waiting candidate; missing or tied sequence numbers keep every
        candidate pending pending explicit selection."""
        unique = cg.migrate_state(
            json.loads(json.dumps(MIGRATION_FIXTURE_UNIQUE_WAITING["schema9_state"])),
            {"session_id": "baseline"},
        )
        units = {unit["id"]: unit for unit in unique["work_units"]}
        reopened = [
            unit_id
            for unit_id, unit in units.items()
            if unit.get("resume_pending_reopen") is True
        ]
        self.assertEqual(reopened, MIGRATION_FIXTURE_UNIQUE_WAITING["expected"]["resume_reopens"])
        tie = cg.migrate_state(
            json.loads(json.dumps(MIGRATION_FIXTURE_TIE["schema9_state"])),
            {"session_id": "baseline"},
        )
        tie_units = {unit["id"]: unit for unit in tie["work_units"]}
        for unit_id in MIGRATION_FIXTURE_TIE["expected"]["requires_explicit_selection"]:
            self.assertNotEqual(tie_units[unit_id].get("resume_pending_reopen"), True)


class ReplayLaneTests(BaselineTestCase):
    """Sanitized terminal-attempt replays of the three documented session
    chains (T1/T2/T3 in plan section 2.2). Synthetic data only; the private
    per-attempt review packets live in the maintainer corpus."""

    def test_replay_lane_t1_work_unit_debt_and_unbounded_feedback(self) -> None:
        """T1 lane (UX-01/UX-08): sequential requests leave every unit
        active, and a later correction lists IDs from earlier requests."""
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="baseline"):
            for index in range(1, 4):
                self.dispatch(
                    "UserPromptSubmit",
                    turn=f"turn-{index}",
                    prompt=f"独立请求 {index}:请修复对应条目。必须逐项落实。必须运行测试验证。",
                )
        self.dispatch(
            "PostToolUse",
            turn="turn-3",
            tool_name="shell",
            tool_input={"command": "python3 -m unittest"},
            tool_response={"exit_code": 0, "output": "OK"},
        )
        self.stage_disposition("deferred", turn="turn-3")
        blocked = self.dispatch(
            "Stop",
            turn="turn-3",
            last_assistant_message=EXTERNAL_WAIT_REPLY,
        )
        self.assertEqual(blocked.get("decision"), "block")
        reason = blocked["reason"]
        state = self.state()
        for item in state["requirements"] + state["acceptance_items"]:
            self.assertIn(item["id"], reason)
        self.assertTrue(
            all(unit["status"] == "active" for unit in state["work_units"])
        )

    def test_replay_lane_t2_checkpoint_failure_cascade(self) -> None:
        """T2 lane (UX-02): the staged checkpoint fails, the fallback
        disposition mismatches twice, and the third attempt hard-stops."""
        self.prompt_activated(ACTIVATING_PROMPT)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": "python3 -m unittest"},
            tool_response={"exit_code": 0, "output": "OK"},
        )
        state = self.state()
        evidence = self.evidence_id(state)
        requirements = [f"{item['id']}={evidence}" for item in state["requirements"]]
        with self.assertRaises(ValueError) as caught:
            cg.stage_private_checkpoint(
                self.root / "private",
                "baseline",
                "turn-1",
                "baseline",
                requirements,
                [],
            )
        self.assertIn("is missing", str(caught.exception))
        blocks = 0
        for disposition in ("deferred", "user_wait", "user_wait"):
            self.stage_disposition(disposition)
            result = self.dispatch("Stop", last_assistant_message=EXTERNAL_WAIT_REPLY)
            if result.get("decision") == "block":
                blocks += 1
            elif not result.get("continue", True):
                self.assertIn("two correction attempts", result.get("stopReason", ""))
                break
        self.assertEqual(blocks, 2)

    def test_replay_lane_t3_disposition_subclass_chain(self) -> None:
        """T3 lane (UX-03): deferred and user_wait declarations each draw a
        visible continuation against an externally-observed boundary; the
        matching external_wait declaration closes silently."""
        self.prompt_activated(ACTIVATING_PROMPT)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": "python3 -m unittest"},
            tool_response={"exit_code": 0, "output": "OK"},
        )
        outcomes = []
        for disposition in ("deferred", "user_wait", "external_wait"):
            self.stage_disposition(disposition)
            result = self.dispatch("Stop", last_assistant_message=EXTERNAL_WAIT_REPLY)
            outcomes.append(
                "block" if result.get("decision") == "block" else "silent"
            )
        self.assertEqual(outcomes, ["block", "block", "silent"])


if __name__ == "__main__":
    loader = unittest.TestLoader()
    # Load from THIS module instance so the row-level registry populated by
    # the run is the same object the summary below reads.
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    reproduction: dict[str, list[str]] = {}
    for test, _ in result.expectedFailures:
        family = getattr(test, "ux_family", None) or test.__class__.ux_family
        reproduction.setdefault(family or "unassigned", []).append(test.id())
    summary = {
        "baseline_suite": "context-guard-0.12-phase1",
        "decorator_expected_failures": {
            "count": len(result.expectedFailures),
            "by_family": {
                family: sorted(tests) for family, tests in sorted(reproduction.items())
            },
        },
        "row_level_fixture_results": {
            "count": len(ROW_LEVEL_REPORT),
            "rows": ROW_LEVEL_REPORT,
        },
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
        "failures": [test.id() for test, _ in result.failures],
        "errors": [test.id() for test, _ in result.errors],
        "skipped": [test.id() for test in result.skipped],
        "reproduced_families": sorted(reproduction),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    clean = (
        not result.failures
        and not result.errors
        and not result.unexpectedSuccesses
        and not result.skipped
    )
    raise SystemExit(0 if clean else 1)
