#!/usr/bin/env python3
"""Context Guard 0.12 Phase 3 conformance tests (Stop 3.0 + schema 10).

Current-behavior suite for the Phase 3 deliverable. Synthetic data only:
no real thread ids, no private prompts or transcripts, no credentials.

What this suite pins (frozen plan sections 4.2/4.3, 7.1-7.3):

* schema 9 -> 10 live migration: old active chains become
  historical_unresolved, pending items never become pass, the current
  root stays, and explicit resume follows the persisted last_active_seq
  policy (unique max reopens; ties/missing stay pending);
* sibling-root lifecycle: independent requests never chain; displaced
  units are archived as historical_unresolved and leave the default
  completion gate; an awaiting_user unit is reopened by the user's next
  prompt (lifecycle fact, not wording);
* ordinary terminal path: a verifiable whole completion auto-binds unique
  evidence and closes the current unit with NO private commands; ambiguous
  evidence keeps the unit open;
* canonical subject-readback adapter: fully qualified MCP tool names are
  canonical keys, trusted short names map through the explicit registry,
  unknown-namespace same-name tools stay adapter_identity_ambiguous and
  can never satisfy a proof; response echoes stay inert;
* the per-turn visible interruption budget is exactly one for Stop
  corrections (PreToolUse hard denies are budget-exempt), default
  feedback is <= 240 characters with no historical ID lists, and IDs
  stay available through the diagnose surface;
* sanitized T1/T2/T3 replay lanes hold at the 0.12 target behavior;
* the 0.12.0 structured authorization contract (cg_authority): one
  root-user statement of a semantic action authorizes it; targets are
  resolved and bound internally; ambiguity, drift, and out-of-scope
  qualifiers ask or refuse. (PreToolUse enforcement of this contract is
  Phase 4 scope and is intentionally not wired here.)
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard_phase3", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)

AUTHORITY_PATH = Path(__file__).resolve().parents[1] / "scripts" / "cg_authority.py"
AUTH_SPEC = importlib.util.spec_from_file_location("cg_authority_phase3", AUTHORITY_PATH)
assert AUTH_SPEC and AUTH_SPEC.loader
authority = importlib.util.module_from_spec(AUTH_SPEC)
AUTH_SPEC.loader.exec_module(authority)

# Synthetic thread uuids (never real session ids).
THREAD_IDS = [f"bb11{index}-c0de-4d5e-8f90-{index:012d}" for index in range(3)]
THREAD_URIS = [f"codex://threads/{value}" for value in THREAD_IDS]


class Phase3TestCase(unittest.TestCase):
    """Temp-state harness; dispatches hooks exactly like the host."""

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

    def dispatch(
        self, event: str, turn: str = "turn-1", session: str = "p3", **extra: object
    ) -> dict:
        payload = {
            "hook_event_name": event,
            "session_id": session,
            "cwd": str(self.project),
            "turn_id": turn,
        }
        payload.update(extra)
        return cg.dispatch(payload)

    def state(self, session: str = "p3") -> dict:
        path = self.root / "private" / "sessions" / session / "state.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def prompt(self, text: str, turn: str = "turn-1", session: str = "p3") -> None:
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="token"):
            self.dispatch("UserPromptSubmit", turn=turn, session=session, prompt=text)

    def unit(self, state: dict, unit_id: str) -> dict:
        return next(item for item in state["work_units"] if item["id"] == unit_id)


class Schema10MigrationConformanceTests(Phase3TestCase):
    """Live schema 9 -> 10 migration (CGR1-P2-C native path)."""

    def build_schema9_state(self) -> Path:
        """Create a real runtime state, then downgrade it to a schema-9
        chained ledger (per-prompt child units, v1 protocol) exactly as
        0.11.x would have written it."""
        self.prompt("请修复模块。必须逐项落实。必须运行测试验证。", turn="t1")
        self.prompt("请修复文档。必须逐项落实。必须运行测试验证。", turn="t2")
        session_dir = self.root / "private" / "sessions" / "p3"
        legacy = json.loads((session_dir / "state.json").read_text("utf-8"))
        units = legacy["work_units"]
        self.assertEqual(len(units), 2)
        units[0]["protocol_version"] = "1.0.0"
        units[1]["protocol_version"] = "1.0.0"
        units[1]["parent_id"] = units[0]["id"]
        for unit in units:
            unit.pop("last_active_seq", None)
            unit.pop("resume_pending_reopen", None)
        for key in ("status", "closed_at"):
            units[0][key] = "active" if key == "status" else None
        units[1]["status"] = "active"
        units[1]["closed_at"] = None
        legacy["work_state"]["active_work_unit_id"] = "WU0002"
        legacy["work_state"].pop("unit_activity_seq", None)
        legacy["schema_version"] = 9
        legacy["content_hash"] = cg.state_content_hash(legacy)
        (session_dir / "state.json").write_text(
            json.dumps(legacy, ensure_ascii=False), encoding="utf-8"
        )
        return session_dir

    def test_live_migration_isolates_chain_and_never_marks_pass(self) -> None:
        session_dir = self.build_schema9_state()
        migrated = cg.load_state(
            session_dir, {"session_id": "p3"}
        )
        self.assertEqual(migrated["schema_version"], 10)
        units = {item["id"]: item for item in migrated["work_units"]}
        self.assertEqual(units["WU0001"]["status"], "historical_unresolved")
        self.assertEqual(units["WU0002"]["status"], "active")
        self.assertIsNotNone(units["WU0001"]["closed_at"])
        for item in migrated["requirements"]:
            self.assertNotEqual(item["status"], "pass")
        # The migrated state round-trips through the schema-10 validator
        # once the next save recomputes its content hash.
        migrated["content_hash"] = cg.state_content_hash(migrated)
        cg.validate_state_integrity(migrated)

    def test_migrated_chain_leaves_the_default_completion_gate(self) -> None:
        session_dir = self.build_schema9_state()
        migrated = cg.load_state(session_dir, {"session_id": "p3"})
        scoped, ancestors = cg.checkpoint_scope_item_ids(migrated)
        historical_items = {
            item["id"]
            for item in migrated["requirements"]
            if item.get("work_unit_id") == "WU0001"
        }
        self.assertTrue(historical_items)
        self.assertEqual(historical_items & scoped, set())
        self.assertEqual(historical_items & ancestors, set())


class LifecycleConformanceTests(Phase3TestCase):
    """Sibling roots, displacement, parked units, and explicit resume."""

    def test_sibling_roots_and_displacement_to_historical(self) -> None:
        self.prompt("请处理第一项修复任务。必须逐项落实。必须运行测试验证。", turn="t1")
        self.prompt("请处理第二项修复任务。必须逐项落实。必须运行测试验证。", turn="t2")
        state = self.state()
        units = state["work_units"]
        self.assertEqual([unit["parent_id"] for unit in units], [None, None])
        self.assertEqual(units[0]["status"], "historical_unresolved")
        self.assertEqual(units[1]["status"], "active")
        self.assertEqual(state["requirements"][0]["status"], "pending")
        # Historical items stay auditable but leave the default gate.
        scoped, _ancestors = cg.checkpoint_scope_item_ids(state)
        self.assertNotIn("R001", scoped)
        self.assertIn("R002", scoped)

    def test_awaiting_user_is_reopened_by_the_user_reply(self) -> None:
        self.prompt("请修复模块。必须逐项落实。必须运行测试验证。", turn="t1")
        self.dispatch(
            "Stop",
            turn="t1",
            last_assistant_message="需要你先在方案 A 与方案 B 之间做出选择。",
        )
        state = self.state()
        self.assertEqual(state["work_units"][0]["status"], "awaiting_user")
        # The user answers the parked question: same unit, no new root.
        self.prompt(
            "选择方案 B;补充一条:必须同时更新文档。必须运行测试验证。", turn="t2"
        )
        state = self.state()
        self.assertEqual(len(state["work_units"]), 1)
        self.assertEqual(state["work_units"][0]["status"], "active")
        self.assertIsNone(state["work_units"][0]["closed_at"])
        self.assertEqual(len(state["requirements"]), 2)

    def test_awaiting_external_stays_parked_without_explicit_resume(self) -> None:
        self.prompt("请发布目录并等待外部审核。必须逐项落实。必须运行测试验证。", turn="t1")
        self.dispatch(
            "Stop",
            turn="t1",
            last_assistant_message="目录发布已完成,当前等待外部审核。",
        )
        self.assertEqual(self.state()["work_units"][0]["status"], "awaiting_external")
        # A plain new prompt opens a sibling root; the parked unit survives.
        self.prompt("另一件独立事项:请检查拼写。必须运行测试验证。", turn="t2")
        state = self.state()
        self.assertEqual(state["work_units"][0]["status"], "awaiting_external")
        self.assertEqual(state["work_units"][1]["status"], "active")

    def test_explicit_resume_reopens_the_unique_parked_unit(self) -> None:
        self.prompt("请发布目录并等待外部审核。必须逐项落实。必须运行测试验证。", turn="t1")
        self.dispatch(
            "Stop",
            turn="t1",
            last_assistant_message="目录发布已完成,当前等待外部审核。",
        )
        self.prompt("继续刚才的任务。", turn="t2")
        state = self.state()
        self.assertEqual(len(state["work_units"]), 1)
        self.assertEqual(state["work_units"][0]["status"], "active")
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0001")

    def test_resume_tie_requires_selection_and_stays_pending(self) -> None:
        self.prompt("初始任务:请检查拼写。必须运行测试验证。", turn="t1")
        state = self.state()
        # Fabricate two parked units with tied activity sequences.
        state["work_units"].extend(
            [
                {
                    "id": "WU0091",
                    "protocol_version": cg.WORK_UNIT_PROTOCOL_VERSION,
                    "prompt_id": "P0001",
                    "parent_id": None,
                    "kind": "general",
                    "status": "awaiting_user",
                    "created_at": "2026-01-01T00:00:00Z",
                    "closed_at": "2026-01-01T00:00:00Z",
                    "last_active_seq": 4,
                    "scope_sha256": "0" * 64,
                },
                {
                    "id": "WU0092",
                    "protocol_version": cg.WORK_UNIT_PROTOCOL_VERSION,
                    "prompt_id": "P0001",
                    "parent_id": None,
                    "kind": "general",
                    "status": "awaiting_external",
                    "created_at": "2026-01-01T00:00:00Z",
                    "closed_at": "2026-01-01T00:00:00Z",
                    "last_active_seq": 4,
                    "scope_sha256": "0" * 64,
                },
            ]
        )
        state["work_state"]["active_work_unit_id"] = None
        state["work_unit_sequence"] = 92
        session_dir = self.root / "private" / "sessions" / "p3"
        cg.save_state(session_dir, state)
        self.prompt("继续刚才的任务。", turn="t9")
        reloaded = self.state()
        statuses = {
            item["id"]: item["status"]
            for item in reloaded["work_units"]
            if item["id"] in {"WU0091", "WU0092"}
        }
        self.assertEqual(
            statuses, {"WU0091": "awaiting_user", "WU0092": "awaiting_external"}
        )
        self.assertEqual(
            reloaded["work_state"].get("resume_selection_required"),
            ["WU0091", "WU0092"],
        )
        # The resume attempt opened a fresh root; the tied candidates were
        # never auto-reopened.
        self.assertNotIn(
            reloaded["work_state"]["active_work_unit_id"], {"WU0091", "WU0092"}
        )


class OrdinaryTerminalCompletionTests(Phase3TestCase):
    """Auto evidence/disposition on the ordinary terminal path."""

    def build_single_read_task(self) -> Path:
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        # One deterministic requirement, no acceptance clauses: every item
        # in the unit is verifiable, so the ordinary terminal path can
        # auto-close it. The "$context-guard" prefix forces activation.
        self.prompt(
            f"$context-guard\n请先核对 {target} 后修复文档。",
            turn="t1",
        )
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": f"cat {target}"},
            tool_response={"exit_code": 0, "output": "subject"},
        )
        return target

    def test_unique_evidence_auto_closes_the_unit_without_commands(self) -> None:
        self.build_single_read_task()
        result = self.dispatch(
            "Stop", turn="t1", last_assistant_message="任务已经全部完成。"
        )
        # Verified completion: silent, unit completed, items pass, no
        # private commands were ever issued.
        self.assertEqual(result, {})
        state = self.state()
        unit = self.unit(state, "WU0001")
        self.assertEqual(unit["status"], "completed")
        self.assertIsNotNone(unit["closed_at"])
        self.assertTrue(
            all(item["status"] == "pass" for item in state["requirements"])
        )
        self.assertTrue(
            all(item["status"] == "pass" for item in state["acceptance_items"])
        )
        self.assertEqual(state["open_items"], [])
        self.assertIsNotNone(state.get("completion_checkpoint"))

    def test_ambiguous_evidence_keeps_the_unit_open_and_pending(self) -> None:
        self.build_single_read_task()
        # Duplicate the unique read: candidates are no longer unique.
        state = self.state()
        evidence = list(state["evidence"])
        second = dict(evidence[-1])
        second["id"] = "E9999"
        state["evidence"].append(second)
        state["evidence_sequence"] = 9999
        cg.save_state(self.root / "private" / "sessions" / "p3", state)
        result = self.dispatch(
            "Stop", turn="t1", last_assistant_message="任务已经全部完成。"
        )
        self.assertEqual(result.get("decision"), "block")
        self.assertLessEqual(len(result["reason"]), 240)
        # Acceptance-D: the default feedback is anonymous - it never names
        # a work-unit/requirement/acceptance/evidence ID.
        self.assertNotRegex(result["reason"], r"\b(?:WU|R|A|E)\d{3,}\b")
        self.assertIn("1 unverified item", result["reason"])
        # The whole-completion claim never closed anything.
        self.assertEqual(self.state()["work_units"][0]["status"], "active")
        self.assertIsNone(self.state().get("completion_checkpoint"))

    def test_second_correction_is_silent_and_pending_is_preserved(self) -> None:
        self.build_single_read_task()
        state = self.state()
        second = dict(state["evidence"][-1])
        second["id"] = "E9999"
        state["evidence"].append(second)
        state["evidence_sequence"] = 9999
        cg.save_state(self.root / "private" / "sessions" / "p3", state)
        first = self.dispatch(
            "Stop", turn="t1", last_assistant_message="任务已经全部完成。"
        )
        self.assertEqual(first.get("decision"), "block")
        second = self.dispatch(
            "Stop", turn="t1", last_assistant_message="任务已经全部完成。"
        )
        self.assertEqual(second, {})
        reloaded = self.state()
        self.assertEqual(reloaded["work_units"][0]["status"], "active")
        self.assertTrue(reloaded["open_items"])
        self.assertEqual(
            reloaded["decision_log"][-1]["reason_codes"][-1],
            "wrong_whole_completion",
        )
        self.assertIn(
            "visible_interruption_budget_exhausted",
            reloaded["decision_log"][-1]["reason_codes"],
        )


class AdapterReadbackConformanceTests(Phase3TestCase):
    """Joint Skill-file + three-thread readback; identity ambiguity."""

    def joint_read_prompt(self) -> str:
        skill_file = self.project / "SKILL.md"
        skill_file.write_text("skill body", encoding="utf-8")
        threads = "、".join(THREAD_URIS)
        # The "$context-guard" prefix forces activation; no "必须 ..." clauses
        # keeps every acceptance item out, because an acceptance item without
        # a deterministic contract is legacy and intentionally cannot
        # auto-close.
        return (
            "$context-guard\n"
            f"请先读取 {skill_file} 与 {threads} 中的决定,再修复对应脚本。"
        )

    def test_windows_shell_read_preserves_drive_path_backslashes(self) -> None:
        target = r"E:\work\spec.txt"
        expected = {
            item["id"]
            for item in cg.prompt_subjects(target, include_threads=False)
            if item["kind"] == "path"
        }
        self.assertEqual(
            set(cg._read_command_subject_ids(f"cat {target}", windows=True)),
            expected,
        )

    def test_windows_shell_read_strips_matching_path_quotes(self) -> None:
        target = r"E:\work\spec.txt"
        expected = {
            item["id"]
            for item in cg.prompt_subjects(target, include_threads=False)
            if item["kind"] == "path"
        }
        for quoted in (f"'{target}'", f'"{target}"'):
            with self.subTest(quoted=quoted[0]):
                self.assertEqual(
                    set(
                        cg._read_command_subject_ids(
                            f"cat {quoted}", windows=True
                        )
                    ),
                    expected,
                )
        self.assertEqual(
            cg._read_command_subject_ids(f"cat '{target}", windows=True),
            [],
        )

    def perform_joint_reads(self) -> None:
        skill_file = self.project / "SKILL.md"
        self.dispatch(
            "PostToolUse",
            tool_name="Read",
            tool_input={"file_path": str(skill_file)},
            tool_response={"exit_code": 0, "output": "skill body"},
        )
        for index, thread_id in enumerate(THREAD_IDS):
            self.dispatch(
                "PostToolUse",
                turn="turn-1",
                tool_name="mcp__codex_app__read_thread",
                tool_input={"threadId": thread_id},
                tool_response={"exit_code": 0, "output": "thread decision"},
            )
            del index

    def test_joint_skill_and_thread_readback_auto_closes(self) -> None:
        self.prompt(self.joint_read_prompt())
        self.perform_joint_reads()
        state = self.state()
        contract = state["requirements"][0]["verification_contract"]
        self.assertEqual(contract["mode"], "enforced")
        self.assertEqual(
            [item["kind"] for item in contract["obligations"]],
            ["subject_readback"],
        )
        required = set(contract["obligations"][0]["subject_ids"])
        self.assertEqual(len(required), 4)
        bound: set[str] = set()
        for evidence in state["evidence"]:
            bound |= set(evidence["readback_subjects"])
        self.assertEqual(bound, required)
        result = self.dispatch(
            "Stop", turn="turn-1", last_assistant_message="任务已经全部完成。"
        )
        self.assertEqual(result, {})
        state = self.state()
        self.assertEqual(state["work_units"][0]["status"], "completed")
        self.assertEqual(state["open_items"], [])

    def test_unknown_namespace_thread_read_is_ambiguous_and_inert(self) -> None:
        self.prompt(self.joint_read_prompt())
        self.dispatch(
            "PostToolUse",
            tool_name="mcp__unrelated_vendor__read_thread",
            tool_input={"threadId": THREAD_IDS[0]},
            tool_response={"exit_code": 0, "output": "thread decision"},
        )
        state = self.state()
        evidence = state["evidence"][-1]
        self.assertEqual(evidence["adapter_identity"], "adapter_identity_ambiguous")
        # No readback binding and no thread subject anywhere: the ambiguous
        # identity records evidence but can never satisfy a proof.
        self.assertEqual(evidence["readback_subjects"], [])
        self.assertNotIn(
            cg.thread_subject_item(THREAD_URIS[0])["id"],
            evidence["subject_ids"],
        )

    def test_thread_echo_in_response_text_never_binds(self) -> None:
        self.prompt(self.joint_read_prompt())
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": f"echo {THREAD_URIS[0]}"},
            tool_response={"exit_code": 0, "output": THREAD_URIS[0]},
        )
        evidence = self.state()["evidence"][-1]
        self.assertNotIn(
            cg.thread_subject_item(THREAD_URIS[0])["id"],
            evidence["subject_ids"],
        )
        self.assertEqual(evidence["readback_subjects"], [])


class ClosedWorldAdapterRegistryTests(Phase3TestCase):
    """P1-A: the adapter registry is a closed world.

    Table-driven negative controls through the REAL PostToolUse hook: only
    registered tools generate readback_subjects. No suffix, substring, or
    wildcard trust exists; an unregistered name never binds under any
    namespace.
    """

    TABLE = [
        # (tool_name, binding expected?)
        ("mcp__codex_app__read_thread", True),  # trusted full name
        ("read_thread", True),  # explicit bare short name
        ("mcp__unknownsvc__read_thread", False),  # known short, unknown ns
        ("mcp__codex_app__evil_read_file", False),  # trusted ns, unregistered short
        ("evil_read_file", False),  # unregistered bare name
        ("server_read_text_file", False),  # legacy suffix form, not registered
    ]

    @staticmethod
    def thread_prompt() -> str:
        return (
            "$context-guard\n"
            f"请先读取 {THREAD_URIS[0]} 中的决定,再修复对应脚本。"
            "必须逐条落实其中决定。"
        )

    def test_post_tool_use_binding_table(self) -> None:
        thread_subject = cg.thread_subject_item(THREAD_URIS[0])["id"]
        for index, (tool_name, should_bind) in enumerate(self.TABLE):
            with self.subTest(tool_name=tool_name):
                session = f"closed-world-{index}"
                with mock.patch.object(
                    cg.secrets, "token_urlsafe", return_value="token"
                ):
                    self.dispatch(
                        "UserPromptSubmit",
                        turn="turn-1",
                        session=session,
                        prompt=self.thread_prompt(),
                    )
                self.dispatch(
                    "PostToolUse",
                    turn="turn-1",
                    session=session,
                    tool_name=tool_name,
                    tool_input={"threadId": THREAD_IDS[0]},
                    tool_response={"exit_code": 0, "output": "thread decision"},
                )
                evidence = self.state(session)["evidence"][-1]
                self.assertEqual(
                    evidence["tool"],
                    tool_name,
                    "evidence is recorded for every tool, binding is not",
                )
                if should_bind:
                    self.assertIn(thread_subject, evidence["readback_subjects"])
                    self.assertIn(thread_subject, evidence["subject_ids"])
                else:
                    self.assertEqual(evidence["readback_subjects"], [])
                    self.assertNotIn(thread_subject, evidence["subject_ids"])
                if tool_name == "mcp__unknownsvc__read_thread":
                    self.assertEqual(
                        evidence["adapter_identity"], "adapter_identity_ambiguous"
                    )

    def test_registry_canonical_keys_are_the_exact_cross_product(self) -> None:
        for adapter, spec in cg.stop3().ADAPTER_REGISTRY.items():
            expected = {
                f"mcp__{namespace}__{short}"
                for namespace in spec["trusted_namespaces"]
                for short in spec["trusted_short_names"]
            }
            self.assertEqual(spec["canonical_tools"], expected)
            self.assertNotIn("trusted_short_suffixes", spec)

    def test_file_read_alias_surface_mirrors_the_registry(self) -> None:
        # The diagnostic surface must be derived from the closed-world
        # registry, never an independent wildcard-capable list.
        self.assertEqual(
            set(cg.FILE_READ_TOOL_ALIASES),
            set(cg.stop3().ADAPTER_REGISTRY["file_read"]["trusted_short_names"]),
        )


class MatcherIdentityBindingTests(Phase3TestCase):
    """P1-B: evaluate_reason binds item identity across all three inputs.

    The coordinator's independent counterexample: projection.item.id=R2
    with item_id=binding.itemId=R1 and one unique evidence record used to
    return ``fulfilled``. Identity must now be exact and tripartite;
    missing or conflicting values yield one stable invalid-binding reason
    (never silently evaluated, never conflated with unknown_obligation).
    """

    @staticmethod
    def projection_for(item_id: str, evidence: list[dict]) -> dict:
        return {
            "item": {
                "id": item_id,
                "verification_contract": {
                    "mode": "enforced",
                    "obligations": [
                        {
                            "id": f"O-{item_id}-001",
                            "kind": "subject_readback",
                            "surface": "artifact",
                            "subject_ids": ["subject:abc"],
                            "operation": "modify",
                            "requested_surface": "artifact",
                        }
                    ],
                },
            },
            "evidence": evidence,
        }

    @staticmethod
    def unique_evidence() -> list[dict]:
        return [
            {"id": "E0001", "outcome": "success", "readback_subjects": ["subject:abc"]},
        ]

    def expected_fulfilled(self, item_id: str) -> dict:
        return {
            "outcome": "fulfilled",
            "reason_code": "unique_deterministic_evidence",
            "obligation": f"O-{item_id}-001",
            "selected_evidence": ["E0001"],
        }

    def test_cross_item_identity_conflict_is_never_fulfilled(self) -> None:
        result = cg.evaluate_reason(
            "R001",
            {"itemId": "R001", "evidenceIds": ["E0001"]},
            self.projection_for("R002", self.unique_evidence()),
        )
        self.assertEqual(
            result,
            {
                "outcome": "invalid_binding",
                "reason_code": "item_identity_conflict",
                "obligation": "",
                "selected_evidence": [],
            },
        )

    def test_missing_identity_leg_is_a_conflict(self) -> None:
        for item_id, binding in (
            ("", {"itemId": "R001", "evidenceIds": ["E0001"]}),
            (None, {"itemId": "R001", "evidenceIds": ["E0001"]}),
            ("R001", {"evidenceIds": ["E0001"]}),
            ("R001", None),
        ):
            with self.subTest(item_id=item_id, binding=binding):
                result = cg.evaluate_reason(
                    item_id, binding, self.projection_for("R001", self.unique_evidence())
                )
                self.assertEqual(result["reason_code"], "item_identity_conflict")
                self.assertEqual(result["outcome"], "invalid_binding")

    def test_projection_without_item_id_is_a_conflict(self) -> None:
        projection = {
            "item": {"verification_contract": {"mode": "enforced", "obligations": []}},
            "evidence": self.unique_evidence(),
        }
        result = cg.evaluate_reason(
            "R001", {"itemId": "R001", "evidenceIds": ["E0001"]}, projection
        )
        self.assertEqual(result["reason_code"], "item_identity_conflict")

    def test_conflict_is_stable_across_repeat_permutation_and_concurrency(self) -> None:
        import concurrent.futures

        conflicting = lambda: cg.evaluate_reason(  # noqa: E731
            "R001",
            {"itemId": "R001", "evidenceIds": ["E0001"]},
            self.projection_for("R002", list(reversed(self.unique_evidence()))),
        )
        baseline = json.dumps(conflicting(), sort_keys=True)
        repeats = {json.dumps(conflicting(), sort_keys=True) for _ in range(3)}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            concurrent_results = list(pool.map(lambda _: conflicting(), range(8)))
        concurrent_normalized = {
            json.dumps(item, sort_keys=True) for item in concurrent_results
        }
        self.assertEqual(repeats, {baseline})
        self.assertEqual(concurrent_normalized, {baseline})

    def test_consistent_identity_with_unique_evidence_still_fulfills(self) -> None:
        """Reachable recovery positive: aligning the three identities (and
        keeping the unique evidence) closes the obligation."""
        for item_id in ("R001", "R002"):
            result = cg.evaluate_reason(
                item_id,
                {"itemId": item_id, "evidenceIds": ["E0001"]},
                self.projection_for(item_id, self.unique_evidence()),
            )
            self.assertEqual(result, self.expected_fulfilled(item_id))

    def test_production_caller_consumes_the_invariant(self) -> None:
        """The production scoped-state builder passes tripartite identity by
        construction and surfaces per-obligation reason codes."""
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        self.prompt(
            f"$context-guard\n请先核对 {target} 后修复文档。", turn="turn-1"
        )
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": f"cat {target}"},
            tool_response={"exit_code": 0, "output": "subject"},
        )
        state = self.state()
        scoped, _ancestors = cg.checkpoint_scope_item_ids(state)
        states = cg._scoped_obligation_states(state, scoped)
        self.assertTrue(states)
        self.assertEqual(set(states.values()), {"unique_deterministic_evidence"})


class MatcherProjectionIntegrityTests(Phase3TestCase):
    """P1-B2: canonical-projection integrity closure, table-driven.

    Any malformed or ambiguous projection is rejected with a single
    order-independent reason BEFORE matching, so no permutation, repeat,
    or concurrent evaluation can turn it into ``fulfilled``. The
    coordinator's counterexample family: one projection carrying E1
    success and E1 failure resolved order-dependently (last-wins dict).
    """

    CONTRACT = {
        "mode": "enforced",
        "obligations": [
            {
                "id": "O-R001-001",
                "kind": "subject_readback",
                "surface": "artifact",
                "subject_ids": ["subject:abc"],
                "operation": "modify",
                "requested_surface": "artifact",
            }
        ],
    }
    UNIQUE = {"id": "E0001", "outcome": "success", "readback_subjects": ["subject:abc"]}

    def projection(self, evidence, obligations=None):
        contract = dict(self.CONTRACT)
        if obligations is not None:
            contract["obligations"] = obligations
        return {"item": {"id": "R001", "verification_contract": contract}, "evidence": evidence}

    def binding(self, evidence_ids=("E0001",)):
        return {"itemId": "R001", "evidenceIds": list(evidence_ids)}

    def evaluate(self, evidence, evidence_ids=("E0001",), obligations=None):
        return cg.evaluate_reason(
            "R001", self.binding(evidence_ids), self.projection(evidence, obligations)
        )

    def test_duplicate_evidence_identity_table(self) -> None:
        rows = [
            (
                "same-value duplicate",
                [dict(self.UNIQUE), dict(self.UNIQUE)],
                ["E0001"],
            ),
            (
                "conflicting duplicate (coordinator counterexample)",
                [
                    dict(self.UNIQUE),
                    dict(self.UNIQUE, outcome="failed"),
                ],
                ["E0001"],
            ),
            (
                "duplicate in binding references",
                [dict(self.UNIQUE)],
                ["E0001", "E0001"],
            ),
        ]
        for label, evidence, evidence_ids in rows:
            with self.subTest(row=label):
                forward = self.evaluate(evidence, evidence_ids)
                backward = self.evaluate(list(reversed(evidence)), evidence_ids)
                for result in (forward, backward):
                    self.assertEqual(result["outcome"], "invalid_binding", label)
                    self.assertEqual(
                        result["reason_code"],
                        "duplicate_evidence_identity",
                        label,
                    )
                    self.assertEqual(result, forward, label)

    def test_missing_or_empty_evidence_identity_table(self) -> None:
        rows = [
            ("record without id", [{"outcome": "success"}]),
            ("record with empty id", [{"id": "", "outcome": "success"}]),
            ("non-dict record", ["E0001"]),
            ("empty id in binding references", [dict(self.UNIQUE)]),
        ]
        for label, evidence in rows[:3]:
            with self.subTest(row=label):
                result = self.evaluate(evidence)
                self.assertEqual(result["reason_code"], "evidence_identity_missing")
                self.assertEqual(result["outcome"], "invalid_binding")
        with self.subTest(row="empty id in binding references"):
            result = self.evaluate([dict(self.UNIQUE)], evidence_ids=[""])
            self.assertEqual(result["reason_code"], "evidence_identity_missing")

    def test_unknown_binding_reference_has_dedicated_reason(self) -> None:
        result = self.evaluate([dict(self.UNIQUE)], evidence_ids=["E9999"])
        self.assertEqual(result["outcome"], "invalid_binding")
        self.assertEqual(result["reason_code"], "unknown_evidence_reference")

    def test_duplicate_and_malformed_obligation_records(self) -> None:
        duplicate = [
            dict(self.CONTRACT["obligations"][0]),
            dict(self.CONTRACT["obligations"][0]),
        ]
        result = self.evaluate([dict(self.UNIQUE)], obligations=duplicate)
        self.assertEqual(result["outcome"], "invalid_binding")
        self.assertEqual(result["reason_code"], "duplicate_obligation_identity")
        for malformed in ([{"kind": "subject_readback"}], ["not-a-dict"]):
            with self.subTest(malformed=malformed):
                result = self.evaluate([dict(self.UNIQUE)], obligations=malformed)
                self.assertEqual(result["outcome"], "invalid_binding")
                self.assertEqual(
                    result["reason_code"], "malformed_obligation_record"
                )

    def test_integrity_reasons_survive_permutation_and_concurrency(self) -> None:
        import concurrent.futures

        conflicting = [
            dict(self.UNIQUE),
            dict(self.UNIQUE, outcome="failed"),
        ]
        runs = lambda: [  # noqa: E731
            self.evaluate(conflicting),
            self.evaluate(list(reversed(conflicting))),
        ]
        baseline = [json.dumps(item, sort_keys=True) for item in runs()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            concurrent_results = list(pool.map(lambda _: runs(), range(8)))
        flattened = {
            json.dumps(item, sort_keys=True)
            for batch in concurrent_results
            for item in batch
        }
        self.assertEqual(set(baseline), flattened)
        self.assertEqual(len(flattened), 1)
        self.assertIn("duplicate_evidence_identity", flattened.pop())

    def test_clean_projection_recovery_positive(self) -> None:
        """Reachable recovery: removing the duplicate record closes the
        obligation with the unique remaining evidence."""
        result = self.evaluate([dict(self.UNIQUE)])
        self.assertEqual(
            result,
            {
                "outcome": "fulfilled",
                "reason_code": "unique_deterministic_evidence",
                "obligation": "O-R001-001",
                "selected_evidence": ["E0001"],
            },
        )


class VerificationContractIntegrityTests(Phase3TestCase):
    """P1-B3: single canonical verification-contract validator.

    The matcher and the runtime state-integrity check share one closed
    world (cg_stop3.obligations_reason / evidence_record_reason): an
    enforced contract with an empty, unknown-kind, illegal-surface, or
    empty-subject obligation can never reach ``fulfilled`` through the
    matcher, and a persisted state carrying one fails the integrity gate
    instead of silently satisfying the completion check.
    """

    def projection(self, obligations, evidence=None, evidence_ids=None):
        return {
            "item": {
                "id": "R001",
                "verification_contract": {
                    "mode": "enforced",
                    "obligations": obligations,
                },
            },
            "evidence": evidence or [],
        }

    def evaluate(self, obligations, evidence=None):
        evidence_ids = [str(item["id"]) for item in (evidence or []) if isinstance(item, dict)]
        return cg.evaluate_reason(
            "R001",
            {"itemId": "R001", "evidenceIds": evidence_ids},
            self.projection(obligations, evidence),
        )

    MALFORMED_TABLE = [
        (
            "empty enforced obligations",
            [],
            "empty_enforced_obligations",
        ),
        (
            "unknown kind with empty subjects (coordinator counterexample)",
            [{"id": "O1", "kind": "wibble", "surface": "artifact", "subject_ids": []}],
            "unknown_obligation_kind",
        ),
        (
            "thread surface subject_readback (coordinator counterexample)",
            [{"id": "O1", "kind": "subject_readback", "surface": "thread", "subject_ids": []}],
            "illegal_obligation_surface",
        ),
        (
            "empty subject_ids on a registered combo",
            [{"id": "O1", "kind": "subject_readback", "surface": "artifact", "subject_ids": []}],
            "malformed_subject_ids",
        ),
        (
            "duplicate subject_ids",
            [{
                "id": "O1",
                "kind": "subject_readback",
                "surface": "artifact",
                "subject_ids": ["subject:abc", "subject:abc"],
            }],
            "malformed_subject_ids",
        ),
        (
            "scope coverage with malformed digest",
            [{
                "id": "O1",
                "kind": "scope_coverage",
                "surface": "scope",
                "subject_ids": ["subject:abc"],
                "expected_scope_count": 1,
                "expected_scope_sha256": "nothex",
            }],
            "malformed_scope_expectation",
        ),
        (
            "scope coverage with zero count",
            [{
                "id": "O1",
                "kind": "scope_coverage",
                "surface": "scope",
                "subject_ids": ["subject:abc"],
                "expected_scope_count": 0,
            }],
            "malformed_scope_expectation",
        ),
        (
            "obligation record without id",
            [{"kind": "subject_readback", "surface": "artifact", "subject_ids": ["subject:abc"]}],
            "malformed_obligation_record",
        ),
    ]

    def test_malformed_obligation_table_is_order_stable(self) -> None:
        import concurrent.futures

        for label, obligations, expected_reason in self.MALFORMED_TABLE:
            with self.subTest(row=label):
                forward = self.evaluate(obligations)
                self.assertEqual(forward["outcome"], "invalid_binding", label)
                self.assertEqual(forward["reason_code"], expected_reason, label)
                reversed_rows = list(reversed(obligations))
                backward = self.evaluate(reversed_rows)
                self.assertEqual(backward, forward, label)
        # The whole malformed table is stable under concurrency.
        def row_digests(row):
            first = json.dumps(self.evaluate(row[1]), sort_keys=True)
            second = json.dumps(
                self.evaluate(list(reversed(row[1]))), sort_keys=True
            )
            return first, second

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(row_digests, self.MALFORMED_TABLE))
        for first, second in results:
            self.assertEqual(first, second)

    UNIQUE_EVIDENCE = {"id": "E0001", "outcome": "success", "readback_subjects": ["subject:abc"]}

    def test_underivable_scope_stays_pending_and_never_fulfilled(self) -> None:
        """A schema-legal scope expectation without a derivable digest is
        production-shaped; the matcher keeps it pending (fail closed) and
        never fulfills it — with or without evidence, in any order."""
        rows = [
            [{"id": "O1", "kind": "scope_coverage", "surface": "scope", "subject_ids": []}],
            [{
                "id": "O1",
                "kind": "scope_coverage",
                "surface": "scope",
                "subject_ids": ["subject:abc"],
                "expected_scope_count": 1,
            }],
            [{
                "id": "O1",
                "kind": "scope_coverage",
                "surface": "scope",
                "subject_ids": ["subject:abc"],
                "expected_scope_count": 1,
                "expected_scope_sha256": None,
            }],
        ]
        for index, obligations in enumerate(rows):
            for evidence in ([], [dict(self.UNIQUE_EVIDENCE)]):
                with self.subTest(row=index, evidence=len(evidence)):
                    result = self.evaluate(obligations, evidence=evidence)
                    self.assertEqual(result["outcome"], "pending")
                    self.assertNotEqual(
                        result["reason_code"], "unique_deterministic_evidence"
                    )

    def test_clean_contract_recovery_positive(self) -> None:
        obligations = [
            {
                "id": "O-R001-001",
                "kind": "subject_readback",
                "surface": "artifact",
                "subject_ids": ["subject:abc"],
                "operation": "modify",
                "requested_surface": "artifact",
            }
        ]
        result = self.evaluate(
            obligations,
            evidence=[
                {"id": "E0001", "outcome": "success", "readback_subjects": ["subject:abc"]}
            ],
        )
        self.assertEqual(
            result,
            {
                "outcome": "fulfilled",
                "reason_code": "unique_deterministic_evidence",
                "obligation": "O-R001-001",
                "selected_evidence": ["E0001"],
            },
        )

    def test_malformed_evidence_records_are_rejected(self) -> None:
        obligations = self.MALFORMED_TABLE[3][1]
        rows = (
            ("bogus outcome", [{"id": "E0001", "outcome": "weird"}], "malformed_evidence_record"),
            ("non-dict record", ["E0001"], "evidence_identity_missing"),
        )
        for label, evidence, expected in rows:
            with self.subTest(row=label):
                result = self.evaluate(obligations, evidence=evidence)
                self.assertEqual(result["outcome"], "invalid_binding", label)
                self.assertEqual(result["reason_code"], expected, label)

    def test_persistent_empty_obligation_never_enters_terminal_approval(self) -> None:
        """Real dispatch negative: a persisted state whose enforced
        contract was corrupted to zero obligations fails the integrity
        gate on load; the completion claim cannot close anything."""
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        self.prompt(f"$context-guard\n请先核对 {target} 后修复文档。", turn="t1")
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": f"cat {target}"},
            tool_response={"exit_code": 0, "output": "subject"},
        )
        session_dir = self.root / "private" / "sessions" / "p3"
        tampered = json.loads((session_dir / "state.json").read_text("utf-8"))
        contract = tampered["requirements"][0]["verification_contract"]
        self.assertEqual(contract["mode"], "enforced")
        contract["obligations"] = []
        tampered["content_hash"] = cg.state_content_hash(tampered)
        (session_dir / "state.json").write_text(
            json.dumps(tampered, ensure_ascii=False), encoding="utf-8"
        )
        result = self.dispatch(
            "Stop", turn="t1", last_assistant_message="任务已经全部完成。"
        )
        reloaded = self.state()
        # The integrity gate recovered from prompts: no item was marked
        # pass, no unit closed, no completion checkpoint exists.
        self.assertNotEqual(
            reloaded["decision_log"][-1].get("outcome"), "auto_complete_verified"
        )
        self.assertIsNone(reloaded.get("completion_checkpoint"))
        self.assertEqual(reloaded["work_units"][0]["status"], "active")
        for item in reloaded["requirements"]:
            self.assertNotEqual(item["status"], "pass")
        self.assertTrue(
            reloaded["integrity"]["status"] in {"recovered_from_prompts", "failed"}
        )
        del result

    def test_persistent_unknown_kind_obligation_fails_integrity(self) -> None:
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        self.prompt(f"$context-guard\n请先核对 {target} 后修复文档。", turn="t1")
        session_dir = self.root / "private" / "sessions" / "p3"
        tampered = json.loads((session_dir / "state.json").read_text("utf-8"))
        contract = tampered["requirements"][0]["verification_contract"]
        contract["obligations"] = [
            {"id": "O1", "kind": "wibble", "surface": "artifact", "subject_ids": []}
        ]
        tampered["content_hash"] = cg.state_content_hash(tampered)
        (session_dir / "state.json").write_text(
            json.dumps(tampered, ensure_ascii=False), encoding="utf-8"
        )
        reloaded = cg.load_state(session_dir, {"session_id": "p3"})
        self.assertEqual(reloaded["integrity"]["status"], "recovered_from_prompts")
        for item in reloaded["requirements"]:
            self.assertNotEqual(item["status"], "pass")


class Stop3BudgetAndFeedbackTests(Phase3TestCase):
    """Budget=1 per turn, bounded feedback, PreToolUse exemption."""

    PERSISTENCE_PROMPT = (
        "请修复模块、修复文档、修复测试三件事。必须逐项落实。必须运行测试验证。"
        "不要停止,一直推进直到完成。"
    )
    ASSISTANT_REPLY = "我会继续修复模块和文档,并运行测试。"

    def test_budget_is_one_and_pretool_deny_is_exempt(self) -> None:
        self.prompt(self.PERSISTENCE_PROMPT)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": "python3 -m unittest"},
            tool_response={"exit_code": 0, "output": "OK"},
        )
        blocks = 0
        for _ in range(4):
            result = self.dispatch(
                "Stop", turn="turn-1", last_assistant_message=self.ASSISTANT_REPLY
            )
            if result.get("decision") == "block":
                blocks += 1
                self.assertLessEqual(len(result["reason"]), 240)
                self.assertNotIn("R001", result["reason"])
        self.assertEqual(blocks, 1)
        # A real high-risk action with no authorization is still denied on
        # every attempt; the Stop budget never silences it.
        for _ in range(2):
            denied = self.dispatch(
                "PreToolUse",
                turn="turn-1",
                tool_name="shell",
                tool_input={"command": "git tag v9.9.9"},
            )
            self.assertEqual(
                denied["hookSpecificOutput"]["permissionDecision"], "deny"
            )

    def test_t2_lane_target_staged_failure_never_cascades(self) -> None:
        self.prompt("请修复模块。必须逐项落实。必须运行测试验证。", turn="t1")
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": "python3 -m unittest"},
            tool_response={"exit_code": 0, "output": "OK"},
        )
        state = self.state()
        evidence = f"E{state['evidence_sequence']:04d}"
        with self.assertRaises(ValueError):
            cg.stage_private_checkpoint(
                self.root / "private",
                "p3",
                "t1",
                "token",
                [f"{item['id']}={evidence}" for item in state["requirements"]],
                [],
            )
        outcomes = []
        for disposition in ("deferred", "user_wait", "external_wait"):
            cg.stage_private_disposition(
                self.root / "private", "p3", "t1", "token", disposition, replace=True
            )
            result = self.dispatch(
                "Stop",
                turn="t1",
                last_assistant_message="目录发布已完成,当前等待外部审核。",
            )
            outcomes.append("block" if result.get("decision") == "block" else "silent")
        # UX-02/UX-03 target: the sub-class chain never cascades.
        self.assertEqual(outcomes, ["silent", "silent", "silent"])
        self.assertEqual(self.state()["work_units"][0]["status"], "awaiting_external")

    def test_t1_lane_target_bounded_units_and_feedback(self) -> None:
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="token"):
            for index in range(1, 4):
                self.dispatch(
                    "UserPromptSubmit",
                    turn=f"turn-{index}",
                    prompt=(
                        f"独立请求 {index}:请修复对应条目。必须逐项落实。必须运行测试验证。"
                    ),
                )
        self.dispatch(
            "PostToolUse",
            turn="turn-3",
            tool_name="shell",
            tool_input={"command": "python3 -m unittest"},
            tool_response={"exit_code": 0, "output": "OK"},
        )
        cg.stage_private_disposition(
            self.root / "private", "p3", "turn-3", "token", "deferred", replace=True
        )
        blocked = self.dispatch(
            "Stop",
            turn="turn-3",
            last_assistant_message="目录发布已完成,当前等待外部审核。",
        )
        state = self.state()
        # UX-01/UX-08 target: history is archived, the current unit closes,
        # and the default feedback stays bounded with no historical IDs.
        self.assertEqual(blocked, {})
        self.assertEqual(state["work_units"][0]["status"], "historical_unresolved")
        self.assertEqual(state["work_units"][1]["status"], "historical_unresolved")
        # The reply's structured external-wait facts outrank the staged
        # deferred sub-class (UX-03 target): the unit closes awaiting_external.
        self.assertEqual(state["work_units"][2]["status"], "awaiting_external")
        for item in state["requirements"]:
            self.assertNotEqual(item["status"], "pass")

    def test_default_status_stays_under_4kib_after_120_turns(self) -> None:
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="token"):
            for index in range(1, 122):
                self.dispatch(
                    "UserPromptSubmit",
                    turn=f"turn-{index}",
                    prompt=f"批量任务第 {index} 步:请修复对应条目。必须运行测试验证。",
                )
        state = self.state()
        self.assertEqual(len(state["work_units"]), 121)
        self.assertEqual(state["work_units"][-1]["status"], "active")
        self.assertEqual(state["work_units"][0]["status"], "historical_unresolved")
        status = cg.status_context(state)
        self.assertLess(len(status.encode("utf-8")), 4096)

    def test_default_feedback_is_anonymous_and_audit_keeps_ids(self) -> None:
        self.prompt(self.PERSISTENCE_PROMPT, turn="t1")
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": "python3 -m unittest"},
            tool_response={"exit_code": 0, "output": "OK"},
        )
        blocked = self.dispatch(
            "Stop", turn="t1", last_assistant_message=self.ASSISTANT_REPLY
        )
        self.assertEqual(blocked.get("decision"), "block")
        # Acceptance-D: anonymous default feedback - no unit/item IDs, no
        # reason-code tokens.
        self.assertNotRegex(blocked["reason"], r"\b(?:WU|R|A|E)\d{3,}\b")
        self.assertNotIn("explicit_user_persistence", blocked["reason"])
        self.assertIn("2 unverified items", blocked["reason"])
        # The diagnose/full surfaces keep the exact IDs and reason codes.
        state = self.state()
        diagnose = json.dumps(state.get("decision_log", []), ensure_ascii=False)
        self.assertIn("explicit_user_persistence", diagnose)
        full = cg.checkpoint_status_snapshot(state, "t1", full=True)
        item_ids = [
            item["id"]
            for key in ("requirements", "acceptance")
            for item in full[key]
        ]
        self.assertIn("R001", item_ids)

    def test_assistant_pending_actions_is_recorded_on_silent_end(self) -> None:
        self.prompt(
            "请修复模块、修复文档、修复测试三件事。必须逐项落实。必须运行测试验证。",
            turn="t1",
        )
        self.dispatch(
            "Stop",
            turn="t1",
            last_assistant_message="我会继续修复模块和文档,并运行测试。",
        )
        latest = self.state()["decision_log"][-1]
        self.assertEqual(latest["outcome"], "silent_end_assistant_pending_actions")
        self.assertIn("assistant_pending_actions", latest["reason_codes"])
        self.assertEqual(self.state()["continuation_attempts"], 0)


class AuthorizationContractTests(Phase3TestCase):
    """0.12.0 structured authorization contract (pure layer).

    P1-C2 family closure, table-driven: the binding's mandatory validity
    facts (work unit + generation) and the evaluator's mandatory validity
    arguments form one failure family. Every mandatory-field row, caller
    omission row, cross-unit row, expiry row, drift row, and unique-target
    row is data below; any authorized_unique result outside the two
    positive unique-target rows fails the matrix.
    """

    COMMIT_TARGET = {
        "repository": "https://github.com/example/synthetic-repo",
        "ref": "refs/heads/main",
        "commit_sha256": "a" * 64,
    }
    PUSH_TARGET = dict(COMMIT_TARGET, remote="origin")
    TAG_TARGET = dict(COMMIT_TARGET, tag="v1.2.3")
    RELEASE_TARGET = dict(COMMIT_TARGET, release_version="1.2.3")

    UNIT = "WU0001"
    GENERATION = 1

    def bind(
        self,
        actions,
        targets,
        *,
        work_unit_id=UNIT,
        generation=GENERATION,
    ):
        return authority.bind_authorization(
            actions, targets, work_unit_id=work_unit_id, generation=generation
        )

    def evaluate(self, action, binding, targets, *, unit=UNIT, generation=GENERATION, **kwargs):
        return authority.evaluate_action_authorization(
            action,
            binding,
            targets,
            current_work_unit_id=unit,
            authorization_generation=generation,
            **kwargs,
        )

    INVALID = authority.STATUS_AUTHORIZATION_INVALID

    def test_mandatory_binding_context_table(self) -> None:
        """bind() without work unit or generation never yields an
        executable binding (coordinator counterexample: bind with
        work_unit_id=None, generation=None produced authorized_unique)."""
        rows = [
            ("missing work unit", dict(work_unit_id=None)),
            ("empty work unit", dict(work_unit_id="  ")),
            ("missing generation", dict(generation=None)),
            ("boolean generation", dict(generation=True)),
            ("negative generation", dict(generation=-1)),
        ]
        for label, kwargs in rows:
            with self.subTest(row=label):
                binding = self.bind(
                    [authority.ACTION_PUSH], [dict(self.PUSH_TARGET)], **kwargs
                )
                self.assertEqual(binding["status"], self.INVALID, label)
                self.assertIsNone(binding["target"], label)
                self.assertTrue(
                    binding["reason_code"]
                    in {
                        authority.REASON_WORK_UNIT_BINDING_REQUIRED,
                        authority.REASON_GENERATION_BINDING_REQUIRED,
                    },
                    label,
                )
                decision = self.evaluate(
                    authority.ACTION_PUSH, binding, [dict(self.PUSH_TARGET)]
                )
                self.assertEqual(decision["status"], self.INVALID, label)
                self.assertTrue(decision["ask_user"], label)

    def test_caller_omission_table_fails_closed(self) -> None:
        """evaluate() with an omitted/malformed validity argument never
        authorizes — even against a perfectly bound unique target
        (coordinator counterexample: omitting both facts returned
        authorized_unique with ask_user=False)."""
        binding = self.bind([authority.ACTION_PUSH], [dict(self.PUSH_TARGET)])
        rows = [
            ("omit unit", dict(unit=None, generation=self.GENERATION)),
            ("empty unit", dict(unit="", generation=self.GENERATION)),
            ("omit generation", dict(unit=self.UNIT, generation=None)),
            ("boolean generation", dict(unit=self.UNIT, generation=True)),
            ("negative generation", dict(unit=self.UNIT, generation=-1)),
        ]
        for label, kwargs in rows:
            with self.subTest(row=label):
                decision = self.evaluate(
                    authority.ACTION_PUSH, dict(self.PUSH_TARGET) and binding,
                    [dict(self.PUSH_TARGET)], **kwargs,
                )
                self.assertEqual(decision["status"], self.INVALID, label)
                self.assertEqual(
                    decision["reason_code"],
                    authority.REASON_MISSING_VALIDITY_FACT,
                    label,
                )
                self.assertTrue(decision["ask_user"], label)

    def test_binding_context_incomplete_is_invalid(self) -> None:
        """A binding record that lost its context fields (tampered or
        legacy) fails closed instead of evaluating."""
        binding = self.bind([authority.ACTION_PUSH], [dict(self.PUSH_TARGET)])
        for field in ("work_unit_id", "generation"):
            with self.subTest(field=field):
                broken = dict(binding)
                broken[field] = None
                decision = self.evaluate(
                    authority.ACTION_PUSH, broken, [dict(self.PUSH_TARGET)]
                )
                self.assertEqual(decision["status"], self.INVALID)
                self.assertEqual(
                    decision["reason_code"],
                    authority.REASON_BINDING_CONTEXT_INCOMPLETE,
                )

    def test_cross_unit_and_expiry_table(self) -> None:
        binding = self.bind([authority.ACTION_PUSH], [dict(self.PUSH_TARGET)])
        rows = [
            (
                "cross unit",
                dict(unit="WU0002", generation=self.GENERATION),
                authority.REASON_CROSS_UNIT_REPLAY,
            ),
            (
                "expired generation",
                dict(unit=self.UNIT, generation=self.GENERATION + 1),
                authority.REASON_GENERATION_EXPIRED,
            ),
            (
                "older generation",
                dict(unit=self.UNIT, generation=self.GENERATION - 1),
                authority.REASON_GENERATION_EXPIRED,
            ),
        ]
        for label, kwargs, reason in rows:
            with self.subTest(row=label):
                decision = self.evaluate(
                    authority.ACTION_PUSH,
                    binding,
                    [dict(self.PUSH_TARGET)],
                    **kwargs,
                )
                self.assertEqual(decision["status"], self.INVALID, label)
                self.assertEqual(decision["reason_code"], reason, label)
                self.assertTrue(decision["ask_user"], label)

    def test_drift_and_multi_candidate_rows(self) -> None:
        binding = self.bind([authority.ACTION_PUSH], [dict(self.PUSH_TARGET)])
        drifted = self.evaluate(
            authority.ACTION_PUSH, binding, [dict(self.PUSH_TARGET, commit_sha256="b" * 64)]
        )
        self.assertEqual(drifted["status"], authority.STATUS_DRIFTED)
        self.assertTrue(drifted["ask_user"])
        other = dict(self.PUSH_TARGET, remote="upstream")
        multi = self.bind(
            [authority.ACTION_PUSH], [dict(self.PUSH_TARGET), other]
        )
        self.assertEqual(multi["status"], authority.STATUS_REQUIRES_SELECTION)
        decision = self.evaluate(authority.ACTION_PUSH, multi, [dict(self.PUSH_TARGET)])
        self.assertEqual(decision["status"], authority.STATUS_REQUIRES_SELECTION)
        self.assertTrue(decision["ask_user"])

    def test_unique_target_rows_remain_ask_free(self) -> None:
        """The ONLY authorized_unique rows of the family: a complete
        unique target, same unit, live generation, no drift."""
        rows = [
            (authority.ACTION_COMMIT, [dict(self.COMMIT_TARGET)], frozenset()),
            (authority.ACTION_PUSH, [dict(self.PUSH_TARGET)], frozenset()),
        ]
        for action, targets, flags in rows:
            with self.subTest(action=action):
                binding = self.bind([action], [dict(targets[0])])
                decision = self.evaluate(action, binding, targets, action_flags=flags)
                self.assertEqual(decision["status"], authority.STATUS_AUTHORIZED_UNIQUE)
                self.assertFalse(decision["ask_user"])

    def test_scope_boundaries_stay_out_of_scope(self) -> None:
        binding = self.bind(
            [authority.ACTION_COMMIT, authority.ACTION_PUSH], [dict(self.PUSH_TARGET)]
        )
        forced = authority.evaluate_action_authorization(
            authority.ACTION_PUSH,
            binding,
            [dict(self.PUSH_TARGET)],
            current_work_unit_id=self.UNIT,
            authorization_generation=self.GENERATION,
            action_flags={"force"},
        )
        self.assertEqual(forced["status"], authority.STATUS_OUT_OF_SCOPE)
        release = self.evaluate(
            authority.ACTION_RELEASE, binding, [dict(self.PUSH_TARGET)]
        )
        self.assertEqual(release["status"], authority.STATUS_OUT_OF_SCOPE)
        nothing = authority.evaluate_action_authorization(
            authority.ACTION_COMMIT,
            None,
            [dict(self.COMMIT_TARGET)],
            current_work_unit_id=self.UNIT,
            authorization_generation=self.GENERATION,
        )
        self.assertEqual(nothing["status"], authority.STATUS_OUT_OF_SCOPE)

    def test_unique_tag_and_release_authorization_never_ask(self) -> None:
        tag_binding = self.bind([authority.ACTION_TAG], [dict(self.TAG_TARGET)])
        decision = self.evaluate(authority.ACTION_TAG, tag_binding, [dict(self.TAG_TARGET)])
        self.assertEqual(decision["status"], authority.STATUS_AUTHORIZED_UNIQUE)
        self.assertFalse(decision["ask_user"])
        release_binding = self.bind(
            [authority.ACTION_RELEASE], [dict(self.RELEASE_TARGET)]
        )
        release_decision = self.evaluate(
            authority.ACTION_RELEASE, release_binding, [dict(self.RELEASE_TARGET)]
        )
        self.assertEqual(release_decision["status"], authority.STATUS_AUTHORIZED_UNIQUE)
        self.assertFalse(release_decision["ask_user"])

    def test_empty_target_and_missing_field_stay_undetermined(self) -> None:
        binding = self.bind([authority.ACTION_RELEASE], [{}])
        self.assertEqual(binding["status"], authority.STATUS_REQUIRES_SELECTION)
        self.assertEqual(binding["reason_code"], authority.REASON_TARGET_UNDETERMINED)
        missing_remote = {
            key: value for key, value in self.PUSH_TARGET.items() if key != "remote"
        }
        push_binding = self.bind([authority.ACTION_PUSH], [missing_remote])
        self.assertEqual(push_binding["status"], authority.STATUS_REQUIRES_SELECTION)
        self.assertEqual(
            push_binding["reason_code"], authority.REASON_TARGET_UNDETERMINED
        )


class RunnerDiscoveryEvidenceTests(Phase3TestCase):
    """Evidence-E / P1-E2: dynamic closed-world discovery, proven without
    writing into the source tree.

    The census negative control builds an INDEPENDENT tests directory in a
    TemporaryDirectory, drops a FAILING probe module into it, and verifies
    (a) discovery collects it, (b) its failure propagates through the
    runner's loader path, and (c) a read-only directory still discovers,
    mirroring a read-only checkout. The real repository tests directory is
    only read, never written; the probe must never leak into it.
    """

    PROBE_MODULE = "test_phase3_runner_census_probe"

    def setUp(self) -> None:
        super().setUp()
        self.temp_tests = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_tests.cleanup)
        self.temp_dir = Path(self.temp_tests.name)
        self.real_tests_dir = Path(__file__).resolve().parent
        self.snapshot_before = sorted(p.name for p in self.real_tests_dir.iterdir())

    def tearDown(self) -> None:
        leaked = sorted(p.name for p in self.real_tests_dir.iterdir())
        self.assertEqual(
            leaked,
            self.snapshot_before,
            "the census control must not write into the source tree",
        )
        sys.modules.pop(f"tests.{self.PROBE_MODULE}", None)
        sys.modules.pop(self.PROBE_MODULE, None)
        super().tearDown()

    @staticmethod
    def write_probe(directory: Path, *, failing: bool = True) -> None:
        outcome = (
            "self.fail('census probe: the runner must see this module')"
            if failing
            else "pass"
        )
        (directory / f"{RunnerDiscoveryEvidenceTests.PROBE_MODULE}.py").write_text(
            "from __future__ import annotations\n"
            "import unittest\n\n\n"
            "class ProbeFailure(unittest.TestCase):\n"
            "    def test_probe(self) -> None:\n"
            f"        {outcome}\n",
            encoding="utf-8",
        )

    def test_baseline_is_the_single_exclusion(self) -> None:
        from run_current_behavior_suite import discover_current_modules

        modules = discover_current_modules()
        self.assertNotIn("test_context_guard_012_baseline", modules)
        self.assertIn("test_context_guard_phase3", modules)
        self.assertEqual(modules, sorted(modules))
        self.assertEqual(len(modules), len(set(modules)))

    def test_new_failing_module_is_discovered_and_propagates(self) -> None:
        from run_current_behavior_suite import discover_current_modules

        directory = self.temp_dir / "tests"
        directory.mkdir()
        (directory / "test_known_ok.py").write_text(
            "import unittest\n\n\n"
            "class Known(unittest.TestCase):\n"
            "    def test_ok(self) -> None:\n"
            "        pass\n",
            encoding="utf-8",
        )
        self.assertEqual(discover_current_modules(directory), ["test_known_ok"])
        self.write_probe(directory, failing=True)
        self.assertEqual(
            discover_current_modules(directory),
            ["test_known_ok", self.PROBE_MODULE],
        )
        # The probe's failure propagates through the runner's loader path;
        # the nested runner stream is captured so no bare FAILED block
        # leaks into the top-level green log.
        import io

        nested_stream = io.StringIO()
        sys.path.insert(0, str(directory))
        try:
            probe = __import__(self.PROBE_MODULE, fromlist=[self.PROBE_MODULE])
            result = unittest.TextTestRunner(
                verbosity=0, stream=nested_stream
            ).run(unittest.TestLoader().loadTestsFromModule(probe))
            self.assertEqual(len(result.failures), 1)
            self.assertEqual(len(result.errors), 0)
            self.assertIn("FAILED", nested_stream.getvalue())
            self.assertIn("census probe", nested_stream.getvalue())
        finally:
            sys.path.remove(str(directory))
            sys.modules.pop(self.PROBE_MODULE, None)
        self.assertFalse(
            (self.real_tests_dir / f"{self.PROBE_MODULE}.py").exists()
        )

    def test_readonly_checkout_still_discovers(self) -> None:
        """Negative control mirroring a read-only source checkout: the
        directory is made read-only (temp only, never the real repo), a
        write attempt fails, and discovery keeps working."""
        import stat

        from run_current_behavior_suite import discover_current_modules

        directory = self.temp_dir / "readonly-tests"
        directory.mkdir()
        self.write_probe(directory, failing=False)
        directory.chmod(stat.S_IRUSR | stat.S_IXUSR)
        try:
            with self.assertRaises(PermissionError):
                (directory / "must_not_write.py").write_text("x", encoding="utf-8")
            modules = discover_current_modules(directory)
            self.assertIn(self.PROBE_MODULE, modules)
        finally:
            directory.chmod(stat.S_IRWXU)

    def test_empty_discovery_fails_loudly(self) -> None:
        from run_current_behavior_suite import discover_current_modules

        empty = self.temp_dir / "empty-tests"
        empty.mkdir()
        with self.assertRaises(RuntimeError):
            discover_current_modules(empty)


class SchemaUpgradePromptIntegrationTests(Phase3TestCase):
    """Migration evidence through the REAL UserPromptSubmit path.

    The load_state-only migration tests do not exercise the native event;
    this adds the integration the coordinator required: after the 9 -> 10
    upgrade, a plain new prompt archives the old active root as
    historical_unresolved and creates a fresh sibling root; explicit
    resume then reopens the unique parked unit under the persisted
    last_active_seq policy.
    """

    def build_schema9_state(self) -> None:
        self.prompt("请修复模块。必须逐项落实。必须运行测试验证。", turn="t1")
        self.prompt("请修复文档。必须逐项落实。必须运行测试验证。", turn="t2")
        session_dir = self.root / "private" / "sessions" / "p3"
        legacy = json.loads((session_dir / "state.json").read_text("utf-8"))
        units = legacy["work_units"]
        for unit in units:
            unit["protocol_version"] = "1.0.0"
            unit.pop("last_active_seq", None)
            unit.pop("resume_pending_reopen", None)
            unit["status"] = "active"
            unit["closed_at"] = None
        units[1]["parent_id"] = units[0]["id"]
        legacy["work_state"]["active_work_unit_id"] = "WU0002"
        legacy["work_state"].pop("unit_activity_seq", None)
        legacy["schema_version"] = 9
        legacy["content_hash"] = cg.state_content_hash(legacy)
        (session_dir / "state.json").write_text(
            json.dumps(legacy, ensure_ascii=False), encoding="utf-8"
        )

    def test_plain_prompt_after_upgrade_archives_old_root_and_starts_sibling(
        self,
    ) -> None:
        self.build_schema9_state()
        # The upgrade happens lazily on the next native event: a plain
        # UserPromptSubmit (no resume intent, no control syntax).
        self.prompt("另一件独立事项:请检查文档拼写。必须运行测试验证。", turn="t3")
        state = self.state()
        self.assertEqual(state["schema_version"], 10)
        units = {unit["id"]: unit for unit in state["work_units"]}
        self.assertEqual(len(units), 3)
        self.assertEqual(units["WU0001"]["status"], "historical_unresolved")
        self.assertEqual(units["WU0002"]["status"], "historical_unresolved")
        self.assertIsNone(units["WU0003"]["parent_id"])
        self.assertEqual(units["WU0003"]["status"], "active")
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0003")
        for item in state["requirements"]:
            self.assertNotEqual(item["status"], "pass")

    def test_explicit_resume_after_upgrade_reopens_the_unique_parked_root(
        self,
    ) -> None:
        self.build_schema9_state()
        # A plain sibling request displaces the migrated active root to
        # historical; the only parked unit is then the post-upgrade root
        # with a persisted activity sequence. The explicit resume reopens
        # exactly that unique waiting candidate (plan 4.2).
        self.prompt("先看一下别的问题。必须运行测试验证。", turn="t3")
        state = self.state()
        self.assertEqual(state["work_units"][1]["status"], "historical_unresolved")
        self.assertEqual(state["work_units"][2]["status"], "active")
        self.dispatch(
            "Stop",
            turn="t3",
            last_assistant_message="目录发布已完成,当前等待外部审核。",
        )
        self.assertEqual(self.state()["work_units"][2]["status"], "awaiting_external")
        self.prompt("继续刚才的任务。", turn="t4")
        state = self.state()
        units = {unit["id"]: unit for unit in state["work_units"]}
        self.assertEqual(units["WU0003"]["status"], "active")
        self.assertEqual(state["work_state"]["active_work_unit_id"], "WU0003")
        self.assertEqual(units["WU0002"]["status"], "historical_unresolved")
        self.assertEqual(units["WU0001"]["status"], "historical_unresolved")

class ResumePolicyMatrixTests(Phase3TestCase):
    """FAM-SCHEMA9-RESUME-MIGRATION-BLOCKED: one table-driven failure family
    over the migration/resume boundary (coordinator convergence; frozen plan
    section 4.2 is the oracle).

    Dimensions: candidate status (awaiting_user, awaiting_external,
    deferred, historical_unresolved), persisted last_active_seq (unique-max
    present / missing / tied), resume intent (unqualified explicit resume vs
    a targeted unit selection), and the migration source (schema 9 units can
    only be active/passed/superseded, so the schema-9 cells are the
    migration rows here; the waiting/seq cells run on the migrated
    schema-10 ledger).

    Oracle (plan 4.2): only a uniquely qualified waiting candidate auto-
    reopens; ambiguity (missing/tied sequence, deferred or historical
    candidates, several waiting candidates) fails closed to an explicit
    selection list; a targeted named unit is an explicit selection and may
    reopen a parked or historical unit; a named unit that does not exist
    fails closed. Historical units never silently reopen and never suppress
    a qualified waiting candidate.
    """

    def build_schema9_state(self) -> None:
        self.prompt("请修复模块。必须逐项落实。必须运行测试验证。", turn="t1")
        self.prompt("请修复文档。必须逐项落实。必须运行测试验证。", turn="t2")
        session_dir = self.root / "private" / "sessions" / "p3"
        legacy = json.loads((session_dir / "state.json").read_text("utf-8"))
        units = legacy["work_units"]
        for unit in units:
            unit["protocol_version"] = "1.0.0"
            unit.pop("last_active_seq", None)
            unit.pop("resume_pending_reopen", None)
            unit["status"] = "active"
            unit["closed_at"] = None
        units[1]["parent_id"] = units[0]["id"]
        legacy["work_state"]["active_work_unit_id"] = "WU0002"
        legacy["work_state"].pop("unit_activity_seq", None)
        legacy["schema_version"] = 9
        legacy["content_hash"] = cg.state_content_hash(legacy)
        (session_dir / "state.json").write_text(
            json.dumps(legacy, ensure_ascii=False), encoding="utf-8"
        )

    def candidate(self, unit_id: str, status: str, seq: int | None) -> dict:
        return {
            "id": unit_id,
            "protocol_version": cg.WORK_UNIT_PROTOCOL_VERSION,
            "prompt_id": "P0001",
            "parent_id": None,
            "kind": "general",
            "status": status,
            "created_at": "2026-01-01T00:00:00Z",
            "closed_at": None if status == "active" else "2026-01-02T00:00:00Z",
            "last_active_seq": seq,
            "scope_sha256": "0" * 64,
        }

    def run_matrix_row(
        self,
        candidates: list[dict],
        intent: str,
    ) -> tuple[dict, dict[str, str]]:
        """Seed a pristine schema-10 ledger with the candidate units (no
        active unit), dispatch the resume prompt, and return
        (state, statuses). Each row starts from a wiped session so rows
        cannot contaminate each other."""
        session_dir = self.root / "private" / "sessions" / "p3"
        if session_dir.exists():
            shutil.rmtree(session_dir)
        self.prompt("请修复模块。必须逐项落实。必须运行测试验证。", turn="t1")
        state = self.state()
        base = list(state["work_units"])
        for unit in base:
            if unit["status"] == "active":
                unit["status"] = "historical_unresolved"
                unit["closed_at"] = "2026-01-02T00:00:00Z"
        for spec in candidates:
            base.append(self.candidate(*spec))
        state["work_units"] = base
        state["work_state"]["active_work_unit_id"] = None
        seq_values = [spec[2] for spec in candidates if isinstance(spec[2], int)]
        state["work_state"]["unit_activity_seq"] = max(seq_values, default=0)
        state["work_unit_sequence"] = max(
            int(state["work_unit_sequence"]),
            max((int(spec[0][2:]) for spec in candidates), default=0),
        )
        state["content_hash"] = cg.state_content_hash(state)
        cg.save_state(session_dir, state)
        self.prompt(intent, turn="resume-turn")
        reloaded = self.state()
        statuses = {item["id"]: item["status"] for item in reloaded["work_units"]}
        return reloaded, statuses

    ROWS = [
        # (label, candidates, intent, expectation)
        ("awaiting_user_unique_seq_reopens",
         [("WU0002", "awaiting_user", 4)],
         "继续刚才的任务。", "reopen:WU0002"),
        ("awaiting_external_unique_seq_reopens",
         [("WU0002", "awaiting_external", 4)],
         "继续刚才的任务。", "reopen:WU0002"),
        ("awaiting_external_missing_seq_fails_closed",
         [("WU0002", "awaiting_external", None)],
         "继续刚才的任务。", "selection:WU0002"),
        ("two_waiting_tied_seq_fails_closed",
         [("WU0002", "awaiting_user", 4), ("WU0003", "awaiting_external", 4)],
         "继续刚才的任务。", "selection:WU0002,WU0003"),
        ("waiting_missing_seq_plus_waiting_seq_fails_closed",
         [("WU0002", "awaiting_external", None), ("WU0003", "awaiting_user", 5)],
         "继续刚才的任务。", "selection:WU0002,WU0003"),
        ("deferred_unique_seq_not_auto_reopened",
         [("WU0002", "deferred", 4)],
         "继续刚才的任务。", "selection:WU0002"),
        ("historical_unique_seq_not_auto_reopened",
         [("WU0002", "historical_unresolved", 4)],
         "继续刚才的任务。", "selection:WU0002"),
        ("historical_missing_seq_does_not_suppress_waiting",
         [("WU0002", "historical_unresolved", None),
          ("WU0003", "awaiting_external", 4)],
         "继续刚才的任务。", "reopen:WU0003"),
        ("targeted_selection_reopens_named_historical",
         [("WU0002", "historical_unresolved", None)],
         "继续 WU0002 的任务。", "reopen:WU0002"),
        ("targeted_selection_reopens_named_seqless_waiting",
         [("WU0002", "awaiting_external", None)],
         "恢复 WU0002。", "reopen:WU0002"),
        ("targeted_selection_reopens_named_deferred",
         [("WU0002", "deferred", None)],
         "恢复 WU0002。", "reopen:WU0002"),
        ("targeted_unknown_unit_fails_closed",
         [("WU0002", "awaiting_external", 4)],
         "继续 WU9999。", "selection:WU0002"),
    ]

    def test_resume_policy_matrix(self) -> None:
        self.prompt("请修复模块。必须逐项落实。必须运行测试验证。", turn="t1")
        failures: list[str] = []
        for label, candidates, intent, expected in self.ROWS:
            state, statuses = self.run_matrix_row(candidates, intent)
            kind, _, target = expected.partition(":")
            names = target.split(",") if target else []
            new_root = max(statuses, key=lambda uid: int(uid[2:]))
            active_id = state["work_state"]["active_work_unit_id"]
            selection = state["work_state"].get("resume_selection_required")
            if kind == "reopen":
                ok = (
                    statuses.get(target) == "active"
                    and active_id == target
                    and new_root == target
                )
            else:
                ok = (
                    all(statuses.get(n) != "active" for n in names)
                    and active_id == new_root
                    and bool(selection)
                    and all(n in selection for n in names)
                )
            if not ok:
                failures.append(
                    f"{label}: expected {expected}, got active={active_id} "
                    f"statuses={statuses} selection={selection}"
                )
        self.assertEqual(failures, [])

    def test_migration_runs_the_migrator_not_the_rebuild_path(self) -> None:
        """Gate A of the family: a schema-9 state file is a full migration
        source. validate_state_integrity rejected schema 9 before the
        migrator could run, so every real resume quarantined the ledger as
        state.corrupt.* and rebuilt it from prompt records (the rebuild
        happens to produce the same unit statuses, which masked the
        defect). The migration path is reached only when the load completes
        without a corruption backup or prompt-record rebuild."""
        self.build_schema9_state()
        session_dir = self.root / "private" / "sessions" / "p3"
        migrated = cg.load_state(session_dir, {"session_id": "p3"})
        self.assertEqual(migrated["schema_version"], 10)
        self.assertEqual(migrated["integrity"]["status"], "ok")
        self.assertIsNone(migrated["integrity"]["issue"])
        self.assertIsNone(migrated["integrity"]["backup_file"])
        self.assertEqual(
            [path.name for path in sorted(session_dir.glob("state.corrupt.*.json"))],
            [],
        )
        self.assertEqual(len(migrated["prompts"]), 2)
        migrated["content_hash"] = cg.state_content_hash(migrated)
        cg.validate_state_integrity(migrated)

    def test_migrated_ledger_parked_units_follow_the_same_matrix(self) -> None:
        """Schema-9 source cells: after a real in-place migration the
        migrated ledger obeys the identical resume policy (a migrated
        seq-less parked unit fails closed instead of auto-reopening)."""
        self.build_schema9_state()
        session_dir = self.root / "private" / "sessions" / "p3"
        migrated = cg.load_state(session_dir, {"session_id": "p3"})
        migrated["work_state"]["active_work_unit_id"] = None
        migrated["work_units"][0]["status"] = "awaiting_external"
        migrated["work_units"][0]["closed_at"] = "2026-01-02T00:00:00Z"
        migrated["content_hash"] = cg.state_content_hash(migrated)
        cg.save_state(session_dir, migrated)
        self.prompt("继续刚才的任务。", turn="resume-turn")
        state = self.state()
        statuses = {u["id"]: u["status"] for u in state["work_units"]}
        self.assertEqual(statuses["WU0001"], "awaiting_external")
        self.assertIn("WU0001", state["work_state"].get("resume_selection_required", []))


if __name__ == "__main__":
    unittest.main(verbosity=2)
