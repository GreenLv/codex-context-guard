#!/usr/bin/env python3
"""v0.9.5 regression tests: auto-derived proofs, compatibility patches, and
the frozen privacy grammar boundary."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)

THREAD_UUID = "01a01503-a631-7681-92cb-cac150d2b94a"
THREAD_URI = f"codex://threads/{THREAD_UUID}"


class V095UILexicalTests(unittest.TestCase):
    def test_ui_signal_negatives_do_not_match(self) -> None:
        negatives = [
            "运行 academic-literature-acquisition 技能",
            "完成 build 与 squid 检查",
            "列出三个文件",
            "检查 invisible result 是否被忽略",
            "提取 PDF 页面文本",
            "确认网络可见性正常",
            "回到 acquire 流程",
        ]
        for text in negatives:
            self.assertIsNone(
                cg.UI_SURFACE_RE.search(text), f"unexpected UI signal: {text}"
            )

    def test_explicit_ui_requests_still_match(self) -> None:
        positives = [
            "检查 UI",
            "打开 GUI 页面",
            "在浏览器窗口中检查可见结果",
            "inspect the visible browser window",
            "检查网页显示结果",
        ]
        for text in positives:
            self.assertIsNotNone(
                cg.UI_SURFACE_RE.search(text), f"missing UI signal: {text}"
            )


class V095WindowsSubjectTests(unittest.TestCase):
    def test_supported_drive_path_is_canonically_captured(self) -> None:
        subjects = cg.prompt_subjects("读取 C:\\repo\\file.txt 并总结")
        self.assertEqual(len(subjects), 1)
        subject = subjects[0]
        self.assertEqual(subject["display"], "file.txt")
        canonical = "C:\\repo\\file.txt"
        self.assertEqual(subject["id"], f"subject:{cg.sha256_text(canonical)[:20]}")

    def test_forward_slashes_and_dot_segments_resolve_lexically(self) -> None:
        direct = cg.prompt_subjects("check C:/repo/./sub/../file.txt")
        self.assertEqual(direct[0]["id"], cg.prompt_subjects("see C:\\repo\\file.txt")[0]["id"])

    def test_component_case_is_preserved_as_distinct_subjects(self) -> None:
        left = cg.prompt_subjects("对比 C:\\Repo\\File.txt 与 C:\\repo\\file.txt")
        self.assertEqual(len(left), 2)
        self.assertNotEqual(left[0]["id"], left[1]["id"])

    def test_markdown_link_target_is_captured(self) -> None:
        subjects = cg.prompt_subjects("见 [报告](C:\\repo\\file.txt) 的内容")
        self.assertEqual(len(subjects), 1)
        self.assertEqual(subjects[0]["display"], "file.txt")

    def test_unsupported_forms_get_distinct_opaque_subjects(self) -> None:
        cases = {
            "\\\\server\\share\\file.txt": "unc",
            "\\\\.\\C:\\repo\\file.txt": "device_path",
            "C:\\repo\\file.txt:stream": "ads",
            "C:\\..\\outside.txt": "beyond_root",
            "C:\\repo\\CON": "reserved_name",
            "C:\\repo\\name.\\sub": "trailing_dots_spaces",
        }
        for raw, reason in cases.items():
            text = f"检查 {raw}"
            subjects = cg.prompt_subjects(text)
            self.assertEqual(len(subjects), 1, raw)
            self.assertIn(
                f"{cg.UNSUPPORTED_SUBJECT_PREFIX}{reason}/",
                subjects[0]["id"],
                f"{raw} -> {subjects[0]['id']}",
            )
        # Same reason, different locator: distinct subjects, never collapsed.
        first = cg.unsupported_subject("unc", "\\\\server\\share\\a.txt")
        second = cg.unsupported_subject("unc", "\\\\server\\share\\b.txt")
        self.assertNotEqual(first, second)
        # Domain-separated digests: the same locator text under a different
        # reason token also differs.
        self.assertNotEqual(
            cg.unsupported_subject("unc", "\\\\s\\a.txt"),
            cg.unsupported_subject("device_path", "\\\\s\\a.txt"),
        )

    def test_physical_identity_requirement_creates_unbindable_obligations(self) -> None:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        try:
            with mock.patch.dict(
                os.environ, {"CONTEXT_GUARD_DATA_DIR": str(root / "private")}
            ):
                turn = "turn-phys"
                cg.dispatch(
                    {
                        "hook_event_name": "UserPromptSubmit",
                        "session_id": "session-phys",
                        "cwd": str(root),
                        "turn_id": turn,
                        "prompt": (
                            "读取 C:\\repo\\file.txt 与 C:\\other\\data.bin，"
                            "并证明没有经过 junction。"
                        ),
                    }
                )
                state = json.loads(
                    (root / "private" / "sessions" / "session-phys" / "state.json")
                    .read_text(encoding="utf-8")
                )
                item = state["requirements"][0]
                contract = item["verification_contract"]
                self.assertEqual(contract["mode"], "enforced")
                physical = [
                    obligation
                    for obligation in contract["obligations"]
                    if any(
                        subject.startswith(cg.UNSUPPORTED_SUBJECT_PREFIX)
                        for subject in obligation["subject_ids"]
                    )
                ]
                self.assertEqual(len(physical), 1)
                self.assertEqual(len(physical[0]["subject_ids"]), 2)
                self.assertEqual(
                    len({tuple(obligation["subject_ids"]) for obligation in [physical[0]]}),
                    1,
                )
                for subject in physical[0]["subject_ids"]:
                    self.assertIn("physical_identity", subject)
        finally:
            temp.cleanup()

    def test_prompt_without_signal_has_no_physical_identity_obligation(self) -> None:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        try:
            with mock.patch.dict(
                os.environ, {"CONTEXT_GUARD_DATA_DIR": str(root / "private")}
            ):
                cg.dispatch(
                    {
                        "hook_event_name": "UserPromptSubmit",
                        "session_id": "session-plain",
                        "cwd": str(root),
                        "turn_id": "turn-plain",
                        "prompt": "读取 C:\\data\\file.txt 并总结内容。",
                    }
                )
                state = json.loads(
                    (root / "private" / "sessions" / "session-plain" / "state.json")
                    .read_text(encoding="utf-8")
                )
                contract = state["requirements"][0]["verification_contract"]
                for obligation in contract["obligations"]:
                    for subject in obligation["subject_ids"]:
                        self.assertFalse(
                            subject.startswith(cg.UNSUPPORTED_SUBJECT_PREFIX),
                            obligation,
                        )
        finally:
            temp.cleanup()


class V095ThreadLocatorTests(unittest.TestCase):
    def test_prompt_uri_and_read_thread_share_one_subject_id(self) -> None:
        from_uri = cg.prompt_subjects(f"继续分析 {THREAD_URI}")
        from_argument = cg.thread_subject_id_from_thread_id(THREAD_UUID.upper())
        self.assertEqual(len(from_uri), 1)
        self.assertEqual(from_uri[0]["id"], from_argument)

    def test_arbitrary_uuid_is_not_a_thread_subject(self) -> None:
        self.assertIsNone(cg.thread_subject_id_from_thread_id("not-a-thread-uuid"))
        self.assertIsNone(cg.canonical_thread_uri("codex://threads/short"))

    def test_wrong_tool_output_cannot_bind_thread_subject(self) -> None:
        text = json.dumps({"thread": THREAD_URI, "result": "navigated"})
        subjects = cg.prompt_subjects(text, include_threads=False)
        thread_ids = [item for item in subjects if item["kind"] == "thread"]
        self.assertEqual(thread_ids, [])


class V095CapabilityTrustRootTests(unittest.TestCase):
    def test_registered_ui_tools_get_ui_exact_name_membership(self) -> None:
        self.assertIn("ui", cg.evidence_capabilities("computer_use"))
        self.assertIn("ui", cg.evidence_capabilities("browserUse"))
        # Substring matches must not upgrade.
        self.assertEqual(cg.evidence_capabilities("mcp__node_repl__js"), ["artifact"])

    def test_shell_capability_unchanged(self) -> None:
        self.assertIn("scope", cg.evidence_capabilities("Bash"))

    def test_host_envelope_metadata_upgrades_completed_event_only(self) -> None:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        try:
            with mock.patch.dict(
                os.environ, {"CONTEXT_GUARD_DATA_DIR": str(root / "private")}
            ):
                envelope = {
                    "hook": {
                        "session_id": "session-cap",
                        "turn_id": "turn-cap",
                        "tool_use_id": "item-1",
                    },
                    "event": {
                        "thread_id": "session-cap",
                        "turn_id": "turn-cap",
                        "item": {"id": "item-1", "status": "completed"},
                    },
                    "surface": "ui",
                }
                state = {"session": {"id": "session-cap"}}
                payload = {
                    "tool_name": "mcp__node_repl__js",
                    "turn_id": "turn-cap",
                    "codex/toolSurface": envelope,
                }
                upgraded, disposition = cg.host_tool_surface_disposition(state, payload)
                self.assertTrue(upgraded)
                self.assertIsNone(disposition)
                # Status not completed.
                broken = dict(envelope)
                broken["event"] = {
                    "thread_id": "session-cap",
                    "turn_id": "turn-cap",
                    "item": {"id": "item-1", "status": "failed"},
                }
                upgraded, disposition = cg.host_tool_surface_disposition(
                    state, {**payload, "codex/toolSurface": broken}
                )
                self.assertFalse(upgraded)
                self.assertEqual(disposition, "unavailable")
                # Turn mismatch between hook and event.
                broken = {
                    "hook": {**envelope["hook"], "turn_id": "other-turn"},
                    "event": envelope["event"],
                    "surface": "ui",
                }
                upgraded, disposition = cg.host_tool_surface_disposition(
                    state, {**payload, "codex/toolSurface": broken}
                )
                self.assertFalse(upgraded)
                # Session must match the runtime state.
                upgraded, disposition = cg.host_tool_surface_disposition(
                    {"session": {"id": "other-session"}}, payload
                )
                self.assertFalse(upgraded)
                # Duplicate events are ambiguous.
                duplicated = {**envelope, "events": [envelope["event"], envelope["event"]]}
                upgraded, disposition = cg.host_tool_surface_disposition(
                    state, {**payload, "codex/toolSurface": duplicated}
                )
                self.assertFalse(upgraded)
                # Metadata absent for a candidate tool reports unavailable.
                upgraded, disposition = cg.host_tool_surface_disposition(
                    state, {"tool_name": "computer_use", "turn_id": "turn-cap"}
                )
                self.assertFalse(upgraded)
                self.assertEqual(disposition, "unavailable")
        finally:
            temp.cleanup()


class V095AutoProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.turn_index = 0
        self.current_turn = "turn-0"
        self.environment = mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.root / "private")}
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def payload(self, event: str, session: str = "session-a", **extra: object) -> dict:
        result = {
            "hook_event_name": event,
            "session_id": session,
            "cwd": str(self.project),
            "turn_id": self.current_turn,
        }
        result.update(extra)
        return result

    def state(self, session: str = "session-a") -> dict:
        path = self.root / "private" / "sessions" / session / "state.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def prompt(self, text: str, session: str = "session-a") -> dict:
        self.turn_index += 1
        self.current_turn = f"turn-{self.turn_index}"
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="test-token"):
            return cg.dispatch(
                self.payload("UserPromptSubmit", session=session, prompt=text)
            )

    def record_tool(
        self,
        *,
        session: str = "session-a",
        tool: str = "Bash",
        tool_input: dict | None = None,
        response: dict | None = None,
        extra_payload: dict | None = None,
        turn_id: str | None = None,
    ) -> str:
        cg.dispatch(
            {
                **self.payload("PostToolUse", session=session),
                **({"turn_id": turn_id} if turn_id else {}),
                "tool_name": tool,
                "tool_input": tool_input or {"command": "synthetic verification"},
                "tool_response": response or {"exit_code": 0, "output": "PASS"},
                **(extra_payload or {}),
            }
        )
        return self.state(session)["evidence"][-1]["id"]

    def stage_all(self, evidence_id: str, session: str = "session-a") -> dict:
        state = self.state(session)
        requirements = [
            f"{item['id']}={evidence_id}"
            for item in state["requirements"]
            if item["status"] not in {"pass", "superseded"}
        ]
        acceptance = [
            f"{item['id']}={evidence_id}"
            for item in state["acceptance_items"]
            if item["status"] not in {"pass", "superseded"}
        ]
        return cg.stage_private_checkpoint(
            self.root / "private",
            session,
            self.current_turn,
            "test-token",
            requirements,
            acceptance,
        )

    def test_artifact_subject_readback_is_derived_from_a_real_read(self) -> None:
        path = "/tmp/cg-v095/report-final.md"
        self.prompt(f"实现并验证：总结 {path} 的关键结果，必须逐条核对后交付。")
        # A registered read adapter reading the subject in its *input* is the
        # only surface that binds a readback subject.
        evidence_id = self.record_tool(
            tool_input={"command": f"cat {path}"},
            response={"exit_code": 0, "output": f"# report body of {path}"},
        )
        receipt = self.stage_all(evidence_id)
        self.assertFalse(receipt["idempotent"])
        state = self.state()
        enforced_items = [
            item
            for collection in ("requirements", "acceptance_items")
            for item in state[collection]
            if item.get("status") != "superseded"
            and isinstance(item.get("verification_contract"), dict)
            and item["verification_contract"].get("mode") == "enforced"
        ]
        # Every enforced item (the prompt also captured an acceptance item)
        # has its ordinary proof derived automatically.
        self.assertEqual(len(state["proofs"]), len(enforced_items))
        proof = state["proofs"][0]
        self.assertEqual(proof["kind"], "subject_readback")
        self.assertEqual(proof["surface"], "artifact")
        expected_subjects = sorted(
            {
                item["id"]
                for item in cg.prompt_subjects(
                    f"实现并验证：总结 {path} 的关键结果，必须逐条核对后交付。"
                )
            }
        )
        self.assertEqual(proof["subject_ids"], expected_subjects)
        self.assertEqual(proof["evidence_ids"], [evidence_id])
        # The checkpoint re-stages idempotently with no duplicate proof.
        receipt = self.stage_all(evidence_id)
        self.assertTrue(receipt["idempotent"])
        self.assertEqual(len(self.state()["proofs"]), len(enforced_items))

    def test_response_echo_alone_never_derives_subject_readback(self) -> None:
        # CG-CODEX-001 regression: a successful tool call that merely echoes
        # the target path in its response — without a read-shaped input — must
        # not auto-derive a subject_readback proof.
        path = "/tmp/cg-v095/report-final.md"
        self.prompt(f"实现并验证：总结 {path} 的关键结果，必须逐条核对后交付。")
        evidence_id = self.record_tool(
            tool_input={"command": "synthetic verification"},
            response={"exit_code": 0, "output": f"verified {path} OK"},
        )
        self.assertEqual(self.state()["evidence"][-1]["readback_subjects"], [])
        with self.assertRaises(ValueError):
            self.stage_all(evidence_id)
        self.assertEqual(self.state()["proofs"], [])

    def test_superset_read_fails_readback_derivation_closed(self) -> None:
        first = "/tmp/cg-v095/alpha.md"
        second = "/tmp/cg-v095/beta.md"
        self.prompt(f"实现并验证：总结 {first} 的关键结果，必须逐条核对后交付。")
        # The read covers both files while the obligation requires only the
        # first: a superset binding is not a unique derivation.
        evidence_id = self.record_tool(
            tool_input={"command": f"cat {first} {second}"},
            response={"exit_code": 0, "output": "ok"},
        )
        with self.assertRaises(ValueError):
            self.stage_all(evidence_id)
        self.assertEqual(self.state()["proofs"], [])

    def test_ambiguous_read_shapes_fail_closed(self) -> None:
        path = "/tmp/cg-v095/report-final.md"
        self.prompt(f"实现并验证：总结 {path} 的关键结果，必须逐条核对后交付。")
        for command in (
            f"cat {path} > /tmp/cg-v095/copy.md",
            f"sed -i 's/a/b/' {path}",
            f"ls {path}",
        ):
            with self.subTest(command=command):
                evidence_id = self.record_tool(
                    tool_input={"command": command},
                    response={"exit_code": 0, "output": "ok"},
                )
                with self.assertRaises(ValueError):
                    self.stage_all(evidence_id)
                self.assertEqual(self.state()["proofs"], [])

    def _artifact_readback_manifest(self, path: str) -> tuple[dict, list[str]]:
        state = self.state()
        item = next(
            item
            for item in state["requirements"]
            if any(
                obligation.get("kind") == "subject_readback"
                and obligation.get("surface") == "artifact"
                for obligation in item["verification_contract"]["obligations"]
            )
        )
        obligation = next(
            obligation
            for obligation in item["verification_contract"]["obligations"]
            if obligation.get("kind") == "subject_readback"
            and obligation.get("surface") == "artifact"
        )
        subjects = sorted({str(subject) for subject in obligation.get("subject_ids", [])})
        return (
            {
                "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                "item_id": item["id"],
                "obligation_id": obligation["id"],
                "evidence_ids": [],
                "surface": "artifact",
                "subject_ids": subjects,
            },
            subjects,
        )

    def test_explicit_artifact_readback_requires_real_read_evidence(self) -> None:
        # CG-CODEX-001 regression: the explicit register-proof path cannot
        # bypass the read-adapter binding either — echo-only evidence with
        # readback_subjects=[] is rejected, a real read is accepted, and the
        # manifest may not expand the obligation's subjects.
        path = "/tmp/cg-v095/explicit.md"
        self.prompt(f"实现并验证：总结 {path} 的关键结果，必须逐条核对后交付。")
        echo_evidence = self.record_tool(
            tool_input={"command": "echo synthetic-verification"},
            response={"exit_code": 0, "output": f"verified {path} OK"},
        )
        manifest, subjects = self._artifact_readback_manifest(path)
        manifest["evidence_ids"] = [echo_evidence]
        with self.assertRaisesRegex(ValueError, "registered read adapter"):
            cg.normalize_proof_manifest(self.state(), manifest)
        read_evidence = self.record_tool(
            tool_input={"command": f"cat {path}"},
            response={"exit_code": 0, "output": "body"},
        )
        manifest["evidence_ids"] = [read_evidence]
        normalized = cg.normalize_proof_manifest(self.state(), manifest)
        self.assertEqual(normalized["subject_ids"], subjects)
        expanded = {
            **manifest,
            "subject_ids": [*subjects, "subject:ffffffffffffffffffff"],
        }
        with self.assertRaisesRegex(ValueError, "exactly the required subjects"):
            cg.normalize_proof_manifest(self.state(), expanded)

    def test_scope_coverage_is_derived_only_on_exact_set_equality(self) -> None:
        first = "/tmp/cg-v095/alpha.md"
        second = "/tmp/cg-v095/beta.md"
        subjects = sorted({item["id"] for item in cg.prompt_subjects(
            f"处理 {first} 和 {second}"
        )})
        self.assertEqual(len(subjects), 2)
        state = {
            "requirements": [
                {
                    "id": "R001",
                    "status": "pending",
                    "prompt_id": "P0001",
                    "verification_contract": {
                        "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                        "mode": "enforced",
                        "reason": "deterministic_prompt_contract",
                        "obligations": [
                            {
                                "id": "O-R001-001",
                                "kind": "scope_coverage",
                                "surface": "scope",
                                "subject_ids": subjects,
                                "expected_scope_count": 2,
                                "expected_scope_sha256": cg.sha256_text(
                                    cg.canonical_json(subjects)
                                ),
                            },
                        ],
                    },
                }
            ],
            "acceptance_items": [],
            "evidence": [
                {
                    "id": "E0001",
                    "outcome": "success",
                    "created_at": "2026-08-31T00:00:00Z",
                    "capabilities": ["artifact", "scope"],
                    "subject_ids": subjects,
                    "asset_ids": [],
                }
            ],
            "proofs": [],
        }
        derived = cg.derive_ordinary_proofs(state)
        self.assertEqual([proof["kind"] for proof in derived], ["scope_coverage"])
        self.assertEqual(derived[0]["evidence_ids"], ["E0001"])
        self.assertEqual(derived[0]["subject_ids"], subjects)
        self.assertEqual(derived[0]["expected_scope_sha256"], derived[0]["observed_scope_sha256"])

    def test_superset_evidence_fails_scope_derivation_closed(self) -> None:
        first = "/tmp/cg-v095/alpha.md"
        second = "/tmp/cg-v095/beta.md"
        extra = "/tmp/cg-v095/gamma.md"
        self.prompt(
            f"实现并验证：处理全部 2 个文件 {first} 和 {second}，必须全部完成。"
        )
        evidence_id = self.record_tool(
            response={"exit_code": 0, "output": f"done {first} {second} {extra}"}
        )
        state = self.state()
        requirements = [
            f"{item['id']}={evidence_id}"
            for item in state["requirements"]
            if item["status"] not in {"pass", "superseded"}
        ]
        with self.assertRaises(ValueError):
            cg.stage_private_checkpoint(
                self.root / "private",
                "session-a",
                self.current_turn,
                "test-token",
                requirements,
                [],
            )
        # Nothing half-derived: no proofs exist.
        self.assertEqual(self.state()["proofs"], [])

    def test_failed_or_stale_evidence_is_never_derived(self) -> None:
        path = "/tmp/cg-v095/report-final.md"
        self.prompt(f"实现并验证：总结 {path} 的关键结果，必须逐条核对后交付。")
        failed = self.record_tool(
            response={"exit_code": 1, "output": f"verified {path} FAILED"}
        )
        with self.assertRaises(ValueError):
            self.stage_all(failed)
        self.assertEqual(self.state()["proofs"], [])

    def test_visual_obligations_are_not_auto_derived(self) -> None:
        state = {
            "requirements": [
                {
                    "id": "R001",
                    "status": "pending",
                    "prompt_id": "P0001",
                    "verification_contract": {
                        "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                        "mode": "enforced",
                        "reason": "deterministic_prompt_contract",
                        "obligations": [
                            {
                                "id": "O-R001-001",
                                "kind": "input_asset_inspection",
                                "surface": "visual",
                                "subject_ids": ["M0001"],
                            },
                            {
                                "id": "O-R001-002",
                                "kind": "subject_readback",
                                "surface": "ui",
                                "subject_ids": ["subject:uiartifact0000000000"],
                            },
                        ],
                    },
                }
            ],
            "acceptance_items": [],
            "evidence": [
                {
                    "id": "E0001",
                    "outcome": "success",
                    "created_at": "2026-08-31T00:00:00Z",
                    "capabilities": ["artifact", "scope", "ui", "visual"],
                    "subject_ids": ["M0001", "subject:uiartifact0000000000"],
                    "asset_ids": ["M0001"],
                }
            ],
            "proofs": [],
        }
        derived = cg.derive_ordinary_proofs(state)
        # Visual inspection and UI-surface readbacks stay on the explicit
        # register-proof path even when seemingly sufficient evidence exists.
        self.assertEqual(derived, [])

    def test_failed_staging_rolls_back_derived_proofs(self) -> None:
        good = "/tmp/cg-v095/report-final.md"
        self.prompt(
            f"实现并验证：总结 {good} 的关键结果，之后必须读取 C:\\require\\locked.txt 才算完成。"
        )
        evidence_id = self.record_tool(
            response={"exit_code": 0, "output": f"verified {good} OK"}
        )
        state = self.state()
        # The Windows unsupported subject has an unbindable obligation, so the
        # whole checkpoint fails; the derivable proof must not survive.
        requirements = [
            f"{item['id']}={evidence_id}"
            for item in state["requirements"]
            if item["status"] not in {"pass", "superseded"}
        ]
        with self.assertRaises(ValueError):
            cg.stage_private_checkpoint(
                self.root / "private",
                "session-a",
                self.current_turn,
                "test-token",
                requirements,
                [],
            )
        self.assertEqual(self.state()["proofs"], [])

    def test_unsupported_namespace_is_not_bindable_via_register_proof(self) -> None:
        item_id = "R001"
        obligation_id = "O-R001-001"
        required = [cg.unsupported_subject("unc", "\\\\server\\share\\file.txt")]
        state = {
            "requirements": [
                {
                    "id": item_id,
                    "status": "pending",
                    "prompt_id": "P0001",
                    "verification_contract": {
                        "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                        "mode": "enforced",
                        "reason": "deterministic_prompt_contract",
                        "obligations": [
                            {
                                "id": obligation_id,
                                "kind": "subject_readback",
                                "surface": "artifact",
                                "subject_ids": required,
                            }
                        ],
                    },
                }
            ],
            "acceptance_items": [],
            "evidence": [
                {
                    "id": "E0001",
                    "outcome": "success",
                    "created_at": "2026-08-31T00:00:00Z",
                    "capabilities": ["artifact"],
                    "subject_ids": required,
                    "asset_ids": [],
                }
            ],
            "proofs": [],
        }
        manifest = {
            "protocol_version": cg.PROOF_PROTOCOL_VERSION,
            "item_id": item_id,
            "obligation_id": obligation_id,
            "evidence_ids": ["E0001"],
            "surface": "artifact",
            "subject_ids": required,
        }
        with self.assertRaises(ValueError):
            cg.normalize_proof_manifest(state, manifest)
        derived = cg.derive_ordinary_proofs(state)
        self.assertEqual(derived, [])

    def test_checkpoint_diagnostic_names_surface_capabilities_and_binding(self) -> None:
        path = "/tmp/cg-v095/report-final.md"
        self.prompt(
            f"实现并验证：必须检查 UI 后总结 {path} 的关键结果。"
        )
        evidence_id = self.record_tool(
            response={"exit_code": 0, "output": f"verified {path} OK"}
        )
        state = self.state()
        requirements = [
            f"{item['id']}={evidence_id}"
            for item in state["requirements"]
            if item["status"] not in {"pass", "superseded"}
        ]
        with self.assertRaises(ValueError) as context:
            cg.stage_private_checkpoint(
                self.root / "private",
                "session-a",
                self.current_turn,
                "test-token",
                requirements,
                [],
            )
        message = str(context.exception)
        self.assertIn("unresolved proof obligations", message)
        self.assertIn("required_surface=ui", message)
        self.assertIn("subject_binding=", message)


class V095PrivacyGrammarBoundaryTests(unittest.TestCase):
    def test_bare_control_names_remain_explanatory(self) -> None:
        explanations = [
            "The stage-checkpoint command stages a private checkpoint.",
            "You can inspect state with checkpoint-status before finishing.",
            "Context Guard 的 register-proof 会登记不可变证明。",
            "The guard exposes stage-checkpoint, stage-disposition, and register-proof.",
        ]
        for text in explanations:
            category, _reasons = cg.classify_private_metadata(text)
            self.assertEqual(
                category, "explanatory_reference", f"{category}: {text}"
            )

    def test_actual_invocations_and_bindings_stay_sensitive(self) -> None:
        sensitive = [
            "stage-checkpoint --token AQ3d_9x-token-value-length-32-xxxxxxxxxxxx",
            "context_guard.py stage-checkpoint --data-dir /home/u/.guard --session-id s1",
            '{"command": "stage-checkpoint", "token": "real-secret-value"}',
            "run: register-proof --manifest /tmp/proof.json",
            "CONTEXT_GUARD_DATA_DIR=/home/u/.guard-private",
        ]
        for text in sensitive:
            category, _reasons = cg.classify_private_metadata(text)
            self.assertEqual(category, "sensitive_control", f"{category}: {text}")

    def test_ambiguous_fragments_are_not_upgraded_or_downgraded(self) -> None:
        category, _reasons = cg.classify_private_metadata(
            "stage-checkpoint --requirement"
        )
        self.assertEqual(category, "ambiguous_control_fragment")


if __name__ == "__main__":
    unittest.main()
