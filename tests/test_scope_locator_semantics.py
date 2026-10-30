"""Literal locator bytes are opaque only to scope intent, never to targets."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import test_clause_source_semantics as owner

cg = owner.cg


class ScopeLocatorSemantics(unittest.TestCase):
    def contract(self, text):
        return cg.verification_contract("R001", text, {"assets": []}, [])

    def scope(self, text):
        return [row for row in self.contract(text)["obligations"]
                if row["kind"] == "scope_coverage"]

    def test_original_22_locator_projections_keep_readback(self):
        markers = ("fall", "full", "native", "validation", "all", "whole", "complete",
                   "fullness", "source-native-full-validation-v1",
                   "source-code-mode-format-validation-v1", "entire")
        for marker in markers:
            target = "/tmp/" + marker + "/spec.txt"
            for template in ("Read {} and verify its content.", "请先核对 {} 后修复文档。"):
                with self.subTest(marker=marker, template=template):
                    text = template.format(target)
                    result = self.contract(text)
                    self.assertEqual(result["mode"], "enforced")
                    self.assertEqual(result["obligations"][0]["kind"], "subject_readback")
                    self.assertEqual(result["obligations"][0]["subject_ids"],
                                     [cg.prompt_subjects(target)[0]["id"]])
                    self.assertEqual(self.scope(text), [])

    def test_absolute_locator_platform_quotes_spaces_and_cjk(self):
        paths = ("/work/full/spec.txt", "/work/全部/spec.txt", "/work/完整.txt",
                 '"/work/all 7 files/报告.txt"', '“/work/not full/全部.txt”',
                 r'C:\work\whole\spec.txt', r'"C:\work\all 7 files\报告.txt"',
                 r'"D:\work\not full\完整.txt"')
        for target in paths:
            with self.subTest(target=target):
                text = "Read " + target + " and verify its content."
                result = self.contract(text)
                self.assertEqual(result["mode"], "enforced")
                expected = [row["id"] for row in cg.prompt_subjects(text)]
                self.assertTrue(expected)
                self.assertEqual(result["obligations"][0]["subject_ids"], expected)
                self.assertEqual(self.scope(text), [])

    def test_relative_and_filename_locators_do_not_supply_scope(self):
        # These are scope lexing controls, not a new relative-target adapter.
        for target in ("./full/spec.txt", "../all/spec.txt", "whole/spec.txt",
                       r"all\spec.txt", "目录/全部/spec.txt", "full.txt", "完整.txt",
                       '"all 7 files/spec.txt"', "<full/spec.txt>"):
            with self.subTest(target=target):
                view = cg.scope_intent_source_text("Read " + target + " then verify.")
                self.assertIsNone(cg.FULL_SCOPE_RE.search(view))
                self.assertIsNone(cg.deterministic_scope_spec(target, [], []))

    def test_locator_quantities_and_negation_cannot_change_real_scope(self):
        paths = ("/work/not-full/a.txt", '"/work/not full/a.txt"',
                 '"/work/all 7 files/a.txt"', "/work/3/3/a.txt",
                 '"C:\\work\\all 7 files\\a.txt"', "/work/全部/a.txt")
        for path in paths:
            text = "Read all 2 files " + path + " and /work/b.txt."
            with self.subTest(path=path):
                rows = self.scope(text)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["expected_scope_count"], 2)
                ids = sorted(row["id"] for row in cg.prompt_subjects(text))
                self.assertEqual(rows[0]["expected_scope_sha256"],
                                 cg.sha256_text(cg.canonical_json(ids)))

    def test_real_unknown_full_scope_stays_fallback_even_with_path_negation(self):
        for word in ("all", "every", "entire", "whole", "complete", "full"):
            for target in ("/work/a.txt", '"/work/not full/a.txt"'):
                with self.subTest(word=word, target=target):
                    result = self.contract("Read " + word + " files " + target + ".")
                    self.assertEqual(result["reason"], "scope_not_constructible")
                    self.assertEqual(result["obligations"], [])
        for word in ("全部", "所有", "完整", "整个", "全量"):
            result = self.contract("请核对" + word + "对象 /work/a.txt。")
            self.assertEqual(result["reason"], "scope_not_constructible")

    def test_slash_quantifier_alternatives_remain_real_scope_prose(self):
        for prose in ("Read all/every files", "Read full/whole files", "核对全部/所有对象",
                      'Read "all/every files"'):
            with self.subTest(prose=prose):
                text = prose + " /work/a.txt."
                self.assertTrue(cg.FULL_SCOPE_RE.search(cg.scope_intent_source_text(text)))
                self.assertEqual(self.contract(text)["reason"], "scope_not_constructible")

    def test_prose_counts_ratios_and_conflicts_are_preserved(self):
        subjects = cg.prompt_subjects("/work/a.txt /work/b.txt")
        for text in ("all 2 files", "2/2", "全部2个文件", '"all 2 files"'):
            with self.subTest(text=text):
                spec = cg.deterministic_scope_spec(text + " /work/9/9/a.txt", subjects, [])
                self.assertEqual(spec["expected_scope_count"], 2)
        self.assertIsNone(cg.deterministic_scope_spec("all 2 files and all 3 files", subjects, []))
        view = cg.scope_intent_source_text('Do not read all files. "all 2 files" `run all tests`')
        self.assertIn("Do not read all files", view)
        self.assertIn('"all 2 files"', view)
        self.assertIn("`run all tests`", view)
        self.assertTrue(cg.FULL_SCOPE_NEGATION_RE.search(
            cg.scope_intent_source_text('not all files /work/full/a.txt')))

    def test_command_prose_and_inner_literal_paths_are_distinct(self):
        text = '`cat "/work/all 7 files/spec.txt"` and verify all 2 files.'
        view = cg.scope_intent_source_text(text)
        self.assertIn("`cat ", view)
        self.assertIn("verify all 2 files", view)
        self.assertNotIn("all 7 files", view)
        self.assertEqual(len(view), len(text))
        # A quoted explanation is still prose, never a blanket opaque span.
        self.assertEqual(cg.scope_intent_source_text('"Read all files"'), '"Read all files"')

    def test_full_content_readback_is_not_project_scope(self):
        for template in ("Read the complete contents of {}.", "Read {} in full.",
                         "读取 {} 的完整文件内容。"):
            result = self.contract(template.format("/work/full/spec.txt"))
            self.assertEqual(result["mode"], "enforced")
            self.assertEqual(result["obligations"][0]["kind"], "subject_readback")
            self.assertFalse(any(x["kind"] == "scope_coverage" for x in result["obligations"]))

    def test_subject_ids_still_come_from_original_locator_bytes(self):
        a, b = "/work/full/spec.txt", "/work/fall/spec.txt"
        self.assertNotEqual(cg.prompt_subjects(a)[0]["id"], cg.prompt_subjects(b)[0]["id"])
        for target in (a, b):
            text = "Read all 2 files " + target + " and /work/b.txt."
            self.assertEqual(self.scope(text)[0]["subject_ids"],
                             [row["id"] for row in cg.prompt_subjects(text)])

    def test_diagnostic_clauses_cannot_replace_original_prose_scope(self):
        text = "Read all files /work/not-full/a.txt."
        result = cg.verification_contract("R001", text, {"assets": []}, [],
                                         clauses=cg.clause_metadata("Read /work/a.txt."))
        self.assertEqual(result["reason"], "scope_not_constructible")


class ScopeLocatorPersistence(unittest.TestCase):
    def test_old_fallback_cache_rederived_only_from_intact_immutable_source(self):
        for damage in ("intact", "missing", "changed", "binding", "unbound", "true_scope", "terminal"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as root:
                base = Path(root)
                with mock.patch.dict(os.environ, {
                    "HOME": str(base / "home"), "USERPROFILE": str(base / "home"),
                    "CODEX_HOME": str(base / "codex"),
                    "CONTEXT_GUARD_DATA_DIR": str(base / "data"),
                }):
                    self.assertEqual(cg.data_root().resolve(), (base / "data").resolve())
                    payload = {"session_id": "old-scope", "cwd": str(base), "turn_id": "t1"}
                    cg.dispatch({**payload, "hook_event_name": "UserPromptSubmit",
                                 "prompt": "context-guard on"})
                    text = ("Read all files /work/full/spec.txt." if damage == "true_scope"
                            else "Read /work/full/spec.txt and verify its content.")
                    cg.dispatch({**payload, "hook_event_name": "UserPromptSubmit", "prompt": text})
                    session = base / "data/sessions-v2/old-scope"
                    state = cg.load_state(session, payload)
                    item = state["requirements"][-1]
                    # Exact old derived cache, serialized with the real current-schema
                    # writer/hash. Authoritative prompt records are never replaced.
                    item["verification_contract"] = {
                        "protocol_version": "1.0.0", "mode": "legacy_fallback",
                        "reason": "scope_not_constructible", "obligations": [],
                    }
                    metadata = next(p for p in state["prompts"] if p["id"] == item["prompt_id"])
                    record_path = session / metadata["file"]
                    original = record_path.read_bytes()
                    if damage == "terminal":
                        item["status"] = "pass"
                    if damage == "unbound":
                        metadata.pop("record_sha256", None)
                    cg.begin_completion_attempt(state, payload, "t1")
                    # A known synthetic token is needed only by the read-only query.
                    state["completion_attempt"]["token_sha256"] = cg.sha256_text("synthetic-token")
                    cg.save_state(session, state)
                    if damage == "missing":
                        record_path.unlink()
                    elif damage == "changed":
                        record = json.loads(original)
                        record["text"] = "Read /work/other.txt."
                        record_path.write_text(json.dumps(record))
                    elif damage == "binding":
                        record = json.loads(original)
                        record["record_sha256"] = "0" * 64
                        record_path.write_text(json.dumps(record))
                    if damage == "intact":
                        before = (session / "state.json").read_bytes()
                        snapshot = cg.checkpoint_status(base / "data", "old-scope", "t1",
                                                        "synthetic-token")
                        self.assertEqual((session / "state.json").read_bytes(), before)
                        self.assertEqual(snapshot["revision"], json.loads(before)["content_hash"])
                        self.assertEqual(cg.load_state(session, payload)["requirements"][-1]
                                         ["verification_contract"]["mode"], "legacy_fallback")
                    cg.dispatch({**payload, "hook_event_name": "SessionStart", "source": "resume"})
                    loaded = cg.load_state(session, payload)
                    cg.validate_state_integrity(loaded)
                    contract = loaded["requirements"][-1]["verification_contract"]
                    if damage == "intact":
                        self.assertEqual(contract["mode"], "enforced")
                        self.assertEqual(contract["obligations"][0]["kind"], "subject_readback")
                        self.assertEqual(record_path.read_bytes(), original)
                        cg.save_state(session, loaded)
                        self.assertEqual(cg.load_state(session, payload)["requirements"][-1]
                                         ["verification_contract"], contract)
                        result = cg.dispatch({**payload, "hook_event_name": "Stop",
                                              "last_assistant_message": "任务已经全部完成。"})
                        self.assertEqual(result.get("decision"), "block")
                    else:
                        self.assertEqual(contract["mode"], "legacy_fallback")
                        self.assertEqual(contract["obligations"], [])
                        if damage in {"missing", "changed", "binding", "unbound"}:
                            self.assertEqual(loaded["requirements"][-1]["status"], "pending")
                            cg.dispatch({**payload, "hook_event_name": "Stop",
                                         "last_assistant_message": "任务已经全部完成。"})
                            stopped = cg.load_state(session, payload)
                            self.assertEqual(stopped["requirements"][-1]["status"], "pending")
                            self.assertEqual(stopped["proofs"], [])
                            self.assertEqual(stopped["requirements"][-1]
                                             ["verification_contract"]["mode"], "legacy_fallback")

    def test_literal_full_target_survives_prompt_state_recovery_and_stop(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            target = base / "full" / "全部" / "spec.txt"
            target.parent.mkdir(parents=True)
            target.write_text("synthetic subject", encoding="utf-8")
            with mock.patch.dict(os.environ, {
                "HOME": str(base / "home"), "USERPROFILE": str(base / "home"),
                "CODEX_HOME": str(base / "codex"), "CONTEXT_GUARD_DATA_DIR": str(base / "data"),
            }):
                self.assertEqual(cg.data_root().resolve(), (base / "data").resolve())
                payload = {"session_id": "scope-locator", "cwd": str(base), "turn_id": "t1"}
                cg.dispatch({**payload, "hook_event_name": "UserPromptSubmit",
                             "prompt": "context-guard on"})
                text = f"请先核对 {target} 后修复文档。"
                cg.dispatch({**payload, "hook_event_name": "UserPromptSubmit", "prompt": text})
                session = base / "data/sessions-v2/scope-locator"
                state = cg.load_state(session, payload)
                requirement = state["requirements"][-1]
                expected = cg.prompt_subjects(str(target))[0]["id"]
                self.assertEqual(requirement["subjectId"], [expected])
                self.assertEqual(requirement["verification_contract"]["mode"], "enforced")
                prompts = list((session / "prompts").glob("P*.json"))
                self.assertTrue(any(text in json.loads(p.read_text())["text"] for p in prompts))
                cg.dispatch({**payload, "hook_event_name": "PreCompact", "trigger": "manual"})
                cg.dispatch({**payload, "hook_event_name": "SessionStart", "source": "compact"})
                recovered = cg.load_state(session, payload)
                self.assertEqual(recovered["requirements"][-1]["subjectId"], [expected])
                result = cg.dispatch({**payload, "hook_event_name": "Stop",
                                      "last_assistant_message": "任务已经全部完成。"})
                self.assertEqual(result.get("decision"), "block")
                self.assertEqual(recovered["schema_version"], 13)


if __name__ == "__main__":
    unittest.main()
