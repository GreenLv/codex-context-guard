"""Exact ephemeral clause semantics versus bounded persisted diagnostics."""

import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "cg_clause_source", Path(__file__).resolve().parents[1] / "scripts/context_guard.py")
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)


def subject(path):
    return cg.prompt_subjects(path)[0]["id"]


def readbacks(contract):
    return [row for row in contract["obligations"] if row["kind"] == "subject_readback"]


class ClauseSourceSemantics(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {
            "HOME": str(self.root / "os-home"), "USERPROFILE": str(self.root / "os-home"),
            "CODEX_HOME": str(self.root / "codex-home"),
            "CONTEXT_GUARD_DATA_DIR": str(self.root / "data"),
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.session = self.root / "data/sessions-v2/clause-source"
        self.state = cg.new_state({"session_id": "clause-source", "cwd": str(self.root)})

    def append(self, text):
        prompt = cg.append_prompt(self.session, self.state, text)
        cg.append_requirement(self.state, prompt, text)
        return prompt, self.state["requirements"][-1]

    def contract(self, text, diagnostic=False):
        kwargs = {"clauses": cg.clause_metadata(text)} if diagnostic else {}
        return cg.verification_contract("R001", text, {"assets": []}, [], **kwargs)

    def test_second_locator_around_400_uses_full_source_in_both_routes(self):
        other = "/" + "a" * 166 + "/other.py"
        for length in range(399, 410):
            suite = "/" + "a" * (166 + length - 399) + "/suite.py"
            text = f"Run pytest {suite} and read the complete contents of {other}."
            self.assertEqual(len(text), length)
            for diagnostic in (False, True):
                with self.subTest(length=length, diagnostic=diagnostic):
                    self.assertEqual(readbacks(self.contract(text, diagnostic))[0]["subject_ids"],
                                     [subject(other)])

    def test_supplied_diagnostics_cannot_replace_source_or_erase_negation(self):
        source = "Read the complete contents of /work/actual.py."
        wrong = cg.clause_metadata("Read the complete contents of /work/other.py.")
        actual = cg.verification_contract("R001", source, {"assets": []}, [], clauses=wrong)
        self.assertEqual(readbacks(actual)[0]["subject_ids"], [subject("/work/actual.py")])
        denied = "Do not read the complete contents of /work/actual.py."
        self.assertEqual(cg.verification_contract("R001", denied, {"assets": []}, [],
                                                clauses=wrong)["obligations"], [])

    def test_coordination_order_quotes_language_same_and_different_objects(self):
        # Multi-component paths have individually valid component lengths.
        prefix = "/visualizations/images/test-data/" + "/".join(["a" * 70] * 6)
        suite, other = prefix + "/suite.py", prefix + "/other.py"
        templates = (
            "Run pytest {suite} and read the complete contents of {other}.",
            "Read the complete contents of {other} and run pytest {suite}.",
            "Run pytest {suite}. Then read {other} in full.",
            "Run pytest {suite}; then read {other} in full.",
            "运行 pytest {suite} 并读取 {other} 的完整文件内容。",
            "读取 {other} 的完整文件内容并运行 pytest {suite} 验证。",
            'Run pytest "{suite}" and read the complete contents of "{other}".',
        )
        for selected in (suite, other):
            for template in templates:
                text = template.format(suite=suite, other=selected)
                with self.subTest(template=template, same=selected == suite):
                    contract = self.contract(text)
                    self.assertNotEqual(contract.get("reason"), "asset_reference_unresolved")
                    self.assertEqual(readbacks(contract)[0]["subject_ids"], [subject(selected)])

    def test_quoted_command_description_and_test_only_remain_non_readbacks(self):
        path = "/" + "/".join(["a" * 70] * 7) + "/other.py"
        roots = (
            f"Run pytest {path}.",
            f"Run `pytest {path} and read {path}`.",
            f'The document says, "Read the complete contents of {path}." Explain why.',
            f"Do not read the complete contents of {path}.",
        )
        for text in roots:
            with self.subTest(text=text[:70]):
                self.assertEqual(readbacks(self.contract(text)), [])

    def test_negation_beyond_diagnostic_cut_has_no_subject_or_pending_stamp(self):
        path = "/" + "/".join(["a" * 70] * 7) + "/other.py"
        text = f"Edit {path} but do not edit it."
        self.assertGreater(text.index("do not"), 400)
        self.assertEqual(cg.primary_clause_operation(text), "unspecified")
        _, item = self.append(text)
        self.assertEqual(item["subjectId"], [])
        self.assertEqual(item["verification_contract"]["obligations"], [])
        self.assertEqual(self.state["pending"]["operations"], [])

    def test_stored_subjects_pending_and_contract_share_exact_semantics(self):
        path = "/" + "/".join(["a" * 70] * 15) + "/config.py"
        text = f"Edit {path} and read the complete contents of {path}."
        _, item = self.append(text)
        self.assertEqual(item["subjectId"], [subject(path)])
        self.assertEqual(item["operation"], "local_edit")
        self.assertEqual(readbacks(item["verification_contract"])[0]["subject_ids"], [subject(path)])
        self.assertEqual(self.state["pending"]["operations"][-1]["subjectId"], subject(path))
        self.assertEqual(cg.primary_clause_operation(text), "local_edit")
        self.assertEqual(item["text"], cg.bounded(text, 900))
        self.assertEqual(item["clause_metadata"], cg.clause_metadata(text))
        self.assertEqual(item["clause_metadata"]["clauses"][0]["clause"],
                         cg.bounded(cg._protected_prompt_clauses(text)[0], 400))
        self.assertNotIn(path, json.dumps(item["clause_metadata"]))
        self.assertEqual(set(item), {"id", "prompt_id", "work_unit_id", "text", "sha256",
                                    "status", "evidence", "operation", "subjectId",
                                    "requestedSurface", "clause_metadata", "verification_contract"})

    def test_persisted_state_cold_load_keeps_full_target_and_diagnostic_bounds(self):
        path = "/" + "/".join(["a" * 70] * 15) + "/config.py"
        text = f"Edit {path} and read the complete contents of {path}."
        payload = {"session_id": "clause-source", "cwd": str(self.root), "turn_id": "t1"}
        cg.dispatch({**payload, "hook_event_name": "UserPromptSubmit", "prompt": "context-guard on"})
        cg.dispatch({**payload, "hook_event_name": "UserPromptSubmit", "prompt": text})
        stored = json.loads((self.session / "state.json").read_bytes())
        loaded = cg.load_state(self.session, {**payload, "hook_event_name": "Stop"})
        item = loaded["requirements"][-1]
        self.assertEqual(item, stored["requirements"][-1])
        self.assertEqual(item["subjectId"], [subject(path)])
        self.assertEqual(readbacks(item["verification_contract"])[0]["subject_ids"], [subject(path)])
        self.assertEqual(item["text"], cg.bounded(text, 900))
        self.assertNotIn(path, json.dumps(item["clause_metadata"]))
        self.assertEqual(loaded["schema_version"], 13)

    def test_latest_evidence_source_does_not_fall_back_to_item_summary(self):
        text = "Edit /work/actual.py."
        prompt, _ = self.append(text)
        self.assertEqual(cg.latest_requirement_text(self.session, self.state), text)
        state = copy.deepcopy(self.state)
        state["prompts"] = []
        self.assertEqual(cg.latest_requirement_text(self.session, state), "")
        (self.session / prompt["file"]).unlink()
        self.assertEqual(cg.latest_requirement_text(self.session, self.state), "")

    def late_fixture(self):
        text = "Inspect the attached image. " + "ordinary " * 120 + "Read the complete contents of /work/target.py."
        prompt, item = self.append(text)
        self.assertNotIn("/work/target.py", item["text"])
        self.assertEqual(item["verification_contract"]["mode"], "legacy_fallback")
        record = {"type": "event_msg", "payload": {"type": "user_message", "message": text}}
        return text, prompt, item, record

    def reconcile(self, prompt, record, mutation=None):
        def discover(state, _payload, **_kwargs):
            state["assets"].append({"id": "asset:late", "available": True,
                                    "prompt_ids": [prompt["id"]]})
            if mutation:
                mutation()
        with mock.patch.object(cg, "transcript_tail_records", return_value=[record]), \
                mock.patch.object(cg, "discover_assets", side_effect=discover):
            cg.reconcile_transcript_assets(self.state, {}, trigger="pre_compact", session_dir=self.session)

    def test_late_asset_upgrade_recovers_target_after_900_from_verified_root(self):
        text, prompt, item, record = self.late_fixture()
        before = copy.deepcopy(item)
        self.reconcile(prompt, record)
        self.assertEqual(item["verification_contract"],
                         cg.verification_contract(item["id"], text, self.state, ["asset:late"]))
        self.assertEqual(readbacks(item["verification_contract"])[0]["subject_ids"], [subject("/work/target.py")])
        self.assertEqual({k: v for k, v in item.items() if k != "verification_contract"},
                         {k: v for k, v in before.items() if k != "verification_contract"})

    def test_late_asset_acceptance_is_rederived_from_verified_root(self):
        text = "ordinary " * 120 + "\nMust inspect the attached image and read /work/accepted.py in full."
        prompt, _ = self.append(text)
        cg.append_acceptance(self.state, prompt["id"], text)
        item = self.state["acceptance_items"][0]
        self.assertEqual(item["verification_contract"]["mode"], "legacy_fallback")
        record = {"type": "event_msg", "payload": {"type": "user_message", "message": text}}
        self.reconcile(prompt, record)
        self.assertEqual(item["verification_contract"], cg.verification_contract(
            item["id"], item["text"], self.state, ["asset:late"]))
        self.assertEqual(item["verification_contract"]["mode"], "enforced")

    def test_late_asset_missing_tampered_and_resealed_roots_do_not_upgrade(self):
        for variant in ("missing", "text", "resealed"):
            with self.subTest(variant=variant):
                self.state = cg.new_state({"session_id": "clause-source", "cwd": str(self.root)})
                # Distinct existing immutable file names must not be reused.
                self.session = self.root / variant
                _, prompt, item, record = self.late_fixture()
                path = self.session / prompt["file"]
                if variant == "missing":
                    path.unlink()
                else:
                    raw = json.loads(path.read_bytes())
                    raw["origin"] = "internal" if variant == "resealed" else raw["origin"]
                    if variant == "text":
                        raw["text"] += " changed"
                    else:
                        raw["record_sha256"] = cg.prompt_record_hash(raw)
                    path.write_text(json.dumps(raw), encoding="utf-8")
                self.reconcile(prompt, record)
                self.assertEqual(item["verification_contract"]["mode"], "legacy_fallback")
                self.assertEqual(self.state["assets"], [])

    def test_late_upgrade_rechecks_source_after_discovery(self):
        _, prompt, item, record = self.late_fixture()
        self.reconcile(prompt, record, mutation=lambda: (self.session / prompt["file"]).unlink())
        self.assertEqual(item["verification_contract"]["mode"], "legacy_fallback")

    def test_late_upgrade_rechecks_source_after_contract_derivation(self):
        _, prompt, item, record = self.late_fixture()
        derive = cg.verification_contract

        def changed(*args, **kwargs):
            result = derive(*args, **kwargs)
            (self.session / prompt["file"]).unlink()
            return result

        with mock.patch.object(cg, "verification_contract", side_effect=changed):
            self.reconcile(prompt, record)
        self.assertEqual(item["verification_contract"]["mode"], "legacy_fallback")

    def test_child_source_spans_and_acceptance_are_validated_without_summary_fallback(self):
        text = "说明。" + "Inspect the attached image. " + "ordinary " * 120 + "Read /work/end.py in full."
        prompt = cg.append_prompt(self.session, self.state, text)
        root = cg.read_prompt_record(self.session, prompt)
        fragment = text[3:]
        for name in ("execution", "information"):
            child = {"prompt_id": prompt["id"], "sha256": prompt["sha256"],
                     "parent_id": "R001", "text": cg.bounded(fragment, 900),
                     name + "_source_span": [len(text[:3].encode()), len(text.encode())],
                     name + "_source_sha256": cg.sha256_text(fragment)}
            self.assertEqual(cg._item_contract_source_text(child, root), fragment)
            for corrupt in ("hash", "bounds", "summary"):
                bad = copy.deepcopy(child)
                if corrupt == "hash":
                    bad[name + "_source_sha256"] = "0" * 64
                if corrupt == "bounds":
                    bad[name + "_source_span"][0] = 1
                if corrupt == "summary":
                    bad["text"] = "a different item"
                self.assertIsNone(cg._item_contract_source_text(bad, root))
        candidate = {"prompt_id": prompt["id"], "text": "must read /work/forged.py"}
        self.assertIsNone(cg._item_contract_source_text(candidate, root, acceptance=True))


if __name__ == "__main__":
    unittest.main()
