"""Independent predicate controls for the provisional shared state machine."""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cg_core_v2 import canonical_bytes, project
from cg_core_v2_schema import load_strict


def snapshot():
    text = "继续执行，运行测试 test-suite。"
    sha = hashlib.sha256(text.encode()).hexdigest()
    span = dict(source_id="root", start=0, end=len(text.encode()), sha256=sha)
    root = dict(
        id="root",
        seq=1,
        kind="root",
        unit="u",
        revision=1,
        sha256=sha,
        byte_length=len(text.encode()),
        text=text,
        call_id=None,
        turn="t",
    )
    call = dict(root, id="call", seq=2, kind="host_call", text=None, call_id="c")
    call["target"] = "test-suite"
    call["target_kind"] = "opaque"
    result = dict(call, id="result", seq=3, kind="host_result")
    result.pop("target")
    result.pop("target_kind")
    req = dict(
        id="r",
        unit="u",
        revision=1,
        seq=1,
        source=span,
        kind="execution",
        action="test_verify",
        target="test-suite",
        predicate="test_passed",
        scope_sha256=sha,
        required=True,
        status="pending",
        parent_id=None,
        evidence_kind="action_event",
        condition_ids=[],
        target_origin=dict(
            constraint_kind="exact",
            subject_kind="opaque",
            selection_source_id=None,
            root_constraint="test-suite",
            root_constraint_source=dict(
                span,
                start=len("继续执行，运行测试 ".encode()),
                end=len("继续执行，运行测试 test-suite".encode()),
            ),
            implementation_choice="test-suite",
            host_selection="test-suite",
            resolved="test-suite",
            observed="test-suite",
        ),
    )
    ready = dict(
        id="ready",
        seq=3,
        unit="u",
        revision=1,
        source_id="result",
        call_source_id="call",
        kind="readiness",
        target="test-suite",
        predicate="inputs_ready",
        outcome="success",
        operation_id=None,
        requirement_id="r",
        condition_id=None,
        invalidates=[],
    )
    action = dict(
        schema="current-action-basis/v1",
        requirement_id="r",
        unit="u",
        revision=1,
        seq=3,
        source=span,
        scope_sha256=sha,
        action="test_verify",
        target="test-suite",
        predicate="test_passed",
        owner="assistant",
        relation="direct",
        readiness_fact_ids=["ready"],
        state="current",
    )
    return dict(
        schema="core-observation/v2",
        unit="u",
        revision=1,
        as_of=3,
        turn="t",
        units=[dict(id="u", parent_id=None, required=True, source_id="root")],
        sources=[root, call, result],
        requirements=[req],
        facts=[ready],
        actions=[action],
        intent=dict(source=span, kind="resume"),
        completion_claim=False,
        proof_violation=False,
        corrections_used=0,
        progress_changed=True,
        goal_contract_adopted=True,
        release_state="not_adopted",
        conditions=[],
        coverage=[dict(source=span, kind="interpreted")],
    )


class CoreTests(unittest.TestCase):
    def test_bare_resume_requires_separate_current_action_basis(self):
        # The intent span is immutable root text; it never creates an action.
        for text, utterance in [
            ("继续。运行测试 test-suite。", "继续。"),
            ("Continue. Run test-suite.", "Continue."),
        ]:
            with self.subTest(utterance=utterance):
                x = snapshot()
                raw = text.encode("utf-8")
                sha = hashlib.sha256(raw).hexdigest()
                x["sources"][0].update(text=text, sha256=sha, byte_length=len(raw))
                for row in [x["requirements"][0], x["actions"][0]]:
                    row["source"].update(start=0, end=len(raw), sha256=sha)
                    row["scope_sha256"] = sha
                x["requirements"][0]["target_origin"]["root_constraint_source"].update(
                    start=raw.index(b"test-suite"),
                    end=raw.index(b"test-suite") + len(b"test-suite"),
                    sha256=sha,
                )
                x["coverage"][0]["source"].update(start=0, end=len(raw), sha256=sha)
                x["intent"]["source"].update(
                    start=0, end=len(utterance.encode("utf-8")), sha256=sha
                )
                self.assertTrue(project(x)["resume_with_actionable_work"])
                self.assertFalse(project(x)["explicit_user_persistence"])
                x["actions"] = []
                self.assertFalse(project(x)["resume_with_actionable_work"])
                self.assertFalse(project(x)["explicit_user_persistence"])

    def test_ready_unrun_test_is_actionable_not_persistence(self):
        result = project(snapshot())
        self.assertEqual(
            [a["action"] for a in result["current_actions"]], ["test_verify"]
        )
        self.assertTrue(result["resume_with_actionable_work"])
        self.assertFalse(result["explicit_user_persistence"])
        self.assertEqual(result["stop"], "bounded_correction")
        self.assertFalse(result["goal_complete_allowed"])

    def test_completed_future_unknown_never_actionable(self):
        for state in [
            "completed",
            "future_observation",
            "capability_unavailable",
            "evidence_insufficient",
            "unknown",
        ]:
            x = snapshot()
            x["actions"][0]["state"] = state
            result = project(x)
            self.assertEqual(result["current_actions"], [])
            self.assertEqual(result["stop"], "ordinary_end")
            self.assertFalse(result["certifiable"])

    def test_positive_host_test_closes_and_wrong_target_does_not(self):
        x = snapshot()
        x["facts"].append(
            dict(
                x["facts"][0], id="tested", kind="action_event", predicate="test_passed"
            )
        )
        self.assertTrue(project(x)["certifiable"])
        x["facts"][-1]["target"] = "other-suite"
        self.assertFalse(project(x)["certifiable"])

    def test_host_call_target_must_match_result_facts(self):
        x = snapshot()
        x["facts"].append(dict(x["facts"][0], id="tested", kind="action_event",
                               predicate="test_passed"))
        self.assertTrue(project(x)["certifiable"])
        x["sources"][1]["target"] = "other-suite"
        result = project(x)
        self.assertFalse(result["certifiable"])
        self.assertEqual(result["current_actions"], [])
        self.assertEqual(result["stop"], "ordinary_end")

    def test_host_call_origin_must_be_a_same_turn_root(self):
        x = snapshot()
        x["sources"][1]["origin_root_source_id"] = "root"
        self.assertTrue(project(x)["resume_with_actionable_work"])
        x["sources"][1]["origin_root_source_id"] = "result"
        with self.assertRaisesRegex(ValueError, "host_call_origin_root_mismatch"):
            project(x)
        x["sources"][1]["origin_root_source_id"] = "root"
        x["sources"][1]["turn"] = "other-turn"
        with self.assertRaisesRegex(ValueError, "host_call_origin_root_mismatch"):
            project(x)

    def test_state_readback_is_not_action_history(self):
        x = snapshot()
        x["facts"].append(
            dict(
                x["facts"][0], id="state", kind="state_outcome", predicate="test_passed"
            )
        )
        self.assertFalse(project(x)["certifiable"])

    def test_call_pair_must_match_and_new_failure_invalidates_success(self):
        x = snapshot()
        x["sources"][2]["call_id"] = "unrelated"
        self.assertEqual(project(x)["current_actions"], [])
        x = snapshot()
        x["facts"].append(
            dict(x["facts"][0], id="pass", kind="action_event", predicate="test_passed")
        )
        x["as_of"] = 4
        x["facts"].append(dict(x["facts"][-1], id="fail", seq=4, outcome="failure"))
        self.assertFalse(project(x)["certifiable"])

    def test_unknown_uncovered_empty_and_utf8_split_do_not_certify(self):
        for mutate in [
            lambda x: x.update(coverage=[]),
            lambda x: x["coverage"][0].update(kind="unknown"),
            lambda x: x.update(requirements=[], actions=[]),
            lambda x: x["coverage"][0]["source"].update(start=1),
        ]:
            x = snapshot()
            mutate(x)
            self.assertFalse(project(x)["certifiable"])

    def test_later_facts_cannot_change_old_stop(self):
        x = snapshot()
        before = project(x)
        x["facts"].append(
            dict(
                x["facts"][0],
                id="later",
                seq=4,
                kind="action_event",
                predicate="test_passed",
            )
        )
        self.assertEqual(before, project(x))

    def test_budget_and_proof_independent(self):
        x = snapshot()
        x["actions"] = []
        x["proof_violation"] = True
        self.assertEqual(project(x)["reason_codes"], ["explicit_proof_unsatisfied"])
        x["corrections_used"] = 1
        self.assertEqual(project(x)["stop"], "ordinary_end")
        self.assertFalse(project(x)["certifiable"])

    def test_generic_and_old_terminal_not_promoted(self):
        x = snapshot()
        x["actions"][0]["action"] = "generic_work"
        self.assertEqual(project(x)["current_actions"], [])
        x["requirements"][0]["status"] = "legacy_review"
        self.assertEqual(project(x)["predicates"]["r"], "legacy_review")

    def test_invalid_input_and_duplicate_json(self):
        x = snapshot()
        x["forged"] = "x"
        with self.assertRaises(ValueError):
            project(x)
        with self.assertRaises(ValueError):
            load_strict('{"a":1,"a":2}')
        for value in [float("nan"), 1.2, 9007199254740992, "\ud800"]:
            with self.assertRaises((ValueError, UnicodeEncodeError)):
                canonical_bytes(value)

    def test_coverage_requires_obligation_and_child_revision_is_independent(self):
        x = snapshot()
        x["requirements"][0]["source"] = dict(x["requirements"][0]["source"], end=6)
        x["actions"] = []
        x["facts"].append(
            dict(
                x["facts"][0], id="passed", kind="action_event", predicate="test_passed"
            )
        )
        self.assertFalse(project(x)["certifiable"])
        x = snapshot()
        x["facts"].append(
            dict(
                x["facts"][0], id="passed", kind="action_event", predicate="test_passed"
            )
        )
        child = dict(x["sources"][0], id="child-root", unit="child", revision=2)
        x["sources"].append(child)
        x["units"].append(
            dict(id="child", parent_id="u", required=True, source_id="child-root")
        )
        child_span = dict(x["coverage"][0]["source"], source_id="child-root")
        x["coverage"].append(dict(source=child_span, kind="interpreted"))
        self.assertFalse(project(x)["certifiable"])

    def test_root_target_conflict_and_late_delivery(self):
        x = snapshot()
        x["facts"].append(
            dict(
                x["facts"][0], id="passed", kind="action_event", predicate="test_passed"
            )
        )
        x["requirements"][0]["target_origin"]["root_constraint"] = "other"
        self.assertFalse(project(x)["certifiable"])
        x = snapshot()
        x["requirements"][0].update(kind="information", evidence_kind="delivery")
        x["sources"][2].update(kind="final_delivery", turn="old-turn")
        x["facts"].append(
            dict(
                x["facts"][0], id="delivered", kind="delivery", predicate="test_passed"
            )
        )
        self.assertFalse(project(x)["certifiable"])
        x["sources"][2]["turn"] = "t"
        self.assertTrue(project(x)["certifiable"])

    def test_work_unit_choice_requires_root_scope_and_trusted_host_selection(self):
        x = snapshot()
        text = "请现在评估本次改动的效果。"
        raw = text.encode("utf-8")
        sha = hashlib.sha256(raw).hexdigest()
        x["sources"][0].update(text=text, sha256=sha, byte_length=len(raw))
        for span in (x["requirements"][0]["source"], x["actions"][0]["source"],
                     x["coverage"][0]["source"], x["intent"]["source"]):
            span.update(sha256=sha, end=len(raw))
        scope = "本次改动的效果"
        begin = len(text[:text.index(scope)].encode("utf-8"))
        end = begin + len(scope.encode("utf-8"))
        origin = x["requirements"][0]["target_origin"]
        origin.update(constraint_kind="work_unit", root_constraint=scope,
                      root_constraint_source=dict(origin["root_constraint_source"],
                                                  start=begin, end=end, sha256=sha),
                      selection_source_id="call")
        target = "measurement:current-change"
        for value in (origin, x["requirements"][0], x["actions"][0], x["facts"][0]):
            if value is origin:
                value.update(implementation_choice=target, host_selection=target,
                             resolved=target, observed=target)
            else:
                value["target"] = target
        x["requirements"][0]["action"] = "evaluate_current_effect"
        x["actions"][0]["action"] = "evaluate_current_effect"
        x["sources"][1]["target"] = target
        self.assertEqual([a["action"] for a in project(x)["current_actions"]],
                         ["evaluate_current_effect"])
        for mutate in (
            lambda y: y["requirements"][0]["target_origin"].update(selection_source_id=None),
            lambda y: y["sources"][1].update(target="another-measurement"),
            lambda y: y["requirements"][0]["target_origin"].update(constraint_kind="exact"),
            lambda y: y.update(facts=[]),
            lambda y: y["sources"][1].update(seq=4),
        ):
            y = json.loads(json.dumps(x))
            mutate(y)
            self.assertEqual(project(y)["current_actions"], [])

    def test_quoted_persistence_is_not_root_intent(self):
        x = snapshot()
        text = "“持续执行直到工作完成”"
        sha = hashlib.sha256(text.encode()).hexdigest()
        x["sources"][0].update(text=text, sha256=sha, byte_length=len(text.encode()))
        for span in [
            x["requirements"][0]["source"],
            x["actions"][0]["source"],
            x["intent"]["source"],
            x["coverage"][0]["source"],
        ]:
            span.update(sha256=sha, end=len(text.encode()))
        x["intent"]["kind"] = "persistence"
        self.assertFalse(project(x)["explicit_user_persistence"])

    def test_normative_event_vectors(self):
        path = Path(__file__).parent / "fixtures/conformance/core_v2/events.json"
        for case in json.loads(path.read_text())["cases"]:
            with self.subTest(case=case["id"]):
                if "expected_error" in case:
                    with self.assertRaisesRegex(ValueError, case["expected_error"]):
                        project(case["input"])
                    continue
                actual = project(case["input"])
                actual["actions"] = [a["action"] for a in actual["current_actions"]]
                for key, value in case["expected"].items():
                    self.assertEqual(actual[key], value)

    def test_oracle_preexists_and_positive_negative_are_separate(self):
        path = (
            Path(__file__).parent
            / "fixtures/conformance/core_v2/independent-oracle.json"
        )
        oracle = json.loads(path.read_text())
        self.assertGreaterEqual(len(oracle["core_cases"]), 19)
        self.assertGreaterEqual(len(oracle["holdout_cases"]), 6)


if __name__ == "__main__":
    unittest.main()
