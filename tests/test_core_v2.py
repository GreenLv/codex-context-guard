"""Independent predicate controls for the provisional shared state machine."""

import copy
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

def controlled_snapshot():
    x = snapshot()
    text = "持续执行直到当前任务完成。运行测试 test-suite。"
    raw = text.encode("utf-8")
    sha = hashlib.sha256(raw).hexdigest()
    x["sources"][0].update(text=text, sha256=sha, byte_length=len(raw))
    for row in (x["requirements"][0], x["actions"][0]):
        row["source"].update(end=len(raw), sha256=sha)
        row["scope_sha256"] = sha
    start = raw.index(b"test-suite")
    x["requirements"][0]["target_origin"]["root_constraint_source"].update(
        start=start, end=start + len(b"test-suite"), sha256=sha,
    )
    x["coverage"][0]["source"].update(end=len(raw), sha256=sha)
    x["intent"] = {"source": None, "kind": "none"}
    control_span = dict(source_id="root", start=0,
                        end=len("持续执行直到当前任务完成".encode()), sha256=sha)
    req = x["requirements"][0]
    ref = dict(requirement_id="r", unit="u", revision=1, source_id="root",
               seq=1, target="test-suite", scope_sha256=req["scope_sha256"])
    x["root_controls"] = [dict(
        id="persist", kind="persistence", source=control_span, seq=1,
        scope_basis=dict(kind="current_unit", target=None, target_source=None),
        controlled_requirements=[ref],
    )]
    return x


def compound_ellipsis_snapshot(*, independent_second: bool = False):
    x = snapshot()
    text = ("运行测试 test-suite。运行测试 other-suite。不要停止,一直推进直到完成。"
            if independent_second else
            "运行测试 test-suite。不要停止,一直推进直到完成。")
    raw = text.encode("utf-8")
    sha = hashlib.sha256(raw).hexdigest()
    x["sources"][0].update(text=text, sha256=sha, byte_length=len(raw))
    for row in (x["requirements"][0], x["actions"][0]):
        row["source"].update(end=len(raw), sha256=sha)
        row["scope_sha256"] = sha
    target_at = raw.index(b"test-suite")
    x["requirements"][0]["target_origin"]["root_constraint_source"].update(
        start=target_at, end=target_at + len(b"test-suite"), sha256=sha)
    x["coverage"][0]["source"].update(end=len(raw), sha256=sha)
    x["intent"] = {"source": None, "kind": "none"}
    begin = raw.index("不要停止".encode())
    end = begin + len("不要停止,一直推进直到完成".encode())
    refs = [dict(requirement_id="r", unit="u", revision=1, source_id="root",
                 seq=1, target="test-suite", scope_sha256=sha)]
    if independent_second:
        other = copy.deepcopy(x["requirements"][0])
        other.update(id="r2", target="other-suite")
        origin = other["target_origin"]
        at = raw.index(b"other-suite")
        origin.update(root_constraint="other-suite", implementation_choice="other-suite",
                      host_selection="other-suite", resolved="other-suite",
                      observed="other-suite")
        origin["root_constraint_source"].update(start=at, end=at + len(b"other-suite"))
        x["requirements"].append(other)
        refs.append(dict(requirement_id="r2", unit="u", revision=1,
                         source_id="root", seq=1, target="other-suite",
                         scope_sha256=sha))
    x["root_controls"] = [dict(
        id="compound", kind="persistence", seq=1,
        source=dict(source_id="root", start=begin, end=end, sha256=sha),
        scope_basis=dict(kind="current_unit", target=None, target_source=None),
        controlled_requirements=refs,
    )]
    return x


def two_action_snapshot():
    """One real-root edit and an independent focused test, both host-ready."""
    x = snapshot()
    text = "修复 /work/A.py，运行测试 test-suite。"
    raw = text.encode()
    sha = hashlib.sha256(raw).hexdigest()
    x["sources"][0].update(text=text, byte_length=len(raw), sha256=sha)
    test = x["requirements"][0]
    test["source"].update(end=len(raw), sha256=sha)
    test["scope_sha256"] = sha
    test_at = raw.index(b"test-suite")
    test["target_origin"]["root_constraint_source"].update(
        start=test_at, end=test_at + 10, sha256=sha)
    x["actions"][0]["source"].update(end=len(raw), sha256=sha)
    x["actions"][0]["scope_sha256"] = sha
    x["coverage"][0]["source"].update(end=len(raw), sha256=sha)
    x["intent"] = {"source": None, "kind": "none"}
    edit = copy.deepcopy(test)
    edit.update(id="edit", action="local_edit", target="/work/A.py",
                predicate="state_matches", evidence_kind="state_outcome")
    edit_at = raw.index(b"/work/A.py")
    edit["target_origin"].update(
        root_constraint="/work/A.py", subject_kind="filesystem",
        root_constraint_source=dict(source_id="root", start=edit_at,
                                    end=edit_at + len(b"/work/A.py"), sha256=sha),
        implementation_choice="/work/A.py", host_selection="/work/A.py",
        resolved="/work/A.py", observed="/work/A.py",
    )
    x["requirements"].append(edit)
    call = copy.deepcopy(x["sources"][1])
    call.update(id="editcall", seq=4, call_id="edit-call", target="/work/A.py",
                target_kind="filesystem")
    result = copy.deepcopy(x["sources"][2])
    result.update(id="editresult", seq=5, call_id="edit-call")
    x["sources"].extend((call, result))
    ready = copy.deepcopy(x["facts"][0])
    ready.update(id="editready", seq=5, source_id="editresult",
                 call_source_id="editcall", target="/work/A.py",
                 predicate="file_exists", requirement_id="edit")
    x["facts"].append(ready)
    action = copy.deepcopy(x["actions"][0])
    action.update(requirement_id="edit", seq=5, action="local_edit",
                  target="/work/A.py", predicate="state_matches",
                  readiness_fact_ids=["editready"])
    x["actions"].append(action)
    x["as_of"] = 5
    return x


class CoreTests(unittest.TestCase):
    def test_compound_ellipsis_binds_only_one_same_root_task(self):
        positive = project(compound_ellipsis_snapshot())
        self.assertEqual(positive["root_control_states"], {"r": "persistent"})
        self.assertEqual(positive["root_control_errors"], [])
        self.assertTrue(positive["explicit_user_persistence"])
        multiple = project(compound_ellipsis_snapshot(independent_second=True))
        self.assertEqual(multiple["root_control_states"], {})
        self.assertEqual(multiple["root_control_errors"], ["compound"])
        self.assertFalse(multiple["explicit_user_persistence"])

    def test_supersession_window_preserves_earlier_control_but_closes_current_debt(self):
        x = controlled_snapshot()
        text = "改为运行 test-suite。"
        raw = text.encode()
        sha = hashlib.sha256(raw).hexdigest()
        x["sources"].append(dict(x["sources"][0], id="replacement_root", seq=4,
                                 revision=2, text=text, byte_length=len(raw),
                                 sha256=sha, turn="t2"))
        successor = copy.deepcopy(x["requirements"][0])
        successor.update(id="replacement", seq=4, revision=2,
                         source=dict(source_id="replacement_root", start=0,
                                     end=len(raw), sha256=sha), scope_sha256=sha)
        at = raw.index(b"test-suite")
        successor["target_origin"]["root_constraint_source"].update(
            source_id="replacement_root", start=at, end=at + 10, sha256=sha)
        x["requirements"].append(successor)
        old = x["requirements"][0]
        old.update(status="superseded", superseded_at_seq=4,
                   supersession_source_id="replacement_root",
                   superseded_by_requirement_id="replacement")
        x["coverage"].append(dict(source=successor["source"], kind="interpreted"))
        earlier = project(x)
        self.assertEqual(earlier["root_control_states"], {"r": "persistent"})
        self.assertEqual([a["requirement_id"] for a in earlier["current_actions"]], ["r"])
        self.assertEqual(earlier["coverage_errors"], [])
        x["as_of"] = 4
        x["revision"] = 2
        later = project(x)
        self.assertEqual(later["root_control_states"], {"r": "persistent"})
        self.assertFalse(later["explicit_user_persistence"])
        self.assertEqual(later["current_actions"], [])
        self.assertNotIn("r", later["unmet_requirements"])
        self.assertEqual(later["coverage_errors"], [])
        self.assertEqual(later["unknown_coverage"], [])
        with self.subTest("historical_unknown_bytes_still_prevent_certification"):
            y = copy.deepcopy(x)
            y["coverage"][0]["kind"] = "unknown"
            result = project(y)
            self.assertEqual(result["unknown_coverage"], ["root"])
            self.assertFalse(result["certifiable"])
        with self.subTest("unbound_label"):
            y = copy.deepcopy(x)
            for field in ("superseded_at_seq", "supersession_source_id",
                          "superseded_by_requirement_id"):
                y["requirements"][0].pop(field)
            self.assertEqual(project(y)["root_control_errors"], ["persist"])
            self.assertFalse(project(y)["certifiable"])
        with self.subTest("wrong_source"):
            y = copy.deepcopy(x)
            y["requirements"][0]["supersession_source_id"] = "root"
            with self.assertRaisesRegex(ValueError, "supersession_source_mismatch"):
                project(y)
        with self.subTest("same_sequence_control_has_unknown_order"):
            y = copy.deepcopy(x)
            text = "暂停当前任务。改为运行 test-suite。"
            raw = text.encode()
            sha = hashlib.sha256(raw).hexdigest()
            y["sources"][-1].update(text=text, byte_length=len(raw), sha256=sha)
            newer = y["requirements"][-1]
            newer["source"].update(end=len(raw), sha256=sha)
            newer["scope_sha256"] = sha
            target_at = raw.index(b"test-suite")
            newer["target_origin"]["root_constraint_source"].update(
                start=target_at, end=target_at + 10, sha256=sha)
            y["coverage"][-1]["source"].update(end=len(raw), sha256=sha)
            y["root_controls"].append(dict(
                id="pause_same_seq", kind="pause", seq=4,
                source=dict(source_id="replacement_root", start=0,
                            end=len("暂停当前任务".encode()), sha256=sha),
                scope_basis=dict(kind="current_unit", target=None, target_source=None),
                controlled_requirements=[dict(
                    requirement_id="replacement", unit="u", revision=2,
                    source_id="replacement_root", seq=4,
                    target="test-suite", scope_sha256=sha)],
            ))
            self.assertEqual(project(y)["root_control_errors"], ["pause_same_seq"])

    def test_coordinated_direct_control_requires_governing_work_clause(self):
        cases = (
            ("请运行 test-suite 的测试并持续执行直到任务完成。", True),
            ("张三说要运行 test-suite 的测试并持续执行直到任务完成。", False),
            ("不要运行 test-suite 的测试并持续执行直到任务完成。", False),
            ("未来观察 test-suite 的测试并持续执行直到任务完成。", False),
            ("“请运行 test-suite 的测试并持续执行直到任务完成。”", False),
            ("请运行 test-suite 的测试，用户手册写着：并持续执行直到任务完成。", False),
            ("请运行 test-suite 的测试，然后转述别人说：并持续执行直到任务完成。", False),
        )
        for text, accepted in cases:
            with self.subTest(text=text):
                x = controlled_snapshot()
                raw = text.encode()
                sha = hashlib.sha256(raw).hexdigest()
                x["sources"][0].update(text=text, byte_length=len(raw), sha256=sha)
                for row in (x["requirements"][0], x["actions"][0]):
                    row["source"].update(end=len(raw), sha256=sha)
                    row["scope_sha256"] = sha
                x["coverage"][0]["source"].update(end=len(raw), sha256=sha)
                at = raw.index("持续执行".encode())
                x["root_controls"][0]["source"].update(
                    start=at, end=at + len("持续执行直到任务完成".encode()), sha256=sha)
                x["root_controls"][0]["controlled_requirements"][0]["scope_sha256"] = sha
                target_at = raw.index(b"test-suite")
                x["requirements"][0]["target_origin"]["root_constraint_source"].update(
                    start=target_at, end=target_at + 10, sha256=sha)
                self.assertEqual(project(x)["root_control_errors"] == [], accepted)

    def test_current_unit_persistence_natural_english_and_governed_negatives(self):
        positive = (
            "Keep working on this task until it is done.",
            "Keep working until this task is done.",
        )
        negative = (
            "Do not keep working on this task until it is done.",
            '"Keep working on this task until it is done."',
            "Later, keep working on this task until it is done.",
        )
        for clause, expected in [(s, True) for s in positive] + [(s, False) for s in negative]:
            with self.subTest(clause=clause):
                x = controlled_snapshot()
                text = clause + " Run test-suite."
                raw = text.encode()
                sha = hashlib.sha256(raw).hexdigest()
                x["sources"][0].update(text=text, byte_length=len(raw), sha256=sha)
                for row in (x["requirements"][0], x["actions"][0]):
                    row["source"].update(end=len(raw), sha256=sha)
                    row["scope_sha256"] = sha
                x["coverage"][0]["source"].update(end=len(raw), sha256=sha)
                x["root_controls"][0]["source"].update(
                    end=len(clause.rstrip(".").encode()), sha256=sha)
                x["root_controls"][0]["controlled_requirements"][0]["scope_sha256"] = sha
                at = raw.index(b"test-suite")
                x["requirements"][0]["target_origin"]["root_constraint_source"].update(
                    start=at, end=at + len(b"test-suite"), sha256=sha)
                result = project(x)
                self.assertEqual(result["root_control_errors"] == [], expected)

    def test_typed_test_scope_suspends_only_test_not_ready_edit(self):
        x = two_action_snapshot()
        self.assertEqual({a["requirement_id"] for a in project(x)["current_actions"]},
                         {"r", "edit"})
        text = "暂停本轮测试。"
        raw = text.encode()
        sha = hashlib.sha256(raw).hexdigest()
        x["sources"].append(dict(x["sources"][0], id="pause_tests", seq=6,
                                 revision=2, text=text, byte_length=len(raw),
                                 sha256=sha, turn="t2"))
        target = "本轮测试".encode()
        x["root_controls"] = [dict(
            id="pause_tests", kind="pause", seq=6,
            source=dict(source_id="pause_tests", start=0, end=len(raw), sha256=sha),
            scope_basis=dict(kind="action_class", target="test_verify",
                             target_source=dict(source_id="pause_tests",
                                                start=raw.index(target),
                                                end=raw.index(target) + len(target),
                                                sha256=sha)),
            controlled_requirements=[dict(requirement_id="r", unit="u", revision=1,
                                          source_id="root", seq=1,
                                          target="test-suite",
                                          scope_sha256=x["requirements"][0]["scope_sha256"])],
        )]
        x["as_of"] = 6
        result = project(x)
        self.assertEqual(result["root_control_states"], {"r": "paused"})
        self.assertEqual([a["requirement_id"] for a in result["current_actions"]], ["edit"])

    def test_singular_test_scope_requires_unique_test(self):
        x = two_action_snapshot()
        second = copy.deepcopy(x["requirements"][0])
        second["id"] = "second_test"
        x["requirements"].append(second)
        text = "暂停这项测试。"
        raw = text.encode()
        sha = hashlib.sha256(raw).hexdigest()
        x["sources"].append(dict(x["sources"][0], id="pause_one", seq=6,
                                 revision=2, text=text, byte_length=len(raw),
                                 sha256=sha, turn="t2"))
        noun = "这项测试".encode()
        x["root_controls"] = [dict(
            id="pause_one", kind="pause", seq=6,
            source=dict(source_id="pause_one", start=0, end=len(raw), sha256=sha),
            scope_basis=dict(kind="action_class", target="test_verify",
                             target_source=dict(source_id="pause_one", start=raw.index(noun),
                                                end=raw.index(noun) + len(noun), sha256=sha)),
            controlled_requirements=[dict(requirement_id=req["id"], unit="u",
                                          revision=1, source_id="root", seq=1,
                                          target=req["target"],
                                          scope_sha256=req["scope_sha256"])
                                     for req in x["requirements"] if req["action"] == "test_verify"],
        )]
        x["as_of"] = 6
        result = project(x)
        self.assertEqual(result["root_control_states"], {})
        self.assertEqual(result["root_control_errors"], ["pause_one"])

    def test_repair_parent_scope_includes_required_child_not_unrelated_test(self):
        x = two_action_snapshot()
        x["requirements"][0]["parent_id"] = "edit"
        readback = copy.deepcopy(x["requirements"][1])
        readback.update(id="readback", parent_id="edit", action="readback",
                        predicate="state_matches")
        x["requirements"].append(readback)
        other = copy.deepcopy(x["requirements"][0])
        other.update(id="other", parent_id=None, target="other-suite")
        other["target_origin"].update(root_constraint="other-suite",
                                      implementation_choice="other-suite",
                                      host_selection="other-suite", resolved="other-suite",
                                      observed="other-suite")
        x["requirements"].append(other)
        text = "暂停这项修复。"
        raw = text.encode()
        sha = hashlib.sha256(raw).hexdigest()
        x["sources"].append(dict(x["sources"][0], id="pause_repair", seq=6,
                                 revision=2, text=text, byte_length=len(raw),
                                 sha256=sha, turn="t2"))
        noun = "这项修复".encode()
        x["root_controls"] = [dict(
            id="pause_repair", kind="pause", seq=6,
            source=dict(source_id="pause_repair", start=0, end=len(raw), sha256=sha),
            scope_basis=dict(kind="parent_task", target="edit",
                             target_source=dict(source_id="pause_repair", start=raw.index(noun),
                                                end=raw.index(noun) + len(noun), sha256=sha)),
            controlled_requirements=[dict(requirement_id=req["id"], unit="u",
                                          revision=1, source_id="root", seq=1,
                                          target=req["target"],
                                          scope_sha256=req["scope_sha256"])
                                     for req in x["requirements"] if req["id"] != "other"],
        )]
        x["as_of"] = 6
        result = project(x)
        self.assertEqual(result["root_control_states"],
                         {"edit": "paused", "r": "paused", "readback": "paused"})
        self.assertNotIn("other", result["root_control_states"])
        x["requirements"][0]["parent_id"] = None
        self.assertEqual(project(x)["root_control_errors"], ["pause_repair"])

    def test_qualified_repair_until_clause_keeps_parent_scope(self):
        x = two_action_snapshot()
        text = ("请持续完成本轮 parser 修复和测试，直到当前任务完成。"
                "修复 /work/A.py，运行测试 test-suite。")
        raw = text.encode()
        sha = hashlib.sha256(raw).hexdigest()
        x["sources"][0].update(text=text, byte_length=len(raw), sha256=sha)
        for req in x["requirements"]:
            req["source"].update(end=len(raw), sha256=sha)
            req["scope_sha256"] = sha
            literal = req["target"].encode()
            at = raw.index(literal)
            req["target_origin"]["root_constraint_source"].update(
                start=at, end=at + len(literal), sha256=sha)
        for action in x["actions"]:
            action["source"].update(end=len(raw), sha256=sha)
            action["scope_sha256"] = sha
        x["coverage"][0]["source"].update(end=len(raw), sha256=sha)
        x["requirements"][0]["parent_id"] = "edit"
        control_text = text.split("。", 1)[0]
        noun = "本轮 parser 修复和测试".encode()
        x["root_controls"] = [dict(
            id="keep_repair", kind="persistence", seq=1,
            source=dict(source_id="root", start=0,
                        end=len(control_text.encode()), sha256=sha),
            scope_basis=dict(kind="parent_task", target="edit",
                             target_source=dict(source_id="root", start=raw.index(noun),
                                                end=raw.index(noun) + len(noun), sha256=sha)),
            controlled_requirements=[dict(requirement_id=req["id"], unit="u",
                                          revision=1, source_id="root", seq=1,
                                          target=req["target"], scope_sha256=sha)
                                     for req in x["requirements"]],
        )]
        result = project(x)
        self.assertEqual(result["root_control_errors"], [])
        self.assertEqual(result["root_control_states"],
                         {"edit": "persistent", "r": "persistent"})
        unrelated = copy.deepcopy(x["requirements"][0])
        unrelated.update(id="unrelated", parent_id=None, target="other-suite")
        x["requirements"].append(unrelated)
        self.assertNotIn("unrelated", project(x)["root_control_states"])

    def test_root_control_persistence_survives_interlude_but_not_future_scope(self):
        x = controlled_snapshot()
        initial = project(x)
        self.assertEqual(initial["root_control_states"], {"r": "persistent"})
        self.assertEqual(initial["reason_codes"], ["explicit_user_persistence"])
        question = "这项测试为什么必要？"
        raw = question.encode()
        x["sources"].append(dict(x["sources"][0], id="question", seq=4,
                                 revision=2, text=question, sha256=hashlib.sha256(raw).hexdigest(),
                                 byte_length=len(raw), turn="t2"))
        x["as_of"] = 4
        self.assertEqual(project(x)["reason_codes"], ["explicit_user_persistence"])
        # Even when a later requirement appears in the same work unit, the
        # earlier control remains tied to its at-receipt reference set.
        later = copy.deepcopy(x["requirements"][0])
        later.update(id="future", seq=4, revision=2, target="other-suite")
        later["source"] = dict(source_id="question", start=0, end=len(raw),
                               sha256=x["sources"][-1]["sha256"])
        later["scope_sha256"] = later["source"]["sha256"]
        x["requirements"].append(later)
        self.assertEqual(project(x)["root_control_states"], {"r": "persistent"})

    def test_cross_revision_current_catalog_keeps_old_facts_and_information_delivery(self):
        x = snapshot()
        question = "为什么需要测试？"
        raw = question.encode()
        sha = hashlib.sha256(raw).hexdigest()
        question_span = dict(source_id="question", start=0, end=len(raw), sha256=sha)
        question_root = dict(x["sources"][0], id="question", seq=4, revision=2,
                             text=question, sha256=sha, byte_length=len(raw), turn="t2")
        delivered = dict(x["sources"][2], id="delivered", seq=5, revision=2,
                         kind="final_delivery", turn="t2", call_id=None)
        x["sources"].extend((question_root, delivered))
        info = copy.deepcopy(x["requirements"][0])
        info.update(id="information", revision=2, seq=4, source=question_span,
                    kind="information", action="none", target="为什么需要测试",
                    predicate="answer_delivered", scope_sha256=sha,
                    evidence_kind="delivery")
        info["target_origin"].update(root_constraint="为什么需要测试",
                                      implementation_choice="为什么需要测试",
                                      host_selection="为什么需要测试",
                                      resolved="为什么需要测试",
                                      observed="为什么需要测试",
                                      root_constraint_source=dict(question_span, end=len("为什么需要测试".encode())))
        x["requirements"].append(info)
        x["facts"].append(dict(x["facts"][0], id="answer", seq=5, unit="u",
                               revision=2, source_id="delivered", call_source_id=None,
                               kind="delivery", target="为什么需要测试",
                               predicate="answer_delivered", outcome="success",
                               requirement_id="information"))
        x["coverage"].append(dict(source=question_span, kind="interpreted"))
        x.update(revision=2, as_of=5, turn="t2", intent=dict(source=None, kind="none"))
        result = project(x)
        self.assertEqual(result["predicates"], {"r": "insufficient", "information": "satisfied"})
        self.assertEqual(result["delivery"], ["information"])
        self.assertEqual([a["requirement_id"] for a in result["current_actions"]], ["r"])
        self.assertEqual(result["coverage_errors"], [])
        self.assertEqual(result["unknown_coverage"], [])
        self.assertIn("ready", result["facts"])

    def test_foreign_root_control_does_not_create_current_coverage_debt(self):
        x = controlled_snapshot()
        foreign = "暂停当前任务。"
        raw = foreign.encode()
        sha = hashlib.sha256(raw).hexdigest()
        x["units"].append(dict(id="foreign", parent_id=None, required=True,
                               source_id="foreign-root"))
        x["sources"].append(dict(x["sources"][0], id="foreign-root", unit="foreign",
                                 seq=4, revision=2, text=foreign, sha256=sha,
                                 byte_length=len(raw), turn="foreign-turn"))
        control = copy.deepcopy(x["root_controls"][0])
        control.update(id="foreign-control", kind="pause", seq=4,
                       source=dict(source_id="foreign-root", start=0, end=len(raw), sha256=sha))
        x["root_controls"].append(control)
        x["as_of"] = 4
        result = project(x)
        self.assertEqual(result["root_control_states"], {"r": "persistent"})
        self.assertEqual(result["root_control_errors"], [])
        self.assertEqual(result["coverage_errors"], [])
        self.assertEqual(result["unknown_coverage"], [])
        self.assertEqual([a["requirement_id"] for a in result["current_actions"]], ["r"])

    def test_required_child_control_stays_effective_in_parent_closure(self):
        path = Path(__file__).parent / "fixtures/conformance/core_v2/events.json"
        case = next(row for row in json.loads(path.read_text(encoding="utf-8"))["cases"]
                    if row["id"] == "required_child_control_in_parent_closure")
        parent = project(case["input"])
        self.assertEqual(parent["root_control_states"], {"child-r": "paused"})
        self.assertEqual([a["requirement_id"] for a in parent["current_actions"]], ["r"])
        child = copy.deepcopy(case["input"])
        child["unit"] = "child"
        child_projection = project(child)
        self.assertEqual(child_projection["root_control_states"], {"child-r": "paused"})
        self.assertEqual(child_projection["current_actions"], [])

    def test_root_control_pause_resume_cancel_are_prospective(self):
        x = controlled_snapshot()
        original = project(x)
        for seq, kind, text in ((4, "pause", "暂停当前任务。"),
                                (5, "resume", "继续。"),
                                (6, "cancel", "取消当前任务。")):
            raw = text.encode()
            sha = hashlib.sha256(raw).hexdigest()
            source_id = f"control{seq}"
            x["sources"].append(dict(x["sources"][0], id=source_id, seq=seq,
                                     revision=seq, text=text, sha256=sha,
                                     byte_length=len(raw), turn=f"t{seq}"))
            x["root_controls"].append(dict(
                id=source_id, kind=kind,
                source=dict(source_id=source_id, start=0, end=len(raw), sha256=sha),
                seq=seq, scope_basis=dict(kind="current_unit", target=None,
                                          target_source=None),
                controlled_requirements=copy.deepcopy(
                    x["root_controls"][0]["controlled_requirements"]),
            ))
            x["coverage"].append(dict(
                source=dict(source_id=source_id, start=0, end=len(raw), sha256=sha),
                kind="interpreted",
            ))
            x["as_of"] = seq
            result = project(x)
            self.assertEqual(result["coverage_errors"], [])
            self.assertEqual(result["root_control_states"], {
                4: {"r": "persistent_paused"}, 5: {"r": "persistent"},
                6: {"r": "cancelled"},
            }[seq])
            self.assertEqual(bool(result["current_actions"]), seq == 5)
            self.assertEqual(bool(result["unmet_requirements"]), seq != 6)
        x["as_of"] = 3
        earlier = project(x)
        for key in ("root_control_states", "root_control_errors", "current_actions",
                    "explicit_user_persistence", "reason_codes", "stop", "certifiable"):
            self.assertEqual(earlier[key], original[key])

    def test_root_control_source_and_scope_cannot_be_self_asserted(self):
        x = controlled_snapshot()
        for corrupt in (
            lambda y: y["root_controls"][0]["controlled_requirements"][0].update(target="other-suite"),
            lambda y: y["root_controls"][0].update(seq=2),
            lambda y: y["root_controls"][0]["scope_basis"].update(target="test-suite"),
            lambda y: y["root_controls"][0]["source"].update(start=1),
        ):
            y = copy.deepcopy(x)
            corrupt(y)
            result = project(y)
            self.assertFalse(result["explicit_user_persistence"])
            self.assertEqual(result["reason_codes"], [])
            self.assertTrue(result["root_control_errors"])

    def test_root_control_cannot_crop_reported_speech_or_borrow_later_target(self):
        x = controlled_snapshot()
        text = "张三说要持续执行直到当前任务完成。运行测试 test-suite。"
        raw = text.encode()
        sha = hashlib.sha256(raw).hexdigest()
        x["sources"][0].update(text=text, byte_length=len(raw), sha256=sha)
        for row in (x["requirements"][0], x["actions"][0]):
            row["source"].update(end=len(raw), sha256=sha)
            row["scope_sha256"] = sha
        x["coverage"][0]["source"].update(end=len(raw), sha256=sha)
        phrase = "持续执行直到当前任务完成".encode()
        begin = raw.index(phrase)
        x["root_controls"][0]["source"].update(start=begin,
            end=begin + len(phrase), sha256=sha)
        x["root_controls"][0]["controlled_requirements"][0]["scope_sha256"] = sha
        target = raw.index(b"test-suite")
        x["requirements"][0]["target_origin"]["root_constraint_source"].update(
            start=target, end=target + len(b"test-suite"), sha256=sha)
        self.assertEqual(project(x)["root_control_errors"], ["persist"])
        # A separate sentence's target cannot serve as this control's scope.
        x = controlled_snapshot()
        x["root_controls"][0]["scope_basis"] = dict(kind="exact",
            target="test-suite",
            target_source=x["requirements"][0]["target_origin"]["root_constraint_source"])
        self.assertEqual(project(x)["root_control_errors"], ["persist"])

    def test_repeated_pause_keeps_persistence_and_not_ready_does_not_correct(self):
        x = controlled_snapshot()
        x["actions"] = []
        result = project(x)
        self.assertTrue(result["explicit_user_persistence"])
        self.assertEqual(result["stop"], "ordinary_end")
        for seq in (4, 5):
            text = "暂停当前任务。"
            raw = text.encode()
            sha = hashlib.sha256(raw).hexdigest()
            source_id = f"pause{seq}"
            x["sources"].append(dict(x["sources"][0], id=source_id, seq=seq,
                                     revision=seq, text=text, byte_length=len(raw), sha256=sha))
            control = copy.deepcopy(x["root_controls"][0])
            control.update(id=source_id, kind="pause", seq=seq,
                source=dict(source_id=source_id, start=0, end=len(raw), sha256=sha))
            x["root_controls"].append(control)
            x["as_of"] = seq
            self.assertEqual(project(x)["root_control_states"], {"r": "persistent_paused"})

    def test_singleton_scope_cannot_turn_cancel_other_target_into_current_unit(self):
        x = controlled_snapshot()
        text = "取消 B。"
        raw = text.encode()
        sha = hashlib.sha256(raw).hexdigest()
        x["sources"].append(dict(x["sources"][0], id="cancel_other", seq=4,
                                 revision=2, text=text, byte_length=len(raw),
                                 sha256=sha, turn="t2"))
        control = copy.deepcopy(x["root_controls"][0])
        control.update(id="cancel_other", kind="cancel", seq=4,
                       source=dict(source_id="cancel_other", start=0,
                                   end=len(raw), sha256=sha))
        x["root_controls"].append(control)
        x["as_of"] = 4
        result = project(x)
        self.assertEqual(result["root_control_states"], {"r": "persistent"})
        self.assertEqual(result["root_control_errors"], ["cancel_other"])

    def test_specific_action_noun_cannot_govern_whole_unit(self):
        x = controlled_snapshot()
        second = copy.deepcopy(x["requirements"][0])
        second.update(id="edit", action="local_edit", target="/work/A.py",
                      predicate="state_matches", evidence_kind="state_outcome")
        x["requirements"].append(second)
        x["root_controls"][0]["controlled_requirements"].append(dict(
            x["root_controls"][0]["controlled_requirements"][0],
            requirement_id="edit", target="/work/A.py"))
        x["root_controls"][0]["kind"] = "pause"
        text = "暂停本轮测试。运行测试 test-suite。"
        raw = text.encode()
        sha = hashlib.sha256(raw).hexdigest()
        x["sources"][0].update(text=text, sha256=sha, byte_length=len(raw))
        for req in x["requirements"]:
            req["source"].update(end=len(raw), sha256=sha)
            req["scope_sha256"] = sha
        x["actions"][0]["source"].update(end=len(raw), sha256=sha)
        x["actions"][0]["scope_sha256"] = sha
        for ref in x["root_controls"][0]["controlled_requirements"]:
            ref["scope_sha256"] = sha
        x["root_controls"][0]["source"].update(
            end=len("暂停本轮测试".encode()), sha256=sha)
        x["coverage"][0]["source"].update(end=len(raw), sha256=sha)
        at = raw.index(b"test-suite")
        for req in x["requirements"]:
            req["target_origin"]["root_constraint_source"].update(
                start=at, end=at + 10, sha256=sha)
        result = project(x)
        self.assertEqual(result["root_control_states"], {})
        self.assertEqual(result["root_control_errors"], ["persist"])

    def test_quoted_punctuation_and_other_clause_target_do_not_create_control(self):
        for text, phrase, kind, exact in (
            ("“他说；持续执行直到当前任务完成。”运行测试 test-suite。",
             "持续执行直到当前任务完成", "persistence", False),
            ("取消 A，并检查 test-suite。", "取消 A", "cancel", True),
            ("取消 A 和 test-suite。", "取消 A", "cancel", True),
        ):
            with self.subTest(text=text):
                x = controlled_snapshot()
                raw = text.encode()
                sha = hashlib.sha256(raw).hexdigest()
                x["sources"][0].update(text=text, byte_length=len(raw), sha256=sha)
                for row in (x["requirements"][0], x["actions"][0]):
                    row["source"].update(end=len(raw), sha256=sha)
                    row["scope_sha256"] = sha
                x["coverage"][0]["source"].update(end=len(raw), sha256=sha)
                start = raw.index(phrase.encode())
                x["root_controls"][0].update(kind=kind,
                    source=dict(source_id="root", start=start,
                                end=start + len(phrase.encode()), sha256=sha))
                x["root_controls"][0]["controlled_requirements"][0]["scope_sha256"] = sha
                target_at = raw.index(b"test-suite")
                target_span = dict(source_id="root", start=target_at,
                                   end=target_at + len(b"test-suite"), sha256=sha)
                x["requirements"][0]["target_origin"]["root_constraint_source"] = target_span
                if exact:
                    x["root_controls"][0]["scope_basis"] = dict(
                        kind="exact", target="test-suite", target_source=target_span)
                self.assertEqual(project(x)["root_control_errors"], ["persist"])

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
        for case in json.loads(path.read_text(encoding="utf-8"))["cases"]:
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
        oracle = json.loads(path.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(oracle["core_cases"]), 19)
        self.assertGreaterEqual(len(oracle["holdout_cases"]), 6)


if __name__ == "__main__":
    unittest.main()
