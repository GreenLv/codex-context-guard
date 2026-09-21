"""Paired production Stop replays for current-action provenance."""

import copy
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import context_guard as cg
from cg_codex_core_adapter import project_current_action


@contextmanager
def physical_tempdir(*, prefix: str):
    """Give positive Host replays a root-time physical path spelling."""
    with tempfile.TemporaryDirectory(prefix=prefix) as raw:
        yield str(Path(raw).resolve(strict=True)) if os.name == "nt" else raw


def root_locator(path: Path) -> str:
    """Give Windows root speech one complete drive-path token."""
    return f'"{path}"' if os.name == "nt" else str(path)


class StopV5Tests(unittest.TestCase):
    def test_english_current_unit_controls_survive_hook_restore_and_keep_stop_watermarks(self):
        nouns = ("this task", "the current task", "current task", "this current task")
        for noun in nouns:
            with self.subTest(noun=noun), physical_tempdir(prefix="stop-v5-en-current-") as tmp:
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
                try:
                    suite = Path(tmp) / "suite.py"
                    suite.write_text("def test_ok(): assert True\n", encoding="utf-8")
                    session = "english-current-unit"
                    def event(kind, turn, **fields):
                        return dict(hook_event_name=kind, session_id=session,
                                    cwd=tmp, turn_id=turn, **fields)
                    directory = Path(tmp) / "private/sessions" / session
                    cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                    cg.dispatch(event("UserPromptSubmit", "t1", prompt=(
                        f"继续执行，运行 {root_locator(suite)} 的测试。")))
                    cg.dispatch(event("UserPromptSubmit", "t2", prompt=(
                        f"Keep working on {noun} until it is complete.")))
                    first = cg.load_state(directory, event("Stop", "t2"))
                    controls = first["root_controls"]
                    self.assertEqual([row["kind"] for row in controls], ["persistence"])
                    self.assertEqual(controls[0]["scope_kind"], "current_unit")
                    self.assertEqual([row["action"] for row in controls[0]["items"]],
                                     ["test_verify"])
                    item_id = controls[0]["items"][0]["id"]
                    self.assertIn(item_id, {row["id"] for row in first["requirements"]})
                    self.assertEqual([row["id"] for row in controls[0]["items"]], [item_id])
                    self.assertEqual(cg.current_root_control_projection(first, directory)[
                        "root_control_states"], {item_id: "persistent"})
                    self.assertEqual(cg.current_root_control_projection(first, directory)[
                        "root_control_errors"], [])
                    cg.dispatch(event("Stop", "t2", last_assistant_message="测试尚未运行。"))
                    old_decision = copy.deepcopy(cg.load_state(directory, event("Stop", "t2"))[
                        "decision_log"][-1])

                    cg.dispatch(event("UserPromptSubmit", "t3", prompt=(
                        "顺便解释一下这个函数为什么要处理空输入？")))
                    information = cg.load_state(directory, event("Stop", "t3"))
                    self.assertEqual(cg.current_root_control_projection(information, directory)[
                        "root_control_states"], {item_id: "persistent"})
                    cg.dispatch(event("UserPromptSubmit", "t4", prompt=f"Pause {noun}."))
                    paused = cg.load_state(directory, event("Stop", "t4"))
                    self.assertEqual([row["kind"] for row in paused["root_controls"]],
                                     ["persistence", "pause"])
                    self.assertEqual(cg.current_root_control_projection(paused, directory)[
                        "root_control_states"], {item_id: "persistent_paused"})
                    self.assertEqual(paused["decision_log"][-1], old_decision)
                    cg.dispatch(event("UserPromptSubmit", "t5", prompt=f"Continue {noun}."))
                    resumed = cg.load_state(directory, event("Stop", "t5"))
                    self.assertEqual(cg.current_root_control_projection(resumed, directory)[
                        "root_control_states"], {item_id: "persistent"})
                    cg.dispatch(event("UserPromptSubmit", "t6", prompt=f"Cancel {noun}."))
                    cancelled = cg.load_state(directory, event("Stop", "t6"))
                    self.assertEqual([row["kind"] for row in cancelled["root_controls"]],
                                     ["persistence", "pause", "resume", "cancel"])
                    self.assertEqual([row["id"] for row in cancelled["root_controls"][-1]["items"]],
                                     [item_id])
                    self.assertEqual(cancelled["decision_log"][-1], old_decision)
                    # Cold load reads persisted receipts; it may not derive a new
                    # control from the latest text or bind it to a later item.
                    again = cg.load_state(directory, event("Stop", "t6"))
                    self.assertEqual(again["root_controls"], cancelled["root_controls"])
                    self.assertEqual(again["work_state"]["active_work_unit_id"], None)
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_english_control_negative_sources_do_not_bind_current_task(self):
        negative = (
            'The README says "Pause the current task."',
            'The user once wrote "Keep working on this current task until it is complete."',
            'If the test fails later, pause the current task.',
            'At a future time, cancel this current task.',
            'Pause the deployment task.',
            'Do not pause the current task.',
        )
        for index, text in enumerate(negative):
            with self.subTest(text=text), physical_tempdir(prefix="stop-v5-en-negative-") as tmp:
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
                try:
                    session = f"en-negative-{index}"
                    def event(kind, turn, **fields):
                        return dict(hook_event_name=kind, session_id=session,
                                    cwd=tmp, turn_id=turn, **fields)
                    cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                    cg.dispatch(event("UserPromptSubmit", "t1", prompt="运行 suite 测试。"))
                    cg.dispatch(event("UserPromptSubmit", "t2", prompt=text))
                    directory = Path(tmp) / "private/sessions" / session
                    state = cg.load_state(directory, event("Stop", "t2"))
                    self.assertEqual(state["root_controls"], [])
                    projected = cg.current_root_control_projection(state, directory)
                    if projected is not None:
                        self.assertEqual(projected["root_control_states"], {})
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_complete_english_cancel_prompt_preserves_span_and_does_not_swallow_business_tail(self):
        complete = (
            "Cancel this task.",
            "Cancel this task",
            "Cancel this task。",
            "  Cancel this task.  ",
        )
        for index, text in enumerate(complete):
            with self.subTest(text=text), physical_tempdir(prefix="stop-v5-en-cancel-edge-") as tmp:
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
                try:
                    session = f"en-cancel-edge-{index}"
                    def event(kind, turn, **fields):
                        return dict(hook_event_name=kind, session_id=session,
                                    cwd=tmp, turn_id=turn, **fields)
                    cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                    cg.dispatch(event("UserPromptSubmit", "t1", prompt="运行 suite 测试。"))
                    cg.dispatch(event("UserPromptSubmit", "t2", prompt=text))
                    directory = Path(tmp) / "private/sessions" / session
                    state = cg.load_state(directory, event("Stop", "t2"))
                    self.assertEqual(state["root_controls"][-1]["kind"], "cancel")
                    self.assertEqual(state["work_state"]["active_work_unit_id"], None)
                    self.assertEqual(state["work_units"][0]["status"],
                                     "historical_unresolved")
                    self.assertFalse(any(item["prompt_id"] == state["prompts"][-1]["id"]
                                         for item in state["acceptance_items"]))
                    self.assertEqual(cg.load_state(directory, event("Stop", "t2"))[
                        "root_controls"], state["root_controls"])
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous
        mixed = "Cancel this task. Run another test."
        segments = cg._root_control_segments(mixed)
        self.assertTrue(segments)
        self.assertFalse(any(cg._root_control_covers_prompt(mixed, begin, end)
                             for _, begin, end, _ in segments))
        self.assertEqual(cg._root_control_segments('The log says "Cancel this task."'), [])

    def test_completed_english_persistence_does_not_create_resume_test_action(self):
        with physical_tempdir(prefix="stop-v5-en-complete-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                suite = Path(tmp) / "suite.py"
                suite.write_text("def test_ok(): assert True\n", encoding="utf-8")
                session = "en-completed-current-unit"
                def event(kind, turn, **fields):
                    return dict(hook_event_name=kind, session_id=session,
                                cwd=tmp, turn_id=turn, **fields)
                directory = Path(tmp) / "private/sessions" / session
                cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", "t1", prompt=(
                    f"请运行 {root_locator(suite)} 的测试并持续执行直到任务完成。")))
                cg.dispatch(event("UserPromptSubmit", "t2", prompt=(
                    "Keep working on this current task until it is complete.")))
                for command in (f"test -f {suite}", f"pytest {suite}"):
                    cg.dispatch(event("PostToolUse", "t2", tool_name="exec_command",
                                      tool_input={"cmd": command},
                                      tool_response={"exit_code": 0, "output": "1 passed"}))
                cg.dispatch(event("Stop", "t2", last_assistant_message="测试通过。"))
                completed = cg.load_state(directory, event("Stop", "t2"))
                projection = cg.current_root_control_projection(completed, directory)
                self.assertIsNotNone(projection)
                self.assertEqual(projection["current_actions"], [])
                self.assertFalse(cg.current_persistence_actions(completed, directory)[1])
                cg.dispatch(event("UserPromptSubmit", "t3", prompt="Continue."))
                resumed = cg.load_state(directory, event("Stop", "t3"))
                self.assertEqual(cg.current_persistence_actions(resumed, directory)[1], [])
                self.assertEqual(cg.current_root_control_projection(resumed, directory)[
                    "current_actions"], [])
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_subjectless_compound_control_uses_only_same_root_task(self):
        cases = (
            ("unique", ("运行suite测试。不要停止,一直推进直到完成。",), True),
            ("quoted", ("运行 suite 测试。文档写着：“不要停止，一直推进直到完成。”",), False),
            ("future", ("运行 suite 测试。以后观察是否要一直推进直到完成。",), False),
            ("attributed", ("运行 suite 测试。张三说不要停止，一直推进直到完成。",), False),
            ("independent", ("运行 suiteA 测试并修改 B。不要停止,一直推进直到完成。",), False),
            ("two-tests", ("运行 suiteA 测试。运行 suiteB 测试。不要停止，一直推进直到完成。",), False),
            ("cross-root", ("运行 suite 测试。", "不要停止，一直推进直到完成。"), False),
            ("negated", ("运行suite测试。不要一直推进直到完成。",), False),
            ("reported", ("运行suite测试。文档提醒：不要停止,一直推进直到完成。",), False),
        )
        for label, roots, expected in cases:
            with self.subTest(label=label), physical_tempdir(prefix="stop-v5-ellipsis-") as tmp:
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
                try:
                    session = f"ellipsis-{label}"
                    def event(turn, prompt):
                        return dict(hook_event_name="UserPromptSubmit", session_id=session,
                                    cwd=tmp, turn_id=turn, prompt=prompt)
                    cg.dispatch(event("t0", "context-guard on"))
                    for index, root in enumerate(roots, start=1):
                        cg.dispatch(event(f"t{index}", root))
                    directory = Path(tmp) / "private/sessions" / session
                    state = cg.load_state(directory, dict(hook_event_name="Stop",
                        session_id=session, cwd=tmp, turn_id=f"t{len(roots)}"))
                    controls = [c for c in state["root_controls"]
                                if c.get("kind") == "persistence"]
                    self.assertEqual(bool(controls), expected)
                    if expected:
                        self.assertEqual(len(controls), 1)
                        self.assertEqual(len(controls[0]["items"]), 1)
                        span = controls[0]["source_span"]
                        self.assertIn("不要停止", roots[-1].encode("utf-8")[
                            span[0]:span[1]].decode("utf-8"))
                        self.assertEqual(controls[0]["scope_kind"], "current_unit")
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_subjectless_compound_control_includes_root_proven_repair_children(self):
        with physical_tempdir(prefix="stop-v5-ellipsis-parent-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                target = Path(tmp) / "A.ts"
                target.write_bytes(b"old\n")
                session = "ellipsis-parent"
                def event(turn, prompt):
                    return dict(hook_event_name="UserPromptSubmit", session_id=session,
                                cwd=tmp, turn_id=turn, prompt=prompt)
                cg.dispatch(event("t0", "context-guard on"))
                cg.dispatch(event("t1", f"修改 {root_locator(target)} 并运行 {root_locator(target)} 的测试。不要停止,一直推进直到完成。"))
                directory = Path(tmp) / "private/sessions" / session
                state = cg.load_state(directory, dict(hook_event_name="Stop",
                    session_id=session, cwd=tmp, turn_id="t1"))
                children = [r for r in state["requirements"]
                            if r.get("execution_source_span") is not None]
                self.assertEqual({r["execution_kind"] for r in children},
                                 {"local_edit", "test_verify"})
                edit = next(r for r in children if r["execution_kind"] == "local_edit")
                test = next(r for r in children if r["execution_kind"] == "test_verify")
                self.assertEqual(test["required_for_item_id"], edit["id"])
                controls = [c for c in state["root_controls"]
                            if c.get("kind") == "persistence"]
                self.assertEqual(len(controls), 1)
                self.assertEqual({r["id"] for r in controls[0]["items"]},
                                 {edit["id"], test["id"]})
                normalized = cg.current_root_control_projection(state, directory)
                self.assertEqual(set(normalized["root_control_states"].values()),
                                 {"persistent"})
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_subjectless_compound_control_includes_all_required_tests(self):
        with physical_tempdir(prefix="stop-v5-ellipsis-children-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                target = Path(tmp) / "A.ts"
                target.write_bytes(b"old\n")
                session = "ellipsis-children"
                def event(turn, prompt):
                    return dict(hook_event_name="UserPromptSubmit", session_id=session,
                                cwd=tmp, turn_id=turn, prompt=prompt)
                cg.dispatch(event("t0", "context-guard on"))
                cg.dispatch(event("t1", f"修改 {root_locator(target)}，并运行 {root_locator(target)} 的单元测试，"
                          f"并运行 {root_locator(target)} 的回归测试。不要停止,一直推进直到完成。"))
                directory = Path(tmp) / "private/sessions" / session
                state = cg.load_state(directory, dict(hook_event_name="Stop",
                    session_id=session, cwd=tmp, turn_id="t1"))
                children = [r for r in state["requirements"]
                            if r.get("execution_source_span") is not None]
                self.assertEqual(len(children), 3)
                parent = next(r for r in children if r["execution_kind"] == "local_edit")
                self.assertEqual({r.get("required_for_item_id") for r in children[1:]},
                                 {parent["id"]})
                controls = [c for c in state["root_controls"]
                            if c.get("kind") == "persistence"]
                self.assertEqual(len(controls), 1)
                self.assertEqual({row["id"] for row in controls[0]["items"]},
                                 {row["id"] for row in children})
                normalized = cg.current_root_control_projection(state, directory)
                self.assertEqual(set(normalized["root_control_states"].values()),
                                 {"persistent"})
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_subjectless_compound_control_does_not_follow_later_task(self):
        with physical_tempdir(prefix="stop-v5-ellipsis-later-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                session = "ellipsis-later"
                def event(turn, prompt):
                    return dict(hook_event_name="UserPromptSubmit", session_id=session,
                                cwd=tmp, turn_id=turn, prompt=prompt)
                cg.dispatch(event("t0", "context-guard on"))
                cg.dispatch(event("t1", "运行 suite 测试。不要停止,一直推进直到完成。"))
                directory = Path(tmp) / "private/sessions" / session
                before = cg.load_state(directory, dict(hook_event_name="Stop",
                    session_id=session, cwd=tmp, turn_id="t1"))
                prior = next(c for c in before["root_controls"]
                             if c.get("kind") == "persistence")
                bound = {row["id"] for row in prior["items"]}
                self.assertEqual(len(bound), 1)
                cg.dispatch(event("t2", "另运行 B 的测试。"))
                after = cg.load_state(directory, dict(hook_event_name="Stop",
                    session_id=session, cwd=tmp, turn_id="t2"))
                retained = next(c for c in after["root_controls"]
                                if c.get("kind") == "persistence")
                self.assertEqual({row["id"] for row in retained["items"]}, bound)
                later = [r for r in after["requirements"]
                         if r["prompt_id"] != before["root_controls"][0]["source_prompt_id"]
                         and "B" in r["text"]]
                self.assertTrue(later)
                self.assertFalse(bound & {r["id"] for r in later})
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    @staticmethod
    def root_file(cwd, relative):
        # Windows relative root constraints are explicitly unsupported in
        # core/v2; keep this positive Host replay on one complete absolute
        # root token, including when the physical temp directory has spaces.
        return root_locator(Path(cwd) / relative) if os.name == "nt" else relative

    def test_windows_drive_host_commands_keep_typed_targets(self):
        state = {
            "session": {"cwd": "D:\\work"},
            "work_state": {"active_work_unit_id": "w"},
            "work_units": [{"id": "w", "prompt_id": "P0001"}],
            "requirements": [{"work_unit_id": "w", "prompt_id": "P0001"}],
        }
        for command, target, predicate in (
            (r"test -f D:\work\suite.py", r"D:\work\suite.py", "file_exists"),
            (r'cat "D:\work\a file.ts"', r"D:\work\a file.ts", "content_hash"),
            (r"pytest D:\work\suite.py", r"D:\work\suite.py", "test_passed"),
        ):
            with self.subTest(command=command):
                payload = {"tool_name": "exec_command", "tool_input": {"cmd": command},
                           "tool_response": {"exit_code": 0, "output": "ok"},
                           "turn_id": "turn"}
                # A lexical drive path and a claimed successful tool result
                # alone never establish physical identity on this host.
                self.assertIsNone(cg.core_shell_observation(
                    state, payload, "success", "structured_exit_code"))
                with mock.patch.object(cg, "_verified_windows_target", return_value=target):
                    observation = cg.core_shell_observation(
                        state, payload, "success", "structured_exit_code")
                self.assertIsNotNone(observation)
                self.assertEqual(observation["target"], target)
                self.assertEqual(observation["predicate"], predicate)
        git_payload = {"tool_name": "exec_command",
                       "tool_input": {"cmd": r"git -C D:\repo rev-parse --show-toplevel"},
                       "tool_response": {"exit_code": 0, "output": "D:\\repo\n"},
                       "turn_id": "turn"}
        self.assertIsNone(cg.core_git_observation(
            state, git_payload, "success", "structured_exit_code"))
        with mock.patch.object(cg, "_verified_windows_target", return_value=r"D:\repo"):
            git = cg.core_git_observation(
                state, git_payload, "success", "structured_exit_code")
        self.assertIsNotNone(git)
        self.assertEqual(git["target"], r"D:\repo")
        for command in (r"test -f D:\work\suite.py; echo ok",
                        r"test -f \\server\share\suite.py"):
            with self.subTest(rejected=command):
                self.assertIsNone(cg.core_shell_observation(
                    state,
                    {"tool_name": "exec_command", "tool_input": {"cmd": command},
                     "tool_response": {"exit_code": 0, "output": ""}},
                    "success", "structured_exit_code",
                ))

    def test_observation_uses_declared_shell_dialect(self):
        state = {
            "session": {"cwd": r"D:\work"},
            "work_state": {"active_work_unit_id": "w"},
            "work_units": [{"id": "w", "prompt_id": "P0001"}],
            "requirements": [{"work_unit_id": "w", "prompt_id": "P0001"}],
        }
        command = r"test -f D:\work\suite.py"
        def payload(shell):
            return {"tool_name": "exec_command",
                    "tool_input": {"cmd": command, "shell": shell},
                    "tool_response": {"exit_code": 0, "output": ""},
                    "turn_id": "turn"}
        with mock.patch.object(cg, "_verified_windows_target", return_value=r"D:\work\suite.py") as verify:
            observed = cg.core_shell_observation(
                state, payload("pwsh"), "success", "structured_exit_code")
            self.assertIsNotNone(observed)
            self.assertEqual(observed["target"], r"D:\work\suite.py")
            verify.reset_mock()
            for shell in ("bash", "fish", ""):
                with self.subTest(shell=shell):
                    self.assertIsNone(cg.core_shell_observation(
                        state, payload(shell), "success", "structured_exit_code"))
                    verify.assert_not_called()

    def test_drive_absolute_root_to_host_fact_needs_physical_identity(self):
        target = r"D:\work\suite.py"
        root = f'继续执行，运行 "{target}" 的测试。'
        def ready(_cg, event, _cwd):
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                        tool_input={"cmd": f"test -f {target}", "shell": "pwsh"},
                        tool_response={"exit_code": 0, "output": ""}))
        with mock.patch.object(cg, "_verified_windows_target", return_value=target):
            result, decision, state = self.replay(
                root, "测试尚未运行。", preparation=ready, include_state=True)
        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(len(decision["core_projections"]), 1)
        self.assertEqual(decision["actions"][0]["actionability"], "current_ready")
        self.assertTrue(any(e.get("core_observation", {}).get("target") == target
                            for e in state["evidence"]))
        with mock.patch.object(cg, "_verified_windows_target", return_value=None):
            result, decision, state = self.replay(
                root, "测试尚未运行。", preparation=ready, include_state=True)
        self.assertEqual(result, {})
        self.assertEqual(decision["core_projections"], [])
        self.assertFalse(any(e.get("core_observation") for e in state["evidence"]))
        with mock.patch.object(cg, "_verified_windows_target", return_value=target):
            result, decision = self.replay(
                f"继续执行，运行 {target} 的测试。", "测试尚未运行。",
                preparation=ready)
        self.assertEqual(result, {})
        self.assertEqual(decision["core_projections"], [])
        self.assertFalse(any(a.get("actionability") == "current_ready"
                             for a in decision["actions"]))

    def test_unquoted_windows_path_with_space_never_selects_prefix(self):
        root = r"修改 C:\Work Space\A.ts 并运行测试。"
        self.assertTrue(cg.root_absolute_locator_mentions(root)[1])
        prefix = r"C:\Work"
        def ready(_cg, event, _cwd):
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                              tool_input={"cmd": f"test -f {prefix}", "shell": "pwsh"},
                              tool_response={"exit_code": 0, "output": ""}))
        with mock.patch.object(cg, "_verified_windows_target", return_value=prefix):
            result, decision = self.replay(root, "修改和测试尚未完成。", preparation=ready)
        self.assertEqual(result, {})
        self.assertEqual(decision["core_projections"], [])
        self.assertFalse(any(a.get("actionability") == "current_ready"
                             for a in decision["actions"]))

    def test_drive_absolute_prohibition_uses_root_target_and_host_effect(self):
        api = r"D:\work\packages\api\src\request.ts"
        web = r"D:\work\packages\web\src\request.ts"
        root = f"请只修改 {api}。错误日志还提到了 {web}，但本轮不要动后者。"

        def observed(_cg, event, _cwd, *, change_web=False):
            for target in ((api, web) if change_web else (api,)):
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"cat {target}", "shell": "pwsh"},
                                  tool_response={"exit_code": 0, "output": "before\n"}))
                cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                                  tool_input={"patch": f"*** Begin Patch\n*** Update File: {target}\n@@\n-before\n+after\n*** End Patch\n"},
                                  tool_response={"success": True}))
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"cat {target}", "shell": "pwsh"},
                                  tool_response={"exit_code": 0, "output": "after\n"}))

        with mock.patch.object(cg, "_verified_windows_target", side_effect=lambda raw, **_: raw):
            for change_web, expected in ((False, "constraint_active"),
                                         (True, "constraint_violated")):
                with self.subTest(change_web=change_web):
                    _, decision = self.replay(
                        root, "API 文件已修改并核对。",
                        preparation=lambda a, b, c: observed(a, b, c, change_web=change_web))
                    row = next(r for r in decision["core_projections"]
                               if r["predicate"] == "edit_with_prohibition")
                    self.assertEqual(row["constraint_state"], expected)
                    self.assertEqual(row["certifiable"], not change_web)
                    self.assertEqual(bool(row["violating_host_event_ids"]), change_web)
            _, claim = self.replay(root, "API 和 web 文件都改了。", preparation=observed)
        row = next(r for r in claim["core_projections"]
                   if r["predicate"] == "edit_with_prohibition")
        self.assertEqual(row["constraint_state"], "constraint_active")

    def test_windows_physical_alias_is_not_a_file_fact(self):
        class PhysicalPath:
            def __init__(self, resolved, links):
                self.resolved = resolved
                self.links = links

            def resolve(self, *, strict):
                self_test.assertTrue(strict)
                return self.resolved

            def is_file(self):
                return True

            def stat(self):
                return SimpleNamespace(st_nlink=self.links)

        self_test = self
        with mock.patch.object(cg.os, "name", "nt"):
            for physical, links, expected in (
                (r"D:\work\file.ts", 1, r"D:\work\file.ts"),
                (r"D:\real\file.ts", 1, None),
                (r"D:\Work\file.ts", 1, None),
                (r"D:\work\file.ts", 2, None),
            ):
                with self.subTest(physical=physical, links=links), mock.patch.object(
                    cg, "Path", return_value=PhysicalPath(physical, links)
                ):
                    self.assertEqual(
                        cg._verified_windows_target(r"D:\work\file.ts"), expected
                    )
            self.assertIsNone(cg._verified_windows_target(r"\\server\share\file.ts"))
            self.assertIsNone(cg._verified_windows_target(r"D:work\file.ts"))

    def test_text_only_owner_roles_do_not_create_current_readiness(self):
        prompt = "请运行本轮测试。"
        cases = (
            ("本轮测试还未运行，我会继续。", "assistant", "allow_neutral"),
            ("请先登录 GitHub Desktop，完成后告诉我。", "user", "allow_user_handoff"),
            ("PR 正在等待外部审核。", "external", "allow_external_wait"),
        )
        for reply, role, expected in cases:
            with self.subTest(role=role):
                decision = cg.classify_stop_decision(reply, prompt)
                self.assertEqual(decision["outcome"], expected)
                self.assertTrue(any(a["owner"] == role for a in decision["actions"]))
                self.assertFalse(any(a.get("authorization") == "authorized"
                                     for a in decision["actions"]))
                self.assertEqual(decision["interpretation"]["remaining_action_owner"],
                                 "unknown")

    def test_delivered_explanation_and_verified_edit_share_complete_root_coverage(self):
        def observed(_cg, event, cwd):
            target = Path(cwd) / "src/queue.ts"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"before\n")
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                              tool_input={"cmd": f"cat {root_locator(target)}"},
                              tool_response={"exit_code": 0, "output": "before\n"}))
            target.write_bytes(b"after\n")
            cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                              tool_input={"patch": f"*** Begin Patch\n*** Update File: {target}\n@@\n-before\n+after\n*** End Patch\n"},
                              tool_response={"success": True}))
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                              tool_input={"cmd": f"cat {root_locator(target)}"},
                              tool_response={"exit_code": 0, "output": "after\n"}))
        result, decision, state = self.replay(
            lambda cwd: ("先说明原因，再修正 "
                         f"{self.root_file(cwd, 'src/queue.ts')} 并核对文件内容。"),
            "原因已说明，文件已修正并回读。", preparation=observed, include_state=True)
        self.assertEqual(result, {})
        self.assertTrue(any(r.get("information_source_span") is not None and
                            r["status"] == "answered" for r in state["requirements"]))
        mixed = [r for r in decision["core_projections"]
                 if r["predicate"] == "information_and_edit"]
        self.assertEqual(len(mixed), 1)
        self.assertEqual(mixed[0]["predicate_state"], "satisfied")
        self.assertTrue(mixed[0]["certifiable"])
        self.assertEqual(mixed[0]["unknown_coverage_count"], 0)

    def test_exact_edit_with_reported_other_path_and_prohibition(self):
        def observed(_cg, event, cwd):
            target = Path(cwd) / "packages/api/src/request.ts"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("before\n", encoding="utf-8")
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                              tool_input={"cmd": f"cat {target}"},
                              tool_response={"exit_code": 0, "output": "before\n"}))
            target.write_text("after\n", encoding="utf-8")
            cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                              tool_input={"patch": f"*** Begin Patch\n*** Update File: {target}\n@@\n-before\n+after\n*** End Patch\n"},
                              tool_response={"success": True}))
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                              tool_input={"cmd": f"cat {target}"},
                              tool_response={"exit_code": 0, "output": "after\n"}))
        def root(cwd):
            return (
                f"请只修改 {self.root_file(cwd, 'packages/api/src/request.ts')}。"
                "错误日志还提到了 "
                f"{self.root_file(cwd, 'packages/web/src/request.ts')}，但本轮不要动后者。"
            )
        result, decision = self.replay(root, "API 文件已修改并核对。", preparation=observed)
        self.assertEqual(result, {})
        rows = [r for r in decision["core_projections"]
                if r["predicate"] == "edit_with_prohibition"]
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["certifiable"])
        self.assertEqual(rows[0]["violating_host_event_ids"], [])
        _, mere_claim = self.replay(root, "API 已修改，web 文件也改了。", preparation=observed)
        claimed_rows = [r for r in mere_claim["core_projections"]
                        if r["predicate"] == "edit_with_prohibition"]
        self.assertEqual(len(claimed_rows), 1)
        self.assertTrue(claimed_rows[0]["certifiable"])

        def observed_with_forbidden_edit(_cg, event, cwd):
            observed(_cg, event, cwd)
            forbidden = Path(cwd) / "packages/web/src/request.ts"
            forbidden.parent.mkdir(parents=True, exist_ok=True)
            forbidden.write_text("before\n", encoding="utf-8")
            forbidden.write_text("after\n", encoding="utf-8")
            cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                              tool_input={"patch": f"*** Begin Patch\n*** Update File: {forbidden}\n@@\n-before\n+after\n*** End Patch\n"},
                              tool_response={"success": True}))
        _, forbidden_effect = self.replay(root, "API 文件已修改并核对。",
                                          preparation=observed_with_forbidden_edit)
        forbidden_rows = [r for r in forbidden_effect["core_projections"]
                          if r["predicate"] == "edit_with_prohibition"]
        self.assertEqual(len(forbidden_rows), 1)
        self.assertEqual(forbidden_rows[0]["constraint_state"], "constraint_violated")
        self.assertFalse(forbidden_rows[0]["certifiable"])
        self.assertTrue(forbidden_rows[0]["violating_host_event_ids"])
        for operation in ("Add", "Delete"):
            with self.subTest(operation=operation):
                def observed_with_other_mutation(_cg, event, cwd):
                    observed(_cg, event, cwd)
                    forbidden = Path(cwd) / "packages/web/src/request.ts"
                    forbidden.parent.mkdir(parents=True, exist_ok=True)
                    if operation == "Add":
                        forbidden.write_text("created\n", encoding="utf-8")
                        patch = f"*** Begin Patch\n*** Add File: {forbidden}\n+created\n*** End Patch\n"
                    else:
                        forbidden.write_text("old\n", encoding="utf-8")
                        forbidden.unlink()
                        patch = f"*** Begin Patch\n*** Delete File: {forbidden}\n*** End Patch\n"
                    cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                                      tool_input={"patch": patch},
                                      tool_response={"success": True}))
                _, mutation = self.replay(root, "API 文件已修改并核对。",
                                          preparation=observed_with_other_mutation)
                row = next(r for r in mutation["core_projections"]
                           if r["predicate"] == "edit_with_prohibition")
                self.assertEqual(row["constraint_state"], "constraint_violated")
                self.assertFalse(row["certifiable"])
                self.assertTrue(row["violating_host_event_ids"])

        def observed_with_unknown_shell(_cg, event, cwd):
            observed(_cg, event, cwd)
            cg.dispatch(event("PostToolUse", tool_name="exec_command",
                              tool_input={"cmd": "printf changed > packages/web/src/request.ts"},
                              tool_response={"exit_code": 0, "output": ""}))
        _, unknown_effect = self.replay(root, "API 文件已修改并核对。",
                                        preparation=observed_with_unknown_shell)
        row = next(r for r in unknown_effect["core_projections"]
                   if r["predicate"] == "edit_with_prohibition")
        self.assertFalse(row["certifiable"])
        self.assertTrue(row["unattributed_host_event_ids"])
        def observed_with_alias_edit(_cg, event, cwd):
            observed(_cg, event, cwd)
            outside = Path(cwd) / "outside.ts"
            outside.write_text("before\n", encoding="utf-8")
            forbidden = Path(cwd) / "packages/web/src/request.ts"
            forbidden.parent.mkdir(parents=True, exist_ok=True)
            try:
                forbidden.symlink_to(outside)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows symlink privilege is unavailable")
                raise
            outside.write_text("after\n", encoding="utf-8")
            cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                              tool_input={"patch": f"*** Begin Patch\n*** Update File: {forbidden}\n@@\n-before\n+after\n*** End Patch\n"},
                              tool_response={"success": True}))
        with self.subTest(case="symlinked forbidden target"):
            _, alias_effect = self.replay(root, "API 文件已修改并核对。",
                                          preparation=observed_with_alias_edit)
            alias_row = next(r for r in alias_effect["core_projections"]
                             if r["predicate"] == "edit_with_prohibition")
            self.assertFalse(alias_row["certifiable"])
            self.assertEqual(alias_row["violating_host_event_ids"], [])
        # An extra unresolved positive request must remain open even when the
        # exact edit and prohibition are otherwise identical.
        _, unresolved = self.replay(lambda cwd: root(cwd) + " 同时完成未命名的迁移。",
                                    "API 文件已修改并核对。", preparation=observed)
        self.assertFalse(any(r["certifiable"] for r in unresolved["core_projections"]))
        competing = ("请只修改 packages/api/src/request.ts。日志还提到了 "
                     "packages/web/src/request.ts 与 packages/mobile/src/request.ts，"
                     "但本轮不要动后者。")
        _, ambiguous = self.replay(competing, "API 文件已修改并核对。",
                                   preparation=observed)
        self.assertFalse(any(r["certifiable"] for r in ambiguous["core_projections"]))

    def test_existing_root_speech_act_keeps_information_questions_out_of_edit_basis(self):
        with physical_tempdir(prefix="core-question-role-") as tmp:
            selected = Path(tmp) / "parser.py"
            selected.write_text("before\n", encoding="utf-8")
            def readback(_cg, event, _cwd):
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"cat {selected}"},
                                  tool_response={"exit_code": 0, "output": "before\n"}))
            for root in (
                "修复解析器是否会影响性能？",
                "修改 src/a.ts 会导致什么后果？",
            ):
                with self.subTest(root=root):
                    result, decision = self.replay(root, "这是影响分析。", preparation=readback)
                    self.assertEqual(result, {})
                    self.assertEqual(decision["actions"], [])
                    self.assertEqual(decision["core_projections"], [])

    def replay(self, root: str, final: str, *, preparation=None, include_state=False):
        with physical_tempdir(prefix="stop-v5-") as tmp:
            if callable(root):
                root = root(tmp)
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(kind, turn="turn", **fields):
                    return dict(hook_event_name=kind, session_id="synthetic-v5",
                                cwd=tmp, turn_id=turn, **fields)
                cg.dispatch(event("UserPromptSubmit", "control", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", prompt=root))
                if preparation:
                    preparation(cg, event, tmp)
                result = cg.dispatch(event("Stop", last_assistant_message=final))
                state = cg.load_state(Path(tmp) / "private/sessions/synthetic-v5", event("Stop"))
                if include_state:
                    return result, state["decision_log"][-1], state
                return result, state["decision_log"][-1]
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_persistence_source_survives_information_interlude_only_for_ready_work(self):
        # The second human root is an information request. It neither grants
        # test authority nor erases the first root's still-live persistence.
        # A ready selected test is an actual current action; without the
        # persistence phrase, the same honest answer may end ordinarily.
        cases = (
            (True, True, "顺便解释一下这个函数为什么要处理空输入？", True),
            (False, True, "顺便解释一下这个函数为什么要处理空输入？", False),
            (True, False, "顺便解释一下这个函数为什么要处理空输入？", False),
            (True, True, "先暂停这项测试，只回答这个问题：这个函数为什么处理空输入？", False),
        )
        for persistent, ready, interlude, expected_block in cases:
            with self.subTest(persistent=persistent, ready=ready,
                              interlude=interlude), physical_tempdir(
                prefix="stop-v5-persistence-interlude-"
            ) as tmp:
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
                try:
                    target = Path(tmp) / "suite.py"
                    target.write_bytes(b"def test_ok(): assert True\n")
                    def event(kind, turn, **fields):
                        return dict(hook_event_name=kind, session_id="interlude-fixture",
                                    cwd=tmp, turn_id=turn, **fields)
                    cg.dispatch(event("UserPromptSubmit", "control", prompt="context-guard on"))
                    root = (f"请运行 {root_locator(target)} 的测试并持续执行直到任务完成。" if persistent
                            else f"请运行 {root_locator(target)} 的测试。")
                    cg.dispatch(event("UserPromptSubmit", "t1", prompt=root))
                    if ready:
                        cg.dispatch(event(
                            "PostToolUse", "t1", tool_name="exec_command",
                            tool_input={"cmd": f"test -f {target}"},
                            tool_response={"exit_code": 0, "output": ""},
                        ))
                    cg.dispatch(event("UserPromptSubmit", "t2",
                                      prompt=interlude))
                    result = cg.dispatch(event(
                        "Stop", "t2", last_assistant_message="空输入需要返回默认结果。"))
                    state = cg.load_state(Path(tmp) / "private/sessions/interlude-fixture",
                                          event("Stop", "t2"))
                    decision = state["decision_log"][-1]
                    basis = cg._current_action_basis(
                        state, "test_verify", "",
                        Path(tmp) / "private/sessions/interlude-fixture")
                    self.assertEqual(result.get("decision") == "block", expected_block,
                                     (decision["outcome"], decision["reason_codes"], decision["actions"],
                                      None if basis is None else {
                                          "requirement_id": basis["requirement_id"],
                                          "readiness": basis["readiness"],
                                          "predicate_state": basis["predicate_state"],
                                      }, [(w["status"], w["owner_work_unit_id"])
                                          for w in state["wait_conditions"]],
                                      [(w["status"], w["raised_by_kind"])
                                       for w in cg.current_scope_projection(state)["waiting_conditions"]]))
                    if expected_block:
                        self.assertIn("explicit_user_persistence", decision["reason_codes"])
                        normalized = cg.current_root_control_projection(
                            state, Path(tmp) / "private/sessions/interlude-fixture")
                        self.assertIsNotNone(normalized)
                        self.assertIn("persistent", normalized["root_control_states"].values())
                        self.assertEqual([a["requirement_id"] for a in normalized["current_actions"]],
                                         [basis["requirement_id"]])
                    if not ready:
                        self.assertFalse(any(a.get("actionability") == "current_ready"
                                             for a in decision["actions"]))
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_root_controls_bind_full_edit_test_catalog_through_reload(self):
        with physical_tempdir(prefix="stop-v5-control-catalog-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(kind, turn, **fields):
                    return dict(hook_event_name=kind, session_id="control-catalog-v5",
                                cwd=tmp, turn_id=turn, **fields)
                session_dir = Path(tmp) / "private/sessions/control-catalog-v5"
                target = Path(tmp) / "a.py"
                target.write_bytes(b"before\n")
                cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", "t1",
                                  prompt=f"请修改 {root_locator(target)}，并运行 {root_locator(target)} 的测试。"))
                cg.dispatch(event("UserPromptSubmit", "t2",
                                  prompt="持续执行直到当前任务完成。"))
                state = cg.load_state(session_dir, event("Stop", "t2"))
                first = state["root_controls"][-1]
                self.assertEqual(first["kind"], "persistence")
                self.assertEqual({row["action"] for row in first["items"]},
                                 {"local_edit", "test_verify"})
                self.assertEqual(
                    cg.sha256_text(cg.canonical_json(cg._root_control_catalog(
                        state, first["work_unit_id"], first["source_seq"]
                    ))), first["catalog_sha256"])
                normalized = cg.current_root_control_projection(state, session_dir)
                self.assertIsNotNone(normalized)
                self.assertEqual(set(normalized["root_control_states"]),
                                 {row["id"] for row in first["items"]})
                tampered = copy.deepcopy(state)
                tampered["requirements"] = [row for row in tampered["requirements"]
                                            if row["id"] != first["items"][-1]["id"]]
                self.assertNotEqual(
                    cg.sha256_text(cg.canonical_json(cg._root_control_catalog(
                        tampered, first["work_unit_id"], first["source_seq"]
                    ))), first["catalog_sha256"])
                cg.dispatch(event("UserPromptSubmit", "t3", prompt="暂停本轮测试。"))
                state = cg.load_state(session_dir, event("Stop", "t3"))
                _, _, folded = cg.current_persistence_actions(state, session_dir)
                self.assertEqual({folded[row["id"]] for row in first["items"]},
                                 {"persistent", "persistent_paused"})
                cg.dispatch(event("UserPromptSubmit", "t4", prompt="继续。"))
                state = cg.load_state(session_dir, event("Stop", "t4"))
                _, _, folded = cg.current_persistence_actions(state, session_dir)
                self.assertEqual({folded[row["id"]] for row in first["items"]},
                                 {"persistent"})
                cg.dispatch(event("UserPromptSubmit", "t5", prompt="取消当前任务。"))
                state = cg.load_state(session_dir, event("Stop", "t5"))
                in_force, actions, folded = cg.current_persistence_actions(state, session_dir)
                self.assertFalse(in_force)
                self.assertEqual(actions, [])
                self.assertEqual(folded, {})
                self.assertEqual(state["work_units"][0]["status"], "historical_unresolved")
                self.assertIsNone(state["work_state"]["active_work_unit_id"])
                self.assertEqual(state["root_controls"][-1]["kind"], "cancel")
                self.assertEqual({row["id"] for row in state["root_controls"][-1]["items"]},
                                 {row["id"] for row in first["items"]})
                self.assertEqual(cg.pending_scoped_item_count(
                    state, cg.current_scope_projection(state)["scoped_item_ids"]), 0)
                protected = copy.deepcopy(state)
                proof_item = copy.deepcopy(protected["acceptance_items"][0])
                proof_item.update(id="A999", text="提交显式 proof 证据", status="pending")
                proof_item["verification_contract"] = {
                    "mode": "enforced", "obligations": [
                        {"kind": "input_asset_inspection", "surface": "visual"}
                    ],
                }
                protected["acceptance_items"].append(proof_item)
                protected_scope = cg.current_scope_projection(protected)
                self.assertIn("A999", protected_scope["ancestor_constraint_ids"])
                self.assertNotIn(protected["acceptance_items"][0]["id"],
                                 protected_scope["scoped_item_ids"])
                cg.dispatch(event("UserPromptSubmit", "t6", prompt="暂停当前任务。"))
                after_cancel = cg.load_state(session_dir, event("Stop", "t6"))
                _, _, folded = cg.current_persistence_actions(after_cancel, session_dir)
                self.assertEqual(folded, {})
                self.assertEqual(after_cancel["work_units"][0]["status"],
                                 "historical_unresolved")
                self.assertEqual(after_cancel["root_controls"][-1]["kind"], "cancel")
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_exact_cancel_uses_sourced_target_and_wrong_target_stays_pending(self):
        for matching in (True, False):
            with self.subTest(matching=matching), physical_tempdir(
                prefix="stop-v5-exact-control-"
            ) as tmp:
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
                try:
                    def event(kind, turn, **fields):
                        return dict(hook_event_name=kind, session_id="exact-control-v5",
                                    cwd=tmp, turn_id=turn, **fields)
                    target = Path(tmp) / "B.py"
                    other = Path(tmp) / "A.py"
                    target.write_bytes(b"old\n")
                    cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                    cg.dispatch(event("UserPromptSubmit", "t1",
                                      prompt=f"请修改 {target}。"))
                    cg.dispatch(event("UserPromptSubmit", "t2",
                                      prompt=f"取消 {target if matching else other}。"))
                    directory = Path(tmp) / "private/sessions/exact-control-v5"
                    state = cg.load_state(directory, event("Stop", "t2"))
                    bindings = [c for c in state["root_controls"] if c.get("kind") == "cancel"]
                    self.assertEqual(bool(bindings), matching)
                    if matching:
                        self.assertEqual(bindings[0]["scope_kind"], "exact")
                        normalized = cg.current_root_control_projection(state, directory)
                        self.assertIsNotNone(normalized)
                        self.assertEqual(normalized["root_control_states"],
                                         {bindings[0]["items"][0]["id"]: "cancelled"})
                        self.assertEqual(cg.pending_scoped_item_count(
                            state, cg.current_scope_projection(state)["scoped_item_ids"]), 0)
                    else:
                        self.assertGreater(cg.pending_scoped_item_count(
                            state, cg.current_scope_projection(state)["scoped_item_ids"]), 0)
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_rehashed_drop_child_recovers_as_untrusted_not_complete_subset(self):
        with physical_tempdir(prefix="stop-v5-drop-child-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(kind, turn, **fields):
                    return dict(hook_event_name=kind, session_id="drop-child-v5",
                                cwd=tmp, turn_id=turn, **fields)
                target = Path(tmp) / "a.py"
                target.write_bytes(b"old\n")
                cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", "t1",
                                  prompt=f"请修改 {root_locator(target)}，并运行 {root_locator(target)} 的测试。"))
                cg.dispatch(event("UserPromptSubmit", "t2",
                                  prompt="持续执行直到当前任务完成。"))
                directory = Path(tmp) / "private/sessions/drop-child-v5"
                state = cg.load_state(directory, event("Stop", "t2"))
                tampered = copy.deepcopy(state)
                binding = tampered["root_controls"][0]
                removed = binding["items"].pop()
                tampered["requirements"] = [row for row in tampered["requirements"]
                                            if row["id"] != removed["id"]]
                binding["catalog_sha256"] = cg.sha256_text(cg.canonical_json(
                    cg._root_control_catalog(tampered, binding["work_unit_id"],
                                             binding["source_seq"])))
                tampered["open_items"] = cg.open_item_ids(tampered)
                tampered["content_hash"] = cg.state_content_hash(tampered)
                self.assertFalse(cg._root_control_decomposition_valid(tampered, directory))
                (directory / "state.json").write_text(
                    cg.canonical_json(tampered), encoding="utf-8")
                recovered = cg.load_state(directory, event("Stop", "t2"))
                self.assertEqual(recovered["integrity"]["status"],
                                 "recovered_from_prompts")
                self.assertEqual(recovered["root_controls"], [])
                self.assertIsNone(cg.current_root_control_projection(recovered, directory))
                self.assertGreater(cg.pending_scoped_item_count(
                    recovered, cg.current_scope_projection(recovered)["scoped_item_ids"]), 0)
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_independent_root_and_missing_unit_binding_cannot_shrink_catalog(self):
        for missing_binding in (False, True):
            with self.subTest(missing_binding=missing_binding), physical_tempdir(
                prefix="stop-v5-independent-root-"
            ) as tmp:
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
                try:
                    def event(kind, turn, **fields):
                        return dict(hook_event_name=kind, session_id="independent-root-v5",
                                    cwd=tmp, turn_id=turn, **fields)
                    a, b = Path(tmp) / "a.py", Path(tmp) / "b.py"
                    a.write_bytes(b"a\n")
                    b.write_bytes(b"b\n")
                    cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                    cg.dispatch(event("UserPromptSubmit", "t1", prompt=f"请修改 {root_locator(a)}。"))
                    cg.dispatch(event("UserPromptSubmit", "t2", prompt=f"请运行 {root_locator(b)} 的测试。"))
                    cg.dispatch(event("UserPromptSubmit", "t3",
                                      prompt="持续执行直到当前任务完成。"))
                    directory = Path(tmp) / "private/sessions/independent-root-v5"
                    state = cg.load_state(directory, event("Stop", "t3"))
                    self.assertEqual(state["integrity"]["status"], "ok")
                    self.assertEqual(len(state["root_controls"][0]["items"]), 2)
                    self.assertIsNotNone(cg.current_root_control_projection(state, directory))
                    if missing_binding:
                        (directory / "prompts/units/P0003.json").unlink()
                    else:
                        tampered = copy.deepcopy(state)
                        control = tampered["root_controls"][0]
                        removed = next(row for row in control["items"]
                                       if row["action"] == "test_verify")
                        control["items"] = [row for row in control["items"]
                                            if row["id"] != removed["id"]]
                        tampered["requirements"] = [row for row in tampered["requirements"]
                                                    if row["id"] != removed["id"]]
                        tampered["acceptance_items"] = [row for row in tampered["acceptance_items"]
                                                       if row.get("prompt_id") != removed["prompt_id"]]
                        control["catalog_sha256"] = cg.sha256_text(cg.canonical_json(
                            cg._root_control_catalog(tampered, control["work_unit_id"],
                                                     control["source_seq"])))
                        tampered["open_items"] = cg.open_item_ids(tampered)
                        tampered["content_hash"] = cg.state_content_hash(tampered)
                        self.assertFalse(cg._root_control_decomposition_valid(tampered, directory))
                        (directory / "state.json").write_text(
                            cg.canonical_json(tampered), encoding="utf-8")
                    recovered = cg.load_state(directory, event("Stop", "t3"))
                    self.assertEqual(recovered["integrity"]["status"],
                                     "recovered_from_prompts")
                    self.assertEqual(recovered["root_controls"], [])
                    self.assertIsNone(cg.current_root_control_projection(recovered, directory))
                    self.assertGreater(cg.pending_scoped_item_count(
                        recovered, cg.current_scope_projection(recovered)["scoped_item_ids"]), 0)
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_unsourced_later_root_cannot_forge_supersession_of_persistent_work(self):
        with physical_tempdir(prefix="stop-v5-unsourced-successor-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(kind, turn, **fields):
                    return dict(hook_event_name=kind, session_id="unsourced-successor-v5",
                                cwd=tmp, turn_id=turn, **fields)
                a, b = Path(tmp) / "a.py", Path(tmp) / "b.py"
                a.write_bytes(b"a\n")
                b.write_bytes(b"b\n")
                cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", "t1", prompt=f"请修改 {root_locator(a)}。"))
                cg.dispatch(event("UserPromptSubmit", "t2",
                                  prompt="持续执行直到当前任务完成。"))
                cg.dispatch(event("UserPromptSubmit", "t3", prompt=f"请修改 {root_locator(b)}。"))
                directory = Path(tmp) / "private/sessions/unsourced-successor-v5"
                state = cg.load_state(directory, event("Stop", "t3"))
                self.assertEqual(state["supersedes"], [])
                self.assertEqual(state["integrity"]["status"], "ok")
                self.assertIsNotNone(cg.current_root_control_projection(state, directory))
                tampered = copy.deepcopy(state)
                old, new = tampered["requirements"][0], tampered["requirements"][-1]
                tampered["supersedes"].append({
                    "old_id": old["id"], "new_id": new["id"],
                    "created_at": cg.utc_now(), "reason": "replacement",
                })
                old["status"] = "superseded"
                tampered["open_items"] = cg.open_item_ids(tampered)
                tampered["content_hash"] = cg.state_content_hash(tampered)
                self.assertFalse(cg._root_control_decomposition_valid(tampered, directory))
                (directory / "state.json").write_text(
                    cg.canonical_json(tampered), encoding="utf-8")
                recovered = cg.load_state(directory, event("Stop", "t3"))
                self.assertEqual(recovered["integrity"]["status"], "recovered_from_prompts")
                self.assertEqual(recovered["supersedes"], [])
                self.assertIsNone(cg.current_root_control_projection(recovered, directory))
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_uncommitted_new_root_after_prompt_write_invalidates_old_catalog(self):
        with physical_tempdir(prefix="stop-v5-uncommitted-root-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(turn, prompt):
                    return dict(hook_event_name="UserPromptSubmit",
                                session_id="uncommitted-root-v5", cwd=tmp,
                                turn_id=turn, prompt=prompt)
                a, b = Path(tmp) / "a.py", Path(tmp) / "b.py"
                a.write_bytes(b"a\n")
                b.write_bytes(b"b\n")
                cg.dispatch(event("t0", "context-guard on"))
                cg.dispatch(event("t1", f"请修改 {root_locator(a)}。"))
                cg.dispatch(event("t2", "持续执行直到当前任务完成。"))
                directory = Path(tmp) / "private/sessions/uncommitted-root-v5"
                before = cg.load_state(directory, event("t2", ""))
                self.assertEqual(before["integrity"]["status"], "ok")
                self.assertIsNotNone(cg.current_root_control_projection(before, directory))
                new_root = cg.append_prompt(
                    directory, before, f"请运行 {root_locator(b)} 的测试。", turn_id="t3")
                self.assertTrue(new_root["id"])
                self.assertFalse((directory / "prompts/units" /
                                  f"{new_root['id']}.json").exists())
                # The state transaction and unit binding were never saved.
                recovered = cg.load_state(directory, event("t3", ""))
                self.assertEqual(recovered["integrity"]["status"],
                                 "recovered_from_prompts")
                self.assertEqual(recovered["root_controls"], [])
                self.assertIsNone(cg.current_root_control_projection(recovered, directory))
                self.assertTrue(any(row["prompt_id"] == new_root["id"]
                                    for row in recovered["requirements"]))
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_repair_parent_pause_binds_required_edit_and_test_children(self):
        with physical_tempdir(prefix="stop-v5-parent-control-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(kind, turn, **fields):
                    return dict(hook_event_name=kind, session_id="parent-control-v5",
                                cwd=tmp, turn_id=turn, **fields)
                target = Path(tmp) / "parser.py"
                target.write_bytes(b"old\n")
                cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", "t1",
                                  prompt=f"请修复 {root_locator(target)}，并运行 {root_locator(target)} 的测试。"))
                cg.dispatch(event("UserPromptSubmit", "t2", prompt="暂停这项修复。"))
                directory = Path(tmp) / "private/sessions/parent-control-v5"
                state = cg.load_state(directory, event("Stop", "t2"))
                bindings = [c for c in state["root_controls"] if c.get("kind") == "pause"]
                self.assertEqual(len(bindings), 1)
                self.assertEqual(bindings[0]["scope_kind"], "parent_task")
                self.assertEqual({r["action"] for r in bindings[0]["items"]},
                                 {"local_edit", "test_verify"})
                normalized = cg.current_root_control_projection(state, directory)
                self.assertIsNotNone(normalized)
                self.assertEqual(set(normalized["root_control_states"]),
                                 {r["id"] for r in bindings[0]["items"]})
                self.assertEqual(set(normalized["root_control_states"].values()),
                                 {"paused"})
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_qualified_persistence_keeps_until_clause_with_repair_children(self):
        with physical_tempdir(prefix="stop-v5-qualified-control-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(kind, turn, **fields):
                    return dict(hook_event_name=kind, session_id="qualified-control-v5",
                                cwd=tmp, turn_id=turn, **fields)
                cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", "t1", prompt=(
                    "请持续完成本轮 parser 修复和测试，直到当前任务完成。")))
                directory = Path(tmp) / "private/sessions/qualified-control-v5"
                state = cg.load_state(directory, event("Stop", "t1"))
                controls = [c for c in state["root_controls"]
                            if c.get("kind") == "persistence"]
                self.assertEqual(len(controls), 1)
                self.assertEqual(controls[0]["scope_kind"], "parent_task")
                self.assertEqual({row["action"] for row in controls[0]["items"]},
                                 {"local_edit", "test_verify"})
                self.assertEqual(len(controls[0]["items"]), 2)
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_test_class_persistence_binds_existing_test_only(self):
        with physical_tempdir(prefix="stop-v5-test-role-control-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(turn, prompt):
                    return dict(hook_event_name="UserPromptSubmit",
                                session_id="test-role-control-v5", cwd=tmp,
                                turn_id=turn, prompt=prompt)
                cg.dispatch(event("t0", "context-guard on"))
                cg.dispatch(event("t1", "请运行当前测试。"))
                cg.dispatch(event("t2", "持续推进，直到本轮测试完成为止。"))
                directory = Path(tmp) / "private/sessions/test-role-control-v5"
                state = cg.load_state(directory, dict(hook_event_name="Stop",
                                    session_id="test-role-control-v5", cwd=tmp,
                                    turn_id="t2"))
                controls = [c for c in state["root_controls"]
                            if c.get("kind") == "persistence"]
                self.assertEqual(len(controls), 1)
                self.assertEqual(controls[0]["scope_kind"], "action_class")
                self.assertEqual({row["action"] for row in controls[0]["items"]},
                                 {"test_verify"})
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_root_time_repair_dependency_excludes_independent_target_and_has_many_children(self):
        with physical_tempdir(prefix="stop-v5-repair-graph-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(session, turn, prompt):
                    return dict(hook_event_name="UserPromptSubmit", session_id=session,
                                cwd=tmp, turn_id=turn, prompt=prompt)
                target = Path(tmp) / "parser.py"
                other = Path(tmp) / "other.py"
                target.write_bytes(b"old\n")
                other.write_bytes(b"old\n")
                cg.dispatch(event("repair-graph-positive", "t0", "context-guard on"))
                cg.dispatch(event("repair-graph-positive", "t1", (
                    f"请修复 {root_locator(target)}，运行 {root_locator(target)} 的单元测试，"
                    f"然后运行 {root_locator(target)} 的回归测试。")))
                cg.dispatch(event("repair-graph-positive", "t2", "暂停这项修复。"))
                directory = Path(tmp) / "private/sessions/repair-graph-positive"
                state = cg.load_state(directory, dict(hook_event_name="Stop",
                    session_id="repair-graph-positive", cwd=tmp, turn_id="t2"))
                children = [r for r in state["requirements"]
                            if r.get("execution_source_span") is not None]
                self.assertEqual(len(children), 3)
                repair = next(r for r in children if r["execution_kind"] == "local_edit")
                self.assertEqual({r.get("required_for_item_id") for r in children
                                  if r["execution_kind"] == "test_verify"}, {repair["id"]})
                control = next(c for c in state["root_controls"]
                               if c.get("scope_kind") == "parent_task")
                self.assertEqual({r["id"] for r in control["items"]},
                                 {r["id"] for r in children})
                normalized = cg.current_root_control_projection(state, directory)
                self.assertIsNotNone(normalized)
                self.assertEqual(normalized["root_control_states"],
                                 {r["id"]: "paused" for r in children})
                self.assertFalse(any(a["requirement_id"] in {r["id"] for r in children}
                                     for a in normalized["current_actions"]))

                cg.dispatch(event("repair-graph-negative", "t0", "context-guard on"))
                cg.dispatch(event("repair-graph-negative", "t1", (
                    f"请修复 {root_locator(target)}，并运行 {root_locator(other)} 的测试。")))
                cg.dispatch(event("repair-graph-negative", "t2", "暂停这项修复。"))
                other_state = cg.load_state(
                    Path(tmp) / "private/sessions/repair-graph-negative",
                    dict(hook_event_name="Stop", session_id="repair-graph-negative",
                         cwd=tmp, turn_id="t2"))
                self.assertFalse(any(r.get("required_for_item_id")
                                     for r in other_state["requirements"]))
                self.assertFalse(any(c.get("scope_kind") == "parent_task"
                                     for c in other_state["root_controls"]))
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_historical_control_survives_sourced_supersession_without_transferring(self):
        with physical_tempdir(prefix="stop-v5-history-control-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(turn, prompt):
                    return dict(hook_event_name="UserPromptSubmit",
                                session_id="history-control-v5", cwd=tmp,
                                turn_id=turn, prompt=prompt)
                a, b = Path(tmp) / "a.py", Path(tmp) / "b.py"
                a.write_bytes(b"a\n")
                b.write_bytes(b"b\n")
                cg.dispatch(event("t0", "context-guard on"))
                cg.dispatch(event("t1", f"请修改 {root_locator(a)}。"))
                cg.dispatch(event("t2", "持续执行直到当前任务完成。"))
                directory = Path(tmp) / "private/sessions/history-control-v5"
                earlier = cg.load_state(directory, dict(hook_event_name="Stop",
                    session_id="history-control-v5", cwd=tmp, turn_id="t2"))
                before = cg.current_root_control_projection(earlier, directory)
                self.assertEqual(before["root_control_states"], {"R001": "persistent"})
                cg.dispatch(event("t3", f"用修改 {root_locator(b)} 替代 R001。"))
                later = cg.load_state(directory, dict(hook_event_name="Stop",
                    session_id="history-control-v5", cwd=tmp, turn_id="t3"))
                self.assertEqual(later["supersedes"][0]["old_id"], "R001")
                after = cg.current_root_control_projection(later, directory)
                self.assertIsNotNone(after)
                self.assertEqual(after["root_control_states"], {"R001": "persistent"})
                self.assertNotIn("R001", {a["requirement_id"] for a in after["current_actions"]})
                self.assertNotIn("R003", after["root_control_states"])
                self.assertEqual(after["coverage_errors"], [])
                self.assertEqual(cg.current_root_control_projection(
                    cg.load_state(directory, dict(hook_event_name="Stop",
                        session_id="history-control-v5", cwd=tmp, turn_id="t3")),
                    directory)["root_control_states"], after["root_control_states"])
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_future_observation_and_specific_unrun_test(self):
        cases = [
            ("按既定计划执行本轮修复。",
             "本轮修复和回归验证已完成。实际收益仍需后续使用观察。改动保持未提交。", False),
            ("按既定计划执行本轮修复。",
             "本轮修改已完成，长期稳定性尚待真实使用检验。", False),
            ("按既定计划执行本轮修复并运行测试。",
             "本地修改已完成。我接下来需要运行测试。", False),
            ("按既定计划执行本轮修复并运行测试。",
             "本地修改已完成。测试尚未运行。", False),
        ]
        for root, final, blocked in cases:
            with self.subTest(final=final):
                result, decision = self.replay(root, final)
                self.assertEqual(result.get("decision") == "block", blocked)
                self.assertEqual(decision["protocol_version"], "5.0.0")
                self.assertNotIn("explicit_user_persistence", decision["reason_codes"])
                self.assertFalse(any(a["category"] == "generic_work" and
                                     a.get("actionability") == "current_ready"
                                     for a in decision["actions"]))
                self.assertTrue(all("authorization" not in a for a in decision["actions"]))

    def test_reply_wait_does_not_register_external_operation(self):
        _, decision, state = self.replay("查看本轮材料并说明结果。",
                                         "外部审核还在继续，后续等结果。",
                                         include_state=True)
        self.assertNotEqual(decision["outcome"], "silent_yield_preserve_pending")
        self.assertEqual(state["wait_conditions"], [])

    def test_host_goal_adoption_reports_unavailable_without_creating_work(self):
        with physical_tempdir(prefix="core-goal-capability-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(prompt):
                    return dict(hook_event_name="UserPromptSubmit", session_id="goal-capability-v5",
                                cwd=tmp, turn_id="turn", prompt=prompt)
                cg.dispatch(event("context-guard on"))
                response = cg.dispatch(event("context-guard goal-adopt"))
                self.assertIn("capability_unavailable", str(response))
                state = cg.load_state(Path(tmp) / "private/sessions/goal-capability-v5",
                                      event("context-guard status"))
                self.assertEqual(state["requirements"], [])
                self.assertIn("goal_host_completion=capability_unavailable",
                              cg.status_context(state))
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_mixed_information_delivers_only_its_utf8_span(self):
        root = "请解释方案并修改文件 /tmp/cg-mixed-A.py。未知条件保持原样。"
        result, _, state = self.replay(
            root, "方案的做法是先检查，再修改；文件仍待处理。", include_state=True)
        self.assertEqual(result, {})
        current = [i for i in state["requirements"] if i.get("prompt_id") == state["prompts"][-1]["id"]]
        self.assertGreaterEqual(len(current), 2)
        parent = next(i for i in current if "information_source_span" not in i)
        child = next(i for i in current if "information_source_span" in i)
        self.assertEqual(parent["status"], "pending")
        self.assertEqual(child["status"], "answered")
        start, end = child["information_source_span"]
        self.assertEqual(root.encode("utf-8")[start:end].decode("utf-8"), child["text"])
        self.assertIn("未知条件保持原样", parent["text"])

    def test_explain_install_restart_is_delivery_not_tool_intent(self):
        cases = (
            ("请解释如何重启宿主。", "先保存状态，再由操作者重启宿主。"),
            ("Explain how to install the plugin.", "The installer copies a validated package."),
        )
        for root, final in cases:
            with self.subTest(root=root):
                result, decision, state = self.replay(root, final, include_state=True)
                self.assertEqual(result, {})
                self.assertEqual(state["requirements"][-1]["status"], "answered")
                self.assertEqual(decision["core_projections"], [])
        for command in ("请安装插件。", "Restart the host."):
            with self.subTest(command=command):
                _, _, state = self.replay(command, "操作尚未执行。", include_state=True)
                self.assertEqual(state["requirements"][-1]["status"], "pending")

    def test_information_with_execution_prohibition_delivers_information_only(self):
        cases = (
            ("解释安装流程，不执行安装。", "安装流程是先校验包，再由操作者启动安装。"),
            ("说明重启步骤，但不要重启宿主。", "步骤是保存状态并由操作者重启。"),
            ("说明数据同步机制，不执行同步。", "机制先比较版本，再传输差异。"),
            ("Explain the installation steps, but do not install the plugin.",
             "The steps are to verify the package and then install it."),
            ("Describe the data synchronization workflow, but do not run it.",
             "The workflow compares versions and then transfers differences."),
        )
        for root, final in cases:
            with self.subTest(root=root):
                result, decision, state = self.replay(root, final, include_state=True)
                self.assertEqual(result, {})
                current = [i for i in state["requirements"]
                           if i.get("prompt_id") == state["prompts"][-1]["id"]]
                self.assertTrue(any(i["status"] == "answered" and
                                    i.get("information_source_span") is not None
                                    for i in current))
                self.assertTrue(any(i["status"] == "pending" for i in current))
                self.assertFalse(any(a.get("actionability") == "current_ready"
                                     for a in decision["actions"]))

    def test_trusted_preflight_makes_unrun_test_actionable(self):
        with physical_tempdir(prefix="core-input-") as tmp:
            suite = Path(tmp) / "suite.py"
            suite.write_text("def test_ok(): assert True\n", encoding="utf-8")
            def preparation(_cg, event, _cwd):
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"test -f {suite}"},
                                  tool_response={"exit_code": 0, "output": ""}))
            root = f"继续执行，运行 {root_locator(suite)} 的测试。"
            result, decision = self.replay(root, "测试尚未运行。", preparation=preparation)
            self.assertEqual(result.get("decision"), "block")
            self.assertIn("resume_with_actionable_work", decision["reason_codes"])
            self.assertNotIn("explicit_user_persistence", decision["reason_codes"])

    def test_one_test_fact_cannot_close_a_combined_edit_and_test(self):
        with physical_tempdir(prefix="core-combined-") as tmp:
            suite = Path(tmp) / "suite.py"
            suite.write_text("def test_ok(): assert True\n", encoding="utf-8")
            def observed(_cg, event, _cwd):
                for command in (f"test -f {suite}", f"pytest {suite}"):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": command},
                                      tool_response={"exit_code": 0, "output": "1 passed"}))
            root = f"请修改 {root_locator(suite)}，并运行 {root_locator(suite)} 的测试。"
            _, decision, state = self.replay(
                root, "测试通过，但修改尚未完成。",
                preparation=observed, include_state=True)
            aggregate = next(row for row in decision["core_projections"]
                             if row["predicate"] == "edit_and_test")
            self.assertFalse(aggregate["certifiable"])
            self.assertEqual(aggregate["predicate_state"], "insufficient")
            self.assertTrue(any(i.get("execution_kind") == "local_edit"
                                and i["status"] == "pending"
                                for i in state["requirements"]))

    def test_combined_edit_and_test_have_distinct_sourced_children(self):
        with physical_tempdir(prefix="core-combined-positive-") as tmp:
            suite = Path(tmp) / "suite.py"
            suite.write_text("before\n", encoding="utf-8")
            patch = (f"*** Begin Patch\n*** Update File: {suite}\n@@\n"
                     "-before\n+after\n*** End Patch\n")
            def observed(_cg, event, _cwd):
                for cmd, output in ((f"cat {suite}", "before\n"),
                                    (f"test -f {suite}", "")):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": cmd},
                                      tool_response={"exit_code": 0, "output": output}))
                suite.write_text("after\n", encoding="utf-8")
                cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                                  tool_input={"patch": patch},
                                  tool_response={"success": True}))
                for cmd, output in ((f"cat {suite}", "after\n"),
                                    (f"pytest {suite}", "1 passed")):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": cmd},
                                      tool_response={"exit_code": 0, "output": output}))
            _, decision, state = self.replay(
                f"请修改 {root_locator(suite)}，并运行 {root_locator(suite)} 的测试。", "修改和测试已完成。",
                preparation=observed, include_state=True)
            current = [i for i in state["requirements"]
                       if i.get("prompt_id") == state["prompts"][-1]["id"]]
            children = [i for i in current if i.get("execution_source_span") is not None]
            self.assertEqual({i["execution_kind"] for i in children},
                             {"local_edit", "test_verify"})
            self.assertEqual(len(decision["core_projections"]), 3)
            self.assertTrue(all(row["predicate_state"] == "satisfied"
                                for row in decision["core_projections"]))
            aggregate = next(row for row in decision["core_projections"]
                             if row["predicate"] == "edit_and_test")
            self.assertTrue(aggregate["certifiable"])
            self.assertEqual(aggregate["unknown_coverage_count"], 0)

    def test_later_commit_push_synthetic_host_lineage_reuses_sourced_repo(self):
        """Structured Hook replay only: this test never runs Git commands."""
        with physical_tempdir(prefix="core-git-replay-") as tmp:
            root = Path(tmp)
            repo_a, repo_b = root / "A", root / "B"
            repo_a.mkdir()
            repo_b.mkdir()
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(root / "private")
            try:
                def event(kind, **fields):
                    return dict(hook_event_name=kind, session_id="git-replay-v5",
                                cwd=str(repo_a), turn_id="turn", **fields)
                def observed(command, output):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": f"git -C {repo_b} {command}"},
                                      tool_response={"exit_code": 0, "output": output}))
                cg.dispatch(event("UserPromptSubmit", prompt="context-guard on"))
                prior = (f'请在 "{repo_b}" 仓库工作。' if os.name == "nt"
                         else f"请在 {repo_b} 仓库工作。")
                cg.dispatch(event("UserPromptSubmit", prompt=prior))
                cg.dispatch(event("UserPromptSubmit", prompt="提交改动，并推送 origin main。"))
                old, new = "a" * 40, "b" * 40
                observed("rev-parse --show-toplevel", str(repo_b) + "\n")
                observed("show -s --format=%H%n%P%n%T HEAD", f"{old}\n\n{'1' * 40}\n")
                observed("commit -m change", "[main bbbbbbb] change\n")
                observed("show -s --format=%H%n%P%n%T HEAD",
                         f"{new}\n{old}\n{'2' * 40}\n")
                observed("symbolic-ref --short HEAD", "main\n")
                observed("push origin main", "To local fixture\n")
                observed("ls-remote origin refs/heads/main", f"{new}\trefs/heads/main\n")
                cg.dispatch(event("Stop", last_assistant_message="提交并推送完成。"))
                state = cg.load_state(root / "private/sessions/git-replay-v5", event("Stop"))
                rows = state["decision_log"][-1]["core_projections"]
                self.assertEqual({row["predicate"] for row in rows},
                                 {"commit_verified", "push_verified", "commit_and_push"})
                self.assertTrue(all(row["predicate_state"] == "satisfied" for row in rows))
                aggregate = next(row for row in rows if row["predicate"] == "commit_and_push")
                self.assertTrue(aggregate["certifiable"])
                git_facts = [e["core_observation"] for e in state["evidence"]
                             if isinstance(e.get("core_observation"), dict)
                             and isinstance(e["core_observation"].get("git"), dict)]
                self.assertIn({"oid": new, "parent": old, "tree": "2" * 40},
                              [f["git"] for f in git_facts])
                self.assertIn({"oid": new, "remote": "origin", "refspec": "main"},
                              [f["git"] for f in git_facts])
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_quoted_windows_repo_root_never_authorizes_prefix_selection(self):
        """Structured Hook replay only; no Git command is executed."""
        full = r"D:\Work Space\repo"
        old, new = "a" * 40, "b" * 40
        self.assertEqual(cg.root_absolute_locator_mentions(f'请在 "{full}" 工作。'),
                         ({full}, False))
        self.assertEqual(cg.root_absolute_locator_mentions(r"请在 D:\Work。"),
                         ({r"D:\Work"}, False))
        for malformed in (
            r"D:\Work Space\repo", r"D:\Work Space", r"D:\Work\..\repo",
            r"D:\Work?bad", r"D:\Work]bad", r"D:\Work[bad",
            r"D:\Work<bad", r"D:\Work|bad", r"D:\Work*bad",
            r'"D:\Work"^suffix', r'"D:\Work"?bad',
        ):
            with self.subTest(malformed=malformed):
                targets, _ = cg.root_absolute_locator_mentions(f"请在 {malformed} 仓库工作。")
                self.assertNotIn(r"D:\Work", targets)
        cases = (
            (f'请在 "{full}" 仓库工作。', full, True),
            (f'请在 "{full}" 仓库工作。', r"D:\Work", False),
            (r"请在 D:\Work。", r"D:\Work", True),
            (f'请在 "{full}" 与 "D:\\Work?bad" 仓库工作。', full, False),
        )
        for prior_text, selected, expected in cases:
            with self.subTest(prior_text=prior_text, selected=selected), physical_tempdir(prefix="win-git-root-") as tmp:
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
                try:
                    def event(kind, **fields):
                        return dict(hook_event_name=kind, session_id="win-git-v5",
                                    cwd=tmp, turn_id="turn", **fields)
                    def observed(command, output):
                        cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                          tool_input={"cmd": f'git -C "{selected}" {command}',
                                                      "shell": "pwsh"},
                                          tool_response={"exit_code": 0, "output": output}))
                    with mock.patch.object(cg, "_verified_windows_target",
                                           side_effect=lambda raw, **_: raw):
                        cg.dispatch(event("UserPromptSubmit", prompt="context-guard on"))
                        cg.dispatch(event("UserPromptSubmit", prompt=prior_text))
                        cg.dispatch(event("UserPromptSubmit", prompt="提交改动，并推送 origin main。"))
                        observed("rev-parse --show-toplevel", selected + "\n")
                        observed("show -s --format=%H%n%P%n%T HEAD",
                                 f"{old}\n\n{'1' * 40}\n")
                        observed("commit -m change", "[main bbbbbbb] change\n")
                        observed("show -s --format=%H%n%P%n%T HEAD",
                                 f"{new}\n{old}\n{'2' * 40}\n")
                        observed("symbolic-ref --short HEAD", "main\n")
                        observed("push origin main", "To local fixture\n")
                        observed("ls-remote origin refs/heads/main",
                                 f"{new}\trefs/heads/main\n")
                        cg.dispatch(event("Stop", last_assistant_message="提交并推送完成。"))
                    state = cg.load_state(Path(tmp) / "private/sessions/win-git-v5", event("Stop"))
                    predicates = {r["predicate"] for r in state["decision_log"][-1]["core_projections"]}
                    self.assertEqual(predicates == {
                        "commit_verified", "push_verified", "commit_and_push"}, expected)
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_git_target_requires_unique_prior_root_and_current_host_selection(self):
        for mode in ("wrong_target", "ambiguous_prior", "stale_selection", "reply_only"):
            with self.subTest(mode=mode), physical_tempdir(prefix="core-git-negative-") as tmp:
                root = Path(tmp)
                repo_a, repo_b, repo_c = (root / name for name in ("A", "B", "C"))
                for repo in (repo_a, repo_b, repo_c):
                    repo.mkdir()
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(root / "private")
                try:
                    def event(kind, **fields):
                        return dict(hook_event_name=kind, session_id="git-negative-v5",
                                    cwd=str(repo_a), turn_id="turn", **fields)
                    def selected(target):
                        cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                          tool_input={"cmd": f"git -C {target} rev-parse --show-toplevel"},
                                          tool_response={"exit_code": 0, "output": str(target) + "\n"}))
                    cg.dispatch(event("UserPromptSubmit", prompt="context-guard on"))
                    quote = '"' if os.name == "nt" else ""
                    first = (f"请在 {quote}{repo_b}{quote} 与 {quote}{repo_c}{quote} 仓库工作。"
                             if mode == "ambiguous_prior"
                             else f"请在 {quote}{repo_b}{quote} 仓库工作。")
                    cg.dispatch(event("UserPromptSubmit", prompt=first))
                    if mode == "stale_selection":
                        selected(repo_b)
                    cg.dispatch(event("UserPromptSubmit", prompt="提交改动，并推送 origin main。"))
                    if mode not in {"stale_selection", "reply_only"}:
                        selected(repo_c if mode == "wrong_target" else repo_b)
                    cg.dispatch(event("Stop", last_assistant_message=f"将在 {repo_b} 提交并推送。"))
                    state = cg.load_state(root / "private/sessions/git-negative-v5", event("Stop"))
                    self.assertEqual(state["decision_log"][-1]["core_projections"], [])
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_git_readback_does_not_certify_wrong_parent_tree_branch_or_remote(self):
        """No Git effect: adversarial structured Hook captures only."""
        for defect in ("parent", "tree", "branch", "remote", "no_commit", "no_push"):
            with self.subTest(defect=defect), physical_tempdir(prefix="core-git-effect-") as tmp:
                root, repo = Path(tmp), Path(tmp) / "B"
                repo.mkdir()
                previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
                os.environ["CONTEXT_GUARD_DATA_DIR"] = str(root / "private")
                try:
                    def event(kind, **fields):
                        return dict(hook_event_name=kind, session_id="git-effect-v5",
                                    cwd=str(root), turn_id="turn", **fields)
                    def observed(command, output):
                        cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                          tool_input={"cmd": f"git -C {repo} {command}"},
                                          tool_response={"exit_code": 0, "output": output}))
                    cg.dispatch(event("UserPromptSubmit", prompt="context-guard on"))
                    prior = (f'请在 "{repo}" 仓库工作。' if os.name == "nt"
                             else f"请在 {repo} 仓库工作。")
                    cg.dispatch(event("UserPromptSubmit", prompt=prior))
                    cg.dispatch(event("UserPromptSubmit", prompt="提交改动，并推送 origin main。"))
                    old, new = "a" * 40, "b" * 40
                    observed("rev-parse --show-toplevel", str(repo) + "\n")
                    observed("show -s --format=%H%n%P%n%T HEAD", f"{old}\n\n{'1' * 40}\n")
                    if defect != "no_commit":
                        observed("commit -m change", "[main bbbbbbb] change\n")
                    parent = "c" * 40 if defect == "parent" else old
                    tree = "1" * 40 if defect == "tree" else "2" * 40
                    observed("show -s --format=%H%n%P%n%T HEAD", f"{new}\n{parent}\n{tree}\n")
                    observed("symbolic-ref --short HEAD", "dev\n" if defect == "branch" else "main\n")
                    if defect != "no_push":
                        observed("push origin main", "To local fixture\n")
                    remote = "c" * 40 if defect == "remote" else new
                    observed("ls-remote origin refs/heads/main", f"{remote}\trefs/heads/main\n")
                    cg.dispatch(event("Stop", last_assistant_message="已完成。"))
                    state = cg.load_state(root / "private/sessions/git-effect-v5", event("Stop"))
                    aggregates = [row for row in state["decision_log"][-1]["core_projections"]
                                  if row["predicate"] == "commit_and_push"]
                    self.assertFalse(aggregates and aggregates[0]["certifiable"])
                finally:
                    if previous is None:
                        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                    else:
                        os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_successful_test_projection_is_persisted_at_stop(self):
        with physical_tempdir(prefix="core-success-") as tmp:
            suite = Path(tmp) / "suite.py"
            suite.write_text("def test_ok(): assert True\n", encoding="utf-8")
            def observed(_cg, event, _cwd):
                for command in (f"test -f {suite}", f"pytest {suite}"):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": command},
                                      tool_response={"exit_code": 0, "output": "1 passed"}))
            _, decision, state = self.replay(
                f"继续执行，运行 {root_locator(suite)} 的测试。", "测试通过。",
                preparation=observed, include_state=True)
            rows = decision["core_projections"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["predicate_state"], "satisfied")
            self.assertTrue(rows[0]["certifiable"])
            self.assertEqual(rows[0]["unknown_coverage_count"], 0)
            # The shared projection does not self-apply a whole-work checkpoint.
            self.assertEqual(state["requirements"][-1]["status"], "pending")

    def test_edit_needs_structured_patch_and_changed_readback(self):
        with physical_tempdir(prefix="core-edit-") as tmp:
            target = Path(tmp) / "module.py"
            target.write_text("before\n", encoding="utf-8")
            patch = (f"*** Begin Patch\n*** Update File: {target}\n@@\n"
                     "-before\n+after\n*** End Patch\n")

            def observed(_cg, event, _cwd):
                def readback(content):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": f"cat {target}"},
                                      tool_response={"exit_code": 0, "output": content}))
                readback("before\n")
                target.write_text("after\n", encoding="utf-8")
                cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                                  tool_input={"patch": patch},
                                  tool_response={"success": True}))
                readback("after\n")

            _, decision, state = self.replay(
                f"请修改 {target}。", "修改已完成。", preparation=observed,
                include_state=True)
            self.assertEqual(len(decision["core_projections"]), 1)
            self.assertEqual(decision["core_projections"][0]["predicate_state"], "satisfied")
            self.assertTrue(decision["core_projections"][0]["certifiable"])
            self.assertEqual(state["requirements"][-1]["status"], "pending")

            for root in (f"请修改 {target}，写入指定内容。",
                         f"请修改 {target}，不要覆盖已有内容。"):
                with self.subTest(root=root):
                    _, constrained = self.replay(root, "修改已完成。", preparation=observed)
                    self.assertFalse(any(row["certifiable"]
                                         for row in constrained["core_projections"]))
                    self.assertTrue(all(row["unknown_coverage_count"] > 0
                                        for row in constrained["core_projections"]))

    def test_edit_is_not_proven_by_patch_or_exit_zero_alone(self):
        with physical_tempdir(prefix="core-edit-negative-") as tmp:
            target = Path(tmp) / "module.py"
            target.write_text("before\n", encoding="utf-8")
            patch = (f"*** Begin Patch\n*** Update File: {target}\n@@\n"
                     "-before\n+after\n*** End Patch\n")
            def observed(_cg, event, _cwd):
                for content in ("before\n", "before\n"):
                    cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                      tool_input={"cmd": f"cat {target}"},
                                      tool_response={"exit_code": 0, "output": content}))
                    if content == "before\n":
                        cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                                          tool_input={"patch": patch},
                                          tool_response={"success": True}))
                        break
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"cat {target}"},
                                  tool_response={"exit_code": 0, "output": "before\n"}))
            _, decision = self.replay(f"请修改 {target}。", "修改已完成。",
                                      preparation=observed)
            self.assertNotEqual(decision["core_projections"][0]["predicate_state"], "satisfied")
            self.assertFalse(decision["core_projections"][0]["certifiable"])

    def test_windows_drive_locator_does_not_certify_without_physical_identity(self):
        target = r"C:\Repo\suite.py"
        def observed(_cg, event, _cwd):
            for command in (f"test -f '{target}'", f"pytest '{target}'"):
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": command},
                                  tool_response={"exit_code": 0, "output": "1 passed"}))
        _, decision, _ = self.replay(
            f"继续执行，运行 {target} 的测试。", "测试通过。",
            preparation=observed, include_state=True)
        self.assertFalse(any(row["certifiable"] for row in decision["core_projections"]))
        for unsupported in (r"\\server\share\suite.py", r"C:\Repo\CON\suite.py"):
            with self.subTest(unsupported=unsupported):
                _, decision, _ = self.replay(
                    f"继续执行，运行 {unsupported} 的测试。", "测试尚未运行。",
                    preparation=observed, include_state=True)
                self.assertEqual(decision["core_projections"], [])

    def test_current_effect_is_due_only_from_root_scope_and_host_selection(self):
        with physical_tempdir(prefix="core-eval-") as tmp:
            selected = Path(tmp) / "benchmark.py"
            selected.write_text("def measure(): return 1\n", encoding="utf-8")
            def ready(_cg, event, _cwd):
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"test -f {selected}"},
                                  tool_response={"exit_code": 0, "output": ""}))
            cases = (
                ("现在评估这次修改的效果并给出结果。", "修改完成，效果以后观察。", True),
                ("立刻测量本次改动的吞吐收益。", "已改动；吞吐收益有待评估。", False),
                ("检查这批改动并给出结论。", "这项检查尚未完成。", False),
                ("解释‘现在评估这次修改的效果’这句话。", "未来可以再观察效果。", False),
                ("不要现在评估这次修改的效果。", "效果以后观察。", False),
            )
            for root, final, expected_block in cases:
                with self.subTest(root=root):
                    result, decision = self.replay(root, final, preparation=ready)
                    self.assertEqual(result.get("decision") == "block", expected_block)
                    if expected_block:
                        self.assertIn("current_due_action_omitted", decision["reason_codes"])
                        self.assertEqual(decision["actions"][0]["actionability"],
                                         "current_ready")
            result, _ = self.replay(cases[0][0], cases[0][1])
            self.assertEqual(result, {})

    def test_root_time_and_antecedent_keep_review_deferred(self):
        with physical_tempdir(prefix="core-condition-") as tmp:
            selected = Path(tmp) / "benchmark.py"
            selected.write_text("def measure(): return 1\n", encoding="utf-8")
            def ready(_cg, event, _cwd):
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"test -f {selected}"},
                                  tool_response={"exit_code": 0, "output": ""}))
            cases = (
                ("下周评估这次修改的效果。", "predicate"),
                ("收到外部审批后评估这次修改的效果。", "external_dependency"),
                ("外部审核通过后评估这次修改的效果。", "external_dependency"),
                ("After the external approval, evaluate this change.", "external_dependency"),
                ("Next month evaluate this change.", "predicate"),
            )
            for root, kind in cases:
                with self.subTest(root=root):
                    result, decision = self.replay(root, "修改完成，评估尚未进行。",
                                                   preparation=ready)
                    self.assertEqual(result, {})
                    self.assertNotIn("current_due_action_omitted", decision["reason_codes"])
                    self.assertFalse(any(a.get("actionability") == "current_ready"
                                         for a in decision["actions"]))
                    self.assertFalse(any(w.get("external_source_sha256")
                                         for w in decision.get("wait_conditions", [])))
                    self.assertEqual(len(decision["core_projections"]), 1)
                    self.assertIn("pending", decision["core_projections"][0]["conditions"].values())
                    self.assertEqual(decision["core_projections"][0]["root_condition"]["kind"], kind)
            result, decision = self.replay("现在评估这次修改的效果。",
                                           "评估尚未进行。", preparation=ready)
            self.assertEqual(result, {})
            self.assertNotIn("current_due_action_omitted", decision["reason_codes"])
            self.assertEqual(decision["actions"][0]["actionability"], "current_ready")

    def test_event_sequence_survives_same_timestamp_and_clock_rollback(self):
        with physical_tempdir(prefix="stop-v5-seq-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(kind, turn="turn", **fields):
                    return dict(hook_event_name=kind, session_id="sequence-v5",
                                cwd=tmp, turn_id=turn, **fields)
                suite = Path(tmp) / "suite.py"
                suite.write_text("def test_ok(): assert True\n", encoding="utf-8")
                cg.dispatch(event("UserPromptSubmit", "control", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", prompt=f"继续执行，运行 {root_locator(suite)} 的测试。"))
                cg.dispatch(event("PostToolUse", tool_name="exec_command",
                                  tool_input={"cmd": f"test -f {suite}"},
                                  tool_response={"exit_code": 0, "output": ""}))
                directory = Path(tmp) / "private/sessions/sequence-v5"
                state = cg.load_state(directory, event("Stop"))
                item = state["requirements"][-1]
                root = next(p for p in state["prompts"] if p["id"] == item["prompt_id"])
                record = cg.read_prompt_record(directory, root)
                self.assertIsNotNone(record)
                obs = next(e for e in state["evidence"] if e.get("core_observation"))
                self.assertLess(record["core_event_seq"], obs["core_call_seq"])
                self.assertLess(obs["core_call_seq"], obs["core_result_seq"])
                for root_time, host_time in (("same", "same"), ("later", "earlier")):
                    with self.subTest(root_time=root_time, host_time=host_time):
                        record["created_at"] = root_time
                        obs["created_at"] = host_time
                        projection = project_current_action(
                            state, {root["id"]: record}, item=item,
                            action="test_verify", target=str(suite), turn="turn",
                            root_scope=record["text"].rstrip("。"))
                        self.assertEqual(projection["as_of"], state["core_event_sequence"])
                        self.assertEqual(projection["current_actions"][0]["target"], str(suite))
                prior = cg.dispatch(event("Stop", last_assistant_message="测试尚未运行。"))
                prior_state = cg.load_state(directory, event("Stop"))
                prior_decision = dict(prior_state["decision_log"][-1])
                prior_watermark = prior_state["core_event_sequence"]
                self.assertEqual(prior.get("decision"), "block")
                cg.dispatch(event("UserPromptSubmit", "later", prompt="接下来再安装工具。"))
                latest = cg.load_state(directory, event("Stop", "later"))
                self.assertEqual(latest["decision_log"][-1], prior_decision)
                self.assertGreater(latest["core_event_sequence"], prior_watermark)
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_late_prior_turn_result_cannot_violate_later_root(self):
        with physical_tempdir(prefix="stop-v5-late-") as tmp:
            previous = os.environ.get("CONTEXT_GUARD_DATA_DIR")
            os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(tmp) / "private")
            try:
                def event(kind, turn="prior", **fields):
                    return dict(hook_event_name=kind, session_id="late-v5",
                                cwd=tmp, turn_id=turn, **fields)
                web = Path(tmp) / "packages/web/src/request.ts"
                api = Path(tmp) / "packages/api/src/request.ts"
                for target in (web, api):
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("old\n", encoding="utf-8")
                cg.dispatch(event("UserPromptSubmit", "control", prompt="context-guard on"))
                cg.dispatch(event("UserPromptSubmit", prompt="修复本轮文件。"))
                web_patch = f"*** Begin Patch\n*** Update File: {web}\n@@\n-old\n+new\n*** End Patch\n"
                cg.dispatch(event("PreToolUse", tool_name="apply_patch",
                                  tool_use_id="earlier-call", tool_input={"patch": web_patch}))
                web.write_text("new\n", encoding="utf-8")
                # Windows relative root locators are unavailable in core/v2;
                # the causal late-result check uses the exact physical A/B
                # identity there, while POSIX keeps the relative control.
                api_root = str(api) if os.name == "nt" else "packages/api/src/request.ts"
                web_root = str(web) if os.name == "nt" else "packages/web/src/request.ts"
                root = (f"请只修改 {api_root}。错误日志还提到了 "
                        f"{web_root}，但本轮不要动后者。")
                cg.dispatch(event("UserPromptSubmit", "current", prompt=root))
                cg.dispatch(event("PostToolUse", tool_name="apply_patch",
                                  tool_use_id="earlier-call", tool_input={"patch": web_patch},
                                  tool_response={"success": True}))
                cg.dispatch(event("PostToolUse", "current", tool_name="exec_command",
                                  tool_input={"cmd": f"cat {api}"},
                                  tool_response={"exit_code": 0, "output": "old\n"}))
                api.write_text("new\n", encoding="utf-8")
                api_patch = f"*** Begin Patch\n*** Update File: {api}\n@@\n-old\n+new\n*** End Patch\n"
                cg.dispatch(event("PostToolUse", "current", tool_name="apply_patch",
                                  tool_input={"patch": api_patch},
                                  tool_response={"success": True}))
                cg.dispatch(event("PostToolUse", "current", tool_name="exec_command",
                                  tool_input={"cmd": f"cat {api}"},
                                  tool_response={"exit_code": 0, "output": "new\n"}))
                cg.dispatch(event("Stop", "current", last_assistant_message="API 文件已修改并回读。"))
                directory = Path(tmp) / "private/sessions/late-v5"
                state = cg.load_state(directory, event("Stop", "current"))
                rows = [r for r in state["decision_log"][-1]["core_projections"]
                        if r["predicate"] == "edit_with_prohibition"]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["constraint_state"], "constraint_unresolved")
                self.assertEqual(rows[0]["crossing_host_event_ids"], ["E0001"])
                self.assertEqual(rows[0]["violating_host_event_ids"], [])
                origin = next(p for p in state["prompts"] if p.get("turn_id") == "prior")
                record = cg.read_prompt_record(directory, origin)
                self.assertEqual(record["turn_id"], "prior")
                self.assertEqual(record["record_sha256"], cg.prompt_record_hash(record))
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
                else:
                    os.environ["CONTEXT_GUARD_DATA_DIR"] = previous

    def test_missing_or_competing_prompt_turn_does_not_bind_host_origin(self):
        state = {
            "work_state": {"active_work_unit_id": "WU0001"},
            "requirements": [
                {"prompt_id": "P0001", "work_unit_id": "WU0001"},
                {"prompt_id": "P0002", "work_unit_id": "WU0001"},
            ],
            "prompts": [
                {"id": "P0001", "core_event_seq": 1},  # schema-12 legacy root
                {"id": "P0002", "core_event_seq": 2, "turn_id": "current"},
            ],
        }
        self.assertIsNone(cg.core_host_origin_prompt(state, {"turn_id": "prior"}))
        self.assertEqual(cg.core_host_origin_prompt(state, {"turn_id": "current"}), "P0002")
        state["prompts"][0]["turn_id"] = "current"
        self.assertIsNone(cg.core_host_origin_prompt(state, {"turn_id": "current"}))
        self.assertIsNone(cg.core_host_origin_prompt(state, {}))


if __name__ == "__main__":
    unittest.main()
