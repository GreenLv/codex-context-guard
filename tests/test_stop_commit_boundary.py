"""Stop final-commit-boundary matrix (review R1 family closure).

The consumption-time source recheck runs at the TRUE commit boundary: after
every source-identity-dependent business write (explicit/auto checkpoints,
unit closure, delivery records, ordinary retirements) and before anything
persists. Each cell injects one corruption at one production stage of one
completion path and asserts the RAW persisted state.json: business rows
equal the event entry, only the failure decision is logged.

Matrix dimensions:
  paths    P1 explicit-checkpoint, P2 auto-checkpoint,
           P3 question-delivery, P4 ordinary-test-retirement
  stages   S1 after-source-read (mid-path persistence probe),
           S2 after-closure-apply (apply_checkpoint wrap; P1/P2 only),
           S3 during-delivery-build (delivery().build_record wrap),
           S4 during-retirement (retire_verified_ordinary_core_result wrap;
               P4 only — other paths produce no ordinary projection)
  damages  mutate / delete / same-length swap
Not-applicable cells are asserted as such (a wrap that never fires cannot
inject); they are recorded, never silently skipped.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
import context_guard as cg  # noqa: E402
from test_host_terminal_wire import HostTerminalWireTests  # noqa: E402

SESSION = "commit-boundary"


class CommitBoundaryMatrix(unittest.TestCase):
    def setUp(self):
        self.in_stop = False
        self._wire_session_dir = None
        self._wire_event_base = None
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(self.root / "private")

    def tearDown(self):
        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
        self.temp.cleanup()

    def event(self, kind, turn="t1", **fields):
        base = getattr(self, "_wire_event_base", None)
        if base is not None:
            payload = dict(hook_event_name=kind, **base, **fields)
            payload.setdefault("transcript_path", str(self.wire.transcript))
            return payload
        payload = dict(hook_event_name=kind, session_id=SESSION,
                       cwd=str(self.project), turn_id=turn, **fields)
        return payload

    def raw_state(self):
        directory = getattr(self, "_wire_session_dir", None)
        if directory is None:
            directory = self.root / "private/sessions-v2" / SESSION
        return json.loads(
            (directory / "state.json").read_text(encoding="utf-8"))

    # -- path builders -------------------------------------------------

    def build_p1_explicit_checkpoint(self):
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        with mock.patch.object(cg.secrets, "token_urlsafe",
                               return_value="boundary"):
            cg.dispatch(self.event("UserPromptSubmit",
                                   prompt=f"$context-guard\n请先核对 {target} 后修复文档。"))
        cg.dispatch(self.event("PostToolUse", tool_name="shell",
                               tool_input={"command": f"cat {target}"},
                               tool_response={"exit_code": 0, "output": "subject"}))
        state = self.raw_state()
        evidence = f"E{state['evidence_sequence']:04d}"
        cg.stage_private_checkpoint(
            self.root / "private", SESSION, "t1", "boundary",
            [f"{item['id']}={evidence}" for item in state["requirements"]
             if item["status"] not in {"pass", "superseded"}],
            [f"{item['id']}={evidence}" for item in state["acceptance_items"]
             if item["status"] not in {"pass", "superseded"}])
        return "任务已完成。"

    def build_p2_auto_checkpoint(self):
        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        with mock.patch.object(cg.secrets, "token_urlsafe",
                               return_value="boundary"):
            cg.dispatch(self.event(
                "UserPromptSubmit",
                prompt=f"$context-guard\n请先核对 {target} 后修复文档。"))
        cg.dispatch(self.event("PostToolUse", tool_name="shell",
                               tool_input={"command": f"cat {target}"},
                               tool_response={"exit_code": 0, "output": "subject"}))
        return "任务已经全部完成。"

    def build_p3_question_delivery(self):
        cg.dispatch(self.event("UserPromptSubmit", turn="t0",
                               prompt="context-guard on"))
        with mock.patch.object(cg.secrets, "token_urlsafe",
                               return_value="boundary"):
            cg.dispatch(self.event("UserPromptSubmit",
                                   prompt="解释这个函数为什么要处理空输入"))
        return "缺失值需要保持类型稳定。"

    def build_p4_ordinary_retirement(self):
        # Production chain through the REAL structured-transcript harness
        # (test_host_terminal_wire.HostTerminalWireTests): its transcript,
        # CODEX_HOME and session wiring are exactly what reaches
        # delivered_current_test_projection and the retire call in finish
        # (proven by test_p4_retirement_reachability). The matrix's raw-state
        # reads and corruption delegate to the harness's private root.
        self.wire = HostTerminalWireTests(
            "test_direct_backtick_pytest_object_binds_current_test")
        self.wire.setUp()
        self.addCleanup(self.wire.tearDown)
        suite = self.wire.cwd / "current_suite.py"
        self.wire.write_file(suite, "def test_current(): assert True\n")
        command = f"pytest '{suite}'"
        self.wire.start(f"现在通过宿主 Bash 单独运行 `{command}`，"
                        "并根据本次真实退出结果报告测试。")
        self.wire.command("current-test", command, stdout="1 passed\n",
                          response="1 passed\n")
        # The Stop dispatch below uses self.event()/self.raw_state(); route
        # them to the harness session.
        self._wire_session_dir = self.wire.root / "private/sessions-v2" / self.wire.session_id
        self._wire_event_base = {
            "session_id": self.wire.session_id,
            "cwd": str(self.wire.cwd),
            "turn_id": self.wire.turn_id,
        }
        return "测试通过。\n退出码 0。\n1 passed。"

    # -- corruption and stage wraps ------------------------------------

    def corrupt(self, mode):
        state = self.raw_state()
        directory = getattr(self, "_wire_session_dir", None)
        if directory is None:
            directory = self.root / "private/sessions-v2" / SESSION
        metadata = next(p for p in state["prompts"]
                        if p.get("origin", "human") == "human" and p.get("file"))
        path = directory / metadata["file"]
        if mode == "delete":
            path.unlink()
            return
        record = json.loads(path.read_text(encoding="utf-8"))
        if mode == "same-length":
            text = record["text"]
            record["text"] = ("A" if text[0] != "A" else "B") + text[1:]
        else:
            record["text"] += " changed at boundary"
        record["sha256"] = cg.sha256_text(record["text"])
        path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")

    def stage_wrap(self, stage, mode, path_key=None):
        """Return (context_manager, fired_flag_list) injecting at `stage`.

        S1 is the after-source-read point on each path's real production
        flow: the explicit-checkpoint path returns from its staged-control
        branch before the persistence probe, so its S1 hook is
        ``checkpoint_issues`` (called after records are read, before the
        checkpoint applies); every other path uses
        ``current_persistence_actions``.
        """
        fired = []
        if stage == "S1":
            if path_key == "P1":
                real = cg.checkpoint_issues

                def wrap_cp(state, checkpoint):
                    # stage_private_checkpoint calls the same validator while
                    # staging; inject only during the Stop dispatch itself.
                    if self.in_stop:
                        self.corrupt(mode)
                        fired.append(stage)
                    return real(state, checkpoint)
                return (mock.patch.object(cg, "checkpoint_issues",
                                          side_effect=wrap_cp), fired)
            real = cg.current_persistence_actions

            def wrap(state, session_dir, context=None):
                self.corrupt(mode)
                fired.append(stage)
                return (real(state, session_dir, context) if context is not None
                        else real(state, session_dir))
            return mock.patch.object(cg, "current_persistence_actions",
                                     side_effect=wrap), fired
        if stage == "S2":
            real = cg.apply_checkpoint

            def wrap(state, checkpoint, turn):
                result = real(state, checkpoint, turn)
                self.corrupt(mode)
                fired.append(stage)
                return result
            return mock.patch.object(cg, "apply_checkpoint",
                                     side_effect=wrap), fired
        if stage == "S3":
            delivery = cg.delivery()
            real = delivery.build_record

            def wrap(*args, **kwargs):
                self.corrupt(mode)
                fired.append(stage)
                return real(*args, **kwargs)
            return mock.patch.object(delivery, "build_record",
                                     side_effect=wrap), fired
        if stage == "S4":
            real = cg.retire_verified_ordinary_core_result

            def wrap(*args, **kwargs):
                self.corrupt(mode)
                fired.append(stage)
                return real(*args, **kwargs)
            return mock.patch.object(cg, "retire_verified_ordinary_core_result",
                                     side_effect=wrap), fired
        raise AssertionError(stage)

    # -- the matrix ------------------------------------------------------

    PATHS = {
        "P1": ("explicit-checkpoint", None, {"S1", "S2", "S3"}),
        # P1's S1 uses checkpoint_issues (staged-control early return); see
        # stage_wrap.
        "P2": ("auto-checkpoint", None, {"S1", "S2", "S3"}),
        "P3": ("question-delivery", None, {"S1", "S3"}),
        # S4 (retire wrap) is reachable through the structured-transcript
        # production chain in build_p4_ordinary_retirement; the earlier
        # flat-PostToolUse shape could not reach it.
        "P4": ("ordinary-retirement", None, {"S1", "S3", "S4"}),
    }

    def build_path(self, path_key):
        return {
            "P1": self.build_p1_explicit_checkpoint,
            "P2": self.build_p2_auto_checkpoint,
            "P3": self.build_p3_question_delivery,
            "P4": self.build_p4_ordinary_retirement,
        }[path_key]()
    DAMAGES = ("mutate", "delete", "same-length")

    def test_commit_boundary_matrix(self):
        not_applicable = []
        for path_key, (path_name, _none, stages) in self.PATHS.items():
            for stage in ("S1", "S2", "S3", "S4"):
                for damage in self.DAMAGES:
                    with self.subTest(path=path_name, stage=stage,
                                      damage=damage):
                        self._run_cell(path_key, path_name, stage,
                                       stages, damage, not_applicable)
        # Every excluded cell is recorded with its structural reason:
        # P3/P4 lack S2 (no closure apply); P1/P2/P3 lack S4 (no ordinary
        # retirement on those paths); P4 reaches S4 through the real harness.
        expected_na = 5 * 3  # P1/P2/P3 lack S4; P3/P4 lack S2
        self.assertEqual(len(not_applicable), expected_na, not_applicable)

    def _run_cell(self, path_key, path_name, stage, stages, damage,
                  not_applicable):
        # unittest subTest does not re-run setUp: rebuild a fresh environment
        # for every cell so paths never observe earlier cells' state.
        self.tearDown()
        self.setUp()
        if path_key == "P4":
            self._wire_session_dir = None
            self._wire_event_base = None
        reply = self.build_path(path_key)
        entry = self.raw_state()
        entry_requirements = [i["status"] for i in entry["requirements"]]
        entry_delivery = len(entry.get("response_delivery", {})
                             .get("records", []))
        wrap, fired = self.stage_wrap(stage, damage, path_key)
        self.in_stop = True
        try:
            with wrap:
                result = cg.dispatch(self.event("Stop",
                                                last_assistant_message=reply))
        finally:
            self.in_stop = False
        if stage not in stages:
            not_applicable.append((path_name, stage, damage,
                                   "production path never reaches this stage"))
            # The wrap never fired: the run must have committed normally.
            self.assertFalse(fired)
            self.assertEqual(result, {})
            return
        self.assertTrue(fired, f"injection at {stage} never fired")
        saved = self.raw_state()
        self.assertEqual(result.get("continue"), False)
        self.assertIn("changed before the decision was committed",
                      result.get("stopReason", ""))
        self.assertEqual([i["status"] for i in saved["requirements"]],
                         entry_requirements)
        self.assertTrue(all(unit["status"] != "completed"
                            for unit in saved["work_units"]))
        self.assertIsNone((saved.get("completion_checkpoint") or {}).get("status"))
        self.assertEqual(len(saved.get("response_delivery", {})
                             .get("records", [])), entry_delivery)
        self.assertEqual(saved["decision_log"][-1]["outcome"],
                         "fail_closed_integrity")
        self.assertIn("consumed_source_changed_before_commit",
                      saved["decision_log"][-1]["reason_codes"])

    def test_p4_retirement_reachability(self):
        """The production P4 chain must actually reach the retire call."""
        self.build_path("P4")
        called = []
        real = cg.retire_verified_ordinary_core_result

        def spy(*args, **kwargs):
            called.append(True)
            return real(*args, **kwargs)

        with mock.patch.object(cg, "retire_verified_ordinary_core_result",
                               side_effect=spy):
            cg.dispatch(self.event(
                "Stop", last_assistant_message="测试通过。\n退出码 0。\n1 passed。"))
        self.assertTrue(called, "retire never reached on the P4 path")
        state = self.raw_state()
        rows = state["decision_log"][-1].get("core_projections") or []
        self.assertTrue(any(row.get("predicate") == "test_run_completed"
                            for row in rows))
        self.assertIn("ordinary_core_result_verified",
                      state["decision_log"][-1].get("reason_codes", []))

    def test_clean_paths_commit_normally(self):
        for path_key, (path_name, _none, _stages) in self.PATHS.items():
            with self.subTest(path=path_name):
                self.temp.cleanup()
                self.setUp()
                reply = self.build_path(path_key)
                result = cg.dispatch(self.event("Stop",
                                                last_assistant_message=reply))
                saved = self.raw_state()
                if path_key in ("P1", "P2"):
                    self.assertEqual(result, {})
                    self.assertTrue(all(i["status"] == "pass"
                                        for i in saved["requirements"]))
                else:
                    self.assertEqual(result, {})
                self.assertNotEqual(saved["decision_log"][-1]["outcome"],
                                    "fail_closed_integrity")


if __name__ == "__main__":
    unittest.main()
