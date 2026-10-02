"""Full-Stop performance and safety regressions (plan T01–T20 mapping).

The deterministic work-count assertions fail on any implementation that
re-prepares semantic inputs per item×category inside one Stop event: they
require the event-scoped evaluation context introduced for the long-session
Stop fix. Wall-clock evidence lives in tools/validation/benchmark_stop.py,
which CI does not run as a tight timing test.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "validation"))
import context_guard as cg  # noqa: E402
import stop_performance_fixture as fx  # noqa: E402


class StopPerformanceRegressionTests(unittest.TestCase):
    """S1 work counts stay event-scoped; old trees fail these bounds."""

    def test_s1_work_counts_within_event_scoped_bounds(self):
        captured: dict[str, int] = {}
        original = cg.EvaluationContext

        class Counting(original):  # type: ignore[misc, valid-type]
            def __init__(self, state, session_dir, **kwargs):
                kwargs["counters"] = captured
                super().__init__(state, session_dir, **kwargs)

        with tempfile.TemporaryDirectory(prefix="cg-s1-counts-") as root:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = root
            with mock.patch.object(cg, "EvaluationContext", Counting):
                built = fx.build_session(cg, root, "S1")
                result = cg.dispatch(built["stop_event"])
            self.assertEqual(result, {})
            # One scope per stable phase (2 phases: evaluation, delivery),
            # one verified prompt-record read per prompt, and each distinct
            # source text parsed exactly once.
            self.assertLessEqual(captured.get("scope_computed", 0), 4)
            self.assertLessEqual(captured.get("prompt_record_read", 0), 60)
            self.assertLessEqual(captured.get("fragments_computed", 0), 260)
            self.assertLessEqual(captured.get("basis_evaluated", 0), 2600)
            self.assertLessEqual(captured.get("action_sources_computed", 0), 200)

    def test_s0_small_session_has_no_reuse_overhead_regression(self):
        # The reuse layer must not slow the short-session path materially:
        # a bound at one second is generous; the pre-change path ran in tens
        # of milliseconds and the context adds only dictionary lookups.
        import time

        with tempfile.TemporaryDirectory(prefix="cg-s0-wall-") as root:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = root
            built = fx.build_session(cg, root, "S0")
            started = time.perf_counter()
            self.assertEqual(cg.dispatch(built["stop_event"]), {})
            self.assertLess(time.perf_counter() - started, 1.0)


class StopSourceSafetyTests(unittest.TestCase):
    """T04/T20: no completion is committed from a stale verified source."""

    def _session(self, prefix):
        root = tempfile.mkdtemp(prefix=prefix)
        os.environ["CONTEXT_GUARD_DATA_DIR"] = root
        built = fx.build_session(cg, root, "S0")
        return root, built

    def test_root_corrupted_after_read_blocks_commit(self):
        root, built = self._session("cg-t04-corrupt-")
        real_persistence = cg.current_persistence_actions

        def corrupt_then_continue(state_, session_dir_, context=None):
            # Corrupt one verified record mid-event, after the evaluation
            # context has already read it.
            prompt = next(p for p in state_["prompts"]
                          if p.get("origin", "human") == "human"
                          and p.get("file"))
            path = session_dir_ / prompt["file"]
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["text"] = payload["text"] + "额外要求：必须重新验证。"
            payload["sha256"] = cg.sha256_text(payload["text"])
            path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            if context is not None:
                return real_persistence(state_, session_dir_, context)
            return real_persistence(state_, session_dir_)

        with mock.patch.object(cg, "current_persistence_actions",
                               side_effect=corrupt_then_continue):
            result = cg.dispatch(dict(built["stop_event"]))
        self.assertEqual(result.get("continue"), False)
        self.assertIn("changed before the decision was committed",
                      result.get("stopReason", ""))
        saved = cg.load_state(
            built["session_dir"], dict(hook_event_name="Stop",
                                       session_id=built["session_id"],
                                       cwd=root, turn_id="t-final"))
        self.assertEqual(saved["decision_log"][-1]["outcome"],
                         "fail_closed_integrity")
        self.assertIn("consumed_source_changed_before_commit",
                      saved["decision_log"][-1]["reason_codes"])

    def test_unchanged_sources_still_commit_normally(self):
        root, built = self._session("cg-t04-clean-")
        self.assertEqual(cg.dispatch(built["stop_event"]), {})
        saved = cg.load_state(
            built["session_dir"], dict(hook_event_name="Stop",
                                       session_id=built["session_id"],
                                       cwd=root, turn_id="t-final"))
        self.assertNotEqual(saved["decision_log"][-1]["outcome"],
                            "fail_closed_integrity")


class StopEventBoundaryTests(unittest.TestCase):
    """T13/T18: fresh contexts per event; delivery opens a new phase."""

    def test_two_stop_events_do_not_share_reuse(self):
        with tempfile.TemporaryDirectory(prefix="cg-t13-") as root:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = root
            built = fx.build_session(cg, root, "S0")
            first = cg.dispatch(built["stop_event"])
            state = cg.load_state(
                built["session_dir"], dict(hook_event_name="Stop",
                                           session_id=built["session_id"],
                                           cwd=root, turn_id="t-final"))
            state["requirements"][0]["text"] = "修改后的新任务文本，必须重新验证。"
            cg.save_state(built["session_dir"], state)
            second = cg.dispatch(built["stop_event"])
            # Both events end silently for this neutral reply; the important
            # fact is a fresh evaluation with identical decision surface.
            self.assertEqual(first, second)

    def test_delivery_write_opens_new_phase(self):
        captured: dict[str, int] = {}
        original = cg.EvaluationContext

        class Counting(original):  # type: ignore[misc, valid-type]
            def __init__(self, state, session_dir, **kwargs):
                kwargs["counters"] = captured
                super().__init__(state, session_dir, **kwargs)

            def new_phase(self, reason):
                super().new_phase(reason)
                self.phase_reasons = getattr(self, "phase_reasons", []) + [reason]

        with tempfile.TemporaryDirectory(prefix="cg-t18-") as root:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = root
            built = fx.build_session(cg, root, "S0")
            with mock.patch.object(cg, "EvaluationContext", Counting):
                cg.dispatch(built["stop_event"])
            self.assertGreaterEqual(captured.get("phase", 0), 2)
            self.assertLessEqual(captured.get("scope_computed", 0), 4)

    def test_subprocess_stop_events_are_independent(self):
        # Two full hook processes over sequentially mutated state: no cross
        # event reuse is possible; results must track the state they saw.
        with tempfile.TemporaryDirectory(prefix="cg-t13-proc-") as root:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = root
            built = fx.build_session(cg, root, "S0")
            driver = (
                "import json,sys;sys.path.insert(0,%r);sys.path.insert(0,%r);"
                "import context_guard as cg;"
                "sys.stdout.write(json.dumps(cg.dispatch(json.loads(sys.stdin.read()))))"
                % (str(REPO_ROOT / "scripts"), str(REPO_ROOT / "tools" / "validation")))
            env = {**os.environ, "CONTEXT_GUARD_DATA_DIR": root,
                   "PYTHONDONTWRITEBYTECODE": "1"}
            first = subprocess.run(
                [sys.executable, "-c", driver],
                input=json.dumps(built["stop_event"]),
                capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(first.returncode, 0, first.stderr)
            state = cg.load_state(
                built["session_dir"], dict(hook_event_name="Stop",
                                           session_id=built["session_id"],
                                           cwd=root, turn_id="t-final"))
            state["mode"]["manual_off"] = True
            cg.save_state(built["session_dir"], state)
            second = subprocess.run(
                [sys.executable, "-c", driver],
                input=json.dumps(built["stop_event"]),
                capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(json.loads(first.stdout), {})
            self.assertEqual(json.loads(second.stdout), {})


class CommitAtomicityTests(unittest.TestCase):
    """R1: a fail-closed consumption recheck must never persist success.

    The Stop handler applies checkpoints and closes units in place before its
    final commit. When the consumption-time source recheck fails, the whole
    business state rolls back to the event entry; assertions read the raw
    persisted state.json bytes, never the handler return value alone and
    never a state reloaded through recovery.
    """

    def setUp(self):
        import tempfile
        from pathlib import Path

        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        os.environ["CONTEXT_GUARD_DATA_DIR"] = str(self.root / "private")

    def tearDown(self):
        os.environ.pop("CONTEXT_GUARD_DATA_DIR", None)
        self.temp.cleanup()

    def event(self, kind, turn="turn-1", **fields):
        return dict(hook_event_name=kind, session_id="atomicity",
                    cwd=str(self.project), turn_id=turn, **fields)

    def raw_state(self):
        return json.loads(
            (self.root / "private/sessions-v2/atomicity/state.json").read_text(
                encoding="utf-8"))

    def _activated_with_success_evidence(self, prompt):
        from unittest import mock

        with mock.patch.object(cg.secrets, "token_urlsafe",
                               return_value="atomicity"):
            cg.dispatch(self.event("UserPromptSubmit", prompt=prompt))
        cg.dispatch(self.event("PostToolUse", tool_name="shell",
                               tool_input={"command": "python -m unittest"},
                               tool_response={"exit_code": 0, "output": "OK"}))
        state = self.raw_state()
        evidence = f"E{state['evidence_sequence']:04d}"
        cg.stage_private_checkpoint(
            self.root / "private", "atomicity", "turn-1", "atomicity",
            [f"{item['id']}={evidence}" for item in state["requirements"]
             if item["status"] not in {"pass", "superseded"}],
            [f"{item['id']}={evidence}" for item in state["acceptance_items"]
             if item["status"] not in {"pass", "superseded"}],
        )

    def _corrupt_prompt_record(self, state, mode):
        prompt = next(p for p in state["prompts"]
                      if p.get("origin", "human") == "human" and p.get("file"))
        path = self.root / "private/sessions-v2/atomicity" / prompt["file"]
        if mode == "delete":
            path.unlink()
            return
        value = json.loads(path.read_text(encoding="utf-8"))
        if mode == "same-length-swap":
            text = value["text"]
            value["text"] = ("A" if text[0] != "A" else "B") + text[1:]
        else:
            value["text"] += " changed"
        value["sha256"] = cg.sha256_text(value["text"])
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def test_explicit_checkpoint_rollback_on_each_corruption_mode(self):
        from unittest import mock

        for mode in ("mutate", "same-length-swap", "delete"):
            with self.subTest(mode=mode):
                self._activated_with_success_evidence("$context-guard\n修复模块的问题。")
                before = self.raw_state()
                real_apply = cg.apply_checkpoint

                def corrupt_after_apply(state, checkpoint, turn):
                    real_apply(state, checkpoint, turn)
                    self._corrupt_prompt_record(state, mode)

                with mock.patch.object(cg, "apply_checkpoint",
                                       side_effect=corrupt_after_apply):
                    result = cg.dispatch(self.event(
                        "Stop", last_assistant_message="任务已完成。"))
                saved = self.raw_state()
                self.assertEqual(result.get("continue"), False)
                self.assertIn("changed before the decision was committed",
                              result.get("stopReason", ""))
                self.assertEqual(
                    [i["status"] for i in saved["requirements"]],
                    [i["status"] for i in before["requirements"]], mode)
                self.assertTrue(all(unit["status"] != "completed"
                                    for unit in saved["work_units"]), mode)
                self.assertIsNone((saved.get("completion_checkpoint") or {})
                                  .get("status"), mode)
                self.assertEqual(saved["decision_log"][-1]["outcome"],
                                 "fail_closed_integrity")
                self.assertIn("consumed_source_changed_before_commit",
                              saved["decision_log"][-1]["reason_codes"])
                self.temp.cleanup()
                self.setUp()

    def test_auto_checkpoint_rollback(self):
        from unittest import mock

        target = self.project / "spec.txt"
        target.write_text("subject", encoding="utf-8")
        with mock.patch.object(cg.secrets, "token_urlsafe",
                               return_value="atomicity"):
            cg.dispatch(self.event(
                "UserPromptSubmit",
                prompt=f"$context-guard\n请先核对 {target} 后修复文档。"))
        cg.dispatch(self.event("PostToolUse", tool_name="shell",
                               tool_input={"command": f"cat {target}"},
                               tool_response={"exit_code": 0, "output": "subject"}))
        before = self.raw_state()
        real_apply = cg.apply_checkpoint

        def corrupt_after_apply(state, checkpoint, turn):
            real_apply(state, checkpoint, turn)
            self._corrupt_prompt_record(state, "mutate")

        with mock.patch.object(cg, "apply_checkpoint",
                               side_effect=corrupt_after_apply):
            result = cg.dispatch(self.event(
                "Stop", last_assistant_message="任务已经全部完成。"))
        saved = self.raw_state()
        self.assertEqual(result.get("continue"), False)
        self.assertEqual([i["status"] for i in saved["requirements"]],
                         [i["status"] for i in before["requirements"]])
        self.assertTrue(all(unit["status"] != "completed"
                            for unit in saved["work_units"]))
        self.assertIsNone((saved.get("completion_checkpoint") or {}).get("status"))
        self.assertEqual(saved["decision_log"][-1]["outcome"],
                         "fail_closed_integrity")

    def test_delivery_and_retirement_not_persisted_on_failed_recheck(self):
        from unittest import mock

        with mock.patch.object(cg.secrets, "token_urlsafe",
                               return_value="atomicity"):
            cg.dispatch(self.event("UserPromptSubmit",
                                   prompt="$context-guard\n修复模块的问题。"))
        before = self.raw_state()
        real_persistence = cg.current_persistence_actions

        def corrupt_then_continue(state, session_dir, context=None):
            self._corrupt_prompt_record(state, "mutate")
            if context is not None:
                return real_persistence(state, session_dir, context)
            return real_persistence(state, session_dir)

        with mock.patch.object(cg, "current_persistence_actions",
                               side_effect=corrupt_then_continue):
            result = cg.dispatch(self.event(
                "Stop", last_assistant_message="本轮已完成修复。"))
        saved = self.raw_state()
        self.assertEqual(result.get("continue"), False)
        ledger = saved.get("response_delivery", {}).get("records", [])
        self.assertEqual(len(ledger),
                         len(before.get("response_delivery", {}).get(
                             "records", [])))
        self.assertTrue(all(item["status"] != "answered"
                            for item in saved["requirements"]))
        self.assertEqual(saved["decision_log"][-1]["outcome"],
                         "fail_closed_integrity")

    def test_clean_commit_still_persists_success(self):
        self._activated_with_success_evidence("$context-guard\n修复模块的问题。")
        result = cg.dispatch(self.event("Stop",
                                        last_assistant_message="任务已完成。"))
        saved = self.raw_state()
        self.assertEqual(result, {})
        self.assertTrue(all(item["status"] == "pass"
                            for item in saved["requirements"]))
        self.assertTrue(any(unit["status"] == "completed"
                            for unit in saved["work_units"]))
        self.assertEqual((saved.get("completion_checkpoint") or {})
                         .get("status"), "complete")


class HookColdStartTests(unittest.TestCase):
    """Ordinary PreToolUse whole-process cold start stays inside the active
    hook-timeout contract (the historical 50 ms Phase-2 threshold is
    retired and is not asserted here)."""

    def test_pretool_cold_start_within_timeout(self):
        sys.path.insert(0, str(REPO_ROOT / "tools" / "validation"))
        import stop_performance_fixture as fx

        with tempfile.TemporaryDirectory(prefix="cg-cold-") as root:
            os.environ["CONTEXT_GUARD_DATA_DIR"] = root
            built = fx.build_session(fx.load_runtime(), root, "S0")
            event = dict(hook_event_name="PreToolUse", tool_name="shell",
                         tool_input={"command": "echo cold-start"},
                         session_id=built["session_id"], cwd=root,
                         turn_id="t-cold")
            for _ in range(2):
                clone = tempfile.mkdtemp(prefix="cg-cold-run-")
                shutil.copytree(root, clone, dirs_exist_ok=True)
                started = time.perf_counter()
                completed = subprocess.run(
                    [sys.executable,
                     str(REPO_ROOT / "scripts" / "context_guard.py"), "hook"],
                    input=json.dumps(event), capture_output=True, text=True,
                    timeout=30,
                    env={**os.environ, "CONTEXT_GUARD_DATA_DIR": clone,
                         "PYTHONDONTWRITEBYTECODE": "1"})
                wall = time.perf_counter() - started
                shutil.rmtree(clone, ignore_errors=True)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                json.loads(completed.stdout)
                self.assertLess(wall, 10.0)


if __name__ == "__main__":
    unittest.main()
