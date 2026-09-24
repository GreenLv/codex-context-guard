#!/usr/bin/env python3
"""Bounded official app-server collector for the C2 exact-marker control.

Preflight is zero-model. Collection owns one app-server process and at most
three producer turns. It records native sources but does not by itself certify
model behavior or replace a versioned native-acceptance result.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path

from scripts import context_guard as product
from tools.validation import commentary_fixture as fixture
from tools.validation import commentary_live_adapter as wire
from tools.validation import commentary_live_runner as runner
from tools.validation import commentary_suite_oracle as suite_oracle
from tools.validation.commentary_controls import (
    ControlOracle,
    c2_future_preserved,
    c2_root_sources,
    c2_wait_status,
)
from tools.validation.commentary_live_controller import Controller, exact_suite_approval
from tools.validation.commentary_live_observer import NativeObserver, PendingEvidence

SCHEMA = "cg-commentary-control-native-plan/v1"
ROOT_REPLY = "当前仍等待 CG142-CONFIRM-17，未来观察文件不存在。"
GENERAL_REPLY = ROOT_REPLY
EXACT_REPLY = "已按确认运行测试；未来观察文件仍不存在。"
FOLLOWUPS = ("root_prompt", "general_prompt", "exact_prompt")
CLIENT_IDS = ("root_client_id", "general_client_id", "exact_client_id")


C2_INSTRUCTIONS = (
    "This is a bounded local acceptance scenario with exactly three turns. "
    "In every turn first call cg_commentary_acceptance.ready with {{}}. "
    "Turn 1: do not call any business tool or run tests; send exactly one agent "
    f"message with no extra text: {ROOT_REPLY} "
    "Turn 2 after the general continuation: again do not call any business "
    "tool or run tests; send exactly one agent message with no extra text: "
    f"{ROOT_REPLY} Turn 3 only after the user sends CG142-CONFIRM-17: call "
    "cg_commentary_acceptance.challenge with {{}}, then use its exact returned "
    "nonce to call cg_commentary_acceptance.business exactly once. Use the "
    "built-in terminal once from the current working directory to run exactly: "
    "{suite_action}. Wait for its completion and verify exit code zero, one "
    "unittest test and OK. Do not run another suite command. Only if that test "
    "actually succeeds, send exactly one agent message with no extra text: "
    f"{EXACT_REPLY} Never create or infer the future-observation.json file. "
    "Keep the future observation as a separate pending requirement. If the "
    "test fails or cannot run, report the failure truthfully rather than send "
    "the success sentence."
)


def _validate_output_instructions(instructions: str, cwd: str) -> None:
    """Reject a plan that asks for prose the exact-output oracle must reject."""
    action = runner.frozen_suite_action(instructions, cwd)
    if action is None or instructions != C2_INSTRUCTIONS.format(suite_action=action):
        raise ValueError("control_output_contract_missing")


def _approval_suite_plan(plan: dict) -> dict | None:
    """Bind a future C2 approval to the literal action in its frozen prompt."""
    suite = plan.get("suite_oracle")
    if suite is None:
        return None
    action = runner.frozen_suite_action(plan["developer_instructions"], plan["cwd"])
    if action is None or not isinstance(suite, dict):
        raise ValueError("control_suite_contract_missing")
    platform = suite.get("platform")
    argv = suite_oracle._action_argv(action, platform)
    if (argv is None or len(argv) != 2
            or suite.get("allowed_python") != [argv[0]]
            or suite.get("path") != argv[1]
            or type(suite.get("allowed_outer_commands")) is not list
            or len(suite["allowed_outer_commands"]) != 1):
        raise ValueError("control_suite_contract_missing")
    root = f"请运行 {suite['path']} 的测试并持续执行直到任务完成。"
    adapted = {**plan, "root_prompt": root, "main_requirement_text": root}
    suite_oracle.validate_suite_plan(adapted)
    return adapted


def load_plan(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > runner.MAX_PLAN:
        raise ValueError("unsafe_control_plan")
    plan = runner.legacy.decode_object(path.read_bytes())
    if plan.get("schema") != SCHEMA or plan.get("scenario") != "C2":
        raise ValueError("unsupported_control_plan")
    for key in (*FOLLOWUPS, *CLIENT_IDS, "developer_instructions"):
        if type(plan.get(key)) is not str or not plan[key]:
            raise ValueError("missing_control_input:" + key)
    _validate_output_instructions(plan["developer_instructions"], plan.get("cwd", ""))
    if len({plan[key] for key in CLIENT_IDS}) != len(CLIENT_IDS):
        raise ValueError("reused_control_client_id")
    if (plan["general_prompt"] != "继续；请只报告现在能确认的状态。"
            or plan["exact_prompt"] != "CG142-CONFIRM-17"):
        raise ValueError("unfrozen_control_followups")
    future = plan.get("future_path")
    if (type(future) is not str or not Path(future).is_absolute()
            or Path(future).name != "future-observation.json"):
        raise ValueError("unbound_future_path")
    if ("CG142-CONFIRM-17" not in plan["root_prompt"]
            or future not in plan["root_prompt"]
            or "只有我" not in plan["root_prompt"]
            or "原样发送" not in plan["root_prompt"]):
        raise ValueError("unfrozen_control_root")
    waits = product.root_pause_clauses(plan["root_prompt"])
    if (len(waits) != 1
            or product.root_pause_condition_type(waits[0]) != "exact_input"
            or product.input_wait_subject(waits[0]) != "CG142-CONFIRM-17"):
        raise ValueError("ambiguous_control_root_wait")
    if plan.get("review_budget") != 0 or plan.get("execute_review") is True:
        raise ValueError("c2_reviewer_forbidden")
    if (plan.get("budget") != {"startup": 60, "turn": 240,
                               "compact": 120, "cleanup": 15}
            or plan.get("whole_session_seconds") != 795):
        raise ValueError("c2_budget_changed")
    # Reuse all existing exact-source, Hook, binary, namespace, and process
    # preflight fields without requiring C1's question/reviewer execution.
    common = plan
    for name in ("codex", "codex_home", "cwd", "runtime_root", "hook_source",
                 "trace_root", "capture_dir", "run_dir", "source_manifest_path",
                 "harness_root"):
        if type(common.get(name)) is not str or not Path(common[name]).is_absolute():
            raise ValueError("absolute_control_paths_required")
    for name in ("binary_sha256", "runtime_tree_sha256", "source_tree_sha256",
                 "cold_helper_sha256"):
        if not runner._hex(common.get(name)):
            raise ValueError("invalid_control_subject_digest")
    if type(common.get("values")) is not list or len(common["values"]) != 128:
        raise ValueError("finite_control_fixture_required")
    if (any(type(value) is not int or not -64 <= value <= 63
            for value in common["values"])
            or common["values"] != list(range(-64, 64))):
        raise ValueError("unfrozen_control_values")
    if (type(common.get("namespace")) is not str
            or not re.fullmatch(r"cg-candidate-[a-z0-9][a-z0-9-]{0,40}",
                                common["namespace"])):
        raise ValueError("invalid_control_namespace")
    if (type(common.get("overrides")) is not dict
            or type(common.get("effective_config")) is not dict
            or common["overrides"].get("model_auto_compact_token_limit") != 4096
            or common["effective_config"].get("model_auto_compact_token_limit") != 4096
            or common["overrides"].get("model_auto_compact_token_limit_scope")
            != "body_after_prefix"):
        raise ValueError("unfrozen_control_config")
    if (type(common.get("selected_hook_hashes")) is not dict
            or len(common["selected_hook_hashes"]) != 11
            or any(type(key) is not str or not key or type(value) is not str
                   or not value.startswith("sha256:") or not runner._hex(value[7:])
                   for key, value in common["selected_hook_hashes"].items())):
        raise ValueError("frozen_control_hooks_required")
    plan["question_client_id"] = plan["general_client_id"]
    _approval_suite_plan(plan)
    return plan


def preflight(plan: dict) -> dict:
    result = runner.preflight(plan)
    future = Path(plan["future_path"])
    if future.exists() or future.is_symlink() or future.parent != Path(plan["run_dir"]).parent:
        raise ValueError("future_observation_not_fresh_and_isolated")
    return {**result, "scenario": "C2", "whole_session_seconds": 795,
            "reviewer_calls": 0}


class C2Controller(Controller):
    """Transport-neutral three-turn machine; the collector owns all effects."""

    def __init__(self, plan: dict, observer: NativeObserver, oracle: ControlOracle):
        super().__init__(plan, observer)
        self.oracle = oracle
        self.turn_index = -1
        self.turn_ids: list[str] = []
        self.user_by_client: dict[str, dict] = {}
        self.messages: list[list[str]] = [[], [], []]
        self.ready_counts = [0, 0, 0]
        self.business_requests = 0
        self.challenge = None
        self.challenge_call_id = None
        self.business_call = None
        self.business_source = None
        self.root_sources = None
        self.stage_deadline = None
        self.call_ids: set[str] = set()
        self.deferred_control: list[dict] = []
        self.approval_plan = _approval_suite_plan(plan)
        self.business_request_id = None
        self.business_response = None
        self.business_reply_sent = False
        self.suite_item_started = None
        self.suite_item_completed = False
        self.suite_approval_sent = False

    def start(self):
        self.stage_deadline = time.monotonic() + 60
        return super().start()

    def _response(self, raw):
        original = self.pending.get(raw.get("id"))
        method = original.get("method") if original else None
        if method not in {"thread/start", "turn/start"}:
            return super()._response(raw)
        self.pending.pop(raw["id"])
        if "error" in raw or not isinstance(raw.get("result"), dict):
            raise ValueError("failed_control_rpc")
        result = raw["result"]
        if method == "thread/start" and self.phase == "starting_thread":
            self.selected_model = result.get("model")
            self.thread = result.get("thread", {}).get("id")
            if (not isinstance(self.selected_model, str) or not self.selected_model
                    or not isinstance(self.thread, str) or not self.thread):
                raise ValueError("control_thread_identity_missing")
            self._start_turn(0)
        elif method == "turn/start" and self.phase == "starting_turn":
            turn = result.get("turn", {}).get("id")
            if not isinstance(turn, str) or not turn or turn in self.turn_ids:
                raise ValueError("control_turn_identity_missing")
            self.turn = turn
            self.turn_ids.append(turn)
            self.phase = "active_turn"
            pending, self.deferred_control = self.deferred_control, []
            for notification in pending:
                self._notification(notification)
        else:
            raise ValueError("unexpected_control_response")

    def _start_turn(self, index: int):
        if index != self.turn_index + 1 or index >= 3:
            raise ValueError("control_turn_budget")
        self.turn_index = index
        self.turn = None
        self.stage_deadline = time.monotonic() + 240
        self.request("turn/start", {
            "threadId": self.thread,
            "clientUserMessageId": self.plan[CLIENT_IDS[index]],
            "input": [{"type": "text", "text": self.plan[FOLLOWUPS[index]]}],
        })
        self.phase = "starting_turn"

    def _server_request(self, raw):
        if self.phase != "active_turn" or self.turn is None:
            raise ValueError("control_tool_out_of_turn")
        if raw.get("method") == "item/commandExecution/requestApproval":
            if (self.turn_index != 2 or self.approval_plan is None
                    or self.challenge is None or self.business_source is None
                    or self.oracle.stage != "passed" or not self.business_reply_sent
                    or self.suite_item_started is None or self.suite_item_completed
                    or self.suite_approval_sent):
                raise ValueError("unreviewed_control_suite_approval")
            response = exact_suite_approval(
                raw, started=self.suite_item_started, plan=self.approval_plan,
                thread=self.thread, turn=self.turn)
            self.suite_approval_sent = True
            self.outbox.append(response)
            return
        call = wire.parse_call(raw, thread=self.thread, turn=self.turn)
        if call.call_id in self.call_ids:
            raise ValueError("reused_control_call_id")
        self.call_ids.add(call.call_id)
        if call.tool == wire.READY:
            self.ready_counts[self.turn_index] += 1
            if self.ready_counts[self.turn_index] != 1:
                raise ValueError("duplicate_ready")
            self.outbox.append(wire.response(call, {"ready": True}))
            return
        if call.tool == wire.CHALLENGE:
            if self.turn_index != 2 or self.challenge is not None:
                raise ValueError("premature_or_repeated_challenge")
            self._bind_confirmation()
            nonce = secrets.token_hex(32)
            basis = hashlib.sha256((self.thread + ":" + self.turn + ":"
                                    + self.plan["exact_prompt"]).encode()).hexdigest()
            self.challenge = {"schema": "cg-business-challenge/v1", "nonce": nonce,
                              "commentary_pair_sha256": basis}
            self.challenge_call_id = call.call_id
            self.outbox.append(wire.response(call, self.challenge))
            return
        self.business_requests += 1
        if (self.turn_index != 2 or self.challenge is None
                or self.business_call is not None
                or call.arguments["nonce"] != self.challenge["nonce"]):
            raise ValueError("premature_duplicate_or_unbound_business")
        self.business_call = call
        self.phase = "business_source_pending"

    def _notification(self, raw):
        method = raw.get("method")
        if method not in {"item/started", "item/completed", "hook/completed",
                          "turn/completed"}:
            return
        if self.thread is None or self.turn is None:
            if len(self.deferred_control) >= 128:
                raise ValueError("control_pre_ack_notification_limit")
            self.deferred_control.append(raw)
            return
        params = raw.get("params", {})
        event_turn = (params.get("turn", {}).get("id")
                      if method == "turn/completed" and isinstance(params, dict)
                      and isinstance(params.get("turn"), dict)
                      else params.get("turnId") if isinstance(params, dict) else None)
        if (not isinstance(params, dict) or params.get("threadId") != self.thread
                or (event_turn != self.turn
                    and not (method == "hook/completed"
                             and event_turn is None))):
            raise ValueError("foreign_control_notification")
        if method == "hook/completed":
            return
        if method == "item/started":
            item = params.get("item", {})
            if isinstance(item, dict) and item.get("type") == "commandExecution":
                if self.approval_plan is None:
                    return
                if (self.turn_index != 2 or self.phase != "active_turn"
                        or not self.business_reply_sent
                        or self.suite_item_started is not None
                        or item.get("status") != "inProgress"):
                    raise ValueError("unreviewed_control_command_start")
                suite_oracle.suite_item_identity(item, self.approval_plan)
                self.suite_item_started = copy.deepcopy(item)
            return
        if method == "item/completed":
            item = params.get("item", {})
            if item.get("type") == "userMessage":
                client = item.get("clientId")
                if client in self.user_by_client:
                    raise ValueError("duplicate_control_user_message")
                self.user_by_client[client] = item
            elif item.get("type") == "agentMessage":
                text = item.get("text")
                if not isinstance(text, str):
                    raise ValueError("malformed_control_answer")
                self.messages[self.turn_index].append(text)
            elif self.turn_index < 2 and item.get("type") in {
                "commandExecution", "fileChange", "webSearch", "mcpToolCall",
            }:
                raise ValueError("business_tool_before_confirmation")
            elif item.get("type") == "commandExecution" and self.approval_plan is not None:
                if (self.turn_index != 2 or self.suite_item_started is None
                        or self.suite_item_completed
                        or item.get("id") != self.suite_item_started["id"]
                        or item.get("status") != "completed"):
                    raise ValueError("unreviewed_control_command_completion")
                suite_oracle.suite_item_identity(item, self.approval_plan)
                self.suite_item_completed = True
            return
        completed = params.get("turn")
        if (not isinstance(completed, dict)
                or completed.get("status") != "completed"
                or completed.get("error") is not None
                or params.get("turnId") not in (None, self.turn)):
            raise ValueError("control_turn_not_successful")
        if self.phase not in {"active_turn", "business_source_pending"}:
            raise ValueError("control_turn_ended_out_of_phase")
        if self.phase == "business_source_pending":
            raise ValueError("business_source_missing_before_turn_end")
        self.phase = ("checkpoint_root", "checkpoint_general", "checkpoint_exact")[
            self.turn_index]

    def _require_user(self, index: int) -> dict:
        item = self.user_by_client.get(self.plan[CLIENT_IDS[index]])
        content = item.get("content") if isinstance(item, dict) else None
        if (not isinstance(item, dict) or type(item.get("id")) is not str
                or type(content) is not list or len(content) != 1
                or type(content[0]) is not dict
                or content[0].get("type") != "text"
                or content[0].get("text") != self.plan[FOLLOWUPS[index]]
                or set(content[0]) - {"type", "text", "text_elements"}
                or content[0].get("text_elements", []) != []):
            raise PendingEvidence("control_user_message_pending")
        return item

    def _product_state(self):
        _directory, state = self.observer._state(self.thread)
        if state.get("session", {}).get("id") != self.thread:
            raise ValueError("foreign_control_product_state")
        return state

    def _bind_confirmation(self):
        user = self._require_user(2)
        state = self._product_state()
        c2_future_preserved(state, self.plan["root_prompt"],
                            self.root_sources["future_id"],
                            Path(self.plan["future_path"]))
        self.oracle.c2_confirmation(
            now_ns=time.monotonic_ns(), message_id=user["id"],
            text=self.plan["exact_prompt"], future_wait=self.plan["future_path"],
            business_requests=self.business_requests, wait_id=self.root_sources["wait_id"],
            wait_status=c2_wait_status(state, self.root_sources["wait_id"]),
        )

    def advance(self):
        if self.phase == "business_source_pending":
            try:
                self.business_source = self.observer.business_source(
                    self.thread, self.turn, self.business_call.call_id,
                    self.challenge_call_id, self.challenge,
                )
            except PendingEvidence:
                return []
            value, _report = fixture.business_result(self.plan["values"], self.challenge)
            fixture.exclusive(Path(self.plan["run_dir"]) / "business-result.json", value)
            self.business_response = wire.response(self.business_call, value)
            self.outbox.append(self.business_response)
            self.business_request_id = self.business_call.request_id
            self.oracle.c2_business(
                now_ns=time.monotonic_ns(), call_id=self.business_call.call_id,
                nonce=self.business_call.arguments["nonce"],
                expected_nonce=self.challenge["nonce"], succeeded=True,
                future_wait=self.plan["future_path"],
                business_requests=self.business_requests,
            )
            self.phase = "active_turn"
        elif self.phase == "checkpoint_root":
            state = self._product_state()
            source = c2_root_sources(state, self.plan["root_prompt"],
                                     Path(self.plan["future_path"]))
            self.root_sources = source
            user = self._require_user(0)
            if self.messages[0] != [ROOT_REPLY]:
                raise ValueError("root_status_answer_unfit")
            self.oracle.c2_root(
                now_ns=time.monotonic_ns(), message_id=user["id"],
                main_id=source["main_id"], future_id=source["future_id"],
                main_wait="CG142-CONFIRM-17", future_wait=self.plan["future_path"],
                business_requests=self.business_requests,
                prompt=self.plan["root_prompt"], main_span=source["main_span"],
                future_span=source["future_span"], wait_id=source["wait_id"],
                wait_status=c2_wait_status(state, source["wait_id"]),
            )
            self._start_turn(1)
        elif self.phase == "checkpoint_general":
            state = self._product_state()
            c2_future_preserved(state, self.plan["root_prompt"],
                                self.root_sources["future_id"],
                                Path(self.plan["future_path"]))
            user = self._require_user(1)
            if self.messages[1] != [GENERAL_REPLY]:
                raise ValueError("general_status_answer_unfit")
            self.oracle.c2_general_resume(
                now_ns=time.monotonic_ns(), message_id=user["id"],
                text=self.plan["general_prompt"], business_requests=self.business_requests,
                main_wait="CG142-CONFIRM-17", future_wait=self.plan["future_path"],
                wait_id=self.root_sources["wait_id"],
                wait_status=c2_wait_status(state, self.root_sources["wait_id"]),
            )
            self._start_turn(2)
        elif self.phase == "checkpoint_exact":
            self._require_user(2)
            c2_future_preserved(self._product_state(), self.plan["root_prompt"],
                                self.root_sources["future_id"],
                                Path(self.plan["future_path"]))
            if (self.messages[2] != [EXACT_REPLY] or self.oracle.stage != "passed"
                    or (self.approval_plan is not None
                        and not self.suite_item_completed)):
                raise ValueError("exact_status_or_business_unfit")
            self.phase = "complete"
        return self.drain()

    def sent(self, row: dict) -> None:
        """Release suite approval only after the business response was written."""
        if self.business_request_id is None or row.get("id") != self.business_request_id:
            return
        if (self.phase != "active_turn" or self.business_reply_sent
                or self.business_source is None or row != self.business_response):
            raise ValueError("control_business_reply_send_out_of_order")
        self.business_reply_sent = True


def collect(plan: dict, *, execute: bool) -> dict:
    preflight(plan)
    if not execute or plan.get("execute_producer") is not True:
        raise ValueError("explicit_control_producer_gate_required")
    directory = Path(plan["run_dir"])
    directory.mkdir(mode=0o700)
    (directory / "plan.json").write_text(
        json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    budget = runner.legacy.Budget(**plan["budget"])
    started_ns = time.monotonic_ns()
    deadline = time.monotonic() + 795
    previous_home = os.environ.get("CODEX_HOME")
    previous_trace = os.environ.get("CODEX_ROLLOUT_TRACE_ROOT")
    os.environ["CODEX_HOME"] = plan["codex_home"]
    os.environ["CODEX_ROLLOUT_TRACE_ROOT"] = plan["trace_root"]
    transport = None
    controller = None
    result = {"status": "failed", "reason": "unstarted", "native_acceptance": "not_established"}
    try:
        observer = NativeObserver(plan)
        oracle = ControlOracle("C2", started_ns=started_ns,
                               future_path=Path(plan["future_path"]))
        controller = C2Controller(plan, observer, oracle)
        transport = runner.AppServer(plan, directory / "stderr.log")
        with (directory / "rpc.jsonl").open("xb") as journal:
            journal_size = 0

            def record(direction, raw):
                nonlocal journal_size
                line = json.dumps({"direction": direction, "raw": raw,
                                   "monotonic_ns": time.monotonic_ns()},
                                  ensure_ascii=True).encode() + b"\n"
                journal_size += len(line)
                if len(line) > runner.MAX_RPC_LINE or journal_size > runner.MAX_JOURNAL:
                    raise ValueError("control_journal_budget")
                journal.write(line)
                journal.flush()

            def send_all(rows):
                _send_with_receipt(rows, transport, record, controller)

            send_all(controller.start())
            while time.monotonic() < deadline - budget.cleanup:
                if (controller.stage_deadline is not None
                        and time.monotonic() > controller.stage_deadline):
                    raise TimeoutError("control_turn_deadline")
                send_all(controller.advance())
                if (time.monotonic() >= deadline - budget.cleanup
                        or (controller.stage_deadline is not None
                            and time.monotonic() > controller.stage_deadline)):
                    raise TimeoutError("control_deadline_after_observation")
                if controller.phase == "complete":
                    result = {"status": "source_controls_observed", "scenario": "C2",
                              "native_acceptance": "not_established",
                              "turn_ids": controller.turn_ids,
                              "business_requests": controller.business_requests,
                              "reviewer_calls": 0,
                              "source_bound_business": controller.business_source is not None}
                    break
                raw = transport.receive(0.25)
                if raw is None:
                    raise ValueError("control_host_eof")
                if raw.get("transport_poll") is True:
                    continue
                if "transport_error" in raw:
                    raise ValueError("control_host_read_error")
                record("receive", raw)
                send_all(controller.ingest(raw))
            else:
                raise TimeoutError("control_whole_session_deadline")
    except (OSError, ValueError, TypeError, TimeoutError, KeyError) as exc:
        result = {"status": "failed", "reason": type(exc).__name__ + ":" + str(exc),
                  "phase": controller.phase if controller else "observer_startup",
                  "native_acceptance": "not_established"}
    finally:
        try:
            if transport is not None:
                try:
                    result["cleanup"] = transport.close(budget.cleanup)
                except (OSError, ValueError, TypeError, TimeoutError) as exc:
                    result["cleanup"] = {"error": type(exc).__name__}
                cleanup = result["cleanup"]
                if (cleanup.get("owned_process_exited") is not True
                        or cleanup.get("owned_tree_no_running_members") is not True
                        or cleanup.get("process_group_cleanup_error") is not None):
                    result = {**result, "status": "failed",
                              "reason": "owned_process_tree_cleanup_unverified"}
            (directory / "result.json").write_text(
                json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        finally:
            for name, prior in (("CODEX_HOME", previous_home),
                                ("CODEX_ROLLOUT_TRACE_ROOT", previous_trace)):
                if prior is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = prior
    return result


def _send_with_receipt(rows, transport, record, controller):
    """A failed transport write must never authorize a later suite request."""
    for row in rows:
        record("send", row)
        transport.send(row, timeout=10)
        record("send_complete", row)
        controller.sent(row)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if args.preflight == args.execute:
        parser.error("choose exactly one of --preflight or --execute")
    plan = load_plan(args.plan)
    result = preflight(plan) if args.preflight else collect(plan, execute=True)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
