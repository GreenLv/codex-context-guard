"""Transport-neutral official app-server controller for the 0.14.2 probe.

It emits requests but never launches a host. A native owner must provide an
Observer that reads the real trace, capture, review and cold product state. The
controller refuses to replace any of those sources with notification order.
"""

from __future__ import annotations

import re
from pathlib import Path

from tools.validation import commentary_live_adapter as wire
from tools.validation.commentary_controls import valid_c1_partial_answer
from tools.validation.commentary_live_observer import PendingEvidence

PRODUCT_EVENTS = {
    "preToolUse", "postToolUse", "preCompact", "sessionStart", "sessionEnd",
    "userPromptSubmit", "subagentStart", "subagentStop", "stop",
}


class Controller:
    def __init__(self, plan, observer):
        self.plan = plan
        self.observer = observer
        self.phase = "new"
        self.pending = {}
        self.serial = 0
        self.outbox = []
        self.thread = None
        self.turn = None
        self.selected_model = None
        self.config_request = None
        self.config_response = None
        self.thread_start = None
        self.barrier = None
        self.user_items = []
        self.answer_items = []
        self.hook_runs = []
        self.compaction_items = []
        self.compaction_item = None
        self.deferred = []
        self.question_client_id = plan["question_client_id"]
        self.business_request_id = None
        self.business_call_id = None
        self.business_reply_sent = False
        self.business_terminal_item = None
        self.business_post_hook = None

    def request(self, method, params):
        self.serial += 1
        value = {"id": self.serial, "method": method, "params": params}
        self.pending[self.serial] = value
        self.outbox.append(value)
        return value

    def drain(self):
        result, self.outbox = self.outbox, []
        return result

    def start(self):
        if self.phase != "new":
            raise ValueError("already_started")
        self.phase = "initializing"
        self.request("initialize", {
            "clientInfo": {"name": "cg-commentary-native", "version": "1"},
            "capabilities": {"experimentalApi": True},
        })
        return self.drain()

    def ingest(self, raw):
        if self.phase in {"failed", "complete"}:
            raise ValueError("controller_terminal")
        if not isinstance(raw, dict):
            raise ValueError("malformed_rpc")
        if "id" in raw and "method" not in raw:
            self._response(raw)
        elif "id" in raw:
            self._server_request(raw)
        else:
            self._notification(raw)
        return self.drain()

    def _response(self, raw):
        original = self.pending.pop(raw["id"], None)
        if original is None or "error" in raw or not isinstance(raw.get("result"), dict):
            raise ValueError("unpaired_or_failed_rpc")
        method = original["method"]
        result = raw["result"]
        if method == "initialize" and self.phase == "initializing":
            self.outbox.append({"method": "initialized", "params": {}})
            self.config_request = self.request("config/read", {
                "cwd": self.plan["cwd"], "includeLayers": True,
            })
            self.phase = "configuring"
        elif method == "config/read" and self.phase == "configuring":
            self.config_response = raw
            if "origins" not in result or not isinstance(result.get("config"), dict):
                raise ValueError("effective_config_unavailable")
            self.request("hooks/list", {"cwds": [self.plan["cwd"]]})
            self.phase = "checking_hooks"
        elif method == "hooks/list" and self.phase == "checking_hooks":
            entries = result.get("data")
            if (not isinstance(entries, list) or len(entries) != 1
                    or entries[0].get("cwd") != self.plan["cwd"]
                    or entries[0].get("errors") or entries[0].get("warnings")):
                raise ValueError("official_hook_readback_failed")
            rows = entries[0].get("hooks")
            if not isinstance(rows, list):
                raise ValueError("official_hook_rows_missing")
            product = [h for h in rows if isinstance(h, dict) and
                       h.get("source") == "plugin" and
                       h.get("sourcePath") == self.plan["hook_source"]]
            captures = [h for h in rows if isinstance(h, dict) and
                        h.get("source") == "sessionFlags" and
                        h.get("sourcePath") == self.plan["capture_hook_source"] and
                        "--digest-echo" in h.get("command", "")]
            selected = product + captures
            expected = self.plan["selected_hook_hashes"]
            if (len(product) != 9 or {h.get("eventName") for h in product} != PRODUCT_EVENTS
                    or len(captures) != 2
                    or {h.get("eventName") for h in captures} != {"preCompact", "sessionStart"}
                    or {h.get("key"): h.get("currentHash") for h in selected} != expected
                    or any(h.get("trustStatus") != "trusted" or h.get("enabled") is not True
                           or not h.get("currentHash") for h in selected)):
                raise ValueError("exact_trusted_hooks_required")
            self.thread_start = self.request("thread/start", {
                "cwd": self.plan["cwd"],
                "sandbox": "workspace-write",
                "approvalPolicy": "on-request",
                "developerInstructions": self.plan["developer_instructions"],
                "historyMode": "paginated",
                "dynamicTools": wire.specs(),
            })
            self.phase = "starting_thread"
        elif method == "thread/start" and self.phase == "starting_thread":
            self.selected_model = result.get("model")
            if not isinstance(self.selected_model, str) or not self.selected_model:
                raise ValueError("selected_model_not_confirmed")
            self.thread = result.get("thread", {}).get("id")
            if not isinstance(self.thread, str) or not self.thread:
                raise ValueError("thread_identity_missing")
            self.observer.configure_review_policy(self.thread)
            self.request("turn/start", {
                "threadId": self.thread,
                "clientUserMessageId": self.plan["root_client_id"],
                "input": [{"type": "text", "text": self.plan["root_prompt"]}],
            })
            self.phase = "starting_turn"
        elif method == "turn/start" and self.phase == "starting_turn":
            self.turn = result.get("turn", {}).get("id")
            if not isinstance(self.turn, str) or not self.turn:
                raise ValueError("turn_identity_missing")
            chain = self.observer.make_chain(self.thread, self.turn)
            chain.configuration(self.config_request, self.config_response, self.thread_start)
            self.barrier = wire.LiveBarrier(
                chain, thread=self.thread, turn=self.turn,
                directory=Path(self.plan["run_dir"]), values=self.plan["values"],
            )
            self.phase = "waiting_ready"
            deferred, self.deferred = self.deferred, []
            for event in deferred:
                self._notification(event)
        elif method == "turn/steer" and self.phase == "steering":
            if result.get("turnId") != self.turn:
                raise ValueError("wrong_steer_turn")
            self.outbox.append(self.barrier.release_ready(original, raw))
            self.phase = "waiting_challenge"
        else:
            raise ValueError("unexpected_rpc_response")

    def _server_request(self, raw):
        if raw.get("method") != "item/tool/call" or self.barrier is None:
            raise ValueError("unreviewed_server_request")
        call = self.barrier.receive(raw)
        if self.phase == "waiting_ready" and call.tool == wire.READY:
            self.request("turn/steer", {
                "threadId": self.thread, "expectedTurnId": self.turn,
                "clientUserMessageId": self.question_client_id,
                "input": [{"type": "text", "text": self.plan["question"]}],
            })
            self.phase = "steering"
        elif self.phase == "waiting_challenge" and call.tool == wire.CHALLENGE:
            self.phase = "awaiting_answer_evidence"
            self.try_answer()
        elif self.phase == "waiting_business" and call.tool == wire.BUSINESS:
            self.phase = "awaiting_business_evidence"
            self.try_business()
            # The external owner invokes a distinct, bounded reviewer once.
            # No business result is sent until reviewed() consumes the real
            # product projection; a caller's success flag cannot release it.
        else:
            raise ValueError("tool_call_out_of_phase")

    def try_answer(self):
        if self.phase != "awaiting_answer_evidence":
            return False
        try:
            source = self.observer.answer_source(
                self.thread, self.turn, self.question_client_id,
                self.plan["question"], self.user_items, self.answer_items,
            )
        except PendingEvidence:
            return False
        if (self.plan.get("review_coverage") == "partial"
                and not valid_c1_partial_answer(
                    source["notification"]["params"]["item"].get("text"))):
            raise ValueError("partial_answer_content_unfit")
        self.outbox.append(self.barrier.release_challenge(**source))
        self.phase = "waiting_business"
        return True

    def try_business(self):
        if self.phase != "awaiting_business_evidence":
            return False
        try:
            source = self.observer.business_source(
                self.thread, self.turn, self.barrier.pending.call_id,
                self.barrier.challenge_call_id, self.barrier.chain.business_challenge,
            )
        except PendingEvidence:
            return False
        self.barrier.observe_business(**source)
        self.phase = "awaiting_review"
        return True

    def reviewed(self):
        if self.phase != "awaiting_review":
            raise ValueError("review_not_pending")
        runtime, state, session_dir, question_id, main_ids = self.observer.review_projection(
            self.thread, self.turn,
        )
        pending = self.barrier.pending
        if pending is None:
            raise ValueError("review_business_call_missing")
        self.business_request_id = pending.request_id
        self.business_call_id = pending.call_id
        self.outbox.append(self.barrier.release_after_review(
            runtime, state, session_dir=session_dir,
            codex_home=self.plan["codex_home"],
            question_id=question_id, main_ids=main_ids,
        ))
        self.phase = "awaiting_auto_compaction"
        return self.drain()

    def sent(self, row):
        """Bind the business response to a completed transport write."""
        if self.business_request_id is None or row.get("id") != self.business_request_id:
            return
        if (self.phase != "awaiting_auto_compaction"
                or self.business_reply_sent or "result" not in row):
            raise ValueError("business_reply_send_out_of_order")
        self.business_reply_sent = True

    def _notification(self, raw):
        method, params = raw.get("method"), raw.get("params", {})
        if method not in {"item/completed", "hook/completed", "turn/completed"}:
            return
        if self.thread is None or self.turn is None:
            if len(self.deferred) >= 128:
                raise ValueError("pre_ack_notification_limit")
            self.deferred.append(raw)
            return
        if (not isinstance(params, dict) or params.get("threadId") != self.thread
                or (method == "hook/completed"
                    and params.get("turnId") not in (None, self.turn))
                or (method != "hook/completed" and params.get("turnId") != self.turn)):
            raise ValueError("foreign_notification")
        if method == "turn/completed":
            raise ValueError("turn_ended_before_auto_compaction")
        if method == "hook/completed":
            if self.plan.get("review_coverage") == "partial":
                run = params.get("run", {})
                if (isinstance(run, dict) and run.get("eventName") == "preCompact"
                        and run.get("sourcePath") in {
                            self.plan["hook_source"], self.plan["capture_hook_source"]
                        } and self.business_post_hook is None):
                    raise ValueError("precompact_before_postbusiness_baseline")
                if isinstance(run, dict) and run.get("sourcePath") == self.plan["hook_source"]:
                    if run.get("eventName") == "postToolUse" and self.business_reply_sent:
                        identity = run.get("id")
                        exact_id = (
                            isinstance(identity, str)
                            and re.fullmatch(
                                r"post-tool-use:\d+:"
                                + re.escape(self.plan["hook_source"])
                                + ":" + re.escape(self.business_call_id or ""),
                                identity,
                            ) is not None
                        )
                        if (self.business_terminal_item is None
                                or self.business_post_hook is not None
                                or not exact_id
                                or run.get("status") != "completed"
                                or run.get("statusMessage") is not None
                                or run.get("source") != "plugin"
                                or run.get("handlerType") != "command"
                                or run.get("executionMode") != "sync"
                                or run.get("scope") != "turn"):
                            raise ValueError("unbound_postbusiness_hook")
                        checkpoint = self.observer.postbusiness_projection(
                            self.thread, self.barrier.chain.question_id,
                            self.barrier.chain.main_ids,
                        )
                        self.barrier.chain.postbusiness(
                            checkpoint, item_id=self.business_terminal_item,
                            hook_id=run["id"],
                        )
                        self.business_post_hook = run["id"]
            self.hook_runs.append(raw)
            if self.phase == "awaiting_compaction_evidence":
                self.try_compaction()
            return
        item = params.get("item", {})
        if (self.plan.get("review_coverage") == "partial"
                and self.business_reply_sent and self.business_post_hook is None
                and item.get("type") in {"commandExecution", "fileChange",
                                         "mcpToolCall", "webSearch"}):
            raise ValueError("intervening_tool_before_postbusiness_baseline")
        if (self.plan.get("review_coverage") == "partial"
                and item.get("type") == "dynamicToolCall"
                and self.business_reply_sent):
            if (self.business_terminal_item is not None
                    or item.get("id") != self.business_call_id
                    or item.get("namespace") != wire.TOOL_NAMESPACE
                    or item.get("tool") != wire.BUSINESS
                    or item.get("status") != "completed"
                    or item.get("success") is not True):
                raise ValueError("unbound_business_terminal_item")
            self.business_terminal_item = item["id"]
        if item.get("type") == "userMessage":
            self.user_items.append(raw)
        elif item.get("type") == "agentMessage" and item.get("phase") == "commentary":
            self.answer_items.append(raw)
        elif item.get("type") == "contextCompaction":
            if self.phase != "awaiting_auto_compaction" or self.compaction_item is not None:
                raise ValueError("early_or_duplicate_compaction")
            self.compaction_items.append(raw)
            self.compaction_item = raw
            self.phase = "awaiting_compaction_evidence"
            self.try_compaction()

    def try_compaction(self):
        if self.phase != "awaiting_compaction_evidence" or self.compaction_item is None:
            return False
        try:
            captures, source = self.observer.compaction_source(
                self.thread, self.turn, self.hook_runs, self.compaction_item,
            )
        except PendingEvidence:
            return False
        self.barrier.chain.compaction(
            captures, completed_item=self.compaction_item, **source,
        )
        self.phase = "awaiting_cold_recovery"
        return True

    def cold_recovery(self):
        if self.phase != "awaiting_cold_recovery":
            raise ValueError("compaction_not_complete")
        result = self.barrier.chain.cold_recovery(self.observer.cold_reader)
        self.phase = "complete"
        return result
