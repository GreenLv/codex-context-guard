#!/usr/bin/env python3
"""Offline causal fragments for the official 0.153.4 commentary contract.

Native collection is blocked by audited source-contract gaps. Prepare checks
local inputs; validate replays a retained v6 synthetic journal. Neither local
lifecycle pairs nor RPC acknowledgments establish whole-chain acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import queue
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCHEMA = "cg-commentary-runner/v6"
MAX_LINE = 2 * 1024 * 1024
MAX_RECORDS = 20000
PRODUCT_EVENTS = {
    "userPromptSubmit",
    "preToolUse",
    "postToolUse",
    "preCompact",
    "sessionStart",
    "sessionEnd",
    "stop",
    "subagentStart",
    "subagentStop",
}


def fingerprint(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def decode_object(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("duplicate_json_key")
            result[k] = v
        return result

    def nonfinite(_):
        raise ValueError("nonfinite_json")

    if len(raw) > MAX_LINE:
        raise ValueError("input_size_limit")
    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite
    )
    if not isinstance(value, dict):
        raise ValueError("object_required")
    return value


def read_json(path: Path) -> dict:
    if path.is_symlink() or path.stat().st_size > MAX_LINE:
        raise ValueError("unsafe_input")
    return decode_object(path.read_bytes())


def write_new(path: Path, value: dict) -> None:
    # No parent creation here: prepare/collect own their distinct directories.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write("\n")


@dataclass(frozen=True)
class Budget:
    startup: int = 180
    turn: int = 900
    compact: int = 300
    cleanup: int = 180

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in asdict(self).values()):
            raise ValueError("invalid_budget")

    @property
    def total(self):
        # One active turn, including any steer and all consecutive approvals.
        return self.startup + self.turn + self.compact + self.cleanup


def checked_plan(plan: dict) -> Budget:
    if plan.get("schema") != SCHEMA:
        raise ValueError("unsupported_plan")
    budget = Budget(**plan["budget"])
    for field in ("runtime_tree_sha256", "source_tree_sha256"):
        value = plan.get(field)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
        ):
            raise ValueError("invalid_subject")
    for field in ("codex", "codex_home", "cwd", "runtime_root", "hook_source"):
        if not isinstance(plan.get(field), str) or not Path(plan[field]).is_absolute():
            raise ValueError("absolute_path_required")
    for field in (
        "root_prompt",
        "question",
        "ready_command",
        "continuation_command",
    ):
        if not isinstance(plan.get(field), str) or not plan[field].strip():
            raise ValueError("scenario_field_required")
    if plan.get("model") is not None and (
        not isinstance(plan["model"], str) or not plan["model"].strip()
    ):
        raise ValueError("invalid_optional_model")
    return budget


def runtime_identity(root: Path) -> str:
    # Import by sibling path so the standalone CLI and package tests agree.
    import importlib.util

    path = Path(__file__).with_name("host_capture.py")
    spec = importlib.util.spec_from_file_location("commentary_host_capture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.measure_runtime(root)[0]


def prepare(plan: dict, output: Path) -> dict:
    checked_plan(plan)
    if output.exists() or output.is_symlink():
        raise ValueError("output_exists")
    for field in ("codex_home", "cwd", "runtime_root"):
        if not Path(plan[field]).is_dir():
            raise ValueError("directory_unavailable")
    if not Path(plan["codex"]).is_file() or not Path(plan["hook_source"]).is_file():
        raise ValueError("binary_or_hook_source_unavailable")
    if output.resolve().is_relative_to(
        Path(plan["runtime_root"]).resolve()
    ) or output.resolve().is_relative_to(Path(plan["cwd"]).resolve()):
        raise ValueError("output_must_be_outside_source_and_fixture")
    actual = runtime_identity(Path(plan["runtime_root"]))
    if actual != plan["runtime_tree_sha256"]:
        raise ValueError("runtime_mismatch")
    result = {
        "schema": SCHEMA,
        "stage": "prepare",
        "status": "inputs_checked_only",
        "plan": plan,
        "plan_sha256": fingerprint(plan),
        "binary_sha256": hashlib.sha256(Path(plan["codex"]).read_bytes()).hexdigest(),
        "hook_source_sha256": hashlib.sha256(
            Path(plan["hook_source"]).read_bytes()
        ).hexdigest(),
        "model_requests": 0,
        "native_ready": False,
        "source_contract_gaps": list(SOURCE_GAPS),
        "unknown": [
            "official_trust",
            "authentication",
            "effective_child_route",
            "active_turn_compaction",
            "answer_coverage",
        ],
    }
    write_new(output, result)
    return result


# These are missing evidence contracts, not optional acceptance criteria.
SOURCE_GAPS = (
    "question_to_model_response_source_boundary",
    "commentary_to_business_continuation_source_boundary",
    "manual_compact_replaces_active_turn",
    "compaction_to_true_session_start_trigger",
    "independent_semantic_review",
    "source_bound_cold_recovery",
)


def clock_sample(clock, wall, resolution_ns, mono_resolution_ns=1):
    """Direct samples only. Declared resolution is metadata, never accuracy."""
    before, wall_ns, after = clock(), wall(), clock()
    if (
        type(before) is not int
        or type(after) is not int
        or before > after
        or type(wall_ns) is not int
        or wall_ns < 0
        or type(resolution_ns) is not int
        or resolution_ns < 1
        or type(mono_resolution_ns) is not int
        or mono_resolution_ns < 1
    ):
        raise ValueError("invalid_clock_sample")
    return {
        "mono_before_ns": before,
        "mono_after_ns": after,
        "wall_ns": wall_ns,
        "wall_resolution_ns": resolution_ns,
        "mono_resolution_ns": mono_resolution_ns,
    }


class Machine:
    """Deterministic partial causal automaton. It never interprets answer prose."""

    def __init__(self, plan: dict, initial_clock: dict):
        self.plan = plan
        self.budget = checked_plan(plan)
        self.initial_clock = initial_clock
        self.current_clock = None
        self.clock_diagnostics = []
        self.causal_edges = {}
        self.written_requests = {}
        self.stage = "startup"
        self.deadline = self.budget.startup * 1_000_000_000
        self.now = 0
        self.thread = None
        self.turn = None
        self.selected_model = None
        self.pending: dict[int, str] = {}
        self.serial = 0
        self.status = "collecting"
        self.reason = None
        self.outbox: list[dict] = []
        self.messages: dict[str, str] = {}
        self.message_ids: list[str] = []
        self.steered = False
        self.steer_sent = False
        self.final_seen = False
        self.approval_ids: set[str] = set()
        self.hooks: dict[str, dict] = {}
        self.items: dict[str, dict] = {}
        self.watermarks: dict[str, dict] = {}
        self.unproven: set[str] = set(SOURCE_GAPS)
        self.steer_ack_elapsed = None
        self.deferred: list[dict] = []
        self.observe_clock(initial_clock)
        self.request(
            "initialize",
            {"clientInfo": {"name": "cg-commentary-probe", "version": "6"}},
        )

    def end(self, status: str, reason: str):
        self.status, self.reason = status, reason
        self.outbox.clear()

    def request(self, method: str, params: dict):
        if self.status != "collecting":
            return
        self.serial += 1
        self.pending[self.serial] = method
        self.outbox.append({"id": self.serial, "method": method, "params": params})

    def sent(self, request: dict, elapsed: int):
        """Record the real write-attempt boundary, not outbox creation time."""
        self.tick(elapsed)
        if self.status != "collecting":
            return
        if "id" in request:
            self.written_requests[request["id"]] = fingerprint(request)
        self.watermarks[request.get("method", "notification")] = {
            "write_completed_mono_ns": elapsed
        }
        # Never extend a deadline when writing or acknowledging a request.

    def drain(self):
        result, self.outbox = self.outbox, []
        return result

    def tick(self, elapsed: int):
        if self.status != "collecting":
            return
        if type(elapsed) is not int or elapsed < self.now:
            self.end("failed", "nonmonotonic_capture")
        self.now = elapsed
        if self.status == "collecting" and elapsed >= self.deadline:
            if self.unproven:
                self.end("capability_missing", "causal_chain_not_proven")
            else:
                self.end("timeout", self.stage + "_deadline")

    def cancel(self):
        # No start/steer/compact is issued after cancellation. Transport close
        # ends the owned process; that exit never counts as SessionEnd.
        self.end("cancelled", "operator_cancelled")

    def ingest(self, raw: dict, elapsed: int):
        try:
            self._ingest(raw, elapsed)
        except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
            self.end("failed", "malformed_rpc_fields")

    def _ingest(self, raw: dict, elapsed: int):
        self.tick(elapsed)
        if self.status != "collecting":
            return
        if not isinstance(raw, dict):
            self.end("failed", "malformed_rpc")
            return
        if "id" in raw and "method" not in raw:
            method = self.pending.pop(raw["id"], None)
            if method is None or raw["id"] not in self.written_requests:
                self.end("failed", "unpaired_response")
                return
            if "error" in raw:
                self.end("capability_missing", "rpc_rejected:" + method)
                return
            result = raw.get("result")
            if not isinstance(result, dict):
                self.end("failed", "invalid_rpc_result")
                return
            edge = {
                "kind": "rpc_request_response",
                "method": method,
                "from": "rpc:" + str(raw["id"]) + ":write",
                "to": "rpc:" + str(raw["id"]) + ":ack",
                "request_sha256": self.written_requests[raw["id"]],
                "response_sha256": fingerprint(raw),
                "meaning": "input_enqueued_for_turn"
                if method == "turn/steer"
                else "rpc_acknowledgment_only",
            }
            if method == "initialize":
                self.outbox.append({"method": "initialized", "params": {}})
                self.request("hooks/list", {"cwds": [self.plan["cwd"]]})
            elif method == "hooks/list":
                entries = result.get("data", [])
                if (
                    not isinstance(entries, list)
                    or len(entries) != 1
                    or entries[0].get("cwd") != self.plan["cwd"]
                    or entries[0].get("errors")
                    or entries[0].get("warnings")
                ):
                    self.end("capability_missing", "official_hook_readback_unavailable")
                    return
                hooks = entries[0].get("hooks", [])
                selected = [
                    h
                    for h in hooks
                    if isinstance(h, dict)
                    and h.get("source") == "plugin"
                    and h.get("sourcePath") == self.plan["hook_source"]
                ]
                if (
                    len(selected) != 9
                    or {h.get("eventName") for h in selected} != PRODUCT_EVENTS
                    or any(
                        h.get("enabled") is not True
                        or h.get("trustStatus") not in {"trusted", "managed"}
                        or not isinstance(h.get("currentHash"), str)
                        or not h["currentHash"]
                        for h in selected
                    )
                ):
                    self.end("capability_missing", "normal_product_hook_trust_required")
                    return
                self.request(
                    "thread/start",
                    {
                        "cwd": self.plan["cwd"],
                        **(
                            {"model": self.plan["model"]}
                            if self.plan.get("model")
                            else {}
                        ),
                        "sandbox": "workspace-write",
                        "approvalPolicy": "on-request",
                    },
                )
            elif method == "thread/start":
                self.selected_model = result.get("model")
                if (
                    not isinstance(self.selected_model, str)
                    or not self.selected_model
                    or (
                        self.plan.get("model") is not None
                        and self.selected_model != self.plan["model"]
                    )
                ):
                    self.end("capability_missing", "selected_model_not_confirmed")
                    return
                self.thread = result.get("thread", {}).get("id")
                if not isinstance(self.thread, str) or not self.thread:
                    self.end("failed", "missing_thread")
                    return
                self.stage = "turn"
                self.deadline = self.now + self.budget.turn * 1_000_000_000
                self.request(
                    "turn/start",
                    {
                        "threadId": self.thread,
                        "input": [{"type": "text", "text": self.plan["root_prompt"]}],
                    },
                )
            elif method == "turn/start":
                self.turn = result.get("turn", {}).get("id")
                if not isinstance(self.turn, str) or not self.turn:
                    self.end("failed", "missing_turn")
                else:
                    deferred, self.deferred = self.deferred, []
                    for event in deferred:
                        self.ingest(event, self.now)
            elif method == "turn/steer":
                if result.get("turnId") != self.turn:
                    self.end("failed", "steer_turn_conflict")
                else:
                    self.steered = True
                    # Queued input is not proof of sampling or of a reply.
                    self.steer_ack_elapsed = self.now
            if self.status == "collecting":
                self.causal_edges["rpc:" + str(raw["id"])] = edge
            self.maybe_observed()
            return
        method, params = raw.get("method"), raw.get("params", {})
        if not isinstance(params, dict):
            self.end("failed", "invalid_rpc_params")
            return
        if "id" in raw:  # Official server request; never auto-grant approval.
            if (
                params.get("threadId") != self.thread
                or params.get("turnId") != self.turn
            ):
                self.end("failed", "foreign_server_request")
                return
            self.approval_ids.add(str(raw["id"]))
            return
        if method not in {
            "item/started",
            "item/completed",
            "turn/completed",
            "hook/completed",
            "thread/compacted",
        }:
            return
        if self.thread is None or params.get("threadId") != self.thread:
            self.end("failed", "wrong_session")
            return
        if self.turn is None and "turn/start" in self.pending.values():
            self.deferred.append(raw)
            return
        turn = params.get("turnId")
        if method == "turn/completed":
            turn = params.get("turn", {}).get("id")
        if turn != self.turn and not (method == "hook/completed" and turn is None):
            self.end("failed", "wrong_turn")
            return
        if method == "turn/completed":
            self.end("capability_missing", "turn_ended_before_active_compact_chain")
            return
        if method == "hook/completed":
            run = params.get("run", {})
            if not isinstance(run, dict):
                self.end("failed", "invalid_hook")
                return
            if run.get("sourcePath") != self.plan["hook_source"]:
                if run.get("id") in self.hooks:
                    self.end("failed", "conflicting_hook_identity")
                return
            hook_id = run.get("id")
            if not isinstance(hook_id, str) or not hook_id:
                self.end("failed", "missing_hook_identity")
                return
            previous = self.hooks.get(hook_id)
            if previous is not None:
                if previous["digest"] != fingerprint(params):
                    self.end("failed", "conflicting_hook_identity")
                return
            if run.get("status") != "completed":
                self.end("failed", "hook_not_completed")
                return
            interval = self.hook_wall_fields(
                run.get("startedAt"), run.get("completedAt")
            )
            self.hooks[hook_id] = {
                "run": run,
                "interval": interval,
                "digest": fingerprint(params),
                "received": self.now,
            }
        elif method == "thread/compacted":
            # The deprecated notification has no occurrence timestamp. Keep it
            # visible but never use its delivery order as a compaction clock.
            self.unproven.add("untimed_compaction_notification")
        else:
            item = params.get("item", {})
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("id"), str)
                or not item["id"]
            ):
                self.end("failed", "invalid_item_identity")
                return
            phase = "start" if method == "item/started" else "complete"
            field = "startedAtMs" if phase == "start" else "completedAtMs"
            occurred = params.get(field)
            timing = self.wall_diagnostic(occurred, occurred, 1_000_000)
            # Required invocation fields describe one command, unlike status,
            # output, exit code or duration, which evolve during execution.
            if item.get("type") == "commandExecution" and any(
                not isinstance(item.get(key), str) or not item[key]
                for key in ("command", "cwd")
            ):
                self.end("capability_missing", "command_identity_unavailable")
                return
            entry = self.items.setdefault(item["id"], {})
            if phase in entry:
                if entry[phase]["digest"] != fingerprint(params):
                    self.end("failed", "conflicting_item_lifecycle")
                return
            entry[phase] = {
                "item": item,
                "time": occurred,
                "wall_diagnostic": timing,
                "received": self.now,
                "digest": fingerprint(params),
            }
            if "start" in entry and "complete" in entry:
                if entry["start"]["item"].get("type") != entry["complete"]["item"].get(
                    "type"
                ):
                    self.end("failed", "item_type_changed")
                    return
                if item.get("type") == "commandExecution" and any(
                    entry["start"]["item"][key] != entry["complete"]["item"][key]
                    for key in ("command", "cwd")
                ):
                    self.end("failed", "command_identity_changed")
                    return
            if phase == "complete" and item.get("type") == "agentMessage":
                if not isinstance(item.get("text"), str):
                    self.end("failed", "invalid_message")
                    return
                self.messages[item["id"]] = fingerprint(params)
                self.message_ids.append(item["id"])
                if item.get("phase") == "final_answer":
                    self.final_seen = True
                    self.end("capability_missing", "final_before_active_compact_chain")
                    return
        self.maybe_observed()

    def observe_clock(self, sample):
        if self.status != "collecting":
            return
        try:
            keys = (
                "mono_before_ns",
                "mono_after_ns",
                "wall_ns",
                "wall_resolution_ns",
                "mono_resolution_ns",
            )
            if (
                any(type(sample[k]) is not int for k in keys)
                or sample["mono_before_ns"] > sample["mono_after_ns"]
                or sample["wall_ns"] < 0
                or sample["wall_resolution_ns"] < 1
                or sample["mono_resolution_ns"] < 1
                or (
                    self.current_clock
                    and sample["mono_before_ns"] < self.current_clock["mono_after_ns"]
                )
            ):
                raise ValueError("invalid samples")
            if self.current_clock:
                previous = self.current_clock
                self.clock_diagnostics.append(
                    {
                        "wall_delta_ns": sample["wall_ns"] - previous["wall_ns"],
                        "mono_delta_ns": sample["mono_after_ns"]
                        - previous["mono_after_ns"],
                    }
                )
            self.current_clock = sample
        except (KeyError, TypeError, ValueError):
            self.end("capability_missing", "clock_sample_missing_or_invalid")

    def wall_diagnostic(self, start, end, quantum_ns):
        # All wall comparisons are diagnostic. They cannot prove causal order,
        # freshness or clock accuracy, including within a single host.
        if type(start) is not int or type(end) is not int or start < 0 or end < 0:
            return "missing_or_invalid_wall_field"
        if end < start:
            return "wall_fields_reversed"
        if end * quantum_ns > self.current_clock["wall_ns"]:
            return "wall_field_ahead_of_local_sample"
        return "wall_field_unordered"

    def hook_wall_fields(self, start, end):
        return {
            "started_at": start,
            "completed_at": end,
            "unit": "unix_seconds",
            "diagnostic": self.wall_diagnostic(start, end, 1_000_000_000),
        }

    def advance_causal_fragments(self):
        """Only derive supported local edges; no generic source/receipt order."""
        for identity, entry in self.items.items():
            start, complete = entry.get("start"), entry.get("complete")
            if (
                start
                and complete
                and start["item"].get("type")
                in {
                    "agentMessage",
                    "commandExecution",
                    "contextCompaction",
                    "userMessage",
                }
            ):
                self.causal_edges["item:" + identity] = {
                    "kind": "same_item_lifecycle",
                    "thread": self.thread,
                    "turn": self.turn,
                    "from": "item:" + identity + ":start",
                    "to": "item:" + identity + ":complete",
                    "item_id": identity,
                    "item_type": start["item"]["type"],
                    "start_sha256": start["digest"],
                    "complete_sha256": complete["digest"],
                }
            # This is a trigger to request steering, not evidence the command
            # is still running. Only a matched steer reply proves enqueueing.
            if (
                start
                and start["item"].get("type") == "commandExecution"
                and start["item"].get("command") == self.plan["ready_command"]
                and start["item"].get("cwd") == self.plan["cwd"]
                and not complete
                and not self.steer_sent
            ):
                self.steer_sent = True
                self.request(
                    "turn/steer",
                    {
                        "threadId": self.thread,
                        "expectedTurnId": self.turn,
                        "input": [{"type": "text", "text": self.plan["question"]}],
                    },
                )
        # No manual compact request: official 0.153.4 replaces the active task.
        # A sessionStart summary lacks its source trigger; it cannot prove resume.

    def maybe_observed(self):
        if self.status == "collecting":
            self.advance_causal_fragments()

    def summary(self):
        return {
            "status": self.status,
            "reason": self.reason,
            "selected_model": self.selected_model,
            "local_write_observations": self.watermarks,
            "unproven_observations": sorted(self.unproven),
            "clock_basis": "monotonic_ns_deadlines; wall_samples_diagnostic_only",
            "clock_diagnostics": self.clock_diagnostics,
            "causal_edges": [self.causal_edges[k] for k in sorted(self.causal_edges)],
            "full_chain": "unknown",
            "messages": len(self.message_ids),
            "message_digests": self.messages,
            "approval_requests": len(self.approval_ids),
            "as_of_elapsed_ns": self.now,
            "answer_coverage": "unknown",
            "native_acceptance": "not_established",
            "session_end": "not_inferred",
            "deadline_ns": self.deadline,
        }


class StdioTransport:
    """One owned official app-server process; no shell or permission bypass."""

    kind = "official_stdio"

    def __init__(self, plan: dict, stderr_path: Path):
        self.errors = stderr_path.open("xb")
        self.proc = subprocess.Popen(
            [plan["codex"], "app-server"],
            cwd=plan["cwd"],
            env={**os.environ, "CODEX_HOME": plan["codex_home"]},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.errors,
        )
        self.queue: queue.Queue = queue.Queue(maxsize=MAX_RECORDS)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            while True:
                raw = self.proc.stdout.readline(MAX_LINE + 1)
                if not raw:
                    self.queue.put(None)
                    return
                if len(raw) > MAX_LINE:
                    raise ValueError("rpc_line_limit")
                self.queue.put(decode_object(raw))
        except (ValueError, UnicodeError, OSError, RecursionError) as exc:
            self.queue.put({"transport_error": type(exc).__name__})

    def send(self, raw, timeout):
        done = threading.Event()
        errors = []

        def write():
            try:
                self.proc.stdin.write(
                    json.dumps(raw, ensure_ascii=True).encode() + b"\n"
                )
                self.proc.stdin.flush()
            except (OSError, ValueError) as exc:
                errors.append(exc)
            finally:
                done.set()

        threading.Thread(target=write, daemon=True).start()
        if not done.wait(timeout):
            raise TimeoutError("rpc_write_deadline")
        if errors:
            raise errors[0]

    def receive(self, timeout):
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return {"transport_poll": True}

    def close(self, timeout):
        deadline = time.monotonic_ns() + round(timeout * 1_000_000_000)
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout / 2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(
                    timeout=max(0.001, (deadline - time.monotonic_ns()) / 1_000_000_000)
                )
            return {
                "owned_process_exited": self.proc.poll() is not None,
                "session_end": "not_inferred",
            }
        finally:
            self.errors.close()
            # Closing an owned pipe can release a reader/writer after kill.
            for pipe in (self.proc.stdin, self.proc.stdout):
                if pipe is not None:
                    pipe.close()


def collect(
    plan: dict,
    directory: Path,
    transport_factory,
    *,
    clock=time.monotonic_ns,
    wall=time.time_ns,
    wall_resolution_ns=max(
        1, math.ceil(time.get_clock_info("time").resolution * 1_000_000_000)
    ),
    mono_resolution_ns=max(
        1, math.ceil(time.get_clock_info("monotonic").resolution * 1_000_000_000)
    ),
    cancelled=lambda: False,
    offline=False,
) -> dict:
    budget = checked_plan(plan)
    if offline is not True or transport_factory is StdioTransport:
        raise ValueError("native_source_contract_incomplete")
    if any(
        directory.resolve().is_relative_to(Path(plan[k]).resolve())
        for k in ("runtime_root", "cwd")
    ):
        raise ValueError("capture_inside_source_or_fixture")
    directory.mkdir(
        mode=0o700 if os.name != "nt" else 0o777
    )  # Exclusive; never overwrite a failed run.
    initial_clock = clock_sample(clock, wall, wall_resolution_ns, mono_resolution_ns)
    started = initial_clock["mono_after_ns"]
    machine = Machine(plan, initial_clock)
    transport = None
    seq = 0
    journal_bytes = 0
    cleanup = {"owned_process_exited": None, "session_end": "not_inferred"}
    write_new(
        directory / "subject.json",
        {
            "schema": SCHEMA,
            "plan": plan,
            "plan_sha256": fingerprint(plan),
            "initial_clock": initial_clock,
        },
    )
    fd = os.open(directory / "rpc.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as journal:

        def record(direction, raw, elapsed=None):
            nonlocal seq, journal_bytes
            terminal = direction in {"stop", "end", "transport"}
            if seq >= MAX_RECORDS - 3 and not terminal:
                raise ValueError("record_limit")
            sample = clock_sample(clock, wall, wall_resolution_ns, mono_resolution_ns)
            elapsed = sample["mono_after_ns"] - started if elapsed is None else elapsed
            machine.tick(elapsed)
            if direction in {"send", "send_complete", "receive"}:
                machine.observe_clock(sample)
            line = (
                json.dumps(
                    {
                        "sequence": seq + 1,
                        "elapsed_ns": elapsed,
                        "clock": sample,
                        "direction": direction,
                        "raw": raw,
                    },
                    ensure_ascii=True,
                )
                + "\n"
            )
            size = len(line.encode("utf-8"))
            if size > MAX_LINE or (
                journal_bytes + size > MAX_LINE * 7 and not terminal
            ):
                raise ValueError("journal_size_limit")
            seq += 1
            journal_bytes += size
            journal.write(line)
            journal.flush()
            return elapsed

        try:
            transport = transport_factory(plan, directory / "stderr.log")
            record("transport", {"kind": transport.kind})
            while machine.status == "collecting":
                machine.tick(clock() - started)
                if cancelled():
                    machine.cancel()
                    record("control", {"cancelled": True}, machine.now)
                    break
                for request in machine.drain():
                    machine.tick(clock() - started)
                    if machine.status != "collecting":
                        break
                    if cancelled():
                        machine.cancel()
                        record("control", {"cancelled": True}, machine.now)
                        break
                    # A journal send is a write attempt; only the paired official
                    # response establishes acceptance. Retain failed attempts.
                    record("send", request)
                    if machine.status != "collecting":
                        break
                    transport.send(
                        request,
                        timeout=max(
                            0.001, (machine.deadline - machine.now) / 1_000_000_000
                        ),
                    )
                    written = record("send_complete", request)
                    machine.sent(request, written)
                if machine.status != "collecting":
                    break
                raw = transport.receive(
                    min(
                        0.25,
                        max(0.001, (machine.deadline - machine.now) / 1_000_000_000),
                    )
                )
                if raw is None:
                    record("transport", {"eof": True})
                    machine.end("capability_missing", "transport_eof")
                elif isinstance(raw, dict) and raw.get("transport_poll") is True:
                    continue
                elif isinstance(raw, dict) and "transport_error" in raw:
                    record("transport", raw)
                    machine.end("failed", "transport_read_error")
                else:
                    observed = record("receive", raw)
                    machine.ingest(raw, observed)
        except KeyboardInterrupt:
            machine.cancel()
            record("control", {"cancelled": True}, machine.now)
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            record("transport", {"failure": type(exc).__name__})
            machine.end("failed", type(exc).__name__)
        finally:
            record("stop", {"summary": machine.summary()}, machine.now)
            if transport is not None:
                try:
                    cleanup = transport.close(budget.cleanup)
                except (OSError, subprocess.TimeoutExpired):
                    cleanup = {
                        "owned_process_exited": False,
                        "session_end": "not_inferred",
                    }
            record("end", {"summary": machine.summary(), "cleanup": cleanup})
    result = {
        "schema": SCHEMA,
        "stage": "collect",
        **machine.summary(),
        "plan_sha256": fingerprint(plan),
        "transport": getattr(transport, "kind", "unavailable"),
        "cleanup": cleanup,
        "journal_sha256": hashlib.sha256(
            (directory / "rpc.jsonl").read_bytes()
        ).hexdigest(),
    }
    write_new(directory / "result.json", result)
    return result


def validate(directory: Path, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("output_exists")
    subject, result = (
        read_json(directory / "subject.json"),
        read_json(directory / "result.json"),
    )
    journal_path = directory / "rpc.jsonl"
    if journal_path.is_symlink() or journal_path.stat().st_size > MAX_LINE * 8:
        raise ValueError("unsafe_journal")
    if (
        subject.get("schema") != SCHEMA
        or result.get("schema") != SCHEMA
        or result.get("stage") != "collect"
    ):
        raise ValueError("capture_schema_mismatch")
    raw = journal_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != result["journal_sha256"]:
        raise ValueError("journal_digest_or_size")
    if (
        fingerprint(subject["plan"]) != subject["plan_sha256"]
        or subject["plan_sha256"] != result["plan_sha256"]
    ):
        raise ValueError("subject_mismatch")
    machine = Machine(subject["plan"], subject["initial_clock"])
    expected = machine.drain()
    last_send = None
    ended = False
    stopped = False
    transport_kind = "unavailable"
    last_elapsed = 0
    for seq, line in enumerate(raw.splitlines(), 1):
        row = decode_object(line)
        if seq > MAX_RECORDS or row["sequence"] != seq or ended:
            raise ValueError("sequence_gap_or_tail")
        elapsed = row["elapsed_ns"]
        if type(elapsed) is not int or elapsed < last_elapsed:
            raise ValueError("invalid_elapsed")
        last_elapsed = elapsed
        machine.tick(elapsed)
        direction, value = row["direction"], row["raw"]
        if direction in {"send", "send_complete", "receive"}:
            sample = row.get("clock")
            if (
                not isinstance(sample, dict)
                or sample.get("mono_after_ns", -1)
                - subject["initial_clock"]["mono_after_ns"]
                != elapsed
            ):
                raise ValueError("clock_elapsed_mismatch")
        if stopped and direction != "end":
            raise ValueError("post_stop_event")
        if direction == "send":
            if (
                machine.status != "collecting"
                or not expected
                or value != expected.pop(0)
            ):
                raise ValueError("unexpected_or_post_cancel_request")
            machine.observe_clock(sample)
            last_send = value
        elif direction == "send_complete":
            if not last_send or value != last_send:
                raise ValueError("unpaired_send_completion")
            machine.observe_clock(sample)
            machine.sent(value, elapsed)
            last_send = None
        elif direction == "receive":
            machine.observe_clock(sample)
            machine.ingest(value, elapsed)
            expected.extend(machine.drain())
        elif direction == "control" and value.get("cancelled"):
            machine.cancel()
            expected.clear()
        elif direction == "transport":
            if "kind" in value:
                if seq != 1 or value["kind"] not in {"official_stdio", "fake"}:
                    raise ValueError("transport_identity")
                transport_kind = value["kind"]
            elif value.get("eof"):
                machine.end("capability_missing", "transport_eof")
            elif "failure" in value or "transport_error" in value:
                machine.end("failed", value.get("failure", "transport_read_error"))
            else:
                raise ValueError("unknown_transport_record")
        elif direction == "stop":
            if machine.status == "collecting" or machine.summary() != value["summary"]:
                raise ValueError("stop_mismatch")
            stopped = True
        elif direction == "end":
            if (
                not stopped
                or machine.summary() != value["summary"]
                or value["cleanup"] != result["cleanup"]
            ):
                raise ValueError("summary_mismatch")
            ended = True
        else:
            raise ValueError("unknown_journal_direction")
    if not ended or transport_kind != result["transport"]:
        raise ValueError("missing_end_or_transport_mismatch")
    if machine.summary() != {k: result[k] for k in machine.summary()}:
        raise ValueError("result_mismatch")
    report = {
        "schema": SCHEMA,
        "stage": "validate",
        **machine.summary(),
        "transport": result["transport"],
        "freshness": "historical_capture_as_of_only",
        "cleanup": result["cleanup"],
        "journal_sha256": result["journal_sha256"],
        "plan_sha256": result["plan_sha256"],
    }
    write_new(output, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("collect")
    p.add_argument("--prepared", type=Path, required=True)
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--execute", action="store_true")
    p = sub.add_parser("validate")
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare(read_json(args.plan), args.output)
        elif args.command == "validate":
            result = validate(args.run_dir, args.output)
        else:
            if not args.execute:
                parser.error(
                    "collect requires explicit --execute; prepare never starts a host"
                )
            receipt = read_json(args.prepared)
            plan = receipt["plan"]
            if (
                receipt.get("schema") != SCHEMA
                or receipt.get("stage") != "prepare"
                or fingerprint(plan) != receipt["plan_sha256"]
            ):
                raise ValueError("invalid_preparation")
            if (
                runtime_identity(Path(plan["runtime_root"]))
                != plan["runtime_tree_sha256"]
            ):
                raise ValueError("runtime_changed")
            if (
                hashlib.sha256(Path(plan["codex"]).read_bytes()).hexdigest()
                != receipt["binary_sha256"]
                or hashlib.sha256(Path(plan["hook_source"]).read_bytes()).hexdigest()
                != receipt["hook_source_sha256"]
            ):
                raise ValueError("prepared_input_changed")
            expected_cache = (
                Path(plan["codex_home"])
                / "plugins/cache/codex-context-guard/context-guard/0.14.2"
            )
            if Path(plan["runtime_root"]).resolve() != expected_cache.resolve():
                raise ValueError("exact_isolated_installed_runtime_required")
            if (
                Path(plan["hook_source"]).resolve()
                != (expected_cache / "hooks/hooks.json").resolve()
            ):
                raise ValueError("product_hook_source_must_match_installed_runtime")
            result = collect(plan, args.run_dir, StdioTransport)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        parser.error(
            type(exc).__name__
            + ": invalid input or output; inspect retained private receipt"
        )
    print(json.dumps({k: result[k] for k in ("stage", "status")}, sort_keys=True))
    return 0 if result["status"] == "inputs_checked_only" else 1


if __name__ == "__main__":
    raise SystemExit(main())
