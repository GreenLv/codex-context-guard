"""Read only the native sources used by the commentary acceptance chain.

The observer is deliberately separate from the app-server controller. It does
not start a producer, alter Hook trust, or create a reviewer policy. An explicit
review call may run once only after the owner has selected this native batch.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from tools.validation.commentary_chain import (
    Chain,
    NestedSourcePending,
    nested_business_proof,
)
from tools.validation.host_capture import digest_echo, inspect_directory


def _module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("installed_module_unavailable")
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


class PendingEvidence(ValueError):
    """A source may still arrive within the bounded native compact stage."""


class NativeObserver:
    def __init__(self, plan):
        self.plan = plan
        self.runtime_root = Path(plan["runtime_root"])
        self.capture_dir = Path(plan["capture_dir"])
        self.product_data_root = (Path(plan["codex_home"]) / "plugins/data"
                                  / f"context-guard-{plan['namespace']}")
        self.runtime = _module(
            self.runtime_root / "scripts/context_guard.py", "cg_native_observed_runtime"
        )
        self.binding = _module(
            self.runtime_root / "scripts/cg_commentary_binding.py", "cg_native_observed_binding"
        )
        self.trace = self.binding.trace_module()
        self.thread = None
        self.turn = None
        self.question_id = None
        self.main_ids = None

    def make_chain(self, thread, turn):
        self.thread, self.turn = thread, turn
        return Chain(
            thread=thread, turn=turn, cwd=self.plan["cwd"],
            hook_source=self.plan["hook_source"],
            capture_hook_source=self.plan["capture_hook_source"],
            frozen_config=self.plan["effective_config"],
            threshold=self.plan["threshold_proposal"],
        )

    def configure_review_policy(self, thread):
        """Operator-selected policy; called once before the producer turn starts."""
        policy = self.plan["review_policy"]
        directory = self._product_directory(thread) / "answer-reviews"
        if directory.is_symlink():
            raise ValueError("linked_review_directory")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / "policy.json"
        if path.is_symlink():
            raise ValueError("linked_review_policy")
        if path.exists():
            if json.loads(path.read_bytes()) != policy:
                raise ValueError("review_policy_already_differs")
            return
        with path.open("xb") as stream:
            stream.write(json.dumps(policy, sort_keys=True).encode() + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    def _product_directory(self, thread):
        if (not isinstance(thread, str) or thread in {".", ".."}
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,160}", thread)):
            raise ValueError("unsafe_product_session_identity")
        root = self.product_data_root
        home = Path(self.plan["codex_home"])
        if root != home / "plugins/data" / f"context-guard-{self.plan['namespace']}":
            raise ValueError("foreign_product_data_root")
        sessions = root / "sessions"
        directory = sessions / thread
        if directory.parent != sessions or directory == sessions or directory == root:
            raise ValueError("unsafe_product_session_identity")
        if any(path.is_symlink() for path in (home, home / "plugins",
                                              home / "plugins/data", root,
                                              sessions, directory)):
            raise ValueError("linked_product_data_path")
        return directory

    def _snapshot(self, thread):
        result = self.binding.snapshot(thread)
        if result is None or not result["events"] or not result["payloads"]:
            raise PendingEvidence("official_trace_pending")
        # The installed product reader intentionally retains only inference
        # and compaction payloads. The acceptance probe also needs the
        # official inner tool invocation/result payloads for exec-wrapped
        # dynamic calls. Read them from the same validated bundle without
        # changing installed runtime bytes or accepting caller-supplied paths.
        first = result["events"][0]
        trace_id = first.get("payload", {}).get("trace_id")
        if not isinstance(trace_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,100}", trace_id):
            raise ValueError("invalid_trace_identity")
        bundle = Path(self.plan["trace_root"]) / f"trace-{trace_id}-{thread}"
        extra = {}
        extra_size = 0
        for event in result["events"]:
            kind = event.get("payload", {}).get("type")
            field, expected = {
                "tool_call_started": ("invocation_payload", "tool_invocation"),
                "tool_call_ended": ("result_payload", "tool_result"),
            }.get(kind, (None, None))
            if field is None:
                continue
            ref = event["payload"].get(field)
            path = ref.get("path") if isinstance(ref, dict) else None
            if (not isinstance(path, str)
                    or not re.fullmatch(r"payloads/[1-9][0-9]{0,12}\.json", path)
                    or ref.get("kind") != {"type": expected}
                    or ref.get("raw_payload_id") !=
                    "raw_payload:" + path.removeprefix("payloads/").removesuffix(".json")):
                raise ValueError("invalid_nested_payload_ref")
            if path not in extra:
                extra[path] = self.trace.stable_read(bundle, path)
                extra_size += len(extra[path])
                if len(extra) > 1024 or extra_size > self.trace.MAX_TOTAL:
                    raise ValueError("nested_payload_budget")
                self.trace.decode(extra[path])
        for path, expected in result["hashes"].items():
            if path == "trace.jsonl":
                continue  # append-only events may arrive after this snapshot
            if hashlib.sha256(self.trace.stable_read(bundle, path)).hexdigest() != expected:
                raise ValueError("trace_snapshot_changed")
        later = self.binding.snapshot(thread)
        if later is None or later["events"][:len(result["events"])] != result["events"]:
            raise ValueError("trace_event_prefix_changed")
        if any(self.trace.stable_read(bundle, path) != raw for path, raw in extra.items()):
            raise ValueError("nested_payload_changed")
        result["payloads"] = {**result["payloads"], **extra}
        return result

    def _pending_inferences(self, source, thread, turn, *, question=None):
        """Recognize incomplete official attempts without treating them as proof."""
        starts = {}
        terminals = set()
        for event in source["events"]:
            if event.get("thread_id") != thread or event.get("codex_turn_id") != turn:
                continue
            payload = event.get("payload", {})
            if not isinstance(payload, dict):
                raise ValueError("malformed_inference_event")
            kind = payload.get("type")
            identity = payload.get("inference_call_id")
            if kind not in {"inference_started", "inference_completed",
                            "inference_failed", "inference_cancelled"}:
                continue
            if not isinstance(identity, str) or not identity:
                raise ValueError("malformed_inference_identity")
            if kind == "inference_started":
                if identity in starts:
                    raise ValueError("repeated_inference_start")
                starts[identity] = event
            else:
                if identity in terminals:
                    raise ValueError("repeated_inference_terminal")
                terminals.add(identity)
        pending = []
        for identity, event in starts.items():
            if identity in terminals:
                continue
            ref = event["payload"].get("request_payload", {})
            path = ref.get("path") if isinstance(ref, dict) else None
            if (not isinstance(path, str)
                    or not re.fullmatch(r"payloads/[1-9][0-9]{0,12}\.json", path)
                    or ref.get("kind") != {"type": "inference_request"}
                    or ref.get("raw_payload_id") !=
                    "raw_payload:" + path.removeprefix("payloads/").removesuffix(".json")):
                raise ValueError("malformed_pending_request_ref")
            raw = source["payloads"].get(path)
            if not isinstance(raw, bytes):
                raise ValueError("missing_pending_request_payload")
            request = self.trace.decode(raw)
            if not isinstance(request, dict) or not isinstance(request.get("input"), list):
                raise ValueError("malformed_pending_request")
            if question is None or sum(
                isinstance(item, dict) and item.get("type") == "message"
                and item.get("role") == "user"
                and item.get("content") == [{"type": "input_text", "text": question}]
                for item in request["input"]
            ) == 1:
                pending.append(identity)
        return pending

    def answer_source(self, thread, turn, client_id, question, users, answers):
        matching_users = [row for row in users
                          if row.get("params", {}).get("item", {}).get("clientId") == client_id]
        if len(matching_users) > 1:
            raise ValueError("repeated_question_user_event")
        if not matching_users:
            if any(isinstance(parts := row.get("params", {}).get("item", {}).get("content"), list)
                   and len(parts) == 1 and isinstance(parts[0], dict)
                   and parts[0].get("type") == "text"
                   and parts[0].get("text") == question
                   for row in users):
                raise ValueError("wrong_client_question_event")
            raise PendingEvidence("question_user_event_pending")
        if not answers:
            raise PendingEvidence("commentary_item_pending")
        source = self._snapshot(thread)
        # Include every completed user item. The shared reducer normalizes the
        # official optional text_elements=[] field and rejects a second same-
        # text source, including a different client id or turn. Filtering the
        # list here would hide that ambiguity.
        events = [*users, *source["events"]]
        matching = []
        failures = []
        for answer in answers:
            try:
                self.trace.reduce_pair(
                    events, source["payloads"], thread=thread, turn=turn,
                    client_id=client_id, question=question, commentary=answer,
                )
            except ValueError as exc:
                failures.append(str(exc))
                continue
            matching.append(answer)
        if len(matching) > 1:
            raise ValueError("unique_source_bound_question_answer_required")
        if not matching:
            if any(reason != "nonunique_input_response_pair" for reason in failures):
                raise ValueError("invalid_question_answer_source:" + ",".join(failures))
            pending = self._pending_inferences(source, thread, turn, question=question)
            if len(pending) > 1:
                raise ValueError("repeated_pending_question_inference")
            if pending:
                raise PendingEvidence("answer_inference_completion_pending")
            raise ValueError("unique_source_bound_question_answer_required")
        if self._pending_inferences(source, thread, turn, question=question):
            raise ValueError("repeated_question_inference")
        return dict(events=events,
                    payloads=source["payloads"], client_id=client_id,
                    question=question, notification=matching[0])

    def business_source(self, thread, turn, call_id, challenge_call_id=None,
                        challenge=None):
        source = self._snapshot(thread)
        target_outer = None
        if challenge_call_id is not None:
            started = [e for e in source["events"]
                       if e.get("thread_id") == thread
                       and e.get("codex_turn_id") == turn
                       and e.get("payload", {}).get("type") == "tool_call_started"
                       and e["payload"].get("tool_call_id") == call_id]
            if len(started) > 1:
                raise ValueError("repeated_business_tool_start")
            if started:
                requester = started[0]["payload"].get("requester", {})
                if requester.get("type") != "code_cell":
                    raise ValueError("wrong_business_tool_requester")
                cell = requester.get("runtime_cell_id")
                cells = [e for e in source["events"]
                         if e.get("thread_id") == thread
                         and e.get("codex_turn_id") == turn
                         and e.get("payload", {}).get("type") == "code_cell_started"
                         and e["payload"].get("runtime_cell_id") == cell]
                if len(cells) > 1:
                    raise ValueError("repeated_business_cell")
                if cells:
                    target_outer = cells[0]["payload"].get("model_visible_call_id")
        candidates = {event.get("payload", {}).get("inference_call_id")
                      for event in source["events"]
                      if event.get("thread_id") == thread
                      and event.get("codex_turn_id") == turn
                      and event.get("payload", {}).get("type") == "inference_completed"}
        matches = []
        pending_nested = False
        for identity in candidates:
            if not isinstance(identity, str) or not identity:
                continue
            try:
                _request, response, _proof = self.trace.attempt_pair(
                    source["events"], source["payloads"], kind="inference",
                    call_id=identity, thread=thread, turn=turn,
                )
            except ValueError as exc:
                raise ValueError("invalid_completed_business_source") from exc
            if sum(isinstance(item, dict) and item.get("type") == "function_call"
                   and item.get("call_id") == call_id
                   for item in response.get("output_items", [])) == 1:
                matches.append(identity)
            elif (target_outer is not None and challenge is not None
                  and any(isinstance(item, dict) and item.get("type") == "custom_tool_call"
                          and item.get("name") == "exec"
                          and item.get("call_id") == target_outer
                          for item in response.get("output_items", []))):
                try:
                    nested_business_proof(
                        source["events"], source["payloads"], thread=thread,
                        turn=turn, inference_call_id=identity, call_id=call_id,
                        challenge_call_id=challenge_call_id, challenge=challenge,
                    )
                except NestedSourcePending:
                    pending_nested = True
                except ValueError as exc:
                    raise ValueError("invalid_nested_business_source") from exc
                else:
                    matches.append(identity)
        if len(matches) > 1:
            raise ValueError("unique_business_inference_required")
        if not matches:
            if (pending_nested or (challenge_call_id is not None and target_outer is None)
                    or self._pending_inferences(source, thread, turn)):
                raise PendingEvidence("business_inference_completion_pending")
            raise ValueError("unique_business_inference_required")
        return dict(events=source["events"], payloads=source["payloads"],
                    inference_call_id=matches[0])

    def _state(self, thread):
        directory = self._product_directory(thread)
        if (directory / "state.json").is_symlink() or not (directory / "state.json").is_file():
            raise ValueError("product_state_unavailable")
        return directory, self.runtime.load_state(directory, {"session_id": thread})

    def review_projection(self, thread, turn):
        directory, state = self._state(thread)
        catalog = self.runtime.answer_review_catalog(directory, state)
        questions = [row for row in catalog
                     if row["subject"]["turn_id"] == turn
                     and row["question_text"] == self.plan["question"]]
        if len(questions) != 1:
            raise ValueError("unique_review_question_required")
        question_id = questions[0]["subject"]["question_id"]
        mains = [item["id"] for item in state["requirements"]
                 if item["id"] != question_id and item.get("status") == "pending"
                 and item.get("text") == self.plan["main_requirement_text"]]
        if len(mains) != 1:
            raise ValueError("distinct_main_obligation_required")
        request = self.runtime.answer_review_request(
            directory, state, next(item for item in state["requirements"]
                                   if item["id"] == question_id),
            codex_home=Path(self.plan["codex_home"]),
        )
        review_dir = directory / "answer-reviews"
        if not (review_dir / "policy.json").is_file():
            raise ValueError("operator_review_policy_required")
        if self.plan.get("execute_review") is not True:
            raise ValueError("review_not_authorized_for_run")
        reviewer = self.runtime.answer_review_module()
        result = reviewer.pending_review(
            review_dir, [request], execute=True, codex_home=Path(self.plan["codex_home"])
        )
        if result.get("status") not in {"review_recorded", "no_new_review"}:
            raise ValueError("independent_review_not_recorded")
        _directory, state = self._state(thread)
        self.question_id, self.main_ids = question_id, mains
        return self.runtime, state, directory, question_id, mains

    def compaction_source(self, thread, turn, hook_runs, completed_item):
        # A recorder publishes raw bytes before atomically publishing metadata.
        # Its digest echo is returned only after that rename, and the official
        # completed notification follows the command result. Check only the
        # official notification envelope first: do not read unvalidated meta
        # paths or raw bytes before strict whole-directory inspection.
        # The first sessionStart is the startup capture. The compact-sourced
        # sessionStart follows contextCompaction and has a distinct raw echo.
        for event, expected_count in (("preCompact", 1), ("sessionStart", 2)):
            ready = [row for row in hook_runs
                     if row.get("method") == "hook/completed"
                     and isinstance(row.get("params"), dict)
                     and isinstance(row["params"].get("run"), dict)
                     and row["params"].get("threadId") == thread
                     and row["params"].get("turnId") == turn
                     and row["params"]["run"].get("sourcePath") ==
                     self.plan["capture_hook_source"]
                     and row["params"]["run"].get("eventName") == event]
            if len(ready) > expected_count:
                raise ValueError("duplicate_capture_hook_completion")
            if len(ready) < expected_count:
                raise PendingEvidence("matching_hook_notification_pending")
            markers = set()
            for row in ready:
                run = row["params"]["run"]
                entries = run.get("entries")
                if (run.get("status") != "completed"
                        or run.get("handlerType") != "command"
                        or run.get("executionMode") != "sync"
                        or not isinstance(entries, list) or len(entries) != 1
                        or not isinstance(entries[0], dict)
                        or entries[0].get("kind") != "warning"
                        or not isinstance(entries[0].get("text"), str)
                        or not re.fullmatch(r"cg-hook-input-pair/v1:[0-9a-f]{32}:[0-9a-f]{64}",
                                            entries[0]["text"])):
                    raise ValueError("invalid_capture_hook_completion")
                markers.add(entries[0]["text"])
            if len(markers) != expected_count:
                raise ValueError("duplicate_capture_hook_echo")
        report = inspect_directory(self.capture_dir, self.runtime_root)
        if report["status"] not in {"observed", "pending"}:
            raise ValueError("hook_capture_inspection_failed")
        relevant = {"PreCompact": [], "SessionStart": []}
        for meta_path in sorted(self.capture_dir.glob("capture-*.meta.json")):
            meta = json.loads(meta_path.read_bytes())
            raw = (self.capture_dir / meta["raw_file"]).read_bytes()
            value = self.trace.decode(raw)
            if not isinstance(value, dict) or value.get("session_id") != thread:
                continue
            event = value.get("hook_event_name")
            if event == "PreCompact":
                if value.get("trigger") != "auto" or value.get("turn_id") != turn:
                    continue
            elif event == "SessionStart":
                if value.get("source") != "compact":
                    continue
            else:
                continue
            if value.get("agent_id") is not None or value.get("agent_type") is not None:
                continue
            relevant[event].append((meta, raw))
        if any(len(rows) > 1 for rows in relevant.values()):
            raise ValueError("repeated_auto_compaction_capture")
        if any(len(rows) != 1 for rows in relevant.values()):
            raise PendingEvidence("matching_compaction_capture_pending")
        captures = []
        for event in ("PreCompact", "SessionStart"):
            meta, raw = relevant[event][0]
            marker = digest_echo(raw, meta["capture_id"])
            notifications = [row for row in hook_runs
                             if any(entry.get("kind") == "warning"
                                    and entry.get("text") == marker
                                    for entry in row.get("params", {}).get("run", {}).get("entries", []))]
            if len(notifications) > 1:
                raise ValueError("duplicate_hook_notification_echo")
            if not notifications:
                raise PendingEvidence("matching_hook_notification_pending")
            captures.append(dict(raw=raw, capture_id=meta["capture_id"],
                                 notification=notifications[0]))
        source = self._snapshot(thread)
        compaction_id = completed_item.get("params", {}).get("item", {}).get("id")
        candidates = {event.get("payload", {}).get("compaction_request_id")
                      for event in source["events"]
                      if event.get("thread_id") == thread
                      and event.get("codex_turn_id") == turn
                      and event.get("payload", {}).get("type") == "compaction_request_completed"}
        matches = []
        for identity in candidates:
            if not isinstance(identity, str) or not identity:
                continue
            try:
                _request, _response, proof = self.trace.attempt_pair(
                    source["events"], source["payloads"], kind="compaction",
                    call_id=identity, thread=thread, turn=turn,
                )
            except ValueError:
                continue
            if proof.get("compaction_id") == compaction_id:
                matches.append(identity)
        if len(matches) > 1:
            raise ValueError("repeated_completed_compaction_source")
        if not matches:
            raise PendingEvidence("completed_compaction_source_pending")
        return captures, dict(events=source["events"], payloads=source["payloads"],
                              request_id=matches[0])

    def cold_reader(self, question_id, main_ids):
        if question_id != self.question_id or main_ids != self.main_ids:
            raise ValueError("cold_subject_changed")
        directory = self._product_directory(self.thread)
        program = """
import importlib.util, hashlib, json, sys
from pathlib import Path
root, harness, helper_digest, directory, home, thread, question, mains = json.load(sys.stdin)
helper = Path(harness) / 'tools/validation/commentary_fixture.py'
if hashlib.sha256(helper.read_bytes()).hexdigest() != helper_digest:
    raise ValueError('external_cold_helper_changed')
spec = importlib.util.spec_from_file_location('cg_cold_product', Path(root) / 'scripts/context_guard.py')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
sys.path.insert(0, str(Path(harness)))
from tools.validation.commentary_fixture import product_review_checkpoint
import tools.validation.commentary_fixture as fixture
if Path(fixture.__file__).resolve() != helper.resolve():
    raise ValueError('foreign_cold_helper_loaded')
state = module.load_state(Path(directory), {'session_id': thread})
print(json.dumps(product_review_checkpoint(module, state, session_dir=Path(directory),
                                           codex_home=Path(home),
                                           question_id=question, main_ids=mains)))
"""
        run = subprocess.run(
            [sys.executable, "-c", program],
            input=json.dumps([str(self.runtime_root), self.plan["harness_root"],
                              self.plan["cold_helper_sha256"], str(directory),
                              self.plan["codex_home"], self.thread,
                              question_id, main_ids]),
            text=True, capture_output=True, timeout=15, check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if run.returncode != 0 or len(run.stdout) > 65536:
            raise ValueError("cold_product_read_failed")
        return json.loads(run.stdout)
