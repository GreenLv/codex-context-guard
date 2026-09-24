"""Adversarial source boundaries for the zero-model C2 native profile."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from tools.validation import commentary_control_live as control
from tools.validation import commentary_control_native_profile as profile
from tools.validation import commentary_fixture as fixture
from tools.validation import commentary_live_adapter as wire
from tools.validation.host_capture import digest_echo


class CommentaryControlNativeProfileTests(unittest.TestCase):
    def test_c2_tied_legacy_clock_still_requires_rpc_causality(self):
        request = {"id": 7, "method": "initialize"}
        reply = {"id": 7, "result": {}}
        rows = [
            {"direction": "send", "raw": request, "monotonic_ns": 100},
            {"direction": "send_complete", "raw": request,
             "monotonic_ns": 100},
            {"direction": "receive", "raw": reply, "monotonic_ns": 100},
        ]

        def parse(value):
            raw = ("\n".join(json.dumps(row) for row in value) + "\n").encode()
            return profile.common._rpc(raw, allow_legacy_equal_ticks=True)

        self.assertEqual(len(profile._paired(parse(rows), "initialize")), 1)
        for changed in (
            [rows[0], rows[2], rows[1]],
            [rows[0], rows[1], rows[1], rows[2]],
            [rows[1], rows[0], rows[2]],
        ):
            with self.subTest(changed=changed), self.assertRaises(
                    profile.ControlReplayError):
                profile._paired(parse(changed), "initialize")

    def test_suite_adapter_requires_original_instruction_and_one_pinned_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            python = root / "python"
            suite = root / "suite.py"
            action = str(python) + " " + str(suite)
            original = {"cwd": str(root), "root_prompt": "original C2 marker",
                        "developer_instructions": "Use terminal to run exactly: " + action + "."}
            spec = {"path": str(suite), "sha256":
                    profile.commentary_suite_oracle.SUITE_FIXTURE_SHA256,
                    "platform": "posix", "allowed_python": [str(python)],
                    "allowed_outer_commands": [f"/bin/zsh -lc '{action}'"]}
            with patch.object(profile.commentary_suite_oracle,
                              "validate_suite_plan", return_value=spec):
                adapted = profile._suite_adapter({"suite_oracle": spec}, original)
                self.assertEqual(adapted["suite_oracle"], spec)
                for change in (
                    {"developer_instructions": "The suite already passed."},
                    {"developer_instructions": "run exactly: " + str(root / "other")
                                               + " " + str(suite) + "."},
                ):
                    with self.subTest(change=change), self.assertRaises(ValueError):
                        profile._suite_adapter({"suite_oracle": spec},
                                               {**original, **change})
                widened = {**spec, "allowed_python": [str(python), str(root / "other")]}
                with self.assertRaises(ValueError):
                    profile._suite_adapter({"suite_oracle": widened}, original)
                with self.assertRaisesRegex(ValueError, "suite_adapter_not_frozen"):
                    profile._suite_adapter({"suite_oracle": spec},
                                           {**original, "suite_oracle": {
                                               **spec, "allowed_outer_commands": ["foreign"]}})

    def test_official_items_bind_both_thread_and_turn(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.mkdir(exist_ok=True)
            plan = {"run_dir": str(root), "root_prompt": "root",
                    "general_prompt": "continue", "exact_prompt": "CG142-CONFIRM-17",
                    "root_client_id": "root-client",
                    "general_client_id": "general-client",
                    "exact_client_id": "exact-client",
                    "values": list(range(-64, 64))}
            thread = "thread"
            turns = ["turn-1", "turn-2", "turn-3"]
            result = {"turn_ids": turns, "status": "source_controls_observed",
                      "native_acceptance": "not_established", "business_requests": 1,
                      "source_bound_business": True, "reviewer_calls": 0}
            rows = []

            def add(direction, raw):
                rows.append({"direction": direction, "raw": raw})

            for n, turn in enumerate(turns):
                request = {"id": n + 10, "method": "turn/start", "params": {
                    "threadId": thread, "clientUserMessageId":
                    plan[control.CLIENT_IDS[n]], "input": [{"type": "text",
                    "text": plan[control.FOLLOWUPS[n]]}]}}
                add("send", request)
                add("send_complete", request)
                add("receive", {"id": n + 10, "result": {"turn": {"id": turn}}})
                add("receive", {"method": "item/completed", "params": {
                    "threadId": thread, "turnId": turn, "item": {
                    "type": "userMessage", "id": f"user-{n}",
                    "clientId": plan[control.CLIENT_IDS[n]], "content": [{
                        "type": "text", "text": plan[control.FOLLOWUPS[n]],
                        "text_elements": []}]}}})
                tools = [wire.READY] if n < 2 else [wire.READY, wire.CHALLENGE,
                                                       wire.BUSINESS]
                challenge = {"schema": "cg-business-challenge/v1",
                             "nonce": "a" * 64,
                             "commentary_pair_sha256": hashlib.sha256(
                                 (thread + ":" + turn + ":" +
                                  plan["exact_prompt"]).encode()).hexdigest()}
                for index, name in enumerate(tools):
                    call_id = f"call-{n}-{index}"
                    request_id = n * 10 + index + 100
                    args = {"nonce": challenge["nonce"]} if name == wire.BUSINESS else {}
                    add("receive", {"method": "item/started", "params": {
                        "threadId": thread, "turnId": turn, "item": {
                        "type": "dynamicToolCall", "id": call_id}}})
                    raw = {"id": request_id, "method": "item/tool/call",
                           "params": {"threadId": thread, "turnId": turn,
                                      "callId": call_id, "namespace": wire.TOOL_NAMESPACE,
                                      "tool": name, "arguments": args}}
                    add("receive", raw)
                    call = wire.parse_call(raw, thread=thread, turn=turn)
                    payload = {"ready": True} if name == wire.READY else challenge
                    if name == wire.BUSINESS:
                        payload, _report = fixture.business_result(plan["values"],
                                                                   challenge)
                        (root / "business-result.json").write_text(json.dumps(payload))
                    response = wire.response(call, payload)
                    add("send", response)
                    add("send_complete", response)
                    add("receive", {"method": "item/completed", "params": {
                        "threadId": thread, "turnId": turn, "item": {
                        "type": "dynamicToolCall", "id": call_id,
                        "status": "completed", "success": True}}})
                add("receive", {"method": "item/completed", "params": {
                    "threadId": thread, "turnId": turn, "item": {
                    "type": "agentMessage", "id": f"answer-{n}", "text": (
                        control.EXACT_REPLY if n == 2 else control.ROOT_REPLY)}}})
                add("receive", {"method": "turn/completed", "params": {
                    "threadId": thread, "turn": {"id": turn, "status": "completed",
                                                 "error": None}}})
            profile._source_control(rows, plan, result, thread)
            for mutate in (
                lambda r: [x["raw"]["params"].__setitem__("threadId", "foreign")
                           for x in r if x["direction"] == "receive"
                           and x["raw"].get("method") == "item/completed"
                           and x["raw"]["params"]["item"].get("type") in {
                               "userMessage", "agentMessage"}],
                lambda r: next(x["raw"]["params"].__setitem__("turnId", "turn-1")
                               for x in r if x["direction"] == "receive"
                               and x["raw"].get("method") == "item/completed"
                               and x["raw"]["params"]["item"].get("id") == "user-2"),
                lambda r: next(x["raw"]["params"]["item"].pop("id")
                               for x in r if x["direction"] == "receive"
                               and x["raw"].get("method") == "item/completed"
                               and x["raw"]["params"]["item"].get("id") == "answer-2"),
                lambda r: next(x["raw"]["params"].__setitem__("turnId", "turn-1")
                               for x in r if x["direction"] == "receive"
                               and x["raw"].get("method") == "item/tool/call"
                               and x["raw"]["params"].get("tool") == wire.BUSINESS),
            ):
                changed = deepcopy(rows)
                mutate(changed)
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    profile._source_control(changed, plan, result, thread)

    def test_capture_snapshot_rejects_missing_extra_changed_and_wrong_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, snapshot = root / "capture", root / "snapshot"
            source.mkdir()
            snapshot.mkdir()
            def digest(path):
                return hashlib.sha256(path.read_bytes()).hexdigest()
            files = {}
            events = ["SessionStart", "PreCompact", "SessionStart"]
            for number, event in enumerate(events, 1):
                stem = f"capture-{number:06d}"
                data = {"session_id": "current", "hook_event_name": event}
                if number == 1:
                    data["source"] = "startup"
                elif number == 2:
                    data.update(trigger="auto", turn_id="third")
                else:
                    data["source"] = "compact"
                raw = json.dumps(data).encode()
                meta = json.dumps({"capture_id": f"{number:032x}",
                                   "raw_sha256": hashlib.sha256(raw).hexdigest(),
                                   "raw_bytes": len(raw), "expected_event": event,
                                   "runtime_tree_sha256": "a" * 64}).encode()
                for directory in (source, snapshot):
                    (directory / (stem + ".raw")).write_bytes(raw)
                    (directory / (stem + ".meta.json")).write_bytes(meta)
                files[stem + ".raw"] = digest(snapshot / (stem + ".raw"))
                files[stem + ".meta.json"] = digest(snapshot / (stem + ".meta.json"))
            parent = root / "parent.json"
            parent.write_text(json.dumps({"original_capture_root": str(source),
                                          "files": {"capture-000001.raw":
                                                    files["capture-000001.raw"]}}))
            value = {"schema": "cg142-private-capture-snapshot/v1",
                     "original_capture_root": str(source),
                     "snapshot_root": str(snapshot),
                     "capture_tree_sha256": profile.common._tree_digest(snapshot),
                     "files": files, "parent_snapshot_manifest_path": str(parent),
                     "parent_snapshot_manifest_sha256": digest(parent)}
            plan = {"capture_dir": str(source), "runtime_tree_sha256": "a" * 64}
            def encoded():
                return json.dumps(value).encode()
            profile._snapshot(encoded(), plan, "current")
            (snapshot / "extra").write_bytes(b"extra")
            with self.assertRaises(profile.ControlReplayError):
                profile._snapshot(encoded(), plan, "current")
            (snapshot / "extra").unlink()
            (source / "capture-000002.raw").write_bytes(b"changed")
            with self.assertRaises((profile.ControlReplayError, profile.common.ReplayError)):
                profile._snapshot(encoded(), plan, "current")
            (source / "capture-000002.raw").write_bytes(
                (snapshot / "capture-000002.raw").read_bytes())
            (snapshot / "capture-000003.raw").unlink()
            with self.assertRaises(profile.ControlReplayError):
                profile._snapshot(encoded(), plan, "current")
            (snapshot / "capture-000003.raw").write_bytes(
                (source / "capture-000003.raw").read_bytes())
            with self.assertRaises(profile.ControlReplayError):
                profile._snapshot(encoded(), plan, "different")

            plan["capture_hook_source"] = "/flags/config.toml"
            rows = []
            for number, event in enumerate(events, 1):
                raw = (snapshot / f"capture-{number:06d}.raw").read_bytes()
                marker = digest_echo(raw, f"{number:032x}")
                rows.append({"direction": "receive", "raw": {"method":
                    "hook/completed", "params": {"threadId": "current", "run": {
                        "sourcePath": plan["capture_hook_source"],
                        "eventName": "preCompact" if number == 2 else "sessionStart",
                        "entries": [{"kind": "warning", "text": marker}]}}}})
                if number == 2:
                    rows.append({"direction": "receive", "raw": {"method":
                        "item/completed", "params": {"threadId": "current",
                        "turnId": "third", "item": {"type": "contextCompaction",
                                                     "id": "compact-id"}}}})
            self.assertEqual(profile._capture_bindings(value, plan, "current",
                                                        "third", rows), "compact-id")
            changed = deepcopy(rows)
            changed[0]["raw"]["params"]["run"]["entries"][0]["text"] = "other"
            with self.assertRaises(profile.ControlReplayError):
                profile._capture_bindings(value, plan, "current", "third", changed)
            changed = deepcopy(rows)
            changed[1]["raw"]["params"]["threadId"] = "foreign"
            with self.assertRaises(profile.ControlReplayError):
                profile._capture_bindings(value, plan, "current", "third", changed)
            # Locally consistent bytes and hashes are still not the official
            # Hook run: the recorded digest echo binds the original raw bytes.
            altered = json.loads((snapshot / "capture-000003.raw").read_text())
            altered["extra"] = "different-source"
            new_raw = json.dumps(altered).encode()
            meta = json.loads((snapshot / "capture-000003.meta.json").read_text())
            meta.update(raw_sha256=hashlib.sha256(new_raw).hexdigest(),
                        raw_bytes=len(new_raw))
            for directory in (source, snapshot):
                (directory / "capture-000003.raw").write_bytes(new_raw)
                (directory / "capture-000003.meta.json").write_text(json.dumps(meta))
            value["files"]["capture-000003.raw"] = digest(
                snapshot / "capture-000003.raw")
            value["files"]["capture-000003.meta.json"] = digest(
                snapshot / "capture-000003.meta.json")
            value["capture_tree_sha256"] = profile.common._tree_digest(snapshot)
            profile._snapshot(encoded(), plan, "current")
            with self.assertRaises(profile.ControlReplayError):
                profile._capture_bindings(value, plan, "current", "third", rows)

    def test_hook_notifications_require_every_selected_run_to_complete(self):
        plan = {"hook_source": "/plugin/hooks.json",
                "capture_hook_source": "/flags/config.toml",
                "codex_home": "/isolated/home"}
        user_path = str(Path(plan["codex_home"]) / "hooks.json")
        user_events = {"preToolUse", "postToolUse", "preCompact",
                       "sessionStart", "sessionEnd", "userPromptSubmit", "stop"}
        readback = {"hooks": [
            {"key": "user-" + name, "source": "user", "sourcePath": user_path,
             "eventName": name, "trustStatus": "trusted", "enabled": True}
            for name in sorted(user_events)]}
        user_notice = [{"direction": "receive", "raw": {
            "method": "hook/started", "params": {"run": {"source": "user"}}}}]
        allowed_user = profile._user_hook_events(readback, plan, user_notice)
        self.assertEqual(allowed_user, {user_path: user_events})

        def event(method, identity, *, status, source=None, kind=None,
                  event_name="sessionStart"):
            source_path = source or plan["hook_source"]
            origin = kind or ("plugin" if source_path == plan["hook_source"]
                              else "sessionFlags" if source_path == plan["capture_hook_source"]
                              else "user")
            return {"direction": "receive", "raw": {"method": method,
                    "params": {"threadId": "current", "run": {
                        "id": identity, "status": status, "statusMessage": None,
                        "source": origin, "eventName": event_name,
                        "sourcePath": source_path}}}}

        rows = [event("hook/started", "same", status="running"),
                event("hook/completed", "same", status="completed"),
                event("hook/started", "same", status="running",
                      source=plan["capture_hook_source"]),
                event("hook/completed", "same", status="completed",
                      source=plan["capture_hook_source"]),
                event("hook/started", "user-1", status="running",
                      source=user_path),
                event("hook/completed", "user-1", status="completed",
                      source=user_path)]
        profile._hooks(rows, plan, "current", allowed_user)
        for changed in (rows[:-1],
                        rows[:3] + [event("hook/completed", "same", status="timedOut",
                                          source=plan["capture_hook_source"])],
                        rows[:3] + [event("hook/completed", "other", status="completed",
                                          source=plan["capture_hook_source"])],
                        rows[:3] + [event("hook/completed", "same", status="completed",
                                           source="/unselected")],
                        rows[:4] + [event("hook/started", "user-1", status="running",
                                          source=user_path, event_name="subagentStart"),
                                    event("hook/completed", "user-1", status="completed",
                                          source=user_path, event_name="subagentStart")],
                        rows[:4] + [event("hook/started", "user-1", status="running",
                                          source=user_path, kind="plugin"),
                                    event("hook/completed", "user-1", status="completed",
                                          source=user_path, kind="plugin")],
                        rows[:4] + [event("hook/started", "user-1", status="running",
                                          source=plan["hook_source"], kind="user"),
                                    event("hook/completed", "user-1", status="completed",
                                          source=plan["hook_source"], kind="user")]):
            with self.subTest(changed=changed), self.assertRaises(profile.ControlReplayError):
                profile._hooks(changed, plan, "current", allowed_user)

        inactive = deepcopy(readback)
        for hook in inactive["hooks"]:
            hook["trustStatus"] = "modified"
        self.assertEqual(profile._user_hook_events(inactive, plan, rows[:4]), {})
        profile._hooks(rows[:4], plan, "current",
                       profile._user_hook_events(inactive, plan, rows[:4]))
        with self.assertRaises(profile.ControlReplayError):
            profile._user_hook_events(inactive, plan, rows)

        for mutation in (
            lambda row: row["raw"]["params"].update(threadId="foreign"),
            lambda row: row["raw"]["params"]["run"].update(status="failed"),
            lambda row: row["raw"]["params"]["run"].update(sourcePath="/unknown"),
        ):
            changed = deepcopy(rows)
            mutation(changed[-1])
            with self.subTest(mutation=mutation), self.assertRaises(
                    profile.ControlReplayError):
                profile._hooks(changed, plan, "current", allowed_user)

        for change in (
            lambda hooks: hooks[0].update(trustStatus="modified"),
            lambda hooks: hooks[0].update(enabled=False),
            lambda hooks: hooks[0].update(source="plugin"),
            lambda hooks: hooks[0].update(sourcePath="/unlisted"),
            lambda hooks: hooks[0].update(eventName="subagentStart"),
            lambda hooks: hooks[0].update(key=hooks[1]["key"]),
            lambda hooks: hooks.append({**hooks[0], "key": "extra"}),
        ):
            altered = deepcopy(readback)
            change(altered["hooks"])
            with self.subTest(change=change), self.assertRaises(
                    profile.ControlReplayError):
                profile._user_hook_events(altered, plan, user_notice)

    def test_cold_readback_requires_exact_release_and_future_pending(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home = root / "home"
            session = (home / "plugins/data/context-guard-candidate/sessions/current")
            prompts = session / "prompts"
            prompts.mkdir(parents=True)
            for number in range(1, 4):
                (prompts / f"P{number:04d}.json").write_text("{}")
            future = root / "future-observation.json"
            main = "只有我在后续消息中原样发送 CG142-CONFIRM-17 才可运行测试"
            prompt = main + "。今后再观察 future-observation.json 的性能变化。"
            state = {"session": {"id": "current"}, "requirements": [{
                "id": "R001", "text": prompt, "status": "pending",
                "clause_metadata": {"clauses": [
                    {"operation": "test_verify", "clause": main,
                     "subjectId": ["main"]},
                    {"operation": "unspecified", "clause":
                     "今后再观察 future-observation.json 的性能变化",
                     "subjectId": ["future"]}]}}], "wait_conditions": [{
                         "condition_id": "WC0001", "condition_type": "exact_input",
                         "raised_by_source": "P0001", "raised_by_kind": "root_user",
                         "source_clause_sha256": hashlib.sha256(main.encode()).hexdigest(),
                         "subject_sha256": hashlib.sha256(
                             b"CG142-CONFIRM-17").hexdigest(),
                         "status": "released", "released_by_kind":
                         "root_user_confirmation", "released_by_source": "P0003"}]}
            path = session / "state.json"
            plan = {"codex_home": str(home), "namespace": "candidate",
                    "root_prompt": prompt, "future_path": str(future)}
            path.write_text(json.dumps(state))
            self.assertTrue(profile._cold_state(plan, "current")["future_pending"])
            for mutate in (
                lambda d: d["wait_conditions"][0].update(released_by_source="P0002"),
                lambda d: d["wait_conditions"][0].update(status="waiting"),
                lambda d: d["requirements"][0].update(status="completed"),
                lambda d: d["wait_conditions"][0].update(subject_sha256="0" * 64),
            ):
                changed = deepcopy(state)
                mutate(changed)
                path.write_text(json.dumps(changed))
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    profile._cold_state(plan, "current")
            path.write_text(json.dumps(state))
            future.write_text("claimed")
            with self.assertRaises(ValueError):
                profile._cold_state(plan, "current")
