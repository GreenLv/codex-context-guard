"""Zero-model, exact-source replay of a completed C2 native control run.

The collector's own ``source_controls_observed`` result is an input, never a
native-acceptance verdict. This mapper reads its original RPC, trace, private
Hook captures and product state without starting Codex or changing the HOME.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any

from tools.validation import commentary_control_live as control
from tools.validation import commentary_fixture as fixture
from tools.validation import commentary_live_adapter as wire
from tools.validation import commentary_native_profile as common
from tools.validation import commentary_suite_oracle
from tools.validation.commentary_controls import c2_future_preserved, c2_wait_status
from tools.validation.commentary_live_observer import NativeObserver
from tools.validation.host_capture import digest_echo, measure_runtime

PROFILE = "commentary_control_chain/v1"
SCHEMA = "commentary-control-native-replay/v1"
FIELDS = {"schema", "original_source_commit", "plan", "result", "journal",
          "source_manifest", "capture_snapshot", "suite_oracle", "closures"}
ORIGINAL_COMPONENTS = (
    "tools/validation/commentary_control_live.py",
    "tools/validation/commentary_controls.py",
    "tools/validation/commentary_live_adapter.py",
    "tools/validation/commentary_live_controller.py",
    "tools/validation/commentary_live_observer.py",
    "tools/validation/commentary_trace.py",
    "tools/validation/commentary_fixture.py",
    "tools/validation/commentary_suite_oracle.py",
    "tools/validation/host_capture.py",
    "scripts/cg_process_tree.py",
)


class ControlReplayError(ValueError):
    """A pinned source is missing, ambiguous or contradicted."""


def _fail(reason: str) -> None:
    raise ControlReplayError(reason)


def _one(items: list[Any], reason: str) -> Any:
    if len(items) != 1:
        _fail(reason)
    return items[0]


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _descriptor(manifest: dict, key: str, limit: int) -> bytes:
    item = manifest.get(key)
    if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
        _fail("invalid_descriptor:" + key)
    return common._read(Path(item["path"]), item["sha256"], limit)


def _snapshot(raw: bytes, plan: dict, thread: str | None = None) -> dict:
    """Pin a complete sealed snapshot and require its files at the trusted path.

    Later scenarios may append to the shared source directory. Those extras
    cannot fill a missing pinned file and do not invalidate this older replay.
    """
    value = common._object(raw)
    if (set(value) != {"schema", "original_capture_root", "snapshot_root",
                       "capture_tree_sha256", "files",
                       "parent_snapshot_manifest_path", "parent_snapshot_manifest_sha256"}
            or value["schema"] != "cg142-private-capture-snapshot/v1"
            or value["original_capture_root"] != plan["capture_dir"]
            or not isinstance(value["files"], dict)
            or not 2 <= len(value["files"]) <= 512):
        _fail("capture_snapshot_shape_or_origin")
    root = Path(value["snapshot_root"])
    source = Path(value["original_capture_root"])
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
            or root != root.resolve(strict=True)
            or not source.is_absolute() or source.is_symlink() or not source.is_dir()
            or source != source.resolve(strict=True)):
        _fail("capture_snapshot_path")
    names = set(value["files"])
    members = list(root.rglob("*"))
    actual = {member.relative_to(root).as_posix() for member in members
              if member.is_file()}
    if (actual != names or any(member.is_symlink() for member in root.rglob("*"))
            or any(not member.is_file() for member in members)
            or any("/" in name or "\\" in name or name.startswith(".")
                   or not re.fullmatch(r"capture-[0-9]{6}\.(?:raw|meta\.json)", name)
                   or not common.HEX64.fullmatch(digest)
                   for name, digest in value["files"].items())):
        _fail("capture_snapshot_file_set")
    for name, digest in value["files"].items():
        if (_digest(common._read(root / name, digest, 2 * 1024 * 1024)) != digest
                or _digest(common._read(source / name, digest, 2 * 1024 * 1024))
                != digest):
            _fail("capture_original_or_snapshot_changed")
    if (common._tree_digest(root) != value["capture_tree_sha256"]
            or set(name[:-4] for name in names if name.endswith(".raw"))
            != set(name[:-10] for name in names if name.endswith(".meta.json"))):
        _fail("capture_tree_or_pairs_changed")
    parent = common._object(common._read(
        Path(value["parent_snapshot_manifest_path"]),
        value["parent_snapshot_manifest_sha256"], 65536))
    if (parent.get("original_capture_root") != plan["capture_dir"]
            or not isinstance(parent.get("files"), dict)
            or any(value["files"].get(name) != digest
                   for name, digest in parent["files"].items())):
        _fail("earlier_capture_changed")
    if thread is not None:
        events = []
        for name in sorted(n for n in names if n.endswith(".raw")):
            raw_event = common._object((root / name).read_bytes())
            meta = common._object((root / name.replace(".raw", ".meta.json")).read_bytes())
            if (meta.get("raw_sha256") != value["files"][name]
                    or meta.get("raw_bytes") != (root / name).stat().st_size
                    or meta.get("runtime_tree_sha256") != plan["runtime_tree_sha256"]
                    or meta.get("expected_event") != raw_event.get("hook_event_name")):
                _fail("capture_pair_metadata_changed")
            if raw_event.get("session_id") == thread:
                events.append(raw_event.get("hook_event_name"))
        if events != ["SessionStart", "PreCompact", "SessionStart"]:
            _fail("current_session_capture_chain_missing")
    return value


def _closures(manifest: dict, plan: dict) -> None:
    closures = manifest.get("closures")
    if not isinstance(closures, dict) or set(closures) != {"run", "trace", "session"}:
        _fail("evidence_closure_missing")
    expected = {"run": Path(plan["run_dir"]), "trace": Path(plan["trace_root"])}
    for name, root in expected.items():
        item = closures.get(name)
        if (not isinstance(item, dict) or set(item) != {"root", "sha256"}
                or item["root"] != str(root)
                or common._tree_digest(root) != item["sha256"]):
            _fail("evidence_closure_changed:" + name)
    session = closures["session"]
    sessions = (Path(plan["codex_home"]) / "plugins/data"
                / f"context-guard-{plan['namespace']}" / "sessions")
    if (not isinstance(session, dict) or set(session) != {"root", "sha256"}
            or Path(session["root"]).parent != sessions
            or common._tree_digest(Path(session["root"])) != session["sha256"]):
        _fail("evidence_closure_changed:session")


def _read_inputs(manifest_path: Path, source_commit: str) -> tuple[dict, dict, dict, bytes]:
    raw = common._read_unpinned(manifest_path, 8192)
    manifest = common._object(raw)
    if (set(manifest) not in (FIELDS, FIELDS | {"checkout_projection"},
                              FIELDS | {"source_delta"})
            or manifest["schema"] != SCHEMA
            or manifest["original_source_commit"] != source_commit
            or not re.fullmatch(r"[0-9a-f]{40}", source_commit)):
        _fail("invalid_control_replay_manifest")
    _descriptor(manifest, "plan", 65536)
    result = common._object(_descriptor(manifest, "result", 65536))
    journal = _descriptor(manifest, "journal", 16 * 1024 * 1024)
    _descriptor(manifest, "source_manifest", 1024 * 1024)
    if "checkout_projection" in manifest:
        _descriptor(manifest, "checkout_projection", 65536)
    if "source_delta" in manifest:
        _descriptor(manifest, "source_delta", 65536)
    snapshot = _descriptor(manifest, "capture_snapshot", 65536)
    plan = control.load_plan(Path(manifest["plan"]["path"]))
    run = Path(plan["run_dir"])
    if (run / "result.json" != Path(manifest["result"]["path"])
            or run / "rpc.jsonl" != Path(manifest["journal"]["path"])
            or plan["source_manifest_path"] != manifest["source_manifest"]["path"]
            or common._object(common._read_unpinned(run / "plan.json", 65536)) != plan):
        _fail("runner_plan_or_paths_changed")
    _closures(manifest, plan)
    _snapshot(snapshot, plan)
    _suite_adapter(manifest, plan)
    return manifest, plan, result, journal


def _suite_adapter(manifest: dict, plan: dict) -> dict:
    """Authorize one exact suite command from the original developer input."""
    suite = manifest.get("suite_oracle")
    if (not isinstance(suite, dict)
            or set(suite) != {"path", "sha256", "platform", "allowed_python",
                              "allowed_outer_commands"}
            or not isinstance(suite["allowed_python"], list)
            or len(suite["allowed_python"]) != 1
            or not isinstance(suite["allowed_outer_commands"], list)
            or len(suite["allowed_outer_commands"]) != 1
            or suite["path"] != str(Path(plan["cwd"]) / "suite.py")
            or suite["sha256"] != commentary_suite_oracle.SUITE_FIXTURE_SHA256
            or ("suite_oracle" in plan and plan["suite_oracle"] != suite)):
        _fail("suite_adapter_not_frozen")
    python = suite["allowed_python"][0]
    if not isinstance(python, str) or not Path(python).is_absolute():
        _fail("suite_python_not_absolute")
    if suite["platform"] == "posix":
        action = python + " " + suite["path"]
    elif suite["platform"] == "windows":
        action = "& '" + python + "' '" + suite["path"] + "'"
    else:
        _fail("suite_platform_unsupported")
    if ("run exactly: " + action + ".") not in plan["developer_instructions"]:
        _fail("suite_command_not_in_original_plan")
    adapter = dict(plan)
    adapter["root_prompt"] = adapter["main_requirement_text"] = (
        f"请运行 {suite['path']} 的测试并持续执行直到任务完成。")
    adapter["suite_oracle"] = suite
    commentary_suite_oracle.validate_suite_plan(adapter)
    return adapter


def preflight(manifest_path: Path, source_commit: str) -> None:
    """Verify pinned inputs only; do not start Codex or write a result."""
    _read_inputs(manifest_path, source_commit)


def _paired(rows: list[dict], method: str) -> list[tuple[int, dict, int, dict]]:
    pairs = []
    requests = [(i, row["raw"]) for i, row in enumerate(rows)
                if row["direction"] == "send" and row["raw"].get("method") == method]
    for index, request in requests:
        sent = _one([i for i, row in enumerate(rows) if row["direction"] == "send_complete"
                     and row["raw"] == request], "send_completion_missing:" + method)
        replies = [(i, row["raw"]) for i, row in enumerate(rows)
                   if row["direction"] == "receive" and row["raw"].get("id")
                   == request.get("id") and "method" not in row["raw"]]
        response_index, response = _one(replies, "response_missing:" + method)
        if (not index < sent < response_index or "error" in response
                or not isinstance(response.get("result"), dict)):
            _fail("response_invalid:" + method)
        pairs.append((index, request, response_index, response))
    return pairs


def _user_hook_events(readback: dict, plan: dict,
                      rows: list[dict]) -> dict[str, set[str]]:
    """Bind observed user runs to trusted Hooks in this official readback."""
    if not any(row["direction"] == "receive"
               and row["raw"].get("method") in {"hook/started", "hook/completed"}
               and row["raw"].get("params", {}).get("run", {}).get("source") == "user"
               for row in rows):
        return {}
    hooks = readback.get("hooks")
    if (not isinstance(hooks, list)
            or any(not isinstance(hook, dict) for hook in hooks)):
        _fail("user_hook_readback_missing")
    others = [hook for hook in hooks if hook.get("sourcePath") not in {
        plan["hook_source"], plan["capture_hook_source"]}]
    path = str(Path(plan["codex_home"]) / "hooks.json")
    events = {"preToolUse", "postToolUse", "preCompact", "sessionStart",
              "sessionEnd", "userPromptSubmit", "stop"}
    if (len(others) != 7
            or any(not isinstance(hook.get("key"), str) or not hook["key"]
                   or not isinstance(hook.get("eventName"), str)
                   for hook in others)
            or {hook.get("eventName") for hook in others} != events
            or len({hook.get("key") for hook in others}) != 7
            or any(hook.get("source") != "user"
                   or hook.get("sourcePath") != path
                   or hook.get("trustStatus") != "trusted"
                   or hook.get("enabled") is not True for hook in others)):
        _fail("untrusted_or_ambiguous_user_hook_readback")
    return {path: events}


def _hooks(rows: list[dict], plan: dict, thread: str,
           user_events: dict[str, set[str]] | None = None) -> None:
    starts = [row["raw"].get("params", {}).get("run", {}) for row in rows
              if row["direction"] == "receive" and row["raw"].get("method")
              == "hook/started" and row["raw"].get("params", {}).get("threadId") == thread]
    dones = [row["raw"].get("params", {}).get("run", {}) for row in rows
             if row["direction"] == "receive" and row["raw"].get("method")
             == "hook/completed" and row["raw"].get("params", {}).get("threadId") == thread]
    if not starts or len(starts) != len(dones):
        _fail("hook_lifecycle_incomplete")
    open_runs: dict[str, tuple[str, str]] = {}
    for row in rows:
        if row["direction"] != "receive" or row["raw"].get("method") not in {
                "hook/started", "hook/completed"}:
            continue
        raw = row["raw"]
        if raw.get("params", {}).get("threadId") != thread:
            _fail("foreign_hook_notification")
        run = raw["params"].get("run", {})
        identity = run.get("id")
        source_path = run.get("sourcePath")
        selected = ((source_path == plan["hook_source"]
                     and run.get("source") == "plugin")
                    or (source_path == plan["capture_hook_source"]
                        and run.get("source") == "sessionFlags"))
        known_user = (user_events is not None and source_path in user_events
                      and run.get("source") == "user"
                      and run.get("eventName") in user_events[source_path])
        if (not isinstance(identity, str) or not identity
                or not (selected or known_user)):
            _fail("unbound_hook_notification")
        if raw["method"] == "hook/started":
            if identity in open_runs or run.get("status") != "running":
                _fail("hook_started_twice")
            open_runs[identity] = (run.get("sourcePath"), run.get("eventName"))
        else:
            if (identity not in open_runs or run.get("status") != "completed"
                    or run.get("statusMessage") is not None
                    or open_runs[identity]
                    != (run.get("sourcePath"), run.get("eventName"))):
                _fail("hook_failed_or_unpaired")
            del open_runs[identity]
    if open_runs:
        _fail("hook_lifecycle_incomplete")


def _capture_bindings(snapshot: dict, plan: dict, thread: str,
                      compact_turn: str, rows: list[dict]) -> str:
    """Match current-session captures to official digest echoes and compaction."""
    root = Path(snapshot["snapshot_root"])
    captures = []
    for name in sorted(n for n in snapshot["files"] if n.endswith(".raw")):
        raw = (root / name).read_bytes()
        event = common._object(raw)
        if event.get("session_id") != thread:
            continue
        meta = common._object((root / name.replace(".raw", ".meta.json")).read_bytes())
        marker = digest_echo(raw, meta["capture_id"])
        matched = [(i, row["raw"]) for i, row in enumerate(rows)
                   if row["direction"] == "receive"
                   and row["raw"].get("method") == "hook/completed"
                   and row["raw"].get("params", {}).get("threadId") == thread
                   and row["raw"].get("params", {}).get("run", {}).get("sourcePath")
                   == plan["capture_hook_source"]
                   and any(entry.get("kind") == "warning"
                           and entry.get("text") == marker
                           for entry in row["raw"]["params"]["run"].get("entries", []))]
        index, notification = _one(matched, "capture_official_hook_echo_missing")
        if (notification["params"]["run"].get("eventName")
                != {"SessionStart": "sessionStart", "PreCompact": "preCompact"}.get(
                    event.get("hook_event_name"))):
            _fail("capture_event_mismatched_hook")
        captures.append((index, event))
    if (len(captures) != 3
            or [event.get("hook_event_name") for _i, event in captures]
            != ["SessionStart", "PreCompact", "SessionStart"]
            or captures[0][1].get("source") != "startup"
            or captures[1][1].get("trigger") != "auto"
            or captures[1][1].get("turn_id") != compact_turn
            or captures[2][1].get("source") != "compact"):
        _fail("current_session_capture_sequence_changed")
    compact = _one([(i, row["raw"].get("params", {}).get("item", {}))
                    for i, row in enumerate(rows) if row["direction"] == "receive"
                    and row["raw"].get("method") == "item/completed"
                    and row["raw"].get("params", {}).get("threadId") == thread
                    and row["raw"].get("params", {}).get("turnId") == compact_turn
                    and row["raw"].get("params", {}).get("item", {}).get("type")
                    == "contextCompaction"], "real_compaction_item_missing")
    if not captures[0][0] < captures[1][0] < compact[0] < captures[2][0]:
        _fail("capture_compaction_order_changed")
    return compact[1]["id"]


def _source_control(rows: list[dict], plan: dict, result: dict, thread: str) -> tuple[dict, str]:
    turns = _paired(rows, "turn/start")
    if len(turns) != 3 or len(result.get("turn_ids", [])) != 3:
        _fail("three_turn_identity_missing")
    expected = (control.ROOT_REPLY, control.GENERAL_REPLY, control.EXACT_REPLY)
    call_rows = [(i, row["raw"]) for i, row in enumerate(rows)
                 if row["direction"] == "receive" and row["raw"].get("method")
                 == "item/tool/call"]
    calls = []
    turn_ids = []
    for n, (start, request, _reply_index, reply) in enumerate(turns):
        turn = reply["result"].get("turn", {}).get("id")
        turn_ids.append(turn)
        if (not isinstance(turn, str) or turn != result["turn_ids"][n]
                or request.get("params") != {"threadId": thread,
                    "clientUserMessageId": plan[control.CLIENT_IDS[n]],
                    "input": [{"type": "text", "text": plan[control.FOLLOWUPS[n]]}]}
                or (n and start <= _one([
                    i for i, row in enumerate(rows) if row["direction"] == "receive"
                    and row["raw"].get("method") == "turn/completed"
                    and row["raw"].get("params", {}).get("turn", {}).get("id")
                    == turn_ids[n - 1]], "earlier_turn_not_complete"))):
            _fail("turn_request_or_order_changed")
        items = [row["raw"].get("params", {}).get("item", {}) for row in rows
                 if row["direction"] == "receive" and row["raw"].get("method")
                 == "item/completed" and row["raw"].get("params", {}).get("threadId")
                 == thread and row["raw"].get("params", {}).get("turnId") == turn]
        users = [item for item in items if item.get("type") == "userMessage"]
        messages = [item for item in items if item.get("type") == "agentMessage"]
        content = users[0].get("content") if len(users) == 1 else None
        if (len(users) != 1 or users[0].get("clientId") != plan[control.CLIENT_IDS[n]]
                or not isinstance(users[0].get("id"), str) or not users[0]["id"]
                or not isinstance(content, list) or len(content) != 1
                or content[0] != {"type": "text", "text":
                                  plan[control.FOLLOWUPS[n]], "text_elements": []}
                or len(messages) != 1
                or not isinstance(messages[0].get("id"), str) or not messages[0]["id"]
                or messages[0].get("text") != expected[n]):
            _fail("official_turn_messages_changed")
        completed = _one([
            (i, row["raw"].get("params", {}).get("turn", {}))
            for i, row in enumerate(rows) if row["direction"] == "receive"
            and row["raw"].get("method") == "turn/completed"
            and row["raw"].get("params", {}).get("threadId") == thread
            and row["raw"].get("params", {}).get("turn", {}).get("id") == turn],
            "turn_completion_missing")
        if completed[1].get("status") != "completed" or completed[1].get("error") is not None:
            _fail("turn_failed")
        if n < 2 and any(item.get("type") in {"commandExecution", "fileChange",
                                                 "webSearch", "mcpToolCall"}
                         for item in items):
            _fail("business_tool_before_confirmation")
        user_index = _one([
            i for i, row in enumerate(rows) if row["direction"] == "receive"
            and row["raw"].get("method") == "item/completed"
            and row["raw"].get("params", {}).get("threadId") == thread
            and row["raw"].get("params", {}).get("turnId") == turn
            and row["raw"].get("params", {}).get("item", {}).get("id")
            == users[0].get("id")], "user_delivery_missing")
        message_index = _one([
            i for i, row in enumerate(rows) if row["direction"] == "receive"
            and row["raw"].get("method") == "item/completed"
            and row["raw"].get("params", {}).get("threadId") == thread
            and row["raw"].get("params", {}).get("turnId") == turn
            and row["raw"].get("params", {}).get("item", {}).get("id")
            == messages[0].get("id")], "answer_delivery_missing")
        if not start < user_index < message_index < completed[0]:
            _fail("turn_message_order_changed")
        matching = [(i, raw) for i, raw in call_rows
                    if raw.get("params", {}).get("turnId") == turn]
        tools = [wire.parse_call(raw, thread=thread, turn=turn) for _i, raw in matching]
        if [tool.tool for tool in tools] != ([wire.READY] if n < 2 else
                                           [wire.READY, wire.CHALLENGE, wire.BUSINESS]):
            _fail("premature_or_missing_business")
        for (call_index, _raw), call in zip(matching, tools):
            response = wire.response(call, {"ready": True}) if call.tool == wire.READY else None
            sent = [(i, row["raw"]) for i, row in enumerate(rows)
                    if row["direction"] == "send" and row["raw"].get("id")
                    == call.request_id and "method" not in row["raw"]]
            response_index, recorded = _one(sent, "tool_result_missing")
            send_complete = _one([
                i for i, row in enumerate(rows) if row["direction"] == "send_complete"
                and row["raw"] == recorded], "tool_result_send_unconfirmed")
            started = _one([
                i for i, row in enumerate(rows) if row["direction"] == "receive"
                and row["raw"].get("method") == "item/started"
                and row["raw"].get("params", {}).get("threadId") == thread
                and row["raw"].get("params", {}).get("turnId") == turn
                and row["raw"].get("params", {}).get("item", {}).get("id")
                == call.call_id
                and row["raw"]["params"]["item"].get("type") == "dynamicToolCall"],
                "dynamic_tool_start_missing")
            terminal = _one([
                i for i, row in enumerate(rows) if row["direction"] == "receive"
                and row["raw"].get("method") == "item/completed"
                and row["raw"].get("params", {}).get("threadId") == thread
                and row["raw"].get("params", {}).get("turnId") == turn
                and row["raw"].get("params", {}).get("item", {}).get("id")
                == call.call_id
                and row["raw"]["params"]["item"].get("type") == "dynamicToolCall"
                and row["raw"]["params"]["item"].get("status") == "completed"
                and row["raw"]["params"]["item"].get("success") is True],
                "dynamic_tool_terminal_missing")
            if not (user_index < started < call_index < response_index
                    < send_complete < terminal < completed[0]):
                _fail("tool_response_out_of_order")
            if response is not None and recorded != response:
                _fail("ready_response_changed")
            calls.append((call_index, call, recorded))
    if len(set(turn_ids)) != 3 or len(call_rows) != 5:
        _fail("unexpected_turn_or_tool")
    completed_dynamic = [row["raw"]["params"]["item"].get("id") for row in rows
                         if row["direction"] == "receive"
                         and row["raw"].get("method") == "item/completed"
                         and row["raw"].get("params", {}).get("threadId") == thread
                         and row["raw"].get("params", {}).get("item", {}).get("type")
                         == "dynamicToolCall"]
    if sorted(completed_dynamic) != sorted(call.call_id for _i, call, _r in calls):
        _fail("unbound_dynamic_tool_terminal")
    challenge = calls[3][1]
    challenge_response = calls[3][2]
    try:
        challenge_obj = json.loads(challenge_response["result"]["contentItems"][0]["text"])
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise ControlReplayError("challenge_response_invalid") from exc
    expected_basis = _digest((thread + ":" + turn_ids[2] + ":"
                             + plan["exact_prompt"]).encode())
    if (set(challenge_obj) != {"schema", "nonce", "commentary_pair_sha256"}
            or challenge_obj["schema"] != "cg-business-challenge/v1"
            or not re.fullmatch(r"[0-9a-f]{64}", challenge_obj["nonce"])
            or challenge_obj["commentary_pair_sha256"] != expected_basis
            or challenge_response != wire.response(challenge, challenge_obj)):
        _fail("challenge_not_bound_to_exact_marker")
    business = calls[4][1]
    if business.arguments["nonce"] != challenge_obj["nonce"]:
        _fail("business_nonce_changed")
    expected_business, _report = fixture.business_result(plan["values"], challenge_obj)
    if (calls[4][2] != wire.response(business, expected_business)
            or common._object(common._read_unpinned(
                Path(plan["run_dir"]) / "business-result.json", 65536))
            != expected_business):
        _fail("business_result_changed")
    # The collector must have completed its fixed three-turn contract, rather
    # than merely returning a matching status string in a fabricated result.
    if (result.get("status") != "source_controls_observed"
            or result.get("native_acceptance") != "not_established"
            or result.get("business_requests") != 1
            or result.get("source_bound_business") is not True
            or result.get("reviewer_calls") != 0):
        _fail("original_control_result_unfit")
    return challenge_obj, business.call_id


def _cold_state(plan: dict, thread: str) -> dict:
    session = (Path(plan["codex_home"]) / "plugins/data"
               / f"context-guard-{plan['namespace']}" / "sessions" / thread)
    state = common._object(common._read_unpinned(session / "state.json", 2 * 1024 * 1024))
    if state.get("session", {}).get("id") != thread:
        _fail("cold_session_identity_changed")
    future = Path(plan["future_path"])
    roots = [row for row in state.get("requirements", [])
             if row.get("text") == plan["root_prompt"] and row.get("status") == "pending"]
    root = _one(roots, "future_root_requirement_missing")
    clauses = root.get("clause_metadata", {}).get("clauses", [])
    matches = [row for row in clauses if future.name in row.get("clause", "")
               and isinstance(row.get("subjectId"), list)
               and len(row["subjectId"]) == 1]
    future_id = _one(matches, "future_clause_identity_missing")["subjectId"][0]
    c2_future_preserved(state, plan["root_prompt"], future_id, future)
    waits = [row for row in state.get("wait_conditions", [])
             if row.get("condition_type") == "exact_input"
             and row.get("raised_by_source") == "P0001"]
    wait = _one(waits, "exact_wait_missing")
    main_clauses = [row for row in clauses if row.get("operation") == "test_verify"
                    and "CG142-CONFIRM-17" in row.get("clause", "")]
    main_clause = _one(main_clauses, "main_clause_identity_missing")["clause"]
    main_sentence = _one([part.strip() for part in plan["root_prompt"].split("。")
                          if main_clause in part], "main_wait_source_missing")
    if (c2_wait_status(state, wait["condition_id"]) != "released"
            or wait.get("raised_by_kind") != "root_user"
            or wait.get("subject_sha256") != _digest(b"CG142-CONFIRM-17")
            or wait.get("source_clause_sha256") != _digest(main_sentence.encode())
            or wait.get("released_by_kind") != "root_user_confirmation"
            or wait.get("released_by_source") != "P0003"
            or len(list((session / "prompts").glob("P*.json"))) != 3):
        _fail("exact_release_or_future_state_changed")
    return {"root_id": root["id"], "future_subject": future_id,
            "wait_id": wait["condition_id"], "future_pending": True}


def replay(manifest_path: Path) -> dict[str, Any]:
    manifest_raw = common._read_unpinned(manifest_path, 8192)
    manifest, plan, result, journal = _read_inputs(
        manifest_path, common._object(manifest_raw)["original_source_commit"])
    source_manifest = common._object(_descriptor(manifest, "source_manifest", 1024 * 1024))
    files = source_manifest.get("files")
    if (source_manifest.get("base_commit") != manifest["original_source_commit"]
            or source_manifest.get("source_tree_sha256") != plan["source_tree_sha256"]
            or source_manifest.get("runtime_tree_sha256") != plan["runtime_tree_sha256"]
            or not isinstance(files, dict)
            or _digest(fixture.canonical(files)) != plan["source_tree_sha256"]):
        _fail("original_source_manifest_changed")
    mapper_root = Path(__file__).resolve().parents[2]
    source_delta = None
    if "source_delta" in manifest:
        source_delta = common._verify_source_delta(
            manifest, plan, files,
            common._object(_descriptor(manifest, "source_delta", 65536)), mapper_root)
    else:
        projection = (common._object(_descriptor(manifest, "checkout_projection", 65536))
                      if "checkout_projection" in manifest else None)
        common._verify_checkout_source(manifest, plan, files, projection, mapper_root)
    if any(_digest(common._read_unpinned(mapper_root / name, 2 * 1024 * 1024))
           != files.get(name) for name in ORIGINAL_COMPONENTS):
        _fail("original_collector_or_oracle_bytes_changed")
    # The pinned C2 collector appends and flushes each JSONL row in call order,
    # but its legacy rows lack record_index. Windows monotonic_ns may tie;
    # physical line order plus the independent RPC/Hook bindings is authoritative.
    rows = common._rpc(journal, allow_legacy_equal_ticks=True)
    if (_digest(Path(plan["codex"]).read_bytes()) != plan["binary_sha256"]
            or measure_runtime(Path(plan["runtime_root"]))[0]
            != plan["runtime_tree_sha256"]):
        _fail("host_binary_or_runtime_changed")
    init = _one(_paired(rows, "initialize"), "initialize_missing")[3]["result"]
    codex_version = common._official_codex_version(init, plan["codex_home"])
    host_os = common._official_host_os(init, platform.system().lower())
    config = _one(_paired(rows, "config/read"), "config_read_missing")[3]["result"]
    hooks_response = _one(_paired(rows, "hooks/list"), "hooks_list_missing")[3]["result"]
    items = hooks_response.get("data")
    if not isinstance(items, list) or len(items) != 1:
        _fail("official_hook_readback_missing")
    common._verify_hook_readback(items[0], plan)
    if (config.get("config", {}).get("model_auto_compact_token_limit") != 4096
            or config.get("config", {}).get("model_auto_compact_token_limit_scope")
            != "body_after_prefix"):
        _fail("effective_config_changed")
    thread_pair = _one(_paired(rows, "thread/start"), "thread_start_missing")
    thread = thread_pair[3]["result"].get("thread", {}).get("id")
    if (not isinstance(thread, str) or not thread
            or Path(manifest["closures"]["session"]["root"]).name != thread):
        _fail("session_closure_subject_mismatch")
    snapshot = _snapshot(_descriptor(manifest, "capture_snapshot", 65536), plan, thread)
    _hooks(rows, plan, thread, _user_hook_events(items[0], plan, rows))
    challenge, business_id = _source_control(rows, plan, result, thread)
    compaction_id = _capture_bindings(snapshot, plan, thread,
                                      result["turn_ids"][2], rows)
    prior_home, prior_trace = os.environ.get("CODEX_HOME"), os.environ.get("CODEX_ROLLOUT_TRACE_ROOT")
    try:
        os.environ["CODEX_HOME"] = plan["codex_home"]
        os.environ["CODEX_ROLLOUT_TRACE_ROOT"] = plan["trace_root"]
        observer = NativeObserver(plan)
        observer.business_source(thread, result["turn_ids"][2], business_id,
                                 _one([r["raw"]["params"]["callId"] for r in rows
                                       if r["direction"] == "receive"
                                       and r["raw"].get("method") == "item/tool/call"
                                       and r["raw"].get("params", {}).get("tool")
                                       == wire.CHALLENGE], "challenge_call_missing"),
                                 challenge)
        source = observer._snapshot(thread)
        compactions = [event for event in source["events"]
                       if event.get("thread_id") == thread
                       and event.get("codex_turn_id") == result["turn_ids"][2]
                       and event.get("payload", {}).get("type")
                       == "compaction_request_completed"]
        if len(compactions) != 1:
            _fail("compaction_trace_missing_or_repeated")
        request_id = compactions[0]["payload"].get("compaction_request_id")
        _request, _response, proof = observer.trace.attempt_pair(
            source["events"], source["payloads"], kind="compaction",
            call_id=request_id, thread=thread, turn=result["turn_ids"][2])
        if proof.get("compaction_id") != compaction_id:
            _fail("compaction_trace_item_mismatch")
        cold = _cold_state(plan, thread)
    finally:
        for name, previous in (("CODEX_HOME", prior_home),
                               ("CODEX_ROLLOUT_TRACE_ROOT", prior_trace)):
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
    adapter = _suite_adapter(manifest, plan)
    if ((host_os == "windows") != (adapter["suite_oracle"]["platform"] == "windows")):
        _fail("suite_platform_host_mismatch")
    suite = commentary_suite_oracle.verify_suite(
        rows, adapter, thread, result["turn_ids"][2], business_id)
    if not suite["completed_before_turn_end"]:
        _fail("suite_not_completed")
    suite_index = _one([
        i for i, row in enumerate(rows) if row["direction"] == "receive"
        and row["raw"].get("method") == "item/completed"
        and row["raw"].get("params", {}).get("threadId") == thread
        and row["raw"].get("params", {}).get("turnId") == result["turn_ids"][2]
        and row["raw"].get("params", {}).get("item", {}).get("id")
        == suite["item_id"]], "suite_terminal_missing")
    answer_index = _one([
        i for i, row in enumerate(rows) if row["direction"] == "receive"
        and row["raw"].get("method") == "item/completed"
        and row["raw"].get("params", {}).get("threadId") == thread
        and row["raw"].get("params", {}).get("turnId") == result["turn_ids"][2]
        and row["raw"].get("params", {}).get("item", {}).get("type")
        == "agentMessage"], "exact_answer_missing")
    if suite_index >= answer_index:
        _fail("success_claim_preceded_suite")
    cleanup = result.get("cleanup", {})
    group_absent = None if host_os == "windows" else True
    if (set(cleanup) != {"owned_process_exited", "process_group_kill_attempted",
                        "process_group_cleanup_error", "owned_tree_empty",
                        "owned_tree_no_running_members", "process_group_absent",
                        "process_group_signal_denied", "process_group_query_denied",
                        "escaped_descendants"}
            or cleanup.get("owned_process_exited") is not True
            or cleanup.get("process_group_kill_attempted") is not True
            or cleanup.get("owned_tree_empty") is not True
            or cleanup.get("owned_tree_no_running_members") is not True
            or cleanup.get("process_group_absent") is not group_absent
            or cleanup.get("process_group_cleanup_error") is not None
            or cleanup.get("process_group_signal_denied") is not False
            or cleanup.get("process_group_query_denied") is not False
            or files.get("scripts/cg_process_tree.py") != _digest(
                common._read_unpinned(mapper_root / "scripts/cg_process_tree.py",
                                      2 * 1024 * 1024))):
        _fail("owned_cleanup_unverified")
    _closures(manifest, plan)
    gates = [common._gate(name, "passed") for name in (
        "host_identity", "official_hook_trust", "capture_integrity",
        "three_turn_control", "source_bound_business", "auto_compaction",
        "suite_execution",
        "future_cold_readback", "owned_cleanup")]
    for gate in gates:
        gate.update({"subject": {"kind": "runtime_tree", "id": plan["runtime_tree_sha256"]},
                     "exit_code": 0,
                     "evidence": {"mode": "reviewed_raw_replay",
                                  "source_result_sha256": manifest["result"]["sha256"],
                                  "source_gate_id": None,
                                  "invalidation_reason": "input_or_mapper_changed"}})
    mapper_commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=mapper_root,
                                   check=True, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                                cwd=mapper_root, check=True, capture_output=True,
                                text=True).stdout.strip())
    closure, count = common._mapper_closure(mapper_root)
    return {"schema": "native-acceptance/v2", "status": "passed",
            "native_acceptance": "passed", "product": "codex_context_guard",
            "gate_profile": PROFILE,
            "repository": {"commit": manifest["original_source_commit"]},
            "original_source_commit": manifest["original_source_commit"],
            "prepared_source_sha256": plan["source_tree_sha256"],
            **({"source_delta": source_delta} if source_delta else {}),
            "runtime_tree_sha256": plan["runtime_tree_sha256"],
            "platform": {"os": host_os, "shell": "python-subprocess",
                         "toolchain": {"python": platform.python_version(),
                                       "codex": codex_version},
                         "codex_binary_sha256": plan["binary_sha256"]},
            "mapper_source_commit": mapper_commit, "mapper_candidate_dirty": dirty,
            "mapper_sha256": _digest(Path(__file__).read_bytes()),
            "mapper_closure_sha256": closure, "mapper_file_count": count,
            "input_manifest_sha256": _digest(manifest_raw),
            "control": {"thread_id": thread, "turn_count": 3,
                        "business_call_id": business_id, "suite": suite,
                        "cold": cold, "original_collector_native_acceptance":
                        result["native_acceptance"]},
            "gates": gates,
            "cleanup": {"status": "passed", "remaining_ids": [],
                        "evidence_basis": "original_supervised_runner_owned_process_close",
                        "escaped_descendants": "not_established"},
            "threshold_calibrated": False,
            "unperformed_actions": ["commit", "push", "merge", "tag", "release",
                                    "public_promotion", "model_rerun"]}
