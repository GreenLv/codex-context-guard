"""Zero-model, read-only replay of a completed native commentary run.

This profile derives a bounded chain from the original RPC journal, official
trace, Hook captures and installed product.  A runner's status is never a gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from tools.validation import commentary_fixture as fixture
from tools.validation import commentary_live_runner as runner
from tools.validation.commentary_live_observer import NativeObserver
from tools.validation.host_capture import measure_runtime

SCHEMA = "commentary-native-replay/v2"
PROFILE = "commentary_chain/v1"
GATES = ("host_identity", "official_hook_trust", "answer_delivery",
         "post_answer_business", "auto_compaction", "cold_recovery",
         "owned_cleanup")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ReplayError(ValueError):
    """Contradicted or malformed immutable evidence."""


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read(path: Path, digest: str, limit: int) -> bytes:
    if not HEX64.fullmatch(digest):
        raise ReplayError("invalid_input_digest")
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ReplayError("noncanonical_input_path")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ReplayError("linked_input_path")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ReplayError("input_not_bounded_regular_file")
    raw = path.read_bytes()
    if _digest(raw) != digest:
        raise ReplayError("input_digest_changed")
    return raw


def _read_unpinned(path: Path, limit: int) -> bytes:
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ReplayError("noncanonical_input_path")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ReplayError("linked_input_path")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ReplayError("input_not_bounded_regular_file")
    return path.read_bytes()


def _tree_digest(root: Path, *, max_files: int = 512,
                 max_bytes: int = 32 * 1024 * 1024) -> str:
    if not root.is_absolute() or root != root.resolve(strict=True) or root.is_symlink():
        raise ReplayError("noncanonical_tree_root")
    hashes = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ReplayError("linked_tree_member")
        if path.is_dir():
            continue
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ReplayError("nonregular_tree_member")
        total += info.st_size
        if len(hashes) >= max_files or total > max_bytes:
            raise ReplayError("tree_budget_exceeded")
        hashes[path.relative_to(root).as_posix()] = _digest(path.read_bytes())
    if not hashes:
        raise ReplayError("empty_evidence_tree")
    return _digest(fixture.canonical(hashes))


def _closures(manifest: dict[str, Any], plan: dict[str, Any]) -> None:
    expected = {
        "run": Path(plan["run_dir"]),
        "capture": Path(plan["capture_dir"]),
        "trace": Path(plan["trace_root"]),
    }
    closure = manifest.get("closures")
    if not isinstance(closure, dict) or set(closure) != set(expected) | {"session"}:
        raise ReplayError("evidence_closure_missing")
    for name, root in expected.items():
        item = closure[name]
        if (not isinstance(item, dict) or set(item) != {"root", "sha256"}
                or item["root"] != str(root)
                or _tree_digest(root) != item["sha256"]):
            raise ReplayError("evidence_closure_changed:" + name)
    session_root = Path(closure["session"].get("root", ""))
    product_sessions = (Path(plan["codex_home"]) / "plugins/data"
                        / f"context-guard-{plan['namespace']}" / "sessions")
    if (session_root.parent != product_sessions
            or _tree_digest(session_root) != closure["session"].get("sha256")):
        raise ReplayError("evidence_closure_changed:session")


def _mapper_closure(root: Path) -> tuple[str, int]:
    paths = sorted((root / "tools/validation").glob("*.py"))
    paths += [root / "tools/validation/native-acceptance-v2.schema.json",
              root / "scripts/cg_process_tree.py"]
    hashes = {path.relative_to(root).as_posix():
              _digest(_read_unpinned(path, 2 * 1024 * 1024)) for path in paths}
    return _digest(fixture.canonical(hashes)), len(hashes)


def _object(raw: bytes) -> dict[str, Any]:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ReplayError("duplicate_json_key")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ReplayError("expected_json_object")
    return value


def _gate(name: str, status: str, reason: str | None = None) -> dict[str, Any]:
    return {"id": name, "required": True, "status": status, "reason": reason}


def _one(rows: list[Any], reason: str) -> Any:
    if len(rows) != 1:
        raise ReplayError(reason)
    return rows[0]


def _rpc(journal: bytes) -> list[dict[str, Any]]:
    rows = []
    prior = -1
    for line in journal.splitlines():
        row = _object(line)
        if (set(row) != {"direction", "raw", "monotonic_ns"}
                or row["direction"] not in {"send", "send_complete", "receive"}
                or type(row["monotonic_ns"]) is not int
                or row["monotonic_ns"] <= prior or not isinstance(row["raw"], dict)):
            raise ReplayError("invalid_rpc_journal_order_or_shape")
        prior = row["monotonic_ns"]
        rows.append(row)
    if not rows or len(rows) > 2000:
        raise ReplayError("invalid_rpc_journal_length")
    return rows


def _response(rows, method):
    requests = [(i, r["raw"]) for i, r in enumerate(rows)
                if r["direction"] == "send" and r["raw"].get("method") == method]
    request_index, request = _one(requests, "nonunique_" + method + "_request")
    completions = [(i, r["raw"]) for i, r in enumerate(rows)
                   if r["direction"] == "send_complete" and r["raw"] == request]
    completion_index, _ = _one(completions, "nonunique_" + method + "_send_completion")
    replies = [(i, r["raw"]) for i, r in enumerate(rows)
               if r["direction"] == "receive"
               and r["raw"].get("id") == request.get("id")
               and "method" not in r["raw"]]
    response_index, response = _one(replies, "nonunique_" + method + "_response")
    if not request_index < completion_index < response_index:
        raise ReplayError("rpc_response_before_completed_request")
    if "error" in response or not isinstance(response.get("result"), dict):
        raise ReplayError("failed_" + method + "_response")
    return request, response


def _position(rows, direction, predicate, reason):
    return _one([i for i, row in enumerate(rows)
                 if row["direction"] == direction and predicate(row["raw"])], reason)


def _notifications(rows, method):
    return [r["raw"] for r in rows if r["direction"] == "receive"
            and r["raw"].get("method") == method]


def _verify_hook_readback(data: dict[str, Any], plan: dict[str, Any]) -> None:
    if data.get("cwd") != plan["cwd"] or data.get("errors") or data.get("warnings"):
        raise ReplayError("official_hook_readback_error")
    selected = [h for h in data.get("hooks", []) if h.get("sourcePath") in
                {plan["hook_source"], plan["capture_hook_source"]}]
    product = [h for h in selected if h.get("source") == "plugin"
               and h.get("sourcePath") == plan["hook_source"]]
    captures = [h for h in selected if h.get("source") == "sessionFlags"
                and h.get("sourcePath") == plan["capture_hook_source"]
                and "--digest-echo" in h.get("command", "")]
    if (len(selected) != 11
            or len(product) != 9
            or {h.get("eventName") for h in product} != {
                "preToolUse", "postToolUse", "preCompact", "sessionStart",
                "sessionEnd", "userPromptSubmit", "subagentStart",
                "subagentStop", "stop"}
            or len(captures) != 2
            or {h.get("eventName") for h in captures} != {"preCompact", "sessionStart"}
            or {h.get("key"): h.get("currentHash") for h in selected}
            != plan["selected_hook_hashes"]
            or any(h.get("trustStatus") != "trusted" or h.get("enabled") is not True
                   for h in selected)):
        raise ReplayError("exact_official_hook_trust_missing")


def _official_codex_version(initialized: dict[str, Any], home: str) -> str:
    if initialized.get("codexHome") != home:
        raise ReplayError("official_initialize_home_mismatch")
    agent = initialized.get("userAgent")
    match = re.match(r"^Codex(?: Desktop)?/([0-9]+(?:\.[0-9]+){1,3})(?:\s|$)",
                     agent if isinstance(agent, str) else "")
    return match.group(1) if match else "unknown"


def _verify_owned_cleanup(result: dict[str, Any]) -> None:
    cleanup = result.get("cleanup", {})
    if (result.get("status") != "source_chain_observed"
            or result.get("phase") != "offline_chain_checked"
            or set(cleanup) != {"owned_process_exited", "process_group_kill_attempted",
                                "process_group_cleanup_error", "owned_tree_empty",
                                "owned_tree_no_running_members", "process_group_absent",
                                "process_group_signal_denied", "process_group_query_denied",
                                "escaped_descendants"}
            or cleanup.get("owned_process_exited") is not True
            or cleanup.get("process_group_kill_attempted") is not True
            or cleanup.get("owned_tree_empty") is not True
            or cleanup.get("owned_tree_no_running_members") is not True
            or cleanup.get("process_group_absent") is not True
            or cleanup.get("process_group_cleanup_error") is not None
            or cleanup.get("process_group_signal_denied") is not False
            or cleanup.get("process_group_query_denied") is not False
            or cleanup.get("escaped_descendants") != "not_established"):
        raise ReplayError("owned_cleanup_failed")


def preflight(manifest_path: Path, source_commit: str) -> None:
    """Check frozen local inputs without reading host state or starting a child."""
    manifest = _object(_read_unpinned(manifest_path, 8192))
    if (set(manifest) != {"schema", "original_source_commit", "plan", "result",
                         "journal", "later_cold_receipt", "source_manifest", "closures"}
            or manifest["schema"] != SCHEMA
            or manifest["original_source_commit"] != source_commit):
        raise ReplayError("invalid_replay_manifest")
    for name, limit in (("plan", 65536), ("result", 65536),
                        ("journal", runner.MAX_JOURNAL),
                        ("later_cold_receipt", 65536),
                        ("source_manifest", 1024 * 1024)):
        item = manifest[name]
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ReplayError("invalid_input_descriptor")
        _read(Path(item["path"]), item["sha256"], limit)
    plan = runner.load_plan(Path(manifest["plan"]["path"]))
    if (Path(plan["run_dir"]) / "rpc.jsonl" != Path(manifest["journal"]["path"])
            or Path(plan["run_dir"]) / "result.json" != Path(manifest["result"]["path"])):
        raise ReplayError("run_paths_mismatch")
    if Path(plan["source_manifest_path"]) != Path(manifest["source_manifest"]["path"]):
        raise ReplayError("source_manifest_path_mismatch")
    _closures(manifest, plan)


def replay(manifest_path: Path) -> dict[str, Any]:
    """Read the original run and return a new source-bound result; never start Codex."""
    manifest_raw = _read_unpinned(manifest_path, 8192)
    manifest = _object(manifest_raw)
    if set(manifest) != {"schema", "original_source_commit", "plan", "result",
                         "journal", "later_cold_receipt", "source_manifest",
                         "closures"} or manifest["schema"] != SCHEMA:
        raise ReplayError("invalid_replay_manifest")
    inputs = {}
    for name, limit in (("plan", 65536), ("result", 65536),
                        ("journal", runner.MAX_JOURNAL),
                        ("later_cold_receipt", 65536),
                        ("source_manifest", 1024 * 1024)):
        item = manifest[name]
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ReplayError("invalid_input_descriptor")
        inputs[name] = _read(Path(item["path"]), item["sha256"], limit)
    plan = runner.load_plan(Path(manifest["plan"]["path"]))
    result = _object(inputs["result"])
    later = _object(inputs["later_cold_receipt"])
    run_dir = Path(plan["run_dir"])
    if (run_dir != Path(manifest["result"]["path"]).parent
            or run_dir / "rpc.jsonl" != Path(manifest["journal"]["path"])
            or Path(plan["source_manifest_path"])
            != Path(manifest["source_manifest"]["path"])):
        raise ReplayError("run_paths_mismatch")
    if _object(_read_unpinned(run_dir / "plan.json", 65536)) != plan:
        raise ReplayError("runner_written_plan_differs")
    _closures(manifest, plan)
    if not re.fullmatch(r"[0-9a-f]{40}", manifest["original_source_commit"]):
        raise ReplayError("invalid_original_source_commit")
    source_manifest = _object(inputs["source_manifest"])
    source_files = source_manifest.get("files")
    if (source_manifest.get("base_commit") != manifest["original_source_commit"]
            or source_manifest.get("source_tree_sha256") != plan["source_tree_sha256"]
            or source_manifest.get("runtime_tree_sha256") != plan["runtime_tree_sha256"]
            or not isinstance(source_files, dict)
            or _digest(fixture.canonical(source_files)) != plan["source_tree_sha256"]):
        raise ReplayError("original_source_manifest_mismatch")
    if not 1 <= len(source_files) <= 1024:
        raise ReplayError("original_source_file_count")
    for name, digest in source_files.items():
        member = PurePosixPath(name)
        if (not isinstance(name, str) or member.is_absolute()
                or str(member) != name or ".." in member.parts
                or ":" in name or "\\" in name
                or not isinstance(digest, str) or not HEX64.fullmatch(digest)):
            raise ReplayError("unsafe_original_source_member")
        object_bytes = subprocess.run(
            ["git", "show", manifest["original_source_commit"] + ":" + name],
            cwd=Path(__file__).resolve().parents[2], capture_output=True,
            check=False)
        if object_bytes.returncode or _digest(object_bytes.stdout) != digest:
            raise ReplayError("original_commit_source_mismatch")
    original_components = (
        "tools/validation/commentary_live_runner.py",
        "tools/validation/commentary_live_controller.py",
        "tools/validation/commentary_live_observer.py",
        "tools/validation/commentary_chain.py",
        "tools/validation/commentary_fixture.py",
        "tools/validation/commentary_trace.py",
        "tools/validation/host_capture.py",
        "scripts/cg_process_tree.py",
    )
    mapper_root = Path(__file__).resolve().parents[2]
    if any(_digest(_read_unpinned(mapper_root / name, 2 * 1024 * 1024))
           != source_files.get(name) for name in original_components):
        raise ReplayError("original_runner_oracle_bytes_changed")
    rows = _rpc(inputs["journal"])
    gates = []
    if (_digest(Path(plan["codex"]).read_bytes()) != plan["binary_sha256"]
            or measure_runtime(Path(plan["runtime_root"]))[0] != plan["runtime_tree_sha256"]):
        raise ReplayError("host_binary_or_installed_runtime_changed")
    initialize_request, initialize_response = _response(rows, "initialize")
    codex_version = _official_codex_version(initialize_response["result"],
                                             plan["codex_home"])
    config_request, config_response = _response(rows, "config/read")
    thread_start, thread_response = _response(rows, "thread/start")
    turn_start, turn_response = _response(rows, "turn/start")
    thread = thread_response["result"]["thread"]["id"]
    turn = turn_response["result"]["turn"]["id"]
    if Path(manifest["closures"]["session"]["root"]).name != thread:
        raise ReplayError("session_closure_subject_mismatch")
    handshake = [(method, request, response) for method, request, response in (
        ("initialize", initialize_request, initialize_response),
        ("config/read", config_request, config_response),
        ("hooks/list", *_response(rows, "hooks/list")),
        ("thread/start", thread_start, thread_response),
        ("turn/start", turn_start, turn_response),
    )]
    previous_response = -1
    for method, request, _response_value in handshake:
        sent = _position(rows, "send", lambda raw, r=request: raw == r,
                         "missing_" + method + "_send")
        if sent <= previous_response:
            raise ReplayError("out_of_order_handshake")
        previous_response = _position(
            rows, "receive", lambda raw, r=request: raw.get("id") == r.get("id")
            and "method" not in raw,
            "missing_" + method + "_response")
    if (thread_start["params"].get("cwd") != plan["cwd"]
            or turn_start["params"].get("threadId") != thread
            or turn_start["params"].get("clientUserMessageId") != plan["root_client_id"]):
        raise ReplayError("wrong_native_thread_or_turn")
    gates.append(_gate("host_identity", "passed"))
    _hook_request, hook_response = _response(rows, "hooks/list")
    data = _one(hook_response["result"].get("data", []), "wrong_hook_readback_count")
    _verify_hook_readback(data, plan)
    gates.append(_gate("official_hook_trust", "passed"))
    previous_home = os.environ.get("CODEX_HOME")
    previous_trace = os.environ.get("CODEX_ROLLOUT_TRACE_ROOT")
    os.environ["CODEX_HOME"] = plan["codex_home"]
    os.environ["CODEX_ROLLOUT_TRACE_ROOT"] = plan["trace_root"]
    try:
        observer = NativeObserver(plan)
        chain = observer.make_chain(thread, turn)
        chain.configuration(config_request, config_response, thread_start)
        notices = _notifications(rows, "item/completed")
        users = [n for n in notices if n.get("params", {}).get("item", {}).get("type") == "userMessage"]
        answers = [n for n in notices if n.get("params", {}).get("item", {}).get("type") == "agentMessage"
                   and n["params"]["item"].get("phase") == "commentary"]
        source = observer._snapshot(thread)
        matching = []
        for answer in answers:
            try:
                observer.trace.reduce_pair(
                    [*users, *source["events"]], source["payloads"],
                    thread=thread, turn=turn, client_id=plan["question_client_id"],
                    question=plan["question"], commentary=answer)
            except ValueError:
                continue
            matching.append(answer)
        answer = _one(matching, "unique_source_bound_answer_missing")
        main_event = _position(
            rows, "receive", lambda raw: raw.get("method") == "item/completed"
            and raw.get("params", {}).get("item", {}).get("type") == "userMessage"
            and raw["params"]["item"].get("clientId") == plan["root_client_id"],
            "main_user_event_missing_or_repeated")
        question_event = _position(
            rows, "receive", lambda raw: raw.get("method") == "item/completed"
            and raw.get("params", {}).get("item", {}).get("type") == "userMessage"
            and raw["params"]["item"].get("clientId") == plan["question_client_id"],
            "question_user_event_missing_or_repeated")
        answer_event = _position(
            rows, "receive", lambda raw: raw.get("method") == "item/completed"
            and raw.get("params", {}).get("item", {}).get("id")
            == answer["params"]["item"].get("id"),
            "answer_event_missing_or_repeated")
        ready_event = _position(
            rows, "receive", lambda raw: raw.get("method") == "item/tool/call"
            and raw.get("params", {}).get("tool") == "ready",
            "ready_call_missing_or_repeated")
        steer_request, _steer_response = _response(rows, "turn/steer")
        steer_event = _position(rows, "send", lambda raw: raw == steer_request,
                                "steer_send_missing")
        if not main_event < ready_event < steer_event < question_event < answer_event:
            raise ReplayError("answer_not_after_side_question")
        chain.commentary([*users, *source["events"]], source["payloads"],
                         client_id=plan["question_client_id"],
                         question=plan["question"], notification=answer)
        actual_answer = chain.evidence["commentary"]
        original_answer = result.get("evidence", {}).get("commentary", {})
        if (actual_answer.get("pair") != original_answer.get("pair")
                or any(actual_answer.get("payload_hashes", {}).get(key) != value
                       for key, value in original_answer.get("payload_hashes", {}).items())):
            raise ReplayError("answer_result_disagrees_with_raw_source")
        gates.append(_gate("answer_delivery", "passed"))
        challenge = _object(_read_unpinned(run_dir / "challenge.json", 65536))
        chain.business_challenge = challenge
        chain.phase = "challenge_issued"
        calls = [n for n in _notifications(rows, "item/tool/call")
                 if n.get("params", {}).get("threadId") == thread
                 and n.get("params", {}).get("turnId") == turn]
        challenge_call = _one([n for n in calls if n["params"].get("tool") == "challenge"],
                              "challenge_call_missing_or_repeated")["params"]["callId"]
        business_call = _one([n for n in calls if n["params"].get("tool") == "business"],
                             "business_call_missing_or_repeated")["params"]["callId"]
        challenge_event = _position(
            rows, "receive", lambda raw: raw.get("method") == "item/tool/call"
            and raw.get("params", {}).get("callId") == challenge_call,
            "challenge_event_missing")
        business_event = _position(
            rows, "receive", lambda raw: raw.get("method") == "item/tool/call"
            and raw.get("params", {}).get("callId") == business_call,
            "business_event_missing")
        business_reply = _position(
            rows, "send_complete", lambda raw: raw.get("id") ==
            _one([n for n in calls if n["params"].get("tool") == "business"],
                 "business_call_missing_or_repeated").get("id")
            and "method" not in raw, "business_reply_missing")
        if not answer_event < challenge_event < business_event < business_reply:
            raise ReplayError("business_not_after_answer_and_challenge")
        _read_unpinned(run_dir / "business-result.json", 65536)
        source = observer.business_source(thread, turn, business_call, challenge_call, challenge)
        chain.business(plan["values"], run_dir / "business-result.json",
                       call_id=business_call, challenge_call_id=challenge_call, **source)
        if (chain.evidence["business"] != result["evidence"].get("business")
                or chain.evidence["business_inference"] != result["evidence"].get("business_inference")):
            raise ReplayError("business_result_disagrees_with_raw_source")
        gates.append(_gate("post_answer_business", "passed"))
        directory, state = observer._state(thread)
        question_id = result["evidence"]["precompact_product"]["question_id"]
        question_rows = [item for item in state.get("requirements", [])
                         if item.get("id") == question_id]
        question_row = _one(question_rows, "review_question_missing_or_repeated")
        review_request = observer.runtime.answer_review_request(
            directory, state, question_row, codex_home=Path(plan["codex_home"]))
        message_id = actual_answer["pair"]["commentary_id"]
        if (review_request.get("subject", {}).get("session_id") != thread
                or review_request.get("subject", {}).get("turn_id") != turn
                or [item.get("message_id") for item in review_request.get("messages", [])]
                != [message_id]
                or review_request.get("answer_texts", {}).get(message_id)
                != chain.commentary_text):
            raise ReplayError("sealed_review_not_bound_to_answer")
        before = fixture.product_review_checkpoint(
            observer.runtime, state, session_dir=directory,
            codex_home=plan["codex_home"],
            question_id=question_id,
            main_ids=result["evidence"]["precompact_product"]["main_ids"])
        if before != result["evidence"]["precompact_product"]:
            raise ReplayError("review_projection_changed")
        barrier = _object(_read_unpinned(run_dir / "review-barrier.json", 65536))
        if (barrier.get("schema") != "cg-review-barrier/v1"
                or barrier.get("challenge_nonce") != challenge.get("nonce")
                or barrier.get("projection") != before):
            raise ReplayError("review_barrier_not_bound_to_projection")
        chain.question_id = before["question_id"]
        chain.main_ids = before["main_ids"]
        observer.question_id = before["question_id"]
        observer.main_ids = before["main_ids"]
        completed = _one([n for n in notices if n.get("params", {}).get("item", {}).get("type") == "contextCompaction"],
                         "completed_compaction_missing_or_repeated")
        precompact_event = _position(
            rows, "receive", lambda raw: raw.get("method") == "hook/completed"
            and raw.get("params", {}).get("run", {}).get("sourcePath")
            == plan["capture_hook_source"]
            and raw["params"]["run"].get("eventName") == "preCompact",
            "capture_precompact_event_missing")
        completed_event = _position(
            rows, "receive", lambda raw: raw.get("method") == "item/completed"
            and raw.get("params", {}).get("item", {}).get("type")
            == "contextCompaction", "completed_compaction_event_missing")
        compact_start_events = [i for i, row in enumerate(rows)
                                if row["direction"] == "receive"
                                and row["raw"].get("method") == "hook/completed"
                                and row["raw"].get("params", {}).get("run", {}).get("sourcePath")
                                == plan["capture_hook_source"]
                                and row["raw"]["params"]["run"].get("eventName") == "sessionStart"]
        if (len(compact_start_events) != 2 or not business_reply < precompact_event
                < completed_event < compact_start_events[1]):
            raise ReplayError("compaction_order_or_resume_missing")
        captures, source = observer.compaction_source(
            thread, turn, _notifications(rows, "hook/completed"), completed)
        chain.evidence["precompact_product"] = before
        chain.phase = "review_consumed"
        chain.compaction(captures, completed_item=completed, **source)
        if chain.evidence["compaction"] != result["evidence"].get("compaction"):
            raise ReplayError("compaction_result_disagrees_with_raw_source")
        gates.append(_gate("auto_compaction", "passed"))
        if (later.get("original_result_sha256") != manifest["result"]["sha256"]
                or later.get("projection_equal_to_original_precompact") is not True
                or later.get("runtime_tree_sha256") != plan["runtime_tree_sha256"]):
            raise ReplayError("later_cold_receipt_subject_mismatch")
        cold = chain.cold_recovery(observer.cold_reader)
        if cold["evidence"]["cold_product"] != result["evidence"].get("cold_product"):
            raise ReplayError("cold_projection_disagrees_with_original")
        gates.append(_gate("cold_recovery", "passed"))
    finally:
        for key, previous in (("CODEX_HOME", previous_home),
                              ("CODEX_ROLLOUT_TRACE_ROOT", previous_trace)):
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
    _verify_owned_cleanup(result)
    gates.append(_gate("owned_cleanup", "passed"))
    status = "passed" if all(g["status"] == "passed" for g in gates) else "pending"
    mapper_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=mapper_root, capture_output=True,
        text=True, check=True).stdout.strip()
    dirty = bool(subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=mapper_root, capture_output=True, text=True, check=True).stdout.strip())
    mapper_closure_sha256, mapper_file_count = _mapper_closure(mapper_root)
    _closures(manifest, plan)
    for gate in gates:
        gate["subject"] = {"kind": "runtime_tree", "id": plan["runtime_tree_sha256"]}
        gate["exit_code"] = {"passed": 0, "failed": 1, "pending": 3}[gate["status"]]
        gate["evidence"] = {"mode": "reviewed_raw_replay",
                            "source_result_sha256": manifest["result"]["sha256"],
                            "source_gate_id": None,
                            "invalidation_reason": "input_or_mapper_changed"}
    return {"schema": "native-acceptance/v2", "status": status,
            "product": "codex_context_guard", "gate_profile": PROFILE,
            "repository": {"commit": manifest["original_source_commit"]},
            "original_source_commit": manifest["original_source_commit"],
            "prepared_source_sha256": plan["source_tree_sha256"],
            "runtime_tree_sha256": plan["runtime_tree_sha256"],
            "platform": {"os": platform.system().lower(), "shell": "python-subprocess",
                         "toolchain": {"python": platform.python_version(),
                                       "codex": codex_version},
                         "codex_binary_sha256": plan["binary_sha256"]},
            "mapper_source_commit": mapper_commit,
            "mapper_candidate_dirty": dirty,
            "mapper_sha256": _digest(Path(__file__).read_bytes()),
            "mapper_closure_sha256": mapper_closure_sha256,
            "mapper_file_count": mapper_file_count,
            "host_identity_basis": [
                "original_runner_source_manifest", "runner_written_plan",
                "pinned_binary_bytes", "ordered_official_rpc",
                "same_session_official_trace_and_hook_capture"],
            "input_manifest_sha256": _digest(manifest_raw),
            "gates": gates,
            "cleanup": {"status": "passed", "remaining_ids": [],
                        "evidence_basis": "original_supervised_runner_owned_process_close",
                        "escaped_descendants": "not_established"},
            "threshold_calibrated": False,
            "unperformed_actions": ["commit", "push", "merge", "tag", "release",
                                    "public_promotion", "model_rerun"],
            "native_acceptance": status}
