"""Versioned single transparent command observation for an explicit host profile.

Exact transparent fixture and official rollout observation only. Does not create
commandExecution items, replace product/state oracles, read HOME, or run a model.
Source tests and observations do not establish native acceptance.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime
from pathlib import Path

from tools.validation import native_cli_adoption as cli
from tools.validation import stop_host_acceptance as base

CONTRACT = "transparent-code-mode-command/v1"
MAX_OUTPUT_TOKENS = 6000
TOOLKIT = (
    "incident_host_acceptance.py",
    "native_code_mode_command.py",
    "native_cli_adoption.py",
    "stop_host_acceptance.py",
)


def fixture(command, cwd):
    base.require(
        isinstance(command, str)
        and command
        and "\n" not in command
        and "\r" not in command,
        "one nonempty command required",
    )
    base.require(
        isinstance(cwd, str) and Path(cwd).is_absolute(), "absolute cwd required"
    )
    args = json.dumps(
        {"cmd": command, "workdir": cwd, "max_output_tokens": MAX_OUTPUT_TOKENS},
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return "const r = await tools.exec_command(" + args + ");text(r);"


def pins(plan, command):
    return {
        "schema": CONTRACT,
        "plan_sha256": cli.digest(plan),
        "toolkit": {n: base.sha(Path(__file__).with_name(n)) for n in TOOLKIT},
        "fixture_sha256": hashlib.sha256(
            fixture(command, plan["cwd"]).encode()
        ).hexdigest(),
    }


def decode(raw):
    base.require(
        isinstance(raw, bytes) and 0 < len(raw) <= 16 * 1024 * 1024,
        "bounded source required",
    )
    rows = [cli.strict_json(line) for line in raw.decode().splitlines()]
    base.require(
        0 < len(rows) <= 10000 and all(isinstance(x, dict) for x in rows),
        "bounded rows required",
    )
    return rows


def ms(value):
    base.require(
        isinstance(value, str)
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", value),
        "millisecond UTC timestamp required",
    )
    return round(
        datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000
    )


def observe(
    *,
    subject,
    plan,
    stage,
    inventory,
    rpc_bytes,
    rollout_bytes,
    rollout_path,
    command,
    rejection=False,
):
    """Caller supplies cataloged originals and an independently bound command.

    This local-capture trust boundary does not authenticate a malicious process
    with write access to the capture. Returned output is private tool telemetry.
    """
    base.require(subject == pins(plan, command), "explicit subject/toolkit differs")
    base.require(
        plan.get("cli_version") == cli.VERSION and plan.get("platform") == "Darwin",
        "candidate requires pinned macOS CLI",
    )
    source = plan.get("source")
    base.require(
        isinstance(source, dict)
        and set(source)
        == {"head", "prepared_source_sha256", "dirty_paths", "renamed_away"}
        and re.fullmatch("[0-9a-f]{40}", source.get("head", ""))
        and re.fullmatch("[0-9a-f]{64}", source.get("prepared_source_sha256", ""))
        and source["dirty_paths"] == source["renamed_away"] == [],
        "clean source identity required",
    )
    for key in ("runtime_sha256", "cli_sha256"):
        base.require(
            isinstance(plan.get(key), str) and re.fullmatch("[0-9a-f]{64}", plan[key]),
            "source identity unavailable",
        )
    rpc, trace = decode(rpc_bytes), decode(rollout_bytes)
    thread, turn, selected = stage["thread"], stage["turn"], stage["rows"]
    base.require(
        type(thread) is str and thread and type(turn) is str and turn,
        "nonempty string thread/turn required",
    )
    # This collector starts its integer counter at one. Request IDs are
    # identities, never numeric coercions; do not invent an upper bound.
    for direction in ("request", "response"):
        ids = []
        for row in rpc:
            if row.get("direction") != direction:
                continue
            message = row.get("message", {})
            if "id" in message or message.get("method") == "thread/start":
                value = message.get("id")
                base.require(
                    type(value) is int and value > 0,
                    "positive integer RPC identity required",
                )
                ids.append(value)
        base.require(len(ids) == len(set(ids)), "ambiguous duplicate RPC identity")

    responses = [r["message"] for r in rpc if r.get("direction") == "response"]
    base.require(
        selected
        and sum(
            cli.canonical(responses[i : i + len(selected)]) == cli.canonical(selected)
            for i in range(len(responses))
        )
        == 1,
        "exact contiguous stage RPC required",
    )
    starts = []
    for i, r in enumerate(rpc):
        m = r.get("message", {})
        if (
            r.get("direction") == "response"
            and m.get("result", {}).get("thread", {}).get("id") == thread
        ):
            requests = [
                x["message"]
                for x in rpc[:i]
                if x.get("direction") == "request"
                and x.get("message", {}).get("id") == m.get("id")
            ]
            base.require(
                type(m.get("id")) is int
                and len(requests) == 1
                and type(requests[0].get("id")) is int
                and requests[0]["id"] == m["id"]
                and requests[0].get("method") == "thread/start"
                and requests[0]["params"].get("cwd") == plan["cwd"],
                "exact thread/start required",
            )
            starts.append(m["result"]["thread"])
    base.require(
        len(starts) == 1 and starts[0].get("path") == rollout_path,
        "server-selected rollout required",
    )
    locator = Path(rollout_path)
    base.require(
        locator.is_absolute()
        and ".." not in locator.parts
        and Path(plan["home"]) / "sessions" in locator.parents,
        "isolated rollout locator required",
    )
    meta = [r["payload"] for r in trace if r.get("type") == "session_meta"]
    base.require(
        len(meta) == 1
        and meta[0].get("id") == thread
        and meta[0].get("cwd") == plan["cwd"]
        and meta[0].get("cli_version") == "0.165.0",
        "rollout session differs",
    )
    active, began, ended, calls, outputs, contexts = None, 0, 0, [], [], []
    for r in trace:
        p = r.get("payload", {})
        kind = p.get("type")
        if r.get("type") == "event_msg" and kind == "task_started":
            base.require(
                active is None and isinstance(p.get("turn_id"), str),
                "overlapping turns",
            )
            active = p["turn_id"]
            began += active == turn
        elif r.get("type") == "event_msg" and kind == "task_complete":
            base.require(active == p.get("turn_id"), "terminal turn differs")
            ended += active == turn
            active = None
        elif active == turn:
            if r.get("type") == "turn_context":
                contexts.append(p)
            elif r.get("type") == "response_item":
                base.require(
                    kind
                    in (
                        "message",
                        "additional_tools",
                        "configuration_update",
                        "reasoning",
                        "custom_tool_call",
                        "custom_tool_call_output",
                        "function_call",
                        "function_call_output",
                        "local_shell_call",
                    ),
                    "unsupported rollout item",
                )
                if kind in ("custom_tool_call", "function_call", "local_shell_call"):
                    calls.append(r)
                elif kind in ("custom_tool_call_output", "function_call_output"):
                    outputs.append(r)
    base.require(
        active is None
        and began == ended == 1
        and len(contexts) == 1
        and contexts[0].get("turn_id") == turn
        and contexts[0].get("cwd") == plan["cwd"],
        "complete unambiguous turn required",
    )
    base.require(
        len(calls) == len(outputs) == 1, "one transparent call/output required"
    )
    base.require(
        trace.index(calls[0]) < trace.index(outputs[0]), "call/output order differs"
    )
    a, b = calls[0]["payload"], outputs[0]["payload"]
    base.require(
        a.get("type") == "custom_tool_call"
        and a.get("name") == "exec"
        and a.get("status") == "completed"
        and a.get("input") == fixture(command, plan["cwd"])
        and isinstance(a.get("call_id"), str)
        and a["call_id"]
        and b.get("type") == "custom_tool_call_output"
        and type(b.get("call_id")) is str
        and b.get("call_id") == a["call_id"],
        "fixture/call binding differs",
    )
    raw = b.get("output")
    match = (
        re.fullmatch(
            r"Script completed\nWall time [0-9]+(?:\.[0-9]+)? seconds\nOutput:\n(.+)",
            raw,
            re.S,
        )
        if isinstance(raw, str)
        else None
    )
    base.require(match is not None, "nested terminal result unavailable")
    result = cli.strict_json(match[1])
    base.require(
        isinstance(result, dict)
        and set(result)
        <= {
            "chunk_id",
            "wall_time_seconds",
            "exit_code",
            "output",
            "original_token_count",
        }
        and type(result.get("exit_code")) is int
        and (result["exit_code"] == 2 if rejection else result["exit_code"] == 0)
        and isinstance(result.get("output"), str)
        and result["output"],
        "successful complete result required",
    )
    if "original_token_count" in result:
        count = result["original_token_count"]
        base.require(
            (type(count) is int or type(count) is float and math.isfinite(count))
            and count >= 0,
            "invalid original token count",
        )
        base.require(
            count <= MAX_OUTPUT_TOKENS, "nested result exceeds fixture token budget"
        )

    base.require(
        not any(
            r.get("params", {}).get("item", {}).get("type") == "commandExecution"
            for r in selected
        ),
        "mixed command domain",
    )
    terminal = [r for r in selected if r.get("method") == "turn/completed"]
    base.require(
        len(terminal) == 1
        and terminal[0]["params"].get("threadId") == thread
        and terminal[0]["params"]["turn"].get("id") == turn
        and terminal[0]["params"]["turn"].get("status") == "completed",
        "completed RPC turn required",
    )
    for row in selected:
        if row.get("method") in ("hook/started", "hook/completed"):
            run = row["params"]["run"]
            base.require(
                type(run.get("displayOrder")) is int and isinstance(run.get("id"), str),
                "invalid raw Hook identity",
            )
    hooks = base.paired_hooks(selected, thread, turn, inventory)
    for name in ("userPromptSubmit", "preToolUse", "postToolUse", "stop"):
        values = [h for h in hooks if h["eventName"] == name]
        base.require(
            len(values) == 1
            and values[0]["status"]
            == ("blocked" if rejection and name == "postToolUse" else "completed"),
            "single completed real Hook required",
        )
        if name == "postToolUse" and not rejection:
            base.require(
                values[0].get("entries") == [], "diagnostic PostToolUse not silent"
            )
    boundaries = [
        r
        for r in selected
        if r.get("method") in ("hook/started", "hook/completed")
        and r.get("params", {}).get("run", {}).get("eventName")
        in ("preToolUse", "postToolUse")
    ]
    base.require(
        [(r["method"], r["params"]["run"]["eventName"]) for r in boundaries]
        == [
            ("hook/started", "preToolUse"),
            ("hook/completed", "preToolUse"),
            ("hook/started", "postToolUse"),
            ("hook/completed", "postToolUse"),
        ],
        "real Hook order differs",
    )
    times = [r.get("emittedAtMs") for r in boundaries]
    low, high = ms(calls[0]["timestamp"]), ms(outputs[0]["timestamp"])
    base.require(
        all(type(t) is int for t in times)
        and [low, *times, high] == sorted([low, *times, high]),
        "call/Hook timestamp fence differs",
    )
    return {
        "schema": CONTRACT + "-observation",
        "scope": "bound_command_observation",
        "subject": subject,
        "call_id": a["call_id"],
        "thread": thread,
        "turn": turn,
        "rpc_sha256": hashlib.sha256(rpc_bytes).hexdigest(),
        "rollout_sha256": hashlib.sha256(rollout_bytes).hexdigest(),
        "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
        "exit_code": result["exit_code"],
        "output": result["output"],
    }


def adoption():
    return {
        "schema": CONTRACT,
        "toolkit": {n: base.sha(Path(__file__).with_name(n)) for n in TOOLKIT},
        "fixture": "one-exec-command-explicit-cwd-text-result/v1",
    }


def validate_plan(plan):
    base.require(
        plan.get("command_observation_contract") == adoption(),
        "explicit code-mode adoption differs",
    )
    base.require(
        plan.get("platform") == "Darwin" and plan.get("cli_version") == cli.VERSION,
        "code-mode host domain differs",
    )
    cli.validate(plan, legacy_versions=set())
    receipt = plan["cli_adoption"]["capability_receipt"]
    documents = cli.validate_schemas(receipt["schema_bundle"])
    doc = documents["v2/ThreadStartResponse.json"]
    cli.fields(doc["properties"]["thread"], doc, ("id", "path"))


def capture(plan, stage, thread_record, rpc_path, command):
    """Read only the exact server-returned synthetic session; no discovery."""
    path = Path(thread_record["path"])
    base.require(
        thread_record.get("id") == stage["thread"]
        and path.is_absolute()
        and Path(plan["home"]) / "sessions" in path.parents,
        "exact isolated rollout required",
    )
    for part in (path, *path.parents):
        base.require(not part.is_symlink(), "rollout symlink refused")
    base.require(
        path.is_file() and path.stat().st_size <= 16 * 1024 * 1024,
        "bounded rollout file required",
    )
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    base.require(
        (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ),
        "rollout changed while reading",
    )
    return {
        "schema": CONTRACT,
        "pins": pins(plan, command),
        "command": command,
        "rpc": rpc_path.read_text(encoding="utf-8"),
        "rollout": raw.decode("utf-8"),
        "rollout_path": str(path),
    }


def consume(evidence, plan, stage, inventory, command, *, rejection=False):
    base.require(
        isinstance(evidence, dict)
        and set(evidence)
        == {"schema", "pins", "command", "rpc", "rollout", "rollout_path"}
        and evidence["schema"] == CONTRACT
        and evidence["command"] == command,
        "closed code-mode evidence required",
    )
    return observe(
        subject=evidence["pins"],
        plan=plan,
        stage=stage,
        inventory=inventory,
        rpc_bytes=evidence["rpc"].encode(),
        rollout_bytes=evidence["rollout"].encode(),
        rollout_path=evidence["rollout_path"],
        command=command,
        rejection=rejection,
    )


def verify_bundle_sources(directory, capture):
    journal = (directory / "rpc/rpc.jsonl").read_bytes()
    for name, stage in capture.get("stages", {}).items():
        if name not in ("status", "unknown", "missing", "readonly"):
            continue
        evidence = stage.get("code_mode_evidence")
        base.require(
            isinstance(evidence, dict) and stage.get("name") == name,
            "named code-mode stage evidence required",
        )
        raw_rpc = evidence["rpc"].encode()
        archive = directory / ("rollout-" + name + ".jsonl")
        base.require(
            raw_rpc.endswith(b"\n")
            and journal.startswith(raw_rpc)
            and archive.is_file()
            and not archive.is_symlink()
            and archive.read_bytes() == evidence["rollout"].encode(),
            "original cataloged RPC/rollout source differs",
        )
