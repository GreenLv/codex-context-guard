"""Shared independent native checks for current and retained source subjects.

The caller supplies its independently bound producer helpers. The default
state check remains exact equality; an explicit bound preimage selects the
versioned lifecycle relation without changing any other evidence gate.
"""

import platform
import re
import sys
from pathlib import Path

BASELINE_FUNCTION_SHA256 = (
    "82285d3845da5d06bc4bb0c8726d07e6a05abfe255d880baf0b1b748f27f031b"
)


def verify_core(
    e78, ctx, plan, output, *, preimage_path=None, extra_required_evidence=frozenset()
):
    """Shared exact-check core; e78 is the unmodified original producer module."""
    CONFIG_REFRESH, ENTRY, PLAN, REPORT = (
        e78.CONFIG_REFRESH,
        e78.ENTRY,
        e78.PLAN,
        e78.REPORT,
    )
    require, require_reviewed_cli = e78.require, e78.require_reviewed_cli
    sha, producer_path, diagnostic_path = (
        e78.sha,
        e78.producer_path,
        e78.diagnostic_path,
    )
    strict_read_json, strict_read_jsonl = e78.strict_read_json, e78.strict_read_jsonl
    cleanup_confirmed, client_cleanup_confirmed = (
        e78.cleanup_confirmed,
        e78.client_cleanup_confirmed,
    )
    app_server_argv, selected_backend = e78.app_server_argv, e78.selected_backend
    snapshot, validate_projected_scope = e78.snapshot, e78.validate_projected_scope
    validate_config_refresh_journal = e78.validate_config_refresh_journal
    validate_turn_request_scope = e78.validate_turn_request_scope
    audit_turn_tools, read_command, verify_read_tool = (
        e78.audit_turn_tools,
        e78.read_command,
        e78.verify_read_tool,
    )
    verify_maintained, final_subject_readback = (
        e78.verify_maintained,
        e78.final_subject_readback,
    )
    require(
        extra_required_evidence
        in (
            frozenset(),
            frozenset(
                {
                    "old-after-full-state.json",
                    "post-close-full-state.json",
                    "post-close.json",
                }
            ),
        ),
        "unsupported additional evidence",
    )
    require_reviewed_cli(plan)
    result = strict_read_json(output / "result.json")
    require(
        result.get("schema") == REPORT
        and result.get("config_refresh") == CONFIG_REFRESH
        and plan.get("schema") == PLAN
        and plan.get("config_refresh") == CONFIG_REFRESH
        and result.get("status") in ("provisional_cli_native", "passed_cli_native"),
        "result schema/status differs",
    )
    require(
        result.get("declared_pause") is True
        and type(result.get("login_budget")) is int
        and result.get("login_budget") == 0
        and result.get("platform") == platform.system()
        and result.get("evidence_scope") == "owned app-server real-model CLI threads"
        and result.get("gui") == "unobserved"
        and result.get("cli_version") == plan.get("expected_cli_version")
        and result.get("model") == plan.get("expected_model"),
        "result scope or operator conditions differ",
    )
    gates = result.get("gates", {})
    require(
        all(
            isinstance(gates.get(k), dict) and gates[k].get("status") == "passed"
            for k in (
                "old_model",
                "fresh_model",
                "new_trust",
                "maintained_apply",
                "config_refresh",
            )
        )
        and gates["new_trust"].get("count") == 9,
        "result gates differ",
    )
    require(
        client_cleanup_confirmed(result.get("cleanup")),
        "owned app-server cleanup unconfirmed",
    )
    require(
        "reader_failure" in result["cleanup"]
        and result["cleanup"]["reader_failure"] is None,
        "RPC reader evidence incomplete",
    )
    subject = result.get("subject", {})
    require(
        subject.get("native_plan_sha256")
        == plan.get("_native_plan_sha256")
        == sha(ctx["native_plan_path"])
        and subject.get("producer_sha256") == sha(producer_path()),
        "native producer/plan binding differs",
    )
    require(
        subject.get("diagnostic_sha256")
        == ctx["diagnostic_sha256"]
        == sha(diagnostic_path()),
        "Hook diagnostic helper binding differs",
    )
    require(
        subject.get("helper_closure_sha256")
        == ctx["u"].digest(ctx["daily"]._helper_identities()),
        "helper closure drift",
    )
    evidence = result.get("evidence")
    require(isinstance(evidence, dict), "evidence map missing")
    required = {
        "server.json",
        "old-trust.json",
        "old-state.json",
        "old-after.json",
        "new-trust.json",
        "rpc.jsonl",
        "between-turn-boundary.json",
        "maintained-call.json",
        "official-readback.json",
        "maintained/prepare.json",
        "maintained/apply.json",
        "maintained/verify.json",
        "maintained/apply-events.jsonl",
        "config-refresh.json",
        "config-refresh-attempt.json",
        "config-refresh-outcome.json",
    }
    required |= extra_required_evidence
    optional = {"maintained/verify-after-trust.json", "maintained-verify-call.json"}
    require(
        required <= set(evidence) and set(evidence) <= required | optional,
        "evidence set incomplete",
    )
    for name, expected in evidence.items():
        relative = Path(name)
        require(
            not relative.is_absolute()
            and ".." not in relative.parts
            and sha(output / relative) == expected,
            "evidence changed",
        )
    server = strict_read_json(output / "server.json")
    expected_argv = app_server_argv(plan, ctx["cli"])
    require(
        ctx["app_server_argv"] == expected_argv
        and ctx["windows_backend"] == selected_backend(plan)
        and "windows_backend" in subject
        and "windows_backend" in server
        and subject.get("app_server_argv") == expected_argv
        and subject.get("windows_backend") == selected_backend(plan)
        and server.get("argv") == expected_argv
        and server.get("windows_backend") == selected_backend(plan)
        and server.get("os_backend_observation") == "unobserved",
        "app-server launch binding differs",
    )
    boundary = strict_read_json(output / "between-turn-boundary.json")
    samples = boundary.get("runtime_activity_samples")
    require(
        boundary.get("user_declared_pause") is True
        and isinstance(samples, list)
        and samples
        and samples[-1].get("status") == "clear"
        and all(
            isinstance(row, dict) and row.get("query_cleanup") != "unconfirmed"
            for row in samples
        ),
        "activity/pause boundary not established",
    )
    before = strict_read_json(output / "old-state.json")
    after = strict_read_json(output / "old-after.json")
    old = result["gates"]["old_model"]
    fresh = result["gates"]["fresh_model"]
    prior_official = strict_read_json(output / "official-readback.json")
    require(
        prior_official.get("pluginId") == ENTRY
        and prior_official.get("version") == plan["target_version"]
        and prior_official.get("installed") is True
        and type(prior_official.get("enabled")) is bool
        and prior_official.get("target_source_verified") is True,
        "recorded official readback differs",
    )
    for key in (
        "commit",
        "old_version",
        "target_version",
        "zip_sha256",
        "runtime_sha256",
        "tool_sha256",
        "cli_sha256",
    ):
        require(
            subject.get(key) == plan.get(key), "result subject differs from native plan"
        )
    require(
        type(server.get("pid")) is int and server["pid"] > 0, "invalid owned server PID"
    )
    identities = (
        old.get("thread"),
        fresh.get("thread"),
        old.get("old_turn"),
        old.get("new_turn"),
        fresh.get("turn"),
    )
    require(
        all(
            isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value)
            for value in identities
        )
        and len(set(identities[2:])) == 3,
        "invalid thread or turn identity",
    )
    require(
        server.get("pid")
        == old.get("pid")
        == fresh.get("pid")
        == boundary.get("server_pid")
        and boundary.get("thread") == old.get("thread")
        and old.get("thread") != fresh.get("thread"),
        "server/thread continuity differs",
    )
    require(
        before.get("root") == after.get("root")
        and old.get("old_turn") in before.get("turns", [])
        and old.get("new_turn") in after.get("turns", []),
        "owned state continuation differs",
    )
    ctx["u"].validate_continuity(before["state"], after["state"])
    validate_projected_scope(before, after)
    current = snapshot(ctx, old["thread"])
    require(current["root"] == after["root"], "Guard state root differs")
    if preimage_path is None:
        require(
            current["sha256"] == after["sha256"],
            "Guard state no longer matches validated snapshot",
        )
    else:
        if __package__:
            from .postclose_transition import check_post_close
        else:
            from postclose_transition import check_post_close

        state_proof = check_post_close(
            e78, ctx, after, current, old["thread"], preimage_path
        )

    old_hooks = strict_read_json(output / "old-trust.json")["hooks"]
    new_hooks = strict_read_json(output / "new-trust.json")["hooks"]
    old_src = str(ctx["old_root"] / "hooks/hooks.json")
    new_src = str(ctx["new_root"] / "hooks/hooks.json")
    oldinv = ctx["u"]._inventory({"data": [{"hooks": old_hooks}]}, {old_src: "old"})
    newinv = ctx["u"]._inventory({"data": [{"hooks": new_hooks}]}, {new_src: "new"})
    rows = strict_read_jsonl(output / "rpc.jsonl", 10000)
    require(
        all(row.get("direction") in ("request", "response", "local") for row in rows),
        "RPC journal row malformed",
    )
    marker_names = (
        "old_turn_complete",
        "apply_started",
        "apply_finished",
        "old_continuation_complete",
        "fresh_turn_complete",
    )
    marks = []
    for name in marker_names:
        found = [
            (i, r)
            for i, r in enumerate(rows)
            if r.get("direction") == "local" and r.get("event") == name
        ]
        require(
            len(found) == 1
            and found[0][1].get("pid") == server["pid"]
            and type(found[0][1].get("monotonic_ns")) is int,
            "phase marker missing",
        )
        marks.append(found[0])
    require(
        [i for i, _ in marks] == sorted(i for i, _ in marks)
        and [r["monotonic_ns"] for _, r in marks]
        == sorted(r["monotonic_ns"] for _, r in marks),
        "phase order differs",
    )
    validate_config_refresh_journal(
        ctx,
        rows,
        strict_read_json(output / "config-refresh.json"),
        strict_read_json(output / "config-refresh-attempt.json"),
        strict_read_json(output / "config-refresh-outcome.json"),
        server["pid"],
        old["thread"],
        marks[2][0],
        marks[3][0],
        newinv,
    )
    validate_turn_request_scope(rows, old, fresh)
    call = strict_read_json(output / "maintained-call.json")
    require(
        marks[1][1]["monotonic_ns"]
        <= call["start_ns"]
        <= call["end_ns"]
        <= marks[2][1]["monotonic_ns"],
        "maintained timing differs",
    )
    require(
        cleanup_confirmed(call.get("cleanup")),
        "maintained cleanup unconfirmed",
    )
    expected_call = [
        sys.executable,
        str(ctx["tool"]),
        "--plan",
        str(ctx["maintained_plan"]),
        "--output",
        str(ctx["tool_output"]),
        "--resume",
    ]
    require(
        call.get("argv") == expected_call and call.get("exit_code") in (0, 1),
        "maintained resume command differs",
    )
    followup = {"maintained/verify-after-trust.json", "maintained-verify-call.json"}
    if call["exit_code"] == 1:
        require(followup <= set(evidence), "trust continuation evidence missing")
        verify_maintained(
            ctx, plan, output / "maintained/verify.json", "hook_trust_pending"
        )
        verify_call = strict_read_json(output / "maintained-verify-call.json")
        expected_verify = expected_call[:-1] + [
            "--verify",
            "--verify-output",
            str(ctx["tool_output"] / "verify-after-trust.json"),
        ]
        require(
            verify_call.get("argv") == expected_verify
            and verify_call.get("exit_code") == 0
            and cleanup_confirmed(verify_call.get("cleanup")),
            "verify continuation differs",
        )
    else:
        require(
            not (followup & set(evidence)), "unexpected trust continuation evidence"
        )
    windows = (
        rows[: marks[0][0]],
        rows[marks[2][0] + 1 : marks[3][0]],
        rows[marks[3][0] + 1 : marks[4][0]],
    )
    for window, (thread, turn, inventory, events) in zip(
        windows,
        (
            (old["thread"], old["old_turn"], oldinv, ("userPromptSubmit", "stop")),
            (
                old["thread"],
                old["new_turn"],
                {**oldinv, **newinv},
                ("userPromptSubmit", "stop"),
            ),
            (
                fresh["thread"],
                fresh["turn"],
                newinv,
                ("userPromptSubmit", "stop", "preToolUse", "postToolUse"),
            ),
        ),
    ):
        audit_turn_tools(window, thread, turn, allow_read=(thread == fresh["thread"]))
        for event in events:
            require(
                ctx["u"]._paired(window, inventory, thread, event, turn=turn),
                "actual paired Hook missing",
            )
        starts = [
            r["message"]
            for r in window
            if r.get("direction") == "request"
            and r.get("message", {}).get("method") == "turn/start"
            and r["message"].get("params", {}).get("threadId") == thread
        ]
        require(len(starts) == 1, "turn request missing or duplicated")
        responses = [
            r["message"]
            for r in window
            if r.get("direction") == "response"
            and r.get("message", {}).get("id") == starts[0].get("id")
            and r["message"].get("result", {}).get("turn", {}).get("id") == turn
        ]
        completed = [
            r
            for r in window
            if r.get("direction") == "response"
            and r.get("message", {}).get("method") == "turn/completed"
            and r["message"].get("params", {}).get("threadId") == thread
            and r["message"].get("params", {}).get("turn", {}).get("id") == turn
            and r["message"]["params"]["turn"].get("status") == "completed"
        ]
        require(
            len(responses) == len(completed) == 1,
            "model turn response/completion missing",
        )
    verify_read_tool(
        ctx,
        rows,
        newinv,
        fresh["thread"],
        fresh["turn"],
        read_command(ctx["read_file"].name),
    )
    for thread, turn in (
        (old["thread"], old["old_turn"]),
        (old["thread"], old["new_turn"]),
        (fresh["thread"], fresh["turn"]),
    ):
        completed = [
            r
            for r in rows
            if r.get("direction") == "response"
            and r.get("message", {}).get("method") == "turn/completed"
            and r["message"].get("params", {}).get("threadId") == thread
            and r["message"].get("params", {}).get("turn", {}).get("id") == turn
            and r["message"]["params"]["turn"].get("status") == "completed"
        ]
        require(len(completed) == 1, "completed model turn missing or duplicated")
    config_requests = {}
    provider_checks = []
    for index, row in enumerate(rows):
        message = row.get("message", {})
        if row.get("direction") == "request" and message.get("method") == "config/read":
            require(
                message.get("params")
                in (
                    {"cwd": str(ctx["workspace"]), "includeLayers": False},
                    {"cwd": None, "includeLayers": True},
                ),
                "provider read request differs",
            )
            config_requests[message.get("id")] = message["params"]["includeLayers"]
        elif (
            row.get("direction") == "response" and message.get("id") in config_requests
        ):
            is_layer = config_requests.pop(message["id"])
            if is_layer:
                continue
            expected_fields = {"model_provider", "endpoint_policy", "custom_catalog"}
            if selected_backend(plan) == "mxc":
                expected_fields.add("windows_sandbox")
            require(
                isinstance(message.get("result"), dict)
                and message["result"].get("model_provider") in (None, "openai")
                and set(message["result"]) == expected_fields
                and message["result"].get("endpoint_policy") == "official_default"
                and message["result"].get("custom_catalog") is False
                and (
                    selected_backend(plan) != "mxc"
                    or message["result"].get("windows_sandbox") == "mxc"
                ),
                "provider readback differs",
            )
            provider_checks.append(index)
    require(
        not config_requests
        and len(provider_checks) >= 3
        and any(index < marks[0][0] for index in provider_checks)
        and any(marks[2][0] < index < marks[3][0] for index in provider_checks)
        and any(marks[3][0] < index < marks[4][0] for index in provider_checks),
        "provider configuration readbacks missing for a phase",
    )
    requests = {}
    started = []
    for row in rows:
        msg = row.get("message", {})
        if row["direction"] == "request" and msg.get("method") == "thread/start":
            requests[msg.get("id")] = msg.get("params", {})
        elif row["direction"] == "response" and msg.get("id") in requests:
            params = requests.pop(msg["id"])
            response = msg.get("result", {})
            require(
                params.get("sandbox") == "read-only"
                and params.get("approvalPolicy") == "on-request"
                and response.get("sandbox", {}).get("type") == "readOnly"
                and response.get("approvalPolicy") == "on-request"
                and response.get("modelProvider") == "openai"
                and response.get("model") == plan["expected_model"],
                "sandbox/approval/model binding differs",
            )
            started.append(response.get("thread", {}).get("id"))
    require(
        set(started) == {old["thread"], fresh["thread"]} and len(started) == 2,
        "thread starts differ",
    )
    final_verify = (
        output / "maintained/verify-after-trust.json"
        if (output / "maintained/verify-after-trust.json").exists()
        else output / "maintained/verify.json"
    )
    verify_maintained(ctx, plan, final_verify, "passed")
    final_subject_readback(ctx, plan)
    if preimage_path is not None:
        final = snapshot(ctx, old["thread"])
        require(
            final["root"] == current["root"] and final["sha256"] == current["sha256"],
            "live state drifted after supplemental validation",
        )
        return state_proof
    return True
