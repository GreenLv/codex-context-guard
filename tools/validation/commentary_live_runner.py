#!/usr/bin/env python3
"""Bounded native commentary probe; explicit execution only.

Preflight checks local inputs without starting Codex. Collect uses one owned
official app-server process, one producer turn and at most one reviewer call.
Unknown source evidence fails the run; no retries or synthetic completions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path

from scripts.cg_process_tree import OwnedProcess
from tools.validation import commentary_fixture as fixture
from tools.validation import commentary_runner as legacy
from tools.validation import commentary_suite_oracle as suite_oracle
from tools.validation import commentary_timepoint
from tools.validation.commentary_live_controller import Controller
from tools.validation.commentary_live_observer import NativeObserver

SCHEMA = "cg-commentary-native-plan/v1"
MAX_PLAN = 64 * 1024
MAX_JOURNAL = 14 * 1024 * 1024
MAX_RPC_LINE = 2 * 1024 * 1024
PARTIAL_INSTRUCTIONS = (
    "This is a bounded local acceptance scenario. First call "
    "cg_commentary_acceptance.ready with {{}}. When the user asks the two-part "
    "same-turn question, send exactly one Chinese commentary message: 第一问是 49。 "
    "Leave the second question unanswered. Then call "
    "cg_commentary_acceptance.challenge with {{}}. Use the exact returned nonce "
    "to call cg_commentary_acceptance.business exactly once. After its result, "
    "continue the original user task using the built-in terminal once from the "
    "current working directory to run exactly: {suite_action}. Wait for its "
    "completion and verify exit code zero, one unittest test and OK. Do not run "
    "another suite command. Keep the same turn active; do not issue a final "
    "answer before the suite finishes. Do not use any other tool while the "
    "challenge or business call is pending."
)
SUITE_ACTION_START = "run exactly: "
SUITE_ACTION_END = ". Wait for its completion and verify exit code zero, one unittest test and OK."


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require_remaining(deadline, seconds, stage):
    if deadline - time.monotonic() < seconds:
        raise TimeoutError(stage + "_deadline_reserve")


def deadline_reason(stage, phase):
    missing = {
        "awaiting_answer_evidence": "answer_inference_completion_missing",
        "awaiting_business_evidence": "business_inference_completion_missing",
        "awaiting_compaction_evidence": "matching_compaction_evidence_missing",
        "awaiting_suite": "suite_execution_or_turn_completion_missing",
    }
    return missing.get(phase, stage + "_deadline")


def check_stage_deadline(deadline, stage, phase):
    if time.monotonic() >= deadline:
        raise TimeoutError(deadline_reason(stage, phase))


def advance_pending(controller, send_all):
    if controller.phase == "awaiting_answer_evidence":
        controller.try_answer()
        send_all(controller.drain())
    if controller.phase == "awaiting_business_evidence":
        controller.try_business()
    if controller.phase == "awaiting_compaction_evidence":
        controller.try_compaction()


def _toml(value):
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if type(value) is str:
        return json.dumps(value, ensure_ascii=False)
    if type(value) is list:
        return "[" + ", ".join(_toml(x) for x in value) + "]"
    if type(value) is dict:
        if any(type(k) is not str or not k.isidentifier() for k in value):
            raise ValueError("unsupported_toml_inline_key")
        return "{" + ", ".join(k + " = " + _toml(v) for k, v in value.items()) + "}"
    raise ValueError("unsupported_override_value")


def _hex(value):
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def frozen_suite_action(instructions: str, cwd: str) -> str | None:
    """Extract only the bounded native suite command slot of a fixed template."""
    if (instructions.count(SUITE_ACTION_START) != 1
            or instructions.count(SUITE_ACTION_END) != 1):
        return None
    action = instructions.split(SUITE_ACTION_START, 1)[1].split(
        SUITE_ACTION_END, 1)[0]
    platform = "windows" if os.name == "nt" else "posix"
    argv = suite_oracle._action_argv(action, platform)
    if argv is None or len(argv) != 2:
        return None
    python, suite = argv
    if platform == "windows":
        from pathlib import PureWindowsPath

        normalized_python = suite_oracle._windows_literal_path(python)
        normalized_suite = suite_oracle._windows_literal_path(suite)
        expected_suite = suite_oracle._windows_literal_path(
            str(PureWindowsPath(cwd) / "suite.py"))
        if (normalized_python is None or normalized_suite is None
                or normalized_suite != expected_suite
                or PureWindowsPath(normalized_python).name.lower() != "python.exe"):
            return None
    elif (action != f"{shlex.quote(python)} {shlex.quote(suite)}"
            or not Path(python).is_absolute() or Path(python).name not in {
            "python", "python3", "python3.10", "python3.11", "python3.12",
            "python3.13"}
            or suite != str(Path(cwd) / "suite.py")):
        return None
    return action


def load_plan(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_PLAN:
        raise ValueError("unsafe_plan")
    plan = legacy.decode_object(path.read_bytes())
    if plan.get("schema") != SCHEMA:
        raise ValueError("wrong_plan_schema")
    required_paths = ("codex", "codex_home", "cwd", "runtime_root", "hook_source",
                      "trace_root", "capture_dir", "run_dir", "source_manifest_path",
                      "harness_root")
    if any(type(plan.get(k)) is not str or not Path(plan[k]).is_absolute()
           for k in required_paths):
        raise ValueError("absolute_paths_required")
    if (plan.get("capture_hook_source") != fixture.expected_capture_hook_source(
            plan.get("codex_home"))):
        raise ValueError("unfrozen_capture_hook_source")
    for k in ("binary_sha256", "runtime_tree_sha256", "source_tree_sha256",
              "cold_helper_sha256"):
        if not _hex(plan.get(k)):
            raise ValueError("invalid_subject_digest")
    for k in ("root_prompt", "question", "root_client_id", "question_client_id",
              "main_requirement_text", "developer_instructions"):
        if type(plan.get(k)) is not str or not plan[k]:
            raise ValueError("missing_scenario_field")
    if plan["root_client_id"] == plan["question_client_id"]:
        raise ValueError("reused_client_id")
    if plan.get("review_coverage", "complete") not in {"complete", "partial"}:
        raise ValueError("unsupported_review_coverage")
    if plan.get("review_coverage") == "partial":
        if (plan.get("question") !=
                "请分别告诉我：(1) 7 的平方是多少？(2) 11 的平方是多少？"
                or plan.get("values") != list(range(-64, 64))
                or plan.get("budget") != {"startup": 60, "turn": 240,
                                          "compact": 120, "cleanup": 15}):
            raise ValueError("unfrozen_partial_control_inputs")
        instructions = plan["developer_instructions"]
        action = frozen_suite_action(instructions, plan["cwd"])
        if (action is None or instructions != PARTIAL_INSTRUCTIONS.format(
                suite_action=action)):
            raise ValueError("partial_output_contract_missing")
    if "suite_oracle" in plan:
        if plan.get("review_coverage", "complete") != "complete":
            raise ValueError("suite_oracle_requires_complete_review")
        suite_oracle.validate_suite_plan(plan)
    if (type(plan.get("values")) is not list or not 1 <= len(plan["values"]) <= 256
            or any(type(x) is not int or not -64 <= x <= 63 for x in plan["values"])
            or type(plan.get("overrides")) is not dict
            or type(plan.get("effective_config")) is not dict
            or type(plan.get("threshold_proposal")) is not dict):
        raise ValueError("invalid_fixture_or_config")
    if plan.get("history_mode") != "paginated":
        raise ValueError("paginated_history_required")
    namespace = plan.get("namespace")
    if (type(namespace) is not str
            or not re.fullmatch(r"cg-candidate-[a-z0-9][a-z0-9-]{0,40}", namespace)):
        raise ValueError("candidate_namespace_required")
    if type(plan.get("budget")) is not dict:
        raise ValueError("budget_required")
    budget = legacy.Budget(**plan["budget"])
    if (budget.startup > 60 or budget.turn > 240 or budget.compact > 120
            or budget.cleanup > 15):
        raise ValueError("native_budget_exceeds_frozen_ceiling")
    if (set(plan["threshold_proposal"]) != {"limit", "scope", "status"}
            or type(plan["threshold_proposal"]["limit"]) is not int
            or plan["threshold_proposal"]["limit"] <= 0
            or plan["threshold_proposal"]["scope"] != "body_after_prefix"
            or plan["threshold_proposal"]["status"] !=
            "bounded_proposal_not_token_calibrated"):
        raise ValueError("unmeasured_threshold_must_remain_proposal")
    hashes = plan.get("selected_hook_hashes")
    if (type(hashes) is not dict or len(hashes) != 11
            or any(type(key) is not str or not key or type(value) is not str
                   or not value.startswith("sha256:") or not _hex(value[7:])
                   for key, value in hashes.items())):
        raise ValueError("unfrozen_hook_hashes")
    policy = plan.get("review_policy")
    if (type(policy) is not dict or set(policy) != {"version", "active", "binary", "binary_sha256"}
            or policy["active"] is not True or policy["binary"] != plan["codex"]
            or policy["binary_sha256"] != plan["binary_sha256"]
            or type(policy["version"]) is not str or not policy["version"]):
        raise ValueError("unfrozen_review_policy")
    return plan


def preflight(plan):
    from tools.validation.candidate_namespace import safe_path, source_manifest
    from tools.validation.host_capture import measure_runtime

    root = Path(__file__).resolve().parents[2]
    if os.name not in {"posix", "nt"}:
        raise ValueError("bounded_process_tree_route_unavailable")
    if os.environ.get("CONTEXT_GUARD_DATA_DIR"):
        raise ValueError("foreign_product_data_override")
    for name in ("codex", "codex_home", "cwd", "runtime_root", "hook_source",
                 "trace_root", "capture_dir", "run_dir", "source_manifest_path",
                 "harness_root"):
        path = safe_path(plan[name])
        if name != "run_dir" and not path.exists():
            raise ValueError(name + "_unavailable")
    home = Path(plan["codex_home"])
    if home == Path.home() / ".codex" or home == Path(os.environ.get("CODEX_HOME", "")):
        raise ValueError("daily_or_active_home_forbidden")
    expected_runtime = home / "plugins/cache" / plan["namespace"] / "context-guard/0.14.2"
    if Path(plan["runtime_root"]) != expected_runtime:
        raise ValueError("installed_namespace_mismatch")
    if Path(plan["hook_source"]) != expected_runtime / "hooks/hooks.json":
        raise ValueError("hook_source_mismatch")
    if digest(Path(plan["codex"]).read_bytes()) != plan["binary_sha256"]:
        raise ValueError("official_binary_changed")
    if measure_runtime(Path(plan["runtime_root"]))[0] != plan["runtime_tree_sha256"]:
        raise ValueError("installed_runtime_changed")
    source_manifest(root, Path(plan["source_manifest_path"]),
                    plan["source_tree_sha256"], plan["runtime_tree_sha256"])
    if "suite_oracle" in plan:
        suite_oracle.validate_suite_plan(plan)
    if Path(plan["harness_root"]) != root:
        raise ValueError("external_harness_root_mismatch")
    helper = root / "tools/validation/commentary_fixture.py"
    if digest(helper.read_bytes()) != plan["cold_helper_sha256"]:
        raise ValueError("external_cold_helper_changed")
    if not Path(plan["hook_source"]).is_relative_to(Path(plan["runtime_root"])):
        raise ValueError("foreign_hook_source")
    if (Path(plan["run_dir"]).exists() or Path(plan["run_dir"]).is_symlink()
            or Path(plan["run_dir"]).is_relative_to(root)
            or Path(plan["run_dir"]).is_relative_to(Path(plan["cwd"]))
            or Path(plan["run_dir"]).is_relative_to(Path(plan["runtime_root"]))):
        raise ValueError("unsafe_result_directory")
    config = plan["effective_config"]
    if (config.get("model_auto_compact_token_limit") !=
            plan["threshold_proposal"].get("limit")
            or config.get("model_auto_compact_token_limit_scope") != "body_after_prefix"):
        raise ValueError("unfrozen_auto_compact_config")
    if (plan["overrides"].get("model_auto_compact_token_limit") != config["model_auto_compact_token_limit"]
            or plan["overrides"].get("model_auto_compact_token_limit_scope") != "body_after_prefix"):
        raise ValueError("process_override_mismatch")
    return {"status": "inputs_checked_only", "model_calls": 0,
            "source_tree_sha256": plan["source_tree_sha256"],
            "runtime_tree_sha256": plan["runtime_tree_sha256"],
            "threshold_calibrated": False, "native_acceptance": "not_established"}


class AppServer(legacy.StdioTransport):
    def __init__(self, plan, stderr_path):
        argv = [plan["codex"]]
        for key, value in plan["overrides"].items():
            if type(key) is not str or not key or any(c in key for c in "=\n\r"):
                raise ValueError("invalid_cli_override_key")
            argv.extend(("-c", key + "=" + _toml(value)))
        argv.append("app-server")
        self.errors = stderr_path.open("xb")
        try:
            self.owned = OwnedProcess.spawn(
                argv, cwd=plan["cwd"],
                env={**os.environ, "CODEX_HOME": plan["codex_home"],
                     "CODEX_ROLLOUT_TRACE_ROOT": plan["trace_root"],
                     "PYTHONDONTWRITEBYTECODE": "1"},
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errors,
            )
        except BaseException:
            self.errors.close()
            raise
        self.proc = self.owned.process
        self.queue = queue.Queue(maxsize=legacy.MAX_RECORDS)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def close(self, timeout):
        try:
            return self.owned.close(timeout)
        finally:
            self.errors.close()
            for pipe in (self.proc.stdin, self.proc.stdout):
                if pipe is not None:
                    pipe.close()


def collect(plan, *, execute=False):
    preflight(plan)
    if not execute or plan.get("execute_producer") is not True or plan.get("execute_review") is not True:
        raise ValueError("explicit_producer_and_reviewer_gate_required")
    directory = Path(plan["run_dir"])
    directory.mkdir(mode=0o700)
    plan = {**plan, "run_dir": str(directory)}
    (directory / "plan.json").write_text(
        json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    previous_home = os.environ.get("CODEX_HOME")
    previous_trace = os.environ.get("CODEX_ROLLOUT_TRACE_ROOT")
    os.environ["CODEX_HOME"] = plan["codex_home"]
    os.environ["CODEX_ROLLOUT_TRACE_ROOT"] = plan["trace_root"]
    budget = legacy.Budget(**plan["budget"])
    deadline = time.monotonic() + budget.startup + budget.turn + budget.compact
    stage = "startup"
    stage_deadline = time.monotonic() + budget.startup
    transport = None
    controller = None
    journal_size = 0
    journal_index = 0
    result = {"status": "failed", "reason": "unstarted",
              "native_acceptance": "not_established", "model_calls": "unknown"}
    cold_result = None
    timepoints = {}
    try:
        observer = NativeObserver(plan)
        controller = Controller(plan, observer)
        transport = AppServer(plan, directory / "stderr.log")
        with (directory / "rpc.jsonl").open("xb") as journal:
            def record(direction, raw):
                nonlocal journal_size, journal_index
                journal_index += 1
                line = json.dumps({"direction": direction, "raw": raw,
                                   "monotonic_ns": time.monotonic_ns(),
                                   "record_index": journal_index},
                                  ensure_ascii=True).encode() + b"\n"
                journal_size += len(line)
                if len(line) > MAX_RPC_LINE or journal_size > MAX_JOURNAL:
                    raise ValueError("rpc_journal_budget")
                journal.write(line)
                journal.flush()

            def send_all(requests):
                for request in requests:
                    record("send", request)
                    transport.send(request, timeout=10)
                    record("send_complete", request)
                    controller.sent(request)

            send_all(controller.start())
            while time.monotonic() < deadline:
                if stage == "startup" and controller.phase in {
                    "waiting_ready", "steering", "waiting_challenge",
                    "waiting_business", "awaiting_review",
                }:
                    stage = "turn"
                    stage_deadline = time.monotonic() + budget.turn
                elif stage == "turn" and controller.phase in {
                    "awaiting_auto_compaction", "awaiting_compaction_evidence",
                    "awaiting_cold_recovery",
                }:
                    stage = "compact"
                    stage_deadline = time.monotonic() + budget.compact
                check_stage_deadline(stage_deadline, stage, controller.phase)
                advance_pending(controller, send_all)
                if controller.phase == "awaiting_review":
                    require_remaining(min(deadline, stage_deadline), 65, "review")
                    reviewed = controller.reviewed()
                    if plan.get("suite_oracle"):
                        timepoints["review"] = commentary_timepoint.capture(
                            observer, directory, "review",
                            controller.barrier.chain.evidence["precompact_product"],
                            directory / "rpc.jsonl", controller.business_call_id)
                    if time.monotonic() >= min(deadline, stage_deadline):
                        raise TimeoutError("review_deadline")
                    send_all(reviewed)
                if controller.phase == "awaiting_cold_recovery":
                    require_remaining(min(deadline, stage_deadline), 16, "cold_recovery")
                    cold_result = controller.cold_recovery()
                    if plan.get("suite_oracle"):
                        timepoints["cold"] = commentary_timepoint.capture(
                            observer, directory, "cold",
                            cold_result["evidence"]["cold_product"],
                            directory / "rpc.jsonl",
                            controller.compaction_item["params"]["item"]["id"])
                    if time.monotonic() >= min(deadline, stage_deadline):
                        raise TimeoutError("cold_recovery_deadline")
                    if controller.phase == "complete":
                        result = {"status": "source_chain_observed", **cold_result}
                        break
                raw = transport.receive(0.25)
                if raw is None:
                    raise ValueError("host_eof")
                if raw.get("transport_poll") is True:
                    continue
                if "transport_error" in raw:
                    raise ValueError("host_read_error")
                record("receive", raw)
                send_all(controller.ingest(raw))
                if controller.phase == "turn_completed":
                    if cold_result is None or not plan.get("suite_oracle"):
                        raise ValueError("suite_before_cold_recovery")
                    rows = [json.loads(line) for line in (directory / "rpc.jsonl").read_bytes().splitlines()]
                    suite = suite_oracle.verify_suite(
                        rows, plan, controller.thread, controller.turn,
                        controller.business_call_id)
                    result = {"status": "source_chain_observed", **cold_result,
                              "suite_execution": suite,
                              "timepoint_snapshots": timepoints}
                    break
            else:
                raise TimeoutError(deadline_reason("native_chain", controller.phase))
    except (OSError, ValueError, TypeError, TimeoutError, KeyError) as exc:
        result = {"status": "failed", "reason": type(exc).__name__ + ":" + str(exc),
                  "phase": controller.phase if controller else "observer_startup",
                  "native_acceptance": "not_established"}
    finally:
        try:
            if transport is not None:
                result["cleanup"] = transport.close(budget.cleanup)
                if (not result["cleanup"]["owned_process_exited"]
                        or not result["cleanup"]["owned_tree_no_running_members"]
                        or result["cleanup"]["process_group_cleanup_error"] is not None):
                    result = {**result, "status": "failed",
                              "reason": "owned_process_tree_cleanup_unverified",
                              "native_acceptance": "not_established"}
            (directory / "result.json").write_text(
                json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
        finally:
            for name, prior in (("CODEX_HOME", previous_home),
                                ("CODEX_ROLLOUT_TRACE_ROOT", previous_trace)):
                if prior is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = prior
    return result


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
