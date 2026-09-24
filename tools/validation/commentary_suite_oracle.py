"""Exact, read-only suite execution oracle for a bounded commentary chain."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import Path, PureWindowsPath

from tools.validation.commentary_live_adapter import BUSINESS, TOOL_NAMESPACE


class SuiteEvidenceError(ValueError):
    pass


# The public acceptance fixture's 128 squared rows are the same finite work
# returned by the nonce-bound business tool. Pinning these bytes prevents an
# unrelated same-name script from laundering that tool into the root task.
SUITE_FIXTURE_SHA256 = "e65b96e366fef001a7f8296b9b27b0c6ea2cfc875736339d947e4bc90f3db4e2"


def _action_argv(command: str, platform: str) -> list[str] | None:
    if not isinstance(command, str) or not command:
        return None
    if platform == "posix":
        try:
            return shlex.split(command, posix=True)
        except ValueError:
            return None
    if platform == "windows":
        # The quoted executable needs PowerShell's call operator. No
        # pipelines, expansions, redirection, separators or extra arguments.
        if any(character in command for character in "$`;|<>()\r\n"):
            return None
        token = r"'[^']*'"
        match = re.fullmatch(r"\s*&\s+(" + token + r")\s+(" + token + r")\s*", command)
        if match is None:
            return None
        return [part[1:-1] for part in match.groups()]
    return None


def _windows_literal_path(value: str) -> str | None:
    """Normalize only repeated separators in a literal local drive path."""
    if (not isinstance(value, str) or len(value) < 4
            or not re.fullmatch(r"[A-Za-z]:\\.*", value)
            or any(char in value for char in '/*?"<>|\r\n\0')
            or ':' in value[2:]):
        return None
    parts = [part for part in value[3:].split("\\") if part]
    if not parts or any(part in {".", ".."} or part.endswith((" ", ".")) for part in parts):
        return None
    return value[0].upper() + ":\\" + "\\".join(parts)


def _windows_outer_argv(outer: str) -> tuple[str, list[str]] | None:
    """Parse only the observed quoted pwsh -Command two-argument form."""
    if not isinstance(outer, str):
        return None
    match = re.fullmatch(r'"([^"\r\n]+)" -Command "([^"\r\n]+)"', outer)
    if match is None:
        return None
    shell = _windows_literal_path(match.group(1))
    argv = _action_argv(match.group(2), "windows")
    if shell is None or PureWindowsPath(shell).name.lower() != "pwsh.exe" or argv is None:
        return None
    return shell, argv


def _windows_outer_matches(outer: str, path: str, allowed_python: list[str]) -> bool:
    parsed = _windows_outer_argv(outer)
    if parsed is None or len(parsed[1]) != 2:
        return False
    python, suite = parsed[1]
    return (_windows_literal_path(suite) == _windows_literal_path(path)
            and _windows_literal_path(suite) is not None
            and any(_windows_literal_path(python) == _windows_literal_path(candidate)
                    and _windows_literal_path(python) is not None
                    for candidate in allowed_python))


def validate_suite_plan(plan: dict) -> dict:
    suite = plan.get("suite_oracle")
    if not isinstance(suite, dict) or set(suite) != {
        "path", "sha256", "platform", "allowed_python", "allowed_outer_commands"
    }:
        raise SuiteEvidenceError("suite_oracle_not_frozen")
    path = Path(suite["path"])
    if (not path.is_absolute() or path.name != "suite.py"
            or str(path.parent) != plan.get("cwd")
            or not path.is_file() or path.is_symlink()
            or suite["sha256"] != SUITE_FIXTURE_SHA256
            or hashlib.sha256(path.read_bytes()).hexdigest() != suite["sha256"]):
        raise SuiteEvidenceError("suite_source_changed")
    if (suite["platform"] not in {"posix", "windows"}
            or not isinstance(suite["allowed_python"], list)
            or not 1 <= len(suite["allowed_python"]) <= 3
            or any(not isinstance(v, str) or not v for v in suite["allowed_python"])
            or len(set(suite["allowed_python"])) != len(suite["allowed_python"])
            or not isinstance(suite["allowed_outer_commands"], list)
            or not 1 <= len(suite["allowed_outer_commands"]) <= 3
            or any(not isinstance(v, str) or not v
                   for v in suite["allowed_outer_commands"])):
        raise SuiteEvidenceError("suite_command_scope_invalid")
    for outer in suite["allowed_outer_commands"]:
        if suite["platform"] == "posix":
            try:
                shell_argv = shlex.split(outer, posix=True)
            except ValueError as exc:
                raise SuiteEvidenceError("suite_outer_shell_invalid") from exc
            if (len(shell_argv) != 3
                    or shell_argv[0] not in {"/bin/zsh", "/bin/bash", "/bin/sh"}
                    or shell_argv[1] not in {"-c", "-lc"}
                    or not any(_action_argv(shell_argv[2], "posix") == [python, str(path)]
                               for python in suite["allowed_python"])):
                raise SuiteEvidenceError("suite_outer_shell_invalid")
        else:
            if not _windows_outer_matches(outer, str(path), suite["allowed_python"]):
                raise SuiteEvidenceError("suite_outer_shell_invalid")
    if (plan.get("main_requirement_text") != plan.get("root_prompt")
            or plan["root_prompt"] != f"请运行 {path} 的测试并持续执行直到任务完成。"
            or plan.get("values") != list(range(-64, 64))):
        raise SuiteEvidenceError("suite_not_bound_to_main_work")
    return suite


def suite_item_identity(item: dict, plan: dict) -> str:
    """Bind one command item to the frozen suite, before or after execution."""
    suite = validate_suite_plan(plan)
    if not isinstance(item, dict) or item.get("type") != "commandExecution":
        raise SuiteEvidenceError("suite_invocation_not_bound")
    actions = item.get("commandActions")
    if not isinstance(actions, list) or len(actions) != 1 or not isinstance(actions[0], dict):
        raise SuiteEvidenceError("suite_invocation_not_plain_argv")
    action = actions[0]
    argv = _action_argv(action.get("command"), suite["platform"])
    if argv is None or len(argv) != 2:
        raise SuiteEvidenceError("suite_invocation_not_plain_argv")
    basename = (PureWindowsPath(argv[1]).name if suite["platform"] == "windows"
                else Path(argv[1]).name)
    action_path = (_windows_literal_path(argv[1]) if suite["platform"] == "windows"
                   else argv[1])
    suite_path = (_windows_literal_path(suite["path"])
                  if suite["platform"] == "windows" else suite["path"])
    if basename == "suite.py" and action_path != suite_path:
        raise SuiteEvidenceError("foreign_same_name_suite")
    identity = item.get("id")
    if (basename != "suite.py" or action_path is None or action_path != suite_path
            or action.get("type") != "unknown"
            or not any((_windows_literal_path(argv[0]) == _windows_literal_path(python)
                        if suite["platform"] == "windows" else argv[0] == python)
                       for python in suite["allowed_python"])
            or item.get("command") not in suite["allowed_outer_commands"]
            or item.get("cwd") != plan["cwd"]
            or not isinstance(identity, str) or not identity):
        raise SuiteEvidenceError("suite_invocation_not_bound")
    return identity


def verify_suite(rows: list[dict], plan: dict, thread: str, turn: str,
                 business_call_id: str) -> dict:
    """Derive one successful same-turn suite call from official RPC rows."""
    suite = validate_suite_plan(plan)
    path = suite["path"]
    candidates = {}
    for index, row in enumerate(rows):
        if row.get("direction") != "receive":
            continue
        raw = row.get("raw", {})
        if raw.get("method") not in {"item/started", "item/completed"}:
            continue
        params = raw.get("params", {})
        item = params.get("item", {})
        if item.get("type") != "commandExecution":
            continue
        actions = item.get("commandActions")
        if not isinstance(actions, list) or len(actions) != 1:
            continue
        action = actions[0]
        action_command = action.get("command") if isinstance(action, dict) else None
        argv = _action_argv(action_command, suite["platform"])
        if argv is None or len(argv) != 2:
            if isinstance(action_command, str) and path in action_command:
                raise SuiteEvidenceError("suite_invocation_not_plain_argv")
            continue
        basename = (PureWindowsPath(argv[1]).name if suite["platform"] == "windows"
                    else Path(argv[1]).name)
        if basename != "suite.py":
            if isinstance(action_command, str) and path in action_command:
                raise SuiteEvidenceError("suite_invocation_not_plain_argv")
            continue
        if ((suite["platform"] == "windows" and
             _windows_literal_path(argv[1]) != _windows_literal_path(path))
                or (suite["platform"] == "posix" and argv[1] != path)):
            raise SuiteEvidenceError("foreign_same_name_suite")
        if params.get("threadId") != thread or params.get("turnId") != turn:
            raise SuiteEvidenceError("suite_invocation_not_bound")
        identity = suite_item_identity(item, plan)
        phases = candidates.setdefault(identity, {})
        phase = raw["method"]
        if phase in phases:
            raise SuiteEvidenceError("suite_item_repeated")
        phases[phase] = (index, item)
    if len(candidates) != 1:
        raise SuiteEvidenceError("unique_suite_invocation_missing")
    call_id, phases = next(iter(candidates.items()))
    if set(phases) != {"item/started", "item/completed"}:
        raise SuiteEvidenceError("suite_terminal_missing")
    started_index, started = phases["item/started"]
    completed_index, completed = phases["item/completed"]
    output = completed.get("aggregatedOutput")
    normalized = output.replace("\r\n", "\n") if isinstance(output, str) else ""
    if (started_index >= completed_index
            or started.get("command") != completed.get("command")
            or started.get("cwd") != completed.get("cwd")
            or started.get("status") != "inProgress"
            or completed.get("status") != "completed"
            or completed.get("exitCode") != 0
            or not re.fullmatch(r"\.\n-{70}\nRan 1 test in [0-9]+(?:\.[0-9]+)?s\n\nOK\n",
                                normalized)):
        raise SuiteEvidenceError("suite_execution_not_successful")
    business = [i for i, row in enumerate(rows)
                if row.get("direction") == "receive"
                and row.get("raw", {}).get("method") == "item/completed"
                and row["raw"].get("params", {}).get("threadId") == thread
                and row["raw"].get("params", {}).get("turnId") == turn
                and row["raw"]["params"].get("item", {}).get("type") == "dynamicToolCall"
                and row["raw"]["params"]["item"].get("id") == business_call_id]
    if len(business) != 1 or business[0] >= started_index:
        raise SuiteEvidenceError("suite_not_after_business")
    business_item = rows[business[0]]["raw"]["params"]["item"]
    if (business_item.get("namespace") != TOOL_NAMESPACE
            or business_item.get("tool") != BUSINESS
            or business_item.get("status") != "completed"
            or business_item.get("success") is not True):
        raise SuiteEvidenceError("business_terminal_not_successful")
    hooks = [i for i, row in enumerate(rows) if row.get("direction") == "receive"
             and row.get("raw", {}).get("method") == "hook/completed"
             and (run := row["raw"].get("params", {}).get("run", {})).get("eventName") == "postToolUse"
             and run.get("sourcePath") == plan["hook_source"]
             and re.fullmatch(r"post-tool-use:[0-9]+:" + re.escape(plan["hook_source"])
                              + ":" + re.escape(call_id), str(run.get("id", ""))) is not None]
    terminal = [i for i, row in enumerate(rows) if row.get("direction") == "receive"
                and row.get("raw", {}).get("method") == "turn/completed"
                and row["raw"].get("params", {}).get("threadId") == thread
                and row["raw"].get("params", {}).get("turn", {}).get("id") == turn]
    if (len(hooks) != 1 or len(terminal) != 1
            or not completed_index < hooks[0] < terminal[0]):
        raise SuiteEvidenceError("suite_hook_or_turn_completion_missing")
    hook = rows[hooks[0]]["raw"]["params"]["run"]
    hook_params = rows[hooks[0]]["raw"]["params"]
    completed_turn = rows[terminal[0]]["raw"]["params"]["turn"]
    if (hook_params.get("threadId") != thread
            or hook_params.get("turnId") not in (None, turn)
            or hook.get("status") != "completed" or hook.get("statusMessage") is not None
            or hook.get("source") != "plugin" or hook.get("handlerType") != "command"
            or hook.get("executionMode") != "sync" or hook.get("scope") != "turn"
            or completed_turn.get("status") != "completed"
            or completed_turn.get("error") is not None):
        raise SuiteEvidenceError("suite_hook_or_turn_not_successful")
    return {"schema": "cg-commentary-suite-evidence/v1", "item_id": call_id,
            "item_sha256": hashlib.sha256(json.dumps(
                completed, ensure_ascii=False, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest(),
            "post_hook_id": rows[hooks[0]]["raw"]["params"]["run"]["id"],
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "path_sha256": suite["sha256"], "exit_code": 0,
            "completed_after_business": True,
            "completed_before_turn_end": True}
