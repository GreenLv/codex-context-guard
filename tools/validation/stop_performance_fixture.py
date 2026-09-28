#!/usr/bin/env python3
"""Deterministic synthetic Stop fixtures for performance and regression work.

Every fixture is built through the real hook dispatch path (UserPromptSubmit,
PostToolUse, Stop), so prompt records, work-unit bindings, evidence rows and
integrity digests are exactly what the product itself writes. The generator
never disables a verifier and never injects state JSON by hand.

The shapes mirror public, privacy-reviewed incident dimensions only: item and
evidence counts, root counts and unit counts. No private session text,
identifier or path is reproduced here.

Used by tests (tests/test_stop_performance.py) and by the benchmark entry
point tools/validation/benchmark_stop.py. Standard library only.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_runtime() -> Any:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import context_guard  # noqa: PLC0415 - runtime imported per caller process

    return context_guard


SHAPES: dict[str, dict[str, Any]] = {
    # Short-session control sample.
    "S0": {"preamble_units": 0, "active_roots": 2, "acceptance_first": 2,
           "acceptance_rest": 2, "continuations": 0,
           "evidence": 4, "root_text_builder": "brief"},
    # Incident CGI-2026-046 public shape: 12 human roots, 12 requirements,
    # 98 acceptance items, 200 retained evidence, 3 work units (one active
    # holding nearly all items, two archived roots before it), no controls.
    "S1": {"preamble_units": 2, "active_roots": 10, "acceptance_first": 20,
           "acceptance_rest": 8, "continuations": 0,
           "evidence": 200, "root_text_builder": "review"},
    # Item-count doubling with root count, text length and evidence fixed.
    "S2": {"preamble_units": 2, "active_roots": 10, "acceptance_first": 42,
           "acceptance_rest": 18, "continuations": 0,
           "evidence": 200, "root_text_builder": "review"},
    "S4": {"preamble_units": 2, "active_roots": 10, "acceptance_first": 86,
           "acceptance_rest": 38, "continuations": 0,
           "evidence": 200, "root_text_builder": "review"},
    # Same item count from a few long roots: quotes, code fences, Unicode,
    # path objects and execution clauses expose repeated lexical work.
    "LX": {"preamble_units": 0, "active_roots": 2, "acceptance_first": 30,
           "acceptance_rest": 30, "continuations": 8,
           "evidence": 120, "root_text_builder": "long"},
    # Control catalog, exact markers, pause and supersession.
    "CT": {"preamble_units": 0, "active_roots": 3, "acceptance_first": 4,
           "acceptance_rest": 4, "continuations": 4,
           "evidence": 40, "root_text_builder": "control"},
    # Evidence/proof variety: success, failure, unknown, conflicts.
    "EV": {"preamble_units": 0, "active_roots": 3, "acceptance_first": 4,
           "acceptance_rest": 4, "continuations": 3,
           "evidence": 60, "root_text_builder": "review"},
}

# A pending external-repair review reply (public synthetic wording).
INCIDENT_REPLY = ("本轮复核不通过，仍需修复两项。后续平台验收暂停，等待开发侧交回修复候选。")


def _brief_root(index: int) -> str:
    return (f"修复模块{index}的问题，必须验证修复后的行为。")


def _review_root(index: int, acceptance_lines: list[str]) -> str:
    lines = [f"任务{index}: 修复模块{index}的问题，并完成以下验收。"]
    lines.extend(f"- {text}" for text in acceptance_lines)
    lines.append("完成后运行 tests/ 目录的测试并确认结果。")
    return "\n".join(lines)


def _long_root(index: int, acceptance_lines: list[str]) -> str:
    fence = "```python\nprint('done')\n```"
    quoted = "“不要修改 config/site.yaml”"
    code_path = "scripts/run_"
    check_path = "tools/check_"
    unicode_names = "文件「报告.md」与 `日志.txt` 相邻。"
    lines = [
        f"任务{index}: 继续执行{index}号修复工作，范围见下。",
        fence,
        f"注意 {quoted} 中的约束，不要跳过。",
        f"先运行 {code_path}validate.py，再运行 {check_path}suite.py。",
        unicode_names,
        "修复完成后核对 README.md 与 README.zh-CN.md 的一致性。",
    ]
    lines.extend(f"- {text}" for text in acceptance_lines)
    lines.append("每一步都必须验证输出并记录。")
    return "\n".join(lines)


def _acceptance_line(root_index: int, line_index: int, flavor: str) -> str:
    if flavor == "long":
        return (f"第{line_index}项: 验证模块{root_index}的行为必须与预期一致，"
                f"并确认输出 {line_index} 号样例。")
    return f"验收{line_index}: 必须验证修复{root_index}后第{line_index}项行为正确。"


def _control_root(index: int, acceptance_lines: list[str], suite: str) -> str:
    if index == 0:
        # The executable test root that the persistence control binds.
        return f"继续执行，运行 {suite} 的测试。"
    if index == 1:
        # A standalone persistence marker; attached clauses would break the
        # exact control grammar.
        return "Keep working on this current task until it is complete."
    lines = [f"继续任务{index}: 修复模块{index}的问题，必须验证行为。"]
    lines.extend(f"- {text}" for text in acceptance_lines)
    return "\n".join(lines)


def build_session(
    cg: Any,
    data_dir: str,
    shape_name: str,
    *,
    session_id: str | None = None,
    reply: str = INCIDENT_REPLY,
    cwd: str | None = None,
) -> dict[str, Any]:
    """Drive real dispatch events until the requested shape exists.

    Returns {"session_dir": Path, "session_id": str, "stop_event": dict,
    "counters": {...}} with the fixture's realized dimensions. State filling
    happens here so timing callers only replay the final Stop.
    """
    shape = SHAPES[shape_name]
    session = session_id or f"perf-{shape_name.lower()}"
    tmp = cwd if cwd is not None else data_dir

    def event(kind: str, turn: str, **fields: Any) -> dict[str, Any]:
        return dict(hook_event_name=kind, session_id=session, cwd=tmp,
                    turn_id=turn, **fields)

    cg.dispatch(event("UserPromptSubmit", "t0", prompt="context-guard on"))
    suite = Path(tmp) / "suite.py"
    if not suite.exists():
        suite.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    prompt_count = 0
    for unit_index in range(shape["preamble_units"]):
        prompt_count += 1
        cg.dispatch(event("UserPromptSubmit", f"u{prompt_count}", prompt=(
            f"切换到新任务。准备事项{unit_index}: 确认环境{unit_index}。")))
    root_total = shape["active_roots"]
    for root_index in range(root_total):
        per_root = (shape["acceptance_first"] if root_index == 0
                    else shape["acceptance_rest"])
        acceptance = [_acceptance_line(root_index, i, shape["root_text_builder"])
                      for i in range(1, per_root + 1)]
        if shape["root_text_builder"] == "brief":
            text = _brief_root(root_index)
        elif shape["root_text_builder"] == "long":
            text = _long_root(root_index, acceptance)
        elif shape["root_text_builder"] == "control":
            text = _control_root(root_index, acceptance, str(suite))
        else:
            text = _review_root(root_index, acceptance)
        if root_index == 0 and shape["preamble_units"]:
            text = "切换到新任务。" + text
        prompt_count += 1
        cg.dispatch(event("UserPromptSubmit", f"r{prompt_count}", prompt=text))
    continuations = shape["continuations"]
    while continuations > 0:
        prompt_count += 1
        continuations -= 1
        cg.dispatch(event("UserPromptSubmit", f"c{prompt_count}", prompt=(
            f"继续执行任务，并确认第{prompt_count}步结果。")))

    for i in range(shape["evidence"]):
        cg.dispatch(event("PostToolUse", f"e{i}", tool_name="exec_command",
                          tool_input={"cmd": f"echo step-{i}", "shell": "bash"},
                          tool_response={"exit_code": 0, "output": f"ok-{i}"}))

    directory = Path(tmp) / "sessions" / session
    state = cg.load_state(directory, event("Stop", "t1"))
    projection = cg.current_scope_projection(state, session_dir=directory)
    source_bytes = 0
    for prompt in state.get("prompts", []):
        record = cg.read_prompt_record(directory, prompt)
        if record is not None:
            source_bytes += len(str(record.get("text", "")).encode("utf-8"))
    counters = {
        "prompts": len(state.get("prompts", [])),
        "requirements": len(state.get("requirements", [])),
        "acceptance_items": len(state.get("acceptance_items", [])),
        "evidence": len(state.get("evidence", [])),
        "work_units": len(state.get("work_units", [])),
        "root_controls": len(state.get("root_controls", [])),
        "wait_conditions": len(state.get("wait_conditions", [])),
        "scoped_items": len(projection["scoped_item_ids"]),
        "current_items": len(projection["current_item_ids"]),
        "ancestor_items": len(projection["ancestor_constraint_ids"]),
        "source_bytes": source_bytes,
    }
    return {
        "session_dir": directory,
        "session_id": session,
        "stop_event": event("Stop", "t-final", last_assistant_message=reply),
        "counters": counters,
        "state_integrity": state.get("integrity", {}).get("status"),
    }


def fresh_data_root(base: str, name: str) -> str:
    path = Path(base) / name
    path.mkdir(parents=True, exist_ok=True)
    return str(path)
