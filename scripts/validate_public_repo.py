#!/usr/bin/env python3
"""Validate the standalone Context Guard repository contract."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

VERSION = "0.8.8"
SCHEMA_VERSION = 7
STOP_PROTOCOL_VERSION = "1.1.0"
CLASSIFIER_VERSION = "2.3.0"
PROOF_PROTOCOL_VERSION = "1.0.0"
PRIVATE_SUCCESS_RECEIPT = "Script completed"
DISPOSITION_REASONS = {
    "continue": "assistant_work_remains",
    "user_wait": "user_action_required",
    "external_wait": "external_dependency",
    "deferred": "denied_or_out_of_scope",
}
REPOSITORY = "https://github.com/GreenLv/codex-context-guard"
HOOK_EVENTS = {
    "UserPromptSubmit",
    "PostToolUse",
    "PreCompact",
    "SessionStart",
    "SubagentStart",
    "SubagentStop",
    "Stop",
    "SessionEnd",
}
REQUIRED_FILES = {
    "AGENTS.md",
    ".codex-plugin/plugin.json",
    ".agents/plugins/marketplace.json",
    ".github/workflows/ci.yml",
    ".github/workflows/hol-plugin-scanner.yml",
    ".github/dependabot.yml",
    ".codexignore",
    "LICENSE",
    "README.md",
    "README.zh-CN.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "CHANGELOG.zh-CN.md",
    "requirements-lock.txt",
    "assets/icon.svg",
    "assets/state.schema.json",
    "docs/ARCHITECTURE.md",
    "docs/PRIVACY.md",
    "docs/COMPATIBILITY.md",
    "docs/LOCAL_ACCEPTANCE.md",
    "docs/VERSIONING.md",
    "hooks/hooks.json",
    "scripts/audit_commit_identity.py",
    "scripts/context_guard.py",
    "scripts/run_context_guard.sh",
    "scripts/run-context-guard.ps1",
    "scripts/manage_plugin.py",
    "scripts/smoke_installed.py",
    "skills/context-guard/SKILL.md",
    "skills/context-guard/agents/openai.yaml",
    "skills/context-guard/references/successor-pack.md",
}
FORBIDDEN_FILES = {
    "docs/BLOG.zh-CN.md",
}


def assigned_literal(tree: ast.Module, name: str) -> object:
    for node in tree.body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            target = node.target
            value = node.value
        if isinstance(target, ast.Name) and target.id == name and value is not None:
            return ast.literal_eval(value)
    raise ValueError(f"missing literal assignment: {name}")


def function_ends_with_success_receipt(
    tree: ast.Module, name: str, receipt: str
) -> bool:
    function = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ),
        None,
    )
    if function is None or len(function.body) < 2:
        return False
    receipt_statement, return_statement = function.body[-2:]
    if not isinstance(receipt_statement, ast.Expr) or not isinstance(
        receipt_statement.value, ast.Call
    ):
        return False
    call = receipt_statement.value
    if not isinstance(call.func, ast.Name) or call.func.id != "print":
        return False
    if len(call.args) != 1 or not isinstance(call.args[0], ast.Constant):
        return False
    if call.args[0].value != receipt:
        return False
    return (
        isinstance(return_statement, ast.Return)
        and isinstance(return_statement.value, ast.Constant)
        and return_statement.value.value == 0
    )


def enum_sets(value: object) -> list[set[str]]:
    found: list[set[str]] = []
    if isinstance(value, dict):
        enum = value.get("enum")
        if isinstance(enum, list) and all(isinstance(item, str) for item in enum):
            found.append(set(enum))
        for child in value.values():
            found.extend(enum_sets(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(enum_sets(child))
    return found


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    for relative in sorted(REQUIRED_FILES):
        if not (root / relative).is_file():
            errors.append(f"missing required file: {relative}")
    for relative in sorted(FORBIDDEN_FILES):
        if (root / relative).exists():
            errors.append(
                f"publishing material must stay outside the public tree: {relative}"
            )

    codexignore_path = root / ".codexignore"
    if codexignore_path.is_file():
        ignored = {
            line.strip()
            for line in codexignore_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        for required_pattern in {".git", ".git/"}:
            if required_pattern not in ignored:
                errors.append(
                    ".codexignore must exclude Git metadata as both a worktree "
                    f"file and clone directory: {required_pattern}"
                )

    try:
        manifest = json.loads(
            (root / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
        )
        if manifest.get("name") != "context-guard":
            errors.append("plugin name must be context-guard")
        if manifest.get("version") != VERSION:
            errors.append(f"plugin version must be {VERSION}")
        if manifest.get("repository") != REPOSITORY:
            errors.append("plugin repository URL is not the public repository")
        if manifest.get("license") != "Apache-2.0":
            errors.append("plugin license must be Apache-2.0")
        if manifest.get("skills") != "./skills/":
            errors.append("plugin skills path must be ./skills/")
        if manifest.get("interface", {}).get("composerIcon") != "./assets/icon.svg":
            errors.append("plugin composer icon must be ./assets/icon.svg")
        if "hooks" in manifest:
            errors.append("manifest must rely on default hooks/hooks.json discovery")
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"invalid plugin manifest: {exc}")

    try:
        marketplace = json.loads(
            (root / ".agents" / "plugins" / "marketplace.json").read_text(
                encoding="utf-8"
            )
        )
        if marketplace.get("name") != "codex-context-guard":
            errors.append("marketplace name must be codex-context-guard")
        entries = marketplace.get("plugins")
        if not isinstance(entries, list) or len(entries) != 1:
            errors.append("marketplace must contain exactly one plugin")
        else:
            entry = entries[0]
            if entry.get("name") != "context-guard":
                errors.append("marketplace plugin name must be context-guard")
            if entry.get("source") != {"source": "local", "path": "./"}:
                errors.append("marketplace source must point at the repository root")
            if entry.get("policy") != {
                "installation": "AVAILABLE",
                "authentication": "ON_INSTALL",
            }:
                errors.append("marketplace policy is incomplete")
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"invalid marketplace: {exc}")

    try:
        hooks = json.loads((root / "hooks" / "hooks.json").read_text())["hooks"]
        if set(hooks) != HOOK_EVENTS:
            errors.append("hooks.json must define the exact eight-event lifecycle")
        for event, groups in hooks.items():
            for group in groups:
                for hook in group.get("hooks", []):
                    if "$PLUGIN_ROOT" not in hook.get("command", ""):
                        errors.append(f"{event}: POSIX command must use PLUGIN_ROOT")
                    if "$env:PLUGIN_ROOT" not in hook.get("commandWindows", ""):
                        errors.append(f"{event}: Windows command must use PLUGIN_ROOT")
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"invalid hooks document: {exc}")

    try:
        schema = json.loads(
            (root / "assets" / "state.schema.json").read_text(encoding="utf-8")
        )
        properties = schema.get("properties", {})
        if properties.get("schema_version", {}).get("const") != SCHEMA_VERSION:
            errors.append(f"private state schema must be version {SCHEMA_VERSION}")
        if "decision_log" not in schema.get("required", []):
            errors.append("private state schema must require the bounded decision log")
        for field in ("assets", "asset_sequence", "proofs", "proof_sequence"):
            if field not in schema.get("required", []):
                errors.append(f"private state schema must require {field}")
        completion_attempt = properties.get("completion_attempt", {})
        serialized_attempt = json.dumps(completion_attempt, sort_keys=True)
        for field in ("protocol_version", "staged_control"):
            if field not in serialized_attempt:
                errors.append(
                    f"completion attempt must define {field}"
                )
        if STOP_PROTOCOL_VERSION not in serialized_attempt:
            errors.append(
                "completion attempt must bind the current Stop protocol"
            )
        enums = enum_sets(schema)
        dispositions = set(DISPOSITION_REASONS)
        if dispositions not in enums:
            errors.append(
                "state schema must define the exact four non-completion dispositions"
            )
        if set(DISPOSITION_REASONS.values()) not in enums:
            errors.append("state schema must define the fixed disposition reasons")
        decision_items = properties.get("decision_log", {}).get("items", {})
        decision_required = set(decision_items.get("required", []))
        protocol_fields = {
            "protocol_version",
            "decision_source",
            "declared_disposition",
            "observed_outcome",
        }
        missing_decision_fields = protocol_fields.difference(decision_required)
        if missing_decision_fields:
            errors.append(
                "decision log must require protocol fields: "
                + ", ".join(sorted(missing_decision_fields))
            )
        decision_properties = set(decision_items.get("properties", {}))
        if {"prompt_text", "reply_text"}.intersection(decision_properties):
            errors.append("decision log must not define raw prompt or reply text")
        if REPOSITORY not in str(schema.get("$id", "")):
            errors.append("state schema ID must use the public repository")
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"invalid state schema: {exc}")

    try:
        runtime_text = (root / "scripts" / "context_guard.py").read_text(
            encoding="utf-8"
        )
        runtime_tree = ast.parse(runtime_text)
        expected_literals = {
            "SCHEMA_VERSION": SCHEMA_VERSION,
            "STOP_PROTOCOL_VERSION": STOP_PROTOCOL_VERSION,
            "CLASSIFIER_VERSION": CLASSIFIER_VERSION,
            "PROOF_PROTOCOL_VERSION": PROOF_PROTOCOL_VERSION,
            "DISPOSITION_REASONS": DISPOSITION_REASONS,
        }
        for name, expected in expected_literals.items():
            try:
                actual = assigned_literal(runtime_tree, name)
            except (TypeError, ValueError) as exc:
                errors.append(f"runtime protocol constant {name} is invalid: {exc}")
                continue
            if actual != expected:
                errors.append(f"runtime {name} must be {expected!r}")
        if "stage-disposition" not in runtime_text:
            errors.append("runtime must expose the private stage-disposition CLI")
        if "staged_control" not in runtime_text:
            errors.append("runtime must implement the single staged-control slot")
        if "register-proof" not in runtime_text or "verification_contract" not in runtime_text:
            errors.append("runtime must implement the Proof protocol")
        for fragment in (
            "terminal_stop_policy",
            "protocol_continue_advisory",
            "tool_is_shell_execution",
            "shell_control_operator_present",
        ):
            if fragment not in runtime_text:
                errors.append(f"runtime one-way safety contract is missing: {fragment}")
        for function_name in (
            "command_stage_checkpoint",
            "command_stage_disposition",
        ):
            if not function_ends_with_success_receipt(
                runtime_tree, function_name, PRIVATE_SUCCESS_RECEIPT
            ):
                errors.append(
                    f"{function_name} must end successful execution with the "
                    f"{PRIVATE_SUCCESS_RECEIPT!r} receipt before returning zero"
                )
    except (OSError, SyntaxError) as exc:
        errors.append(f"invalid Context Guard runtime protocol: {exc}")

    try:
        workflow = (root / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        required_identity_gate = (
            "fetch-depth: 0",
            "CONTEXT_GUARD_IDENTITY_BASE:",
            "CONTEXT_GUARD_IDENTITY_HEAD:",
            "python scripts/audit_commit_identity.py .",
        )
        for fragment in required_identity_gate:
            if fragment not in workflow:
                errors.append(f"CI commit-identity gate is missing: {fragment}")
    except OSError as exc:
        errors.append(f"invalid CI workflow: {exc}")

    try:
        icon = root / "assets" / "icon.svg"
        icon_text = icon.read_text(encoding="utf-8")
        if icon.stat().st_size >= 50 * 1024:
            errors.append("plugin icon must remain below 50 KB")
        if "<svg" not in icon_text or 'viewBox="0 0 512 512"' not in icon_text:
            errors.append("plugin icon must be a 512x512 SVG")
        if "<text" in icon_text.casefold():
            errors.append("plugin icon must not contain text")
    except OSError as exc:
        errors.append(f"invalid plugin icon: {exc}")

    try:
        project = (root / "pyproject.toml").read_text(encoding="utf-8")
        if f'version = "{VERSION}"' not in project:
            errors.append(f"pyproject version must be {VERSION}")
        if "dependencies = []" not in project:
            errors.append("Hook runtime project dependencies must remain empty")
        lock = (root / "requirements-lock.txt").read_text(encoding="utf-8")
        if "ruff==0.16.1" not in lock or "plugin-scanner==2.0.1015" not in lock:
            errors.append("validation-tool lock must pin Ruff and HOL scanner")
    except OSError as exc:
        errors.append(f"invalid project metadata or validation lock: {exc}")

    try:
        english = (root / "README.md").read_text(encoding="utf-8")
        chinese = (root / "README.zh-CN.md").read_text(encoding="utf-8")
        if "README.zh-CN.md" not in english:
            errors.append("English README must link to Chinese README")
        if "README.md" not in chinese:
            errors.append("Chinese README must link to English README")
        if VERSION not in english or VERSION not in chinese:
            errors.append(f"both README files must identify version {VERSION}")
    except OSError as exc:
        errors.append(f"could not read README files: {exc}")
    return errors


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").expanduser().resolve()
    errors = validate(root)
    if errors:
        print("Repository validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"Repository validation passed: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
