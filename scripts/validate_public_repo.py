#!/usr/bin/env python3
"""Validate the standalone Context Guard repository contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path

VERSION = "0.4.12"
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
    "requirements-lock.txt",
    "assets/icon.svg",
    "assets/state.schema.json",
    "docs/ARCHITECTURE.md",
    "docs/PRIVACY.md",
    "docs/COMPATIBILITY.md",
    "docs/LOCAL_ACCEPTANCE.md",
    "hooks/hooks.json",
    "scripts/context_guard.py",
    "scripts/manage_plugin.py",
    "scripts/smoke_installed.py",
    "skills/context-guard/SKILL.md",
    "skills/context-guard/agents/openai.yaml",
    "skills/context-guard/references/successor-pack.md",
}
FORBIDDEN_FILES = {
    "docs/BLOG.zh-CN.md",
}


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
        if schema.get("properties", {}).get("schema_version", {}).get("const") != 3:
            errors.append("private state schema must remain version 3")
        if REPOSITORY not in str(schema.get("$id", "")):
            errors.append("state schema ID must use the public repository")
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"invalid state schema: {exc}")

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
