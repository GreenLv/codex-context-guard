"""Maintained daily-upgrade entry for the stable Context Guard identity.

This is the operator entry for routine upgrades of the daily HOME's
``context-guard@codex-context-guard`` installation. It deliberately differs
from ``native_upgrade_acceptance.py``, which serves isolated release
acceptance and refuses the daily HOME; this tool never impersonates that
acceptance and never edits a consumed cache, deletes an active Hook, disables
a Hook, or bypasses official trust. Every host change goes through official
Codex marketplace commands, and Hook trust stays with the normal official
review interface (``/hooks``).

Phases, each bound to the plan digest, tool digest, CLI digest and artifact
manifest digest it actually consumed:

- ``--preflight`` — read-only readiness: pinned executable identities, the
  current official installation state, target artifact verification, data
  policy observation and a host process inventory.
- ``--prepare`` — binds the preflight subject and decides whether the swap
  needs the Desktop host stopped.
- ``--apply`` — the resumable swap. Each destructive stage writes a durable
  intent event before the official command and a fact event afterwards; a
  rerun reconciles every stage against official readbacks before re-running
  anything, so an interrupted or partially reported install continues and
  never repeats blindly.
- ``--verify`` — fresh official readbacks, exact artifact parity against the
  installed cache, a read-only fresh-client Hook probe that records which
  source a new client actually loads, and the trust state.

Command probing is side-effect-free by construction: only ``--version``-style
oracles, parse-only launcher checks and read-only process enumeration are
probed. Nested ``--help`` probing of unknown CLIs is deliberately absent: a
help probe can start real system facilities (2026-11-11 daily-HOME incident).

The stable-identity swap replaces the consumed plugin cache. There is no
supported way to preserve the old bytes for a running host, so when an
installation exists, apply requires a host-absent observation — an exact
pinned-executable inventory with zero unreadable Desktop candidates — before
the first destructive command. A running host is answered with one precise
instruction, never with a claimed hot swap. Pinned sandbox services are
identified by executable identity and recorded; they are not the host and do
not gate the swap.

Results live in the exclusive ``--output`` directory outside the repository;
existing result files are never replaced. Exit codes: ``0`` completed,
``1`` pending (an operator action or a failed-but-resumable stage),
``2`` refused inputs. No login, no credential copy, no model call.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.artifact_identity import (  # noqa: E402
    compare_artifact,
    distribution_manifest,
)
from scripts.cg_process_tree import OwnedProcess  # noqa: E402
from tools.validation import host_process_inventory as inventory  # noqa: E402
from tools.validation import native_acceptance as native  # noqa: E402
from tools.validation import native_cli_adoption as adoption  # noqa: E402
from tools.validation import native_scheduler_batch as scheduler  # noqa: E402
from tools.validation import native_upgrade_acceptance as base  # noqa: E402
from tools.validation import stop_host_acceptance as host  # noqa: E402

PLAN = "cg-daily-upgrade-plan/v1"
REPORT = "cg-daily-upgrade-result/v1"
JOURNAL_SCHEMA = "cg-daily-upgrade-journal/v1"
PROBE_SCHEMA = "cg-daily-loaded-probe/v1"
ENTRY = "context-guard@codex-context-guard"
MARKET = "codex-context-guard"
PLUGIN_NAME = "context-guard"
EVENTS = frozenset(host.EVENTS)
VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")

PREFLIGHT_NAME = "preflight.json"
PREPARE_NAME = "prepare.json"
APPLY_NAME = "apply.json"
VERIFY_NAME = "verify.json"
JOURNAL_NAME = "apply-events.jsonl"
JOURNAL_MAX_EVENTS = 20000
COMMAND_TIMEOUT = 90.0
RPC_TIMEOUT = 45.0
RPC_ROW_LIMIT = 10000
RPC_LINE_CAP = 2 * 1024 * 1024

require = base.require
UpgradeError = base.UpgradeError
CapabilityPending = base.CapabilityPending


class HostPending(Exception):
    """A real operator decision is required before the swap may continue."""


# ------------------------------------------------------------- seams ----


def _run_command(argv: list[str], env: dict[str, str],
                 timeout: float = COMMAND_TIMEOUT) -> Any:
    """One owned official command; tests replace this, never a real CLI."""
    return scheduler._command(native, ROOT, argv, env=env, timeout=timeout)


def _probe_run(argv: list[str], env: dict[str, str] | None,
               timeout: float = 30.0) -> Any:
    """Side-effect-free probe seam; tests replace this, never a real CLI."""
    return scheduler._command(native, ROOT, argv, env=env, timeout=timeout)


def _host_inventory(desktop: str, markers: list[str]) -> dict[str, Any]:
    """Read-only process classification; tests replace this seam."""
    return inventory.classify(inventory.enumerate_processes(), [desktop], markers)


# ------------------------------------------------------------- helpers ----


def _scrubbed_env() -> dict[str, str]:
    """Daily-HOME child environment: credential overrides dropped.

    An inherited ``CODEX_HOME`` is dropped: the daily HOME this tool upgrades
    is resolved from the operator's home directory by ``_daily_home``, and
    the official CLI must observe exactly that HOME, not an inherited override.
    """
    env = {key: value for key, value in os.environ.items()
           if not re.search(r"TOKEN|PASSWORD|SECRET|API_KEY|CREDENTIAL", key, re.I)}
    for key in ("CONTEXT_GUARD_DATA_DIR", "PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT",
                "CODEX_HOME"):
        env.pop(key, None)
    return env


def _sha_loose(path: Path) -> str:
    """Identity digest for executables where the single-link law may not hold."""
    output = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            output.update(chunk)
    return output.hexdigest()


def _daily_home() -> Path:
    """The daily Codex HOME this tool upgrades; tests replace this seam."""
    return (Path.home() / ".codex").resolve()


def _fact(stage: str, argv: list[str], result: Any, observation: Any = None,
          **extra: Any) -> dict[str, Any]:
    return {"stage": stage, "argv": [str(item) for item in argv],
            "status": "completed", "exit_code": result.returncode,
            "stderr_nonempty": bool(result.stderr), "observation": observation, **extra}


def _interpreter_identity() -> dict[str, str]:
    return {"path": str(Path(sys.executable).resolve()), "version": platform.python_version(),
            "sha256": _sha_loose(Path(sys.executable).resolve())}


def _powershell_identity(env: dict[str, str]) -> dict[str, Any] | None:
    shell = shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")
    if shell is None:
        raise CapabilityPending("Windows runs require PowerShell for process enumeration")
    result = _probe_run([shell, "-NoProfile", "-NonInteractive", "-Command",
                         "$PSVersionTable.PSVersion.ToString()"], env)
    require(result.returncode == 0, "PowerShell version probe failed")
    version = result.stdout.decode("utf-8-sig").strip()
    require(bool(version), "PowerShell version unavailable")
    return {"path": str(Path(shell).resolve()), "version": version,
            "sha256": _sha_loose(Path(shell).resolve())}


def _same_path(raw: Any, expected: Any) -> bool:
    if raw is None or expected is None:
        return raw is None and expected is None
    return native._official_path_matches(raw, Path(expected), windows=os.name == "nt")


def _load_plan(plan_path: Path) -> dict[str, Any]:
    raw = base._read_json(plan_path)
    require(raw.get("schema") == PLAN, "wrong plan schema")
    require(raw.get("entry") == ENTRY, "plan entry must be the stable identity")
    require(raw.get("marketplace") == MARKET, "plan marketplace must be the stable marketplace")
    target = raw.get("target_version")
    require(isinstance(target, str) and VERSION_PATTERN.fullmatch(target),
            "target_version must be a semantic version")
    require(isinstance(raw.get("expected_cli_version"), str) or raw.get("expected_cli_version") is None,
            "expected_cli_version must be a string")
    markers = raw.get("sandbox_markers", [])
    require(isinstance(markers, list) and len(markers) <= 64, "sandbox_markers invalid")
    cli_value = raw.get("cli")
    if cli_value is None:
        resolved = shutil.which("codex")
        require(resolved is not None, "no codex CLI on PATH; pin 'cli' in the plan")
        cli = Path(resolved).resolve()
        require(os.access(cli, os.X_OK) if os.name == "posix" else True,
                "resolved CLI is not executable")
    else:
        cli = base._absolute_real(cli_value, "cli", file=True)
    data_dir = raw.get("data_dir")
    if data_dir is not None:
        require(isinstance(data_dir, str) and Path(data_dir).is_absolute(),
                "data_dir must be an absolute path when given")
        base._reject_credential_path(Path(data_dir))
        data_dir = str(Path(data_dir))
    return {"schema": PLAN, "entry": ENTRY, "marketplace": MARKET,
            "target_version": target,
            "artifact_dir": str(base._absolute_real(raw.get("artifact_dir"), "artifact_dir")),
            "cwd": str(base._absolute_real(raw.get("cwd"), "cwd")),
            "desktop_executable": str(base._absolute_real(raw.get("desktop_executable"),
                                                          "desktop_executable", file=True)),
            "sandbox_markers": [str(base._absolute_real(marker, "sandbox_marker", file=True))
                                for marker in markers],
            "cli": str(cli),
            "expected_cli_version": raw.get("expected_cli_version"),
            "data_dir": None if data_dir is None else str(data_dir)}


def _verify_artifact(plan: dict[str, Any]) -> dict[str, Any]:
    """Exact reviewed-manifest verification plus identity checks on the target."""
    artifact = Path(plan["artifact_dir"])
    target = plan["target_version"]
    files = distribution_manifest(artifact)
    manifest_file = artifact / ".codex-plugin" / "distribution-manifest.json"
    plugin = adoption.strict_json((artifact / ".codex-plugin" / "plugin.json").read_text("utf-8"))
    require(isinstance(plugin, dict) and plugin.get("name") == PLUGIN_NAME
            and plugin.get("version") == target,
            "artifact plugin.json differs from the plan target version")
    market = adoption.strict_json((artifact / ".agents" / "plugins" / "marketplace.json").read_text("utf-8"))
    require(isinstance(market, dict) and market.get("name") == MARKET,
            "artifact marketplace manifest name differs from the stable marketplace")
    plugins = market.get("plugins")
    require(isinstance(plugins, list) and len(plugins) == 1
            and isinstance(plugins[0], dict) and plugins[0].get("name") == PLUGIN_NAME,
            "artifact marketplace must expose exactly the stable plugin entry")
    source = plugins[0].get("source")
    require(isinstance(source, dict) and source.get("source") == "local"
            and isinstance(source.get("path"), str)
            and _same_path(str((artifact / source["path"]).resolve()), artifact),
            "artifact marketplace entry must point at the artifact root")
    hooks_doc = adoption.strict_json((artifact / "hooks" / "hooks.json").read_text("utf-8"))
    # hooks.json names are PascalCase definitions; EVENTS are the wire names.
    require(isinstance(hooks_doc, dict) and isinstance(hooks_doc.get("hooks"), dict)
            and {name.casefold() for name in hooks_doc["hooks"]}
            == {event.casefold() for event in EVENTS},
            "artifact Hooks definition does not cover the nine Hook events")
    return {"path": str(artifact), "manifest_sha256": base.sha(manifest_file),
            "file_count": len(files), "version": target}


def _project_market_entries(entries: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for name in sorted(entries):
        entry = entries[name]
        item: dict[str, Any] = {"name": name}
        if name == MARKET:
            if isinstance(entry.get("root"), str):
                item["root"] = entry["root"]
            origin = entry.get("marketplaceSource")
            if isinstance(origin, dict) and origin.get("sourceType") == "local":
                item["marketplaceSource"] = {"sourceType": "local", "source": origin.get("source")}
        rows.append(item)
    return rows


def _project_scoped_rows(rows: Any) -> list[dict[str, Any]]:
    require(isinstance(rows, list), "official plugin inventory unavailable")
    projected = []
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("pluginId"), str),
                "official plugin entry malformed")
        projected.append({key: row.get(key) for key in
                          ("pluginId", "name", "marketplaceName", "version", "installed", "enabled")})
    return projected


def _cache_candidates(daily: Path, target: str) -> list[Path]:
    cache_root = daily / "plugins" / "cache" / MARKET / PLUGIN_NAME
    return [cache_root / name for name in (target, "local")
            if (cache_root / name).is_dir() and not (cache_root / name).is_symlink()]


def _daily_state(cli: Path, env: dict[str, str], stage: str) -> dict[str, Any]:
    """Official read-only registration/installation state with command facts."""
    commands: list[dict[str, Any]] = []
    version_result = _run_command([str(cli), "--version"], env)
    require(version_result.returncode == 0, "official CLI version readback failed")
    cli_version = version_result.stdout.decode("utf-8-sig").strip()
    commands.append(_fact(stage, [str(cli), "--version"], version_result,
                          {"version": cli_version}))
    market_result = _run_command([str(cli), "plugin", "marketplace", "list", "--json"], env)
    require(market_result.returncode == 0, "official marketplace readback failed")
    entries = base._market_entries(market_result)
    commands.append(_fact(stage, [str(cli), "plugin", "marketplace", "list", "--json"],
                          market_result, {"marketplaces": _project_market_entries(entries)}))
    registered = MARKET in entries
    entry = entries.get(MARKET) if registered else {}
    market_root = entry.get("root") if isinstance(entry.get("root"), str) else None
    scoped_result = _run_command([str(cli), "plugin", "list", "--marketplace", MARKET, "--json"], env)
    installed = False
    version = None
    enabled = None
    if scoped_result.returncode == 0:
        rows = base._json_output(scoped_result).get("installed")
        projected = _project_scoped_rows(rows)
        mine = [row for row in projected if row["pluginId"] == ENTRY]
        require(len(mine) <= 1, "ambiguous stable-identity installation")
        commands.append(_fact(stage, [str(cli), "plugin", "list", "--marketplace", MARKET, "--json"],
                              scoped_result, {"installed": projected}))
        row = mine[0] if mine else None
        if row is not None and row.get("installed") is True:
            installed = True
            version = row.get("version")
            enabled = row.get("enabled")
    else:
        require(not registered,
                "official scoped plugin readback failed while the marketplace is registered")
        commands.append(_fact(stage, [str(cli), "plugin", "list", "--marketplace", MARKET, "--json"],
                              scoped_result, {"installed": []}, status="refused_empty_readback"))
    return {"cli_version": cli_version,
            "registered": registered, "market_root": market_root,
            "installed": installed, "version": version, "enabled": enabled,
            "commands": commands}


def _data_policy(plan: dict[str, Any], env: dict[str, str],
                 commands: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Observe the existing retention policy without changing it.

    The readback runs the currently installed copy of the product CLI; with
    no or an ambiguous installation the policy is recorded as skipped and is
    re-observed at verify time.
    """
    data_dir = plan.get("data_dir")
    if data_dir is None:
        return None
    data_dir = Path(data_dir)
    daily = _daily_home()
    candidates = _cache_candidates(daily, plan["target_version"])
    caches = daily / "plugins" / "cache" / MARKET / PLUGIN_NAME
    installed_roots = ([path for path in caches.iterdir()
                        if path.is_dir() and not path.is_symlink()] if caches.is_dir() else [])
    if not candidates and len(installed_roots) != 1:
        return {"data_dir": str(data_dir), "present": data_dir.is_dir(),
                "policy_readback": "skipped_ambiguous_installation"}
    script = (candidates[0] if candidates else installed_roots[0]) / "scripts" / "context_guard.py"
    if not script.is_file():
        return {"data_dir": str(data_dir), "present": data_dir.is_dir(),
                "policy_readback": "skipped_missing_product_cli"}
    argv = [sys.executable, "-B", "-I", str(script.resolve()), "cleanup",
            "--data-dir", str(data_dir), "--policy", "show"]
    result = _run_command(argv, env)
    require(result.returncode == 0, "retention policy readback failed")
    policy = adoption.strict_json(result.stdout.decode("utf-8-sig"))
    commands.append(_fact("policy_readback", argv, result, {
        "policy": policy.get("policy") if isinstance(policy, dict) else None,
        "automatic_maintenance": policy.get("automatic_maintenance") if isinstance(policy, dict) else None}))
    return {"data_dir": str(data_dir), "present": data_dir.is_dir(),
            "policy": policy.get("policy") if isinstance(policy, dict) else None,
            "automatic_maintenance": policy.get("automatic_maintenance") if isinstance(policy, dict) else None}


def _preflight_checks(plan: dict[str, Any]) -> dict[str, Any]:
    """Read-only subject construction; identical inputs for every phase."""
    daily = _daily_home()
    env = _scrubbed_env()
    cli = Path(plan["cli"])
    try:
        cli_sha = base.sha(cli)
    except UpgradeError:
        raise CapabilityPending("public CLI hard-link aliases require review") from None
    artifact = _verify_artifact(plan)
    desktop = plan["desktop_executable"]
    host_state = _host_inventory(desktop, plan["sandbox_markers"])
    state = _daily_state(cli, env, "preflight")
    if plan.get("expected_cli_version") is not None:
        require(state["cli_version"] == plan["expected_cli_version"],
                "CLI version differs from the plan pin")
    data_policy = _data_policy(plan, env, state["commands"])
    subject: dict[str, Any] = {
        "schema": REPORT,
        "tool_sha256": base.sha(Path(__file__)),
        "plan_sha256": base.digest(plan),
        "cli": {"path": str(cli), "sha256": cli_sha, "version": state["cli_version"]},
        "python": _interpreter_identity(),
        "powershell": _powershell_identity(env) if os.name == "nt" else None,
        "daily_home": str(daily),
        "artifact": artifact,
        "market_identity": {"entry": ENTRY, "marketplace": MARKET},
        "desktop_executable": {"path": desktop, "sha256": _sha_loose(Path(desktop))},
        "sandbox_markers": [{"path": marker, "sha256": _sha_loose(Path(marker))}
                            for marker in plan["sandbox_markers"]],
        "installed_before": {key: state[key] for key in
                             ("registered", "market_root", "installed", "version", "enabled")},
        "host": host_state,
        "data_policy": data_policy,
    }
    subject["commands"] = state["commands"]
    return subject


def _binding_view(subject: dict[str, Any]) -> dict[str, Any]:
    """The identity fields whose change is a refused preflight/execution drift.

    ``installed_before``, ``host`` and ``data_policy`` are live observations
    that legitimately change between prepare and apply (the operator quits the
    host, maintenance runs); each is judged by its own explicit gate instead.
    """
    return {key: value for key, value in subject.items()
            if key not in ("installed_before", "host", "data_policy", "commands")}


def _claim_output(subject: dict[str, Any], output: Path) -> None:
    protected = [ROOT.resolve(), Path(subject["daily_home"]), Path(subject["artifact"]["path"])]
    base._new_outside(output, protected)


def _read_bound_result(path: Path, *, stage: str) -> tuple[dict[str, Any], str]:
    value, file_sha = base._read_json_with_sha(path)
    require(value.get("schema") == REPORT and value.get("stage") == stage,
            "bound result has the wrong schema or stage")
    return value, file_sha


# ---------------------------------------------------------------- journal ----


class _Journal:
    """Append-only durable batch journal; existing events are never replaced."""

    def __init__(self, path: Path, begin: dict[str, Any]):
        self.path = path
        if path.exists():
            self.events = _read_journal(path)
            require(self.events and self.events[0] == begin,
                    "existing journal belongs to a different batch")
            descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
                                 0o600)
            self._file = os.fdopen(descriptor, "a", encoding="utf-8", newline="\n")
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self._file = os.fdopen(fd, "a", encoding="utf-8", newline="\n")
            self.events = []
        self._count = len(self.events)
        if not self.events:
            self._append(begin)

    def _append(self, event: dict[str, Any]) -> None:
        self._count += 1
        require(self._count <= JOURNAL_MAX_EVENTS, "apply journal oversized")
        self._file.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        self._file.flush()
        os.fsync(self._file.fileno())
        self.events.append(event)

    def intent(self, stage: str, argv: list[str]) -> None:
        self._append({"event": "intent", "stage": stage, "argv": [str(item) for item in argv]})

    def fact(self, stage: str, argv: list[str], result: Any, **extra: Any) -> None:
        self._append({"event": "fact", **_fact(stage, argv, result, None, **extra)})

    def note(self, stage: str, message: str) -> None:
        self._append({"event": "note", "stage": stage, "message": message})

    def raw_fact(self, fact: dict[str, Any]) -> None:
        self._append({"event": "fact", **fact})

    def facts(self) -> list[dict[str, Any]]:
        return [event for event in self.events if event.get("event") == "fact"]

    def has_intent(self, stage: str) -> bool:
        return any(event.get("event") == "intent" and event.get("stage") == stage
                   for event in self.events)

    def close(self) -> None:
        self._file.close()


def _read_journal(path: Path) -> list[dict[str, Any]]:
    _reject = base._reject_credential_path
    _reject(path)
    base._no_link_ancestors(path.absolute())
    require(path.is_file() and not path.is_symlink(), "journal must be a regular file")
    text = path.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line]
    require(len(lines) <= JOURNAL_MAX_EVENTS, "apply journal oversized")
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            raise UpgradeError("apply journal is corrupt") from None
        require(isinstance(event, dict) and event.get("event") in
                ("begin", "intent", "fact", "note"), "apply journal event invalid")
        events.append(event)
    return events


# ------------------------------------------------------------ preflight ----


def preflight_action(plan: dict[str, Any], output: Path) -> None:
    subject = _preflight_checks(plan)
    _claim_output(subject, output)
    output.mkdir(mode=0o700)
    base._write_new(output / PREFLIGHT_NAME,
                    {"schema": REPORT, "stage": "preflight", "status": "observed",
                     "subject": subject, "subject_sha256": base.digest(subject)})
    print("daily_upgrade_preflight=passed; prepare_not_run")


def preflight_commands(plan: dict[str, Any], plan_path: Path) -> dict[str, Any]:
    """Side-effect-free readiness proof of the exact commands a run can issue.

    Probes are limited to ``--version``-style oracles, parse-only launcher
    checks, the launcher's real ``print-argv`` echo mode and the read-only
    process enumeration already consumed by the subject. No ``--help`` probe
    of any CLI is issued.
    """
    subject = _preflight_checks(plan)
    cli = plan["cli"]
    planned: list[list[str]] = [
        [str(cli), "--version"],
        [str(cli), "plugin", "marketplace", "list", "--json"],
        [str(cli), "plugin", "list", "--marketplace", MARKET, "--json"],
        [str(cli), "plugin", "marketplace", "add", plan["artifact_dir"]],
        [str(cli), "plugin", "add", ENTRY, "--json"],
    ]
    if subject["installed_before"]["registered"]:
        planned.append([str(cli), "plugin", "marketplace", "remove", MARKET])
    env = _scrubbed_env()
    utf8 = _probe_run([sys.executable, "-B", "-c", "import sys; print(sys.flags.utf8_mode)"], env)
    require(utf8.returncode == 0, "child environment probe failed")
    launcher: dict[str, Any]
    opposite: str
    if os.name == "posix":
        launcher = _probe_sh_launcher(ROOT / "tools" / "validation" / "run_daily_upgrade.sh",
                                      ["daily", "--plan", str(plan_path)])
        opposite = "capability_skip: run_daily_upgrade.ps1 requires Windows"
    else:
        launcher = _probe_ps1_launcher(ROOT / "tools" / "validation" / "run_daily_upgrade.ps1",
                                       ["daily", "--plan", str(plan_path)])
        opposite = "capability_skip: run_daily_upgrade.sh requires POSIX sh"
    return {"planned_official_families": planned,
            "probe_oracles": ["--version", "launcher print-argv", "read-only process enumeration"],
            "help_probes": "none",
            "entry_probe": {"argv": [str(cli), "--version"],
                            "version": subject["cli"]["version"]},
            "launcher": launcher,
            "opposite_platform_launcher": opposite,
            "environment": {"utf8_mode": utf8.stdout.decode("utf-8-sig").strip()},
            "enumeration": subject["host"]["enumeration"]}


def _probe_sh_launcher(launcher: Path, passthrough: list[str]) -> dict[str, Any]:
    parsed = _probe_run(["sh", "-n", str(launcher)], {})
    require(parsed.returncode == 0, "sh launcher parse probe failed: sh -n " + str(launcher))
    real_argv = ["/bin/sh", str(launcher), "--print-argv", *passthrough]
    replay = _probe_run(real_argv, {})
    lines = replay.stdout.decode("utf-8").splitlines()
    require(replay.returncode == 0 and lines == passthrough,
            "sh launcher REAL entry probe failed (the launcher did not parse and "
            "pass this run's argv): " + repr(real_argv))
    return {"probed": "sh", "parse": ["sh", "-n", str(launcher)],
            "real_entry": {"argv": real_argv, "echoed": lines}}


def _probe_ps1_launcher(launcher: Path, passthrough: list[str]) -> dict[str, Any]:
    shell = shutil.which("pwsh") or shutil.which("powershell")
    require(shell is not None, "PowerShell launcher probe requires pwsh or powershell")
    script = (
        '$ErrorActionPreference = "Stop"\n'
        '[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n'
        '$tokens = $null; $parseErrors = $null\n'
        '[void][System.Management.Automation.Language.Parser]::ParseFile($env:CG_LAUNCHER_PROBE, '
        '[ref]$tokens, [ref]$parseErrors)\n'
        'if ($parseErrors.Count -gt 0) { throw ($parseErrors -join "`n") }\n'
        '[string[]]$rest = @(ConvertFrom-Json -InputObject $env:CG_PASSTHROUGH_PROBE)\n'
        '& $env:CG_LAUNCHER_PROBE -Target print-argv -Arguments $rest\n'
        'exit $LASTEXITCODE\n')
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    argv = [shell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
    env = {key: value for key, value in os.environ.items()
           if not re.search(r"TOKEN|PASSWORD|SECRET|API_KEY|CREDENTIAL", key, re.I)}
    env.update(CG_LAUNCHER_PROBE=str(launcher), CG_PASSTHROUGH_PROBE=json.dumps(passthrough))
    replay = _probe_run(argv, env, timeout=60.0)
    try:
        echoed = json.loads(replay.stdout.decode("utf-8-sig"))
    except (UnicodeError, ValueError):
        echoed = None
    require(replay.returncode == 0 and echoed == ["print-argv", passthrough],
            "PowerShell launcher entry probe failed: " + str(launcher)
            + " via " + shell + " (exit " + str(replay.returncode) + ")")
    return {"probed": "powershell", "parse": "Parser::ParseFile " + str(launcher),
            "real_entry": {"argv": argv, "echoed": echoed}}


# --------------------------------------------------------------- prepare ----


def prepare(plan: dict[str, Any], output: Path) -> dict[str, Any]:
    subject = _preflight_checks(plan)
    _claim_output(subject, output)
    output.mkdir(mode=0o700)
    installed = subject["installed_before"]
    host_status = subject["host"]["status"]
    if installed["installed"] and installed["version"] == plan["target_version"]:
        status = "already_current"
        swap = {"required": False,
                "reason": "installed version already equals the target version"}
    elif not installed["installed"]:
        status = "prepared"
        swap = {"required": False,
                "reason": "no existing stable-identity installation; nothing consumes the old cache"}
    elif host_status == "absent":
        status = "prepared"
        swap = {"required": False,
                "reason": "Desktop host observed absent by pinned executable identity"}
    else:
        status = "prepared"
        reason = ("the stable-identity swap replaces the consumed plugin cache; the running "
                  "Desktop host would lose the old code under its open tasks"
                  if host_status == "running" else
                  "host state is unknown (" + str(subject["host"]["reason"]) + "); a swap must "
                  "not start while a Desktop host may be running")
        swap = {"required": True, "reason": reason, "observed_host_status": host_status}
    result = {"schema": REPORT, "stage": "prepare", "status": status, "subject": subject,
              "subject_sha256": base.digest(subject), "swap": swap,
              "commands": subject["commands"],
              "pending": ["apply", "verify"]}
    base._write_new(output / PREPARE_NAME, result)
    print(json.dumps({"status": status, "stage": "prepare",
                      "host": host_status, "swap_required": swap["required"]}))
    return result


# ----------------------------------------------------------------- apply ----


def _reconcile_prestate(prepared: dict[str, Any], current: dict[str, Any],
                        journal: _Journal, plan: dict[str, Any]) -> None:
    """Refuse daily-state changes this batch did not record, before mutating."""
    pre = prepared["subject"]["installed_before"]
    target = plan["target_version"]
    if pre["registered"] and not current["registered"]:
        require(journal.has_intent("marketplace_remove"),
                "marketplace registration disappeared without a recorded removal from this batch")
    if pre["registered"] and current["registered"]:
        if _same_path(current["market_root"], pre["market_root"]):
            pass
        else:
            # A crash between the add completing and its fact write leaves an
            # intent without a fact; a registration already moved to this
            # batch's artifact by a recorded intent is a resume, not drift.
            require(journal.has_intent("marketplace_add")
                    and _same_path(current["market_root"], plan["artifact_dir"]),
                    "marketplace registration changed outside this batch; re-prepare")
    if not pre["registered"] and current["registered"]:
        require(journal.has_intent("marketplace_add"),
                "marketplace registration appeared without a recorded add from this batch")
    if current["installed"]:
        require(current["version"] in (pre["version"], target),
                "installed version changed outside this batch; re-prepare")
        if current["version"] == target and pre["version"] != target:
            require(journal.has_intent("plugin_add"),
                    "target installation appeared without a recorded add from this batch")


def apply(plan: dict[str, Any], output: Path, prepared_path: Path) -> dict[str, Any]:
    prepared, prepared_sha = _read_bound_result(prepared_path, stage="prepare")
    require(output.is_dir() and not output.is_symlink(),
            "apply requires the existing batch output directory")
    require(prepared_path.parent == output,
            "the prepare receipt must live in this batch's output directory")
    if prepared.get("status") == "already_current":
        raise UpgradeError("installed version already equals the target; run --verify instead")
    require(prepared.get("status") == "prepared", "prepare receipt is not applicable")
    subject = _preflight_checks(plan)
    drift = sorted(key for key in set(_binding_view(subject))
                   | set(_binding_view(prepared["subject"]))
                   if _binding_view(subject).get(key) != _binding_view(prepared["subject"]).get(key))
    require(not drift, "preparation and execution drifted: " + ", ".join(drift))
    # Host gate: replacing an existing installation always requires an
    # observed host-absent state, whatever prepare observed — the Desktop
    # host may have started between prepare and apply, and the fresh
    # apply-time inventory is the deciding observation.
    if prepared["subject"]["installed_before"]["installed"]:
        host_status = subject["host"]["status"]
        if host_status != "absent":
            raise HostPending(
                "Desktop host must be observed absent before the stable-identity swap "
                "(observed: " + host_status + "; sandbox services do not gate the swap). "
                "Quit the Codex Desktop host, then re-run the same apply command.")
    cli = Path(subject["cli"]["path"])
    env = _scrubbed_env()
    begin = {"event": "begin", "schema": JOURNAL_SCHEMA,
             "subject_sha256": base.digest(_binding_view(subject)),
             "prepared_sha256": prepared_sha}
    journal = _Journal(output / JOURNAL_NAME, begin)
    try:
        current = _daily_state(cli, env, "apply_state")
        for fact in current["commands"]:
            journal.raw_fact(fact)
        _reconcile_prestate(prepared, current, journal, plan)
        artifact_str = plan["artifact_dir"]
        # Stage 1: official marketplace remove (the destructive old-cache
        # step). A registration already at the plan artifact — a resumed batch
        # whose add landed before its fact was written — is never removed
        # again; the stages decide by observed state, not by sequence.
        if current["registered"] and not _same_path(current["market_root"], artifact_str):
            argv = [str(cli), "plugin", "marketplace", "remove", MARKET]
            journal.intent("marketplace_remove", argv)
            result = _run_command(argv, env)
            journal.fact("marketplace_remove", argv, result)
            require(result.returncode == 0, "official marketplace remove failed")
            current = _daily_state(cli, env, "apply_state")
            for fact in current["commands"]:
                journal.raw_fact(fact)
            require(not current["registered"],
                    "marketplace registration persisted after the official remove")
        elif current["registered"]:
            journal.note("marketplace_remove",
                         "registration already at the plan artifact; remove not needed")
        else:
            journal.note("marketplace_remove", "marketplace not registered; remove not needed")
        # Stage 2: official marketplace add of the verified target artifact.
        if current["registered"]:
            require(_same_path(current["market_root"], artifact_str),
                    "registered marketplace source differs from the plan artifact")
            journal.note("marketplace_add", "already registered at the plan artifact")
        else:
            argv = [str(cli), "plugin", "marketplace", "add", artifact_str]
            journal.intent("marketplace_add", argv)
            result = _run_command(argv, env)
            journal.fact("marketplace_add", argv, result)
            require(result.returncode == 0, "official marketplace add failed")
            current = _daily_state(cli, env, "apply_state")
            for fact in current["commands"]:
                journal.raw_fact(fact)
            require(current["registered"]
                    and _same_path(current["market_root"], artifact_str),
                    "marketplace registration after add differs from the plan artifact")
        # Stage 3: official stable plugin add with summary tolerance.
        if current["installed"] and current["version"] == plan["target_version"]:
            journal.note("plugin_add", "target installation already present; add not repeated")
        else:
            # An old installation still present here means the marketplace
            # remove did not retire it; the official same-identity add is the
            # documented replacement, so proceed and let the readback decide.
            argv = [str(cli), "plugin", "add", ENTRY, "--json"]
            journal.intent("plugin_add", argv)
            result = _run_command(argv, env)
            extra: dict[str, Any] = {}
            if result.returncode == 0 and base._summary_dict(result) is None:
                # The host change has already happened; the scoped readback
                # below decides, so an unreadable summary never fails the phase.
                extra = {"summary_parse_failed": True,
                         "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                         "stdout_bytes": len(result.stdout)}
            journal.fact("plugin_add", argv, result, **extra)
            require(result.returncode == 0, "official plugin add failed")
            current = _daily_state(cli, env, "apply_state")
            for fact in current["commands"]:
                journal.raw_fact(fact)
            require(current["installed"] and current["version"] == plan["target_version"],
                    "official readback does not show the target installation")
        # Stage 4: closing readbacks and cache binding.
        daily = Path(subject["daily_home"])
        candidates = _cache_candidates(daily, plan["target_version"])
        require(len(candidates) == 1, "installed cache is missing or ambiguous")
        cache_root = daily / "plugins" / "cache" / MARKET / PLUGIN_NAME
        retained = sorted(path.name for path in cache_root.iterdir()
                          if path.is_dir() and not path.is_symlink())
        installed_after = {"registered": current["registered"],
                           "market_root": current["market_root"],
                           "installed": True, "version": current["version"],
                           "enabled": current["enabled"],
                           "cache_path": str(candidates[0]),
                           "cache_entries": retained}
        journal.note("apply_complete", "official stages reconciled; apply receipt follows")
        result = {"schema": REPORT, "stage": "apply", "status": "applied",
                  "subject_sha256": base.digest(_binding_view(subject)),
                  "prepared_sha256": prepared_sha,
                  "installed_after": installed_after,
                  "commands": journal.facts(),
                  "sandbox_services_present": subject["host"]["counts"].get("sandbox_service", 0),
                  "host_status_at_swap": subject["host"]["status"],
                  "pending": ["hook_trust_review", "verify"]}
        base._write_new(output / APPLY_NAME, result)
        print(json.dumps({"status": "applied", "stage": "apply",
                          "version": installed_after["version"],
                          "hook_trust_pending": installed_after["enabled"] is not True}))
        return result
    finally:
        journal.close()


# ----------------------------------------------------------------- probe ----


class _ProbeClient:
    """Read-only fresh-client probe: initialize, hooks/list, nothing else."""

    METHODS = frozenset({"initialize", "initialized", "hooks/list"})

    def __init__(self, cli: Path, cwd: Path, directory: Path, env: dict[str, str]):
        self.rows: list[dict[str, Any]] = []
        self.pending: dict[int, str] = {}
        self.sequence = 0
        self.q: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=10000)
        self.log = (directory / "rpc.jsonl").open("x", encoding="utf-8")
        self.err = open(os.devnull, "wb")
        self.owned = None
        try:
            launch = [str(cli)]
            if platform.system() == "Windows":
                launch += ["-c", 'windows.sandbox="mxc"', "-c", "allow_login_shell=false"]
            child_env = {**env, "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1"}
            self.owned = OwnedProcess.spawn([*launch, "app-server"], cwd=str(cwd), env=child_env,
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=self.err, text=True, encoding="utf-8")
            threading.Thread(target=self._reader, daemon=True).start()
            self.rpc("initialize", {"clientInfo": {"name": "cg-daily-upgrade", "version": "1"},
                                    "capabilities": {"experimentalApi": True}})
            self.send({"method": "initialized", "params": {}})
            self.hooks_raw = self.rpc("hooks/list", {"cwds": [str(cwd)]})
        except BaseException:
            self.close()
            raise

    def _reader(self) -> None:
        try:
            for line in self.owned.process.stdout:
                if len(line) > RPC_LINE_CAP:
                    raise ValueError("oversized RPC line")
                self.q.put(json.loads(line), timeout=1)
        except Exception as exc:
            self.q.put({"reader_error": type(exc).__name__})

    def send(self, message: dict[str, Any]) -> None:
        require(message.get("method") in self.METHODS, "RPC method outside read-only scope")
        self.log.write(json.dumps({"direction": "request", "message": message}) + "\n")
        self.log.flush()
        assert self.owned is not None and self.owned.process.stdin is not None
        self.owned.process.stdin.write(json.dumps(message) + "\n")
        self.owned.process.stdin.flush()

    def receive(self, deadline: float) -> dict[str, Any]:
        require(len(self.rows) < RPC_ROW_LIMIT, "RPC row limit")
        message = self.q.get(timeout=max(.01, deadline - time.monotonic()))
        self.rows.append(message)
        self.log.write(json.dumps({"direction": "response", "message": message}) + "\n")
        self.log.flush()
        require("reader_error" not in message, "RPC reader failed")
        require(not ("method" in message and "id" in message), "unexpected server request")
        return message

    def rpc(self, method: str, params: dict[str, Any]) -> Any:
        self.sequence += 1
        identifier = self.sequence
        self.pending[identifier] = method
        self.send({"id": identifier, "method": method, "params": params})
        end = time.monotonic() + RPC_TIMEOUT
        while time.monotonic() < end:
            message = self.receive(end)
            if message.get("id") == identifier:
                require("error" not in message, "RPC rejected: " + method)
                return message.get("result")
        raise TimeoutError(method)

    def close(self) -> dict[str, Any]:
        try:
            cleanup = self.owned.close(12) if self.owned else None
        finally:
            self.log.close()
            self.err.close()
        return cleanup


def _loaded_probe(cli: Path, cwd: Path, journal_dir: Path,
                  env: dict[str, str]) -> dict[str, Any]:
    """What Hook sources a brand-new client actually loads; never a turn."""
    record: dict[str, Any] = {"schema": PROBE_SCHEMA, "hooks": [], "cleanup": None,
                              "reason": None}
    client = None
    try:
        client = _ProbeClient(cli, cwd, journal_dir, env)
        data = client.hooks_raw.get("data") if isinstance(client.hooks_raw, dict) else None
        require(isinstance(data, list) and len(data) == 1
                and isinstance(data[0], dict) and isinstance(data[0].get("hooks"), list),
                "Hook inventory unavailable")
        for row in data[0]["hooks"]:
            require(isinstance(row, dict), "Hook inventory row malformed")
            record["hooks"].append({key: row.get(key) for key in
                                    ("eventName", "sourcePath", "source", "trustStatus", "enabled")})
    except BaseException as exc:
        record["reason"] = type(exc).__name__ + ": " + str(exc)[:200]
    finally:
        if client is not None:
            try:
                record["cleanup"] = client.close()
            except BaseException as exc:
                record["cleanup"] = {"cleanup_complete": False,
                                     "error": type(exc).__name__}
        if record["cleanup"] is not None and record["cleanup"].get("cleanup_complete") is not True:
            # An unknown probe cleanup is an honest observation gap, never a
            # pass; verify reports it as loaded_unknown.
            record["reason"] = record["reason"] or "probe_cleanup_unknown"
    return record


def _route_loaded(hooks: list[dict[str, Any]], daily: Path,
                  cache_path: Path) -> str:
    """Old/new routing from observed Hook source paths only.

    ``new`` means at least one Context Guard Hook source resolves under the
    freshly installed cache; ``old`` means Context Guard Hooks still resolve
    only elsewhere in the plugin cache; ``none`` means no Context Guard Hook
    rows; ``unknown`` is never claimed here — the caller handles probe
    failures separately.
    """
    cache_root_prefix = str(daily / "plugins" / "cache").casefold() + os.sep
    fresh_prefix = str(cache_path).casefold() + os.sep
    has_new = has_old = False
    for row in hooks:
        source_path = row.get("sourcePath")
        if not isinstance(source_path, str) or not source_path:
            return "unknown"
        folded = source_path.casefold()
        if folded.startswith(fresh_prefix):
            has_new = True
        elif folded.startswith(cache_root_prefix):
            has_old = True
    if has_new and has_old:
        # Positive evidence of both sources is never a clean new load.
        return "old"
    if has_new:
        return "new"
    if has_old:
        return "old"
    return "none"


# ----------------------------------------------------------------- verify ----


def verify(plan: dict[str, Any], output: Path, prepared_path: Path,
           verify_output: Path) -> dict[str, Any]:
    prepared, prepared_sha = _read_bound_result(prepared_path, stage="prepare")
    require(output.is_dir() and not output.is_symlink(),
            "verify requires the existing batch output directory")
    require(prepared_path.parent == output, "the prepare receipt must live in this output directory")
    subject = _preflight_checks(plan)
    fresh_binding = base.digest(_binding_view(subject))
    drift = sorted(key for key in set(_binding_view(subject))
                   | set(_binding_view(prepared["subject"]))
                   if _binding_view(subject).get(key) != _binding_view(prepared["subject"]).get(key))
    require(not drift, "preparation and execution drifted: " + ", ".join(drift))
    if prepared["status"] == "already_current":
        # No swap happened in this batch; the current installation at target
        # is verified directly without an apply receipt.
        apply_result = None
    else:
        require((output / APPLY_NAME).is_file(),
                "apply has not completed; no apply receipt exists")
        apply_result, _apply_sha = _read_bound_result(output / APPLY_NAME, stage="apply")
        require(apply_result.get("status") == "applied", "apply has not completed")
        require(apply_result.get("prepared_sha256") == prepared_sha,
                "apply result was bound to a different prepare receipt")
        require(apply_result.get("subject_sha256") == fresh_binding,
                "apply result was bound to a different execution identity")
    cli = Path(subject["cli"]["path"])
    env = _scrubbed_env()
    current = _daily_state(cli, env, "verify")
    require(current["registered"] and current["installed"]
            and current["version"] == plan["target_version"],
            "official readback does not show the target installation")
    daily = Path(subject["daily_home"])
    candidates = _cache_candidates(daily, plan["target_version"])
    require(len(candidates) == 1, "installed cache is missing or ambiguous")
    cache_path = candidates[0]
    compare_artifact(Path(plan["artifact_dir"]), cache_path)
    # Fresh-client loaded-version probe, journaled under an unused index.
    probe_root = output / "probe" / "loaded"
    probe_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    index = 1
    while (probe_root / f"loaded-{index}").exists():
        index += 1
    probe = _loaded_probe(cli, plan["cwd"], probe_root / f"loaded-{index}", env)
    loaded = "unknown"
    if probe["reason"] is None:
        loaded = _route_loaded(probe["hooks"], daily, cache_path)
    fresh_prefix = str(cache_path).casefold() + os.sep
    trust_rows = [row for row in probe["hooks"]
                  if isinstance(row.get("sourcePath"), str)
                  and row["sourcePath"].casefold().startswith(fresh_prefix)]
    trust_pending = (not trust_rows or any(row.get("trustStatus") != "trusted"
                                           or row.get("enabled") is not True
                                           for row in trust_rows))
    if loaded == "old":
        status = "restart_required"
        detail = ("a fresh client still loads the old Hook source; quit and reopen the "
                  "Desktop host, then re-run --verify")
    elif loaded == "unknown":
        status = "loaded_unknown"
        detail = probe["reason"] or "loaded Hook sources could not be routed"
    elif loaded == "none":
        status = "loaded_none"
        detail = "the fresh-client Hook inventory shows no Context Guard Hooks"
    elif trust_pending:
        status = "hook_trust_pending"
        detail = ("open the Codex client, review /hooks and trust the nine Hooks from "
                  + str(cache_path))
    else:
        status = "passed"
        detail = None
    data_policy = _data_policy(plan, env, current["commands"])
    result = {"schema": REPORT, "stage": "verify", "status": status, "detail": detail,
              "subject_sha256": base.digest(_binding_view(subject)),
              "prepared_sha256": prepared_sha,
              "installed_after": {"registered": current["registered"],
                                  "installed": current["installed"],
                                  "version": current["version"],
                                  "enabled": current["enabled"],
                                  "cache_path": str(cache_path)},
              "artifact_parity": "passed",
              "fresh_client_loaded": loaded,
              "fresh_client_hooks": probe["hooks"],
              "probe_cleanup": probe["cleanup"],
              "probe_journal": str(probe_root / f"loaded-{index}" / "rpc.jsonl"),
              "host": subject["host"],
              "data_policy": data_policy,
              "commands": current["commands"]}
    if verify_output != output / VERIFY_NAME:
        _claim_output(subject, verify_output)
    base._write_new(verify_output, result)
    print(json.dumps({"status": status, "stage": "verify", "fresh_client_loaded": loaded}))
    return result


# ------------------------------------------------------------------ main ----


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="exclusive batch directory outside the repository")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--preflight-commands", action="store_true")
    action.add_argument("--prepare", action="store_true")
    action.add_argument("--apply", action="store_true")
    action.add_argument("--verify", action="store_true")
    parser.add_argument("--prepared-result", type=Path)
    parser.add_argument("--verify-output", type=Path)
    args = parser.parse_args(argv)
    if not args.verify and args.verify_output is not None:
        parser.error("--verify-output requires --verify")
    if args.apply or args.verify:
        prepared = args.prepared_result or (args.output / PREPARE_NAME)
    elif args.prepared_result is not None:
        parser.error("--prepared-result requires --apply or --verify")
    else:
        prepared = None
    try:
        require(args.output.is_absolute(), "output must be an absolute path")
        plan_path = base._absolute_real(str(args.plan), "plan", file=True)
        plan = _load_plan(plan_path)
        if args.preflight:
            preflight_action(plan, args.output)
        elif args.preflight_commands:
            base._writable_directory(args.output.parent)
            print(json.dumps({"status": "passed", "stage": "preflight-commands",
                              **preflight_commands(plan, plan_path)},
                             ensure_ascii=False, sort_keys=True))
        elif args.prepare:
            prepare(plan, args.output)
        elif args.apply:
            require(prepared is not None, "prepared result required")
            apply(plan, args.output, prepared)
        else:
            require(prepared is not None, "prepared result required")
            verify_output = args.verify_output or (args.output / VERIFY_NAME)
            result = verify(plan, args.output, prepared, verify_output)
            return 0 if result["status"] == "passed" else 1
    except (HostPending, CapabilityPending) as exc:
        print("daily_upgrade=pending; " + str(exc), file=sys.stderr)
        return 1
    except (UpgradeError, OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        print("daily_upgrade=refused; " + type(exc).__name__ + "; " + str(exc)[:300],
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
