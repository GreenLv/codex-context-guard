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
- ``--prepare`` — binds the preflight subject. A v1 plan requires the
  Desktop host stopped for a swap; an explicit between-turns v2 plan requires
  a compatible old/target artifact pair and the operator's pause.
- ``--apply`` — the resumable swap. Each destructive stage writes a durable
  intent event before the official command and a fact event afterwards; a
  rerun reconciles every stage against official readbacks before re-running
  anything, so an interrupted or partially reported install continues and
  never repeats blindly.
- ``--verify`` — fresh official readbacks, exact artifact parity against the
  installed cache, a read-only fresh-client Hook probe that records which
  source a new client actually loads, and the trust state.
- ``--resume`` — the thin same-command continuation: it derives the next
  pending stage from the batch's exclusive receipts and dispatches to the
  existing prepare/apply/verify implementations. It adds no identity rule of
  its own; every stage still re-derives its subject and refuses drift exactly
  like a directly typed command, and the apply host gate stays the one
  precise operator instruction.
- ``--rebind`` — the controlled host re-identification for an unstarted
  batch: when the only binding drift is the same-path desktop executable's
  bytes (a host auto-update after preparation), it records the judgment,
  keeps every prior receipt, and writes the next numbered prepare receipt
  bound to the new host identity. Any other input change (CLI, artifact,
  plan, helpers, interpreter, sandbox markers) refuses with its own category.

Command probing is side-effect-free by construction: only ``--version``-style
oracles, parse-only launcher checks and read-only process enumeration are
probed. Nested ``--help`` probing of unknown CLIs is deliberately absent: a
help probe can start real system facilities (2026-11-11 daily-HOME incident).

The stable-identity swap may prune the old plugin cache through official
Codex commands. The default v1 route requires an absent Desktop host. The
explicit v2 between-turns route keeps the host and tasks open: the operator
pauses new operations, this tool drains existing old-runtime processes, and
then it performs the official swap. It does not preserve old runtime bytes.
The old and target runtime trees must be identical except the two named
version constants and plugin version metadata; an old task can therefore
continue through its existing compatible fallback. Active or ambiguous
process observations remain pending, never permission to kill another task.
Normal Hook review may still be required before continuing. A clear snapshot
is not a lock: keep the pause through the swap and successful verification.

Results live in the exclusive ``--output`` directory outside the repository;
existing result files are never replaced. Exit codes: ``0`` completed,
``1`` pending on an operator decision, ``2`` refused inputs or a failed
official execution. After any nonzero apply or verify exit, re-run the same
command: the resume re-reads the journal and the official readbacks and
never assumes that nothing changed. No login, no credential copy, no model call.
"""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
import platform
import queue
import re
import shutil
import stat
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
    checked_metadata,
    checked_walk,
    compare_artifact,
    distribution_manifest,
)
from scripts.cg_process_tree import OwnedProcess  # noqa: E402
from tools.validation import host_process_inventory as inventory  # noqa: E402
from tools.validation import native_acceptance as native  # noqa: E402
from tools.validation import native_cli_adoption as adoption  # noqa: E402
from tools.validation import native_scheduler_batch as scheduler  # noqa: E402
from tools.validation import native_upgrade_acceptance as base  # noqa: E402
from tools.validation import runtime_activity as activity_observer  # noqa: E402
from tools.validation import stop_host_acceptance as host  # noqa: E402

PLAN = "cg-daily-upgrade-plan/v1"
PLAN_V2 = "cg-daily-upgrade-plan/v2"
REPORT = "cg-daily-upgrade-result/v1"
REPORT_V2 = "cg-daily-upgrade-result/v2"
COLD_MODE = "stopped-host"
HOT_MODE = "between-turns"
DRAIN_SECONDS_DEFAULT = 120
DRAIN_SECONDS_MAX = 900
JOURNAL_SCHEMA = "cg-daily-upgrade-journal/v1"
JOURNAL_SCHEMA_V2 = "cg-daily-upgrade-journal/v2"
PROBE_SCHEMA = "cg-daily-loaded-probe/v1"
ENTRY = "context-guard@codex-context-guard"
MARKET = "codex-context-guard"
PLUGIN_NAME = "context-guard"
EVENTS = frozenset(host.EVENTS)
VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")
TEAM_IDENTIFIER = re.compile(r"^[A-Z0-9]{10}$")
ANCHOR_REQUIREMENT = ('=anchor apple generic and anchor trusted and '
                      'certificate leaf[subject.OU] = "{team}"')

PREFLIGHT_NAME = "preflight.json"
PREPARE_NAME = "prepare.json"
REBIND_NAME = "rebind.json"
APPLY_NAME = "apply.json"
VERIFY_NAME = "verify.json"
JOURNAL_NAME = "apply-events.jsonl"
JOURNAL_MAX_EVENTS = 20000
COMMAND_TIMEOUT = 90.0
RPC_TIMEOUT = 45.0
RPC_ROW_LIMIT = 10000
RPC_LINE_CAP = 2 * 1024 * 1024
WAIT_POLL_SECONDS = 15.0
WAIT_MINUTES_DEFAULT = 60
WAIT_MINUTES_MAX = 720

require = base.require
UpgradeError = base.UpgradeError
CapabilityPending = base.CapabilityPending


def _report_schema(mode: str) -> str:
    require(mode in (COLD_MODE, HOT_MODE), "unknown transition mode")
    return REPORT_V2 if mode == HOT_MODE else REPORT


def _result_mode(value: dict[str, Any]) -> str:
    mode = value.get("mode", COLD_MODE)
    require(mode in (COLD_MODE, HOT_MODE)
            and value.get("schema") == _report_schema(mode),
            "result schema does not match its transition mode")
    return mode


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


def _host_inventory(desktop: str, markers: list[str],
                    host_tools: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read-only process classification; tests replace this seam.

    The enumeration consumes the pinned ps identity on darwin instead of a
    fresh PATH re-resolution, and the Windows Toolhelp route receives the
    pinned candidate basenames for its guarded negative/positive rules.
    """
    tools = host_tools or {}
    candidates = inventory.windows_candidate_basenames([desktop], markers)
    return inventory.classify(
        inventory.enumerate_processes(ps=tools.get("ps", {}).get("path"),
                                      candidate_basenames=candidates),
        [desktop], markers)


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


def _now() -> float:
    """Monotonic clock seam; tests patch this for bounded-wait deadlines."""
    return time.monotonic()


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _inventory_host_tools(env: dict[str, str]) -> dict[str, Any]:
    """The pinned process-enumeration tool identities for one observation."""
    host_tools: dict[str, Any] = {}
    if os.name == "nt":
        host_tools["powershell"] = _powershell_identity(env)
    else:
        ps_identity = _ps_identity()
        if ps_identity is not None:
            host_tools["ps"] = ps_identity
    return host_tools


def _fact(stage: str, argv: list[str], result: Any, observation: Any = None,
          **extra: Any) -> dict[str, Any]:
    return {"stage": stage, "argv": [str(item) for item in argv], "cwd": str(ROOT),
            "status": "completed", "exit_code": result.returncode,
            "stderr_nonempty": bool(result.stderr), "observation": observation, **extra}


def _interpreter_identity() -> dict[str, str]:
    return {"path": str(Path(sys.executable).resolve()), "version": platform.python_version(),
            "sha256": _sha_loose(Path(sys.executable).resolve())}


def _ps_identity() -> dict[str, str] | None:
    """The exact read-only ps executable the formal enumeration will consume."""
    if sys.platform != "darwin":
        return None
    resolved = shutil.which("ps")
    require(resolved is not None, "darwin process enumeration requires ps")
    return {"path": str(Path(resolved).resolve()), "sha256": _sha_loose(Path(resolved).resolve())}


HELPER_SOURCE_LIMIT = 256


def _helper_identities() -> dict[str, str]:
    """Digests of the executed helper closure, as a conservative source inventory.

    Binding only this file's own bytes would let an imported consumer —
    native_acceptance, the scheduler command runner, artifact_identity,
    cg_process_tree, the Hook inventory or their shared helpers — drift
    undetected between prepare and apply/verify. A maintained exact closure is
    fragile, so the binding covers every Python module under ``scripts/`` and
    ``tools/validation/`` plus ``tools/guard_state_migration.py`` (the
    transitive import surface this tool executes), plus the platform
    launchers. A module added to those trees is therefore pinned too.
    """
    helpers: dict[str, str] = {}
    roots = [ROOT / "scripts", ROOT / "tools" / "validation"]
    for root in roots:
        for path in sorted(root.glob("*.py")):
            require(len(helpers) < HELPER_SOURCE_LIMIT,
                    "helper source inventory exceeded its bound")
            helpers[path.relative_to(ROOT).as_posix()] = base.sha(path)
    migration = ROOT / "tools" / "guard_state_migration.py"
    if migration.is_file():
        helpers[migration.relative_to(ROOT).as_posix()] = base.sha(migration)
    for name in ("run_daily_upgrade.sh", "run_daily_upgrade.ps1", "runtime_activity_windows.ps1"):
        path = ROOT / "tools" / "validation" / name
        if path.is_file():
            helpers[path.relative_to(ROOT).as_posix()] = base.sha(path)
    return helpers


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


def _codesign_publisher(path: Path, env: dict[str, str],
                        expected_team: str | None = None) -> dict[str, Any]:
    """macOS host provenance: a trust-anchored team identity, not self-report.

    ``codesign --verify --strict`` alone checks only the internal signature
    and its own designated requirement, so the audited identity must also
    pass an explicit ``--test-requirement`` anchored to Apple's generic
    trusted anchor with the publisher's organizational unit
    (``anchor apple generic and anchor trusted and
    certificate leaf[subject.OU] = "TEAM"``). ``certificate leaf trusted``
    is deliberately not used — official distribution hosts fail it. The team
    identifier is strictly format-validated before any requirement probe,
    and when re-binding, the requirement is evaluated against the prepared
    publisher identity, never against a self-reported or self-signed OU
    string. An unsigned, ad-hoc, team-less or requirement-failing host is
    recorded as unverified and is never a trusted publisher identity.
    """
    verify = _probe_run(["codesign", "--verify", "--strict", str(path)], env)
    detail = _probe_run(["codesign", "-dv", "--verbose=4", str(path)], env)
    text = detail.stderr.decode("utf-8", "replace")
    team_observed = None
    authority = None
    for line in text.splitlines():
        if line.startswith("TeamIdentifier="):
            team_observed = line.split("=", 1)[1].strip() or None
        elif line.startswith("Authority=") and authority is None:
            authority = line.split("=", 1)[1].strip() or None
    team = expected_team if expected_team is not None else team_observed
    require(team is not None and TEAM_IDENTIFIER.fullmatch(team),
            "publisher team identifier is not a valid 10-character issuer identity")
    requirement = ANCHOR_REQUIREMENT.format(team=team)
    anchored = _probe_run(["codesign", "--verify", "--strict",
                           "--test-requirement", requirement, str(path)], env)
    verified = (verify.returncode == 0 and anchored.returncode == 0
                and team_observed == team)
    reason = None
    if not verified:
        if team_observed != team:
            reason = "host team identifier differs from the audited publisher"
        elif verify.returncode != 0:
            reason = "signature verification failed"
        else:
            reason = "trust-anchor requirement failed (rc=%d)" % anchored.returncode
    return {"method": "codesign", "verified": verified,
            "identity": team if verified else None,
            "authority": authority, "team_requirement": requirement,
            "team_observed": team_observed,
            "anchor_requirement_rc": anchored.returncode,
            "verify_rc": verify.returncode, "reason": reason}


def _authenticode_publisher(path: Path, shell: str,
                            env: dict[str, str]) -> dict[str, Any]:
    """Windows host provenance: a Valid Authenticode signer thumbprint."""
    literal = str(path).replace("'", "''")
    script = ("$s = Get-AuthenticodeSignature -LiteralPath '" + literal + "'; "
              "$t = $null; $u = $null; "
              "if ($s -and $s.SignerCertificate) { "
              "$t = $s.SignerCertificate.Thumbprint; "
              "$u = $s.SignerCertificate.Subject }; "
              "(@{ status = [string]$s.Status; thumbprint = $t; subject = $u } | "
              "ConvertTo-Json -Compress)")
    result = _probe_run([shell, "-NoProfile", "-NonInteractive", "-Command",
                         script], env)
    require(result.returncode == 0, "Authenticode publisher probe failed")
    payload = adoption.strict_json(result.stdout.decode("utf-8-sig"))
    require(isinstance(payload, dict), "Authenticode publisher payload invalid")
    thumbprint = payload.get("thumbprint")
    verified = payload.get("status") == "Valid" and isinstance(thumbprint, str) \
        and bool(thumbprint)
    return {"method": "authenticode", "verified": verified,
            "identity": thumbprint if verified else None,
            "subject": payload.get("subject"), "status": payload.get("status")}


def _host_publisher(path: Path, env: dict[str, str], host_tools: dict[str, Any],
                    expected_team: str | None = None) -> dict[str, Any]:
    """Trusted-publisher observation for the desktop host; tests replace this seam.

    Fail-closed by construction: an unavailable verifier, an unsigned or
    ad-hoc host, a non-Valid Authenticode status and an unsupported platform
    all record ``verified: False`` and never become a trusted identity. On
    macOS ``expected_team`` re-audits the bytes against a previously
    verified publisher identity instead of the host's self-reported team.
    This is a signature/publisher boundary only — not a security sandbox.
    """
    try:
        if os.name == "nt":
            shell = (host_tools.get("powershell") or {}).get("path")
            require(shell is not None,
                    "publisher verification requires the pinned PowerShell")
            return _authenticode_publisher(path, shell, env)
        if sys.platform == "darwin":
            return _codesign_publisher(path, env, expected_team=expected_team)
    except (UpgradeError, CapabilityPending, OSError, ValueError) as exc:
        return {"method": None, "verified": False, "identity": None,
                "reason": type(exc).__name__ + ": " + str(exc)[:160]}
    return {"method": None, "verified": False, "identity": None,
            "reason": "publisher verification unsupported on this platform"}


def _load_plan(plan_path: Path) -> dict[str, Any]:
    raw = base._read_json(plan_path)
    schema = raw.get("schema")
    require(schema in (PLAN, PLAN_V2), "wrong plan schema")
    require(raw.get("entry") == ENTRY, "plan entry must be the stable identity")
    require(raw.get("marketplace") == MARKET, "plan marketplace must be the stable marketplace")
    target = raw.get("target_version")
    require(isinstance(target, str) and VERSION_PATTERN.fullmatch(target),
            "target_version must be a semantic version")
    require(isinstance(raw.get("expected_cli_version"), str) or raw.get("expected_cli_version") is None,
            "expected_cli_version must be a string")
    markers = raw.get("sandbox_markers", [])
    require(isinstance(markers, list) and len(markers) <= 64, "sandbox_markers invalid")
    if schema == PLAN_V2:
        require(len(target) <= 16 and re.fullmatch(
            r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", target),
            "between-turns target must be a supported numeric version")
        strategy = raw.get("transition_strategy")
        require(strategy == HOT_MODE,
                'plan v2 transition_strategy must be "between-turns"')
        old_dir = str(base._absolute_real(raw.get("old_artifact_dir"), "old_artifact_dir"))
        drain = raw.get("drain_seconds", DRAIN_SECONDS_DEFAULT)
        require(isinstance(drain, int) and not isinstance(drain, bool)
                and 1 <= drain <= DRAIN_SECONDS_MAX,
                "drain_seconds must be bounded seconds between 1 and %d" % DRAIN_SECONDS_MAX)
        mode = HOT_MODE
    else:
        require(raw.get("transition_strategy") is None,
                "v1 plans are the stopped-host route and must not declare "
                "transition_strategy")
        require(raw.get("old_artifact_dir") is None,
                "old_artifact_dir belongs to the between-turns plan")
        strategy, old_dir, drain, mode = COLD_MODE, None, None, COLD_MODE
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
    return {"schema": schema, "entry": ENTRY, "marketplace": MARKET,
            "mode": mode, "transition_strategy": strategy,
            "old_artifact_dir": old_dir, "drain_seconds": drain,
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


def _verify_artifact(plan: dict[str, Any], artifact_dir: str | None = None,
                     expected_version: str | None = None) -> dict[str, Any]:
    """Exact reviewed-manifest verification plus identity checks on one artifact."""
    artifact = Path(artifact_dir or plan["artifact_dir"])
    target = expected_version or plan["target_version"]
    files = distribution_manifest(artifact)
    require(_walk_regular_files(artifact) == files,
            "expanded artifact contains files outside the reviewed distribution manifest")
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
                 commands: list[dict[str, Any]],
                 installed_version: str | None) -> dict[str, Any] | None:
    """Observe the existing retention policy without changing it.

    The readback runs the observed installed copy of the product CLI — never
    a retained target-version slot that may not be the consuming version. With
    no or an ambiguous observed installation the policy is recorded as
    honestly skipped and is re-observed at verify time.
    """
    data_dir = plan.get("data_dir")
    if data_dir is None:
        return None
    data_dir = Path(data_dir)
    daily = _daily_home()
    if installed_version is None:
        return {"data_dir": str(data_dir), "present": data_dir.is_dir(),
                "policy_readback": "skipped_no_installation_observed"}
    candidates = _cache_candidates(daily, installed_version)
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


# ------------------------------------------------- between-turns route ----

COMPAT_ROOTS = ("hooks", "assets", "skills", "scripts")
VERSION_LITERAL_FILES = {
    "scripts/context_guard.py": "PRODUCT_VERSION",
    "scripts/validate_public_repo.py": "VERSION",
}


def _walk_regular_files(root: Path) -> dict[str, str]:
    """Digests of every regular file under ``root``, nested dirs traversed.

    Links (any depth, including a linked root section), non-regular objects
    and unreadable bytes refuse the tree instead of being skipped or
    silently dropped.
    """
    tree: dict[str, str] = {}
    try:
        for path, info in checked_walk(root):
            rel = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                continue
            require(stat.S_ISREG(info.st_mode),
                    "distribution tree contains a non-regular object: " + rel)
            tree[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, RuntimeError) as exc:
        raise UpgradeError("distribution tree cannot be verified: " + type(exc).__name__) from None
    return tree


def _checked_cache_ancestors(path: Path) -> None:
    for component in reversed((path, *path.parents)):
        try:
            info = checked_metadata(component)
        except FileNotFoundError:
            continue
        except (OSError, RuntimeError):
            raise UpgradeError("cache path cannot be verified") from None
        require(stat.S_ISDIR(info.st_mode), "cache ancestor is not a regular directory")


def _version_literal_swap(name: str, old_text: str, new_text: str,
                          old_version: str, new_version: str) -> bool:
    """True when two files differ by exactly one version-literal replacement.

    Exactly one declaration line may exist on each side (duplicates refuse
    regardless of their value or spacing), and only that declaration span is
    exchanged; any other string that also changed between the versions
    refuses.
    """
    declaration = VERSION_LITERAL_FILES[name]

    def literal(text: str, expected: str) -> tuple[bytes, int, int] | None:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return None
        stores = [node for node in ast.walk(tree)
                  if isinstance(node, ast.Name) and node.id == declaration
                  and isinstance(node.ctx, ast.Store)]
        assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                       and len(node.targets) == 1
                       and isinstance(node.targets[0], ast.Name)
                       and node.targets[0].id == declaration]
        if len(stores) != 1 or len(assignments) != 1:
            return None
        value = assignments[0].value
        if not isinstance(value, ast.Constant) or value.value != expected:
            return None
        lines = text.encode("utf-8").splitlines(keepends=True)
        start = sum(map(len, lines[:value.lineno - 1])) + value.col_offset
        end = sum(map(len, lines[:value.end_lineno - 1])) + value.end_col_offset
        body = text.encode("utf-8")
        if body[start:end] not in (('"' + expected + '"').encode(),
                                   ("'" + expected + "'").encode()):
            return None
        return body, start, end

    before, after = literal(old_text, old_version), literal(new_text, new_version)
    if before is None or after is None:
        return False
    body, start, end = before
    replacement = body[start:start + 1] + new_version.encode() + body[end - 1:end]
    return body != after[0] and body[:start] + replacement + body[end:] == after[0]


def _verify_between_turns_compatibility(plan: dict[str, Any],
                                        installed_version: str) -> dict[str, Any]:
    """The strict gate for the between-turns route; any doubt refuses it.

    The installed old tree must match the verified retained old artifact in
    both directions, and the old artifact may differ from the reviewed
    target only by the exact single ``PRODUCT_VERSION`` / ``VERSION``
    literal replacement plus the ``version`` field of the plugin manifest.
    Generated distribution manifests and packaged reader docs are excluded;
    Hook bodies, runtime files, stable identity and safety fields are not.
    Unknown or unproved compatibility refuses the route rather than
    downgrading it to the stopped-host requirement.
    """
    old_dir = Path(plan["old_artifact_dir"])
    distribution_manifest(old_dir)
    old_metadata = adoption.strict_json(
        (old_dir / ".codex-plugin" / "plugin.json").read_text("utf-8"))
    require(isinstance(old_metadata, dict), "old artifact metadata is malformed")
    old_version = old_metadata.get("version")
    require(isinstance(old_version, str) and len(old_version) <= 16
            and re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", old_version),
            "old artifact version is not a supported numeric version")
    old_artifact = _verify_artifact(plan, artifact_dir=plan["old_artifact_dir"],
                                    expected_version=old_version)
    daily = _daily_home()
    slot = daily / "plugins" / "cache" / MARKET / PLUGIN_NAME / old_version
    _checked_cache_ancestors(slot)
    # The whole installed old distribution must match the retained old
    # artifact; unknown extra files or missing files would be silently
    # deleted or lost by the official prune.
    old_tree = _walk_regular_files(old_dir)
    if installed_version != plan["target_version"]:
        require(installed_version in (None, old_version),
                "installed version differs from the retained old artifact")
        require(tuple(map(int, plan["target_version"].split(".")))
                > tuple(map(int, old_version.split("."))),
                "between-turns transitions require an increasing version")
        target_slot = slot.parent / plan["target_version"]
        require(not target_slot.exists() and not target_slot.is_symlink(),
                "target cache slot already exists without the target official installation")
        for sibling in slot.parent.iterdir():
            require(not sibling.is_symlink(), "unreviewed linked cache entry")
            if sibling.is_dir():
                require(sibling.name == old_version,
                        "unreviewed cache slot would be pruned: " + sibling.name)
        candidates = _cache_candidates(daily, old_version)
        require(len(candidates) == 1 and candidates[0] == slot,
                "the installed old version cache slot is missing or ambiguous")
        require(_walk_regular_files(slot) == old_tree,
                "the installed old distribution differs from the retained old "
                "artifact; the between-turns route refuses migrated or repaired installs")
    # Compatibility between the two verified trees is a separate, scoped
    # comparison: the runtime compatibility roots with the exact literal
    # allowance; distribution manifests and packaged reader docs are outside.
    target_tree = {name: digest for name, digest in
                   _walk_regular_files(Path(plan["artifact_dir"])).items()
                   if name.split("/", 1)[0] in COMPAT_ROOTS}
    old_runtime = {name: digest for name, digest in old_tree.items()
                   if name.split("/", 1)[0] in COMPAT_ROOTS}
    added = sorted(set(target_tree) - set(old_runtime))
    deleted = sorted(set(old_runtime) - set(target_tree))
    require(not added and not deleted,
            "the target artifact adds or deletes runtime files: "
            + ", ".join(added[:4] + deleted[:4]))
    differences = []
    for name in sorted(set(old_runtime) & set(target_tree)):
        if old_runtime[name] == target_tree[name]:
            continue
        require(name in VERSION_LITERAL_FILES,
                "runtime file " + name + " differs beyond the version literal "
                "allowance")
        old_text = (old_dir / name).read_bytes().decode("utf-8")
        new_text = (Path(plan["artifact_dir"]) / name).read_bytes().decode("utf-8")
        require(_version_literal_swap(name, old_text, new_text,
                                      old_version, plan["target_version"]),
                "runtime file " + name + " differs beyond the exact single "
                "version-literal replacement")
        differences.append(name + ": version literal")
    old_plugin = adoption.strict_json(
        (old_dir / ".codex-plugin" / "plugin.json").read_text("utf-8"))
    new_plugin = adoption.strict_json(
        (Path(plan["artifact_dir"]) / ".codex-plugin" / "plugin.json").read_text("utf-8"))
    require(isinstance(old_plugin, dict) and isinstance(new_plugin, dict)
            and set(old_plugin) == set(new_plugin)
            and old_plugin.get("name") == new_plugin.get("name") == PLUGIN_NAME,
            "the plugin manifest name or shape differs")
    manifest_changes = {key for key in old_plugin
                        if old_plugin[key] != new_plugin.get(key)}
    require(manifest_changes <= {"version"},
            "the plugin manifest differs beyond its version field: "
            + ", ".join(sorted(manifest_changes)))
    old_market = adoption.strict_json(
        (old_dir / ".agents" / "plugins" / "marketplace.json").read_text("utf-8"))
    new_market = adoption.strict_json(
        (Path(plan["artifact_dir"]) / ".agents" / "plugins" / "marketplace.json").read_text("utf-8"))
    require(old_market.get("name") == new_market.get("name") == MARKET
            and old_market.get("plugins") == new_market.get("plugins"),
            "the marketplace manifest differs beyond the allowed packaging")
    # This binding is derived from retained artifacts, so it remains identical
    # after official add has pruned the old slot. The initial installed-tree
    # check above is represented by the integrity-bound prepared subject;
    # verification does not pretend to recheck a tree which no longer exists.
    return {"verdict": "compatible", "rule": "version-literals-only/v1",
            "old_version": old_version,
            "old_artifact": old_artifact, "installed_slot": str(slot),
            "old_distribution_sha256": base.digest(old_tree),
            "runtime_differences": differences, "compared_roots": list(COMPAT_ROOTS)}


def _old_slot_outcome(plan: dict[str, Any], compatibility: dict[str, Any]) -> dict[str, Any]:
    """An old slot may survive intact or disappear, never remain partial."""
    slot = Path(compatibility["installed_slot"])
    _checked_cache_ancestors(slot)
    try:
        info = checked_metadata(slot)
    except FileNotFoundError:
        return {"status": "absent"}
    except (OSError, RuntimeError):
        raise UpgradeError("unsafe partial old cache: old slot cannot be verified") from None
    require(stat.S_ISDIR(info.st_mode),
            "unsafe partial old cache: old slot is not a regular directory")
    try:
        actual = _walk_regular_files(slot)
    except (OSError, UpgradeError) as exc:
        raise UpgradeError("unsafe partial old cache: old slot cannot be verified") from exc
    require(base.digest(actual) == compatibility["old_distribution_sha256"],
            "unsafe partial old cache: official add did not remove the whole old tree; "
            "keep new operations paused and review the retained journal")
    return {"status": "retained_intact", "distribution_sha256": base.digest(actual)}


def _runtime_activity(daily_home: Path, version: str,
                      host_tools: dict[str, Any], *, compatibility: dict[str, Any],
                      allow_absent: bool = False) -> dict[str, Any]:
    """Observe only the prepared old slot and byte-bound old Hook definitions."""
    old = compatibility["old_artifact"]
    old_dir = Path(old["path"])
    require(_verify_artifact({}, artifact_dir=str(old_dir), expected_version=version) == old,
            "retained old artifact changed before activity observation")
    for name in ("ps", "powershell"):
        identity = host_tools.get(name)
        if identity is not None:
            require(_sha_loose(Path(identity["path"])) == identity["sha256"],
                    "activity host tool changed before observation")
    definitions = adoption.strict_json((old_dir / "hooks" / "hooks.json").read_text("utf-8"))
    return activity_observer.observe(
        daily_home, version, host_tools, hooks=definitions,
        slots=[Path(compatibility["installed_slot"])], allow_absent=allow_absent)


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
    host_tools = _inventory_host_tools(env)
    host_state = _host_inventory(desktop, plan["sandbox_markers"], host_tools)
    publisher = _host_publisher(Path(desktop), env, host_tools)
    state = _daily_state(cli, env, "preflight")
    if plan.get("expected_cli_version") is not None:
        require(state["cli_version"] == plan["expected_cli_version"],
                "CLI version differs from the plan pin")
    data_policy = _data_policy(plan, env, state["commands"], state["version"])
    compatibility = None
    if plan["mode"] == HOT_MODE:
        compatibility = _verify_between_turns_compatibility(plan, state["version"])
    subject: dict[str, Any] = {
        "schema": _report_schema(plan["mode"]),
        "mode": plan["mode"],
        "tool_sha256": base.sha(Path(__file__)),
        "tool_root": str(ROOT),
        "invocation_cwd": str(Path.cwd().resolve()),
        "helpers": _helper_identities(),
        "plan_sha256": base.digest(plan),
        "cli": {"path": str(cli), "sha256": cli_sha, "version": state["cli_version"]},
        "python": _interpreter_identity(),
        "host_tools": host_tools,
        "daily_home": str(daily),
        "artifact": artifact,
        "market_identity": {"entry": ENTRY, "marketplace": MARKET},
        "desktop_executable": {"path": desktop, "sha256": _sha_loose(Path(desktop)),
                               "publisher": publisher},
        "sandbox_markers": [{"path": marker, "sha256": _sha_loose(Path(marker))}
                            for marker in plan["sandbox_markers"]],
        "installed_before": {key: state[key] for key in
                             ("registered", "market_root", "installed", "version", "enabled")},
        "host": host_state,
        "data_policy": data_policy,
        "compatibility": compatibility,
    }
    subject["commands"] = state["commands"]
    return subject


def _binding_view(subject: dict[str, Any]) -> dict[str, Any]:
    """The identity fields whose change is a refused preflight/execution drift.

    ``installed_before``, ``host`` and ``data_policy`` are
    live observations that legitimately change between prepare, apply and
    verify (the operator quits the host, maintenance runs, the official add
    prunes the old cache); each is judged by its own explicit gate instead.
    """
    return {key: value for key, value in subject.items()
            if key not in ("installed_before", "host", "data_policy", "commands")}


def _claim_output(subject: dict[str, Any], output: Path) -> None:
    protected = [ROOT.resolve(), Path(subject["daily_home"]), Path(subject["artifact"]["path"])]
    base._new_outside(output, protected)


def _read_bound_result(path: Path, *, stage: str,
                       mode: str | None = None) -> tuple[dict[str, Any], str]:
    value, file_sha = base._read_json_with_sha(path)
    require(value.get("stage") == stage, "bound result has the wrong stage")
    observed_mode = _result_mode(value)
    if mode is not None:
        # Receipts carry their transition mode; a v1 stopped-host receipt can
        # never be reinterpreted by a between-turns plan and vice versa.
        require(observed_mode == mode,
                "bound result belongs to a different transition mode: "
                + str(value.get("mode")))
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
            event = adoption.strict_json(line)
        except ValueError:
            raise UpgradeError("apply journal is corrupt") from None
        require(isinstance(event, dict) and event.get("event") in
                ("begin", "intent", "fact", "note"), "apply journal event invalid")
        events.append(event)
    require(events and events[0].get("event") == "begin",
            "apply journal must begin with its identity record")
    mode = events[0].get("mode", COLD_MODE)
    expected_schema = JOURNAL_SCHEMA_V2 if mode == HOT_MODE else JOURNAL_SCHEMA
    require(mode in (COLD_MODE, HOT_MODE)
            and events[0].get("schema") == expected_schema,
            "journal schema does not match its transition mode")
    pending: dict[str, list[list[str]]] = {}
    mutations = {"plugin_remove", "marketplace_remove", "marketplace_add", "plugin_add"}
    for event in events[1:]:
        require(event["event"] != "begin", "apply journal repeats its identity record")
        stage = event.get("stage")
        require(isinstance(stage, str) and bool(stage), "apply journal stage is malformed")
        if event["event"] == "intent":
            require(stage in mutations and not (mode == HOT_MODE and stage == "plugin_remove"),
                    "apply journal contains an unsupported mutation")
            argv = event.get("argv")
            require(isinstance(argv, list) and bool(argv)
                    and all(isinstance(arg, str) and bool(arg) for arg in argv),
                    "apply journal intent command is malformed")
            pending.setdefault(stage, []).append(argv)
        elif event["event"] == "fact" and stage in mutations:
            intents = pending.get(stage, [])
            require(intents and intents[-1] == event.get("argv"),
                    "apply journal mutation fact has no preceding matching intent")
            require(type(event.get("exit_code")) is int,
                    "apply journal mutation result is malformed")
            intents.pop()
    return events


def _check_hot_journal(plan: dict[str, Any], subject: dict[str, Any],
                       prepared_sha: str, output: Path,
                       applied: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    events = _read_journal(output / JOURNAL_NAME)
    expected = {"event": "begin", "schema": JOURNAL_SCHEMA_V2, "mode": HOT_MODE,
                "subject_sha256": base.digest(_binding_view(subject)),
                "prepared_sha256": prepared_sha}
    require(events[0] == expected, "between-turns journal belongs to another preparation")
    cli = subject["cli"]["path"]
    allowed = {
        "marketplace_remove": [cli, "plugin", "marketplace", "remove", MARKET],
        "marketplace_add": [cli, "plugin", "marketplace", "add", plan["artifact_dir"]],
        "plugin_add": [cli, "plugin", "add", ENTRY, "--json"],
    }
    for event in events[1:]:
        argv = event.get("argv")
        if not isinstance(argv, list) or event["event"] not in ("intent", "fact"):
            continue
        mutating = (argv[1:3] in (["plugin", "add"], ["plugin", "remove"])
                    or argv[1:4] in (["plugin", "marketplace", "add"],
                                     ["plugin", "marketplace", "remove"]))
        if mutating or event["event"] == "intent":
            require(event.get("stage") in allowed
                    and argv == allowed[event["stage"]],
                    "between-turns journal contains an out-of-scope command")
    if applied is not None:
        require(applied.get("commands") == [event for event in events
                                            if event["event"] == "fact"],
                "apply receipt facts differ from the retained journal")
    return events


# ------------------------------------------------------------ preflight ----


def preflight_action(plan: dict[str, Any], output: Path) -> None:
    subject = _preflight_checks(plan)
    _claim_output(subject, output)
    base._mkdir_private_new(output)
    base._write_new(output / PREFLIGHT_NAME,
                    {"schema": _report_schema(plan["mode"]), "stage": "preflight", "status": "observed",
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
    probe_shell: str
    if os.name == "posix":
        shell = shutil.which("sh")
        require(shell is not None, "POSIX sh unavailable for launcher probing")
        probe_shell = str(Path(shell).resolve())
        launcher = _probe_sh_launcher(ROOT / "tools" / "validation" / "run_daily_upgrade.sh",
                                      ["daily", "--plan", str(plan_path)], probe_shell)
        opposite = "capability_skip: run_daily_upgrade.ps1 requires Windows"
    else:
        pinned = (subject.get("host_tools") or {}).get("powershell", {}).get("path")
        shell = pinned or shutil.which("pwsh") or shutil.which("powershell")
        require(shell is not None, "PowerShell unavailable for launcher probing")
        probe_shell = str(Path(shell).resolve())
        launcher = _probe_ps1_launcher(ROOT / "tools" / "validation" / "run_daily_upgrade.ps1",
                                       ["daily", "--plan", str(plan_path)], probe_shell)
        opposite = "capability_skip: run_daily_upgrade.sh requires POSIX sh"
    return {"probe_shell": probe_shell,
            "planned_official_families": planned,
            "probe_oracles": ["--version", "launcher print-argv", "read-only process enumeration"],
            "help_probes": "none",
            "entry_probe": {"argv": [str(cli), "--version"],
                            "version": subject["cli"]["version"]},
            "launcher": launcher,
            "opposite_platform_launcher": opposite,
            "environment": {"utf8_mode": utf8.stdout.decode("utf-8-sig").strip()},
            "enumeration": subject["host"]["enumeration"]}


def _probe_sh_launcher(launcher: Path, passthrough: list[str],
                       shell: str) -> dict[str, Any]:
    parsed = _probe_run([shell, "-n", str(launcher)], {})
    require(parsed.returncode == 0, "sh launcher parse probe failed: " + shell
            + " -n " + str(launcher))
    real_argv = [shell, str(launcher), "--print-argv", *passthrough]
    replay = _probe_run(real_argv, {})
    lines = replay.stdout.decode("utf-8").splitlines()
    require(replay.returncode == 0 and lines == passthrough,
            "sh launcher REAL entry probe failed (the launcher did not parse and "
            "pass this run's argv): " + repr(real_argv))
    return {"probed": "sh", "parse": ["sh", "-n", str(launcher)],
            "real_entry": {"argv": real_argv, "echoed": lines}}


def _probe_ps1_launcher(launcher: Path, passthrough: list[str],
                        shell: str) -> dict[str, Any]:
    require(shell is not None, "PowerShell launcher probe requires pwsh or powershell")
    script = (
        '$ErrorActionPreference = "Stop"\n'
        '[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n'
        '$tokens = $null; $parseErrors = $null\n'
        '[void][System.Management.Automation.Language.Parser]::ParseFile($env:CG_LAUNCHER_PROBE, '
        '[ref]$tokens, [ref]$parseErrors)\n'
        'if ($parseErrors.Count -gt 0) { throw ($parseErrors -join "`n") }\n'
        # PowerShell 5.1 emits the parsed array as one pipeline object; an
        # outer @() nests it and casting that element to string merges argv.
        '[string[]]$rest = ConvertFrom-Json -InputObject $env:CG_PASSTHROUGH_PROBE\n'
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


def _prepare_result(plan: dict[str, Any], subject: dict[str, Any]) -> dict[str, Any]:
    """The stage decision for one fresh preflight subject; shared by prepare
    and the controlled rebind, so a rebound batch re-derives the swap gate
    exactly as a first preparation would."""
    installed = subject["installed_before"]
    host_status = subject["host"]["status"]
    if installed["installed"] and installed["version"] == plan["target_version"]:
        status = "already_current"
        swap = {"required": False,
                "reason": "installed version already equals the target version"}
    elif not installed["installed"]:
        if plan["mode"] == HOT_MODE:
            raise UpgradeError("between-turns mode upgrades an existing stable-identity "
                               "installation; none observed; use the stopped-host route")
        status = "prepared"
        swap = {"required": False,
                "reason": "no existing stable-identity installation; nothing consumes the old cache"}
    elif plan["mode"] == HOT_MODE:
        status = "prepared"
        swap = {"required": False,
                "reason": "between-turns route keeps the Desktop host running; the old "
                          "runtime's activity is drained around the official add"}
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
    return {"schema": _report_schema(plan["mode"]), "stage": "prepare", "mode": plan["mode"],
            "status": status, "subject": subject,
            "subject_sha256": base.digest(subject), "swap": swap,
            "commands": subject["commands"],
            "pending": ["apply", "verify"]}


def prepare(plan: dict[str, Any], output: Path) -> dict[str, Any]:
    subject = _preflight_checks(plan)
    _claim_output(subject, output)
    base._mkdir_private_new(output)
    result = _prepare_result(plan, subject)
    base._write_new(output / PREPARE_NAME, result)
    print(json.dumps({"status": result["status"], "stage": "prepare",
                      "host": subject["host"]["status"],
                      "swap_required": result["swap"]["required"]}))
    return result


# ------------------------------------------------------ resume / rebind ----


def _numbered_receipt(output: Path, base_name: str) -> Path:
    """The next exclusive numbered receipt for one stage family.

    Like the verify receipts, existing files are never replaced; the newest
    numbered receipt keeps the latest state and every prior receipt stays.
    """
    candidate = output / base_name
    if not candidate.exists():
        return candidate
    stem = base_name.removesuffix(".json")
    index = 2
    while (output / f"{stem}-{index}.json").exists():
        index += 1
    return output / f"{stem}-{index}.json"


def _rebind_audits(output: Path) -> list[tuple[str, dict[str, Any]]]:
    """Every retained rebind audit receipt, with its own file name."""
    audits = []
    for path in sorted(output.glob("rebind*.json")):
        require(path.is_file() and not path.is_symlink(),
                "rebind audit must be a regular file: " + path.name)
        value = base._read_json(path)
        require(value.get("schema") == REPORT and value.get("stage") == "rebind"
                and isinstance(value.get("rebound_to"), dict),
                "rebind audit is invalid: " + path.name)
        audits.append((path.name, value))
    return audits


def _prepare_receipt_number(path: Path) -> int:
    if path.name == PREPARE_NAME:
        return 1
    match = re.fullmatch(r"prepare-(\d+)\.json", path.name)
    require(match is not None, "unexpected prepare receipt name: " + path.name)
    return int(match.group(1))


def _all_prepare_receipts(output: Path) -> list[Path]:
    """Every prepare receipt on disk, ordered; a gap is removed evidence.

    Enumeration covers the whole directory (glob, not a ``while exists``
    walk), so a deleted middle receipt is never invisible behind a higher
    numbered one.
    """
    found = []
    for path in output.glob("prepare*.json"):
        if not re.fullmatch(r"prepare(-\d+)?\.json", path.name):
            continue
        require(path.is_file() and not path.is_symlink(),
                "prepare receipt must be a regular file: " + path.name)
        found.append(path)
    found.sort(key=_prepare_receipt_number)
    for earlier, later in zip(found, found[1:]):
        require(_prepare_receipt_number(later) == _prepare_receipt_number(earlier) + 1,
                "prepare receipt " + earlier.name + " was removed while "
                + later.name + " exists; retained evidence was removed and the "
                "batch must not continue")
    return found


def _load_prepare_receipt(output: Path, receipt: Path) -> dict[str, Any]:
    """One prepare receipt with its embedded subject digest recomputed."""
    value, _sha = _read_bound_result(receipt, stage="prepare")
    require(isinstance(value.get("subject"), dict)
            and base.digest(value["subject"]) == value.get("subject_sha256"),
            "prepare receipt " + receipt.name + " content does not match its "
            "subject digest; retained evidence was modified")
    return value


def _audit_bound(audits: list[tuple[str, dict[str, Any]]], receipt: Path,
                 subject_sha256: Any) -> bool:
    return any(value["rebound_to"].get("receipt") == receipt.name
               and value["rebound_to"].get("subject_sha256") == subject_sha256
               for _name, value in audits)


def _resolve_prepare_receipt(output: Path, *, strict: bool) -> Path | None:
    """The adoptable prepare receipt for one entry point, over one law.

    Every caller — resume, apply, verify, rebind, an explicit
    ``--prepared-result`` or the batch default — consumes this single
    production path. It enumerates the whole directory, recomputes each
    receipt's subject digest, and validates the audited chain: a numbered
    receipt is adoptable only when it chains to the previously adopted
    receipt through a matching ``rebound_from`` and a retained rebind audit
    binds both its file name and its subject digest. Refusal families:

    - an audit whose target receipt is missing, or a numbering gap, means
      retained evidence was removed and refuses every entry;
    - a receipt whose content no longer matches its subject digest refuses
      everywhere (its evidence was modified);
    - an unchained or unbound numbered receipt behind the adopted chain end
      is retained orphan evidence that cannot bypass it; at or past the chain
      end it refuses with the deterministic recovery (re-run ``--rebind``).
    """
    audits = _rebind_audits(output)
    for audit_name, audit in audits:
        target = str(audit["rebound_to"].get("receipt"))
        require((output / target).is_file(),
                "rebind audit " + audit_name + " references missing prepare receipt "
                + target + "; retained evidence was removed and the batch must "
                "not continue")
    receipts = _all_prepare_receipts(output)
    if not receipts:
        return None
    initial = receipts[0]
    require(_prepare_receipt_number(initial) == 1,
            "the batch's initial prepare receipt is missing; retained evidence "
            "was removed and the batch must not continue")
    initial_value = _load_prepare_receipt(output, initial)
    adoptable = initial
    prev_name, prev_digest = initial.name, initial_value.get("subject_sha256")
    orphans: list[tuple[Path, str]] = []
    for receipt in receipts[1:]:
        # Recovery may retain a valid receipt whose audit was not written.
        # Modified content is an integrity failure for every entry point.
        value = _load_prepare_receipt(output, receipt)
        rebound = value.get("rebound_from")
        linked = (isinstance(rebound, dict)
                  and rebound.get("receipt") == prev_name
                  and rebound.get("subject_sha256") == prev_digest
                  and _audit_bound(audits, receipt, value.get("subject_sha256")))
        if linked:
            adoptable = receipt
            prev_name, prev_digest = receipt.name, value.get("subject_sha256")
        else:
            reason = ("does not chain to the adopted receipt " + str(prev_name)
                      if not isinstance(rebound, dict)
                      or rebound.get("receipt") != prev_name
                      or rebound.get("subject_sha256") != prev_digest
                      else "has no binding rebind audit")
            orphans.append((receipt, reason))
    if strict:
        adopted_number = _prepare_receipt_number(adoptable)
        for orphan, reason in orphans:
            # Orphans behind the adopted chain end are retained evidence and
            # cannot bypass it; an orphan at or past the chain end is an
            # interrupted rebind and refuses with the deterministic recovery.
            require(_prepare_receipt_number(orphan) < adopted_number,
                    "interrupted rebind: " + orphan.name + " " + reason
                    + "; re-run --rebind to recover (prior receipts are retained)")
    return adoptable


def _require_explicit_prepared(output: Path, prepared_path: Path) -> None:
    """An explicit stage target must be the batch's adoptable prepare receipt.

    No entry point may consume a stale, orphaned, modified or removed
    receipt: apply, verify and rebind all resolve the same adopted chain and
    refuse anything else, whatever the operator named on the command line.
    """
    resolved = _resolve_prepare_receipt(output, strict=True)
    require(resolved is not None and resolved == prepared_path,
            "prepared receipt is not this batch's current adoptable prepare "
            "receipt: " + str(resolved))


DRIFT_ADVICE = {
    "cli": "the CLI identity changed; re-review it in a new plan and start a new batch",
    "tool_sha256": "the operator tool changed since preparation; start a new batch",
    "helpers": "the executed helper closure changed since preparation; start a new batch",
    "python": "the interpreter changed; start a new batch",
    "host_tools": "the process-enumeration tool identity changed; start a new batch",
    "plan_sha256": "the plan changed; a rebind never accepts plan changes",
    "artifact": "the target artifact changed; re-run a reviewed preflight in a new batch",
    "market_identity": "the stable marketplace identity changed; start a new batch",
    "daily_home": "the daily HOME changed; start a new batch",
    "invocation_cwd": "re-run from the preparation working directory",
    "sandbox_markers": "a sandbox marker identity changed; start a new batch",
    "desktop_executable": "the desktop executable path changed; write a new plan and start a new batch",
}


def rebind(plan: dict[str, Any], output: Path,
           prepared_path: Path | None) -> dict[str, Any]:
    """Controlled host re-identification for an unstarted batch.

    The rebind belongs to the stopped-host route only; a between-turns batch
    with a changed host or plan starts a new batch instead.

    After a preparation, only one input may legitimately change by itself:
    the Desktop host auto-updates in place, so the pinned desktop executable
    keeps its path but its bytes move. A rebind re-derives the full preflight
    subject (trusted source, actual file identities, host state and every
    other pinned input), accepts exactly that one drift, keeps every prior
    receipt untouched, and writes the next numbered prepare receipt bound to
    the new host identity. Any other change refuses with its own category,
    and a batch whose apply already began is never rebound — it recovers by
    its original journal instead.
    """
    require(plan["mode"] == COLD_MODE,
            "between-turns batches do not use the stopped-host rebind; start a "
            "new batch for a changed host or a changed plan")
    require(output.is_absolute(), "output must be an absolute path")
    require(output.is_dir() and not output.is_symlink(),
            "rebind requires the existing batch output directory")
    if prepared_path is not None:
        # An explicitly named source must be the batch's current adoptable
        # receipt; an operator cannot rebind from a stale one.
        _require_explicit_prepared(output, prepared_path)
    else:
        # The default recovery path rebinds the newest adoptable prepare
        # receipt, so a second host update rebinds the already rebound
        # batch; an orphan receipt from an interrupted rebind stays as
        # retained evidence and is never the source.
        prepared_path = _resolve_prepare_receipt(output, strict=False)
    require(prepared_path is not None,
            "rebind requires an existing prepare receipt")
    require(prepared_path.parent == output,
            "the prepare receipt must live in this batch's output directory")
    require(not (output / JOURNAL_NAME).is_file(),
            "apply already began in this batch; recover by its original journal, "
            "not a rebind")
    require(not (output / APPLY_NAME).is_file(),
            "apply already completed in this batch; a rebind is not available")
    prepared, prepared_sha = _read_bound_result(prepared_path, stage="prepare")
    subject = _preflight_checks(plan)
    old_view, new_view = _binding_view(prepared["subject"]), _binding_view(subject)
    drift = sorted(key for key in set(old_view) | set(new_view)
                   if old_view.get(key) != new_view.get(key))
    if drift != ["desktop_executable"]:
        detail = "; ".join(key + ": " + DRIFT_ADVICE.get(key, "start a new batch")
                           for key in drift) or "no drift; the batch can continue as-is"
        raise UpgradeError("rebind accepts only a same-path desktop executable byte "
                           "change (a host auto-update after preparation); refused: "
                           + detail)
    old_host, new_host = old_view["desktop_executable"], new_view["desktop_executable"]
    require(_same_path(old_host.get("path"), new_host.get("path")),
            DRIFT_ADVICE["desktop_executable"])
    # Trusted-publisher boundary: both the prepared host and the changed
    # host bytes must carry a verified platform signature from the same
    # publisher. An unverifiable signature refuses; this is a provenance
    # check, not a security sandbox.
    old_pub = old_host.get("publisher") or {}
    new_pub = new_host.get("publisher") or {}
    require(old_pub.get("verified") is True and old_pub.get("identity"),
            "the preparation receipt did not record a verified publisher "
            "identity; start a new batch")
    if sys.platform == "darwin":
        # Trust-anchor re-audit: the changed bytes must satisfy the prepared
        # publisher's requirement (anchor + trusted + OU), not merely a
        # self-reported team string.
        bound_pub = _host_publisher(Path(new_host["path"]), _scrubbed_env(),
                                    subject["host_tools"],
                                    expected_team=old_pub.get("identity"))
        require(bound_pub.get("verified") is True,
                "the changed host bytes do not satisfy the prepared publisher "
                "requirement" + (" (" + str(bound_pub.get("reason")) + ")"
                                 if bound_pub.get("reason") else "")
                + "; start a new batch")
        require(bound_pub.get("identity") == old_pub.get("identity"),
                "the host update was signed by a different publisher ("
                + str(old_pub.get("identity")) + " -> "
                + str(bound_pub.get("identity")) + "); start a new batch")
    else:
        # Limited Windows boundary: a Valid Authenticode status with the
        # same certificate thumbprint. Certificate rotation changes the
        # thumbprint and is refused — never auto-allowed.
        require(new_pub.get("verified") is True,
                "the changed host bytes are not a verified publisher-signed update"
                + (" (" + str(new_pub.get("reason")) + ")" if new_pub.get("reason")
                   else "") + "; start a new batch")
        require(new_pub.get("identity") == old_pub.get("identity"),
                "the host update was signed by a different publisher ("
                + str(old_pub.get("identity")) + " -> " + str(new_pub.get("identity"))
                + "); start a new batch")
    new_prepare = _numbered_receipt(output, PREPARE_NAME)
    result = _prepare_result(plan, subject)
    result["rebound_from"] = {"receipt": prepared_path.name,
                              "subject_sha256": prepared["subject_sha256"],
                              "prepared_sha256": prepared_sha,
                              "drift": drift}
    base._write_new(new_prepare, result)
    audit = {"schema": REPORT, "stage": "rebind", "mode": COLD_MODE, "status": "rebound",
             "previous": {"receipt": prepared_path.name,
                          "subject_sha256": prepared["subject_sha256"]},
             "rebound_to": {"receipt": new_prepare.name,
                            "subject_sha256": result["subject_sha256"]},
             "drift": drift,
             "desktop_executable": {"path": new_host["path"],
                                    "previous_sha256": old_host["sha256"],
                                    "current_sha256": new_host["sha256"]}}
    base._write_new(_numbered_receipt(output, REBIND_NAME), audit)
    print(json.dumps({"status": "rebound", "stage": "rebind",
                      "receipt": str(new_prepare),
                      "resume": "re-run the same command with --resume to continue"}))
    return audit


def _wait_for_host_exit(plan: dict[str, Any], deadline: float) -> None:
    """Bounded read-only wait for the Desktop host to exit; closes nothing.

    Polls the pinned-executable inventory until the host is observed absent
    or the deadline passes. The caller re-runs apply afterwards, whose fresh
    apply-time inventory remains the deciding gate. Nothing is ever closed
    or signalled; unrelated processes do not gate the wait.
    """
    env = _scrubbed_env()
    host_tools = _inventory_host_tools(env)
    while _now() < deadline:
        state = _host_inventory(plan["desktop_executable"],
                                plan["sandbox_markers"], host_tools)
        if state.get("status") == "absent":
            return
        _sleep(min(WAIT_POLL_SECONDS, max(0.0, deadline - _now())))


def resume(plan: dict[str, Any], output: Path, wait_minutes: int | None = None) -> int:
    """The thin same-command continuation across the batch's pending stages.

    This dispatches to the existing stage implementations and adds no rule
    of its own: a missing prepare receipt is prepared, an unapplied prepared
    batch is applied (the host-absent gate still answers with its one precise
    instruction), and every arrival verifies. All identity, drift, adoption
    and journal reconciliation checks run exactly as in a directly typed
    command. With ``wait_minutes`` a host-absent pending state becomes a
    bounded in-process wait for the host to exit, after which apply is
    retried — the operator starts the command once, quits the host at
    leisure, and the batch continues; killing the wait loses nothing because
    the batch receipts are the persistence layer and the same command
    resumes.
    """
    require(output.is_absolute(), "output must be an absolute path")
    if _resolve_prepare_receipt(output, strict=True) is None:
        prepare(plan, output)
    prepared_path = _resolve_prepare_receipt(output, strict=True)
    require(prepared_path is not None, "batch has no prepare receipt")
    prepared, _sha = _read_bound_result(prepared_path, stage="prepare",
                                        mode=plan["mode"])
    if prepared.get("status") == "prepared" and not (output / APPLY_NAME).is_file():
        deadline = None if wait_minutes is None else _now() + wait_minutes * 60
        while True:
            try:
                apply(plan, output, prepared_path)
                break
            except HostPending:
                if deadline is None or _now() >= deadline:
                    raise
                print(json.dumps({"stage": "resume", "status": "waiting_for_host_exit",
                                  "wait_minutes": wait_minutes}))
                _wait_for_host_exit(plan, deadline)
    result = verify(plan, output, prepared_path, None)
    return 0 if result["status"] == "passed" else 1


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


def _reconcile_between_turns_prestate(prepared: dict[str, Any], current: dict[str, Any],
                                      journal: _Journal, plan: dict[str, Any]) -> None:
    """Refuse daily-state changes this batch did not record, before mutating.

    The between-turns route moves the marketplace registration only through
    its own recorded intents and expects the official cross-version add to
    prune the old cache; anything else refuses.
    """
    pre = prepared["subject"]["installed_before"]
    target = plan["target_version"]
    successful = {event.get("stage") for event in journal.facts()
                  if event.get("exit_code") == 0}
    if "plugin_add" in successful:
        require(current["installed"] and current["version"] == target,
                "target installation changed after the recorded successful add")
    if "marketplace_add" in successful:
        require(current["registered"]
                and _same_path(current["market_root"], plan["artifact_dir"]),
                "marketplace changed after the recorded successful add")
    if current["installed"]:
        require(current["version"] in (pre["version"], target),
                "installed version changed outside this batch; re-prepare")
        if current["version"] == target and pre["version"] != target:
            require(journal.has_intent("plugin_add"),
                    "target installation appeared without a recorded add from this batch")
    else:
        # The CLI may temporarily omit an unregistered installation during
        # this batch's own registration gap. Its exact old tree must still
        # exist; no plugin removal is part of this transition.
        require(pre["installed"] and journal.has_intent("marketplace_remove")
                and not current["registered"]
                and _old_slot_outcome(plan, prepared["subject"]["compatibility"])["status"]
                == "retained_intact",
                "the existing installation disappeared without a recorded removal "
                "from this batch; the between-turns route never removes the plugin")
    if current["registered"]:
        root = current["market_root"]
        pre_root = pre["market_root"]
        if not _same_path(root, pre_root):
            require(journal.has_intent("marketplace_add")
                    and _same_path(root, plan["artifact_dir"]),
                    "marketplace registration changed outside this batch; re-prepare")
        elif "marketplace_remove" in successful and not _same_path(root, plan["artifact_dir"]):
            raise UpgradeError("marketplace registration reappeared after its recorded removal")
    else:
        require(journal.has_intent("marketplace_remove") or not pre["registered"],
                "marketplace registration disappeared without a recorded removal "
                "from this batch")


def _apply_between_turns(plan: dict[str, Any], output: Path, prepared: dict[str, Any],
                         prepared_sha: str, subject: dict[str, Any]) -> dict[str, Any]:
    """The official between-turns swap; the Desktop host stays running.

    Sequence: fresh activity drain of the old cached runtime, official
    marketplace repoint only if the registration still names another source,
    a second fresh drain, then exactly one official ``plugin add`` — never a
    plugin remove. The official cross-version install prunes the old cache;
    that is the disclosed proved-compatible runtime migration, not old-byte
    preservation. An interrupted run reconciles official readbacks instead of
    repeating the add, and a trust-pending resume never duplicates it.
    """
    cli = Path(subject["cli"]["path"])
    env = _scrubbed_env()
    daily = Path(subject["daily_home"])
    host_tools = subject["host_tools"]
    old_version = prepared["subject"]["installed_before"]["version"]
    drain_deadline = _now() + plan["drain_seconds"]
    begin = {"event": "begin", "schema": JOURNAL_SCHEMA_V2, "mode": HOT_MODE,
             "subject_sha256": base.digest(_binding_view(subject)),
             "prepared_sha256": prepared_sha}
    journal = _Journal(output / JOURNAL_NAME, begin)
    try:
        _check_hot_journal(plan, subject, prepared_sha, output)
        current = _daily_state(cli, env, "apply_state")
        for fact in current["commands"]:
            journal.raw_fact(fact)
        _reconcile_between_turns_prestate(prepared, current, journal, plan)
        while True:
            activity = _runtime_activity(
                daily, old_version, host_tools, compatibility=subject["compatibility"],
                allow_absent=current["version"] == plan["target_version"])
            if activity["status"] == "clear":
                break
            if activity.get("query_cleanup") == "unconfirmed":
                raise HostPending("activity query cleanup unconfirmed; keep new operations paused "
                                  "and review the owned query before retrying")
            if _now() >= drain_deadline:
                raise HostPending(
                    "between-turns activity drain timed out: the old cached runtime "
                    "still shows " + activity["status"] + " process candidates. Pause "
                    "starting new operations, then re-run the same command; nothing "
                    "is ever killed.")
            print(json.dumps({"stage": "apply", "status": "draining",
                              "activity": activity["status"]}))
            _sleep(min(WAIT_POLL_SECONDS, max(0.0, drain_deadline - _now())))
        artifact_str = plan["artifact_dir"]
        # Official marketplace-level repoint; the plugin itself is never removed.
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
        # The first drain may wait for minutes. Recheck all prepared inputs
        # and live official state before the final observation, not only at
        # the start of apply.
        fresh = _preflight_checks(plan)
        require(_binding_view(fresh) == _binding_view(subject),
                "prepared inputs drifted during the activity drain")
        current = fresh["installed_before"]
        for fact in fresh["commands"]:
            journal.raw_fact(fact)
        _reconcile_between_turns_prestate(prepared, current, journal, plan)
        # Second fresh drain immediately before the official add.
        activity = _runtime_activity(
            daily, old_version, host_tools, compatibility=subject["compatibility"],
            allow_absent=current["version"] == plan["target_version"])
        if activity.get("query_cleanup") == "unconfirmed":
            raise HostPending("activity query cleanup unconfirmed; keep new operations paused "
                              "and review the owned query before retrying")
        if activity["status"] != "clear":
            raise HostPending(
                "between-turns activity drain observed " + activity["status"]
                + " before the official add. Pause starting new operations, then "
                "re-run the same command; nothing is ever killed.")
        # A snapshot is not a lock. Bind the actual directory handed to the
        # official add again after the last query, before recording intent.
        require(_verify_artifact(plan) == subject["artifact"],
                "target artifact drifted during the final activity observation")
        require(_helper_identities() == subject["helpers"]
                and _sha_loose(cli) == subject["cli"]["sha256"],
                "execution helpers or CLI drifted during the final observation")
        # Exactly one official plugin add; never a plugin remove.
        if current["installed"] and current["version"] == plan["target_version"]:
            journal.note("plugin_add", "target installation already present; add not repeated")
        else:
            argv = [str(cli), "plugin", "add", ENTRY, "--json"]
            journal.intent("plugin_add", argv)
            result = _run_command(argv, env)
            extra: dict[str, Any] = {}
            if result.returncode == 0 and base._summary_dict(result) is None:
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
        old_outcome = _old_slot_outcome(plan, subject["compatibility"])
        journal.note("apply_complete", "official stages reconciled; apply receipt follows")
        result = {"schema": REPORT_V2, "stage": "apply", "mode": HOT_MODE,
                  "transition": HOT_MODE, "status": "applied",
                  "subject_sha256": base.digest(_binding_view(subject)),
                  "prepared_sha256": prepared_sha,
                  "installed_after": installed_after,
                  "old_slot_outcome": old_outcome,
                  "commands": journal.facts(),
                  "host_status_at_swap": subject["host"]["status"],
                  "pending": ["hook_trust_review", "verify"]}
        base._write_new(output / APPLY_NAME, result)
        print(json.dumps({"status": "applied", "stage": "apply", "mode": HOT_MODE,
                          "version": installed_after["version"],
                          "host": subject["host"]["status"],
                          "hook_trust_pending": installed_after["enabled"] is not True}))
        return result
    finally:
        journal.close()


def apply(plan: dict[str, Any], output: Path, prepared_path: Path) -> dict[str, Any]:
    prepared, prepared_sha = _read_bound_result(prepared_path, stage="prepare",
                                                mode=plan["mode"])
    require(output.is_dir() and not output.is_symlink(),
            "apply requires the existing batch output directory")
    require(prepared_path.parent == output,
            "the prepare receipt must live in this batch's output directory")
    _require_explicit_prepared(output, prepared_path)
    if prepared.get("status") == "already_current":
        raise UpgradeError("installed version already equals the target; run --verify instead")
    require(prepared.get("status") == "prepared", "prepare receipt is not applicable")
    if plan["mode"] == HOT_MODE and (output / APPLY_NAME).exists():
        completed, _sha = _read_bound_result(output / APPLY_NAME, stage="apply", mode=HOT_MODE)
        require(completed.get("prepared_sha256") == prepared_sha,
                "completed apply belongs to another preparation")
        raise UpgradeError("apply has already completed; run --verify or --resume")
    subject = _preflight_checks(plan)
    drift = sorted(key for key in set(_binding_view(subject))
                   | set(_binding_view(prepared["subject"]))
                   if _binding_view(subject).get(key) != _binding_view(prepared["subject"]).get(key))
    require(not drift, "preparation and execution drifted: " + ", ".join(drift))
    if plan["mode"] == HOT_MODE:
        return _apply_between_turns(plan, output, prepared, prepared_sha, subject)
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
        result = {"schema": REPORT, "stage": "apply", "mode": COLD_MODE,
                  "status": "applied",
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
        self.reader = None
        try:
            launch = [str(cli)]
            if platform.system() == "Windows":
                launch += ["-c", 'windows.sandbox="mxc"', "-c", "allow_login_shell=false"]
            child_env = {**env, "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1"}
            self.owned = OwnedProcess.spawn([*launch, "app-server"], cwd=str(cwd), env=child_env,
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=self.err, text=True, encoding="utf-8")
            self.reader = threading.Thread(target=self._reader, daemon=True)
            self.reader.start()
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
            if self.reader is not None:
                self.reader.join(timeout=2)
                require(not self.reader.is_alive(), "probe reader cleanup incomplete")
            if self.owned is not None:
                for stream in (self.owned.process.stdin, self.owned.process.stdout):
                    if stream is not None:
                        stream.close()
        finally:
            self.log.close()
            self.err.close()
        return cleanup


def _loaded_probe(cli: Path, cwd: Path, journal_dir: Path,
                  env: dict[str, str]) -> dict[str, Any]:
    """What Hook sources a brand-new client actually loads; never a turn.

    ``journal_dir`` is created here as an exclusive attempt directory; a
    caller must pick the next unused index instead of reusing one.
    Inventory-level errors/warnings are recorded as flags — their text is
    never retained — and never allow a pass.
    """
    record: dict[str, Any] = {"schema": PROBE_SCHEMA, "hooks": [], "inventory_flagged": False,
                              "cleanup": None, "reason": None}
    client = None
    try:
        base._mkdir_private_new(journal_dir)
        client = _ProbeClient(cli, cwd, journal_dir, env)
        data = client.hooks_raw.get("data") if isinstance(client.hooks_raw, dict) else None
        require(isinstance(data, list) and len(data) == 1
                and isinstance(data[0], dict) and isinstance(data[0].get("hooks"), list),
                "Hook inventory unavailable")
        record["inventory_flagged"] = bool(data[0].get("errors")) or bool(data[0].get("warnings"))
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
        cleanup = record["cleanup"]
        if cleanup is not None and not (
                cleanup.get("cleanup_complete") is True
                or (cleanup.get("owned_process_exited") is True
                    and cleanup.get("owned_tree_no_running_members") is True
                    and not cleanup.get("process_group_cleanup_error"))):
            # An unknown probe cleanup is an honest observation gap, never a
            # pass; verify reports it as loaded_unknown. A group that already
            # vanished naturally is the owned-tree verdict above, matching the
            # acceptance toolkit's cleanup conventions.
            record["reason"] = record["reason"] or "probe_cleanup_unknown"
    return record


def _route_ccg_hooks(rows: list[dict[str, Any]], daily: Path,
                     cache_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool | None]:
    """Split Hook rows into fresh/stale Context Guard identity classes.

    A row carries Context Guard identity only when its ``sourcePath`` is the
    exact ``hooks/hooks.json`` of a Context Guard cache slot (official path
    semantics — Windows case-insensitive, POSIX sensitive). Returned old
    source paths remain stale evidence even after official removal deleted
    that cache slot. Rows of other installed plugins,
    or rows with unreadable paths, are never counted as old Context Guard;
    an unreadable path makes the whole inventory unroutable (``None``).
    """
    fresh_path = cache_path / "hooks" / "hooks.json"
    markets = {MARKET, *base.OLD_MARKETS.values(), base.OLD_0161_WRAPPER_MARKET}
    cache_roots = [daily / "plugins" / "cache" / market / PLUGIN_NAME
                   for market in sorted(markets)]
    fresh: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    for row in rows:
        source_path = row.get("sourcePath")
        if not isinstance(source_path, str) or not source_path:
            return [], [], None
        path = Path(source_path)
        if not path.is_absolute():
            return [], [], None
        if _same_path(source_path, str(fresh_path)):
            fresh.append(row)
            continue
        if len(path.parents) >= 3:
            slot = path.parents[1].name
            if any(_same_path(source_path, str(root / slot / "hooks" / "hooks.json"))
                   for root in cache_roots):
                stale.append(row)
                continue
        if any(_same_path(str(parent), str(root))
               for root in cache_roots for parent in path.parents):
            # A malformed source inside this product's cache is not an
            # unrelated plugin whose row can be discarded.
            return [], [], None
    return fresh, stale, True


# ----------------------------------------------------------------- verify ----


def _next_verify_receipt(output: Path) -> Path:
    """Same-command verification resume: the next exclusive numbered receipt.

    Existing receipts are never replaced or re-read as evidence; the newest
    numbered receipt keeps the latest verdict and every prior receipt stays.
    """
    candidate = output / VERIFY_NAME
    if not candidate.exists():
        return candidate
    index = 2
    while (output / f"verify-{index}.json").exists():
        index += 1
    return output / f"verify-{index}.json"


def verify(plan: dict[str, Any], output: Path, prepared_path: Path,
           verify_output: Path | None) -> dict[str, Any]:
    """Re-derive the current machine state; never reuse a historical receipt.

    A prior verify receipt — passed or pending — is a historical result. Every
    verify refreshes the live official readbacks, the installed-cache parity
    and the fresh-client Hook facts, and records its verdict in the next
    exclusive numbered receipt; prior receipts are never replaced. Only the
    destructive apply stages are resume-once work; verification is a
    measurement, and a passed receipt never substitutes for current state.
    """
    prepared, prepared_sha = _read_bound_result(prepared_path, stage="prepare",
                                                mode=plan["mode"])
    require(output.is_dir() and not output.is_symlink(),
            "verify requires the existing batch output directory")
    require(prepared_path.parent == output, "the prepare receipt must live in this output directory")
    _require_explicit_prepared(output, prepared_path)
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
        apply_result, _apply_sha = _read_bound_result(output / APPLY_NAME, stage="apply",
                                                       mode=plan["mode"])
        require(apply_result.get("status") == "applied", "apply has not completed")
        require(apply_result.get("prepared_sha256") == prepared_sha,
                "apply result was bound to a different prepare receipt")
        require(apply_result.get("subject_sha256") == fresh_binding,
                "apply result was bound to a different execution identity")
        if plan["mode"] == HOT_MODE:
            _check_hot_journal(plan, subject, prepared_sha, output, apply_result)
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
    if plan["mode"] == HOT_MODE:
        _old_slot_outcome(plan, subject["compatibility"])
    # Fresh-client loaded-version probe under an exclusive attempt index.
    probe_root = output / "probe" / "loaded"
    for private_dir in (probe_root.parent, probe_root):
        if private_dir.exists() or private_dir.is_symlink():
            base._no_link_ancestors(private_dir)
            require(private_dir.is_dir(), "probe output must be a directory")
            base._private_directory(private_dir)
        else:
            base._mkdir_private_new(private_dir)
    index = 1
    while (probe_root / f"loaded-{index}").exists():
        index += 1
    probe = _loaded_probe(cli, plan["cwd"], probe_root / f"loaded-{index}", env)
    if probe["reason"] is not None:
        loaded = "unknown"
        fresh_rows: list[dict[str, Any]] = []
        structural = False
    else:
        fresh_rows, stale_rows, routable = _route_ccg_hooks(probe["hooks"], daily, cache_path)
        if routable is None:
            loaded = "unknown"
        elif fresh_rows and stale_rows:
            loaded = "old"
        elif stale_rows:
            loaded = "old"
        elif fresh_rows:
            loaded = "new"
        else:
            loaded = "none"
        # The verdict family: the exact nine events, one row each, plugin
        # source, no inventory errors/warnings. Missing, duplicate, unknown
        # event, wrong-source and flagged inventories never pass.
        structural = (loaded == "new" and not probe["inventory_flagged"]
                      and len(fresh_rows) == len(EVENTS)
                      and sorted(row["eventName"] for row in fresh_rows) == sorted(EVENTS)
                      and all(row.get("source") == "plugin" for row in fresh_rows))
    trust_pending = (structural and (current["enabled"] is not True
                                     or any(row.get("trustStatus") != "trusted"
                                            or row.get("enabled") is not True
                                            for row in fresh_rows)))
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
    elif not structural:
        status = "hook_inventory_incomplete"
        detail = ("the fresh-client Hook inventory is not exactly the nine trusted "
                  "Context Guard plugin Hooks from " + str(cache_path))
    elif trust_pending:
        status = "hook_trust_pending"
        detail = ("review the nine Hooks through CLI /hooks or Desktop Review hooks / "
                  "Settings > Hooks, from "
                  + str(cache_path))
    else:
        status = "passed"
        detail = None
    data_policy = _data_policy(plan, env, current["commands"], current["version"])
    result = {"schema": _report_schema(plan["mode"]), "stage": "verify", "mode": plan["mode"],
              "status": status, "detail": detail,
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
    if verify_output is None:
        verify_output = _next_verify_receipt(output)
    elif Path(verify_output).exists():
        raise UpgradeError("explicit verify output already exists: " + str(verify_output))
    elif Path(verify_output).parent == output:
        pass
    else:
        _claim_output(subject, Path(verify_output))
    base._write_new(Path(verify_output), result)
    print(json.dumps({"status": status, "stage": "verify",
                      "fresh_client_loaded": loaded,
                      "receipt": str(verify_output)}))
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
    action.add_argument("--resume", action="store_true",
                        help="thin same-command continuation over the batch's receipts")
    action.add_argument("--rebind", action="store_true",
                        help="controlled host re-identification for an unstarted batch")
    parser.add_argument("--prepared-result", type=Path)
    parser.add_argument("--verify-output", type=Path)
    parser.add_argument("--wait", action="store_true",
                        help="with --resume: wait for the Desktop host to exit, then continue")
    parser.add_argument("--wait-minutes", type=int, default=WAIT_MINUTES_DEFAULT,
                        help="bounded wait ceiling in minutes (1-%d, default %d)"
                             % (WAIT_MINUTES_MAX, WAIT_MINUTES_DEFAULT))
    args = parser.parse_args(argv)
    if not args.verify and args.verify_output is not None:
        parser.error("--verify-output requires --verify")
    if args.wait and not args.resume:
        parser.error("--wait requires --resume")
    if args.wait and not 1 <= args.wait_minutes <= WAIT_MINUTES_MAX:
        parser.error("--wait-minutes must be between 1 and %d" % WAIT_MINUTES_MAX)
    if not args.wait and args.wait_minutes != WAIT_MINUTES_DEFAULT:
        parser.error("--wait-minutes requires --wait")
    if args.apply or args.verify:
        prepared = args.prepared_result or (args.output / PREPARE_NAME)
    elif args.rebind:
        # Default: the newest numbered prepare receipt in the batch.
        prepared = args.prepared_result
    elif args.prepared_result is not None:
        parser.error("--prepared-result requires --apply, --verify or --rebind")
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
        elif args.rebind:
            rebind(plan, args.output, prepared)
        elif args.resume:
            if args.wait and plan["mode"] == HOT_MODE:
                raise UpgradeError(
                    "--wait waits for the Desktop host to exit; the between-turns mode "
                    "keeps it running across the swap and never asks for a quit. Use a "
                    "stopped-host (v1) plan for the wait route.")
            return resume(plan, args.output,
                          wait_minutes=args.wait_minutes if args.wait else None)
        else:
            require(prepared is not None, "prepared result required")
            result = verify(plan, args.output, prepared, args.verify_output)
            return 0 if result["status"] == "passed" else 1
    except (HostPending, CapabilityPending) as exc:
        print("daily_upgrade=pending; " + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("daily_upgrade=pending; interrupted by the operator; batch "
              "receipts are intact and the same command resumes", file=sys.stderr)
        return 1
    except (UpgradeError, OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        print("daily_upgrade=refused; " + type(exc).__name__ + "; " + str(exc)[:300],
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
