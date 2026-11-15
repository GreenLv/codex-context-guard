#!/usr/bin/env python3
"""Verify one between-turns upgrade using an owned app-server and real turns.

The v2 native plan binds the reviewed source, artifacts and maintained daily
v2 tool. Preflight is read-only; run uses the normal account and Hook review.
The independent verify-result action rechecks saved evidence and final installed
state without starting a model or repeating installation. CLI observations do
not establish Desktop GUI loading or an execution-time file allowlist.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import ntpath
import os
import platform
import queue
import re
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.validation import hook_failure_diagnostics  # noqa: E402
from tools.validation import native_acceptance as native_io  # noqa: E402
from tools.validation import native_upgrade_acceptance as native_identity  # noqa: E402

PLAN = "cg-between-turn-native-plan/v2"
REPORT = "cg-between-turn-native-result/v3"
INDEPENDENT = "cg-between-turn-independent/v3"
STATE_CAPTURE = "cg-between-turn-state-captures/v1"
CAPTURE_EVIDENCE = frozenset({"old-after-full-state.json", "post-close-full-state.json", "post-close.json"})
CONFIG_REFRESH = "reload-user-config-empty-batch"
REVIEWED_CLI_VERSION = "codex-cli 0.169.0-alpha.11.1"
REVIEWED_CLI_SHA256 = {
    "Darwin": "3ea20787e106af94573d3d6c19480aed93a1334b0dd32b6b04e2f780ce82cf4b",
    "Windows": "094d4db493de22025712cc5963854e7654b7c97f4cee795e3e986270a0f4f6b4",
}
ENTRY = "context-guard@codex-context-guard"
OLD_RELEASES = {
    "0.17.3": {
        "zip_sha256": "bfdca4456a0946539d5276288e3f9eb5b6b1bae02159748898ffe770f4d63372",
        "runtime_sha256": "a49ccd0e5dd9bc44a58517dbda3587e2fbd337b79ec7ba1214ebf80babb1aab5",
    }
}
EVENTS = {
    "userPromptSubmit",
    "preToolUse",
    "postToolUse",
    "preCompact",
    "sessionStart",
    "subagentStart",
    "subagentStop",
    "stop",
    "sessionEnd",
}
HEX40 = re.compile(r"^[a-f0-9]{40}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


class Refused(Exception):
    pass


class Pending(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def require_reviewed_cli(plan):
    require(
        platform.system() in REVIEWED_CLI_SHA256
        and plan.get("expected_cli_version") == REVIEWED_CLI_VERSION
        and plan.get("cli_sha256") == REVIEWED_CLI_SHA256.get(platform.system()),
        "config refresh requires the reviewed CLI version and platform binary",
    )


_SENSITIVE = re.compile(
    r"^(?:auth\.json(?:\..*)?|credentials?(?:\.json)?|tokens?(?:\.json)?|secrets?(?:\.json)?|\.env(?:\..*)?|\.netrc|_netrc|\.ssh|\.aws)$|.*(?:token|password|secret|credential).*\.json$|.*\.(?:pem|key|p12|pfx)$",
    re.I,
)


def check_path(path):
    p = Path(path)
    require(p.is_absolute(), "absolute path required")
    for component in p.parts:
        require(not _SENSITIVE.fullmatch(component), "sensitive path name refused")
    for item in reversed((p, *p.parents)):
        try:
            info = item.lstat()
        except FileNotFoundError:
            require(item == p, "missing path ancestor")
            continue
        require(
            not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0) & 0x400,
            "linked/reparse path refused",
        )
        if item != p:
            require(stat.S_ISDIR(info.st_mode), "non-directory ancestor")
    return p


def regular(path):
    p = check_path(path)
    info = p.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
        "single-link regular file required",
    )
    return p.resolve(strict=True)


def directory(path):
    p = check_path(path)
    require(p.is_dir(), "required directory unavailable")
    return p.resolve(strict=True)


def _safe_stat_identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _safe_common_identity(info, *, windows_executable=False):
    # Windows path and handle providers can differ in ctime and executable
    # mode bits. Each provider is still checked in full across the read.
    values = list(_safe_stat_identity(info)[:-1])
    if windows_executable:
        values[2] &= ~0o111
    return tuple(values)


def safe_bytes(path, limit=256 * 1024 * 1024):
    p = regular(path)
    before = p.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and not getattr(before, "st_file_attributes", 0) & 0x400,
        "single-link regular file required",
    )
    require(before.st_size <= limit, "input too large")
    fd = native_io.open_snapshot_file(p)
    with os.fdopen(fd, "rb") as f:
        opened = os.fstat(f.fileno())
        windows_executable = os.name == "nt" and p.suffix.casefold() in {
            ".exe", ".com", ".bat", ".cmd"
        }
        require(
            _safe_common_identity(before, windows_executable=windows_executable)
            == _safe_common_identity(opened, windows_executable=windows_executable),
            "input changed before read",
        )
        data = f.read(limit + 1)
        after = os.fstat(f.fileno())
    current = p.lstat()
    require(not getattr(current, "st_reparse_tag", 0)
            and not getattr(current, "st_file_attributes", 0) & 0x400,
            "input became a reparse object during read")
    require(
        len(data) <= limit
        and _safe_stat_identity(opened) == _safe_stat_identity(after)
        and _safe_stat_identity(before) == _safe_stat_identity(current),
        "input changed during read",
    )
    return data


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def strict_json_bytes(data):
    def reject_constant(_value):
        raise Refused("non-finite JSON constant")

    value = json.loads(
        data.decode("utf-8-sig"),
        object_pairs_hook=_unique_pairs,
        parse_constant=reject_constant,
    )
    require(isinstance(value, dict), "JSON object required")
    return value


def strict_read_json(path):
    return strict_json_bytes(safe_bytes(path, 16 * 1024 * 1024))


def strict_read_jsonl(path, max_rows):
    data = safe_bytes(path, 16 * 1024 * 1024)
    require(not data or data.endswith(b"\n"), "truncated JSONL record")
    lines = data.splitlines()
    require(len(lines) <= max_rows, "JSONL oversized")
    return [strict_json_bytes(line) for line in lines]


def producer_path():
    return Path(__file__).resolve()


def diagnostic_path():
    return Path(hook_failure_diagnostics.__file__).resolve()


def sha(path):
    # Executable identities can exceed the bounded record-reader limit.
    # Reuse the streaming no-follow identity verifier, including its separate
    # path/handle checks; JSON and RPC record limits remain unchanged.
    return native_identity.sha(regular(path))


def write(path, value):
    with Path(path).open("x", encoding="utf-8") as f:
        json.dump(value, f, sort_keys=True, ensure_ascii=False, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def verify_zip(archive, expected):
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(safe_bytes(archive))) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        require(
            len(infos) == len(expected)
            and len({i.filename for i in infos}) == len(infos),
            "ZIP file count differs",
        )
        require(
            len(infos) <= 10000
            and sum(i.file_size for i in infos) <= 256 * 1024 * 1024
            and all(i.file_size <= 32 * 1024 * 1024 for i in infos),
            "ZIP expanded content exceeds limits",
        )
        require(
            {i.filename: hashlib.sha256(z.read(i)).hexdigest() for i in infos}
            == expected,
            "ZIP differs from verified manifest",
        )


def within(path, root):
    return path == root or root in path.parents


def filtered_env(home):
    # Preserve the real platform HOME and normal host environment.  No auth
    # files are opened or copied; no ambient token is logged by this module.
    env = {
        k: v
        for k, v in os.environ.items()
        if not re.search(r"TOKEN|PASSWORD|SECRET|API_KEY|CREDENTIAL", k, re.I)
    }
    env["CODEX_HOME"] = str(home)
    env["PYTHONUTF8"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for key in (
        "PLUGIN_ROOT",
        "PLUGIN_DATA",
        "CLAUDE_PLUGIN_DATA",
        "CONTEXT_GUARD_DATA_DIR",
        "OPENAI_BASE_URL",
        "CODEX_OPENAI_BASE_URL",
        "CODEX_CHATGPT_BASE_URL",
        "CHATGPT_BASE_URL",
    ):
        env.pop(key, None)
    return env


def selected_backend(plan):
    if platform.system() == "Windows":
        require(plan.get("windows_backend") == "mxc", "Windows mxc selection required")
        return "mxc"
    require("windows_backend" not in plan, "Windows backend selection on non-Windows")
    return None


def app_server_argv(plan, cli):
    backend = selected_backend(plan)
    if backend == "mxc":
        return [str(cli), "-c", 'windows.sandbox="mxc"', "app-server"]
    return [str(cli), "app-server"]


def provider_projection(response, *, backend=None):
    """Validate only official endpoint selection; retain no raw configuration."""
    require(
        isinstance(response, dict) and isinstance(response.get("config"), dict),
        "effective provider configuration unavailable",
    )
    config = response["config"]
    providers = config.get("model_providers")
    require(
        "model_provider" in config
        and config.get("model_provider") in (None, "openai")
        and isinstance(providers, dict)
        and "openai" not in providers,
        "official model provider overridden",
    )
    require(
        config.get("openai_base_url") in (None, "https://api.openai.com/v1")
        and config.get("chatgpt_base_url")
        in (None, "https://chatgpt.com/backend-api", "https://chatgpt.com/backend-api/")
        and config.get("model_catalog_json") is None,
        "official provider endpoint or model catalog overridden",
    )
    projection = {
        "model_provider": config.get("model_provider"),
        "endpoint_policy": "official_default",
        "custom_catalog": False,
    }
    if backend == "mxc":
        require(isinstance(config.get("windows"), dict)
                and config["windows"].get("sandbox") == "mxc",
                "Windows mxc selection readback differs")
        projection["windows_sandbox"] = "mxc"
    else:
        require(backend is None, "unsupported backend selection")
    return projection


def config_file_projection(home):
    """Read only the file identity and digest; never persist configuration bytes."""
    path = regular(home / "config.toml")
    before = path.lstat()
    data = safe_bytes(path, 8 * 1024 * 1024)
    after = path.lstat()
    require(
        _safe_stat_identity(before) == _safe_stat_identity(after), "config file changed"
    )
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "identity_sha256": hashlib.sha256(
            json.dumps(_safe_stat_identity(after)).encode()
        ).hexdigest(),
    }


def config_layer_projection(response, c):
    provider = provider_projection(response, backend=c["windows_backend"])
    layers = response.get("layers")
    require(
        isinstance(layers, list)
        and all(
            isinstance(x, dict) and isinstance(x.get("name"), dict) for x in layers
        ),
        "config layers unavailable",
    )
    users = [x for x in layers if x["name"].get("type") == "user"]
    require(len(users) == 1, "unique user layer required")
    layer = users[0]
    name = layer["name"]
    require(
        isinstance(name.get("file"), str)
        and c["daily"]._same_path(name["file"], str(c["home"] / "config.toml"))
        and name.get("profile") is None
        and layer.get("disabledReason") is None,
        "active base user layer differs",
    )
    version = layer.get("version")
    require(
        isinstance(version, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", version),
        "user layer version unavailable",
    )
    config = layer.get("config")
    hooks = config.get("hooks") if isinstance(config, dict) else None
    states = hooks.get("state") if isinstance(hooks, dict) else None
    require(isinstance(states, dict), "user Hook state unavailable")
    tables = [x for x in states.values() if isinstance(x, dict)]
    hashes = [
        x.get("trusted_hash") for x in tables if isinstance(x.get("trusted_hash"), str)
    ]
    counts = {
        "entries": len(states),
        "tables": len(tables),
        "hash_strings": len(hashes),
        "combined_hashes": sum("/" in x for x in hashes),
    }
    require(counts["combined_hashes"] == 0, "user Hook trust migration would write")
    return {
        "version": version,
        "shape": counts,
        "provider": provider,
        "unique_active_base_user_layer": True,
    }


def resume_projection(response, c, thread):
    require(
        isinstance(response, dict)
        and isinstance(response.get("thread"), dict)
        and response["thread"].get("id") == thread
        and response.get("model") == c["expected_model"]
        and response.get("modelProvider") == "openai"
        and response.get("approvalPolicy") == "on-request"
        and isinstance(response.get("sandbox"), dict)
        and response["sandbox"].get("type") == "readOnly"
        and isinstance(response.get("cwd"), str)
        and c["daily"]._same_path(response["cwd"], str(c["workspace"])),
        "loaded thread policy readback differs",
    )
    return {
        "thread": {"id": thread},
        "model": response["model"],
        "modelProvider": "openai",
        "approvalPolicy": "on-request",
        "sandbox": {"type": "readOnly"},
        "cwd_matches": True,
    }


def durable_private_receipt(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    if os.name == "posix":
        directory_fd = os.open(Path(path).parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def import_product(repo):
    sys.path.insert(0, str(repo))
    from scripts import artifact_identity as art
    from tools.validation import daily_upgrade as daily
    from tools.validation import native_upgrade_acceptance as u
    from tools.validation import stop_host_acceptance as host

    return u, host, art, daily


def bind_artifact_subject(
    u, art, host, repo, artifact, archive, old_artifact, old_zip, old_version
):
    files = art.distribution_manifest(artifact)
    art.compare_artifact(artifact, artifact)
    require(u.source_files(artifact) == files, "target artifact full tree differs")
    require(
        art.distribution_manifest(repo) == files,
        "checkout distribution does not match artifact",
    )
    verify_zip(archive, files)
    require(
        sha(old_zip) == OLD_RELEASES[old_version]["zip_sha256"],
        "old published ZIP pin differs",
    )
    old_files = art.distribution_manifest(old_artifact)
    art.compare_artifact(old_artifact, old_artifact)
    require(u.source_files(old_artifact) == old_files, "old artifact full tree differs")
    verify_zip(old_zip, old_files)
    require(
        host.runtime(old_artifact) == OLD_RELEASES[old_version]["runtime_sha256"],
        "old artifact runtime pin differs",
    )
    return files, old_files


def owned_read(ctx, argv, timeout=30):
    """Read-only CLI query with bounded streams and owned process-tree cleanup."""
    fact, stdout = owned_execute(ctx, argv, timeout=timeout)
    require(
        fact.get("exit_code") == 0 and cleanup_confirmed(fact.get("cleanup")),
        "official read command or cleanup failed",
    )
    return stdout


def official_list(ctx, version, expected_source=None, allow_disabled=False):
    cmd = [
        str(ctx["cli"]),
        "plugin",
        "list",
        "--marketplace",
        "codex-context-guard",
        "--json",
    ]
    data = strict_json_bytes(owned_read(ctx, cmd))
    entries = data.get("installed")
    require(isinstance(entries, list), "official plugin list malformed")
    rows = [r for r in entries if isinstance(r, dict) and r.get("pluginId") == ENTRY]
    require(
        len(rows) == 1
        and rows[0].get("version") == version
        and rows[0].get("installed") is True,
        "official plugin version differs",
    )
    require(
        rows[0].get("enabled") is True
        or (allow_disabled and rows[0].get("enabled") is False),
        "official enabled state differs",
    )
    if expected_source is not None:
        market = rows[0].get("marketplaceSource", {})
        source = rows[0].get("source", {})
        require(
            isinstance(market, dict) and market.get("sourceType") == "local"
            and reported_path_matches(market.get("source"), expected_source),
            "official marketplace source differs",
        )
        require(
            isinstance(source, dict) and source.get("source") == "local"
            and reported_path_matches(source.get("path"), expected_source),
            "official plugin source differs",
        )
    return {
        "pluginId": ENTRY,
        "version": version,
        "installed": True,
        "enabled": rows[0]["enabled"],
        "target_source_verified": expected_source is not None,
    }


def preflight(plan, output, *, after=False):
    require(
        isinstance(plan, dict) and plan.get("schema") == PLAN, "wrong producer plan"
    )
    require(
        plan.get("transition_strategy") == "between-turns",
        "unsupported transition strategy",
    )
    require(plan.get("config_refresh") == CONFIG_REFRESH, "unsupported config refresh")
    require_reviewed_cli(plan)
    require(
        plan.get("declared_pause") is True, "user-declared between-turn pause required"
    )
    required = {
        "schema",
        "transition_strategy",
        "config_refresh",
        "declared_pause",
        "read_file_safe_for_model",
        "old_version",
        "target_version",
        "commit",
        "tool_sha256",
        "cli_sha256",
        "zip_sha256",
        "runtime_sha256",
        "maintained_plan_sha256",
        "old_runtime_sha256",
        "native_read_sha256",
        "repo",
        "codex_home",
        "workspace",
        "data_root",
        "cli",
        "maintained_tool",
        "maintained_plan",
        "zip",
        "artifact",
        "old_zip",
        "read_file",
        "old_source_sha256",
        "expected_cli_version",
        "expected_model",
        "witness_mode",
        "_native_plan_sha256",
    }
    if platform.system() == "Windows":
        required.add("windows_backend")
    selected_backend(plan)
    require(
        required <= set(plan)
        and set(plan) <= required | {"trust_wait_seconds", "activity_wait_seconds"},
        "native plan fields differ from closed schema",
    )
    old, new = plan.get("old_version"), plan.get("target_version")
    require(
        isinstance(old, str)
        and VERSION.fullmatch(old)
        and isinstance(new, str)
        and VERSION.fullmatch(new)
        and old != new,
        "invalid version pair",
    )
    for key in (
        "commit",
        "tool_sha256",
        "cli_sha256",
        "zip_sha256",
        "runtime_sha256",
        "maintained_plan_sha256",
        "old_runtime_sha256",
        "native_read_sha256",
    ):
        regex = HEX40 if key == "commit" else HEX64
        require(
            isinstance(plan.get(key), str) and regex.fullmatch(plan[key]),
            "invalid " + key,
        )
    require(
        plan.get("read_file_safe_for_model") is True,
        "explicit safe-for-model test file declaration required",
    )
    require(
        old in OLD_RELEASES
        and plan["old_runtime_sha256"] == OLD_RELEASES[old]["runtime_sha256"],
        "old published runtime pin differs",
    )
    repo = directory(plan["repo"])
    home = directory(plan["codex_home"])
    workspace = directory(plan["workspace"])
    require(workspace == repo, "workspace must be the reviewed source checkout")
    root = directory(plan["data_root"])
    requested_out = check_path(Path(output).absolute())
    out = requested_out.parent.resolve(strict=True) / requested_out.name
    if after:
        require(
            out.is_dir() and not out.is_symlink(),
            "existing private result directory required",
        )
    else:
        require(
            not out.exists() and not out.is_symlink(), "fresh output directory required"
        )
    require(
        not within(out, home) and not within(out, repo) and not within(out, workspace),
        "output overlaps protected root",
    )
    require(within(root, home) and root != home, "data root must be beneath CODEX_HOME")
    cli = regular(plan["cli"])
    tool = regular(plan["maintained_tool"])
    maint_plan = regular(plan["maintained_plan"])
    archive = regular(plan["zip"])
    artifact = directory(plan["artifact"])
    require(
        tool == repo / "tools/validation/daily_upgrade.py",
        "maintained entry must be repository owned",
    )
    require(
        producer_path() == repo / "tools/validation/native_between_turns_acceptance.py",
        "native producer must be repository owned",
    )
    require(
        diagnostic_path() == repo / "tools/validation/hook_failure_diagnostics.py",
        "Hook diagnostic helper must be repository owned",
    )
    tracked_producer = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "ls-files",
            "--error-unmatch",
            "--",
            "tools/validation/native_between_turns_acceptance.py",
            "tools/validation/hook_failure_diagnostics.py",
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    require(tracked_producer.returncode == 0, "native producer and Hook diagnostic helper must be tracked")
    for key, path in [
        ("tool_sha256", tool),
        ("cli_sha256", cli),
        ("zip_sha256", archive),
        ("maintained_plan_sha256", maint_plan),
    ]:
        require(sha(path) == plan[key], key + " changed")
    require(
        not within(artifact, home)
        and not within(archive, home)
        and not within(workspace, home)
        and not within(home, workspace),
        "artifact, ZIP or workspace overlaps daily HOME",
    )
    raw = strict_read_json(maint_plan)
    require(
        raw.get("schema") == "cg-daily-upgrade-plan/v2"
        and raw.get("transition_strategy") == "between-turns",
        "maintained plan is not v2 between-turns",
    )
    require(
        raw.get("target_version") == new
        and Path(raw.get("artifact_dir", "")).resolve() == artifact,
        "maintained target mismatch",
    )
    require(Path(raw.get("cli", "")).resolve() == cli, "maintained CLI differs")
    git = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    ).stdout.strip()
    require(git == plan["commit"], "source commit changed")
    dirty = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    ).stdout
    require(not dirty, "source worktree not clean")
    u, host, art, daily = import_product(repo)
    if after:
        u._no_link_ancestors(out.absolute())
        u._private_directory(out.parent)
        u._private_directory(out)
    else:
        u._new_outside(out, [repo, home, workspace, artifact])
    for path in (repo, home, workspace, root, cli, tool, maint_plan, archive, artifact):
        u._reject_credential_path(path)
        u._no_link_ancestors(path.absolute())
    require(
        daily._daily_home() == home,
        "maintained tool would target a different daily HOME",
    )
    normalized = daily._load_plan(maint_plan)
    require(
        sha(maint_plan) == plan["maintained_plan_sha256"],
        "maintained plan changed while reading",
    )
    require(
        normalized.get("mode") == "between-turns", "normalized maintained mode differs"
    )
    require(
        normalized.get("data_dir") is None or daily._same_path(normalized["data_dir"], str(root)),
        "policy data root differs",
    )
    old_zip = regular(plan["old_zip"])
    old_artifact = directory(normalized["old_artifact_dir"])
    require(
        not within(old_artifact, home) and not within(old_zip, home),
        "old published inputs overlap daily HOME",
    )
    files, old_files = bind_artifact_subject(
        u, art, host, repo, artifact, archive, old_artifact, old_zip, old
    )
    require(host.runtime(artifact) == plan["runtime_sha256"], "runtime digest mismatch")
    require(
        json.loads((artifact / ".codex-plugin/plugin.json").read_text()).get("version")
        == new,
        "artifact version differs",
    )
    verify_zip(archive, files)
    oldroot = home / "plugins/cache/codex-context-guard/context-guard" / old
    newroot = home / "plugins/cache/codex-context-guard/context-guard" / new
    if after:
        directory(newroot)
        art.compare_artifact(artifact, newroot)
        require(u.source_files(newroot) == files, "target cache full tree differs")
        if oldroot.exists() or oldroot.is_symlink():
            directory(oldroot)
            art.compare_artifact(old_artifact, oldroot)
            require(
                u.source_files(oldroot) == old_files,
                "retained old cache full tree differs",
            )
        compatibility = daily._verify_between_turns_compatibility(normalized, new)
    else:
        directory(oldroot)
        art.compare_artifact(old_artifact, oldroot)
        require(u.source_files(oldroot) == old_files, "old cache full tree differs")
        require(
            host.runtime(oldroot) == plan["old_runtime_sha256"], "old runtime mismatch"
        )
        compatibility = daily._verify_between_turns_compatibility(normalized, old)
        require(
            not newroot.exists() and not newroot.is_symlink(),
            "new cache already present; candidate requires a fresh target",
        )
    require(
        compatibility.get("verdict") == "compatible"
        and compatibility.get("old_version") == old
        and Path(compatibility.get("installed_slot", "")).resolve() == oldroot,
        "maintained compatibility subject differs",
    )
    tool_output = out / "maintained"
    require(
        tool_output.is_dir() if after else not tool_output.exists(),
        "maintained output state differs",
    )
    wait = plan.get("trust_wait_seconds", 300)
    require(type(wait) is int and 1 <= wait <= 1200, "invalid trust wait")
    activity_wait = plan.get("activity_wait_seconds", 120)
    require(
        type(activity_wait) is int and 1 <= activity_wait <= 900,
        "invalid activity wait",
    )
    require(
        plan.get("old_source_sha256") == sha(old_artifact / "hooks/hooks.json"),
        "old Hook definition mismatch",
    )
    read_file = regular(plan["read_file"])
    require(
        read_file == repo / "README.md",
        "read file must be the reviewed source README.md",
    )
    require(
        re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}", read_file.name) is not None,
        "unsafe read fixture filename",
    )
    require(
        sha(read_file) == plan["native_read_sha256"], "controlled read fixture differs"
    )
    tracked = subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "ls-files",
            "--error-unmatch",
            "--",
            read_file.name,
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    require(tracked.returncode == 0, "read fixture is not tracked")
    changed = subprocess.run(
        ["git", "-C", str(workspace), "status", "--porcelain", "--", read_file.name],
        capture_output=True,
        text=True,
        timeout=20,
    )
    require(
        changed.returncode == 0 and not changed.stdout,
        "read fixture has uncommitted edits",
    )
    require(
        isinstance(plan.get("expected_model"), str)
        and 1 <= len(plan["expected_model"]) <= 100,
        "expected real model required",
    )
    require(plan.get("witness_mode") == "unknown", "unsupported runtime witness mode")
    require(isinstance(plan.get("expected_cli_version"), str), "CLI version required")
    ctx = {"cli": cli, "workspace": workspace, "home": home, "repo": repo, "u": u}
    cli_version = owned_read(ctx, [str(cli), "--version"])
    require(
        cli_version.decode("utf-8-sig").strip() == plan["expected_cli_version"],
        "CLI version mismatch",
    )
    official_list(ctx, new if after else old, artifact if after else None)
    # No actual app-server or model is started in preflight.
    return {
        "repo": repo,
        "home": home,
        "workspace": workspace,
        "data_root": root,
        "cli": cli,
        "tool": tool,
        "maintained_plan": maint_plan,
        "artifact": artifact,
        "old_root": oldroot,
        "new_root": newroot,
        "output": out,
        "tool_output": tool_output,
        "wait": wait,
        "activity_wait": activity_wait,
        "expected_model": plan["expected_model"],
        "app_server_argv": app_server_argv(plan, cli),
        "windows_backend": selected_backend(plan),
        "read_file": read_file,
        "u": u,
        "host": host,
        "art": art,
        "daily": daily,
        "normalized_plan": normalized,
        "compatibility": compatibility,
        "files": files,
        "old_zip": old_zip,
        "old_files": old_files,
        "helpers": daily._helper_identities(),
        "producer_sha256": sha(producer_path()),
        "diagnostic_sha256": sha(diagnostic_path()),
    }


def norm(p):
    return os.path.normcase(os.path.normpath(str(p)))


def reported_path_matches(raw, trusted):
    return native_io._official_path_matches(raw, Path(trusted), windows=platform.system() == "Windows")


def ccg_scope_path(raw, cache_base):
    """Rejection-only scope test; never authorize a reported path with it."""
    if not isinstance(raw, str):
        return False
    if platform.system() == "Windows":
        def key(value):
            value = str(value).replace("/", "\\")
            if value.startswith(("\\\\?\\", "\\\\.\\")):
                value = value[4:]
                if value[:4].casefold() == "unc\\":
                    value = "\\\\" + value[4:]
            return ntpath.normcase(ntpath.normpath(value))
        path, root = key(raw), key(cache_base)
        candidate = raw.replace("/", "\\").casefold()
        marker = (r"(?:^|\\)plugins[ .]*(?::[^\\]*)?\\cache[ .]*(?::[^\\]*)?\\"
                  r"codex-context-guard[ .]*(?::[^\\]*)?\\context-guard[ .]*(?=\\|:|$)")
        return (path == root or path.startswith(root.rstrip("\\") + "\\")
                or re.search(marker, candidate) is not None)
    path, root = os.path.normpath(raw), os.path.normpath(str(cache_base))
    marker = r"(?:^|/)plugins/cache/codex-context-guard/context-guard(?=/|$)"
    return path == root or path.startswith(root.rstrip("/") + "/") or re.search(marker, raw) is not None


def product_inventory(u, result, cache_base, allowed):
    rows = result.get("data")
    require(
        isinstance(rows, list) and len(rows) == 1, "unexpected Hook inventory shape"
    )
    row = rows[0]
    require(not row.get("errors") and not row.get("warnings"), "Hook inventory errors")
    selected = []
    for h in row.get("hooks", []):
        source = h.get("sourcePath") if isinstance(h, dict) else None
        if not isinstance(source, str):
            continue
        if u._source_key(source, {str(x) for x in allowed}) is not None:
            selected.append(h)
        elif ccg_scope_path(source, cache_base):
            raise Refused("unexpected Context Guard source")
    require(len(selected) == 9 * len(allowed), "incomplete product Hook inventory")
    require(
        all(
            h.get("trustStatus") in ("trusted", "untrusted", "modified")
            and type(h.get("enabled")) is bool
            for h in selected
        ),
        "unknown Hook trust or enabled state",
    )
    # Validate the entire source/event/identity family before classifying a
    # structurally valid review state as pending. Never hide duplicates.
    structural = [{**h, "trustStatus": "trusted", "enabled": True} for h in selected]
    verified = u._inventory(
        {"data": [{"hooks": structural}]}, {str(x): "product" for x in allowed}
    )
    if any(
        h.get("trustStatus") != "trusted" or h.get("enabled") is not True
        for h in selected
    ):
        raise Pending("normal Hook review pending")
    return verified


class BoundedJournal:
    def __init__(self, path, limit=16 * 1024 * 1024):
        self.stream = Path(path).open("x", encoding="utf-8", newline="\n")
        self.limit = limit
        self.size = 0

    def write(self, value):
        encoded = value.encode("utf-8")
        require(self.size + len(encoded) <= self.limit, "RPC journal byte limit")
        written = self.stream.write(value)
        self.size += len(encoded)
        return written

    def flush(self):
        self.stream.flush()

    def close(self):
        self.stream.close()


class DailyClientFactory:
    """Reuse UpgradeClient with a daily-safe child environment and filtered Hooks."""

    def __init__(self, ctx):
        self.ctx = ctx

    def __call__(self):
        c = self.ctx
        u = c["u"]
        host = c["host"]

        class Client(u.UpgradeClient):
            def __init__(self):
                self.turn_limit = 3
                self.turn_count = 0
                self.approved = {}
                self.initial_approved = {}
                self.guard_diagnostic = None
                self.last_rpc_failure = None
                self.initial_sources = {str(c["old_root"] / "hooks/hooks.json"): "old"}
                self.observation_old_sources = set(self.initial_sources)
                self.observation_thread = None
                self.observation_inventory = None
                self.plan = {
                    "codex": str(c["cli"]),
                    "cwd": str(c["workspace"]),
                    "home": str(c["home"]),
                    "plugin_root": str(c["old_root"]),
                }
                self.rows = []
                self.pending = {}
                self.sequence = 0
                self.q = queue.Queue(maxsize=10000)
                self.log = None
                self.err = None
                self.owned = None
                self.reader_thread = None
                self.reader_started = False
                self.reader_failure = None
                self.spawn_attempted = False
                self._client_cleanup = None
                self.layer_ids = set()
                self.refresh_version = None
                self.refresh_sent = False
                self.resume_thread = None
                self.resume_sent = False
                self.loaded_thread = None
                self.controlled_threads = set()
                self.turn_request_threads = {}
                self.active_diagnostic_turn = None
                try:
                    self.log = BoundedJournal(c["output"] / "rpc.jsonl")
                    self.err = open(os.devnull, "wb")
                    self.launch_argv = list(c["app_server_argv"])
                    self.spawn_attempted = True
                    self.owned = host.OwnedProcess.spawn(
                        self.launch_argv,
                        cwd=str(c["workspace"]),
                        env=filtered_env(c["home"]),
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=self.err,
                        text=True,
                        encoding="utf8",
                    )
                    self.reader_thread = threading.Thread(target=self.reader, daemon=True)
                    self.reader_thread.start()
                    self.reader_started = True
                    self.rpc(
                        "initialize",
                        {
                            "clientInfo": {
                                "name": "cg-between-turn-acceptance",
                                "version": "1",
                            },
                            "capabilities": {"experimentalApi": True},
                        },
                    )
                    self.send({"method": "initialized", "params": {}})
                    self.approved = self.inventory_for(
                        [c["old_root"] / "hooks/hooks.json"]
                    )
                    self.initial_approved = dict(self.approved)
                    self.check_provider()
                except BaseException as exc:
                    if self.reader_thread is not None and self.reader_thread.is_alive():
                        self.reader_started = True
                    try:
                        startup_cleanup = self.close(getattr(exc, "cleanup", None))
                    except (KeyboardInterrupt, SystemExit) as cancel:
                        c["startup_cleanup"] = getattr(cancel, "cleanup", None) or {
                            "client_cleanup_complete": False,
                            "reason": "startup_cleanup_interrupted",
                        }
                        raise
                    except BaseException as close_exc:
                        startup_cleanup = getattr(close_exc, "cleanup", None) or {
                            "client_cleanup_complete": False,
                            "reason": "startup_cleanup_unknown",
                        }
                    c["startup_cleanup"] = (
                        startup_cleanup
                        if isinstance(startup_cleanup, dict)
                        else {"client_cleanup_complete": False, "reason": "startup_unobserved"}
                    )
                    raise

            def reader(self):
                try:
                    for line in self.owned.process.stdout:
                        if len(line) > 2 * 1024 * 1024:
                            raise ValueError("oversized RPC line")
                        try:
                            self.q.put(json.loads(line), timeout=1)
                        except queue.Full:
                            self.reader_failure = "queue_full"
                            return
                except Exception as exc:
                    self.reader_failure = type(exc).__name__

            def close(self, startup_receipt=None):
                if self._client_cleanup is not None:
                    return dict(self._client_cleanup)
                cancellation = None
                if self.owned is not None:
                    try:
                        owned_result = self.owned.close(12)
                    except BaseException as exc:
                        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                            cancellation = exc
                        owned_result = getattr(exc, "cleanup", None) or {"cleanup_complete": False}
                elif not self.spawn_attempted:
                    owned_result = {"process_created": False, "cleanup_complete": True}
                else:
                    owned_result = startup_receipt if isinstance(startup_receipt, dict) else {"process_creation_unknown": True, "cleanup_complete": False}
                if not isinstance(owned_result, dict):
                    owned_result = {"cleanup_complete": False}
                if self.reader_started:
                    try:
                        self.reader_thread.join(timeout=3)
                    except (KeyboardInterrupt, SystemExit) as exc:
                        cancellation = cancellation or exc
                reader_stopped = not self.reader_started or not self.reader_thread.is_alive()
                proc = self.owned.process if self.owned is not None else None
                streams = {
                    "stdin": getattr(proc, "stdin", None),
                    "stdout": getattr(proc, "stdout", None),
                    "log": self.log,
                    "err": self.err,
                }
                io_closed = {}
                for name, stream in streams.items():
                    if (name in ("stdin", "stdout") and self.owned is None
                            and self.spawn_attempted and owned_result.get("process_created") is not False):
                        io_closed[name] = None  # Process may have owned inaccessible pipes.
                        continue
                    try:
                        if stream is not None and (
                            name not in ("stdin", "stdout")
                            or (owned_result.get("owned_process_exited") is True and reader_stopped)
                        ):
                            stream.close()
                        io_closed[name] = stream is None or (stream.stream.closed if name == "log" else stream.closed)
                    except BaseException as exc:
                        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                            cancellation = cancellation or exc
                        io_closed[name] = False
                if not self.spawn_attempted:
                    owned_ok = owned_result == {"process_created": False, "cleanup_complete": True}
                elif self.owned is not None:
                    owned_ok = cleanup_confirmed(owned_result)
                else:
                    # Windows startup may fail before assignment; its initial
                    # thread is still suspended. Require the actual Job and
                    # process cleanup receipt, not an assumed no-process case.
                    receipt_ok = (
                        platform.system() == "Windows"
                        and owned_result.get("cleanup_complete") is True
                        and ("process_creation_unknown" not in owned_result or owned_result["process_creation_unknown"] is False)
                        and owned_result.get("process_group_cleanup_error", "missing") is None
                        and owned_result.get("cleanup_errors") == []
                        and owned_result.get("job_close_confirmed") is True
                        and owned_result.get("process_group_signal_denied") is False
                        and owned_result.get("process_group_query_denied") is False
                        and type(owned_result.get("process_created")) is bool
                        and type(owned_result.get("job_assignment_confirmed")) is bool
                    )
                    no_process = owned_result.get("process_created") is False and owned_result.get("job_assignment_confirmed") is False
                    stopped_process = (
                        owned_result.get("process_created") is True
                        and owned_result.get("owned_process_exited") is True
                        and owned_result.get("owned_tree_no_running_members") is True
                    )
                    owned_ok = receipt_ok and (no_process or stopped_process)
                complete = owned_ok and reader_stopped and all(io_closed.values())
                self._client_cleanup = {**owned_result, "reader_started": self.reader_started,
                                        "reader_stopped": reader_stopped, "reader_failure": self.reader_failure,
                                        "io_closed": io_closed,
                                        "client_cleanup_complete": complete}
                if cancellation is not None:
                    cancellation.cleanup = dict(self._client_cleanup)
                    raise cancellation
                return dict(self._client_cleanup)

            def start(self, instructions=""):
                params = {
                    "cwd": str(c["workspace"]),
                    "sandbox": "read-only",
                    "approvalPolicy": "on-request",
                    "model": c["expected_model"],
                    "developerInstructions": "Acceptance task: read only "
                    + c["read_file"].name
                    + " when asked; do not access other files, credentials, network, or modify files.",
                }
                response = self.rpc("thread/start", params)
                require(
                    response.get("modelProvider") == "openai"
                    and response.get("model") == c["expected_model"]
                    and response.get("approvalPolicy") == "on-request"
                    and response.get("sandbox", {}).get("type") == "readOnly",
                    "model/provider readback mismatch",
                )
                thread = response.get("thread", {}).get("id")
                require(isinstance(thread, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", thread),
                        "invalid controlled thread identity")
                self.controlled_threads.add(thread)
                return thread

            def _projection(self, message):
                request_method = self.pending.get(message.get("id"))
                is_layer = message.get("id") in self.layer_ids
                result = super()._projection(message)
                if (
                    result is not None
                    and request_method == "config/read"
                    and "result" in result
                ):
                    result["result"] = (
                        config_layer_projection(message.get("result"), c)
                        if is_layer
                        else provider_projection(
                            message.get("result"), backend=c["windows_backend"]
                        )
                    )
                    self.layer_ids.discard(message.get("id"))
                if (
                    result is not None
                    and request_method == "config/batchWrite"
                    and "result" in result
                ):
                    raw = message.get("result")
                    require(
                        isinstance(raw, dict)
                        and raw.get("status") == "ok"
                        and raw.get("version") == self.refresh_version
                        and isinstance(raw.get("filePath"), str)
                        and c["daily"]._same_path(
                            raw["filePath"], str(c["home"] / "config.toml")
                        )
                        and raw.get("overriddenMetadata") is None,
                        "config refresh response differs",
                    )
                    result["result"] = {
                        "status": "ok",
                        "version": self.refresh_version,
                        "file_matches": True,
                        "overridden": False,
                    }
                if (
                    result is not None
                    and request_method == "thread/resume"
                    and "result" in result
                ):
                    result["result"] = resume_projection(
                        message.get("result"), c, self.resume_thread
                    )
                if result is not None and request_method == "turn/start" and "result" in result:
                    thread = self.turn_request_threads.pop(message.get("id"), None)
                    turn = message.get("result", {}).get("turn", {}).get("id")
                    require(thread in self.controlled_threads and isinstance(turn, str)
                            and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", turn), "controlled turn identity differs")
                    self.active_diagnostic_turn = (thread, turn)
                if (
                    result is not None
                    and request_method == "thread/loaded/list"
                    and "result" in result
                ):
                    raw = message.get("result")
                    require(
                        isinstance(raw, dict)
                        and isinstance(raw.get("data"), list)
                        and all(isinstance(x, str) for x in raw["data"])
                        and raw["data"].count(self.loaded_thread) == 1
                        and raw.get("nextCursor") is None,
                        "loaded old thread unavailable",
                    )
                    result["result"] = {
                        "controlled_thread_loaded": True,
                        "complete": True,
                    }
                if (
                    result is not None
                    and request_method == "thread/start"
                    and "result" in result
                ):
                    raw_response = message.get("result", {})
                    result["result"]["approvalPolicy"] = raw_response.get(
                        "approvalPolicy"
                    )
                    result["result"]["sandbox"] = {
                        "type": raw_response.get("sandbox", {}).get("type")
                    }
                    result["result"]["modelProvider"] = raw_response.get(
                        "modelProvider"
                    )
                    result["result"]["model"] = raw_response.get("model")
                if result is not None and message.get("method") in (
                    "item/started",
                    "item/completed",
                ):
                    raw = message.get("params", {}).get("item", {})
                    projected = result.get("params", {}).get("item", {})
                    if raw.get("type") == "commandExecution":
                        command = read_command(c["read_file"].name)
                        projected["command"] = (
                            command
                            if approved_read(u, raw.get("command"), command)
                            else "<unapproved>"
                        )
                params = message.get("params", {})
                if (result is not None and message.get("method") == "hook/completed"
                        and params.get("threadId") in self.controlled_threads
                        and ((params.get("threadId"), params.get("turnId")) == self.active_diagnostic_turn
                             or "turnId" in params and params.get("turnId") is None
                             and params.get("run", {}).get("eventName") in {"sessionStart", "sessionEnd"})):
                    inventory = (
                        self.observation_inventory
                        if message.get("params", {}).get("threadId")
                        == self.observation_thread
                        and self.observation_inventory is not None
                        else self.approved
                    )
                    diagnostic = hook_failure_diagnostics.project_failed(
                        message, inventory, u._source_key
                    )
                    if diagnostic is not None:
                        result["params"]["run"]["failure_diagnostic"] = diagnostic
                return result

            def send(self, message):
                require(
                    message.get("method")
                    in {
                        "initialize",
                        "initialized",
                        "hooks/list",
                        "turn/start",
                        "thread/start",
                        "config/read",
                        "config/batchWrite",
                        "thread/resume",
                        "thread/loaded/list",
                    },
                    "forbidden RPC method",
                )
                if message.get("method") == "config/read":
                    params = message.get("params")
                    require(
                        params
                        in (
                            {"cwd": str(c["workspace"]), "includeLayers": False},
                            {"cwd": None, "includeLayers": True},
                        ),
                        "config read request differs",
                    )
                    if type(message.get("id")) is int:
                        self.pending[message["id"]] = "config/read"
                        if params["includeLayers"]:
                            self.layer_ids.add(message["id"])
                    return host.Client.send(self, message)
                if message.get("method") == "config/batchWrite":
                    require(
                        not self.refresh_sent
                        and isinstance(self.refresh_version, str)
                        and message.get("params")
                        == {
                            "edits": [],
                            "expectedVersion": self.refresh_version,
                            "reloadUserConfig": True,
                        },
                        "config refresh request differs",
                    )
                    self.refresh_sent = True
                    self.pending[message["id"]] = "config/batchWrite"
                    return host.Client.send(self, message)
                if message.get("method") == "thread/resume":
                    require(
                        not self.resume_sent
                        and self.resume_thread in self.controlled_threads
                        and message.get("params") == {"threadId": self.resume_thread},
                        "loaded thread resume differs",
                    )
                    self.resume_sent = True
                    self.pending[message["id"]] = "thread/resume"
                    return host.Client.send(self, message)
                if message.get("method") == "thread/loaded/list":
                    require(
                        self.loaded_thread in self.controlled_threads
                        and message.get("params") == {},
                        "loaded thread request differs",
                    )
                    self.pending[message["id"]] = "thread/loaded/list"
                    return host.Client.send(self, message)
                if message.get("method") == "turn/start":
                    thread = message.get("params", {}).get("threadId")
                    require(thread in self.controlled_threads and type(message.get("id")) is int,
                            "turn start is outside controlled threads")
                    self.turn_request_threads[message["id"]] = thread
                return super().send(message)

            def observed_turn(self, thread, prompt):
                try:
                    return super().observed_turn(thread, prompt)
                finally:
                    self.active_diagnostic_turn = None

            def refresh_config_for_thread(self, thread):
                require(not self.refresh_sent and thread in self.controlled_threads,
                        "config refresh already attempted or thread not controlled")
                file_before = config_file_projection(c["home"])
                observations = []
                for _ in range(2):
                    raw = self.rpc("config/read", {"cwd": None, "includeLayers": True})
                    observations.append(config_layer_projection(raw, c))
                    del raw
                require(
                    observations[0] == observations[1]
                    and file_before == config_file_projection(c["home"]),
                    "config changed before refresh",
                )
                self.refresh_version = observations[0]["version"]
                durable_private_receipt(
                    c["output"] / "config-refresh-attempt.json",
                    {
                        "schema": "cg-config-refresh-attempt/v1",
                        "server_pid": self.owned.process.pid,
                        "thread": thread,
                        "file_before": file_before,
                        "layer": observations[0],
                    },
                )
                primary = None
                final = None
                try:
                    self.rpc(
                        "config/batchWrite",
                        {
                            "edits": [],
                            "expectedVersion": self.refresh_version,
                            "reloadUserConfig": True,
                        },
                    )
                    raw = self.rpc("config/read", {"cwd": None, "includeLayers": True})
                    final = config_layer_projection(raw, c)
                    del raw
                    require(
                        final == observations[0]
                        and config_file_projection(c["home"]) == file_before,
                        "config changed after refresh",
                    )
                    self.resume_thread = thread
                    self.loaded_thread = thread
                    self.rpc("thread/loaded/list", {})
                    resumed = self.rpc("thread/resume", {"threadId": thread})
                    resume_projection(resumed, c, thread)
                    self.rpc("thread/loaded/list", {})
                except BaseException as exc:
                    primary = exc
                try:
                    file_after = config_file_projection(c["home"])
                    file_state = "unchanged" if file_after == file_before else "changed"
                except BaseException as exc:
                    file_after = None
                    file_state = "unknown"
                    if primary is None:
                        primary = exc
                try:
                    durable_private_receipt(
                        c["output"] / "config-refresh-outcome.json",
                        {
                            "schema": "cg-config-refresh-outcome/v1",
                            "server_pid": self.owned.process.pid,
                            "thread": thread,
                            "batch_send_attempted": self.refresh_sent,
                            "file_after": file_after,
                            "file_state": file_state,
                        },
                    )
                except BaseException as exc:
                    if primary is None:
                        primary = exc
                if primary is not None:
                    raise primary
                require(
                    self.refresh_sent and file_state == "unchanged",
                    "config refresh file outcome differs",
                )
                return {
                    "schema": "cg-user-config-refresh/v1",
                    "mode": CONFIG_REFRESH,
                    "server_pid": self.owned.process.pid,
                    "thread": thread,
                    "file": file_before,
                    "layer": final,
                    "resume_verified": True,
                    "loaded_before": True,
                    "loaded_after": True,
                }

            def check_provider(self):
                return provider_projection(
                    self.rpc(
                        "config/read",
                        {"cwd": str(c["workspace"]), "includeLayers": False},
                    ), backend=c["windows_backend"]
                )

            def inventory_for(self, sources):
                result = self.rpc("hooks/list", {"cwds": [str(c["workspace"])]})
                return product_inventory(
                    u,
                    result,
                    c["home"] / "plugins/cache/codex-context-guard/context-guard",
                    sources,
                )

            def receive(self, deadline):
                require(len(self.rows) < 10000, "RPC row limit")
                require(self.reader_failure is None, "RPC reader failed")
                # Other products may emit Hooks. Do not apply CCG's inventory
                # to them or persist their content; unknown CCG sources fail.
                try:
                    message = self.journal_response(
                        self.q.get(timeout=max(0.01, deadline - time.monotonic()))
                    )
                except queue.Empty as e:
                    raise TimeoutError("RPC deadline") from e
                require(
                    not (
                        "reader_error" in message
                        or ("method" in message and "id" in message)
                    ),
                    "unexpected app-server input",
                )
                require(
                    message.get("method")
                    not in {"thread/closed", "thread/unloaded", "thread/archived"},
                    "controlled thread closed or unloaded",
                )
                if message.get("method") in ("hook/started", "hook/completed"):
                    path = (
                        message.get("params", {}).get("run", {}).get("sourcePath", "")
                    )
                    inventory = (
                        self.observation_inventory
                        if message.get("params", {}).get("threadId")
                        == self.observation_thread
                        and self.observation_inventory is not None
                        else self.approved
                    )
                    event = message.get("params", {}).get("run", {}).get("eventName")
                    source = u._source_key(path, {p for _, p in inventory})
                    base = c["home"] / "plugins/cache/codex-context-guard/context-guard"
                    if source is None and isinstance(path, str) and not ccg_scope_path(path, base):
                        return message
                    expected = inventory.get((event, source))
                    run = message.get("params", {}).get("run", {})
                    require(
                        expected is not None
                        and all(
                            run.get(k) == expected.get(k)
                            for k in (
                                "eventName",
                                "source",
                                "handlerType",
                                "displayOrder",
                            )
                        )
                        and run.get("executionMode")
                        == ("async" if expected.get("async") else "sync"),
                        "unreviewed CCG Hook execution",
                    )
                projection = self._projection(message)
                if projection is not None:
                    self.rows.append(projection)
                    self.log.write(
                        json.dumps({"direction": "response", "message": projection})
                        + "\n"
                    )
                    self.log.flush()
                return message

        return Client()


def snapshot(c, thread):
    root, state, digest = c["u"]._state_at_bound(c["home"], str(c["data_root"]), thread)
    candidates = [
        root / "sessions-v2" / thread / "state.json",
        root / "sessions" / thread / "state.json",
    ]
    paths = [p for p in candidates if p.is_file()]
    require(len(paths) == 1, "state path ambiguous")
    runtime = c["old_root"] if c["old_root"].is_dir() else c["new_root"]
    scope = c["u"]._old_scope(runtime, paths[0], c["home"])
    require(c["u"].sha(paths[0]) == digest, "state changed during integrity check")
    return {"root": str(root), "sha256": digest, "state": state, "scope": scope}


def capture_full_state(ctx, snap, thread, path):
    """Persist only the owned controlled state, with its exact validated bytes."""
    root = Path(snap["root"])
    candidates = [root / name / thread / "state.json" for name in ("sessions-v2", "sessions")]
    present = [item for item in candidates if item.exists() or item.is_symlink()]
    require(len(present) == 1, "full state capture path ambiguous")
    raw = safe_bytes(regular(present[0]), 16 * 1024 * 1024)
    require(hashlib.sha256(raw).hexdigest() == snap["sha256"], "full state capture drift")
    state = strict_json_bytes(raw)
    require(isinstance(state.get("session"), dict) and state["session"].get("id") == thread,
            "full state capture thread differs")
    def canonical(value):
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False)
    require(canonical(state) == canonical(snap["state"]), "full state capture projection differs")
    destination = check_path(Path(path).absolute())
    require(destination.parent == ctx["output"], "full state capture outside result")
    # Private parent is created by the native runner. Never replace a capture.
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(sha(destination) == snap["sha256"], "saved full state capture differs")
    return snap["sha256"]


def capture_post_close(ctx, thread):
    """Capture after confirmed owned cleanup, without changing the live state."""
    current = snapshot(ctx, thread)
    capture_full_state(ctx, current, thread, ctx["output"] / "post-close-full-state.json")
    write(ctx["output"] / "post-close.json", {
        "schema": STATE_CAPTURE,
        "observed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "snapshot": project(ctx, current),
    })


def project(c, snap):
    state = snap["state"]
    acceptance = []
    for item in state.get("acceptance_items", []):
        require(
            isinstance(item, dict)
            and isinstance(item.get("id"), str)
            and isinstance(item.get("status"), str),
            "acceptance entry malformed",
        )
        if item["status"] == "pending":
            require(
                isinstance(item.get("text"), str)
                and isinstance(item.get("work_unit_id"), str),
                "pending acceptance binding missing",
            )
            acceptance.append(
                {
                    "id": item["id"],
                    "text_sha256": hashlib.sha256(
                        item["text"].encode("utf-8")
                    ).hexdigest(),
                    "work_unit_id": item["work_unit_id"],
                }
            )
    require(
        len({item["id"] for item in acceptance}) == len(acceptance),
        "duplicate acceptance identity",
    )
    return {
        "root": snap["root"],
        "sha256": snap["sha256"],
        "state": c["u"]._state_projection(state),
        "scope": snap["scope"],
        "acceptance_pending": acceptance,
        "turns": [
            r.get("turn_id")
            for r in state.get("prompts", [])
            if r.get("turn_id") is not None
        ],
    }


def validate_projected_scope(before, after):
    def rows(value):
        entries = value.get("acceptance_pending")
        require(isinstance(entries, list), "pending acceptance projection missing")
        result = set()
        for item in entries:
            require(
                isinstance(item, dict)
                and set(item) == {"id", "text_sha256", "work_unit_id"}
                and isinstance(item["id"], str)
                and isinstance(item["work_unit_id"], str)
                and isinstance(item["text_sha256"], str)
                and HEX64.fullmatch(item["text_sha256"]),
                "acceptance projection malformed",
            )
            result.add((item["id"], item["text_sha256"], item["work_unit_id"]))
        require(len(result) == len(entries), "duplicate acceptance projection")
        return result

    before_acceptance, after_acceptance = rows(before), rows(after)
    require(
        before_acceptance <= after_acceptance,
        "pending acceptance criteria not preserved",
    )

    def scope(value):
        item = value.get("scope")
        require(
            isinstance(item, dict)
            and isinstance(item.get("current"), list)
            and isinstance(item.get("ancestor"), list)
            and all(isinstance(x, str) for x in item["current"] + item["ancestor"]),
            "scope projection malformed",
        )
        return set(item["current"]) | set(item["ancestor"])

    before_scope, after_scope = scope(before), scope(after)
    pending_ids = {entry[0] for entry in before_acceptance}
    pending_ids.update(
        item["id"]
        for item in before["state"].get("requirements", [])
        if item.get("status") == "pending"
    )
    require(
        (before_scope & pending_ids) <= after_scope,
        "pending applicable scope not preserved",
    )


def pairs(c, rows, inv, thread, turn, events):
    return {
        event: len(c["u"]._paired(rows, inv, thread, event, turn=turn))
        for event in events
    }


def cleanup_confirmed(value):
    if not isinstance(value, dict):
        return False
    clean = (
        ("cleanup_complete" not in value or value["cleanup_complete"] is True)
        and ("process_creation_unknown" not in value or value["process_creation_unknown"] is False)
        and value.get("owned_process_exited") is True
        and value.get("owned_tree_no_running_members") is True
        and "process_group_cleanup_error" in value
        and value["process_group_cleanup_error"] is None
    )
    if platform.system() == "Windows":
        clean = (
            clean
            and value.get("cleanup_complete") is True
            and value.get("job_close_confirmed") is True
            and value.get("job_assignment_confirmed") is True
        )
    return clean


def client_cleanup_confirmed(value):
    return (
        cleanup_confirmed(value)
        and value.get("client_cleanup_complete") is True
        and value.get("reader_started") is True
        and value.get("reader_stopped") is True
        and isinstance(value.get("io_closed"), dict)
        and set(value["io_closed"]) == {"stdin", "stdout", "log", "err"}
        and all(v is True for v in value["io_closed"].values())
    )


def owned_execute(c, argv, timeout):
    """Bounded output without retaining raw stderr; own whole process tree."""
    start = time.monotonic_ns()
    owner = None
    cleanup = None
    failure = None
    natural = False
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = threading.Event()
    readers = []

    def drain(stream, name, limit):
        try:
            while True:
                data = stream.read(65536)
                if not data:
                    break
                if len(buffers[name]) + len(data) > limit:
                    overflow.set()
                    break
                buffers[name].extend(data)
        except (OSError, ValueError, AttributeError):
            overflow.set()

    try:
        tree = c["u"].native.load_process_tree()
        owner = tree.OwnedProcess.spawn(
            argv,
            cwd=str(c["repo"]),
            env=filtered_env(c["home"]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for name, limit in (("stdout", 16 * 1024 * 1024), ("stderr", 1024 * 1024)):
            reader = threading.Thread(
                target=drain,
                args=(getattr(owner.process, name), name, limit),
                daemon=True,
            )
            reader.start()
            readers.append(reader)
        deadline = time.monotonic() + timeout
        while owner.process.poll() is None:
            if overflow.is_set():
                failure = "output_limit"
                break
            if time.monotonic() >= deadline:
                failure = "TimeoutExpired"
                break
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        if failure is None:
            natural = (
                c["u"].native.load_natural_observer()(owner).get("no_running_members")
                is True
            )
    except BaseException as exc:
        failure = type(exc).__name__
        inherited = getattr(exc, "cleanup", None)
        if owner is None:
            cleanup = (
                inherited
                if isinstance(inherited, dict)
                else {"cleanup_complete": False, "process_creation_unknown": True}
            )
    finally:
        if owner is not None:
            try:
                cleanup = owner.close(5)
            except BaseException as exc:
                cleanup = getattr(exc, "cleanup", None) or {
                    "cleanup_complete": False,
                    "cleanup_unknown": type(exc).__name__,
                }
            for reader in readers:
                reader.join(timeout=2)
            for index, stream in enumerate(
                (owner.process.stdout, owner.process.stderr)
            ):
                if stream is not None and (
                    index >= len(readers) or not readers[index].is_alive()
                ):
                    stream.close()
    if any(reader.is_alive() for reader in readers):
        failure = "reader_cleanup_unconfirmed"
    if overflow.is_set():
        failure = failure or "output_limit"
    stdout, stderr = bytes(buffers["stdout"]), bytes(buffers["stderr"])
    complete = cleanup_confirmed(cleanup)
    pending_kind = None
    if b"activity query cleanup unconfirmed" in stderr:
        pending_kind = "query_cleanup_unconfirmed"
    elif b"between-turns activity drain" in stderr:
        pending_kind = "activity_pending"
    fact = {
        "argv": argv,
        "pending_kind": pending_kind,
        "start_ns": start,
        "end_ns": time.monotonic_ns(),
        "exit_code": owner.process.returncode
        if owner is not None and failure is None and natural and complete
        else None,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_nonempty": bool(stderr),
        "failure": failure
        or (None if natural else "natural_tree_completion_unconfirmed"),
        "cleanup": cleanup,
    }
    return fact, stdout


def maintained_call(c, action, verify_output=None):
    require(action in ("--resume", "--verify"), "unsupported maintained action")
    argv = [
        sys.executable,
        str(c["tool"]),
        "--plan",
        str(c["maintained_plan"]),
        "--output",
        str(c["tool_output"]),
        action,
    ]
    if verify_output is not None:
        argv += ["--verify-output", str(verify_output)]
    return owned_execute(c, argv, timeout=300)[0]


def verify_maintained(c, plan, verify_path, expected_status):
    d = c["daily"]
    u = c["u"]
    out = c["tool_output"]
    prepared, prepared_sha = d._read_bound_result(
        out / "prepare.json", stage="prepare", mode="between-turns"
    )
    subject = prepared.get("subject", {})
    require(
        prepared.get("status") == "prepared"
        and prepared.get("subject_sha256") == u.digest(subject),
        "prepare subject digest differs",
    )
    require(
        subject.get("plan_sha256") == u.digest(c["normalized_plan"])
        and subject.get("tool_sha256") == plan["tool_sha256"],
        "maintained plan/tool binding differs",
    )
    require(
        subject.get("daily_home") == str(c["home"])
        and subject.get("cli", {}).get("sha256") == plan["cli_sha256"]
        and subject.get("cli", {}).get("path") == str(c["cli"])
        and subject.get("cli", {}).get("version") == plan["expected_cli_version"],
        "maintained HOME/CLI binding differs",
    )
    require(
        subject.get("artifact", {}).get("path") == str(c["artifact"])
        and subject.get("artifact", {}).get("version") == plan["target_version"],
        "maintained artifact binding differs",
    )
    require(subject.get("helpers") == c["helpers"], "maintained helper closure differs")
    require(
        subject.get("artifact", {}).get("manifest_sha256")
        == sha(c["artifact"] / ".codex-plugin/distribution-manifest.json"),
        "maintained artifact manifest differs",
    )
    require(
        subject.get("python", {}).get("path") == str(Path(sys.executable).resolve())
        and subject.get("python", {}).get("sha256")
        == sha(Path(sys.executable).resolve()),
        "maintained interpreter differs",
    )
    require(
        subject.get("installed_before", {}).get("version") == plan["old_version"]
        and subject.get("compatibility") == c["compatibility"],
        "old version compatibility not proven",
    )
    binding = u.digest(d._binding_view(subject))
    applied, _ = d._read_bound_result(
        out / "apply.json", stage="apply", mode="between-turns"
    )
    require(
        applied.get("status") == "applied"
        and applied.get("prepared_sha256") == prepared_sha
        and applied.get("subject_sha256") == binding,
        "apply binding differs",
    )
    installed = applied.get("installed_after", {})
    require(
        installed.get("registered") is True
        and installed.get("installed") is True
        and installed.get("version") == plan["target_version"]
        and reported_path_matches(installed.get("market_root"), c["artifact"])
        and reported_path_matches(installed.get("cache_path"), c["new_root"]),
        "apply target identity differs",
    )
    events = strict_read_jsonl(out / "apply-events.jsonl", 20000)
    require(
        applied.get("commands")
        == [event for event in events if event.get("event") == "fact"],
        "apply receipt facts differ from journal",
    )
    require(
        events == d._read_journal(out / "apply-events.jsonl"),
        "journal changed during read",
    )
    require(
        events
        and events[0]
        == {
            "event": "begin",
            "schema": d.JOURNAL_SCHEMA_V2,
            "mode": "between-turns",
            "subject_sha256": binding,
            "prepared_sha256": prepared_sha,
        },
        "journal binding differs",
    )
    require(
        sum(e.get("event") == "begin" for e in events) == 1, "duplicate journal begin"
    )
    expected_commands = {
        "marketplace_remove": [
            str(c["cli"]),
            "plugin",
            "marketplace",
            "remove",
            "codex-context-guard",
        ],
        "marketplace_add": [
            str(c["cli"]),
            "plugin",
            "marketplace",
            "add",
            str(c["artifact"]),
        ],
        "plugin_add": [str(c["cli"]), "plugin", "add", ENTRY, "--json"],
    }
    read_commands = (
        [str(c["cli"]), "--version"],
        [str(c["cli"]), "plugin", "marketplace", "list", "--json"],
        [
            str(c["cli"]),
            "plugin",
            "list",
            "--marketplace",
            "codex-context-guard",
            "--json",
        ],
    )
    rank = {"marketplace_remove": 0, "marketplace_add": 1, "plugin_add": 2}
    policy_dir = c["normalized_plan"].get("data_dir")
    if policy_dir is not None:
        require(d._same_path(policy_dir, str(c["data_root"])), "policy data root differs")
    policy_command = [sys.executable, "-B", "-I", str(c["old_root"] / "scripts/context_guard.py"),
                      "cleanup", "--data-dir", str(policy_dir), "--policy", "show"]
    read_stage = None
    read_index = 0
    read_registered = None
    preflight_ready = False
    policy_pending = False
    retry_observation = False
    pending_stage = None
    seen = set()
    successful_plugin_adds = 0
    last = -1
    finished = False
    for event in events[1:]:
        kind, stage = event.get("event"), event.get("stage")
        require(not finished, "journal contains events after completion")
        if kind == "fact" and stage in ("apply_state", "preflight"):
            require(pending_stage is None and not policy_pending, "journal read interrupts a pending operation")
            if read_index == 0:
                require(stage != "preflight" or (last >= rank["marketplace_add"] and "plugin_add" not in seen),
                        "preflight read out of order")
                read_stage = stage
                if stage == "apply_state":
                    preflight_ready = False
                else:
                    retry_observation = False
            require(stage == read_stage and event.get("argv") == read_commands[read_index],
                    "journal read command or sequence differs")
            require(set(event) == {"event", "stage", "argv", "cwd", "status", "exit_code", "stderr_nonempty", "observation"}
                    and event.get("cwd") == str(c["repo"])
                    and type(event.get("stderr_nonempty")) is bool
                    and type(event.get("exit_code")) is int
                    and isinstance(event.get("observation"), dict),
                    "journal read fact malformed")
            if read_index == 0:
                require(event["observation"].get("version") == plan["expected_cli_version"],
                        "journal CLI version differs")
            if read_index == 1:
                markets = event["observation"].get("marketplaces")
                require(isinstance(markets, list) and all(isinstance(x, dict) and isinstance(x.get("name"), str) for x in markets),
                        "journal marketplace readback malformed")
                stable_markets = [x for x in markets if x["name"] == "codex-context-guard"]
                require(len(stable_markets) <= 1, "ambiguous marketplace readback")
                read_registered = bool(stable_markets)
                if stage == "preflight":
                    require(read_registered and isinstance(stable_markets[0].get("root"), str)
                            and d._same_path(stable_markets[0]["root"], str(c["artifact"])),
                            "preflight marketplace source differs")
            refused_gap = (stage == "apply_state" and read_index == 2 and read_registered is False
                           and event.get("status") == "refused_empty_readback"
                           and event["exit_code"] != 0 and event["observation"] == {"installed": []})
            require(refused_gap or (event.get("status") == "completed" and event["exit_code"] == 0),
                    "journal read fact failed")
            if stage == "preflight" and read_index == 2:
                installed_rows = event["observation"].get("installed")
                require(isinstance(installed_rows, list)
                        and all(isinstance(row, dict) for row in installed_rows),
                        "preflight plugin readback malformed")
                stable_rows = [row for row in installed_rows if row.get("pluginId") == ENTRY]
                require(len(stable_rows) == 1 and stable_rows[0].get("installed") is True
                        and stable_rows[0].get("version") == plan["old_version"],
                        "preflight old installation differs")
            read_index += 1
            if read_index == len(read_commands):
                read_index = 0
                read_stage = None
                if stage == "preflight":
                    policy_pending = policy_dir is not None
                    preflight_ready = not policy_pending
                elif last >= rank["marketplace_add"] and "plugin_add" not in seen:
                    retry_observation = True
            continue
        require(read_index == 0, "incomplete journal read group")
        if kind == "fact" and stage == "policy_readback":
            require(policy_pending and pending_stage is None
                    and set(event) == {"event", "stage", "argv", "cwd", "status", "exit_code", "stderr_nonempty", "observation"}
                    and event.get("argv") == policy_command and event.get("cwd") == str(c["repo"])
                    and event.get("status") == "completed" and type(event.get("exit_code")) is int
                    and event["exit_code"] == 0 and type(event.get("stderr_nonempty")) is bool
                    and isinstance(event.get("observation"), dict), "policy readback differs")
            policy_pending = False
            preflight_ready = True
            continue
        require(not policy_pending, "missing policy readback")
        if kind == "note":
            require(
                pending_stage is None and stage in (*rank, "apply_complete"),
                "unknown journal note",
            )
            if stage == "apply_complete":
                finished = True
            else:
                require(
                    stage != "plugin_add",
                    "plugin add note cannot establish this upgrade",
                )
                if stage in seen:
                    require(retry_observation, "journal note out of order")
                else:
                    require(rank[stage] >= last, "journal note out of order")
                seen.add(stage)
                last = max(last, rank[stage])
            continue
        require(kind in ("intent", "fact"), "unknown journal event")
        require(
            stage in rank and event.get("argv") == expected_commands[stage],
            "unexpected journal mutation",
        )
        if kind == "intent":
            if stage == "plugin_add":
                require(preflight_ready, "preflight readback missing before plugin add")
                preflight_ready = False
            require(
                pending_stage is None and stage not in seen and rank[stage] >= last,
                "journal mutation intent out of order",
            )
            pending_stage = stage
            seen.add(stage)
            last = rank[stage]
        else:
            fact_fields = {"event", "stage", "argv", "cwd", "status", "exit_code", "stderr_nonempty", "observation"}
            summary_fields = {"summary_parse_failed", "stdout_sha256", "stdout_bytes"}
            summary = set(event) == fact_fields | summary_fields
            require(
                pending_stage == stage
                and event.get("status") == "completed"
                and type(event.get("exit_code")) is int
                and event["exit_code"] == 0
                and event.get("cwd") == str(c["repo"])
                and type(event.get("stderr_nonempty")) is bool
                and event.get("observation", "missing") is None
                and (set(event) == fact_fields or
                     (stage == "plugin_add" and summary and event.get("summary_parse_failed") is True
                      and isinstance(event.get("stdout_sha256"), str) and HEX64.fullmatch(event["stdout_sha256"])
                      and type(event.get("stdout_bytes")) is int and event["stdout_bytes"] >= 0)),
                "journal mutation fact without successful matching intent",
            )
            if stage == "plugin_add":
                successful_plugin_adds += 1
            pending_stage = None
    require(
        pending_stage is None and successful_plugin_adds == 1 and finished,
        "journal incomplete",
    )
    verified, _ = d._read_bound_result(
        verify_path, stage="verify", mode="between-turns"
    )
    require(
        verified.get("status") == expected_status
        and verified.get("prepared_sha256") == prepared_sha
        and verified.get("subject_sha256") == binding,
        "verify receipt status/binding differs",
    )
    after = verified.get("installed_after", {})
    require(
        after.get("installed") is True
        and after.get("version") == plan["target_version"]
        and reported_path_matches(after.get("cache_path"), c["new_root"])
        and verified.get("artifact_parity") == "passed"
        and verified.get("fresh_client_loaded") == "new",
        "verify installation facts differ",
    )
    return {
        "prepared_sha256": prepared_sha,
        "subject_sha256": binding,
        "verify_status": expected_status,
        "journal_add_count": successful_plugin_adds,
    }


def old_runtime_classification(c):
    old = c["old_root"]
    new = c["new_root"]
    base = old.parent
    if old.exists():
        try:
            c["art"].compare_artifact(
                Path(c["normalized_plan"]["old_artifact_dir"]), old
            )
        except Exception:
            return "unknown_old_tree_partial"
        return "old_or_new_compatible"
    trees = [p for p in base.iterdir() if p.is_dir() and not p.is_symlink()]
    old_hooks = Path(c["normalized_plan"]["old_artifact_dir"]) / "hooks/hooks.json"
    if trees == [new] and sha(old_hooks) == sha(new / "hooks/hooks.json"):
        return "new_runtime_inferred_from_unique_tree_and_compatible_fallback"
    return "unknown_multiple_or_missing_trees"


def read_command(filename):
    return (
        ("Get-Content -LiteralPath " + filename)
        if platform.system() == "Windows"
        else ("cat " + filename)
    )


def approved_read(u, raw, expected):
    if not isinstance(raw, str) or raw.count(expected) != 1:
        return False
    canonical = (
        "Get-Content -LiteralPath native-read.txt"
        if platform.system() == "Windows"
        else "cat native-read.txt"
    )
    return u._approved_read_command(raw.replace(expected, canonical), canonical)


def verify_read_tool(ctx, rows, inventory, thread, turn, command):
    pre = []
    post = []
    starts = {}
    completed = []
    for index, entry in enumerate(rows):
        msg = entry.get("message", {})
        params = msg.get("params", {})
        if (
            entry.get("direction") != "response"
            or params.get("threadId") != thread
            or params.get("turnId") != turn
        ):
            continue
        run = params.get("run", {})
        item = params.get("item", {})
        if (
            msg.get("method") == "hook/completed"
            and run.get("eventName") == "preToolUse"
        ):
            pre.append(index)
        if (
            msg.get("method") == "hook/started"
            and run.get("eventName") == "postToolUse"
        ):
            post.append(index)
        if item.get("type") != "commandExecution":
            continue
        require(
            item.get("command") == command
            and reported_path_matches(item.get("cwd"), ctx["workspace"]),
            "read command differs",
        )
        item_id = item.get("id")
        require(isinstance(item_id, str) and item_id, "read item id missing")
        if msg.get("method") == "item/started":
            require(item_id not in starts, "duplicate read start")
            starts[item_id] = index
        elif msg.get("method") == "item/completed":
            require(
                item_id in starts
                and type(item.get("exitCode")) is int
                and item.get("exitCode") == 0,
                "read command failed",
            )
            completed.append((starts.pop(item_id), index))
    require(
        len(completed) == 1
        and not starts
        and pre
        and post
        and max(pre) < completed[0][0] < completed[0][1] < min(post),
        "read event order missing",
    )
    require(
        ctx["u"]._paired(rows, inventory, thread, "preToolUse", turn=turn)
        and ctx["u"]._paired(rows, inventory, thread, "postToolUse", turn=turn),
        "read Hook pair missing",
    )


def log_marker(client, event):
    client.log.write(
        json.dumps(
            {
                "direction": "local",
                "event": event,
                "pid": client.owned.process.pid,
                "monotonic_ns": time.monotonic_ns(),
            }
        )
        + "\n"
    )
    client.log.flush()


def final_subject_readback(ctx, plan):
    """Re-read the current installed identity and immutable inputs, no server/model."""
    for key, path in (
        ("cli_sha256", ctx["cli"]),
        ("tool_sha256", ctx["tool"]),
        ("zip_sha256", Path(plan["zip"])),
        ("maintained_plan_sha256", ctx["maintained_plan"]),
    ):
        require(sha(path) == plan[key], "final subject drift: " + key)
    require(
        sha(ctx["old_zip"]) == OLD_RELEASES[plan["old_version"]]["zip_sha256"],
        "old ZIP drift",
    )
    require(
        sha(ctx["read_file"]) == plan["native_read_sha256"], "reviewed README drift"
    )
    require(ctx["daily"]._helper_identities() == ctx["helpers"], "helper closure drift")
    head = subprocess.run(
        ["git", "-C", str(ctx["repo"]), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    status = subprocess.run(
        ["git", "-C", str(ctx["repo"]), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    require(
        head.stdout.strip() == plan["commit"] and not status.stdout,
        "source commit/worktree drift",
    )
    art = ctx["art"]
    u = ctx["u"]
    files = art.distribution_manifest(ctx["artifact"])
    require(
        files == ctx["files"] == art.distribution_manifest(ctx["repo"]),
        "source artifact distribution drift",
    )
    require(
        u.source_files(ctx["artifact"]) == files
        and u.source_files(ctx["new_root"]) == files,
        "current target tree differs",
    )
    art.compare_artifact(ctx["artifact"], ctx["new_root"])
    verify_zip(Path(plan["zip"]), files)
    old_artifact = Path(ctx["normalized_plan"]["old_artifact_dir"])
    require(
        art.distribution_manifest(old_artifact)
        == ctx["old_files"]
        == u.source_files(old_artifact),
        "old artifact drift",
    )
    verify_zip(ctx["old_zip"], ctx["old_files"])
    return official_list(ctx, plan["target_version"], ctx["artifact"])


def validate_config_refresh_journal(
    ctx, rows, receipt, attempt, outcome, server_pid, thread, lower, upper, newinv
):
    require(
        isinstance(receipt, dict)
        and set(receipt)
        == {
            "schema",
            "mode",
            "server_pid",
            "thread",
            "file",
            "layer",
            "resume_verified",
            "loaded_before",
            "loaded_after",
        }
        and receipt["schema"] == "cg-user-config-refresh/v1"
        and receipt["mode"] == CONFIG_REFRESH
        and receipt["server_pid"] == server_pid
        and receipt["thread"] == thread
        and receipt["resume_verified"] is True
        and receipt["loaded_before"] is True
        and receipt["loaded_after"] is True,
        "config refresh receipt differs",
    )
    require(
        receipt["file"] == config_file_projection(ctx["home"]),
        "config file evidence changed",
    )
    layer = receipt["layer"]
    require(
        attempt
        == {
            "schema": "cg-config-refresh-attempt/v1",
            "server_pid": server_pid,
            "thread": thread,
            "file_before": receipt["file"],
            "layer": layer,
        }
        and outcome
        == {
            "schema": "cg-config-refresh-outcome/v1",
            "server_pid": server_pid,
            "thread": thread,
            "batch_send_attempted": True,
            "file_after": receipt["file"],
            "file_state": "unchanged",
        },
        "config refresh attempt/outcome differs",
    )
    require(
        isinstance(layer, dict)
        and set(layer)
        == {"version", "shape", "provider", "unique_active_base_user_layer"}
        and layer["unique_active_base_user_layer"] is True
        and isinstance(layer["version"], str)
        and re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", layer["version"]),
        "config layer evidence malformed",
    )
    shape = layer["shape"]
    require(
        isinstance(shape, dict)
        and set(shape) == {"entries", "tables", "hash_strings", "combined_hashes"}
        and all(type(x) is int and x >= 0 for x in shape.values())
        and shape["combined_hashes"] == 0
        and shape["hash_strings"] <= shape["tables"] <= shape["entries"],
        "config shape evidence differs",
    )
    provider = layer["provider"]
    provider_fields = {"model_provider", "endpoint_policy", "custom_catalog"}
    if ctx["windows_backend"] == "mxc":
        provider_fields.add("windows_sandbox")
    require(
        isinstance(provider, dict)
        and set(provider) == provider_fields
        and provider["model_provider"] in (None, "openai")
        and provider["endpoint_policy"] == "official_default"
        and provider["custom_catalog"] is False
        and (ctx["windows_backend"] != "mxc" or provider["windows_sandbox"] == "mxc"),
        "config layer provider evidence differs",
    )
    requests = {}
    paired = []
    allowed = {
        "initialize",
        "initialized",
        "hooks/list",
        "config/read",
        "config/batchWrite",
        "thread/start",
        "thread/resume",
        "thread/loaded/list",
        "turn/start",
    }
    seen_ids = set()
    for index, row in enumerate(rows):
        msg = row.get("message", {})
        require(
            not (
                row.get("direction") == "response"
                and isinstance(msg, dict)
                and msg.get("method")
                in {"thread/closed", "thread/unloaded", "thread/archived"}
            ),
            "controlled thread closed or unloaded",
        )
        if row.get("direction") == "request":
            require(
                isinstance(msg, dict) and msg.get("method") in allowed,
                "unexpected RPC request",
            )
            if "id" in msg:
                ident = msg["id"]
                require(
                    type(ident) is int and ident not in seen_ids,
                    "duplicate RPC request id",
                )
                seen_ids.add(ident)
                requests[ident] = (index, msg)
            else:
                require(msg.get("method") == "initialized", "unexpected notification")
        elif (
            row.get("direction") == "response" and isinstance(msg, dict) and "id" in msg
        ):
            ident = msg["id"]
            require(type(ident) is int and ident in requests, "unmatched RPC response")
            start, request = requests.pop(ident)
            require("result" in msg and "error" not in msg, "RPC response failed")
            paired.append((start, index, request, msg["result"]))
    require(not requests, "unanswered RPC request")
    markers = {}
    for name in ("new_trust_confirmed", "config_refresh_completed"):
        found = [
            (i, r)
            for i, r in enumerate(rows)
            if r.get("direction") == "local" and r.get("event") == name
        ]
        require(
            len(found) == 1
            and found[0][1].get("pid") == server_pid
            and type(found[0][1].get("monotonic_ns")) is int,
            "config refresh marker differs",
        )
        markers[name] = found[0][0]
    trust, done = markers["new_trust_confirmed"], markers["config_refresh_completed"]
    require(lower < trust < done < upper, "config refresh phase differs")
    require(
        rows[lower]["monotonic_ns"]
        <= rows[trust]["monotonic_ns"]
        <= rows[done]["monotonic_ns"]
        <= rows[upper]["monotonic_ns"],
        "config refresh timing differs",
    )
    target_inventories = []
    for start, end, req, result in paired:
        if req.get("method") == "hooks/list" and lower < start < end < trust:
            try:
                found = product_inventory(
                    ctx["u"],
                    result,
                    ctx["home"] / "plugins/cache/codex-context-guard/context-guard",
                    [ctx["new_root"] / "hooks/hooks.json"],
                )
                if found == newinv:
                    target_inventories.append(end)
            except (Pending, Refused, ValueError, KeyError, TypeError):
                pass
    require(target_inventories, "trusted target inventory missing before refresh")
    layer_reads = [
        x
        for x in paired
        if x[2].get("method") == "config/read"
        and x[2].get("params") == {"cwd": None, "includeLayers": True}
    ]
    batches = [x for x in paired if x[2].get("method") == "config/batchWrite"]
    resumes = [x for x in paired if x[2].get("method") == "thread/resume"]
    loaded = [x for x in paired if x[2].get("method") == "thread/loaded/list"]
    require(
        len(layer_reads) == 3
        and len(batches) == 1
        and len(resumes) == 1
        and len(loaded) == 2,
        "config refresh RPC count differs",
    )
    a, b, post = layer_reads
    batch, resume = batches[0], resumes[0]
    first_loaded, last_loaded = loaded
    require(
        trust
        < a[0]
        < a[1]
        < b[0]
        < b[1]
        < batch[0]
        < batch[1]
        < post[0]
        < post[1]
        < first_loaded[0]
        < first_loaded[1]
        < resume[0]
        < resume[1]
        < last_loaded[0]
        < last_loaded[1]
        < done,
        "config refresh RPC sequence differs",
    )
    require(all(x[3] == layer for x in layer_reads), "config layer readback differs")
    require(
        batch[2].get("params")
        == {"edits": [], "expectedVersion": layer["version"], "reloadUserConfig": True}
        and batch[3]
        == {
            "status": "ok",
            "version": layer["version"],
            "file_matches": True,
            "overridden": False,
        },
        "config batch evidence differs",
    )
    require(
        resume[2].get("params") == {"threadId": thread}
        and resume[3]
        == {
            "thread": {"id": thread},
            "model": ctx["expected_model"],
            "modelProvider": "openai",
            "approvalPolicy": "on-request",
            "sandbox": {"type": "readOnly"},
            "cwd_matches": True,
        },
        "loaded thread policy evidence differs",
    )
    require(
        all(
            x[2].get("params") == {}
            and x[3] == {"controlled_thread_loaded": True, "complete": True}
            for x in loaded
        ),
        "loaded thread evidence differs",
    )


def validate_turn_request_scope(rows, old, fresh):
    markers = {}
    for name in ("old_turn_complete", "config_refresh_completed", "old_continuation_complete", "fresh_turn_complete"):
        found = [i for i, row in enumerate(rows) if row.get("direction") == "local" and row.get("event") == name]
        require(len(found) == 1, "turn scope marker differs")
        markers[name] = found[0]
    requests = [(i, row["message"]) for i, row in enumerate(rows)
                if row.get("direction") == "request" and row.get("message", {}).get("method") == "turn/start"]
    require(len(requests) == 3, "unexpected turn request")
    wanted = [(old["thread"], old["old_turn"]), (old["thread"], old["new_turn"]),
              (fresh["thread"], fresh["turn"])]
    bounds = [(0, markers["old_turn_complete"]),
              (markers["config_refresh_completed"], markers["old_continuation_complete"]),
              (markers["old_continuation_complete"], markers["fresh_turn_complete"])]
    for (index, request), (thread, turn), (lower, upper) in zip(requests, wanted, bounds):
        responses = [(i, row["message"]) for i, row in enumerate(rows)
                     if row.get("direction") == "response" and row.get("message", {}).get("id") == request.get("id")]
        require(lower < index < upper and request.get("params", {}).get("threadId") == thread
                and len(responses) == 1 and index < responses[0][0] < upper
                and responses[0][1].get("result", {}).get("turn", {}).get("id") == turn,
                "turn request scope differs")


def _capture_time(value):
    require(isinstance(value, str) and re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", value),
        "capture UTC timestamp malformed")
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise Refused("capture UTC timestamp malformed") from exc


def validate_state_captures(ctx, output):
    """Bind v3 full captures to the evidence map and current validated state."""
    saved = strict_read_json(output / "result.json")
    require(saved.get("schema") == REPORT
            and saved.get("subject", {}).get("state_capture") == STATE_CAPTURE,
            "v3 state capture contract missing")
    evidence = saved.get("evidence", {})
    require(isinstance(evidence, dict), "capture evidence map missing")
    for name in CAPTURE_EVIDENCE | {"old-after.json"}:
        digest = evidence.get(name)
        require(isinstance(digest, str) and HEX64.fullmatch(digest)
                and sha(output / name) == digest, "capture evidence binding differs")
    before = strict_read_json(output / "old-after.json")
    preimage = output / "old-after-full-state.json"
    require(sha(preimage) == before.get("sha256"), "capture preimage binding differs")
    post = strict_read_json(output / "post-close.json")
    require(set(post) == {"schema", "observed_at_utc", "snapshot"}
            and post["schema"] == STATE_CAPTURE and isinstance(post["snapshot"], dict),
            "post-close capture shape differs")
    thread = saved.get("gates", {}).get("old_model", {}).get("thread")
    require(isinstance(thread, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", thread),
            "capture thread malformed")
    current = snapshot(ctx, thread)
    require(current["root"] == before.get("root")
            and project(ctx, current) == post["snapshot"]
            and sha(output / "post-close-full-state.json") == current["sha256"],
            "post-close capture no longer matches current state")
    state = strict_read_json(output / "post-close-full-state.json")
    require(json.dumps(state, sort_keys=True, ensure_ascii=False, allow_nan=False)
            == json.dumps(current["state"], sort_keys=True, ensure_ascii=False, allow_nan=False)
            and state.get("session", {}).get("id") == thread,
            "post-close full state differs")
    observed = _capture_time(post["observed_at_utc"])
    require(_capture_time(state["session"].get("updated_at")) <= observed
            <= dt.datetime.now(dt.timezone.utc), "post-close observation time differs")
    return preimage, thread, current, {name: evidence[name] for name in CAPTURE_EVIDENCE}


def independent_verify(ctx, plan, output):
    """Re-derive v3 facts with exact captures and the narrow lifecycle relation."""
    from tools.validation.shared_verify import verify_core

    preimage, thread, current, captures = validate_state_captures(ctx, output)
    proof = verify_core(sys.modules[__name__], ctx, plan, output,
                        preimage_path=preimage, extra_required_evidence=CAPTURE_EVIDENCE)
    for name, digest in captures.items():
        require(sha(output / name) == digest, "capture evidence drift after verification")
    final = snapshot(ctx, thread)
    require(final["sha256"] == current["sha256"] and final["root"] == current["root"],
            "post-close state drift after verification")
    return proof


def wait_for_activity(
    ctx, old_version, samples, *, clock=time.monotonic, sleeper=time.sleep
):
    """Bounded observations only; unknown never becomes clear by interpretation."""
    deadline = clock() + ctx["activity_wait"]
    tools = ctx["daily"]._inventory_host_tools(ctx["daily"]._scrubbed_env())
    while True:
        activity = ctx["daily"]._runtime_activity(
            ctx["home"],
            old_version,
            tools,
            compatibility=ctx["compatibility"],
            allow_absent=False,
        )
        require(
            isinstance(activity, dict)
            and activity.get("status") in ("clear", "active", "unknown"),
            "invalid activity observation",
        )
        require(len(samples) < 1000, "activity observation budget exhausted")
        samples.append(activity)
        if activity.get("query_cleanup") == "unconfirmed":
            raise Pending("activity query cleanup unconfirmed; stop and inspect")
        if activity["status"] == "clear":
            return activity
        if clock() >= deadline:
            raise Pending(
                "activity remains "
                + activity["status"]
                + "; pause new operations and inspect before retry"
            )
        sleeper(min(2.0, max(0.0, deadline - clock())))


def no_add_attempted(ctx):
    """Only a bound, valid journal without any plugin-add command supports this fact."""
    output = ctx["tool_output"]
    journal = output / "apply-events.jsonl"
    if not journal.exists() or not (output / "prepare.json").exists():
        return False
    prepared, prepared_sha = ctx["daily"]._read_bound_result(
        output / "prepare.json", stage="prepare", mode="between-turns"
    )
    subject = prepared.get("subject", {})
    if prepared.get("status") != "prepared" or prepared.get("subject_sha256") != ctx[
        "u"
    ].digest(subject):
        return False
    events = strict_read_jsonl(journal, 20000)
    expected = {
        "event": "begin",
        "schema": ctx["daily"].JOURNAL_SCHEMA_V2,
        "mode": "between-turns",
        "subject_sha256": ctx["u"].digest(ctx["daily"]._binding_view(subject)),
        "prepared_sha256": prepared_sha,
    }
    if (
        not events
        or events[0] != expected
        or events != ctx["daily"]._read_journal(journal)
    ):
        return False
    for event in events:
        argv = event.get("argv")
        if event.get("stage") == "plugin_add" and event.get("event") in (
            "intent",
            "fact",
        ):
            return False
        if isinstance(argv, list) and argv[1:3] == ["plugin", "add"]:
            return False
    return True


def audit_turn_tools(rows, thread, turn, *, allow_read):
    """Post-turn observation only; read-only sandbox is not a tool whitelist."""
    allowed_non_tool = {"agentMessage", "userMessage", "reasoning", "plan"}
    for row in rows:
        message = row.get("message", {})
        params = message.get("params", {})
        if row.get("direction") != "response" or params.get("threadId") != thread:
            continue
        if message.get("method") not in ("item/started", "item/completed"):
            continue
        require(
            params.get("turnId") == turn,
            "controlled thread item has missing or unexpected turnId",
        )
        item = params.get("item")
        require(
            isinstance(item, dict) and isinstance(item.get("type"), str),
            "unclassified item in turn",
        )
        if item["type"] in allowed_non_tool:
            continue
        require(
            allow_read and item["type"] == "commandExecution",
            "unexpected tool or item in controlled turn",
        )


def runtime_witness(_ctx, _thread, _turn):
    # Interface for a separately reviewed, read-only OS collector.  The
    # candidate has no such adapter and never elevates an inference to pass.
    return {
        "status": "unknown",
        "reason": "read-only OS runtime-path adapter unavailable",
    }


def run(
    plan,
    ctx,
    client_factory=None,
    apply=maintained_call,
    witness=runtime_witness,
    clock=time.monotonic,
    sleeper=time.sleep,
):
    require(plan.get("schema") == PLAN and plan.get("config_refresh") == CONFIG_REFRESH,
            "native plan does not authorize config refresh")
    require_reviewed_cli(plan)
    out = ctx["output"]
    launch_argv = app_server_argv(plan, ctx["cli"])
    require(ctx["app_server_argv"] == launch_argv
            and ctx["windows_backend"] == selected_backend(plan), "app-server launch drift")
    ctx["u"]._mkdir_private_new(out)
    result = {
        "schema": REPORT,
        "config_refresh": CONFIG_REFRESH,
        "status": "pending",
        "subject": {
            k: plan[k]
            for k in (
                "commit",
                "old_version",
                "target_version",
                "zip_sha256",
                "runtime_sha256",
                "tool_sha256",
                "cli_sha256",
            )
        },
        "declared_pause": True,
        "platform": platform.system(),
        "evidence_scope": "owned app-server real-model CLI threads",
        "cli_version": plan.get("expected_cli_version"),
        "model": plan.get("expected_model"),
        "login_budget": 0,
        "gui": "unobserved",
        "gates": {},
        "cleanup": None,
    }
    c = None
    result["subject"]["app_server_argv"] = launch_argv
    result["subject"]["windows_backend"] = selected_backend(plan)
    stage = "startup"
    try:
        c = (client_factory or DailyClientFactory(ctx))()
        require(c.launch_argv == launch_argv, "app-server launch differs")
        pid = c.owned.process.pid
        oldinv = dict(c.approved)
        write(out / "server.json", {"pid": pid, "event": "owned_app_server_started",
                                    "argv": launch_argv, "windows_backend": selected_backend(plan),
                                    "os_backend_observation": "unobserved"})
        write(out / "old-trust.json", {"hooks": list(oldinv.values())})
        stage = "old_turn"
        thread = c.start()
        turn, rows = c.observed_turn(
            thread,
            "$context-guard 请登记此受控验收任务：在收到后续指示前，保留一项待完成要求：核对升级后的会话状态。此回合只确认记录，不执行该要求。",
        )
        log_marker(c, "old_turn_complete")
        audit_turn_tools(rows, thread, turn, allow_read=False)
        events = pairs(ctx, rows, oldinv, thread, turn, ("userPromptSubmit", "stop"))
        require(all(events.values()), "old turn Hooks missing")
        before = snapshot(ctx, thread)
        pending = ctx["u"]._pending(before["state"])
        require(bool(pending), "old pending requirements missing")
        result["gates"]["old_model"] = {
            "status": "passed",
            "thread": thread,
            "turn": turn,
            "pid": pid,
            "hooks": events,
        }
        write(out / "old-state.json", project(ctx, before))
        # Explicitly an observation/declaration, not a global lock: other
        # processes must be coordinated externally as required by the plan.
        statuses = [
            r.get("params", {}).get("status", {}).get("type")
            for r in getattr(c, "rows", [])
            if r.get("method") == "thread/status/changed"
            and r.get("params", {}).get("threadId") == thread
        ]
        stage = "activity_wait"
        samples = []
        try:
            wait_for_activity(ctx, plan["old_version"], samples)
        finally:
            write(
                out / "between-turn-boundary.json",
                {
                    "thread": thread,
                    "completed_turn": turn,
                    "server_pid": pid,
                    "user_declared_pause": True,
                    "own_thread_last_status": statuses[-1]
                    if statuses
                    else "not_observed",
                    "runtime_activity_samples": samples,
                    "other_shared_home_inflight": "unknown_not_locked",
                },
            )
        require(c.owned.process.poll() is None, "app-server exited before apply")
        stage = "apply"
        require(
            sha(ctx["native_plan_path"]) == plan["_native_plan_sha256"],
            "native plan drift before apply",
        )
        require(
            sha(producer_path()) == ctx["producer_sha256"],
            "producer drift before apply",
        )
        require(
            sha(diagnostic_path()) == ctx["diagnostic_sha256"],
            "Hook diagnostic helper drift before apply",
        )
        for key, path in [
            ("tool_sha256", ctx["tool"]),
            ("cli_sha256", ctx["cli"]),
            ("zip_sha256", Path(plan["zip"])),
            ("maintained_plan_sha256", ctx["maintained_plan"]),
        ]:
            require(sha(path) == plan[key], key + " drift before apply")
        require(
            ctx["art"].distribution_manifest(ctx["artifact"])
            == ctx["files"]
            == ctx["art"].distribution_manifest(ctx["repo"]),
            "source/artifact drift before apply",
        )
        require(
            ctx["daily"]._helper_identities() == ctx["helpers"],
            "helper closure drift before apply",
        )
        require(
            sha(ctx["old_zip"]) == OLD_RELEASES[plan["old_version"]]["zip_sha256"],
            "published old ZIP drift",
        )
        require(
            ctx["art"].distribution_manifest(
                Path(ctx["normalized_plan"]["old_artifact_dir"])
            )
            == ctx["old_files"],
            "old artifact drift",
        )
        verify_zip(ctx["old_zip"], ctx["old_files"])
        require(
            ctx["daily"]._verify_between_turns_compatibility(
                ctx["normalized_plan"], plan["old_version"]
            )
            == ctx["compatibility"],
            "compatibility drift before apply",
        )
        require(
            subprocess.run(
                ["git", "-C", str(ctx["repo"]), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
                timeout=20,
            ).stdout.strip()
            == plan["commit"],
            "commit drift before apply",
        )
        require(
            not ctx["new_root"].exists() and not ctx["new_root"].is_symlink(),
            "target cache appeared before maintained command",
        )
        official_list(ctx, plan["old_version"])
        log_marker(c, "apply_started")
        fact = apply(ctx, "--resume")
        log_marker(c, "apply_finished")
        write(out / "maintained-call.json", fact)
        rc = fact.get("exit_code")
        require(
            cleanup_confirmed(fact.get("cleanup")),
            "maintained process cleanup unconfirmed",
        )
        require(rc in (0, 1), "maintained apply failed; inspect its durable receipts")
        if rc == 1 and fact.get("pending_kind") in (
            "activity_pending",
            "query_cleanup_unconfirmed",
        ):
            if fact["pending_kind"] == "query_cleanup_unconfirmed":
                raise Pending(
                    "activity query cleanup unconfirmed; stop and inspect the retained batch"
                )
            if no_add_attempted(ctx):
                raise Pending(
                    "activity pending before plugin add; retained batch requires pause and review before retry"
                )
            raise Pending(
                "activity pending with possible add; inspect the retained journal before any retry"
            )
        expected_verify = "passed" if rc == 0 else "hook_trust_pending"
        binding = verify_maintained(
            ctx, plan, ctx["tool_output"] / "verify.json", expected_verify
        )
        official = official_list(
            ctx, plan["target_version"], ctx["artifact"], allow_disabled=(rc == 1)
        )
        write(out / "official-readback.json", official)
        require(c.owned.process.poll() is None, "app-server exited during apply")
        ctx["art"].compare_artifact(ctx["artifact"], ctx["new_root"])
        require(
            ctx["u"].source_files(ctx["new_root"]) == ctx["files"],
            "target cache full tree differs",
        )
        result["gates"]["maintained_apply"] = {
            "status": "passed",
            "receipt": str(ctx["tool_output"]),
            "binding": binding,
        }
        stage = "trust_wait"
        deadline = clock() + ctx["wait"]
        newsource = ctx["new_root"] / "hooks/hooks.json"
        write(
            out / "trust-wait-start.json",
            {
                "server_pid": pid,
                "thread": thread,
                "budget_seconds": ctx["wait"],
                "apply_repeated": False,
            },
        )
        while True:
            try:
                newinv = c.inventory_for([newsource])
                break
            except Pending as e:
                if clock() >= deadline:
                    raise Pending(
                        "normal Hook review pending; live continuation unavailable after this bounded wait"
                    ) from e
                sleeper(min(2, max(0, deadline - clock())))
        if expected_verify == "hook_trust_pending":
            verified_path = ctx["tool_output"] / "verify-after-trust.json"
            verify_fact = apply(ctx, "--verify", verify_output=verified_path)
            write(out / "maintained-verify-call.json", verify_fact)
            require(
                cleanup_confirmed(verify_fact.get("cleanup"))
                and verify_fact.get("exit_code") == 0,
                "maintained verify did not pass after trust review",
            )
            verify_maintained(ctx, plan, verified_path, "passed")
        c.approved = newinv
        c.observation_thread = thread
        c.observation_inventory = {**oldinv, **newinv}
        result["gates"]["new_trust"] = {"status": "passed", "count": 9}
        write(
            out / "new-trust.json",
            {"count": len(newinv), "hooks": list(newinv.values())},
        )
        log_marker(c, "new_trust_confirmed")
        stage = "config_refresh"
        require(
            sha(producer_path()) == ctx["producer_sha256"]
            and sha(diagnostic_path()) == ctx["diagnostic_sha256"],
            "native code drift before config refresh",
        )
        refresh_receipt = c.refresh_config_for_thread(thread)
        write(out / "config-refresh.json", refresh_receipt)
        result["gates"]["config_refresh"] = {"status": "passed"}
        log_marker(c, "config_refresh_completed")
        stage = "old_continuation"
        c.check_provider()
        turn2, rows2 = c.observed_turn(
            thread, "请继续保留先前待完成的验收要求，本回合仅回复继续观察。"
        )
        log_marker(c, "old_continuation_complete")
        audit_turn_tools(rows2, thread, turn2, allow_read=False)
        events = pairs(
            ctx,
            rows2,
            c.observation_inventory,
            thread,
            turn2,
            ("userPromptSubmit", "stop"),
        )
        require(all(events.values()), "old continuation Hooks missing")
        after = snapshot(ctx, thread)
        ctx["u"].validate_continuity(before["state"], after["state"])
        validate_projected_scope(project(ctx, before), project(ctx, after))
        require(before["root"] == after["root"], "data root changed")
        markers = [
            x for x in after["state"].get("prompts", []) if x.get("turn_id") == turn2
        ]
        require(len(markers) == 1, "new old-thread prompt state not observed")
        capture_full_state(ctx, after, thread, out / "old-after-full-state.json")
        write(out / "old-after.json", project(ctx, after))
        old_witness = witness(ctx, thread, turn2)
        definitions = sorted(
            {
                r.get("sourcePath")
                for e in ("userPromptSubmit", "stop")
                for r in ctx["u"]._paired(
                    rows2, c.observation_inventory, thread, e, turn=turn2
                )
            }
        )
        result["gates"]["old_model"] = {
            "status": "passed",
            "thread": thread,
            "old_turn": turn,
            "new_turn": turn2,
            "pid": pid,
            "hooks": events,
            "definition_sources": definitions,
            "runtime_os_path": old_witness,
            "runtime_classification": old_runtime_classification(ctx),
        }
        stage = "fresh_turn"
        c.check_provider()
        fresh = c.start()
        require(fresh != thread, "fresh thread identity reused")
        require(
            sha(ctx["read_file"]) == plan["native_read_sha256"],
            "controlled read fixture drift before turn",
        )
        command = read_command(ctx["read_file"].name)
        freshturn, freshrows = c.observed_turn(
            fresh,
            "请只读取一次 "
            + ctx["read_file"].name
            + "，执行精确命令 "
            + command
            + "，随后报告完成。",
        )
        log_marker(c, "fresh_turn_complete")
        audit_turn_tools(freshrows, fresh, freshturn, allow_read=True)
        fresh_events = pairs(
            ctx,
            freshrows,
            newinv,
            fresh,
            freshturn,
            ("userPromptSubmit", "stop", "preToolUse", "postToolUse"),
        )
        require(all(fresh_events.values()), "fresh Hook execution incomplete")
        verify_read_tool(ctx, freshrows, newinv, fresh, freshturn, command)
        require(
            sha(ctx["read_file"]) == plan["native_read_sha256"],
            "controlled read fixture changed",
        )
        require(
            c.owned.process.poll() is None and c.owned.process.pid == pid,
            "app-server identity changed",
        )
        fresh_witness = witness(ctx, fresh, freshturn)
        result["gates"]["fresh_model"] = {
            "status": "passed",
            "thread": fresh,
            "turn": freshturn,
            "pid": pid,
            "hooks": fresh_events,
            "definition_source": str(newsource),
            "runtime_os_path": fresh_witness,
        }
        result["status"] = "passed_cli_native"
    except Pending as e:
        result.update(status="pending", stage=stage, reason=str(e))
    except Exception as e:
        result.update(
            status="failed", stage=stage, reason=type(e).__name__ + ": " + str(e)
        )
    finally:
        if c is None and "startup_cleanup" in ctx:
            result["cleanup"] = ctx["startup_cleanup"]
            if ctx["startup_cleanup"].get("client_cleanup_complete") is not True:
                result["status"] = "failed_cleanup"
        if c is not None:
            try:
                result["cleanup"] = c.close()
                if not client_cleanup_confirmed(result["cleanup"]):
                    result["status"] = "failed_cleanup"
                elif result["cleanup"].get("reader_failure", "missing") is not None:
                    result["status"] = "failed"
                    result["stage"] = "reader"
                    result["reason"] = "RPC reader evidence incomplete"
            except Exception as e:
                result["cleanup"] = {"cleanup_unknown": type(e).__name__}
                result["status"] = "failed_cleanup"
        if result["status"] == "passed_cli_native":
            try:
                capture_post_close(ctx, result["gates"]["old_model"]["thread"])
            except Exception as exc:
                result.update(status="failed_evidence", stage="post_close_capture", reason=type(exc).__name__)
        if result["status"] == "passed_cli_native":
            names = [
                "old-after-full-state.json",
                "post-close-full-state.json",
                "post-close.json",
                "server.json",
                "old-trust.json",
                "old-state.json",
                "old-after.json",
                "new-trust.json",
                "rpc.jsonl",
                "between-turn-boundary.json",
                "maintained-call.json",
                "official-readback.json",
                "config-refresh.json",
                "config-refresh-attempt.json",
                "config-refresh-outcome.json",
            ]
            try:
                result["evidence"] = {name: sha(out / name) for name in names}
                for name in (
                    "prepare.json",
                    "apply.json",
                    "verify.json",
                    "apply-events.jsonl",
                ):
                    result["evidence"]["maintained/" + name] = sha(
                        ctx["tool_output"] / name
                    )
                optional = ctx["tool_output"] / "verify-after-trust.json"
                if optional.exists():
                    result["evidence"]["maintained/verify-after-trust.json"] = sha(
                        optional
                    )
                    result["evidence"]["maintained-verify-call.json"] = sha(
                        out / "maintained-verify-call.json"
                    )
                result["subject"]["state_capture"] = STATE_CAPTURE
                result["subject"]["native_plan_sha256"] = plan["_native_plan_sha256"]
                result["subject"]["producer_sha256"] = ctx["producer_sha256"]
                result["subject"]["diagnostic_sha256"] = ctx["diagnostic_sha256"]
                result["subject"]["helper_closure_sha256"] = ctx["u"].digest(
                    ctx["helpers"]
                )
            except Exception as exc:
                result.update(status="failed_evidence", reason=type(exc).__name__)
        if result["status"] == "passed_cli_native":
            result["status"] = "provisional_cli_native"
        write(out / "result.json", result)
        if result["status"] == "provisional_cli_native":
            try:
                independent_verify(ctx, plan, out)
                write(
                    out / "independent-verification.json",
                    {
                        "schema": INDEPENDENT,
                        "status": "passed",
                        "result_sha256": sha(out / "result.json"),
                    },
                )
                result["status"] = "passed_cli_native"
            except Exception as exc:
                write(
                    out / "independent-verification.json",
                    {
                        "schema": INDEPENDENT,
                        "status": "failed",
                        "reason": type(exc).__name__,
                        "result_sha256": sha(out / "result.json"),
                    },
                )
                result["status"] = "failed_independent_verification"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--run", action="store_true")
    action.add_argument("--verify-result", action="store_true")
    a = parser.parse_args()
    plan_bytes = safe_bytes(regular(a.plan), 16 * 1024 * 1024)
    plan = strict_json_bytes(plan_bytes)
    require("_native_plan_sha256" not in plan, "reserved plan field")
    plan["_native_plan_sha256"] = hashlib.sha256(plan_bytes).hexdigest()
    ctx = preflight(plan, a.output, after=a.verify_result)
    ctx["native_plan_path"] = regular(a.plan)
    if a.verify_result:
        saved = strict_read_json(ctx["output"] / "result.json")
        result_sha = sha(ctx["output"] / "result.json")
        sidecar_path = ctx["output"] / "independent-verification.json"
        if saved.get("status") == "provisional_cli_native" or sidecar_path.exists():
            sidecar = strict_read_json(sidecar_path)
            require(
                sidecar.get("schema") == INDEPENDENT
                and sidecar.get("status") == "passed"
                and sidecar.get("result_sha256") == result_sha,
                "independent result receipt missing or mismatched",
            )
        independent_verify(ctx, plan, ctx["output"])
        print(
            json.dumps(
                {
                    "schema": INDEPENDENT,
                    "status": "reverified_read_only",
                    "result_sha256": result_sha,
                }
            )
        )
        return 0
    if a.preflight:
        print(
            json.dumps(
                {
                    "schema": REPORT,
                    "status": "preflight_passed_only",
                    "target_version": plan["target_version"],
                    "commit": plan["commit"],
                    "file_count": len(ctx["files"]),
                }
            )
        )
        return 0
    result = run(plan, ctx)
    print(json.dumps({"status": result["status"], "stage": result.get("stage")}))
    return 0 if result["status"] == "passed_cli_native" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("refused: " + type(e).__name__ + ": " + str(e), file=sys.stderr)
        sys.exit(2)
