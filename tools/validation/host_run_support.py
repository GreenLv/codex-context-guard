#!/usr/bin/env python3
"""Pinned toolchain and resumable bookkeeping for native host acceptance.

This helper does not decide any host gate. The existing capture, mapping and
native-acceptance validators remain authoritative. Private run files stay
outside the source tree; exported bundles contain only allowlisted facts.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

STAGES = ("prepared", "login", "trust", "scenario", "mapping", "validation", "export")
SCHEMA = "context-guard-host-run/v1"
TEXT_SUFFIXES = {".py", ".sh", ".ps1", ".json", ".md", ".toml"}
HOST_GATES = {"hook_trust", "commit_event", "local_push_readback",
              "continuity_wait", "compact_resume", "cleanup"}
RESULT_STATUSES = {"passed", "failed", "pending", "skipped"}
CLEANUP_STATUSES = RESULT_STATUSES | {"observed_facts_required"}


class RunError(ValueError):
    pass


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    with path.open("xb") as stream:
        stream.write(raw)


def write_replace(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise RunError("stale stage temporary file; inspect before retry")
    write_new(temporary, value)
    os.replace(temporary, path)


def regular(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_file():
        raise RunError("tool must be a regular file")
    return resolved


def version(path: Path, *args: str) -> str:
    result = subprocess.run([str(path), *args], text=True, capture_output=True,
                            encoding="utf-8", errors="replace", timeout=20, check=False)
    if result.returncode:
        raise RunError("pinned tool version probe failed")
    return (result.stdout or result.stderr).strip().splitlines()[0]


def identity(path: Path, *args: str) -> dict:
    actual = regular(path)
    return {"path": str(actual), "sha256": sha(actual), "version": version(actual, *args)}


def check_runtime_newlines(root: Path, paths: dict) -> None:
    crlf = [name for name in paths if Path(name).suffix in TEXT_SUFFIXES
            and b"\r\n" in (root / name).read_bytes()]
    if crlf:
        raise RunError("runtime text has CRLF checkout conversion: " + ", ".join(crlf[:8]))


def runtime_identity(root: Path) -> dict:
    module_path = Path(__file__).with_name("host_capture.py")
    spec = importlib.util.spec_from_file_location("pinned_host_capture", module_path)
    if spec is None or spec.loader is None:
        raise RunError("host capture module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    digest, plugin_version, file_count = module.measure_runtime(root)
    manager = module._load_manager(root)  # share the product's runtime-tree definition
    paths = manager.tree_manifest(root)
    check_runtime_newlines(root, paths)
    return {"root": str(root.resolve(strict=True)), "sha256": digest,
            "plugin_version": plugin_version, "file_count": file_count,
            "newlines": "LF"}


def make_lock(args: argparse.Namespace) -> dict:
    codex = identity(args.codex, "--version")
    if Path(codex["path"]).suffix.lower() != ".exe" and os.name == "nt":
        raise RunError("Windows host runs require the actual Codex .exe, not a PATH launcher")
    python = identity(args.python, "--version")
    shell = identity(args.shell, "-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()")
    home = args.codex_home.resolve(strict=True)
    return {"schema": SCHEMA, "toolchain": {"codex": codex, "python": python,
                                               "shell": shell},
            "runtime": runtime_identity(args.runtime_root),
            "codex_home": str(home), "stages": {"prepared": {"status": "passed"}}}


def load_and_verify(args: argparse.Namespace) -> dict:
    path = args.run_dir / "run.json"
    item = json.loads(path.read_text(encoding="utf-8"))
    if item.get("schema") != SCHEMA or set(item.get("stages", {})) - set(STAGES):
        raise RunError("invalid run journal")
    if item["codex_home"] != str(args.codex_home.resolve(strict=True)):
        raise RunError("isolated HOME changed")
    for name, params in (("codex", ("--version",)), ("python", ("--version",)),
                         ("shell", ("-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"))):
        old = item["toolchain"][name]
        if identity(Path(old["path"]), *params) != old:
            raise RunError(name + " executable drifted after preflight")
    if runtime_identity(Path(item["runtime"]["root"])) != item["runtime"]:
        raise RunError("runtime bytes or newline identity drifted after preflight")
    return item


def advance(args: argparse.Namespace, item: dict) -> None:
    stage = args.stage
    if stage == "prepared":
        raise RunError("preparation is created only by preflight")
    prior = STAGES[STAGES.index(stage) - 1]
    if item["stages"].get(prior, {}).get("status") != "passed":
        raise RunError("previous stage is not complete: " + prior)
    proof = regular(args.proof)
    fingerprint = sha(proof)
    old = item["stages"].get(stage)
    if old:
        if old.get("proof_sha256") != fingerprint:
            raise RunError("completed stage has different evidence; retain old journal")
        print("stage=noop; already bound")
        return
    if stage == "trust":
        if not args.reviewed:
            raise RunError("trust requires explicit operator review of the Hook record")
        record = json.loads(proof.read_text(encoding="utf-8"))
        if record.get("status") != "trusted" or record.get("errors") or record.get("warnings"):
            raise RunError("Hook trust readback is not clean")
    if stage == "validation":
        result = json.loads(proof.read_text(encoding="utf-8"))
        if result.get("status") != "passed" or result.get("runtime_tree_sha256") != item["runtime"]["sha256"]:
            raise RunError("validation proof is not a passed result for pinned runtime")
    if stage == "mapping":
        manifest = json.loads(proof.read_text(encoding="utf-8"))
        if (manifest.get("schema") not in {"context-guard-reviewed-host-mapping/v1",
                                            "context-guard-reviewed-host-continuity/v1"}
                or manifest.get("subject", {}).get("runtime_tree_sha256") != item["runtime"]["sha256"]
                or manifest.get("subject", {}).get("plugin_version") != item["runtime"]["plugin_version"]
                or not manifest.get("reviewed_at")):
            raise RunError("mapping is not a reviewed manifest for pinned runtime")
    if stage == "export":
        if proof.name != "manifest.json":
            raise RunError("export proof must be the bundle manifest")
        verify_bundle(proof.parent)
        summary = json.loads((proof.parent / "summary.json").read_text(encoding="utf-8"))
        if summary.get("runtime_tree_sha256") != item["runtime"]["sha256"]:
            raise RunError("export bundle differs from pinned runtime")
    item["stages"][stage] = {"status": "passed", "proof_path": str(proof),
                              "proof_sha256": fingerprint,
                              **({"operator_reviewed": True} if stage == "trust" else {})}
    write_replace(args.run_dir / "run.json", item)
    print("stage=" + stage + "; evidence_bound=true")


def draft(args: argparse.Namespace, item: dict) -> None:
    if args.scenario not in {"git", "continuity"}:
        raise RunError("draft requires git or continuity scenario")
    folder = args.run_dir / args.scenario
    config = folder / "hooks.draft.json"
    mapping = folder / "mapping.draft.json"
    commands = folder / "commands.draft.json"
    if config.exists() or mapping.exists() or commands.exists():
        raise RunError("draft already exists; verify its bytes instead of overwriting")
    capture = folder / "capture"
    events = (("PreToolUse", "PostToolUse") if args.scenario == "git" else
              ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PreCompact",
               "SessionStart", "Stop", "SessionEnd"))
    module_path = Path(__file__).with_name("host_capture.py")
    spec = importlib.util.spec_from_file_location("draft_host_capture", module_path)
    if spec is None or spec.loader is None:
        raise RunError("host capture module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    setup = module.prepare_hooks(
        config, python=Path(item["toolchain"]["python"]["path"]),
        capture_dir=capture, runtime_root=Path(item["runtime"]["root"]),
        events=events,
    )
    command_sha = None
    if args.scenario == "continuity":
        marker = "CG_CONT_" + item["runtime"]["sha256"][:12]
        prompts = [
            "For this isolated continuity test, remember the marker " + marker
            + ". Wait for my explicit next message before completing the task. Do not use tools or change files.",
            "Continue the synthetic task now. State the marker from my earlier message, then stop. Do not use tools or change files.",
            "What marker did I ask you to remember before the compact? Answer with the marker only. Do not use tools.",
        ]
        write_new(commands, {
            "schema": "context-guard-continuity-commands-draft/v1", "reviewed": False,
            "runtime_tree_sha256": item["runtime"]["sha256"], "marker": marker,
            "prompts": prompts,
            "prompt_sha256": [hashlib.sha256(value.encode("utf-8")).hexdigest()
                              for value in prompts],
            "operator_commands": ["/compact", "/exit"],
            "required_review": "Review the prompts and inspect the live wait, compact, state and cleanup witnesses before mapping.",
        })
        command_sha = sha(commands)
    write_new(mapping, {
        "schema": "context-guard-host-mapping-draft/v1",
        "reviewed": False, "scenario": args.scenario,
        "runtime_tree_sha256": item["runtime"]["sha256"],
        "plugin_version": item["runtime"]["plugin_version"],
        "capture_setup_sha256": setup["hooks_file_sha256"],
        "capture_tool_sha256": setup["capture_tool_sha256"],
        "command_draft_sha256": command_sha,
        "events": list(events),
        "required_review": ["actual Codex Hook list and trust status",
                            "raw capture and independent state or Git witnesses",
                            "exact mapping manifest for existing validator"],
    })
    print("draft=created; reviewed=false; hooks_sha256=" + setup["hooks_file_sha256"])


def fixture_git(args: argparse.Namespace, item: dict) -> None:
    """Create only the local baseline; the Codex session must do gate actions."""
    folder = args.run_dir / "git" / "fixture"
    if folder.exists():
        raise RunError("Git fixture already exists; preserve and resume it")
    folder.mkdir(parents=True)
    remote, work = folder / "remote.git", folder / "work"
    work.mkdir()
    env = {**os.environ, "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
           "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z"}

    def git(*parts: str) -> str:
        result = subprocess.run(["git", *parts], capture_output=True,
                                check=False, env=env, timeout=30)
        if result.returncode:
            raise RunError("local Git fixture preparation failed; inspect retained directory")
        return result.stdout.decode("utf-8", errors="replace").strip()

    git("init", "--bare", str(remote))
    git("-C", str(work), "init", "-b", "main")
    target = work / "artifact.txt"
    target.write_bytes(b"baseline\n")
    git("-C", str(work), "-c", "core.autocrlf=false", "add", "artifact.txt")
    git("-C", str(work), "-c", "user.name=Context Guard Fixture",
        "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "-c", "commit.gpgsign=false", "commit", "-m", "baseline")
    git("-C", str(work), "remote", "add", "origin", str(remote))
    git("-C", str(work), "push", "origin", "HEAD:refs/heads/main")
    baseline = git("-C", str(work), "rev-parse", "HEAD")
    if git("--git-dir", str(remote), "rev-parse", "refs/heads/main") != baseline:
        raise RunError("local remote readback differs from fixture baseline")
    target.write_bytes(b"candidate\n")
    write_new(folder / "commands.draft.json", {
        "schema": "context-guard-git-fixture-draft/v1", "reviewed": False,
        "runtime_tree_sha256": item["runtime"]["sha256"],
        "baseline_commit": baseline, "baseline_blob_sha256": hashlib.sha256(b"baseline\n").hexdigest(),
        "candidate_blob_sha256": sha(target),
        "worktree": str(work.resolve()), "bare_remote": str(remote.resolve()),
        "model_commands": ["git add artifact.txt",
                           "git commit -m native-gate-acceptance",
                           "git push origin HEAD:refs/heads/main"],
        "required_review": "Inspect commands and capture setup before trusting hooks; the model performs commit and local push.",
    })
    print("git_fixture=prepared; reviewed=false; baseline=" + baseline)


def login_status(args: argparse.Namespace, item: dict) -> None:
    if item["stages"].get("login", {}).get("status") == "passed":
        print("login=noop; already verified for this isolated HOME")
        return
    tool = item["toolchain"]["codex"]["path"]
    env = {**os.environ, "CODEX_HOME": item["codex_home"]}
    checked = subprocess.run([tool, "login", "status"], env=env,
                             capture_output=True, timeout=30, check=False)
    # Never print or persist the command output; it is an auth-lane readback.
    if checked.returncode:
        raise RunError("pinned Codex is not logged in for this isolated HOME")
    item["stages"]["login"] = {"status": "passed",
                               "codex_sha256": item["toolchain"]["codex"]["sha256"]}
    write_replace(args.run_dir / "run.json", item)
    print("login=passed; isolated HOME reused")


def bundle(args: argparse.Namespace, item: dict) -> None:
    if args.result is None or args.bundle_dir is None:
        raise RunError("bundle needs --result and --bundle-dir")
    result = json.loads(regular(args.result).read_text(encoding="utf-8"))
    if result.get("runtime_tree_sha256") != item["runtime"]["sha256"]:
        raise RunError("result runtime differs from pinned run")
    if (result.get("status") not in RESULT_STATUSES
            or result.get("gate_profile") != "host_behavior"
            or result.get("cleanup", {}).get("status") not in CLEANUP_STATUSES):
        raise RunError("host result has unrecognized status fields")
    gates = result.get("gates", [])
    if (not isinstance(gates, list)
            or any(gate.get("id") not in HOST_GATES
                   or gate.get("status") not in RESULT_STATUSES for gate in gates)
            or len({gate["id"] for gate in gates}) != len(gates)):
        raise RunError("host result has unrecognized gate fields")
    out = args.bundle_dir
    if out.exists():
        raise RunError("bundle directory already exists")
    out.mkdir(parents=True)
    summary = {
        "schema": "context-guard-host-result-bundle/v1",
        "source_result_sha256": sha(args.result),
        "runtime_tree_sha256": item["runtime"]["sha256"],
        "plugin_version": item["runtime"]["plugin_version"],
        "status": result.get("status"),
        "gate_profile": result.get("gate_profile"),
        "gates": [{"id": gate["id"], "status": gate["status"]}
                  for gate in gates],
        "cleanup": {"status": result.get("cleanup", {}).get("status"),
                    "remaining_count": (None if result["cleanup"]["status"] == "observed_facts_required"
                                        else len(result["cleanup"].get("remaining_ids", [])))},
        "toolchain": {name: {"sha256": value["sha256"], "version": value["version"]}
                      for name, value in item["toolchain"].items()},
        "stages": {name: record["status"] for name, record in item["stages"].items()},
    }
    write_new(out / "summary.json", summary)
    write_new(out / "manifest.json", {"schema": "context-guard-file-manifest/v1",
                                      "files": {"summary.json": sha(out / "summary.json")}})
    print("bundle=created; manifest_sha256=" + sha(out / "manifest.json"))


def verify_bundle(folder: Path) -> None:
    if ({path.name for path in folder.iterdir()} != {"summary.json", "manifest.json"}
            or any(path.is_symlink() or not path.is_file() for path in folder.iterdir())):
        raise RunError("bundle contains an unexpected or unsafe file")
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if manifest != {"schema": "context-guard-file-manifest/v1",
                    "files": {"summary.json": sha(folder / "summary.json")}}:
        raise RunError("bundle file digest or manifest changed")
    summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
    if summary.get("schema") != "context-guard-host-result-bundle/v1":
        raise RunError("bundle summary schema invalid")
    print("bundle_verification=passed")


def launch_environment(item: dict) -> dict[str, str]:
    """Make the preflighted interpreters first on the child process PATH."""
    python_dir = str(Path(item["toolchain"]["python"]["path"]).parent)
    shell_dir = str(Path(item["toolchain"]["shell"]["path"]).parent)
    return {**os.environ, "CODEX_HOME": item["codex_home"],
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": os.pathsep.join((python_dir, shell_dir, os.environ.get("PATH", "")))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "verify", "launch", "stage",
                                             "login-status",
                                             "draft", "fixture-git", "bundle",
                                             "verify-bundle"))
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--codex-home", type=Path)
    parser.add_argument("--codex", type=Path)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--shell", type=Path)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--stage", choices=STAGES)
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--reviewed", action="store_true")
    parser.add_argument("--scenario", choices=("git", "continuity"))
    parser.add_argument("--result", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    args, launch_args = parser.parse_known_args()
    if args.command != "launch" and launch_args:
        parser.error("unknown arguments: " + " ".join(launch_args))
    if args.command != "verify-bundle" and (args.run_dir is None or args.codex_home is None):
        parser.error("--run-dir and --codex-home are required")
    try:
        if args.command == "verify-bundle":
            if args.bundle_dir is None:
                raise RunError("verify-bundle needs --bundle-dir")
            verify_bundle(args.bundle_dir)
        elif args.command == "preflight":
            if any(value is None for value in (args.codex, args.python, args.shell, args.runtime_root)):
                raise RunError("preflight needs explicit Codex, Python, Shell and runtime paths")
            lock = make_lock(args)
            target = args.run_dir / "run.json"
            if target.exists():
                existing = load_and_verify(args)
                if {k: v for k, v in existing.items() if k != "stages"} != {
                    k: v for k, v in lock.items() if k != "stages"
                }:
                    raise RunError("existing run journal differs from preflight; keep it")
                print("preflight=noop; pinned identity unchanged")
            else:
                write_new(target, lock)
                print("preflight=passed; pinned identity saved")
        else:
            item = load_and_verify(args)
            if args.command == "verify":
                print("run_identity=passed")
            elif args.command == "stage":
                if not args.stage or not args.proof:
                    raise RunError("stage and proof are required")
                advance(args, item)
            elif args.command == "login-status":
                login_status(args, item)
            elif args.command == "draft":
                draft(args, item)
            elif args.command == "fixture-git":
                fixture_git(args, item)
            elif args.command == "bundle":
                bundle(args, item)
            else:
                tool = item["toolchain"]["codex"]["path"]
                forwarded = launch_args
                if forwarded[:1] == ["--"]:
                    forwarded = forwarded[1:]
                env = launch_environment(item)
                return subprocess.run([tool, *forwarded], env=env, check=False).returncode
        return 0
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as exc:
        print("host_run_failed: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
