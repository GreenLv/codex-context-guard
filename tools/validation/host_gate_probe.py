#!/usr/bin/env python3
"""Run the exact synthetic commit/local-push host-gate scenario."""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def _adapter() -> Any:
    path = Path(__file__).with_name("host_gate_adapter.py")
    spec = importlib.util.spec_from_file_location("host_gate_probe_adapter", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load host_gate_adapter.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(cwd: Path, *args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"scenario Git command failed: {args[0]}")
    return result.stdout


def run(experiment_path: Path) -> str:
    adapter = _adapter()
    experiment, experiment_sha = adapter.load_experiment(experiment_path)
    adapter.validate_probe_bytes(experiment)
    git = experiment["git"]
    worktree = Path(git["worktree"]).resolve(strict=True)
    target = git["target_path"]
    if _git(worktree, "rev-parse", "HEAD").decode().strip() != git["initial_head"]:
        raise RuntimeError("scenario initial HEAD drifted")
    target_bytes = (worktree / target).read_bytes()
    if adapter.sha256_bytes(target_bytes) != git["target_sha256"]:
        raise RuntimeError("scenario target bytes drifted")
    if _git(worktree, "diff", "--cached", "--name-only", "-z"):
        raise RuntimeError("scenario index was not empty")
    _git(worktree, "add", "--", target)
    staged = [
        os.fsdecode(x)
        for x in _git(worktree, "diff", "--cached", "--name-only", "-z").split(b"\0")
        if x
    ]
    if staged != [target]:
        raise RuntimeError("scenario staged paths differ from exact target")
    _git(
        worktree,
        "-c", "user.name=Context Guard Fixture",
        "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "commit", "--no-gpg-sign", "-m", git["commit_message"], "--", target,
    )
    _git(
        worktree, "push", git["bare_remote"],
        f"HEAD:refs/heads/{git['branch']}",
    )
    readback = adapter.git_readback(experiment)
    marker = {
        "schema": adapter.MARKER_SCHEMA,
        "experiment_sha256": experiment_sha,
        "nonce": experiment["nonce"],
        "scenario": "commit_push",
        **readback,
    }
    return adapter.encode_marker(marker)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("commit-push")
    run_parser.add_argument("--experiment", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        marker = run(args.experiment)
    except Exception as exc:  # bounded CLI failure; no marker on any error
        print(f"host_gate_probe_failed: {exc}", file=sys.stderr)
        return 2
    print(marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
