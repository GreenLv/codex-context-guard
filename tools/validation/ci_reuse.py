#!/usr/bin/env python3
"""Consume an already passed full candidate run on this exact commit.

CI policy allows reusing a prior full-profile candidate run when it passed on
the exact commit: ``docs/CI_POLICY.md`` — "If the earlier full run already
passed on the exact commit, reuse it; tag creation does not require another
run." This tool is that rule's real result consumer. It queries the official
GitHub Actions API for completed runs of the candidate workflow on the exact
head commit, re-derives the prior run's full-coverage facts from its job
list, verifies the candidate artifact receipt against this checkout when the
escrow artifact exists, and emits one bounded evidence receipt.

Fail-closed by construction: any missing evidence, any non-success required
job, any workflow or commit identity mismatch, any artifact receipt mismatch
and every API or local failure answers ``denied`` — the caller then runs the
ordinary lanes, which is the safer direction. A reuse verdict never relaxes
the required-job summary: the summary still demands ``classify``, ``static``
and this job's success, and a confirmed reuse only exempts the lanes that
the prior full run already passed on the same bytes.

Results live in the exclusive ``--output`` receipt, which is never replaced.
The receipt schema is ``cg-ci-reuse-evidence/v1``. Exit codes: ``0``
confirmed; ``3`` not confirmed (denied, refused or failed — the safer
direction is always to run the ordinary lanes, and a receipt is written
whenever the output path is writable).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.validation.acceptance_identity import runtime_tree_digest  # noqa: E402
from tools.validation.ci_policy import CI_LANES  # noqa: E402

SCHEMA = "cg-ci-reuse-evidence/v1"
CANDIDATE_WORKFLOW = ".github/workflows/ci.yml"
CANDIDATE_ARTIFACT_PREFIX = "context-guard-candidate-"
ARTIFACT_RECEIPT = "artifact.json"
STATIC_JOB_NAME = "Identity, repository, privacy, lint, and compile"
CLASSIFY_JOB_NAME = "Classify candidate bytes"
PORTABLE_JOB_NAME = "Windows portable installed-runtime acceptance"
REQUIRED_JOB_NAME = "Candidate CI required"
EVENTS = ("push", "workflow_dispatch")
MAX_RUN_PAGES = 5
MAX_RUNS_PER_PAGE = 100
MAX_ARTIFACTS = 64
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_JOB_NAMES = 64
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
API_TIMEOUT = 60.0

# A reusable prior run must have run and passed every job the full profile
# requires. Skipped or missing names mean the run was not a genuine full run
# (for example a run that itself reused an even earlier one); such candidates
# are skipped, never cited.
REQUIRED_JOB_NAMES = frozenset(
    [CLASSIFY_JOB_NAME, STATIC_JOB_NAME, PORTABLE_JOB_NAME, REQUIRED_JOB_NAME,
     *(row[1] for row in CI_LANES)])


class ReuseError(Exception):
    """A refused input or a failed evaluation; the caller keeps running lanes."""


def _gh_api(path: str, timeout: float = API_TIMEOUT) -> bytes:
    """One official GitHub API call through the authenticated ``gh`` CLI.

    Tests replace this seam; the tool never reads or logs a token.
    """
    result = subprocess.run(["gh", "api", path], capture_output=True,
                            timeout=timeout)
    if result.returncode != 0:
        raise ReuseError("gh api failed: " + path + "; "
                         + result.stderr.decode("utf-8", "replace")[:200])
    return result.stdout


def _gh_download(path: str, target: Path, timeout: float = API_TIMEOUT) -> None:
    """One official binary artifact download; tests replace this seam."""
    with open(target, "wb") as sink:
        result = subprocess.run(["gh", "api", path], stdout=sink,
                                stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode != 0:
        raise ReuseError("gh download failed: " + path + "; "
                         + result.stderr.decode("utf-8", "replace")[:200])


def _local_commit(source_root: Path, timeout: float = 30.0) -> str:
    """The exact commit of this checkout; the light main-side identity check."""
    result = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"],
                            capture_output=True, timeout=timeout)
    if result.returncode != 0:
        raise ReuseError("cannot read the local commit: "
                         + result.stderr.decode("utf-8", "replace")[:120])
    return result.stdout.decode().strip()


def _json_api(path: str) -> dict[str, Any]:
    try:
        value = json.loads(_gh_api(path).decode("utf-8", "strict"))
    except (UnicodeError, ValueError) as exc:
        raise ReuseError("GitHub API returned invalid JSON for " + path) from exc
    if not isinstance(value, dict):
        raise ReuseError("GitHub API returned a non-object for " + path)
    return value


def _candidate_runs(repo: str, commit: str, workflow: str,
                    current_run: str) -> list[dict[str, Any]]:
    """Completed successful candidate-workflow runs on this exact commit."""
    found: list[dict[str, Any]] = []
    for page in range(1, MAX_RUN_PAGES + 1):
        listing = _json_api(
            f"repos/{repo}/actions/runs?head_sha={commit}"
            f"&per_page={MAX_RUNS_PER_PAGE}&page={page}")
        runs = listing.get("workflow_runs")
        if not isinstance(runs, list):
            raise ReuseError("run listing is malformed")
        for run in runs:
            if not isinstance(run, dict):
                raise ReuseError("run entry is malformed")
            if (str(run.get("id")) == current_run
                    or run.get("path") != workflow
                    or run.get("event") not in EVENTS
                    or run.get("status") != "completed"
                    or run.get("conclusion") != "success"
                    or run.get("head_sha") != commit):
                continue
            found.append({"id": str(run["id"]), "url": run.get("html_url"),
                          "created_at": run.get("created_at"),
                          "event": run.get("event")})
        if len(runs) < MAX_RUNS_PER_PAGE:
            break
    return found[:MAX_RUN_PAGES * MAX_RUNS_PER_PAGE]


def _prior_run_jobs(repo: str, run_id: str) -> dict[str, str]:
    """Job name to conclusion for one prior run, bounded."""
    listing = _json_api(f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")
    jobs = listing.get("jobs")
    if not isinstance(jobs, list) or len(jobs) > MAX_JOB_NAMES * 4:
        raise ReuseError("job listing is malformed or oversized")
    conclusions: dict[str, str] = {}
    for job in jobs:
        if not isinstance(job, dict) or not isinstance(job.get("name"), str):
            raise ReuseError("job entry is malformed")
        name = job["name"]
        if name in conclusions:
            raise ReuseError("duplicate job name in the prior run")
        conclusions[name] = str(job.get("conclusion"))
    return conclusions


def _verify_prior_jobs(conclusions: dict[str, str]) -> str | None:
    """``None`` when every full-profile job passed; else a short refusal.

    Missing or skipped names refuse this candidate without poisoning the
    search (an older genuine full run may still exist); any failed or
    cancelled full-profile job on this exact commit is evidence against
    reuse and refuses the whole evaluation.
    """
    if len(conclusions) > MAX_JOB_NAMES * 4:
        return "job listing oversized"
    missing = sorted(REQUIRED_JOB_NAMES - set(conclusions))
    skipped = sorted(name for name in REQUIRED_JOB_NAMES
                     if conclusions.get(name) == "skipped")
    if missing or skipped:
        return "not_a_genuine_full_run"
    failed = sorted(name for name in REQUIRED_JOB_NAMES
                    if conclusions.get(name) != "success")
    if failed:
        return "prior_full_run_has_failed_jobs: " + ", ".join(failed[:8])
    broken = sorted(name for name, result in conclusions.items()
                    if result not in ("success", "skipped", None)
                    and name not in REQUIRED_JOB_NAMES)
    if broken:
        return "prior_run_has_unexpected_job_results: " + ", ".join(broken[:8])
    return None


def _candidate_artifact(repo: str, run_id: str, commit: str) -> dict[str, Any] | None:
    listing = _json_api(f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100")
    artifacts = listing.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) > MAX_ARTIFACTS:
        raise ReuseError("artifact listing is malformed or oversized")
    wanted = CANDIDATE_ARTIFACT_PREFIX + commit
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("name"), str):
            raise ReuseError("artifact entry is malformed")
        if artifact["name"] == wanted:
            return artifact
    return None


def _artifact_receipt(repo: str, artifact: dict[str, Any],
                      source_root: Path) -> dict[str, Any]:
    """Download the escrow ZIP and verify its receipt against this checkout."""
    identifier = artifact.get("id")
    size = artifact.get("size_in_bytes")
    if not isinstance(identifier, int) or not isinstance(size, int) \
            or size <= 0 or size > MAX_ARTIFACT_BYTES:
        raise ReuseError("candidate artifact metadata is malformed or oversized")
    with tempfile.TemporaryDirectory() as temporary:
        target = Path(temporary) / "candidate.zip"
        _gh_download(f"repos/{repo}/actions/artifacts/{identifier}/zip", target)
        if target.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ReuseError("candidate artifact exceeds its size bound")
        with zipfile.ZipFile(target) as zipped:
            names = zipped.namelist()
            if ARTIFACT_RECEIPT not in names or len(names) > 256:
                raise ReuseError("candidate artifact lacks its receipt or is oversized")
            body = zipped.read(ARTIFACT_RECEIPT)
    try:
        receipt = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeError, ValueError) as exc:
        raise ReuseError("candidate artifact receipt is not JSON") from exc
    if not isinstance(receipt, dict) or receipt.get("schema") != "cg-candidate-artifact/v1":
        raise ReuseError("candidate artifact receipt schema is unknown")
    if receipt.get("source_commit") != _local_commit(source_root):
        raise ReuseError("candidate artifact receipt binds a different source commit")
    if receipt.get("runtime_tree_sha256") != runtime_tree_digest(source_root):
        raise ReuseError("candidate artifact runtime digest differs from this checkout")
    return {"name": artifact["name"], "artifact_id": str(identifier),
            "source_commit": receipt.get("source_commit"),
            "runtime_tree_sha256": receipt.get("runtime_tree_sha256"),
            "sha256": receipt.get("sha256"), "size_bytes": receipt.get("size_bytes"),
            "file_count": receipt.get("file_count")}


def evaluate(repo: str, commit: str, current_run: str, workflow: str,
             source_root: Path) -> dict[str, Any]:
    if not REPO.fullmatch(repo):
        raise ReuseError("repository must be owner/name")
    if not SHA.fullmatch(commit):
        raise ReuseError("commit must be a full 40-hex SHA")
    if not str(current_run).isdigit() or not current_run:
        raise ReuseError("current run id must be numeric")
    local_commit = _local_commit(source_root)
    if local_commit != commit:
        raise ReuseError("this checkout is not at the evaluated commit: "
                         + local_commit)
    checked: list[dict[str, Any]] = []
    for run in _candidate_runs(repo, commit, workflow, current_run):
        conclusions = _prior_run_jobs(repo, run["id"])
        verdict = _verify_prior_jobs(conclusions)
        checked.append({"run": run, "job_count": len(conclusions),
                        "refusal": verdict})
        if verdict is not None:
            if verdict.startswith("not_a_genuine_full_run"):
                continue  # an older genuine full run may still exist
            return {"verdict": "denied", "reason": verdict,
                    "prior_run": run, "jobs": conclusions, "checked": checked,
                    "artifact": None}
        artifact = _candidate_artifact(repo, run["id"], commit)
        if artifact is None:
            return {"verdict": "confirmed", "reason": "prior full run passed "
                    "every full-profile job on this exact commit; escrow "
                    "artifact absent from that run",
                    "prior_run": run, "jobs": conclusions, "checked": checked,
                    "artifact": {"status": "absent"}}
        try:
            receipt = _artifact_receipt(repo, artifact, source_root)
        except ReuseError as exc:
            return {"verdict": "denied", "reason": str(exc),
                    "prior_run": run, "jobs": conclusions, "checked": checked,
                    "artifact": None}
        return {"verdict": "confirmed", "reason": "prior full run passed "
                "every full-profile job on this exact commit and its escrow "
                "artifact receipt matches this checkout",
                "prior_run": run, "jobs": conclusions, "checked": checked,
                "artifact": {"status": "checked", **receipt}}
    return {"verdict": "denied",
            "reason": "no completed full-profile candidate run passed on this "
            "exact commit", "prior_run": None, "jobs": None,
            "checked": checked, "artifact": None}


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    parent = path.parent
    if not parent.is_dir():
        raise ReuseError("receipt parent directory does not exist: " + str(parent))
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument("--commit", required=True, help="exact head commit")
    parser.add_argument("--current-run", required=True, help="this run's id")
    parser.add_argument("--workflow", default=CANDIDATE_WORKFLOW)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True,
                        help="exclusive receipt path; never replaced")
    args = parser.parse_args(argv)
    receipt: dict[str, Any] = {
        "schema": SCHEMA, "commit": args.commit, "workflow": args.workflow,
        "current_run": args.current_run, "verdict": "denied",
        "reason": "evaluation did not complete", "prior_run": None,
        "jobs": None, "checked": [], "artifact": None}
    try:
        result = evaluate(args.repo, args.commit, args.current_run,
                          args.workflow, args.source_root.resolve())
        receipt.update(result)
    except (ReuseError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        receipt["reason"] = type(exc).__name__ + ": " + str(exc)[:300]
    try:
        _write_receipt(args.output, receipt)
    except OSError as exc:
        # A verdict without its receipt is not consumable evidence; refusing
        # loudly beats printing a bare verdict the release flow would trust.
        print("ci_reuse receipt not written: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"verdict": receipt["verdict"], "reason": receipt["reason"]},
                     ensure_ascii=False))
    return 0 if receipt["verdict"] == "confirmed" else 3


if __name__ == "__main__":
    raise SystemExit(main())
