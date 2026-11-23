"""Fast-forward a checked Dependabot HOL Action patch from trusted main code."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

from scripts.audit_commit_identity import violations

REPOSITORY = "GreenLv/codex-context-guard"
UPSTREAM_ACTION = "hashgraph-online/ai-plugin-scanner-action"
HOL_WORKFLOW = "hol-plugin-scanner.yml"
HOL_PATH = f".github/workflows/{HOL_WORKFLOW}"
BRANCH_PREFIX = f"dependabot/github_actions/{UPSTREAM_ACTION}-"
DEPENDABOT_ID = 49699333
SHA = re.compile(r"[0-9a-f]{40}")
VERSION = r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})"
PIN = re.compile(
    rf"(?m)^( +uses: {re.escape(UPSTREAM_ACTION)}@)([0-9a-f]{{40}})( # v){VERSION}$".encode()
)
CHECKS = (("validation-shadow.yml", "PR validation required"), (HOL_WORKFLOW, "scan"))
UPDATE_MAIN = """
mutation($repository: ID!, $base: GitObjectID!, $head: GitObjectID!) {
  updateRefs(input: { repositoryId: $repository, refUpdates: [
    { name: "refs/heads/main", beforeOid: $base, afterOid: $head, force: false }
  ] }) { clientMutationId }
}
"""


class Ineligible(Exception):
    """A PR falls outside the approved scope or has incomplete checks."""


class OperationFailed(Exception):
    """An unexpected execution or readback failure with no raw output."""


@dataclass(frozen=True)
class Candidate:
    number: int
    head: str
    branch: str
    base: str
    merge: str


def command(*args: str, app: bool = False) -> bytes:
    env = os.environ.copy()
    token = env.pop("HOL_APP_TOKEN", None)
    if app:
        if not token:
            raise OperationFailed("installation token is missing")
        env["GH_TOKEN"] = token
    result = subprocess.run(args, capture_output=True, env=env, timeout=60, check=False)
    if result.returncode != 0:
        raise OperationFailed(f"{args[0]} operation failed")
    return result.stdout


def api(path: str, *, app: bool = False):
    return json.loads(command("gh", "api", path, app=app))


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Ineligible(reason)


def candidate_from_pr(repo: dict, pr: dict, branch: str, head: str, base: str) -> Candidate:
    author, source, target = pr["user"], pr["head"], pr["base"]
    require(
        pr["state"] == "open" and pr["draft"] is False
        and (author["id"], author["login"], author["type"]) == (
            DEPENDABOT_ID, "dependabot[bot]", "Bot"
        )
        and (source.get("repo") or {}).get("id") == repo["id"] == target["repo"]["id"]
        and (source["ref"], source["sha"], target["ref"], target["sha"]) == (
            branch, head, "main", base
        ),
        "PR author, repository, branch or commit is outside scope",
    )
    require(
        pr["commits"] == 1 and pr["mergeable"] is True
        and SHA.fullmatch(pr["merge_commit_sha"] or "") is not None,
        "PR must have one commit and a current GitHub test merge",
    )
    return Candidate(pr["number"], head, branch, base, pr["merge_commit_sha"])


def changed_pin(before: bytes, after: bytes) -> tuple[str, str]:
    old, new = tuple(PIN.finditer(before)), tuple(PIN.finditer(after))
    require(len(old) == len(new) == 1, "HOL Action must have exactly one full SHA and version")
    old_pin, new_pin = old[0], new[0]
    old_sha, new_sha = old_pin[2], new_pin[2]
    old_version = tuple(map(int, old_pin.groups()[3:]))
    new_version = tuple(map(int, new_pin.groups()[3:]))
    require(
        old_sha != new_sha and old_version[:2] == new_version[:2]
        and new_version[2] > old_version[2],
        "HOL Action update is outside the patch release series",
    )
    require(
        before[:old_pin.start(2)] + new_pin[2] + old_pin[3]
        + b".".join(new_pin.groups()[3:]) + before[old_pin.end():] == after,
        "HOL workflow contains changes outside the Action pin",
    )
    return ".".join(map(str, new_version)), new_sha.decode("ascii")


def verify_commit(candidate: Candidate, endpoint: str) -> None:
    head, base = candidate.head, candidate.base
    commit = api(f"{endpoint}/commits/{head}")
    require(
        commit["sha"] == head and [parent["sha"] for parent in commit["parents"]] == [base]
        and (commit.get("author") or {}).get("id") == DEPENDABOT_ID
        and commit["commit"]["verification"]["verified"] is True,
        "candidate must be a verified Dependabot commit directly on current main",
    )
    # Fetch objects for inspection. The workflow never checks out or executes PR code.
    command(
        "git", "fetch", "--no-tags", "--no-recurse-submodules", "origin",
        f"refs/pull/{candidate.number}/head",
    )
    require(command("git", "rev-parse", "FETCH_HEAD").decode().strip() == head,
            "PR head moved while fetching")
    require(not violations(Path.cwd(), [head]), "commit identity audit failed")

    raw = command("git", "diff-tree", "--no-commit-id", "--no-abbrev", "--no-renames", "-r", base, head)
    require(
        re.fullmatch(rb":100644 100644 [0-9a-f]{40} [0-9a-f]{40} M\t"
                     + re.escape(HOL_PATH.encode()) + rb"\n", raw) is not None,
        "PR must change only the regular HOL workflow file",
    )
    version, sha = changed_pin(
        command("git", "show", f"{base}:{HOL_PATH}"), command("git", "show", f"{head}:{HOL_PATH}")
    )
    require(candidate.branch == BRANCH_PREFIX + version, "Dependabot ref and target version differ")
    tag = api(f"repos/{UPSTREAM_ACTION}/commits/v{version}")
    require(tag["sha"] == sha, "HOL Action SHA differs from the upstream release tag")


def verify_checks(candidate: Candidate, endpoint: str, repo_id: int) -> None:
    head = candidate.head
    for workflow, required_job in CHECKS:
        runs = api(f"{endpoint}/actions/workflows/{workflow}/runs?"
                   f"event=pull_request&head_sha={head}&per_page=1")["workflow_runs"]
        require(bool(runs), "required PR workflow has no current run")
        run = runs[0]
        require(
            (run["event"], run["path"], run["head_sha"], run["head_branch"]) == (
                "pull_request", f".github/workflows/{workflow}", head, candidate.branch
            )
            and (run.get("head_repository") or {}).get("id") == repo_id
            and (run["status"], run["conclusion"]) == ("completed", "success"),
            "latest required PR workflow has not passed for this head",
        )
        run_endpoint = f"{endpoint}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"
        jobs = api(f"{run_endpoint}/jobs?per_page=100")["jobs"]
        require([job["conclusion"] for job in jobs if job["name"] == required_job] == ["success"],
                "required PR job did not pass")
        if workflow == HOL_WORKFLOW:
            artifacts = api(f"{endpoint}/actions/runs/{run['id']}/artifacts?per_page=100")["artifacts"]
            require(
                [item["expired"] for item in artifacts
                 if item["name"] == f"hol-scan-evidence-{candidate.merge}"] == [False],
                "HOL scan does not attest the current GitHub test merge",
            )


def evaluate(repo: dict, endpoint: str, run: dict) -> Candidate:
    branch, head = run["head_branch"], run["head_sha"]
    require(
        run["event"] == "pull_request" and run["conclusion"] == "success"
        and (run.get("head_repository") or {}).get("id") == repo["id"]
        and SHA.fullmatch(head) is not None
        and re.fullmatch(re.escape(BRANCH_PREFIX) + VERSION, branch) is not None,
        "completion event is outside the Dependabot HOL patch scope",
    )
    owner = repo["full_name"].split("/")[0]
    query = urlencode({"state": "open", "base": "main", "head": f"{owner}:{branch}"})
    pulls = api(f"{endpoint}/pulls?{query}")
    require(len(pulls) == 1, "no unique open PR for this head branch")
    pr = api(f"{endpoint}/pulls/{pulls[0]['number']}")
    base = api(f"{endpoint}/git/ref/heads/main")["object"]["sha"]
    require(SHA.fullmatch(base) is not None and base == os.environ["GITHUB_SHA"]
            and command("git", "rev-parse", "HEAD").decode().strip() == base,
            "main advanced after the trusted workflow started")
    candidate = candidate_from_pr(repo, pr, branch, head, base)
    verify_checks(candidate, endpoint, repo["id"])
    verify_commit(candidate, endpoint)
    return candidate


def fast_forward(repo: dict, endpoint: str, candidate: Candidate) -> None:
    current = api(f"{endpoint}/pulls/{candidate.number}")
    require(candidate_from_pr(repo, current, candidate.branch, candidate.head, candidate.base)
            == candidate, "PR moved before the fast-forward")
    # GitHub compares the old main SHA atomically and refuses non-fast-forwards.
    command("gh", "api", "graphql", "-f", f"query={UPDATE_MAIN}",
            "-f", f"repository={repo['node_id']}", "-f", f"base={candidate.base}",
            "-f", f"head={candidate.head}", app=True)
    main = api(f"{endpoint}/git/ref/heads/main")["object"]["sha"]
    if main != candidate.head:
        raise OperationFailed("fast-forward response did not match main readback")
    print(f"Fast-forwarded main to {candidate.head} from PR #{candidate.number}.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--check-installation", action="store_true")
    args = parser.parse_args()
    try:
        event_name = os.environ["GITHUB_EVENT_NAME"]
        if os.environ["GITHUB_REPOSITORY"] != REPOSITORY or os.environ["GITHUB_REF"] != "refs/heads/main":
            raise OperationFailed("workflow must run from main in the owning repository")
        if args.check_installation:
            if event_name != "workflow_dispatch":
                raise OperationFailed("installation check requires manual dispatch")
            install = api("installation/repositories", app=True)
            if install["total_count"] != 1 or [repo["full_name"] for repo in install["repositories"]] != [REPOSITORY]:
                raise OperationFailed("installation token scope did not match this repository")
            print("GitHub App installation token can access only this repository.")
            return 0
        if event_name != "workflow_run":
            raise OperationFailed("fast-forward requires a workflow completion event")
        endpoint = f"repos/{REPOSITORY}"
        repo = api(endpoint)
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        candidate = evaluate(repo, endpoint, event["workflow_run"])
        if args.apply:
            fast_forward(repo, endpoint, candidate)
        else:
            with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
                print("eligible=true", file=output)
            print(f"PR #{candidate.number} passed the fast-forward checks.")
    except Ineligible as exc:
        print(f"Fast-forward skipped: {exc}.")
    except (OperationFailed, OSError, KeyError, IndexError, TypeError, ValueError,
            subprocess.TimeoutExpired) as exc:
        detail = str(exc) if isinstance(exc, OperationFailed) else type(exc).__name__
        print(f"Fast-forward check failed: {detail}.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
