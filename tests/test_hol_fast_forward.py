"""Exercise patch scope, exact check evidence, and the main ref update."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.validation import hol_fast_forward as hol

BASE, HEAD, MERGE = "a" * 40, "b" * 40, "c" * 40
REPO = {"id": 137, "full_name": hol.REPOSITORY, "node_id": "R_fixture"}
ENDPOINT = f"repos/{hol.REPOSITORY}"
BRANCH = hol.BRANCH_PREFIX + "1.2.817"
CANDIDATE = hol.Candidate(36, HEAD, BRANCH, BASE, MERGE)


def workflow(sha: str, version: str) -> bytes:
    return (f"      - id: scanner\n        uses: {hol.UPSTREAM_ACTION}@{sha} # v{version}\n"
            "        with:\n          min_score: 80\n").encode()


def pull():
    return {
        "number": 36, "state": "open", "draft": False, "commits": 1, "mergeable": True,
        "merge_commit_sha": MERGE,
        "user": {"id": hol.DEPENDABOT_ID, "login": "dependabot[bot]", "type": "Bot"},
        "base": {"repo": {"id": REPO["id"]}, "ref": "main", "sha": BASE},
        "head": {"repo": {"id": REPO["id"]}, "ref": BRANCH, "sha": HEAD},
    }


def check_data():
    result = {}
    for run_id, (filename, job) in enumerate(hol.CHECKS, 1):
        runs_path = f"{ENDPOINT}/actions/workflows/{filename}/runs?event=pull_request&head_sha={HEAD}&per_page=1"
        result[runs_path] = {"workflow_runs": [{
            "id": run_id, "run_attempt": 2, "event": "pull_request",
            "path": f".github/workflows/{filename}", "head_sha": HEAD, "head_branch": BRANCH,
            "head_repository": {"id": REPO["id"]}, "status": "completed", "conclusion": "success",
        }]}
        result[f"{ENDPOINT}/actions/runs/{run_id}/attempts/2/jobs?per_page=100"] = {
            "jobs": [{"name": job, "conclusion": "success"}]
        }
    result[f"{ENDPOINT}/actions/runs/2/artifacts?per_page=100"] = {
        "artifacts": [{"name": f"hol-scan-evidence-{MERGE}", "expired": False}]
    }
    return result


class ScopeTests(unittest.TestCase):
    def test_admits_only_forward_patch_pin(self):
        self.assertEqual(hol.changed_pin(workflow(BASE, "1.2.816"), workflow(HEAD, "1.2.817")),
                         ("1.2.817", HEAD))
        for version, sha in (("2.2.817", HEAD), ("1.3.0", HEAD), ("1.2.815", HEAD),
                             ("1.2.817", BASE), ("1.2.817", HEAD[:12]), ("1.2.817-rc.1", HEAD)):
            with self.subTest(version=version, sha=sha), self.assertRaises(hol.Ineligible):
                hol.changed_pin(workflow(BASE, "1.2.816"), workflow(sha, version))

    def test_rejects_other_workflow_changes_and_duplicate_pins(self):
        before, after = workflow(BASE, "1.2.816"), workflow(HEAD, "1.2.817")
        for changed in (after.replace(b"80", b"70"), after + after,
                        after.replace(hol.UPSTREAM_ACTION.encode(), b"other/scanner")):
            with self.subTest(changed=changed), self.assertRaises(hol.Ineligible):
                hol.changed_pin(before, changed)

    def test_rejects_fork_human_draft_stale_or_multi_commit_pr(self):
        self.assertEqual(hol.candidate_from_pr(REPO, pull(), BRANCH, HEAD, BASE), CANDIDATE)
        changed = [
            {"user": {"id": 42, "login": "dependabot[bot]", "type": "Bot"}},
            {"head": {**pull()["head"], "repo": {"id": 99}}},
            {"head": {**pull()["head"], "sha": MERGE}},
            {"base": {**pull()["base"], "sha": MERGE}},
            {"commits": 2}, {"state": "closed"}, {"draft": True}, {"mergeable": None},
        ]
        for fields in changed:
            with self.subTest(fields=fields), self.assertRaises(hol.Ineligible):
                hol.candidate_from_pr(REPO, {**pull(), **fields}, BRANCH, HEAD, BASE)


class EvidenceTests(unittest.TestCase):
    def test_rejects_stale_workflow_checkout_before_fetching_pr(self):
        event = {"head_branch": BRANCH, "head_sha": HEAD, "event": "pull_request",
                 "conclusion": "success", "head_repository": {"id": REPO["id"]}}
        with (patch.dict("os.environ", {"GITHUB_SHA": BASE}),
              patch.object(hol, "api", side_effect=[[pull()], pull(), {"object": {"sha": BASE}}]),
              patch.object(hol, "command", return_value=MERGE.encode()) as command,
              self.assertRaisesRegex(hol.Ineligible, "main advanced")):
            hol.evaluate(REPO, ENDPOINT, event)
        command.assert_called_once_with("git", "rev-parse", "HEAD")

    def test_both_exact_workflows_pass_current_attempt_jobs_and_hol_artifact(self):
        with patch.object(hol, "api", side_effect=check_data().__getitem__):
            hol.verify_checks(CANDIDATE, ENDPOINT, REPO["id"])

    def test_fails_closed_on_stale_or_failed_run_wrong_job_or_wrong_hol_merge(self):
        for case in ("in_progress", "failure", "wrong_head", "wrong_path", "skip_job", "old_merge", "expired"):
            data = check_data()
            pr_run = next(iter(data.values()))["workflow_runs"][0]
            hol_artifact = data[f"{ENDPOINT}/actions/runs/2/artifacts?per_page=100"]["artifacts"][0]
            if case == "in_progress":
                pr_run.update(status="in_progress", conclusion=None)
            elif case == "failure":
                pr_run["conclusion"] = "failure"
            elif case == "wrong_head":
                pr_run["head_sha"] = BASE
            elif case == "wrong_path":
                pr_run["path"] = ".github/workflows/similar-name.yml"
            elif case == "skip_job":
                data[f"{ENDPOINT}/actions/runs/1/attempts/2/jobs?per_page=100"]["jobs"][0]["conclusion"] = "skipped"
            elif case == "old_merge":
                hol_artifact["name"] = f"hol-scan-evidence-{BASE}"
            else:
                hol_artifact["expired"] = True
            with (self.subTest(case=case), patch.object(hol, "api", side_effect=data.__getitem__),
                  self.assertRaises(hol.Ineligible)):
                hol.verify_checks(CANDIDATE, ENDPOINT, REPO["id"])

    def test_recheck_blocks_mutation_when_pr_head_changes(self):
        current = pull()
        current["head"]["sha"] = MERGE
        with (patch.object(hol, "api", return_value=current), patch.object(hol, "command") as command,
              self.assertRaises(hol.Ineligible)):
            hol.fast_forward(REPO, ENDPOINT, CANDIDATE)
        command.assert_not_called()

    def test_ref_mutation_has_atomic_base_and_forbids_force(self):
        with (patch.object(hol, "api", side_effect=[pull(), {"object": {"sha": HEAD}}]),
              patch.object(hol, "command") as command):
            hol.fast_forward(REPO, ENDPOINT, CANDIDATE)
        call = command.call_args
        self.assertEqual(call.kwargs, {"app": True})
        self.assertIn(f"base={BASE}", call.args)
        self.assertIn(f"head={HEAD}", call.args)
        self.assertIn('name: "refs/heads/main", beforeOid: $base, afterOid: $head, force: false', call.args[4])


if __name__ == "__main__":
    unittest.main()
