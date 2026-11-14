"""No-network fixtures for the exact-commit candidate-run reuse consumer.

Every GitHub API call is answered by an in-memory fake; the artifact download
and the local commit identity are patched seams, and the runtime digest is
stubbed to a fixture value. No fixture touches the network or a real token.
"""
from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.validation import ci_reuse as R
from tools.validation.ci_policy import CI_LANES

COMMIT = "a" * 40
CURRENT_RUN = "9001"
FIXTURE_DIGEST = "b" * 64
FULL_JOB_NAMES = sorted(R.REQUIRED_JOB_NAMES)
assert len(FULL_JOB_NAMES) == len(CI_LANES) + 4


def run_entry(run_id, *, event="push", status="completed", conclusion="success",
              head_sha=COMMIT, path=R.CANDIDATE_WORKFLOW):
    return {"id": run_id, "name": "Candidate CI", "event": event,
            "status": status, "conclusion": conclusion, "head_sha": head_sha,
            "path": path, "html_url": f"https://example/runs/{run_id}",
            "created_at": "2026-11-14T00:00:00Z"}


def jobs_page(conclusions):
    return {"total_count": len(conclusions),
            "jobs": [{"name": name, "conclusion": result}
                     for name, result in conclusions.items()]}


def successful_full_jobs():
    return {name: "success" for name in FULL_JOB_NAMES}


def reuse_run_jobs():
    # A run that itself consumed an earlier reuse: lanes skipped, gates passed.
    jobs = successful_full_jobs()
    for name in FULL_JOB_NAMES:
        if name not in ("Classify candidate bytes",
                        "Identity, repository, privacy, lint, and compile",
                        "Candidate CI required"):
            jobs[name] = "skipped"
    return jobs


class FakeAPI:
    """In-memory GitHub Actions API keyed by request path prefix."""

    def __init__(self, runs, jobs_by_run, artifacts_by_run=None):
        self.runs = runs
        self.jobs_by_run = jobs_by_run
        self.artifacts_by_run = artifacts_by_run or {}
        self.calls: list[str] = []

    def api(self, path, timeout=60.0):
        self.calls.append(path)
        if path.startswith("repos/o/r/actions/runs?head_sha="):
            return json.dumps({"total_count": len(self.runs),
                               "workflow_runs": self.runs}).encode()
        if "/jobs?per_page=" in path:
            run_id = path.split("/runs/")[1].split("/jobs")[0]
            return json.dumps(self.jobs_by_run[run_id]).encode()
        if "/artifacts?per_page=" in path:
            run_id = path.split("/runs/")[1].split("/artifacts")[0]
            return json.dumps({"total_count": len(self.artifacts_by_run.get(run_id, [])),
                               "artifacts": self.artifacts_by_run.get(run_id, [])}).encode()
        raise AssertionError("unexpected API path: " + path)


def candidate_zip(receipt):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zipped:
        zipped.writestr("artifact.json", json.dumps(receipt))
        zipped.writestr("context-guard-0.17.3.zip", b"PK fake bytes")
    return buffer.getvalue()


class ReuseCase(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._temp.name)
        self.source_root = self.tmp / "source"
        self.source_root.mkdir()
        self.receipt_path = self.tmp / "evidence.json"
        self.digest = FIXTURE_DIGEST

    def tearDown(self):
        self._temp.cleanup()

    def evaluate(self, api, commit=COMMIT, current_run=CURRENT_RUN, repo="o/r"):
        R._gh_api = api.api
        R._gh_download = self._download
        R._local_commit = lambda root, timeout=30.0: commit
        original_digest = R.runtime_tree_digest
        R.runtime_tree_digest = lambda root: self.digest
        try:
            return R.evaluate(repo, commit, current_run, R.CANDIDATE_WORKFLOW,
                              self.source_root)
        finally:
            R._gh_api = self._original(R, "_gh_api")
            R._gh_download = self._original(R, "_gh_download")
            R._local_commit = self._original(R, "_local_commit")
            R.runtime_tree_digest = original_digest

    def _original(self, target, name):
        # The evaluate() call restored its own runtime digest patch; the other
        # seams are class-level assignments that this helper just clears.
        return getattr(target, name)

    def _download(self, path, target, timeout=60.0):
        if self.download_body is None:
            raise R.ReuseError("download failed")
        target.write_bytes(self.download_body)

    download_body = None


class TestConfirm(ReuseCase):
    def test_confirmed_without_escrow_artifact(self):
        api = FakeAPI([run_entry("42")], {"42": jobs_page(successful_full_jobs())})
        result = self.evaluate(api)
        self.assertEqual(result["verdict"], "confirmed")
        self.assertEqual(result["prior_run"]["id"], "42")
        self.assertEqual(result["artifact"], {"status": "absent"})
        self.assertEqual(result["jobs"]["Candidate CI required"], "success")

    def test_reuse_run_is_skipped_and_genuine_full_run_is_cited(self):
        api = FakeAPI([run_entry("77"), run_entry("42")],
                      {"77": jobs_page(reuse_run_jobs()),
                       "42": jobs_page(successful_full_jobs())})
        result = self.evaluate(api)
        self.assertEqual(result["verdict"], "confirmed")
        self.assertEqual(result["prior_run"]["id"], "42")
        refusals = [entry["refusal"] for entry in result["checked"]]
        self.assertEqual(refusals[0], "not_a_genuine_full_run")

    def test_confirmed_with_matching_escrow_artifact(self):
        receipt = {"schema": "cg-candidate-artifact/v1", "source_commit": COMMIT,
                   "runtime_tree_sha256": FIXTURE_DIGEST, "sha256": "c" * 64,
                   "size_bytes": 928085, "file_count": 107}
        self.download_body = candidate_zip(receipt)
        api = FakeAPI([run_entry("42")], {"42": jobs_page(successful_full_jobs())},
                      {"42": [{"id": 555, "name": R.CANDIDATE_ARTIFACT_PREFIX + COMMIT,
                               "size_in_bytes": 928085}]})
        result = self.evaluate(api)
        self.assertEqual(result["verdict"], "confirmed")
        self.assertEqual(result["artifact"]["status"], "checked")
        self.assertEqual(result["artifact"]["source_commit"], COMMIT)
        self.assertEqual(result["artifact"]["file_count"], 107)


class TestDeny(ReuseCase):
    def test_no_prior_run_denies(self):
        api = FakeAPI([], {})
        result = self.evaluate(api)
        self.assertEqual(result["verdict"], "denied")
        self.assertIn("no completed full-profile", result["reason"])

    def test_in_progress_or_unrelated_runs_are_not_candidates(self):
        runs = [run_entry("11", status="in_progress", conclusion=None),
                run_entry("12", conclusion="failure"),
                run_entry("13", event="pull_request"),
                run_entry("14", head_sha="f" * 40),
                run_entry("15", path=".github/workflows/other.yml")]
        api = FakeAPI(runs, {})
        result = self.evaluate(api)
        self.assertEqual(result["verdict"], "denied")
        self.assertEqual(result["checked"], [])

    def test_missing_or_skipped_lanes_are_never_a_genuine_full_run(self):
        partial = {name: "success" for name in FULL_JOB_NAMES[:8]}
        api = FakeAPI([run_entry("21")], {"21": jobs_page(partial)})
        result = self.evaluate(api)
        self.assertEqual(result["verdict"], "denied")
        self.assertIn("no completed full-profile", result["reason"])

    def test_failed_lane_on_this_exact_commit_denies_without_shopping(self):
        jobs = successful_full_jobs()
        jobs["macOS / Python 3.11"] = "failure"
        api = FakeAPI([run_entry("31"), run_entry("32")],
                      {"31": jobs_page(jobs),
                       "32": jobs_page(successful_full_jobs())})
        result = self.evaluate(api)
        self.assertEqual(result["verdict"], "denied")
        self.assertIn("prior_full_run_has_failed_jobs", result["reason"])
        self.assertEqual(result["prior_run"]["id"], "31")

    def test_mismatched_artifact_receipt_denies(self):
        receipt = {"schema": "cg-candidate-artifact/v1", "source_commit": "e" * 40,
                   "runtime_tree_sha256": FIXTURE_DIGEST, "sha256": "c" * 64,
                   "size_bytes": 1, "file_count": 1}
        self.download_body = candidate_zip(receipt)
        api = FakeAPI([run_entry("42")], {"42": jobs_page(successful_full_jobs())},
                      {"42": [{"id": 555, "name": R.CANDIDATE_ARTIFACT_PREFIX + COMMIT,
                               "size_in_bytes": 100}]})
        result = self.evaluate(api)
        self.assertEqual(result["verdict"], "denied")
        self.assertIn("different source commit", result["reason"])

    def test_runtime_digest_drift_between_artifact_and_checkout_denies(self):
        receipt = {"schema": "cg-candidate-artifact/v1", "source_commit": COMMIT,
                   "runtime_tree_sha256": "d" * 64, "sha256": "c" * 64,
                   "size_bytes": 1, "file_count": 1}
        self.download_body = candidate_zip(receipt)
        api = FakeAPI([run_entry("42")], {"42": jobs_page(successful_full_jobs())},
                      {"42": [{"id": 555, "name": R.CANDIDATE_ARTIFACT_PREFIX + COMMIT,
                               "size_in_bytes": 100}]})
        result = self.evaluate(api)
        self.assertEqual(result["verdict"], "denied")
        self.assertIn("runtime digest differs", result["reason"])

    def test_unexpected_non_required_job_result_denies(self):
        jobs = successful_full_jobs()
        jobs["Manifest-exact candidate artifact"] = "failure"
        api = FakeAPI([run_entry("42")], {"42": jobs_page(jobs)})
        result = self.evaluate(api)
        self.assertEqual(result["verdict"], "denied")
        self.assertIn("unexpected_job_results", result["reason"])

    def test_refused_inputs_and_failures_answer_denied(self):
        for repo, commit, run in (("bad", COMMIT, CURRENT_RUN),
                                  ("o/r", "abc123", CURRENT_RUN),
                                  ("o/r", COMMIT, "x")):
            with self.subTest(repo=repo, commit=commit, run=run):
                with self.assertRaises(R.ReuseError):
                    R.evaluate(repo, commit, run, R.CANDIDATE_WORKFLOW,
                               self.source_root)


class TestReceipt(unittest.TestCase):
    def test_main_writes_exclusive_receipt_with_exit_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence.json"
            api = FakeAPI([run_entry("42")], {"42": jobs_page(successful_full_jobs())})
            original = (R._gh_api, R._gh_download, R._local_commit,
                        R.runtime_tree_digest)
            R._gh_api = api.api
            R._gh_download = lambda path, target, timeout=60.0: None
            R._local_commit = lambda root, timeout=30.0: COMMIT
            R.runtime_tree_digest = lambda root: FIXTURE_DIGEST
            try:
                self.assertEqual(R.main(["--repo", "o/r", "--commit", COMMIT,
                                         "--current-run", CURRENT_RUN,
                                         "--source-root", str(Path(temporary)),
                                         "--output", str(output)]), 0)
                confirmed = json.loads(output.read_text())
                self.assertEqual(confirmed["schema"], R.SCHEMA)
                self.assertEqual(confirmed["verdict"], "confirmed")
                self.assertEqual(confirmed["prior_run"]["id"], "42")
                # Existing receipts are never replaced; a verdict without its
                # own receipt refuses loudly instead of passing bare.
                self.assertEqual(R.main(["--repo", "o/r", "--commit", COMMIT,
                                         "--current-run", CURRENT_RUN,
                                         "--source-root", str(Path(temporary)),
                                         "--output", str(output)]), 2)
            finally:
                (R._gh_api, R._gh_download, R._local_commit,
                 R.runtime_tree_digest) = original

    def test_api_failure_still_writes_a_denied_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence.json"
            original = (R._gh_api, R._local_commit)
            R._gh_api = lambda path, timeout=60.0: (
                (_ for _ in ()).throw(R.ReuseError("gh api failed")))
            R._local_commit = lambda root, timeout=30.0: COMMIT
            try:
                self.assertEqual(R.main(["--repo", "o/r", "--commit", COMMIT,
                                         "--current-run", CURRENT_RUN,
                                         "--source-root", str(Path(temporary)),
                                         "--output", str(output)]), 3)
            finally:
                (R._gh_api, R._local_commit) = original
            denied = json.loads(output.read_text())
            self.assertEqual(denied["verdict"], "denied")
            self.assertIn("gh api failed", denied["reason"])


if __name__ == "__main__":
    unittest.main()
