"""Live-HEAD re-authorization regressions from the native direct-Git gate.

0.13 layer transfer: the DEFAULT execution-approval gate was removed, so
the live re-authorization machinery this module verified — prompt-bound
authorization records carrying ``context.head_sha256`` /
``expected_commits.push`` / ``binding.target.commit_sha256``, live-HEAD
rebinding on resume, stale-SHA target-move denies — is no longer produced
or enforced. Each old failure family transfers to one of three layers,
asserted here: (a) executing-agent/host responsibility — whether the
pushed commit is the commit the user meant (live HEAD vs a named SHA) is
no longer a Guard question, so the same push wire is the plain allow with
NO authorization record, NO expected-commit plan, and no fabricated
evidence (INV-01/INV-02); (b) release-adapter exact contracts — an exact
commit identity can still be bound, but only behind an explicitly adopted
release contract (tested under explicit adoption elsewhere); (c)
preserved constraint recording asserted here — the re-authorization
statements (including the exact SHA they name) survive verbatim as
pending requirements, and pure statement parsing (candidate-commit noun
grammar) is unchanged product behavior.
"""

from __future__ import annotations

import json

from tests.test_cg122_p0_counterexamples import P0Harness, cg


class LivePushReauthorizationTests(P0Harness):
    def assert_no_authorization_records(self) -> None:
        state = self.state()
        rendered = json.dumps(state["work_units"], ensure_ascii=False)
        for unit in state["work_units"]:
            self.assertNotIn(
                "authorizations", unit,
                "0.13 must not fabricate authorization records from prompts",
            )
        self.assertNotIn("expected_commits", rendered)
        self.assertNotIn("commit_context", rendered)
        for item in state["requirements"]:
            self.assertEqual(item["status"], "pending")

    def advance_head_outside_authorization(self) -> tuple[str, str]:
        old = self.git_out("rev-parse", "HEAD")
        self.write("owned.txt", "v2\n")
        self.git("add", "owned.txt")
        self.git("commit", "-q", "-m", "current candidate")
        return old, self.git_out("rev-parse", "HEAD")

    def test_candidate_commit_noun_is_push_only(self) -> None:
        sha = "a" * 40
        parsed = cg.parse_authorization_statement(
            f"现在明确授权把当前候选提交 {sha} 推送到 origin/main。"
        )
        self.assertEqual(parsed["actions"], ["push"])
        self.assertEqual(parsed["hints"]["commits"], [sha])
        parsed_en = cg.parse_authorization_statement(
            f"Authorize push of the current candidate commit {sha} to origin main."
        )
        self.assertEqual(parsed_en["actions"], ["push"])
        self.assertEqual(parsed_en["hints"]["commits"], [sha])

    def test_commit_imperative_remains_commit_and_push(self) -> None:
        parsed = cg.parse_authorization_statement(
            "提交 `owned.txt` 并推送 origin 的 main 分支。"
        )
        self.assertEqual(parsed["actions"], ["push", "commit"])

    def test_resume_reauthorization_binds_live_head_and_allows_exact_push(self) -> None:
        """0.13 transfer: a resumed turn that re-states the exact candidate
        SHA no longer CREATES a binding — the statement is constraint
        recording, and the push is not a Guard decision. The transfer
        asserts: plain allow wire, no authorization/expected-commit record
        naming the live head, the statement preserved verbatim, and the
        live HEAD visible as ordinary Git fact."""
        self.activate()
        self.prompt("推送 origin 的 main 分支。")
        old, current = self.advance_head_outside_authorization()
        self.assertNotEqual(old, current)
        self.dispatch("SessionStart", source="resume")
        self.prompt(
            f"现在明确授权把当前候选提交 {current} 推送到 origin/main，"
            "执行唯一一个独立 Bash 工具调用："
            "`git push origin HEAD:refs/heads/main`。"
            "此授权明确取代先前负向阶段对该确切 main 操作的限制，"
            "不授权 other ref。"
        )

        # The live head is exactly what Git reports (host fact).
        self.assertEqual(self.git_out("rev-parse", "HEAD"), current)
        permission, reason = self.decision(
            "git push origin HEAD:refs/heads/main"
        )
        self.assertEqual((permission, reason), ("allow", ""))
        state = self.state()
        self.assertTrue(
            any(current in item["text"] for item in state["requirements"]),
            "the re-authorization statement with its exact SHA must survive",
        )
        # No fabricated binding anywhere: the sha appears in the recorded
        # requirement text only, never as an authorization fact.
        for unit in state["work_units"]:
            self.assertNotIn("authorizations", unit)
        self.assertNotIn("expected_commits", json.dumps(state["work_units"]))
        self.assert_requirements_all_pending()

    def test_statement_named_stale_sha_does_not_rebind_to_live_head(self) -> None:
        """0.13 transfer: a statement naming a stale SHA cannot bind to
        anything — there is no binding to move and no target-move deny.
        Detecting that the named commit is not HEAD is the executing
        agent's duty; the Guard records the statement verbatim and stays
        silent on the push wire."""
        self.activate()
        stale, current = self.advance_head_outside_authorization()
        self.prompt(f"现在明确授权把当前候选提交 {stale} 推送到 origin/main。")

        permission, reason = self.decision(
            "git push origin HEAD:refs/heads/main"
        )
        self.assertEqual((permission, reason), ("allow", ""))
        state = self.state()
        # The stale SHA survives only as recorded constraint text.
        self.assertTrue(
            any(stale in item["text"] for item in state["requirements"])
        )
        for unit in state["work_units"]:
            self.assertNotIn("authorizations", unit)
        rendered = json.dumps(state["work_units"], ensure_ascii=False)
        self.assertNotIn("expected_commits", rendered)
        self.assertNotIn(stale, rendered)
        self.assert_requirements_all_pending()

    def test_push_current_commit_without_sha_is_not_a_commit_action(self) -> None:
        """0.13 transfer: the pure statement grammar still reads "当前提交"
        as push (never a commit action), and the prompt produces no
        authorization record at all — the old expected-commit plan for the
        live head is gone with the provenance chain."""
        self.activate()
        _old, current = self.advance_head_outside_authorization()
        self.prompt("授权把当前提交推送到 origin/main。")
        parsed = cg.parse_authorization_statement("授权把当前提交推送到 origin/main。")
        self.assertEqual(parsed["actions"], ["push"])
        state = self.state()
        self.assertTrue(
            any("当前提交" in item["text"] for item in state["requirements"])
        )
        for unit in state["work_units"]:
            self.assertNotIn("authorizations", unit)
        self.assertNotIn(
            "expected_commits", json.dumps(state["work_units"], ensure_ascii=False)
        )
        # Nothing names the live head as an executable expectation.
        rendered = json.dumps(state["work_units"], ensure_ascii=False)
        self.assertNotIn(current, rendered)
        self.assert_requirements_all_pending()


if __name__ == "__main__":
    import unittest

    unittest.main()
