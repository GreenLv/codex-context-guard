#!/usr/bin/env python3
"""Live-HEAD re-authorization regressions from the native direct-Git gate."""

from __future__ import annotations

from tests.test_cg122_p0_counterexamples import P0Harness, cg


class LivePushReauthorizationTests(P0Harness):
    def active_push_binding(self) -> dict:
        state = self.state()
        unit = self.unit(state, state["work_state"]["active_work_unit_id"])
        return next(
            record
            for record in reversed(unit.get("authorizations") or [])
            if record.get("state") == "active" and record.get("actions") == ["push"]
        )

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

        binding = self.active_push_binding()
        self.assertEqual(binding["context"]["head_sha256"], current)
        self.assertEqual(binding["expected_commits"]["push"], current)
        self.assertEqual(
            binding["binding"]["target"]["commit_sha256"], current
        )
        permission, reason = self.decision(
            "git push origin HEAD:refs/heads/main"
        )
        self.assertEqual((permission, reason), ("allow", ""))

    def test_statement_named_stale_sha_does_not_rebind_to_live_head(self) -> None:
        self.activate()
        stale, current = self.advance_head_outside_authorization()
        self.prompt(f"现在明确授权把当前候选提交 {stale} 推送到 origin/main。")

        binding = self.active_push_binding()
        self.assertEqual(binding["context"]["head_sha256"], current)
        self.assertEqual(binding["expected_commits"]["push"], stale)
        self.assertEqual(
            binding["binding"]["target"]["commit_sha256"], stale
        )
        permission, reason = self.decision(
            "git push origin HEAD:refs/heads/main"
        )
        self.assertEqual(permission, "deny")
        self.assertIn("target commit moved", reason.lower())

    def test_push_current_commit_without_sha_is_not_a_commit_action(self) -> None:
        self.activate()
        _old, current = self.advance_head_outside_authorization()
        self.prompt("授权把当前提交推送到 origin/main。")
        binding = self.active_push_binding()
        self.assertEqual(binding["actions"], ["push"])
        self.assertEqual(binding["expected_commits"]["push"], current)


if __name__ == "__main__":
    import unittest

    unittest.main()
