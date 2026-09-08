"""Windows R5 authorization ref-target grammar and Git branch regressions."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cg_actions  # noqa: E402
import context_guard as cg  # noqa: E402


class AuthorizationRefHintTests(unittest.TestCase):
    def _binding(
        self, statement: str, *, current_branch: str = "feature/current"
    ) -> tuple[dict[str, object], dict[str, object]]:
        parsed = cg.parse_authorization_statement(statement)
        self.assertIsNotNone(parsed, statement)
        assert parsed is not None
        targets = cg._authorization_snapshot_targets(
            parsed["actions"],
            parsed["hints"],
            self._resolved(current_branch),
        )
        binding = cg._authority_module().bind_authorization(
            parsed["actions"],
            targets,
            work_unit_id="WU-R5",
            generation=1,
        )
        return parsed, binding

    def test_explicit_remote_ref_forms_bind_both_dimensions(self) -> None:
        rows = (
            ("push to origin main", ["origin"], ["main"]),
            ("请明确推送到 origin 的 main 分支", ["origin"], ["main"]),
            (
                "push to origin HEAD:refs/heads/main",
                ["origin"],
                ["main"],
            ),
            (
                "push to origin codex/0.12.2-stabilization",
                ["origin"],
                ["codex/0.12.2-stabilization"],
            ),
        )
        for statement, remotes, refs in rows:
            with self.subTest(statement=statement):
                parsed = cg.parse_authorization_statement(statement)
                self.assertEqual(parsed["actions"], ["push"])
                self.assertEqual(parsed["hints"]["remotes"], remotes)
                self.assertEqual(parsed["hints"]["refs"], refs)

    def test_multiple_explicit_targets_remain_ambiguous(self) -> None:
        parsed = cg.parse_authorization_statement(
            "push to origin main and upstream other"
        )
        self.assertEqual(parsed["actions"], ["push"])
        self.assertEqual(parsed["hints"]["remotes"], ["origin", "upstream"])
        self.assertEqual(parsed["hints"]["refs"], ["main", "other"])
        targets = cg._authorization_snapshot_targets(
            parsed["actions"], parsed["hints"], self._resolved("feature/current")
        )
        self.assertEqual(len(targets), 4)
        self.assertEqual({target["ref"] for target in targets}, {"main", "other"})

    def test_position_aware_branch_grammar_binds_the_exact_target(self) -> None:
        rows = (
            ("push to origin main", "origin", "main"),
            ("push main to origin", "origin", "main"),
            ("push to origin branch main", "origin", "main"),
            ("push to origin branches main", "origin", "main"),
            ("push branch main to origin", "origin", "main"),
            ("push branches main to origin", "origin", "main"),
            ("push to origin main branch", "origin", "main"),
            ("push to origin main branches", "origin", "main"),
            ("push main branch to origin", "origin", "main"),
            ("push main branches to origin", "origin", "main"),
            ("请推送到 origin 的 main 分支", "origin", "main"),
            ("请推送到 origin 的分支 main", "origin", "main"),
            ("请推送 main 分支到 origin", "origin", "main"),
            ("请推送分支 main 到 origin", "origin", "main"),
            (
                "push to origin HEAD:refs/heads/main",
                "origin",
                "main",
            ),
            (
                "push to origin branch release/topic",
                "origin",
                "release/topic",
            ),
        )
        for statement, remote, ref in rows:
            with self.subTest(statement=statement):
                _parsed, binding = self._binding(statement)
                self.assertEqual(binding["status"], "authorized_unique")
                self.assertEqual(binding["target"]["remote"], remote)
                self.assertEqual(binding["target"]["ref"], ref)

    def test_remote_and_ref_names_are_owned_by_syntax_position(self) -> None:
        rows = (
            ("push to origin branch origin", "origin", "origin"),
            ("push origin branch to upstream", "upstream", "origin"),
            ("push to upstream branch branch", "upstream", "branch"),
            ("push to origin refs/heads/upstream", "origin", "upstream"),
        )
        for statement, remote, ref in rows:
            with self.subTest(statement=statement):
                parsed, binding = self._binding(statement)
                self.assertEqual(parsed["hints"]["remotes"], [remote])
                self.assertEqual(parsed["hints"]["refs"], [ref])
                self.assertEqual(binding["status"], "authorized_unique")
                self.assertEqual(binding["target"]["remote"], remote)
                self.assertEqual(binding["target"]["ref"], ref)

    def test_invalid_or_incomplete_explicit_ref_never_falls_back(self) -> None:
        rows = (
            "push to origin branch",
            "push branch to origin",
            "push to origin branch ../main",
            "push branch feature..bad to origin",
            "请推送到 origin 的分支",
            "请推送分支到 origin",
        )
        for statement in rows:
            with self.subTest(statement=statement):
                parsed, binding = self._binding(statement)
                self.assertNotIn("refs", parsed["hints"])
                self.assertEqual(binding["status"], "requires_selection")
                self.assertIsNone(binding["target"])

    def test_multiple_positioned_ref_targets_require_selection(self) -> None:
        rows = (
            "push to origin branch main and to upstream branch other",
            "push branch main to origin and branch other to upstream",
            "push to origin branch main and branch other",
            "push to origin main branch and other branch",
            "请推送 main 分支到 origin 和 other 分支到 upstream",
            "请推送到 origin 的 main 分支和 other 分支",
        )
        for statement in rows:
            with self.subTest(statement=statement):
                parsed, binding = self._binding(statement)
                self.assertEqual(set(parsed["hints"]["refs"]), {"main", "other"})
                self.assertEqual(binding["status"], "requires_selection")
                self.assertIsNone(binding["target"])

    def test_plain_push_without_explicit_ref_keeps_structured_fallback(self) -> None:
        _parsed, binding = self._binding("push to origin")
        self.assertEqual(binding["status"], "authorized_unique")
        self.assertEqual(binding["target"]["remote"], "origin")
        self.assertEqual(binding["target"]["ref"], "feature/current")

    def test_invalid_or_weak_tokens_never_become_ref_hints(self) -> None:
        statements = (
            "push to origin ../main",
            "push to origin feature..bad",
            "push to origin main.lock",
            "push to origin after tests",
        )
        for statement in statements:
            with self.subTest(statement=statement):
                parsed = cg.parse_authorization_statement(statement)
                self.assertEqual(parsed["actions"], ["push"])
                self.assertNotIn("refs", parsed["hints"])
                if "after tests" not in statement:
                    self.assertEqual(
                        cg._authorization_snapshot_targets(
                            parsed["actions"],
                            parsed["hints"],
                            self._resolved("feature/current"),
                        ),
                        [],
                    )

    def test_statement_ref_wins_over_different_current_branch(self) -> None:
        parsed = cg.parse_authorization_statement("push to origin main")
        targets = cg._authorization_snapshot_targets(
            parsed["actions"], parsed["hints"], self._resolved("feature/current")
        )
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["remote"], "origin")
        self.assertEqual(targets[0]["ref"], "main")

    @staticmethod
    def _resolved(branch: str) -> dict[str, object]:
        return {
            "repository": "repo:test",
            "ref": branch,
            "upstream_remote": "origin",
            "head_sha256": "a" * 40,
            "verified_commit": "a" * 40,
            "clean": True,
            "cwd": ".",
            "github_repo": None,
        }

    def test_negated_push_never_authorizes(self) -> None:
        self.assertIsNone(
            cg.parse_authorization_statement("do not push to origin main")
        )


class GitBranchValidationTests(unittest.TestCase):
    def test_bounded_git_branch_validator_is_mirrored(self) -> None:
        rows = (
            ("main", True),
            ("codex/0.12.2-stabilization", True),
            ("release/feature_one", True),
            ("", False),
            ("-main", False),
            ("HEAD", False),
            ("../main", False),
            ("feature..bad", False),
            ("feature@{bad", False),
            ("feature.lock", False),
            ("feature bad", False),
            ("feature:bad", False),
            ("feature\\bad", False),
        )
        for value, expected in rows:
            with self.subTest(value=value):
                self.assertEqual(
                    cg_actions._is_valid_git_branch_name(value), expected
                )
                self.assertEqual(cg._is_valid_git_branch_name(value), expected)

    def test_current_branch_accepts_slash_and_detached_head_stays_unknown(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.name", "Context Guard Tests")
            self._git(root, "config", "user.email", "tests@example.invalid")
            (root / "tracked.txt").write_text(
                "ready\n", encoding="utf-8", newline=""
            )
            self._git(root, "add", "tracked.txt")
            self._git(root, "commit", "-q", "-m", "base")
            self._git(root, "checkout", "-q", "-b", "codex/0.12.2-stabilization")
            for module in (cg_actions, cg):
                self.assertEqual(
                    module.current_branch(root),
                    "codex/0.12.2-stabilization",
                )
            self._git(root, "checkout", "-q", "--detach", "HEAD")
            for module in (cg_actions, cg):
                self.assertEqual(module.current_branch(root), "unknown")

    def _git(self, root: Path, *args: str) -> None:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
