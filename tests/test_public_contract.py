#!/usr/bin/env python3
"""Regression tests for the standalone public repository contract."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = load("audit_public_tree", ROOT / "scripts" / "audit_public_tree.py")
contract = load("validate_public_repo", ROOT / "scripts" / "validate_public_repo.py")
identity = load(
    "audit_commit_identity", ROOT / "scripts" / "audit_commit_identity.py"
)


class PublicContractTests(unittest.TestCase):
    def test_repository_contract(self) -> None:
        self.assertEqual(contract.validate(ROOT), [])

    def test_public_tree_has_no_private_material(self) -> None:
        self.assertEqual(audit.findings(ROOT), [])

    def test_plugin_package_excludes_clone_and_worktree_git_metadata(self) -> None:
        patterns = {
            line.strip()
            for line in (ROOT / ".codexignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertTrue({".git", ".git/"}.issubset(patterns))

    def test_audit_detects_private_material_and_generated_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "leak.txt").write_text(
                "private path: " + "/Users" + "/example/secret\n", encoding="utf-8"
            )
            (root / ".DS_Store").write_text("generated\n", encoding="utf-8")
            issues = audit.findings(root)
            self.assertTrue(any("macOS user-specific path" in item for item in issues))
            self.assertTrue(any("generated/private" in item for item in issues))

    def test_readmes_keep_bilingual_diagram_and_example_parity(self) -> None:
        english = (ROOT / "README.md").read_text(encoding="utf-8")
        chinese = (ROOT / "README.zh-CN.md").read_text(encoding="utf-8")

        self.assertIn("```mermaid\nflowchart TB", english)
        self.assertIn("```mermaid\nflowchart TB", chinese)
        self.assertIn(
            "## Everyday example: refactor code without breaking callers", english
        )
        self.assertIn("## 日常示例：重构代码，但不能破坏现有调用方", chinese)
        for term in ("submit_order(payload)", "normalize_phone()"):
            self.assertIn(term, english)
            self.assertIn(term, chinese)

        self.assertIn("## Observed token overhead", english)
        self.assertIn("about 1%–2%", english)
        self.assertIn("## 实测 token 开销", chinese)
        self.assertIn("约 1%–2%", chinese)
        self.assertIn(
            "> Release status: `0.6.1` is the current release.", english
        )
        self.assertIn("> 发布状态：`0.6.1` 是当前正式版本；", chinese)
        self.assertIn("`0.6.3` is an unreleased", english)
        self.assertIn("`0.6.3` 是尚未发布的单向安全候选", chinese)
        self.assertIn("Stop protocol 1.1.0", english)
        self.assertIn("Stop protocol 1.1.0", chinese)
        self.assertIn("advisory only and cannot force a new turn", english)
        self.assertIn("仅作为提示，不能强制开启新一轮", chinese)

        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        compatibility = (ROOT / "docs" / "COMPATIBILITY.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("## 0.6.1 - 2026-08-11", changelog)
        self.assertIn("Version 0.6.3", changelog)
        self.assertIn("Current Context Guard release: `0.6.1`", compatibility)
        self.assertIn("Current source candidate: `0.6.3`", compatibility)
        for stale in (
            "`0.6.1` is an unreleased candidate",
            "`0.6.1` 是未发布候选",
            "final CI/HOL/PR gates remain pending",
            "最终 CI、HOL、PR 门仍为 pending",
        ):
            self.assertNotIn(stale, english + chinese + changelog + compatibility)

        architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("```mermaid\nsequenceDiagram", architecture)


class CommitIdentityTests(unittest.TestCase):
    def git(self, root: Path, *arguments: str, env: dict[str, str] | None = None) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
        return result.stdout.strip()

    def commit(
        self,
        root: Path,
        filename: str,
        author_email: str,
        committer_email: str,
    ) -> str:
        (root / filename).write_text(filename, encoding="utf-8")
        self.git(root, "add", filename)
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_NAME": "Example Author",
                "GIT_AUTHOR_EMAIL": author_email,
                "GIT_COMMITTER_NAME": "Example Committer",
                "GIT_COMMITTER_EMAIL": committer_email,
            }
        )
        self.git(root, "commit", "-m", filename, env=environment)
        return self.git(root, "rev-parse", "HEAD")

    def repository(self, root: Path) -> None:
        self.git(root, "init", "-q")

    def test_accepts_github_user_bot_and_service_noreply_forms(self) -> None:
        accepted = (
            "123456+example-user@users.noreply.github.com",
            "example-user@users.noreply.github.com",
            "123456+example-bot[bot]@users.noreply.github.com",
            "noreply@github.com",
        )
        for email in accepted:
            with self.subTest(email=email):
                self.assertIsNotNone(identity.NOREPLY_EMAIL_RE.fullmatch(email))

    def test_rejects_non_github_noreply_domains(self) -> None:
        rejected = (
            "example@example.com",
            "noreply@example.com",
            "example@users.noreply.github.test",
        )
        for email in rejected:
            with self.subTest(email=email):
                self.assertIsNone(identity.NOREPLY_EMAIL_RE.fullmatch(email))

    def test_range_excludes_the_base_commit_and_checks_both_roles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository(root)
            base = self.commit(
                root,
                "base.txt",
                "old-author@example.com",
                "old-committer@example.com",
            )
            accepted = "example-user@users.noreply.github.com"
            author_bad = self.commit(
                root, "author.txt", "author@example.com", accepted
            )
            committer_bad = self.commit(
                root, "committer.txt", accepted, "committer@example.com"
            )

            commits = identity.candidate_commits(root, base, committer_bad)
            self.assertEqual(commits, [author_bad, committer_bad])
            self.assertEqual(
                identity.violations(root, commits),
                [(author_bad, ("author",)), (committer_bad, ("committer",))],
            )

    def test_zero_base_checks_only_the_resolved_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository(root)
            self.commit(
                root,
                "historical.txt",
                "historical@example.com",
                "historical@example.com",
            )
            accepted = "123456+example-user@users.noreply.github.com"
            head = self.commit(root, "head.txt", accepted, accepted)

            commits = identity.candidate_commits(root, "0" * 40, head)
            self.assertEqual(commits, [head])
            self.assertEqual(identity.violations(root, commits), [])

    def test_cli_redacts_invalid_email_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository(root)
            invalid = "private-person@example.com"
            head = self.commit(root, "candidate.txt", invalid, invalid)
            stderr = io.StringIO()
            argv = [
                "audit_commit_identity.py",
                str(root),
                "--head",
                head,
            ]
            with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(
                stderr
            ):
                result = identity.main()

            output = stderr.getvalue()
            self.assertEqual(result, 1)
            self.assertNotIn(invalid, output)
            self.assertIn(head[:12], output)
            self.assertIn("invalid author, committer identity", output)
            self.assertIn("Identity values are redacted", output)


if __name__ == "__main__":
    unittest.main()
