#!/usr/bin/env python3
"""Regression tests for the standalone public repository contract."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
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
            "## Everyday example: write a technical design document without losing decisions",
            english,
        )
        self.assertIn("## 日常示例：撰写技术方案，但不能漏掉已确认决策", chinese)
        for term in ("docs/design/checkout-v2.md", "RFC template"):
            self.assertIn(term, english)
        for term in ("docs/design/checkout-v2.md", "RFC 模板"):
            self.assertIn(term, chinese)

        self.assertIn("## Observed token overhead", english)
        self.assertIn("about 1%–2%", english)
        self.assertIn("## 实测 token 开销", chinese)
        self.assertIn("约 1%–2%", chinese)
        self.assertIn("## What you may see in a guarded task", english)
        self.assertIn("## 在受保护任务中可能看到什么", chinese)
        self.assertIn("## How 0.8.3 separates different sources", english)
        self.assertIn("## 0.8.3 如何区分不同来源", chinese)
        for term in ("selected Skills", "Codex Plan", "image", "public-readback"):
            self.assertIn(term, english)
        for term in ("已选择的 Skill", "Codex Plan", "图片", "公开读回"):
            self.assertIn(term, chinese)
        for readme in (english, chinese):
            for term in (
                "R001",
                "A003",
                "whole_completion_without_checkpoint",
                "[Context Guard continuation] The task is not yet safely complete.",
                "can't open file '.../context-guard/0.7.3/scripts/context_guard.py'",
            ):
                self.assertIn(term, readme)
        self.assertIn(
            "> Release status: `0.8.12` is the latest published release.",
            english,
        )
        self.assertIn(
            "> 发布状态：`0.8.12` 是最近一次已发布版本。",
            chinese,
        )
        self.assertIn("Stop protocol 2.0.0", english)
        self.assertIn("Stop protocol 2.0.0", chinese)
        self.assertIn("advisory only and cannot force a new turn", english)
        self.assertIn("它只是一个需要检查的信号，并不能单独证明存在 bug", chinese)
        self.assertIn("The message is normal when requested work is still open.", english)
        self.assertIn("context-guard diagnose", english)

        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        changelog_zh = (ROOT / "CHANGELOG.zh-CN.md").read_text(encoding="utf-8")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        compatibility = (ROOT / "docs" / "COMPATIBILITY.md").read_text(
            encoding="utf-8"
        )
        self.assertLess(
            changelog.index("### Highlights"), changelog.index("### Changes")
        )
        self.assertLess(
            changelog.index("### Changes"),
            changelog.index("### Validation"),
        )
        self.assertIn("Write for adopters, not as a commit transcript.", agents)
        self.assertIn("Derive the GitHub Release body", agents)
        self.assertIn(
            "the English section links only the\n  English changelog", agents
        )
        self.assertIn(
            "the Simplified Chinese section links only the Chinese\n  changelog",
            agents,
        )
        self.assertIn("Create and push an annotated `vX.Y.Z` tag", agents)
        self.assertIn("[简体中文](CHANGELOG.zh-CN.md)", changelog)
        self.assertIn("[English](CHANGELOG.md)", changelog_zh)
        self.assertIn("## How protection evolved", changelog)
        self.assertIn("## 各版本主要保护什么", changelog_zh)
        self.assertIn("**0.4.x — remember the user's task:**", changelog)
        self.assertIn(
            "**0.7.x — bind evidence to the thing being verified:**", changelog
        )
        self.assertIn(
            "**0.8.x — separate what user instructions, Skills, and the model plan may decide:**",
            changelog,
        )
        self.assertIn("**0.4.x——记住用户交代的任务：**", changelog_zh)
        self.assertIn(
            "**0.7.x——把证据绑定到需要验证的对象：**", changelog_zh
        )
        self.assertIn(
            "**0.8.x——分清用户要求、Skill 和模型计划各自能决定什么：**",
            changelog_zh,
        )
        english_line_order = [
            changelog.index(f"**0.{minor}.x") for minor in range(8, 3, -1)
        ]
        chinese_line_order = [
            changelog_zh.index(f"**0.{minor}.x") for minor in range(8, 3, -1)
        ]
        self.assertEqual(english_line_order, sorted(english_line_order))
        self.assertEqual(chinese_line_order, sorted(chinese_line_order))
        version_heading = re.compile(r"^## (0\.\d+\.\d+)(?:\s+-|$)", re.MULTILINE)
        self.assertEqual(
            version_heading.findall(changelog), version_heading.findall(changelog_zh)
        )
        self.assertIn("### 变更", changelog_zh)
        self.assertIn("### 验证", changelog_zh)
        self.assertNotIn("execution checklist", english + changelog)
        self.assertNotIn("执行清单", chinese + changelog_zh)
        self.assertIn("## 0.7.7 - 2026-08-18", changelog)
        self.assertIn("## 0.8.3 - 2026-08-24", changelog)
        self.assertIn("## 0.8.5 - 2026-08-25", changelog)
        self.assertIn("## 0.8.6 - 2026-08-25", changelog)
        self.assertIn("## 0.8.7 - 2026-08-25", changelog)
        self.assertIn("## 0.8.7 - 2026-08-25", changelog_zh)
        self.assertIn("## 0.8.8 - 2026-08-25", changelog)
        self.assertIn("## 0.8.8 - 2026-08-25", changelog_zh)
        self.assertIn("## 0.8.11 - 2026-08-27", changelog)
        self.assertIn("## 0.8.11 - 2026-08-27", changelog_zh)
        self.assertIn("## 0.8.12 - 2026-08-27", changelog)
        self.assertIn("## 0.8.12 - 2026-08-27", changelog_zh)
        self.assertIn("## 0.9.3 - Unreleased", changelog)
        self.assertIn("## 0.9.3 - Unreleased", changelog_zh)
        self.assertIn("## 0.7.6 - 2026-08-17", changelog)
        self.assertIn("## 0.7.3 - 2026-08-14", changelog)
        self.assertIn("0.7.4–0.7.6", changelog)
        self.assertIn("## 0.6.3 - 2026-08-12", changelog)
        self.assertIn("## 0.6.1 - 2026-08-11", changelog)
        self.assertIn("`0.6.0` introduced this line but was never released", changelog)
        self.assertIn(
            "Current published Context Guard release: `0.8.12`", compatibility
        )
        self.assertIn(
            "Current source line: `0.9.3` (`Unreleased` source candidate)", compatibility
        )
        self.assertIn("Proof protocol: `1.0.0`", compatibility)
        self.assertIn("Execution protocol: `1.0.0`", compatibility)
        self.assertIn("Diagnostic classifier: `2.3.2`", compatibility)
        self.assertIn("Stop protocol: `2.0.0`", compatibility)
        versioning = (ROOT / "docs" / "VERSIONING.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("`0.7.4` keeps schema 6", versioning)
        self.assertIn("`0.7.5` keeps the 0.7.4 protocol", versioning)
        self.assertIn("`0.7.6` keeps the 0.7.5 protocol", versioning)
        self.assertIn("`0.7.7` keeps schema 6", versioning)
        self.assertIn("`0.8.3` is the first completed Phase 3 release", versioning)
        self.assertIn("`0.8.5` corrects commit-addressed consumer upgrades", versioning)
        self.assertIn("`0.8.6` corrects the installed lifecycle smoke", versioning)
        self.assertIn("`0.8.7` is a cache-lifecycle preservation patch", versioning)
        self.assertIn("`0.8.8` selects a supported Hook interpreter", versioning)
        self.assertIn(
            "`0.8.9` is a consumed intermediate candidate",
            versioning,
        )
        self.assertIn(
            "`0.8.10` is a consumed intermediate candidate",
            versioning,
        )
        self.assertIn(
            "`0.8.11` is the 2026-08-27 Hook-lifecycle availability patch",
            versioning,
        )
        self.assertIn(
            "`0.8.12` is the 2026-08-27 compatible Stop-classifier patch",
            versioning,
        )
        self.assertIn(
            "`0.9.0` is a consumed intermediate candidate",
            versioning,
        )
        self.assertIn(
            "`0.9.1` is a consumed intermediate candidate",
            versioning,
        )
        self.assertIn(
            "`0.9.2` is a consumed intermediate protocol-authority candidate",
            versioning,
        )
        self.assertIn(
            "`0.9.3` keeps Stop protocol 2.0.0",
            versioning,
        )
        for stale in (
            "`0.6.1` is an unreleased candidate",
            "`0.6.1` 是未发布候选",
            "merged, natively accepted, untagged source line",
            "已合并、已完成原生验收但尚未打 tag",
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

    def test_non_ancestor_base_uses_new_head_first_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository(root)
            accepted = "123456+example-user@users.noreply.github.com"
            initial = self.commit(root, "initial.txt", accepted, accepted)
            old_history = self.commit(
                root,
                "old-history.txt",
                "private-author@example.com",
                "private-committer@example.com",
            )
            self.git(root, "checkout", "-q", "-b", "rewritten", initial)
            head = self.commit(root, "replacement.txt", accepted, accepted)

            commits = identity.candidate_commits(root, old_history, head)
            self.assertEqual(commits, [head])
            self.assertEqual(identity.violations(root, commits), [])

    def test_unavailable_force_push_base_uses_new_head_first_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository(root)
            accepted = "123456+example-user@users.noreply.github.com"
            self.commit(root, "initial.txt", accepted, accepted)
            head = self.commit(root, "replacement.txt", accepted, accepted)

            commits = identity.candidate_commits(root, "f" * 40, head)
            self.assertEqual(commits, [head])
            self.assertEqual(identity.violations(root, commits), [])

    def test_invalid_unavailable_base_does_not_use_force_push_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository(root)
            accepted = "123456+example-user@users.noreply.github.com"
            self.commit(root, "initial.txt", accepted, accepted)
            head = self.commit(root, "replacement.txt", accepted, accepted)

            with self.assertRaises(identity.GitInspectionError):
                identity.candidate_commits(root, "not-a-commit", head)

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
