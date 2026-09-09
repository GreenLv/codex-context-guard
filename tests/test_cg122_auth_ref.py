"""Windows R5 authorization ref-target grammar and Git branch regressions.

0.13 layer transfer: the DEFAULT execution-approval gate was removed, so
the resolution half of the old ref-target grammar —
``cg._authorization_snapshot_targets`` turning statement hints plus the
live repository snapshot into candidate targets, and the PreToolUse
enforcement consuming those bindings — is deleted from the product. Each
old failure family transfers to one of three layers, asserted here:
(a) the pure statement grammar (``cg.parse_authorization_statement``) is
UNCHANGED and still extracts ordered remote/ref hints, rejects invalid and
weak tokens, keeps negated clauses non-authorizing, and keeps multiple
targets as multiple candidates; (b) the retained pure binder
(``cg_authority.bind_authorization``, consumed by validators and
migration) still owns unique-vs-ambiguous selection over EXPLICIT
candidate facts — exercised here with explicit candidate dicts, because
resolving those facts from the live repository is no longer Guard work;
(c) the release-adapter exact contracts behind an explicitly adopted
release profile (tested under explicit adoption elsewhere); and
(d) preserved constraint recording — a ref-target statement in an active
standard session yields the plain allow wire, no fabricated authorization
record, and the statement survives verbatim as a pending requirement.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cg_actions  # noqa: E402
import cg_authority  # noqa: E402
import context_guard as cg  # noqa: E402


class AuthorizationRefHintTests(unittest.TestCase):
    def _candidate_targets(
        self, hints: dict[str, object], resolved: dict[str, object],
    ) -> list[dict[str, str]]:
        """Explicit candidate facts for the retained pure binder.

        This is TEST-side construction only: 0.13 deleted the runtime
        resolver that projected hints onto the live repository snapshot.
        The binder keeps consuming explicit exact candidates, which under
        0.13 are supplied by release-adapter contracts instead.
        """
        remotes = list(hints.get("remotes") or [resolved["upstream_remote"]])
        refs = list(hints.get("refs") or [resolved["ref"]])
        return [
            {
                "repository": str(resolved["repository"]),
                "remote": remote,
                "ref": ref,
                "commit_sha256": str(resolved["head_sha256"]),
            }
            for remote in remotes
            for ref in refs
        ]

    def _binding(
        self, statement: str, *, current_branch: str = "feature/current"
    ) -> tuple[dict[str, object], dict[str, object]]:
        parsed = cg.parse_authorization_statement(statement)
        self.assertIsNotNone(parsed, statement)
        assert parsed is not None
        # Statements that named an invalid ref produce no candidate fact
        # at all — the old snapshot resolver resolved them to [] and the
        # binder must keep reporting requires_selection with no target.
        if parsed["hints"].get("invalid_refs"):
            candidates: list[dict[str, str]] = []
        else:
            candidates = self._candidate_targets(
                parsed["hints"], self._resolved(current_branch)
            )
        binding = cg_authority.bind_authorization(
            parsed["actions"],
            candidates,
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
        # 0.13 transfer (b): ambiguity stays a requires_selection fact on
        # the retained pure binder over explicit candidates — two remotes
        # times two refs are four candidates, never one silent bind.
        binding = cg_authority.bind_authorization(
            parsed["actions"],
            self._candidate_targets(parsed["hints"], self._resolved("feature/current")),
            work_unit_id="WU-R5",
            generation=1,
        )
        self.assertEqual(binding["status"], "requires_selection")
        self.assertIsNone(binding["target"])
        self.assertEqual(len(binding["candidates"]), 4)
        self.assertEqual(
            {candidate["ref"] for candidate in binding["candidates"]},
            {"main", "other"},
        )

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
                parsed, binding = self._binding(statement)
                self.assertEqual(parsed["hints"]["remotes"], [remote])
                self.assertEqual(parsed["hints"]["refs"], [ref])
                # 0.13 transfer (b): the grammar output still selects one
                # exact target when ONE candidate fact exists.
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
                # 0.13 transfer: with no usable ref hint and no candidate
                # fact, nothing is invented — the binder reports
                # requires_selection with no target, and the runtime no
                # longer resolves a fallback on its own (INV-02).
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
        # 0.13 transfer: the statement itself fabricates no ref hint — the
        # old live-repository fallback resolution left the Guard with the
        # deleted snapshot resolver. What remains: (a) the parse layer
        # invents nothing, (b) the executing agent's explicit candidate
        # facts still bind uniquely through the retained pure binder.
        parsed = cg.parse_authorization_statement("push to origin")
        self.assertEqual(parsed["actions"], ["push"])
        self.assertNotIn("refs", parsed["hints"])
        binding = cg_authority.bind_authorization(
            parsed["actions"],
            self._candidate_targets(parsed["hints"], self._resolved("feature/current")),
            work_unit_id="WU-R5",
            generation=1,
        )
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
                    binding = cg_authority.bind_authorization(
                        parsed["actions"],
                        [],
                        work_unit_id="WU-R5",
                        generation=1,
                    )
                    self.assertEqual(binding["status"], "requires_selection")
                    self.assertIsNone(binding["target"])

    def test_statement_ref_wins_over_different_current_branch(self) -> None:
        parsed = cg.parse_authorization_statement("push to origin main")
        binding = cg_authority.bind_authorization(
            parsed["actions"],
            self._candidate_targets(parsed["hints"], self._resolved("feature/current")),
            work_unit_id="WU-R5",
            generation=1,
        )
        self.assertEqual(len(parsed["hints"]["refs"]), 1)
        self.assertEqual(binding["status"], "authorized_unique")
        self.assertEqual(binding["target"]["remote"], "origin")
        self.assertEqual(binding["target"]["ref"], "main")

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


class RefStatementStandardProfileTransferTests(unittest.TestCase):
    """0.13 transfer (d): a ref-target statement in an active standard
    session is constraint recording, not enforcement."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name) / "project"
        self.project.mkdir()
        env = {
            "CONTEXT_GUARD_DATA_DIR": str(Path(self.temp.name) / "private")
        }
        patcher = mock.patch.dict("os.environ", env)
        patcher.start()
        self.addCleanup(patcher.stop)
        subprocess.run(
            ["git", "init", "-q", str(self.project)], check=True,
            capture_output=True,
        )
        for key, value in (("user.name", "R5 Synthetic"), ("user.email", "r5@example.invalid")):
            subprocess.run(
                ["git", "-C", str(self.project), "config", key, value],
                check=True, capture_output=True,
            )
        self.turn = 0

    def dispatch(self, event: str, **extra: object) -> dict:
        self.turn += 1
        payload = {
            "hook_event_name": event,
            "session_id": "r5",
            "cwd": str(self.project),
            "turn_id": f"t{self.turn}",
            "tool_use_id": f"tool-{self.turn}",
        }
        payload.update(extra)
        return cg.dispatch(payload)

    def prompt(self, text: str) -> None:
        self.dispatch("UserPromptSubmit", prompt=text)

    def test_ref_statement_records_a_requirement_and_never_gates(self) -> None:
        self.prompt("context-guard on")
        self.prompt("现在明确授权把候选提交推送到 origin 的 main 分支。")
        result = self.dispatch(
            "PreToolUse",
            tool_name="shell",
            tool_input={"command": "git push origin HEAD:refs/heads/main"},
        )
        # Plain allow wire: no permissionDecision text, no deny.
        self.assertEqual(result, {})
        state = json.loads(
            (Path(self.temp.name) / "private" / "sessions" / "r5" / "state.json")
            .read_text(encoding="utf-8")
        )
        self.assertTrue(
            any("origin 的 main 分支" in item["text"] for item in state["requirements"]),
            "the ref-target statement must survive as a recorded requirement",
        )
        for unit in state["work_units"]:
            self.assertNotIn(
                "authorizations", unit,
                "0.13 fabricates no authorization from ref statements",
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
    import unittest

    unittest.main()
