#!/usr/bin/env python3
"""Phase-4 conformance: profiles, position-aware classifier, authorization UX.

Frozen plan sections 4.1/4.4 and section 7.1/7.2 acceptance rows:

* profiles — standard gates root-user semantic authorization only; strict
  never implies release; release adds candidate/readiness/ticket facts
  through the versioned adapter; observe computes the would-be decision
  and records it without denying; off/inactive perform no action gating at
  all, and corrupt state never denies ordinary tools;
* classifier — real executable positions, subcommands, and effects; echo/
  printf/rg/grep/quoted/doc text and --dry-run/--check forms never gate;
  adversarial matrix (compound, env/wrapper, quoting, option order, alias
  ambiguity, unknown remote mutation tools, argument runners);
* authorization UX — one root-user statement in the current work unit
  authorizes the semantic action; repository/branch/commit/tag targets are
  bound internally from unique structured state; "继续" never erases a
  precise authorization; multi-target/undetermined/drift/out-of-scope ask
  once with one actionable reason; allow paths stay silent.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import cg_actions  # noqa: E402
import cg_authority  # noqa: E402
import cg_release_adapter  # noqa: E402

MODULE_PATH = REPO / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard_phase4", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)


def git_init(project: Path) -> None:
    subprocess.run(["git", "init", "-q", str(project)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(project), "config", "user.name", "Context Guard Test"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(project), "config", "user.email", "test@example.invalid"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(project), "commit", "-q", "--allow-empty", "-m", "init"],
        check=True,
        capture_output=True,
    )


class Phase4Harness(unittest.TestCase):
    """Temp-state harness dispatching hooks exactly like the host."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.data_dir = self.root / "private"
        self.environment = mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.data_dir)}
        )
        self.environment.start()
        self.turn = 0
        # Exact authorization identities need a resolvable Git target.
        subprocess.run(
            ["git", "init", "-q", str(self.project)], check=True, capture_output=True
        )
        subprocess.run(
            ["git", "-C", str(self.project), "config", "user.name", "Context Guard Test"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.project), "config", "user.email", "test@example.invalid"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.project), "commit", "-q", "--allow-empty", "-m", "base"],
            check=True, capture_output=True,
        )

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def dispatch(self, event: str, session: str = "p4", **extra: object) -> dict:
        self.turn += 1
        payload = {
            "hook_event_name": event,
            "session_id": session,
            "cwd": str(self.project),
            "turn_id": f"t{self.turn}",
        }
        payload.update(extra)
        return cg.dispatch(payload)

    def prompt(self, text: str, session: str = "p4") -> dict:
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="p4token"):
            return self.dispatch("UserPromptSubmit", session=session, prompt=text)

    def activate(self, session: str = "p4") -> None:
        self.prompt("context-guard on", session=session)
        self.assertTrue(self.state(session)["mode"]["active"])

    def pre(self, command: str, session: str = "p4", tool: str = "shell") -> dict:
        return self.dispatch(
            "PreToolUse",
            session=session,
            tool_name=tool,
            tool_input={"command": command},
            tool_use_id=f"tool-{self.turn}",
        )

    def decision(self, command: str, session: str = "p4") -> tuple[str, str]:
        result = self.pre(command, session=session)
        output = result.get("hookSpecificOutput")
        if not output:
            return "allow", ""
        return (
            str(output.get("permissionDecision")),
            str(output.get("permissionDecisionReason") or ""),
        )

    def state(self, session: str = "p4") -> dict:
        path = self.root / "private" / "sessions" / session / "state.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def unit_record(self, session: str = "p4") -> dict:
        unit_id = self.state(session)["work_state"]["active_work_unit_id"]
        return next(
            (
                item
                for item in self.state(session)["work_units"]
                if item["id"] == unit_id
            ),
            {},
        )

    def current_unit_id(self, session: str = "p4") -> str:
        return str(self.state(session)["work_state"]["active_work_unit_id"] or "")

    def bindings(self, session: str = "p4") -> list[dict]:
        return [
            record
            for record in (self.unit_record(session).get("authorizations") or [])
            if isinstance(record, dict) and record.get("state") == "active"
        ]

    def _git(self, *args: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.project), *args], check=True, capture_output=True
        )

    def _run_command(self, command: str, exit_code: int = 0) -> dict:
        result = self.pre(command)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": command},
            tool_response={"exit_code": exit_code},
            tool_use_id=f"post-{self.turn}",
        )
        return result

    def _write(self, name: str, content: str) -> None:
        (self.project / name).write_text(content, encoding="utf-8")


class BothClassifierCopiesMixin:
    """Every matrix row must classify identically in the router module and
    the heavy core's mirrored copy."""

    def classify_action(self, command: str):
        router = cg_actions.classify_pre_tool_action(
            {"tool_name": "shell", "tool_input": {"command": command}}
        )
        heavy = cg.classify_pre_tool_action(
            {"tool_name": "shell", "tool_input": {"command": command}}
        )
        return router, heavy


class ClassifierPositionMatrixTests(BothClassifierCopiesMixin, Phase4Harness):
    PLAN_TABLE_TEXT_POSITION = [
        "echo git tag v1.2.3",
        "echo git push origin main",
        "rg -n npm publish README.md",
        'printf "%s\\n" "git push origin main"',
        'rg -n "npm" publish README.md',
        "echo 'gh release create v1.2.3 --notes x'",
        "printf '%s' git tag v9.9.9",
        "grep -rn git tag docs/",
        'grep "git" tag docs/x.md',
        'echo "npm" publish',
        "echo git 'tag' v1.2.3",
        "cat README.md | grep -n 'npm publish'",
        "man git-push | col -b",
    ]

    SIMULATION_AND_READ_ONLY = [
        "npm publish --dry-run",
        "git push --dry-run origin main",
        "git push -n origin main",
        "gh release create v1.2.3 --dry-run",
        "cargo publish --dry-run",
        "cargo publish -n",
        "docker push --dry-run",
        "git tag -l",
        "git tag --list",
        "gh release view v1.2.3",
        "gh release list",
        "git status --porcelain",
        "git diff --check",
        "echo npm publish --dry-run",
    ]

    REAL_MUTATIONS = [
        "git tag v1.2.3",
        "git push origin main",
        "git push --tags",
        "gh release create v1.2.3 --notes x",
        "gh release edit v1.2.3 --notes y",
        "gh release delete v1.2.3",
        "gh release upload v1.2.3 dist.tgz",
        "npm publish",
        "cargo yank",
        "gem push pkg.gem",
        "twine upload dist/*",
        "docker push img:tag",
        "npm unpublish pkg",
    ]

    def test_plan_table_text_positions_never_gate(self) -> None:
        for command in self.PLAN_TABLE_TEXT_POSITION:
            with self.subTest(command=command):
                router, heavy = self.classify_action(command)
                self.assertIsNone(router, command)
                self.assertIsNone(heavy, command)
                self.assertEqual(
                    cg_actions.classify_pre_tool_state("shell", {"command": command}),
                    cg_actions.STATE_SAFE,
                    command,
                )

    def test_simulation_and_read_only_never_gate(self) -> None:
        for command in self.SIMULATION_AND_READ_ONLY:
            with self.subTest(command=command):
                router, heavy = self.classify_action(command)
                self.assertIsNone(router, command)
                self.assertIsNone(heavy, command)
                self.assertEqual(
                    cg_actions.classify_pre_tool_state("shell", {"command": command}),
                    cg_actions.STATE_SAFE,
                    command,
                )

    def test_real_mutations_still_detected_tier_a_or_b(self) -> None:
        tier = {
            "git push origin main": "B",
            "git tag v1.2.3": "A",
        }
        for command in self.REAL_MUTATIONS:
            with self.subTest(command=command):
                router, heavy = self.classify_action(command)
                self.assertIsNotNone(router, command)
                self.assertIsNotNone(heavy, command)
                expected_tier = tier.get(command, "A")
                self.assertEqual(router["tier"], expected_tier, command)

    def test_compound_env_wrapper_and_option_order(self) -> None:
        candidates = [
            "git tag v1.2.3 && git push origin v1.2.3",
            "FOO=1 git push origin main",
            "env GIT_TRACE=0 git tag v1.2.3",
            "sudo git tag v1.2.3",
            "timeout 10 git push origin main",
            "git -C /tmp/x tag v1.2.3",
            "bash -c 'git tag v1.2.3'",
            'pwsh -Command "git tag v1.2.3"',
            'powershell -NoProfile -Command "npm publish"',
            "/bin/zsh -lc 'git tag v1.2.3'",
            "git tag v1.2.3 || echo retry-needed",
            "echo done; git tag v1.2.3",
            "npm publish && git push origin main",
        ]
        for command in candidates:
            with self.subTest(command=command):
                router, heavy = self.classify_action(command)
                self.assertIsNotNone(router, command)
                self.assertIsNotNone(heavy, command)

    def test_simulation_inside_compound_does_not_hide_the_mutation(self) -> None:
        router, _ = self.classify_action("npm publish --dry-run && git push origin main")
        self.assertIsNotNone(router)
        self.assertEqual(router["semantic_action_id"], "remote_push")

    def test_argument_runner_ambiguity_is_bounded_and_deterministic(self) -> None:
        ambiguous = [
            "xargs git push origin main",
            "find . -name '*.md' -exec git push origin main {} +",
            "watch git push origin main",
            "parallel npm publish ::: pkg",
        ]
        for command in ambiguous:
            with self.subTest(command=command):
                self.assertEqual(
                    cg_actions.classify_pre_tool_state("shell", {"command": command}),
                    cg_actions.STATE_AMBIGUOUS_CANDIDATE,
                    command,
                )
        inert = [
            "xargs grep todo",
            "find . -name '*.py'",
            "echo xargs git push origin main",
        ]
        for command in inert:
            with self.subTest(command=command):
                self.assertEqual(
                    cg_actions.classify_pre_tool_state("shell", {"command": command}),
                    cg_actions.STATE_SAFE,
                    command,
                )

    def test_unknown_tools_and_unregistered_mcp_methods_are_safe(self) -> None:
        safe_tools = [
            ("totally_unknown_tool", {}),
            ("update_plan", {"plan": []}),
            ("mcp__whatever__anything", {}),
            ("mcp__github__search_repo", {"q": "x"}),
            ("read", {"path": "docs/x.md"}),
        ]
        for tool_name, tool_input in safe_tools:
            with self.subTest(tool=tool_name):
                self.assertEqual(
                    cg_actions.classify_pre_tool_state(tool_name, tool_input),
                    cg_actions.STATE_SAFE,
                )

    def test_registered_mcp_mutation_methods_stay_candidates(self) -> None:
        for tool_name in (
            "mcp__github__create_release",
            "mcp__github__delete_release",
            "mcp__github__upload_release_asset",
            "mcp__pypi__publish_package",
            "mcp__pypi__yank_package",
        ):
            with self.subTest(tool=tool_name):
                self.assertEqual(
                    cg_actions.classify_pre_tool_state(tool_name, {}),
                    cg_actions.STATE_CANDIDATE,
                )

    def test_effect_ladder_rows(self) -> None:
        rows = cg.classify_shell_effects("git push --dry-run origin main; git push origin main")
        self.assertEqual([row["effect"] for row in rows], ["simulation", "mutation"])
        rows = cg.classify_shell_effects("gh release view v1; gh release create v1")
        self.assertEqual([row["effect"] for row in rows], ["read_only", "mutation"])
        rows = cg.classify_shell_effects("echo git push origin main")
        self.assertEqual([row["effect"] for row in rows], ["inert"])


class ProfileLadderTests(Phase4Harness):
    UNAUTHORIZED_TAG = "git tag v9.9.9"

    def test_inactive_session_performs_no_action_gating(self) -> None:
        self.prompt("fix something small")
        self.assertEqual(self.decision(self.UNAUTHORIZED_TAG), ("allow", ""))
        self.assertEqual(self.decision("npm publish"), ("allow", ""))

    def test_off_session_performs_no_action_gating(self) -> None:
        self.prompt("context-guard on")
        self.prompt("context-guard off")
        self.assertEqual(self.decision(self.UNAUTHORIZED_TAG), ("allow", ""))
        self.assertEqual(self.decision("npm publish"), ("allow", ""))

    def test_standard_denies_unauthorized_and_allows_authorized(self) -> None:
        self.activate()
        permission, reason = self.decision(self.UNAUTHORIZED_TAG)
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)
        self.assertNotIn("ticket", reason.lower())
        self.prompt("请为本仓库创建标签 v9.9.9。")
        self.assertEqual(self.decision("git tag v9.9.9"), ("allow", ""))

    def test_strict_profile_gates_like_standard_and_never_implies_release(self) -> None:
        self.prompt("context-guard strict")
        self.assertEqual(self.state()["mode"]["profile"], "strict")
        self.assertEqual(self.decision(self.UNAUTHORIZED_TAG)[0], "deny")
        self.prompt("请为本仓库创建标签 v9.9.9。")
        # Authorized tag passes WITHOUT any release contract or ticket.
        self.assertEqual(self.decision("git tag v9.9.9"), ("allow", ""))
        self.assertEqual(self.state()["execution"]["contract"]["state"], "absent")

    def test_standard_profile_is_the_default_for_active_sessions(self) -> None:
        self.activate()
        self.assertEqual(cg.effective_action_profile(self.state()), "standard")
        self.assertIsNone(self.state()["mode"]["profile"])

    def test_observe_records_the_would_be_decision_without_denying(self) -> None:
        self.prompt("context-guard observe")
        self.prompt("修复模块。")
        permission, _ = self.decision(self.UNAUTHORIZED_TAG)
        self.assertEqual(permission, "allow")
        entries = [
            entry
            for entry in self.state()["decision_log"]
            if entry.get("decision_source") == "pre_tool_observe"
        ]
        self.assertTrue(entries)
        self.assertEqual(entries[-1]["outcome"], "observe_would_deny")
        self.assertIn("release_tag_mutation", entries[-1]["reason_codes"])

    def test_observe_allows_even_what_release_would_deny(self) -> None:
        self.prompt("context-guard observe")
        self.prompt("授权在精确候选上创建 v1.2.3 release tag。")
        self.assertEqual(self.decision("git tag v1.2.3"), ("allow", ""))

    def test_release_without_adopted_contract_fails_closed_for_tier_a(self) -> None:
        self.prompt("context-guard release")
        self.prompt("请为本仓库创建标签 v9.9.9。")
        permission, reason = self.decision("git tag v9.9.9")
        self.assertEqual(permission, "deny")
        self.assertIn("action-ticket/v1", reason)

    def test_corrupt_state_never_denies_low_risk_tools(self) -> None:
        safe_payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "shell",
            "tool_input": {"command": "echo hello"},
            "tool_use_id": "tool-safe",
        }
        candidate_payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "shell",
            "tool_input": {"command": "git tag v1.2.3"},
            "tool_use_id": "tool-cand",
        }
        # A state without any usable mode evidence cannot gate anything —
        # not even a candidate mutation.
        bare_broken: dict = {"schema_version": 10, "integrity": {"status": "failed"}}
        self.assertEqual(
            cg.handle_pre_tool(Path(self.root / "nowhere"), bare_broken, safe_payload), {}
        )
        self.assertEqual(
            cg.handle_pre_tool(Path(self.root / "nowhere"), bare_broken, candidate_payload),
            {},
        )
        # An ACTIVE session whose private state failed verification keeps
        # the fail-closed guarantee for real mutations: deny once, with one
        # actionable reason — but the low-risk tool above stays untouched.
        active_broken: dict = {
            "schema_version": 10,
            "integrity": {"status": "failed"},
            "mode": {"active": True, "manual_off": False},
        }
        self.assertEqual(
            cg.handle_pre_tool(Path(self.root / "nowhere"), active_broken, safe_payload), {}
        )
        result = cg.handle_pre_tool(
            Path(self.root / "nowhere"), active_broken, candidate_payload
        )
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )

    def test_runner_envelope_fails_open_with_diagnostic(self) -> None:
        """The runner envelope is the ONLY ambiguity that reaches the heavy
        core; standard profile fails open with a classifier_ambiguous
        diagnostic recorded against usable state."""
        self.activate()
        permission, _ = self.decision("xargs git push origin main")
        self.assertEqual(permission, "allow")
        entries = [
            entry
            for entry in self.state()["decision_log"]
            if entry.get("outcome") == "classifier_ambiguous"
        ]
        self.assertTrue(entries)
        self.assertEqual(
            entries[-1]["reason_codes"],
            ["runner_envelope", "classifier_ambiguous", "fail_open"],
        )

    def test_ambiguous_fail_open_survives_unusable_state(self) -> None:
        broken: dict = {"schema_version": 10, "integrity": {"status": "failed"}}
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "shell",
            "tool_input": {"command": "xargs git push origin main"},
            "tool_use_id": "tool-amb",
        }
        self.assertEqual(
            cg.handle_pre_tool(Path(self.root / "nowhere"), broken, payload), {}
        )

    def test_release_profile_fails_closed_on_runner_ambiguity(self) -> None:
        self.prompt("context-guard release")
        self.prompt("准备发布。")
        permission, reason = self.decision("xargs git push origin main")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)


class AuthorizationStatementTargetFamilyTests(Phase4Harness):
    """FAM-AUTH-STATEMENT-TARGET-HINTS: one table-driven failure family over
    the root-user authorization statement surface (coordinator convergence;
    frozen plan section 4.4 and the COMPATIBILITY one-statement example are
    the oracle).

    The canary false deny: an explicit exact authorization phrased with the
    bare Git command form ("git tag v9.9.9") was not recognized as a tag
    statement at all, and when the action verb was recognized in one clause
    while the version was named in an adjacent clause, the clause-scoped
    hint extraction produced an empty target and the real action was denied
    as ``target_undetermined``. Oracle: a statement that names the action
    and its exact target in the current work unit binds that target; the
    statement (all non-negated clauses) is the hint boundary; negated
    clauses never contribute; two named targets stay two candidates
    (ask-once); deletion/negation forms never authorize creation.
    """

    ROWS = [
        # (label, statement, expected_actions, expected_tag_hints)
        ("bare_git_command_form",
         "我现在明确授权：请在本目录执行 git tag v9.9.9，只允许创建这一个 tag，"
         "然后报告 git tag -l 的结果并结束。",
         ["tag"], ["v9.9.9"]),
        ("bare_git_tag_short",
         "git tag v9.9.9", ["tag"], ["v9.9.9"]),
        ("documented_english_example",
         "tag v1.2.3 on this repo", ["tag"], ["v1.2.3"]),
        ("cross_clause_target",
         "创建这个 tag，目标 v9.9.9", ["tag"], ["v9.9.9"]),
        ("two_versions_stay_two_candidates",
         "创建 tag v1.2.3 和 v1.2.4", ["tag"], ["v1.2.3", "v1.2.4"]),
        ("negated_bare_form_never_authorizes",
         "不要 tag v9.9.9", [], []),
        ("negated_clause_excluded_from_hints",
         "创建 tag v1.2.3，但不要 tag v9.9.9", ["tag"], ["v1.2.3"]),
        # "发布 release v2.0.0" carries both the release and publish
        # semantics in the pre-existing action vocabulary; this row pins
        # that the tag authorization keeps only its own version.
        ("two_actions_keep_own_versions",
         "打 tag v1.2.3，发布 release v2.0.0", ["tag", "release", "publish"],
         ["v1.2.3"]),
        ("english_two_actions_keep_own_versions",
         "create tag v1.2.3 and publish release v2.0.0",
         ["tag", "release"], ["v1.2.3"]),
        ("reverse_tag_reference",
         "create v1.2.3 release tag", ["tag"], ["v1.2.3"]),
        ("tag_listing_flag_is_not_a_target",
         "报告 git tag -l 的结果", [], []),
        ("deletion_form_is_not_creation",
         "删除 tag v9.9.9", [], []),
        ("short_delete_command_is_not_creation",
         "git tag -d v9.9.9", [], []),
        ("long_delete_command_is_not_creation",
         "git tag --delete v9.9.9", [], []),
    ]

    def test_statement_target_matrix(self) -> None:
        self.activate()
        failures: list[str] = []
        for label, statement, actions, tags in self.ROWS:
            parsed = cg.parse_authorization_statement(statement)
            got_actions = list((parsed or {}).get("actions", []))
            got_tags = list((parsed or {}).get("hints", {}).get("tags", []))
            if got_actions != actions or got_tags != tags:
                failures.append(
                    f"{label}: expected actions={actions} tags={tags}, "
                    f"got actions={got_actions} tags={got_tags} (parsed={parsed})"
                )
        self.assertEqual(failures, [])

    def test_canary_false_deny_end_to_end(self) -> None:
        """The exact canary scenario: the explicit exact authorization is
        bound, and the tagged action it names proceeds without asking."""
        self.activate()
        self.prompt(
            "我现在明确授权：请在本目录执行 git tag v9.9.9，只允许创建这一个 tag，"
            "然后报告 git tag -l 的结果并结束。"
        )
        permission, _ = self.decision("git tag v9.9.9")
        self.assertEqual(permission, "allow")

    def test_two_candidate_statement_still_asks_once(self) -> None:
        self.activate()
        self.prompt("创建 tag v1.2.3 和 v1.2.4。")
        permission, _ = self.decision("git tag v1.2.3")
        self.assertEqual(permission, "deny")

    DELETION_ROWS = [
        # Coordinator reproductions (P1, FAM-AUTH-STATEMENT-TARGET-HINTS):
        # deletion semantics in the clause must NEVER authorize tag creation,
        # regardless of qualifiers, possessives, demonstratives, position of
        # the deletion verb, whitespace, or punctuation.
        ("coordinator_zh_bare", "删除 tag v9.9.9"),
        ("coordinator_zh_qualifier", "删除本仓库的 tag v9.9.9"),
        ("coordinator_zh_demonstrative", "请删除这个 tag v9.9.9"),
        ("coordinator_en_bare", "delete tag v1.2.3"),
        ("coordinator_en_article", "delete the tag v1.2.3"),
        ("coordinator_en_demonstrative", "remove this tag v1.2.3"),
        ("coordinator_negation_control", "不要创建 tag v9.9.9"),
        ("zh_possessive_prefix", "请先删除仓库里的 tag v1.0.0"),
        ("zh_deletion_after_target", "帮我把这个仓库的 tag v1.0.0 删掉"),
        ("en_possessive", "delete our tag v1.2.3"),
        ("en_modifier", "please remove the old tag v1.2.3"),
        ("en_drop", "drop the tag v1.2.3"),
        ("zh_no_space", "删除一下tag v9.9.9"),
        ("zh_softener", "麻烦删除掉这个 tag v2.0.0"),
        ("en_trailing_period", "delete tag v1.2.3."),
        ("zh_flag_form", "git tag -d v9.9.9"),
        ("zh_long_flag_form", "git tag --delete v9.9.9"),
    ]

    def test_deletion_semantics_never_authorize_tag_creation(self) -> None:
        failures: list[str] = []
        for label, statement in self.DELETION_ROWS:
            parsed = cg.parse_authorization_statement(statement)
            if parsed is not None:
                failures.append(f"{label}: {statement!r} parsed as {parsed}")
        self.assertEqual(failures, [])

    def test_deletion_statement_never_creates_authorization_end_to_end(self) -> None:
        """The persisted authorization path: a deletion prompt must leave no
        active tag authorization binding, so the tagged action stays denied
        (this is the _record_prompt_authorization surface, not just the pure
        parser)."""
        self.activate()
        self.prompt(
            "删除本仓库的 tag v9.9.9。必须逐项落实。必须运行测试验证。"
        )
        self.assertEqual(self.bindings(), [])
        permission, _ = self.decision("git tag v9.9.9")
        self.assertEqual(permission, "deny")

    def test_deletion_clause_excluded_from_cross_clause_targets(self) -> None:
        """A create-then-delete statement binds exactly the creation target:
        the deletion clause contributes no candidate (the removed tag is a
        removal subject, not a second creation candidate)."""
        parsed = cg.parse_authorization_statement("创建 tag v1.2.3，然后删除旧 tag v0.9")
        self.assertEqual(parsed["actions"], ["tag"])
        self.assertEqual(parsed["hints"]["tags"], ["v1.2.3"])
        parsed3 = cg.parse_authorization_statement(
            "创建 tag v1.2.3，然后删除旧 tag v0.9.0"
        )
        self.assertEqual(parsed3["actions"], ["tag"])
        self.assertEqual(parsed3["hints"]["tags"], ["v1.2.3"])

    def test_mixed_removal_and_creation_clause_binds_the_creation_target(self) -> None:
        """One clause carrying both a removal subject and a creation verb
        binds the creation target: the bare-form reference in the removal
        position is guarded, and the two-component removal version is not a
        valid creation candidate."""
        parsed = cg.parse_authorization_statement("删除旧 tag v0.9 后创建 tag v2.0.0")
        self.assertEqual(parsed["actions"], ["tag"])
        self.assertEqual(parsed["hints"]["tags"], ["v2.0.0"])

    SPAN_PROJECTION_ROWS = [
        # Round-3 counterexamples (P1): mixed removal+creation clauses must
        # bind ONLY the creation action's own target, whatever the order,
        # connector language, or punctuation.
        ("coordinator_zh_delete_then_create",
         "删除旧 tag v1.0.0 后创建 tag v2.0.0", ["v2.0.0"]),
        ("coordinator_en_create_then_delete",
         "create tag v2.0.0 after deleting tag v1.0.0", ["v2.0.0"]),
        ("zh_create_then_delete_and", "创建 tag v2.0.0 并删除旧 tag v1.0.0", ["v2.0.0"]),
        ("en_delete_then_create_then", "delete tag v1.0.0 and then create tag v2.0.0", ["v2.0.0"]),
        ("zh_zai_no_punctuation", "删除旧 tag v1.0.0 再创建 tag v2.0.0", ["v2.0.0"]),
        ("zh_creation_first", "先创建 tag v2.0.0，之后删除旧 tag v1.0.0", ["v2.0.0"]),
        ("label_form_creation", "创建标签 v3.0.0", ["v3.0.0"]),
        # Several genuine creation targets stay multi-candidate (ask-once).
        ("two_creation_refs_ask_once", "创建 tag v2.0.0 和 tag v3.0.0", ["v2.0.0", "v3.0.0"]),
        ("release_version_does_not_extend_tag_list",
         "创建 tag v2.0.0 and release v3.0.0", ["v2.0.0"]),
    ]

    def test_span_projection_binds_only_creation_targets(self) -> None:
        failures: list[str] = []
        for label, statement, expected_tags in self.SPAN_PROJECTION_ROWS:
            parsed = cg.parse_authorization_statement(statement)
            got_actions = list((parsed or {}).get("actions", []))
            got_tags = list((parsed or {}).get("hints", {}).get("tags", []))
            if "tag" not in got_actions or got_tags != expected_tags:
                failures.append(
                    f"{label}: expected tags={expected_tags}, "
                    f"got actions={got_actions} tags={got_tags} (parsed={parsed})"
                )
        self.assertEqual(failures, [])

    def test_pure_deletion_chain_stays_null(self) -> None:
        parsed = cg.parse_authorization_statement("删除 tag v1.0.0 后删除 tag v2.0.0")
        self.assertIsNone(parsed)

    def test_mixed_clause_creation_binds_only_creation_target_end_to_end(self) -> None:
        """Persisted path (round 3): the mixed clause authorizes exactly the
        creation target; the removed tag is not a second candidate."""
        self.activate()
        self.prompt("删除旧 tag v1.0.0 后创建 tag v2.0.0。必须逐项落实。必须运行测试验证。")
        bindings = self.bindings()
        self.assertEqual([item["actions"] for item in bindings], [["tag"]])
        self.assertEqual(bindings[0]["binding"]["target"]["tag"], "v2.0.0")
        self.assertEqual(self.decision("git tag v2.0.0"), ("allow", ""))
        permission, _ = self.decision("git tag v1.0.0")
        self.assertEqual(permission, "deny")

    def test_english_mixed_order_binds_creation_target_end_to_end(self) -> None:
        self.activate()
        self.prompt("Create tag v2.0.0 after deleting tag v1.0.0. Must verify by running the tests.")
        bindings = self.bindings()
        self.assertEqual([item["actions"] for item in bindings], [["tag"]])
        self.assertEqual(bindings[0]["binding"]["target"]["tag"], "v2.0.0")
        self.assertEqual(self.decision("git tag v2.0.0"), ("allow", ""))
        permission, _ = self.decision("git tag v1.0.0")
        self.assertEqual(permission, "deny")

    def test_tag_and_release_keep_distinct_targets_end_to_end(self) -> None:
        """A sibling release version must not turn the tag binding into a
        multi-tag ask-once candidate or authorize creation of that version."""
        git_init(self.project)
        self._git(
            "remote", "add", "origin",
            "https://github.com/GreenLv/codex-context-guard.git",
        )
        self.activate()
        self.prompt(
            "创建 tag v1.2.3，并创建 release v2.0.0。必须运行测试验证。"
        )
        bindings = self.bindings()
        self.assertEqual(len(bindings), 2)
        tag_binding = next(item for item in bindings if item["actions"] == ["tag"])
        release_binding = next(
            item for item in bindings if item["actions"] == ["release"]
        )
        self.assertEqual(tag_binding["binding"]["target"]["tag"], "v1.2.3")
        self.assertEqual(
            release_binding["binding"]["target"]["release_version"], "v2.0.0"
        )
        self.assertEqual(self.decision("git tag v1.2.3"), ("allow", ""))
        permission, _ = self.decision("git tag v2.0.0")
        self.assertEqual(permission, "deny")


class AuthorizationUXTests(Phase4Harness):
    def test_one_statement_authorizes_tag_without_restating_targets(self) -> None:
        git_init(self.project)
        self.activate()
        self.prompt("请为本仓库创建标签 v1.0.0。必须运行测试验证。")
        bindings = self.bindings()
        self.assertEqual([item["actions"] for item in bindings], [["tag"]])
        self.assertEqual(bindings[0]["binding"]["target"]["tag"], "v1.0.0")
        self.assertEqual(self.decision("git tag v1.0.0"), ("allow", ""))

    def test_commit_and_push_statement_covers_push(self) -> None:
        git_init(self.project)
        self.activate()
        self.prompt("提交并推送 origin 的 main 分支。")
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertIn("has not verifiably completed", reason)
        self._git("commit", "--allow-empty", "-q", "-m", "authorized work")
        self._run_command("git commit -q --allow-empty -m authorized work")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        permission, _ = self.decision("git push upstream main")
        self.assertEqual(permission, "deny")

    def test_https_destination_and_refspec_authority(self) -> None:
        """The commit→push chain: push passes only after the authorized
        commit verifiably completed, bound to the produced commit."""
        git_init(self.project)
        self.activate()
        self.prompt(
            "提交候选，并将生成的精确提交推送到 "
            "https://github.com/GreenLv/codex-context-guard.git 的 refs/heads/main。"
        )
        permission, reason = self.decision(
            "git push https://github.com/GreenLv/codex-context-guard.git "
            "HEAD:refs/heads/main"
        )
        self.assertEqual(permission, "deny")
        self.assertIn("has not verifiably completed", reason)
        commit_cmd = "git commit -q --allow-empty -m candidate"
        self.assertEqual(self.pre(commit_cmd), {})
        # The authorized commit REALLY runs; the PostToolUse result is what
        # the transition advance verifies against the prepared snapshot.
        self._git("commit", "-q", "--allow-empty", "-m", "candidate")
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": commit_cmd},
            tool_response={"exit_code": 0},
            tool_use_id="commit-authorized",
        )
        self.assertEqual(
            self.decision(
                "git push https://github.com/GreenLv/codex-context-guard.git "
                "HEAD:refs/heads/main"
            ),
            ("allow", ""),
        )
        permission, _ = self.decision(
            "git push https://github.com/GreenLv/codex-context-guard.git "
            "HEAD:refs/heads/other"
        )
        self.assertEqual(permission, "deny")

    def test_negated_statement_never_authorizes(self) -> None:
        self.activate()
        self.prompt("只运行本地检查，不创建 tag，不发布。")
        self.assertEqual(self.bindings(), [])
        permission, _ = self.decision("git tag v1.2.3")
        self.assertEqual(permission, "deny")

    def test_continue_does_not_erase_a_precise_authorization(self) -> None:
        self.activate()
        self.prompt("请为本仓库创建标签 v9.9.9。")
        self.prompt("继续刚才的任务。")
        self.assertEqual(self.decision("git tag v9.9.9"), ("allow", ""))

    def test_multiple_targets_in_one_statement_ask_once(self) -> None:
        self.activate()
        self.prompt("打 tag v1.2.3，另外也可能需要打 tag v2.0.0。")
        permission, reason = self.decision("git tag v1.2.3")
        self.assertEqual(permission, "deny")
        self.assertIn("Several targets match", reason)

    def test_undetermined_target_asks_instead_of_silent_binding(self) -> None:
        self.activate()
        self.prompt("明确 push main，但没有指定 remote。")
        permission, reason = self.decision("git push")
        self.assertEqual(permission, "deny")
        self.assertIn("Cannot determine the exact target", reason)

    def test_drift_after_authorization_asks(self) -> None:
        self.activate()
        self.prompt("打 tag v9.9.9。")
        permission, reason = self.decision("git tag v8.0.0")
        self.assertEqual(permission, "deny")
        self.assertIn("differs from the authorized one", reason)

    def test_force_push_needs_its_own_statement(self) -> None:
        self.activate()
        self.prompt("推送 origin 的 main 分支，但不要强制推送。")
        permission, reason = self.decision("git push -f origin main")
        self.assertEqual(permission, "deny")
        self.assertIn("force push", reason)
        self.prompt("强制推送到 origin 的 main 分支。")
        self.assertEqual(self.decision("git push -f origin main"), ("allow", ""))

    def test_remote_branch_delete_needs_exact_statement_targets(self) -> None:
        self.activate()
        self.prompt("推送 origin 的 main 分支。")
        permission, reason = self.decision("git push --delete origin feature")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)
        self.prompt("删除 origin 的 feature 远程分支。")
        self.assertEqual(self.decision("git push --delete origin feature"), ("allow", ""))

    def test_compound_remote_mutations_require_splitting(self) -> None:
        self.activate()
        self.prompt("推送 origin 的 main 分支。")
        permission, reason = self.decision("git push origin main && git tag v1.2.3")
        self.assertEqual(permission, "deny")
        self.assertIn("separate", reason)

    def test_registry_publish_authorization(self) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0"}), encoding="utf-8"
        )
        self.activate()
        self.prompt("发布 npm 包。")
        bindings = self.bindings()
        self.assertEqual(bindings[0]["binding"]["target"]["release_version"], "1.0.0")
        self.assertEqual(self.decision("npm publish"), ("allow", ""))
        permission, _ = self.decision("cargo publish")
        self.assertEqual(permission, "deny")

    def test_registry_publish_without_resolvable_version_asks_once(self) -> None:
        """P1-1 counterexample B: no trusted metadata means the package
        identity is not exact — ask once, never unresolved==unresolved."""
        self.activate()
        self.prompt("请发布 npm 包。")
        bindings = self.bindings()
        self.assertEqual(
            bindings[0]["binding"]["status"], "requires_selection"
        )
        permission, reason = self.decision("npm publish")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)

    def test_cross_unit_authorization_cannot_replay(self) -> None:
        self.activate()
        self.prompt("打 tag v9.9.9。")
        self.prompt(" completely unrelated new task ")
        self.assertEqual(self.decision("git tag v9.9.9")[0], "deny")


class AllowSilenceAndDenyReasonTests(Phase4Harness):
    def test_allow_wire_is_the_plain_empty_object(self) -> None:
        """UX-05 closure under the frozen §4.4 wire: an authorized real
        mutation returns the PLAIN EMPTY OBJECT — no hookSpecificOutput,
        no permissionDecision, no permissionDecisionReason."""
        self.activate()
        self.prompt("请为本仓库创建标签 v9.9.9。")
        self.assertEqual(self.pre("git tag v9.9.9"), {})

    def test_empty_allow_is_the_plain_empty_object_for_safe_tools(self) -> None:
        self.activate()
        self.assertEqual(self.pre("echo hello"), {})

    def test_deny_reason_is_single_bounded_and_actionable(self) -> None:
        self.activate()
        self.prompt("修复模块。")
        _, reason = self.decision("git tag v1.2.3")
        self.assertLessEqual(len(reason), 512)
        self.assertGreater(len(reason), 0)
        self.assertEqual(reason.count("\n"), 0)


class ReleaseAdapterTests(Phase4Harness):
    def _action(self, command: str = "git tag v1.2.3") -> dict:
        return cg.classify_pre_tool_action(
            {
                "tool_name": "exec_command",
                "tool_input": {"cmd": command},
                "cwd": str(self.project),
            }
        )

    def test_adapter_schema_is_versioned(self) -> None:
        self.assertEqual(cg_release_adapter.RELEASE_ADAPTER_SCHEMA, "release-adapter/v1")

    def test_facts_without_contract_report_no_adopted_contract(self) -> None:
        state = cg.new_state({"session_id": "s"})
        facts = cg_release_adapter.release_facts(state, self._action())
        self.assertEqual(facts["schema"], "release-adapter/v1")
        self.assertFalse(facts["contract_active"])
        self.assertFalse(facts["ticket_matched"])
        self.assertEqual(facts["reason"], "no_adopted_release_contract")

    def test_ticket_replay_is_denied_after_consumption(self) -> None:
        execution = {
            "contract": {"state": "active", "revision": 1, "canonical_sha256": "c" * 64},
            "action_tickets": [
                {
                    "ticket_schema": "action-ticket/v1",
                    "state": "reserved",
                    "repository_id": "repo-x",
                    "candidate_commit": "a" * 40,
                    "contract_revision": 1,
                    "contract_sha256": "c" * 64,
                    "semantic_action_id": "release_tag_mutation",
                    "canonical_target_id": "tag:v1.2.3",
                    "write_surface_id": "git_release_tag",
                    "release_version": "v1.2.3",
                    "input_sha256": "d" * 64,
                    "attempt_count": 0,
                }
            ],
        }
        action = {
            "semantic_action_id": "release_tag_mutation",
            "canonical_target_id": "tag:v1.2.3",
            "write_surface_id": "git_release_tag",
            "repository_id": "repo-x",
            "candidate_commit": "a" * 40,
            "release_version": "v1.2.3",
            "input_sha256": "d" * 64,
        }
        ticket = cg_release_adapter.match_action_ticket(execution, action)
        self.assertIsNotNone(ticket)
        cg_release_adapter.reserve_ticket(ticket, "tool-1", "2026-09-05T00:00:00Z")
        self.assertEqual(ticket["state"], "in_flight")
        self.assertEqual(
            cg_release_adapter.match_action_ticket(execution, action), None
        )

    def test_target_drift_invalidates_the_exact_match(self) -> None:
        action = {
            "semantic_action_id": "release_tag_mutation",
            "canonical_target_id": "tag:v1.2.3",
            "write_surface_id": "git_release_tag",
            "repository_id": "repo-x",
            "candidate_commit": "a" * 40,
            "release_version": "v1.2.3",
            "input_sha256": "d" * 64,
        }
        execution = {
            "contract": {"state": "active", "revision": 1, "canonical_sha256": "c" * 64},
            "action_tickets": [
                {
                    "ticket_schema": "action-ticket/v1",
                    "state": "reserved",
                    "repository_id": "repo-x",
                    "candidate_commit": "a" * 40,
                    "contract_sha256": "c" * 64,
                    "contract_revision": 1,
                    "semantic_action_id": "release_tag_mutation",
                    "canonical_target_id": "tag:v1.2.3",
                    "write_surface_id": "git_release_tag",
                    "release_version": "v1.2.3",
                    "input_sha256": "d" * 64,
                    "attempt_count": 0,
                }
            ],
        }
        drifted = {
            "semantic_action_id": "release_tag_mutation",
            "canonical_target_id": "tag:v2.0.0",
            "write_surface_id": "git_release_tag",
            "repository_id": "repo-x",
            "candidate_commit": "a" * 40,
            "release_version": "v2.0.0",
            "input_sha256": "d" * 64,
        }
        # A target-drifted attempt is never matched, and it never consumes
        # the one-shot ticket: the ticket stays reserved for its exact,
        # still-valid target.
        self.assertIsNone(cg_release_adapter.match_action_ticket(execution, drifted))
        self.assertEqual(execution["action_tickets"][0]["state"], "reserved")
        self.assertIsNotNone(cg_release_adapter.match_action_ticket(execution, action))
        # Commit/contract drift (a stale binding) invalidates the ticket so
        # the stale identity can never be replayed later.
        stale = dict(action, candidate_commit="b" * 40)
        self.assertIsNone(cg_release_adapter.match_action_ticket(execution, stale))
        self.assertEqual(execution["action_tickets"][0]["state"], "invalidated")


class AuthorizationSnapshotTests(Phase4Harness):
    """P1-1: authorization persists an immutable target snapshot AT
    ADOPTION time; execution re-resolves and denies material drift."""

    def _git_repo(self) -> None:
        git_init(self.project)

    def _steps(self, prompt, after=None):
        self.activate()
        self.prompt(prompt)
        if after is not None:
            after()
        return self

    def _run_command(self, command: str, exit_code: int = 0) -> dict:
        result = self.pre(command)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": command},
            tool_response={"exit_code": exit_code},
            tool_use_id=f"post-{self.turn}",
        )
        return result

    def _git(self, *args: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.project), *args], check=True, capture_output=True
        )

    def test_binding_persists_an_immutable_snapshot(self) -> None:
        self._git_repo()
        self.activate()
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        bindings = self.bindings()
        self.assertEqual(len(bindings), 1)
        record = bindings[0]
        self.assertEqual(record["actions"], ["tag"])
        self.assertEqual(record["surfaces"], {"tag": "git_release_tag"})
        self.assertEqual(record["binding"]["status"], "authorized_unique")
        self.assertEqual(record["binding"]["work_unit_id"], self.current_unit_id())
        self.assertRegex(record["context"]["head_sha256"], r"^[0-9a-f]{40}$")

    def test_no_drift_allows(self) -> None:
        self._git_repo()
        self.activate()
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        self.assertEqual(self.pre("git tag v1.2.3"), {})

    def test_unrelated_commit_material_drift_denies(self) -> None:
        self._git_repo()
        self.activate()
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        self._git("commit", "--allow-empty", "-q", "-m", "unrelated")
        permission, reason = self.decision("git tag v1.2.3")
        self.assertEqual(permission, "deny")
        self.assertIn("commit moved", reason)

    def test_branch_drift_denies(self) -> None:
        self._git_repo()
        self.activate()
        self.prompt("请推送 origin 的 main 分支。")
        self._git("checkout", "-q", "-b", "feature")
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertIn("branch moved", reason)

    def test_upstream_drift_denies(self) -> None:
        origin = self.root / "remote-origin"
        origin.mkdir()
        subprocess.run(
            ["git", "init", "-q", "--bare", str(origin)], check=True, capture_output=True
        )
        self._git_repo()
        self._git("remote", "add", "origin", str(origin))
        self._git("push", "-q", "origin", "HEAD:refs/heads/main")
        self._git("branch", "--set-upstream-to=origin/main")
        self.activate()
        self.prompt("请推送 origin 的 main 分支。")
        # Move the branch's upstream to a second remote: the binding's
        # upstream snapshot no longer matches the current structured state.
        elsewhere = self.root / "remote-elsewhere"
        elsewhere.mkdir()
        subprocess.run(
            ["git", "init", "-q", "--bare", str(elsewhere)], check=True, capture_output=True
        )
        self._git("remote", "add", "elsewhere", str(elsewhere))
        self._git("push", "-q", "elsewhere", "HEAD:refs/heads/elsewhere-main")
        self._git("branch", "--set-upstream-to=elsewhere/elsewhere-main")
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertIn("upstream changed", reason)

    def test_commit_push_chain_expected_transition_allows(self) -> None:
        self._git_repo()
        self.activate()
        self.prompt("提交并推送 origin 的 main 分支。")
        # Before the authorized commit: the push expectation is pending.
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertIn("has not verifiably completed", reason)
        self._git("commit", "--allow-empty", "-q", "-m", "authorized work")
        self._run_command("git commit -q --allow-empty -m authorized work")
        self.assertEqual(self.pre("git push origin main"), {})

    def test_failed_commit_never_advances_the_binding(self) -> None:
        self._git_repo()
        self.activate()
        self.prompt("提交并推送 origin 的 main 分支。")
        self._run_command("git commit -q --allow-empty -m work", exit_code=1)
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertIn("has not verifiably completed", reason)

    def test_ambiguous_commit_outcome_never_advances_the_binding(self) -> None:
        self._git_repo()
        self.activate()
        self.prompt("提交并推送 origin 的 main 分支。")
        # A dirty worktree makes the commit identity unverifiable: the
        # outcome is ambiguous, so the binding must stay pending.
        (self.project / "dirty.txt").write_text("x", encoding="utf-8")
        self._run_command("git commit -q --allow-empty -m work")
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)

    def test_second_unrelated_commit_after_chain_advances_denies(self) -> None:
        self._git_repo()
        self.activate()
        self.prompt("提交并推送 origin 的 main 分支。")
        self._git("commit", "--allow-empty", "-q", "-m", "authorized work")
        self._run_command("git commit -q --allow-empty -m authorized work")
        self._git("commit", "--allow-empty", "-q", "-m", "second unrelated")
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertIn("commit moved", reason)

    def test_re_authorization_supersedes_the_previous_binding(self) -> None:
        self._git_repo()
        self.activate()
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        self._git("commit", "--allow-empty", "-q", "-m", "unrelated")
        permission, _ = self.decision("git tag v1.2.3")
        self.assertEqual(permission, "deny")
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        bindings = self.bindings()
        self.assertEqual(len(bindings), 1)
        self.assertEqual(self.pre("git tag v1.2.3"), {})

    def bindings(self) -> list[dict]:
        return [
            record
            for record in (self.unit_record().get("authorizations") or [])
            if record.get("state") == "active"
        ]


class PreparedCandidateRegressionTests(Phase4Harness):
    """Independent counterexamples A/B/C replayed against REAL temp git
    repositories (coordinator Round-3 rejection evidence)."""

    def _write(self, name: str, content: str) -> None:
        (self.project / name).write_text(content, encoding="utf-8")

    def test_counterexample_a_dirty_head_is_now_bound_and_drift_visible(self) -> None:
        self._write("base.txt", "base")
        self._git("add", "base.txt")
        self._git("commit", "-q", "-m", "A")
        self._write("dirty.txt", "uncommitted")  # dirty worktree at auth
        self.activate()
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        bindings = self.bindings()
        # The target identity is the resolvable HEAD even on a dirty tree.
        self.assertRegex(bindings[0]["context"]["head_sha256"], r"^[0-9a-f]{40}$")
        # Still on A, still dirty: the tag binds A and may proceed.
        self.assertEqual(self.pre("git tag v1.2.3"), {})
        # Unrelated commit B, still dirty: the drift is now VISIBLE.
        self._write("b.txt", "b")
        self._git("add", "b.txt")
        self._git("commit", "-q", "-m", "B")
        permission, reason = self.decision("git tag v1.2.3")
        self.assertEqual(permission, "deny")
        self.assertIn("commit moved", reason)

    def test_counterexample_b_publish_without_metadata_asks_never_sentinel(self) -> None:
        self.activate()
        self.prompt("请发布 npm 包。")
        bindings = self.bindings()
        self.assertEqual(bindings[0]["binding"]["status"], "requires_selection")
        self.assertIsNone(bindings[0]["binding"]["target"])
        permission, reason = self.decision("npm publish")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)

    def test_counterexample_b_version_bump_after_authorization_denies(self) -> None:
        self._write("package.json", json.dumps({"name": "demo", "version": "1.0.0"}))
        self.activate()
        self.prompt("请发布 npm 包。")
        self.assertEqual(self.decision("npm publish"), ("allow", ""))
        # The package identity moved: 2.0.0 was never authorized.
        self._write("package.json", json.dumps({"name": "demo", "version": "2.0.0"}))
        permission, reason = self.decision("npm publish")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)

    def test_counterexample_c_prepared_bytes_bind_the_transition(self) -> None:
        self._write("base.txt", "base")
        self._git("add", "base.txt")
        self._git("commit", "-q", "-m", "A")
        self._write("candidate.txt", "prepared bytes A")
        self.activate()
        self.prompt("提交并推送 origin 的 main 分支。")
        # Drift the prepared bytes to B, then commit B: the transition must
        # NOT advance — B was never the authorized prepared candidate.
        self._write("candidate.txt", "drifted bytes B")
        self._git("add", "candidate.txt")
        self._git("commit", "-q", "-m", "commit B")
        self._run_command("git commit -q -m commit B", exit_code=1)
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertIn("has not verifiably completed", reason)

    def test_counterexample_c_matching_prepared_bytes_advance_and_allow(self) -> None:
        self._write("base.txt", "base")
        self._git("add", "base.txt")
        self._git("commit", "-q", "-m", "A")
        self._write("candidate.txt", "prepared bytes A")
        self.activate()
        self.prompt("提交并推送 origin 的 main 分支。")
        self._git("add", "candidate.txt")
        self._git("commit", "-q", "-m", "commit prepared A")
        self._run_command("git commit -q -m commit prepared A")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_counterexample_c_partial_commit_never_advances(self) -> None:
        self._write("base.txt", "base")
        self._git("add", "base.txt")
        self._git("commit", "-q", "-m", "A")
        self._write("prepared.txt", "prepared")
        self._write("extra.txt", "extra")
        self.activate()
        self.prompt("提交并推送 origin 的 main 分支。")
        # Only part of the prepared candidate is committed (and an extra
        # file rides along): no exact correspondence, no advance.
        self._git("add", "prepared.txt")
        self._git("commit", "-q", "-m", "partial")
        self._run_command("git commit -q -m partial")
        permission, _ = self.decision("git push origin main")
        self.assertEqual(permission, "deny")

    def _run_command(self, command: str, exit_code: int = 0) -> dict:
        result = self.pre(command)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": command},
            tool_response={"exit_code": exit_code},
            tool_use_id=f"post-{self.turn}",
        )
        return result


class AuthorizationValueClassMatrixTests(unittest.TestCase):
    """Action × required-field × value-class table with a differential run:
    the pure contract and the heavy production loop must agree on every
    row. Only exact values authorize; unknown/unresolved/all/empty/
    malformed/multiple/drift never do."""

    SHA = "b" * 40
    EXACT = {
        "repository": "repo-x",
        "remote": "origin",
        "ref": "main",
        "commit_sha256": SHA,
        "tag": "v1.2.3",
        "release_version": "v1.2.3",
        "tool": "npm",
        "package": "authorized-pkg",
        "source": "/src/authorized-pkg",
        "registry": "registry.npmjs.org",
    }
    BAD_CLASSES = {
        "unknown": "unknown",
        "unresolved": "unresolved",
        "all": "all",
        "empty": "",
        "whitespace": "   ",
        "malformed-none": None,
        "malformed-bool": True,
        "malformed-list": ["x"],
    }

    def _candidate(self, action: str, field: str | None, value) -> dict:
        candidate = {
            field_name: self.EXACT[field_name]
            for field_name in cg_authority.ACTION_REQUIRED_FIELDS[action]
        }
        if field is not None:
            candidate[field] = value
        return candidate

    def test_only_exact_fields_authorize(self) -> None:
        for action, fields in cg_authority.ACTION_REQUIRED_FIELDS.items():
            with self.subTest(action=action, field="<all-exact>"):
                binding = cg_authority.bind_authorization(
                    [action], [self._candidate(action, None, None)],
                    work_unit_id="WU1", generation=1,
                )
                self.assertEqual(binding["status"], "authorized_unique", action)
            for field in fields:
                for class_name, bad_value in self.BAD_CLASSES.items():
                    with self.subTest(action=action, field=field, value_class=class_name):
                        candidate = self._candidate(action, field, bad_value)
                        binding = cg_authority.bind_authorization(
                            [action], [candidate],
                            work_unit_id="WU1", generation=1,
                        )
                        self.assertNotEqual(
                            binding["status"], "authorized_unique",
                            (action, field, class_name),
                        )

    def test_multiple_candidates_ask_and_drift_denies(self) -> None:
        for action in ("tag", "push", "publish"):
            with self.subTest(action=action, case="multiple"):
                base = self._candidate(action, None, None)
                variant = dict(base)
                variant_key = {
                    "tag": "tag", "push": "remote", "publish": "tool",
                }[action]
                variant[variant_key] = {
                    "tag": "v2.0.0", "remote": "upstream", "tool": "cargo",
                }[variant_key]
                binding = cg_authority.bind_authorization(
                    [action], [base, variant],
                    work_unit_id="WU1", generation=1,
                )
                self.assertEqual(binding["status"], "requires_selection")
            with self.subTest(action=action, case="drift"):
                binding = cg_authority.bind_authorization(
                    [action], [self._candidate(action, None, None)],
                    work_unit_id="WU1", generation=1,
                )
                drifted = dict(self._candidate(action, None, None))
                variant_key = {
                    "tag": "tag", "push": "remote", "publish": "tool",
                }[action]
                drifted[variant_key] = {
                    "tag": "v9.9.9", "remote": "upstream", "tool": "cargo",
                }[variant_key]
                result = cg_authority.evaluate_action_authorization(
                    action, binding, [drifted],
                    current_work_unit_id="WU1", authorization_generation=1,
                )
                self.assertEqual(result["status"], "drifted")

    def test_pending_transition_matrix(self) -> None:
        binding = cg_authority.bind_authorization(
            ["push"],
            [{"repository": "repo-x", "remote": "origin", "ref": "main"}],
            work_unit_id="WU1", generation=1,
            pending={"commit_sha256": "authorized_commit"},
        )
        self.assertEqual(binding["status"], "pending_transition")
        concrete = {
            "repository": "repo-x", "remote": "origin", "ref": "main",
            "commit_sha256": self.SHA,
        }
        for class_name, bad in (
            ("unresolved", "unresolved"),
            ("unknown", "unknown"),
            ("empty", ""),
            ("missing", None),
        ):
            with self.subTest(value_class=class_name):
                result = cg_authority.evaluate_action_authorization(
                    "push", binding, [concrete],
                    current_work_unit_id="WU1", authorization_generation=1,
                    resolved_pending={"commit_sha256": bad} if bad is not None else None,
                )
                self.assertEqual(result["status"], "pending_transition")
        result = cg_authority.evaluate_action_authorization(
            "push", binding, [dict(concrete, commit_sha256="c" * 40)],
            current_work_unit_id="WU1", authorization_generation=1,
            resolved_pending={"commit_sha256": self.SHA},
        )
        self.assertEqual(result["status"], "drifted")
        result = cg_authority.evaluate_action_authorization(
            "push", binding, [concrete],
            current_work_unit_id="WU1", authorization_generation=1,
            resolved_pending={"commit_sha256": self.SHA},
        )
        self.assertEqual(result["status"], "authorized_unique")

    def test_differential_pure_vs_production_loop(self) -> None:
        """Every matrix row decides identically through the pure contract
        and through the heavy production evaluation loop."""
        for action, fields in cg_authority.ACTION_REQUIRED_FIELDS.items():
            for field in fields:
                for class_name, bad_value in list(self.BAD_CLASSES.items()) + [("exact", self.EXACT[field])]:
                    with self.subTest(action=action, field=field, value_class=class_name):
                        candidate = self._candidate(action, field, bad_value)
                        binding = cg_authority.bind_authorization(
                            [action], [candidate],
                            work_unit_id="WU1", generation=1,
                        )
                        pure = cg_authority.evaluate_action_authorization(
                            action, binding, [candidate],
                            current_work_unit_id="WU1", authorization_generation=1,
                        )
                        record = {
                            "actions": list(binding.get("actions") or []),
                            "binding": binding,
                            "context": {"head_sha256": self.SHA},
                            "expected_commits": {},
                            "state": "active",
                        }
                        record_out, reason = cg._evaluate_persisted_bindings(
                            [record], action, candidate,
                            {"repository": "repo-x", "ref": "main", "head_sha256": self.SHA,
                             "upstream_remote": "unknown", "cwd": ""},
                            "WU1",
                        )
                        if pure["status"] == "authorized_unique":
                            self.assertIsNotNone(record_out)
                            self.assertIn(reason, (None, ""))
                        else:
                            self.assertIsNone(record_out)
                            self.assertTrue(reason)


class PreparedProjectionPlumbingTests(Phase4Harness):
    """P1-B: the prepared projection is provable Git plumbing over base
    HEAD + index/staged + unstaged + untracked (path/mode/blob/delete),
    with staged deletions, renames, mode changes, and worktree/staging
    combinations all visible; the commit correspondence is strict."""

    def _auth_chain(self) -> None:
        self.activate()
        self.prompt("提交并推送 origin 的 main 分支。")

    def _commit_via_hooks(self, command: str, uid: str) -> None:
        self.pre(command)
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": command},
            tool_response={"exit_code": 0},
            tool_use_id=uid,
        )

    def _projection(self) -> dict:
        return cg.prepared_source_identity(str(self.project))

    def test_staged_deletion_is_projected_and_advances(self) -> None:
        self._write("victim.txt", "victim")
        self._git("add", "victim.txt")
        self._git("commit", "-q", "-m", "add victim")
        self._git("rm", "-q", "victim.txt")  # staged deletion
        self._auth_chain()
        entries = self._projection()["entries"]
        self.assertIn(
            ("victim.txt", "deleted"),
            [(entry["path"], entry["status"]) for entry in entries],
        )
        self._git("commit", "-q", "-m", "delete victim")
        self._commit_via_hooks("git commit -q -m delete victim", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_projection_invariant_across_staging_of_the_same_deletion(self) -> None:
        self._write("gone.txt", "bye")
        self._git("add", "gone.txt")
        self._git("commit", "-q", "-m", "add gone")
        self._git("rm", "-q", "gone.txt")
        before = self._projection()
        self._git("add", "-u")
        after = self._projection()
        # Worktree-deleted and staged-deleted project to the SAME delta
        # (origin provenance aside): staging can never hide a deletion.
        self.assertEqual(
            [(entry["path"], entry["status"]) for entry in before["entries"]],
            [(entry["path"], entry["status"]) for entry in after["entries"]],
        )
        self.assertEqual(before["projection_sha256"], after["projection_sha256"])

    def test_rename_projects_as_delete_plus_add(self) -> None:
        self._write("old.txt", "content")
        self._git("add", "old.txt")
        self._git("commit", "-q", "-m", "add old")
        self._git("mv", "old.txt", "new.txt")
        self._auth_chain()
        entries = {
            (entry["path"], entry["status"]) for entry in self._projection()["entries"]
        }
        self.assertIn(("old.txt", "deleted"), entries)
        self.assertIn(("new.txt", "modified"), entries)
        self._git("commit", "-q", "-m", "rename")
        self._commit_via_hooks("git commit -q -m rename", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_mode_change_is_projected_and_advances(self) -> None:
        self._write("run.sh", "#!/bin/sh\necho ok\n")
        self._git("add", "run.sh")
        self._git("commit", "-q", "-m", "add run.sh")
        # The WORKTREE file itself becomes executable: the net tree delta
        # vs HEAD is a real mode change (index-only chmod with an unchanged
        # worktree file is a net no-op and projects to an empty delta).
        self._git("update-index", "--chmod=+x", "run.sh")
        os.chmod(self.project / "run.sh", 0o755)
        self._auth_chain()
        entries = self._projection()["entries"]
        self.assertTrue(
            any(entry["path"] == "run.sh" and entry["mode"] == "100755" for entry in entries),
            entries,
        )
        self._git("commit", "-q", "-m", "mode change")
        self._commit_via_hooks("git commit -q -m mode change", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    @unittest.skipUnless(os.name == "nt", "Windows Git mode regression")
    def test_windows_untracked_regular_file_projects_non_executable_mode(self) -> None:
        self._write("candidate.txt", "prepared bytes")
        entries = self._projection()["entries"]
        candidate = next(
            entry for entry in entries if entry["path"] == "candidate.txt"
        )
        self.assertEqual(candidate["mode"], "100644")

    def test_windows_untracked_mode_contract_does_not_use_x_ok(self) -> None:
        self._write("candidate.txt", "prepared bytes")
        with mock.patch.object(cg.os, "access", return_value=True):
            self.assertEqual(
                cg._untracked_regular_git_mode(
                    self.project / "candidate.txt", windows=True
                ),
                "100644",
            )

    def test_staged_plus_unstaged_requires_the_full_candidate(self) -> None:
        self._write("a.txt", "A")
        self._git("add", "a.txt")
        self._git("commit", "-q", "-m", "base2")
        self._write("staged.txt", "staged content")
        self._git("add", "staged.txt")
        self._write("unstaged.txt", "unstaged content")
        self._auth_chain()
        # Commit only the staged half: the prepared candidate (both files)
        # is not fully committed, so the transition never advances.
        self._git("commit", "-q", "-m", "partial")
        self._commit_via_hooks("git commit -q -m partial", "c1")
        permission, _ = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        # Committing the rest still does not advance: the second commit's
        # parent is no longer the authorized base HEAD.
        self._git("add", "unstaged.txt")
        self._git("commit", "-q", "-m", "rest")
        self._commit_via_hooks("git commit -q -m rest", "c2")
        permission, _ = self.decision("git push origin main")
        self.assertEqual(permission, "deny")

    def test_full_candidate_commit_after_partial_staging_allows(self) -> None:
        self._write("staged.txt", "staged content")
        self._git("add", "staged.txt")
        self._write("unstaged.txt", "unstaged content")
        self._auth_chain()
        self._git("add", "unstaged.txt")
        self._git("commit", "-q", "-m", "everything")
        self._commit_via_hooks("git commit -q -m everything", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_extra_uncommitted_file_blocks_advance_until_committed(self) -> None:
        self._write("prepared.txt", "prepared")
        self._write("extra.txt", "extra")
        self._auth_chain()
        # Commit ONLY the extra file: the prepared candidate (prepared.txt)
        # is not fully committed, so the transition never advances.
        self._git("add", "extra.txt")
        self._git("commit", "-q", "-m", "extra only")
        self._commit_via_hooks("git commit -q -m extra only", "c1")
        permission, _ = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        # Committing the prepared file afterwards still cannot advance: the
        # commit's parent is no longer the authorized base HEAD.
        self._git("add", "prepared.txt")
        self._git("commit", "-q", "-m", "prepared")
        self._commit_via_hooks("git commit -q -m prepared", "c2")
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)

    def test_untracked_and_empty_commit_definitions(self) -> None:
        # Clean tree: an allow-empty commit corresponds to the empty
        # prepared projection and advances.
        self._auth_chain()
        self.assertEqual(self._projection()["entries"], [])
        self._git("commit", "-q", "--allow-empty", "-m", "empty")
        self._commit_via_hooks("git commit -q --allow-empty -m empty", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))


class RegistryMonorepoTableTests(Phase4Harness):
    """P1-A: registry operations are distinct exact semantics; publish
    authorization binds operation+tool+package+version+source and never
    covers unpublish/yank/deprecate or a different package."""

    def _metadata(self, name: str, version: str) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": name, "version": version}), encoding="utf-8"
        )

    def test_publish_authorization_binds_exact_registry_identity(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        self.activate()
        self.prompt("请发布 npm 包")
        binding = self.bindings()[0]["binding"]
        self.assertEqual(binding["status"], "authorized_unique")
        self.assertEqual(binding["target"]["tool"], "npm")
        self.assertEqual(binding["target"]["package"], "authorized-pkg")
        self.assertEqual(binding["target"]["release_version"], "1.0.0")
        self.assertEqual(self.decision("npm publish"), ("allow", ""))

    def test_publish_authorization_denies_reverse_mutations(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        self.activate()
        self.prompt("请发布 npm 包")
        for command in (
            "npm unpublish authorized-pkg@1.0.0",
            "npm unpublish authorized-pkg@1.0.0 --force",
            "npm deprecate authorized-pkg@1.0.0 retired",
            "cargo yank authorized-pkg@1.0.0",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertIn("does not cover", reason)

    def test_publish_authorization_denies_other_package_sources(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        sibling = self.root / "other-package"
        sibling.mkdir()
        (sibling / "package.json").write_text(
            json.dumps({"name": "other-package", "version": "9.9.9"}),
            encoding="utf-8",
        )
        self.activate()
        self.prompt("请发布 npm 包")
        permission, _ = self.decision("npm publish ../other-package")
        self.assertEqual(permission, "deny")

    def test_reverse_mutations_need_their_own_exact_statement(self) -> None:
        self.activate()
        self.prompt("撤销发布 npm 包 authorized-pkg@1.0.0。")
        binding = self.bindings()[0]["binding"]
        self.assertEqual(binding["target"]["package"], "authorized-pkg")
        self.assertEqual(binding["target"]["release_version"], "1.0.0")
        self.assertEqual(self.decision("npm unpublish authorized-pkg@1.0.0"), ("allow", ""))
        permission, _ = self.decision("npm unpublish other-pkg@1.0.0")
        self.assertEqual(permission, "deny")

    def test_deprecate_and_yank_need_their_own_exact_statement(self) -> None:
        self.activate()
        self.prompt("废弃 npm 包 authorized-pkg@1.0.0。")
        self.assertEqual(
            self.decision("npm deprecate authorized-pkg@1.0.0 retired"), ("allow", "")
        )
        permission, _ = self.decision("npm deprecate other-pkg@1.0.0 old")
        self.assertEqual(permission, "deny")
        self.prompt("yank cargo 包 authorized-pkg@1.0.0。")
        self.assertEqual(self.decision("cargo yank authorized-pkg@1.0.0"), ("allow", ""))

    def test_publish_tarball_source_must_match_the_bound_source(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        self.activate()
        self.prompt("请发布 npm 包")
        permission, _ = self.decision("npm publish /tmp/anywhere/pkg-9.9.9.tgz")
        self.assertEqual(permission, "deny")

    def test_mcp_registry_methods_do_not_collapse(self) -> None:
        self.activate()
        self.prompt("请发布 npm 包")
        permission, _ = self.decision(
            "registry publish", tool="mcp__pypi__yank_package"
        )
        self.assertEqual(permission, "deny")

    def decision(self, command: str, session: str = "p4", tool: str = "shell") -> tuple[str, str]:
        result = self.pre(command, session=session, tool=tool)
        output = result.get("hookSpecificOutput")
        if not output:
            return "allow", ""
        return (
            str(output.get("permissionDecision")),
            str(output.get("permissionDecisionReason") or ""),
        )


class RegistryGrammarClosureTableTests(Phase4Harness):
    """The executable x operation x option-grammar x effective-target x
    simulation x canonical-action closure table. Every declared mutation
    surface satisfies: unauthorized deny; exact statement reaches allow;
    any effective-field drift denies; unresolvable asks; simulation is
    silent; nothing raises. Differential: both classifier copies agree on
    every row."""

    def _metadata(self, name: str, version: str) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": name, "version": version}), encoding="utf-8"
        )

    def test_grammar_rows_classify_identically_both_copies(self) -> None:
        rows = [
            ("npm publish", "candidate", False),
            ("npm --workspace packages/other publish", "candidate", False),
            ("npm --workspace=packages/other publish", "candidate", False),
            ("npm --registry https://private.example publish", "candidate", False),
            ("npm publish --registry https://private.example", "candidate", False),
            ("npm publish --dry-run", "safe", True),
            ("npm --dry-run publish", "safe", True),
            ("npm publish --dry-run=false", "candidate", False),
            ("npm --dry-run=false publish", "candidate", False),
            ("npm unpublish authorized-pkg@1.0.0", "candidate", False),
            ("npm deprecate authorized-pkg@1.0.0 retired", "candidate", False),
            ("cargo publish", "candidate", False),
            ("cargo publish --dry-run", "safe", True),
            ("cargo publish -n", "safe", True),
            ("cargo yank authorized-crate@1.0.0", "candidate", False),
            ("cargo --manifest-path other/Cargo.toml publish", "candidate", False),
            ("gem push pkg-1.0.0.gem", "candidate", False),
            ("gem yank pkg-1.0.0 -v 1.0.0", "candidate", False),
            ("docker push repo/img:1.0.0", "candidate", False),
            ("docker --context other push repo/img:1.0.0", "candidate", False),
            ("twine upload dist/demo-1.0.0-py3-none-any.whl", "candidate", False),
            ("twine upload --repository-url https://pypi.org demo.tar.gz", "candidate", False),
            ("gh --repo o/r release create v1.2.3", "candidate", False),
            ("gh release create --title v1.2.3 v9.9.9", "candidate", False),
            ("gh release create v1.2.3 --dry-run", "safe", True),
            ("gh --unknown-flag release create v1.2.3", "envelope", False),
            ("npm --unknown-flag publish", "envelope", False),
            # R7 P1-C: gh inherited options are valid AFTER the verb, in
            # separated and = value forms; --target is captured anywhere.
            ("gh release create v1.2.3 --repo o/r", "candidate", False),
            ("gh release create v1.2.3 -R o/r", "candidate", False),
            ("gh release create --repo=o/r v1.2.3", "candidate", False),
            ("gh release create v1.2.3 --repo=o/r", "candidate", False),
            ("gh release create --target deadbeef v1.2.3", "candidate", False),
            ("gh release create v1.2.3 --target deadbeef", "candidate", False),
            ("gh release create --target=deadbeef v1.2.3", "candidate", False),
            ("gh release create --latest v1.2.3", "candidate", False),
            # R7 P1-D: visible env/config selectors never bypass gating.
            ("npm_config_registry=https://x.example npm publish", "candidate", False),
            ("NPM_CONFIG_REGISTRY=https://x.example npm publish", "candidate", False),
            ("env npm_config_registry=https://x.example npm publish", "candidate", False),
            ("GH_REPO=o/r gh release create v1.2.3", "candidate", False),
            ("GH_HOST=enterprise.example gh release create v1.2.3", "candidate", False),
            ("CARGO_REGISTRY_DEFAULT=my-registry cargo publish", "candidate", False),
            ("npm --userconfig /tmp/evil.npmrc publish", "candidate", False),
            ("npm publish --userconfig /tmp/evil.npmrc", "candidate", False),
            ("npm --prefix packages/other publish", "candidate", False),
            ("env -u X npm publish", "candidate", False),
            ("env -i npm publish", "candidate", False),
            ("env --unknown-option npm publish", "envelope", False),
            # R7 P1-F: real per-tool grammars stay candidates; a publish
            # naming several distribution files cannot be one exact target.
            ("twine upload a.tar.gz b.whl", "envelope", False),
            ("cargo yank --version 1.0.0 demo", "candidate", False),
            ("cargo yank demo --version 1.0.0", "candidate", False),
            ("gem yank -v 1.0.0 demo", "candidate", False),
            ("docker push repo/img", "candidate", False),
        ]
        for command, expected_state, expected_simulation in rows:
            with self.subTest(command=command):
                router_state = cg_actions.classify_pre_tool_state(
                    "shell", {"command": command}
                )
                heavy_state = cg.classify_pre_tool_state(
                    "shell", {"command": command}
                )
                self.assertEqual(router_state, heavy_state, command)
                expected_map = {
                    "candidate": {cg_actions.STATE_CANDIDATE},
                    "safe": {cg_actions.STATE_SAFE},
                    "envelope": {cg_actions.STATE_AMBIGUOUS_CANDIDATE},
                }[expected_state]
                self.assertIn(router_state, expected_map, command)
                router_action = cg_actions.classify_pre_tool_action(
                    {"tool_name": "shell", "tool_input": {"command": command}}
                )
                heavy_action = cg.classify_pre_tool_action(
                    {"tool_name": "shell", "tool_input": {"command": command}}
                )
                expected_action_none = (
                    expected_state == "safe"
                    or expected_state == "envelope"
                    or expected_simulation
                )
                self.assertEqual(
                    router_action is None, expected_action_none, command
                )
                self.assertEqual(
                    heavy_action is None, expected_action_none, command
                )
                if expected_simulation:
                    effects = cg.classify_shell_effects(command)
                    self.assertIn(
                        "simulation", [row["effect"] for row in effects], command
                    )

    def test_registry_endpoints_and_sources_bind_exactly(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        self.activate()
        self.prompt("请发布 npm 包")
        binding = self.bindings()[0]["binding"]["target"]
        self.assertEqual(binding["registry"], "registry.npmjs.org")
        self.assertEqual(binding["package"], "authorized-pkg")
        self.assertEqual(binding["release_version"], "1.0.0")
        self.assertEqual(binding["tool"], "npm")
        self.assertEqual(self.decision("npm publish"), ("allow", ""))


class RegistryOptionGrammarTests(Phase4Harness):
    """P1-B/P1-C: supported-CLI option grammar is parsed for the
    subcommand, option values are never sources, unknown pre-subcommand
    options are the bounded envelope, and none of it bypasses gating."""

    def _metadata(self, name: str, version: str) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": name, "version": version}), encoding="utf-8"
        )

    def test_option_first_registry_forms_never_bypass(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        self.activate()
        self.prompt("只做本地检查。")
        for command in (
            "npm --workspace packages/other publish",
            "npm --workspace=packages/other publish",
            "npm -w packages/other publish",
            "cargo --config $CONFIG publish",
            "docker --context other push img",
            "gh --repo o/r release create v1",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)

    def test_option_first_forms_are_candidate_or_envelope_both_copies(self) -> None:
        for command, kind in (
            ("npm --workspace packages/other publish", "candidate"),
            ("npm --workspace=packages/other publish", "candidate"),
            ("npm --unknown-flag publish", "envelope"),
            ("npm --workspaces publish", "envelope"),
            ("gh --repo o/r release create v1", "candidate"),
            ("gh --unknown release create v1", "envelope"),
            ("cargo --config other publish", "candidate"),
            ("docker --context c push img", "candidate"),
        ):
            with self.subTest(command=command):
                router = cg_actions.classify_pre_tool_state(
                    "shell", {"command": command}
                )
                heavy = cg.classify_pre_tool_state("shell", {"command": command})
                self.assertEqual(router, heavy, command)
                expected_states = {
                    "candidate": {"candidate"},
                    "envelope": {"ambiguous_candidate"},
                }[kind]
                self.assertIn(router, expected_states, command)

    def test_registry_option_values_are_never_publish_sources(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        self.activate()
        self.prompt("请发布 npm 包")
        # The registry URL is an option value, not the publish source: the
        # bound root source still matches (no source drift). The decision
        # is deny because the registry ENDPOINT drifted from the default
        # the statement bound.
        permission, reason = self.decision(
            "npm publish --registry https://registry.example"
        )
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)

    def test_registry_endpoint_drift_denies(self) -> None:
        """P1-3: --registry changes the remote registry endpoint; that is
        part of the canonical identity and its drift denies."""
        self._metadata("authorized-pkg", "1.0.0")
        self.activate()
        self.prompt("请发布 npm 包")
        binding = self.bindings()[0]["binding"]["target"]
        self.assertEqual(binding["registry"], "registry.npmjs.org")
        permission, _ = self.decision("npm publish --registry https://private.example")
        self.assertEqual(permission, "deny")

    def test_workspace_selector_resolves_the_effective_source(self) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": "root-pkg", "version": "1.0.0"}), encoding="utf-8"
        )
        workspace = self.project / "packages" / "other"
        workspace.mkdir(parents=True)
        (workspace / "package.json").write_text(
            json.dumps({"name": "other-pkg", "version": "2.0.0"}), encoding="utf-8"
        )
        self.activate()
        self.prompt("请发布 npm 包")
        # The workspace selector resolves the effective source metadata:
        # other-pkg@2.0.0 was never authorized.
        for command in (
            "npm --workspace packages/other publish",
            "npm --workspace=packages/other publish",
            "npm publish --workspace packages/other",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny")

    def test_dry_run_false_is_not_a_simulation(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        self.activate()
        self.prompt("请发布 npm 包")
        self.assertEqual(self.decision("npm publish --dry-run=false"), ("allow", ""))
        self.assertEqual(self.decision("npm publish --dry-run"), ("allow", ""))

    def test_reverse_operations_with_pre_subcommand_options_still_gate(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        self.activate()
        self.prompt("只做本地检查。")
        for command in (
            "npm --workspace packages/other unpublish authorized-pkg@1.0.0",
            "npm --userconfig other.ini deprecate authorized-pkg@1.0.0 old",
            "cargo --config x yank authorized-pkg@1.0.0",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)
class TarballSourceRestatementTests(Phase4Harness):
    """P1-A/P1-E: valid and malformed tarballs never leak exceptions; the
    tarball source is bindable through an explicit restatement and the
    bound source is the only one that authorizes."""

    def _make_tarball(self, name: str, pkg_name: str, version: str) -> None:
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as archive:
            data = json.dumps({"name": pkg_name, "version": version}).encode()
            info = tarfile.TarInfo("package/package.json")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        (self.project / name).write_bytes(buf.getvalue())

    def test_valid_and_malformed_tarballs_never_leak_exceptions(self) -> None:
        self._make_tarball("other-pkg.tgz", "tar-pkg", "2.0.0")
        (self.project / "bad.tgz").write_bytes(b"not a tarball at all")
        self.activate()
        self.prompt("请发布 npm 包")
        for command in (
            "npm publish ./other-pkg.tgz",
            "npm publish ./bad.tgz",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_restated_tarball_source_reaches_the_binding(self) -> None:
        self._make_tarball("other-pkg.tgz", "tar-pkg", "2.0.0")
        self.activate()
        self.prompt("请发布 npm 包")
        permission, _ = self.decision("npm publish ./other-pkg.tgz")
        self.assertEqual(permission, "deny")
        self.prompt("请发布 npm 包 ./other-pkg.tgz")
        bindings = self.bindings()
        self.assertEqual(len(bindings), 1)
        self.assertEqual(
            bindings[0]["binding"]["target"]["source"],
            os.path.abspath(str(self.project / "other-pkg.tgz")),
        )
        self.assertEqual(bindings[0]["binding"]["target"]["package"], "tar-pkg")
        self.assertEqual(self.decision("npm publish ./other-pkg.tgz"), ("allow", ""))
        self._write("package.json", json.dumps({"name": "root-pkg", "version": "1.0.0"}))
        permission, _ = self.decision("npm publish")
        self.assertEqual(permission, "deny")


class McpStructuredPublishTests(Phase4Harness):
    """P1-D: CLI and MCP publish share one canonical schema
    (operation+tool+package+version+source); MCP structured publishes can
    reach authorized_unique and every field drift denies; the reverse MCP
    mutations keep their own semantics."""

    def _auth(self) -> None:
        (self.project / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "1.0.0"\n', encoding="utf-8"
        )
        # The release identity requires a VERIFIED candidate: commit the
        # prepared metadata so the worktree is clean.
        self._git("add", "pyproject.toml")
        self._git("commit", "-q", "-m", "prepared metadata")
        self.activate()
        self.prompt("请发布 pypi 包 demo@1.0.0")

    def _mcp(self, **fields) -> dict:
        tool_input = {
            "tool": "pypi", "package": "demo", "version": "1.0.0",
            "source": str(self.project),
        }
        tool_input.update(fields)
        return self.dispatch(
            "PreToolUse",
            tool_name="mcp__pypi__publish_package",
            tool_input=tool_input,
            tool_use_id=f"mcp-{self.turn}",
        )

    def test_exact_structured_publish_allows(self) -> None:
        self._auth()
        self.assertEqual(self._mcp(), {})

    def test_each_field_drift_denies(self) -> None:
        self._auth()
        for fields in (
            {"package": "other"},
            {"version": "2.0.0"},
            {"tool": "cargo"},
            {"source": "/elsewhere"},
        ):
            with self.subTest(fields=fields):
                result = self._mcp(**fields)
                self.assertEqual(
                    result["hookSpecificOutput"]["permissionDecision"], "deny"
                )

    def test_publish_statement_never_covers_mcp_reverse_mutations(self) -> None:
        self._auth()
        for tool_name in (
            "mcp__pypi__yank_package",
            "mcp__pypi__unpublish_package",
            "mcp__pypi__deprecate_package",
        ):
            with self.subTest(tool=tool_name):
                result = self.dispatch(
                    "PreToolUse",
                    tool_name=tool_name,
                    tool_input={"package": "demo", "version": "1.0.0",
                                "tool": "pypi", "source": str(self.project)},
                    tool_use_id=f"mcp-{self.turn}",
                )
                self.assertEqual(
                    result["hookSpecificOutput"]["permissionDecision"], "deny"
                )

    def test_missing_source_asks_instead_of_defaulting(self) -> None:
        self._auth()
        result = self.dispatch(
            "PreToolUse",
            tool_name="mcp__pypi__publish_package",
            tool_input={"package": "demo", "version": "1.0.0", "tool": "pypi"},
            tool_use_id=f"mcp-{self.turn}",
        )
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )


class ForcePushValueFormTests(Phase4Harness):
    """P1-5: --force-with-lease=<ref>[:<expect>] and --force-if-includes
    are force-push semantics; a plain push authorization never covers
    them, in any combination."""

    def _auth_plain_push(self) -> None:
        self.activate()
        self.prompt("推送 origin 的 main 分支，但不要强制推送。")

    def test_force_with_lease_value_form_is_force_push(self) -> None:
        self._auth_plain_push()
        for command in (
            "git push --force-with-lease=refs/heads/master origin master",
            "git push --force-with-lease origin master",
            "git push --force-if-includes --force-with-lease origin master",
            "git push --force-if-includes origin master",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertIn("force push", reason)

    def test_exact_force_statement_authorizes_force_with_lease(self) -> None:
        self._auth_plain_push()
        self.prompt("强制推送到 origin 的 main 分支。")
        self.assertEqual(self.decision("git push --force-with-lease origin main"), ("allow", ""))
        self.assertEqual(
            self.decision("git push --force-with-lease=refs/heads/main origin main"),
            ("allow", ""),
        )


class GithubReleaseTargetBindingTests(Phase4Harness):
    """P1-3/P1-4: gh --repo binds the real target repository into the
    canonical target; verb-tail option values can never impersonate the
    release tag; MCP structured release surfaces share the schema."""

    def _repo_with_github_origin(self) -> None:
        self._git("remote", "add", "origin", "https://github.com/GreenLv/demo.git")

    def test_gh_repo_option_binds_the_real_target(self) -> None:
        self._repo_with_github_origin()
        self.activate()
        self.prompt("创建 release v1.2.3。")
        permission, _ = self.decision("gh release create v1.2.3 --notes x")
        self.assertEqual(permission, "allow")
        for command in (
            "gh --repo o/r release create v1.2.3",
            "gh -R o/r release create v1.2.3",
            "gh --repo=o/r release create v1.2.3",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny")

    def test_verb_tail_option_value_never_impersonates_the_tag(self) -> None:
        self.activate()
        self.prompt("创建 release v1.2.3。")
        permission, reason = self.decision("gh release create --title v1.2.3 v9.9.9")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)
        permission, _ = self.decision("gh release create v9.9.9 --title x")
        self.assertEqual(permission, "deny")

    def test_mcp_github_release_exact_allow_and_drift_deny(self) -> None:
        self._repo_with_github_origin()
        self.activate()
        self.prompt("创建 release v1.2.3。")

        def mcp(repository="GreenLv/demo", tag_name="v1.2.3"):
            return self.dispatch(
                "PreToolUse",
                tool_name="mcp__github__create_release",
                tool_input={"repository": repository, "tag_name": tag_name},
                tool_use_id=f"mcp-{self.turn}",
            )

        self.assertEqual(mcp(), {})
        drifted = mcp(tag_name="v9.9.9")
        self.assertEqual(
            drifted["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        drifted_repo = mcp(repository="Other/repo")
        self.assertEqual(
            drifted_repo["hookSpecificOutput"]["permissionDecision"], "deny"
        )

    def test_mcp_release_delete_needs_its_own_statement(self) -> None:
        self._repo_with_github_origin()
        self.activate()
        self.prompt("创建 release v1.2.3。")
        result = self.dispatch(
            "PreToolUse",
            tool_name="mcp__github__delete_release",
            tool_input={"repository": "GreenLv/demo", "tag_name": "v1.2.3"},
            tool_use_id=f"mcp-{self.turn}",
        )
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.prompt("删除 GreenLv/demo 的 release v1.2.3。")
        # Allow wire: the plain empty object.
        self.assertEqual(
            self.dispatch(
                "PreToolUse",
                tool_name="mcp__github__delete_release",
                tool_input={"repository": "GreenLv/demo", "tag_name": "v1.2.3"},
                tool_use_id=f"mcp-{self.turn}",
            ),
            {},
        )

    def test_unknown_namespace_same_name_is_gated(self) -> None:
        self._repo_with_github_origin()
        self.activate()
        self.prompt("创建 release v1.2.3。")
        result = self.dispatch(
            "PreToolUse",
            tool_name="mcp__unknownsvc__create_release",
            tool_input={"repository": "GreenLv/demo", "tag_name": "v1.2.3"},
            tool_use_id=f"mcp-{self.turn}",
        )
        # Unknown namespace: still gated as a candidate — without a
        # binding covering it, the decision is deny, never a silent allow.
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )

    def test_inherited_repo_options_after_the_verb_bind_the_real_target(self) -> None:
        """P1-C: -R/--repo is an INHERITED gh option — valid after the verb
        in separated and = forms — and its value is the real target repo."""
        self._repo_with_github_origin()
        self.activate()
        self.prompt("创建 release v1.2.3。")
        self.assertEqual(self.decision("gh release create v1.2.3"), ("allow", ""))
        for command in (
            "gh release create v1.2.3 --repo o/r",
            "gh release create v1.2.3 -R o/r",
            "gh release create --repo=o/r v1.2.3",
            "gh release create v1.2.3 --repo=o/r",
            "gh release upload v1.2.3 dist.tgz --repo o/r",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_target_option_enters_the_canonical_target(self) -> None:
        """P1-C: --target moves the commit an auto-created tag points at;
        the exact resolved commit is part of the release target — the same
        verified commit allows, another real commit or an unresolvable
        value denies (never ignored)."""
        self._repo_with_github_origin()
        subprocess.run(
            ["git", "-C", str(self.project), "checkout", "-qb", "side"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.project), "commit", "-q",
             "--allow-empty", "-m", "side"],
            check=True, capture_output=True,
        )
        side_sha = subprocess.run(
            ["git", "-C", str(self.project), "rev-parse", "HEAD"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(self.project), "checkout", "-q", "-"],
            check=True, capture_output=True,
        )
        verified = subprocess.run(
            ["git", "-C", str(self.project), "rev-parse", "HEAD"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        self.activate()
        self.prompt("创建 release v1.2.3。")
        self.assertEqual(
            self.decision(f"gh release create v1.2.3 --target {verified}"),
            ("allow", ""),
        )
        for command in (
            f"gh release create v1.2.3 --target {side_sha}",
            "gh release create v1.2.3 --target deadbeef",
            "gh release create --target deadbeef v1.2.3",
            "gh release create --target=deadbeef v1.2.3",
            "gh release create v1.2.3 --target '--reset'",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_github_env_selectors_bind_the_real_target(self) -> None:
        """P1-D: GH_REPO/GH_HOST are visible in the command and change the
        real remote target — they enter the canonical identity. The
        documented default host is not drift."""
        self._repo_with_github_origin()
        self.activate()
        self.prompt("创建 release v1.2.3。")
        self.assertEqual(
            self.decision("GH_HOST=github.com gh release create v1.2.3"),
            ("allow", ""),
        )
        for command in (
            "GH_REPO=o/r gh release create v1.2.3",
            "GH_HOST=enterprise.example gh release create v1.2.3",
            "env GH_REPO=o/r gh release create v1.2.3",
            "GH_REPO=o/r GH_HOST=enterprise.example gh release create v1.2.3",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)


class RunnerEnvelopeBoundaryTests(Phase4Harness):
    """P1-3: generic/malformed ambiguity fails open ON THE LIGHT LAYER with
    observably zero subprocess, zero heavy import, zero lock, and zero
    state-path I/O; only the runner envelope reaches the heavy core."""

    def test_router_generic_ambiguity_no_subprocess_no_state_io(self) -> None:
        import cg_hook  # noqa: F401 - import IS the boundary under test

        payload = json.dumps({
            "hook_event_name": "PreToolUse",
            "session_id": "env",
            "cwd": str(self.project),
            "tool_name": "bash",
            "tool_input": {"command": 'echo "oops'},
        }).encode("utf-8")
        fake = _FakeSubprocess()
        with mock.patch.dict(sys.modules, {"subprocess": fake}):
            rc, out = self._run_router(payload)
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), b"{}")
        self.assertEqual(fake.calls, [])
        self.assertEqual(list(self.data_dir.rglob("*")), [])

    def test_router_generic_ambiguity_never_imports_the_heavy_core(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SCRIPTS)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["CONTEXT_GUARD_DATA_DIR"] = str(self.data_dir)
        probe = (
            "import io, json, sys\n"
            "sys.modules['context_guard'] = None\n"
            "sys.modules['cg_release_adapter'] = None\n"
            "sys.modules['cg_authority'] = None\n"
            "sys.modules['cg_stop3'] = None\n"
            "import cg_hook\n"
            "class S:\n"
            "    def __init__(self, data): self.buffer = io.BytesIO(data)\n"
            "    def write(self, d): return self.buffer.write(d.encode() if isinstance(d, str) else d)\n"
            "    def flush(self): pass\n"
            "payload = json.dumps({'hook_event_name': 'PreToolUse', 'session_id': 'iso',"
            " 'tool_name': 'bash', 'tool_input': {'command': 'echo \"unterminated'}})\n"
            "sys.stdin = S(payload.encode())\n"
            "real = sys.stdout\n"
            "sys.stdout = S(b'')\n"
            "sys.stderr = S(b'')\n"
            "cg_hook.main()\n"
            "assert sys.stdout.buffer.getvalue().strip() == b'{}', sys.stdout.buffer.getvalue()\n"
            "assert not __import__('os').path.exists("
            "sys.modules['os'].environ['CONTEXT_GUARD_DATA_DIR'] + '/sessions'), 'state tree created'\n"
            "real.write('OK\\n')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            cwd=str(REPO),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK", result.stdout)

    def test_heavy_dispatch_generic_ambiguity_never_creates_state(self) -> None:
        result = cg.dispatch({
            "hook_event_name": "PreToolUse",
            "session_id": "no-lock",
            "cwd": str(self.project),
            "tool_name": "bash",
            "tool_input": {"command": 'echo "oops'},
        })
        self.assertEqual(result, {})
        sessions = self.root / "private" / "sessions"
        self.assertFalse(sessions.exists(), "session state created for generic ambiguity")

    def test_generic_ambiguity_does_not_wait_for_a_held_lock(self) -> None:
        self.activate()
        session_dir = self.data_dir / "sessions" / "held"
        with cg.filesystem_session_lock(session_dir, 30):
            started = time.monotonic()
            result = cg.dispatch({
                "hook_event_name": "PreToolUse",
                "session_id": "held",
                "cwd": str(self.project),
                "tool_name": "bash",
                "tool_input": {"command": 'echo "unterminated'},
            })
            elapsed = time.monotonic() - started
        self.assertEqual(result, {})
        self.assertLess(elapsed, 5.0, "generic ambiguity waited on a held lock")

    def test_corrupt_state_generic_ambiguity_stays_fail_open(self) -> None:
        broken: dict = {"schema_version": 10, "integrity": {"status": "failed"}}
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "xargs unknown-thing"},
            "tool_use_id": "tool-amb",
        }
        self.assertEqual(
            cg.handle_pre_tool(Path(self.root / "nowhere"), broken, payload), {}
        )

    def _run_router(self, payload: bytes) -> tuple[int, bytes]:
        import cg_hook

        stdin = _BytesStream(payload)
        stdout = _BytesStream()
        stderr = _BytesStream()
        with mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.data_dir)}
        ), mock.patch.object(sys, "stdin", stdin), mock.patch.object(
            sys, "stdout", stdout
        ), mock.patch.object(sys, "stderr", stderr):
            try:
                cg_hook.main()
                rc = 0
            except SystemExit as exc:
                rc = exc.code if isinstance(exc.code, int) else 0
        return rc, stdout.getvalue()


class _FakeSubprocess:
    def __init__(self):
        self.calls = []

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("generic ambiguity must never spawn the heavy core")


class _BytesStream(io.BytesIO):
    @property
    def buffer(self):
        return self

    def write(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        return super().write(data)


class ObserveNoSideEffectTests(Phase4Harness):
    TICKET = {
        "ticket_schema": "action-ticket/v1",
        "state": "reserved",
        "repository_id": "repo-x",
        "candidate_commit": "a" * 40,
        "contract_revision": 1,
        "contract_sha256": "c" * 64,
        "semantic_action_id": "release_tag_mutation",
        "canonical_target_id": "tag:v1.2.3",
        "write_surface_id": "git_release_tag",
        "release_version": "v1.2.3",
        "input_sha256": "d" * 64,
        "attempt_count": 0,
    }

    def _state_with_ticket(self) -> dict:
        state = cg.new_state({"session_id": "obs"})
        state["mode"]["active"] = True
        state["work_state"]["active_work_unit_id"] = "WU0001"
        state["work_units"] = [{
            "id": "WU0001", "protocol_version": "2.0.0", "prompt_id": "P0001",
            "parent_id": None, "kind": "general", "status": "active",
            "created_at": cg.utc_now(), "closed_at": None,
            "scope_sha256": "a" * 64, "last_active_seq": 1,
        }]
        state["execution"]["contract"] = {
            "state": "active", "revision": 1, "canonical_sha256": "c" * 64,
        }
        state["execution"]["action_tickets"] = [dict(self.TICKET)]
        return state

    def _record_binding(self, state: dict) -> None:
        statement = "请为本仓库创建标签 v1.2.3。"
        prompt_record = {
            "id": "P0001",
            "sha256": cg.sha256_text(statement),
            "created_at": cg.utc_now(),
        }
        recorded = cg._record_prompt_authorization(
            state, "WU0001", prompt_record, statement
        )
        self.assertIsNotNone(recorded)

    def _resolution_mocks(self):
        return (
            mock.patch.object(cg, "repository_identity", return_value="repo-x"),
            mock.patch.object(cg, "git_head", return_value="a" * 40),
            mock.patch.object(cg, "repository_commit", return_value="a" * 40),
            mock.patch.object(cg, "current_branch", return_value="main"),
            mock.patch.object(cg, "current_upstream_remote", return_value="unknown"),
            # The minimal synthetic ledger intentionally skips the full
            # execution-state validation the expiry sweep performs.
            mock.patch.object(cg, "expire_execution_tickets", lambda *_a, **_k: None),
        )

    def _ticketed_action(self) -> dict:
        return {
            "semantic_action_id": "release_tag_mutation",
            "canonical_target_id": "tag:v1.2.3",
            "write_surface_id": "git_release_tag",
            "tier": "A",
            "repository_id": "repo-x",
            "candidate_commit": "a" * 40,
            "release_version": "v1.2.3",
            "input_sha256": "d" * 64,
        }

    def test_observe_never_consumes_a_one_shot_ticket(self) -> None:
        state = self._state_with_ticket()
        mocks = self._resolution_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], mocks[5]:
            self._record_binding(state)
            result = cg._enforce_candidate(
                Path(self.root / "nowhere"),
                state,
                {"tool_use_id": "tool-obs", "cwd": str(self.project)},
                self._ticketed_action(),
                "release",
                dry_run=True,
            )
        self.assertEqual(result, {})
        self.assertEqual(state["execution"]["action_tickets"][0]["state"], "reserved")

    def test_enforcement_reserves_the_ticket_for_real(self) -> None:
        state = self._state_with_ticket()
        mocks = self._resolution_mocks()
        with mocks[0], mocks[1], mocks[2], mocks[3], mocks[4], mocks[5]:
            self._record_binding(state)
            result = cg._enforce_candidate(
                Path(self.root / "nowhere"),
                state,
                {"tool_use_id": "tool-real", "cwd": str(self.project)},
                self._ticketed_action(),
                "release",
            )
        self.assertEqual(result, {})
        self.assertEqual(state["execution"]["action_tickets"][0]["state"], "in_flight")


class AuthorityVocabularyTests(unittest.TestCase):
    def test_precise_action_vocabulary_fields(self) -> None:
        self.assertEqual(
            cg_authority.ACTION_REQUIRED_FIELDS["force_push"],
            ("repository", "remote", "ref", "commit_sha256"),
        )
        self.assertEqual(
            cg_authority.ACTION_REQUIRED_FIELDS["tag_push"],
            ("repository", "remote", "tag"),
        )
        self.assertEqual(
            cg_authority.ACTION_REQUIRED_FIELDS["remote_branch_delete"],
            ("repository", "remote", "ref"),
        )
        self.assertEqual(
            cg_authority.ACTION_REQUIRED_FIELDS["release_delete"],
            ("repository", "release_version"),
        )

    def test_implied_coverage_through_the_production_path(self) -> None:
        """A tag-push statement covers evaluating the plain tag action: the
        requested action's own normative fields are re-resolved from the
        statement hints plus the structured state."""
        statement = cg.parse_authorization_statement("创建并推送 tag v1.0.0 到 origin。")
        self.assertIsNotNone(statement)
        self.assertIn("tag_push", statement["actions"])
        self.assertIn("tag", statement["actions"])
        resolved = {
            "repository": "repo-x",
            "ref": "main",
            "head_sha256": "a" * 40,
            "upstream_remote": "unknown",
            "verified_commit": "a" * 40,
            "clean": True,
            "cwd": "",
        }
        tag_candidates = cg._authorization_snapshot_targets(
            ["tag"], statement["hints"], resolved
        )
        self.assertEqual(len(tag_candidates), 1)
        authority = cg._authority_module()
        binding = authority.bind_authorization(
            ["tag"], tag_candidates, work_unit_id="WU0001", generation=1
        )
        result = authority.evaluate_action_authorization(
            "tag",
            binding,
            [tag_candidates[0]],
            current_work_unit_id="WU0001",
            authorization_generation=1,
        )
        self.assertEqual(result["status"], authority.STATUS_AUTHORIZED_UNIQUE)


class FastPathIsolationTests(unittest.TestCase):
    """Non-candidate PreToolUse entries never import the release adapter,
    the authority contract, the ledger migration, or the Stop runtime."""

    def _poisoned(self, poisoned, code):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SCRIPTS)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["CG_HEAVY"] = str(MODULE_PATH)
        poison_lines = "".join("sys.modules[%r] = None\n" % n for n in poisoned)
        full = "import sys\n" + poison_lines + code
        result = subprocess.run(
            [sys.executable, "-c", full],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            cwd=str(REPO),
        )
        return result.returncode, result.stdout + result.stderr

    def test_router_safe_path_needs_none_of_the_private_machinery(self) -> None:
        rc, out = self._poisoned(
            ["cg_release_adapter", "cg_authority", "cg_stop3", "context_guard"],
            "import io, json\n"
            "import cg_hook\n"
            "payload = json.dumps({\n"
            "  'hook_event_name': 'PreToolUse', 'session_id': 'iso',\n"
            "  'tool_name': 'shell', 'tool_input': {'command': 'echo git tag v1.2.3'}})\n"
            "class _Stream:\n"
            "    def __init__(self, data):\n"
            "        self.buffer = io.BytesIO(data)\n"
            "    def write(self, data):\n"
            "        return self.buffer.write(data.encode() if isinstance(data, str) else data)\n"
            "    def flush(self):\n"
            "        pass\n"
            "sys.stdin = _Stream(payload.encode())\n"
            "real = sys.stdout\n"
            "sys.stdout = _Stream(b'')\n"
            "sys.stderr = _Stream(b'')\n"
            "cg_hook.main()\n"
            "assert sys.stdout.buffer.getvalue().strip() == b'{}'\n"
            "real.write('OK\\n')",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("OK", out)

    def test_ambiguous_fail_open_needs_none_of_the_release_machinery(self) -> None:
        """The heavy core can decide an ambiguous call fail-open with the
        release adapter and authority contract poisoned — the fail-open
        branch records its diagnostic without them."""
        rc, out = self._poisoned(
            ["cg_release_adapter", "cg_authority"],
            "import json, os, tempfile\n"
            "import importlib.util\n"
            "temp = tempfile.mkdtemp()\n"
            "os.environ['CONTEXT_GUARD_DATA_DIR'] = os.path.join(temp, 'private')\n"
            "spec = importlib.util.spec_from_file_location('cg_heavy', "
            "os.environ['CG_HEAVY'])\n"
            "cg = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(cg)\n"
            "payload = {'hook_event_name': 'PreToolUse', 'session_id': 'iso-amb',\n"
            "  'cwd': temp, 'turn_id': 't1', 'tool_name': 'shell',\n"
            "  'tool_input': {'command': 'xargs grep todo'}}\n"
            "result = cg.dispatch(payload)\n"
            "assert result == {}, result\n"
            "print('OK')",
        )
        self.assertEqual(rc, 0, out)

    def test_candidate_in_release_profile_uses_the_adapter(self) -> None:
        rc, out = self._poisoned(
            ["cg_release_adapter"],
            "import json, os, tempfile\n"
            "import importlib.util\n"
            "temp = tempfile.mkdtemp()\n"
            "os.environ['CONTEXT_GUARD_DATA_DIR'] = os.path.join(temp, 'private')\n"
            "spec = importlib.util.spec_from_file_location('cg_heavy2', "
            "os.environ['CG_HEAVY'])\n"
            "cg = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(cg)\n"
            "payload = {'hook_event_name': 'UserPromptSubmit', 'session_id': 'iso-rel',\n"
            "  'cwd': temp, 'turn_id': 't1', 'prompt': 'context-guard release'}\n"
            "cg.dispatch(payload)\n"
            "payload2 = {'hook_event_name': 'PreToolUse', 'session_id': 'iso-rel',\n"
            "  'cwd': temp, 'turn_id': 't2', 'tool_name': 'shell',\n"
            "  'tool_input': {'command': 'git tag v1.2.3'}, 'tool_use_id': 'tool-1'}\n"
            "result = cg.dispatch(payload2)\n"
            "decision = result['hookSpecificOutput']['permissionDecision']\n"
            "assert decision == 'deny', result\n"
            "print('OK')",
        )
        self.assertEqual(rc, 0, out)


class CanonicalProjectionDomainTests(unittest.TestCase):
    """R7 P1-E/P1-B: the canonical value domains and adapter provenance of
    the execution projection closure table — one semantic source, asserted
    identical between the router module and the heavy core's mirrored
    copy on every row (strict dual-copy differential)."""

    def _both(self, name):
        return getattr(cg_actions, name), getattr(cg, name)

    def test_canonical_registry_url_rows(self) -> None:
        router, heavy = self._both("canonical_registry_url")
        rows = [
            ("https://registry.npmjs.org/", "registry.npmjs.org"),
            ("https://registry.npmjs.org", "registry.npmjs.org"),
            ("registry.npmjs.org", "registry.npmjs.org"),
            ("HTTPS://Registry.NPMJS.ORG", "registry.npmjs.org"),
            ("http://localhost:4873/", "localhost:4873"),
            ("https://registry.example/private/path", "registry.example/private/path"),
        ]
        for raw, expected in rows:
            with self.subTest(raw=raw):
                self.assertEqual(router(raw), expected)
                self.assertEqual(router(raw), heavy(raw))

    def test_canonical_registry_identity_rows(self) -> None:
        router, heavy = self._both("canonical_registry_identity")
        rows = [
            ("npm", "--registry", "https://registry.npmjs.org/", "registry.npmjs.org"),
            ("cargo", "--registry", "crates-io", "crates.io"),
            ("cargo", "--registry", "crates.io", "crates.io"),
            ("cargo", "--registry", "my-registry", "my-registry"),
            ("cargo", "--index", "https://index.crates.io/", "index:index.crates.io"),
            ("twine", "--repository", "pypi", "pypi.org"),
            ("twine", "--repository", "testpypi", "testpypi"),
            ("twine", "--repository-url", "https://upload.pypi.org/legacy/", "pypi.org"),
            ("gem", "--host", "https://rubygems.org/", "rubygems.org"),
        ]
        for tool, option, raw, expected in rows:
            with self.subTest(tool=tool, raw=raw):
                self.assertEqual(router(tool, option, raw), expected)
                self.assertEqual(router(tool, option, raw), heavy(tool, option, raw))

    def test_canonical_endpoint_equivalence_and_drift_rows(self) -> None:
        router, heavy = self._both("canonical_registry_endpoint")
        npm_default = "registry.npmjs.org"
        rows = [
            # documented default spellings: no false deny
            ("npm", {}, npm_default),
            ("npm", {"--registry": "https://registry.npmjs.org/"}, npm_default),
            ("npm", {"--registry": "https://registry.npmjs.org"}, npm_default),
            ("cargo", {"--registry": "crates-io"}, "crates.io"),
            ("cargo", {"--registry": "https://registry.npmjs.org"},
             "crates.io|--registry=https://registry.npmjs.org"),
            # non-default dimensions are named drift components
            ("npm", {"--registry": "https://private.example"},
             f"{npm_default}|--registry=private.example"),
            ("cargo", {"--index": "https://index.crates.io/"},
             "crates.io|--index=index:index.crates.io"),
            ("twine", {"--repository": "testpypi"},
             "pypi.org|--repository=testpypi"),
            # an explicitly EMPTY value is unresolvable, never the default
            ("npm", {"--registry": ""}, ""),
            ("cargo", {"--registry": ""}, ""),
        ]
        for tool, values, expected in rows:
            with self.subTest(tool=tool, values=values):
                self.assertEqual(router(tool, values), expected)
                self.assertEqual(router(tool, values), heavy(tool, values))

    def test_split_docker_image_reference_rows(self) -> None:
        router, heavy = self._both("split_docker_image_reference")
        rows = [
            ("repo/img:1.0.0", ("", "repo/img", "1.0.0")),
            ("ghcr.io/org/img:1.0.0", ("ghcr.io", "org/img", "1.0.0")),
            ("localhost/img:1.0", ("localhost", "img", "1.0")),
            ("org/img", ("", "org/img", "")),
            ("repo//img:1.0.0", None),
            ("", None),
        ]
        for raw, expected in rows:
            with self.subTest(raw=raw):
                self.assertEqual(router(raw), expected)
                self.assertEqual(router(raw), heavy(raw))

    def test_reverse_spec_grammar_rows(self) -> None:
        router, heavy = self._both("registry_reverse_identity")
        rows = [
            ("npm", ["@scope/pkg@1.2.3"], {}, ("@scope/pkg", "1.2.3")),
            ("npm", ["pkg@v1.2.3"], {}, ("pkg", "1.2.3")),
            ("npm", ["pkg"], {}, ("", "")),
            ("cargo", ["demo@1.0.0"], {}, ("demo", "1.0.0")),
            ("cargo", ["demo"], {"--version": "1.0.0"}, ("demo", "1.0.0")),
            ("cargo", ["demo"], {}, ("", "")),
            ("gem", ["demo"], {"-v": "1.0.0"}, ("demo", "1.0.0")),
            ("gem", ["demo"], {"--version": "v1.0.0"}, ("demo", "1.0.0")),
            ("gem", [], {"-v": "1.0.0"}, ("", "")),
        ]
        for tool, positionals, values, expected in rows:
            with self.subTest(tool=tool, positionals=positionals):
                self.assertEqual(router(tool, positionals, values), expected)
                self.assertEqual(router(tool, positionals, values), heavy(tool, positionals, values))

    def test_mcp_provenance_rows(self) -> None:
        router_fn, heavy_fn = self._both("mcp_adapter_provenance")
        trusted_router = cg_actions.trusted_mcp_adapter
        trusted_heavy = cg.trusted_mcp_adapter
        rows = [
            ("mcp__pypi__publish_package", ("pypi", "registry_package", False)),
            ("mcp__github__create_release", ("github", "github_release", False)),
            # An exact registered method under an unknown namespace: the
            # METHOD is exact (near_miss False) but the NAMESPACE is
            # outside the closed allowlist, so it is never trusted.
            ("mcp__unknownsvc__publish_package", ("unknownsvc", "registry_package", False)),
            ("publish_package", ("", "registry_package", False)),
            ("mcp__pypi__read_package", ("", "", False)),
        ]
        for tool_name, expected in rows:
            with self.subTest(tool_name=tool_name):
                self.assertEqual(router_fn(tool_name), expected)
                self.assertEqual(router_fn(tool_name), heavy_fn(tool_name))
        trust_rows = [
            ("mcp__pypi__publish_package", "pypi", True),
            ("mcp__pypi__publish_package", "cargo", False),
            ("mcp__github__publish_package", "pypi", False),
            ("mcp__unknownsvc__publish_package", "pypi", False),
            ("publish_package", "pypi", False),
            ("mcp__github__create_release", None, True),
            ("mcp__unknownsvc__create_release", None, False),
            ("create_release", None, False),
        ]
        for tool_name, structured, expected in trust_rows:
            with self.subTest(tool_name=tool_name):
                self.assertEqual(trusted_router(tool_name, structured), expected)
                self.assertEqual(trusted_router(tool_name, structured), trusted_heavy(tool_name, structured))


class McpAdapterProvenanceClosedSetTests(Phase4Harness):
    """R7 P1-B: the structured registry surfaces are bound by a CLOSED
    allowlist — adapter namespace, method family, and tool identity must
    agree. Unknown namespaces, cross-namespace adapters, and non-MCP bare
    tool names never inherit an authorization, over publish/unpublish/
    yank/deprecate alike."""

    def _auth(self) -> None:
        (self.project / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "1.0.0"\n', encoding="utf-8"
        )
        self._git("add", "pyproject.toml")
        self._git("commit", "-q", "-m", "prepared metadata")
        self.activate()
        self.prompt("请发布 pypi 包 demo@1.0.0")

    def _mcp(self, namespace="pypi", method="publish_package", **fields) -> dict:
        tool_input = {
            "tool": "pypi", "package": "demo", "version": "1.0.0",
            "source": str(self.project),
        }
        tool_input.update(fields)
        return self.dispatch(
            "PreToolUse",
            tool_name=f"mcp__{namespace}__{method}",
            tool_input=tool_input,
            tool_use_id=f"mcp-{self.turn}",
        )

    def test_cross_namespace_and_bare_tools_never_inherit(self) -> None:
        self._auth()
        for tool_name in (
            "mcp__unknownsvc__publish_package",
            "mcp__github__publish_package",
            "mcp__npm__publish_package",
            "publish_package",
        ):
            with self.subTest(tool_name=tool_name):
                result = self.dispatch(
                    "PreToolUse",
                    tool_name=tool_name,
                    tool_input={
                        "tool": "pypi", "package": "demo", "version": "1.0.0",
                        "source": str(self.project),
                    },
                    tool_use_id=f"mcp-{self.turn}",
                )
                self.assertEqual(
                    result["hookSpecificOutput"]["permissionDecision"], "deny",
                    tool_name,
                )

    def test_namespace_must_equal_the_structured_tool_identity(self) -> None:
        self._auth()
        result = self._mcp(namespace="npm", tool="pypi")
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )

    def test_reverse_methods_cover_the_closed_set(self) -> None:
        self._auth()
        # Same payload, trusted namespace: still denied — a publish
        # statement covers neither reverse mutation.
        for method in ("yank_package", "unpublish_package", "deprecate_package"):
            with self.subTest(method=method):
                self.assertEqual(
                    self._mcp(method=method)["hookSpecificOutput"]["permissionDecision"],
                    "deny",
                    method,
                )
        self.prompt("yank pypi 包 demo@1.0.0")
        # The trusted adapter reaches allow; an unknown namespace with the
        # SAME payload never inherits the yank authorization.
        self.assertEqual(self._mcp(method="yank_package"), {})
        self.assertEqual(
            self._mcp(
                namespace="unknownsvc", method="yank_package"
            )["hookSpecificOutput"]["permissionDecision"],
            "deny",
        )


class ConfigEnvSelectorTests(Phase4Harness):
    """R7 P1-D: visible environment/config selectors are never dropped by
    the transparent wrapper — canonicalizable values enter the target,
    unresolvable config-file selectors are the controlled deny, and the
    documented default spellings do not false-deny."""

    def _npm_metadata(self, name="authorized-pkg", version="1.0.0") -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": name, "version": version}), encoding="utf-8"
        )

    def _npm_authorized(self) -> None:
        self._npm_metadata()
        self.activate()
        self.prompt("请发布 npm 包")

    def test_registry_env_selectors_enter_the_target(self) -> None:
        self._npm_authorized()
        for command in (
            "npm_config_registry=https://evil.example npm publish",
            "NPM_CONFIG_REGISTRY=https://evil.example npm publish",
            "env npm_config_registry=https://evil.example npm publish",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)
        # The documented default host is NOT drift, in env spelling too.
        self.assertEqual(
            self.decision(
                "npm_config_registry=https://registry.npmjs.org/ npm publish"
            ),
            ("allow", ""),
        )
        # An EMPTY selector value cannot prove the endpoint: deny.
        permission, _ = self.decision("npm_config_registry= npm publish")
        self.assertEqual(permission, "deny")

    def test_windows_bash_wrapper_unquotes_env_selector_value(self) -> None:
        command = (
            "bash -lc 'npm_config_registry=\"https://evil.example\" npm publish'"
        )
        for module in (cg_actions, cg):
            with self.subTest(module=module.__name__):
                actions = module._shell_actions(command, posix=False)
                self.assertEqual(len(actions), 1)
                self.assertEqual(
                    actions[0]["semantic_action_id"], "registry_npm_publish"
                )
                self.assertEqual(
                    actions[0]["registry_values"]["--registry"],
                    "https://evil.example",
                )

    def test_windows_bash_wrapper_keeps_quoted_semicolon_in_selector(self) -> None:
        command = (
            "bash -lc 'npm_config_registry=\"https://e; note\" npm publish'"
        )
        for module in (cg_actions, cg):
            with self.subTest(module=module.__name__):
                actions = module._shell_actions(command, posix=False)
                self.assertEqual(len(actions), 1)
                self.assertEqual(
                    actions[0]["semantic_action_id"], "registry_npm_publish"
                )
                self.assertEqual(
                    actions[0]["registry_values"]["--registry"],
                    "https://e; note",
                )

    def test_userconfig_selector_is_the_controlled_deny(self) -> None:
        self._npm_authorized()
        for command in (
            "npm --userconfig /tmp/evil.npmrc publish",
            "npm publish --userconfig /tmp/evil.npmrc",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_prefix_selector_resolves_the_effective_source(self) -> None:
        self._npm_authorized()
        other = self.project / "packages" / "other"
        other.mkdir(parents=True)
        (other / "package.json").write_text(
            json.dumps({"name": "other-pkg", "version": "2.0.0"}),
            encoding="utf-8",
        )
        for command in (
            "npm --prefix packages/other publish",
            "npm publish --prefix packages/other",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)
        # The same prefix spelling for the bound source is no drift.
        self.assertEqual(self.decision("npm --prefix . publish"), ("allow", ""))

    def test_cargo_registry_default_env_selector(self) -> None:
        (self.project / "Cargo.toml").write_text(
            '[package]\nname = "demo-crate"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        self.activate()
        self.prompt("请发布 cargo 包")
        permission, reason = self.decision(
            "CARGO_REGISTRY_DEFAULT=my-registry cargo publish"
        )
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)
        # The default registry NAME (crates-io) is the documented default:
        # no false deny.
        self.assertEqual(
            self.decision("CARGO_REGISTRY_DEFAULT=crates-io cargo publish"),
            ("allow", ""),
        )

    def test_hostile_selector_values_deny_without_throwing(self) -> None:
        self._npm_authorized()
        for command in (
            'npm_config_registry="https://evil.example; rm -rf /" npm publish',
            "npm_config_registry=https://user:pass@evil.example npm publish",
            "NPM_CONFIG_REGISTRY=$EVIL npm publish",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)


class RegistryValueEquivalenceTests(Phase4Harness):
    """R7 P1-E: the registry value domain is canonical — documented
    default spellings (URL forms, trailing slash, crates-io) are the same
    identity as the bound default and must not false-deny."""

    def _npm_authorized(self) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": "authorized-pkg", "version": "1.0.0"}),
            encoding="utf-8",
        )
        self.activate()
        self.prompt("请发布 npm 包")

    def test_npm_default_registry_forms_allow(self) -> None:
        self._npm_authorized()
        for command in (
            "npm publish",
            "npm publish --registry https://registry.npmjs.org/",
            "npm publish --registry=https://registry.npmjs.org",
            "npm --registry https://registry.npmjs.org/ publish",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.decision(command), ("allow", ""), command)

    def test_non_default_registry_still_denies(self) -> None:
        self._npm_authorized()
        for command in (
            "npm publish --registry https://private.example",
            "npm publish --registry https://registry.npmjs.org/legacy",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)

    def test_cargo_default_registry_name_allows(self) -> None:
        (self.project / "Cargo.toml").write_text(
            '[package]\nname = "demo-crate"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        self.activate()
        self.prompt("请发布 cargo 包")
        self.assertEqual(
            self.decision("cargo publish --registry crates-io"), ("allow", "")
        )
        permission, _ = self.decision("cargo publish --registry my-registry")
        self.assertEqual(permission, "deny")


class DeclaredSurfaceIdentityTests(Phase4Harness):
    """R7 P1-F: every declared mutation surface has a real canonical
    identity with at least one reachable exact allow, or is a declared
    unsupported surface (gem push) whose deny is the CONTRACT — never a
    claimed support with a permanent false deny."""

    def test_docker_push_binds_the_image_reference(self) -> None:
        self.activate()
        self.prompt("发布 docker 包 repo/img:1.0.0")
        binding = self.bindings()[0]["binding"]["target"]
        self.assertEqual(binding["tool"], "docker")
        self.assertEqual(binding["package"], "repo/img")
        self.assertEqual(binding["release_version"], "1.0.0")
        self.assertEqual(binding["registry"], "docker.io")
        self.assertEqual(binding["source"], "repo/img:1.0.0")
        self.assertEqual(self.decision("docker push repo/img:1.0.0"), ("allow", ""))
        for command in (
            "docker push repo/other:1.0.0",
            "docker push repo/img:2.0.0",
            "docker push ghcr.io/repo/img:1.0.0",
            "docker --context other push repo/img:1.0.0",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)
        # No tag = EVERY tag of the repository: never one exact target.
        permission, reason = self.decision("docker push repo/img")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)
        # Malformed reference: deny, no throw.
        permission, _ = self.decision("docker push repo//img:1.0.0")
        self.assertEqual(permission, "deny")

    def test_mcp_structured_docker_publish_reaches_allow(self) -> None:
        self.activate()
        self.prompt("发布 docker 包 repo/img:1.0.0")
        result = self.dispatch(
            "PreToolUse",
            tool_name="mcp__docker__publish_package",
            tool_input={"tool": "docker", "package": "repo/img",
                        "version": "1.0.0"},
            tool_use_id=f"mcp-{self.turn}",
        )
        self.assertEqual(result, {})

    def _make_sdist(self, path: str, name: str, version: str) -> None:
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as archive:
            data = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()
            info = tarfile.TarInfo("demo-1.0.0/PKG-INFO")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        target = self.project / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(buf.getvalue())

    def test_twine_upload_binds_the_sdist_identity(self) -> None:
        self._make_sdist("dist/demo-1.0.0.tar.gz", "demo", "1.0.0")
        self.activate()
        self.prompt("请发布 twine 包 ./dist/demo-1.0.0.tar.gz")
        binding = self.bindings()[0]["binding"]["target"]
        self.assertEqual(binding["package"], "demo")
        self.assertEqual(binding["release_version"], "1.0.0")
        self.assertEqual(
            binding["source"],
            os.path.abspath(str(self.project / "dist/demo-1.0.0.tar.gz")),
        )
        self.assertEqual(
            self.decision("twine upload dist/demo-1.0.0.tar.gz"), ("allow", "")
        )
        # Drifted distribution file: deny.
        self._make_sdist("dist/other-2.0.0.tar.gz", "other", "2.0.0")
        permission, _ = self.decision("twine upload dist/other-2.0.0.tar.gz")
        self.assertEqual(permission, "deny")
        # Malformed archive: deny, no throw.
        (self.project / "dist" / "bad.tar.gz").write_bytes(b"not a tarball")
        permission, reason = self.decision("twine upload dist/bad.tar.gz")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason)

    def test_gem_yank_binds_name_and_version(self) -> None:
        self.activate()
        self.prompt("yank gem 包 demo@1.0.0")
        binding = self.bindings()[0]["binding"]["target"]
        self.assertEqual(binding["tool"], "gem")
        self.assertEqual(binding["package"], "demo")
        self.assertEqual(binding["registry"], "rubygems.org")
        # Both official flag positions reach the exact allow.
        self.assertEqual(self.decision("gem yank demo -v 1.0.0"), ("allow", ""))
        self.assertEqual(self.decision("gem yank -v 1.0.0 demo"), ("allow", ""))
        for command in (
            "gem yank other -v 1.0.0",
            "gem yank demo -v 2.0.0",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)

    def test_cargo_yank_supports_the_version_flag_forms(self) -> None:
        self.activate()
        self.prompt("yank cargo 包 demo@1.0.0")
        for command in (
            "cargo yank demo@1.0.0",
            "cargo yank --version 1.0.0 demo",
            "cargo yank demo --version 1.0.0",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.decision(command), ("allow", ""), command)
        for command in (
            "cargo yank other@1.0.0",
            "cargo yank --version 2.0.0 demo",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)

    def test_gem_push_is_a_declared_unsupported_surface(self) -> None:
        """gem push can never bind an exact identity (RubyGems metadata is
        a binary Marshal blob): the deny IS the contract, even after a
        publish statement, in every profile — and the message says so."""
        (self.project / "demo-1.0.0.gem").write_bytes(b"not really a gem")
        self.activate()
        self.prompt("请发布 gem 包")
        permission, reason = self.decision("gem push demo-1.0.0.gem")
        self.assertEqual(permission, "deny")
        self.assertIn("unsupported", reason)
        # MCP structured gem publish shares the same declared contract.
        result = self.dispatch(
            "PreToolUse",
            tool_name="mcp__gem__publish_package",
            tool_input={"tool": "gem", "package": "demo", "version": "1.0.0",
                        "source": str(self.project)},
            tool_use_id=f"mcp-{self.turn}",
        )
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )


class McpMethodClosedSetTests(Phase4Harness):
    """R8 P1-G: the raw mcp__<namespace>__<method> triple must agree on
    namespace, EXACT registered method, and structured tool identity.
    Near-miss method spellings (garbage prefix/suffix, wrong case, extra
    __-segments) stay gated candidates and can never inherit an
    authorization — and are never silently safe."""

    def _auth(self) -> None:
        (self.project / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "1.0.0"\n', encoding="utf-8"
        )
        self._git("add", "pyproject.toml")
        self._git("commit", "-q", "-m", "prepared metadata")
        self.activate()
        self.prompt("请发布 pypi 包 demo@1.0.0")

    def _mcp(self, tool_name, **fields) -> dict:
        tool_input = {
            "tool": "pypi", "package": "demo", "version": "1.0.0",
            "source": str(self.project),
        }
        tool_input.update(fields)
        return self.dispatch(
            "PreToolUse",
            tool_name=tool_name,
            tool_input=tool_input,
            tool_use_id=f"mcp-{self.turn}",
        )

    def test_exact_method_still_reaches_allow(self) -> None:
        self._auth()
        self.assertEqual(self._mcp("mcp__pypi__publish_package"), {})

    def test_near_miss_methods_never_inherit(self) -> None:
        self._auth()
        for tool_name in (
            "mcp__pypi__foo_publish_package",
            "mcp__pypi__read_publish_package",
            "mcp__github__foo_create_release",
            "mcp__github__read_create_release",
            "mcp__pypi__publish_package_extra",
            "mcp__pypi__PUBLISH_PACKAGE",
            "mcp__pypi__x__publish_package",
            "mcp__pypi__unpublish_package_",
            "mcp__pypi__publish__package",
            "publish_package_collector",
        ):
            with self.subTest(tool_name=tool_name):
                # A near-miss is a GATED candidate, never silently safe.
                state = cg_actions.classify_pre_tool_state(
                    tool_name, {"tool": "pypi"}
                )
                self.assertEqual(
                    state, cg_actions.STATE_CANDIDATE, tool_name
                )
                result = self._mcp(tool_name)
                self.assertEqual(
                    result["hookSpecificOutput"]["permissionDecision"],
                    "deny",
                    tool_name,
                )

    def test_github_near_miss_never_inherits(self) -> None:
        self._git("remote", "add", "origin", "https://github.com/GreenLv/demo.git")
        self.activate()
        self.prompt("创建 release v1.2.3。")
        for tool_name in (
            "mcp__github__foo_create_release",
            "mcp__github__create_release_extra",
            "mcp__github__CREATE_RELEASE",
        ):
            with self.subTest(tool_name=tool_name):
                result = self.dispatch(
                    "PreToolUse",
                    tool_name=tool_name,
                    tool_input={"repository": "GreenLv/demo", "tag_name": "v1.2.3"},
                    tool_use_id=f"mcp-{self.turn}",
                )
                self.assertEqual(
                    result["hookSpecificOutput"]["permissionDecision"],
                    "deny",
                    tool_name,
                )

    def test_reverse_methods_stay_exact_after_the_closure(self) -> None:
        self._auth()
        self.prompt("yank pypi 包 demo@1.0.0")
        self.assertEqual(self._mcp("mcp__pypi__yank_package"), {})
        for tool_name in (
            "mcp__pypi__foo_yank_package",
            "mcp__unknownsvc__yank_package",
        ):
            with self.subTest(tool_name=tool_name):
                result = self._mcp(tool_name)
                self.assertEqual(
                    result["hookSpecificOutput"]["permissionDecision"],
                    "deny",
                    tool_name,
                )


class GhInheritedRegionTests(Phase4Harness):
    """R8 P1-H: gh inherited options are legal in ALL THREE regions (after
    gh, between release and the verb, after the verb) and bind the real
    target in separated and = forms; missing values and conflicting
    repeats are the controlled deny; the DEFAULT host spelling
    github.com/OWNER/REPO is the same identity as OWNER/REPO."""

    def _authorized(self) -> None:
        self._git("remote", "add", "origin", "https://github.com/GreenLv/demo.git")
        self.activate()
        self.prompt("创建 release v1.2.3。")

    def test_region_two_options_bind_and_drift_deny(self) -> None:
        self._authorized()
        self.assertEqual(self.decision("gh release create v1.2.3"), ("allow", ""))
        for command in (
            "gh release --repo o/r create v1.2.3",
            "gh release -R o/r create v1.2.3",
            "gh release --repo=o/r create v1.2.3",
            "gh release --repo o/r --hostname github.com create v1.2.3",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_default_host_spelling_is_no_drift(self) -> None:
        self._authorized()
        for command in (
            "gh release create v1.2.3 --repo github.com/GreenLv/demo",
            "gh release --repo github.com/GreenLv/demo create v1.2.3",
            "GH_REPO=github.com/GreenLv/demo gh release create v1.2.3",
            "gh release create v1.2.3 --repo GreenLv/demo",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.decision(command), ("allow", ""), command)

    def test_non_default_host_is_a_distinct_identity(self) -> None:
        self._authorized()
        for command in (
            "gh release create v1.2.3 --repo enterprise.example/GreenLv/demo",
            "gh release create v1.2.3 --hostname enterprise.example",
            "GH_HOST=enterprise.example gh release create v1.2.3",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)

    def test_missing_and_conflicting_values_deny(self) -> None:
        self._authorized()
        for command in (
            # --repo left without its value at the tail of a REAL mutation.
            "gh release create v1.2.3 --repo",
            "gh release create --repo",
            # Conflicting repeats across regions: never last-wins.
            "gh release create v1.2.3 --repo o/r --repo p/q",
            "gh release --repo=o/r create v1.2.3 --repo p/q",
            "gh --repo o/r release create v1.2.3 --repo p/q",
            "gh release --repo o/r create v1.2.3 --hostname github.com --repo p/q",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_same_value_repeat_is_no_conflict(self) -> None:
        self._authorized()
        self.assertEqual(
            self.decision("gh release create v1.2.3 --repo GreenLv/demo --repo GreenLv/demo"),
            ("allow", ""),
        )

    def test_read_only_verb_stays_inert_with_options(self) -> None:
        self._authorized()
        self.assertEqual(
            cg_actions.classify_pre_tool_state(
                "shell", {"command": "gh release --repo o/r view v1.2.3"}
            ),
            cg_actions.STATE_SAFE,
        )


class GhRepoAliasCanonicalDimensionTests(BothClassifierCopiesMixin, Phase4Harness):
    """R9 P1-J: -R and --repo are the SAME repo option. Values are
    captured and compared on the canonical --repo dimension, so a
    cross-alias repeat with a different value is a conflict (undetermined
    — controlled deny) and a same-value repeat is idempotent, in every
    legal region, spelling, and order — the decision can never depend on
    which alias carries which value."""

    def _authorized(self) -> None:
        self._git("remote", "add", "origin", "https://github.com/GreenLv/demo.git")
        self.activate()
        self.prompt("创建 release v1.2.3。")

    def test_coordinator_reproducers_deny_in_every_region(self) -> None:
        self._authorized()
        for command in (
            # The coordinator's three region reproducers: the authorized
            # value in --repo must not silence the drift in -R.
            "gh --repo GreenLv/demo -R o/r release create v1.2.3",
            "gh release --repo GreenLv/demo -R o/r create v1.2.3",
            "gh release create v1.2.3 --repo GreenLv/demo -R o/r",
            # = form, and the mirror image (authorized value in -R).
            "gh --repo=GreenLv/demo -R o/r release create v1.2.3",
            "gh -R o/r --repo GreenLv/demo release create v1.2.3",
            "gh -R GreenLv/demo --repo o/r release create v1.2.3",
            "gh -R=GreenLv/demo --repo=o/r release create v1.2.3",
            # Cross-region conflicts.
            "gh --repo GreenLv/demo release -R o/r create v1.2.3",
            "gh --repo GreenLv/demo release create v1.2.3 -R o/r",
            "gh release -R o/r create v1.2.3 --repo GreenLv/demo",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_same_value_repeat_is_idempotent_everywhere(self) -> None:
        self._authorized()
        for command in (
            "gh --repo GreenLv/demo -R GreenLv/demo release create v1.2.3",
            "gh release --repo GreenLv/demo -R GreenLv/demo create v1.2.3",
            "gh release create v1.2.3 --repo GreenLv/demo -R GreenLv/demo",
            "gh --repo=GreenLv/demo -R GreenLv/demo release create v1.2.3",
            "gh --repo GreenLv/demo release -R GreenLv/demo create v1.2.3",
            "gh --repo GreenLv/demo release create v1.2.3 -R GreenLv/demo",
            # Same-value repeat on ONE alias across regions stays fine.
            "gh --repo GreenLv/demo release create v1.2.3 --repo GreenLv/demo",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.decision(command), ("allow", ""), command)

    def test_missing_value_conflicts_on_the_canonical_dimension(self) -> None:
        self._authorized()
        for command in (
            "gh release create v1.2.3 -R",
            "gh release create v1.2.3 --repo GreenLv/demo -R",
            "gh release create v1.2.3 --repo GreenLv/demo --repo=",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_permutation_table_is_order_and_spelling_independent(self) -> None:
        """Table-driven differential: every permutation of {--repo, -R}
        x {separated, =} x the three regions classifies IDENTICALLY in
        both classifier copies, and cross-alias different values always
        carry the canonical --repo conflict while same values never do."""
        authorized = "GreenLv/demo"
        drifted = "o/r"

        def occurrence(spelling: str, form: str, value: str) -> str:
            return f"{spelling}{form}{value}" if form == "=" else f"{spelling} {value}"

        rows: list[tuple[str, bool]] = []
        for first, second in (("--repo", "-R"), ("-R", "--repo")):
            for form_a in (" ", "="):
                for form_b in (" ", "="):
                    for value_a, value_b in (
                        (authorized, drifted),
                        (drifted, authorized),
                        (authorized, authorized),
                    ):
                        one = occurrence(first, form_a, value_a)
                        two = occurrence(second, form_b, value_b)
                        for command in (
                            f"gh {one} {two} release create v1.2.3",
                            f"gh release {one} {two} create v1.2.3",
                            f"gh release create v1.2.3 {one} {two}",
                            f"gh {one} release {two} create v1.2.3",
                            f"gh {one} release create v1.2.3 {two}",
                            f"gh release {one} create v1.2.3 {two}",
                        ):
                            rows.append((command, value_a != value_b))
        self.assertGreaterEqual(len(rows), 96)
        for command, is_conflict in rows:
            with self.subTest(command=command):
                router, heavy = self.classify_action(command)
                self.assertEqual(router, heavy, command)
                router_conflicts = (router or {}).get("gh_conflicts") or []
                heavy_conflicts = (heavy or {}).get("gh_conflicts") or []
                self.assertEqual(router_conflicts, heavy_conflicts, command)
                if is_conflict:
                    self.assertEqual(router_conflicts, ["--repo"], command)
                else:
                    self.assertEqual(router_conflicts, [], command)


class RegistryAliasCanonicalDimensionTests(BothClassifierCopiesMixin, Phase4Harness):
    """R9 P1-J extension: every real alias pair in the same grammars
    (npm -w/--workspace, docker -c/--context and -H/--host, twine
    -r/--repository, gem -v/--version, cargo -j/--jobs) compares values
    on the canonical dimension — same value idempotent, different values
    the controlled conflict, never a spelling- or order-dependent pick."""

    def _npm_authorized(self) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": "authorized-pkg", "version": "1.0.0"}),
            encoding="utf-8",
        )
        other = self.project / "packages" / "other"
        other.mkdir(parents=True)
        (other / "package.json").write_text(
            json.dumps({"name": "other-pkg", "version": "2.0.0"}),
            encoding="utf-8",
        )
        self.activate()
        self.prompt("请发布 npm 包")

    def test_npm_workspace_regions_conflict_on_different_values(self) -> None:
        self._npm_authorized()
        self.assertEqual(self.decision("npm -w . publish"), ("allow", ""))
        self.assertEqual(
            self.decision("npm -w . publish --workspace ."), ("allow", "")
        )
        for command in (
            "npm -w packages/other publish --workspace .",
            "npm --workspace . publish -w packages/other",
            "npm -w=. publish --workspace=packages/other",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_gem_version_aliases_conflict_on_different_values(self) -> None:
        self.activate()
        self.prompt("yank gem 包 demo@1.0.0")
        # Same value through BOTH aliases: idempotent allow.
        self.assertEqual(
            self.decision("gem yank demo -v 1.0.0 --version 1.0.0"),
            ("allow", ""),
        )
        # The pre-fix false allow: the -v spelling carried the authorized
        # version while --version carried the drift (and the mirror).
        for command in (
            "gem yank demo -v 1.0.0 --version 2.0.0",
            "gem yank demo --version 2.0.0 -v 1.0.0",
            "gem yank demo --version 1.0.0 -v 2.0.0",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_docker_and_twine_aliases_stay_canonical(self) -> None:
        self.activate()
        self.prompt("发布 docker 包 repo/img:1.0.0")
        for command in (
            "docker --context prod -c dev push repo/img:1.0.0",
            "docker -c dev --context prod push repo/img:1.0.0",
            "docker --host tcp://a -H tcp://b push repo/img:1.0.0",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)
        # The same value through both aliases is no conflict; the default
        # context spelling keeps the authorized endpoint.
        self.assertEqual(
            self.decision("docker --context default -c default push repo/img:1.0.0"),
            ("allow", ""),
        )
        # twine: -r and --repository project the SAME canonical identity
        # (spelling-invariant), and a cross-alias conflict is recorded.
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as archive:
            data = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n"
            info = tarfile.TarInfo("demo-1.0.0/PKG-INFO")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        (self.project / "dist").mkdir(exist_ok=True)
        (self.project / "dist" / "demo-1.0.0.tar.gz").write_bytes(buf.getvalue())
        self.prompt("请发布 twine 包 ./dist/demo-1.0.0.tar.gz")
        self.assertEqual(
            self.decision("twine upload -r pypi --repository pypi dist/demo-1.0.0.tar.gz"),
            ("allow", ""),
        )
        for command in (
            "twine upload -r private --repository other dist/demo-1.0.0.tar.gz",
            "twine upload --repository other -r private dist/demo-1.0.0.tar.gz",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)

    def test_alias_permutation_rows_are_differential_and_canonical(self) -> None:
        """Every alias-pair row classifies identically in both classifier
        copies, stores values under the canonical long spelling, and
        records the canonical conflict exactly when the values differ."""
        rows = [
            ("gem yank demo -v 1.0.0 --version 2.0.0", "--version", True),
            ("gem yank demo --version 2.0.0 -v 1.0.0", "--version", True),
            ("gem yank demo -v 1.0.0 --version 1.0.0", "--version", False),
            ("docker --context prod -c dev push repo/img:1.0.0", "--context", True),
            ("docker -c dev --context prod push repo/img:1.0.0", "--context", True),
            ("docker --context prod -c prod push repo/img:1.0.0", "--context", False),
            ("docker --host tcp://a -H tcp://b push repo/img:1.0.0", "--host", True),
            ("docker --host tcp://a -H tcp://a push repo/img:1.0.0", "--host", False),
            ("twine upload -r private --repository other dist/x.tar.gz", "--repository", True),
            ("twine upload --repository other -r private dist/x.tar.gz", "--repository", True),
            ("twine upload -r private --repository private dist/x.tar.gz", "--repository", False),
            ("cargo publish -j 1 --jobs 2", "--jobs", True),
            ("cargo publish --jobs 2 -j 1", "--jobs", True),
            ("cargo publish -j 1 --jobs 1", "--jobs", False),
            ("npm --registry a.example --registry b.example publish", "--registry", True),
            ("npm -w a publish --workspace b", "--workspace", True),
            ("npm -w a publish --workspace a", "--workspace", False),
        ]
        for command, canonical_key, is_conflict in rows:
            with self.subTest(command=command):
                router, heavy = self.classify_action(command)
                self.assertEqual(router, heavy, command)
                conflicts_key = (
                    "gh_conflicts" if command.startswith("gh ") else "registry_conflicts"
                )
                self.assertEqual(
                    (router or {}).get(conflicts_key) or [],
                    (heavy or {}).get(conflicts_key) or [],
                    command,
                )
                conflicts = (router or {}).get(conflicts_key) or []
                if is_conflict:
                    self.assertEqual(conflicts, [canonical_key], command)
                else:
                    self.assertEqual(conflicts, [], command)
                values = (router or {}).get("registry_values") or {}
                for key in values:
                    self.assertNotIn(
                        key, {"-v", "-c", "-H", "-r", "-j", "-w"}, command
                    )


class NpmEnvConfigSelectorTests(Phase4Harness):
    """R8 P1-I: npm exposes its whole config surface as npm_config_*
    environment variables (case-insensitive) — the target-affecting
    allowlist (userconfig/prefix/workspace/workspaces) joins registry.
    userconfig is the controlled deny (never read); prefix/workspace
    resolve the effective source; workspaces=true is the multi-target
    envelope; conflicts/empty/interpolated values are undetermined."""

    def _npm_authorized(self) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": "authorized-pkg", "version": "1.0.0"}),
            encoding="utf-8",
        )
        self.activate()
        self.prompt("请发布 npm 包")

    def test_userconfig_env_is_the_controlled_deny(self) -> None:
        self._npm_authorized()
        for command in (
            "npm_config_userconfig=/tmp/evil.npmrc npm publish",
            "NPM_CONFIG_USERCONFIG=/tmp/evil.npmrc npm publish",
            "env npm_config_userconfig=/tmp/evil.npmrc npm publish",
            "npm publish --userconfig=/tmp/evil.npmrc",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_prefix_env_resolves_the_effective_source(self) -> None:
        self._npm_authorized()
        other = self.project / "packages" / "other"
        other.mkdir(parents=True)
        (other / "package.json").write_text(
            json.dumps({"name": "other-pkg", "version": "2.0.0"}),
            encoding="utf-8",
        )
        for command in (
            "npm_config_prefix=packages/other npm publish",
            "NPM_CONFIG_PREFIX=packages/other npm publish",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)
        # The bound source through the same selector is no drift.
        self.assertEqual(
            self.decision("npm_config_prefix=. npm publish"), ("allow", "")
        )

    def test_workspace_env_resolves_the_effective_source(self) -> None:
        self._npm_authorized()
        other = self.project / "other"
        other.mkdir()
        (other / "package.json").write_text(
            json.dumps({"name": "other-pkg", "version": "2.0.0"}),
            encoding="utf-8",
        )
        for command in (
            "npm_config_workspace=other npm publish",
            "NPM_CONFIG_WORKSPACE=other npm publish",
        ):
            with self.subTest(command=command):
                permission, _ = self.decision(command)
                self.assertEqual(permission, "deny", command)

    def test_workspaces_true_is_the_multi_target_envelope(self) -> None:
        self._npm_authorized()
        state = cg_actions.classify_pre_tool_state(
            "shell", {"command": "npm_config_workspaces=true npm publish"}
        )
        self.assertEqual(state, cg_actions.STATE_AMBIGUOUS_CANDIDATE)
        state = cg_actions.classify_pre_tool_state(
            "shell", {"command": "NPM_CONFIG_WORKSPACES=1 npm publish"}
        )
        self.assertEqual(state, cg_actions.STATE_AMBIGUOUS_CANDIDATE)
        # The explicit false spelling disables the multi-target mode.
        self.assertEqual(
            cg_actions.classify_pre_tool_state(
                "shell", {"command": "npm --workspaces=false publish"}
            ),
            cg_actions.STATE_CANDIDATE,
        )

    def test_selector_conflicts_and_empty_values_deny(self) -> None:
        self._npm_authorized()
        for command in (
            "npm_config_registry=https://a.example NPM_CONFIG_REGISTRY=https://b.example npm publish",
            "npm_config_registry= npm publish",
            "npm publish --registry=",
            "npm publish --registry",
            "npm --registry a.example --registry b.example publish",
            "npm_config_prefix= npm publish",
        ):
            with self.subTest(command=command):
                permission, reason = self.decision(command)
                self.assertEqual(permission, "deny", command)
                self.assertTrue(reason, command)

    def test_cli_option_wins_over_env_but_env_conflict_still_denies(self) -> None:
        self._npm_authorized()
        # CLI registry beats the env registry (documented npm precedence):
        # the private CLI value drifts and denies.
        permission, _ = self.decision(
            "NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ npm publish --registry https://private.example"
        )
        self.assertEqual(permission, "deny")


if __name__ == "__main__":
    unittest.main()
