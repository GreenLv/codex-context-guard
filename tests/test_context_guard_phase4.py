#!/usr/bin/env python3
"""Phase-4 conformance under the 0.13 responsibility boundary: profiles,
position-aware classifier, release-contract enforcement, and the retired
default authorization gate.

0.13 layer transfer (AUTHORIZATION RETIREMENT): root-user natural-language
authorization is owned by the executing agent, the repository rules, and
the host permission system. The Guard no longer parses authorization
statements into enforcement facts, mints work-unit authorization records,
or enforces prepared-source/expected-commit chains: standard/strict
PreToolUse returns the plain empty object for every candidate, and
UserPromptSubmit/PostToolUse create no ``authorizations`` or
``commit_context`` facts. Authorization records migrated from pre-0.13
state carry ``participation: "historical"`` and never block. The tables in
this module that used to pin the removed default-deny gate now pin what
still exists in 0.13:

* profiles — standard/strict perform NO action gating; observe computes
  and records the would-be release decision without denying; release
  (declared via "context-guard release" or an adopted contract) fails
  closed for tier-A candidates without an exact unexpired action-ticket/v1
  from the adopted repository-release contract, denies compound remote
  mutations and the declared-unsupported gem push surface, and denies
  unresolvable targets; off/inactive perform no action gating at all, and
  corrupt state only denies where release obligations exist;
* classifier — real executable positions, subcommands, and effects; echo/
  printf/rg/grep/quoted/doc text and --dry-run/--check forms never gate;
  adversarial matrix (compound, env/wrapper, quoting, option order, alias
  ambiguity, unknown remote mutation tools, argument runners); detection
  is unchanged, only enforcement moved;
* target identity — the tier-A canonicalization tables (registry endpoints,
  gh repo regions/aliases, docker/twine/gem identities, MCP provenance)
  keep asserting their exact resolved targets through the classifier and
  the release target mapper, so release enforcement still resolves the
  same identities end to end;
* authorization retirement — statements (including negated, deletion, and
  quoted forms) never create Guard authorization facts; cross-unit replay
  is meaningless because no records exist; commit/push/tag/publish run
  with the plain empty object under standard/strict, and the pure
  cg_authority contract survives as a validator/historical-record
  vocabulary.
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

    def activate_release(self, session: str = "p4") -> None:
        """Declare the 0.13 release profile via the control prompt."""
        self.prompt("context-guard release", session=session)
        self.assertEqual(self.state(session)["mode"]["profile"], "release")

    def activate_observe(self, session: str = "p4") -> None:
        self.prompt("context-guard observe", session=session)
        self.assertEqual(self.state(session)["mode"]["profile"], "observe")

    def release_denies(self, command: str, session: str = "p4", **kwargs: object) -> str:
        """Tier-A candidate under release without a ticket: deny whose reason
        names the exact action-ticket/v1 requirement (target resolution ran
        end to end)."""
        permission, reason = self.decision(command, session=session, **kwargs)
        self.assertEqual(permission, "deny", command)
        self.assertIn("action-ticket/v1", reason, command)
        return reason

    def release_denies_unresolvable(
        self, command: str, session: str = "p4", **kwargs: object
    ) -> str:
        """Tier-A candidate whose canonical target is undetermined
        (conflicts, empty values, malformed references): the controlled
        unresolvable-target deny."""
        permission, reason = self.decision(command, session=session, **kwargs)
        self.assertEqual(permission, "deny", command)
        self.assertIn("could not be resolved", reason, command)
        return reason

    def concrete_target(self, command: str, *, tool: str = "shell") -> tuple[dict, dict]:
        """The production release target mapper: classify the command and
        resolve its normative tier-A target exactly as the release gate
        does (no profile, no state)."""
        payload = {
            "tool_name": tool,
            "tool_input": {"command": command},
            "cwd": str(self.project),
        }
        action = cg.classify_pre_tool_action(payload)
        self.assertIsNotNone(action, command)
        resolved = cg.resolve_internal_targets(str(self.project))
        mapped = cg._concrete_action_target(action, resolved, payload["tool_input"])
        self.assertIsNotNone(mapped, command)
        return mapped  # type: ignore[return-value]

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
        result = {}  # No retroactive Pre: unique readback is tested here.
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

    def test_standard_profile_allows_every_candidate_without_state_writes(self) -> None:
        """0.13 transfer: the default path has NO execution veto. A Guard
        allow is not authorization (INV-01) — the decision belongs to the
        executing agent and the host; detection still runs."""
        self.activate()
        before = json.dumps(self.state(), sort_keys=True)
        for command in (
            self.UNAUTHORIZED_TAG,
            "npm publish",
            "gh release create v1.2.3 --notes x",
            "git push origin main",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.decision(command), ("allow", ""))
                action = cg.classify_pre_tool_action(
                    {
                        "tool_name": "shell",
                        "tool_input": {"command": command},
                        "cwd": str(self.project),
                    }
                )
                self.assertIsNotNone(action, command)
        self.assertEqual(json.dumps(self.state(), sort_keys=True), before)

    def test_strict_profile_allows_and_never_implies_release(self) -> None:
        """0.13 transfer: strict is an enforcement posture without release
        facts; it never gates candidates and never implies the release
        contract."""
        self.prompt("context-guard strict")
        self.assertEqual(self.state()["mode"]["profile"], "strict")
        self.assertEqual(self.decision(self.UNAUTHORIZED_TAG), ("allow", ""))
        self.assertEqual(self.decision("npm publish"), ("allow", ""))
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
        # 0.13 transfer: an ACTIVE standard session whose private state
        # failed verification no longer fails closed for real mutations —
        # the removed default gate took its fail-closed guarantee with it.
        active_broken: dict = {
            "schema_version": 10,
            "integrity": {"status": "failed"},
            "mode": {"active": True, "manual_off": False},
        }
        self.assertEqual(
            cg.handle_pre_tool(Path(self.root / "nowhere"), active_broken, safe_payload), {}
        )
        self.assertEqual(
            cg.handle_pre_tool(Path(self.root / "nowhere"), active_broken, candidate_payload),
            {},
        )
        # Only the declared release profile keeps its fail-closed posture
        # over an unverifiable ledger: deny once, with one actionable reason.
        release_broken: dict = {
            "schema_version": 10,
            "integrity": {"status": "failed"},
            "mode": {"active": True, "manual_off": False, "profile": "release"},
        }
        self.assertEqual(
            cg.handle_pre_tool(Path(self.root / "nowhere"), release_broken, safe_payload), {}
        )
        result = cg.handle_pre_tool(
            Path(self.root / "nowhere"), release_broken, candidate_payload
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
    """FAM-AUTH-STATEMENT-TARGET-HINTS under the 0.13 responsibility
    boundary. AUTHORIZATION RETIREMENT: root-user natural-language
    authorization is owned by the executing agent and the host; the Guard
    no longer mints work-unit authorization records or enforces
    statement-bound targets. The statement parser survives as PURE text
    analysis, so this family keeps asserting the classification knowledge
    (action vocabulary, span projection, negation/deletion semantics) and
    the negative-case INTENT in its new form: statements — including
    negated, deletion, and multi-target forms — never create Guard
    authorization facts, and the tagged actions run ungated under
    standard/strict while release still fails them closed on ticket
    facts."""

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
        # Pure parser vocabulary (retained for requirement analysis only).
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
        """0.13 transfer: the historical canary false-deny input now runs
        with the plain empty object under the standard profile — the Guard
        neither asks nor blocks, and no authorization record exists."""
        self.activate()
        self.prompt(
            "我现在明确授权：请在本目录执行 git tag v9.9.9，只允许创建这一个 tag，"
            "然后报告 git tag -l 的结果并结束。"
        )
        self.assertEqual(self.bindings(), [])
        self.assertFalse(self.unit_record().get("authorizations"))
        self.assertEqual(self.decision("git tag v9.9.9"), ("allow", ""))

    def test_two_candidate_statement_still_asks_once(self) -> None:
        """0.13 transfer: two named versions used to force the ask-once
        deny; the ask now belongs to the executing agent. The statement
        creates no Guard records and the tag runs ungated, while the
        classifier still sees the two distinct target identities."""
        self.activate()
        self.prompt("创建 tag v1.2.3 和 v1.2.4。")
        self.assertFalse(self.unit_record().get("authorizations"))
        self.assertEqual(self.decision("git tag v1.2.3"), ("allow", ""))
        action = cg.classify_pre_tool_action(
            {"tool_name": "shell", "tool_input": {"command": "git tag v1.2.3"},
             "cwd": str(self.project)}
        )
        self.assertEqual(action["canonical_target_id"], "tag:v1.2.3")

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
        """0.13 transfer: a deletion prompt creates no authorization
        binding at all; under standard the tagged action runs ungated, and
        under release the fail-closed outcome is preserved through ticket
        facts instead of a binding mismatch."""
        self.activate()
        self.prompt(
            "删除本仓库的 tag v9.9.9。必须逐项落实。必须运行测试验证。"
        )
        self.assertFalse(self.unit_record().get("authorizations"))
        self.assertEqual(self.decision("git tag v9.9.9"), ("allow", ""))
        self.activate_release()
        self.release_denies("git tag v9.9.9")

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
        """0.13 transfer: the mixed clause's creation target lives only in
        the pure parser; no persisted binding exists, no tag is gated, and
        the classifier still separates the created target from the removed
        one."""
        self.activate()
        self.prompt("删除旧 tag v1.0.0 后创建 tag v2.0.0。必须逐项落实。必须运行测试验证。")
        self.assertFalse(self.unit_record().get("authorizations"))
        self.assertEqual(self.decision("git tag v2.0.0"), ("allow", ""))
        self.assertEqual(self.decision("git tag v1.0.0"), ("allow", ""))
        action = cg.classify_pre_tool_action(
            {"tool_name": "shell", "tool_input": {"command": "git tag v2.0.0"},
             "cwd": str(self.project)}
        )
        self.assertEqual(action["canonical_target_id"], "tag:v2.0.0")

    def test_english_mixed_order_binds_creation_target_end_to_end(self) -> None:
        """0.13 transfer (English form): statement → no Guard records, no
        enforcement; the target distinction is classifier-visible only."""
        self.activate()
        self.prompt("Create tag v2.0.0 after deleting tag v1.0.0. Must verify by running the tests.")
        self.assertFalse(self.unit_record().get("authorizations"))
        self.assertEqual(self.decision("git tag v2.0.0"), ("allow", ""))
        self.assertEqual(self.decision("git tag v1.0.0"), ("allow", ""))

    def test_tag_and_release_keep_distinct_targets_end_to_end(self) -> None:
        """0.13 transfer: the parser keeps the tag version and the sibling
        release version in their own hint dimensions (a release version
        never extends the tag candidate list); no records persist, and the
        sibling tag runs ungated under standard."""
        git_init(self.project)
        self._git(
            "remote", "add", "origin",
            "https://github.com/GreenLv/codex-context-guard.git",
        )
        self.activate()
        self.prompt(
            "创建 tag v1.2.3，并创建 release v2.0.0。必须运行测试验证。"
        )
        self.assertFalse(self.unit_record().get("authorizations"))
        parsed = cg.parse_authorization_statement(
            "创建 tag v1.2.3，并创建 release v2.0.0。"
        )
        self.assertIn("tag", parsed["actions"])
        self.assertEqual(parsed["hints"]["tags"], ["v1.2.3"])
        self.assertEqual(parsed["hints"]["versions"], ["v2.0.0"])
        self.assertEqual(self.decision("git tag v1.2.3"), ("allow", ""))
        self.assertEqual(self.decision("git tag v2.0.0"), ("allow", ""))


class AuthorizationUXTests(Phase4Harness):
    """0.13 authorization retirement of the old statement-driven UX
    family. AUTHORIZATION RETIREMENT: the executing agent + host own the
    authorization questions the Guard used to ask — the Guard no longer
    parses authorization statements into records, resolves targets from
    unique structured state into bindings, or enforces
    prepared-source/expected-commit chains. Every input family the old UX
    covered keeps a row here in its transferred form:

    * every statement shape (plain, negated, deletion, quoted, multi- and
      undetermined-target, registry) creates NO ``authorizations`` facts
      on any work unit — cross-unit replay is meaningless because no
      records exist;
    * commit/push/tag/publish sequences run end-to-end with the plain
      empty object under standard, including the historical canary
      no-false-deny inputs (python-edited commits, dirty trees, partial
      staging);
    * the Guard still DETECTS each semantic and its exact target
      identity, so the host's own decisioning keeps a deterministic
      vocabulary (tier, semantic id, canonical target);
    * where the old UX denied, the release profile still fails closed —
      now on ticket facts rather than bindings.
    """

    def _unique_push_upstream(self) -> None:
        self._git("branch", "-M", "main")
        self._git("remote", "add", "origin", str(self.root / "remote-origin"))
        self._git("update-ref", "refs/remotes/origin/main", "HEAD")
        self._git("branch", "--set-upstream-to=origin/main")

    def _classify(self, command: str) -> dict:
        action = cg.classify_pre_tool_action(
            {"tool_name": "shell", "tool_input": {"command": command},
             "cwd": str(self.project)}
        )
        self.assertIsNotNone(action, command)
        return action

    def _assert_no_authorization_facts(self) -> None:
        # 0.13: no unit carries an "authorizations" record at all.
        self.assertFalse(self.unit_record().get("authorizations"))

    def test_plain_push_statement_creates_no_records_and_push_runs(self) -> None:
        """0.13 transfer of the unique-upstream UX: statements bind
        nothing; the push runs ungated; the upstream resolution the Guard
        used to perform survives as a classifier target fact."""
        self._unique_push_upstream()
        self.activate()
        for prompt_text in ("推送。", "请推送本仓库。", "Push this repository."):
            with self.subTest(prompt=prompt_text):
                self.prompt(prompt_text)
                self._assert_no_authorization_facts()
                self.assertEqual(
                    self.decision("git push origin HEAD:refs/heads/main"),
                    ("allow", ""),
                )
                action = self._classify("git push origin HEAD:refs/heads/main")
                self.assertEqual(action["semantic_action_id"], "remote_push")
                self.assertEqual(action["tier"], "B")
                self.assertEqual(action["canonical_target_id"], "remote:origin:refs/heads/main")

    def test_plain_commit_push_chain_has_no_transition(self) -> None:
        """0.13 transfer of the commit→push chain: PostToolUse no longer
        advances any expected-commit transition, so the push needs no
        verified commit — it runs {} before and after a real commit, and
        no commit facts land on the unit."""
        self._unique_push_upstream()
        self._write("candidate.txt", "approved candidate\n")
        self.activate()
        self.prompt("提交 `candidate.txt` 并推送。")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("git push origin HEAD:refs/heads/main"), ("allow", ""))
        self._git("add", "candidate.txt")
        self._git("commit", "-q", "-m", "candidate")
        self._run_command("git commit -q -m candidate")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("git push origin HEAD:refs/heads/main"), ("allow", ""))

    def test_ambiguous_remote_selection_is_the_hosts_question(self) -> None:
        """0.13 transfer of requires_selection: with two remotes the Guard
        records nothing and defers silently; asking is the host's job."""
        self._git("branch", "-M", "main")
        for remote in ("origin", "upstream"):
            self._git("remote", "add", remote, str(self.root / remote))
        self.activate()
        self.prompt("推送。")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_inferred_push_target_does_not_expand_destination_or_action(self) -> None:
        """0.13 transfer: destination/action expansion was a binding
        concern; what remains is exact DETECTION — force pushes, branch
        deletes, other remotes, and other refs each carry their own
        semantic and canonical target, and all run ungated."""
        self._unique_push_upstream()
        self.activate()
        expectations = (
            ("git push upstream main", "remote_push", "remote:upstream:main"),
            ("git push origin HEAD:refs/heads/other", "remote_push", "remote:origin:refs/heads/other"),
            ("git push --force origin main", "force_push", "remote:origin:main"),
            ("git push --delete origin main", "remote_branch_delete", "remote:origin:main"),
        )
        for command, semantic, target_id in expectations:
            with self.subTest(command=command):
                action = self._classify(command)
                self.assertEqual(action["semantic_action_id"], semantic, command)
                self.assertEqual(action["canonical_target_id"], target_id, command)
                self.assertEqual(self.decision(command), ("allow", ""), command)
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_one_statement_authorizes_tag_without_restating_targets(self) -> None:
        """0.13 transfer: the tag statement creates no binding; the tag
        runs ungated; the classifier still resolves the tag identity that
        the old binding captured."""
        git_init(self.project)
        self.activate()
        self.prompt("请为本仓库创建标签 v1.0.0。必须运行测试验证。")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("git tag v1.0.0"), ("allow", ""))
        self.assertEqual(
            self._classify("git tag v1.0.0")["canonical_target_id"], "tag:v1.0.0"
        )

    def test_commit_and_push_statement_covers_push(self) -> None:
        """0.13 transfer of the implied-coverage UX: with the chain
        removed, commit and push both run {} immediately — including the
        empty-commit canary — and another remote stays a distinct
        classifier identity."""
        git_init(self.project)
        self.activate()
        self.prompt("空提交并推送 origin 的 main 分支。")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self._git("commit", "--allow-empty", "-q", "-m", "authorized work")
        self._run_command("git commit -q --allow-empty -m authorized work")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assertEqual(
            self._classify("git push upstream main")["canonical_target_id"],
            "remote:upstream:main",
        )

    def test_https_destination_and_refspec_authority(self) -> None:
        """0.13 transfer of the exact push UX (https destination +
        refspec): the full explicit push runs {} end to end; the
        destination/refspec distinctions are classifier identities."""
        git_init(self.project)
        self.activate()
        self.prompt(
            "空提交候选，并将生成的精确提交推送到 "
            "https://github.com/GreenLv/codex-context-guard.git 的 refs/heads/main。"
        )
        self._assert_no_authorization_facts()
        push_cmd = (
            "git push https://github.com/GreenLv/codex-context-guard.git "
            "HEAD:refs/heads/main"
        )
        self.assertEqual(self.decision(push_cmd), ("allow", ""))
        commit_cmd = "git commit -q --allow-empty -m candidate"
        self.assertEqual(self.pre(commit_cmd), {})
        self._git("commit", "-q", "--allow-empty", "-m", "candidate")
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": commit_cmd},
            tool_response={"exit_code": 0},
            tool_use_id="commit-authorized",
        )
        self.assertEqual(self.decision(push_cmd), ("allow", ""))
        self.assertEqual(
            self._classify(
                "git push https://github.com/GreenLv/codex-context-guard.git "
                "HEAD:refs/heads/other"
            )["canonical_target_id"],
            "remote:https://github.com/GreenLv/codex-context-guard.git:refs/heads/other",
        )

    def test_negated_statement_never_authorizes(self) -> None:
        """0.13 transfer: a negated statement creates no records; the tag
        is ungated under standard, and the release profile preserves the
        old fail-closed outcome through ticket facts."""
        self.activate()
        self.prompt("只运行本地检查，不创建 tag，不发布。")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("git tag v1.2.3"), ("allow", ""))
        self.activate_release()
        self.release_denies("git tag v1.2.3")

    def test_multiple_targets_in_one_statement_ask_once(self) -> None:
        """0.13 transfer of ask-once: two named tags used to deny with
        "Several targets match"; the statement now creates no records, and
        the two distinct canonical identities remain classifier-visible
        for the host that must ask."""
        self.activate()
        self.prompt("打 tag v1.2.3，另外也可能需要打 tag v2.0.0。")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("git tag v1.2.3"), ("allow", ""))
        self.assertEqual(
            self._classify("git tag v1.2.3")["canonical_target_id"], "tag:v1.2.3"
        )
        self.assertEqual(
            self._classify("git tag v2.0.0")["canonical_target_id"], "tag:v2.0.0"
        )

    def test_undetermined_target_asks_instead_of_silent_binding(self) -> None:
        """0.13 transfer of target_undetermined: a bare "git push" is a
        detected tier-B candidate whose remote stays the unknown sentinel
        in the canonical target; the Guard neither asks nor blocks."""
        self._git("branch", "-M", "main")
        self.activate()
        self.prompt("明确 push main，但没有指定 remote。")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("git push"), ("allow", ""))
        action = self._classify("git push")
        self.assertEqual(action["canonical_target_id"], "remote:unknown:main")

    def test_drift_after_authorization_asks(self) -> None:
        """0.13 transfer of drift: with bindings removed the Guard no
        longer compares a requested target against an authorized one —
        both versions run ungated under standard and are indistinguishable
        to the release gate (ticket facts only). Target comparison is the
        executing agent's responsibility."""
        self.activate()
        self.prompt("打 tag v9.9.9。")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("git tag v8.0.0"), ("allow", ""))
        self.activate_release()
        self.release_denies("git tag v8.0.0")
        self.release_denies("git tag v9.9.9")

    def test_force_push_needs_its_own_statement(self) -> None:
        """0.13 transfer of out-of-scope qualifiers: force push keeps its
        own semantic (never implied by a plain push) and — as a tier-B
        write — runs ungated in every profile; the qualifier boundary is
        now classifier vocabulary for the host."""
        self.activate()
        self.prompt("推送 origin 的 main 分支，但不要强制推送。")
        action = self._classify("git push -f origin main")
        self.assertEqual(action["semantic_action_id"], "force_push")
        self.assertEqual(action["tier"], "B")
        self.assertEqual(self.decision("git push -f origin main"), ("allow", ""))
        self.prompt("context-guard release")
        self.assertEqual(self.decision("git push -f origin main"), ("allow", ""))

    def test_remote_branch_delete_needs_exact_statement_targets(self) -> None:
        """0.13 transfer: remote branch deletes keep their own semantic
        and canonical target and run ungated under standard and release
        (tier B)."""
        self.activate()
        self.prompt("推送 origin 的 main 分支。")
        action = self._classify("git push --delete origin feature")
        self.assertEqual(action["semantic_action_id"], "remote_branch_delete")
        self.assertEqual(action["canonical_target_id"], "remote:origin:feature")
        self.assertEqual(self.decision("git push --delete origin feature"), ("allow", ""))
        self.prompt("context-guard release")
        self.assertEqual(self.decision("git push --delete origin feature"), ("allow", ""))

    def test_compound_remote_mutations_require_splitting(self) -> None:
        """0.13 transfer: compound remote mutations stay a distinct
        tier-A semantic; standard runs them ungated while release denies
        with the split-them reason — the only place the old "ask once for
        each" intent survives."""
        self.activate()
        self.prompt("推送 origin 的 main 分支。")
        compound = "git push origin main && git tag v1.2.3"
        self.assertEqual(self.decision(compound), ("allow", ""))
        self.assertEqual(
            self._classify(compound)["semantic_action_id"], "compound_remote_mutation"
        )
        self.prompt("context-guard release")
        permission, reason = self.decision(compound)
        self.assertEqual(permission, "deny")
        self.assertIn("separate", reason)

    def test_registry_publish_authorization(self) -> None:
        """0.13 transfer: the npm publish statement binds nothing; the
        publish runs ungated under standard; under release both the npm
        and the cargo publish fail closed on ticket facts, and the two
        keep distinct registry semantics."""
        (self.project / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0"}), encoding="utf-8"
        )
        self.activate()
        self.prompt("发布 npm 包。")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("npm publish"), ("allow", ""))
        self.assertEqual(
            self._classify("npm publish")["semantic_action_id"], "registry_npm_publish"
        )
        self.assertEqual(
            self._classify("cargo publish")["semantic_action_id"], "registry_cargo_publish"
        )
        self.activate_release()
        self.release_denies("npm publish")
        self.release_denies("cargo publish")

    def test_registry_publish_without_resolvable_version_asks_once(self) -> None:
        """0.13 transfer of the P1-1 counterexample B: without trusted
        metadata the mapped identity has NO package/version (never an
        unresolved==unresolved sentinel match); standard runs ungated and
        release still refuses on ticket facts."""
        self.activate()
        self.prompt("请发布 npm 包。")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("npm publish"), ("allow", ""))
        self.activate_release()
        _operation, target = self.concrete_target("npm publish")
        self.assertNotIn("package", target)
        self.assertNotIn("release_version", target)
        self.release_denies("npm publish")

    def test_cross_unit_authorization_cannot_replay(self) -> None:
        """0.13 transfer of cross-unit replay: replay is meaningless
        because NO unit ever carries authorization records — not even the
        unit the statement appeared in."""
        self.activate()
        self.prompt("打 tag v9.9.9。")
        self._assert_no_authorization_facts()
        self.prompt(" completely unrelated new task ")
        self._assert_no_authorization_facts()
        self.assertEqual(self.decision("git tag v9.9.9"), ("allow", ""))


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
        """0.13 transfer: the only PreToolUse deny left on this path is the
        release-profile gate — its reason stays single, bounded, and
        actionable."""
        self.activate_release()
        _, reason = self.decision("git tag v1.2.3")
        self.assertLessEqual(len(reason), 512)
        self.assertGreater(len(reason), 0)
        self.assertEqual(reason.count("\n"), 0)
        self.assertIn("action-ticket/v1", reason)


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
    """0.13 retirement of the P1-1 immutable-snapshot family. The
    authorization snapshot (bound target, head/branch/upstream context,
    expected commit transitions) no longer exists: UserPromptSubmit
    creates NO ``authorizations`` records and PostToolUse advances no
    commit chains. Every old drift/transition scenario keeps a row in its
    transferred form: statements plus material changes never create Guard
    facts and every action runs {} under standard; the release profile's
    fail-closed posture is independent of the removed snapshots. Migrated
    pre-0.13 records keep one residual contract — they are marked
    ``participation: "historical"`` and never block."""

    def _git_repo(self) -> None:
        git_init(self.project)

    def _steps(self, prompt, after=None):
        self.activate()
        self.prompt(prompt)
        if after is not None:
            after()
        return self

    def _run_command(self, command: str, exit_code: int = 0) -> dict:
        result = {}  # No retroactive Pre: unique readback is tested here.
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

    def bindings(self) -> list[dict]:
        return [
            record
            for record in (self.unit_record().get("authorizations") or [])
            if isinstance(record, dict) and record.get("state") == "active"
        ]

    def test_binding_persists_an_immutable_snapshot(self) -> None:
        """0.13 transfer: the snapshot does not exist — a tag statement
        leaves the work unit with NO ``authorizations`` records at all."""
        self._git_repo()
        self.activate()
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        self.assertEqual(self.bindings(), [])
        self.assertIsNone(self.unit_record().get("authorizations"))

    def test_no_drift_allows(self) -> None:
        self._git_repo()
        self.activate()
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        self.assertEqual(self.pre("git tag v1.2.3"), {})

    def test_unrelated_commit_material_drift_denies(self) -> None:
        """0.13 transfer: HEAD movement used to read as binding drift and
        deny; the Guard no longer binds or compares — the tag runs {}
        under standard, and release refuses it on ticket facts either
        way."""
        self._git_repo()
        self.activate()
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        self._git("commit", "--allow-empty", "-q", "-m", "unrelated")
        self.assertEqual(self.bindings(), [])
        self.assertEqual(self.decision("git tag v1.2.3"), ("allow", ""))
        self.activate_release()
        self.release_denies("git tag v1.2.3")

    def test_branch_drift_denies(self) -> None:
        """0.13 transfer: switching branches is no Guard business — the
        push runs {} with no binding to drift."""
        self._git_repo()
        self.activate()
        self.prompt("请推送 origin 的 main 分支。")
        self._git("checkout", "-q", "-b", "feature")
        self._assert_no_authorizations()
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def _assert_no_authorizations(self) -> None:
        self.assertIsNone(self.unit_record().get("authorizations"))

    def test_upstream_drift_denies(self) -> None:
        """0.13 transfer: re-pointing the upstream is invisible to the
        Guard — no upstream snapshot exists, the push runs {}."""
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
        elsewhere = self.root / "remote-elsewhere"
        elsewhere.mkdir()
        subprocess.run(
            ["git", "init", "-q", "--bare", str(elsewhere)], check=True, capture_output=True
        )
        self._git("remote", "add", "elsewhere", str(elsewhere))
        self._git("push", "-q", "elsewhere", "HEAD:refs/heads/elsewhere-main")
        self._git("branch", "--set-upstream-to=elsewhere/elsewhere-main")
        self._assert_no_authorizations()
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_commit_push_chain_expected_transition_allows(self) -> None:
        """0.13 transfer of the pending transition: there is no pending
        state and no advance — the push runs {} before and after the
        commit, with no commit facts recorded between."""
        self._git_repo()
        self.activate()
        self.prompt("空提交并推送 origin 的 main 分支。")
        self._assert_no_authorizations()
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self._git("commit", "--allow-empty", "-q", "-m", "authorized work")
        self._run_command("git commit -q --allow-empty -m authorized work")
        self._assert_no_authorizations()
        self.assertEqual(self.pre("git push origin main"), {})

    def test_failed_commit_never_advances_the_binding(self) -> None:
        """0.13 transfer: a failed commit produces no Guard-visible
        transition at all; the push is {} regardless of the outcome."""
        self._git_repo()
        self.activate()
        self.prompt("空提交并推送 origin 的 main 分支。")
        self._run_command("git commit -q --allow-empty -m work", exit_code=1)
        self._assert_no_authorizations()
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_ambiguous_commit_outcome_never_advances_the_binding(self) -> None:
        """0.13 transfer: the historical dirty-tree ambiguity (which the
        old chain resolved fail-closed) is now simply not Guard business —
        the push runs {} with nothing recorded."""
        self._git_repo()
        self.activate()
        self.prompt("提交并推送 origin 的 main 分支。")
        (self.project / "dirty.txt").write_text("x", encoding="utf-8")
        self._run_command("git commit -q --allow-empty -m work")
        self._assert_no_authorizations()
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_second_unrelated_commit_after_chain_advances_denies(self) -> None:
        """0.13 transfer: a second unrelated commit cannot "invalidate" a
        chain that no longer exists; the push stays {}."""
        self._git_repo()
        self.activate()
        self.prompt("空提交并推送 origin 的 main 分支。")
        self._git("commit", "--allow-empty", "-q", "-m", "authorized work")
        self._run_command("git commit -q --allow-empty -m authorized work")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self._git("commit", "--allow-empty", "-q", "-m", "second unrelated")
        self._assert_no_authorizations()
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_re_authorization_supersedes_the_previous_binding(self) -> None:
        """0.13 transfer of supersession: restating a request creates no
        second binding because it creates none at all; the tag runs {}
        across re-statements and HEAD movement."""
        self._git_repo()
        self.activate()
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        self._git("commit", "--allow-empty", "-q", "-m", "unrelated")
        self.assertEqual(self.decision("git tag v1.2.3"), ("allow", ""))
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        self._assert_no_authorizations()
        self.assertEqual(self.pre("git tag v1.2.3"), {})

    def test_migrated_authorization_records_are_historical_and_never_block(self) -> None:
        """The one residual snapshot contract (schema 9/10/11 → 12): a
        pre-0.13 ``authorizations`` record survives migration marked
        ``participation: "historical"``, still validates against the
        state schema, and never participates in any PreToolUse
        decision."""
        self._git_repo()
        self.activate()
        self.prompt("请为本仓库创建标签 v1.2.3。")
        state = self.state()
        unit_id = state["work_state"]["active_work_unit_id"]
        historical = {
            "id": "AUTH-0001",
            "actions": ["tag"],
            "binding": {
                "status": "authorized_unique",
                "target": {"repository": "legacy", "tag": "v0.9.0"},
                "work_unit_id": unit_id,
                "generation": 1,
            },
            "state": "active",
        }
        state["work_units"][0]["authorizations"] = [historical]
        # The live state is already schema 12; downgrade the marker so the
        # 9/10/11 -> 12 migration branch actually rewrites the record.
        state["schema_version"] = 11
        migrated = cg.migrate_state(state, {"session_id": "p4"})
        records = migrated["work_units"][0]["authorizations"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["participation"], "historical")
        # Historical participation never blocks: standard runs the tag
        # ungated and the release gate ignores the legacy binding.
        self.assertEqual(self.pre("git tag v9.9.9"), {})
        self.prompt("context-guard release")
        self.release_denies("git tag v9.9.9")


class PreparedCandidateRegressionTests(Phase4Harness):
    """Independent counterexamples A/B/C over REAL temp git repositories,
    replayed against the 0.13 boundary. AUTHORIZATION RETIREMENT: the
    prepared-candidate/expected-commit chain these counterexamples drove
    was removed — dirty trees, version bumps, and prepared-byte drift
    create no Guard facts and never change a decision. Each scenario keeps
    a row: the actions run {} under standard (the no-false-deny canaries
    of the old gate), the release profile still fails tier-A candidates
    closed on ticket facts, and no unit ever gains an ``authorizations``
    record."""

    def _write(self, name: str, content: str) -> None:
        (self.project / name).write_text(content, encoding="utf-8")

    def _assert_no_authorizations(self) -> None:
        self.assertIsNone(self.unit_record().get("authorizations"))

    def test_counterexample_a_dirty_head_is_now_bound_and_drift_visible(self) -> None:
        """0.13 transfer: the dirty-tree tag canary — the Guard neither
        binds HEAD nor compares it after commit B; both tags run {}
        under standard with no records, and release refuses either
        version on ticket facts alone."""
        self._write("base.txt", "base")
        self._git("add", "base.txt")
        self._git("commit", "-q", "-m", "A")
        self._write("dirty.txt", "uncommitted")  # dirty worktree at auth
        self.activate()
        self.prompt("请为当前已验证候选打 tag v1.2.3。")
        self._assert_no_authorizations()
        self.assertEqual(self.pre("git tag v1.2.3"), {})
        self._write("b.txt", "b")
        self._git("add", "b.txt")
        self._git("commit", "-q", "-m", "B")
        self.assertEqual(self.decision("git tag v1.2.3"), ("allow", ""))
        self._assert_no_authorizations()
        self.activate_release()
        self.release_denies("git tag v1.2.3")

    def test_counterexample_b_publish_without_metadata_asks_never_sentinel(self) -> None:
        """0.13 transfer: without trusted metadata the release target
        mapper leaves package/version ABSENT (never sentinel-compared);
        standard runs ungated and release refuses without a ticket."""
        self.activate()
        self.prompt("请发布 npm 包。")
        self._assert_no_authorizations()
        self.assertEqual(self.decision("npm publish"), ("allow", ""))
        self.activate_release()
        _operation, target = self.concrete_target("npm publish")
        self.assertNotIn("package", target)
        self.assertNotIn("release_version", target)
        self.release_denies("npm publish")

    def test_counterexample_b_version_bump_after_authorization_denies(self) -> None:
        """0.13 transfer: a version bump is not Guard-visible drift
        anymore — both publishes run {} under standard, and release
        refuses each on ticket facts (identically, by design)."""
        self._write("package.json", json.dumps({"name": "demo", "version": "1.0.0"}))
        self.activate()
        self.prompt("请发布 npm 包。")
        self._assert_no_authorizations()
        self.assertEqual(self.decision("npm publish"), ("allow", ""))
        self._write("package.json", json.dumps({"name": "demo", "version": "2.0.0"}))
        self.assertEqual(self.decision("npm publish"), ("allow", ""))
        self.activate_release()
        self.release_denies("npm publish")

    def test_counterexample_c_prepared_bytes_bind_the_transition(self) -> None:
        """0.13 transfer of counterexample C: prepared bytes bind nothing;
        committing drifted bytes produces no Guard-visible transition and
        the push runs {} — the agent owns candidate identity."""
        self._write("base.txt", "base")
        self._git("add", "base.txt")
        self._git("commit", "-q", "-m", "A")
        self._write("candidate.txt", "prepared bytes A")
        self.activate()
        self.prompt("提交 `candidate.txt` 并推送 origin 的 main 分支。")
        self._assert_no_authorizations()
        self._write("candidate.txt", "drifted bytes B")
        self._git("add", "candidate.txt")
        self._git("commit", "-q", "-m", "commit B")
        self._run_command("git commit -q -m commit B", exit_code=1)
        self._assert_no_authorizations()
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_counterexample_c_matching_prepared_bytes_advance_and_allow(self) -> None:
        self._write("base.txt", "base")
        self._git("add", "base.txt")
        self._git("commit", "-q", "-m", "A")
        self._write("candidate.txt", "prepared bytes A")
        self.activate()
        self.prompt("提交 `candidate.txt` 并推送 origin 的 main 分支。")
        self._git("add", "candidate.txt")
        self._git("commit", "-q", "-m", "commit prepared A")
        self._run_command("git commit -q -m commit prepared A")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_counterexample_c_partial_commit_never_advances(self) -> None:
        """0.13 transfer: partial staging cannot "fail to advance" a
        removed chain; the push runs {} and nothing is recorded."""
        self._write("base.txt", "base")
        self._git("add", "base.txt")
        self._git("commit", "-q", "-m", "A")
        self._write("prepared.txt", "prepared")
        self._write("extra.txt", "extra")
        self.activate()
        self.prompt("提交 `prepared.txt`、`extra.txt` 并推送 origin 的 main 分支。")
        self._git("add", "prepared.txt")
        self._git("commit", "-q", "-m", "partial")
        self._run_command("git commit -q -m partial")
        self._assert_no_authorizations()
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def _run_command(self, command: str, exit_code: int = 0) -> dict:
        result = {}  # No retroactive Pre: unique readback is tested here.
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": command},
            tool_response={"exit_code": exit_code},
            tool_use_id=f"post-{self.turn}",
        )
        return result


class AuthorizationValueClassMatrixTests(Phase4Harness):
    """Action × required-field × value-class table over the PURE authority
    contract, with a 0.13 differential against the production release gate.

    0.13 transfer: the production PreToolUse loop no longer evaluates
    authorization bindings — the release profile decides on ticket facts
    alone. The pure contract (validators, migrated historical records)
    still distinguishes exact from sentinel/drifted values, while the
    production gate fails closed for every tier-A candidate without a
    matching ticket regardless of value class."""

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

    def test_differential_pure_contract_vs_release_gate(self) -> None:
        """0.13 transfer of the old pure-vs-production-loop differential:
        the pure contract keeps classifying exact/drift/sentinel value
        classes deterministically, and the production release gate denies
        every tier-A candidate without a ticket — value-class independent,
        so no removed-authorization distinction can leak into outcomes."""
        self.activate_release()
        (self.project / "package.json").write_text(
            json.dumps({"name": "authorized-pkg", "version": "1.0.0"}), encoding="utf-8"
        )
        rows = (
            ("tag", "git tag v1.2.3", "git tag v9.9.9", "tag"),
            ("tag_push", "git push origin v1.2.3", "git push origin v9.9.9", "tag"),
            ("publish", "npm publish", "cargo publish", "tool"),
        )
        for action, exact_command, drifted_command, variant_key in rows:
            with self.subTest(action=action):
                exact = self._candidate(action, None, None)
                binding = cg_authority.bind_authorization(
                    [action], [exact], work_unit_id="WU1", generation=1,
                )
                pure = cg_authority.evaluate_action_authorization(
                    action, binding, [exact],
                    current_work_unit_id="WU1", authorization_generation=1,
                )
                self.assertEqual(
                    pure["status"], cg_authority.STATUS_AUTHORIZED_UNIQUE, action
                )
                drifted = dict(exact)
                drifted[variant_key] = {
                    "tag": "v9.9.9", "remote": "upstream", "tool": "cargo",
                }[variant_key]
                pure_drift = cg_authority.evaluate_action_authorization(
                    action, binding, [drifted],
                    current_work_unit_id="WU1", authorization_generation=1,
                )
                self.assertEqual(
                    pure_drift["status"], cg_authority.STATUS_DRIFTED, action
                )
                # The production gate is blind to both bindings: exact and
                # drifted candidates fail closed on the same missing-ticket
                # facts.
                self.assertIn("action-ticket/v1", self.release_denies(exact_command))
                self.assertIn("action-ticket/v1", self.release_denies(drifted_command))


class PreparedProjectionPlumbingTests(Phase4Harness):
    """0.13 retirement of the prepared-projection plumbing family. The
    projection (base HEAD + index/staged + unstaged + untracked →
    candidate identity) and the strict commit correspondence were removed
    with the default authorization path: PostToolUse is completion
    evidence only, records no ``commit_context``, and advances no chains.
    Every old row keeps a Git-plumbing scenario in transferred form — the
    commit/push sequence runs {} under standard whatever the staging
    shape — and the Windows untracked-mode contract still asserts through
    its surviving pure helper."""

    def _auth_chain(self, *paths: str) -> None:
        self.activate()
        self.prompt("提交 " + ("、".join(f"`{path}`" for path in paths) if paths else "空提交") + " 并推送 origin 的 main 分支。")
        self.assertIsNone(self.unit_record().get("authorizations"))

    def _commit_via_hooks(self, command: str, uid: str) -> None:
        # 0.13: PostToolUse records completion evidence only — no commit
        # facts land on the unit.
        self.dispatch(
            "PostToolUse",
            tool_name="shell",
            tool_input={"command": command},
            tool_response={"exit_code": 0},
            tool_use_id=uid,
        )
        self.assertIsNone(self.unit_record().get("authorizations"))

    def test_staged_deletion_runs_ungated_end_to_end(self) -> None:
        self._write("victim.txt", "victim")
        self._git("add", "victim.txt")
        self._git("commit", "-q", "-m", "add victim")
        self._git("rm", "-q", "victim.txt")  # staged deletion
        self._auth_chain("victim.txt")
        self._git("commit", "-q", "-m", "delete victim")
        self._commit_via_hooks("git commit -q -m delete victim", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_projection_invariant_across_staging_of_the_same_deletion(self) -> None:
        """0.13 transfer: the projection no longer exists, so the Guard's
        behavior cannot depend on staging provenance at all — worktree-
        deleted and staged-deleted shapes both run {} end to end."""
        self._write("gone.txt", "bye")
        self._git("add", "gone.txt")
        self._git("commit", "-q", "-m", "add gone")
        self._git("rm", "-q", "gone.txt")
        self._auth_chain("gone.txt")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self._git("add", "-u")
        self._commit_via_hooks("git add -u", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_rename_projects_as_delete_plus_add(self) -> None:
        self._write("old.txt", "content")
        self._git("add", "old.txt")
        self._git("commit", "-q", "-m", "add old")
        self._git("mv", "old.txt", "new.txt")
        self._auth_chain("old.txt", "new.txt")
        self._git("commit", "-q", "-m", "rename")
        self._commit_via_hooks("git commit -q -m rename", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_mode_change_is_projected_and_advances(self) -> None:
        self._write("run.sh", "#!/bin/sh\necho ok\n")
        self._git("add", "run.sh")
        self._git("commit", "-q", "-m", "add run.sh")
        self._git("update-index", "--chmod=+x", "run.sh")
        os.chmod(self.project / "run.sh", 0o755)
        self._auth_chain("run.sh")
        self._git("commit", "-q", "-m", "mode change")
        self._commit_via_hooks("git commit -q -m mode change", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    @unittest.skipUnless(os.name == "nt", "Windows Git mode regression")
    def test_windows_untracked_regular_file_projects_non_executable_mode(self) -> None:
        self._write("candidate.txt", "prepared bytes")
        self.assertEqual(
            cg._untracked_regular_git_mode(
                self.project / "candidate.txt", windows=True
            ),
            "100644",
        )

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
        """0.13 transfer: partial candidates used to block the advance;
        with the correspondence removed both commits (staged half, then
        the rest) leave the push {} — no baseline/parent bookkeeping."""
        self._write("a.txt", "A")
        self._git("add", "a.txt")
        self._git("commit", "-q", "-m", "base2")
        self._write("staged.txt", "staged content")
        self._git("add", "staged.txt")
        self._write("unstaged.txt", "unstaged content")
        self._auth_chain("staged.txt", "unstaged.txt")
        self._git("commit", "-q", "-m", "partial")
        self._commit_via_hooks("git commit -q -m partial", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self._git("add", "unstaged.txt")
        self._git("commit", "-q", "-m", "rest")
        self._commit_via_hooks("git commit -q -m rest", "c2")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_full_candidate_commit_after_partial_staging_allows(self) -> None:
        self._write("staged.txt", "staged content")
        self._git("add", "staged.txt")
        self._write("unstaged.txt", "unstaged content")
        self._auth_chain("staged.txt", "unstaged.txt")
        self._git("add", "unstaged.txt")
        self._git("commit", "-q", "-m", "everything")
        self._commit_via_hooks("git commit -q -m everything", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_extra_uncommitted_file_blocks_advance_until_committed(self) -> None:
        """0.13 transfer: an extra uncommitted file cannot block a chain
        that no longer exists; the push stays {} through every step."""
        self._write("prepared.txt", "prepared")
        self._write("extra.txt", "extra")
        self._auth_chain("prepared.txt")
        self._git("add", "extra.txt")
        self._git("commit", "-q", "-m", "extra only")
        self._commit_via_hooks("git commit -q -m extra only", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self._git("add", "prepared.txt")
        self._git("commit", "-q", "-m", "prepared")
        self._commit_via_hooks("git commit -q -m prepared", "c2")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_untracked_and_empty_commit_definitions(self) -> None:
        """0.13 transfer: the empty prepared projection and its
        allow-empty commit correspondence are gone; the empty-commit
        canary simply runs {} end to end."""
        self._auth_chain()
        self._git("commit", "-q", "--allow-empty", "-m", "empty")
        self._commit_via_hooks("git commit -q --allow-empty -m empty", "c1")
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))


class RegistryMonorepoTableTests(Phase4Harness):
    """P1-A: registry operations are distinct exact semantics; the release
    target mapper binds operation+tool+package+version+source and never
    collapses publish into unpublish/yank/deprecate or another package.
    0.13 transfer: the old statement→binding→allow/deny UX is gone; the
    same identities now assert through the classifier/target mapper plus
    the release-profile ticket gate."""

    def _metadata(self, name: str, version: str) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": name, "version": version}), encoding="utf-8"
        )

    def test_publish_authorization_binds_exact_registry_identity(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        operation, target = self.concrete_target("npm publish")
        self.assertEqual(operation, "publish")
        self.assertEqual(target["tool"], "npm")
        self.assertEqual(target["package"], "authorized-pkg")
        self.assertEqual(target["release_version"], "1.0.0")
        self.assertEqual(target["registry"], "registry.npmjs.org")
        self.activate_release()
        self.release_denies("npm publish")

    def test_publish_authorization_denies_reverse_mutations(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        self.activate_release()
        # 0.13 transfer: a publish statement no longer exists as Guard
        # state, and the reverse mutations are tier-A candidates of their
        # OWN semantic — never implied by publish in the pure vocabulary.
        self.assertEqual(
            cg_authority.evaluate_action_authorization(
                "unpublish",
                cg_authority.bind_authorization(
                    ["publish"], [self._publish_target()], work_unit_id="WU",
                    generation=1,
                ),
                [self._publish_target()],
                current_work_unit_id="WU", authorization_generation=1,
            )["status"],
            "out_of_scope",
        )
        for command, semantic in (
            ("npm unpublish authorized-pkg@1.0.0", "registry_npm_unpublish"),
            ("npm unpublish authorized-pkg@1.0.0 --force", "registry_npm_unpublish"),
            ("npm deprecate authorized-pkg@1.0.0 retired", "registry_npm_deprecate"),
            ("cargo yank authorized-pkg@1.0.0", "registry_cargo_yank"),
        ):
            with self.subTest(command=command):
                action = cg.classify_pre_tool_action(
                    {"tool_name": "shell", "tool_input": {"command": command},
                     "cwd": str(self.project)}
                )
                self.assertEqual(action["semantic_action_id"], semantic, command)
                self.assertEqual(action["tier"], "A", command)
                self.release_denies(command)

    def _publish_target(self) -> dict:
        return {
            "repository": "repo-x", "tool": "npm", "package": "authorized-pkg",
            "release_version": "1.0.0", "source": str(self.project),
            "registry": "registry.npmjs.org",
        }

    def test_publish_authorization_denies_other_package_sources(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        sibling = self.root / "other-package"
        sibling.mkdir()
        (sibling / "package.json").write_text(
            json.dumps({"name": "other-package", "version": "9.9.9"}),
            encoding="utf-8",
        )
        _operation, target = self.concrete_target("npm publish ../other-package")
        # The positional source resolves ITS OWN trusted metadata: a
        # distinct package identity, never collapsed into the root.
        self.assertEqual(target["package"], "other-package")
        self.assertEqual(target["release_version"], "9.9.9")
        self.activate_release()
        self.release_denies("npm publish ../other-package")

    def test_reverse_mutations_need_their_own_exact_statement(self) -> None:
        # 0.13 transfer: the exact spec identity is resolved in the tool's
        # own grammar (same mapper the release gate uses).
        _operation, target = self.concrete_target("npm unpublish authorized-pkg@1.0.0")
        self.assertEqual(target["package"], "authorized-pkg")
        self.assertEqual(target["release_version"], "1.0.0")
        self.activate_release()
        self.release_denies("npm unpublish authorized-pkg@1.0.0")
        _operation, other = self.concrete_target("npm unpublish other-pkg@1.0.0")
        self.assertEqual(other["package"], "other-pkg")

    def test_deprecate_and_yank_need_their_own_exact_statement(self) -> None:
        _operation, deprecate = self.concrete_target(
            "npm deprecate authorized-pkg@1.0.0 retired"
        )
        self.assertEqual(deprecate["package"], "authorized-pkg")
        self.assertEqual(deprecate["release_version"], "1.0.0")
        self.activate_release()
        self.release_denies("npm deprecate authorized-pkg@1.0.0 retired")
        _operation, yank = self.concrete_target("cargo yank authorized-pkg@1.0.0")
        self.assertEqual(yank["package"], "authorized-pkg")
        self.release_denies("cargo yank authorized-pkg@1.0.0")

    def test_publish_tarball_source_must_match_the_bound_source(self) -> None:
        self._metadata("authorized-pkg", "1.0.0")
        _operation, root_target = self.concrete_target("npm publish")
        _operation, tarball = self.concrete_target("npm publish /tmp/anywhere/pkg-9.9.9.tgz")
        self.assertEqual(tarball["source"], "/tmp/anywhere/pkg-9.9.9.tgz")
        self.assertNotEqual(tarball["source"], root_target["source"])
        self.activate_release()
        self.release_denies("npm publish /tmp/anywhere/pkg-9.9.9.tgz")

    def test_mcp_registry_methods_do_not_collapse(self) -> None:
        self.activate_release()
        # A publish-identity MCP payload on a REVERSE method stays its own
        # gated candidate; under release it fails closed on ticket facts.
        action = cg.classify_pre_tool_action(
            {"tool_name": "mcp__pypi__yank_package",
             "tool_input": {"tool": "pypi", "package": "x", "version": "1"},
             "cwd": str(self.project)}
        )
        self.assertEqual(action["semantic_action_id"], "registry_yank_package")
        permission, _reason = self.decision(
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
        _operation, target = self.concrete_target("npm publish")
        self.assertEqual(target["registry"], "registry.npmjs.org")
        self.assertEqual(target["package"], "authorized-pkg")
        self.assertEqual(target["release_version"], "1.0.0")
        self.assertEqual(target["tool"], "npm")
        self.activate_release()
        self.release_denies("npm publish")


class RegistryOptionGrammarTests(Phase4Harness):
    """P1-B/P1-C: supported-CLI option grammar is parsed for the
    subcommand, option values are never sources, unknown pre-subcommand
    options are the bounded envelope, and none of it bypasses gating."""

    def _metadata(self, name: str, version: str) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": name, "version": version}), encoding="utf-8"
        )

    def test_option_first_registry_forms_never_bypass(self) -> None:
        """0.13 transfer: option-first forms stay detected tier-A
        candidates (never silently safe), and the release profile fails
        each of them closed on ticket facts — the option grammar cannot
        bypass either detection or the release gate."""
        self._metadata("authorized-pkg", "1.0.0")
        self.activate_release()
        for command in (
            "npm --workspace packages/other publish",
            "npm --workspace=packages/other publish",
            "npm -w packages/other publish",
            "cargo --config $CONFIG publish",
            "docker --context other push img",
            "gh --repo o/r release create v1",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    cg.classify_pre_tool_state("shell", {"command": command}),
                    cg_actions.STATE_CANDIDATE,
                    command,
                )
                self.release_denies(command)

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
        # 0.13 transfer: the registry URL is an option value, not the
        # publish source — the effective source stays the bound root (no
        # source drift), while the registry ENDPOINT carries the named
        # non-default dimension.
        _operation, target = self.concrete_target(
            "npm publish --registry https://registry.example"
        )
        self.assertEqual(target["source"], os.path.abspath(str(self.project)))
        self.assertEqual(target["registry"], "registry.npmjs.org|--registry=registry.example")
        self.activate_release()
        self.release_denies("npm publish --registry https://registry.example")

    def test_registry_endpoint_drift_denies(self) -> None:
        """P1-3: --registry changes the remote registry endpoint; that is
        part of the canonical identity. 0.13 transfer: the drift is a named
        identity component and the release gate denies without a ticket."""
        self._metadata("authorized-pkg", "1.0.0")
        _operation, bound = self.concrete_target("npm publish")
        self.assertEqual(bound["registry"], "registry.npmjs.org")
        _operation, drifted = self.concrete_target("npm publish --registry https://private.example")
        self.assertEqual(
            drifted["registry"], "registry.npmjs.org|--registry=private.example"
        )
        self.activate_release()
        self.release_denies("npm publish --registry https://private.example")

    def test_workspace_selector_resolves_the_effective_source(self) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"name": "root-pkg", "version": "1.0.0"}), encoding="utf-8"
        )
        workspace = self.project / "packages" / "other"
        workspace.mkdir(parents=True)
        (workspace / "package.json").write_text(
            json.dumps({"name": "other-pkg", "version": "2.0.0"}), encoding="utf-8"
        )
        self.activate_release()
        # 0.13 transfer: the workspace selector resolves the effective
        # source metadata — other-pkg@2.0.0 stays a distinct identity from
        # the root package, and release fails it closed.
        _operation, root_target = self.concrete_target("npm publish")
        self.assertEqual(root_target["package"], "root-pkg")
        self.assertEqual(root_target["release_version"], "1.0.0")
        for command in (
            "npm --workspace packages/other publish",
            "npm --workspace=packages/other publish",
            "npm publish --workspace packages/other",
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertEqual(target["package"], "other-pkg", command)
                self.assertEqual(target["release_version"], "2.0.0", command)
                self.release_denies(command)

    def test_dry_run_false_is_not_a_simulation(self) -> None:
        """0.13 transfer: --dry-run=false is a real candidate (the release
        gate denies it without a ticket); --dry-run stays a silent
        simulation in every profile."""
        self._metadata("authorized-pkg", "1.0.0")
        self.activate_release()
        self.assertEqual(
            cg.classify_pre_tool_state(
                "shell", {"command": "npm publish --dry-run=false"}
            ),
            cg_actions.STATE_CANDIDATE,
        )
        self.release_denies("npm publish --dry-run=false")
        self.assertEqual(self.decision("npm publish --dry-run"), ("allow", ""))
        effects = cg.classify_shell_effects("npm publish --dry-run")
        self.assertIn("simulation", [row["effect"] for row in effects])

    def test_reverse_operations_with_pre_subcommand_options_still_gate(self) -> None:
        """0.13 transfer: pre-subcommand options never hide the reverse
        mutation — each stays a detected tier-A candidate with its own
        exact spec identity, failed closed by the release gate."""
        self._metadata("authorized-pkg", "1.0.0")
        self.activate_release()
        for command, semantic in (
            ("npm --workspace packages/other unpublish authorized-pkg@1.0.0",
             "registry_npm_unpublish"),
            ("npm --userconfig other.ini deprecate authorized-pkg@1.0.0 old",
             "registry_npm_deprecate"),
            ("cargo --config x yank authorized-pkg@1.0.0", "registry_cargo_yank"),
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    cg.classify_pre_tool_state("shell", {"command": command}),
                    cg_actions.STATE_CANDIDATE,
                    command,
                )
                action = cg.classify_pre_tool_action(
                    {"tool_name": "shell", "tool_input": {"command": command},
                     "cwd": str(self.project)}
                )
                self.assertEqual(action["semantic_action_id"], semantic, command)
                self.release_denies(command)
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
        """0.13 transfer: classification and release target resolution never
        throw on valid or malformed tarballs; each names its own effective
        source and the release gate fails both closed."""
        self._make_tarball("other-pkg.tgz", "tar-pkg", "2.0.0")
        (self.project / "bad.tgz").write_bytes(b"not a tarball at all")
        self.activate_release()
        for command, source_name in (
            ("npm publish ./other-pkg.tgz", "other-pkg.tgz"),
            ("npm publish ./bad.tgz", "bad.tgz"),
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertEqual(
                    target["source"],
                    os.path.abspath(str(self.project / source_name)),
                    command,
                )
                self.release_denies(command)

    def test_restated_tarball_source_reaches_the_binding(self) -> None:
        """0.13 transfer: an explicit tarball source restatement resolves to
        the tarball's own trusted metadata (package identity from THAT
        source, never the cwd root); without a ticket the release gate
        still refuses the publish."""
        self._make_tarball("other-pkg.tgz", "tar-pkg", "2.0.0")
        self.activate_release()
        _operation, target = self.concrete_target("npm publish ./other-pkg.tgz")
        self.assertEqual(
            target["source"], os.path.abspath(str(self.project / "other-pkg.tgz"))
        )
        self.assertEqual(target["package"], "tar-pkg")
        self.assertEqual(target["release_version"], "2.0.0")
        self.release_denies("npm publish ./other-pkg.tgz")
        # The root source stays a distinct identity from the tarball.
        self._write("package.json", json.dumps({"name": "root-pkg", "version": "1.0.0"}))
        _operation, root = self.concrete_target("npm publish")
        self.assertEqual(root["package"], "root-pkg")
        self.assertNotEqual(root["source"], target["source"])


class McpStructuredPublishTests(Phase4Harness):
    """P1-D: CLI and MCP publish share one canonical schema
    (operation+tool+package+version+source). 0.13 transfer: the old
    statement→binding→allow/deny UX is gone; the structured schema asserts
    through the release target mapper, and every drift plus the exact
    publish itself fails closed under the release profile without a
    ticket."""

    def _metadata(self) -> None:
        (self.project / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "1.0.0"\n', encoding="utf-8"
        )
        self._git("add", "pyproject.toml")
        self._git("commit", "-q", "-m", "prepared metadata")

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

    def _mcp_target(self, **fields) -> tuple[str, dict]:
        tool_input = {
            "tool": "pypi", "package": "demo", "version": "1.0.0",
            "source": str(self.project),
        }
        tool_input.update(fields)
        action = cg.classify_pre_tool_action(
            {"tool_name": "mcp__pypi__publish_package",
             "tool_input": tool_input, "cwd": str(self.project)}
        )
        resolved = cg.resolve_internal_targets(str(self.project))
        mapped = cg._concrete_action_target(action, resolved, tool_input)
        self.assertIsNotNone(mapped)
        return mapped

    def test_exact_structured_publish_allows(self) -> None:
        """0.13 transfer: the exact structured publish resolves to its
        declared identity; under release it fails closed without a ticket
        (the old allow came from the removed statement binding)."""
        self._metadata()
        operation, target = self._mcp_target()
        self.assertEqual(operation, "publish")
        self.assertEqual(target["tool"], "pypi")
        self.assertEqual(target["package"], "demo")
        self.assertEqual(target["release_version"], "1.0.0")
        self.assertEqual(target["source"], str(self.project))
        self.activate_release()
        result = self._mcp()
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn(
            "action-ticket/v1",
            result["hookSpecificOutput"]["permissionDecisionReason"],
        )

    def test_each_field_drift_denies(self) -> None:
        self._metadata()
        operation, exact = self._mcp_target()
        for fields, check in (
            ({"package": "other"}, lambda t: self.assertEqual(t["package"], "other")),
            ({"version": "2.0.0"}, lambda t: self.assertEqual(t["release_version"], "2.0.0")),
            ({"source": "/elsewhere"}, lambda t: self.assertEqual(t["source"], "/elsewhere")),
            # A cross-tool structured identity leaves the closed set: the
            # pypi adapter namespace can never satisfy a cargo publish.
            ({"tool": "cargo"}, lambda t: self.assertEqual(
                t["repository"], "untrusted-adapter:pypi")),
        ):
            with self.subTest(fields=fields):
                _operation, target = self._mcp_target(**fields)
                check(target)
                self.assertNotEqual(target, exact)
        self.activate_release()
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
        """0.13 transfer: reverse MCP methods keep their own semantics and
        fail closed under release even with a publish-shaped payload."""
        self._metadata()
        self.activate_release()
        for tool_name, semantic in (
            ("mcp__pypi__yank_package", "registry_yank_package"),
            ("mcp__pypi__unpublish_package", "registry_unpublish_package"),
            ("mcp__pypi__deprecate_package", "registry_deprecate_package"),
        ):
            with self.subTest(tool=tool_name):
                action = cg.classify_pre_tool_action(
                    {"tool_name": tool_name,
                     "tool_input": {"package": "demo", "version": "1.0.0",
                                    "tool": "pypi", "source": str(self.project)},
                     "cwd": str(self.project)}
                )
                self.assertEqual(action["semantic_action_id"], semantic)
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
        """0.13 transfer: a structured publish without a source never
        defaults the source to the cwd — the mapped identity stays
        incomplete, and the release gate refuses it."""
        self._metadata()
        _operation, target = self._mcp_target(
            source=None, version="1.0.0",
        )
        self.assertEqual(target.get("source") or "", "")
        self.activate_release()
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
        """0.13 transfer: the value forms are still FORCE semantics at
        detection — their own semantic id, never the plain push — and in
        0.13 they run ungated under every profile (the requesting side is
        the executing agent's responsibility)."""
        self._auth_plain_push()
        self.prompt("context-guard release")
        for command in (
            "git push --force-with-lease=refs/heads/master origin master",
            "git push --force-with-lease origin master",
            "git push --force-if-includes --force-with-lease origin master",
            "git push --force-if-includes origin master",
        ):
            with self.subTest(command=command):
                router = cg.classify_pre_tool_action(
                    {"tool_name": "shell", "tool_input": {"command": command},
                     "cwd": str(self.project)}
                )
                self.assertIsNotNone(router, command)
                self.assertEqual(router["semantic_action_id"], "force_push", command)
                self.assertEqual(self.decision(command), ("allow", ""), command)

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
    release tag; MCP structured release surfaces share the schema.
    0.13 transfer: target identities assert through the release target
    mapper, and every release surface fails closed under the release
    profile without a ticket."""

    def _repo_with_github_origin(self) -> None:
        self._git("remote", "add", "origin", "https://github.com/GreenLv/demo.git")

    def test_gh_repo_option_binds_the_real_target(self) -> None:
        """0.13 transfer: the inherited --repo value IS the canonical
        repository identity; origin's identity is distinct from it."""
        self._repo_with_github_origin()
        _requested, origin_target = self.concrete_target("gh release create v1.2.3 --notes x")
        self.assertEqual(origin_target["repository"], "github:greenlv/demo")
        self.assertEqual(origin_target["release_version"], "v1.2.3")
        for command, repo in (
            ("gh --repo o/r release create v1.2.3", "github:o/r"),
            ("gh -R o/r release create v1.2.3", "github:o/r"),
            ("gh --repo=o/r release create v1.2.3", "github:o/r"),
        ):
            with self.subTest(command=command):
                _requested, target = self.concrete_target(command)
                self.assertEqual(target["repository"], repo)
        self.activate_release()
        self.release_denies("gh release create v1.2.3 --notes x")
        self.release_denies("gh --repo o/r release create v1.2.3")

    def test_verb_tail_option_value_never_impersonates_the_tag(self) -> None:
        """0.13 transfer: a --title value in the verb tail is never the
        release version — the positional tag remains the identity."""
        self.activate_release()
        _requested, target = self.concrete_target("gh release create --title v1.2.3 v9.9.9")
        self.assertEqual(target["release_version"], "v9.9.9")
        _requested, plain = self.concrete_target("gh release create v9.9.9 --title x")
        self.assertEqual(plain["release_version"], "v9.9.9")
        self.release_denies("gh release create --title v1.2.3 v9.9.9")
        self.release_denies("gh release create v9.9.9 --title x")

    def test_mcp_github_release_exact_allow_and_drift_deny(self) -> None:
        """0.13 transfer: the exact structured release resolves to its
        identity; tag/repo drift produces distinct identities; every row
        fails closed under release without a ticket."""
        self._repo_with_github_origin()
        self.activate_release()

        def mcp_target(repository="GreenLv/demo", tag_name="v1.2.3"):
            tool_input = {"repository": repository, "tag_name": tag_name}
            action = cg.classify_pre_tool_action(
                {"tool_name": "mcp__github__create_release",
                 "tool_input": tool_input, "cwd": str(self.project)}
            )
            resolved = cg.resolve_internal_targets(str(self.project))
            return cg._concrete_action_target(action, resolved, tool_input)

        requested, exact = mcp_target()
        self.assertEqual(requested, "release")
        self.assertEqual(exact["repository"], "github:greenlv/demo")
        self.assertEqual(exact["release_version"], "v1.2.3")
        _requested, drifted = mcp_target(tag_name="v9.9.9")
        self.assertEqual(drifted["release_version"], "v9.9.9")
        _requested, drifted_repo = mcp_target(repository="Other/repo")
        self.assertEqual(drifted_repo["repository"], "github:other/repo")

        def mcp(repository="GreenLv/demo", tag_name="v1.2.3"):
            return self.dispatch(
                "PreToolUse",
                tool_name="mcp__github__create_release",
                tool_input={"repository": repository, "tag_name": tag_name},
                tool_use_id=f"mcp-{self.turn}",
            )

        self.assertEqual(
            mcp()["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertEqual(
            mcp(tag_name="v9.9.9")["hookSpecificOutput"]["permissionDecision"],
            "deny",
        )
        self.assertEqual(
            mcp(repository="Other/repo")["hookSpecificOutput"]["permissionDecision"],
            "deny",
        )

    def test_mcp_release_delete_needs_its_own_statement(self) -> None:
        """0.13 transfer: delete_release keeps its own release_delete
        semantics; under release it fails closed instead of inheriting a
        create authorization that no longer exists."""
        self._repo_with_github_origin()
        self.activate_release()
        tool_input = {"repository": "GreenLv/demo", "tag_name": "v1.2.3"}
        action = cg.classify_pre_tool_action(
            {"tool_name": "mcp__github__delete_release",
             "tool_input": tool_input, "cwd": str(self.project)}
        )
        resolved = cg.resolve_internal_targets(str(self.project))
        requested, target = cg._concrete_action_target(action, resolved, tool_input)
        self.assertEqual(requested, "release_delete")
        self.assertEqual(target["repository"], "github:greenlv/demo")
        result = self.dispatch(
            "PreToolUse",
            tool_name="mcp__github__delete_release",
            tool_input=tool_input,
            tool_use_id=f"mcp-{self.turn}",
        )
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn(
            "action-ticket/v1",
            result["hookSpecificOutput"]["permissionDecisionReason"],
        )

    def test_unknown_namespace_same_name_is_gated(self) -> None:
        """0.13 transfer: an unknown namespace with the exact method stays
        an unmatchable, untrusted identity — and under release it fails
        closed on ticket facts instead of passing silently."""
        self._repo_with_github_origin()
        self.activate_release()
        tool_input = {"repository": "GreenLv/demo", "tag_name": "v1.2.3"}
        action = cg.classify_pre_tool_action(
            {"tool_name": "mcp__unknownsvc__create_release",
             "tool_input": tool_input, "cwd": str(self.project)}
        )
        resolved = cg.resolve_internal_targets(str(self.project))
        _requested, target = cg._concrete_action_target(action, resolved, tool_input)
        self.assertEqual(target["repository"], "untrusted-adapter:unknownsvc")
        result = self.dispatch(
            "PreToolUse",
            tool_name="mcp__unknownsvc__create_release",
            tool_input=tool_input,
            tool_use_id=f"mcp-{self.turn}",
        )
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )

    def test_inherited_repo_options_after_the_verb_bind_the_real_target(self) -> None:
        """P1-C: -R/--repo is an INHERITED gh option — valid after the verb
        in separated and = forms — and its value is the real target repo.
        0.13 transfer: identities assert through the target mapper and the
        release gate refuses each without a ticket."""
        self._repo_with_github_origin()
        self.activate_release()
        _requested, origin_target = self.concrete_target("gh release create v1.2.3")
        self.assertEqual(origin_target["repository"], "github:greenlv/demo")
        for command in (
            "gh release create v1.2.3 --repo o/r",
            "gh release create v1.2.3 -R o/r",
            "gh release create --repo=o/r v1.2.3",
            "gh release create v1.2.3 --repo=o/r",
            "gh release upload v1.2.3 dist.tgz --repo o/r",
        ):
            with self.subTest(command=command):
                _requested, target = self.concrete_target(command)
                self.assertEqual(target["repository"], "github:o/r", command)
                self.release_denies(command)

    def test_target_option_enters_the_canonical_target(self) -> None:
        """P1-C: --target moves the commit an auto-created tag points at;
        the exact resolved commit is part of the release target — the same
        verified commit resolves exactly, another real commit resolves to a
        distinct identity, and an unresolvable value resolves to nothing
        (never ignored). 0.13 transfer: every variant fails closed under
        release."""
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
        self.activate_release()
        _requested, same = self.concrete_target(f"gh release create v1.2.3 --target {verified}")
        self.assertEqual(same["commit_sha256"], verified)
        _requested, other = self.concrete_target(f"gh release create v1.2.3 --target {side_sha}")
        self.assertEqual(other["commit_sha256"], side_sha)
        for command in (
            "gh release create v1.2.3 --target deadbeef",
            "gh release create --target deadbeef v1.2.3",
            "gh release create --target=deadbeef v1.2.3",
            "gh release create v1.2.3 --target '--reset'",
        ):
            with self.subTest(command=command):
                _requested, target = self.concrete_target(command)
                self.assertEqual(target["commit_sha256"], "", command)
                self.release_denies(command)
        self.release_denies(f"gh release create v1.2.3 --target {side_sha}")

    def test_github_env_selectors_bind_the_real_target(self) -> None:
        """P1-D: GH_REPO/GH_HOST are visible in the command and change the
        real remote target — they enter the canonical identity. The
        documented default host is not drift.
        0.13 transfer: identities assert through the target mapper; every
        variant still fails closed under release without a ticket."""
        self._repo_with_github_origin()
        self.activate_release()
        _requested, default_host = self.concrete_target(
            "GH_HOST=github.com gh release create v1.2.3"
        )
        self.assertEqual(default_host["repository"], "github:greenlv/demo")
        for command, repo in (
            ("GH_REPO=o/r gh release create v1.2.3", "github:o/r"),
            ("env GH_REPO=o/r gh release create v1.2.3", "github:o/r"),
            (
                "GH_REPO=o/r GH_HOST=enterprise.example gh release create v1.2.3",
                "github:enterprise.example/o/r",
            ),
        ):
            with self.subTest(command=command):
                _requested, target = self.concrete_target(command)
                self.assertEqual(target["repository"], repo, command)
                self.release_denies(command)
        # A non-default GH_HOST is a distinct identity that carries the
        # host component; it never collapses into the origin default.
        _requested, enterprise = self.concrete_target(
            "GH_HOST=enterprise.example gh release create v1.2.3"
        )
        self.assertIn("enterprise.example", enterprise["repository"])
        self.assertNotEqual(enterprise["repository"], "github:greenlv/demo")
        self.release_denies("GH_HOST=enterprise.example gh release create v1.2.3")


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
    """0.13 transfer: the would-be decision under observe is computed by the
    release gate over a DETACHED state copy, and the real release gate is
    the only path that may reserve the one-shot ticket. The removed
    authorization binding has no part in either."""

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

    def _release_session(self) -> Path:
        session_dir = self.root / "private" / "sessions" / "obs"
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir

    def _release_payload(self, tool_use_id: str) -> dict:
        return {
            "tool_name": "shell",
            "tool_input": {"command": "git tag v1.2.3"},
            "tool_use_id": tool_use_id,
            "cwd": str(self.project),
        }

    def _ticketed_action(self, payload: dict) -> dict:
        """The classifier's detection facts with the synthetic ticket's
        identity fields (repository/commit/input are environment facts the
        ledger was built against)."""
        action = cg.classify_pre_tool_action(payload)
        self.assertIsNotNone(action)
        self.assertEqual(action["semantic_action_id"], "release_tag_mutation")
        return {
            **action,
            "repository_id": "repo-x",
            "candidate_commit": "a" * 40,
            "release_version": "v1.2.3",
            "input_sha256": "d" * 64,
        }

    def test_observe_never_consumes_a_one_shot_ticket(self) -> None:
        state = self._state_with_ticket()
        result = cg._release_enforcement_decision(
            self._release_session(),
            state,
            self._release_payload("tool-obs"),
            self._ticketed_action(self._release_payload("tool-obs")),
            "release",
            dry_run=True,
        )
        self.assertEqual(result, {})
        self.assertEqual(state["execution"]["action_tickets"][0]["state"], "reserved")

    def test_enforcement_reserves_the_ticket_for_real(self) -> None:
        state = self._state_with_ticket()
        mocks = (
            # The minimal synthetic ledger intentionally skips the full
            # execution-state validation the expiry sweep performs.
            mock.patch.object(cg, "expire_execution_tickets", lambda *_a, **_k: None),
        )
        with mocks[0]:
            result = cg._release_enforcement_decision(
                self._release_session(),
                state,
                self._release_payload("tool-real"),
                self._ticketed_action(self._release_payload("tool-real")),
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

    def test_implied_coverage_through_the_pure_contract(self) -> None:
        """0.13 transfer: the pure authority vocabulary still owns implied
        coverage — a tag-push binding covers evaluating the plain tag
        action — but no production PreToolUse loop consumes it anymore;
        statements never create Guard enforcement facts."""
        statement = cg.parse_authorization_statement("创建并推送 tag v1.0.0 到 origin。")
        self.assertIsNotNone(statement)
        self.assertIn("tag_push", statement["actions"])
        self.assertIn("tag", statement["actions"])
        authority = cg._authority_module()
        # The deleted `_authorization_snapshot_targets` step used to project
        # the statement hints onto the REQUESTED action's own normative
        # fields; the pure contract keeps that shape.
        candidate = {
            "repository": "repo-x",
            "ref": "main",
            "commit_sha256": "a" * 40,
            "tag": "v1.0.0",
        }
        binding = authority.bind_authorization(
            ["tag"], [candidate], work_unit_id="WU0001", generation=1
        )
        result = authority.evaluate_action_authorization(
            "tag",
            binding,
            [candidate],
            current_work_unit_id="WU0001",
            authorization_generation=1,
        )
        self.assertEqual(result["status"], authority.STATUS_AUTHORIZED_UNIQUE)
        # Implied coverage: a tag_push binding still covers the plain tag
        # action in the pure vocabulary (out_of_scope only for unrelated
        # actions such as publish).
        implied = authority.bind_authorization(
            ["tag_push"],
            [{"repository": "repo-x", "remote": "origin", "tag": "v1.0.0"}],
            work_unit_id="WU0001", generation=1,
        )
        self.assertEqual(
            authority.evaluate_action_authorization(
                "tag_push", implied, [dict(candidate, remote="origin")],
                current_work_unit_id="WU0001", authorization_generation=1,
            )["status"],
            authority.STATUS_AUTHORIZED_UNIQUE,
        )
        self.assertEqual(
            authority.evaluate_action_authorization(
                "publish", implied, [candidate],
                current_work_unit_id="WU0001", authorization_generation=1,
            )["status"],
            authority.STATUS_OUT_OF_SCOPE,
        )


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
    tool names are unmatchable identities. 0.13 transfer: nothing is
    inherited from a statement anymore; the release target mapper marks
    every untrusted provenance explicitly and the release profile fails
    all of these surfaces closed without a ticket."""

    def _release_metadata(self) -> None:
        (self.project / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "1.0.0"\n', encoding="utf-8"
        )
        self._git("add", "pyproject.toml")
        self._git("commit", "-q", "-m", "prepared metadata")
        self.activate_release()

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

    def _mcp_target(self, namespace, method, **fields) -> tuple[str, dict]:
        tool_input = {
            "tool": "pypi", "package": "demo", "version": "1.0.0",
            "source": str(self.project),
        }
        tool_input.update(fields)
        action = cg.classify_pre_tool_action(
            {"tool_name": f"mcp__{namespace}__{method}",
             "tool_input": tool_input, "cwd": str(self.project)}
        )
        resolved = cg.resolve_internal_targets(str(self.project))
        return cg._concrete_action_target(action, resolved, tool_input)

    def test_cross_namespace_and_bare_tools_never_inherit(self) -> None:
        self._release_metadata()
        for namespace, expected_provenance in (
            ("unknownsvc", "untrusted-adapter:unknownsvc"),
            ("github", "untrusted-adapter:github"),
            ("npm", "untrusted-adapter:npm"),
        ):
            with self.subTest(namespace=namespace):
                _requested, target = self._mcp_target(namespace, "publish_package")
                self.assertEqual(target["repository"], expected_provenance)
        # A non-MCP bare tool name has no adapter namespace at all.
        _requested, bare = self._mcp_target("", "publish_package")
        self.assertEqual(bare["repository"], "untrusted-adapter:unnamed")
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
        self._release_metadata()
        _requested, target = self._mcp_target("npm", "publish_package", tool="pypi")
        self.assertEqual(target["repository"], "untrusted-adapter:npm")
        result = self._mcp(namespace="npm", tool="pypi")
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )

    def test_reverse_methods_cover_the_closed_set(self) -> None:
        """0.13 transfer: same payload, trusted namespace — every reverse
        mutation still fails closed under release; the untrusted namespace
        is an explicitly marked, distinct identity."""
        self._release_metadata()
        for method in ("yank_package", "unpublish_package", "deprecate_package"):
            with self.subTest(method=method):
                result = self._mcp(method=method)
                self.assertEqual(
                    result["hookSpecificOutput"]["permissionDecision"],
                    "deny",
                    method,
                )
        # The trusted adapter's yank identity is exact; an unknown
        # namespace with the SAME payload carries the untrusted marker.
        _requested, trusted = self._mcp_target("pypi", "yank_package")
        self.assertEqual(trusted["package"], "demo")
        _requested, untrusted = self._mcp_target("unknownsvc", "yank_package")
        self.assertEqual(untrusted["repository"], "untrusted-adapter:unknownsvc")
        self.assertEqual(
            self._mcp(
                namespace="unknownsvc", method="yank_package"
            )["hookSpecificOutput"]["permissionDecision"],
            "deny",
        )


class WindowsNonPosixQuoteBoundaryTests(Phase4Harness):
    """R3: native Windows quote spans never swallow real shell boundaries."""

    def test_trailing_backslash_before_double_quote_keeps_cmd_boundaries(self) -> None:
        operators = ("&", "&&", "|", "||")
        mutations = (
            ("git push origin main", "remote_push"),
            ("npm publish", "registry_npm_publish"),
        )
        for module in (cg_actions, cg):
            for operator in operators:
                for mutation, action_id in mutations:
                    command = f'echo "C:\\foo\\" {operator} {mutation}'
                    with self.subTest(
                        module=module.__name__,
                        operator=operator,
                        action_id=action_id,
                    ):
                        actions = module._shell_actions(command, posix=False)
                        self.assertEqual(
                            [action["semantic_action_id"] for action in actions],
                            [action_id],
                        )

    def test_same_backslash_quote_is_not_a_posix_boundary(self) -> None:
        command = 'echo "C:\\foo\\" & git push origin main'
        for module in (cg_actions, cg):
            with self.subTest(module=module.__name__):
                self.assertEqual(module._shell_actions(command, posix=True), [])

    def test_cmd_single_quotes_do_not_hide_a_real_boundary(self) -> None:
        command = "echo 'literal & git push origin main'"
        for module in (cg_actions, cg):
            with self.subTest(module=module.__name__):
                actions = module._shell_actions(command, posix=False)
                self.assertEqual(
                    [action["semantic_action_id"] for action in actions],
                    ["remote_push"],
                )

    def test_posix_single_quotes_and_windows_double_quotes_keep_literals_inert(
        self,
    ) -> None:
        cases = (
            (True, "echo 'literal & git push origin main'"),
            (False, 'echo "literal & git push origin main"'),
        )
        for module in (cg_actions, cg):
            for posix, command in cases:
                with self.subTest(
                    module=module.__name__, posix=posix, command=command
                ):
                    self.assertEqual(module._shell_actions(command, posix=posix), [])

    def test_hostile_inline_env_selector_remains_visible(self) -> None:
        command = (
            'npm_config_registry="https://evil.example; rm -rf /" npm publish'
        )
        for module in (cg_actions, cg):
            for posix in (False, True):
                with self.subTest(module=module.__name__, posix=posix):
                    actions = module._shell_actions(command, posix=posix)
                    self.assertEqual(
                        [action["semantic_action_id"] for action in actions],
                        ["registry_npm_publish"],
                    )
                    self.assertEqual(
                        actions[0]["registry_values"]["--registry"],
                        "https://evil.example; rm -rf /",
                    )

    def test_normal_non_mutations_and_powershell_literal_stay_inert(self) -> None:
        commands = (
            'echo "C:\\foo\\bar"',
            'echo "literal ; & && | || text"',
            "powershell -NoProfile -Command \"Write-Output 'literal & git push origin main'\"",
            "powershell -NoProfile -Command \"Write-Output 'it''s literal & git push origin main'\"",
        )
        for module in (cg_actions, cg):
            for command in commands:
                with self.subTest(module=module.__name__, command=command):
                    self.assertEqual(module._shell_actions(command, posix=False), [])

    def test_powershell_backslash_quote_keeps_real_boundary_visible(self) -> None:
        command = (
            "powershell -NoProfile -Command "
            "'Write-Output \"C:\\foo\\\"; git push origin main'"
        )
        for module in (cg_actions, cg):
            with self.subTest(module=module.__name__):
                actions = module._shell_actions(command, posix=False)
                self.assertEqual(
                    [action["semantic_action_id"] for action in actions],
                    ["remote_push"],
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
        """0.13 transfer: env registry spellings enter the canonical
        endpoint — the documented default is the same identity, a hostile
        value is a named drift component, and an empty value is
        unresolvable; release refuses the non-default rows."""
        self._npm_authorized()
        self.activate_release()
        for command in (
            "npm_config_registry=https://evil.example npm publish",
            "NPM_CONFIG_REGISTRY=https://evil.example npm publish",
            "env npm_config_registry=https://evil.example npm publish",
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertEqual(
                    target["registry"],
                    "registry.npmjs.org|--registry=evil.example",
                    command,
                )
                self.release_denies(command)
        # The documented default host is the SAME identity, in env
        # spelling too — and stays a real gated candidate without a ticket.
        _operation, default_env = self.concrete_target(
            "npm_config_registry=https://registry.npmjs.org/ npm publish"
        )
        self.assertEqual(default_env["registry"], "registry.npmjs.org")
        self.release_denies("npm_config_registry=https://registry.npmjs.org/ npm publish")
        # An EMPTY selector value cannot prove the endpoint: unresolvable.
        self.release_denies_unresolvable("npm_config_registry= npm publish")

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
        """0.13 transfer: a config-file selector cannot be resolved without
        reading it — the identity carries no registry component and the
        release profile refuses the publish."""
        self._npm_authorized()
        self.activate_release()
        for command in (
            "npm --userconfig /tmp/evil.npmrc publish",
            "npm publish --userconfig /tmp/evil.npmrc",
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertNotIn("registry", target, command)
                self.release_denies(command)

    def test_prefix_selector_resolves_the_effective_source(self) -> None:
        self._npm_authorized()
        other = self.project / "packages" / "other"
        other.mkdir(parents=True)
        (other / "package.json").write_text(
            json.dumps({"name": "other-pkg", "version": "2.0.0"}),
            encoding="utf-8",
        )
        self.activate_release()
        for command in (
            "npm --prefix packages/other publish",
            "npm publish --prefix packages/other",
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertEqual(target["package"], "other-pkg", command)
                self.assertEqual(target["release_version"], "2.0.0", command)
                self.release_denies(command)
        # The same prefix spelling resolves the bound root identity.
        _operation, root = self.concrete_target("npm --prefix . publish")
        self.assertEqual(root["package"], "authorized-pkg")
        self.release_denies("npm --prefix . publish")

    def test_cargo_registry_default_env_selector(self) -> None:
        """0.13 transfer: the default registry NAME (crates-io) resolves to
        the same crates.io identity; a custom registry name is a named
        drift component; release refuses both without a ticket."""
        (self.project / "Cargo.toml").write_text(
            '[package]\nname = "demo-crate"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        self.activate_release()
        _operation, drifted = self.concrete_target(
            "CARGO_REGISTRY_DEFAULT=my-registry cargo publish"
        )
        self.assertEqual(drifted["registry"], "crates.io|--registry=my-registry")
        self.release_denies("CARGO_REGISTRY_DEFAULT=my-registry cargo publish")
        _operation, default_name = self.concrete_target(
            "CARGO_REGISTRY_DEFAULT=crates-io cargo publish"
        )
        self.assertEqual(default_name["registry"], "crates.io")
        self.release_denies("CARGO_REGISTRY_DEFAULT=crates-io cargo publish")

    def test_hostile_selector_values_deny_without_throwing(self) -> None:
        """0.13 transfer: hostile selector values never throw — each is
        classified, resolved without executing anything, and refused by
        the release profile."""
        self._npm_authorized()
        self.activate_release()
        for command in (
            'npm_config_registry="https://evil.example; rm -rf /" npm publish',
            "npm_config_registry=https://user:pass@evil.example npm publish",
            "NPM_CONFIG_REGISTRY=$EVIL npm publish",
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertTrue(target.get("registry"), command)
                self.release_denies(command)


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
        """0.13 transfer: documented default spellings resolve to the SAME
        canonical registry identity (no false drift); each stays a real
        tier-A candidate that release refuses without a ticket."""
        self._npm_authorized()
        self.activate_release()
        for command in (
            "npm publish",
            "npm publish --registry https://registry.npmjs.org/",
            "npm publish --registry=https://registry.npmjs.org",
            "npm --registry https://registry.npmjs.org/ publish",
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertEqual(target["registry"], "registry.npmjs.org", command)
                self.release_denies(command)

    def test_non_default_registry_still_denies(self) -> None:
        self._npm_authorized()
        self.activate_release()
        for command in (
            "npm publish --registry https://private.example",
            "npm publish --registry https://registry.npmjs.org/legacy",
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertNotEqual(target["registry"], "registry.npmjs.org", command)
                self.release_denies(command)

    def test_cargo_default_registry_name_allows(self) -> None:
        """0.13 transfer: crates-io and the default endpoint are one
        identity; a custom name is a distinct one; both stay gated
        candidates refused by release without a ticket."""
        (self.project / "Cargo.toml").write_text(
            '[package]\nname = "demo-crate"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        self.activate_release()
        _operation, default_name = self.concrete_target("cargo publish --registry crates-io")
        self.assertEqual(default_name["registry"], "crates.io")
        self.release_denies("cargo publish --registry crates-io")
        _operation, custom = self.concrete_target("cargo publish --registry my-registry")
        self.assertNotEqual(custom["registry"], "crates.io")
        self.release_denies("cargo publish --registry my-registry")


class DeclaredSurfaceIdentityTests(Phase4Harness):
    """R7 P1-F: every declared mutation surface has a real canonical
    identity that the release target mapper resolves, or is a declared
    unsupported surface (gem push) whose deny IS the contract — never a
    claimed support with a false identity. 0.13 transfer: the old
    statement→binding→allow UX is gone; identities assert through the
    mapper and every surface fails closed under release without a
    ticket."""

    def test_docker_push_binds_the_image_reference(self) -> None:
        self.activate_release()
        _operation, target = self.concrete_target("docker push repo/img:1.0.0")
        self.assertEqual(target["tool"], "docker")
        self.assertEqual(target["package"], "repo/img")
        self.assertEqual(target["release_version"], "1.0.0")
        self.assertEqual(target["registry"], "docker.io")
        self.assertEqual(target["source"], "repo/img:1.0.0")
        self.release_denies("docker push repo/img:1.0.0")
        for command, package, version in (
            ("docker push repo/other:1.0.0", "repo/other", "1.0.0"),
            ("docker push repo/img:2.0.0", "repo/img", "2.0.0"),
            ("docker push ghcr.io/repo/img:1.0.0", "repo/img", "1.0.0"),
            ("docker --context other push repo/img:1.0.0", "repo/img", "1.0.0"),
        ):
            with self.subTest(command=command):
                _operation, drifted = self.concrete_target(command)
                self.assertEqual(drifted["package"], package, command)
                self.assertEqual(drifted["release_version"], version, command)
                self.release_denies(command)
        # No tag = EVERY tag of the repository: the version stays
        # undetermined in the identity, never defaulted.
        _operation, untagged = self.concrete_target("docker push repo/img")
        self.assertNotIn("release_version", untagged)
        self.release_denies("docker push repo/img")
        # Malformed reference: unresolvable target, deny, no throw.
        self.release_denies_unresolvable("docker push repo//img:1.0.0")

    def test_mcp_structured_docker_publish_reaches_allow(self) -> None:
        """0.13 transfer: the structured docker publish resolves to the
        image-reference identity (source folded from package:version);
        under release it fails closed without a ticket."""
        self.activate_release()
        tool_input = {"tool": "docker", "package": "repo/img", "version": "1.0.0"}
        action = cg.classify_pre_tool_action(
            {"tool_name": "mcp__docker__publish_package",
             "tool_input": tool_input, "cwd": str(self.project)}
        )
        resolved = cg.resolve_internal_targets(str(self.project))
        _requested, target = cg._concrete_action_target(action, resolved, tool_input)
        self.assertEqual(target["package"], "repo/img")
        self.assertEqual(target["release_version"], "1.0.0")
        self.assertEqual(target["source"], "repo/img:1.0.0")
        result = self.dispatch(
            "PreToolUse",
            tool_name="mcp__docker__publish_package",
            tool_input=tool_input,
            tool_use_id=f"mcp-{self.turn}",
        )
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )

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
        """0.13 transfer: the sdist's OWN trusted metadata is the bound
        identity; a drifted distribution file and a malformed archive stay
        distinct (never throwing), and release refuses each without a
        ticket."""
        self._make_sdist("dist/demo-1.0.0.tar.gz", "demo", "1.0.0")
        self.activate_release()
        _operation, target = self.concrete_target("twine upload dist/demo-1.0.0.tar.gz")
        self.assertEqual(target["package"], "demo")
        self.assertEqual(target["release_version"], "1.0.0")
        self.assertEqual(
            target["source"],
            os.path.abspath(str(self.project / "dist/demo-1.0.0.tar.gz")),
        )
        self.release_denies("twine upload dist/demo-1.0.0.tar.gz")
        # Drifted distribution file: a distinct identity.
        self._make_sdist("dist/other-2.0.0.tar.gz", "other", "2.0.0")
        _operation, drifted = self.concrete_target("twine upload dist/other-2.0.0.tar.gz")
        self.assertEqual(drifted["package"], "other")
        self.release_denies("twine upload dist/other-2.0.0.tar.gz")
        # Malformed archive: no throw, no identity.
        (self.project / "dist" / "bad.tar.gz").write_bytes(b"not a tarball")
        _operation, bad = self.concrete_target("twine upload dist/bad.tar.gz")
        self.assertNotIn("package", bad)
        self.release_denies("twine upload dist/bad.tar.gz")

    def test_gem_yank_binds_name_and_version(self) -> None:
        """0.13 transfer: both official flag positions resolve the one
        exact yank identity (tool gem, rubygems.org); a different name or
        version is a distinct identity; release refuses each without a
        ticket."""
        self.activate_release()
        for command in ("gem yank demo -v 1.0.0", "gem yank -v 1.0.0 demo"):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertEqual(target["tool"], "gem", command)
                self.assertEqual(target["package"], "demo", command)
                self.assertEqual(target["registry"], "rubygems.org", command)
                self.assertEqual(target["release_version"], "1.0.0", command)
                self.release_denies(command)
        for command, package, version in (
            ("gem yank other -v 1.0.0", "other", "1.0.0"),
            ("gem yank demo -v 2.0.0", "demo", "2.0.0"),
        ):
            with self.subTest(command=command):
                _operation, drifted = self.concrete_target(command)
                self.assertEqual(drifted["package"], package, command)
                self.assertEqual(drifted["release_version"], version, command)
                self.release_denies(command)

    def test_cargo_yank_supports_the_version_flag_forms(self) -> None:
        """0.13 transfer: @spec and both --version positions resolve the
        one crates.io identity; other packages/versions stay distinct;
        release refuses each without a ticket."""
        self.activate_release()
        for command in (
            "cargo yank demo@1.0.0",
            "cargo yank --version 1.0.0 demo",
            "cargo yank demo --version 1.0.0",
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertEqual(target["package"], "demo", command)
                self.assertEqual(target["release_version"], "1.0.0", command)
                self.assertEqual(target["registry"], "crates.io", command)
                self.release_denies(command)
        for command, package, version in (
            ("cargo yank other@1.0.0", "other", "1.0.0"),
            ("cargo yank --version 2.0.0 demo", "demo", "2.0.0"),
        ):
            with self.subTest(command=command):
                _operation, drifted = self.concrete_target(command)
                self.assertEqual(drifted["package"], package, command)
                self.assertEqual(drifted["release_version"], version, command)
                self.release_denies(command)

    def test_gem_push_is_a_declared_unsupported_surface(self) -> None:
        """gem push can never bind an exact identity (RubyGems metadata is
        a binary Marshal blob): the deny IS the contract for the release
        profile — and the message says so. 0.13 transfer: under
        standard/strict it now runs ungated; the release ceremony is where
        the declared refusal lives."""
        (self.project / "demo-1.0.0.gem").write_bytes(b"not really a gem")
        self.activate()
        self.assertEqual(self.decision("gem push demo-1.0.0.gem"), ("allow", ""))
        self.activate_release()
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
        # The structured gem method is a registry candidate on the closed
        # adapter path: still refused without a ticket.
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn(
            "action-ticket/v1",
            result["hookSpecificOutput"]["permissionDecisionReason"],
        )


class McpMethodClosedSetTests(Phase4Harness):
    """R8 P1-G: the raw mcp__<namespace>__<method> triple must agree on
    namespace, EXACT registered method, and structured tool identity.
    Near-miss method spellings (garbage prefix/suffix, wrong case, extra
    __-segments) stay gated candidates and are never silently safe.
    0.13 transfer: the old statement→binding→allow UX is gone; every
    structured surface — exact, near-miss, reverse — fails closed under
    the release profile without a ticket."""

    def _metadata(self) -> None:
        (self.project / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "1.0.0"\n', encoding="utf-8"
        )
        self._git("add", "pyproject.toml")
        self._git("commit", "-q", "-m", "prepared metadata")
        self.activate_release()

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
        """0.13 transfer: the exact trusted method still resolves the one
        declared identity; without a ticket the release profile refuses
        it (the old allow came from the removed statement binding)."""
        self._metadata()
        tool_input = {
            "tool": "pypi", "package": "demo", "version": "1.0.0",
            "source": str(self.project),
        }
        action = cg.classify_pre_tool_action(
            {"tool_name": "mcp__pypi__publish_package",
             "tool_input": tool_input, "cwd": str(self.project)}
        )
        resolved = cg.resolve_internal_targets(str(self.project))
        _requested, target = cg._concrete_action_target(action, resolved, tool_input)
        self.assertEqual(target["package"], "demo")
        self.assertEqual(target["release_version"], "1.0.0")
        result = self._mcp("mcp__pypi__publish_package")
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn(
            "action-ticket/v1",
            result["hookSpecificOutput"]["permissionDecisionReason"],
        )

    def test_near_miss_methods_never_inherit(self) -> None:
        """0.13 transfer: a near-miss is still a GATED candidate, never
        silently safe, and the release profile fails each one closed."""
        self._metadata()
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
        """0.13 transfer: near-miss github methods keep the untrusted
        provenance and the release profile refuses each one."""
        self._git("remote", "add", "origin", "https://github.com/GreenLv/demo.git")
        self._metadata()
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
        """0.13 transfer: the trusted reverse method and its near-miss /
        unknown-namespace variants all fail closed under release — no
        statement binding exists to inherit anymore."""
        self._metadata()
        result = self._mcp("mcp__pypi__yank_package")
        self.assertEqual(
            result["hookSpecificOutput"]["permissionDecision"], "deny"
        )
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
        """0.13 transfer: region-two inherited options bind the real target
        in the release target mapper; a drifted repo identity and the
        default-host pairing resolve distinctly, and release refuses every
        row without a ticket."""
        self._authorized()
        self.activate_release()
        _requested, origin = self.concrete_target("gh release create v1.2.3")
        self.assertEqual(origin["repository"], "github:greenlv/demo")
        for command, repo in (
            ("gh release --repo o/r create v1.2.3", "github:o/r"),
            ("gh release -R o/r create v1.2.3", "github:o/r"),
            ("gh release --repo=o/r create v1.2.3", "github:o/r"),
            ("gh release --repo o/r --hostname github.com create v1.2.3", "github:o/r"),
        ):
            with self.subTest(command=command):
                _requested, target = self.concrete_target(command)
                self.assertEqual(target["repository"], repo, command)
                self.release_denies(command)

    def test_default_host_spelling_is_no_drift(self) -> None:
        """0.13 transfer: the documented default host spelling is the SAME
        canonical identity as the bare OWNER/REPO origin."""
        self._authorized()
        for command in (
            "gh release create v1.2.3 --repo github.com/GreenLv/demo",
            "gh release --repo github.com/GreenLv/demo create v1.2.3",
            "GH_REPO=github.com/GreenLv/demo gh release create v1.2.3",
            "gh release create v1.2.3 --repo GreenLv/demo",
        ):
            with self.subTest(command=command):
                _requested, target = self.concrete_target(command)
                self.assertEqual(target["repository"], "github:greenlv/demo", command)

    def test_non_default_host_is_a_distinct_identity(self) -> None:
        """0.13 transfer: a non-default host enters the canonical identity
        (never collapsing into the origin default) and the release gate
        still refuses the row without a ticket."""
        self._authorized()
        self.activate_release()
        for command in (
            "gh release create v1.2.3 --repo enterprise.example/GreenLv/demo",
            "gh release create v1.2.3 --hostname enterprise.example",
            "GH_HOST=enterprise.example gh release create v1.2.3",
        ):
            with self.subTest(command=command):
                _requested, target = self.concrete_target(command)
                self.assertIn("enterprise.example", target["repository"], command)
                self.assertNotEqual(target["repository"], "github:greenlv/demo", command)
                self.release_denies(command)

    def test_missing_and_conflicting_values_deny(self) -> None:
        """0.13 transfer: missing values and conflicting repeats leave the
        canonical repository UNDETERMINED (empty — never last-wins), and
        the release profile fails every row closed."""
        self._authorized()
        self.activate_release()
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
                _requested, target = self.concrete_target(command)
                self.assertEqual(target["repository"], "", command)
                self.release_denies(command)

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
        """0.13 transfer: every cross-alias conflict leaves the canonical
        repository UNDETERMINED (empty) in the release target mapper, and
        the release profile fails each reproducer closed — in every legal
        region, spelling, and alias order."""
        self._authorized()
        self.activate_release()
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
                _requested, target = self.concrete_target(command)
                self.assertEqual(target["repository"], "", command)
                self.release_denies(command)

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
        """0.13 transfer: a missing or empty value on either alias is a
        conflict on the canonical --repo dimension — the repository stays
        undetermined and the release profile refuses the row."""
        self._authorized()
        self.activate_release()
        for command in (
            "gh release create v1.2.3 -R",
            "gh release create v1.2.3 --repo GreenLv/demo -R",
            "gh release create v1.2.3 --repo GreenLv/demo --repo=",
        ):
            with self.subTest(command=command):
                _requested, target = self.concrete_target(command)
                self.assertEqual(target["repository"], "", command)
                self.release_denies(command)

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

    def test_npm_workspace_regions_conflict_on_different_values(self) -> None:
        """0.13 transfer: same-value alias repeats resolve the same bound
        root identity; cross-alias different values conflict on the
        canonical --workspace dimension and fail closed (unresolvable
        target) under release."""
        self._npm_authorized()
        self.activate_release()
        for command in ("npm -w . publish", "npm -w . publish --workspace ."):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertEqual(target["package"], "authorized-pkg", command)
                self.release_denies(command)
        for command in (
            "npm -w packages/other publish --workspace .",
            "npm --workspace . publish -w packages/other",
            "npm -w=. publish --workspace=packages/other",
        ):
            with self.subTest(command=command):
                self.release_denies_unresolvable(command)

    def test_gem_version_aliases_conflict_on_different_values(self) -> None:
        """0.13 transfer: same value through BOTH aliases resolves the one
        exact yank identity; a different value through either spelling is
        the canonical --version conflict (unresolvable under release)."""
        self.activate_release()
        _operation, same = self.concrete_target("gem yank demo -v 1.0.0 --version 1.0.0")
        self.assertEqual(same["package"], "demo")
        self.assertEqual(same["release_version"], "1.0.0")
        self.assertEqual(same["registry"], "rubygems.org")
        self.release_denies("gem yank demo -v 1.0.0 --version 1.0.0")
        # The pre-fix false allow: the -v spelling carried the authorized
        # version while --version carried the drift (and the mirror).
        for command in (
            "gem yank demo -v 1.0.0 --version 2.0.0",
            "gem yank demo --version 2.0.0 -v 1.0.0",
            "gem yank demo --version 1.0.0 -v 2.0.0",
        ):
            with self.subTest(command=command):
                self.release_denies_unresolvable(command)

    def test_docker_and_twine_aliases_stay_canonical(self) -> None:
        """0.13 transfer: alias conflicts stay canonical in the release
        target mapper — different values are unresolvable, same values
        resolve the one identity (default context included)."""
        self.activate_release()
        for command in (
            "docker --context prod -c dev push repo/img:1.0.0",
            "docker -c dev --context prod push repo/img:1.0.0",
            "docker --host tcp://a -H tcp://b push repo/img:1.0.0",
        ):
            with self.subTest(command=command):
                self.release_denies_unresolvable(command)
        # The same value through both aliases is no conflict; the default
        # context spelling keeps the same canonical endpoint.
        _operation, docker = self.concrete_target(
            "docker --context default -c default push repo/img:1.0.0"
        )
        self.assertEqual(docker["registry"], "docker.io")
        self.assertEqual(docker["package"], "repo/img")
        self.release_denies("docker --context default -c default push repo/img:1.0.0")
        # twine: -r and --repository project the SAME canonical identity
        # (spelling-invariant), and a cross-alias conflict is unresolvable.
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
        _operation, twine = self.concrete_target(
            "twine upload -r pypi --repository pypi dist/demo-1.0.0.tar.gz"
        )
        self.assertEqual(twine["registry"], "pypi.org")
        self.release_denies(
            "twine upload -r pypi --repository pypi dist/demo-1.0.0.tar.gz"
        )
        for command in (
            "twine upload -r private --repository other dist/demo-1.0.0.tar.gz",
            "twine upload --repository other -r private dist/demo-1.0.0.tar.gz",
        ):
            with self.subTest(command=command):
                self.release_denies_unresolvable(command)

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
        """0.13 transfer: a userconfig selector (env or CLI) cannot prove
        the registry endpoint — the mapped identity carries NO registry
        component — and the release profile refuses every form."""
        self._npm_authorized()
        self.activate_release()
        for command in (
            "npm_config_userconfig=/tmp/evil.npmrc npm publish",
            "NPM_CONFIG_USERCONFIG=/tmp/evil.npmrc npm publish",
            "env npm_config_userconfig=/tmp/evil.npmrc npm publish",
            "npm publish --userconfig=/tmp/evil.npmrc",
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertNotIn("registry", target, command)
                self.release_denies(command)

    def test_prefix_env_resolves_the_effective_source(self) -> None:
        self._npm_authorized()
        other = self.project / "packages" / "other"
        other.mkdir(parents=True)
        (other / "package.json").write_text(
            json.dumps({"name": "other-pkg", "version": "2.0.0"}),
            encoding="utf-8",
        )
        self.activate_release()
        for command in (
            "npm_config_prefix=packages/other npm publish",
            "NPM_CONFIG_PREFIX=packages/other npm publish",
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertEqual(target["package"], "other-pkg", command)
                self.assertEqual(target["release_version"], "2.0.0", command)
                self.release_denies(command)
        # The bound source through the same selector is one identity.
        _operation, root = self.concrete_target("npm_config_prefix=. npm publish")
        self.assertEqual(root["package"], "authorized-pkg")
        self.release_denies("npm_config_prefix=. npm publish")

    def test_workspace_env_resolves_the_effective_source(self) -> None:
        self._npm_authorized()
        self.activate_release()
        for command in (
            "npm_config_workspace=other npm publish",
            "NPM_CONFIG_WORKSPACE=other npm publish",
        ):
            with self.subTest(command=command):
                _operation, target = self.concrete_target(command)
                self.assertEqual(
                    target["source"],
                    os.path.abspath(str(self.project / "other")),
                    command,
                )
                self.release_denies(command)

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
        """0.13 transfer: conflicting env spellings, empty explicit values,
        and missing option values make the affected dimension undetermined;
        the release profile fails each form closed with the unresolvable
        target deny."""
        self._npm_authorized()
        self.activate_release()
        for command in (
            "npm_config_registry=https://a.example NPM_CONFIG_REGISTRY=https://b.example npm publish",
            "npm_config_registry= npm publish",
            "npm publish --registry=",
            "npm publish --registry",
            "npm --registry a.example --registry b.example publish",
            "npm_config_prefix= npm publish",
        ):
            with self.subTest(command=command):
                self.release_denies_unresolvable(command)

    def test_cli_option_wins_over_env_but_env_conflict_still_denies(self) -> None:
        """0.13 transfer: the CLI registry beats the env registry
        (documented npm precedence) — the drift is the named non-default
        component and the release profile still refuses the publish."""
        self._npm_authorized()
        self.activate_release()
        _operation, target = self.concrete_target(
            "NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ npm publish --registry https://private.example"
        )
        self.assertEqual(
            target["registry"], "registry.npmjs.org|--registry=private.example"
        )
        self.release_denies(
            "NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ npm publish --registry https://private.example"
        )


if __name__ == "__main__":
    unittest.main()
