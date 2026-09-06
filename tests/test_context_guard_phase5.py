#!/usr/bin/env python3
"""Phase-5 conformance: Hook visibility — success paths are silent.

Frozen plan sections 4.4/4.5 and the Phase-5 scope of the 0.12 plan:

* hooks.json carries NO persistent ``statusMessage`` on any of the nine
  lifecycle events (UX-04: normal allow paths stay invisible);
* the PostToolUse success receipts for private proof registration and
  private turn-bound control staging return the plain empty object —
  no developer text enters the visible event stream on success;
* every failure, integrity, and deny surface keeps its existing visible
  contract: malformed staging still blocks with a bounded reason, a failed
  stage tool result still blocks, and the Stop-3.0 UserPromptSubmit
  completion instructions keep flowing;
* per the official Codex Hooks matcher contract (matcher = regex over
  tool_name and its aliases), the PreToolUse matcher is shrunk from "*"
  to exactly the surfaces the Phase-4 classifier can gate — the Bash
  shell/unified-exec alias, apply_patch with its Edit/Write aliases, all
  MCP names, and every bare mutation-method name — while PostToolUse
  keeps the match-everything wire for broad evidence collection. The
  expected matcher is DERIVED from the live classifier constants so the
  two can never drift.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import cg_actions  # noqa: E402

MODULE_PATH = REPO / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard_phase5", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)


def _load_hooks_config() -> dict:
    return json.loads(
        (REPO / "hooks" / "hooks.json").read_text(encoding="utf-8")
    )["hooks"]


# Official Codex Hooks matcher contract (learn.chatgpt.com/docs/hooks): the
# matcher is a regex over tool_name AND its aliases; shell/unified exec match
# as "Bash", apply_patch matches as "apply_patch", "Edit", or "Write" while
# the hook input still reports tool_name "apply_patch", MCP tools match by
# full name, and hosted tools (e.g. WebSearch) never reach tool hooks. These
# alias spellings therefore belong to the matcher domain even though the
# classifier itself only ever sees the reported tool_name.
PLATFORM_MATCHER_ALIASES = ("edit", "write")
_SUFFIX_FAMILIES = ("exec_command", "apply_patch")


def expected_pre_tool_matcher() -> str:
    """Derive the required PreToolUse matcher from live classifier constants.

    Exact gated names become anchored alternatives, the open ``*_exec_command``
    and ``*_apply_patch`` suffix families become prefix-open anchored
    alternatives, every registered MCP mutation marker becomes an unanchored
    containment alternative (bare method names are function tools the
    classifier gates by containment), and every MCP surface is passed through
    via the ``mcp__`` prefix so near-miss/case variants can never bypass."""
    sep = "[^a-z0-9]+"

    def spaced(name: str) -> str:
        return sep.join(name.split("_"))

    exact: list[str] = []
    suffix: list[str] = []
    for name in sorted(cg_actions.SHELL_TOOL_NAMES | cg_actions.APPLY_PATCH_TOOL_NAMES):
        tail = "_".join(name.split("_")[-2:])
        if tail in _SUFFIX_FAMILIES:
            token = spaced(tail)
            if token not in suffix:
                suffix.append(token)
        else:
            exact.append(spaced(name))
    exact.extend(sorted(PLATFORM_MATCHER_ALIASES))
    contains = [spaced(marker) for marker in sorted(cg_actions._MCP_MUTATION_MARKERS)]
    alternatives = (
        ["^(?:" + "|".join(exact) + ")$"]
        + [token + "$" for token in suffix]
        + contains
        + ["^mcp__"]
    )
    return "(?i)" + "|".join(alternatives)


# Official matcher ALIASES of the apply_patch surface: they must match the
# matcher so the hook fires, while the hook input reports tool_name
# "apply_patch" — which the classifier must keep gating.
PLATFORM_ALIAS_NAMES = (
    "Edit",
    "Write",
)

# Names the classifier gates (STATE_CANDIDATE / STATE_AMBIGUOUS_CANDIDATE):
# matcher MUST match all of them.
GATED_SURFACE_NAMES = (
    "Bash",
    "bash",
    "shell",
    "unified_exec",
    "unified-exec",
    "exec_command",
    "exec-command",
    "mcp_exec_command",
    "deploy_exec_command",
    "apply_patch",
    "Apply-Patch",
    "mcp_apply_patch",
    "tools.apply_patch",
    "mcp__pypi__publish_package",
    "mcp__GitHub__Create-Release",
    "create_release",
    "publish_package",
    "create-release",
    "unpublish_package",
    "yank.package.v1",
    "deprecate_package",
    "upload_release_asset",
    "MyPublish_Package_Tool",
)

# Every MCP surface passes the matcher (coordinator-mandated safety margin),
# but non-marker MCP tools stay SAFE at the router: matched, then silent.
MATCHED_SAFE_MCP_NAMES = (
    "mcp__filesystem__read_file",
    "mcp__codex_app__read_thread",
)

# Representative non-candidate names the shrunk matcher must NOT match, so
# ordinary read-only tools do not even spawn the hook.
UNMATCHED_READONLY_NAMES = (
    "Read",
    "WebSearch",
    "Glob",
    "Grep",
    "view",
    "fetch",
    "search",
    "update_plan",
    "todo_write",
    "read_thread",
    "list_releases",
    "note_edit",
    "bulk_edit",
)


class HooksConfigVisibilityTests(unittest.TestCase):
    """The persisted Hook configuration is the visibility contract."""

    def test_no_persistent_status_message_on_any_event(self) -> None:
        hooks = _load_hooks_config()
        carrying: list[str] = []
        for event, groups in hooks.items():
            for group in groups:
                for hook in group.get("hooks", []):
                    if isinstance(hook, dict) and hook.get("statusMessage"):
                        carrying.append(event)
        self.assertEqual(
            carrying,
            [],
            "persistent statusMessage text must not run on normal hook paths",
        )

    def test_nine_events_and_post_tool_matcher_unchanged(self) -> None:
        hooks = _load_hooks_config()
        self.assertEqual(
            set(hooks),
            {
                "UserPromptSubmit",
                "PreToolUse",
                "PostToolUse",
                "PreCompact",
                "SessionStart",
                "SubagentStart",
                "SubagentStop",
                "Stop",
                "SessionEnd",
            },
        )
        self.assertEqual(hooks["PreCompact"][0].get("matcher"), "manual|auto")
        self.assertEqual(hooks["SessionStart"][0].get("matcher"), "resume|compact")
        # Frozen plan 4.5: PostToolUse keeps broad coverage to collect
        # evidence; only PreToolUse is shrunk (4.4).
        self.assertEqual(hooks["PostToolUse"][0].get("matcher"), "*")

    def test_pre_tool_matcher_is_derived_from_the_classifier_domain(self) -> None:
        """Plan 4.4 with the official matcher contract: the PreToolUse
        matcher must cover EXACTLY the classifier's candidate domain plus
        the documented platform aliases, derived here from the live
        classifier constants so the matcher can never drift from what the
        classifier gates."""
        self.assertEqual(
            _load_hooks_config()["PreToolUse"][0].get("matcher"),
            expected_pre_tool_matcher(),
        )

    def test_pre_tool_matcher_behavioral_contract(self) -> None:
        matcher = _load_hooks_config()["PreToolUse"][0].get("matcher")
        pattern = re.compile(matcher)
        for name in GATED_SURFACE_NAMES:
            with self.subTest(gated=name):
                self.assertRegex(name, pattern)
                self.assertIn(
                    cg_actions.classify_pre_tool_state(name, {"command": "git tag v1"}),
                    {
                        cg_actions.STATE_CANDIDATE,
                        cg_actions.STATE_AMBIGUOUS_CANDIDATE,
                    },
                    f"{name} must stay gated so matcher coverage is meaningful",
                )
        for name in PLATFORM_ALIAS_NAMES:
            with self.subTest(alias=name):
                # Official matcher contract: Edit/Write are apply_patch
                # matcher aliases and the hook input still reports
                # tool_name "apply_patch" — the classifier only ever sees
                # the resolved name, which must stay gated so the
                # cleanup->product-edit protection survives the shrink.
                self.assertRegex(name, pattern)
                self.assertEqual(
                    cg_actions.classify_pre_tool_state("apply_patch", {"patch": ""}),
                    cg_actions.STATE_CANDIDATE,
                )
        for name in MATCHED_SAFE_MCP_NAMES:
            with self.subTest(safe_mcp=name):
                # The mcp__ prefix passes every MCP surface to the hook as a
                # safety margin; the router still classifies non-marker MCP
                # tools SAFE and returns silently.
                self.assertRegex(name, pattern)
                self.assertEqual(
                    cg_actions.classify_pre_tool_state(name, {"path": "x"}),
                    cg_actions.STATE_SAFE,
                )
        for name in UNMATCHED_READONLY_NAMES:
            with self.subTest(readonly=name):
                self.assertNotRegex(name, pattern)


class SilentSuccessWireTests(unittest.TestCase):
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

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def payload(self, event: str, session: str = "p5", **extra: object) -> dict:
        result = {
            "hook_event_name": event,
            "session_id": session,
            "cwd": str(self.project),
            "turn_id": f"t{self.turn}",
        }
        result.update(extra)
        return result

    def dispatch(self, event: str, session: str = "p5", **extra: object) -> dict:
        return cg.dispatch(self.payload(event, session=session, **extra))

    def prompt(self, text: str, session: str = "p5") -> dict:
        self.turn += 1
        with mock.patch.object(cg.secrets, "token_urlsafe", return_value="p5token"):
            return self.dispatch("UserPromptSubmit", session=session, prompt=text)

    def state(self, session: str = "p5") -> dict:
        path = self.data_dir / "sessions" / session / "state.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def private_common(self, session: str = "p5") -> list[str]:
        return [
            "--data-dir",
            str(self.data_dir),
            "--session-id",
            session,
            "--turn-id",
            f"t{self.turn}",
            "--token",
            "p5token",
        ]

    def run_stage(
        self, arguments: list[str], *, exit_code: int = 0, session: str = "p5"
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        staged = subprocess.run(
            arguments,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=15,
            check=False,
        )
        hook_result = cg.dispatch(
            self.payload(
                "PostToolUse",
                session=session,
                tool_name="Bash",
                tool_input={"command": cg.shell_join(arguments)},
                tool_response={"exit_code": exit_code, "output": staged.stdout},
            )
        )
        return staged, hook_result

    def stage_disposition(
        self, disposition: str, *, session: str = "p5", token: str = "p5token"
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        common = self.private_common(session)
        common = common[:-2] + [f"--token={token}"]
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-disposition",
            *common,
            "--disposition",
            disposition,
        ]
        return self.run_stage(arguments, session=session)

    def record_tool(self, *, session: str = "p5") -> str:
        self.dispatch(
            "PostToolUse",
            session=session,
            tool_name="Bash",
            tool_input={"command": "synthetic verification"},
            tool_response={"exit_code": 0, "output": "PASS"},
        )
        return self.state(session)["evidence"][-1]["id"]

    def test_disposition_staging_success_returns_plain_empty_object(self) -> None:
        self.prompt("$context-guard\n完成认证流程。")
        staged, hook_result = self.stage_disposition("deferred")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertEqual(
            hook_result,
            {},
            "successful private staging must not emit developer text",
        )
        self.assertEqual(
            self.state()["completion_attempt"]["staged_control"]["kind"],
            "disposition",
        )

    def test_checkpoint_staging_success_returns_plain_empty_object(self) -> None:
        self.prompt("实现复杂系统。必须保存需求，必须执行测试，必须提供验收证据。")
        evidence_id = self.record_tool()
        state = self.state()
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-checkpoint",
            *self.private_common(),
        ]
        scoped, ancestor = cg.checkpoint_scope_item_ids(state)
        for item in state["requirements"]:
            if item["status"] in {"pass", "superseded"}:
                continue
            if item["id"] in scoped or item["id"] in ancestor:
                arguments.extend(["--requirement", f"{item['id']}={evidence_id}"])
        for item in state["acceptance_items"]:
            if item["status"] in {"pass", "superseded"}:
                continue
            if item["id"] in scoped:
                arguments.extend(["--acceptance", f"{item['id']}={evidence_id}"])
        staged, hook_result = self.run_stage(arguments)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertEqual(
            hook_result,
            {},
            "successful checkpoint staging must not emit developer text",
        )
        self.assertEqual(
            self.state()["completion_attempt"]["staged_control"]["kind"],
            "checkpoint",
        )

    def test_proof_registration_success_returns_plain_empty_object(self) -> None:
        self.prompt("$context-guard\n核验全部 2 个条目。")
        evidence_id = self.record_tool()
        state = self.state()
        obligation = state["requirements"][0]["verification_contract"][
            "obligations"
        ][0]
        manifest_path = self.root / "proof.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "protocol_version": cg.PROOF_PROTOCOL_VERSION,
                    "item_id": "R001",
                    "obligation_id": obligation["id"],
                    "evidence_ids": [evidence_id],
                    "surface": "scope",
                    "subject_ids": [],
                    "expected_scope": ["one", "two"],
                    "observed_scope": ["two", "one"],
                }
            ),
            encoding="utf-8",
        )
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "register-proof",
            *self.private_common(),
            "--manifest",
            str(manifest_path),
        ]
        registered, hook_result = self.run_stage(arguments)
        self.assertEqual(registered.returncode, 0, registered.stderr)
        self.assertEqual(
            hook_result,
            {},
            "successful proof registration must not emit developer text",
        )
        self.assertEqual(len(self.state()["proofs"]), 1)

    def test_malformed_private_control_still_blocks(self) -> None:
        self.prompt("$context-guard\n完成认证流程。")
        arguments = [
            sys.executable,
            str(MODULE_PATH),
            "stage-disposition",
            *self.private_common(),
            "--disposition",
            "deferred",
        ]
        result = cg.dispatch(
            self.payload(
                "PostToolUse",
                tool_name="Bash",
                tool_input={"command": cg.shell_join(arguments)},
                tool_response={"exit_code": 0, "output": "no marker at all"},
            )
        )
        self.assertEqual(result.get("decision"), "block")
        self.assertTrue(result.get("reason"))

    def test_failed_stage_tool_result_still_blocks(self) -> None:
        self.prompt("$context-guard\n完成认证流程。")
        staged, hook_result = self.stage_disposition("deferred", token="invalid")
        self.assertNotEqual(staged.returncode, 0)
        self.assertEqual(hook_result.get("decision"), "block")
        self.assertTrue(hook_result.get("reason"))
        self.assertIsNone(self.state()["completion_attempt"].get("staged_control"))

    def test_user_prompt_submit_completion_instructions_unchanged(self) -> None:
        result = self.prompt("$context-guard\n完成认证流程。")
        context = result["hookSpecificOutput"]["additionalContext"]
        self.assertIn(cg.STOP_PROTOCOL_VERSION, context)
        self.assertIn("Ordinary endings need no commands", context)


if __name__ == "__main__":
    unittest.main()
