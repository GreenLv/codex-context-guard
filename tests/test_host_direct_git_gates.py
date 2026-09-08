#!/usr/bin/env python3
"""Direct-Git host-gate regressions for the real Context Guard state chain."""

from __future__ import annotations

import json
import subprocess
from unittest import mock

from tests.test_cg122_p0_counterexamples import P0Harness


class DirectCommitTransitionTests(P0Harness):
    def add_bare_remote(self) -> None:
        self.remote = self.root / "remote.git"
        subprocess.run(
            ["git", "init", "-q", "--bare", str(self.remote)],
            check=True,
            capture_output=True,
        )
        self.git("remote", "add", "origin", str(self.remote))

    def prepare_authorized_commit(self) -> str:
        self.write("owned.txt", "v1\n")
        self.git("add", "owned.txt")
        self.git("commit", "-q", "-m", "track owned")
        self.prompt("请修改 owned.txt 并验证。")
        self.task_edit("owned.txt", "v2\n")
        self.authorize_commit_push("仅提交 `owned.txt` 并推送 origin 的 main 分支。")
        self.git("add", "owned.txt")
        return "git commit -q --no-gpg-sign -m direct-gate -- owned.txt"

    def direct_commit_with_string_response(self, command: str) -> str:
        self.turn_counter += 1
        turn_id = f"direct-turn-{self.turn_counter}"
        tool_use_id = f"direct-tool-{self.turn_counter}"
        payload = {
            "turn_id": turn_id,
            "tool_use_id": tool_use_id,
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        pre = self.dispatch("PreToolUse", **payload)
        self.assertNotEqual(
            (pre.get("hookSpecificOutput") or {}).get("permissionDecision"),
            "deny",
        )
        completed = subprocess.run(
            command,
            shell=True,
            cwd=self.project,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.dispatch(
            "PostToolUse",
            **payload,
            # Genuine Codex command Hooks expose one opaque response string.
            # The production runtime must use the paired call plus exact Git
            # readback; this string supplies no success authority.
            tool_response=completed.stdout + completed.stderr,
        )
        return self.git_out("rev-parse", "HEAD")

    def test_direct_commit_pair_advances_from_independent_readback(self) -> None:
        self.activate()
        command = self.prepare_authorized_commit()
        commit = self.direct_commit_with_string_response(command)
        state = self.state()
        binding = self.current_binding(state)
        expected = binding["expected_commits"]["push"]
        self.assertEqual(expected["commit_sha256"], commit)
        self.assertEqual(expected["advanced_source"], "causal_commit_readback")
        context = self.unit(state, state["work_state"]["active_work_unit_id"])[
            "commit_context"
        ]
        self.assertIn(expected["advanced_from_tool_sha256"], context["consumed"])

    def test_resume_combined_authorization_advances_the_same_commit_chain(self) -> None:
        """A resumed turn keeps the genuine commit-and-push transition."""
        self.activate()
        self.write("owned.txt", "v1\n")
        self.git("add", "owned.txt")
        self.git("commit", "-q", "-m", "track owned")
        self.prompt("请修改 owned.txt；此轮不得提交或推送。")
        self.task_edit("owned.txt", "v2\n")
        self.dispatch("SessionStart", source="resume")
        self.authorize_commit_push(
            "本轮明确取代先前的限制。提交 `owned.txt` 并推送 origin 的 main 分支。"
        )
        binding = self.current_binding(self.state())
        self.assertEqual(set(binding["actions"]), {"commit", "push"})
        self.git("add", "owned.txt")
        commit = self.direct_commit_with_string_response(
            "git commit -q --no-gpg-sign -m resumed-chain -- owned.txt"
        )
        expected = self.current_binding(self.state())["expected_commits"]["push"]
        self.assertEqual(expected["commit_sha256"], commit)
        self.assertEqual(expected["advanced_source"], "causal_commit_readback")

    def test_direct_push_allow_is_persisted_and_remote_ref_matches(self) -> None:
        self.add_bare_remote()
        self.activate()
        commit = self.direct_commit_with_string_response(
            self.prepare_authorized_commit()
        )
        self.turn_counter += 1
        payload = {
            "turn_id": f"direct-turn-{self.turn_counter}",
            "tool_use_id": f"direct-tool-{self.turn_counter}",
            "tool_name": "Bash",
            "tool_input": {"command": "git push origin HEAD:refs/heads/main"},
        }
        pre = self.dispatch("PreToolUse", **payload)
        self.assertEqual(pre, {})
        completed = subprocess.run(
            payload["tool_input"]["command"], shell=True, cwd=self.project,
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.dispatch(
            "PostToolUse", **payload,
            tool_response=completed.stdout + completed.stderr,
        )
        remote_head = subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        self.assertEqual(remote_head, commit)
        decision = self.source_context()["decisions"][-1]
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(
            decision["authorization_generation"], self.current_binding(self.state())["generation"]
        )
        self.assertEqual(decision["target"]["commit_sha256"], commit)

    def test_push_wire_and_ledger_share_one_authoritative_evaluation(self) -> None:
        """A later lookup cannot turn an emitted allow into a ledger deny."""
        self.add_bare_remote()
        self.activate()
        self.direct_commit_with_string_response(self.prepare_authorized_commit())
        binding = self.current_binding(self.state())
        with mock.patch(
            "tests.test_cg122_p0_counterexamples.cg._evaluate_persisted_bindings",
            side_effect=[
                (binding, None),
                (None, "authorization disappeared after the wire decision"),
            ],
        ) as evaluate:
            self.turn_counter += 1
            result = self.dispatch(
                "PreToolUse",
                turn_id=f"direct-turn-{self.turn_counter}",
                tool_use_id=f"direct-tool-{self.turn_counter}",
                tool_name="Bash",
                tool_input={"command": "git push origin HEAD:refs/heads/main"},
            )
        self.assertEqual(result, {})
        self.assertEqual(evaluate.call_count, 1)
        decision = self.source_context()["decisions"][-1]
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(
            decision["authorization_generation"], binding["generation"]
        )

    def test_old_schema11_commit_context_load_resume_preserves_evidence(self) -> None:
        """The pre-decision schema-11 shape remains a valid read input."""
        self.activate()
        commit = self.direct_commit_with_string_response(
            self.prepare_authorized_commit()
        )
        state = self.state()
        unit = self.unit(state, state["work_state"]["active_work_unit_id"])
        old_context = dict(unit["commit_context"])
        old_context.pop("decisions")
        unit["commit_context"] = old_context
        state["content_hash"] = __import__(
            "tests.test_cg122_p0_counterexamples", fromlist=["cg"]
        ).cg.state_content_hash(state)
        state_path = self.root / "private" / "sessions" / "p0" / "state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")

        self.dispatch("SessionStart", source="resume")
        resumed = self.state()
        binding = self.current_binding(resumed)
        self.assertEqual(
            binding["expected_commits"]["push"]["commit_sha256"], commit
        )
        context = self.unit(
            resumed, resumed["work_state"]["active_work_unit_id"]
        )["commit_context"]
        self.assertEqual(context["decisions"], [])
        for field in ("pending", "edits", "consumed", "targets"):
            self.assertEqual(context[field], old_context[field])
        self.assertNotEqual(resumed["integrity"]["status"], "recovered_from_prompts")

    def test_corrupt_old_schema11_commit_context_still_fails_closed(self) -> None:
        """Compatibility never admits malformed legacy observation facts."""
        self.activate()
        self.direct_commit_with_string_response(self.prepare_authorized_commit())
        state = self.state()
        unit = self.unit(state, state["work_state"]["active_work_unit_id"])
        unit["commit_context"].pop("decisions")
        unit["commit_context"]["consumed"] = ["not-a-sha256"]
        cg = __import__(
            "tests.test_cg122_p0_counterexamples", fromlist=["cg"]
        ).cg
        state["content_hash"] = cg.state_content_hash(state)
        state_path = self.root / "private" / "sessions" / "p0" / "state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")

        self.dispatch("SessionStart", source="resume")
        resumed = self.state()
        self.assertEqual(resumed["integrity"]["status"], "recovered_from_prompts")
        context = self.unit(
            resumed, resumed["work_state"]["active_work_unit_id"]
        ).get("commit_context")
        self.assertFalse(
            context and "not-a-sha256" in context.get("consumed", [])
        )

    def test_wrong_scope_push_is_denied_without_ref_change(self) -> None:
        self.add_bare_remote()
        self.activate()
        self.prompt("检查当前状态并运行测试。")
        self.git("push", "origin", "HEAD:refs/heads/main")
        initial_remote = subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        self.prompt("推送 origin 的 main 分支。")
        self.assert_denied_push("git push origin HEAD:refs/heads/other")

        final_remote = subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        self.assertEqual(final_remote, initial_remote)

    def test_unauthorized_push_is_denied_without_ref_change(self) -> None:
        self.add_bare_remote()
        self.activate()
        self.prompt("检查当前状态并运行测试。")
        self.git("push", "origin", "HEAD:refs/heads/main")
        initial_remote = subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        self.assert_denied_push("git push origin HEAD:refs/heads/main")
        final_remote = subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        self.assertEqual(final_remote, initial_remote)

    def assert_denied_push(self, command: str) -> None:
        self.turn_counter += 1
        result = self.dispatch(
            "PreToolUse",
            turn_id=f"denied-turn-{self.turn_counter}",
            tool_use_id=f"denied-tool-{self.turn_counter}",
            tool_name="Bash",
            tool_input={"command": command},
        )
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(self.source_context()["decisions"][-1]["decision"], "deny")

    def source_context(self) -> dict:
        state = self.state()
        return self.unit(state, state["work_state"]["active_work_unit_id"])[
            "commit_context"
        ]

    @staticmethod
    def current_binding(state: dict) -> dict:
        unit_id = state["work_state"]["active_work_unit_id"]
        unit = next(item for item in state["work_units"] if item["id"] == unit_id)
        return next(
            item
            for item in unit["authorizations"]
            if item["state"] == "active" and "commit" in item["actions"]
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
