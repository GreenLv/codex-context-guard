#!/usr/bin/env python3
"""Direct-Git host-gate regressions for the real Context Guard state chain.

0.13 layer transfer: the DEFAULT execution-approval gate was removed. The
direct-Git chain this module verified — commit/push authorization
bindings, expectation advancement from paired-call readbacks, per-push
decision ledgers inside ``commit_context``, and the unauthorized/wrong-
scope push denies — is no longer produced or enforced. Each old failure
family transfers to one of three layers, asserted here: (a)
executing-agent/host responsibility — the push wire is the plain empty
allow, the pushed ref and produced commits are ordinary Git facts the
agent owns, and the Guard fabricates no authorization, expectation, or
decision record around them (INV-01/INV-02); (b) release-adapter exact
contracts — exact-commit push binding survives only behind an explicitly
adopted release contract (tested under explicit adoption elsewhere);
(c) preserved recording and integrity — user statements and restrictions
still become durable pending requirements, legacy states keep their
existing ``commit_context`` evidence on load/resume (commit-context
records are never deleted), and malformed legacy contexts still fail
closed into deterministic recovery. Git-object evidence facts stay
available to Stop completion; push/commit are simply no longer gated.
"""

from __future__ import annotations

import json
import subprocess

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
        """Track owned.txt, edit it as task work, and state the intent.

        0.13: the statement is recorded as a constraint; it produces no
        authorization record to consume later."""
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
        # 0.13: the default path never denies a commit candidate — the
        # allow wire is the plain empty object.
        self.assertEqual(pre, {})
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
            # 0.13: the pair records at most an ordinary observation; it
            # constructs no success authority.
            tool_response=completed.stdout + completed.stderr,
        )
        return self.git_out("rev-parse", "HEAD")

    def assert_no_binding_records(self) -> None:
        state = self.state()
        rendered = json.dumps(state["work_units"], ensure_ascii=False)
        for unit in state["work_units"]:
            self.assertNotIn("authorizations", unit)
        self.assertNotIn("expected_commits", rendered)
        self.assertNotIn("commit_context", rendered)

    def test_direct_commit_pair_advances_from_independent_readback(self) -> None:
        """0.13 transfer: the paired commit executes ungated and the exact
        HEAD sha comes from Git itself, not from a Guard expectation. The
        old advanced-expectation assertions become absence assertions: no
        expected_commits, no commit_context, no authorization record."""
        self.activate()
        command = self.prepare_authorized_commit()
        commit = self.direct_commit_with_string_response(command)
        self.assertEqual(self.git_out("rev-parse", "HEAD"), commit)
        self.assert_no_binding_records()
        state = self.state()
        self.assertTrue(
            any("仅提交 `owned.txt`" in item["text"]
                for item in state["requirements"])
        )
        for item in state["requirements"]:
            self.assertEqual(item["status"], "pending")

    def test_resume_combined_authorization_advances_the_same_commit_chain(self) -> None:
        """0.13 transfer: a resumed turn keeps the genuine commit-and-push
        sequence working as ordinary work. The earlier restriction and the
        superseding statement are both recorded as requirements; the push
        stays ungated and no combined authorization binding is produced."""
        self.activate()
        self.write("owned.txt", "v1\n")
        self.git("add", "owned.txt")
        self.git("commit", "-q", "-m", "track owned")
        self.prompt("请修改 owned.txt；此轮不得提交或推送。")
        state = self.state()
        self.assertTrue(
            any("不得提交或推送" in item["text"] for item in state["requirements"]),
            "the negative-phase restriction must be recorded",
        )
        self.task_edit("owned.txt", "v2\n")
        self.dispatch("SessionStart", source="resume")
        self.authorize_commit_push(
            "本轮明确取代先前的限制。提交 `owned.txt` 并推送 origin 的 main 分支。"
        )
        state = self.state()
        self.assertTrue(
            any("本轮明确取代先前的限制" in item["text"]
                for item in state["requirements"]),
            "the superseding statement must be recorded",
        )
        self.git("add", "owned.txt")
        commit = self.direct_commit_with_string_response(
            "git commit -q --no-gpg-sign -m resumed-chain -- owned.txt"
        )
        self.assertEqual(self.git_out("rev-parse", "HEAD"), commit)
        self.turn_counter += 1
        pre = self.dispatch(
            "PreToolUse",
            turn_id=f"direct-turn-{self.turn_counter}",
            tool_use_id=f"direct-tool-{self.turn_counter}",
            tool_name="Bash",
            tool_input={"command": "git push origin HEAD:refs/heads/main"},
        )
        self.assertEqual(pre, {})
        self.assert_no_binding_records()
        for item in self.state()["requirements"]:
            self.assertEqual(item["status"], "pending")

    def test_direct_push_allow_is_persisted_and_remote_ref_matches(self) -> None:
        """0.13 transfer: the push is executed by the host, the remote ref
        matches the produced commit as plain Git fact, and the Guard
        persists no push decision ledger — the old commit_context.decisions
        record no longer exists."""
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
        self.assert_no_binding_records()

    def test_push_wire_and_ledger_share_one_authoritative_evaluation(self) -> None:
        """0.13 transfer: there is no persisted authorization ledger left
        to consult, so "a later lookup cannot turn an emitted allow into a
        ledger deny" holds structurally: the wire decision is the plain
        empty object, computed from nothing, and repeated dispatches stay
        byte-identical instead of replaying ledger state."""
        self.add_bare_remote()
        self.activate()
        self.direct_commit_with_string_response(self.prepare_authorized_commit())
        self.turn_counter += 1
        payload = dict(
            turn_id=f"direct-turn-{self.turn_counter}",
            tool_use_id=f"direct-tool-{self.turn_counter}",
            tool_name="Bash",
            tool_input={"command": "git push origin HEAD:refs/heads/main"},
        )
        first = self.dispatch("PreToolUse", **payload)
        second = self.dispatch("PreToolUse", **payload)
        self.assertEqual(first, {})
        self.assertEqual(first, second)
        self.assert_no_binding_records()

    def test_old_schema11_commit_context_load_resume_preserves_evidence(self) -> None:
        """Pre-decision commit-context evidence from an older state is a
        valid read input: 0.13 stops CREATING these records but never
        destroys evidence recorded by a previous version."""
        self.activate()
        commit = self.direct_commit_with_string_response(
            self.prepare_authorized_commit()
        )
        state = self.state()
        unit = self.unit(state, state["work_state"]["active_work_unit_id"])
        # Inject the legacy (schema-11 writer) shape: no decisions field.
        legacy_context = {
            "pending": [],
            "edits": [],
            "consumed": ["c" * 64],
            "targets": [],
        }
        unit["commit_context"] = legacy_context
        self.save_state(state)

        self.dispatch("SessionStart", source="resume")
        resumed = self.state()
        context = self.unit(
            resumed, resumed["work_state"]["active_work_unit_id"]
        )["commit_context"]
        for field in ("pending", "edits", "consumed", "targets"):
            self.assertEqual(context[field], legacy_context[field])
        self.assertNotEqual(resumed["integrity"]["status"], "recovered_from_prompts")
        # The commit itself remains plain Git fact for Stop completion.
        self.assertEqual(self.git_out("rev-parse", "HEAD"), commit)

    def test_corrupt_old_schema11_commit_context_still_fails_closed(self) -> None:
        """Compatibility never admits malformed legacy observation facts."""
        self.activate()
        self.direct_commit_with_string_response(self.prepare_authorized_commit())
        state = self.state()
        unit = self.unit(state, state["work_state"]["active_work_unit_id"])
        unit["commit_context"] = {
            "pending": [],
            "edits": [],
            "consumed": ["not-a-sha256"],
            "targets": [],
        }
        self.save_state(state)

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
        """0.13 transfer: the Guard neither denies nor allows a wrong-ref
        push into its ledger — the plain allow wire carries no permission
        text, ref exactness is the executing agent's duty, and this
        harness (as the host) declines to execute the off-scope push, so
        the remote ref cannot change through any Guard action."""
        self.add_bare_remote()
        self.activate()
        self.prompt("检查当前状态并运行测试。")
        self.git("push", "origin", "HEAD:refs/heads/main")
        initial_remote = subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        self.prompt("推送 origin 的 main 分支。")
        self.turn_counter += 1
        result = self.dispatch(
            "PreToolUse",
            turn_id=f"wrong-turn-{self.turn_counter}",
            tool_use_id=f"wrong-tool-{self.turn_counter}",
            tool_name="Bash",
            tool_input={"command": "git push origin HEAD:refs/heads/other"},
        )
        self.assertEqual(result, {})
        self.assert_no_binding_records()
        state = self.state()
        self.assertTrue(
            any("推送 origin 的 main 分支" in item["text"]
                for item in state["requirements"])
        )

        final_remote = subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        self.assertEqual(final_remote, initial_remote)

    def test_unauthorized_push_is_denied_without_ref_change(self) -> None:
        """0.13 transfer: without an adopted contract an unauthorized push
        is not a Guard question — the wire is the plain allow, the user's
        restriction stays a pending requirement, and no remote write
        happens unless the host chooses to perform it."""
        self.add_bare_remote()
        self.activate()
        self.prompt("检查当前状态并运行测试。")
        self.git("push", "origin", "HEAD:refs/heads/main")
        initial_remote = subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        self.prompt("检查完成后不要推送，等我确认。")
        self.turn_counter += 1
        result = self.dispatch(
            "PreToolUse",
            turn_id=f"denied-turn-{self.turn_counter}",
            tool_use_id=f"denied-tool-{self.turn_counter}",
            tool_name="Bash",
            tool_input={"command": "git push origin HEAD:refs/heads/main"},
        )
        self.assertEqual(result, {})
        state = self.state()
        self.assertTrue(
            any("不要推送" in item["text"] for item in state["requirements"]),
            "the user's restriction must survive as a pending requirement",
        )
        for item in state["requirements"]:
            self.assertEqual(item["status"], "pending")
        self.assert_no_binding_records()
        final_remote = subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        self.assertEqual(final_remote, initial_remote)


if __name__ == "__main__":
    import unittest

    unittest.main()
