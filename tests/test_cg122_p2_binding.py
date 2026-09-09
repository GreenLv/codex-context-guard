"""Synthetic current-task target facts and root confirmation, no network.

0.13 layer transfer: the DEFAULT execution-approval gate was removed. The
per-claim provenance chain this module used to police — attempt facts,
root/delegated confirmation authority, exact commit/readback targets,
expectation advancement across tool pairs, and the generation/repository
denies around them — is no longer produced or enforced. Every old failure
family transfers to one of three layers, asserted here: (a)
executing-agent/host responsibility — target selection, confirmation
authority, and result checking are no longer Guard questions, so the same
inputs yield the plain allow wire with NO fabricated authorization,
``expected_commits`` or ``commit_context`` records (INV-01/INV-02);
(b) release-adapter exact contracts — tested under explicit adoption
elsewhere; (c) preserved constraint recording asserted here — the user's
statements and restrictions still become durable pending requirements,
and delegated confirmations still never become root authority records.
The pure classification/oracle helpers (local_source_effect, input_path,
projection, repository, _validate_commit_context) are unchanged product
code and keep their original tests.
"""
import json

from tests.test_cg122_p0_counterexamples import P0Harness


class CurrentTargetTests(P0Harness):
    def setUp(self):
        super().setUp()
        self.git("branch", "-M", "main")
        self.activate()
        self.prompt("请核对当前修改。")

    def assert_no_binding_records(self):
        state = self.state()
        for unit in state["work_units"]:
            self.assertNotIn("authorizations", unit)
            self.assertNotIn("commit_context", unit)
        self.assertNotIn("expected_commits", json.dumps(state["work_units"]))

    def test_attempt_fact_needs_root_confirmation(self):
        command = "git push https://example.invalid/synthetic/repo.git HEAD:main"
        # 0.13 transfer: an attempt no longer creates a Guard question.
        # The first push, the plain confirmation, the changed target and
        # the force variant are all plain allows; nothing about the
        # attempt is recorded as an authorization fact (INV-02).
        self.assertEqual(self.decision(command), ("allow", ""))
        self.prompt("我授权你现在推送。")
        self.assertEqual(self.decision(command), ("allow", ""))
        self.assertEqual(
            self.decision(command.replace("main", "other")), ("allow", "")
        )
        self.assertEqual(
            self.decision(command.replace("push", "push --force")),
            ("allow", ""),
        )
        self.assert_no_binding_records()
        state = self.state()
        self.assertTrue(
            any("我授权你现在推送" in item["text"] for item in state["requirements"]),
            "the root confirmation statement must survive as a requirement",
        )
        for item in state["requirements"]:
            self.assertEqual(item["status"], "pending")

    def test_multiple_targets_are_not_implicitly_selected(self):
        self.decision("git push https://example.invalid/one/repo.git HEAD:main")
        self.decision("git push https://example.invalid/two/repo.git HEAD:main")
        self.prompt("我授权你现在推送。")
        # 0.13 transfer (a): selection between attempted targets is not a
        # Guard decision; no implicit selection record exists to consult.
        self.assertEqual(
            self.decision("git push https://example.invalid/one/repo.git HEAD:main"),
            ("allow", ""),
        )
        self.assert_no_binding_records()

    def test_delegated_confirmation_is_not_root_authority(self):
        command = "git push https://example.invalid/synthetic/repo.git HEAD:main"
        self.decision(command)
        self.dispatch("UserPromptSubmit", prompt="我授权你现在推送。", agent_id="worker-synthetic")
        # 0.13 transfer (c): the delegated confirmation is still recorded
        # with its delegated provenance (never root authority), and the
        # push is a plain allow — authority evaluation moved to the
        # executing agent/host, not to a Guard deny.
        state = self.state()
        delegated = [
            p for p in state["prompts"] if p.get("actor_id") == "worker-synthetic"
        ]
        self.assertTrue(delegated, "the delegated prompt must be journaled")
        self.assertEqual(delegated[-1].get("authority"), "delegated")
        self.assert_no_binding_records()
        self.assertEqual(self.decision(command), ("allow", ""))

    def test_unknown_target_does_not_acquire_authority_from_attempt(self):
        self.prompt("我授权你现在推送。")
        # 0.13 transfer: an authorization statement alone fabricates no
        # resolvable target record; the under-specified push stays with
        # the executing agent (INV-02) and the wire is the plain allow.
        self.assertEqual(
            self.decision("git push https://example.invalid/synthetic/repo.git HEAD:main"),
            ("allow", ""),
        )
        self.assert_no_binding_records()
        state = self.state()
        self.assertTrue(
            any("我授权你现在推送" in item["text"] for item in state["requirements"])
        )

    def test_old_commit_target_cannot_be_inherited(self):
        command = "git push https://example.invalid/synthetic/repo.git HEAD:main"
        self.decision(command)
        self.git("commit", "-q", "--allow-empty", "-m", "other")
        self.prompt("我授权你现在推送。")
        # 0.13 transfer: there is no commit target record to inherit — the
        # inheritance question disappeared with the record. The wire is
        # the plain allow and no binding was fabricated around either HEAD.
        self.assertEqual(self.decision(command), ("allow", ""))
        self.assert_no_binding_records()


class CommitObservationTests(P0Harness):
    def setUp(self):
        super().setUp()
        self.git("branch", "-M", "main")
        self.git("remote", "add", "origin", "https://example.invalid/synthetic/repo.git")
        self.activate()

    def assert_no_binding_records(self):
        state = self.state()
        for unit in state["work_units"]:
            self.assertNotIn("authorizations", unit)
            self.assertNotIn("commit_context", unit)
        self.assertNotIn("expected_commits", json.dumps(state["work_units"]))

    def test_authorization_before_edit_freezes_verified_ready_bytes(self):
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        self.task_edit("owned.txt", "ready")
        self.git("add", "owned.txt")
        self.commit_and_post(["git", "commit", "-q", "-m", "ready"])
        # 0.13 transfer (a): the commit/push sequence is not a Guard
        # decision; the produced commit remains ordinary Git fact for Stop
        # completion, and no expectation/advanced-source record exists.
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()
        state = self.state()
        self.assertTrue(
            any("提交" in item["text"] and "推送" in item["text"]
                for item in state["requirements"])
        )

    def test_unattributed_dirty_file_is_not_blanket_scope(self):
        self.write("foreign.txt", "foreign")
        self.authorize_commit_push()
        self.git("add", "foreign.txt")
        self.commit_and_post(["git", "commit", "-q", "-m", "foreign"])
        # 0.13 transfer: nothing is scoped at all, so unattributed dirt
        # cannot join a Guard scope; attribution is the agent's duty and
        # the push wire is the plain allow.
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()
        self.assert_no_authorization_records()
        state = self.state()
        for item in state["requirements"]:
            self.assertEqual(item["status"], "pending")

    def test_same_pair_with_forged_printed_sha_cannot_advance(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        payload = dict(turn_id="paired", tool_use_id="paired", tool_name="shell", tool_input={"command": "git commit -m ready"})
        self.dispatch("PreToolUse", **payload)
        self.dispatch("PostToolUse", **payload, tool_response={"exit_code": 0, "stdout": "[main " + "a" * 40 + "] ready"})
        # 0.13 transfer: the printed sha cannot advance anything because
        # no expectation exists; it must not enter any authorization or
        # commit-transition record either.
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()
        state = self.state()
        rendered = json.dumps(state["work_units"], ensure_ascii=False)
        self.assertNotIn("a" * 40, rendered)

    def test_failed_real_commit_has_specific_reason(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        _, code, _ = self.causal_command("git commit -m ready")
        self.assertNotEqual(code, 0)
        # 0.13 transfer (a): a failed commit produces no success record and
        # no commit_failed deny; checking the outcome is the executor's
        # duty, so the push wire is the plain allow either way.
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()

    def test_dry_run_does_not_advance(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        self.git("add", "owned.txt")
        before = self.git_out("rev-parse", "HEAD")
        self.causal_command("git commit --dry-run")
        # A dry run is not a commit: HEAD is unchanged as ordinary Git fact.
        self.assertEqual(self.git_out("rev-parse", "HEAD"), before)
        # 0.13 transfer: no expectation exists to advance or deny on.
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()

    def test_multi_command_commit_is_causally_bound(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        _, code, _ = self.causal_command("git add owned.txt && git commit -q -m ready && git status --short")
        self.assertEqual(code, 0)
        # 0.13 transfer (a): the compound commit command executes freely
        # and the resulting HEAD is the independent evidence; the Guard
        # records no binding of it.
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()
        self.assertIn("ready", self.git_out("log", "--format=%s", "-1"))

    def test_scope_ceiling_does_not_expand_for_later_task_edit(self):
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        self.task_edit("owned.txt", "ready")
        self.task_edit("other.txt", "other")
        self.git("add", "-A")
        self.commit_and_post(["git", "commit", "-q", "-m", "too broad"])
        # 0.13 transfer: the ceiling cannot expand because none exists;
        # the broad commit is ordinary work and the original restriction
        # survives as a pending requirement for the agent/recovery.
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()
        state = self.state()
        self.assertTrue(
            any("提交 `owned.txt`" in item["text"] for item in state["requirements"])
        )
        for item in state["requirements"]:
            self.assertEqual(item["status"], "pending")

    def test_unstructured_success_uses_exact_causal_readback(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        self.git("add", "owned.txt")
        payload = dict(turn_id="paired", tool_use_id="paired", tool_name="shell", tool_input={"command": "git commit -q -m ready"})
        self.dispatch("PreToolUse", **payload)
        self.git("commit", "-q", "-m", "ready")
        self.dispatch("PostToolUse", **payload, tool_response="Process exited with code 0")
        # 0.13 transfer: the causal pair reconstructs no expected commit.
        # The exact HEAD sha stays available as Git fact (what the agent
        # and Stop completion consume), and no binding names it.
        head = self.git_out("rev-parse", "HEAD")
        self.assertEqual(self.git_out("log", "--format=%s", "-1"), "ready")
        state = self.state()
        rendered = json.dumps(state["work_units"], ensure_ascii=False)
        self.assertNotIn(head, rendered)
        self.assertNotIn("expected_commits", rendered)
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))

    def test_shell_quotes_preserve_literal_newline_and_unicode(self):
        from cg_actions import local_source_effect
        effect = local_source_effect("printf 'a\\n' > '目录/line\nbreak.txt'")
        self.assertEqual(effect, {"kind": "edit", "paths": ["目录/line\nbreak.txt"]})
        self.assertEqual(local_source_effect('Set-Content -LiteralPath "dir\\owned.txt" -Value "ready"'),
                         {"kind": "edit", "paths": ["dir\\owned.txt"]})

    def test_input_separator_mapping_must_be_unique(self):
        import os

        from cg_commit import input_path
        if os.name == "nt":
            (self.project / "dir").mkdir()
            self.write("dir/owned.txt", "slash")
            self.assertEqual(input_path(str(self.project), "dir\\owned.txt"),
                             "dir/owned.txt")
            for invalid in ("../escape.txt", ":(glob)*", "dir/*.txt"):
                self.assertIsNone(input_path(str(self.project), invalid))
            return
        (self.project / "dir").mkdir()
        self.write("dir/owned.txt", "slash")
        self.assertEqual(input_path(str(self.project), "dir\\owned.txt"), "dir/owned.txt")
        self.write("dir\\owned.txt", "backslash")
        self.assertIsNone(input_path(str(self.project), "dir\\owned.txt"))
        for invalid in ("../escape.txt", ":(glob)*", "dir/*.txt"):
            self.assertIsNone(input_path(str(self.project), invalid))

    def test_parent_symlink_escape_is_not_source_scope(self):
        import os

        from cg_commit import input_path, projection
        if os.name == "nt":
            self.skipTest("POSIX symlink fixture; native Windows symlink privileges separate")
        (self.project / "link").symlink_to(self.root, target_is_directory=True)
        self.assertIsNone(input_path(str(self.project), "link/escape.txt"))
        self.assertIsNone(projection(str(self.project), ["link/escape.txt"]))

    def test_malformed_context_fails_closed(self):
        from tests.test_cg122_p0_counterexamples import cg
        with self.assertRaises(cg.StateIntegrityError):
            cg._validate_commit_context({"pending": {}, "edits": [], "consumed": [], "targets": []})

    def test_authority_generation_change_rejects_old_pair(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        self.git("add", "owned.txt")
        payload = dict(turn_id="paired", tool_use_id="paired", tool_name="shell", tool_input={"command": "git commit -q -m ready"})
        self.dispatch("PreToolUse", **payload)
        self.authorize_commit_push("现在重新授权提交 `owned.txt` 并推送 origin main。")
        self.git("commit", "-q", "-m", "ready")
        self.dispatch("PostToolUse", **payload, tool_response={"exit_code": 0})
        # 0.13 transfer: no generations are produced, so there is no
        # generation boundary to violate and no commit_authority_changed
        # deny; both statements survive as pending requirements and no
        # binding attaches the cross-statement pair.
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()
        state = self.state()
        self.assertTrue(
            any("现在重新授权" in item["text"] for item in state["requirements"])
        )

    def test_replayed_tool_pair_cannot_advance_new_authorization(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        self.git("add", "owned.txt")
        payload = dict(turn_id="paired", tool_use_id="paired", tool_name="shell", tool_input={"command": "git commit -q -m ready"})
        self.dispatch("PreToolUse", **payload)
        self.git("commit", "-q", "-m", "ready")
        self.dispatch("PostToolUse", **payload, tool_response={"exit_code": 0})
        self.write("owned.txt", "new bytes")
        self.authorize_commit_push("现在重新授权提交 `owned.txt` 并推送 origin main。")
        self.dispatch("PreToolUse", **payload)
        self.dispatch("PostToolUse", **payload, tool_response={"exit_code": 0})
        # 0.13 transfer: the replay cannot advance anything because no
        # expectation ledger exists at all (structural elimination of the
        # replay surface); the wire is the plain allow and no transition
        # record was created for either pair.
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()

    def test_observation_parser_mirrors_stay_equivalent(self):
        from cg_actions import local_source_effect

        from tests.test_cg122_p0_counterexamples import cg
        for command in ("git commit --only owned.txt -m ready", "git -C repo commit -m ready", "git commit --dry-run", "echo 'git commit'", "printf 'x' > '目录/a\nb.txt'", 'Set-Content -Path "dir\\a.txt" -Value x', "cd other && git commit -m ready"):
            with self.subTest(command=command):
                self.assertEqual(cg.local_source_effect(command), local_source_effect(command))

    def test_delegated_edit_is_not_implicit_root_file_scope(self):
        self.prompt("请修复当前文件。")
        payload = dict(turn_id="delegate", tool_use_id="delegate", actor_id="worker-synthetic", tool_name="shell", tool_input={"command": "printf ready > owned.txt"})
        self.dispatch("PreToolUse", **payload)
        self.write("owned.txt", "ready")
        self.dispatch("PostToolUse", **payload, tool_response={"exit_code": 0})
        self.authorize_commit_push()
        # 0.13 transfer (c): a delegated edit implies no root file scope —
        # and no scope exists at all; the push wire is the plain allow and
        # the statement survives as a pending requirement.
        self.assertEqual(self.frozen_scope_paths(), [])
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()

    def test_edit_workdir_maps_to_repository_relative_object(self):
        import subprocess
        self.prompt("请修复当前文件。")
        (self.project / "sub").mkdir()
        command = self.shell_write_command("owned.txt", "ready")
        payload = dict(turn_id="sub", tool_use_id="sub", tool_name="exec_command", tool_input={"cmd": command, "workdir": "./sub"})
        self.dispatch("PreToolUse", **payload)
        subprocess.run(command, shell=True, cwd=self.project / "sub", check=True)
        self.dispatch("PostToolUse", **payload, tool_response={"exit_code": 0})
        self.authorize_commit_push()
        # 0.13 transfer: workdir mapping is no longer baked into a frozen
        # scope; the pure separator/identity mapping remains product code
        # (asserted on cg_commit.input_path), and the observed edit stays
        # an ordinary non-authoritative observation.
        from cg_commit import input_path
        self.assertEqual(input_path(str(self.project), "sub/owned.txt"), "sub/owned.txt")
        self.assertEqual(self.frozen_scope_paths(), [])
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()

    def test_cross_repository_commit_is_not_current_task_result(self):
        import subprocess
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        other = self.root / "other-repo"
        subprocess.run(["git", "init", "-q", str(other)], check=True)
        argv = ["git", "-C", str(other), "-c", "user.name=Synthetic", "-c",
                "user.email=test@example.invalid", "commit", "-q", "--allow-empty",
                "-m", "other"]
        command = self.shell_join(argv)
        _, code, _ = self.causal_command(command)
        self.assertEqual(code, 0)
        # 0.13 transfer (a): a cross-repository commit is not a Guard
        # question any more; repository matching moved to the executing
        # agent and to release-adapter exact contracts. No binding may
        # name the other repository's commit.
        self.assertEqual(self.decision("git push origin main"), ("allow", ""))
        self.assert_no_binding_records()

    def test_repository_root_newline_is_not_stripped(self):
        import os
        import subprocess

        from cg_commit import repository
        if os.name == "nt":
            self.skipTest("POSIX newline directory identity")
        root = self.root / "repo\n"
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        self.assertEqual(repository(str(root)), str(root.resolve()))
