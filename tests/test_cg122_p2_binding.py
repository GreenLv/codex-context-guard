"""Synthetic current-task target facts and root confirmation, no network."""
from tests.test_cg122_p0_counterexamples import P0Harness


class CurrentTargetTests(P0Harness):
    def setUp(self):
        super().setUp()
        self.git("branch", "-M", "main")
        self.activate()
        self.prompt("请核对当前修改。")

    def test_attempt_fact_needs_root_confirmation(self):
        command = "git push https://example.invalid/synthetic/repo.git HEAD:main"
        self.assertEqual(self.decision(command)[0], "deny")
        self.prompt("我授权你现在推送。")
        self.assertEqual(self.decision(command)[0], "allow")
        self.assertEqual(self.decision(command.replace("main", "other"))[0], "deny")
        self.assertEqual(self.decision(command.replace("push", "push --force"))[0], "deny")

    def test_multiple_targets_are_not_implicitly_selected(self):
        self.decision("git push https://example.invalid/one/repo.git HEAD:main")
        self.decision("git push https://example.invalid/two/repo.git HEAD:main")
        self.prompt("我授权你现在推送。")
        self.assertEqual(self.decision("git push https://example.invalid/one/repo.git HEAD:main")[0], "deny")

    def test_delegated_confirmation_is_not_root_authority(self):
        command = "git push https://example.invalid/synthetic/repo.git HEAD:main"
        self.decision(command)
        self.dispatch("UserPromptSubmit", prompt="我授权你现在推送。", agent_id="worker-synthetic")
        self.assertEqual(self.decision(command)[0], "deny")

    def test_unknown_target_does_not_acquire_authority_from_attempt(self):
        self.prompt("我授权你现在推送。")
        self.assertEqual(self.decision("git push https://example.invalid/synthetic/repo.git HEAD:main")[0], "deny")

    def test_old_commit_target_cannot_be_inherited(self):
        command = "git push https://example.invalid/synthetic/repo.git HEAD:main"
        self.decision(command)
        self.git("commit", "-q", "--allow-empty", "-m", "other")
        self.prompt("我授权你现在推送。")
        self.assertEqual(self.decision(command)[0], "deny")


class CommitObservationTests(P0Harness):
    def setUp(self):
        super().setUp()
        self.git("branch", "-M", "main")
        self.git("remote", "add", "origin", "https://example.invalid/synthetic/repo.git")
        self.activate()

    def binding(self):
        state = self.state()
        unit = self.unit(state, state["work_state"]["active_work_unit_id"])
        return next(r for r in reversed(unit["authorizations"]) if r["state"] == "active")

    def test_authorization_before_edit_freezes_verified_ready_bytes(self):
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        self.task_edit("owned.txt", "ready")
        self.git("add", "owned.txt")
        self.commit_and_post(["git", "commit", "-q", "-m", "ready"])
        self.assertEqual(self.decision("git push origin main")[0], "allow")
        self.assertEqual(self.binding()["expected_commits"]["push"]["advanced_source"], "causal_commit")

    def test_unattributed_dirty_file_is_not_blanket_scope(self):
        self.write("foreign.txt", "foreign")
        self.authorize_commit_push()
        self.git("add", "foreign.txt")
        self.commit_and_post(["git", "commit", "-q", "-m", "foreign"])
        self.assertEqual(self.decision("git push origin main")[0], "deny")

    def test_same_pair_with_forged_printed_sha_cannot_advance(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        payload = dict(turn_id="paired", tool_use_id="paired", tool_name="shell", tool_input={"command": "git commit -m ready"})
        self.dispatch("PreToolUse", **payload)
        self.dispatch("PostToolUse", **payload, tool_response={"exit_code": 0, "stdout": "[main " + "a" * 40 + "] ready"})
        self.assertEqual(self.decision("git push origin main")[0], "deny")

    def test_failed_real_commit_has_specific_reason(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        _, code, _ = self.causal_command("git commit -m ready")
        self.assertNotEqual(code, 0)
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason.startswith("commit_failed:"), reason)

    def test_dry_run_does_not_advance(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        self.git("add", "owned.txt")
        self.causal_command("git commit --dry-run")
        self.assertEqual(self.decision("git push origin main")[0], "deny")

    def test_multi_command_commit_is_causally_bound(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        _, code, _ = self.causal_command("git add owned.txt && git commit -q -m ready && git status --short")
        self.assertEqual(code, 0)
        self.assertEqual(self.decision("git push origin main")[0], "allow")
        self.assertEqual(self.binding()["expected_commits"]["push"]["advanced_source"], "causal_commit")

    def test_scope_ceiling_does_not_expand_for_later_task_edit(self):
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        self.task_edit("owned.txt", "ready")
        self.task_edit("other.txt", "other")
        self.git("add", "-A")
        self.commit_and_post(["git", "commit", "-q", "-m", "too broad"])
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason.startswith("commit_scope_mismatch:"), reason)

    def test_unstructured_success_uses_exact_causal_readback(self):
        self.write("owned.txt", "ready")
        self.authorize_commit_push("提交 `owned.txt` 并推送 origin main。")
        self.git("add", "owned.txt")
        payload = dict(turn_id="paired", tool_use_id="paired", tool_name="shell", tool_input={"command": "git commit -q -m ready"})
        self.dispatch("PreToolUse", **payload)
        self.git("commit", "-q", "-m", "ready")
        self.dispatch("PostToolUse", **payload, tool_response="Process exited with code 0")
        self.assertEqual(
            self.binding()["expected_commits"]["push"]["commit_sha256"],
            self.git_out("rev-parse", "HEAD"),
        )
        self.assertEqual(
            self.binding()["expected_commits"]["push"]["advanced_source"],
            "causal_commit_readback",
        )

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
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason.startswith("commit_authority_changed:"), reason)

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
        self.assertIsNone(self.binding()["expected_commits"]["push"]["commit_sha256"])
        self.assertEqual(self.decision("git push origin main")[0], "deny")

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
        self.assertEqual(self.frozen_scope_paths(), [])
        self.assertEqual(self.decision("git push origin main")[0], "deny")

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
        self.assertEqual(self.frozen_scope_paths(), ["sub/owned.txt"])

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
        permission, reason = self.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason.startswith("commit_repository_mismatch:"), reason)

    def test_repository_root_newline_is_not_stripped(self):
        import os
        import subprocess

        from cg_commit import repository
        if os.name == "nt":
            self.skipTest("POSIX newline directory identity")
        root = self.root / "repo\n"
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        self.assertEqual(repository(str(root)), str(root.resolve()))
