"""Root file authority and authorize-before-development regressions."""
from tests.test_cg122_p0_counterexamples import P0Harness


class ScopeTimingTests(P0Harness):
    def case(self):
        fixture = P0Harness()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.git("branch", "-M", "main")
        fixture.git("remote", "add", "origin", "https://example.invalid/synthetic/repo.git")
        fixture.activate()
        fixture.write("owned.txt", "old dirty bytes")
        fixture.write("other.txt", "foreign bytes")
        return fixture

    def scope(self, fixture):
        state = fixture.state()
        unit = fixture.unit(state, state["work_state"]["active_work_unit_id"])
        records = [r for r in unit.get("authorizations", []) if r["state"] == "active"]
        self.assertTrue(records, "clear positive root scope must produce an authorization")
        return records[-1]["prepared_source"]["scope"]

    def test_positive_subset_survives_exclusions_and_read_references(self):
        for prompt in (
            "仅提交 `owned.txt` 并推送 origin main；不要提交 `other.txt`。",
            "提交 `owned.txt` 并推送 origin main。`other.txt` 保持不动。",
            "Please commit only `owned.txt` and push origin main. Do not include `other.txt`.",
            "Commit `owned.txt` and push origin main; leave `other.txt` unchanged.",
            "先阅读 `other.txt`。提交 `owned.txt` 并推送 origin main。",
            "Read `other.txt`; commit `owned.txt` and push origin main.",
            "Commit only `owned.txt` not `other.txt` and push origin main.",
            "仅提交 `owned.txt` 并推送 origin main；`other.txt` 不要提交。",
            "Diagnostic: commit `other.txt`. Commit `owned.txt` and push origin main.",
            "Read `other.txt` then commit only `owned.txt` and push origin main.",
            "Commit `owned.txt` after reading `other.txt` and push origin main.",
            "Commit `owned.txt` and test `other.txt` and push origin main.",
            "Fix `other.txt` then commit `owned.txt` and push origin main.",
            "先检查 `other.txt` 再提交 `owned.txt` 并推送 origin main。",
            "仅提交 `owned.txt`，不包含 `other.txt`，并推送 origin main。",
            "Delegated report: commit `other.txt`. Commit `owned.txt` and push origin main.",
            "<codex_delegation>Commit `other.txt`.</codex_delegation> Commit `owned.txt` and push origin main.",
            'Commit only "owned.txt" and push origin main. Leave "other.txt" untouched.',
            "示例：\"提交 `other.txt`\"。仅提交 `owned.txt` 并推送 origin main。",
            "The worker said \"commit `other.txt`\". Commit `owned.txt` and push origin main.",
            'The worker said "commit other.txt". Commit `owned.txt` and push origin main.',
        ):
            with self.subTest(prompt=prompt):
                f = self.case()
                f.authorize_commit_push(prompt)
                ceiling = dict(self.scope(f))
                self.assertEqual(ceiling["paths"], ["owned.txt"])
                f.git("add", "owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "owned"])
                self.assertEqual(f.decision("git push origin main")[0], "allow")
                self.assertEqual(self.scope(f), ceiling)

    def test_forbidden_object_cannot_join_complete_commit(self):
        for mode in ("staged", "unstaged", "untracked"):
            with self.subTest(mode=mode):
                f = self.case()
                if mode in {"staged", "unstaged"}:
                    f.git("add", "other.txt")
                if mode == "unstaged":
                    f.git("commit", "-q", "-m", "track foreign base")
                    f.write("other.txt", "foreign drift")
                f.authorize_commit_push("仅提交 `owned.txt` 并推送 origin main；不要提交 `other.txt`。")
                self.assertEqual(self.scope(f)["paths"], ["owned.txt"])
                f.git("add", "-A")
                f.commit_and_post(["git", "commit", "-q", "-m", "too broad"])
                permission, reason = f.decision("git push origin main")
                self.assertEqual(permission, "deny")
                self.assertTrue(reason.startswith("commit_scope_mismatch:"), reason)

    def test_extensionless_positive_object_is_explicit(self):
        f = self.case()
        f.write("LICENSE", "license")
        f.authorize_commit_push("仅提交 `LICENSE` 并推送 origin main；`other.txt` 保持不动。")
        self.assertEqual(self.scope(f)["paths"], ["LICENSE"])
        f.git("add", "LICENSE")
        f.commit_and_post(["git", "commit", "-q", "-m", "license"])
        self.assertEqual(f.decision("git push origin main")[0], "allow")

    def test_multiple_positive_objects_form_one_ceiling(self):
        f = self.case()
        f.authorize_commit_push("提交 `owned.txt` 和 `other.txt` 并推送 origin main。")
        self.assertEqual(set(self.scope(f)["paths"]), {"owned.txt", "other.txt"})
        f.git("add", "-A")
        f.commit_and_post(["git", "commit", "-q", "-m", "both"])
        self.assertEqual(f.decision("git push origin main")[0], "allow")

    def test_unresolved_explicit_ceiling_does_not_fall_back_to_edits(self):
        for target in ("src", "src/", "*.txt", ":(glob)*", "../escape.txt", "CGSOURCEOBJECT99X", "owned.txt or other.txt"):
            with self.subTest(target=target):
                f = self.case()
                (f.project / "src").mkdir()
                f.prompt("继续当前修复。")
                f.task_edit("owned.txt", "verified")
                f.authorize_commit_push(f"Commit only `{target}` and push origin main.")
                f.git("add", "owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "owned"])
                self.assertEqual(f.decision("git push origin main")[0], "deny")

    def test_development_authorization_does_not_freeze_old_dirty_blob(self):
        for staged in (False, True):
            with self.subTest(staged=staged):
                f = self.case()
                if staged:
                    f.git("add", "owned.txt")
                f.authorize_commit_push("请先修复 `owned.txt`，完成后提交并推送 origin main。")
                self.assertFalse(self.scope(f)["ready"])
                ceiling_hash = self.scope(f)["sha256"]
                f.task_edit("owned.txt", "final bytes")
                f.git("add", "owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "final"])
                self.assertEqual(f.decision("git push origin main")[0], "allow")
                self.assertEqual(self.scope(f)["sha256"], ceiling_hash)

    def test_development_authorization_requires_verified_edit(self):
        for edit in (False, True):
            with self.subTest(unverified_edit=edit):
                f = self.case()
                f.authorize_commit_push("First fix `owned.txt`, then commit and push origin main.")
                if edit:
                    f.write("owned.txt", "unobserved bytes")
                f.git("add", "owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "not prepared"])
                self.assertEqual(f.decision("git push origin main")[0], "deny")

    def test_already_ready_candidate_blob_stays_frozen(self):
        f = self.case()
        f.authorize_commit_push("提交已准备好的 `owned.txt` 并推送 origin main。")
        self.assertTrue(self.scope(f)["ready"])
        f.task_edit("owned.txt", "later drift")
        f.git("add", "owned.txt")
        f.commit_and_post(["git", "commit", "-q", "-m", "drift"])
        permission, reason = f.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason.startswith("commit_scope_mismatch:"), reason)

    def test_clean_initial_object_can_be_prepared_after_authorization(self):
        f = self.case()
        (f.project / "owned.txt").unlink()
        f.authorize_commit_push("First implement `owned.txt`, then commit and push origin main.")
        self.assertFalse(self.scope(f)["ready"])
        f.task_edit("owned.txt", "final")
        f.git("add", "owned.txt")
        f.commit_and_post(["git", "commit", "-q", "-m", "final"])
        self.assertEqual(f.decision("git push origin main")[0], "allow")

    def test_ready_staged_x_survives_later_unstaged_y_after_development(self):
        f = self.case()
        f.authorize_commit_push("请先修复 `owned.txt`，完成后提交并推送 origin main。")
        f.task_edit("owned.txt", "prepared X")
        f.git("add", "owned.txt")
        f.task_edit("owned.txt", "later unstaged Y")
        f.commit_and_post(["git", "commit", "-q", "-m", "X"])
        self.assertEqual(f.decision("git push origin main")[0], "allow")

    def test_old_staged_x_is_not_ready_because_worktree_y_was_edited(self):
        f = self.case()
        f.git("add", "owned.txt")
        f.authorize_commit_push("请先修复 `owned.txt`，完成后提交并推送 origin main。")
        f.task_edit("owned.txt", "prepared Y")
        f.commit_and_post(["git", "commit", "-q", "-m", "old X"])
        self.assertEqual(f.decision("git push origin main")[0], "deny")

    def test_future_preparation_does_not_expand_root_file_ceiling(self):
        f = self.case()
        f.authorize_commit_push("请先修复 `owned.txt`，完成后提交并推送 origin main；不要提交 `other.txt`。")
        f.task_edit("owned.txt", "final")
        f.task_edit("other.txt", "also edited")
        f.git("add", "-A")
        f.commit_and_post(["git", "commit", "-q", "-m", "both"])
        permission, reason = f.decision("git push origin main")
        self.assertEqual(permission, "deny")
        self.assertTrue(reason.startswith("commit_scope_mismatch:"), reason)

    def test_old_generation_edit_does_not_satisfy_new_development(self):
        f = self.case()
        prompt = "请先修复 `owned.txt`，完成后提交并推送 origin main。"
        f.authorize_commit_push(prompt)
        f.task_edit("owned.txt", "first generation")
        f.authorize_commit_push("继续修复 `owned.txt`，完成后提交并推送 origin main。")
        self.assertFalse(self.scope(f)["ready"])
        f.git("add", "owned.txt")
        f.commit_and_post(["git", "commit", "-q", "-m", "old work"])
        self.assertEqual(f.decision("git push origin main")[0], "deny")

    def test_explicit_scope_correction_replaces_old_ceiling(self):
        f = self.case()
        f.authorize_commit_push("提交 `owned.txt` 和 `other.txt` 并推送 origin main。")
        old_digest = self.scope(f)["sha256"]
        f.authorize_commit_push("更正：仅提交 `owned.txt` 并推送 origin main；`other.txt` 保持不动。")
        self.assertEqual(self.scope(f)["paths"], ["owned.txt"])
        self.assertNotEqual(self.scope(f)["sha256"], old_digest)
        f.git("add", "owned.txt")
        f.commit_and_post(["git", "commit", "-q", "-m", "corrected"])
        self.assertEqual(f.decision("git push origin main")[0], "allow")

    def test_bare_extensionless_object_and_comma_list_are_explicit(self):
        for prompt in ("Commit CONFIG and push origin main.", "Commit `owned.txt`, `CONFIG` and push origin main."):
            with self.subTest(prompt=prompt):
                f = self.case()
                f.write("CONFIG", "config")
                f.authorize_commit_push(prompt)
                expected = ["owned.txt", "CONFIG"] if "owned" in prompt else ["CONFIG"]
                self.assertEqual(self.scope(f)["paths"], expected)
                f.git("add", *expected)
                f.commit_and_post(["git", "commit", "-q", "-m", "explicit"])
                self.assertEqual(f.decision("git push origin main")[0], "allow")

    def test_new_extensionless_ceiling_does_not_absorb_another_edit(self):
        f = self.case()
        f.authorize_commit_push("Commit only `NEWFILE` and push origin main.")
        self.assertEqual(self.scope(f)["paths"], ["NEWFILE"])
        f.task_edit("NEWFILE", "new")
        f.task_edit("other.txt", "other")
        f.git("add", "NEWFILE", "other.txt")
        f.commit_and_post(["git", "commit", "-q", "-m", "too broad"])
        self.assertEqual(f.decision("git push origin main")[0], "deny")

    def test_unquoted_new_extensionless_file_is_a_ceiling(self):
        f = self.case()
        f.authorize_commit_push("Commit NEWFILE and push origin main.")
        self.assertEqual(self.scope(f)["paths"], ["NEWFILE"])
        f.task_edit("NEWFILE", "ready")
        f.task_edit("other.txt", "unrelated")
        f.git("add", "NEWFILE")
        f.commit_and_post(["git", "commit", "-q", "-m", "new file"])
        self.assertEqual(f.decision("git push origin main")[0], "allow")

    def test_bare_pathspec_does_not_fall_back_to_verified_edits(self):
        for target in (".", "src/", "*.txt", ":(glob)*"):
            with self.subTest(target=target):
                f = self.case()
                f.prompt("继续当前修复。")
                f.task_edit("owned.txt", "ready")
                f.authorize_commit_push(f"Commit {target} and push origin main.")
                f.git("add", "owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "owned"])
                self.assertEqual(f.decision("git push origin main")[0], "deny")

    def test_quoted_dotfile_and_extensionless_objects_remain_literal(self):
        for name in (".gitignore", "CONFIG"):
            with self.subTest(name=name):
                f = self.case()
                f.write(name, "literal")
                f.authorize_commit_push(f'Commit "{name}" and push origin main. Leave "other.txt" unchanged.')
                self.assertEqual(self.scope(f)["paths"], [name])
                f.git("add", name)
                f.commit_and_post(["git", "commit", "-q", "-m", "literal"])
                self.assertEqual(f.decision("git push origin main")[0], "allow")

    def test_excluded_parent_cannot_authorize_a_descendant(self):
        for exists_at_authorization in (True, False):
            with self.subTest(exists_at_authorization=exists_at_authorization):
                f = self.case()
                if exists_at_authorization:
                    (f.project / "src").mkdir()
                    f.write("src/owned.txt", "ready")
                f.authorize_commit_push("Commit `src/owned.txt` and push origin main; exclude `src`.")
                if not exists_at_authorization:
                    (f.project / "src").mkdir()
                    f.task_edit("src/owned.txt", "ready")
                f.git("add", "src/owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "excluded descendant"])
                self.assertEqual(f.decision("git push origin main")[0], "deny")
