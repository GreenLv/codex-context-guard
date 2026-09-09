"""Root file authority and authorize-before-development regressions.

0.13 layer transfer: the DEFAULT execution-approval gate was removed, so
the per-claim provenance chain this module used to verify — prepared_source
scope ceilings (paths/ready/sha256), authorize-before-development timing,
generation swaps, and the commit_scope_mismatch denies they produced — is
no longer produced or enforced. Each old failure family transfers to one
of three layers, and every test below asserts the layer that now owns it:
(a) executing-agent/host responsibility — object selection, timing, and
scope discipline are no longer Guard questions, so the same inputs yield
the plain allow wire with no fabricated authorization or frozen scope in
state (INV-01/INV-02); (b) release-adapter exact contracts — tested under
explicit adoption elsewhere (see also the release-boundary transfer in
tests/test_cg122_p0_counterexamples.py); (c) preserved constraint
recording asserted here — the user's positive object lists and 不要/必须
restrictions still become durable pending requirements, and quoted/
delegated mentions still never become root constraints. The statement
grammar coverage that remains purely parseable (explicit object nouns,
exclusions, quoted examples) is asserted through the recorded requirement
text; pure classification tests live in the sibling modules.
"""
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

    def recorded_requirement_texts(self, fixture):
        state = fixture.state()
        return [item["text"] for item in state["requirements"]]

    def assert_statement_recorded(self, fixture, *needles):
        texts = "\n".join(self.recorded_requirement_texts(fixture))
        for needle in needles:
            self.assertIn(needle, texts,
                          f"constraint {needle!r} must survive as a requirement")
        fixture_state = fixture.state()
        for item in fixture_state["requirements"]:
            self.assertEqual(item["status"], "pending")

    def assert_no_fabricated_scope(self, fixture):
        state = fixture.state()
        for unit in state["work_units"]:
            self.assertNotIn(
                "authorizations", unit,
                "0.13 records no prepared scope ceiling for prompts",
            )
        self.assertEqual(self.frozen_scope_paths_of(fixture), [])

    def frozen_scope_paths_of(self, fixture):
        state = fixture.state()
        unit_id = state["work_state"]["active_work_unit_id"]
        unit = fixture.unit(state, unit_id)
        paths: list[str] = []
        for record in unit.get("authorizations") or []:
            if not isinstance(record, dict) or record.get("state") != "active":
                continue
            prepared = record.get("prepared_source")
            if isinstance(prepared, dict):
                paths.extend(
                    str(entry.get("path"))
                    for entry in prepared.get("entries") or []
                    if isinstance(entry, dict)
                )
        return paths

    def assert_plain_allow(self, fixture, command="git push origin main"):
        permission, reason = fixture.decision(command)
        self.assertEqual(
            (permission, reason), ("allow", ""),
            "the 0.13 default path must return the plain empty-object allow",
        )

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
                # 0.13 transfer: no scope ceiling is solved or frozen from
                # the statement; the positive/negative object grammar is
                # preserved by recording, not enforcement.
                self.assert_no_fabricated_scope(f)
                self.assert_statement_recorded(f, "owned.txt")
                f.git("add", "owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "owned"])
                self.assert_plain_allow(f)
                self.assert_no_fabricated_scope(f)
                self.assert_statement_recorded(f, "owned.txt")

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
                self.assert_no_fabricated_scope(f)
                # The too-broad commit itself is ordinary work now: the
                # exclusion is an executing-agent duty, not a Guard veto.
                f.git("add", "-A")
                f.commit_and_post(["git", "commit", "-q", "-m", "too broad"])
                self.assert_plain_allow(f)
                # 0.13 transfer (c): the 不要提交 restriction survives as a
                # pending requirement for recovery/Stop to surface.
                self.assert_statement_recorded(f, "不要提交 `other.txt`")
                self.assert_no_fabricated_scope(f)

    def test_extensionless_positive_object_is_explicit(self):
        f = self.case()
        f.write("LICENSE", "license")
        f.authorize_commit_push("仅提交 `LICENSE` 并推送 origin main；`other.txt` 保持不动。")
        self.assert_no_fabricated_scope(f)
        self.assert_statement_recorded(f, "LICENSE")
        f.git("add", "LICENSE")
        f.commit_and_post(["git", "commit", "-q", "-m", "license"])
        self.assert_plain_allow(f)

    def test_multiple_positive_objects_form_one_ceiling(self):
        f = self.case()
        f.authorize_commit_push("提交 `owned.txt` 和 `other.txt` 并推送 origin main。")
        self.assert_no_fabricated_scope(f)
        self.assert_statement_recorded(f, "owned.txt", "other.txt")
        f.git("add", "-A")
        f.commit_and_post(["git", "commit", "-q", "-m", "both"])
        self.assert_plain_allow(f)

    def test_unresolved_explicit_ceiling_does_not_fall_back_to_edits(self):
        for target in ("src", "src/", "*.txt", ":(glob)*", "../escape.txt", "CGSOURCEOBJECT99X", "owned.txt or other.txt"):
            with self.subTest(target=target):
                f = self.case()
                (f.project / "src").mkdir()
                f.prompt("继续当前修复。")
                f.task_edit("owned.txt", "verified")
                f.authorize_commit_push(f"Commit only `{target}` and push origin main.")
                # 0.13 transfer (a): an unresolvable target is not a Guard
                # question (INV-02) — no ask, no deny, no silent fallback
                # projection; the agent owns target resolution.
                self.assert_no_fabricated_scope(f)
                f.git("add", "owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "owned"])
                self.assert_plain_allow(f)
                self.assert_statement_recorded(f, target)

    def test_development_authorization_does_not_freeze_old_dirty_blob(self):
        for staged in (False, True):
            with self.subTest(staged=staged):
                f = self.case()
                if staged:
                    f.git("add", "owned.txt")
                f.authorize_commit_push("请先修复 `owned.txt`，完成后提交并推送 origin main。")
                # 0.13 transfer: "authorize before development" no longer
                # freezes any blob at authorization time — the old
                # ready/sha256 ceiling is simply absent.
                self.assert_no_fabricated_scope(f)
                f.task_edit("owned.txt", "final bytes")
                f.git("add", "owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "final"])
                self.assert_plain_allow(f)
                self.assert_no_fabricated_scope(f)
                self.assert_statement_recorded(f, "owned.txt")

    def test_development_authorization_requires_verified_edit(self):
        for edit in (False, True):
            with self.subTest(unverified_edit=edit):
                f = self.case()
                f.authorize_commit_push("First fix `owned.txt`, then commit and push origin main.")
                if edit:
                    f.write("owned.txt", "unobserved bytes")
                f.git("add", "owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "not prepared"])
                # 0.13 transfer (a): whether the edit was observed is not an
                # authorization question (INV-02). Both outcomes yield the
                # plain allow and no fabricated preparation record.
                self.assert_plain_allow(f)
                self.assert_no_fabricated_scope(f)
                self.assert_statement_recorded(f, "owned.txt")

    def test_already_ready_candidate_blob_stays_frozen(self):
        f = self.case()
        f.authorize_commit_push("提交已准备好的 `owned.txt` 并推送 origin main。")
        self.assert_no_fabricated_scope(f)
        f.task_edit("owned.txt", "later drift")
        f.git("add", "owned.txt")
        f.commit_and_post(["git", "commit", "-q", "-m", "drift"])
        # 0.13 transfer: post-statement drift is not a Guard deny; drift
        # detection belongs to the executing agent and review.
        self.assert_plain_allow(f)
        self.assert_no_fabricated_scope(f)

    def test_clean_initial_object_can_be_prepared_after_authorization(self):
        f = self.case()
        (f.project / "owned.txt").unlink()
        f.authorize_commit_push("First implement `owned.txt`, then commit and push origin main.")
        self.assert_no_fabricated_scope(f)
        f.task_edit("owned.txt", "final")
        f.git("add", "owned.txt")
        f.commit_and_post(["git", "commit", "-q", "-m", "final"])
        self.assert_plain_allow(f)
        self.assert_statement_recorded(f, "owned.txt")

    def test_ready_staged_x_survives_later_unstaged_y_after_development(self):
        f = self.case()
        f.authorize_commit_push("请先修复 `owned.txt`，完成后提交并推送 origin main。")
        f.task_edit("owned.txt", "prepared X")
        f.git("add", "owned.txt")
        f.task_edit("owned.txt", "later unstaged Y")
        f.commit_and_post(["git", "commit", "-q", "-m", "X"])
        self.assert_plain_allow(f)

    def test_old_staged_x_is_not_ready_because_worktree_y_was_edited(self):
        f = self.case()
        f.git("add", "owned.txt")
        f.authorize_commit_push("请先修复 `owned.txt`，完成后提交并推送 origin main。")
        f.task_edit("owned.txt", "prepared Y")
        f.commit_and_post(["git", "commit", "-q", "-m", "old X"])
        # 0.13 transfer (a): the staged-vs-worktree distinction that used
        # to decide readiness is no longer a Guard decision; both sides of
        # the old allow/deny pair are plain allows now, and the timing
        # discipline moved to the executing agent.
        self.assert_plain_allow(f)
        self.assert_no_fabricated_scope(f)

    def test_future_preparation_does_not_expand_root_file_ceiling(self):
        f = self.case()
        f.authorize_commit_push("请先修复 `owned.txt`，完成后提交并推送 origin main；不要提交 `other.txt`。")
        f.task_edit("owned.txt", "final")
        f.task_edit("other.txt", "also edited")
        f.git("add", "-A")
        f.commit_and_post(["git", "commit", "-q", "-m", "both"])
        self.assert_plain_allow(f)
        # 0.13 transfer (c): the negative constraint survives verbatim.
        self.assert_statement_recorded(f, "不要提交 `other.txt`")
        self.assert_no_fabricated_scope(f)

    def test_old_generation_edit_does_not_satisfy_new_development(self):
        f = self.case()
        prompt = "请先修复 `owned.txt`，完成后提交并推送 origin main。"
        f.authorize_commit_push(prompt)
        f.task_edit("owned.txt", "first generation")
        f.authorize_commit_push("继续修复 `owned.txt`，完成后提交并推送 origin main。")
        # 0.13 transfer: no generation records exist, so there is no
        # generation to satisfy or expire; both statements are recorded as
        # requirements and the work stays ungated.
        self.assert_no_fabricated_scope(f)
        self.assert_statement_recorded(f, "请先修复", "继续修复")
        f.git("add", "owned.txt")
        f.commit_and_post(["git", "commit", "-q", "-m", "old work"])
        self.assert_plain_allow(f)

    def test_explicit_scope_correction_replaces_old_ceiling(self):
        f = self.case()
        f.authorize_commit_push("提交 `owned.txt` 和 `other.txt` 并推送 origin main。")
        f.authorize_commit_push("更正：仅提交 `owned.txt` 并推送 origin main；`other.txt` 保持不动。")
        # 0.13 transfer: the ceiling is not recomputed — but the
        # correction itself must be recorded so the latest user intent is
        # recoverable (constraint preservation replaces scope replacement).
        self.assert_no_fabricated_scope(f)
        self.assert_statement_recorded(f, "更正", "仅提交 `owned.txt`")
        f.git("add", "owned.txt")
        f.commit_and_post(["git", "commit", "-q", "-m", "corrected"])
        self.assert_plain_allow(f)

    def test_bare_extensionless_object_and_comma_list_are_explicit(self):
        for prompt in ("Commit CONFIG and push origin main.", "Commit `owned.txt`, `CONFIG` and push origin main."):
            with self.subTest(prompt=prompt):
                f = self.case()
                f.write("CONFIG", "config")
                f.authorize_commit_push(prompt)
                expected = ["owned.txt", "CONFIG"] if "owned" in prompt else ["CONFIG"]
                self.assert_no_fabricated_scope(f)
                self.assert_statement_recorded(f, *expected)
                f.git("add", *expected)
                f.commit_and_post(["git", "commit", "-q", "-m", "explicit"])
                self.assert_plain_allow(f)

    def test_new_extensionless_ceiling_does_not_absorb_another_edit(self):
        f = self.case()
        f.authorize_commit_push("Commit only `NEWFILE` and push origin main.")
        self.assertEqual(self.frozen_scope_paths_of(f), [])
        f.task_edit("NEWFILE", "new")
        f.task_edit("other.txt", "other")
        f.git("add", "NEWFILE", "other.txt")
        f.commit_and_post(["git", "commit", "-q", "-m", "too broad"])
        # 0.13 transfer (a): the ceiling cannot absorb edits because no
        # ceiling exists; guarding the object list is the agent's duty.
        self.assert_plain_allow(f)
        self.assert_statement_recorded(f, "NEWFILE")

    def test_unquoted_new_extensionless_file_is_a_ceiling(self):
        f = self.case()
        f.authorize_commit_push("Commit NEWFILE and push origin main.")
        self.assert_no_fabricated_scope(f)
        self.assert_statement_recorded(f, "NEWFILE")
        f.task_edit("NEWFILE", "ready")
        f.task_edit("other.txt", "unrelated")
        f.git("add", "NEWFILE")
        f.commit_and_post(["git", "commit", "-q", "-m", "new file"])
        self.assert_plain_allow(f)

    def test_bare_pathspec_does_not_fall_back_to_verified_edits(self):
        for target in (".", "src/", "*.txt", ":(glob)*"):
            with self.subTest(target=target):
                f = self.case()
                f.prompt("继续当前修复。")
                f.task_edit("owned.txt", "ready")
                f.authorize_commit_push(f"Commit {target} and push origin main.")
                # 0.13 transfer (a): no fallback projection is built from
                # verified edits (INV-02); the push stays a plain allow.
                self.assert_no_fabricated_scope(f)
                f.git("add", "owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "owned"])
                self.assert_plain_allow(f)

    def test_quoted_dotfile_and_extensionless_objects_remain_literal(self):
        for name in (".gitignore", "CONFIG"):
            with self.subTest(name=name):
                f = self.case()
                f.write(name, "literal")
                f.authorize_commit_push(f'Commit "{name}" and push origin main. Leave "other.txt" unchanged.')
                self.assert_no_fabricated_scope(f)
                self.assert_statement_recorded(f, name)
                f.git("add", name)
                f.commit_and_post(["git", "commit", "-q", "-m", "literal"])
                self.assert_plain_allow(f)

    def test_excluded_parent_cannot_authorize_a_descendant(self):
        for exists_at_authorization in (True, False):
            with self.subTest(exists_at_authorization=exists_at_authorization):
                f = self.case()
                if exists_at_authorization:
                    (f.project / "src").mkdir()
                    f.write("src/owned.txt", "ready")
                f.authorize_commit_push("Commit `src/owned.txt` and push origin main; exclude `src`.")
                self.assert_no_fabricated_scope(f)
                if not exists_at_authorization:
                    (f.project / "src").mkdir()
                    f.task_edit("src/owned.txt", "ready")
                f.git("add", "src/owned.txt")
                f.commit_and_post(["git", "commit", "-q", "-m", "excluded descendant"])
                # 0.13 transfer: the contradictory exclusion is preserved
                # as a recorded constraint for the agent/recovery to honor,
                # not resolved into an enforcement veto.
                self.assert_plain_allow(f)
                self.assert_statement_recorded(f, "exclude `src`")


if __name__ == "__main__":
    import unittest

    unittest.main()
