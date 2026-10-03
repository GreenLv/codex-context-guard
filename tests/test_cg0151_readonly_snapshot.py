"""CGI-20261003 read-only snapshot regression (CG-0151 D3).

The checkpoint_status diagnostic read path must be a whole-query property:
no lifecycle lock creation or owner write, no chmod/mkdir, no migration,
rebuild, backup or sidecar write, and no fabricated freshness. Every row
below witnesses the byte/filesystem state of the private tree before and
after real queries; the native two-platform restricted-child facts stay a
separate pending gate.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

from tests.test_cg122_p0_counterexamples import P0Harness, cg


def tree_inventory(root: Path) -> dict[str, list]:
    result: dict[str, list] = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        info = path.lstat()
        result[rel] = [
            stat.S_ISLNK(info.st_mode),
            stat.S_ISDIR(info.st_mode),
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            info.st_ino,
        ]
    return result


class ReadOnlySnapshotTests(P0Harness):
    def ready(self, session: str = "p0"):
        self.activate(session)
        self.prompt("请核对示例诊断结果。", session)
        state = self.state(session)
        self.turn = state["completion_attempt"]["turn_id"]
        self.session_dir = self.root / "private" / "sessions-v2" / session
        return state

    def query(self, session: str = "p0", turn: str | None = None, **kw):
        return cg.checkpoint_status(
            self.root / "private", session, turn or self.turn, "p0token", **kw
        )

    # -- R01: every mode succeeds with a byte-stable private tree --------
    def test_r01_all_modes_read_without_tree_changes(self):
        self.ready()
        # A writer flow first, so a lock file exists and must not change.
        self.dispatch("Stop", last_assistant_message="诊断中。")
        lock_path = self.root / "private" / "sessions-v2" / ".locks" / "p0.lock"
        lock_before = lock_path.read_bytes()
        before = tree_inventory(self.root / "private")
        turn = self.state()["completion_attempt"]["turn_id"]
        default = self.query(turn=turn)
        self.assertEqual(default["mode"], "current_work_unit")
        self.assertNotIn("advanced_commands", default)
        commands = self.query(turn=turn, commands=True)
        self.assertIn("advanced_commands", commands)
        full = self.query(turn=turn, full=True)
        self.assertEqual(full["mode"], "full")
        item = self.query(turn=turn, item_id="R001")
        self.assertEqual(item["item"]["id"], "R001")
        revision = default["revision"]
        unchanged = self.query(turn=turn, after_revision=revision)
        self.assertTrue(unchanged.get("unchanged"))
        after = tree_inventory(self.root / "private")
        self.assertEqual(before, after)
        self.assertEqual(lock_path.read_bytes(), lock_before)

    # -- R02: read-only directory still serves the query ------------------
    # POSIX mode-bit denial probe. On Windows, directory write denial is an
    # ACL/restricted-token fact that mode bits cannot express; that surface
    # stays a required native-Windows restricted-child gate and is never
    # substituted by a skip here.
    @unittest.skipUnless(hasattr(os, "geteuid"),
                         "POSIX mode-bit write denial requires os.geteuid; "
                         "native Windows ACL/restricted-child probe remains "
                         "a separate required gate")
    def test_r02_write_denied_tree_still_readable(self):
        if os.geteuid() == 0:
            self.skipTest("permission denial requires a non-root runner")
        if sys.platform == "win32":
            self.skipTest("POSIX mode-bit denial does not model Windows ACLs")
        self.ready()
        self.dispatch("Stop", last_assistant_message="诊断中。")
        before = tree_inventory(self.root / "private")
        session_dir = self.root / "private" / "sessions-v2" / "p0"
        original_mode = session_dir.stat().st_mode
        try:
            session_dir.chmod(0o500)
            turn = self.state()["completion_attempt"]["turn_id"]
            result = self.query(turn=turn)
            self.assertEqual(result["mode"], "current_work_unit")
            after = tree_inventory(self.root / "private")
            # APFS chmod can rescale directory sizes; the write witness is
            # the exact path set plus byte-level stability of regular files.
            self.assertEqual(set(after), set(before))
            self.assertEqual(
                {k: v for k, v in after.items() if not v[1]},
                {k: v for k, v in before.items() if not v[1]})
        finally:
            session_dir.chmod(original_mode)
        # Not an unexercised mkdir: a real write must fail on this tree
        # while the reader succeeds on the same bytes.
        session_dir.chmod(0o500)
        try:
            with self.assertRaises(OSError):
                (session_dir / "probe").write_text("x")
            turn = self.state()["completion_attempt"]["turn_id"]
            self.assertEqual(self.query(turn=turn)["mode"], "current_work_unit")
        finally:
            session_dir.chmod(original_mode)

    # -- R03: fresh and legacy boundaries create nothing ------------------
    def test_r03_missing_and_legacy_sessions_create_nothing(self):
        self.ready()
        self.dispatch("Stop", last_assistant_message="诊断中。")
        before = tree_inventory(self.root / "private")
        with self.assertRaisesRegex(RuntimeError, "session_not_found"):
            self.query(session="missing-session")
        self.assertEqual(tree_inventory(self.root / "private"), before)
        # Legacy namespace bytes stay untouched by the same runtime.
        legacy_root = self.root / "private" / "sessions" / "legacy-s"
        legacy_root.mkdir(parents=True)
        legacy_state = self.state()
        legacy_state["session"]["id"] = "legacy-s"
        legacy_state["content_hash"] = cg.state_content_hash(legacy_state)
        legacy_state_path = legacy_root / "state.json"
        legacy_state_path.write_text(json.dumps(legacy_state),
                                     encoding="utf-8")
        legacy_before = legacy_state_path.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "invalid private completion"):
            cg.checkpoint_status(
                self.root / "private", "legacy-s", self.turn, "wrong")
        self.assertEqual(legacy_state_path.read_bytes(), legacy_before)
        after = tree_inventory(self.root / "private")
        self.assertEqual(sorted(set(after) - set(before)),
                         ["sessions", "sessions/legacy-s",
                          "sessions/legacy-s/state.json"])

    # -- R04: damaged states fail explicitly without repair ---------------
    def test_r04_damaged_states_fail_without_rebuild_or_backup(self):
        self.ready()
        self.dispatch("Stop", last_assistant_message="诊断中。")
        state_path = self.session_dir / "state.json"
        original = state_path.read_bytes()
        turn = json.loads(original)["completion_attempt"]["turn_id"]
        unknown_schema = json.loads(original)
        unknown_schema["schema_version"] = 99
        unknown_schema["content_hash"] = cg.state_content_hash(unknown_schema)
        hash_mismatch = json.loads(original)
        hash_mismatch["requirements"] = []
        hash_mismatch["content_hash"] = "0" * 64
        cases = {
            "corrupt": (b"{not json at all", "state_file_not_valid_json"),
            "truncated": (original[: len(original) // 2],
                          "state_file_not_valid_json|state_integrity_failed"),
            "unknown-schema": (json.dumps(unknown_schema).encode(),
                               "unsupported_state_schema_for_readonly_snapshot"),
            "hash-mismatch": (json.dumps(hash_mismatch).encode(),
                              "state_integrity_failed"),
        }
        before_state_files = {
            key for key in tree_inventory(self.root / "private")
            if "state" in key
        }
        try:
            for label, (payload, expected) in cases.items():
                with self.subTest(case=label):
                    state_path.write_bytes(payload)
                    with self.assertRaisesRegex(RuntimeError, expected):
                        self.query(turn=turn)
                    after_state_files = {
                        key
                        for key in tree_inventory(self.root / "private")
                        if "state" in key
                    }
                    self.assertEqual(after_state_files,
                                     set(before_state_files), label)
                    self.assertFalse(
                        list(self.session_dir.glob("state.corrupt.*.json")))
                    self.assertFalse(list(self.session_dir.glob("*.bak")))
        finally:
            state_path.write_bytes(original)

    def test_r04b_replaced_state_file_identity_is_rejected(self):
        self.ready()
        state_path = self.session_dir / "state.json"
        state_path.unlink()
        record = next(item for item in
                      (self.session_dir / "prompts").iterdir()
                      if item.is_file())
        try:
            state_path.symlink_to(record)
        except (OSError, NotImplementedError):
            # Unprivileged Windows cannot create this symlink; the
            # replaced-identity rejection then stays covered by the
            # platform-capable lanes and the native gates.
            self.skipTest("symlink creation unavailable for this principal")
        with self.assertRaisesRegex(RuntimeError,
                                    "state_file_not_a_regular_file"):
            self.query()

    # -- R05: concurrent publication returns one consistent revision -----
    def test_r05_writer_publication_yields_whole_revisions(self):
        self.ready()
        published: list[str] = [self.state()["content_hash"]]
        stop = threading.Event()

        def writer():
            index = 0
            while not stop.is_set() and index < 24:
                state = self.state()
                state["wait_condition_sequence"] = index + 1
                self.save_state(state)
                published.append(self.state()["content_hash"])
                index += 1

        thread = threading.Thread(target=writer)
        thread.start()
        try:
            revisions = set()
            for _ in range(20):
                try:
                    result = self.query()
                except RuntimeError as exc:
                    # A bounded transient failure is allowed; an invented
                    # revision never is.
                    self.assertIn(str(exc), {
                        "state_changed_during_read", "state_read_unstable",
                        "state_replaced_during_query",
                        "authority_sources_changed_during_query"})
                    continue
                revisions.add(result["revision"])
            thread.join(timeout=10)
            stop.set()
            self.assertFalse(thread.is_alive())
            # Every racing query may legitimately report explicit stale: the
            # whole-query verifier now spans the final projection too. Once
            # publication is quiescent, a healthy snapshot must succeed.
            final = self.query()
            revisions.add(final["revision"])
            self.assertTrue(revisions <= set(published),
                            (revisions, published))
            self.assertIn(final["revision"], published)
        finally:
            stop.set()
            thread.join(timeout=10)

    # -- R06: replaced lock path and cleanup races stay read-only --------
    def test_r06_replaced_lock_path_neither_read_nor_repaired(self):
        self.ready()
        self.dispatch("Stop", last_assistant_message="诊断中。")
        lock_path = self.root / "private" / "sessions-v2" / ".locks" / "p0.lock"
        decoy = self.root / "private" / "sessions-v2" / ".locks" / "decoy.lock"
        decoy.write_bytes(b"decoy")
        lock_path.unlink()
        try:
            lock_path.symlink_to(decoy)
        except (OSError, NotImplementedError):
            decoy.unlink()
            self.skipTest("symlink creation unavailable for this principal")
        try:
            turn = self.state()["completion_attempt"]["turn_id"]
            result = self.query(turn=turn)
            self.assertEqual(result["mode"], "current_work_unit")
            self.assertTrue(lock_path.is_symlink())
            self.assertEqual(decoy.read_bytes(), b"decoy")
            # The reader never revived the session or weakened the writer
            # contract: a writer still fails closed on the linked path.
            with self.assertRaises(cg.StateIntegrityError):
                with cg.session_lock(self.session_dir):
                    pass
        finally:
            lock_path.unlink()
            decoy.unlink()

    # -- R07: missing or corrupt derived sidecar writes nothing ----------
    def test_r07_missing_or_corrupt_sidecar_writes_nothing(self):
        self.ready()
        self.dispatch("Stop", last_assistant_message="诊断中。")
        turn = self.state()["completion_attempt"]["turn_id"]
        observation = self.session_dir / "commentary-observation.json"
        result = self.query(turn=turn)
        self.assertEqual(result["commentary_observation"]["status"], "absent")
        self.assertFalse(observation.exists())
        observation.write_text("{broken", encoding="utf-8")
        before_broken = tree_inventory(self.root / "private")
        try:
            result = self.query(turn=turn)
            self.assertEqual(
                result["commentary_observation"]["status"], "unknown")
            after = tree_inventory(self.root / "private")
            self.assertEqual(after, before_broken)
            self.assertEqual(observation.read_text(encoding="utf-8"),
                             "{broken")
        finally:
            observation.unlink()

    # -- R08: bounded retries end in an explicit unknown ------------------
    def test_r08_continuous_change_returns_explicit_failure(self):
        self.ready()
        state_path = self.session_dir / "state.json"
        original = state_path.read_bytes()
        payload = json.loads(original)
        turn = payload["completion_attempt"]["turn_id"]
        real_open = os.open
        replacements = {"count": 0}

        def replace_then_open(path: object, flags: int, *rest: object,
                              **keywords: object) -> int:
            descriptor = real_open(path, flags, *rest, **keywords)
            if (os.fsdecode(path) == str(state_path)
                    and replacements["count"] < 8):
                replacements["count"] += 1
                payload["wait_condition_sequence"] = 100 + replacements["count"]
                cg.atomic_write_json(state_path, payload)
            return descriptor

        try:
            with mock.patch.object(cg.os, "open", side_effect=replace_then_open):
                with self.assertRaisesRegex(
                    RuntimeError, "state_changed_during_read"
                ):
                    self.query(turn=turn)
            self.assertLessEqual(replacements["count"], 8)
        finally:
            state_path.write_bytes(original)

    # -- R09: writer lifecycle is unaffected by the read path -------------
    def test_r09_writer_lifecycle_still_owns_the_kernel_lock(self):
        self.ready()
        turn_a = self.state()["completion_attempt"]["turn_id"]
        self.assertEqual(self.query(turn=turn_a)["mode"], "current_work_unit")
        with cg.session_lock(self.session_dir):
            state = self.state()
            state["wait_condition_sequence"] = 7
            state["content_hash"] = cg.state_content_hash(state)
            cg.save_state(self.session_dir, state)
        turn_b = self.state()["completion_attempt"]["turn_id"]
        self.assertEqual(self.query(turn=turn_b)["mode"], "current_work_unit")
        lock_path = self.root / "private" / "sessions-v2" / ".locks" / "p0.lock"
        self.assertTrue(lock_path.exists())
        lock_content = json.loads(lock_path.read_bytes())
        self.assertEqual(lock_content["lock_protocol"], 2)

    # -- R10: private bindings stay inside the private discovery path ----
    def test_r10_default_snapshot_carries_no_advanced_commands(self):
        self.ready()
        turn = self.state()["completion_attempt"]["turn_id"]
        default = self.query(turn=turn)
        serialized = json.dumps(default, ensure_ascii=True)
        self.assertNotIn("advanced_commands", serialized)
        self.assertNotIn("stage-checkpoint", serialized)
        self.assertNotIn("register-proof", serialized)
        commands = self.query(turn=turn, commands=True)
        self.assertIn("advanced_commands", json.dumps(commands))

    # -- F3: read-only queries verify their still-authoritative sources ---
    def typed_fixture(self):
        target = self.root / "example.py"
        target.write_text("before\n", encoding="utf-8")
        self.activate()
        self.prompt(f"请修改 {target}，并运行 {target} 的测试。")
        self.prompt("持续执行直到当前任务完成。")
        state = self.state()
        self.assertTrue([row for row in state.get("root_controls", [])
                         if "kind" in row])
        self.turn = state["completion_attempt"]["turn_id"]
        self.session_dir = self.root / "private" / "sessions-v2" / "p0"
        return state

    def test_f3_typed_control_source_mutations_fail_explicitly(self):
        state = self.typed_fixture()
        directory = self.session_dir
        metadata = state["prompts"][-1]
        source = directory / metadata["file"]
        companion = directory / "prompts" / "units" / (metadata["id"] + ".json")
        original = source.read_bytes()
        original_companion = companion.read_bytes()
        before = set(tree_inventory(self.root / "private"))
        mutations = {
            "missing-control-source": (lambda: source.unlink(),
                                       str(source.relative_to(self.root / "private"))),
            "changed-control-source": (
                lambda: source.write_text(
                    json.dumps({**json.loads(original),
                                "text": "另一个合成指令。"}), encoding="utf-8"),
                str(source.relative_to(self.root / "private"))),
            "missing-unit-companion": (lambda: companion.unlink(),
                                       str(companion.relative_to(self.root / "private"))),
        }
        try:
            for label, (mutate, mutated_path) in mutations.items():
                with self.subTest(case=label):
                    mutate()
                    with self.assertRaisesRegex(
                        RuntimeError, "authority_source"
                    ):
                        self.query()
                    after = set(tree_inventory(self.root / "private"))
                    # The query itself must add or remove nothing; the
                    # mutated path is the deliberate fixture edit, so its
                    # own existence is normalized out on both sides.
                    self.assertEqual(after | {mutated_path},
                                     before | {mutated_path}, label)
                    self.assertFalse(
                        list(self.session_dir.glob("state.corrupt.*.json")))
        finally:
            source.write_bytes(original)
            companion.write_bytes(original_companion)

    def test_f3_typed_control_healthy_state_still_serves(self):
        self.typed_fixture()
        turn = self.state()["completion_attempt"]["turn_id"]
        result = self.query(turn=turn)
        self.assertEqual(result["mode"], "current_work_unit")
        commands = self.query(turn=turn, commands=True)
        self.assertIn("advanced_commands", commands)

    def test_f3_ordinary_root_source_mutations_fail_explicitly(self):
        self.ready()
        self.dispatch("Stop", last_assistant_message="诊断中。")
        state = self.state()
        directory = self.session_dir
        source = directory / state["prompts"][-1]["file"]
        original = source.read_bytes()
        for label, mutate in {
            "missing": source.unlink,
            "changed": lambda: source.write_text(
                json.dumps({**json.loads(original),
                            "text": "请检查另一个示例。"}), encoding="utf-8"),
        }.items():
            with self.subTest(case=label):
                mutate()
                with self.assertRaisesRegex(
                    RuntimeError, "authority_source"
                ):
                    self.query()
                self.assertFalse(
                    list(self.session_dir.glob("state.corrupt.*.json")))
        source.write_bytes(original)
        turn = self.state()["completion_attempt"]["turn_id"]
        self.assertEqual(self.query(turn=turn)["mode"], "current_work_unit")

    def test_f3_source_change_between_passes_is_explicit_real_event(self):
        """Real production witness: a genuine UserPromptSubmit lands a new
        committed root between the two validator passes (no mocked return
        values); the query must fail as stale instead of serving advanced
        commands bound to the retired turn (review R2 probe 4)."""
        self.ready()
        turn = self.state()["completion_attempt"]["turn_id"]
        state_path = self.session_dir / "state.json"
        original_state = state_path.read_bytes()
        pass_results = []
        original_validator = cg._read_only_prompt_dependencies_valid

        def validator_with_real_new_root(session_dir, state):
            outcome = original_validator(session_dir, state)
            pass_results.append(outcome)
            if len(pass_results) == 1:
                self.prompt("请检查第二份示例文档。")
            return outcome

        try:
            with mock.patch.object(
                cg, "_read_only_prompt_dependencies_valid",
                side_effect=validator_with_real_new_root,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "authority_sources_changed_during_query|"
                    "state_replaced_during_query",
                ):
                    self.query(turn=turn)
            # File witnesses: the query saw two different committed
            # worlds, and the turn really moved on disk.
            self.assertEqual(pass_results, [True, False])
            committed = json.loads(state_path.read_text())
            self.assertNotEqual(committed["completion_attempt"]["turn_id"],
                                turn)
        finally:
            state_path.write_bytes(original_state)

    def test_f3_state_replacement_between_passes_is_explicit_real_file(self):
        """A committed-state replacement (new inode, valid rehashed bytes)
        between the passes invalidates the queried revision even when both
        validator passes agree on their local world."""
        self.ready()
        turn = self.state()["completion_attempt"]["turn_id"]
        state_path = self.session_dir / "state.json"
        original_state = state_path.read_bytes()
        original_validator = cg._read_only_prompt_dependencies_valid

        def validator_with_real_state_replace(session_dir, state):
            outcome = original_validator(session_dir, state)
            if len([True]) == 1 and not getattr(
                    validator_with_real_state_replace, "done", False):
                validator_with_real_state_replace.done = True
                payload = json.loads(original_state)
                payload["wait_condition_sequence"] = 77
                cg.atomic_write_json(state_path, payload)
            return outcome

        validator_with_real_state_replace.done = False
        try:
            with mock.patch.object(
                cg, "_read_only_prompt_dependencies_valid",
                side_effect=validator_with_real_state_replace,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "state_replaced_during_query"
                ):
                    self.query(turn=turn)
            committed = json.loads(state_path.read_text())
            self.assertEqual(committed["wait_condition_sequence"], 77)
        finally:
            state_path.write_bytes(original_state)

    # -- R2 source-snapshot family matrix ---------------------------------
    def _source_matrix_fixture(self, typed: bool):
        if typed:
            return self.typed_fixture()
        self.ready()
        return self.state()

    def test_r2_source_snapshot_family_matrix(self):
        cases = {
            "rehashed-identity": lambda source, companion: (
                lambda: self._mutate_rehashed(source, companion)),
            "removed-record-hash": lambda source, companion: (
                lambda: self._mutate_drop_record_hash(source)),
            "newer-uncommitted-root": lambda source, companion: (
                lambda: self._mutate_newer_root()),
            "missing-source": lambda source, companion: (
                lambda: source.unlink()),
            "changed-text": lambda source, companion: (
                lambda: self._mutate_changed_text(source)),
            "missing-companion": lambda source, companion: (
                lambda: companion.unlink()),
        }
        for typed in (False, True):
            state = self._source_matrix_fixture(typed)
            metadata = state["prompts"][-1]
            source = self.session_dir / metadata["file"]
            companion = (self.session_dir / "prompts" / "units"
                         / (metadata["id"] + ".json"))
            original_source = source.read_bytes()
            has_companion = companion.exists()
            original_companion = companion.read_bytes() if has_companion else None
            for label, build in cases.items():
                if label == "missing-companion" and not has_companion:
                    continue
                with self.subTest(root=("typed" if typed else "plain"),
                                  case=label):
                    build(source, companion)()
                    with self.assertRaisesRegex(
                        RuntimeError, "authority_source|state_"
                    ):
                        self.query()
                    self.assertFalse(
                        list(self.session_dir.glob("state.corrupt.*.json")))
                    if label == "newer-uncommitted-root":
                        (self.session_dir / "prompts" / "P9999.json").unlink()
                    elif label == "missing-source":
                        source.write_bytes(original_source)
                    elif label == "missing-companion":
                        companion.write_bytes(original_companion)
                    else:
                        source.write_bytes(original_source)

    def _mutate_rehashed(self, source, companion):
        record = json.loads(source.read_text())
        record["authority"] = "untrusted_attachment"
        record["origin"] = "delegated"
        record["record_sha256"] = cg.prompt_record_hash(record)
        source.write_text(json.dumps(record), encoding="utf-8")
        if companion.exists():
            binding = json.loads(companion.read_text())
            binding["prompt_record_sha256"] = record["record_sha256"]
            binding["record_sha256"] = cg.sha256_text(cg.canonical_json(
                {key: value for key, value in binding.items()
                 if key != "record_sha256"}))
            companion.write_text(json.dumps(binding), encoding="utf-8")

    def _mutate_drop_record_hash(self, source):
        record = json.loads(source.read_text())
        record.pop("record_sha256", None)
        source.write_text(json.dumps(record), encoding="utf-8")

    def _mutate_newer_root(self):
        state = self.state()
        seq = int(state["core_event_sequence"])
        record = {
            "id": "P9999", "created_at": cg.utc_now(),
            "sha256": cg.sha256_text("请检查另一个示例。"),
            "text": "请检查另一个示例。",
            "unicode_repairs": 0, "origin": "human", "authority": "user",
            "actor_id": None, "core_event_seq": seq + 1,
        }
        record["record_sha256"] = cg.prompt_record_hash(record)
        cg.atomic_write_json(self.session_dir / "prompts" / "P9999.json",
                             record)

    def _mutate_changed_text(self, source):
        record = json.loads(source.read_text())
        record["text"] = "请检查另一个示例。"
        source.write_text(json.dumps(record), encoding="utf-8")

    def test_r2_healthy_modes_still_serve_after_matrix(self):
        state = self._source_matrix_fixture(typed=False)
        turn = state["completion_attempt"]["turn_id"]
        default = self.query(turn=turn)
        self.assertEqual(default["mode"], "current_work_unit")
        self.assertIn("advanced_commands",
                      json.dumps(self.query(turn=turn, commands=True)))
        self.assertEqual(self.query(turn=turn, full=True)["mode"], "full")
        self.assertEqual(self.query(turn=turn, item_id="R001")["item"]["id"],
                         "R001")
        unchanged = self.query(turn=turn, after_revision=default["revision"])
        self.assertTrue(unchanged.get("unchanged"))

    def test_r3_query_lifecycle_matrix(self):
        """Real resume/new-root writers across all modes and both root kinds.

        The loader must return its own identity, and no projection may escape
        the final state/binding/source check. Only the arranged Hook writes;
        compare the private inventory after it with the query's final tree.
        """
        modes = {"current": {}, "full": {"full": True},
                 "item": {"item_id": "R001"}, "after_revision": {},
                 "commands": {"commands": True}}
        for typed in (False, True):
            for timing in ("healthy", "after_load", "during_projection"):
                for mode, options in modes.items():
                    with self.subTest(typed=typed, timing=timing, mode=mode):
                        h = P0Harness()
                        h.setUp()
                        try:
                            h.activate()
                            if typed:
                                target = h.root / "example.py"
                                target.write_text("before\n", encoding="utf-8")
                                h.prompt(f"请修改 {target}，并运行 {target} 的测试。")
                                h.prompt("持续执行直到当前任务完成。")
                            else:
                                h.prompt("请检查示例文档。")
                            before = h.state()
                            turn = before["completion_attempt"]["turn_id"]
                            kw = dict(options)
                            if mode == "after_revision":
                                kw["after_revision"] = before["content_hash"]
                            helper = ("read_only_committed_state" if timing == "after_load"
                                      else "advanced_command_context" if mode == "commands"
                                      else "checkpoint_status_snapshot")
                            original = getattr(cg, helper)
                            private = h.root / "private"
                            inventory = tree_inventory(private)
                            def writer(*args, **kwargs):
                                nonlocal inventory
                                if timing == "after_load":
                                    loaded = original(*args, **kwargs)
                                    h.dispatch("SessionStart", source="resume",
                                               turn_id="synthetic-new-turn")
                                    inventory = tree_inventory(private)
                                    return loaded
                                h.prompt("请检查第二份示例文档。")
                                inventory = tree_inventory(private)
                                return original(*args, **kwargs)
                            def query():
                                return cg.checkpoint_status(private, "p0", turn,
                                                            "p0token", **kw)
                            if timing == "healthy":
                                self.assertEqual(query()["revision"], before["content_hash"])
                            else:
                                with mock.patch.object(cg, helper, side_effect=writer):
                                    with self.assertRaisesRegex(
                                        RuntimeError, "state_replaced|authority_source"):
                                        query()
                                current = h.state()
                                self.assertNotEqual(current["content_hash"], before["content_hash"])
                                self.assertNotEqual(current["completion_attempt"],
                                                    before["completion_attempt"])
                            self.assertEqual(tree_inventory(private), inventory)
                        finally:
                            h.doCleanups()

    def test_r3_final_projection_rechecks_authority_matrix(self):
        # State stays byte-identical; only an applicable dependency changes
        # inside the real projection. A state probe alone cannot catch this.
        modes = ({}, {"full": True}, {"item_id": "R001"},
                 {"after_revision": "same"}, {"commands": True})
        for typed in (False, True):
            state = self._source_matrix_fixture(typed)
            source = self.session_dir / state["prompts"][-1]["file"]
            original_bytes = source.read_bytes()
            for options in modes:
                with self.subTest(typed=typed, options=options):
                    kw = dict(options)
                    if "after_revision" in kw:
                        kw["after_revision"] = state["content_hash"]
                    helper = ("advanced_command_context" if kw.get("commands")
                              else "checkpoint_status_snapshot")
                    original = getattr(cg, helper)
                    def mutate(*args, **kwargs):
                        result = original(*args, **kwargs)
                        record = json.loads(original_bytes)
                        record["text"] = "请检查另一个示例。"
                        source.write_text(json.dumps(record), encoding="utf-8")
                        return result
                    try:
                        with mock.patch.object(cg, helper, side_effect=mutate):
                            with self.assertRaisesRegex(RuntimeError, "authority_source"):
                                self.query(**kw)
                        self.assertEqual(self.state()["content_hash"], state["content_hash"])
                    finally:
                        source.write_bytes(original_bytes)

    def test_f3_newer_root_on_disk_fails_typed_query(self):
        self.typed_fixture()
        state = self.state()
        seq = int(state["core_event_seq"] if "core_event_seq" in state
                  else state["core_event_sequence"])
        record = {
            "id": "P9999", "created_at": cg.utc_now(),
            "sha256": cg.sha256_text("较新的合成根指令"), "text": "较新的合成根指令",
            "unicode_repairs": 0, "origin": "human", "authority": "user",
            "actor_id": None, "core_event_seq": seq + 1,
        }
        record["record_sha256"] = cg.prompt_record_hash(record)
        cg.atomic_write_json(self.session_dir / "prompts" / "P9999.json",
                             record)
        turn = state["completion_attempt"]["turn_id"]
        with self.assertRaisesRegex(RuntimeError, "authority_source"):
            self.query(turn=turn)
        (self.session_dir / "prompts" / "P9999.json").unlink()
        result = self.query(turn=turn)
        self.assertEqual(result["mode"], "current_work_unit")


if __name__ == "__main__":
    unittest.main()
