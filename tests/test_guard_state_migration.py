"""Synthetic-fixture controls for the Guard state migration tool.

No real HOME, plugin cache, trust file or private session is ever read: every
fixture below is synthetic and self-contained. The fixtures pin the plan
contract: read-only by default, explicit apply, copy-only migration, same-id
same-digest idempotency, digest-diff conflict isolation outside the data root,
and a compensating restore that removes exactly this run's created paths.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "guard_state_migration_tested", ROOT / "tools/guard_state_migration.py")
assert SPEC and SPEC.loader
GSM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GSM)

V0161 = "context-guard-codex-context-guard-v0161"
STABLE = "context-guard-codex-context-guard"
V0161_ID = "codex-context-guard-v0161"
STABLE_ID = "codex-context-guard"


def write_session(root: Path, session_id: str, *, schema=13, marker="a",
                  prompts=True) -> Path:
    session = root / session_id
    (session / "prompts").mkdir(parents=True)
    (session / "state.json").write_text(
        json.dumps({"schema": schema, "session_id": session_id,
                    "marker": marker * 32}),
        encoding="utf-8")
    if prompts:
        (session / "prompts" / "units.json").write_text("[]", encoding="utf-8")
    return session


def make_home(base: Path, name="home") -> Path:
    home = base / name
    (home / "plugins" / "data" / V0161).mkdir(parents=True)
    (home / "plugins" / "data" / STABLE).mkdir(parents=True)
    return home


def ns(home: Path, identity: str, namespace="sessions-v2") -> Path:
    path = home / "plugins" / "data" / identity / namespace
    path.mkdir(parents=True, exist_ok=True)
    return path


def run(args, **kwargs):
    return GSM.main(args)


class InventoryControls(unittest.TestCase):
    def test_inventory_classifies_roots_and_conflicts_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home = make_home(base)
            source = ns(home, V0161)
            write_session(source, "0aa00000-0000-0000-0000-000000000001")
            stable = ns(home, STABLE)
            write_session(stable, "0aa00000-0000-0000-0000-000000000002")
            write_session(stable, "0aa00000-0000-0000-0000-000000000001",
                          marker="b")  # same id, different content
            legacy = ns(home, V0161, "sessions")
            write_session(legacy, "0aa00000-0000-0000-0000-000000000003",
                          prompts=False)
            before = {p: p.stat().st_mtime_ns for p in home.rglob("*")}
            out = base / "results" / "inventory.json"
            code = run(["inventory", "--home", str(home), "--output", str(out)])
            self.assertEqual(0, code)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(GSM.SCHEMA, payload["schema"])
            self.assertTrue(payload["read_only"])
            identities = {root["identity"] for root in payload["homes"][0]["data_roots"]}
            self.assertEqual({V0161_ID, STABLE_ID}, identities)
            self.assertGreaterEqual(payload["unique_session_ids"], 3)
            conflict = [row for row in payload["conflicts"]
                        if row["id"] == "0aa00000-0000-0000-0000-000000000001"]
            self.assertEqual(1, len(conflict))
            self.assertIn("never", conflict[0]["note"])
            after = {p: p.stat().st_mtime_ns for p in home.rglob("*")}
            self.assertEqual(before, after, "inventory must not write to the home")

    def test_inventory_requires_explicit_home_and_new_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            out = base / "x.json"
            self.assertEqual(2, run(["inventory", "--home", str(base / "missing"),
                                     "--output", str(out)]))
            existing = base / "existing.json"
            existing.write_text("{}", encoding="utf-8")
            home = make_home(base)
            self.assertEqual(2, run(["inventory", "--home", str(home),
                                     "--output", str(existing)]))


class PlanControls(unittest.TestCase):
    def test_plan_decisions_cover_copy_skip_isolate_and_unsupported(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home = make_home(base)
            write_session(ns(home, V0161), "0bb00000-0000-0000-0000-000000000001")
            write_session(ns(home, V0161), "0bb00000-0000-0000-0000-000000000002",
                          schema=99)
            write_session(ns(home, V0161), "0bb00000-0000-0000-0000-000000000003")
            # target already has same id with different content -> isolate
            write_session(ns(home, STABLE), "0bb00000-0000-0000-0000-000000000003",
                          marker="z")
            plan_path = base / "plan.json"
            code = run(["plan", "--source-home", str(home),
                        "--source-identity", V0161_ID,
                        "--target-home", str(home),
                        "--target-identity", STABLE_ID,
                        "--output", str(plan_path)])
            self.assertEqual(0, code)
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            decisions = {row["id"]: row["decision"] for row in plan["sessions"]}
            self.assertEqual("copy", decisions["0bb00000-0000-0000-0000-000000000001"])
            self.assertEqual("excluded_unsupported_state",
                             decisions["0bb00000-0000-0000-0000-000000000002"])
            self.assertEqual("isolate",
                             decisions["0bb00000-0000-0000-0000-000000000003"])
            self.assertEqual(1, len(plan["conflicts"]))

    def test_plan_refuses_non_stable_target_and_identical_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home = make_home(base)
            identity = V0161_ID
            self.assertEqual(2, run(["plan", "--source-home", str(home),
                                     "--source-identity", identity,
                                     "--target-home", str(home),
                                     "--target-identity", identity,
                                     "--output", str(base / "p.json")]))
            self.assertEqual(2, run(["plan", "--source-home", str(home),
                                     "--source-identity", identity,
                                     "--target-home", str(home),
                                     "--target-identity", "codex-context-guard-v0161",
                                     "--output", str(base / "p2.json")]))

    def test_plan_reports_legacy_sessions_as_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home = make_home(base)
            write_session(ns(home, V0161, "sessions"),
                          "0cc00000-0000-0000-0000-000000000001", prompts=False)
            write_session(ns(home, V0161), "0cc00000-0000-0000-0000-000000000002")
            plan_path = base / "plan.json"
            code = run(["plan", "--source-home", str(home),
                        "--source-identity", V0161_ID,
                        "--target-home", str(home),
                        "--target-identity", STABLE_ID,
                        "--output", str(plan_path)])
            self.assertEqual(0, code)
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(1, plan["legacy_session_count"])
            self.assertIn("retain_in_place", plan["scope"])
            self.assertTrue(all(row["id"] != "0cc00000-0000-0000-0000-000000000001"
                                for row in plan["sessions"]))


class ApplyControls(unittest.TestCase):
    def plan_for(self, base: Path) -> tuple[Path, Path, Path]:
        home = make_home(base)
        write_session(ns(home, V0161), "0dd00000-0000-0000-0000-000000000001")
        write_session(ns(home, V0161), "0dd00000-0000-0000-0000-000000000002",
                      marker="b")
        write_session(ns(home, STABLE), "0dd00000-0000-0000-0000-000000000002",
                      marker="target")
        write_session(ns(home, STABLE), "0dd00000-0000-0000-0000-000000000009")
        plan_path = base / "plan.json"
        code = run(["plan", "--source-home", str(home),
                    "--source-identity", V0161_ID,
                    "--target-home", str(home),
                    "--target-identity", STABLE_ID,
                    "--output", str(plan_path)])
        self.assertEqual(0, code)
        return home, plan_path, ns(home, STABLE)

    def test_apply_is_copy_only_and_isolates_conflicts_outside_data_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home, plan_path, target_root = self.plan_for(base)
            before_target = {p: p.read_bytes() for p in target_root.rglob("*")
                             if p.is_file()}
            workspace = base / "workspace"
            code = run(["apply", "--plan", str(plan_path),
                        "--workspace", str(workspace)])
            self.assertEqual(0, code)
            manifest = json.loads((workspace / "apply-manifest.json").read_text(
                encoding="utf-8"))
            created_ids = {row["id"] for row in manifest["created"]}
            self.assertEqual({"0dd00000-0000-0000-0000-000000000001"}, created_ids)
            isolated = {row["id"] for row in manifest["isolated"]}
            self.assertEqual({"0dd00000-0000-0000-0000-000000000002"}, isolated)
            # The conflict copy went to the workspace, never into the data
            # root: the pre-existing target session keeps its original bytes.
            self.assertEqual(
                "target" * 32,
                json.loads((target_root / "0dd00000-0000-0000-0000-000000000002"
                            / "state.json").read_text(encoding="utf-8"))["marker"])
            self.assertTrue((workspace / "conflicts" /
                             "0dd00000-0000-0000-0000-000000000002" / "state.json")
                            .is_file())
            # Pre-existing target session untouched; target lifecycle locks exist.
            after_target = {p: p.read_bytes() for p in target_root.rglob("*")
                            if p.is_file()}
            for path, payload in before_target.items():
                self.assertEqual(payload, after_target[path])
            self.assertTrue((target_root / ".locks" /
                             "0dd00000-0000-0000-0000-000000000001.lock").is_file())

    def test_apply_is_idempotent_and_refuses_changed_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home, plan_path, target_root = self.plan_for(base)
            workspace = base / "workspace"
            self.assertEqual(0, run(["apply", "--plan", str(plan_path),
                                     "--workspace", str(workspace)]))
            workspace2 = base / "workspace2"
            self.assertEqual(0, run(["apply", "--plan", str(plan_path),
                                     "--workspace", str(workspace2)]))
            manifest2 = json.loads((workspace2 / "apply-manifest.json").read_text(
                encoding="utf-8"))
            self.assertEqual([], manifest2["created"])
            reasons = " ".join(row["reason"] for row in manifest2["skipped"])
            self.assertIn("target identical", reasons)
            # Source mutated after plan -> that row fails closed, nothing written.
            session = ns(home, V0161) / "0dd00000-0000-0000-0000-000000000001"
            (session / "state.json").write_text('{"schema": 13, "marker": "mutated"}',
                                                encoding="utf-8")
            plan3 = base / "plan3.json"
            code = run(["plan", "--source-home", str(home),
                        "--source-identity", V0161_ID,
                        "--target-home", str(home),
                        "--target-identity", STABLE_ID,
                        "--output", str(plan3)])
            self.assertEqual(0, code)
            plan = json.loads(plan3.read_text(encoding="utf-8"))
            row = next(r for r in plan["sessions"]
                       if r["id"] == "0dd00000-0000-0000-0000-000000000001")
            # The target holds the previously copied (old) digest; the mutated
            # source digest differs, so the plan isolates instead of overwriting.
            self.assertEqual("isolate", row["decision"])

    def test_apply_fails_row_when_writer_holds_source_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home, plan_path, target_root = self.plan_for(base)
            workspace = base / "workspace"
            import fcntl

            lock = home / "plugins" / "data" / V0161 / "sessions-v2" / ".locks" \
                / "0dd00000-0000-0000-0000-000000000001.lock"
            lock.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                with mock.patch.object(GSM, "LOCK_DEADLINE_SECONDS", 0.4):
                    code = run(["apply", "--plan", str(plan_path),
                                "--workspace", str(workspace)])
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            self.assertEqual(1, code)
            manifest = json.loads((workspace / "apply-manifest.json").read_text(
                encoding="utf-8"))
            failed_ids = {row["id"] for row in manifest["failed"]}
            self.assertIn("0dd00000-0000-0000-0000-000000000001", failed_ids)
            self.assertFalse((target_root /
                              "0dd00000-0000-0000-0000-000000000001").exists())

    def test_interrupted_copy_is_cleaned_and_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home, plan_path, target_root = self.plan_for(base)
            workspace = base / "workspace"

            def exploding_copy(source, target):
                target.mkdir(mode=0o700)
                (target / "state.json").write_text("partial", encoding="utf-8")
                raise OSError("simulated interruption")

            with mock.patch.object(GSM, "_copy_tree_exclusive",
                                   side_effect=exploding_copy):
                code = run(["apply", "--plan", str(plan_path),
                            "--workspace", str(workspace)])
            self.assertEqual(1, code)
            self.assertFalse((target_root /
                              "0dd00000-0000-0000-0000-000000000001").exists())
            manifest = json.loads((workspace / "apply-manifest.json").read_text(
                encoding="utf-8"))
            # Both the copy row and the conflict-isolation row fail closed, and
            # neither leaves a partial directory behind.
            self.assertIn("0dd00000-0000-0000-0000-000000000001",
                          {row["id"] for row in manifest["failed"]})
            self.assertEqual([], manifest["created"])
            self.assertFalse((workspace / "conflicts" /
                              "0dd00000-0000-0000-0000-000000000002").exists())

    def test_apply_refuses_symlinked_session_and_existing_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home, plan_path, _ = self.plan_for(base)
            workspace = base / "workspace"
            workspace.mkdir()
            self.assertEqual(2, run(["apply", "--plan", str(plan_path),
                                     "--workspace", str(workspace)]))
            # A symlinked source session is never followed and stays visible.
            source = ns(home, V0161)
            outside = base / "outside"
            outside.mkdir()
            link = source / "0ee00000-0000-0000-0000-000000000001"
            os.symlink(outside, link)
            plan_symlink = base / "plan-symlink.json"
            self.assertEqual(0, run(["plan", "--source-home", str(home),
                                     "--source-identity", V0161_ID,
                                     "--target-home", str(home),
                                     "--target-identity", STABLE_ID,
                                     "--output", str(plan_symlink)]))
            plan = json.loads(plan_symlink.read_text(encoding="utf-8"))
            decisions = {row["id"]: row["decision"] for row in plan["sessions"]}
            self.assertEqual("excluded_symlink",
                             decisions["0ee00000-0000-0000-0000-000000000001"])
            # Apply never follows the linked entry either.
            workspace3 = base / "workspace3"
            self.assertEqual(0, run(["apply", "--plan", str(plan_symlink),
                                     "--workspace", str(workspace3)]))
            manifest3 = json.loads((workspace3 / "apply-manifest.json").read_text(
                encoding="utf-8"))
            self.assertNotIn(
                "0ee00000-0000-0000-0000-000000000001",
                {row["id"] for row in manifest3["created"]})


class VerifyRestoreControls(unittest.TestCase):
    def full_cycle(self, base: Path):
        home = make_home(base)
        write_session(ns(home, V0161), "0ff00000-0000-0000-0000-000000000001")
        write_session(ns(home, V0161), "0ff00000-0000-0000-0000-000000000002",
                      marker="b")
        write_session(ns(home, STABLE), "0ff00000-0000-0000-0000-000000000002",
                      marker="target")
        plan_path = base / "plan.json"
        code = run(["plan", "--source-home", str(home),
                    "--source-identity", V0161_ID,
                    "--target-home", str(home),
                    "--target-identity", STABLE_ID,
                    "--output", str(plan_path)])
        self.assertEqual(0, code)
        workspace = base / "workspace"
        code = run(["apply", "--plan", str(plan_path), "--workspace", str(workspace)])
        self.assertEqual(0, code)
        return home, plan_path, workspace, ns(home, STABLE)

    def test_verify_passes_then_detects_post_apply_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home, plan_path, workspace, target_root = self.full_cycle(base)
            self.assertEqual(0, run(["verify", "--plan", str(plan_path),
                                     "--workspace", str(workspace)]))
            created = target_root / "0ff00000-0000-0000-0000-000000000001"
            (created / "state.json").write_text('{"schema": 13, "marker": "edited"}',
                                                encoding="utf-8")
            workspace2 = base / "workspace2"
            # Re-verify the same apply manifest through a fresh workspace copy.
            manifest_path = workspace / "apply-manifest.json"
            workspace2.mkdir()
            (workspace2 / "apply-manifest.json").write_text(
                manifest_path.read_text(encoding="utf-8"), encoding="utf-8")
            code = run(["verify", "--plan", str(plan_path),
                        "--workspace", str(workspace2)])
            self.assertEqual(1, code)
            result = json.loads((workspace2 / "verify-result.json").read_text(
                encoding="utf-8"))
            self.assertEqual("problems", result["status"])

    def test_restore_removes_exactly_created_paths_and_refuses_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home, plan_path, workspace, target_root = self.full_cycle(base)
            untouched = target_root / "0ff00000-0000-0000-0000-000000000002"
            self.assertTrue(untouched.exists())
            code = run(["restore", "--workspace", str(workspace)])
            self.assertEqual(0, code)
            self.assertFalse((target_root /
                              "0ff00000-0000-0000-0000-000000000001").exists())
            self.assertTrue(untouched.exists(), "unrelated target must stay")
            result = json.loads((workspace / "restore-result.json").read_text(
                encoding="utf-8"))
            self.assertEqual("restored", result["status"])
            # Restoring again is a no-op on already-absent paths.
            code = run(["restore", "--workspace", str(workspace)])
            self.assertEqual(0, code)

    def test_restore_refuses_to_remove_changed_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            home, plan_path, workspace, target_root = self.full_cycle(base)
            created = target_root / "0ff00000-0000-0000-0000-000000000001"
            (created / "state.json").write_text('{"schema": 13, "marker": "live now"}',
                                                encoding="utf-8")
            code = run(["restore", "--workspace", str(workspace)])
            self.assertEqual(1, code)
            self.assertTrue(created.exists(), "changed target must not be removed")
            result = json.loads((workspace / "restore-result.json").read_text(
                encoding="utf-8"))
            self.assertEqual("partial_refused", result["status"])


class SubprocessWire(unittest.TestCase):
    def test_cli_entry_refuses_without_command(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/guard_state_migration.py")],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(2, result.returncode)

    def test_cli_refused_inputs_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/guard_state_migration.py"),
                 "inventory", "--home", str(base / "missing"),
                 "--output", str(base / "out.json")],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(2, result.returncode)
            self.assertIn("guard_state_migration=refused", result.stderr)


if __name__ == "__main__":
    unittest.main()
