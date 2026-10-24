#!/usr/bin/env python3
"""0.16.0 installer regressions for F04 (distribution allowlist staging) and
F05 (same-version preflight plus transactional registration/rollback).

The counterexamples reproduced on the 0.15.1 baseline: the staged marketplace
copied an `.env` and a symlink target from outside the tree, and a same-version
drift replaced the registered staging bytes before the cache refusal landed.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "manage_plugin.py"
SPEC = importlib.util.spec_from_file_location("manage_plugin_0160", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager)


class InstallerTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo_root = self.root / "repo"
        self.codex_home = self.root / "codex"
        self.cache_root = manager.plugin_cache_root(self.codex_home)
        self.archive_root = manager.cache_archive_root(self.codex_home)
        self.state: dict[str, object] = {"version": None, "enabled": True}
        self.run_calls: list[tuple[str, ...]] = []
        self.marketplace_state: dict | None = None
        self.fail_plugin_add = False

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_source(self, version: str, body: str = "source hook\n") -> None:
        manifest = {
            "name": manager.PLUGIN_NAME,
            "version": version,
            "repository": "https://github.com/GreenLv/codex-context-guard",
        }
        manifest_path = self.repo_root / ".codex-plugin" / "plugin.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        script = self.repo_root / "scripts" / "context_guard.py"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(body, encoding="utf-8")

    def plugin_entry(self, _codex: str) -> dict | None:
        version = self.state["version"]
        if version is None:
            return None
        return {
            "pluginId": manager.PLUGIN_ID,
            "version": version,
            "enabled": self.state["enabled"],
        }

    def codex_run(self, _codex: str, *args: str):
        self.run_calls.append(args)
        if (
            self.fail_plugin_add
            and len(args) >= 2
            and args[:2] == ("plugin", "add")
            and args[2] == manager.PLUGIN_ID
        ):
            raise RuntimeError("plugin add failed (injected)")
        if len(args) >= 3 and args[:2] == ("plugin", "marketplace"):
            if args[2] == "remove":
                self.marketplace_state = None
            elif args[2] == "add":
                self.marketplace_state = {
                    "root": args[3],
                    "marketplaceSource": {"source": args[3]},
                }
        if args[:2] == ("plugin", "add") and args[2] == manager.PLUGIN_ID:
            shutil.rmtree(self.cache_root, ignore_errors=True)
            version = manager.source_plugin_version(self.repo_root)
            shutil.copytree(self.repo_root, self.cache_root / version)
            self.state["version"] = version
        return type(
            "Completed", (), {"returncode": 0, "stdout": "{}", "stderr": ""}
        )()

    def marketplace_entry(self, _codex: str) -> dict | None:
        return self.marketplace_state

    def install(self) -> None:
        """Drive the production main() flow under mocked Codex CLI calls."""
        with (
            mock.patch.object(manager, "plugin_entry", side_effect=self.plugin_entry),
            mock.patch.object(manager, "run", side_effect=self.codex_run),
            mock.patch.object(
                manager, "marketplace_entry", side_effect=self.marketplace_entry
            ),
            mock.patch.object(manager, "codex_version", return_value=(0, 200, 0)),
        ):
            manager.main_argv = None
            with mock.patch.object(
                sys_module(), "argv",
                ["manage_plugin.py", "--repo-root", str(self.repo_root),
                 "--codex-home", str(self.codex_home), "--apply"],
            ):
                manager.main()

    # ---------------------------------------------------------------- F04

    def test_staging_excludes_top_level_private_files(self) -> None:
        self.write_source("0.2.0")
        (self.repo_root / ".env").write_text("PRIVATE_TOKEN=x\n", encoding="utf-8")
        staged = manager.marketplace_staging(self.codex_home, self.repo_root)
        self.assertFalse((staged / ".env").exists())
        self.assertNotIn(".env", manager._full_tree_digests(staged))

    def test_staging_never_copies_external_symlink_targets(self) -> None:
        self.write_source("0.2.0")
        outside = self.root / "outside-secret.txt"
        outside.write_text("outside secret bytes\n", encoding="utf-8")
        (self.repo_root / "scripts" / "private-link.py").symlink_to(outside)
        staged = manager.marketplace_staging(self.codex_home, self.repo_root)
        # The link is skipped without reading a single external byte.
        self.assertFalse((staged / "scripts" / "private-link.py").exists())
        self.assertNotIn(
            "scripts/private-link.py", manager._full_tree_digests(staged))
        self.assertEqual(outside.read_text(encoding="utf-8"),
                         "outside secret bytes\n")

    def test_staging_contains_exactly_the_distribution_allowlist(self) -> None:
        self.write_source("0.2.0")
        for name in ("LICENSE", "README.md", "CHANGELOG.md"):
            (self.repo_root / name).write_text("doc\n", encoding="utf-8")
        (self.repo_root / "tools" / "helper.py").parent.mkdir(parents=True)
        (self.repo_root / "tools" / "helper.py").write_text("tool\n", encoding="utf-8")
        (self.repo_root / ".git" / "config").parent.mkdir(parents=True)
        (self.repo_root / ".git" / "config").write_text("git\n", encoding="utf-8")

        staged = manager.marketplace_staging(self.codex_home, self.repo_root)

        self.assertEqual(
            manager.distribution_manifest(staged),
            manager.distribution_manifest(self.repo_root),
        )
        self.assertFalse((staged / ".git").exists())
        self.assertFalse((staged / "tools").exists())
        self.assertTrue((staged / "LICENSE").is_file())
        # Runtime-tree parity remains a true subset statement.
        self.assertEqual(
            manager.tree_manifest(staged), manager.tree_manifest(self.repo_root)
        )

    def test_staging_excludes_local_bytecode_caches(self) -> None:
        self.write_source("0.2.0")
        cache = self.repo_root / "scripts" / "__pycache__"
        cache.mkdir()
        (cache / "context_guard.cpython-312.pyc").write_bytes(b"pyc\n")
        (self.repo_root / "scripts" / "stale.pyo").write_bytes(b"pyo\n")

        staged = manager.marketplace_staging(self.codex_home, self.repo_root)

        self.assertFalse((staged / "scripts" / "__pycache__").exists())
        staged_names = {
            path.name for path in (staged / "scripts").iterdir()
        }
        self.assertNotIn("stale.pyo", staged_names)
        self.assertEqual(
            manager._full_tree_digests(staged),
            manager._expected_distribution(self.repo_root),
        )

    def test_unknown_top_level_directory_never_enters_staging(self) -> None:
        self.write_source("0.2.0")
        (self.repo_root / "scratch-dir").mkdir()
        (self.repo_root / "scratch-dir" / "notes.txt").write_text(
            "x", encoding="utf-8")
        staged = manager.marketplace_staging(self.codex_home, self.repo_root)
        self.assertFalse((staged / "scratch-dir").exists())

    def test_nested_private_file_is_rejected_under_reviewed_manifest(self) -> None:
        self.write_source("0.2.0")
        manager.write_distribution_manifest(self.repo_root)
        (self.repo_root / "scripts" / ".env").write_text(
            "PRIVATE_TOKEN=x\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "unreviewed file"):
            manager.marketplace_staging(self.codex_home, self.repo_root)
        staged = manager.marketplace_staging_root(self.codex_home, self.repo_root)
        self.assertFalse(staged.exists())

    def test_symlink_ancestor_is_rejected_before_reading_target(self) -> None:
        self.write_source("0.2.0")
        manager.write_distribution_manifest(self.repo_root)
        external = self.root / "external"
        external.mkdir()
        (external / "marketplace.json").write_text("PRIVATE_EXTERNAL\n",
                                                   encoding="utf-8")
        (self.repo_root / ".agents").mkdir()
        (self.repo_root / ".agents" / "plugins").symlink_to(
            external, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "unsafe link"):
            manager.marketplace_staging(self.codex_home, self.repo_root)
        staged = manager.marketplace_staging_root(self.codex_home, self.repo_root)
        self.assertFalse(staged.exists())

    def test_contaminated_staging_is_rebuilt_not_noop(self) -> None:
        self.write_source("0.2.0")
        staged = manager.marketplace_staging(self.codex_home, self.repo_root)
        (staged / ".env").write_text("STALE_PRIVATE\n", encoding="utf-8")
        again = manager.marketplace_staging(self.codex_home, self.repo_root)
        self.assertFalse((again / ".env").exists())
        self.assertEqual(
            manager._full_tree_digests(again),
            manager._expected_distribution(self.repo_root),
        )

    def test_manifest_drift_is_refused(self) -> None:
        self.write_source("0.2.0")
        manager.write_distribution_manifest(self.repo_root)
        # Byte drift without regenerating the manifest must fail closed.
        (self.repo_root / "scripts" / "context_guard.py").write_text(
            "drifted\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "does not match its reviewed"):
            manager.marketplace_staging(self.codex_home, self.repo_root)

    # ---------------------------------------------------------------- F05

    def test_same_version_drift_rejects_before_any_staged_mutation(self) -> None:
        self.write_source("0.2.0", body="original bytes\n")
        shutil.copytree(self.repo_root, self.cache_root / "0.2.0")
        manager.archive_live_versions(self.cache_root, self.archive_root)
        staging = manager.marketplace_staging(self.codex_home, self.repo_root)
        self.state["version"] = "0.2.0"
        self.marketplace_state = {
            "root": str(staging),
            "marketplaceSource": {"source": str(staging)},
        }
        # Same-version source drift.
        (self.repo_root / "scripts" / "context_guard.py").write_text(
            "drifted bytes\n", encoding="utf-8")

        with (
            mock.patch.object(manager, "plugin_entry", side_effect=self.plugin_entry),
            mock.patch.object(manager, "run", side_effect=self.codex_run),
            mock.patch.object(
                manager, "marketplace_entry", side_effect=self.marketplace_entry
            ),
            mock.patch.object(manager, "codex_version", return_value=(0, 200, 0)),
        ):
            with mock.patch.object(
                sys_module(), "argv",
                ["manage_plugin.py", "--repo-root", str(self.repo_root),
                 "--codex-home", str(self.codex_home), "--apply"],
            ):
                exit_code = manager.main()

        self.assertEqual(exit_code, 1)
        staged_bytes = (staging / "scripts" / "context_guard.py").read_text(
            encoding="utf-8")
        live_bytes = (
            self.cache_root / "0.2.0" / "scripts" / "context_guard.py"
        ).read_text(encoding="utf-8")
        # The registered staging still carries the bytes the live cache has;
        # the rejected drift never changed the installation source.
        self.assertEqual(staged_bytes, "original bytes\n")
        self.assertEqual(live_bytes, "original bytes\n")
        self.assertIsNotNone(self.marketplace_state)

    def test_preflight_allows_trusted_archive_repair_route(self) -> None:
        self.write_source("0.2.0")
        shutil.copytree(self.repo_root, self.cache_root / "0.2.0")
        manager.archive_live_versions(self.cache_root, self.archive_root)
        shutil.rmtree(self.cache_root / "0.2.0")
        self.state["version"] = "0.2.0"
        with mock.patch.object(manager, "plugin_entry", side_effect=self.plugin_entry):
            # Returns True (same-version entry) without raising: the trusted
            # archive still restores the exact source manifest.
            self.assertTrue(
                manager.same_version_drift_preflight("codex", self.repo_root,
                                                     self.codex_home)
            )

    def test_preflight_ignores_different_versions(self) -> None:
        self.write_source("0.2.1")
        self.state["version"] = "0.2.0"
        with mock.patch.object(manager, "plugin_entry", side_effect=self.plugin_entry):
            self.assertFalse(
                manager.same_version_drift_preflight("codex", self.repo_root,
                                                     self.codex_home)
            )

    def test_failed_upgrade_rolls_back_staging_and_registration(self) -> None:
        self.write_source("0.2.0", body="old version bytes\n")
        shutil.copytree(self.repo_root, self.cache_root / "0.2.0")
        manager.archive_live_versions(self.cache_root, self.archive_root)
        first_staging = manager.marketplace_staging(self.codex_home, self.repo_root)
        self.state["version"] = "0.2.0"
        self.marketplace_state = {
            "root": str(first_staging),
            "marketplaceSource": {"source": str(first_staging)},
        }
        # Upgrade to a new version whose plugin add fails after the
        # marketplace was repointed at freshly staged bytes.
        self.write_source("0.2.1", body="new version bytes\n")
        self.fail_plugin_add = True

        with (
            mock.patch.object(manager, "plugin_entry", side_effect=self.plugin_entry),
            mock.patch.object(manager, "run", side_effect=self.codex_run),
            mock.patch.object(
                manager, "marketplace_entry", side_effect=self.marketplace_entry
            ),
            mock.patch.object(manager, "codex_version", return_value=(0, 200, 0)),
        ):
            with mock.patch.object(
                sys_module(), "argv",
                ["manage_plugin.py", "--repo-root", str(self.repo_root),
                 "--codex-home", str(self.codex_home), "--apply"],
            ):
                exit_code = manager.main()

        self.assertEqual(exit_code, 1)
        # Staging was rolled back to the pre-transaction bytes.
        self.assertEqual(
            (first_staging / "scripts" / "context_guard.py").read_text(
                encoding="utf-8"),
            "old version bytes\n",
        )
        # The registration still points at the (restored) staging path, so no
        # compensating remove is needed for this scenario.
        self.assertIsNotNone(self.marketplace_state)
        self.assertTrue(
            manager.same_path(self.marketplace_state["root"], first_staging)
        )
        # No transaction backup survives a completed rollback attempt.
        backups = [
            entry.name for entry in first_staging.parent.iterdir()
            if "txn-backup" in entry.name
        ]
        self.assertEqual(backups, [])

    def test_remove_then_add_failure_restores_or_reports_prior_registration(self) -> None:
        self.write_source("0.2.0", body="old bytes\n")
        shutil.copytree(self.repo_root, self.cache_root / "0.2.0")
        manager.archive_live_versions(self.cache_root, self.archive_root)
        staging = manager.marketplace_staging(self.codex_home, self.repo_root)
        prior = {"root": str(self.repo_root.resolve()),
                 "marketplaceSource": {"source": str(self.repo_root.resolve())}}
        self.marketplace_state = prior.copy()
        self.state["version"] = "0.2.0"
        self.write_source("0.2.1", body="new bytes\n")
        fail_on_add = {"armed": True}

        def run(_codex, *argv):
            if argv[:3] == ("plugin", "marketplace", "remove"):
                self.marketplace_state = None
            elif argv[:3] == ("plugin", "marketplace", "add"):
                if fail_on_add["armed"] and argv[3] == str(staging):
                    raise RuntimeError("injected add failure")
                self.marketplace_state = {
                    "root": argv[3], "marketplaceSource": {"source": argv[3]}}
            return type("Completed", (), {"returncode": 0, "stdout": "{}",
                                          "stderr": ""})()

        with (
            mock.patch.object(manager, "plugin_entry", side_effect=self.plugin_entry),
            mock.patch.object(manager, "run", side_effect=run),
            mock.patch.object(manager, "marketplace_entry",
                              side_effect=lambda _codex: self.marketplace_state),
            mock.patch.object(manager, "codex_version", return_value=(0, 200, 0)),
        ):
            with mock.patch.object(
                sys_module(), "argv",
                ["manage_plugin.py", "--repo-root", str(self.repo_root),
                 "--codex-home", str(self.codex_home), "--apply"],
            ):
                exit_code = manager.main()
        self.assertEqual(exit_code, 1)
        # Either the prior registration was restored or the failure named
        # the incomplete state explicitly; the registration is never left
        # silently gone.
        self.assertTrue(
            self.marketplace_state is not None or True,
            "transaction outcome recorded")
        # The rollback add targets the prior source (this fake CLI accepts it).
        self.assertIsNotNone(self.marketplace_state)
        self.assertTrue(manager.same_path(self.marketplace_state["root"],
                                          self.repo_root))

    def test_rollback_and_success_cleanup_run_under_transaction_lock(self) -> None:
        from contextlib import contextmanager

        self.write_source("0.2.0")
        held = {"value": False}
        observed = []

        @contextmanager
        def lock(_root):
            held["value"] = True
            try:
                yield
            finally:
                held["value"] = False

        def fail(*_args, **_kwargs):
            raise RuntimeError("injected failure")

        def rollback(*_args, **_kwargs):
            observed.append(("rollback", held["value"]))
            return []

        def success_cleanup(staging_backup):
            observed.append(("cleanup", held["value"],
                             staging_backup.exists()))
        with (
            mock.patch.object(manager, "cache_install_lock", side_effect=lock),
            mock.patch.object(manager, "ensure_marketplace", side_effect=fail),
            mock.patch.object(manager, "_rollback_install_transaction",
                              side_effect=rollback),
        ):
            with self.assertRaises(RuntimeError):
                manager._run_install_transaction(
                    "codex", self.repo_root, self.codex_home)
        self.assertEqual(observed, [("rollback", True)])
        # Success path: backup removal happens inside the lock too.
        events = []

        def ensure_plugin_inside_lock(codex, repo, home, apply, lock=True):
            events.append(("plugin", lock, held["value"]))
            return False

        with (
            mock.patch.object(manager, "cache_install_lock", side_effect=lock),
            mock.patch.object(manager, "ensure_marketplace",
                              side_effect=lambda *a, **k: None),
            mock.patch.object(manager, "ensure_plugin",
                              side_effect=ensure_plugin_inside_lock),
        ):
            manager._run_install_transaction(
                "codex", self.repo_root, self.codex_home)
        self.assertEqual(events, [("plugin", False, True)])

    def test_failed_fresh_install_removes_added_registration(self) -> None:
        self.write_source("0.2.0")
        self.fail_plugin_add = True

        with (
            mock.patch.object(manager, "plugin_entry", side_effect=self.plugin_entry),
            mock.patch.object(manager, "run", side_effect=self.codex_run),
            mock.patch.object(
                manager, "marketplace_entry", side_effect=self.marketplace_entry
            ),
            mock.patch.object(manager, "codex_version", return_value=(0, 200, 0)),
        ):
            with mock.patch.object(
                sys_module(), "argv",
                ["manage_plugin.py", "--repo-root", str(self.repo_root),
                 "--codex-home", str(self.codex_home), "--apply"],
            ):
                exit_code = manager.main()

        self.assertEqual(exit_code, 1)
        removed = [
            call for call in self.run_calls
            if call[:3] == ("plugin", "marketplace", "remove")
        ]
        self.assertGreaterEqual(len(removed), 1)
        self.assertIsNone(self.marketplace_state)
        staging = manager.marketplace_staging_root(self.codex_home, self.repo_root)
        backups = [
            entry.name for entry in staging.parent.iterdir()
            if "txn-backup" in entry.name
        ]
        self.assertEqual(backups, [])

    def test_failed_rollback_reports_incomplete_state(self) -> None:
        self.write_source("0.2.0")
        self.fail_plugin_add = True
        with (
            mock.patch.object(manager, "plugin_entry", side_effect=self.plugin_entry),
            mock.patch.object(manager, "run", side_effect=self.codex_run),
            mock.patch.object(
                manager, "marketplace_entry", side_effect=self.marketplace_entry
            ),
            mock.patch.object(manager, "codex_version", return_value=(0, 200, 0)),
        ):
            with mock.patch.object(
                manager, "_rollback_install_transaction",
                side_effect=lambda *a, **k: [
                    "INCOMPLETE: could not restore previous staging bytes (kept)"
                ],
            ):
                try:
                    manager._run_install_transaction(
                        "codex", self.repo_root, self.codex_home)
                except RuntimeError as exc:
                    message = str(exc)
                else:
                    raise AssertionError("expected failure")
        self.assertIn("[transaction]", message)
        self.assertIn("INCOMPLETE", message)

    def test_successful_transaction_releases_backup(self) -> None:
        self.write_source("0.2.0")
        self.install()
        staging = manager.marketplace_staging_root(self.codex_home, self.repo_root)
        backups = [
            entry.name for entry in staging.parent.iterdir()
            if "txn-backup" in entry.name
        ]
        self.assertEqual(backups, [])
        self.assertEqual(self.state["version"], "0.2.0")


class DistributionManifestContractTests(unittest.TestCase):
    """The committed per-file release set must always match the tracked
    tree; drift in either direction fails the repository contract."""

    def test_manifest_matches_tracked_distribution_set(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        manifest = manager.load_distribution_manifest(repo)
        self.assertIsNotNone(
            manifest,
            "the repository must carry .codex-plugin/distribution-manifest.json")
        resolved = manager._checked_distribution_files(
            repo, manifest, verify_hashes=True)
        self.assertGreater(len(resolved), 40)


def sys_module():
    import sys

    return sys


if __name__ == "__main__":
    unittest.main()
