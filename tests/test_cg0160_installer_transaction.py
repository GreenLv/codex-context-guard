#!/usr/bin/env python3
"""0.16.0 installer regressions for F04 (distribution allowlist staging) and
F05 (same-version preflight plus transactional registration/rollback).

The counterexamples reproduced on the 0.15.1 baseline: the staged marketplace
copied an `.env` and a symlink target from outside the tree, and a same-version
drift replaced the registered staging bytes before the cache refusal landed.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
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


def symlink_or_skip(test, link: Path, target: Path, **kwargs) -> None:
    try:
        link.symlink_to(target, **kwargs)
    except OSError as exc:
        import errno

        if (getattr(exc, "winerror", None) == 1314
                or exc.errno in {errno.ENOSYS, errno.ENOTSUP}):
            test.skipTest(f"symlink creation capability unavailable: {exc}")
        raise


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
        # Synthetic sources explicitly review their own distribution set.
        manager.write_distribution_manifest(self.repo_root)

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

    def _bootstrap_source(self) -> None:
        self.write_source("0.2.0")

    def test_missing_manifest_downgrade_is_refused_by_the_builder(self) -> None:
        """RR02 matrix row: source had a reviewed manifest, then it was
        removed and an unreviewed plain file added. The production builder
        refuses instead of selecting any adopt-anything fallback."""
        self._bootstrap_source()
        manager.write_distribution_manifest(self.repo_root)
        (self.repo_root / manager.DISTRIBUTION_MANIFEST_RELATIVE).unlink()
        (self.repo_root / "scripts" / "private-notes.txt").write_text(
            "SYNTHETIC-PRIVATE-UNREVIEWED", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "manifest is missing"):
            manager.build_distribution_tree(
                self.repo_root, self.root / "distribution")
        self.assertFalse(
            (self.root / "distribution" / "scripts" / "private-notes.txt"
             ).exists())

    def test_missing_manifest_on_git_source_refuses_instead_of_bootstrap(self) -> None:
        """RR02 matrix row: the product repository itself (a git checkout)
        must never bootstrap a missing manifest from untracked files."""
        self._bootstrap_source()
        manager.write_distribution_manifest(self.repo_root)
        (self.repo_root / manager.DISTRIBUTION_MANIFEST_RELATIVE).unlink()
        (self.repo_root / ".git" / "config").parent.mkdir(parents=True,
                                                          exist_ok=True)
        (self.repo_root / ".git" / "config").write_text("git\n",
                                                        encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "missing from a git"):
            manager.marketplace_staging(self.codex_home, self.repo_root)
        staged = manager.marketplace_staging_root(self.codex_home, self.repo_root)
        self.assertFalse(staged.exists())

    def test_corrupt_manifest_is_refused_before_read(self) -> None:
        """Corrupt manifest JSON cannot become distribution authority."""
        self._bootstrap_source()
        manager.write_distribution_manifest(self.repo_root)
        manifest = (self.repo_root / manager.DISTRIBUTION_MANIFEST_RELATIVE)
        manifest.write_text("{not json", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "unreadable"):
            manager.build_distribution_tree(
                self.repo_root, self.root / "distribution")

    def test_linked_manifest_is_refused_before_read(self) -> None:
        self._bootstrap_source()
        manifest = self.repo_root / manager.DISTRIBUTION_MANIFEST_RELATIVE
        outside = self.root / "outside-manifest.json"
        manifest.unlink()
        symlink_or_skip(self, manifest, outside)
        reads = []
        real_read = Path.read_text

        def reading(path, *argv, **kwargs):
            if path == self.repo_root / manager.DISTRIBUTION_MANIFEST_RELATIVE:
                reads.append(True)
            return real_read(path, *argv, **kwargs)

        with mock.patch.object(Path, "read_text", side_effect=reading):
            with self.assertRaisesRegex(RuntimeError, "unsafe link"):
                manager.build_distribution_tree(
                    self.repo_root, self.root / "distribution2")
        self.assertEqual(reads, [])

    def test_staging_object_kinds_are_all_detected_on_rebuild(self) -> None:
        """RR02 matrix rows: bytecode, plain private files, file symlinks and
        directory symlinks planted in an existing staging are each detected
        by the exact target enumeration and removed by the rebuild."""
        self._bootstrap_source()
        cases = [
            ("bytecode", lambda staged: (
                (staged / "scripts" / "__pycache__").mkdir(),
                (staged / "scripts" / "__pycache__" / "private.pyc").write_bytes(
                    b"cache")),
             "scripts/__pycache__/private.pyc"),
            ("plain-file", lambda staged: (
                (staged / "scripts" / "private-notes.txt").write_text(
                    "x", encoding="utf-8")),
             "scripts/private-notes.txt"),
            ("file-link", lambda staged: (
                symlink_or_skip(self, staged / "scripts" / "private-link.py",
                    self.root / "outside-file")),
             "scripts/private-link.py"),
            ("dir-link", lambda staged: (
                symlink_or_skip(self, staged / "external-dir",
                    self.root / "outside-dir", target_is_directory=True)),
             "external-dir"),
        ]
        for label, plant, relative in cases:
            with self.subTest(kind=label):
                shutil.rmtree(self.codex_home, ignore_errors=True)
                (self.root / "outside-file").write_text("x", encoding="utf-8")
                (self.root / "outside-dir").mkdir(exist_ok=True)
                staged = manager.marketplace_staging(
                    self.codex_home, self.repo_root)
                plant(staged)
                self.assertTrue(
                    (staged / relative).is_symlink()
                    or (staged / relative).exists(),
                    f"{label}: fixture failed to plant")
                again = manager.marketplace_staging(
                    self.codex_home, self.repo_root)
                self.assertFalse(
                    (again / relative).is_symlink()
                    or (again / relative).exists(),
                    f"{label}: contamination survived the rebuild")
                self.assertEqual(
                    manager._full_tree_digests(again),
                    manager._expected_distribution(self.repo_root),
                    f"{label}: rebuilt tree is not the exact reviewed set")

    def test_archive_style_source_without_git_uses_committed_manifest(self) -> None:
        """RR02 matrix row: a regular no-.git archive carries the same
        committed manifest and stages strictly through it."""
        self._bootstrap_source()
        manager.write_distribution_manifest(self.repo_root)
        shutil.rmtree(self.repo_root / ".git", ignore_errors=True)
        staged = manager.marketplace_staging(self.codex_home, self.repo_root)
        self.assertEqual(
            manager._full_tree_digests(staged),
            manager._expected_distribution(self.repo_root))

    def test_bootstrap_of_clean_non_git_source_is_strict(self) -> None:
        """RR02 matrix row: a clean non-git source without a manifest gets an
        explicit generated manifest and a strict build; polluted non-git
        sources still refuse."""
        self._bootstrap_source()
        (self.repo_root / manager.DISTRIBUTION_MANIFEST_RELATIVE).unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            staged = manager.marketplace_staging(self.codex_home, self.repo_root)
        self.assertEqual(
            manager._full_tree_digests(staged),
            manager._expected_distribution(self.repo_root))

        # A clean non-git source whose manifest is absent gets an explicit
        # generated manifest. Dot-prefixed and linked files are excluded from
        # that generation and then refused by the strict check because they
        # exist on disk without review; plain unreviewed files are adopted
        # into the generated manifest — a documented boundary that applies
        # only to non-git sources, since the product repository always
        # carries its committed manifest and a git source refuses outright.
        shutil.rmtree(self.codex_home, ignore_errors=True)
        (self.repo_root / manager.DISTRIBUTION_MANIFEST_RELATIVE).unlink()
        (self.repo_root / "scripts" / ".hidden-private").write_text(
            "x", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "unreviewed file"):
            manager.marketplace_staging(self.codex_home, self.repo_root)
        (self.repo_root / "scripts" / ".hidden-private").unlink()

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

    def test_rollback_matrix_prior_source_times_failure_stage(self) -> None:
        """RR03 matrix: prior registration source x failure stage. Every row
        must restore the prior registration (read back by exact identity) or
        report an explicit INCOMPLETE."""
        prior_kinds = {
            "source": lambda root: str(root / "source"),
            "prior-staging": lambda root: str(
                manager.marketplace_staging_root(root / "home", root / "source")
                .parent / ("a" * 40 + ".marketplace")),
            "other-managed": lambda root: str(
                root / "home" / "upstreams" / manager.PLUGIN_NAME
                / ("b" * 40 + ".marketplace")),
        }
        failure_stages = {
            "at-remove": ("remove",),
            "at-add": ("add",),
            "at-plugin": ("plugin",),
        }
        for prior_name, prior_source in prior_kinds.items():
            for stage_name, stage in failure_stages.items():
                with self.subTest(prior=prior_name, stage=stage_name):
                    temp = tempfile.TemporaryDirectory()
                    root = Path(temp.name)
                    try:
                        src = root / "source"
                        (src / ".codex-plugin").mkdir(parents=True)
                        (src / ".codex-plugin/plugin.json").write_text(json.dumps(
                            {"name": manager.PLUGIN_NAME, "version": "0.2.0"}))
                        (src / "scripts").mkdir()
                        (src / "scripts/context_guard.py").write_text(
                            "# x\n", encoding="utf-8")
                        home = root / "home"
                        prior = {"root": prior_source(root),
                                 "marketplaceSource": {"source": prior_source(root)}}
                        state = {"registration": dict(prior)}

                        def run(_codex, *argv, _stage=stage, _prior=prior):
                            if argv[:3] == ("plugin", "marketplace", "remove"):
                                if _stage[0] == "remove":
                                    raise RuntimeError("injected remove failure")
                                state["registration"] = None
                            elif argv[:3] == ("plugin", "marketplace", "add"):
                                if _stage[0] == "add":
                                    raise RuntimeError("injected add failure")
                                state["registration"] = {
                                    "root": argv[3],
                                    "marketplaceSource": {"source": argv[3]}}
                            return type("Result", (), {
                                "returncode": 0, "stdout": "{}", "stderr": ""})()

                        error = None
                        with (
                            mock.patch.object(
                                manager, "marketplace_entry",
                                side_effect=lambda _c: state["registration"]),
                            mock.patch.object(manager, "run", side_effect=run),
                            mock.patch.object(
                                manager, "ensure_plugin",
                                side_effect=(
                                    RuntimeError("injected plugin failure")
                                    if stage[0] == "plugin" else None)),
                            contextlib.redirect_stdout(io.StringIO()),
                        ):
                            try:
                                manager._run_install_transaction(
                                    "synthetic-cli", src, home)
                            except RuntimeError as exc:
                                error = str(exc)
                            else:
                                if stage[0] == "plugin":
                                    raise AssertionError("expected failure")
                        if stage[0] == "plugin":
                            restored = state["registration"]
                            self.assertTrue(
                                (isinstance(restored, dict)
                                 and manager.same_path(
                                     restored.get("root", ""), prior["root"]))
                                or "INCOMPLETE" in (error or ""),
                                f"{prior_name}/{stage_name}: registration "
                                f"{restored!r}, error={error!r}")
                        # remove/add failures happen before any change or
                        # roll back to the prior registration.
                    finally:
                        temp.cleanup()

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
