#!/usr/bin/env python3
"""Regression tests for safe Context Guard plugin cache updates."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "manage_plugin.py"
SPEC = importlib.util.spec_from_file_location("manage_plugin", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager)


class SafePluginInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo_root = self.root / "repo"
        self.codex_home = self.root / "codex"
        self.source_root = self.repo_root
        self.cache_root = manager.plugin_cache_root(self.codex_home)
        self.state: dict[str, object] = {"version": None, "enabled": True}
        self.run_calls: list[tuple[str, ...]] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_source(self, version: str, body: str = "source hook\n") -> None:
        manifest = {
            "name": manager.PLUGIN_NAME,
            "version": version,
        }
        manifest_path = self.source_root / ".codex-plugin" / "plugin.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        script = self.source_root / "scripts" / "context_guard.py"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(body, encoding="utf-8")

    def cache_source_as(self, version: str) -> Path:
        target = self.cache_root / version
        shutil.copytree(self.source_root, target)
        return target

    def plugin_entry(self, _codex: str) -> dict | None:
        version = self.state["version"]
        if version is None:
            return None
        return {
            "pluginId": manager.PLUGIN_ID,
            "version": version,
            "enabled": self.state["enabled"],
        }

    def successful_add(self, _codex: str, *args: str) -> subprocess.CompletedProcess[str]:
        self.run_calls.append(args)
        shutil.rmtree(self.cache_root, ignore_errors=True)
        version = manager.source_plugin_version(self.source_root)
        shutil.copytree(self.source_root, self.cache_root / version)
        self.state["version"] = version
        return subprocess.CompletedProcess(["codex", *args], 0, "{}", "")

    def ensure(self, apply: bool = True) -> bool:
        with (
            mock.patch.object(manager, "plugin_entry", side_effect=self.plugin_entry),
            mock.patch.object(manager, "run", side_effect=self.successful_add),
        ):
            return manager.ensure_plugin(
                "codex", self.repo_root, self.codex_home, apply
            )

    def test_same_version_with_matching_cache_is_strict_no_op(self) -> None:
        self.write_source("0.1.2")
        self.cache_source_as("0.1.2")
        self.state["version"] = "0.1.2"

        installed = self.ensure()

        self.assertFalse(installed)
        self.assertEqual(self.run_calls, [])

    def test_cache_manifest_ignores_repository_only_files(self) -> None:
        self.write_source("0.1.2")
        (self.repo_root / "README.md").write_text("repository docs\n", encoding="utf-8")
        git_config = self.repo_root / ".git" / "config"
        git_config.parent.mkdir(parents=True)
        git_config.write_text("private repository metadata\n", encoding="utf-8")

        manifest = manager.tree_manifest(self.repo_root)

        self.assertIn(".codex-plugin/plugin.json", manifest)
        self.assertIn("scripts/context_guard.py", manifest)
        self.assertNotIn("README.md", manifest)
        self.assertNotIn(".git/config", manifest)

    def test_same_version_missing_cache_refuses_destructive_refresh(self) -> None:
        self.write_source("0.1.2")
        self.state["version"] = "0.1.2"

        with self.assertRaisesRegex(RuntimeError, "refusing an in-place refresh"):
            self.ensure()

        self.assertEqual(self.run_calls, [])

    def test_same_version_source_drift_requires_version_bump(self) -> None:
        self.write_source("0.1.2", body="old hook\n")
        self.cache_source_as("0.1.2")
        self.state["version"] = "0.1.2"
        self.write_source("0.1.2", body="changed without bump\n")

        with self.assertRaisesRegex(RuntimeError, "Bump the plugin version"):
            self.ensure()

        self.assertEqual(self.run_calls, [])

    def test_upgrade_restores_old_version_after_codex_deletes_cache_root(self) -> None:
        self.write_source("0.1.2", body="old hook\n")
        old_cache = self.cache_source_as("0.1.2")
        self.state["version"] = "0.1.2"
        self.write_source("0.1.3", body="new hook\n")

        installed = self.ensure()

        self.assertFalse(installed)
        self.assertEqual(
            (old_cache / "scripts" / "context_guard.py").read_text(encoding="utf-8"),
            "old hook\n",
        )
        self.assertEqual(
            (self.cache_root / "0.1.3" / "scripts" / "context_guard.py").read_text(
                encoding="utf-8"
            ),
            "new hook\n",
        )
        self.assertEqual(
            self.run_calls,
            [("plugin", "add", manager.PLUGIN_ID, "--json")],
        )

    def test_failed_upgrade_still_restores_old_hook_script(self) -> None:
        self.write_source("0.1.2", body="old hook\n")
        old_cache = self.cache_source_as("0.1.2")
        self.state["version"] = "0.1.2"
        self.write_source("0.1.3", body="new hook\n")

        def failed_add(_codex: str, *args: str) -> subprocess.CompletedProcess[str]:
            self.run_calls.append(args)
            shutil.rmtree(self.cache_root, ignore_errors=True)
            raise RuntimeError("synthetic install failure")

        with (
            mock.patch.object(manager, "plugin_entry", side_effect=self.plugin_entry),
            mock.patch.object(manager, "run", side_effect=failed_add),
            self.assertRaisesRegex(RuntimeError, "synthetic install failure"),
        ):
            manager.ensure_plugin(
                "codex", self.repo_root, self.codex_home, apply=True
            )

        self.assertEqual(
            (old_cache / "scripts" / "context_guard.py").read_text(encoding="utf-8"),
            "old hook\n",
        )

    def test_dry_run_reports_version_mismatch_without_installing(self) -> None:
        self.write_source("0.1.2")
        self.cache_source_as("0.1.2")
        self.state["version"] = "0.1.1"

        with self.assertRaisesRegex(RuntimeError, "repository requires"):
            self.ensure(apply=False)

        self.assertEqual(self.run_calls, [])

    def test_main_routes_codex_subprocesses_to_explicit_home(self) -> None:
        self.write_source("0.1.2")
        observed: list[str | None] = []

        def observe_marketplace(_codex: str, _repo: Path, _apply: bool) -> bool:
            observed.append(os.environ.get("CODEX_HOME"))
            return False

        def observe_plugin(
            _codex: str, _repo: Path, codex_home: Path, _apply: bool
        ) -> bool:
            observed.append(os.environ.get("CODEX_HOME"))
            self.assertEqual(codex_home, self.codex_home.resolve())
            return False

        argv = [
            "manage_plugin.py",
            "--repo-root",
            str(self.repo_root),
            "--codex-home",
            str(self.codex_home),
        ]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(manager, "codex_version", return_value=(0, 146, 0)),
            mock.patch.object(
                manager, "ensure_marketplace", side_effect=observe_marketplace
            ),
            mock.patch.object(manager, "ensure_plugin", side_effect=observe_plugin),
        ):
            self.assertEqual(manager.main(), 0)

        self.assertEqual(observed, [str(self.codex_home.resolve())] * 2)


if __name__ == "__main__":
    unittest.main()
