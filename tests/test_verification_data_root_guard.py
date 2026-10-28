#!/usr/bin/env python3
"""The conftest isolation guard must mirror the product resolver exactly.

Eleventh-review P2 (omitted-root-resolver-guard): the previous conftest
compared only the raw ``CONTEXT_GUARD_DATA_DIR`` variable against a
hard-coded default and passed silently whenever the variable was missing,
so a verification process without explicit roots resolved the HOME-derived
daily default and kept running. The guard now resolves the EFFECTIVE root
through a self-contained mirror of the product resolver's priority and
refuses the daily default.

This regression pins that mirror to ``data_root()`` across the resolver's
whole priority surface (explicit roots, CODEX_HOME tier, HOME tier, and
every missing/blank combination), and pins the refusal decision for the
two historical counterexamples while keeping legitimate isolated roots
allowed. The conftest is loaded here once as a separate module; its
import-time fallback mutation is captured and restored, so the ambient
suite environment is untouched.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard_guard_drift", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)

CONFTEST_PATH = Path(__file__).resolve().parent / "conftest.py"
CONFTEST_SPEC = importlib.util.spec_from_file_location(
    "cg_verification_conftest_under_test", CONFTEST_PATH)
assert CONFTEST_SPEC is not None and CONFTEST_SPEC.loader is not None
conftest = importlib.util.module_from_spec(CONFTEST_SPEC)
_ambient_for_conftest_load = dict(os.environ)
try:
    CONFTEST_SPEC.loader.exec_module(conftest)
finally:
    os.environ.clear()
    os.environ.update(_ambient_for_conftest_load)


class GuardEnvironmentCase(unittest.TestCase):
    """Base: fresh temporary tree, captured ambient environment."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "simulated-operator-home"
        self.ambient = dict(os.environ)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self.ambient)
        self.temporary.cleanup()

    def _configure(self, **env) -> None:
        for key, value in env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class VerificationDataRootGuardMirror(GuardEnvironmentCase):
    """The guard's resolver mirror equals the product resolver on the
    whole priority surface, including every missing/blank tier."""

    def _assert_mirror_matches_resolver(self, **env) -> None:
        self._configure(**env)
        expected = cg.data_root()
        self.assertEqual(conftest._effective_data_root(), expected)

    def test_explicit_data_dir_wins(self) -> None:
        self._assert_mirror_matches_resolver(
            CONTEXT_GUARD_DATA_DIR=str(self.root / "guard-data"),
            PLUGIN_DATA=str(self.root / "plugin-data"),
            CODEX_HOME=str(self.root / "codex-home"),
            HOME=str(self.home))

    def test_blank_data_dir_falls_to_plugin_data(self) -> None:
        self._assert_mirror_matches_resolver(
            CONTEXT_GUARD_DATA_DIR="   ",
            PLUGIN_DATA=str(self.root / "plugin-data"),
            CODEX_HOME=str(self.root / "codex-home"),
            HOME=str(self.home))

    def test_missing_data_dir_falls_to_plugin_data(self) -> None:
        self._assert_mirror_matches_resolver(
            CONTEXT_GUARD_DATA_DIR=None,
            PLUGIN_DATA=str(self.root / "plugin-data"),
            CODEX_HOME=str(self.root / "codex-home"),
            HOME=str(self.home))

    def test_blank_plugin_data_falls_to_claude_plugin_data(self) -> None:
        self._assert_mirror_matches_resolver(
            CONTEXT_GUARD_DATA_DIR=None,
            PLUGIN_DATA="",
            CLAUDE_PLUGIN_DATA=str(self.root / "claude-plugin-data"),
            CODEX_HOME=str(self.root / "codex-home"),
            HOME=str(self.home))

    def test_missing_plugin_roots_fall_to_codex_home(self) -> None:
        self._assert_mirror_matches_resolver(
            CONTEXT_GUARD_DATA_DIR=None,
            PLUGIN_DATA=None,
            CLAUDE_PLUGIN_DATA=None,
            CODEX_HOME=str(self.root / "codex-home"),
            HOME=str(self.home))
        self.assertEqual(conftest._effective_data_root(),
                         self.root / "codex-home" / "context-guard")

    def test_blank_codex_home_falls_to_home_default(self) -> None:
        self._assert_mirror_matches_resolver(
            CONTEXT_GUARD_DATA_DIR=None,
            PLUGIN_DATA=None,
            CLAUDE_PLUGIN_DATA=None,
            CODEX_HOME="  ",
            HOME=str(self.home))
        self.assertEqual(conftest._effective_data_root(),
                         self.home / ".codex" / "context-guard")

    def test_missing_explicit_tiers_use_home_tier(self) -> None:
        self._assert_mirror_matches_resolver(
            CONTEXT_GUARD_DATA_DIR=None,
            PLUGIN_DATA=None,
            CLAUDE_PLUGIN_DATA=None,
            CODEX_HOME=None,
            HOME=str(self.home))
        self.assertEqual(conftest._effective_data_root(),
                         self.home / ".codex" / "context-guard")

    def test_explicit_data_dir_is_expandusered_like_the_resolver(self) -> None:
        self._assert_mirror_matches_resolver(
            CONTEXT_GUARD_DATA_DIR="~/cg-guard-drift-probe",
            CODEX_HOME=None,
            HOME=str(self.home))
        self.assertEqual(conftest._effective_data_root(),
                         Path("~/cg-guard-drift-probe").expanduser())


class VerificationDataRootGuardDecision(GuardEnvironmentCase):
    """The refusal decision rejects the daily default in both historical
    shapes and keeps legitimate isolated roots allowed."""

    def test_missing_explicit_roots_refuse_daily_default(self) -> None:
        # Eleventh-review counterexample: the probe process deleted
        # CONTEXT_GUARD_DATA_DIR and CODEX_HOME, the resolver fell through
        # to the HOME tier, and the previous guard passed silently.
        self._configure(CONTEXT_GUARD_DATA_DIR=None, PLUGIN_DATA=None,
                        CLAUDE_PLUGIN_DATA=None, CODEX_HOME=None,
                        HOME=str(self.home))
        self.assertTrue(conftest._resolves_to_daily_default())
        self.assertEqual(conftest._effective_data_root(),
                         self.home / ".codex" / "context-guard")

    def test_explicit_daily_path_refuses(self) -> None:
        # Historical control: an explicit root pointed AT the daily
        # default path must refuse, not only missing variables.
        self._configure(CONTEXT_GUARD_DATA_DIR=str(
            self.home / ".codex" / "context-guard"),
            CODEX_HOME=None, HOME=str(self.home))
        self.assertTrue(conftest._resolves_to_daily_default())

    def test_legitimate_temporary_root_is_allowed(self) -> None:
        self._configure(CONTEXT_GUARD_DATA_DIR=str(self.root / "guard-data"),
                        CODEX_HOME=None, HOME=str(self.home))
        self.assertFalse(conftest._resolves_to_daily_default())

    def test_codex_home_owned_root_is_allowed(self) -> None:
        self._configure(CONTEXT_GUARD_DATA_DIR=None,
                        CODEX_HOME=str(self.root / "codex-home"),
                        HOME=str(self.home))
        self.assertFalse(conftest._resolves_to_daily_default())

    def test_plugin_data_root_is_allowed(self) -> None:
        self._configure(CONTEXT_GUARD_DATA_DIR=None,
                        PLUGIN_DATA=str(self.root / "plugin-data"),
                        CODEX_HOME=None, HOME=str(self.home))
        self.assertFalse(conftest._resolves_to_daily_default())

    def test_process_fallback_tree_is_allowed(self) -> None:
        # The conftest's own import-time fallback must satisfy the guard,
        # so the ordinary suite never trips the autouse assertion.
        self.assertFalse(conftest._resolves_to_daily_default())

    def test_autouse_check_refuses_before_test_body(self) -> None:
        self._configure(CONTEXT_GUARD_DATA_DIR=None, CODEX_HOME=None,
                        HOME=str(self.home))
        refused = False
        try:
            conftest._refuse_daily_default()
        except BaseException as error:  # pytest.fail raises its outcome type
            if isinstance(error, KeyboardInterrupt):
                raise
            refused = "daily default" in str(error)
            if not refused:
                raise
        self.assertTrue(refused,
                        "the guard fixture did not refuse the daily default")

    def test_autouse_check_passes_on_isolated_root(self) -> None:
        self._configure(CONTEXT_GUARD_DATA_DIR=str(self.root / "guard-data"),
                        CODEX_HOME=None, HOME=str(self.home))
        conftest._refuse_daily_default()  # must not raise


if __name__ == "__main__":
    unittest.main()
