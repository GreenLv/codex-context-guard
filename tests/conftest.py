"""Process-level isolation guard for the verification suite.

Installed BEFORE any test module is imported: every pytest process gets a
temporary fallback HOME / CODEX_HOME / CONTEXT_GUARD_DATA_DIR, so a probe
or fixture that forgets its own environment patch can never resolve the
production data root. An autouse assertion re-checks, before each test,
the EFFECTIVE data root — resolved through the product resolver's exact
priority (explicit roots, then CODEX_HOME, then the HOME-derived daily
default) — and refuses the run when it lands on the daily default.

This is the durable guard added after the ninth review's daily-data
incident record, corrected after the eleventh review: the previous
version compared only the raw ``CONTEXT_GUARD_DATA_DIR`` variable and
passed silently whenever that variable was missing, so a process with
no explicit roots resolved the daily default and kept running. The
guard now evaluates the resolver's whole priority surface, including
every missing/blank tier.

Protection scope (stated, not implied):
- pytest: this conftest applies automatically to every run under this
  ``tests/`` tree.
- Official ``unittest`` runs and inline verification scripts are NOT
  covered by this file. They must install their own process fallback
  (HOME / CODEX_HOME / CONTEXT_GUARD_DATA_DIR into a temporary tree)
  BEFORE importing the product module and verify the effective data
  root before the first dispatch/save — the isolated-executor pattern
  the repository's validation probes follow. An entry-time check that
  the effective root is an explicit temporary root (never the
  HOME-derived default) is the minimal equivalent of the autouse
  assertion below.
"""
import os
import tempfile
from pathlib import Path

import pytest

_FALLBACK = tempfile.mkdtemp(prefix="cg-verification-fallback-")
os.environ.setdefault("HOME", str(Path(_FALLBACK) / "os-home"))
os.environ["CODEX_HOME"] = str(Path(_FALLBACK) / "codex-home")
os.environ["CONTEXT_GUARD_DATA_DIR"] = str(Path(_FALLBACK) / "guard-data")
for _key in ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "PLUGIN_ROOT"):
    os.environ.pop(_key, None)


def _effective_data_root(env=None) -> Path:
    """Validation-side mirror of the product resolver's exact priority.

    Mirrors ``scripts/context_guard.py`` ``data_root()``: explicit roots
    win in order ``CONTEXT_GUARD_DATA_DIR`` > ``PLUGIN_DATA`` >
    ``CLAUDE_PLUGIN_DATA`` (blank values count as unset), then a set
    ``CODEX_HOME`` owns ``<home>/context-guard``, and only without any of
    them does the root fall back to the HOME-derived daily default. A
    regression test pins this mirror to the product resolver so resolver
    changes cannot silently desynchronize the guard.
    """
    env = os.environ if env is None else env
    for name in ("CONTEXT_GUARD_DATA_DIR", "PLUGIN_DATA", "CLAUDE_PLUGIN_DATA"):
        configured = env.get(name)
        if configured and configured.strip():
            return Path(configured).expanduser()
    codex_home = env.get("CODEX_HOME")
    if codex_home and codex_home.strip():
        return Path(codex_home).expanduser() / "context-guard"
    return Path.home() / ".codex" / "context-guard"


def _resolves_to_daily_default(env=None) -> bool:
    """True when the effective data root is the HOME-derived daily
    default of the current process — the write target of the historical
    inline-harness leak. Legitimate isolated roots (temporary explicit
    roots, CODEX_HOME-owned trees) never match."""
    effective = _effective_data_root(env).resolve()
    daily = (Path.home() / ".codex" / "context-guard").resolve()
    return effective == daily


def _refuse_daily_default() -> None:
    """Raise before a test body runs when the effective data root (product
    resolver priority) is the HOME-derived daily default — the write
    target of the historical inline-harness leak. Legitimate isolated
    roots (temporary explicit roots, CODEX_HOME-owned trees) never
    trigger it."""
    if _resolves_to_daily_default():
        pytest.fail(
            "verification test resolved to the daily default data root; "
            "process fallback isolation is missing")


@pytest.fixture(autouse=True)
def _assert_verification_isolation():
    """Fail any test whose effective data root (product resolver
    priority) resolves to the daily default instead of an explicit
    isolated root."""
    _refuse_daily_default()
    yield
