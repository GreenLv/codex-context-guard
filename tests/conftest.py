"""Process-level isolation guard for the verification suite.

Installed BEFORE any test module is imported: every pytest process gets a
temporary fallback HOME / CODEX_HOME / CONTEXT_GUARD_DATA_DIR, so a probe
or fixture that forgets its own environment patch can never resolve the
production data root. An autouse assertion re-checks, before each test,
that the production default root is not the active data root.

This is the durable guard added after the ninth review's daily-data
incident record: an inline harness without environment isolation once
resolved synthetic sessions to the operator's default data root. Probe
reproductions must run through this suite (or the isolated-executor
pattern with a temporary process fallback set before import).
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


def _default_data_root() -> Path:
    home = Path(os.environ.get("CODEX_HOME") or
                Path(os.environ.get("HOME", str(Path.home()))) / ".codex")
    return home / "context-guard"


@pytest.fixture(autouse=True)
def _assert_verification_isolation():
    """Fail any test whose active data root resolves to the operator's
    daily default instead of the process fallback tree."""
    root = Path(os.environ.get("CONTEXT_GUARD_DATA_DIR") or "")
    default = Path.home() / ".codex" / "context-guard"
    if root and root.resolve() == default.resolve():
        pytest.fail(
            "verification test resolved to the daily default data root; "
            "process fallback isolation is missing")
    yield
