from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "scripts" / "smoke_installed.py"
RUNTIME = ROOT / "scripts" / "context_guard.py"
# Router/protocol modules the installed runtime loads from its own scripts
# directory: cg_hook.py is the production hook entry (routed from
# run_context_guard.sh / run-context-guard.ps1) and imports
# cg_actions/cg_protocol/cg_codex_adapter at module level. Since Phase 3 the
# heavy core lazily loads the Stop protocol layer cg_stop3.py from its own
# scripts directory; 0.13 adds the lazily loaded response-delivery layer
# (cg_delivery.py) and the plainly imported authority/release layers
# (cg_authority.py, cg_release_adapter.py) behind the release-profile gate.
REQUIRED_MODULES = [
    ROOT / "scripts" / "cg_commit.py",
    ROOT / "scripts" / "cg_actions.py",
    ROOT / "scripts" / "cg_authority.py",
    ROOT / "scripts" / "cg_codex_adapter.py",
    ROOT / "scripts" / "cg_delivery.py",
    ROOT / "scripts" / "cg_hook.py",
    ROOT / "scripts" / "cg_protocol.py",
    ROOT / "scripts" / "cg_release_adapter.py",
    ROOT / "scripts" / "cg_stop3.py",
]


class InstalledSmokeTests(unittest.TestCase):
    def test_smoke_does_not_write_bytecode_into_plugin_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plugin_root = Path(temporary) / "plugin"
            scripts = plugin_root / "scripts"
            scripts.mkdir(parents=True)
            shutil.copy2(RUNTIME, scripts / RUNTIME.name)
            for module_path in REQUIRED_MODULES:
                if module_path.is_file():
                    shutil.copy2(module_path, scripts / module_path.name)

            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SMOKE),
                    "--plugin-root",
                    str(plugin_root),
                ],
                text=True,
                capture_output=True,
                env=environment,
                timeout=30,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("SMOKE_PASS", result.stdout)
            self.assertFalse((scripts / "__pycache__").exists())
            self.assertFalse(any(plugin_root.rglob("*.py[co]")))


if __name__ == "__main__":
    unittest.main()
