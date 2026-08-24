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


class InstalledSmokeTests(unittest.TestCase):
    def test_smoke_does_not_write_bytecode_into_plugin_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plugin_root = Path(temporary) / "plugin"
            scripts = plugin_root / "scripts"
            scripts.mkdir(parents=True)
            shutil.copy2(RUNTIME, scripts / RUNTIME.name)

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
