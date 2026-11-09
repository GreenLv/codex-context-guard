"""Bounded Windows fixed regressions for the native validation toolkit.

Capability-aware: assertions that need a real PowerShell run only on Windows
hosts, while every platform executes the classifier controls so the module is
never entirely skipped. Personal ACLs and private sessions are never copied;
all samples below are synthetic.

Fixed-regression coverage map for the native toolkit (the remaining items are
pinned by the modules named here, not duplicated):

- process cwd vs PowerShell location separation: this module.
- OWNER RIGHTS vs explicit user SID: this module plus
  ``tests.test_windows_retention_native.PrivateDaclClassification``.
- read-only sandbox relative paths, trust saved then exit, read success but
  digest failure, interrupt recovery, second no-op:
  ``tests.test_native_upgrade_acceptance`` (bounded replay controls).
- locked files, case aliasing, long paths: ``tests.test_windows_retention_native``
  and the ``cg-retention-native-batch`` scenarios in
  ``tools/validation/native_acceptance.py``.
- Unicode/quotes and PowerShell quoting: ``tests.test_native_scheduler_batch``
  plus the launcher-wire fixtures in ``tests/test_windows_launcher_wire.py``.
- pipeline exit codes and foreign-entry refusals: ``tests.test_native_scheduler_batch``.
- large-frame transport bounds: oversized-row controls in
  ``tests.test_cg0170_host_evidence_family`` and the 2 MiB line cap in
  ``tools/validation/stop_host_acceptance.py``.
- module search path behavior: ``tests.test_native_scheduler_batch`` (child
  environment strips only ``PSMODULEPATH``; ``schtasks.exe`` preferred over
  module-loading cmdlets).
- system clock precision: scheduler trigger-boundary guards in
  ``tests.test_native_scheduler_batch``; the retention adjudication time is
  declared, never mocked.
"""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_scheduler_batch_regression",
    ROOT / "tools/validation/native_scheduler_batch.py")
assert SPEC and SPEC.loader
SCHED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCHED)

RETENTION_SPEC = importlib.util.spec_from_file_location(
    "windows_retention_native_regression",
    ROOT / "tools/validation/windows_retention_native.py")
assert RETENTION_SPEC and RETENTION_SPEC.loader
RETENTION = importlib.util.module_from_spec(RETENTION_SPEC)
RETENTION_SPEC.loader.exec_module(RETENTION)


def _powershell_executable():
    for name in ("pwsh", "powershell"):
        found = shutil.which(name)
        if found:
            return found
    return None


class _FakeOwned:
    def __init__(self, process):
        self.process = process

    def close(self, timeout):
        self.process.wait(timeout=timeout)
        return {"owned_process_exited": True,
                "owned_tree_no_running_members": True,
                "process_group_cleanup_error": None}


class _FakeProcessTree:
    class OwnedProcess:
        @staticmethod
        def spawn(argv, cwd, env, stdin, stdout, stderr):
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=stdin,
                                       stdout=stdout, stderr=stderr)
            return _FakeOwned(process)


class _FakeNative:
    def load_process_tree(self):
        return _FakeProcessTree

    def load_natural_observer(self):
        return lambda owner: {"no_running_members": True}


class WindowsRegressionControls(unittest.TestCase):
    def test_powershell_child_location_follows_spawned_cwd(self):
        """The owned runner's explicit cwd — not the caller's location —
        becomes the child PowerShell location and its process directory."""
        executable = _powershell_executable()
        if not executable:
            self.skipTest("no PowerShell executable on PATH")
        with tempfile.TemporaryDirectory(prefix="cg-cwd-sep-") as temp:
            # A space and a non-ASCII name exercise quoting together.
            root = Path(temp).resolve() / "北 lib 副本"
            root.mkdir()
            result = SCHED._command(
                _FakeNative(), root,
                [executable, "-NoProfile", "-NonInteractive", "-Command",
                 "(Get-Location).Path; [Environment]::CurrentDirectory"],
                timeout=60.0)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = [line for line in
                     result.stdout.decode("utf-8-sig").splitlines() if line]
            self.assertEqual(len(lines), 2, lines)
            for reported in lines:
                self.assertEqual(Path(reported), root)
            # Separation: the caller's working directory was never the target.
            self.assertNotEqual(Path.cwd(), root)

    def test_private_dacl_classifier_refuses_owner_rights_trustee(self):
        user = "S-1-5-21-9999999999-8888888888-7777777777-1001"
        # The OWNER RIGHTS trustee classifies as "other", so the private
        # parent role contract (exactly user+system) is never satisfied.
        _, roles = RETENTION._classify_private_dacl(
            "D:P(A;ID;FA;;;S-1-3-4)(A;ID;FA;;;SY)", user)
        self.assertNotIn("user", roles)
        _, roles = RETENTION._classify_private_dacl(
            f"D:P(A;ID;FA;;;{user})(A;ID;FA;;;SY)", user)
        self.assertEqual(sorted(roles), ["system", "user"])


if __name__ == "__main__":
    unittest.main()
