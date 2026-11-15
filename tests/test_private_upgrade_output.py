"""Exclusive private output creation; native Windows ACL tests stay separate."""

import os
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from tools.validation import native_upgrade_acceptance as upgrade


class PrivateOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    @unittest.skipUnless(os.name == "posix", "POSIX permission regression")
    def test_private_child_and_existing_object_preservation(self):
        child = self.root / "new"
        upgrade._mkdir_private_new(child)
        self.assertTrue(child.is_dir())
        self.assertEqual(stat.S_IMODE(child.stat().st_mode) & 0o077, 0)
        sentinel = child / "retained"
        sentinel.write_bytes(b"preserve")
        with self.assertRaises(upgrade.UpgradeError):
            upgrade._mkdir_private_new(child)
        self.assertEqual(sentinel.read_bytes(), b"preserve")
        self.root.chmod(0o755)
        with self.assertRaises(upgrade.UpgradeError):
            upgrade._mkdir_private_new(self.root / "refused")
        self.assertFalse((self.root / "refused").exists())

    def test_windows_creation_uses_inheritance_before_child_audit(self):
        child = self.root / "new"
        original = Path.mkdir
        calls = []

        def mkdir(path, *args, **kwargs):
            calls.append(kwargs)
            return original(path, *args, **kwargs)

        with (
            mock.patch.object(upgrade, "os", types.SimpleNamespace(name="nt")),
            mock.patch.object(upgrade, "_private_directory") as audit,
            mock.patch.object(Path, "mkdir", mkdir),
        ):
            upgrade._mkdir_private_new(child)
        self.assertEqual(calls, [{"exist_ok": False}])
        self.assertEqual(audit.call_args_list, [mock.call(self.root), mock.call(child)])

    def test_failed_child_audit_retains_only_empty_new_directory(self):
        child = self.root / "refused"

        def audit(path):
            if path == child:
                raise upgrade.UpgradeError("child privacy not established")

        with mock.patch.object(upgrade, "_private_directory", side_effect=audit):
            with self.assertRaises(upgrade.UpgradeError):
                upgrade._mkdir_private_new(child)
        self.assertTrue(child.is_dir())
        self.assertEqual(list(child.iterdir()), [])

    def test_existing_file_and_linked_parent_are_never_repaired(self):
        existing = self.root / "existing"
        existing.write_bytes(b"preserve")
        with mock.patch.object(upgrade, "_private_directory"):
            with self.assertRaises(upgrade.UpgradeError):
                upgrade._mkdir_private_new(existing)
        self.assertEqual(existing.read_bytes(), b"preserve")
        link = self.root / "linked-parent"
        try:
            link.symlink_to(self.root, target_is_directory=True)
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                self.skipTest("native symlink privilege unavailable")
            raise
        with self.assertRaises(upgrade.UpgradeError):
            upgrade._mkdir_private_new(link / "refused")
        self.assertFalse((self.root / "refused").exists())


if __name__ == "__main__":
    unittest.main()
