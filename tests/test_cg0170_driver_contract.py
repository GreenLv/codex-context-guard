"""The crash injector counts real purge-object unlinks on both platforms."""
import unittest
from pathlib import Path

from tests.cg0170_fresh_process_driver import is_purge_object_unlink


class PurgeCrashInjectionTests(unittest.TestCase):
    def test_descriptor_and_full_object_paths_are_counted(self):
        quarantine = Path.cwd() / "synthetic-quarantine"
        self.assertTrue(is_purge_object_unlink("payload", 7, quarantine))
        self.assertTrue(is_purge_object_unlink(
            quarantine / "object" / "payload", None, quarantine))
        self.assertTrue(is_purge_object_unlink(
            quarantine / "object" / "nested" / "payload", None, quarantine))

    def test_transaction_metadata_and_unrelated_paths_are_not_counted(self):
        quarantine = Path.cwd() / "synthetic-quarantine"
        self.assertFalse(is_purge_object_unlink(
            quarantine / "object.record.json", None, quarantine))
        self.assertFalse(is_purge_object_unlink(
            quarantine.parent / "outside" / "payload", None, quarantine))


if __name__ == "__main__":
    unittest.main()
