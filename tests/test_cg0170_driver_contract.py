"""The crash injector counts real purge-object unlinks on both platforms."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.cg0170_fresh_process_driver import (
    is_purge_object_unlink,
    purge_unlink_patch,
)


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

    def test_cached_pathlib_accessor_is_observed_after_real_removal(self):
        # Model Python 3.10's import-time accessor binding on every host.
        cached_unlink = os.unlink

        def legacy_path_unlink(path):
            cached_unlink(path)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            quarantine = root / "quarantine"
            obj = quarantine / "object"
            obj.mkdir(parents=True)
            payloads = [obj / str(index) for index in range(3)]
            metadata, outside = quarantine / "object.record.json", root / "outside"
            for path in [*payloads, metadata, outside]:
                path.write_text("synthetic", encoding="utf-8")
            observations = []

            def observed():
                observations.append(sum(path.exists() for path in payloads))

            with mock.patch.object(Path, "unlink", new=legacy_path_unlink):
                with mock.patch.object(os, "unlink", wraps=os.unlink) as os_unlink:
                    with purge_unlink_patch(quarantine, observed, use_pathlib=True):
                        metadata.unlink()
                        outside.unlink()
                        for path in payloads:
                            path.unlink()
                    self.assertEqual(os_unlink.call_count, 0)
            self.assertEqual(observations, [2, 1, 0])

    def test_pathlib_and_os_entrypoints_count_each_removal_once(self):
        with tempfile.TemporaryDirectory() as directory:
            quarantine = Path(directory)
            obj = quarantine / "object"
            obj.mkdir()
            for use_pathlib in (True, False):
                with self.subTest(use_pathlib=use_pathlib):
                    payload = obj / "payload"
                    payload.write_text("synthetic", encoding="utf-8")
                    observed = mock.Mock()
                    with purge_unlink_patch(
                            quarantine, observed, use_pathlib=use_pathlib):
                        if use_pathlib:
                            payload.unlink()
                        else:
                            os.unlink(payload)
                        self.assertFalse(payload.exists())
                        observed.assert_called_once_with()
                        with self.assertRaises(FileNotFoundError):
                            if use_pathlib:
                                payload.unlink()
                            else:
                                os.unlink(payload)
                        observed.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
