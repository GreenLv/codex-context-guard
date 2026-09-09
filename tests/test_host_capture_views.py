"""Synthetic offline-view transaction tests, not native-host acceptance."""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_host_behavior_composite import C, Fixture


class ViewFixture(Fixture):
    def __init__(self, root):
        super().__init__(root)
        self.sink = self.root / "capture"
        self.sink.mkdir()
        self.views = {}
        for child in self.children:
            kind = child["kind"]
            archive = self.root / (kind + "-archive")
            archive.mkdir()
            (archive / "capture-000001.raw").write_bytes(kind.encode())
            self.views[kind] = {"archive_root": str(archive), "files": C.capture_inventory(archive)}
            manifest = Path(child["manifest"])
            data = json.loads(manifest.read_bytes())
            if kind == "git_trust":
                data["evidence"] = {"capture_dir": str(self.sink)}
            else:
                data["capture"]["directory"] = str(self.sink)
            manifest.write_text(json.dumps(data))
            child["manifest_sha256"] = C.sha(manifest.read_bytes())
            adapter = Path(child["carrier_root"]) / "tools/validation" / C.ADAPTERS[kind]
            adapter.write_text(
                "from pathlib import Path\n"
                "def adapt(path, runtime, expected):\n"
                f"    assert Path({str(self.sink / 'capture-000001.raw')!r}).read_bytes() == {kind.encode()!r}\n"
                '    return {"subject": {}}, {"fresh_test_token": True}\n'
            )
            child["tool_sha256"][adapter.name] = C.sha(adapter.read_bytes())
        (self.sink / "capture-000001.raw").write_bytes(b"git_trust")
        self.original = C.capture_inventory(self.sink)
        self.m.update(schema=C.VIEW_MANIFEST_SCHEMA, capture_views={
            "schema": "offline-capture-views/v1", "directory": str(self.sink),
            "original_files": copy.deepcopy(self.original), "children": self.views,
        })


class CaptureViewTests(unittest.TestCase):
    def test_fresh_serial_replay_restores_original_and_retains_views(self):
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            result = f.run()
            self.assertEqual(result["status"], "passed")
            self.assertEqual(C.capture_inventory(f.sink), f.original)
            self.assertFalse(f.sink.with_name("capture.offline-replay.lock").exists())
            for child in result["validation"]["children"]:
                receipt = child["capture_view_replay"]
                self.assertTrue(receipt["restored"])
                self.assertEqual(C.capture_inventory(Path(receipt["transaction_directory"]) / "replayed"),
                                 f.views[child["kind"]]["files"])
                self.assertEqual(C.capture_inventory(Path(receipt["archive_root"])), receipt["archive_files"])
            self.assertIn("no shared executable", result["validation"]["executable_identity_scope"])

    def test_v1_same_sink_still_rejects_and_never_switches(self):
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            f.m["schema"] = C.MANIFEST_SCHEMA
            del f.m["capture_views"]
            with self.assertRaisesRegex(C.CompositeError, "fresh continuity"):
                f.run()
            self.assertEqual(C.capture_inventory(f.sink), f.original)
            self.assertEqual(list(f.root.glob(".capture-replay-*")), [])

    def test_archive_changed_extra_missing_or_escape_rejected_before_switch(self):
        for variant in ("changed", "extra", "missing", "escape"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as d:
                f = ViewFixture(Path(d))
                archive = Path(f.views["continuity"]["archive_root"])
                if variant == "changed":
                    (archive / "capture-000001.raw").write_bytes(b"changed")
                elif variant == "extra":
                    (archive / "unexpected").write_bytes(b"unowned")
                elif variant == "missing":
                    (archive / "capture-000001.raw").unlink()
                else:
                    f.views["continuity"]["files"]["../escape.raw"] = "a" * 64
                with self.assertRaises(C.CompositeError):
                    f.run()
                self.assertEqual(C.capture_inventory(f.sink), f.original)

    def test_overlap_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            f.views["git_trust"]["archive_root"] = str(f.sink)
            with self.assertRaisesRegex(C.CompositeError, "overlap"):
                f.run()

    def test_symlink_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            alias = f.root / "alias"
            try:
                alias.symlink_to(f.views["continuity"]["archive_root"], target_is_directory=True)
            except OSError as exc:
                if getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows symbolic-link privilege unavailable")
                raise
            f.views["continuity"]["archive_root"] = str(alias)
            with self.assertRaises(C.CompositeError):
                f.run()

    def test_failed_worker_restores_and_preserves_unknown_added_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            with self.assertRaisesRegex(C.CompositeError, "unexpected"):
                with C.capture_view(f.m, "continuity") as receipt:
                    (f.sink / "writer-added.txt").write_bytes(b"must preserve")
            self.assertEqual(C.capture_inventory(f.sink), f.original)
            self.assertEqual((Path(receipt["transaction_directory"]) / "replayed/writer-added.txt").read_bytes(), b"must preserve")

    def test_worker_exception_still_restores(self):
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            with self.assertRaisesRegex(RuntimeError, "worker failed"):
                with C.capture_view(f.m, "continuity"):
                    raise RuntimeError("worker failed")
            self.assertEqual(C.capture_inventory(f.sink), f.original)

    def test_changed_archive_during_worker_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            with self.assertRaises(C.CompositeError):
                with C.capture_view(f.m, "continuity"):
                    (Path(f.views["continuity"]["archive_root"]) / "capture-000001.raw").write_bytes(b"race")
            self.assertEqual(C.capture_inventory(f.sink), f.original)

    def test_existing_lock_blocks_without_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            lock = f.sink.with_name("capture.offline-replay.lock")
            lock.write_bytes(b"someone else")
            with self.assertRaises(FileExistsError):
                f.run()
            self.assertEqual(lock.read_bytes(), b"someone else")
            self.assertEqual(C.capture_inventory(f.sink), f.original)

    def test_restore_conflict_preserves_backup_and_unknown_destination(self):
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            rename = C.rename_exclusive
            def collide(source, target):
                if source.name == "original":
                    target.mkdir()
                    (target / "unknown").write_bytes(b"keep")
                rename(source, target)
            with mock.patch.object(C, "rename_exclusive", side_effect=collide), self.assertRaises(OSError):
                with C.capture_view(f.m, "continuity") as receipt:
                    pass
            transaction = Path(receipt["transaction_directory"])
            self.assertEqual(C.capture_inventory(transaction / "original"), f.original)
            self.assertEqual((f.sink / "unknown").read_bytes(), b"keep")
            self.assertTrue(f.sink.with_name("capture.offline-replay.lock").exists())

    def test_no_replace_rename_refuses_existing_empty_directory(self):
        with tempfile.TemporaryDirectory() as d:
            first, second = Path(d) / "first", Path(d) / "second"
            first.mkdir()
            second.mkdir()
            with self.assertRaises(OSError):
                C.rename_exclusive(first, second)
            self.assertTrue(first.is_dir())
            self.assertTrue(second.is_dir())

    def test_mismatched_original_or_manifest_path_rejects(self):
        for variant in ("original", "manifest"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as d:
                f = ViewFixture(Path(d))
                if variant == "original":
                    f.m["capture_views"]["original_files"]["capture-000001.raw"] = "a" * 64
                else:
                    child = f.children[0]
                    p = Path(child["manifest"])
                    value = json.loads(p.read_bytes())
                    value["evidence"]["capture_dir"] = str(f.root / "other")
                    p.write_text(json.dumps(value))
                    child["manifest_sha256"] = C.sha(p.read_bytes())
                with self.assertRaises(C.CompositeError):
                    f.run()
                self.assertEqual(C.capture_inventory(f.sink), f.original)

    def test_windows_linux_macos_output_scope_uses_fresh_children(self):
        for platform, original in (("windows", "Windows"), ("linux", "Linux"), ("macos", "Darwin")):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as d:
                f = Fixture(Path(d))
                f.m["platform"]["os"] = platform
                for child in f.children:
                    p = Path(child["result"])
                    result = json.loads(p.read_bytes())
                    result["platform"]["os"] = original
                    p.write_text(json.dumps(result))
                    child["result_sha256"] = C.sha(p.read_bytes())
                    validator = Path(child["carrier_root"]) / "tools/validation/host_behavior.py"
                    validator.write_text(validator.read_text().replace("Darwin", original))
                    child["tool_sha256"][validator.name] = C.sha(validator.read_bytes())
                result = f.run()
                self.assertEqual(result["status"], "passed")
                self.assertEqual(result["scope"]["windows"], "six_gates_composite" if platform == "windows" else "not_established")
                self.assertEqual(result["scope"]["macos_composite_only"], platform == "macos")
                for key in ("whole_p4", "p3", "p5"):
                    self.assertIn(result["scope"][key], ("pending", "not_established"))

    def test_worker_timeout_still_restores(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            with mock.patch.object(C, "run_worker", side_effect=subprocess.TimeoutExpired("worker", 90)):
                with self.assertRaises(subprocess.TimeoutExpired):
                    f.run()
            self.assertEqual(C.capture_inventory(f.sink), f.original)

    def test_backup_change_preserves_recovery_paths_without_acceptance(self):
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            with self.assertRaisesRegex(C.CompositeError, "original changed"):
                with C.capture_view(f.m, "continuity") as receipt:
                    backup = Path(receipt["transaction_directory"]) / "original"
                    (backup / "capture-000001.raw").write_bytes(b"external writer")
            self.assertEqual((backup / "capture-000001.raw").read_bytes(), b"external writer")
            self.assertTrue(f.sink.exists())
            self.assertTrue(f.sink.with_name("capture.offline-replay.lock").exists())
            self.assertFalse(receipt["restored"])

    def test_ancestor_capture_view_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            nested = f.sink / "nested"
            nested.mkdir()
            (nested / "capture-000001.raw").write_bytes(b"continuity")
            f.views["continuity"]["archive_root"] = str(nested)
            with self.assertRaisesRegex(C.CompositeError, "overlap"):
                C.verify_capture_views(f.m)

    def test_archive_hardlink_is_rejected(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            archive = Path(f.views["continuity"]["archive_root"])
            os.link(archive / "capture-000001.raw", f.root / "external-hardlink")
            with self.assertRaisesRegex(C.CompositeError, "hard links"):
                f.run()
            self.assertEqual(C.capture_inventory(f.sink), f.original)

    def test_manifest_schema_v1_v2_contract(self):
        schema = json.loads((Path(C.__file__).parent / "host-composite-manifest.schema.json").read_bytes())
        self.assertEqual(schema["properties"]["schema"]["enum"], [C.MANIFEST_SCHEMA, C.VIEW_MANIFEST_SCHEMA])
        self.assertIn("capture_views", schema["allOf"][0]["then"]["required"])
        with tempfile.TemporaryDirectory() as d:
            f = ViewFixture(Path(d))
            f.m["schema"] = C.MANIFEST_SCHEMA
            with self.assertRaisesRegex(C.CompositeError, "shape"):
                f.run()


if __name__ == "__main__":
    unittest.main()
