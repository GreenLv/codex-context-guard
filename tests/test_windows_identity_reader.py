"""Windows v2 resolver reader sharing; ABI controls are not native evidence."""
from __future__ import annotations

import inspect
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests import test_cg0151_readonly_snapshot as snapshots
from tests.test_cg122_p0_counterexamples import P0Harness

cg = snapshots.cg


class WindowsIdentityReaderTests(P0Harness):
    ready = snapshots.ReadOnlySnapshotTests.ready
    query = snapshots.ReadOnlySnapshotTests.query

    def resolve_windows(self, payload=None, failure=None):
        path = self.session_dir / "state.json"
        if payload is not None:
            path.write_bytes(payload)
        descriptors = []

        def opened(target):
            if failure is not None:
                raise failure
            descriptor = os.open(target, os.O_RDONLY)
            descriptors.append(descriptor)
            return descriptor

        with mock.patch.object(cg, "os", wraps=os) as platform, \
                mock.patch.object(cg, "_open_committed_state", side_effect=opened) as adapter, \
                mock.patch.object(cg, "read_json", side_effect=AssertionError("legacy reader used")):
            platform.name = "nt"
            try:
                result = cg.resolve_supplied_session(self.root / "private", "p0")
            finally:
                adapter.assert_called_once_with(path)
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
        return result

    def test_windows_resolver_uses_committed_reader_and_closes_it(self):
        self.ready()
        self.assertEqual(self.resolve_windows(), ("p0", self.session_dir))

    def test_windows_resolver_rejects_json_damage_and_open_failures(self):
        self.ready()
        with self.assertRaisesRegex(cg.SessionIdentityError, "could not be read"):
            self.resolve_windows(payload=b"{broken")
        with self.assertRaisesRegex(cg.SessionIdentityError, "could not be read"):
            self.resolve_windows(failure=PermissionError("denied"))

    def test_windows_resolver_does_not_fallback_on_reparse_or_open_refusal(self):
        self.ready()
        with self.assertRaisesRegex(cg.SessionIdentityError, "could not be read"):
            self.resolve_windows(failure=OSError("reparse refusal"))

    def test_windows_resolver_preserves_missing_id_alias(self):
        self.ready()
        self.assertEqual(self.resolve_windows(payload=b"{}"),
                         ("p0", self.session_dir))

    def test_windows_resolver_rejects_mismatched_identity(self):
        self.ready()
        state = self.state()
        state["session"]["id"] = "different-session"
        with self.assertRaises(cg.SessionIdentityError):
            self.resolve_windows(payload=json.dumps(state).encode("utf-8"))

    def test_windows_descriptor_conversion_failure_closes_owned_descriptor(self):
        self.ready()
        path = self.session_dir / "state.json"
        descriptor = os.open(path, os.O_RDONLY)
        with mock.patch.object(cg, "os", wraps=os) as platform, \
                mock.patch.object(cg, "_open_committed_state", return_value=descriptor), \
                mock.patch.object(cg.os, "fdopen", side_effect=OSError("conversion denied")):
            platform.name = "nt"
            with self.assertRaisesRegex(cg.SessionIdentityError, "could not be read"):
                cg._read_v2_identity_state(path)
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_windows_unicode_failure_still_propagates_and_closes(self):
        self.ready()
        with self.assertRaises(UnicodeDecodeError):
            self.resolve_windows(payload=b"\xff")
        # Also capture the helper's exact descriptor independently.
        path = self.session_dir / "state.json"
        descriptor = os.open(path, os.O_RDONLY)
        with mock.patch.object(cg, "os", wraps=os) as platform, \
                mock.patch.object(cg, "_open_committed_state", return_value=descriptor):
            platform.name = "nt"
            with self.assertRaises(UnicodeDecodeError):
                cg._read_v2_identity_state(path)
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_nonobject_roots_fail_closed_on_both_platform_paths(self):
        self.ready()
        path = self.session_dir / "state.json"
        for payload in (b"[]", b"null", b"17", b'"scalar"', b"{broken"):
            with self.subTest(payload=payload):
                with self.assertRaises(cg.SessionIdentityError):
                    self.resolve_windows(payload=payload)
                with mock.patch.object(cg, "os", wraps=os) as platform:
                    platform.name = "posix"
                    with self.assertRaises(cg.SessionIdentityError):
                        cg.resolve_supplied_session(self.root / "private", "p0")
        path.write_bytes(b"{}")
        with mock.patch.object(cg, "os", wraps=os) as platform:
            platform.name = "posix"
            self.assertEqual(cg.resolve_supplied_session(self.root / "private", "p0"),
                             ("p0", self.session_dir))

    def test_resolver_refusal_stops_query_and_clear_before_followup(self):
        self.ready()
        with mock.patch.object(cg, "os", wraps=os) as platform, \
                mock.patch.object(cg, "_open_committed_state",
                                  side_effect=OSError("boundary refusal")), \
                mock.patch.object(cg, "read_only_committed_state") as snapshot, \
                mock.patch.object(cg, "writable_session_dir") as writable, \
                mock.patch.object(cg, "load_state") as loader, \
                mock.patch.object(cg, "save_state") as saver:
            platform.name = "nt"
            with self.assertRaises(cg.SessionIdentityError):
                self.query()
            with self.assertRaises(cg.SessionIdentityError):
                cg.clear_pending_request(self.root / "private", "p0", self.turn, "p0token")
            snapshot.assert_not_called()
            writable.assert_not_called()
            loader.assert_not_called()
            saver.assert_not_called()

    def test_recovery_page_reports_identity_refusal_without_content(self):
        self.ready()
        with mock.patch.object(cg, "os", wraps=os) as platform, \
                mock.patch.object(cg, "data_root", return_value=self.root / "private"), \
                mock.patch.object(cg, "_open_committed_state",
                                  side_effect=OSError("boundary refusal")), \
                mock.patch("builtins.print") as output:
            platform.name = "nt"
            self.assertEqual(cg.command_recovery_page(
                cg.argparse.Namespace(session_id="p0")), 2)
        output.assert_called_once_with(json.dumps({"error": "explicit_session_required"}))

    @unittest.skipIf(sys.platform == "win32", "POSIX unchanged-opener control")
    def test_posix_resolver_keeps_existing_path_opener(self):
        self.ready()
        real = Path.open
        calls = []

        def observed(path, *args, **kwargs):
            calls.append((path, args, kwargs))
            return real(path, *args, **kwargs)

        with mock.patch.object(Path, "open", observed), \
                mock.patch.object(cg, "_open_committed_state",
                                  side_effect=AssertionError("Windows adapter on POSIX")):
            self.assertEqual(cg.resolve_supplied_session(self.root / "private", "p0"),
                             ("p0", self.session_dir))
        self.assertEqual(calls, [(self.session_dir / "state.json", ("r",), {"encoding": "utf-8"})])

    @unittest.skipUnless(sys.platform == "win32", "real Windows resolver sharing")
    def test_native_resolver_reader_permits_one_locked_publication(self):
        self.ready()
        path = self.session_dir / "state.json"
        pending = self.state()
        pending["wait_condition_sequence"] += 1
        original = path.read_bytes()
        real_load = cg.json.load
        publications = []

        def publish_inside_resolver_read(handle, *args, **kwargs):
            caller = inspect.currentframe().f_back
            if (caller.f_code.co_name in {"read_json", "_read_v2_identity_state"}
                    and caller.f_back.f_code.co_name == "resolve_supplied_session"
                    and caller.f_locals.get("path") == path):
                # Run with the actual resolver data reader held. The same
                # positive assertion fails on the old CRT resolver reader.
                self.assertEqual(publications, [])
                held = os.fstat(handle.fileno())
                with cg.session_lock(self.session_dir):
                    cg.save_state(self.session_dir, pending)
                after = path.read_bytes()
                self.assertNotEqual(after, original)
                self.assertEqual(held.st_ino, os.fstat(handle.fileno()).st_ino)
                publications.append(after)
            return real_load(handle, *args, **kwargs)

        with mock.patch.object(cg.json, "load", publish_inside_resolver_read):
            result = self.query()
        self.assertEqual(len(publications), 1)
        state = json.loads(publications[0])
        cg.validate_state_integrity(state)
        self.assertEqual(result["revision"], state["content_hash"])
        self.assertEqual(state["wait_condition_sequence"], pending["wait_condition_sequence"])
