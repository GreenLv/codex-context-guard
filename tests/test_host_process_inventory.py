"""Synthetic host-process inventory classification; no real process claims.

Every fixture here is synthetic: rows are dictionaries passed straight to
``classify``. Only one test performs a real read-only enumeration, and it
asserts the result shape only, never a specific host state.
"""
from __future__ import annotations

import importlib.util
import ntpath
import sys
import unittest
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "host_process_inventory_under_test",
    "tools/validation/host_process_inventory.py")
INV = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(INV)

DESKTOP = "/Applications/Codex.app/Contents/MacOS/Codex"
HELPER = "/Applications/Codex.app/Contents/Library/CodexHelper"
SANDBOX = "/Applications/Codex.app/Contents/Library/CodexSandboxService"
OTHER = "/usr/sbin/unrelated-daemon"


def enum(rows, source="darwin-ps-libproc", observer_uid=501):
    return {"status": "observed", "reason": None, "source": source,
            "observer_uid": observer_uid, "rows": rows}


def win_enum(rows):
    """Windows Toolhelp payload shape: no observer uid, snapshot summary."""
    return {"status": "observed", "reason": None, "source": "windows-toolhelp",
            "snapshot": {"snapshots": 1, "processes": len(rows),
                         "candidates": 0,
                         "image_path_reads": {"ok": 0, "failed": 0}},
            "rows": rows}


def row(pid, ppid, executable=None, uid=501, source="posix", exe_name=None):
    if source == "windows":
        return {"pid": pid, "ppid": ppid, "uid": None, "executable": executable,
                "exe_name": exe_name,
                "identity": "observed" if executable else "unreadable"}
    return {"pid": pid, "ppid": ppid, "uid": uid,
            "executable": executable,
            "identity": "observed" if executable else "unreadable"}


class TestClassification(unittest.TestCase):
    def test_desktop_running_by_exact_executable_identity(self):
        result = INV.classify(enum([row(100, 1, DESKTOP), row(200, 1, OTHER)]),
                            [DESKTOP])
        self.assertEqual(result["status"], "running")
        self.assertEqual(result["counts"]["desktop_host"], 1)
        self.assertEqual(result["desktop_host_processes"],
                         [{"pid": 100, "ppid": 1, "executable": DESKTOP}])
        # Unrelated rows contribute a count only; their paths are not retained.
        self.assertEqual(result["counts"]["unrelated"], 1)

    def test_absent_when_enumeration_is_clean(self):
        result = INV.classify(enum([row(200, 1, OTHER), row(300, 1, OTHER)]),
                            [DESKTOP])
        self.assertEqual(result["status"], "absent")
        self.assertEqual(result["counts"]["desktop_host"], 0)

    def test_sandbox_service_is_not_the_desktop_host(self):
        result = INV.classify(enum([row(400, 1, SANDBOX), row(500, 1, OTHER)]),
                            [DESKTOP], [SANDBOX])
        self.assertEqual(result["status"], "absent",
                         "a sandbox service must never be classified as the Desktop host")
        self.assertEqual(result["counts"]["sandbox_service"], 1)
        self.assertEqual(result["sandbox_service_processes"],
                         [{"pid": 400, "ppid": 1, "executable": SANDBOX}])

    def test_unreadable_same_owner_identity_keeps_desktop_candidacy(self):
        result = INV.classify(enum([row(600, 1, None)]), [DESKTOP])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["unreadable_processes"], [{"pid": 600, "ppid": 1}])

    def test_other_owner_unreadable_process_is_kernel_family(self):
        result = INV.classify(enum([row(700, 1, None, uid=0),
                                  row(701, 1, None, uid=502),
                                  row(800, 1, OTHER)]),
                            [DESKTOP])
        self.assertEqual(result["status"], "absent",
                         "another-owner unreadable processes cannot be the user's GUI host")
        self.assertEqual(result["counts"]["system_kernel"], 2)

    def test_unknown_owner_keeps_desktop_candidacy(self):
        # No owner evidence and no observed observer uid never resolves to
        # kernel-family; the row stays a Desktop candidate (status unknown).
        result = INV.classify(enum([row(710, 1, None, uid=None)]), [DESKTOP])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["counts"]["system_kernel"], 0)

    def test_other_owner_rule_does_not_call_platform_uid(self):
        # The same-owner / other-owner decision consumes the enumeration's
        # observer context only, so the synthetic family runs on every
        # platform (Windows has no os.getuid).
        same = INV.classify(enum([row(720, 1, None, uid=501)]), [DESKTOP])
        self.assertEqual(same["status"], "unknown")
        other = INV.classify(enum([row(721, 1, None, uid=501)],
                                  observer_uid=999), [DESKTOP])
        self.assertEqual(other["status"], "absent")

    def test_windows_kernel_family_is_structural(self):
        result = INV.classify(win_enum([row(4, 0, None, source="windows"),
                                        row(1200, 4, None, source="windows")]),
                              [r"C:\Apps\Codex.exe"])
        self.assertEqual(result["status"], "absent")
        self.assertEqual(result["counts"]["system_kernel"], 2)

    def test_windows_identity_matches_case_insensitively(self):
        result = INV.classify(win_enum([row(900, 100, r"c:\apps\codex.EXE",
                                            source="windows")]),
                              [r"C:\Apps\Codex.exe"])
        self.assertEqual(result["status"], "running")

    def test_descendant_of_desktop_by_parent_chain(self):
        result = INV.classify(enum([row(100, 1, DESKTOP), row(101, 100, HELPER),
                                  row(102, 101, OTHER)]),
                            [DESKTOP])
        self.assertEqual(result["status"], "running")
        self.assertEqual(result["counts"]["desktop_descendant"], 2)

    def test_unreadable_descendant_of_living_desktop_is_not_a_host_candidate(self):
        result = INV.classify(enum([row(100, 1, DESKTOP), row(101, 100, None)]),
                            [DESKTOP])
        self.assertEqual(result["status"], "running")
        self.assertEqual(result["counts"]["desktop_descendant"], 1)
        self.assertEqual(result["counts"]["unreadable"], 0)

    def test_orphaned_process_without_living_ancestor_is_unrelated(self):
        result = INV.classify(enum([row(101, 9999, HELPER)]), [DESKTOP])
        self.assertEqual(result["status"], "absent")
        self.assertEqual(result["counts"]["unrelated"], 1)

    def test_parent_cycle_never_misclassifies(self):
        result = INV.classify(enum([row(101, 102, HELPER), row(102, 101, HELPER)]),
                            [DESKTOP])
        self.assertEqual(result["status"], "absent")

    def test_failed_enumeration_is_unknown_never_absence(self):
        result = INV.classify({"status": "failed", "reason": "ps_unavailable",
                             "source": None, "rows": []}, [DESKTOP])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "ps_unavailable")

    def test_duplicate_pid_is_refused(self):
        with self.assertRaises(INV.InventoryError):
            INV.classify(enum([row(100, 1, DESKTOP), row(100, 1, OTHER)]), [DESKTOP])

    def test_desktop_and_sandbox_identities_may_not_overlap(self):
        with self.assertRaises(INV.InventoryError):
            INV.classify(enum([row(100, 1, SANDBOX)]), [SANDBOX], [SANDBOX])

    def test_real_enumeration_reports_shape_only(self):
        # One real read-only enumeration on the running host: only the result
        # shape is asserted, never a specific process state.
        enumeration = INV.enumerate_processes()
        self.assertIn(enumeration["status"], ("observed", "failed"))
        result = INV.classify(enumeration, ["/nonexistent/desktop/path"], [])
        self.assertIn(result["schema"], (INV.SCHEMA,))
        self.assertIn(result["status"], ("running", "absent", "unknown"))


@unittest.skipUnless(sys.platform == "darwin", "darwin ps pinning")
class TestDarwinPsPinning(unittest.TestCase):
    def test_enumeration_consumes_the_pinned_ps_and_reports_it(self):
        seen = []

        def fake_ps_rows(ps):
            seen.append(ps)
            return [{"pid": 1, "ppid": 0, "uid": 0}]

        original = INV._ps_rows
        INV._ps_rows = fake_ps_rows
        try:
            payload = INV.enumerate_processes(ps="/usr/bin/ps-under-test")
        finally:
            INV._ps_rows = original
        self.assertEqual(seen, ["/usr/bin/ps-under-test"])
        self.assertEqual(payload["ps_path"], "/usr/bin/ps-under-test")
        result = INV.classify(payload, ["/nonexistent/desktop"], [])
        self.assertEqual(result["enumeration"]["ps_path"], "/usr/bin/ps-under-test")
        self.assertEqual(result["enumeration"]["ps_arguments"], INV._PS_ARGUMENTS)


PINNED_DESKTOP = r"C:\Apps\ChatGPT.exe"


class FakeKernel32:
    """No-model kernel32 for the Toolhelp pipeline; no real Windows calls."""

    def __init__(self, snapshots, image_paths=None, *, snapshot_fail=False,
                 walk_fail_at=None, close_fail_handles=(), open_fail_pids=(),
                 query_fail_pids=()):
        self.snapshots = snapshots
        self._last_error = 0
        self.image_paths = image_paths or {}
        self.snapshot_fail = snapshot_fail
        self.walk_fail_at = walk_fail_at
        self.close_fail_handles = set(close_fail_handles)
        self.open_fail_pids = set(open_fail_pids)
        self.query_fail_pids = set(query_fail_pids)
        self._snap_index = 0
        self._walk_index = 0
        self._current = []
        self._next_handle = 5000
        self._handle_pid = {}
        self.snapshot_handles = []
        self.opened_handles = []
        self.closed_handles = []
        self.live_handles = set()
        self.close_calls = []
        self.query_calls = []

    def get_last_error(self):
        return self._last_error

    def CreateToolhelp32Snapshot(self, flags, process_id):
        if self.snapshot_fail:
            return 0
        handle = self._next_handle
        self._next_handle += 1
        self.snapshot_handles.append(handle)
        self.live_handles.add(handle)
        index = min(self._snap_index, len(self.snapshots) - 1)
        self._current = list(self.snapshots[index])
        self._walk_index = 0
        self._snap_index += 1
        return handle

    def _fill(self, ref):
        pid, ppid, name = self._current[self._walk_index]
        entry = ref._obj
        entry.th32ProcessID = pid
        entry.th32ParentProcessID = ppid
        # The kernel fills the MAX_PATH buffer; a longer image name arrives
        # truncated, which the pipeline's truncation guard must treat as
        # unusable evidence.
        entry.szExeFile = name[:259]

    def Process32FirstW(self, handle, ref):
        if self.walk_fail_at == 0:
            self._last_error = 87
            return 0
        if not self._current:
            self._last_error = 18
            return 0
        self._fill(ref)
        self._walk_index += 1
        return 1

    def Process32NextW(self, handle, ref):
        if self.walk_fail_at == self._walk_index:
            self._last_error = 87
            return 0
        if self._walk_index >= len(self._current):
            self._last_error = 18  # ERROR_NO_MORE_FILES: clean end
            return 0
        self._fill(ref)
        self._walk_index += 1
        return 1

    def OpenProcess(self, access, inherit, pid):
        if pid in self.open_fail_pids:
            return 0
        handle = self._next_handle
        self._next_handle += 1
        self.opened_handles.append(handle)
        self.live_handles.add(handle)
        self._handle_pid[handle] = pid
        return handle

    def QueryFullProcessImageNameW(self, handle, flags, buffer_ref, size_ref):
        pid = self._handle_pid[handle]
        self.query_calls.append(pid)
        path = self.image_paths.get(pid)
        if pid in self.query_fail_pids or path is None:
            self._last_error = 5
            return 0
        buffer_ref.value = path  # the real call passes the mutable wchar array
        size_ref._obj.value = len(path)
        return 1

    def CloseHandle(self, handle):
        self.close_calls.append(handle)
        if handle in self.close_fail_handles or handle not in self.live_handles:
            self._last_error = 6  # ERROR_INVALID_HANDLE, including a double close
            return 0
        self.live_handles.remove(handle)
        self.closed_handles.append(handle)
        return 1

    def all_handles_closed(self):
        return not self.live_handles


class TestWindowsToolhelp(unittest.TestCase):
    """The Toolhelp Windows pipeline against a no-model fake kernel32."""

    CANDIDATES = {ntpath.normcase("ChatGPT.exe")}

    def run_windows(self, fake):
        payload = INV._enumerate_windows(candidate_basenames=self.CANDIDATES, api=fake)
        return {"status": "observed", "reason": None, **payload}

    def test_positive_identity_via_full_path(self):
        fake = FakeKernel32(
            [[(200, 1, "ChatGPT.exe"), (300, 1, "notepad.exe")]],
            {200: PINNED_DESKTOP})
        payload = self.run_windows(fake)
        self.assertEqual(payload["source"], "windows-toolhelp")
        self.assertEqual(payload["snapshot"]["candidates"], 1)
        self.assertEqual(payload["snapshot"]["image_path_reads"], {"ok": 1, "failed": 0})
        result = INV.classify(payload, [PINNED_DESKTOP])
        self.assertEqual(result["status"], "running")
        self.assertEqual(result["desktop_host_processes"],
                         [{"pid": 200, "ppid": 1, "executable": PINNED_DESKTOP}])
        self.assertEqual(result["counts"]["unrelated"], 1)
        self.assertTrue(fake.all_handles_closed())
        self.assertEqual(len(fake.close_calls), len(set(fake.close_calls)),
                         "every snapshot and candidate handle has exactly one owner")

    def test_different_basename_is_negative_evidence_only(self):
        # Unreadable rows whose snapshot basename
        # differs from the pinned basename are excluded from candidacy for
        # that exact pinned image — and from nothing else.
        fake = FakeKernel32([[(300, 1, "notepad.exe"), (301, 1, "svchost.exe")]])
        payload = self.run_windows(fake)
        self.assertEqual(payload["snapshot"]["candidates"], 0)
        self.assertEqual(fake.query_calls, [])
        result = INV.classify(payload, [PINNED_DESKTOP])
        self.assertEqual(result["status"], "absent")
        self.assertEqual(result["counts"]["unrelated"], 2)
        self.assertEqual(result["counts"]["unreadable"], 0)

    def test_same_name_unreadable_keeps_candidacy(self):
        fake = FakeKernel32([[(200, 1, "ChatGPT.exe")]], {}, query_fail_pids={200})
        payload = self.run_windows(fake)
        row = payload["rows"][0]
        self.assertEqual(row["identity"], "unreadable")
        self.assertEqual(row["exe_name"], "ChatGPT.exe")
        result = INV.classify(payload, [PINNED_DESKTOP])
        self.assertEqual(result["status"], "unknown",
                         "same name without a readable path is never absence")
        self.assertTrue(fake.all_handles_closed())

    def test_truncated_and_shape_anomalous_names_keep_candidacy(self):
        long_name = "X" * 259 + ".exe"
        fake = FakeKernel32([[(400, 1, long_name), (401, 1, "odd/path/weird.exe"),
                             (402, 1, r"odd\path\weird.exe"), (403, 1, "bad|name.exe")]])
        payload = self.run_windows(fake)
        self.assertTrue(all(row["exe_name"] is None and row["identity"] == "unreadable"
                            for row in payload["rows"]))
        result = INV.classify(payload, [PINNED_DESKTOP])
        self.assertEqual(result["status"], "unknown")

    def test_incomplete_walk_fails_the_enumeration(self):
        fake = FakeKernel32([[(300, 1, "notepad.exe")]], walk_fail_at=0)
        with self.assertRaises(INV.InventoryError):
            self.run_windows(fake)
        self.assertTrue(fake.all_handles_closed())

    def test_walk_exception_still_closes_snapshot(self):
        fake = FakeKernel32([[(300, 1, "notepad.exe")]])
        with mock.patch.object(fake, "Process32NextW", side_effect=OSError("read failed")):
            with self.assertRaises(OSError):
                self.run_windows(fake)
        self.assertTrue(fake.all_handles_closed())

    def test_snapshot_size_limit_closes_handle(self):
        fake = FakeKernel32([[(300, 1, "one.exe"), (301, 1, "two.exe")]])
        with mock.patch.object(INV, "MAX_PROCESSES", 1):
            with self.assertRaises(INV.InventoryError):
                self.run_windows(fake)
        self.assertTrue(fake.all_handles_closed())

    def test_empty_snapshot_never_proves_absence(self):
        fake = FakeKernel32([[]])
        with self.assertRaises(INV.InventoryError):
            self.run_windows(fake)
        self.assertTrue(fake.all_handles_closed())

    def test_duplicate_pid_snapshot_is_refused_before_query(self):
        fake = FakeKernel32([[(200, 1, "ChatGPT.exe"), (200, 1, "ChatGPT.exe")]])
        with self.assertRaises(INV.InventoryError):
            self.run_windows(fake)
        self.assertEqual(fake.query_calls, [])
        self.assertTrue(fake.all_handles_closed())

    def test_case_only_confirmation_keeps_windows_path_semantics(self):
        fake = FakeKernel32([[(200, 1, "ChatGPT.exe")], [(200, 1, "CHATGPT.EXE")]],
                            {200: PINNED_DESKTOP})
        payload = self.run_windows(fake)
        self.assertEqual(INV.classify(payload, [PINNED_DESKTOP])["status"], "running")
        self.assertTrue(fake.all_handles_closed())

    def test_snapshot_unavailable_fails_the_enumeration(self):
        fake = FakeKernel32([[]], snapshot_fail=True)
        with self.assertRaises(INV.InventoryError):
            self.run_windows(fake)

    def test_pid_name_change_between_snapshots_blocks_positive_read(self):
        fake = FakeKernel32(
            [[(200, 1, "ChatGPT.exe")], [(200, 1, "notepad.exe")]],
            {200: PINNED_DESKTOP})
        payload = self.run_windows(fake)
        self.assertEqual(fake.query_calls, [],
                         "a pid that changed basename between snapshots is never read")
        self.assertEqual(payload["rows"][0]["identity"], "unreadable")
        result = INV.classify(payload, [PINNED_DESKTOP])
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(fake.all_handles_closed())

    def test_snapshot_handle_close_failure_fails_the_enumeration(self):
        fake = FakeKernel32([[(300, 1, "notepad.exe")]], close_fail_handles={5000})
        with self.assertRaises(INV.InventoryError):
            self.run_windows(fake)

    def test_candidate_handle_close_failure_fails_the_enumeration(self):
        fake = FakeKernel32([[(200, 1, "ChatGPT.exe")]], {200: PINNED_DESKTOP})
        fake.close_fail_handles = {5002}  # after the first and confirmation snapshots
        with self.assertRaises(INV.InventoryError):
            self.run_windows(fake)
        self.assertEqual(fake.query_calls, [200], "exercise the candidate handle, not a snapshot")

    def test_classification_rejects_unusable_negative_name(self):
        payload = enum([{"pid": 200, "ppid": 1, "uid": None,
                         "identity": "unreadable", "executable": None,
                         "exe_name": r"bad\name.exe"}], source="windows-toolhelp")
        self.assertEqual(INV.classify(payload, [PINNED_DESKTOP])["status"], "unknown")

    def test_generic_pinned_basename_is_refused(self):
        with self.assertRaises(INV.InventoryError):
            INV.windows_candidate_basenames(["x" * 259 + ".exe"])

    def test_classification_reports_snapshot_facts(self):
        fake = FakeKernel32(
            [[(200, 1, "ChatGPT.exe")]],
            {200: PINNED_DESKTOP})
        payload = self.run_windows(fake)
        result = INV.classify(payload, [PINNED_DESKTOP])
        self.assertEqual(result["enumeration"]["snapshot"]["candidates"], 1)
        self.assertEqual(result["enumeration"]["snapshot"]["image_path_reads"],
                         {"ok": 1, "failed": 0})


if __name__ == "__main__":
    unittest.main()
