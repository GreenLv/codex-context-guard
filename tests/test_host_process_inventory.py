"""Synthetic host-process inventory classification; no real process claims.

Every fixture here is synthetic: rows are dictionaries passed straight to
``classify``. Only one test performs a real read-only enumeration, and it
asserts the result shape only, never a specific host state.
"""
from __future__ import annotations

import importlib.util
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "host_process_inventory_under_test",
    "tools/validation/host_process_inventory.py")
INV = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(INV)

DESKTOP = "/Applications/Codex.app/Contents/MacOS/Codex"
HELPER = "/Applications/Codex.app/Contents/Library/CodexHelper"
SANDBOX = "/Applications/Codex.app/Contents/Library/CodexSandboxService"
OTHER = "/usr/sbin/unrelated-daemon"


def enum(rows, source="darwin-ps-libproc"):
    return {"status": "observed", "reason": None, "source": source, "rows": rows}


def row(pid, ppid, executable=None, uid=501, source="posix"):
    if source == "windows":
        return {"pid": pid, "ppid": ppid, "uid": None, "executable": executable,
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

    def test_windows_kernel_family_is_structural(self):
        result = INV.classify(enum([row(4, 0, None, source="windows"),
                                  row(1200, 4, None, source="windows")],
                                 source="windows-cim"),
                            [r"C:\Apps\Codex.exe"])
        self.assertEqual(result["status"], "absent")
        self.assertEqual(result["counts"]["system_kernel"], 2)

    def test_windows_identity_matches_case_insensitively(self):
        result = INV.classify(enum([{"pid": 900, "ppid": 100, "uid": None,
                                   "executable": r"c:\apps\codex.EXE",
                                   "identity": "observed"}], source="windows-cim"),
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


if __name__ == "__main__":
    unittest.main()
