"""Synthetic redaction/observation controls; not native Windows evidence."""

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "dacl_diagnostic", SOURCE / "tools/validation/diagnose_windows_private_dacl.py")
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)
SID = "S-1-5-21-100-200-300-1001"
EXPECTED = f"D:P(A;OICI;FA;;;{SID})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"


class DaclDiagnosticTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "requires native Windows DACL APIs")
    def test_native_private_directory_contract_reports_redacted_details(self):
        result = subprocess.run(
            [sys.executable, "-B", str(
                SOURCE / "tools/validation/diagnose_windows_private_dacl.py")],
            capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stdout)
        observation = json.loads(result.stdout)
        self.assertTrue(observation["contract_matches"])
        self.assertFalse(observation["native_acceptance"])

    def test_shapes_preserve_order_controls_and_alias_without_identity(self):
        shape = diagnostic.descriptor_shape(EXPECTED.replace(SID, "LA"), SID)
        self.assertEqual([ace["trustee"] for ace in shape["aces"]],
                         ["alias_LA", "system", "administrators"])
        self.assertTrue(shape["protected"])
        self.assertFalse(shape["auto_inherited"])
        self.assertTrue(diagnostic.descriptor_shape(
            EXPECTED.replace("D:P", "D:PAI"), SID)["auto_inherited"])
        text = json.dumps(diagnostic.descriptor_shape(EXPECTED, SID))
        self.assertNotIn(SID, text)
        self.assertNotIn("S-1-", text)

    def test_unknown_fields_and_identifiers_are_not_echoed(self):
        marker = "synthetic-sensitive-value"
        shape = diagnostic.descriptor_shape(
            f"D:P({marker};{marker};{marker};{marker};{marker};{marker})", SID)
        self.assertNotIn(marker, json.dumps(shape))
        self.assertTrue(shape["aces"][0]["has_object_guid"])
        self.assertEqual(shape["aces"][0]["trustee"], "other")

    def runtime(self, after=EXPECTED, matches=True):
        runtime = mock.Mock()
        runtime._windows_current_user_sid.return_value = SID
        runtime._windows_expected_sddl.return_value = EXPECTED
        runtime._windows_query_dacl_sddl.side_effect = ["D:", after]
        runtime._windows_private_directory_dacl_matches.return_value = matches
        return runtime

    def test_success_calls_unchanged_product_contract(self):
        runtime = self.runtime()
        directory = Path("synthetic-only")
        result = diagnostic.observe(runtime, directory)
        runtime._windows_apply_protected_dacl.assert_called_once_with(directory, EXPECTED)
        runtime._windows_private_directory_dacl_matches.assert_called_once_with(
            EXPECTED, EXPECTED)
        self.assertTrue(result["contract_matches"])
        self.assertFalse(result["native_acceptance"])

    def test_mismatch_unreadable_and_error_do_not_become_success(self):
        for after in [None, "D:P", EXPECTED.replace("FA", "FR", 1)]:
            with self.subTest(after=after):
                result = diagnostic.observe(self.runtime(after, False), Path("synthetic-only"))
                self.assertFalse(result["contract_matches"])
        runtime = self.runtime()
        runtime._windows_apply_protected_dacl.side_effect = OSError(
            5, "synthetic-sensitive-path-and-account")
        result = diagnostic.observe(runtime, Path("synthetic-sensitive-path"))
        self.assertNotIn("synthetic-sensitive", json.dumps(result))
        self.assertNotIn("contract_matches", result)
        self.assertEqual(result["error"]["stage"], "apply")


if __name__ == "__main__":
    unittest.main()
