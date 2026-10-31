"""Bounded protected-directory DACL readback contract (synthetic API inputs).

These tests do not establish native Windows acceptance. All identities are
synthetic; the P/PAI distinction replays the observed native control flags.
"""

import ctypes
import importlib.util
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "cg_windows_private_dacl", Path(__file__).resolve().parents[1]
    / "scripts" / "context_guard.py")
assert _SPEC is not None and _SPEC.loader is not None
cg = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cg)

USER_SID = "S-1-5-21-100-200-300-1001"
ACES = (
    f"(A;OICI;FA;;;{USER_SID})",
    "(A;OICI;FA;;;SY)",
    "(A;OICI;FA;;;BA)",
)
EXPECTED = "D:P" + "".join(ACES)
ADMIN_SID = "S-1-5-21-100-200-300-500"
ADMIN_EXPECTED = EXPECTED.replace(USER_SID, ADMIN_SID)
LA_READBACK = ADMIN_EXPECTED.replace(ADMIN_SID, "LA")


class WindowsPrivateDaclContract(unittest.TestCase):
    def harden(self, readbacks, sid=USER_SID):
        with mock.patch.object(cg, "_windows_current_user_sid", return_value=sid), \
                mock.patch.object(cg, "_windows_query_dacl_sddl", side_effect=readbacks), \
                mock.patch.object(cg, "_windows_apply_protected_dacl") as apply:
            cg._harden_private_directory_windows(Path("synthetic-private"))
        return apply

    def test_verified_la_readback_and_apply_recovery(self):
        for prefix in ("D:P", "D:PAI", "D:AIP"):
            observed = prefix + LA_READBACK[3:]
            with self.subTest(prefix=prefix), mock.patch.object(
                    cg, "_windows_local_admin_sid_matches", return_value=True) as resolve:
                self.harden([observed], ADMIN_SID).assert_not_called()
                self.harden(["D:", observed], ADMIN_SID).assert_called_once_with(
                    Path("synthetic-private"), ADMIN_EXPECTED)
                self.assertTrue(resolve.call_args_list)
                for call in resolve.call_args_list:
                    self.assertEqual(call, mock.call(ADMIN_SID))

    def test_unproven_la_fails_closed_and_later_numeric_readback_recovers(self):
        for outcome in (False, OSError("synthetic resolver unavailable")):
            with self.subTest(outcome=type(outcome).__name__), mock.patch.object(
                    cg, "_windows_local_admin_sid_matches",
                    **({"side_effect": outcome} if isinstance(outcome, OSError)
                       else {"return_value": outcome})):
                with self.assertRaises(cg.PrivateBoundaryError):
                    self.harden(["D:", LA_READBACK], ADMIN_SID)
                self.harden([LA_READBACK, ADMIN_EXPECTED], ADMIN_SID
                            ).assert_called_once()

    def test_verified_la_does_not_relax_other_boundaries(self):
        invalid = (
            LA_READBACK.replace("D:P", "D:AI"),
            LA_READBACK.replace(";FA;", ";FR;", 1),
            LA_READBACK.replace(";OICI;", ";OICIID;", 1),
            LA_READBACK.replace(";;;SY)", ";;;LA)"),
            LA_READBACK.replace(";;;BA)", ";;;LA)"),
            LA_READBACK.replace(";;;LA)", ";;;LG)"),
            "D:P" + ACES[1] + "(A;OICI;FA;;;LA)" + ACES[2],
            LA_READBACK + ACES[1],
            LA_READBACK.replace(";;;BA)", f";;;{ADMIN_SID})"),
        )
        with mock.patch.object(cg, "_windows_local_admin_sid_matches", return_value=True):
            for observed in invalid:
                with self.subTest(observed=observed):
                    with self.assertRaises(cg.PrivateBoundaryError):
                        self.harden(["D:", observed], ADMIN_SID)
            self.assertFalse(cg._windows_private_directory_dacl_matches(
                LA_READBACK, LA_READBACK))

    def test_numeric_readback_never_calls_alias_resolver(self):
        with mock.patch.object(cg, "_windows_local_admin_sid_matches") as resolve:
            self.harden([EXPECTED]).assert_not_called()
        resolve.assert_not_called()

    def test_windows_api_compares_complete_sids_and_frees_allocations(self):
        # API-shaped substitutes exercise real pointer outputs and cleanup.
        # They are synthetic, not proof of LA resolution on a Windows host.
        for same_identity in (True, False):
            for expected_sid in (ADMIN_SID, "S-1-5-21-400-500-600-500", USER_SID):
                advapi = mock.Mock()
                kernel = mock.Mock()

                def convert(text, output):
                    output._obj.value = 101 if text == "LA" else 202
                    return 1

                advapi.ConvertStringSidToSidW.side_effect = convert
                advapi.EqualSid.return_value = same_identity
                with mock.patch.object(ctypes, "WinDLL", create=True,
                                       side_effect=[advapi, kernel]):
                    self.assertEqual(cg._windows_local_admin_sid_matches(expected_sid),
                                     same_identity)
                self.assertEqual([call.args[0] for call in
                                  advapi.ConvertStringSidToSidW.call_args_list],
                                 ["LA", expected_sid])
                self.assertEqual([arg.value for arg in
                                  advapi.EqualSid.call_args.args], [101, 202])
                self.assertEqual([call.args[0].value for call in
                                  kernel.LocalFree.call_args_list], [202, 101])

    def test_windows_api_conversion_failures_are_closed_and_freed(self):
        for failed_call in (1, 2):
            for failure in ("zero", "null", "oserror"):
                advapi = mock.Mock()
                kernel = mock.Mock()
                calls = 0

                def convert(text, output):
                    nonlocal calls
                    calls += 1
                    if calls == failed_call:
                        if failure == "oserror":
                            raise OSError("synthetic conversion failure")
                        if failure == "null":
                            return 1
                        return 0
                    output._obj.value = 101
                    return 1

                advapi.ConvertStringSidToSidW.side_effect = convert
                with self.subTest(failed_call=failed_call, failure=failure), \
                        mock.patch.object(ctypes, "WinDLL", create=True,
                                          side_effect=[advapi, kernel]):
                    self.assertFalse(cg._windows_private_directory_dacl_matches(
                        LA_READBACK, ADMIN_EXPECTED))
                advapi.EqualSid.assert_not_called()
                self.assertEqual(kernel.LocalFree.call_count, failed_call - 1)

    def test_la_for_different_machine_or_user_is_not_current_user(self):
        for expected_sid in ("S-1-5-21-400-500-600-500", USER_SID):
            advapi = mock.Mock()
            kernel = mock.Mock()
            identities = {101: ADMIN_SID, 202: expected_sid}

            def convert(text, output):
                output._obj.value = 101 if text == "LA" else 202
                return 1

            advapi.ConvertStringSidToSidW.side_effect = convert
            advapi.EqualSid.side_effect = lambda left, right: (
                identities[left.value] == identities[right.value])
            with self.subTest(expected_sid=expected_sid), mock.patch.object(
                    ctypes, "WinDLL", create=True, side_effect=[advapi, kernel]):
                self.assertFalse(cg._windows_private_directory_dacl_matches(
                    LA_READBACK, ADMIN_EXPECTED.replace(ADMIN_SID, expected_sid)))
            advapi.EqualSid.assert_called_once()
            self.assertEqual(kernel.LocalFree.call_count, 2)

    def test_windows_api_load_and_comparison_errors_fail_closed(self):
        with mock.patch.object(ctypes, "WinDLL", create=True,
                               side_effect=OSError("synthetic load failure")):
            self.assertFalse(cg._windows_private_directory_dacl_matches(
                LA_READBACK, ADMIN_EXPECTED))
        advapi = mock.Mock()
        kernel = mock.Mock()

        def convert(text, output):
            output._obj.value = 101 if text == "LA" else 202
            return 1

        advapi.ConvertStringSidToSidW.side_effect = convert
        advapi.EqualSid.side_effect = OSError("synthetic comparison failure")
        with mock.patch.object(ctypes, "WinDLL", create=True,
                               side_effect=[advapi, kernel]):
            self.assertFalse(cg._windows_private_directory_dacl_matches(
                LA_READBACK, ADMIN_EXPECTED))
        self.assertEqual(kernel.LocalFree.call_count, 2)

    def test_missing_windows_api_symbols_fail_closed_before_allocation(self):
        for missing in ("ConvertStringSidToSidW", "EqualSid", "LocalFree"):
            advapi = mock.Mock(spec=["ConvertStringSidToSidW", "EqualSid"])
            kernel = mock.Mock(spec=["LocalFree"])
            delattr(kernel if missing == "LocalFree" else advapi, missing)
            with self.subTest(missing=missing), mock.patch.object(
                    ctypes, "WinDLL", create=True, side_effect=[advapi, kernel]):
                with self.assertRaises(cg.PrivateBoundaryError):
                    self.harden(["D:", LA_READBACK], ADMIN_SID)
            if missing != "ConvertStringSidToSidW":
                advapi.ConvertStringSidToSidW.assert_not_called()

    def test_first_free_exception_still_attempts_both_and_fails_closed(self):
        for error in (OSError("synthetic free failure"),
                      AttributeError("synthetic free unavailable")):
            advapi = mock.Mock()
            kernel = mock.Mock()

            def convert(text, output):
                output._obj.value = 101 if text == "LA" else 202
                return 1

            advapi.ConvertStringSidToSidW.side_effect = convert
            advapi.EqualSid.return_value = True
            kernel.LocalFree.side_effect = [error, None]
            with self.subTest(error=type(error).__name__), mock.patch.object(
                    ctypes, "WinDLL", create=True, side_effect=[advapi, kernel]):
                with self.assertRaises(cg.PrivateBoundaryError):
                    self.harden(["D:", LA_READBACK], ADMIN_SID)
            self.assertEqual([call.args[0].value for call in
                              kernel.LocalFree.call_args_list], [202, 101])

    def test_exact_protected_p_readback_is_noop(self):
        self.harden([EXPECTED]).assert_not_called()

    def test_protected_pai_readback_is_noop(self):
        observed = EXPECTED.replace("D:P", "D:PAI", 1)
        self.harden([observed, observed]).assert_not_called()

    def test_successful_apply_then_p_readback(self):
        self.harden(["D:", EXPECTED]).assert_called_once_with(
            Path("synthetic-private"), EXPECTED)

    def test_successful_apply_then_pai_readback(self):
        self.harden(["D:", EXPECTED.replace("D:P", "D:PAI", 1)]).assert_called_once_with(
            Path("synthetic-private"), EXPECTED)

    def test_equivalent_masks_sids_and_inheritance_order(self):
        equivalent = (EXPECTED.replace("D:P", "D:AIP", 1)
                      .replace(";OICI;", ";CIOI;")
                      .replace(";FA;", ";0x001f01ff;")
                      .replace(";;;SY)", ";;;S-1-5-18)")
                      .replace(";;;BA)", ";;;S-1-5-32-544)"))
        self.harden([equivalent, equivalent]).assert_not_called()

    def test_invalid_boundaries_remain_fail_closed_after_successful_set(self):
        invalid = {
            "unreadable": None,
            "empty": "",
            "absent": "O:SY",
            "empty_dacl": "D:P",
            "null_dacl": "D:PNO_ACCESS_CONTROL",
            "missing_protected": "D:" + "".join(ACES),
            "ai_without_protected": "D:AI" + "".join(ACES),
            "auto_inherit_request": EXPECTED.replace("D:P", "D:PAR"),
            "protected_ai_request": EXPECTED.replace("D:P", "D:PAIAR"),
            "duplicate_protected": EXPECTED.replace("D:P", "D:PP"),
            "duplicate_ai": EXPECTED.replace("D:P", "D:PAIAI"),
            "unknown_control": EXPECTED.replace("D:P", "D:PX"),
            "extra_ace": EXPECTED + "(A;OICI;FA;;;WD)",
            "missing_ace": "D:PAI" + "".join(ACES[:2]),
            "duplicate_ace": "D:PAI" + ACES[0] + ACES[1] * 2,
            "wrong_user": EXPECTED.replace(USER_SID, "S-1-5-21-100-200-300-1002"),
            "everyone": EXPECTED.replace(";;;BA)", ";;;WD)"),
            "wrong_rights": EXPECTED.replace(";FA;", ";FR;", 1),
            "wrong_mask": EXPECTED.replace(";FA;", ";0x001f01fe;", 1),
            "generic_all": EXPECTED.replace(";FA;", ";GA;", 1),
            "deny_ace": EXPECTED.replace("(A;", "(D;", 1),
            "inherited_ace": EXPECTED.replace(";OICI;", ";OICIID;", 1),
            "inherit_only": EXPECTED.replace(";OICI;", ";OICIIO;", 1),
            "no_propagate": EXPECTED.replace(";OICI;", ";OICINP;", 1),
            "missing_object_inherit": EXPECTED.replace(";OICI;", ";CI;", 1),
            "missing_container_inherit": EXPECTED.replace(";OICI;", ";OI;", 1),
            "duplicate_inherit_flag": EXPECTED.replace(";OICI;", ";OICIOI;", 1),
            "object_guid": EXPECTED.replace("FA;;;", "FA;guid;;", 1),
            "ace_order": "D:PAI" + ACES[1] + ACES[0] + ACES[2],
            "extra_section": EXPECTED + "S:P",
            "trailing_junk": EXPECTED + "garbage",
            "ai_inside_sid": EXPECTED.replace(USER_SID, USER_SID + "AI"),
        }
        # Repeat every protected malformed ACE/control input with AI too:
        # accepting that metadata must not mask any permission mismatch.
        invalid.update({
            label + "_with_ai": "D:PAI" + observed[3:]
            for label, observed in list(invalid.items())
            if isinstance(observed, str) and observed.startswith("D:P")
        })
        for label, observed in invalid.items():
            with self.subTest(label=label):
                with self.assertRaises(cg.PrivateBoundaryError):
                    self.harden(["D:", observed])

    def test_query_oserror_is_fail_closed(self):
        with self.assertRaises(cg.PrivateBoundaryError):
            self.harden([OSError("synthetic read denied")])

    def test_set_oserror_is_fail_closed(self):
        with mock.patch.object(cg, "_windows_current_user_sid", return_value=USER_SID), \
                mock.patch.object(cg, "_windows_query_dacl_sddl", return_value="D:"), \
                mock.patch.object(cg, "_windows_apply_protected_dacl",
                                  side_effect=OSError("synthetic set denied")):
            with self.assertRaises(cg.PrivateBoundaryError):
                cg._harden_private_directory_windows(Path("synthetic-private"))


if __name__ == "__main__":
    unittest.main()
