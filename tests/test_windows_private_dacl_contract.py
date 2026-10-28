"""Bounded protected-directory DACL readback contract (synthetic API inputs).

These tests do not establish native Windows acceptance. All identities are
synthetic; the P/PAI distinction replays the observed native control flags.
"""

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


class WindowsPrivateDaclContract(unittest.TestCase):
    def harden(self, readbacks):
        with mock.patch.object(cg, "_windows_current_user_sid", return_value=USER_SID), \
                mock.patch.object(cg, "_windows_query_dacl_sddl", side_effect=readbacks), \
                mock.patch.object(cg, "_windows_apply_protected_dacl") as apply:
            cg._harden_private_directory_windows(Path("synthetic-private"))
        return apply

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
