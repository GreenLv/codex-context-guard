"""Pure consumer/guard controls for the proposal; no Windows scenes executed."""

import copy
import ctypes
import errno
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path, PureWindowsPath
from unittest import mock

MODULE = (
    Path(__file__).resolve().parents[1] / "tools/validation/windows_retention_native.py"
)
SPEC = importlib.util.spec_from_file_location(
    "windows_retention_native_proposal", MODULE
)
w = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(w)


def snap():
    return {
        "dev": 1,
        "ino": 2,
        "birth_ns": 3,
        "session_id": "candidate",
        "ledger_sha256": "a" * 64,
        "state_sha256": "b" * 64,
    }


def winid():
    return {
        "volume_serial": 1,
        "file_id": "2" * 32,
        "kind": "directory",
        "reparse_tag": 0,
    }


def report(reason=None, quarantine=0):
    entry = {
        "name": "candidate",
        "verdict": "quarantined" if reason is None else "protected",
    }
    if reason:
        entry["reason"] = reason
    return {"counts": {"scanned": 2, "quarantined": quarantine}, "entries": [entry]}


def native_denial():
    return {
        "api": "CreateFileW_FILE_READ_DATA",
        "desired_access": 1,
        "share_mode": 7,
        "creation_disposition": 3,
        "flags": 0x00200000,
        "opened": False,
        "winerror": 5,
    }


def python_denial(winerror=None):
    return {
        "outcome": "error",
        "type": "PermissionError",
        "errno": 13,
        "winerror": winerror,
    }


def valid_result():
    binding = {"tool_commit": "1" * 40, "fixture_root": "C:\\private\\fixture"}
    rows = []
    for name in w.CASES:
        row = {
            "name": name,
            "status": "passed",
            "before": snap(),
            "protected_reader": snap(),
            "positive_reference": snap(),
            "guard_before": snap(),
            "guard_reader": snap(),
            "resources": {"dacl_restored": True, "handles_closed": True},
            "positive": {
                "reader": snap(),
                "restore_outcome": "restored",
                "record_binding": {
                    "identity": [1, 2],
                    "object_stamp": {"kind": "birth", "ns": 3},
                    "original_name": "candidate",
                },
                "target_absent": True,
                "record_absent": True,
                "tombstone_exists": True,
                "purge_report": {"purged": 1},
                "quarantine_report": report(quarantine=1),
            },
        }
        reason = {
            "dacl_refusal": "state_unreadable",
            "no_delete_share": "quarantine_failed",
            "case_alias": "busy_lock",
            "long_payload": "unfinished_work",
        }[name]
        c = row["condition"] = {"report": report(reason)}
        if name == "dacl_refusal":
            pinned = dict(winid(), kind="file")
            c.update(
                dacl_changed=True,
                native_read_probe=native_denial(),
                python_read_probe=python_denial(),
                pinned_before=copy.deepcopy(pinned),
                pinned_after=copy.deepcopy(pinned),
                path_after=copy.deepcopy(pinned),
                read_path_before=copy.deepcopy(pinned),
                read_path_after=copy.deepcopy(pinned),
                restored_state_sha256=snap()["state_sha256"],
                original_dacl_sha256="e" * 64,
                restored_dacl_sha256="e" * 64,
                apply_api={
                    "api": "SetSecurityInfo_DACL_only",
                    "flags": 4,
                    "winerror": 0,
                },
                restore_api={
                    "api": "SetSecurityInfo_DACL_only",
                    "flags": 0x80000004,
                    "winerror": 0,
                },
                close={"return_value": 1},
            )
        elif name == "no_delete_share":
            c.update(
                share_mode=3,
                delete_probe={"winerror": 32},
                handle_identity=winid(),
                path_identity=winid(),
                close={"return_value": 1},
            )
        elif name == "case_alias":
            c.update(
                original="C:\\private\\fixture\\case_alias\\data",
                alias="C:\\private\\fixture\\case_alias\\DATA",
                original_identity=winid(),
                alias_identity=winid(),
                kernel_lock_released=True,
            )
        else:
            path = str(
                PureWindowsPath(binding["fixture_root"])
                / "long_payload"
                / "data"
                / "sessions-v2"
                / "candidate"
                / ("x" * 100)
                / ("y" * 100)
                / ("z" * 60)
                / "payload.bin"
            )
            c.update(
                path_form="ordinary_absolute",
                payload_path=path,
                path_chars=len(path),
                max_component_chars=max(map(len, PureWindowsPath(path).parts)),
                payload_sha256="c" * 64,
                protected_payload_sha256="c" * 64,
                synthetic_completion=True,
                payload_absent_after_purge=True,
            )
            row["positive"]["payload_readback_sha256"] = "c" * 64
        rows.append(row)
    return {
        "schema": w.SCHEMA,
        "binding": binding,
        "fixture_root": binding["fixture_root"],
        "binding_unchanged_after_execution": True,
        "status": "passed",
        "cases": rows,
        "resources_released": True,
    }, binding


class ConsumerControls(unittest.TestCase):
    def test_python_crt_and_win32_denials_are_independent(self):
        for winerror in (None, 5):
            value, binding = valid_result()
            value["cases"][0]["condition"]["python_read_probe"] = python_denial(
                winerror
            )
            self.assertEqual(w.verify_result(value, binding), [])
        for key in ("native_read_probe", "python_read_probe"):
            self.rejected(lambda x: x["cases"][0]["condition"].pop(key))
        for key, values in {
            "api": ("CreateFileW_DELETE", ""),
            "desired_access": (0, 0x80, True, 1.0),
            "share_mode": (3, 7.0, True),
            "creation_disposition": (2, 3.0, True),
            "flags": (0, 0x00200000 * 1.0, True),
            "opened": (True, 0, None),
            "winerror": (0, 2, 32, None, 5.0, True, "5"),
        }.items():
            for bad in values:
                with self.subTest(native_key=key, bad=bad):
                    self.rejected(
                        lambda x: x["cases"][0]["condition"][
                            "native_read_probe"
                        ].update({key: bad})
                    )
        for key, values in {
            "outcome": ("read", None),
            "type": ("OSError", "FileNotFoundError", "IsADirectoryError", None),
            "errno": (None, 0, 1, 2, 5, 13.0, True, "13"),
            "winerror": (0, 2, 32, 5.0, True, "5"),
        }.items():
            for bad in values:
                with self.subTest(python_key=key, bad=bad):
                    self.rejected(
                        lambda x: x["cases"][0]["condition"][
                            "python_read_probe"
                        ].update({key: bad})
                    )

    def test_v1_and_single_error_field_cannot_be_promoted(self):
        self.rejected(lambda x: x.update(schema="cg-windows-retention-native/v1"))

        def old_condition(x):
            c = x["cases"][0]["condition"]
            c.pop("native_read_probe")
            c.pop("python_read_probe")
            c["read_winerror"] = 5

        self.rejected(old_condition)

    def test_dacl_requires_actual_api_binding_and_restoration(self):
        for edit in (
            lambda x: x["cases"][0]["condition"].pop("restore_api"),
            lambda x: x["cases"][0]["condition"]["apply_api"].update(flags=0x10),
            lambda x: x["cases"][0]["condition"]["restore_api"].update(winerror=5),
            lambda x: x["cases"][0]["condition"].update(restored_dacl_sha256="d" * 64),
            lambda x: x["cases"][0]["condition"].update(pinned_before={}),
            lambda x: x["cases"][0]["condition"]["path_after"].update(file_id="3" * 32),
            lambda x: x["cases"][0]["condition"]["read_path_before"].update(
                file_id="3" * 32
            ),
            lambda x: x["cases"][0]["condition"]["read_path_after"].update(
                file_id="3" * 32
            ),
            lambda x: x["cases"][0]["condition"].update(restored_state_sha256="d" * 64),
            lambda x: x["cases"][0]["resources"].update(handles_closed=False),
        ):
            self.rejected(edit)

    def test_each_native_identity_is_typed_before_equality(self):
        groups = (
            (
                0,
                (
                    "pinned_before",
                    "pinned_after",
                    "path_after",
                    "read_path_before",
                    "read_path_after",
                ),
            ),
            (1, ("handle_identity", "path_identity")),
            (2, ("original_identity", "alias_identity")),
        )
        for index, keys in groups:
            for key in keys:
                for field, values in {
                    "volume_serial": (True, 1.0),
                    "reparse_tag": (False, 0.0),
                }.items():
                    for bad in values:
                        with self.subTest(index=index, key=key, field=field, bad=bad):
                            self.rejected(
                                lambda x: x["cases"][index]["condition"][key].update(
                                    {field: bad}
                                )
                            )

    def test_long_path_recomputes_scope_and_components(self):
        paths = [
            "C:\\" + "x" * 300,
            "C:\\outside\\" + "x" * 200 + "\\" + "y" * 100,
            "\\\\?\\C:\\private\\fixture\\" + "x" * 300,
            "C:\\private\\fixture\\long_payload\\data\\sessions-v2\\candidate\\..\\"
            + "x" * 200
            + "\\"
            + "y" * 100,
        ]
        for raw in paths:
            self.rejected(
                lambda x: x["cases"][3]["condition"].update(
                    payload_path=raw, path_chars=len(raw), max_component_chars=50
                )
            )
        self.rejected(
            lambda x: x["cases"][3]["condition"].update(max_component_chars=49)
        )

    def test_eligible_aggregate_cannot_replace_named_quarantine(self):
        self.rejected(
            lambda x: x["cases"][0]["positive"]["quarantine_report"].update(
                entries=[{"name": "candidate", "verdict": "eligible"}]
            )
        )
        self.rejected(
            lambda x: x["cases"][0]["positive"]["record_binding"].update(
                original_name="other"
            )
        )

    def test_complete_recorded_positive(self):
        value, binding = valid_result()
        self.assertEqual(w.verify_result(value, binding), [])

    def rejected(self, edit):
        value, binding = valid_result()
        edit(value)
        self.assertTrue(w.verify_result(value, binding))

    def test_missing_duplicate_extra_and_wrong_binding(self):
        for edit in (
            lambda x: x["cases"].pop(),
            lambda x: x["cases"].append(copy.deepcopy(x["cases"][0])),
            lambda x: x["cases"][1].update(name="dacl_refusal"),
            lambda x: x.update(binding={}),
            lambda x: x.update(fixture_root="other"),
            lambda x: x.update(binding_unchanged_after_execution=False),
        ):
            with self.subTest(edit=edit):
                self.rejected(edit)

    def test_capability_and_unrun_never_pass(self):
        for status in ("capability_unavailable", "not_run", "running", "failed"):
            with self.subTest(status=status):
                self.rejected(lambda x: x["cases"][0].update(status=status))

    def test_report_requires_candidate_and_named_refusal(self):
        for entry in (
            [],
            [{"name": "other", "reason": "state_unreadable"}],
            [{"name": "candidate", "reason": "deadline"}],
        ):
            self.rejected(
                lambda x: x["cases"][0]["condition"]["report"].update(entries=entry)
            )
        self.rejected(
            lambda x: x["cases"][0]["condition"]["report"].update(
                deadline_reached="yes"
            )
        )
        self.rejected(
            lambda x: x["cases"][0]["condition"]["report"]["counts"].update(scanned=0)
        )

    def test_silent_replacement_or_empty_reader_rejected(self):
        self.rejected(lambda x: x["cases"][0]["positive_reference"].update(ino=99))
        self.rejected(
            lambda x: x["cases"][0]["positive_reference"].update(ledger_sha256="d" * 64)
        )
        self.rejected(
            lambda x: x["cases"][0]["protected_reader"].update(ledger_sha256="d" * 64)
        )
        self.rejected(
            lambda x: x["cases"][0]["guard_reader"].update(state_sha256="d" * 64)
        )

    def test_cleanup_and_bool_numeric_confusion_rejected(self):
        for edit in (
            lambda x: x["cases"][0]["resources"].update(dacl_restored=1),
            lambda x: x.update(resources_released=1),
            lambda x: x["cases"][1]["condition"]["close"].update(return_value=True),
            lambda x: x["cases"][0]["before"].update(dev=True),
            lambda x: x["cases"][0]["before"].update(ino=-1),
            lambda x: x["cases"][0]["before"].update(session_id=["candidate"]),
            lambda x: x["cases"][0]["positive"]["record_binding"].update(
                identity=[True, 2]
            ),
            lambda x: x["cases"][0]["positive"]["purge_report"].update(purged=True),
        ):
            self.rejected(edit)

    def test_no_delete_share_requires_real_probe_and_identity(self):
        self.rejected(
            lambda x: x["cases"][1]["condition"]["delete_probe"].update(winerror=0)
        )
        self.rejected(
            lambda x: x["cases"][1]["condition"].update(
                handle_identity={}, path_identity={}
            )
        )
        self.rejected(lambda x: x["cases"][1]["condition"].update(share_mode=7))

    def test_alias_requires_two_spellings_and_nonempty_identity(self):
        self.rejected(
            lambda x: x["cases"][2]["condition"].update(alias="C:\\fixture\\data")
        )
        self.rejected(
            lambda x: x["cases"][2]["condition"].update(
                original_identity={}, alias_identity={}
            )
        )
        self.rejected(
            lambda x: x["cases"][2]["condition"]["alias_identity"].update(
                file_id="3" * 32
            )
        )

    def test_long_path_requires_real_length_and_readback(self):
        for edit in (
            lambda x: x["cases"][3]["condition"].update(path_chars=260),
            lambda x: x["cases"][3]["condition"].update(max_component_chars=-1),
            lambda x: x["cases"][3]["condition"].update(max_component_chars=1.0),
            lambda x: x["cases"][3]["condition"].update(
                protected_payload_sha256="d" * 64
            ),
            lambda x: x["cases"][3]["positive"].update(payload_readback_sha256=None),
            lambda x: x["cases"][3]["condition"].pop("payload_sha256"),
        ):
            self.rejected(edit)

    def test_positive_requires_bound_move_restore_and_purge(self):
        self.rejected(
            lambda x: x["cases"][0]["positive"].update(restore_outcome="not_found")
        )
        self.rejected(lambda x: x["cases"][0]["positive"].update(record_absent=False))
        self.rejected(
            lambda x: x["cases"][0]["positive"]["quarantine_report"]["counts"].update(
                quarantined=0
            )
        )

    def test_combined_review_counterexample_rejected(self):
        value, binding = valid_result()
        for row in value["cases"]:
            row["positive_reference"]["ino"] = 9
            row["condition"]["report"] = {"counts": {"quarantined": 0}}
        value["cases"][1]["condition"].update(handle_identity={}, path_identity={})
        value["cases"][2]["condition"].update(original_identity={}, alias_identity={})
        value["cases"][3]["condition"].update(max_component_chars=-1)
        self.assertTrue(w.verify_result(value, binding))

    def test_malformed_rows_fail_closed_without_crash(self):
        for row in (
            None,
            [],
            {},
            {"name": []},
            {"name": "dacl_refusal", "status": "passed"},
        ):
            self.rejected(lambda x: x["cases"].__setitem__(0, row))

    def test_strict_json_rejects_duplicates_nonfinite_overflow(self):
        for text in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":-1e999}'):
            with self.assertRaises(ValueError):
                w.strict_json(text)


class ReadProbeControls(unittest.TestCase):
    def test_native_requests_data_and_captures_real_last_error(self):
        api = mock.Mock()
        api.CreateFileW.return_value = ctypes.c_void_p(-1).value
        for code in (5, 32, 2, 0):
            with (
                mock.patch.object(
                    w.ctypes, "WinDLL", return_value=api, create=True
                ) as dll,
                mock.patch.object(
                    w.ctypes, "get_last_error", return_value=code, create=True
                ) as error,
            ):
                result = w.read_access_probe(Path("synthetic.bin"))
            dll.assert_called_once_with("kernel32", use_last_error=True)
            api.CreateFileW.assert_called_with(
                "synthetic.bin", 1, 7, None, 3, 0x00200000, None
            )
            error.assert_called_once_with()
            self.assertEqual(result["winerror"], code)
            self.assertIs(result["opened"], False)
            self.assertEqual(w.dacl_reads_denied(result, python_denial()), code == 5)
        api.CloseHandle.assert_not_called()

    def test_native_unexpected_open_closes_and_never_uses_stale_error(self):
        api = mock.Mock()
        api.CreateFileW.return_value = 42
        api.CloseHandle.return_value = 1
        with (
            mock.patch.object(w.ctypes, "WinDLL", return_value=api, create=True),
            mock.patch.object(
                w.ctypes,
                "get_last_error",
                side_effect=AssertionError("stale error"),
                create=True,
            ),
        ):
            result = w.read_access_probe(Path("synthetic.bin"))
        api.CloseHandle.assert_called_once_with(42)
        self.assertIs(result["opened"], True)
        self.assertEqual(result["winerror"], 0)
        self.assertFalse(w.dacl_reads_denied(result, python_denial()))

    def test_native_unexpected_open_close_failure_is_recorded(self):
        api = mock.Mock()
        api.CreateFileW.return_value = 42
        api.CloseHandle.return_value = 0
        with (
            mock.patch.object(w.ctypes, "WinDLL", return_value=api, create=True),
            mock.patch.object(w.ctypes, "get_last_error", return_value=6, create=True),
        ):
            result = w.read_access_probe(Path("synthetic.bin"))
        self.assertEqual(result["close"]["return_value"], 0)
        self.assertEqual(result["close"]["winerror"], 6)
        self.assertFalse(w.dacl_reads_denied(result, python_denial()))

    def test_native_close_exception_retains_unconfirmed_resource(self):
        for close_raises in (True, False):
            api = mock.Mock()
            api.CreateFileW.return_value = 42
            api.CloseHandle.return_value = 0
            if close_raises:
                api.CloseHandle.side_effect = OSError(
                    errno.EIO, "synthetic close error"
                )
            with (
                mock.patch.object(w.ctypes, "WinDLL", return_value=api, create=True),
                mock.patch.object(
                    w.ctypes,
                    "get_last_error",
                    side_effect=OSError(errno.EIO, "synthetic last-error failure"),
                    create=True,
                ),
            ):
                result = w.read_access_probe(Path("synthetic.bin"))
            self.assertEqual(
                result["close"]["return_value"], None if close_raises else 0
            )
            self.assertEqual(result["close"]["error"]["errno"], errno.EIO)
            self.assertFalse(w.dacl_reads_denied(result, python_denial()))

    def test_python_records_actual_exception_without_filling_winerror(self):
        errors = [
            PermissionError(errno.EACCES, "denied"),
            OSError(errno.EIO, "io"),
            FileNotFoundError(errno.ENOENT, "missing"),
        ]
        native = PermissionError(errno.EACCES, "denied")
        native.winerror = 5
        errors.append(native)
        for exc in errors:
            with (
                self.subTest(exc=exc),
                mock.patch.object(Path, "open", side_effect=exc),
            ):
                result = w.python_read_probe(Path("synthetic.bin"))
            self.assertEqual(
                result,
                {
                    "outcome": "error",
                    "type": type(exc).__name__,
                    "errno": exc.errno,
                    "winerror": getattr(exc, "winerror", None),
                },
            )
            self.assertEqual(
                w.dacl_reads_denied(native_denial(), result),
                isinstance(exc, PermissionError),
            )

    def test_python_success_and_non_os_error_never_denied(self):
        path = mock.MagicMock()
        result = w.python_read_probe(path)
        self.assertEqual(result["outcome"], "read")
        self.assertFalse(w.dacl_reads_denied(native_denial(), result))
        path.open.side_effect = RuntimeError("unexpected")
        with self.assertRaises(RuntimeError):
            w.python_read_probe(path)


class DaclProducerControls(unittest.TestCase):
    def run_scene(
        self,
        *,
        native=None,
        python=None,
        identity_mismatch=False,
        restore_error=False,
        changed_content=False,
        dacl_unchanged=False,
        restore_identity_mismatch=False,
    ):
        # Pure harness controls: no native API or actual ACL mutation occurs.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "candidate"
            home.mkdir()
            (home / "state.json").write_text("synthetic", encoding="utf-8")
            fixture = mock.Mock(work=root, guard=root / "guard")
            fixture.make.return_value = home
            before = snap()
            before["state_sha256"] = w.file_digest(home / "state.json")
            fixture.guard_before = copy.deepcopy(before)
            fixture.reader.return_value = copy.deepcopy(before)
            fixture.advance.return_value = {}
            backend = fixture.backend
            backend.open_windows_handle.return_value = ("api", "pinned-handle")
            identity = dict(winid(), kind="file")
            backend.windows_handle_identity.return_value = identity
            backend.windows_object_identity.return_value = identity
            if identity_mismatch:
                backend.windows_object_identity.side_effect = [
                    dict(identity, file_id="3" * 32),
                    identity,
                    identity,
                ]
            descriptor = ["saved"]
            backend.windows_handle_descriptor.side_effect = lambda _: descriptor[0]
            backend.descriptor_contract.side_effect = lambda value: {
                "aces": [] if value == "saved" or dacl_unchanged else ["deny"]
            }
            backend.sid_bytes.return_value = b"synthetic-sid"
            backend.descriptor_with_aces.return_value = "denied"
            backend.close_windows_handle.return_value = {"return_value": 1}

            def apply(_backend, handle, value, *, restore=False):
                self.assertEqual(handle, "pinned-handle")
                if restore_error and restore:
                    raise OSError(errno.EIO, "synthetic restoration failure")
                descriptor[0] = value
                if restore and restore_identity_mismatch:
                    backend.windows_object_identity.return_value = dict(
                        identity, file_id="3" * 32
                    )
                if changed_content and restore:
                    (home / "state.json").write_text("changed", encoding="utf-8")
                return {
                    "api": "SetSecurityInfo_DACL_only",
                    "flags": 0x80000004 if restore else 4,
                    "winerror": 0,
                }

            original_open = Path.open

            def controlled_open(path, mode="r", *args, **kwargs):
                if (
                    path == home / "state.json"
                    and mode == "rb"
                    and descriptor[0] == "denied"
                ):
                    raise PermissionError(errno.EACCES, "synthetic denied CRT read")
                return original_open(path, mode, *args, **kwargs)

            with (
                mock.patch.object(w, "snapshot", return_value=before),
                mock.patch.object(w, "private_acl"),
                mock.patch.object(w, "set_handle_dacl", side_effect=apply),
                mock.patch.object(
                    w,
                    "read_access_probe",
                    return_value=native if native is not None else native_denial(),
                    create=True,
                ),
                mock.patch.object(
                    w,
                    "python_read_probe",
                    return_value=python if python is not None else python_denial(),
                    create=True,
                ),
                mock.patch.object(Path, "open", new=controlled_open),
            ):
                row = w.scenario("dacl_refusal", fixture)
            return row, fixture, backend

    def test_crt_mapping_gap_reaches_retention_then_restores_original_handle(self):
        row, fixture, backend = self.run_scene()
        self.assertEqual(row["status"], "passed")
        fixture.run.assert_called_once_with()
        self.assertIsNone(row["condition"]["python_read_probe"]["winerror"])
        self.assertEqual(row["condition"]["native_read_probe"]["winerror"], 5)
        self.assertEqual(
            row["resources"], {"dacl_restored": True, "handles_closed": True}
        )
        backend.close_windows_handle.assert_called_once_with("api", "pinned-handle")

    def test_missing_independent_denial_never_runs_retention_and_still_restores(self):
        for native, python in (
            (
                dict(
                    native_denial(), opened=True, winerror=0, close={"return_value": 1}
                ),
                python_denial(),
            ),
            (dict(native_denial(), winerror=32), python_denial()),
            (
                native_denial(),
                {"outcome": "read", "type": None, "errno": None, "winerror": None},
            ),
            (native_denial(), dict(python_denial(), type="FileNotFoundError", errno=2)),
        ):
            with self.subTest(native=native, python=python):
                row, fixture, _ = self.run_scene(native=native, python=python)
                self.assertEqual(row["status"], "failed")
                fixture.run.assert_not_called()
                self.assertEqual(row["condition"]["native_read_probe"], native)
                self.assertEqual(row["condition"]["python_read_probe"], python)
                self.assertEqual(
                    row["resources"], {"dacl_restored": True, "handles_closed": True}
                )

    def test_read_identity_mismatch_refused_before_retention(self):
        row, fixture, _ = self.run_scene(identity_mismatch=True)
        self.assertEqual(row["status"], "failed")
        fixture.run.assert_not_called()

    def test_unchanged_dacl_cannot_use_other_denials_to_reach_retention(self):
        row, fixture, _ = self.run_scene(dacl_unchanged=True)
        self.assertEqual(row["status"], "failed")
        fixture.run.assert_not_called()

    def test_restoration_failure_and_changed_content_cannot_pass(self):
        for kwargs in (
            {"restore_error": True},
            {"changed_content": True},
            {"restore_identity_mismatch": True},
        ):
            with self.subTest(kwargs=kwargs):
                row, _, backend = self.run_scene(**kwargs)
                self.assertEqual(row["status"], "failed")
                self.assertIn("cleanup_error", row["condition"])
                backend.close_windows_handle.assert_called_once_with(
                    "api", "pinned-handle"
                )

    def test_failed_unexpected_read_handle_close_stays_failed_after_pinned_close(self):
        for close in (
            {"return_value": 0, "winerror": 6},
            {
                "return_value": None,
                "winerror": None,
                "error": {"type": "OSError", "errno": errno.EIO},
            },
        ):
            row, fixture, _ = self.run_scene(
                native=dict(
                    native_denial(),
                    opened=True,
                    winerror=0,
                    close=close,
                )
            )
            self.assertEqual(row["status"], "failed")
            self.assertIs(row["resources"]["handles_closed"], False)
            fixture.run.assert_not_called()

    def test_primary_and_cleanup_errors_both_survive(self):
        row, fixture, _ = self.run_scene(
            native=dict(native_denial(), winerror=32), restore_error=True
        )
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["condition"]["primary_error"]["type"], "AssertionError")
        self.assertEqual(row["condition"]["cleanup_error"]["errno"], errno.EIO)
        self.assertIs(row["resources"]["dacl_restored"], False)
        fixture.run.assert_not_called()


class GuardControls(unittest.TestCase):
    def test_extra_zip_auth_member_refused_before_archive_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp).resolve() / "synthetic.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("safe.txt", "synthetic")
                z.writestr("auth.json", "synthetic-not-a-credential")
            with mock.patch.object(
                w, "file_digest", side_effect=AssertionError("must not hash archive")
            ):
                with self.assertRaisesRegex(ValueError, "no payload"):
                    w.validate_archive(archive, {"safe.txt": "a" * 64}, "b" * 64)

    def test_extra_credential_named_artifact_is_rejected_before_content_read(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve()
            (parent / "safe.txt").write_text("synthetic", encoding="utf-8")
            (parent / "auth.json").write_text(
                "synthetic-not-a-credential", encoding="utf-8"
            )

            class Identity:
                @staticmethod
                def checked_walk(root):
                    return ((p, p.lstat()) for p in root.iterdir())

                @staticmethod
                def safe_file(_root, _rel):
                    raise AssertionError(
                        "must reject filename set before reading content"
                    )

            with self.assertRaisesRegex(ValueError, "no extra content read"):
                w.compare_installed_without_extra_reads(
                    Identity, parent, {"safe.txt": "a" * 64}
                )

    def test_existing_output_and_fixture_refused_without_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve()
            output, fixture = parent / "result.json", parent / "fixture"
            output.write_text("preserve", encoding="utf-8")
            with self.assertRaises(ValueError):
                w.check_destinations(output, fixture, parent, [])
            self.assertEqual(output.read_text(encoding="utf-8"), "preserve")
            self.assertFalse(fixture.exists())

    def test_protected_overlap_and_events_fixture_collision_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve()
            for fixture, protected in (
                (parent / "fixture", [parent]),
                (parent / "result.events.jsonl", []),
            ):
                with self.assertRaises(ValueError):
                    w.check_destinations(
                        parent / "result.json", fixture, parent, protected
                    )
            self.assertEqual(list(parent.iterdir()), [])

    def test_preflight_does_not_need_to_create_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve()
            w.check_destinations(parent / "result.json", parent / "fixture", parent, [])
            self.assertEqual(list(parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
