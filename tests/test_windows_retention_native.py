"""Pure consumer/guard controls for the proposal; no Windows scenes executed."""

import copy
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
                read_winerror=5,
                pinned_before=copy.deepcopy(pinned),
                pinned_after=copy.deepcopy(pinned),
                path_after=copy.deepcopy(pinned),
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
    def test_dacl_requires_actual_api_binding_and_restoration(self):
        for edit in (
            lambda x: x["cases"][0]["condition"].pop("restore_api"),
            lambda x: x["cases"][0]["condition"]["apply_api"].update(flags=0x10),
            lambda x: x["cases"][0]["condition"]["restore_api"].update(winerror=5),
            lambda x: x["cases"][0]["condition"].update(restored_dacl_sha256="d" * 64),
            lambda x: x["cases"][0]["condition"].update(pinned_before={}),
            lambda x: x["cases"][0]["condition"]["path_after"].update(file_id="3" * 32),
        ):
            self.rejected(edit)

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
