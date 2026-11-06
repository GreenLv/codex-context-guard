"""Tests of scheduler batch facts. No real task or scheduler is started."""
from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_scheduler_batch_tested", ROOT / "tools/validation/native_scheduler_batch.py")
assert SPEC and SPEC.loader
SCHED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCHED)


def command(status, state, **extra):
    return {"exit_code": 0, "json": {"status": status, "state": state, **extra}}


def passing_macos():
    fixture = Path("/private/tmp/scheduler-fixture")
    subject = {"source_commit": "a" * 40, "toolkit_commit": "b" * 40,
               "installed_plugin_root": "/private/tmp/canonical/cache", "python": "/usr/bin/python3"}
    expected = SCHED._expected_definition(subject, fixture / "guard-data", "Darwin")
    file_facts = {"sha256": "c" * 64, "inode": 123, "mode": 0o600, "mtime_ns": 42}
    definition = {**file_facts, **expected, "run_at_load": False, "calendar": {"Hour": 3, "Minute": 17}}
    foreign_facts = {**file_facts, "program_arguments": ["/usr/bin/true"],
                     "run_at_load": False, "calendar": None}
    foreign = {"enable": {"exit_code": 2, "json": {"reason": "foreign_entry", "owned": False}},
               "disable": {"exit_code": 2, "json": {"reason": "foreign_entry", "owned": False}},
               "before": foreign_facts, "after": dict(foreign_facts), "removed": True}
    snapshot = {"definition": definition, "ownership_manifest": dict(file_facts)}
    eligible_obj = {"identity": [1, 2], "object_stamp": {"kind": "birth", "ns": 3},
                    "tree_sha256": "e" * 64, "file_count": 1}
    protected_obj = {"identity": [1, 4], "object_stamp": {"kind": "birth", "ns": 5},
                     "tree_sha256": "f" * 64, "file_count": 1}
    before = {"policy_enabled": True, "eligible_exists": True, "protected_unfinished": 1,
              "eligible_state_sha256": "a" * 64, "protected_state_sha256": "b" * 64,
              "records_empty": True, "eligible_object": eligible_obj, "protected_object": protected_obj}
    after = {"eligible_exists": False, "record_count": 1, "record_state": "quarantined",
             "record_original": "scheduler-eligible", "quarantine_state_sha256": "a" * 64,
             "protected_state_sha256": "b" * 64,
             "quarantine_object": copy.deepcopy(eligible_obj), "protected_object": copy.deepcopy(protected_obj),
             "record_binding": {"identity": [1, 2], "object_stamp": {"kind": "birth", "ns": 3},
                                "state": "quarantined", "original_name": "scheduler-eligible",
                                "quarantine_object": "scheduler-eligible.123"}}
    reader = {"eligible_state_sha256": "a" * 64, "protected_state_sha256": "b" * 64,
              "protected_unfinished": 1, "quarantine_record_exists": False,
              "eligible_object": copy.deepcopy(eligible_obj), "protected_object": copy.deepcopy(protected_obj)}
    scene = {"initial_status": command("read_back", "disabled"),
             "enable": command("enabled", "enabled", owned=True, current=True),
             "status": command("read_back", "enabled"),
             "second_enable": command("already_enabled", "enabled", no_op=True),
             "before_second": snapshot, "after_second": copy.deepcopy(snapshot),
             "job_before": {"runs": 0, "last_exit_code": None, "state": "waiting", "pid": None},
             "job_after": {"runs": 1, "last_exit_code": 0, "state": "waiting", "pid": None},
             "trigger": {"exit_code": 0, "pid": 123, "trigger_attempted": True,
                         "job_stdout": "unavailable", "job_stderr": "unavailable"},
             "observation_seconds": 0.1,
             "post_job_preview": {"exit_code": 0, "json": {"mode": "preview", "capacity_exceeded": False,
                 "counts": {"protected": 1}, "entries": [{"name": "scheduler-pending", "reason": "unfinished_work"}]}},
             "fixture_before": before, "fixture_after_job": after, "reader": reader,
             "disable": command("disabled", "disabled"),
             "second_disable": command("already_disabled", "disabled", no_op=True),
             "final_status": command("read_back", "disabled")}
    inventory = {"count": 1, "sha256": "d" * 64, "scope": "synthetic names"}
    report = {"schema": SCHED.SCHEMA, "status": "passed", "platform": "macos",
              "fixture_root": str(fixture), "foreign_label": "cg-ccg0170-test-foreign",
              "subject": {**subject, "expected_definition": expected},
              "foreign": foreign, "scene": scene,
              "cleanup": {"job_absent": True, "foreign_absent": True,
                          "command_process_unknown": False, "job_process_unknown": False,
                          "job_before_disable": {"runs": 1, "last_exit_code": 0, "state": "waiting", "pid": None},
                          "unrelated_before": inventory, "unrelated_after": dict(inventory)}}
    return report, subject, fixture


class SchedulerBatchTests(unittest.TestCase):
    def consume(self, report, subject, fixture):
        return SCHED.consume(report, expected_subject=subject, fixture=fixture, system="Darwin")

    def test_v2_rejects_missing_or_altered_native_witnesses(self):
        report, subject, fixture = passing_macos()
        mutations = [
            lambda x: x.update(schema=SCHED.WINDOWS_V1_SCHEMA),
            lambda x: x["scene"]["fixture_before"].update(records_empty=False),
            lambda x: x["scene"]["fixture_before"]["eligible_object"].update(tree_sha256=None),
            lambda x: x["scene"]["fixture_before"]["eligible_object"].update(identity=[]),
            lambda x: x["scene"]["fixture_before"]["eligible_object"].update(object_stamp=None),
            lambda x: x["scene"]["fixture_after_job"]["record_binding"].update(identity=[8, 9]),
            lambda x: x["scene"]["fixture_after_job"]["record_binding"].update(object_stamp={"kind": "birth", "ns": 8}),
            lambda x: x["scene"]["reader"].pop("eligible_object"),
            lambda x: x["scene"]["fixture_after_job"]["protected_object"].update(tree_sha256="0" * 64),
            lambda x: x["scene"]["trigger"].update(trigger_attempted=False),
            lambda x: x["scene"]["job_after"].update(last_exit_code=1),
            lambda x: x["scene"]["job_after"].update(runs=2),
            lambda x: x["scene"]["post_job_preview"]["json"]["entries"][0].update(reason="wrong"),
            lambda x: x["scene"].update(job_report=x["scene"].pop("post_job_preview")),
            lambda x: x["cleanup"].update(job_process_unknown=None),
        ]
        for mutate in mutations:
            bad = copy.deepcopy(report)
            mutate(bad)
            self.assertTrue(self.consume(bad, subject, fixture))

    def test_object_snapshot_uses_real_anchored_tree_and_refuses_links(self):
        spec = importlib.util.spec_from_file_location("snapshot_native", ROOT / "tools/validation/native_acceptance.py")
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        cg = mock.Mock()
        cg._retention_object_stamp.return_value = {"kind": "birth", "ns": 3}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "object"
            root.mkdir()
            (root / "payload").write_bytes(b"first")
            before = SCHED._object_snapshot(native, cg, root)
            self.assertEqual(before["file_count"], 1)
            (root / "payload").write_bytes(b"changed")
            self.assertNotEqual(before["tree_sha256"], SCHED._object_snapshot(native, cg, root)["tree_sha256"])
            if os.name != "nt":
                (root / "link").symlink_to(root / "payload")
                with self.assertRaises(native.NativeRunError):
                    SCHED._object_snapshot(native, cg, root)

    def test_macos_trigger_uses_only_user_kickstart(self):
        driver = object.__new__(SCHED._Mac)
        driver.domain = "gui/501"
        driver.call = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"123\n", b""))
        result = driver.trigger("cg-ccg0170-test", Path("/unused"))
        driver.call.assert_called_once_with("kickstart", "-p", "gui/501/cg-ccg0170-test")
        self.assertEqual(result["pid"], 123)
        self.assertEqual(result["job_stdout"], "unavailable")

    def test_mac_fields_ignore_nested_resource_and_environment_values(self):
        nested = ("\tresource coalition = {\n\t\tstate = active\n"
                  "\t\tpid = 999\n\t\truns = 8\n\t\tlast exit code = 99\n\t}\n")
        raw = ("gui/1/cg-example = {\n\tstate = not running\n\truns = 1\n"
               "\tlast exit code = 0\n" + nested + "}\n").encode()
        fields = SCHED._mac_fields(raw)
        self.assertEqual(fields, {"state": "not running", "runs": 1,
                                  "last_exit_code": 0, "pid": None})
        self.assertTrue(SCHED._completed_job({"runs": 0}, fields, "Darwin"))
        self.assertTrue(SCHED._job_nonrunning(fields, "Darwin"))
        running = ("gui/1/cg-example = {\n\tstate = running\n\tpid = 33\n"
                   "\truns = 1\n\tlast exit code = (never exited)\n"
                   "\tenvironment = {\n\t\tstate = not running\n"
                   "\t\tlast exit code = 0\n\t}\n}\n").encode()
        fields = SCHED._mac_fields(running)
        self.assertEqual(fields["state"], "running")
        self.assertEqual(fields["pid"], 33)
        self.assertFalse(SCHED._completed_job({"runs": 0}, fields, "Darwin"))
        self.assertFalse(SCHED._job_nonrunning(fields, "Darwin"))

    def test_mac_duplicate_or_missing_job_fields_fail_closed(self):
        raw = b"x = {\n\tstate = not running\n\tstate = running\n\truns = 1\n}\n"
        fields = SCHED._mac_fields(raw)
        self.assertTrue(all(value is None for value in fields.values()))
        self.assertFalse(SCHED._job_nonrunning(fields, "Darwin"))
        nested_only = b"x = {\n\tcoalition = {\n\t\tstate = not running\n\t\truns = 1\n\t}\n}\n"
        fields = SCHED._mac_fields(nested_only)
        self.assertFalse(SCHED._job_nonrunning(fields, "Darwin"))

    def test_mac_malformed_or_contradictory_pid_cannot_prove_exit(self):
        for key, value in (("pid", "malformed"), ("pid", "-1"), ("pid", "0"),
                           ("runs", "unknown"), ("pid", "1" * 30), ("last exit code", "?")):
            raw = {"state": "not running", "runs": "1", "last exit code": "0"}
            raw[key] = value
            data = ("job = {\n" + "".join("\t" + k + " = " + v + "\n" for k, v in raw.items()) + "}\n").encode()
            fields = SCHED._mac_fields(data)
            self.assertFalse(SCHED._job_nonrunning(fields, "Darwin"))
            self.assertFalse(SCHED._completed_job({"runs": 0}, fields, "Darwin"))
        fields = {"state": "not running", "runs": 1, "last_exit_code": 0, "pid": 33}
        self.assertFalse(SCHED._job_nonrunning(fields, "Darwin"))
        self.assertFalse(SCHED._completed_job({"runs": 0}, fields, "Darwin"))
        fields.pop("pid")
        self.assertFalse(SCHED._job_nonrunning(fields, "Darwin"))
        never = b"job = {\n\tstate = not running\n\truns = 0\n\tlast exit code = (never exited)\n}\n"
        self.assertTrue(SCHED._job_nonrunning(SCHED._mac_fields(never), "Darwin"))
        contradictory = never.replace(b"runs = 0", b"runs = 1")
        self.assertFalse(SCHED._job_nonrunning(SCHED._mac_fields(contradictory), "Darwin"))
        missing = b"job = {\n\tstate = not running\n\truns = 0\n}\n"
        self.assertTrue(all(value is None for value in SCHED._mac_fields(missing).values()))
        false_exit = never.replace(b"(never exited)", b"0")
        self.assertTrue(all(value is None for value in SCHED._mac_fields(false_exit).values()))

    def test_valid_facts_and_cli_success_without_movement(self):
        report, subject, fixture = passing_macos()
        self.assertEqual([], self.consume(report, subject, fixture))
        report["scene"]["fixture_after_job"]["eligible_exists"] = True
        self.assertIn("fixture", self.consume(report, subject, fixture))

    def test_invalid_binding_foreign_and_changed_job_are_rejected(self):
        report, subject, fixture = passing_macos()
        report["subject"]["toolkit_commit"] = "c" * 40
        report["foreign"]["after"] = {"sha256": "changed"}
        report["scene"]["after_second"]["definition"]["program_arguments"][2] = "/bad/script"
        errors = self.consume(report, subject, fixture)
        self.assertTrue({"subject", "foreign_preservation", "strict_noop"}.issubset(errors))

    def test_failed_or_unknown_process_cannot_pass(self):
        report, subject, fixture = passing_macos()
        report["status"] = "failed"
        report["cleanup"]["command_process_unknown"] = True
        errors = self.consume(report, subject, fixture)
        self.assertIn("producer_reported_failure", errors)
        self.assertIn("cleanup", errors)

    def test_missing_or_malformed_witnesses_never_pass(self):
        report, subject, fixture = passing_macos()
        for key in ("command_process_unknown", "job_process_unknown"):
            for value in (None, True):
                bad = copy.deepcopy(report)
                bad["cleanup"][key] = value
                self.assertIn("cleanup", self.consume(bad, subject, fixture))
            bad = copy.deepcopy(report)
            del bad["cleanup"][key]
            self.assertIn("cleanup", self.consume(bad, subject, fixture))
        for key in ("eligible_state_sha256", "protected_state_sha256"):
            bad = copy.deepcopy(report)
            bad["scene"]["fixture_before"][key] = None
            bad["scene"]["reader"][key] = None
            after_key = "quarantine_state_sha256" if key.startswith("eligible") else key
            bad["scene"]["fixture_after_job"][after_key] = None
            self.assertIn("fixture_digest", self.consume(bad, subject, fixture))
        bad = copy.deepcopy(report)
        for side in ("before_second", "after_second"):
            del bad["scene"][side]["ownership_manifest"]
        self.assertIn("strict_noop", self.consume(bad, subject, fixture))
        bad = copy.deepcopy(report)
        bad["foreign"]["before"] = bad["foreign"]["after"] = {"present": True}
        self.assertIn("foreign_preservation", self.consume(bad, subject, fixture))
        bad = copy.deepcopy(report)
        bad["cleanup"]["unrelated_before"] = bad["cleanup"]["unrelated_after"] = {"count": 1}
        self.assertIn("cleanup", self.consume(bad, subject, fixture))
        bad = copy.deepcopy(report)
        bad["cleanup"]["job_before_disable"]["runs"] = 2
        self.assertIn("cleanup", self.consume(bad, subject, fixture))

    def test_protected_root_rejection_is_noncreating(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            installed = root / "installed"
            installed.mkdir()
            protected = installed / "original"
            protected.write_bytes(b"original")
            before = {str(p.relative_to(installed)): p.read_bytes()
                      for p in installed.rglob("*") if p.is_file()}
            native = mock.Mock()
            for output in (installed / "result.json", installed / "new-parent" / "result.json"):
                with self.assertRaises((OSError, SCHED.SchedulerBatchError)):
                    SCHED.preflight(native, ROOT, "a" * 40, "b" * 40, installed, root / "unused.zip",
                                    "c" * 64, output, root / "fixture", "cg-ccg0170-test")
                native.check_retention_batch_inputs.assert_not_called()
                self.assertFalse((installed / "new-parent").exists())
                self.assertEqual(before, {str(p.relative_to(installed)): p.read_bytes()
                                          for p in installed.rglob("*") if p.is_file()})
            codex_home = root / "codex-home"
            codex_home.mkdir()
            marker = codex_home / "marker"
            marker.write_bytes(b"preserved")
            with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
                with self.assertRaises(SCHED.SchedulerBatchError):
                    SCHED.preflight(native, ROOT, "a" * 40, "b" * 40, installed,
                                    root / "unused.zip", "c" * 64, codex_home / "result.json",
                                    root / "fixture", "cg-ccg0170-test")
            native.check_retention_batch_inputs.assert_not_called()
            self.assertEqual([marker], list(codex_home.iterdir()))
            self.assertEqual(b"preserved", marker.read_bytes())

    def test_malformed_fact_types_fail_closed(self):
        report, subject, fixture = passing_macos()
        for key in ("subject", "foreign", "scene", "cleanup"):
            bad = copy.deepcopy(report)
            bad[key] = None
            self.assertTrue(self.consume(bad, subject, fixture))
        bad = copy.deepcopy(report)
        bad["scene"]["enable"]["json"] = None
        bad["scene"]["post_job_preview"]["json"] = None
        self.assertTrue(self.consume(bad, subject, fixture))

    def test_registration_args_checked_against_installed_cache(self):
        report, subject, fixture = passing_macos()
        expected = SCHED._expected_definition(subject, fixture / "guard-data", "Darwin")
        actual = report["scene"]["before_second"]["definition"]
        self.assertTrue(SCHED._definition_matches(actual, expected, "Darwin"))
        actual["program_arguments"][2] = "/source/scripts/context_guard.py"
        self.assertFalse(SCHED._definition_matches(actual, expected, "Darwin"))
        self.assertIn("registered_definition", self.consume(report, subject, fixture))

    def test_windows_native_facts_need_a_new_successful_run(self):
        report, subject, fixture = passing_macos()
        report["platform"] = "windows"
        report["schema"] = SCHED.WINDOWS_V1_SCHEMA
        report["started_at"] = "2026-01-01T00:00:00+00:00"
        start = dt.datetime.fromisoformat(report["started_at"])
        delta = start - dt.datetime(1, 1, 1, tzinfo=dt.timezone.utc)
        ticks = (delta.days * 86400 + delta.seconds) * 10_000_000
        expected = SCHED._expected_definition(subject, fixture / "guard-data", "Windows")
        report["subject"]["expected_definition"] = expected
        definition = {**expected, "enabled": "true", "logon_type": "InteractiveToken",
                      "run_level": "LeastPrivilege", "sha256": "c" * 64,
                      "security_sha256": "f" * 64}
        report["scene"]["before_second"]["definition"] = definition
        report["scene"]["after_second"]["definition"] = copy.deepcopy(definition)
        report["scene"]["before_second"]["ownership_manifest"]["security_sha256"] = "f" * 64
        report["scene"]["after_second"]["ownership_manifest"]["security_sha256"] = "f" * 64
        foreign = {"sha256": "e" * 64, "description": "ccg0170-owned-foreign-fixture-"
                   + report["foreign_label"], "enabled": "false", "logon_type": "InteractiveToken",
                   "run_level": "LeastPrivilege", "security_sha256": "a" * 64}
        report["foreign"]["before"] = foreign
        report["foreign"]["after"] = dict(foreign)
        report["scene"]["job_before"] = {"last_run_ticks": ticks - 1, "state": "Ready"}
        report["scene"]["job_after"] = {"last_run_ticks": ticks + 1, "last_result": 0, "state": "Ready"}
        report["cleanup"]["job_before_disable"] = dict(report["scene"]["job_after"])
        self.assertEqual([], SCHED.consume(report, expected_subject=subject, fixture=fixture, system="Windows"))
        for collection in ("definition", "ownership_manifest"):
            for value in (None, "d" * 64):
                bad = copy.deepcopy(report)
                bad["scene"]["after_second"][collection]["security_sha256"] = value
                self.assertIn("strict_noop", SCHED.consume(
                    bad, expected_subject=subject, fixture=fixture, system="Windows"))
        for value in (None, "d" * 64):
            bad = copy.deepcopy(report)
            bad["foreign"]["after"]["security_sha256"] = value
            self.assertIn("foreign_preservation", SCHED.consume(
                bad, expected_subject=subject, fixture=fixture, system="Windows"))
        report["scene"]["job_after"]["last_result"] = 5
        self.assertIn("native_execution", SCHED.consume(
            report, expected_subject=subject, fixture=fixture, system="Windows"))

    def test_windows_foreign_principal_matches_product_and_is_disabled(self):
        spec = importlib.util.spec_from_file_location("scheduler_fixture_product", ROOT / "scripts/context_guard.py")
        assert spec and spec.loader
        product = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(product)
        namespace = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        owner = ET.fromstring(product._retention_windows_task_xml(Path("/synthetic")))
        foreign = ET.fromstring(SCHED._windows_foreign_xml("cg-ccg0170-test-foreign", r"C:\Windows\System32\cmd.exe"))
        self.assertEqual(ET.tostring(owner.find("t:Principals", namespace)),
                         ET.tostring(foreign.find("t:Principals", namespace)))
        self.assertEqual(owner.find("t:Actions", namespace).get("Context"),
                         foreign.find("t:Actions", namespace).get("Context"))
        self.assertEqual("false", foreign.find("t:Settings/t:Enabled", namespace).text)
        self.assertEqual("false", foreign.find("t:Triggers/t:TimeTrigger/t:Enabled", namespace).text)

    def test_windows_powershell_removes_only_module_path_in_child(self):
        driver = object.__new__(SCHED._Windows)
        driver.native, driver.source, driver.powershell = mock.Mock(), ROOT, "powershell.exe"
        driver.env = {"PSModulePath": "one", "psmodulepath": "two", "PsMoDuLePaTh": "three",
                      "PATH": "keep-path", "SYSTEMROOT": "keep-system", "OTHER": "keep-other"}
        original = dict(driver.env)
        parent = dict(os.environ)
        with mock.patch.object(SCHED, "_command", return_value=subprocess.CompletedProcess([], 0, b"PRIVATE", b"")) as call:
            self.assertTrue(driver.private_parent(Path("private")))
        self.assertEqual(call.call_args.kwargs["env"],
                         {"PATH": "keep-path", "SYSTEMROOT": "keep-system", "OTHER": "keep-other"})
        self.assertEqual(driver.env, original)
        self.assertEqual(dict(os.environ), parent)
        # Even a misleading stdout cannot override a failing Get-Acl process.
        with mock.patch.object(SCHED, "_command", return_value=subprocess.CompletedProcess([], 1, b"PRIVATE", b"Get-Acl failed")):
            self.assertFalse(driver.private_parent(Path("private")))
        self.assertEqual(driver.env, original)
        self.assertEqual(dict(os.environ), parent)

    def test_windows_security_capture_exports_only_valid_digest(self):
        driver = object.__new__(SCHED._Windows)
        driver.ps = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"a" * 64 + b"\n", b""))
        self.assertEqual("a" * 64, driver.task_security("cg-ccg0170-test"))
        self.assertIn("GetSecurityDescriptor(7)", driver.ps.call_args.args[0])
        self.assertEqual("a" * 64, driver.manifest_security(Path("/synthetic/owned.json")))
        self.assertIn("Get-Acl -LiteralPath", driver.ps.call_args.args[0])
        driver.ps.return_value = subprocess.CompletedProcess([], 0, b"S-1-raw-descriptor", b"")
        with self.assertRaises(SCHED.SchedulerBatchError):
            driver.manifest_security(Path("/synthetic/owned.json"))

    def test_windows_scene_captures_owned_manifest_security(self):
        driver = object.__new__(SCHED._Windows)
        driver.manifest_security = mock.Mock(return_value="a" * 64)
        driver.definition = mock.Mock(return_value={"sha256": "b" * 64,
                                                     "security_sha256": "c" * 64})
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "owned.json"
            manifest.write_text("synthetic", encoding="utf-8")
            cg = mock.Mock()
            cg._retention_schedule_manifest_path.return_value = manifest
            scene = SCHED._scene_snapshot(driver, cg, Path(directory), "cg-ccg0170-test")
        self.assertEqual("a" * 64, scene["ownership_manifest"]["security_sha256"])
        self.assertEqual("c" * 64, scene["definition"]["security_sha256"])
        driver.manifest_security.assert_called_once_with(manifest)

    def test_real_fixture_without_changing_home_or_starting_scheduler(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "scene"
            fixture.mkdir()
            home, userprofile = os.environ.get("HOME"), os.environ.get("USERPROFILE")
            with SCHED._environment(SCHED._fixture_env(fixture)), SCHED._installed_imports(ROOT):
                obj, cg, eligible, protected = SCHED._load_fixture(ROOT, ROOT, fixture)
                self.assertEqual(home, os.environ.get("HOME"))
                self.assertEqual(userprofile, os.environ.get("USERPROFILE"))
                self.assertTrue(cg.read_retention_policy(obj.data_dir)["enabled"])
                self.assertTrue(eligible.is_dir())
                state = cg.load_state(protected, obj.payload("SessionStart", "scheduler-pending"))
                self.assertGreater(SCHED._unfinished(state), 0)

    def test_fixture_uses_installed_runtime_when_roots_are_distinct(self):
        # A disposable fake installation, never a consumed or live cache.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            installed, fixture = root / "fake-install", root / "fixture"
            installed.mkdir()
            fixture.mkdir()
            shutil.copytree(ROOT / "scripts", installed / "scripts")
            shutil.copytree(ROOT / "assets", installed / "assets")
            with SCHED._environment(SCHED._fixture_env(fixture)), SCHED._installed_imports(installed):
                import test_cg0170_retention_restored as helper
                prior = helper.cg
                called = []
                original = helper.RetentionFixtureBase.make_session

                def observe(obj, *args, **kwargs):
                    called.append(Path(helper.cg.__file__).resolve())
                    return original(obj, *args, **kwargs)

                with mock.patch.object(helper.RetentionFixtureBase, "make_session", observe):
                    obj, cg, eligible, protected = SCHED._load_fixture(ROOT, installed, fixture)
                self.assertIs(helper.cg, prior)
                self.assertEqual(called, [(installed / "scripts/context_guard.py").resolve()] * 2)
                self.assertEqual(Path(cg.__file__).resolve(), (installed / "scripts/context_guard.py").resolve())
                self.assertTrue(eligible.is_dir())
                self.assertTrue(protected.is_dir())
                self.assertTrue(cg.read_retention_policy(obj.data_dir)["enabled"])

    def test_preflight_label_and_capability_do_not_register(self):
        native = mock.Mock()
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(SCHED, "subject_identity", return_value={}), \
             mock.patch.object(SCHED, "_driver") as make_driver, \
             mock.patch.object(SCHED, "_safe_new_path"), \
             mock.patch.object(SCHED, "_private_parent"):
            parent = Path(directory).resolve()
            driver = make_driver.return_value
            driver.absent.return_value = True
            with mock.patch.object(SCHED, "_safe_time", return_value=True):
                SCHED.preflight(native, ROOT, "a" * 40, "b" * 40, ROOT,
                                ROOT / "x.zip", "c" * 64, parent / "out.json",
                                parent / "fixture", "cg-ccg0170-unique")
            driver.foreign_create.assert_not_called()
            driver.trigger.assert_not_called()
            driver.foreign_remove.assert_not_called()
            self.assertEqual(driver.absent.call_count, 2)

    def test_coordinator_with_fake_scheduler_and_real_synthetic_data(self):
        # This double uses no system scheduler. The only mutation is in a
        # temporary synthetic data root; it tests the acceptance glue, not OS
        # scheduling, installation, or the external artifact identity checks.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture = root / "fixture"
            output = root / "result.json"
            label = "cg-ccg0170-test"
            subject = {"source_commit": "a" * 40, "toolkit_commit": "b" * 40,
                       "installed_plugin_root": str(ROOT), "python": str(Path(sys.executable).absolute())}
            expected = SCHED._expected_definition(subject, fixture / "guard-data", "Darwin")
            file_facts = {"sha256": "c" * 64, "inode": 123, "mode": 0o600, "mtime_ns": 42}
            definition = {**file_facts, **expected, "run_at_load": False,
                          "calendar": {"Hour": 3, "Minute": 17}}
            foreign_definition = {**file_facts, "program_arguments": ["/usr/bin/true"],
                                  "run_at_load": False, "calendar": None}
            job = {"runs": 0, "state": "waiting", "last_exit_code": None, "pid": None}
            driver = mock.Mock()
            driver.inventory.return_value = {"count": 1, "sha256": "d" * 64, "scope": "synthetic names"}
            driver.foreign_create.return_value = {"definition": foreign_definition}
            driver.definition.side_effect = lambda name: foreign_definition if name.endswith("-foreign") else definition
            driver.foreign_remove.return_value = True
            driver.absent.return_value = True
            driver.job.side_effect = lambda unused, **kwargs: dict(job)
            fixture_product = []
            original_load = SCHED._load_fixture

            def load_fixture(*args):
                loaded = original_load(*args)
                fixture_product.append(loaded[1])
                return loaded

            def trigger(unused, scratch):
                cg = fixture_product[-1]
                report = cg.cleanup_old_sessions(fixture / "guard-data", deadline=time.monotonic() + 20, apply=True)
                self.assertEqual(report["counts"]["quarantined"], 1)
                job.update(runs=1, state="waiting", last_exit_code=0)
                return {"exit_code": 0, "pid": 123, "trigger_attempted": True,
                        "job_stdout": "unavailable", "job_stderr": "unavailable"}

            driver.trigger.side_effect = trigger
            reads = 0

            def cli(unused_native, unused_source, unused_script, unused_data, target, op, unused_env):
                nonlocal reads
                if target.endswith("-foreign"):
                    return {"exit_code": 2, "json": {"reason": "foreign_entry", "owned": False}}
                if op == "enable":
                    reads += 1
                    return command("enabled", "enabled", owned=True, current=True) if reads == 1 else command(
                        "already_enabled", "enabled", no_op=True)
                if op == "status":
                    state = "enabled" if reads and driver.absent.call_count == 0 else "disabled"
                    return command("read_back", state, owned=state == "enabled")
                if op == "disable":
                    # The first disable changes fake state; the second is a no-op.
                    if getattr(cli, "disabled", False):
                        return command("already_disabled", "disabled", no_op=True)
                    cli.disabled = True
                    return command("disabled", "disabled")
                raise AssertionError(op)

            # Status after disable must read back disabled.
            old_cli = cli

            def observed_cli(*args):
                if args[4] == label and args[5] == "status" and getattr(cli, "disabled", False):
                    return command("read_back", "disabled")
                return old_cli(*args)

            snapshot = {"definition": definition, "ownership_manifest": dict(file_facts)}
            with mock.patch.object(SCHED, "preflight", return_value=subject), \
                 mock.patch.object(SCHED, "_driver", return_value=driver), \
                 mock.patch.object(SCHED, "_load_fixture", side_effect=load_fixture), \
                 mock.patch.object(SCHED, "_scene_snapshot", return_value=snapshot) as scene_mock, \
                 mock.patch.object(SCHED, "_command", side_effect=lambda native, source, argv, **kw: subprocess.run(argv, cwd=source, env=kw.get("env"), capture_output=True, check=False)), \
                 mock.patch.object(SCHED, "_cli", side_effect=observed_cli) as cli_mock, \
                 mock.patch.object(SCHED.platform, "system", return_value="Darwin"), \
                 mock.patch.object(SCHED, "_safe_time", return_value=True):
                native_spec = importlib.util.spec_from_file_location(
                    "scheduler_native_snapshot", ROOT / "tools/validation/native_acceptance.py")
                native = importlib.util.module_from_spec(native_spec)
                native_spec.loader.exec_module(native)
                result = SCHED.execute(native, ROOT, "a" * 40, "b" * 40, ROOT,
                                       root / "unused.zip", "c" * 64, output, fixture, label)
                self.assertEqual("passed", result["status"], (result.get("error"), result.get("consumer_errors")))
                self.assertEqual("passed", json.loads(output.read_text())["status"])
                driver.trigger.assert_called_once()

                # A task appears running again at cleanup; stopping it has an
                # unknown process result. The batch must retain registration,
                # refrain from disable, and fail the result.
                driver.reset_mock()
                cli_mock.reset_mock()
                reads = 0
                cli.disabled = False
                fixture = root / "fixture-unknown"
                output = root / "result-unknown.json"
                expected = SCHED._expected_definition(subject, fixture / "guard-data", "Darwin")
                definition = {**file_facts, **expected, "run_at_load": False,
                              "calendar": {"Hour": 3, "Minute": 17}}
                scene_mock.return_value = {"definition": definition, "ownership_manifest": dict(file_facts)}
                job.update(runs=0, state="waiting", last_exit_code=None)

                def became_running(unused, **kwargs):
                    if driver.job.call_count >= 3:
                        job.update(runs=2, state="running", pid=456, last_exit_code=None)
                    return dict(job)

                driver.job.side_effect = became_running
                driver.stop.side_effect = SCHED.ProcessStateUnknown("stop unknown")
                result = SCHED.execute(native, ROOT, "a" * 40, "b" * 40, ROOT,
                                       root / "unused.zip", "c" * 64, output, fixture, label)
                self.assertEqual("failed", result["status"])
                self.assertIs(result["cleanup"]["command_process_unknown"], True)
                self.assertIs(result["cleanup"]["job_process_unknown"], True)
                driver.stop.assert_called_once_with(label)
                self.assertFalse(any(call.args[4] == label and call.args[5] == "disable"
                                     for call in cli_mock.call_args_list))


if __name__ == "__main__":
    unittest.main()
