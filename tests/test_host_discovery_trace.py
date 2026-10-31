"""Offline format/readback and ownership controls; no native behavior claim."""
import codecs
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

DIRECTORY = Path(__file__).resolve().parents[1] / "tools/validation"
sys.path.insert(0, str(DIRECTORY))
try:
    SPEC = importlib.util.spec_from_file_location("host_trace", DIRECTORY / "host_discovery_trace.py")
    d = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(d)
finally:
    sys.path.pop(0)

PREFIX = "CommandDiscovery Information: 0 : "
KNOWN = PREFIX + "Looking up command: Join-Path\n"


class DiscoveryTraceControls(unittest.TestCase):
    def test_two_cases_share_utility_import_and_exact_expression(self):
        control, traced = (d.script_for(case).decode("ascii") for case in d.CASES)
        for source in (control, traced):
            self.assertEqual(source.count("Microsoft.PowerShell.Core\\Import-Module"), 1)
            self.assertIn("Microsoft.PowerShell.Utility.psd1", source)
            for forbidden in ("New-Object", "Get-Command", "Get-ExecutionPolicy", "-ExecutionPolicy", "cg_hook", "context_guard.py"):
                self.assertNotIn(forbidden, source)
        def expression(source):
            return source.split("$cgExpression = {", 1)[1].split("}\nWrite-CgHostStage", 1)[0]
        self.assertEqual(expression(control), expression(traced))
        self.assertIn("Microsoft.PowerShell.Utility\\Trace-Command -Name CommandDiscovery", traced)
        self.assertIn("-FilePath $env:CG_HOST_RAW_TRACE", traced)
        self.assertNotIn("-PSHost", traced)

    def test_absent_empty_unknown_and_truncated_are_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "raw"
            self.assertEqual(d.trace_summary(path, r"C:\Windows\PS")["state"], "absent")
            path.write_bytes(b"")
            self.assertEqual(d.trace_summary(path, r"C:\Windows\PS")["state"], "empty")
            path.write_bytes(b"unknown-secret-format\n")
            unknown = d.trace_summary(path, r"C:\Windows\PS")
            self.assertEqual(unknown["state"], "unrecognized")
            self.assertEqual(unknown["unknown_count"], 1)
            self.assertNotIn("secret", json.dumps(unknown))
            path.write_bytes(b"x" * (d.LIMIT + 99) + b"\n" + KNOWN.encode())
            truncated = d.trace_summary(path, r"C:\Windows\PS")
            self.assertEqual(truncated["state"], "truncated")
            self.assertEqual(truncated["total_bytes"], path.stat().st_size)
            self.assertLessEqual(truncated["window_bytes"], d.LIMIT)
            self.assertFalse(truncated["window_complete"])
            self.assertTrue(truncated["discarded_first_fragment"])
            self.assertEqual(truncated["counts"], {"lookup_join": 1})

    def test_utf8_utf16_timestamps_and_environment_redaction(self):
        text = (KNOWN + "    DateTime=2026-11-01T01:02:03.1234567Z\n" +
                PREFIX + "PATH: C:\\private-secret;token=secret\n" +
                PREFIX + "Attempting to load module: secret-personal-module\n" +
                PREFIX + "Attempting to load module: C:\\Windows\\PS\\Modules\\Microsoft.PowerShell.Management\\module.psd1\n")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "raw"
            for raw in (text.encode(), codecs.BOM_UTF16_LE + text.encode("utf-16-le"),
                        codecs.BOM_UTF16_BE + text.encode("utf-16-be")):
                path.write_bytes(raw)
                result = d.trace_summary(path, r"C:\Windows\PS")
                self.assertEqual(result["events"][0]["timestamp_utc"], "2026-11-01T01:02:03.1234567Z")
                self.assertEqual(result["counts"]["environment_path_suppressed"], 1)
                self.assertEqual(result["unknown_count"], 1)
                self.assertEqual(result["events"][-1]["module_id"], "management")
                self.assertNotIn("secret", json.dumps(result))
                self.assertNotIn("C:\\", json.dumps(result))
            path.write_text(KNOWN + "DateTime=2026-02-30T01:02:03Z\n", encoding="utf-8")
            result = d.trace_summary(path, r"C:\Windows\PS")
            self.assertIsNone(result["events"][0]["timestamp_utc"])
            self.assertEqual(result["unknown_count"], 1)

    def test_unknown_encoding_read_failure_and_bounded_event_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "raw"
            path.write_bytes(b"\xffsecret")
            self.assertEqual(d.trace_summary(path, "system")["state"], "unrecognized")
            path.write_bytes((KNOWN * 40).encode())
            result = d.trace_summary(path, "system")
            self.assertEqual(len(result["events"]), 16)
            self.assertEqual(result["counts"]["lookup_join"], 40)
            with mock.patch.object(Path, "open", side_effect=PermissionError("secret-path")):
                result = d.trace_summary(path, "system")
            self.assertEqual(result["state"], "unknown")
            self.assertNotIn("secret", json.dumps(result))
        self.assertIsNone(d.module_id(r"C:\private-secret\Microsoft.PowerShell.Management.psd1", r"C:\Windows\PS"))

    def case(self, *, unknown=False, cleanup=True):
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary) / "fixture"
            outer.mkdir()
            payload = b'{"hook_event_name":"UserPromptSubmit"}'
            class Process:
                returncode = 0
                calls = 0
                def communicate(process, input=None, timeout=None):
                    process.calls += 1
                    if process.calls == 1:
                        self.assertEqual(input, payload)
                        self.assertEqual(timeout, 30)
                    return b'{"host_probe_completed":true}', b""
            owner = types.SimpleNamespace(process=Process(), close=mock.Mock(return_value={
                "cleanup_complete": cleanup, "owned_process_exited": True, "owned_tree_no_running_members": cleanup}))
            def spawn(command, **kwargs):
                self.assertEqual(kwargs["cwd"], Path("fixed-subject"))
                self.assertNotIn("PSModulePath", kwargs["env"])
                self.assertEqual(command[1:4], ["-NoProfile", "-NonInteractive", "-File"])
                Path(kwargs["env"]["CG_HOST_STAGE"]).write_text(
                    '{"phase":"entry","elapsed_ms":0,"version":"5.1.1.1"}', encoding="utf-8")
                Path(kwargs["env"]["CG_HOST_RAW_TRACE"]).write_bytes(KNOWN.encode())
                return owner
            owned = types.SimpleNamespace(spawn=mock.Mock(side_effect=spawn))
            with mock.patch.object(d.host.common, "tree_observation", return_value={"active_processes": 0}):
                if unknown:
                    with mock.patch.object(d, "trace_summary", return_value={"state": "unknown"}):
                        row = d.run_case(Path("fixed-subject"), outer, d.CASES[1], "inert-shell", owned, payload)
                else:
                    row = d.run_case(Path("fixed-subject"), outer, d.CASES[1], "inert-shell", owned, payload)
            owner.close.assert_called_once_with(timeout=5)
            self.assertTrue(outer.exists())  # Raw never uploaded or silently discarded.
            self.assertNotIn(str(outer), json.dumps(row))
            return row

    def test_terminal_driver_error_or_unknown_accounting_cannot_complete_collection(self):
        good = {"fixture_cleanup": "retained_runner_local_raw_trace", "result": "returned",
                "before_cleanup": {"active_processes": 0}}
        self.assertTrue(d.collection_complete([good, good]))
        self.assertFalse(d.collection_complete([good, dict(good, result="driver_error")]))
        self.assertFalse(d.collection_complete([good, dict(good, before_cleanup={"active_processes": None})]))

    def test_owned_cleanup_and_unknown_readback_retain_local_raw(self):
        self.assertEqual(self.case()["fixture_cleanup"], "retained_runner_local_raw_trace")
        self.assertEqual(self.case(unknown=True)["fixture_cleanup"], "retained")
        self.assertEqual(self.case(cleanup=False)["fixture_cleanup"], "retained")


if __name__ == "__main__":
    unittest.main()
