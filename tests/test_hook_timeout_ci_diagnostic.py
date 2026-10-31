"""Diagnostic controls only; no Windows, PowerShell, Hook or network execution."""
import ctypes
import importlib.util
import json
import os
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "tools/validation/hook_timeout_ci_diagnostic.py"
SPEC = importlib.util.spec_from_file_location("hook_diagnostic", PATH)
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)


class DiagnosticControls(unittest.TestCase):
    def test_orders_keep_the_original_control_and_reverse_the_pair(self):
        self.assertEqual(d.CASES, ("trace_only", "private_environment_trace"))
        self.assertEqual(d.ORDERS, {
            "ABA": ("trace_only", "private_environment_trace", "trace_only"),
            "BAB": ("private_environment_trace", "trace_only", "private_environment_trace")})

    def test_environment_variants_change_only_declared_inputs(self):
        with mock.patch.object(os, "pathsep", ";"), mock.patch.object(os, "defpath", ".;C:\\bin"):
            cases = {name: d.environment_for(Path("C:/private"), name,
                     "C:/Python/python.exe") for name in d.CASES}
        original = cases["trace_only"]
        complete = dict(cases["private_environment_trace"])
        additions = {"TMP", "TEMP", "APPDATA", "LOCALAPPDATA", "PSModuleAnalysisCachePath"}
        self.assertEqual(set(complete) - set(original), additions)
        self.assertEqual(complete.pop("TMP"), str(Path("C:/private") / "tmp"))
        self.assertEqual(complete.pop("TEMP"), str(Path("C:/private") / "tmp"))
        self.assertEqual(complete.pop("APPDATA"), str(Path("C:/private") / "appdata"))
        self.assertEqual(complete.pop("LOCALAPPDATA"), str(Path("C:/private") / "localappdata"))
        self.assertEqual(complete.pop("PSModuleAnalysisCachePath"),
                         str(Path("C:/private") / "module-cache/ModuleAnalysisCache"))
        self.assertEqual(complete, original)
        self.assertEqual(original["PATH"], str(Path("C:/Python")) + ";.;C:\\bin")
        self.assertNotIn("PYTHONDONTWRITEBYTECODE", original)

    def test_trace_is_bounded_and_never_echoes_unknown_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "synthetic.jsonl"
            log.write_text('{"phase":"start","elapsed_ms":0}\n')
            self.assertEqual(d.trace_shape(root)["records"], [{"phase": "start", "elapsed_ms": 0}])
            log.write_text('{"phase":"start","elapsed_ms":0,"private":"secret-path"}\n')
            self.assertNotIn("secret-path", json.dumps(d.trace_shape(root)))
            self.assertEqual(d.trace_shape(root)["state"], "unavailable")

    def case(self, *, timed_out=False, cleanup=True, private_environment=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subject = root / "source"
            (subject / "scripts").mkdir(parents=True)
            (subject / "scripts/run-context-guard.ps1").write_text("# inert fixture\n")
            outer = root / "fixture"
            outer.mkdir()
            class Accounting(ctypes.Structure):
                _fields_ = [("ActiveProcesses", ctypes.c_ulong)]
            class Process:
                returncode = 0
                count = 0
                def poll(self):
                    return 0
                def communicate(self, input=None, timeout=None):
                    self.count += 1
                    if timed_out and self.count == 1:
                        raise subprocess.TimeoutExpired("secret-command", timeout,
                            output=b"{}", stderr=b"secret-path-and-content")
                    return b"{}", b""
            def query(job, number, pointer, size, unused):
                pointer._obj.ActiveProcesses = 1 if timed_out else 0
                return True
            owner = types.SimpleNamespace(process=Process(), job=1,
                accounting_type=Accounting, api=types.SimpleNamespace(QueryInformationJobObject=query),
                close=mock.Mock(return_value={"cleanup_complete": cleanup,
                    "owned_process_exited": True, "owned_tree_no_running_members": cleanup}))
            owned = mock.Mock()
            def spawn(*args, **kwargs):
                self.assertEqual((outer / "os-home").is_dir(), private_environment)
                for name in ("tmp", "appdata", "localappdata", "module-cache"):
                    self.assertEqual((outer / name).is_dir(), private_environment)
                return owner
            owned.spawn.side_effect = spawn
            identity = types.SimpleNamespace(distribution_manifest=lambda root:
                {"scripts/run-context-guard.ps1": "synthetic"}, compare_artifact=lambda *args: None)
            case = "private_environment_trace" if private_environment else "trace_only"
            row = d.run_case(subject, outer, case, "inert-powershell", identity, owned)
            self.assertEqual(owned.spawn.call_args.kwargs["stdin"], subprocess.PIPE)
            owner.close.assert_called_once_with(timeout=5)
            self.assertEqual(row["fixture_cleanup"], "removed" if cleanup else "retained")
            self.assertEqual(outer.exists(), not cleanup)
            text = json.dumps(row)
            self.assertNotIn("secret", text)
            self.assertNotIn(str(root), text)
            return row

    def test_returned_case_keeps_wire_parity_and_cleanup_observations(self):
        row = self.case()
        self.assertEqual(row["result"], "returned")
        self.assertEqual(row["returncode"], 0)
        self.assertTrue(row["stdout_json_object"])
        self.assertTrue(row["artifact_parity_unchanged"])
        self.assertTrue(row["no_bytecode"])

    def test_private_environment_directories_exist_before_spawn(self):
        row = self.case(private_environment=True)
        self.assertTrue(row["os_home_present_before_spawn"])
        self.assertFalse(row["configured"])
        self.assertEqual(row["timeout_seconds"], 30)

    def test_timeout_with_exited_leader_is_not_called_a_live_process(self):
        row = self.case(timed_out=True)
        self.assertEqual(row["result"], "timeout")
        self.assertEqual(row["before_cleanup"], {"leader_returncode": 0, "active_processes": 1})
        self.assertTrue(row["stdout_json_object"])
        self.assertEqual(row["timeout_seconds"], 30)

    def test_unconfirmed_job_cleanup_retains_fixture(self):
        row = self.case(cleanup=False)
        self.assertFalse(row["cleanup"]["owned_tree_no_running_members"])
        self.assertEqual(row["fixture_cleanup"], "retained")


if __name__ == "__main__":
    unittest.main()
