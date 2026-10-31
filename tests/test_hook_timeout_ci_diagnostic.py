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
    def test_environment_variants_change_only_declared_inputs(self):
        with mock.patch.object(os, "pathsep", ";"), mock.patch.object(os, "defpath", ".;C:\\bin"):
            cases = {name: d.environment_for(Path("C:/private"), name,
                     "C:/Python/python.exe") for name in d.CASES}
        original, traced = cases["original"], dict(cases["trace_only"])
        traced.pop("CONTEXT_GUARD_HOOK_TRACE_DIR")
        self.assertEqual(original, traced)
        self.assertEqual(cases["trace_only"], cases["configured_trace"])
        changed = dict(cases["path_without_dot_trace"])
        self.assertEqual(changed.pop("PATH"), "C:/Python;C:\\bin")
        expected = dict(cases["trace_only"])
        expected.pop("PATH")
        self.assertEqual(changed, expected)
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

    def case(self, *, timed_out=False, cleanup=True):
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
            owned.spawn.return_value = owner
            identity = types.SimpleNamespace(distribution_manifest=lambda root:
                {"scripts/run-context-guard.ps1": "synthetic"}, compare_artifact=lambda *args: None)
            row = d.run_case(subject, outer, "original", "inert-powershell", identity, owned)
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
