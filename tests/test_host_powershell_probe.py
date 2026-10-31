"""Small offline controls; no PowerShell, product or network execution."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

DIRECTORY = Path(__file__).resolve().parents[1] / "tools/validation"
sys.path.insert(0, str(DIRECTORY))
try:
    SPEC = importlib.util.spec_from_file_location("host_probe", DIRECTORY / "host_powershell_probe.py")
    d = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(d)
finally:
    sys.path.pop(0)


class HostProbeControls(unittest.TestCase):
    def test_three_fixed_scripts_have_no_prewarm_or_policy_bypass(self):
        self.assertEqual(len(d.CASES), 3)
        for case in d.CASES:
            source = d.script_for(case).decode("ascii")
            for forbidden in ("New-Object", "Get-Command", "Get-ExecutionPolicy", "-ExecutionPolicy", "cg_hook", "context_guard.py"):
                self.assertNotIn(forbidden, source)
            self.assertIn("[IO.File]::AppendAllText", source)
            self.assertIn("host_probe_completed", source)
        self.assertIn("Microsoft.PowerShell.Management\\Join-Path", d.script_for(d.CASES[1]).decode())
        self.assertIn("Microsoft.PowerShell.Core\\Import-Module", d.script_for(d.CASES[2]).decode())
        self.assertNotIn("Import-Module", d.script_for(d.CASES[0]).decode())

    def test_cwd_candidates_and_stage_unknown_fields_are_checked_without_echo(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(d.cwd_candidate_count(root, ".EXE;.CMD"), 0)
            (root / "Join-Path.exe").write_bytes(b"inert")
            self.assertEqual(d.cwd_candidate_count(root, ".EXE;.CMD"), 1)
            path = root / "stages"
            record = {"phase": "entry", "elapsed_ms": 0, "version": "5.1.1.1"}
            path.write_text(json.dumps(record), encoding="utf-8")
            self.assertEqual(d.phases(path)["records"], [record])
            path.write_text(json.dumps(dict(record, private="secret")), encoding="utf-8")
            with self.assertRaises(ValueError):
                d.phases(path)
            with self.assertRaises(ValueError):
                d.cwd_candidate_count(root, ".EXE;../secret")

    def run_probe(self, *, timeout=False, cleanup=True, bad_stage=False):
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary) / "fixture"
            outer.mkdir()
            payload = b'{"hook_event_name":"UserPromptSubmit","prompt":"hello"}'
            class Process:
                returncode = 0
                calls = 0
                def communicate(process, input=None, timeout=None):
                    process.calls += 1
                    if process.calls == 1:
                        self.assertEqual(input, payload)
                        self.assertEqual(timeout, 30)
                        if timed_out:
                            raise subprocess.TimeoutExpired("secret-path", 30, stderr=b"secret-content")
                    return b'{"host_probe_completed":true}', b""
            timed_out = timeout
            owner = types.SimpleNamespace(process=Process(), close=mock.Mock(return_value={
                "cleanup_complete": cleanup, "owned_process_exited": True,
                "owned_tree_no_running_members": cleanup}))
            def spawn(command, **kwargs):
                self.assertEqual(kwargs["cwd"], Path("fixed-subject"))
                self.assertEqual(command[1:4], ["-NoProfile", "-NonInteractive", "-File"])
                self.assertNotIn("PSModulePath", kwargs["env"])
                stage = Path(kwargs["env"]["CG_HOST_STAGE"])
                stage.write_text("secret" if bad_stage else
                    '{"phase":"entry","elapsed_ms":0,"version":"5.1.1.1"}', encoding="utf-8")
                return owner
            owned = types.SimpleNamespace(spawn=mock.Mock(side_effect=spawn))
            with mock.patch.object(d.common, "tree_observation", return_value={"active_processes": 1}):
                result = d.run_probe(Path("fixed-subject"), outer, d.CASES[0], "inert-shell", owned, payload)
            owner.close.assert_called_once_with(timeout=5)
            self.assertEqual(result["stdin_length"], len(payload))
            self.assertTrue(result["stdin_matches_original_fixture"])
            self.assertNotIn("secret", json.dumps(result))
            self.assertNotIn(str(outer), json.dumps(result))
            self.assertEqual(outer.exists(), not cleanup or bad_stage)
            return result

    def test_returned_and_timeout_results_preserve_input_and_owned_cleanup(self):
        self.assertTrue(self.run_probe()["fixed_completion_json"])
        self.assertEqual(self.run_probe(timeout=True)["result"], "timeout")

    def test_unknown_cleanup_or_stage_read_preserves_fixture(self):
        self.assertEqual(self.run_probe(cleanup=False)["fixture_cleanup"], "retained")
        self.assertEqual(self.run_probe(bad_stage=True)["stages"]["state"], "unavailable")


if __name__ == "__main__":
    unittest.main()
