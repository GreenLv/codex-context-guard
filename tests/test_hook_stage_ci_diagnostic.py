"""Offline controls; native parser check explicitly requires Windows PS5.1."""
import ctypes
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "tools/validation"
sys.path.insert(0, str(DIRECTORY))
try:
    SPEC = importlib.util.spec_from_file_location("hook_stage_diagnostic", DIRECTORY / "hook_stage_ci_diagnostic.py")
    d = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(d)
finally:
    sys.path.pop(0)
ORIGINAL = (ROOT / d.LAUNCHER).read_bytes()


class StageControls(unittest.TestCase):
    def test_insertion_preserves_every_original_line_in_order(self):
        text = d.instrument(ORIGINAL).decode()
        lines = iter(text.splitlines())
        for original in ORIGINAL.decode().splitlines():
            self.assertTrue(any(line == original for line in lines), original)
        self.assertTrue(text.startswith("try {\n    [System.IO.File]::AppendAllText"))
        self.assertNotIn("New-Object", d.PRELUDE)
        for phase in d.PHASES - {"script_entry"}:
            self.assertEqual(text.count("Write-CgDiagnosticStage '" + phase + "'"), 1)
        self.assertEqual(hashlib.sha256(ORIGINAL).hexdigest(), d.LAUNCHER_SHA)

    def test_drift_and_ambiguous_anchors_are_refused(self):
        with self.assertRaises(ValueError):
            d.instrument(ORIGINAL + b"# drift\n")
        changed = ORIGINAL + b"\n$candidates = @(\n"
        with mock.patch.object(d, "LAUNCHER_SHA", hashlib.sha256(changed).hexdigest()):
            with self.assertRaises(ValueError):
                d.instrument(changed)

    def test_stage_reader_redacts_invalid_unbounded_and_partial_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "stages"
            self.assertEqual(d.stages(path), {"state": "absent", "records": []})
            valid = {"phase": "script_entry", "candidate": -1, "elapsed_ms": 0, "value": 0}
            path.write_text(json.dumps(valid) + "\n", encoding="utf-8")
            self.assertEqual(d.stages(path)["records"], [valid])
            for content in (json.dumps(dict(valid, private="secret-path")),
                            json.dumps(dict(valid, candidate=True)),
                            json.dumps(dict(valid, phase="secret-path")),
                            '{"private":"secret-path"', "secret-path" * 2000):
                path.write_text(content, encoding="utf-8")
                self.assertEqual(d.stages(path), {"state": "unavailable"})
                self.assertNotIn("secret", json.dumps(d.stages(path)))

    def observe(self, *, trace=True, timeout=False, entry=True, cleanup=True):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subject = root / "subject"
            (subject / "scripts").mkdir(parents=True)
            (subject / d.LAUNCHER).write_bytes(ORIGINAL)
            outer = root / "fixture"
            outer.mkdir()
            class Accounting(ctypes.Structure):
                _fields_ = [("ActiveProcesses", ctypes.c_ulong)]
            class Process:
                returncode = None if timeout else 0
                calls = 0
                def poll(self):
                    return self.returncode
                def communicate(self, input=None, timeout=None):
                    self.calls += 1
                    if self.calls == 1:
                        self.payload = json.loads(input)
                        self.limit = timeout
                        if timeout == 30 and self.returncode is None:
                            raise subprocess.TimeoutExpired("secret-path", timeout, stderr=b"secret-content")
                    return b"{}", b""
            def query(job, number, pointer, size, unused):
                pointer._obj.ActiveProcesses = 1 if timeout else 0
                return True
            owner = types.SimpleNamespace(process=Process(), job=1, accounting_type=Accounting,
                api=types.SimpleNamespace(QueryInformationJobObject=query),
                close=mock.Mock(return_value={"cleanup_complete": cleanup,
                    "owned_process_exited": True, "owned_tree_no_running_members": cleanup}))
            owned = mock.Mock()
            def spawn(command, **kwargs):
                environment = kwargs["env"]
                expected = d.base.environment_for(outer, "trace_only", sys.executable)
                if not trace:
                    expected.pop("CONTEXT_GUARD_HOOK_TRACE_DIR")
                expected["CG_DIAGNOSTIC_STAGE_FILE"] = str(outer / "stages.jsonl")
                self.assertEqual(environment, expected)
                self.assertFalse((outer / "os-home").exists())
                if entry:
                    (outer / "stages.jsonl").write_text(
                        '{"phase":"script_entry","candidate":-1,"elapsed_ms":0,"value":0}\n', encoding="utf-8")
                return owner
            owned.spawn.side_effect = spawn
            identity = types.SimpleNamespace(distribution_manifest=lambda p: {d.LAUNCHER: "unused"},
                                             compare_artifact=lambda *args: None)
            result = d.observe(subject, outer, trace, "inert-powershell", identity, owned)
            self.assertEqual(owner.process.limit, 30)
            self.assertEqual(owner.process.payload["hook_event_name"], "UserPromptSubmit")
            owner.close.assert_called_once_with(timeout=5)
            self.assertTrue(result["instrumented_artifact_matches_expected"])
            self.assertTrue(result["original_artifact_verified"])
            self.assertEqual(result["fixture_cleanup"], "removed" if cleanup else "retained")
            self.assertEqual(outer.exists(), not cleanup)
            self.assertNotIn(str(root), json.dumps(result))
            self.assertNotIn("secret", json.dumps(result))
            return result

    def test_trace_on_and_off_change_only_original_trace_environment(self):
        for trace in (True, False):
            row = self.observe(trace=trace)
            self.assertEqual(row["result"], "returned")
            self.assertTrue(row["stdout_json_object"])
            self.assertEqual(row["stages"]["records"][0]["phase"], "script_entry")

    def test_timeout_with_and_without_entry_is_observed_without_attribution(self):
        for entry in (True, False):
            row = self.observe(timeout=True, entry=entry)
            self.assertEqual(row["result"], "timeout")
            self.assertEqual(row["stages"]["state"], "observed" if entry else "absent")
            self.assertEqual(row["before_cleanup"], {"leader_returncode": None, "active_processes": 1})
            self.assertNotIn("inferred_phase", row)

    def test_unknown_cleanup_retains_fixture(self):
        row = self.observe(cleanup=False)
        self.assertFalse(row["cleanup"]["cleanup_complete"])

    @unittest.skipUnless(os.name == "nt" and shutil.which("powershell.exe"), "requires actual Windows PowerShell")
    def test_instrumented_copy_parses_in_native_powershell_51(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "instrumented.ps1"
            script.write_bytes(d.instrument(ORIGINAL))
            source = ("$t=$null; $e=$null; "
                      "[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$t,[ref]$e) > $null; "
                      "if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { exit 91 }; "
                      "if ($e.Count -ne 0) { exit 2 }")
            parser = Path(temporary) / "parse.ps1"
            parser.write_text(source, encoding="ascii")
            fixture = Path(temporary)
            for name in ("os-home", "tmp", "appdata", "localappdata", "module-cache"):
                (fixture / name).mkdir()
            environment = d.base.environment_for(fixture, "private_environment_trace", sys.executable)
            result = subprocess.run([shutil.which("powershell.exe"), "-NoProfile", "-NonInteractive",
                                     "-File", str(parser), str(script)], env=environment,
                                    cwd=fixture, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0)  # Do not echo parser diagnostics or paths.


if __name__ == "__main__":
    unittest.main()
