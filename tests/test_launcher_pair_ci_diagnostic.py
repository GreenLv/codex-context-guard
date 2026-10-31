"""Local synthetic controls: no Windows, PowerShell, Hook or network execution."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pair_diagnostic", ROOT / "tools/validation/launcher_pair_ci_diagnostic.py")
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)


class PairControls(unittest.TestCase):
    def test_original_environment_is_small_has_dot_and_no_trace_or_credentials(self):
        with mock.patch.dict(os.environ, {"SYSTEMROOT": "synthetic-system", "OPENAI_API_KEY": "secret"}, clear=True), mock.patch.object(os, "defpath", ".;/synthetic/bin"), mock.patch.object(os, "pathsep", ";"):
            env = d.environment_for(Path("/synthetic/fixture"), "/synthetic/python/python.exe")
        self.assertEqual(env["PATH"], "/synthetic/python;.;/synthetic/bin")
        self.assertEqual(set(env), {"PATH", "HOME", "USERPROFILE", "CODEX_HOME", "PLUGIN_DATA", "TMPDIR", "SYSTEMROOT"})
        self.assertNotIn("secret", json.dumps(env))

    def test_bound_candidate_bytes_and_tampering_fail_before_execution(self):
        path = ROOT / "tools/validation/candidate-launcher.ps1"
        raw = d.candidate_bytes(path)
        self.assertEqual(d.sha(raw), d.CANDIDATE_SHA256)
        with tempfile.TemporaryDirectory() as temporary:
            altered = Path(temporary) / "candidate.ps1"
            altered.write_bytes(raw + b"\n")
            with self.assertRaises(ValueError):
                d.candidate_bytes(altered)

    def test_variant_verifier_rejects_changed_other_file_extra_file_and_missing_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "core.py"
            target.write_bytes(b"synthetic")
            expected = {"core.py": d.sha(b"synthetic")}
            d.verify_variant(root, expected)
            target.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                d.verify_variant(root, expected)
            target.write_bytes(b"synthetic")
            extra = root / "extra"
            extra.write_bytes(b"unexpected")
            with self.assertRaises(ValueError):
                d.verify_variant(root, expected)
            extra.unlink()
            target.unlink()
            with self.assertRaises(ValueError):
                d.verify_variant(root, expected)

    def case(self, variant="original", timeout=False, cleanup=True, corrupt=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subject = root / "subject"
            (subject / "scripts").mkdir(parents=True)
            original, candidate = b"# inert original\n", b"# inert candidate\n"
            (subject / d.LAUNCHER).write_bytes(original)
            (subject / "scripts/core.py").write_bytes(b"inert core\n")
            files = {p.relative_to(subject).as_posix(): d.sha(p.read_bytes()) for p in subject.rglob("*") if p.is_file()}
            outer = root / "fixture"
            outer.mkdir()
            class Accounting(ctypes.Structure):
                _fields_ = [("ActiveProcesses", ctypes.c_ulong)]
            class Process:
                returncode = 0
                calls = 0
                def poll(self):
                    return 0
                def communicate(process, input=None, timeout=None):
                    process.calls += 1
                    if process.calls == 1:
                        self.assertEqual(timeout, 30)
                        payload = json.loads(input)
                        self.assertEqual(payload, {"hook_event_name": "UserPromptSubmit", "session_id": "synthetic-bytecode", "cwd": str(outer / "project"), "prompt": "hello", "trigger": "manual", "last_assistant_message": "waiting"})
                        if corrupt:
                            (outer / "installed/scripts/core.py").write_bytes(b"changed")
                        if timed_out:
                            raise subprocess.TimeoutExpired("secret-command-path", 30, output=b"{}", stderr=b"secret-content")
                    return b"{}", b""
            timed_out = timeout
            def query(job, number, pointer, size, unused):
                pointer._obj.ActiveProcesses = 1 if timed_out else 0
                return True
            owner = types.SimpleNamespace(process=Process(), job=1, accounting_type=Accounting,
                api=types.SimpleNamespace(QueryInformationJobObject=query),
                close=mock.Mock(return_value={"cleanup_complete": cleanup, "owned_process_exited": True, "owned_tree_no_running_members": cleanup}))
            def spawn(command, **kwargs):
                self.assertEqual(command, ["synthetic-powershell", "-NoProfile", "-NonInteractive", "-File", str(outer / "installed" / d.LAUNCHER), "hook"])
                self.assertFalse((outer / "os-home").exists())
                self.assertFalse((outer / "home/context-guard/interpreter.conf").exists())
                self.assertEqual((outer / "installed" / d.LAUNCHER).read_bytes(), candidate if variant == "candidate" else original)
                self.assertEqual(kwargs["cwd"], subject)
                self.assertNotIn("CONTEXT_GUARD_HOOK_TRACE_DIR", kwargs["env"])
                return owner
            owned = types.SimpleNamespace(spawn=mock.Mock(side_effect=spawn))
            identity = types.SimpleNamespace(distribution_manifest=lambda root: files,
                compare_artifact=lambda root, installed: d.verify_variant(installed, files))
            with mock.patch.object(d, "ORIGINAL_SHA256", d.sha(original)), mock.patch.object(d, "CANDIDATE_SHA256", d.sha(candidate)), mock.patch.object(os, "defpath", "." + os.pathsep + "/synthetic/bin"):
                row = d.run_case(subject, outer, variant, "synthetic-powershell", identity, owned, candidate)
            owner.close.assert_called_once_with(timeout=5)
            self.assertEqual(outer.exists(), not cleanup)
            self.assertNotIn("secret", json.dumps(row))
            self.assertNotIn(str(root), json.dumps(row))
            return row

    def test_original_and_candidate_share_input_environment_and_exact_other_bytes(self):
        for variant in ("original", "candidate"):
            row = self.case(variant)
            self.assertEqual(row["result"], "returned")
            self.assertTrue(row["hook_returned_zero_json_object"])
            self.assertTrue(row["controlled_variant_bytes_unchanged"])
            self.assertTrue(row["other_distribution_bytes_match_subject"])
            self.assertEqual(row["fixture_cleanup"], "removed")

    def test_timeout_retains_failure_and_observes_exited_leader_with_live_members(self):
        row = self.case(timeout=True)
        self.assertEqual(row["result"], "timeout")
        self.assertFalse(row["hook_returned_zero_json_object"])
        self.assertEqual(row["before_cleanup"], {"leader_returncode": 0, "active_processes": 1})

    def test_unconfirmed_cleanup_retains_fixture(self):
        row = self.case(cleanup=False)
        self.assertEqual(row["fixture_cleanup"], "retained")
        self.assertFalse(row["cleanup"]["owned_tree_no_running_members"])

    def test_changed_nonlauncher_bytes_are_detected(self):
        row = self.case("candidate", corrupt=True)
        self.assertFalse(row["controlled_variant_bytes_unchanged"])
        self.assertFalse(row["other_distribution_bytes_match_subject"])


if __name__ == "__main__":
    unittest.main()
