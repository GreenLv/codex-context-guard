"""Offline collection controls; no Windows, Hook or network execution."""
import importlib.util
import json
import shutil
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
    SPEC = importlib.util.spec_from_file_location("published_comparison", DIRECTORY / "published_baseline_ci_diagnostic.py")
    d = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(d)
finally:
    sys.path.pop(0)


class BaselineControls(unittest.TestCase):
    def test_manifest_pins_public_tag_and_candidate_and_rejects_drift(self):
        descriptors = d.manifest_bytes(DIRECTORY / "published_baseline_manifests.json")
        self.assertEqual(tuple(descriptors[k]["commit"] for k in d.ORDER), d.COMMITS)
        self.assertEqual(len(descriptors[d.ORDER[0]]["files"]), 43)
        self.assertEqual(len(descriptors[d.ORDER[1]]["files"]), 45)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest"
            path.write_bytes(b"{}")
            with self.assertRaises(ValueError):
                d.manifest_bytes(path)

    def test_git_batch_verifies_exact_bytes_and_source_head(self):
        raw = b"line1\nline2\n"
        descriptor = {"commit": d.COMMITS[0], "files": {"scripts/file": d.common.sha(raw)}}
        batch = b"a" * 40 + b" blob " + str(len(raw)).encode() + b"\n" + raw + b"\n"
        with mock.patch.object(d.subprocess, "run", side_effect=[
                types.SimpleNamespace(stdout=d.COMMITS[0] + "\n"), types.SimpleNamespace(stdout=batch)]):
            self.assertEqual(d.git_blobs(Path("private"), descriptor), {"scripts/file": raw})
        with mock.patch.object(d.subprocess, "run", return_value=types.SimpleNamespace(stdout="wrong\n")):
            with self.assertRaises(ValueError):
                d.git_blobs(Path("private"), descriptor)
        changed = batch.replace(b"line1\n", b"line1\r\n")
        with mock.patch.object(d.subprocess, "run", side_effect=[
                types.SimpleNamespace(stdout=d.COMMITS[0]), types.SimpleNamespace(stdout=changed)]):
            with self.assertRaises(ValueError):
                d.git_blobs(Path("private"), descriptor)

    def observe(self, outer, files, *, cleanup=True, timeout=False):
        env = {"PATH": "synthetic;.;path", "HOME": str(outer / "os-home")}
        payload = b'{"hook_event_name":"UserPromptSubmit","prompt":"hello"}'
        class Process:
            returncode = 0
            calls = 0
            def communicate(self, value=None, timeout=None):
                self.calls += 1
                if self.calls == 1:
                    if timeout != 30 or value != payload:
                        raise AssertionError("changed input")
                    cache = outer / "installed/scripts/__pycache__"
                    cache.mkdir()
                    (cache / "synthetic.pyc").write_bytes(b"synthetic")
                    if self.timed_out:
                        raise subprocess.TimeoutExpired("secret-path", 30, stderr=b"secret-content")
                return b"{}", b""
        process = Process()
        process.timed_out = timeout
        owner = types.SimpleNamespace(process=process, close=mock.Mock(return_value={
            "cleanup_complete": cleanup, "owned_process_exited": True,
            "owned_tree_no_running_members": cleanup}))
        owned = mock.Mock()
        owned.spawn.return_value = owner
        with mock.patch.object(d.common, "tree_observation", return_value={"active_processes": 1}):
            row = d.observe(outer, files, env, payload, "inert-powershell", owned, outer.parent / "candidate-checkout")
        self.assertEqual(owned.spawn.call_args.kwargs["cwd"], outer.parent / "candidate-checkout")
        self.assertEqual(owned.spawn.call_args.kwargs["env"], env)
        owner.close.assert_called_once_with(timeout=5)
        self.assertNotIn("secret", json.dumps(row))
        self.assertNotIn(str(outer), json.dumps(row))
        return row

    def test_same_synthetic_paths_reset_only_after_owned_cleanup_and_preserve_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary) / "fixture"
            outer.mkdir()
            for index, raw in enumerate((b"released", b"candidate")):
                row = self.observe(outer, {d.LAUNCHER: raw})
                self.assertTrue(d.safe_to_reset(row))
                self.assertTrue(row["original_runtime_files_unchanged"])
                self.assertEqual(row["bytecode_file_count"], 1)  # Never a failure gate.
                saved = Path(temporary) / (str(index) + ".json")
                d.write_new(saved, row)
                shutil.rmtree(outer)
                outer.mkdir()
                self.assertFalse((outer / "installed").exists())
            self.assertEqual(len(list(Path(temporary).glob("*.json"))), 2)

    def test_timeout_observation_is_kept_and_unknown_cleanup_disallows_reset(self):
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary)
            row = self.observe(outer, {d.LAUNCHER: b"synthetic"}, timeout=True, cleanup=False)
            self.assertEqual(row["result"], "timeout")
            self.assertFalse(d.safe_to_reset(row))
            self.assertTrue((outer / "installed").is_dir())

    def test_outputs_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "result.json"
            d.write_new(path, {"first": True})
            with self.assertRaises(FileExistsError):
                d.write_new(path, {"second": True})
            self.assertEqual(json.loads(path.read_text()), {"first": True})


if __name__ == "__main__":
    unittest.main()
