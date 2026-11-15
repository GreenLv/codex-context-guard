"""Synthetic tests only: no real state, Git, child process, CLI or model."""

import copy
import hashlib
import importlib.util
import os
import py_compile
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.test_native_postclose_relation import raw, sealed
from tools.validation import postclose_transition as transition
from tools.validation import state_relation as relation
from tools.validation import supplement_post_close as supplement


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.live = self.root / "sessions-v2/thread_1/state.json"
        self.live.parent.mkdir(parents=True)
        self.pre = self.root / "pre.json"
        self.before = sealed(
            {
                "session": {
                    "id": "thread_1",
                    "ended_at": None,
                    "updated_at": "2020-01-01T00:00:00Z",
                },
                "scope": ["keep"],
                "pending": [1],
            }
        )
        self.after = copy.deepcopy(self.before)
        self.after["session"]["ended_at"] = "2020-01-01T00:00:01Z"
        self.after["session"]["updated_at"] = "2020-01-01T00:00:02Z"
        self.after = sealed(self.after)
        self.pre.write_bytes(raw(self.before))
        self.live.write_bytes(raw(self.after))
        self.scope_calls = []

        def check(value, message):
            if not value:
                raise ValueError(message)

        def scope(runtime, path, home):
            self.scope_calls.append((runtime, path, home))
            return {"scope": "validated"}

        self.e = SimpleNamespace(
            regular=lambda path: path,
            safe_bytes=lambda path, limit: path.read_bytes(),
            require=check,
            project=lambda ctx, snap: {
                "root": snap["root"],
                "sha256": snap["sha256"],
                "scope": snap["scope"],
            },
        )
        self.ctx = {
            "old_root": self.root,
            "new_root": self.root,
            "home": self.root,
            "u": SimpleNamespace(_old_scope=scope),
        }
        self.recorded = {
            "root": str(self.root),
            "sha256": hashlib.sha256(self.pre.read_bytes()).hexdigest(),
            "scope": {"scope": "validated"},
        }

    def current(self, state=None):
        return {
            "root": str(self.root),
            "sha256": hashlib.sha256(self.live.read_bytes()).hexdigest(),
            "state": self.after if state is None else state,
        }

    def call(self, current=None):
        return transition.check_post_close(
            self.e,
            self.ctx,
            self.recorded,
            self.current() if current is None else current,
            "thread_1",
            self.pre,
        )

    def test_metadata_and_exact_relation(self):
        self.assertEqual(self.call()["relation"], "session_end_metadata_consistent")
        self.assertEqual(len(self.scope_calls), 1)
        self.live.write_bytes(self.pre.read_bytes())
        self.assertEqual(
            self.call(self.current(self.before))["relation"], "exact_raw_match"
        )

    def test_changed_preimage_scope_and_current_are_refused(self):
        self.pre.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.call()
        self.pre.write_bytes(raw(self.before))
        self.ctx["u"]._old_scope = lambda *_: {"scope": "untrusted"}
        with self.assertRaises(ValueError):
            self.call()
        self.ctx["u"]._old_scope = lambda *_: {"scope": "validated"}
        self.live.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.call(self.current(self.after))

    def test_ambiguous_or_changed_business_state_refused(self):
        alternate = self.root / "sessions/thread_1/state.json"
        alternate.parent.mkdir(parents=True)
        alternate.write_bytes(self.live.read_bytes())
        with self.assertRaises(ValueError):
            self.call()
        alternate.unlink()
        changed = copy.deepcopy(self.after)
        changed["pending"].append(2)
        changed = sealed(changed)
        self.live.write_bytes(raw(changed))
        with self.assertRaises(relation.Refused):
            self.call(self.current(changed))


class ReaderTests(unittest.TestCase):
    def test_safe_read_nested_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t).resolve()
            nested = root / "maintained/prepare.json"
            nested.parent.mkdir()
            nested.write_bytes(b"{}")
            self.assertEqual(supplement.safe_bytes(nested), b"{}")
            link = root / "link"
            link.symlink_to(nested)
            with self.assertRaises(supplement.Refused):
                supplement.safe_bytes(link)

    def test_evidence_nested_passes_and_traversal_or_drift_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t).resolve()
            path = root / "maintained/prepare.json"
            path.parent.mkdir()
            path.write_bytes(b"{}")
            digest = hashlib.sha256(b"{}").hexdigest()
            supplement.verify_evidence_readback(
                root, {"maintained/prepare.json": digest}
            )
            for evidence in (
                {"../outside": digest},
                {str(path): digest},
                {"maintained/prepare.json": "0" * 64},
            ):
                with (
                    self.subTest(evidence=evidence),
                    self.assertRaises(supplement.Refused),
                ):
                    supplement.verify_evidence_readback(root, evidence)

    def test_receipt_protects_both_artifact_trees_and_input_directories(self):
        args = SimpleNamespace(
            preimage="/pre/evidence",
            plan="/plans/native",
            reader_manifest="/reader/manifest",
        )
        ctx = {
            "repo": Path("/repo"),
            "home": Path("/home"),
            "artifact": Path("/artifact"),
            "normalized_plan": {"old_artifact_dir": "/oldartifact"},
        }
        protected = supplement.protected_inputs(
            args,
            ctx,
            {"zip": "/zip1/a.zip", "old_zip": "/zip2/b.zip"},
            Path("/original"),
        )
        for expected in (
            "/repo",
            "/home",
            "/artifact",
            "/oldartifact",
            "/zip1",
            "/zip2",
            "/pre",
            "/plans",
            "/reader",
            "/original",
        ):
            self.assertIn(Path(expected), protected)

    def test_duplicate_json_and_nonfinite_rejected(self):
        for raw_json in (b'{"a":1,"a":2}', b'{"a":NaN}', b"\xff"):
            with self.subTest(raw=raw_json), self.assertRaises(supplement.Refused):
                supplement.strict(raw_json)

    def test_run_preflight_cannot_verify_or_write(self):
        ctx = (None,) * 8
        with (
            mock.patch.object(supplement, "prepare", return_value=ctx),
            mock.patch.object(supplement.shared_verify, "verify_core") as verify,
        ):
            result = supplement.run(SimpleNamespace(preflight=True))
        self.assertEqual(result["status"], "preflight_read_only_only")
        verify.assert_not_called()

    def test_existing_unchecked_bytecode_is_not_imported(self):
        with tempfile.TemporaryDirectory() as t:
            source = Path(t).resolve() / "synthetic_module.py"
            source.write_text("value = 'old'\n")
            with mock.patch.object(sys, "pycache_prefix", None):
                py_compile.compile(str(source), doraise=True)
            old = source.stat()
            source.write_text("value = 'new'\n")
            os.utime(source, ns=(old.st_atime_ns, old.st_mtime_ns))
            with (
                mock.patch.object(sys, "pycache_prefix", sys.pycache_prefix),
                mock.patch.object(sys, "dont_write_bytecode", sys.dont_write_bytecode),
            ):
                supplement.isolate_bytecode()
                spec = importlib.util.spec_from_file_location(
                    "synthetic_module", source
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.assertEqual(module.value, "new")
                self.assertFalse(Path(sys.pycache_prefix).exists())

    def test_original_git_binding_precedes_use_and_rejects_dirty_or_changed(self):
        calls = []

        def git(repo, *args):
            calls.append(args)
            if args[0] == "rev-parse":
                return b"a" * 40 + b"\n"
            if args[0] == "status":
                return b""
            return b"tracked"

        with (
            mock.patch.object(supplement, "readonly_git", side_effect=git),
            mock.patch.object(
                supplement, "source_digest_map", return_value={"scripts/a.py": "1"}
            ),
        ):
            supplement.verify_original_checkout(
                Path("/fake/repo"), "a" * 40, {"scripts/a.py": "1"}
            )
        self.assertEqual(
            [call[0] for call in calls], ["rev-parse", "status", "ls-files"]
        )
        self.assertIn("scripts/a.py", calls[-1])
        self.assertIn("tools/validation/hook_failure_diagnostics.py", calls[-1])
        for bad in (b"b" * 40 + b"\n", b"dirty"):

            def invalid(repo, *args, value=bad):
                if args[0] == "rev-parse":
                    return value if value.endswith(b"\n") else b"a" * 40 + b"\n"
                return value

            with (
                mock.patch.object(supplement, "readonly_git", side_effect=invalid),
                self.assertRaises(supplement.Refused),
            ):
                supplement.verify_original_checkout(Path("/fake/repo"), "a" * 40, {})
        with self.assertRaises(supplement.Refused):
            supplement.verify_original_checkout(Path("/fake/.ssh/repo"), "a" * 40, {})

    def test_final_live_drift_cannot_create_receipt(self):
        digest = hashlib.sha256(b"bound").hexdigest()
        args = SimpleNamespace(
            preflight=False,
            output=Path("/fake/out"),
            preimage=Path("/fake/pre"),
            plan=Path("/fake/plan"),
            receipt=Path("/fake/receipt"),
            result_sha256=digest,
            sidecar_sha256=digest,
        )
        module = SimpleNamespace(
            snapshot=mock.Mock(return_value={"root": "/root", "sha256": "bad"}),
            write=mock.Mock(),
        )
        ctx = {"repo": Path("/fake/repo"), "helpers": {}}
        plan = {"_native_plan_sha256": digest}
        result = {"gates": {"old_model": {"thread": "old"}}, "evidence": {}}
        ready = (
            {"files": {}},
            module,
            ctx,
            plan,
            result,
            {"status": "failed"},
            {"root": "/root"},
            digest,
        )
        with (
            mock.patch.object(supplement, "prepare", return_value=ready),
            mock.patch.object(
                supplement.shared_verify,
                "verify_core",
                return_value={"current_sha256": "expected"},
            ),
            mock.patch.object(supplement, "safe_bytes", return_value=b"bound"),
            mock.patch.object(supplement, "source_digest_map", return_value={}),
            self.assertRaises(supplement.Refused),
        ):
            supplement.run(args)
        module.snapshot.assert_called_once_with(ctx, "old")
        module.write.assert_not_called()

    def test_safe_bytes_detects_changed_path_metadata(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t).resolve() / "f"
            p.write_bytes(b"hello")
            with (
                mock.patch.object(
                    supplement.os, "fstat", side_effect=OSError("changed")
                ),
                self.assertRaises(OSError),
            ):
                supplement.safe_bytes(p)


if __name__ == "__main__":
    unittest.main()
