"""Maintenance must report failed progress persistence, including after commits."""
import contextlib
import io
import json
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cg0170_retention_restored import RetentionFixtureBase, cg  # noqa: E402


class DiscoveryWriteErrorTests(RetentionFixtureBase):
    def prepare(self):
        old = self.make_session("progress-write-error", ended_days_ago=45)
        self.enable_policy()
        return old

    def test_intent_write_failure_keeps_ledger_and_recovers_after_io_repair(self):
        old = self.prepare()
        before = (old / "state.json").read_bytes()
        real_write = cg.atomic_write_text

        def fail_progress(path, text, *args, **kwargs):
            if path == cg._discovery_state_path(self.data_dir):
                raise OSError("synthetic progress write failure")
            return real_write(path, text, *args, **kwargs)

        with mock.patch.object(cg, "atomic_write_text", side_effect=fail_progress):
            with self.assertRaisesRegex(RuntimeError, "discovery progress write failed"):
                cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual((old / "state.json").read_bytes(), before)
        report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(report["counts"]["quarantined"], 1)
        self.assertFalse(old.exists())

    def test_cli_returns_failure_instead_of_successful_backlog(self):
        old = self.prepare()
        out, err = io.StringIO(), io.StringIO()
        argv = ["context_guard.py", "cleanup", "--data-dir", str(self.data_dir),
                "--apply", "--json"]
        with mock.patch.object(cg, "_discovery_write_state", return_value=False), \
                mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cg.main()
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("discovery progress write failed", err.getvalue())
        self.assertTrue((old / "state.json").is_file())

    def test_failure_after_snapshot_commit_does_not_claim_completed_attempt(self):
        old = self.prepare()
        real_write = cg._discovery_write_state
        writes = []

        def fail_attempt_commit(root, state):
            writes.append(state["attempt_open"])
            return real_write(root, state) if len(writes) == 1 else False

        with mock.patch.object(cg, "_discovery_write_state", side_effect=fail_attempt_commit):
            with self.assertRaisesRegex(RuntimeError, "discovery progress write failed"):
                cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(len(writes), 2)
        self.assertIsNotNone(writes[0])
        self.assertIsNone(writes[1])
        self.assertTrue(old.exists())
        self.assertEqual(cg.cleanup_old_sessions(self.data_dir, apply=True)["counts"]["quarantined"], 1)

    def test_final_cursor_write_failure_preserves_completed_quarantine(self):
        old = self.prepare()
        before = (old / "state.json").read_bytes()
        real_write = cg._discovery_write_state
        writes = []

        def fail_finish(root, state):
            writes.append(state["attempt_open"])
            return real_write(root, state) if len(writes) < 3 else False

        with mock.patch.object(cg, "_discovery_write_state", side_effect=fail_finish):
            with self.assertRaisesRegex(RuntimeError, "discovery progress write failed"):
                cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(len(writes), 3)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record = json.loads(next(qdir.glob("*.record.json")).read_text())
        self.assertEqual(record["state"], "quarantined")
        self.assertEqual((qdir / record["quarantine_object"] / "state.json").read_bytes(), before)
        self.assertEqual(cg.retention_restore(self.data_dir, old.name)["outcome"], "restored")
        self.assertEqual((old / "state.json").read_bytes(), before)
