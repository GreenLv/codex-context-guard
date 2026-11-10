"""0.17.2 default-automatic maintenance: policy resolution, the durable
opt-out, and the SessionEnd background trigger.

The trigger contract under test: after SessionEnd durably saves the
session, the hook fires at most one bounded, deduplicated, DETACHED
maintenance child per data root per minimum interval; every failure mode
degrades to a recorded skip reason; the hook itself never scans, deletes,
or writes a policy object. The detached child re-authorizes independently,
materializes the automatic default policy once, runs the ordinary bounded
apply pass, records a bounded outcome, and releases its claim in every
path. All spawn seams are patched here; the native no-model probe
(``tools/validation/retention_trigger_probe.py``) exercises the real seam
per platform.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import importlib.util  # noqa: E402

from test_cg0170_retention_restored import (  # noqa: E402
    RetentionFixtureBase,
)

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard_0172", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)

CLAIM = cg._RETENTION_TRIGGER_CLAIM_NAME
STATE = cg.RETENTION_TRIGGER_STATE_NAME
OPTOUT = cg.RETENTION_OPTOUT_NAME
POLICY = cg.RETENTION_POLICY_NAME


def locks_dir(root: Path) -> Path:
    return root / cg.V2_NAMESPACE / ".locks"


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False) + "\n", encoding="utf-8")


class TriggerDecisionTests(RetentionFixtureBase):
    """Hook-side trigger decisions; the spawn seam is always patched."""

    def trigger(self, *, remaining=2.5, spawn=None, env=None):
        """Run the SessionEnd trigger for this fixture root and return
        (dispatched argv list, trigger state after the attempt)."""
        dispatched = []

        def seam(argv):
            dispatched.append(list(argv))
            return True if spawn is None else spawn(argv)

        env_patch = {"CONTEXT_GUARD_DISABLE_RETENTION_TRIGGER": ""}
        env_patch.update(env or {})
        with mock.patch.dict(os.environ, env_patch, clear=False), \
                mock.patch.object(cg, "_retention_trigger_spawn", side_effect=seam):
            cg._retention_session_end_trigger(self.data_dir, remaining_budget=remaining)
        return dispatched, cg._retention_read_trigger_state(self.data_dir)

    def setUp(self):
        super().setUp()
        # A real journaled root: the trigger needs sessions-v2 to exist.
        self.make_session("anchor", ended_days_ago=None, finished=False)

    def test_default_policy_dispatches_one_detached_child(self):
        dispatched, state = self.trigger()
        self.assertEqual(len(dispatched), 1)
        argv = dispatched[0]
        # The ordinary maintenance executor, plus the trigger child flags.
        self.assertEqual(argv[1:8],
                         ["-B", str(MODULE_PATH), "cleanup",
                          "--data-dir", str(self.data_dir),
                          "--apply", "--json"])
        self.assertIn("--trigger-run", argv)
        self.assertIn("--budget-seconds", argv)
        self.assertTrue((locks_dir(self.data_dir) / CLAIM).exists())
        self.assertIsNotNone(state.get("last_dispatch_at"))
        self.assertIsNotNone(state.get("next_due_at"))

    def test_opt_out_record_skips_the_trigger(self):
        cg._retention_write_optout(self.data_dir, reason="user choice")
        dispatched, state = self.trigger()
        self.assertEqual(dispatched, [])
        self.assertEqual(state["last_skip"]["reason"], "opt_out")
        self.assertFalse((locks_dir(self.data_dir) / CLAIM).exists())

    def test_unverifiable_opt_out_record_still_skips(self):
        # Control state that cannot be trusted disables destructive
        # automatic maintenance instead of enabling it.
        write_json(locks_dir(self.data_dir) / OPTOUT, {"schema": "nope"})
        dispatched, state = self.trigger()
        self.assertEqual(dispatched, [])
        self.assertEqual(state["last_skip"]["reason"], "opt_out")
        self.assertEqual(state["last_skip"]["detail"], "unverifiable")

    def test_explicit_disabled_policy_skips_the_trigger(self):
        cg.write_retention_policy(self.data_dir, enabled=False)
        dispatched, state = self.trigger()
        self.assertEqual(dispatched, [])
        self.assertEqual(state["last_skip"]["reason"], "policy_disabled")

    def test_corrupted_policy_never_authorizes_a_trigger(self):
        for corruption in ("{broken", "[]", '{"schema": "other"}'):
            with self.subTest(corruption=corruption):
                (locks_dir(self.data_dir) / POLICY).write_text(
                    corruption, encoding="utf-8")
                dispatched, state = self.trigger()
                self.assertEqual(dispatched, [])
                self.assertEqual(state["last_skip"]["reason"], "policy_invalid")
                self.assertTrue(state["last_skip"]["detail"])
        # A hostile hand edit of one field also refuses.
        good = cg.write_retention_policy(self.data_dir, enabled=True)
        bad = {**good, "min_age_days": 0}
        (locks_dir(self.data_dir) / POLICY).write_text(
            json.dumps(bad), encoding="utf-8")
        dispatched, state = self.trigger()
        self.assertEqual(dispatched, [])
        self.assertEqual(state["last_skip"]["detail"], "field:min_age_days")

    def test_missing_namespace_skips_silently(self):
        root = self.root / "empty-guard-data"
        root.mkdir()
        dispatched = []
        with mock.patch.dict(os.environ,
                             {"CONTEXT_GUARD_DISABLE_RETENTION_TRIGGER": ""}), \
                mock.patch.object(cg, "_retention_trigger_spawn",
                                  side_effect=lambda argv: dispatched.append(argv) or True):
            cg._retention_session_end_trigger(root, remaining_budget=2.5)
        self.assertEqual(dispatched, [])
        self.assertEqual(cg._retention_read_trigger_state(root), {})
        # Nothing was created on the empty root, and the anchor session's
        # own root is untouched by this call.
        self.assertFalse((root / cg.V2_NAMESPACE / ".locks").exists())
        self.assertFalse((locks_dir(self.data_dir) / CLAIM).exists())

    def test_fresh_claim_blocks_and_stale_claim_recover(self):
        claim = locks_dir(self.data_dir) / CLAIM
        write_json(claim, {"schema": cg._RETENTION_TRIGGER_CLAIM_SCHEMA,
                           "pid": os.getpid(), "started_at": cg.utc_now()})
        dispatched, state = self.trigger()
        self.assertEqual(dispatched, [])
        self.assertEqual(state["last_skip"]["reason"], "claim_held")
        self.assertTrue(claim.exists())
        # A claim older than the TTL is stranded; the next trigger removes
        # it and dispatches.
        old = time.time() - (cg._RETENTION_TRIGGER_CLAIM_TTL_SECONDS + 60)
        os.utime(claim, (old, old))
        dispatched, _ = self.trigger()
        self.assertEqual(len(dispatched), 1)

    def test_minimum_interval_throttles_with_next_due(self):
        self.trigger()  # first dispatch records last_attempt_at
        # The real child would have completed and released its claim.
        cg._retention_release_trigger_claim(self.data_dir)
        dispatched, state = self.trigger()
        self.assertEqual(dispatched, [])
        self.assertEqual(state["last_skip"]["reason"], "throttled")
        self.assertIsNotNone(state.get("next_due_at"))

    def test_spawn_failure_releases_the_claim_and_records(self):
        dispatched, state = self.trigger(spawn=lambda argv: False)
        self.assertEqual(len(dispatched), 1)
        self.assertEqual(state["last_skip"]["reason"], "spawn_failed")
        self.assertFalse((locks_dir(self.data_dir) / CLAIM).exists())

    def test_concurrent_session_end_claims_are_deduplicated(self):
        # Two hooks that both saw the same stale claim must not both
        # dispatch. The O_EXCL create is the final arbiter: a hook whose
        # takeover succeeded but whose exclusive create lost the race
        # records claim_race and dispatches nothing.
        claim = locks_dir(self.data_dir) / CLAIM
        write_json(claim, {"schema": cg._RETENTION_TRIGGER_CLAIM_SCHEMA,
                           "pid": os.getpid(), "started_at": cg.utc_now()})
        old = time.time() - (cg._RETENTION_TRIGGER_CLAIM_TTL_SECONDS + 60)
        os.utime(claim, (old, old))
        # Another host process already replaced the claim between the
        # takeover and the exclusive create.
        with mock.patch.object(cg, "_retention_remove_stale_claim",
                               side_effect=lambda _path: True):
            dispatched, state = self.trigger()
        self.assertEqual(dispatched, [])
        self.assertEqual(state["last_skip"]["reason"], "claim_race")

    def test_lost_stale_claim_takeover_skips_instead_of_dispatching(self):
        claim = locks_dir(self.data_dir) / CLAIM
        write_json(claim, {"schema": cg._RETENTION_TRIGGER_CLAIM_SCHEMA,
                           "pid": os.getpid(), "started_at": cg.utc_now()})
        old = time.time() - (cg._RETENTION_TRIGGER_CLAIM_TTL_SECONDS + 60)
        os.utime(claim, (old, old))
        # Another hook holds the object lock: the takeover loses and the
        # hook skips rather than deleting the object blind.
        with mock.patch.object(cg, "_retention_remove_stale_claim",
                               side_effect=lambda _path: False):
            dispatched, state = self.trigger()
        self.assertEqual(dispatched, [])
        self.assertEqual(state["last_skip"]["reason"], "claim_held")

    def test_stale_claim_takeover_verifies_the_locked_identity(self):
        # The takeover unlinks only when the locked inode still matches the
        # path: a replacement object (fresh claim) is never removed blind.
        claim = locks_dir(self.data_dir) / CLAIM
        write_json(claim, {"schema": cg._RETENTION_TRIGGER_CLAIM_SCHEMA,
                           "pid": os.getpid(), "started_at": cg.utc_now()})
        old = time.time() - (cg._RETENTION_TRIGGER_CLAIM_TTL_SECONDS + 60)
        os.utime(claim, (old, old))
        with mock.patch.object(cg.os, "fstat",
                               side_effect=lambda _fd: mock.Mock(
                                   st_ino=999999, st_dev=1)):
            self.assertFalse(cg._retention_remove_stale_claim(claim))
        self.assertTrue(claim.exists())

    def test_trigger_failure_never_fails_session_end(self):
        def broken(argv):
            raise RuntimeError("synthetic spawn failure")

        with mock.patch.dict(os.environ,
                             {"CONTEXT_GUARD_DISABLE_RETENTION_TRIGGER": ""}), \
                mock.patch.object(cg, "_retention_trigger_spawn",
                                  side_effect=broken):
            self.assertEqual(
                cg.dispatch(self.payload("SessionEnd", "anchor")), {})
        state = cg._retention_read_trigger_state(self.data_dir)
        self.assertEqual(state["last_skip"]["reason"], "internal_error")
        # The session itself still ended cleanly.
        ended = json.loads(
            (self.session_dir("anchor") / "state.json").read_text(encoding="utf-8"))
        self.assertIsNotNone(ended["session"]["ended_at"])

    def test_unknown_or_exhausted_budget_gate_is_silent_and_first(self):
        # The budget gate runs before any read or bookkeeping write: an
        # unknown or exhausted anchor dispatches nothing and records
        # nothing, so an exhausted SessionEnd never pays for the trigger.
        for remaining in (None, 0.0, 0.05):
            with self.subTest(remaining=remaining):
                dispatched, state = self.trigger(remaining=remaining)
                self.assertEqual(dispatched, [])
                self.assertEqual(state, {})

    def test_kill_switch_env_skips_silently(self):
        dispatched, state = self.trigger(
            env={"CONTEXT_GUARD_DISABLE_RETENTION_TRIGGER": "1"})
        self.assertEqual(dispatched, [])
        self.assertEqual(state, {})


class TriggerChildPassTests(RetentionFixtureBase):
    """The detached child: independent authorization, default materialize,
    bounded apply pass, outcome record, claim release."""

    def run_child(self, budget=5.0):
        return cg._retention_trigger_child_pass(self.data_dir, budget_seconds=budget)

    def setUp(self):
        super().setUp()
        self.make_session("expired", ended_days_ago=45)
        self.make_session("young", ended_days_ago=2)
        claim = locks_dir(self.data_dir) / CLAIM
        write_json(claim, {"schema": cg._RETENTION_TRIGGER_CLAIM_SCHEMA,
                           "pid": os.getpid(), "started_at": cg.utc_now()})

    def claim_present(self) -> bool:
        return (locks_dir(self.data_dir) / CLAIM).exists()

    def test_child_materializes_default_policy_and_quarantines(self):
        self.assertEqual(self.run_child(), 0)
        policy = cg._retention_policy_path(self.data_dir)
        self.assertTrue(policy.exists())
        stored = json.loads(policy.read_text(encoding="utf-8"))
        self.assertEqual(stored["policy_source"], "default_auto")
        self.assertTrue(stored["enabled"])
        self.assertEqual(stored["policy_version"], 1)
        self.assertFalse(self.session_dir("expired").is_dir())
        self.assertTrue(self.session_dir("young").is_dir())
        qdir = cg._retention_quarantine_dir(self.data_dir)
        self.assertTrue(any(qdir.glob("*.record.json")))
        state = cg._retention_read_trigger_state(self.data_dir)
        self.assertIsNotNone(state.get("last_success_at"))
        self.assertEqual(state["last_outcome"]["counts"]["quarantined"], 1)
        self.assertNotIn("last_skip", state)
        self.assertFalse(self.claim_present())

    def test_child_respects_a_fresh_opt_out(self):
        cg._retention_write_optout(self.data_dir, reason="user")
        self.assertEqual(self.run_child(), 0)
        self.assertTrue(self.session_dir("expired").is_dir())
        self.assertFalse(cg._retention_policy_path(self.data_dir).exists())
        state = cg._retention_read_trigger_state(self.data_dir)
        self.assertEqual(state["last_skip"]["reason"], "child_opt_out")
        self.assertFalse(self.claim_present())

    def test_child_refuses_a_corrupted_policy(self):
        write_json(locks_dir(self.data_dir) / POLICY,
                   {"schema": cg.RETENTION_POLICY_SCHEMA, "enabled": True})
        self.assertEqual(self.run_child(), 0)
        self.assertTrue(self.session_dir("expired").is_dir())
        state = cg._retention_read_trigger_state(self.data_dir)
        self.assertEqual(state["last_skip"]["reason"], "child_policy_invalid")
        self.assertFalse(self.claim_present())

    def test_child_busy_maintenance_lock_defers_without_deleting(self):
        cg.write_retention_policy(self.data_dir, enabled=True)
        handle = open(locks_dir(self.data_dir) / "retention-maintenance.lock", "a+b")
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            self.assertEqual(self.run_child(budget=0.2), 0)
        finally:
            handle.close()
        self.assertTrue(self.session_dir("expired").is_dir())
        state = cg._retention_read_trigger_state(self.data_dir)
        self.assertEqual(state["last_skip"]["reason"], "child_pass_deferred")
        self.assertFalse(self.claim_present())

    def test_child_purges_after_quarantine_grace_and_leaves_tombstone(self):
        self.assertEqual(self.run_child(), 0)
        qdir = cg._retention_quarantine_dir(self.data_dir)
        record_path = next(qdir.glob("*.record.json"))
        record = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(record["state"], "quarantined")
        old = (cg.dt.datetime.now(cg.dt.timezone.utc)
               - cg.dt.timedelta(days=cg._RETENTION_POLICY_DEFAULTS["quarantine_days"] + 2)
               ).isoformat().replace("+00:00", "Z")
        record["quarantined_at"] = old
        write_json(record_path, record)
        self.assertEqual(self.run_child(), 0)
        self.assertFalse((qdir / record_path.name).exists())
        tombstones = list(qdir.glob("*.tombstone.json"))
        self.assertEqual(len(tombstones), 1)
        # The purged name is guarded against silent recreation.
        with self.assertRaises(cg.RetentionRecreationRefused):
            cg._retention_recreation_guard(self.session_dir("expired"))
        state = cg._retention_read_trigger_state(self.data_dir)
        self.assertGreaterEqual(
            (state["last_outcome"]["purge"] or {}).get("purged", 0), 1)

    def test_child_cli_wiring_runs_and_releases_claim(self):
        # The full command surface the detached spawn uses, in a real
        # subprocess: authorization, materialization, pass, claim release.
        self.assertEqual(
            subprocess.run(
                [sys.executable, "-B", str(MODULE_PATH), "cleanup",
                 "--data-dir", str(self.data_dir), "--apply", "--json",
                 "--budget-seconds", "10", "--trigger-run"],
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                text=True, capture_output=True, timeout=120).returncode, 0)
        self.assertTrue(cg._retention_policy_path(self.data_dir).exists())
        self.assertFalse(self.session_dir("expired").is_dir())
        self.assertFalse(self.claim_present())


class DisableUpgradePersistenceTests(RetentionFixtureBase):
    """关闭 — 普通使用 — 再次升级 仍然关闭：the durable opt-out survives
    ordinary use and later invocations, and enable clears it explicitly."""

    def setUp(self):
        super().setUp()
        self.make_session("anchor", ended_days_ago=None, finished=False)

    def dispatched(self):
        seen = []
        with mock.patch.dict(os.environ,
                             {"CONTEXT_GUARD_DISABLE_RETENTION_TRIGGER": ""}), \
                mock.patch.object(cg, "_retention_trigger_spawn",
                                  side_effect=lambda argv: seen.append(argv) or True):
            cg._retention_session_end_trigger(self.data_dir, remaining_budget=2.5)
        return seen

    def test_apply_refuses_under_a_durable_opt_out_even_with_lost_policy(self):
        # The opt-out is a revocation, not a hint: it blocks destructive
        # apply even when the policy object is lost and the default
        # resolution would otherwise authorize it (the scheduler-entry
        # hole).
        self.make_session("expired", ended_days_ago=45)
        cg._retention_write_optout(self.data_dir, reason="user")
        (locks_dir(self.data_dir) / POLICY).unlink(missing_ok=True)
        with self.assertRaisesRegex(RuntimeError, "opted out"):
            cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertTrue(self.session_dir("expired").is_dir())
        # Preview still works under an opt-out.
        report = cg.cleanup_old_sessions(self.data_dir)
        self.assertEqual(report["mode"], "preview")

    def test_default_policy_materialization_is_a_compare_and_set(self):
        # Fresh root: adoption writes the default policy once.
        self.assertTrue(cg._retention_materialize_default_policy(self.data_dir))
        stored = json.loads(
            (locks_dir(self.data_dir) / POLICY).read_text(encoding="utf-8"))
        self.assertEqual(stored["policy_source"], "default_auto")
        # An existing object is never overwritten by adoption.
        self.assertFalse(cg._retention_materialize_default_policy(self.data_dir))
        # A disable that landed before adoption always wins.
        cg._retention_write_optout(self.data_dir, reason="user")
        (locks_dir(self.data_dir) / POLICY).unlink()
        with self.assertRaisesRegex(RuntimeError, "opted out"):
            cg._retention_materialize_default_policy(self.data_dir)
        self.assertFalse((locks_dir(self.data_dir) / POLICY).exists())

    def test_maintenance_disable_writes_optout_without_a_scheduler(self):
        # A platform with no scheduler (or a failed/foreign removal) still
        # records the durable opt-out and the disabled policy first; the
        # scheduler result is reported separately.
        with mock.patch.object(cg, "_retention_schedule_platform",
                               return_value=None):
            code = self.run_policy_command("--maintenance-disable")
        self.assertEqual(code, 0)
        self.assertFalse(cg.read_retention_policy(self.data_dir)["enabled"])
        self.assertIsNotNone(cg._retention_read_optout(self.data_dir))
        self.assertEqual(self.dispatched(), [])

    def test_maintenance_enable_is_a_real_opt_back_in(self):
        cg._retention_write_optout(self.data_dir, reason="user")
        cg.write_retention_policy(self.data_dir, enabled=False)

        def adapter(argv):
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        facts = {"platform": "macos", "label": "context-guard-retention",
                 "file": "present", "owned": True, "current": True,
                 "loaded": True, "entry": "/tmp/fake.plist"}
        with mock.patch.multiple(
                cg, _retention_schedule_platform=lambda: "macos",
                _retention_scheduler_run=adapter), \
                mock.patch.object(cg, "_retention_macos_facts",
                                  return_value=dict(facts)):
            code = self.run_policy_command("--maintenance-enable")
        self.assertEqual(code, 0)
        self.assertTrue(cg.read_retention_policy(self.data_dir)["enabled"])
        self.assertIsNone(cg._retention_read_optout(self.data_dir))

    def test_failed_maintenance_enable_keeps_the_opt_out(self):
        cg._retention_write_optout(self.data_dir, reason="user")
        with mock.patch.object(cg, "_retention_schedule_platform",
                               return_value=None):
            code = self.run_policy_command("--maintenance-enable")
        self.assertEqual(code, 2)
        record = cg._retention_read_optout(self.data_dir)
        self.assertIsNotNone(record)
        self.assertEqual(record.get("reason"), "user")

    def test_steady_state_skips_do_not_rewrite_the_trigger_state(self):
        cg._retention_write_optout(self.data_dir, reason="user")
        path = locks_dir(self.data_dir) / STATE
        with mock.patch.dict(os.environ,
                             {"CONTEXT_GUARD_DISABLE_RETENTION_TRIGGER": ""}):
            cg._retention_session_end_trigger(self.data_dir, remaining_budget=2.5)
            first = path.read_bytes()
            self.assertIsNotNone(json.loads(first)["last_skip"])
            time.sleep(0.02)
            cg._retention_session_end_trigger(self.data_dir, remaining_budget=2.5)
        self.assertEqual(path.read_bytes(), first)

    def test_policy_disable_cli_writes_the_durable_opt_out(self):
        result = subprocess.run(
            [sys.executable, "-B", str(MODULE_PATH), "cleanup",
             "--data-dir", str(self.data_dir), "--policy", "disable"],
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(cg.read_retention_policy(self.data_dir)["enabled"])
        record = cg._retention_read_optout(self.data_dir)
        self.assertIsNotNone(record)
        self.assertEqual(record.get("reason"), "policy-disable")
        # Ordinary use and a "later upgrade" (a fresh trigger evaluation)
        # stay disabled; nothing dispatches.
        self.assertEqual(self.dispatched(), [])
        self.assertEqual(
            cg._retention_read_trigger_state(self.data_dir)["last_skip"]["reason"],
            "opt_out")
        self.assertIsNotNone(cg._retention_read_optout(self.data_dir))

    def test_maintenance_disable_cli_writes_optout_and_disabled_policy(self):
        # Scheduler seam: a macOS host where no managed entry exists, so
        # disable is "already_disabled" yet still writes the durable
        # opt-out covering the background trigger.
        def adapter(argv):
            return subprocess.CompletedProcess(argv, 1, b"", b"")
        with mock.patch.multiple(
                cg, _retention_schedule_platform=lambda: "macos",
                _retention_scheduler_run=adapter):
            code = self.run_policy_command("--maintenance-disable")
        self.assertEqual(code, 0)
        self.assertFalse(cg.read_retention_policy(self.data_dir)["enabled"])
        record = cg._retention_read_optout(self.data_dir)
        self.assertIsNotNone(record)
        self.assertEqual(record.get("reason"), "maintenance-disable")
        self.assertEqual(self.dispatched(), [])

    def run_policy_command(self, *flags):
        import argparse
        args = argparse.Namespace(
            data_dir=self.data_dir, json=False, apply=False,
            apply_manifest=None, save_manifest=None, restore=None,
            policy=flags[1] if flags[0] == "--policy" else None,
            min_age_days=None, quarantine_days=None, no_purge=False,
            budget_seconds=20.0, trigger_run=False,
            maintenance_enable=flags == ("--maintenance-enable",),
            maintenance_disable=flags == ("--maintenance-disable",),
            maintenance_status=False,
            maintenance_label="context-guard-retention")
        return cg.command_cleanup(args)

    def test_explicit_policy_enable_clears_a_trusted_opt_out(self):
        cg._retention_write_optout(self.data_dir, reason="old choice")
        cg.write_retention_policy(self.data_dir, enabled=False)
        self.assertEqual(self.run_policy_command("--policy", "enable"), 0)
        self.assertIsNone(cg._retention_read_optout(self.data_dir))
        self.assertTrue(cg.read_retention_policy(self.data_dir)["enabled"])

    def test_unverifiable_opt_out_refuses_reenable(self):
        write_json(locks_dir(self.data_dir) / OPTOUT, {"schema": "garbage"})
        cg.write_retention_policy(self.data_dir, enabled=False)
        self.assertEqual(self.run_policy_command("--policy", "enable"), 2)
        self.assertFalse(cg.read_retention_policy(self.data_dir)["enabled"])
        self.assertIsNotNone(cg._retention_read_optout(self.data_dir))

    def test_revocation_refuses_every_new_destructive_pass(self):
        # Revocation linearizes against destructive transitions: a pass
        # already running under the previously enabled policy finishes its
        # in-flight transition under its own authorization; every NEW
        # apply re-reads the revoked control state and refuses.
        self.make_session("expired", ended_days_ago=45)
        cg.write_retention_policy(self.data_dir, enabled=True)
        report = cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertEqual(report["counts"]["quarantined"], 1)
        cg.write_retention_policy(self.data_dir, enabled=False)
        self.make_session("expired2", ended_days_ago=45)
        with self.assertRaisesRegex(RuntimeError, "enabled policy"):
            cg.cleanup_old_sessions(self.data_dir, apply=True)
        self.assertTrue(self.session_dir("expired2").is_dir())
        # And the trigger agrees.
        self.assertEqual(self.dispatched(), [])


class TailAdvancementTests(RetentionFixtureBase):
    """Repeated trigger children with small budgets reach the tail of a
    long registered prefix (the retired RV03 risk, under the trigger)."""

    def test_repeated_small_child_passes_quarantine_every_eligible(self):
        total = 24
        for index in range(total):
            self.make_session(f"bulk-{index:03d}", ended_days_ago=45)
        self.make_session("keeper", ended_days_ago=1)
        claim = locks_dir(self.data_dir) / CLAIM
        write_json(claim, {"schema": cg._RETENTION_TRIGGER_CLAIM_SCHEMA,
                           "pid": os.getpid(), "started_at": cg.utc_now()})
        quarantined = 0
        for _ in range(40):
            code = cg._retention_trigger_child_pass(self.data_dir,
                                                    budget_seconds=0.35)
            self.assertEqual(code, 0)
            state = cg._retention_read_trigger_state(self.data_dir)
            quarantined += ((state.get("last_outcome") or {})
                            .get("counts", {}).get("quarantined", 0))
            remaining = [entry for entry in (self.data_dir / cg.V2_NAMESPACE).iterdir()
                         if entry.name.startswith("bulk-")]
            if not remaining:
                break
        self.assertFalse(list((self.data_dir / cg.V2_NAMESPACE).glob("bulk-*")))
        self.assertEqual(quarantined, total)
        self.assertTrue(self.session_dir("keeper").is_dir())
        state = cg._retention_read_trigger_state(self.data_dir)
        self.assertTrue(state["last_outcome"]["scan_complete"])


class SessionEndIntegrationTests(RetentionFixtureBase):
    """Full dispatch path: SessionEnd saves, then exactly one dispatch."""

    def test_session_end_dispatches_exactly_one_child_after_save(self):
        self.make_session("expired", ended_days_ago=45)
        self.make_session("current", ended_days_ago=None, finished=False)
        seen = []
        with mock.patch.dict(os.environ,
                             {"CONTEXT_GUARD_DISABLE_RETENTION_TRIGGER": ""}), \
                mock.patch.object(cg, "_retention_trigger_spawn",
                                  side_effect=lambda argv: seen.append(list(argv)) or True):
            self.assertEqual(
                cg.dispatch(self.payload("SessionEnd", "current")), {})
        self.assertEqual(len(seen), 1)
        self.assertIn("--trigger-run", seen[0])
        # The hook itself never touched the expired session or the policy.
        self.assertTrue(self.session_dir("expired").is_dir())
        self.assertFalse(cg._retention_policy_path(self.data_dir).exists())
        # The child (run for real here) cleans up under the same contract.
        claim = locks_dir(self.data_dir) / CLAIM
        self.assertTrue(claim.exists())
        self.assertEqual(
            cg._retention_trigger_child_pass(self.data_dir, budget_seconds=5.0), 0)
        self.assertFalse(self.session_dir("expired").is_dir())
        self.assertFalse(claim.exists())


class TriggerCliSurfaceTests(RetentionFixtureBase):
    def test_trigger_run_without_data_dir_refuses(self):
        result = subprocess.run(
            [sys.executable, "-B", str(MODULE_PATH), "cleanup", "--trigger-run"],
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                     CONTEXT_GUARD_DISABLE_RETENTION_TRIGGER=""),
            text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--data-dir", result.stderr)

    def test_policy_show_reports_automatic_maintenance_state(self):
        self.make_session("anchor", ended_days_ago=None, finished=False)
        result = subprocess.run(
            [sys.executable, "-B", str(MODULE_PATH), "cleanup",
             "--data-dir", str(self.data_dir), "--policy", "show"],
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["policy"]["policy_source"], "default")
        self.assertTrue(payload["policy"]["enabled"])
        self.assertIsNone(payload["automatic_maintenance"]["optout"])
        self.assertIsInstance(payload["automatic_maintenance"]["trigger"], dict)


if __name__ == "__main__":
    unittest.main()
