"""No-model fixtures for the daily-upgrade entry; no real CLI, host, or trust.

Every official command is answered by an in-memory fake host; process
classification and the fresh-client probe are patched seams. The artifact
identity machinery (``distribution_manifest``, ``compare_artifact``) and the
launcher probe run for real against synthetic fixtures. No fixture touches a
daily HOME, a consumed cache, or the network.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "daily_upgrade_under_test", REPO / "tools" / "validation" / "daily_upgrade.py")
U = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(U)

TARGET = "0.17.2"
OLD = "0.17.1"
MARKET = U.MARKET
ENTRY = U.ENTRY


def completed(argv, stdout=b"", rc=0, stderr=b""):
    return subprocess.CompletedProcess(argv, rc, stdout, stderr)


def make_artifact(root: Path, version: str = TARGET) -> Path:
    (root / ".codex-plugin").mkdir(parents=True, exist_ok=True)
    (root / ".codex-plugin" / "plugin.json").write_text(
        json.dumps({"name": "context-guard", "version": version}), encoding="utf-8")
    (root / "hooks").mkdir(exist_ok=True)
    (root / "hooks" / "hooks.json").write_text(
        json.dumps({"hooks": {event: [] for event in U.EVENTS}}), encoding="utf-8")
    (root / "scripts").mkdir(exist_ok=True)
    (root / "scripts" / "context_guard.py").write_text("# candidate runtime\n", encoding="utf-8")
    (root / ".agents" / "plugins").mkdir(parents=True, exist_ok=True)
    (root / ".agents" / "plugins" / "marketplace.json").write_text(json.dumps({
        "name": MARKET,
        "plugins": [{"name": "context-guard",
                     "source": {"source": "local", "path": "./"}}]}), encoding="utf-8")
    from scripts.artifact_identity import distribution_files
    files = distribution_files(root)
    (root / ".codex-plugin" / "distribution-manifest.json").write_text(json.dumps({
        "schema": "cg-distribution-manifest/v1",
        "file_count": len(files), "files": files}), encoding="utf-8")
    return root


class FakeHost:
    """In-memory official CLI; the command families mirror the daily flow."""

    def __init__(self, tmp: Path, *, registered=True, installed_version=OLD,
                 market_root=None, cli_version="codex-cli 0.42.0",
                 enabled=True, remove_retires_plugin=True):
        self.tmp = tmp
        self.registered = registered
        self.installed_version = installed_version
        self.market_root = market_root or str(tmp / "old-source")
        self.cli_version = cli_version
        self.enabled = enabled
        self.remove_retires_plugin = remove_retires_plugin
        self.calls: list[list[str]] = []
        self.crash_argv: list[str] | None = None
        self.crash_after_add = False
        self.plugin_add_stdout = json.dumps(
            {"pluginId": ENTRY, "name": "context-guard", "marketplaceName": MARKET,
             "version": TARGET, "installedPath": str(tmp / "cache")}).encode()

    # ---- seam used by daily_upgrade._run_command ----
    def run(self, argv, env, timeout=90.0):
        self.calls.append([str(item) for item in argv])
        if self.crash_argv is not None and [str(item) for item in argv] == self.crash_argv:
            raise OSError("simulated command crash")
        rest = [str(item) for item in argv[1:]]
        if rest == ["--version"]:
            return completed(argv, (self.cli_version + "\n").encode())
        if rest == ["plugin", "marketplace", "list", "--json"]:
            rows = []
            if self.registered:
                rows.append({"name": MARKET, "root": self.market_root,
                             "marketplaceSource": {"sourceType": "local",
                                                   "source": self.market_root}})
            return completed(argv, json.dumps({"marketplaces": rows}).encode())
        if rest == ["plugin", "list", "--marketplace", MARKET, "--json"]:
            installed = []
            if self.installed_version is not None:
                installed.append({"pluginId": ENTRY, "name": "context-guard",
                                  "marketplaceName": MARKET,
                                  "version": self.installed_version,
                                  "installed": True, "enabled": self.enabled})
            return completed(argv, json.dumps({"installed": installed}).encode())
        if rest == ["plugin", "marketplace", "remove", MARKET]:
            self.registered = False
            if self.remove_retires_plugin:
                self.installed_version = None
            return completed(argv)
        if rest == ["plugin", "marketplace", "add", str(self.tmp / "artifact")]:
            self.registered = True
            self.market_root = str(self.tmp / "artifact")
            if self.crash_after_add:
                raise OSError("simulated crash after the add landed")
            return completed(argv)
        if rest == ["plugin", "add", ENTRY, "--json"]:
            self.installed_version = TARGET
            return completed(argv, self.plugin_add_stdout)
        if "cleanup" in rest and "--policy" in rest and "show" in rest:
            return completed(argv, json.dumps({
                "policy": {"enabled": True, "min_age_days": 30},
                "automatic_maintenance": {"optout": None,
                                          "trigger": {"mode": "unavailable"}}}).encode())
        raise AssertionError("unexpected official command: " + repr(argv))


def inventory_result(status="absent", desktop_pids=(), sandbox_pids=(), source="darwin-ps-libproc"):
    rows = []
    next_pid = 5000
    for pid in desktop_pids:
        rows.append({"pid": pid, "ppid": 1, "uid": 501,
                     "executable": "/Applications/Codex.app/Contents/MacOS/Codex",
                     "identity": "observed"})
    for pid in sandbox_pids:
        rows.append({"pid": pid, "ppid": 1, "uid": 501,
                     "executable": "/Applications/Codex.app/Contents/MacOS/CodexSandboxService",
                     "identity": "observed"})
    rows.append({"pid": next_pid, "ppid": 1, "uid": 0, "executable": "/usr/libexec/unrelated",
                 "identity": "observed"})
    if status == "unknown":
        rows.append({"pid": next_pid + 1, "ppid": 1, "uid": 501,
                     "executable": None, "identity": "unreadable"})
    return I_classify({"status": "observed", "reason": None, "source": source, "rows": rows})


def I_classify(enumeration):
    return U.inventory.classify(enumeration, ["/Applications/Codex.app/Contents/MacOS/Codex"],
                                ["/Applications/Codex.app/Contents/MacOS/CodexSandboxService"])


class DailyUpgradeCase(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._temp = tempfile.TemporaryDirectory()
        tmp = Path(self._temp.name).resolve()
        self.tmp = tmp
        self.artifact = make_artifact(tmp / "artifact")
        self.daily = tmp / "daily-home" / ".codex"
        self.daily.mkdir(parents=True)
        self.output = tmp / "batch"
        self.fake = FakeHost(tmp)
        self.cache_root = self.daily / "plugins" / "cache" / MARKET / "context-guard"
        self.host_status = inventory_result("absent")
        self.patch(U, "_run_command", self.fake.run)
        self.patch(U, "_daily_home", lambda: self.daily)
        self.patch(U, "_host_inventory", lambda desktop, markers: self.host_status)
        self.patch(U, "_loaded_probe", self._loaded_probe)
        self.probe = {"hooks": self.trusted_hooks(), "reason": None,
                      "cleanup": {"cleanup_complete": True, "owned_process_exited": True}}
        (tmp / "cwd").mkdir()
        (tmp / "codex").write_bytes(b"#!/bin/sh\n")
        (tmp / "Codex").write_bytes(b"MZ")
        (tmp / "CodexSandboxService").write_bytes(b"helper")
        self.plan_path = self.write_plan()

    def tearDown(self):
        self._temp.cleanup()

    def patch(self, target, name, value):
        self._patches = getattr(self, "_patches", [])
        original = getattr(target, name)
        self._patches.append((target, name, original))
        setattr(target, name, value)

    def trusted_hooks(self):
        cache = self.cache_root / TARGET / "hooks" / "hooks.json"
        return [{"eventName": event, "sourcePath": str(cache), "source": "plugin",
                 "trustStatus": "trusted", "enabled": True} for event in U.EVENTS]

    def _loaded_probe(self, cli, cwd, journal_dir, env):
        return {"schema": U.PROBE_SCHEMA, "hooks": self.probe["hooks"],
                "cleanup": self.probe["cleanup"], "reason": self.probe["reason"]}

    def write_plan(self, **overrides) -> Path:
        plan = {"schema": U.PLAN, "entry": ENTRY, "marketplace": MARKET,
                "target_version": TARGET, "artifact_dir": str(self.artifact),
                "cwd": str(self.tmp / "cwd"), "desktop_executable": str(self.tmp / "Codex"),
                "sandbox_markers": [str(self.tmp / "CodexSandboxService")],
                "cli": str(self.tmp / "codex")}
        plan.update(overrides)
        path = self.tmp / "plan.json"
        path.write_text(json.dumps(plan), encoding="utf-8")
        return path

    def seed_old_cache(self, version=OLD):
        cache = self.cache_root / version
        (cache / "scripts").mkdir(parents=True, exist_ok=True)
        (cache / "marker.txt").write_text("old consumed cache bytes", encoding="utf-8")
        (cache / "scripts" / "context_guard.py").write_text("# old runtime\n", encoding="utf-8")

    def seed_installed_cache(self):
        """An on-disk target cache slot, as the official add would create."""
        (self.cache_root / TARGET).mkdir(parents=True, exist_ok=True)

    def seed_target_cache(self):
        """An exact target cache, as artifact parity requires."""
        shutil.copytree(self.artifact, self.cache_root / TARGET, dirs_exist_ok=True)

    def main(self, *args):
        return U.main(["--plan", str(self.plan_path), "--output", str(self.output), *args])

    def read(self, name):
        return json.loads((self.output / name).read_text(encoding="utf-8"))


class TestPrepare(DailyUpgradeCase):
    def test_running_host_requires_restart_with_reason(self):
        self.host_status = inventory_result("running", desktop_pids=(4242,))
        self.seed_old_cache()
        self.assertEqual(self.main("--prepare"), 0)
        prepared = self.read("prepare.json")
        self.assertTrue(prepared["swap"]["required"])
        self.assertIn("replaces the consumed plugin cache", prepared["swap"]["reason"])

    def test_unknown_host_state_requires_restart(self):
        self.host_status = inventory_result("unknown")
        self.seed_old_cache()
        self.main("--prepare")
        prepared = self.read("prepare.json")
        self.assertTrue(prepared["swap"]["required"])
        self.assertIn("unknown", prepared["swap"]["reason"])

    def test_absent_host_does_not_require_restart(self):
        self.seed_old_cache()
        self.assertEqual(self.main("--prepare"), 0)
        prepared = self.read("prepare.json")
        self.assertFalse(prepared["swap"]["required"])
        self.assertEqual(prepared["subject"]["installed_before"]["version"], OLD)

    def test_sandbox_services_never_gate_the_swap(self):
        self.host_status = inventory_result("absent", sandbox_pids=(7001, 7002))
        self.seed_old_cache()
        self.assertEqual(self.main("--prepare"), 0)
        prepared = self.read("prepare.json")
        self.assertFalse(prepared["swap"]["required"])

    def test_fresh_install_requires_no_restart(self):
        self.fake.registered = False
        self.fake.installed_version = None
        self.host_status = inventory_result("running", desktop_pids=(4242,))
        self.assertEqual(self.main("--prepare"), 0)
        prepared = self.read("prepare.json")
        self.assertFalse(prepared["swap"]["required"])
        self.assertFalse(prepared["subject"]["installed_before"]["installed"])

    def test_already_current_is_reported(self):
        self.fake.installed_version = TARGET
        self.assertEqual(self.main("--prepare"), 0)
        self.assertEqual(self.read("prepare.json")["status"], "already_current")

    def test_data_policy_observed_without_mutation(self):
        self.seed_old_cache()
        data_dir = self.tmp / "plugin-data"
        data_dir.mkdir()
        self.plan_path = self.write_plan(data_dir=str(data_dir))
        self.assertEqual(self.main("--prepare"), 0)
        policy = self.read("prepare.json")["subject"]["data_policy"]
        self.assertTrue(policy["present"])
        self.assertTrue(policy["policy"]["enabled"])
        self.assertEqual(self.fake.calls[-1][4:6], ["cleanup", "--data-dir"])

    def test_preflight_refuses_to_rerun_into_the_same_output(self):
        self.assertEqual(self.main("--preflight"), 0)
        preflight = self.read("preflight.json")
        self.assertEqual(preflight["stage"], "preflight")
        self.assertEqual(preflight["status"], "observed")
        self.assertEqual(self.main("--preflight"), 2)


class TestApply(DailyUpgradeCase):
    def apply(self):
        return self.main("--apply")

    def test_running_host_is_pending_with_one_instruction(self):
        self.seed_old_cache()
        self.host_status = inventory_result("running", desktop_pids=(4242,))
        self.assertEqual(self.main("--prepare"), 0)
        self.assertTrue(self.read("prepare.json")["swap"]["required"])
        self.assertEqual(self.apply(), 1)
        self.assertFalse((self.output / "apply.json").exists())

    def test_official_swap_completes_and_binds_identity(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.seed_installed_cache()
        self.assertEqual(self.apply(), 0)
        applied = self.read("apply.json")
        self.assertEqual(applied["status"], "applied")
        self.assertEqual(applied["installed_after"]["version"], TARGET)
        self.assertEqual(applied["installed_after"]["cache_path"],
                         str(self.cache_root / TARGET))
        # The old consumed cache is never edited; removal goes through the
        # official marketplace remove exactly once.
        self.assertTrue((self.cache_root / OLD / "marker.txt").exists())
        self.assertEqual(self.fake.calls.count(
            [str(self.tmp / "codex"), "plugin", "marketplace", "remove", MARKET]), 1)

    def test_summary_parse_failure_continues_on_official_readback(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.seed_installed_cache()
        self.fake.plugin_add_stdout = b"\xff\xfe not json at all"
        self.assertEqual(self.apply(), 0)
        applied = self.read("apply.json")
        add_facts = [fact for fact in applied["commands"]
                     if fact.get("stage") == "plugin_add" and fact.get("argv", [None] * 3)[1:3] == ["plugin", "add"]]
        self.assertTrue(add_facts and add_facts[0].get("summary_parse_failed"))
        self.assertEqual(applied["installed_after"]["version"], TARGET)

    def test_marketplace_remove_that_keeps_the_plugin_still_upgrades(self):
        self.seed_old_cache()
        self.fake.remove_retires_plugin = False
        self.main("--prepare")
        self.seed_installed_cache()
        self.assertEqual(self.apply(), 0)
        self.assertEqual(self.read("apply.json")["installed_after"]["version"], TARGET)

    def test_cli_version_drift_between_prepare_and_apply_is_refused(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.fake.cli_version = "codex-cli 0.43.0"
        self.assertEqual(self.apply(), 2)

    def test_outside_registration_removal_is_refused(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.fake.registered = False
        self.assertEqual(self.apply(), 2)

    def test_host_started_between_prepare_and_apply_is_pending(self):
        # Prepare observed the host absent; the apply-time inventory is the
        # deciding observation and must gate the swap on its own.
        self.seed_old_cache()
        self.main("--prepare")
        self.seed_installed_cache()
        self.host_status = inventory_result("running", desktop_pids=(4242,))
        self.assertEqual(self.apply(), 1)
        self.assertFalse((self.output / "apply.json").exists())
        self.assertEqual(self.fake.calls.count(
            [str(self.tmp / "codex"), "plugin", "marketplace", "remove", MARKET]), 0)

    def test_resume_after_add_landed_without_fact(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.seed_installed_cache()
        self.fake.crash_after_add = True
        self.assertEqual(self.apply(), 2)
        self.fake.crash_after_add = False
        self.assertEqual(self.apply(), 0)
        # The add ran exactly once; the resume reconciled by readback.
        self.assertEqual(self.fake.calls.count(
            [str(self.tmp / "codex"), "plugin", "marketplace", "add",
             str(self.artifact)]), 1)
        self.assertEqual(self.read("apply.json")["installed_after"]["version"], TARGET)

    def test_corrupt_journal_is_refused(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.seed_installed_cache()
        (self.output / "apply-events.jsonl").write_text(
            json.dumps({"event": "begin"}) + "\n{not json}\n", encoding="utf-8")
        self.assertEqual(self.apply(), 2)

    def test_foreign_journal_begin_is_refused(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.seed_installed_cache()
        (self.output / "apply-events.jsonl").write_text(
            json.dumps({"event": "begin", "schema": U.JOURNAL_SCHEMA,
                        "subject_sha256": "0" * 64, "prepared_sha256": "1" * 64}) + "\n",
            encoding="utf-8")
        self.assertEqual(self.apply(), 2)

    def test_target_installation_without_recorded_intent_is_refused(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.fake.installed_version = TARGET
        self.assertEqual(self.apply(), 2)

    def test_interrupted_apply_resumes_without_repeating_remove(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.seed_installed_cache()
        self.fake.crash_argv = [str(self.tmp / "codex"), "plugin", "marketplace",
                                "add", str(self.artifact)]
        self.assertEqual(self.apply(), 2)
        journal = (self.output / "apply-events.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertIn('"marketplace_add"', "\n".join(journal))
        self.fake.crash_argv = None
        self.assertEqual(self.apply(), 0)
        # Exactly one removal across both runs; the resume reconciled by
        # official readback instead of repeating the destructive stage.
        self.assertEqual(self.fake.calls.count(
            [str(self.tmp / "codex"), "plugin", "marketplace", "remove", MARKET]), 1)
        self.assertEqual(self.read("apply.json")["installed_after"]["version"], TARGET)
        self.assertEqual(self.apply(), 2)  # completed apply never reruns


class TestVerify(DailyUpgradeCase):
    def prepare_and_apply(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.seed_target_cache()
        assert self.main("--apply") == 0

    def test_new_and_trusted_passes(self):
        self.prepare_and_apply()
        self.assertEqual(self.main("--verify"), 0)
        verified = self.read("verify.json")
        self.assertEqual(verified["status"], "passed")
        self.assertEqual(verified["fresh_client_loaded"], "new")
        self.assertEqual(verified["artifact_parity"], "passed")

    def test_old_loaded_requires_restart(self):
        self.prepare_and_apply()
        old_cache = self.cache_root / OLD / "hooks" / "hooks.json"
        self.probe["hooks"] = [{"eventName": event, "sourcePath": str(old_cache),
                                "source": "plugin", "trustStatus": "trusted",
                                "enabled": True} for event in U.EVENTS]
        self.assertEqual(self.main("--verify"), 1)
        verified = self.read("verify.json")
        self.assertEqual(verified["status"], "restart_required")
        self.assertEqual(verified["fresh_client_loaded"], "old")

    def test_trust_pending_is_one_precise_action(self):
        self.prepare_and_apply()
        self.probe["hooks"] = [{**row, "trustStatus": "untrusted"}
                               for row in self.probe["hooks"]]
        self.assertEqual(self.main("--verify"), 1)
        verified = self.read("verify.json")
        self.assertEqual(verified["status"], "hook_trust_pending")

    def test_probe_failure_is_unknown_never_a_pass(self):
        self.prepare_and_apply()
        self.probe["reason"] = "TimeoutError: hooks/list"
        self.probe["hooks"] = []
        self.assertEqual(self.main("--verify"), 1)
        verified = self.read("verify.json")
        self.assertEqual(verified["status"], "loaded_unknown")
        self.assertEqual(verified["fresh_client_loaded"], "unknown")

    def test_verify_works_directly_after_already_current(self):
        self.seed_target_cache()
        self.fake.installed_version = TARGET
        self.fake.registered = True
        self.fake.market_root = str(self.artifact)
        self.main("--prepare")
        self.assertEqual(self.read("prepare.json")["status"], "already_current")
        self.assertEqual(self.main("--verify"), 0)
        self.assertEqual(self.read("verify.json")["status"], "passed")

    def test_verify_receipt_is_never_replaced(self):
        self.prepare_and_apply()
        self.assertEqual(self.main("--verify"), 0)
        self.assertEqual(self.main("--verify"), 2)


class TestPlanAndCommandLaw(DailyUpgradeCase):
    def test_wrong_entry_is_refused(self):
        plan = self.tmp / "bad.json"
        plan.write_text(json.dumps({"schema": U.PLAN, "entry": "context-guard@other",
                                    "marketplace": MARKET, "target_version": TARGET,
                                    "artifact_dir": str(self.artifact),
                                    "cwd": str(self.tmp / "cwd"),
                                    "desktop_executable": str(self.tmp / "Codex"),
                                    "cli": str(self.tmp / "codex")}), encoding="utf-8")
        self.plan_path = plan
        self.assertEqual(self.main("--preflight"), 2)

    def test_output_inside_artifact_is_refused(self):
        self.output = self.artifact / "batch"
        self.assertEqual(self.main("--preflight"), 2)

    def test_preflight_commands_probe_the_real_launcher_without_help_probes(self):
        self.patch(U.base, "_writable_directory", lambda path: None)

        def probe(argv, env, timeout=30.0):
            argv = [str(item) for item in argv]
            if argv[:2] == ["sh", "-n"] or "--print-argv" in argv:
                return subprocess.run(argv, capture_output=True, timeout=timeout)
            if argv[1:3] == ["-B", "-c"]:
                return subprocess.run(argv, capture_output=True, timeout=timeout)
            raise AssertionError("unexpected probe command: " + repr(argv))

        self.patch(U, "_probe_run", probe)
        self.seed_old_cache()
        self.assertEqual(self.main("--preflight-commands"), 0)
        self.seed_old_cache()  # idempotent seeding; no assertion drift

    def test_scrubbed_env_drops_inherited_codex_home(self):
        import os
        previous = os.environ.get("CODEX_HOME")
        os.environ["CODEX_HOME"] = str(self.tmp / "other-home")
        try:
            env = U._scrubbed_env()
        finally:
            if previous is None:
                os.environ.pop("CODEX_HOME", None)
            else:
                os.environ["CODEX_HOME"] = previous
        self.assertNotIn("CODEX_HOME", env)

    def test_mixed_old_and_new_hook_sources_require_restart(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.seed_target_cache()
        assert self.main("--apply") == 0
        fresh = str(self.cache_root / TARGET / "hooks" / "hooks.json")
        stale = str(self.cache_root / OLD / "hooks" / "hooks.json")
        self.probe["hooks"] = [{"eventName": event, "sourcePath": fresh if i % 2 else stale,
                                "source": "plugin", "trustStatus": "trusted",
                                "enabled": True} for i, event in enumerate(U.EVENTS)]
        self.assertEqual(self.main("--verify"), 1)
        verified = self.read("verify.json")
        self.assertEqual(verified["status"], "restart_required")
        self.assertEqual(verified["fresh_client_loaded"], "old")

    def test_verify_refuses_when_readback_loses_registration(self):
        self.seed_old_cache()
        self.main("--prepare")
        self.seed_target_cache()
        assert self.main("--apply") == 0
        self.fake.registered = False
        self.assertEqual(self.main("--verify"), 2)

    def test_plan_file_law_refuses_relative_output(self):
        import os
        previous = os.getcwd()
        os.chdir(self.tmp)
        try:
            rc = U.main(["--plan", str(self.plan_path), "--output", "batch",
                         "--preflight"])
        finally:
            os.chdir(previous)
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
