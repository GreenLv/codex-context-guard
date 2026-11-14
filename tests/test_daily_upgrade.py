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
import os
import shutil
import subprocess
import sys
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
# The real transport, captured before DailyUpgradeCase.setUp patches the seam.
REAL_LOADED_PROBE = U._loaded_probe


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
        self.patch(U, "_host_inventory",
                   lambda desktop, markers, host_tools=None: self.host_status)
        self.patch(U, "_loaded_probe", self._loaded_probe)
        self.patch(U, "_powershell_identity", self._fixture_powershell_identity)
        self.publisher = {"method": "fixture", "verified": True,
                          "identity": "FIXTURETEAM"}
        self._real_host_publisher = U._host_publisher
        self.patch(U, "_host_publisher",
                   lambda path, env, host_tools=None, expected_team=None:
                   dict(self.publisher))
        # The official-CLI fake must not intercept Windows Get-Acl; privacy is
        # modeled only inside this synthetic tree and the real DACL consumer
        # keeps its own scheduler controls.
        self.patch(U.scheduler._Windows, "private_parent", self._fixture_private_parent)
        self.probe = {"hooks": self.trusted_hooks(), "inventory_flagged": False,
                      "reason": None,
                      "cleanup": {"cleanup_complete": True, "owned_process_exited": True}}
        (tmp / "cwd").mkdir()
        (tmp / "codex").write_bytes(b"#!/bin/sh\n")
        (tmp / "Codex").write_bytes(b"MZ")
        (tmp / "CodexSandboxService").write_bytes(b"helper")
        self.plan_path = self.write_plan()

    def tearDown(self):
        self._temp.cleanup()

    def _fixture_powershell_identity(self, env):
        """Windows fixture identity without the real version probe subprocess.

        The real resolved shell path is pinned (launcher-specific tests still
        run real parse/print-argv against it); only the version probe is
        isolated from the no-model fixtures.
        """
        shell = shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")
        if shell is None:
            raise U.CapabilityPending("PowerShell unavailable for fixture identity")
        return {"path": str(Path(shell).resolve()), "version": "fixture-stubbed",
                "sha256": U._sha_loose(Path(shell).resolve())}

    def _fixture_private_parent(self, path):
        """Model a private directory only inside this synthetic fixture tree.

        Same shape as the acceptance fixture's private-parent stub: the real
        DACL consumer stays exercised by its own scheduler controls and is
        never loosened here.
        """
        candidate = Path(path).resolve()
        return candidate.is_dir() and candidate.is_relative_to(self.tmp.resolve())

    def patch(self, target, name, value):
        # Every seam replacement restores immediately at teardown; the
        # validation modules are shared, so a leaked patch would poison the
        # whole-suite run order.
        original = getattr(target, name)
        setattr(target, name, value)
        self.addCleanup(setattr, target, name, original)

    def trusted_hooks(self):
        cache = self.cache_root / TARGET / "hooks" / "hooks.json"
        return [{"eventName": event, "sourcePath": str(cache), "source": "plugin",
                 "trustStatus": "trusted", "enabled": True} for event in U.EVENTS]

    def _loaded_probe(self, cli, cwd, journal_dir, env):
        return {"schema": U.PROBE_SCHEMA, "hooks": self.probe["hooks"],
                "inventory_flagged": self.probe["inventory_flagged"],
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

    def failing_audit_writer(self, failing_name):
        real_write = U.base._write_new

        def guarded(path, payload):
            if Path(path).name == failing_name:
                raise OSError("simulated audit-write failure")
            return real_write(path, payload)

        original = U.base._write_new
        self.patch(U.base, "_write_new", guarded)

        def restore():
            U.base._write_new = original

        return restore

    def main(self, *args):
        import contextlib
        import io
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = U.main(["--plan", str(self.plan_path),
                           "--output", str(self.output), *args])
        self._stderr = buffer.getvalue()
        return code

    def last_stderr(self):
        return getattr(self, "_stderr", "")

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

    def test_policy_readback_uses_observed_installed_version(self):
        # A retained empty target slot must not shadow the installed version
        # that actually owns the policy.
        self.seed_old_cache()
        (self.cache_root / TARGET).mkdir(parents=True)
        data_dir = self.tmp / "plugin-data"
        data_dir.mkdir()
        self.plan_path = self.write_plan(data_dir=str(data_dir))
        self.assertEqual(self.main("--prepare"), 0)
        policy = self.read("prepare.json")["subject"]["data_policy"]
        self.assertNotIn("policy_readback", policy)
        self.assertTrue(policy["policy"]["enabled"])
        cleanup_calls = [call for call in self.fake.calls if "cleanup" in call]
        self.assertTrue(cleanup_calls)
        self.assertEqual(Path(cleanup_calls[-1][3]),
                         self.cache_root / OLD / "scripts" / "context_guard.py")

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

    def test_removed_old_slot_sources_still_require_restart(self):
        self.prepare_and_apply()
        shutil.rmtree(self.cache_root / OLD)
        roots = [self.cache_root / OLD, self.cache_root / "local",
                 self.daily / "plugins" / "cache" / U.base.OLD_0161_WRAPPER_MARKET
                 / "context-guard" / "0.16.1"]
        for index, root in enumerate(roots):
            with self.subTest(source=root):
                self.assertFalse(root.exists())
                old = {"eventName": "stop", "sourcePath": str(root / "hooks" / "hooks.json"),
                       "source": "plugin", "trustStatus": "trusted", "enabled": True}
                self.probe["hooks"] = self.trusted_hooks() + [old]
                self.assertEqual(self.main("--verify"), 1)
                receipt = "verify.json" if index == 0 else f"verify-{index + 1}.json"
                self.assertEqual(self.read(receipt)["status"], "restart_required")

    def test_malformed_product_source_never_hides_beside_new_hooks(self):
        self.prepare_and_apply()
        self.probe["hooks"] = self.trusted_hooks() + [{
            "eventName": "stop", "sourcePath": str(self.cache_root / OLD / "hooks" / "other.json"),
            "source": "plugin", "trustStatus": "trusted", "enabled": True}]
        self.assertEqual(self.main("--verify"), 1)
        self.assertEqual(self.read("verify.json")["status"], "loaded_unknown")

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

    def test_pending_verify_resumes_with_numbered_receipts(self):
        self.prepare_and_apply()
        self.probe["hooks"] = [{**row, "trustStatus": "untrusted"}
                               for row in self.probe["hooks"]]
        self.assertEqual(self.main("--verify"), 1)
        first = (self.output / "verify.json").read_bytes()
        self.probe["hooks"] = self.trusted_hooks()
        self.assertEqual(self.main("--verify"), 0)
        self.assertTrue((self.output / "verify-2.json").is_file())
        self.assertEqual((self.output / "verify.json").read_bytes(), first)
        self.assertEqual(self.read("verify-2.json")["status"], "passed")

    def test_passed_verify_reread_refreshes_current_facts(self):
        # A passed receipt is historical state: every verify re-measures and
        # appends a numbered receipt without touching prior evidence.
        self.prepare_and_apply()
        self.assertEqual(self.main("--verify"), 0)
        first = (self.output / "verify.json").read_bytes()
        self.assertEqual(self.main("--verify"), 0)
        self.assertTrue((self.output / "verify-2.json").is_file())
        self.assertEqual((self.output / "verify.json").read_bytes(), first)
        self.assertEqual(self.read("verify-2.json")["status"], "passed")

    def test_passed_verify_detects_disabled_installation(self):
        self.prepare_and_apply()
        self.assertEqual(self.main("--verify"), 0)
        self.fake.enabled = False
        self.assertEqual(self.main("--verify"), 1)
        self.assertEqual(self.read("verify-2.json")["status"], "hook_trust_pending")

    def test_passed_verify_detects_trust_change(self):
        self.prepare_and_apply()
        self.assertEqual(self.main("--verify"), 0)
        self.probe["hooks"] = [{**row, "trustStatus": "untrusted"}
                               for row in self.probe["hooks"]]
        self.assertEqual(self.main("--verify"), 1)
        self.assertEqual(self.read("verify-2.json")["status"], "hook_trust_pending")

    def test_passed_verify_detects_cache_drift(self):
        self.prepare_and_apply()
        self.assertEqual(self.main("--verify"), 0)
        cache = self.cache_root / TARGET
        (cache / "tampered.txt").write_text("cache drift", encoding="utf-8")
        self.assertEqual(self.main("--verify"), 2)
        self.assertFalse((self.output / "verify-2.json").is_file())

    def test_explicit_existing_verify_output_is_refused(self):
        self.prepare_and_apply()
        self.assertEqual(self.main("--verify"), 0)
        self.assertEqual(self.main("--verify", "--verify-output",
                                   str(self.output / "verify.json")), 2)

    def test_single_hook_row_never_passes(self):
        # Regression for the pre-repair verdict: one trusted row of nine
        # yielded "passed" under prefix routing alone.
        self.prepare_and_apply()
        self.probe["hooks"] = self.trusted_hooks()[:1]
        self.assertEqual(self.main("--verify"), 1)
        verified = self.read("verify.json")
        self.assertEqual(verified["status"], "hook_inventory_incomplete")

    def test_duplicate_event_row_never_passes(self):
        self.prepare_and_apply()
        rows = self.trusted_hooks()
        self.probe["hooks"] = rows + [dict(rows[0])]
        self.assertEqual(self.main("--verify"), 1)
        self.assertEqual(self.read("verify.json")["status"], "hook_inventory_incomplete")

    def test_flagged_inventory_never_passes(self):
        self.prepare_and_apply()
        self.probe["inventory_flagged"] = True
        self.assertEqual(self.main("--verify"), 1)
        self.assertEqual(self.read("verify.json")["status"], "hook_inventory_incomplete")

    def test_other_plugin_rows_are_not_old_context_guard(self):
        self.prepare_and_apply()
        other = self.daily / "plugins" / "cache" / "other-market" / "other" / "hooks" / "hooks.json"
        self.probe["hooks"] = self.trusted_hooks() + [
            {"eventName": "otherHook", "sourcePath": str(other), "source": "plugin",
             "trustStatus": "trusted", "enabled": True}]
        self.assertEqual(self.main("--verify"), 0)
        verified = self.read("verify.json")
        self.assertEqual(verified["status"], "passed")
        self.assertEqual(verified["fresh_client_loaded"], "new")

    def test_official_disabled_readback_is_trust_pending(self):
        self.prepare_and_apply()
        self.fake.enabled = False
        self.assertEqual(self.main("--verify"), 1)
        self.assertEqual(self.read("verify.json")["status"], "hook_trust_pending")


FAKE_APP_SERVER_SOURCE = """\
import json, sys
hooks_json = %(hooks_json)r
events = %(events)r
def send(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()
for line in sys.stdin:
    try:
        message = json.loads(line)
    except ValueError:
        continue
    identifier = message.get("id")
    if identifier is None:
        continue  # notifications such as 'initialized' are accepted silently
    method = message.get("method")
    if method == "initialize":
        send({"id": identifier, "result": {}})
    elif method == "hooks/list":
        rows = [{"eventName": event, "sourcePath": hooks_json, "source": "plugin",
                 "trustStatus": "trusted", "enabled": True} for event in events]
        send({"id": identifier, "result": {"data": [{"hooks": rows}]}})
    else:
        send({"id": identifier, "error": {"code": -32601, "message": "unimplemented"}})
"""


class TestProbeTransport(DailyUpgradeCase):
    """The real OwnedProcess/RPC transport against a no-model fake app-server.

    Only the spawn argv is shimmed onto the fixture interpreter (a POSIX
    shell script cannot spawn on Windows); the process tree, journaling,
    RPC loop and cleanup run exactly as the real probe runs them.
    """

    def setUp(self):
        super().setUp()
        self.server = self.tmp / "fake_app_server.py"
        self.server.write_text(FAKE_APP_SERVER_SOURCE
                               % {"hooks_json": str(self.cache_root / TARGET
                                                    / "hooks" / "hooks.json"),
                                  "events": sorted(U.EVENTS)}, encoding="utf-8")
        self.fake_cli = str(self.tmp / "fake-codex")
        self.spawned = []
        real_spawn = U.OwnedProcess.spawn
        fake_cli, server = self.fake_cli, str(self.server)

        def shim_spawn(command, **kwargs):
            command = list(command)
            if command and command[0] == fake_cli:
                command = [sys.executable, "-B", server, *command[1:]]
            owned = real_spawn(command, **kwargs)
            self.spawned.append(owned)
            return owned

        self.patch(U, "OwnedProcess",
                   type("SpawnShim", (), {"spawn": staticmethod(shim_spawn)}))

    def transport_env(self):
        # Preserve native loader inputs on Windows; the fake server only
        # consumes its synthetic RPC stream and never opens a real HOME.
        env = {key: os.environ[key] for key in
               ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP")
               if key in os.environ}
        env.update(HOME=str(self.tmp), USERPROFILE=str(self.tmp))
        return env

    def test_probe_transport_and_exclusive_attempt_directory(self):
        env = self.transport_env()
        attempt = self.tmp / "attempt"
        probe = REAL_LOADED_PROBE(self.fake_cli, self.tmp / "cwd", attempt, env)
        self.assertIsNone(probe["reason"], probe["reason"])
        self.assertFalse(probe["inventory_flagged"])
        self.assertEqual(sorted(row["eventName"] for row in probe["hooks"]),
                         sorted(U.EVENTS))
        cleanup = probe["cleanup"]
        self.assertTrue(cleanup["owned_process_exited"])
        self.assertTrue(cleanup.get("cleanup_complete") is True
                        or cleanup["owned_tree_no_running_members"] is True)
        self.assertIsNone(cleanup.get("process_group_cleanup_error"))
        self.assertTrue(self.spawned)
        for owned in self.spawned:
            self.assertTrue(owned.process.stdin.closed)
            self.assertTrue(owned.process.stdout.closed)
        journal = (attempt / "rpc.jsonl").read_text(encoding="utf-8")
        self.assertIn('"direction": "request"', journal)
        self.assertIn('"direction": "response"', journal)
        # A reused attempt directory fails exclusively and is never a pass.
        second = REAL_LOADED_PROBE(self.fake_cli, self.tmp / "cwd", attempt, env)
        self.assertIsNotNone(second["reason"])
        self.assertEqual(second["hooks"], [])

    def test_probe_transport_with_flagged_inventory(self):
        source = (self.server.read_text(encoding="utf-8")
                  .replace('{"data": [{"hooks": rows}]}',
                           '{"data": [{"hooks": rows, "errors": ["redacted"]}]}'))
        flagged = self.tmp / "fake_app_server_flagged.py"
        flagged.write_text(source, encoding="utf-8")
        real_spawn = U.OwnedProcess.spawn
        fake_cli, server = self.fake_cli, str(flagged)

        def shim_spawn(command, **kwargs):
            command = list(command)
            if command and command[0] == fake_cli:
                command = [sys.executable, "-B", server, *command[1:]]
            return real_spawn(command, **kwargs)

        self.patch(U, "OwnedProcess",
                   type("SpawnShim", (), {"spawn": staticmethod(shim_spawn)}))
        probe = REAL_LOADED_PROBE(self.fake_cli, self.tmp / "cwd",
                                  self.tmp / "attempt-flagged", self.transport_env())
        self.assertIsNone(probe["reason"])
        self.assertTrue(probe["inventory_flagged"])


@unittest.skipUnless(os.name == "nt", "native Windows PowerShell argument transport")
class TestNativePowerShellProbe(unittest.TestCase):
    def test_real_powershells_preserve_array_elements(self):
        launcher = REPO / "tools" / "validation" / "run_daily_upgrade.ps1"
        shells = [Path(os.environ["SYSTEMROOT"]) / "System32" / "WindowsPowerShell"
                  / "v1.0" / "powershell.exe"]
        pwsh = shutil.which("pwsh")
        if pwsh:
            shells.append(Path(pwsh).resolve())
        for shell in shells:
            for passthrough in (["daily", "--plan", r"C:\Path With Spaces\计划's.json"],
                                ["daily", "", 'a"b', "semi;colon", "$literal", "单引号'中文"]):
                with self.subTest(shell=shell, argv=passthrough):
                    result = U._probe_ps1_launcher(launcher, passthrough, str(shell))
                    self.assertEqual(result["real_entry"]["echoed"],
                                     ["print-argv", passthrough])


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
            # The parse probe and the real print-argv entry both consume the
            # recorded absolute shell, never a PATH re-resolution; codesign
            # verification of the pinned host fixture is the read-only
            # publisher oracle.
            if argv[1:2] == ["-n"] or "--print-argv" in argv:
                return subprocess.run(argv, capture_output=True, timeout=timeout)
            if argv[0] == "codesign" and Path(argv[-1]).is_absolute():
                return subprocess.run(argv, capture_output=True, timeout=timeout)
            if argv[1:3] == ["-B", "-c"]:
                return subprocess.run(argv, capture_output=True, timeout=timeout, env=env)
            if "-EncodedCommand" in argv and Path(argv[0]).is_absolute():
                return subprocess.run(argv, capture_output=True, timeout=timeout, env=env)
            raise AssertionError("unexpected probe command: " + repr(argv))

        self.patch(U, "_probe_run", probe)
        self.seed_old_cache()
        self.assertEqual(self.main("--preflight-commands"), 0)

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

    def test_subject_pins_helper_closure_and_host_tools(self):
        self.assertEqual(self.main("--preflight"), 0)
        subject = self.read("preflight.json")["subject"]
        self.assertEqual(subject["tool_root"], str(REPO))
        self.assertTrue(Path(subject["invocation_cwd"]).is_absolute())
        self.assertIn("tool_root", U._binding_view(subject))
        self.assertIn("invocation_cwd", U._binding_view(subject))
        self.assertIn("tools/validation/host_process_inventory.py", subject["helpers"])
        self.assertIn("tools/validation/daily_upgrade.py", subject["helpers"])
        self.assertIn("tools/validation/run_daily_upgrade.sh", subject["helpers"])
        self.assertIn("tools/validation/run_daily_upgrade.ps1", subject["helpers"])
        if sys.platform == "darwin":
            self.assertIn("ps", subject["host_tools"])
        if sys.platform == "win32":
            self.assertIn("powershell", subject["host_tools"])

    def test_helper_closure_drift_is_refused(self):
        # Mutate a pre-existing imported consumer (the scheduler command
        # runner this tool executes), not only the new inventory helper.
        self.seed_old_cache()
        self.main("--prepare")
        self.seed_installed_cache()
        prepared = self.read("prepare.json")
        self.assertIn("tools/validation/native_scheduler_batch.py", prepared["subject"]["helpers"])
        prepared["subject"]["helpers"]["tools/validation/native_scheduler_batch.py"] = "0" * 64
        (self.output / "prepare.json").write_text(json.dumps(prepared), encoding="utf-8")
        self.assertEqual(self.main("--apply"), 2)

    def test_helper_closure_covers_executed_imports(self):
        self.main("--preflight")
        helpers = self.read("preflight.json")["subject"]["helpers"]
        for consumed in ("tools/validation/native_acceptance.py",
                         "tools/validation/native_upgrade_acceptance.py",
                         "tools/validation/native_scheduler_batch.py",
                         "tools/validation/native_cli_adoption.py",
                         "tools/validation/stop_host_acceptance.py",
                         "tools/validation/host_process_inventory.py",
                         "scripts/artifact_identity.py",
                         "scripts/cg_process_tree.py",
                         "scripts/context_guard.py",
                         "tools/guard_state_migration.py"):
            self.assertIn(consumed, helpers)

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


class TestResume(DailyUpgradeCase):
    """The thin dispatcher: same receipts, same gates, one command."""

    def test_fresh_batch_completes_in_one_invocation(self):
        self.seed_target_cache()
        self.assertEqual(self.main("--resume"), 0)
        self.assertEqual(self.read("prepare.json")["status"], "prepared")
        self.assertEqual(self.read("apply.json")["installed_after"]["version"], TARGET)
        self.assertEqual(self.read("verify.json")["status"], "passed")

    def test_running_host_pauses_once_then_completes_on_rerun(self):
        self.seed_target_cache()
        self.host_status = inventory_result("running", desktop_pids=(4242,))
        self.assertEqual(self.main("--resume"), 1)
        self.assertTrue((self.output / "prepare.json").is_file())
        self.assertFalse((self.output / "apply.json").exists())
        self.assertFalse((self.output / U.JOURNAL_NAME).exists())
        # The operator quits the host and re-runs the same command.
        self.host_status = inventory_result("absent")
        self.assertEqual(self.main("--resume"), 0)
        self.assertEqual(self.read("verify.json")["status"], "passed")

    def test_interrupted_apply_resumes_to_completion(self):
        self.seed_target_cache()
        self.fake.crash_argv = [str(self.tmp / "codex"), "plugin", "marketplace",
                                "add", str(self.artifact)]
        self.assertEqual(self.main("--resume"), 2)
        self.fake.crash_argv = None
        self.assertEqual(self.main("--resume"), 0)
        self.assertEqual(self.fake.calls.count(
            [str(self.tmp / "codex"), "plugin", "marketplace", "remove", MARKET]), 1)
        self.assertEqual(self.read("verify.json")["status"], "passed")

    def test_already_current_batch_skips_apply(self):
        self.seed_target_cache()
        self.fake.installed_version = TARGET
        self.fake.registered = True
        self.fake.market_root = str(self.artifact)
        self.assertEqual(self.main("--resume"), 0)
        self.assertEqual(self.read("prepare.json")["status"], "already_current")
        self.assertFalse((self.output / "apply.json").exists())
        self.assertEqual(self.read("verify.json")["status"], "passed")

    def test_trust_pending_pause_then_pass_after_review(self):
        self.seed_target_cache()
        self.probe["hooks"] = [{**row, "trustStatus": "untrusted"}
                               for row in self.probe["hooks"]]
        self.assertEqual(self.main("--resume"), 1)
        self.assertEqual(self.read("verify.json")["status"], "hook_trust_pending")
        first_receipt = (self.output / "verify.json").read_bytes()
        self.probe["hooks"] = self.trusted_hooks()
        self.assertEqual(self.main("--resume"), 0)
        self.assertTrue((self.output / "verify-2.json").is_file())
        # The prior receipt stays byte-identical; the fresh verdict lands in
        # the next numbered receipt.
        self.assertEqual((self.output / "verify.json").read_bytes(), first_receipt)
        self.assertEqual(self.read("verify-2.json")["status"], "passed")

    def test_drift_after_prepare_is_refused_like_a_typed_command(self):
        self.seed_target_cache()
        self.main("--prepare")
        self.fake.cli_version = "codex-cli 0.43.0"
        self.assertEqual(self.main("--resume"), 2)
        self.assertFalse((self.output / "apply.json").exists())


class TestRebind(DailyUpgradeCase):
    """Controlled re-identification: same-path host bytes are the only drift."""

    def setUp(self):
        super().setUp()
        # A case-insensitive default volume would alias "Codex" onto the
        # "codex" CLI fixture; these cases mutate the host bytes, so they pin
        # a distinct desktop fixture name.
        (self.tmp / "CodexDesktop").write_bytes(b"MZ")
        self.plan_path = self.write_plan(
            desktop_executable=str(self.tmp / "CodexDesktop"))

    def rebind(self):
        return self.main("--rebind")

    def test_host_byte_change_is_the_only_accepted_drift(self):
        self.seed_target_cache()
        self.main("--prepare")
        original = (self.output / "prepare.json").read_bytes()
        old_sha = U._sha_loose(self.tmp / "CodexDesktop")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-updated-host")
        self.assertEqual(self.rebind(), 0)
        audit = self.read("rebind.json")
        self.assertEqual(audit["stage"], "rebind")
        self.assertEqual(audit["drift"], ["desktop_executable"])
        self.assertEqual(audit["desktop_executable"]["previous_sha256"], old_sha)
        self.assertNotEqual(audit["desktop_executable"]["current_sha256"], old_sha)
        # Prior receipts stay byte-identical; the new prepare receipt is bound
        # to the new host identity and records where it came from.
        self.assertEqual((self.output / "prepare.json").read_bytes(), original)
        rebound = self.read("prepare-2.json")
        self.assertEqual(rebound["stage"], "prepare")
        self.assertEqual(rebound["rebound_from"]["receipt"], "prepare.json")
        self.assertEqual(rebound["rebound_from"]["drift"], ["desktop_executable"])
        self.assertNotEqual(rebound["subject"]["desktop_executable"]["sha256"],
                            old_sha)
        # The rebound batch continues through resume, bound to prepare-2.
        self.assertEqual(self.main("--resume"), 0)
        applied = self.read("apply.json")
        self.assertEqual(applied["prepared_sha256"],
                         U.base.sha(self.output / "prepare-2.json"))
        self.assertEqual(self.read("verify.json")["status"], "passed")

    def test_cli_drift_is_refused_with_its_own_category(self):
        self.main("--prepare")
        self.fake.cli_version = "codex-cli 0.43.0"
        self.assertEqual(self.rebind(), 2)
        self.assertFalse((self.output / "rebind.json").exists())

    def test_artifact_and_plan_drift_are_refused_together(self):
        self.main("--prepare")
        other = make_artifact(self.tmp / "artifact-2")
        self.plan_path = self.write_plan(artifact_dir=str(other))
        self.assertEqual(self.rebind(), 2)
        self.assertFalse((self.output / "prepare-2.json").exists())

    def test_sandbox_marker_change_is_refused(self):
        self.main("--prepare")
        (self.tmp / "CodexSandboxService").write_bytes(b"helper-v2")
        self.assertEqual(self.rebind(), 2)

    def test_desktop_path_change_is_refused(self):
        self.main("--prepare")
        (self.tmp / "CodexDesktop2").write_bytes(b"MZ")
        self.plan_path = self.write_plan(desktop_executable=str(self.tmp / "CodexDesktop2"))
        self.assertEqual(self.rebind(), 2)

    def test_started_batch_is_never_rebound(self):
        self.seed_target_cache()
        self.main("--prepare")
        self.fake.crash_argv = [str(self.tmp / "codex"), "plugin", "marketplace",
                                "add", str(self.artifact)]
        self.assertEqual(self.main("--apply"), 2)
        self.assertTrue((self.output / U.JOURNAL_NAME).is_file())
        self.assertEqual(self.rebind(), 2)
        self.fake.crash_argv = None
        self.assertEqual(self.main("--apply"), 0)
        self.assertEqual(self.rebind(), 2)

    def test_repeated_host_updates_rebind_with_exclusive_receipts(self):
        self.seed_target_cache()
        self.main("--prepare")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-host-v2")
        self.assertEqual(self.rebind(), 0)
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-host-v3")
        self.assertEqual(self.rebind(), 0)
        self.assertTrue((self.output / "prepare-2.json").is_file())
        self.assertTrue((self.output / "prepare-3.json").is_file())
        self.assertTrue((self.output / "rebind.json").is_file())
        self.assertTrue((self.output / "rebind-2.json").is_file())
        self.assertEqual(self.read("prepare-3.json")["rebound_from"]["receipt"],
                         "prepare-2.json")
        self.assertEqual(self.main("--resume"), 0)

    def test_rebind_without_a_batch_is_refused(self):
        self.assertEqual(self.rebind(), 2)

    # ---- trusted-publisher boundary -------------------------------------

    def test_signed_host_update_with_same_publisher_rebinds(self):
        self.seed_target_cache()
        self.main("--prepare")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-updated-host")
        self.assertEqual(self.rebind(), 0)
        audit = self.read("rebind.json")
        self.assertEqual(audit["drift"], ["desktop_executable"])

    def test_unverified_new_host_bytes_are_refused(self):
        self.main("--prepare")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-updated-host")
        self.publisher = {"method": "fixture", "verified": False,
                          "identity": None, "reason": "unsigned"}
        self.assertEqual(self.rebind(), 2)
        refused = ("do not satisfy the prepared publisher requirement"
                   if sys.platform == "darwin"
                   else "not a verified publisher-signed update")
        self.assertIn(refused, self.last_stderr())

    def test_publisher_change_is_refused(self):
        self.main("--prepare")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-other-publisher")
        self.publisher = {"method": "fixture", "verified": True,
                          "identity": "OTHERTEAM"}
        self.assertEqual(self.rebind(), 2)
        self.assertIn("different publisher", self.last_stderr())

    def test_publisher_verification_unavailable_is_refused(self):
        self.main("--prepare")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-updated-host")
        self.publisher = {"method": None, "verified": False, "identity": None,
                          "reason": "codesign missing"}
        self.assertEqual(self.rebind(), 2)

    def test_preparation_without_publisher_record_is_refused(self):
        # Receipts written before the publisher field existed (or with it
        # stripped, re-digested so the receipt itself stays internally
        # consistent) are never upgraded in place.
        self.main("--prepare")
        prepared = self.read("prepare.json")
        del prepared["subject"]["desktop_executable"]["publisher"]
        prepared["subject_sha256"] = U.base.digest(prepared["subject"])
        (self.output / "prepare.json").write_text(json.dumps(prepared),
                                                  encoding="utf-8")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-updated-host")
        self.assertEqual(self.rebind(), 2)
        self.assertIn("did not record a verified publisher identity",
                      self.last_stderr())

    def test_subject_records_the_publisher_observation(self):
        self.main("--preflight")
        subject = self.read("preflight.json")["subject"]
        self.assertEqual(subject["desktop_executable"]["publisher"],
                         self.publisher)

    @unittest.skipUnless(sys.platform == "darwin", "native codesign oracle")
    def test_real_codesign_refuses_unsigned_fixture(self):
        # An unsigned fixture has no team identity at all: the publisher
        # observation refuses before any requirement probe, and the real
        # (unpatched) seam wrapper records it as unverified.
        with self.assertRaises(U.UpgradeError):
            U._codesign_publisher(self.tmp / "CodexDesktop", {})
        publisher = self._real_host_publisher(self.tmp / "CodexDesktop", {}, {})
        self.assertFalse(publisher["verified"])
        self.assertIsNone(publisher["identity"])

    # ---- interrupted-rebind adoption family ------------------------------

    def test_orphan_prepare_is_never_adopted_and_rebind_recovers(self):
        self.seed_target_cache()
        self.main("--prepare")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-updated-host")
        restore = self.failing_audit_writer("rebind.json")
        self.assertEqual(self.rebind(), 2)
        restore()
        self.assertTrue((self.output / "prepare-2.json").is_file())
        self.assertFalse((self.output / "rebind.json").is_file())
        orphan_bytes = (self.output / "prepare-2.json").read_bytes()
        # resume refuses to adopt the unaudited receipt.
        self.assertEqual(self.main("--resume"), 2)
        self.assertIn("interrupted rebind", self.last_stderr())
        # recovery: a fresh rebind writes the next exclusive pair from the
        # last audited receipt, and the orphan stays as retained evidence.
        self.assertEqual(self.rebind(), 0)
        self.assertTrue((self.output / "rebind.json").is_file())
        self.assertTrue((self.output / "prepare-3.json").is_file())
        self.assertEqual((self.output / "prepare-2.json").read_bytes(),
                         orphan_bytes)
        self.assertEqual(self.main("--resume"), 0)
        self.assertEqual(self.read("apply.json")["prepared_sha256"],
                         U.base.sha(self.output / "prepare-3.json"))

    def test_dangling_audit_is_refused_everywhere(self):
        self.seed_target_cache()
        self.main("--prepare")
        audit = {"schema": U.REPORT, "stage": "rebind", "status": "rebound",
                 "rebound_to": {"receipt": "prepare-9.json",
                                "subject_sha256": "0" * 64}}
        (self.output / "rebind.json").write_text(json.dumps(audit),
                                                 encoding="utf-8")
        self.assertEqual(self.main("--resume"), 2)
        self.assertIn("references missing prepare receipt", self.last_stderr())
        self.assertEqual(self.rebind(), 2)

    def test_tampered_newest_prepare_is_never_adopted(self):
        self.seed_target_cache()
        self.main("--prepare")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-updated-host")
        self.assertEqual(self.rebind(), 0)
        rebound = self.read("prepare-2.json")
        rebound["subject_sha256"] = "1" * 64
        (self.output / "prepare-2.json").write_text(json.dumps(rebound),
                                                    encoding="utf-8")
        self.assertEqual(self.main("--resume"), 2)
        self.assertIn("content does not match its subject digest",
                      self.last_stderr())

    def test_apply_refuses_stale_or_orphan_explicit_targets(self):
        self.seed_target_cache()
        self.main("--prepare")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-updated-host")
        self.assertEqual(self.rebind(), 0)
        stale = self.main("--apply", "--prepared-result",
                          str(self.output / "prepare.json"))
        self.assertEqual(stale, 2)
        self.assertIn("current adoptable prepare receipt", self.last_stderr())
        # The adoptable receipt is accepted and completes the batch.
        self.assertEqual(self.main("--apply", "--prepared-result",
                                   str(self.output / "prepare-2.json")), 0)

    def test_forged_audit_digest_does_not_adopt(self):
        self.seed_target_cache()
        self.main("--prepare")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-updated-host")
        self.failing_audit_writer("rebind.json")
        self.assertEqual(self.rebind(), 2)
        # An audit binding the right receipt name but the wrong subject
        # digest must not adopt the orphan.
        forged = {"schema": U.REPORT, "stage": "rebind", "status": "rebound",
                  "rebound_to": {"receipt": "prepare-2.json",
                                 "subject_sha256": "2" * 64}}
        (self.output / "rebind.json").write_text(json.dumps(forged),
                                                 encoding="utf-8")
        self.assertEqual(self.main("--resume"), 2)
        self.assertIn("interrupted rebind", self.last_stderr())


class TestCodesignProvenance(DailyUpgradeCase):
    """The real codesign requirement path: anchor + trusted + OU binding.

    The fixture fakes the codesign oracles but the code under test must
    still construct and pass the actual ``--test-requirement`` argument; a
    mocked ``verified=True`` alone would prove nothing.
    """

    TEAM = "2DC432GLL2"
    DETAIL = (f"Authority=Developer ID Application: OpenAI (application) ({TEAM})\n"
              f"TeamIdentifier={TEAM}\n").encode()

    def recorder(self, *, verify_rc=0, anchor_rc=0):
        calls = []

        def probe(argv, env, timeout=30.0):
            argv = [str(item) for item in argv]
            calls.append(argv)
            rc = anchor_rc if "--test-requirement" in argv else verify_rc
            return completed(argv, rc=rc, stderr=self.DETAIL)

        self.patch(U, "_probe_run", probe)
        return calls

    def requirement_arg(self, calls):
        requirements = [argv[argv.index("--test-requirement") + 1]
                        for argv in calls if "--test-requirement" in argv]
        self.assertEqual(len(requirements), 1)
        return requirements[0]

    def test_trusted_requirement_is_actually_passed(self):
        calls = self.recorder()
        publisher = U._codesign_publisher(self.tmp / "CodexDesktop", {})
        self.assertTrue(publisher["verified"])
        self.assertEqual(publisher["identity"], self.TEAM)
        self.assertIn("codesign --verify --strict", " ".join(calls[0]))
        requirement = self.requirement_arg(calls)
        self.assertEqual(
            requirement,
            '=anchor apple generic and anchor trusted and '
            'certificate leaf[subject.OU] = "2DC432GLL2"')
        self.assertIn("anchor apple generic", requirement)
        self.assertIn("anchor trusted", requirement)
        self.assertIn('certificate leaf[subject.OU] = "%s"' % self.TEAM,
                      requirement)

    def test_unanchored_or_untrusted_requirement_is_refused(self):
        self.recorder(anchor_rc=3)
        publisher = U._codesign_publisher(self.tmp / "CodexDesktop", {})
        self.assertFalse(publisher["verified"])
        self.assertIsNone(publisher["identity"])
        self.assertIn("trust-anchor requirement failed", publisher["reason"])
        self.assertEqual(publisher["anchor_requirement_rc"], 3)

    def test_team_format_is_validated_before_any_requirement_probe(self):
        for team in ("2dc432gll2", "2DC432GLL", "2DC432GLL20", "2DC432G!L2", "adhoc"):
            with self.subTest(team=team):
                calls = self.recorder()
                detail = ("TeamIdentifier=%s\n" % team).encode()
                self.patch(U, "_probe_run",
                           lambda argv, env, timeout=30.0, detail=detail: completed(
                               argv, rc=0, stderr=detail))
                with self.assertRaises(U.UpgradeError):
                    U._codesign_publisher(self.tmp / "CodexDesktop", {})
                # No requirement probe may run with an invalid identity.
                self.assertFalse(any("--test-requirement" in [str(a) for a in argv]
                                     for argv in calls[2:]))  # after verify/-dv pair

    def test_rebind_audits_against_the_prepared_team(self):
        calls = self.recorder()
        publisher = U._codesign_publisher(self.tmp / "CodexDesktop", {},
                                          expected_team=self.TEAM)
        self.assertTrue(publisher["verified"])
        self.assertEqual(self.requirement_arg(calls),
                         '=anchor apple generic and anchor trusted and '
                         'certificate leaf[subject.OU] = "%s"' % self.TEAM)

    def test_self_reported_team_is_never_the_binding(self):
        # A host whose -dv self-reports a different team fails the prepared
        # requirement even if its own signature is internally valid.
        self.recorder()
        detail = "TeamIdentifier=AAAAABBBBB\n".encode()
        self.patch(U, "_probe_run",
                   lambda argv, env, timeout=30.0: completed(argv, rc=0, stderr=detail))
        publisher = U._codesign_publisher(self.tmp / "CodexDesktop", {},
                                          expected_team=self.TEAM)
        self.assertFalse(publisher["verified"])
        self.assertIn("differs from the audited publisher", publisher["reason"])

class TestReceiptIntegrityFamily(DailyUpgradeCase):
    """The four reviewed bypass counterexamples, covered per entry point.

    A stale, removed, orphaned or content-modified prepare receipt must be
    refused by every entry — apply, verify, resume, rebind — whichever
    target the operator names; only the adopted chain may drive a swap.
    """

    def setUp(self):
        super().setUp()
        # Distinct desktop fixture name: a case-insensitive default volume
        # would alias "Codex" onto the "codex" CLI fixture.
        (self.tmp / "CodexDesktop").write_bytes(b"MZ")
        self.plan_path = self.write_plan(
            desktop_executable=str(self.tmp / "CodexDesktop"))

    def prepare_and_rebind(self):
        self.seed_target_cache()
        assert self.main("--prepare") == 0
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-host-v2")
        assert self.main("--rebind") == 0

    def explicit(self, action, receipt):
        return self.main(action, "--prepared-result", str(self.output / receipt))

    def restore_initial_host(self):
        (self.tmp / "CodexDesktop").write_bytes(b"MZ")

    def entries_refuse(self, fragments, allow_rebind_default_recovery=False):
        # The explicit and automatic entries refuse the broken state and
        # nothing installs; only the rebind default may recover the batch by
        # writing the next exclusive pair from the last audited receipt.
        cases = [
            ("apply stale initial", lambda: self.explicit("--apply", "prepare.json")),
            ("verify stale initial", lambda: self.explicit("--verify", "prepare.json")),
            ("resume", lambda: self.main("--resume")),
            ("rebind stale initial", lambda: self.explicit("--rebind", "prepare.json")),
        ]
        for name, entry in cases:
            with self.subTest(entry=name):
                before = sorted(path.name for path in self.output.glob("*.json"))
                self.assertEqual(entry(), 2, name)
                self.assertTrue(any(fragment in self.last_stderr() for fragment in fragments),
                                (name, self.last_stderr()))
                self.assertFalse((self.output / "apply.json").exists(), name)
                self.assertEqual(sorted(path.name for path in self.output.glob("*.json")),
                                 before, name)
        with self.subTest(entry="rebind default"):
            before = sorted(path.name for path in self.output.glob("*.json"))
            code = self.main("--rebind")
            if allow_rebind_default_recovery:
                self.assertEqual(code, 0)
            else:
                self.assertEqual(code, 2)
                self.assertTrue(any(fragment in self.last_stderr() for fragment in fragments))
            self.assertEqual(self.fake.installed_version, OLD)
            if not allow_rebind_default_recovery:
                self.assertEqual(sorted(path.name for path in self.output.glob("*.json")),
                                 before)

    def scenario_a_removed_audited_receipt(self):
        self.prepare_and_rebind()
        (self.output / "prepare-2.json").unlink()
        self.restore_initial_host()

    def scenario_b_stale_explicit_rebind_source(self):
        self.prepare_and_rebind()
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-host-v3")

    def scenario_c_modified_receipt_content(self):
        self.prepare_and_rebind()
        receipt = self.read("prepare-2.json")
        receipt["subject"]["installed_before"]["installed"] = False
        (self.output / "prepare-2.json").write_text(json.dumps(receipt),
                                                    encoding="utf-8")
        self.host_status = inventory_result("running", desktop_pids=(4242,))

    def scenario_d_gap_behind_adopted_chain(self):
        self.seed_target_cache()
        self.main("--prepare")
        # Distinct from every prior scenario's host bytes so the drift gate
        # sees a real change even when this matrix shares one fixture.
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-host-vD")
        restore = self.failing_audit_writer("rebind.json")
        self.assertEqual(self.main("--rebind"), 2)
        restore()
        self.assertEqual(self.main("--rebind"), 0)  # recovery: audited prepare-3
        (self.output / "prepare-2.json").unlink()
        self.restore_initial_host()

    def test_counterexamples_are_refused_by_every_entry(self):
        drifted = "preparation and execution drifted"
        table = [
            ("A removed audited receipt", self.scenario_a_removed_audited_receipt,
             ("references missing prepare receipt",), False),
            ("B stale explicit rebind source", self.scenario_b_stale_explicit_rebind_source,
             ("current adoptable prepare receipt", drifted), True),
            ("C modified receipt content", self.scenario_c_modified_receipt_content,
             ("content does not match its subject digest",), True),
            ("D numbering gap", self.scenario_d_gap_behind_adopted_chain,
             ("was removed while",), False),
        ]
        for name, builder, fragments, recovery in table:
            with self.subTest(scenario=name):
                # Each scenario runs in its own exclusive batch directory;
                # prepare creates it exclusively.
                self.output = self.tmp / ("batch-" + name.split()[0])
                builder()
                self.entries_refuse(fragments, recovery)

    def test_scenario_b_positive_default_rebind_chains_the_adopted_receipt(self):
        self.scenario_b_stale_explicit_rebind_source()
        self.assertEqual(self.main("--rebind"), 0)
        rebound = self.read("prepare-3.json")
        self.assertEqual(rebound["rebound_from"]["receipt"], "prepare-2.json")
        self.assertEqual(self.main("--resume"), 0)
        self.assertEqual(self.read("apply.json")["prepared_sha256"],
                         U.base.sha(self.output / "prepare-3.json"))

    def test_scenario_d_positive_orphan_behind_chain_still_recovers(self):
        self.seed_target_cache()
        self.main("--prepare")
        (self.tmp / "CodexDesktop").write_bytes(b"MZ-host-v2")
        restore = self.failing_audit_writer("rebind.json")
        self.assertEqual(self.main("--rebind"), 2)
        restore()
        self.assertEqual(self.main("--rebind"), 0)
        # The orphan stays behind the adopted chain end; the batch continues.
        self.assertTrue((self.output / "prepare-2.json").is_file())
        self.assertEqual(self.main("--resume"), 0)
        self.assertEqual(self.read("apply.json")["prepared_sha256"],
                         U.base.sha(self.output / "prepare-3.json"))


class TestResumeWait(DailyUpgradeCase):
    """The bounded in-process wait: host quits, one command continues."""

    def wait_main(self, *args):
        import contextlib
        import io
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = U.main(["--plan", str(self.plan_path), "--output",
                           str(self.output), "--wait", *args])
        self._stderr = buffer.getvalue()
        return code

    def test_wait_continues_after_host_exit(self):
        self.seed_target_cache()
        observations = [inventory_result("running", desktop_pids=(4242,)),
                        inventory_result("running", desktop_pids=(4242,)),
                        inventory_result("absent")]
        state = {"polls": 0}

        def flaky_inventory(desktop, markers, host_tools=None):
            index = min(state["polls"], len(observations) - 1)
            state["polls"] += 1
            return observations[index]

        self.patch(U, "_host_inventory", flaky_inventory)
        self.patch(U, "_sleep", lambda seconds: None)
        self.assertEqual(self.wait_main("--resume"), 0)
        self.assertGreaterEqual(state["polls"], 2)
        self.assertEqual(self.read("verify.json")["status"], "passed")

    def test_wait_deadline_exits_pending(self):
        self.seed_target_cache()
        self.patch(U, "_host_inventory",
                   lambda desktop, markers, host_tools=None:
                   inventory_result("running", desktop_pids=(4242,)))
        self.patch(U, "_sleep", lambda seconds: None)
        clock = {"now": 0.0}

        def fake_now():
            clock["now"] += 100.0
            return clock["now"]

        self.patch(U, "_now", fake_now)
        self.assertEqual(self.wait_main("--resume", "--wait-minutes", "1"), 1)
        self.assertFalse((self.output / "apply.json").exists())
        self.assertIn("Desktop host must be observed absent", self.last_stderr())

    def test_wait_requires_resume_and_bounded_minutes(self):
        with self.assertRaises(SystemExit):
            self.main("--apply", "--wait")
        with self.assertRaises(SystemExit):
            self.wait_main("--resume", "--wait-minutes", "0")
        with self.assertRaises(SystemExit):
            self.wait_main("--resume", "--wait-minutes", "721")
        with self.assertRaises(SystemExit):
            self.main("--verify", "--wait-minutes", "30")


if __name__ == "__main__":
    unittest.main()
