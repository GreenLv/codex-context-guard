import copy
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "bt", HERE.parent / "tools/validation/native_between_turns_acceptance.py"
)
bt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bt)
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from tools.validation import native_upgrade_acceptance as u  # noqa: E402


def inv(source):
    return {
        "data": [
            {
                "hooks": [
                    {
                        "eventName": e,
                        "sourcePath": str(source),
                        "source": "plugin",
                        "handlerType": "command",
                        "enabled": True,
                        "trustStatus": "trusted",
                        "key": "k" + e,
                        "currentHash": "h" + e,
                        "displayOrder": 0,
                    }
                    for e in sorted(bt.EVENTS)
                ]
            }
        ]
    }


def state(turn):
    return {
        "session": {"id": "old"},
        "requirements": [
            {
                "id": "R001",
                "sha256": "a" * 64,
                "status": "pending",
                "work_unit_id": "W1",
            }
        ],
        "compactions": [],
        "mode": {"active": True},
        "prompts": [{"turn_id": turn}],
    }


class FakeClient:
    def __init__(self, ctx, trust=0):
        self.ctx = ctx
        self.trust = trust
        self.calls = []
        self.rows = []
        self.n = 0
        self.owned = types.SimpleNamespace(
            process=types.SimpleNamespace(pid=42, poll=lambda: None)
        )
        self.approved = {
            (e, str(ctx["old_root"] / "hooks/hooks.json")): {} for e in bt.EVENTS
        }

    def start(self):
        return "old" if self.n == 0 else "fresh"

    def observed_turn(self, thread, prompt):
        self.n += 1
        return ("t" + str(self.n), [])

    def check_provider(self):
        return {
            "model_provider": "openai",
            "endpoint_policy": "official_default",
            "custom_catalog": False,
        }

    def inventory_for(self, sources):
        self.calls.append("inventory")
        if self.trust:
            self.trust -= 1
            raise bt.Pending("normal Hook review pending")
        return {(e, str(sources[0])): {} for e in bt.EVENTS}

    def close(self):
        if hasattr(self, "log"):
            self.log.close()
        return {
            "cleanup_complete": True,
            "owned_process_exited": True,
            "owned_tree_no_running_members": True,
            "process_group_cleanup_error": None,
            "job_close_confirmed": True,
            "job_assignment_confirmed": True,
        }


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p = Path(self.tmp.name).resolve()
        self.repo = self.p / "repo"
        self.repo.mkdir()
        self.home = self.p / "home"
        self.home.mkdir()
        self.work = self.p / "work"
        self.work.mkdir()
        (self.work / "README.md").write_text("read")
        for name in ("cli", "tool", "plan", "archive"):
            (self.p / name).write_text(name)
        self.artifact = self.p / "artifact"
        self.artifact.mkdir()
        (self.artifact / ".codex-plugin").mkdir()
        (self.artifact / ".codex-plugin/distribution-manifest.json").write_text(
            "manifest"
        )
        self.old = self.home / "old"
        self.old.mkdir()
        self.new = self.home / "new"
        self.normalized = {"mode": "between-turns", "old_artifact_dir": str(self.old)}
        self.plan = {
            "schema": bt.PLAN,
            "transition_strategy": "between-turns",
            "declared_pause": True,
            "commit": "a" * 40,
            "old_version": "0.17.3",
            "target_version": "0.18.0",
            "zip_sha256": bt.sha(self.p / "archive"),
            "runtime_sha256": "b" * 64,
            "tool_sha256": bt.sha(self.p / "tool"),
            "cli_sha256": bt.sha(self.p / "cli"),
            "maintained_plan_sha256": bt.sha(self.p / "plan"),
            "zip": str(self.p / "archive"),
            "native_read_sha256": bt.sha(self.work / "README.md"),
            "_native_plan_sha256": bt.sha(self.p / "plan"),
        }
        self.u = types.SimpleNamespace(
            _private_directory=lambda p: None,
            source_files=lambda p: {"a": "b"},
            _pending=u._pending,
            _state_projection=u._state_projection,
            validate_continuity=u.validate_continuity,
            digest=u.digest,
            _paired=lambda rows, inv, thread, event, turn: [
                {"sourcePath": next(iter(inv))[1]}
            ],
        )

        def read_bound(path, *, stage, mode):
            data = json.loads(path.read_text())
            bt.require(
                data["schema"] == "cg-daily-upgrade-result/v2"
                and data["stage"] == stage
                and data["mode"] == mode,
                "bound mismatch",
            )
            return data, bt.sha(path)

        self.daily = types.SimpleNamespace(
            _read_bound_result=read_bound,
            _binding_view=lambda v: {
                k: x
                for k, x in v.items()
                if k
                not in (
                    "installed_before",
                    "host",
                    "data_policy",
                    "commands",
                )
            },
            _read_journal=lambda p: [json.loads(x) for x in p.read_text().splitlines()],
            _runtime_activity=lambda *a, compatibility, allow_absent: {
                "status": "clear",
                "candidates": [],
                "compatibility": compatibility,
                "allow_absent": allow_absent,
            },
            _inventory_host_tools=lambda *a: {},
            _scrubbed_env=lambda: {},
            _helper_identities=lambda: {"helper": "ok"},
            _verify_between_turns_compatibility=lambda *a: {"verdict": "compatible"},
            JOURNAL_SCHEMA_V2="cg-daily-upgrade-journal/v2",
        )
        self.ctx = {
            "output": self.p / "out",
            "home": self.home,
            "workspace": self.work,
            "data_root": self.home / "data",
            "repo": self.repo,
            "cli": self.p / "cli",
            "tool": self.p / "tool",
            "maintained_plan": self.p / "plan",
            "artifact": self.artifact,
            "old_root": self.old,
            "new_root": self.new,
            "tool_output": self.p / "out" / "maintained",
            "wait": 5,
            "activity_wait": 5,
            "read_file": self.work / "README.md",
            "files": {"a": "b"},
            "u": self.u,
            "daily": self.daily,
            "normalized_plan": self.normalized,
            "compatibility": {"verdict": "compatible"},
            "native_plan_path": self.p / "plan",
            "helpers": {"helper": "ok"},
            "producer_sha256": bt.sha(Path(bt.__file__).resolve()),
            "old_zip": self.p / "archive",
            "old_files": {"a": "b"},
            "art": types.SimpleNamespace(
                compare_artifact=lambda *a: None,
                distribution_manifest=lambda *a: {"a": "b"},
            ),
        }
        self.client = FakeClient(self.ctx)
        self.calls = []
        self.resume_status = "passed"
        self.snapshots = [
            {
                "root": "data",
                "sha256": "1" * 64,
                "state": state("t1"),
                "scope": {"current": ["R001"], "ancestor": []},
            },
            {
                "root": "data",
                "sha256": "2" * 64,
                "state": state("t2"),
                "scope": {"current": ["R001"], "ancestor": []},
            },
        ]

    def tearDown(self):
        if hasattr(self.client, "log") and not self.client.log.closed:
            self.client.log.close()
        self.tmp.cleanup()

    def write_receipts(self):
        self.new.mkdir(exist_ok=True)
        out = self.ctx["tool_output"]
        out.mkdir(parents=True)
        subject = {
            "plan_sha256": u.digest(self.normalized),
            "tool_sha256": self.plan["tool_sha256"],
            "daily_home": str(self.home),
            "cli": {"sha256": self.plan["cli_sha256"], "path": str(self.p / "cli")},
            "artifact": {
                "path": str(self.artifact),
                "version": "0.18.0",
                "manifest_sha256": bt.sha(
                    self.artifact / ".codex-plugin/distribution-manifest.json"
                ),
            },
            "helpers": self.ctx["helpers"],
            "python": {
                "path": str(Path(sys.executable).resolve()),
                "sha256": bt.sha(Path(sys.executable).resolve()),
            },
            "installed_before": {"version": "0.17.3"},
            "compatibility": {"verdict": "compatible"},
        }
        prepared = {
            "schema": "cg-daily-upgrade-result/v2",
            "stage": "prepare",
            "mode": "between-turns",
            "status": "prepared",
            "subject": subject,
            "subject_sha256": u.digest(subject),
        }
        (out / "prepare.json").write_text(json.dumps(prepared))
        prep_sha = bt.sha(out / "prepare.json")
        binding = u.digest(self.daily._binding_view(subject))
        installed = {
            "registered": True,
            "installed": True,
            "version": "0.18.0",
            "market_root": str(self.artifact),
            "cache_path": str(self.new),
        }
        base = {
            "schema": "cg-daily-upgrade-result/v2",
            "mode": "between-turns",
            "prepared_sha256": prep_sha,
            "subject_sha256": binding,
        }
        (out / "apply.json").write_text(
            json.dumps(
                {
                    **base,
                    "stage": "apply",
                    "status": "applied",
                    "installed_after": installed,
                }
            )
        )
        self.verify_base = {
            **base,
            "stage": "verify",
            "installed_after": installed,
            "artifact_parity": "passed",
            "fresh_client_loaded": "new",
        }
        (out / "verify.json").write_text(
            json.dumps({**self.verify_base, "status": self.resume_status})
        )
        argv = [str(self.p / "cli"), "plugin", "add", bt.ENTRY, "--json"]
        events = [
            {
                "event": "begin",
                "schema": self.daily.JOURNAL_SCHEMA_V2,
                "mode": "between-turns",
                "subject_sha256": binding,
                "prepared_sha256": prep_sha,
            },
            {"event": "intent", "stage": "plugin_add", "argv": argv},
            {
                "event": "fact",
                "stage": "plugin_add",
                "argv": argv,
                "status": "completed",
                "exit_code": 0,
            },
            {"event": "note", "stage": "apply_complete", "message": "done"},
        ]
        (out / "apply-events.jsonl").write_text(
            "".join(json.dumps(e) + "\n" for e in events)
        )
        applied_path = out / "apply.json"
        applied = json.loads(applied_path.read_text())
        applied["commands"] = [e for e in events if e.get("event") == "fact"]
        applied_path.write_text(json.dumps(applied))

    def maintained(self, c, action, verify_output=None):
        self.calls.append(action)
        if action == "--resume":
            self.write_receipts()
            return {
                "exit_code": 1 if self.resume_status == "hook_trust_pending" else 0,
                "cleanup": {
                    "cleanup_complete": True,
                    "owned_process_exited": True,
                    "owned_tree_no_running_members": True,
                    "process_group_cleanup_error": None,
                    "job_close_confirmed": True,
                    "job_assignment_confirmed": True,
                },
            }
        self.assertEqual(action, "--verify")
        verify_output.write_text(json.dumps({**self.verify_base, "status": "passed"}))
        return {
            "exit_code": 0,
            "cleanup": {
                "cleanup_complete": True,
                "owned_process_exited": True,
                "owned_tree_no_running_members": True,
                "process_group_cleanup_error": None,
                "job_close_confirmed": True,
                "job_assignment_confirmed": True,
            },
        }

    def execute(self, **kwargs):
        git = types.SimpleNamespace(stdout=self.plan["commit"] + "\n")
        with (
            mock.patch.object(bt, "snapshot", side_effect=self.snapshots),
            mock.patch.object(bt, "official_list", return_value={"version": "0.18.0"}),
            mock.patch.object(bt, "verify_read_tool"),
            mock.patch.object(bt, "independent_verify"),
            mock.patch.object(bt, "verify_zip"),
            mock.patch.dict(
                bt.OLD_RELEASES, {"0.17.3": {"zip_sha256": bt.sha(self.p / "archive")}}
            ),
            mock.patch.object(bt.subprocess, "run", return_value=git),
        ):

            def factory():
                self.client.log = (self.ctx["output"] / "rpc.jsonl").open(
                    "x", encoding="utf8"
                )
                return self.client

            return bt.run(
                self.plan,
                self.ctx,
                client_factory=factory,
                apply=kwargs.pop("apply", self.maintained),
                sleeper=lambda n: None,
                **kwargs,
            )

    def test_success_old_compatible_fresh_new_and_optional_os_path(self):
        result = self.execute()
        self.assertEqual(result["status"], "passed_cli_native")
        self.assertEqual(self.calls, ["--resume"])
        self.assertEqual(
            result["gates"]["old_model"]["runtime_classification"],
            "old_or_new_compatible",
        )
        self.assertEqual(
            result["gates"]["fresh_model"]["runtime_os_path"]["status"], "unknown"
        )
        self.assertEqual(result["gui"], "unobserved")
        boundary = json.loads(
            (self.ctx["output"] / "between-turn-boundary.json").read_text()
        )
        self.assertEqual(
            boundary["runtime_activity_samples"][-1]["compatibility"],
            self.ctx["compatibility"],
        )
        self.assertIs(boundary["runtime_activity_samples"][-1]["allow_absent"], False)

    def test_trust_pending_continues_same_batch_verify_only(self):
        self.resume_status = "hook_trust_pending"
        self.client.trust = 2
        result = self.execute()
        self.assertEqual(result["status"], "passed_cli_native")
        self.assertEqual(self.calls, ["--resume", "--verify"])
        self.assertEqual(len(self.client.calls), 3)
        self.assertTrue(result["cleanup"]["cleanup_complete"])

    def test_trust_timeout_preserves_apply_without_repeat(self):
        self.resume_status = "hook_trust_pending"
        self.client.trust = 100
        times = iter([0, 6])
        result = self.execute(clock=lambda: next(times))
        self.assertEqual(result["status"], "pending")
        self.assertIn("continuation unavailable", result["reason"])
        self.assertEqual(self.calls, ["--resume"])

    def test_nonzero_except_trust_pending_is_failure(self):
        result = self.execute(apply=lambda *a, **k: {"exit_code": 2})
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["stage"], "apply")

    def test_exit_one_without_expected_verify_receipt_is_failure(self):
        self.resume_status = "loaded_unknown"
        result = self.execute()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.calls, ["--resume"])

    def test_lost_pending_state_fails(self):
        self.snapshots[1]["state"]["requirements"] = []
        result = self.execute()
        self.assertEqual(result["stage"], "old_continuation")
        self.assertEqual(result["status"], "failed")

    def test_mismatched_prepare_digest_is_refused(self):
        self.write_receipts = lambda: None
        result = self.execute()
        self.assertEqual(result["stage"], "apply")
        self.assertEqual(result["status"], "failed")

    def test_changed_tool_fails_before_command(self):
        (self.p / "tool").write_text("changed")
        result = self.execute()
        self.assertEqual(result["stage"], "apply")
        self.assertEqual(self.calls, [])

    def test_unconfirmed_cleanup_fails(self):
        self.client.close = lambda: {"cleanup_complete": False}
        self.assertEqual(self.execute()["status"], "failed_cleanup")

    def test_protocol_and_pause_rejected_before_home_access(self):
        for change in (
            {"transition_strategy": "finish-old"},
            {"declared_pause": False},
        ):
            plan = copy.deepcopy(self.plan)
            plan.update(change)
            with self.assertRaises(bt.Refused):
                bt.preflight(plan, self.p / "out")

    def test_other_plugins_allowed_unknown_ccg_source_refused(self):
        src = (
            self.home
            / "plugins/cache/codex-context-guard/context-guard/0.17.3/hooks/hooks.json"
        )
        base = src.parents[2]
        rows = inv(src)
        rows["data"][0]["hooks"].append(
            {"sourcePath": str(self.home / "plugins/cache/other/item/hooks/hooks.json")}
        )
        self.assertEqual(len(bt.product_inventory(u, rows, base, [src])), 9)
        rows["data"][0]["hooks"].append(
            {"sourcePath": str(base / "0.99.0/hooks/hooks.json")}
        )
        with self.assertRaises(bt.Refused):
            bt.product_inventory(u, rows, base, [src])

    def test_untrusted_inventory_is_pending(self):
        src = (
            self.home
            / "plugins/cache/codex-context-guard/context-guard/0.17.3/hooks/hooks.json"
        )
        rows = inv(src)
        rows["data"][0]["hooks"][0]["trustStatus"] = "untrusted"
        with self.assertRaises(bt.Pending):
            bt.product_inventory(u, rows, src.parents[2], [src])

    def test_pair_oracle_enforces_same_run_and_completed(self):
        src = str(self.old / "hooks/hooks.json")
        inventory = u._inventory(inv(src), {src: "old"})

        def row(method, rid, status=None):
            run = {
                "id": rid,
                "eventName": "stop",
                "sourcePath": src,
                "source": "plugin",
                "handlerType": "command",
                "displayOrder": 0,
                "executionMode": "sync",
            }
            if status:
                run.update(status=status, durationMs=1)
            return {
                "direction": "response",
                "message": {
                    "method": method,
                    "params": {"threadId": "old", "turnId": "t1", "run": run},
                },
            }

        start = row("hook/started", "r1")
        self.assertEqual(
            len(
                u._paired(
                    [start, row("hook/completed", "r1", "completed")],
                    inventory,
                    "old",
                    "stop",
                    turn="t1",
                )
            ),
            1,
        )
        for bad in (
            [start, row("hook/completed", "r2", "completed")],
            [start, row("hook/completed", "r1", "failed")],
        ):
            with self.assertRaises(Exception):
                u._paired(bad, inventory, "old", "stop", turn="t1")

    def test_read_command_only_accepts_expected_tracked_name(self):
        self.assertTrue(
            bt.approved_read(u, "/bin/zsh -c 'cat README.md'", "cat README.md")
        )
        self.assertFalse(
            bt.approved_read(u, "cat README.md; cat secret", "cat README.md")
        )

    def test_fresh_event_from_old_definition_is_not_accepted(self):
        old = str(self.old / "hooks/hooks.json")
        new = str(self.new / "hooks/hooks.json")
        inventory = u._inventory(inv(new), {new: "new"})
        run = {
            "id": "r",
            "eventName": "stop",
            "sourcePath": old,
            "source": "plugin",
            "handlerType": "command",
            "displayOrder": 0,
            "executionMode": "sync",
        }
        row = {
            "direction": "response",
            "message": {
                "method": "hook/started",
                "params": {"threadId": "fresh", "turnId": "t3", "run": run},
            },
        }
        with self.assertRaises(Exception):
            u._paired([row], inventory, "fresh", "stop", turn="t3")

    def test_single_new_tree_with_same_fallback_is_inference(self):
        import shutil

        old_artifact = self.p / "old-artifact"
        (old_artifact / "hooks").mkdir(parents=True)
        (self.new / "hooks").mkdir(parents=True)
        (old_artifact / "hooks/hooks.json").write_text("same")
        (self.new / "hooks/hooks.json").write_text("same")
        self.normalized["old_artifact_dir"] = str(old_artifact)
        base = self.p / "cache"
        base.mkdir()
        target = base / "0.18.0"
        shutil.move(self.new, target)
        self.ctx["new_root"] = target
        self.ctx["old_root"] = base / "0.17.3"
        self.assertEqual(
            bt.old_runtime_classification(self.ctx),
            "new_runtime_inferred_from_unique_tree_and_compatible_fallback",
        )
        (target / "hooks/hooks.json").write_text("changed")
        self.assertEqual(
            bt.old_runtime_classification(self.ctx), "unknown_multiple_or_missing_trees"
        )

    def test_windows_read_command_uses_supplied_tracked_filename(self):
        with mock.patch.object(bt.platform, "system", return_value="Windows"):
            command = bt.read_command("README.md")
            self.assertEqual(command, "Get-Content -LiteralPath README.md")
            self.assertTrue(bt.approved_read(u, command, command))
            self.assertFalse(bt.approved_read(u, command + "; whoami", command))

    def test_receipt_with_real_daily_v2_read_helpers(self):
        from tools.validation import daily_upgrade as daily

        self.write_receipts()
        self.ctx["daily"] = daily
        result = bt.verify_maintained(
            self.ctx, self.plan, self.ctx["tool_output"] / "verify.json", "passed"
        )
        self.assertEqual(result["journal_add_count"], 1)
        applied = self.ctx["tool_output"] / "apply.json"
        data = json.loads(applied.read_text())
        data["subject_sha256"] = "f" * 64
        applied.write_text(json.dumps(data))
        with self.assertRaises(bt.Refused):
            bt.verify_maintained(
                self.ctx, self.plan, self.ctx["tool_output"] / "verify.json", "passed"
            )

    def test_malformed_journal_repeated_add_refused(self):
        self.write_receipts()
        path = self.ctx["tool_output"] / "apply-events.jsonl"
        rows = [json.loads(x) for x in path.read_text().splitlines()]
        rows.append(rows[-1])
        path.write_text("".join(json.dumps(x) + "\n" for x in rows))
        with self.assertRaises(bt.Refused):
            bt.verify_maintained(
                self.ctx, self.plan, self.ctx["tool_output"] / "verify.json", "passed"
            )


if __name__ == "__main__":
    unittest.main()
