"""Cheap fail-closed controls; no real trust, model, install, or network."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import types
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("upgrade_tested", ROOT / "tools/validation/native_upgrade_acceptance.py")
assert SPEC and SPEC.loader
U = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(U)


def inventory(source):
    return {"data": [{"hooks": [{"eventName": event, "sourcePath": source, "source": "plugin",
                                  "handlerType": "command", "enabled": True, "trustStatus": "trusted",
                                  "key": "key:" + event, "currentHash": "hash:" + event,
                                  "displayOrder": 1} for event in sorted(U.EVENTS)]}]}


def hook(run_id, source, event, status=None, duration=None):
    run = {"id": run_id, "eventName": event, "sourcePath": source, "source": "plugin",
           "handlerType": "command", "displayOrder": 1, "executionMode": "sync"}
    if status is not None:
        run.update(status=status, durationMs=duration)
    return run


def sentinel(home):
    name = "cg-u01-sentinel-test"
    cache = home / "plugins/cache" / name / "fixture/marker"
    data = home / "u01-sentinel" / name / "marker"
    for path in (cache, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic sentinel")
    return {"marketplace": name, "cache_marker": str(cache), "data_marker": str(data)}


def command_fact(argv, observation=None):
    return {"argv": argv, "exit_code": 0, "stderr_nonempty": False, "observation": observation}


def fixture_path(*parts):
    return str(Path(tempfile.gettempdir()).resolve() / "cg-upgrade-synthetic" / Path(*parts))


def lifecycle_facts(old_version="0.15.1"):
    codex, old, new = (fixture_path(name) for name in ("codex", "old", "new"))
    market, sentinel_name = "codex-context-guard", "cg-u01-sentinel-test"
    plugin = "context-guard@" + market
    baseline = {"marketplace": sentinel_name, "cache_marker": {"path": fixture_path("safe", "cache")},
                "data_marker": {"path": fixture_path("safe", "data")}}
    home = fixture_path("home")
    subject = {"codex": codex, "old_version": old_version, "old_artifact": old,
               "new_artifact": new, "home": home, "sentinel": baseline}
    cache = Path(home) / "plugins/cache/codex-context-guard/context-guard"
    old_path, new_path = str(cache / old_version), str(cache / U.NEW_VERSION)
    old_add = {"pluginId": plugin, "name": "context-guard", "marketplaceName": market,
               "version": old_version, "installedPath": old_path}
    new_add = {**old_add, "version": U.NEW_VERSION, "installedPath": new_path}
    old_entry = {"pluginId": plugin, "name": "context-guard", "marketplaceName": market,
                 "version": old_version, "installed": True, "enabled": True,
                 "source": {"source": "local", "path": old},
                 "marketplaceSource": {"sourceType": "local", "source": old}}
    new_entry = {**old_entry, "version": U.NEW_VERSION, "source": {"source": "local", "path": new},
                 "marketplaceSource": {"sourceType": "local", "source": new}}
    old_list, new_list = {"installed": [old_entry]}, {"installed": [new_entry]}
    disabled = {"installed": [{**new_entry, "enabled": False}]}
    marker = {"name": sentinel_name}
    markets_old = {"marketplaces": [marker, {"name": market, "root": old,
        "marketplaceSource": {"sourceType": "local", "source": old}}]}
    markets_new = {"marketplaces": [marker, {"name": market, "root": new,
        "marketplaceSource": {"sourceType": "local", "source": new}}]}
    markets_empty = {"marketplaces": [marker]}
    ml = [codex, "plugin", "marketplace", "list", "--json"]
    old_pl = [codex, "plugin", "list", "--marketplace", market, "--json"]
    prepared_commands = [command_fact([codex, "--version"], {"version": "codex-cli 0.165.0"}),
        command_fact(ml, markets_empty),
        command_fact([codex, "plugin", "list", "--marketplace", sentinel_name, "--json"], {"installed": []}),
        command_fact([codex, "plugin", "marketplace", "add", old]), command_fact(ml, markets_old),
        command_fact([codex, "plugin", "add", plugin, "--json"], old_add), command_fact(ml, markets_old),
        command_fact(old_pl, old_list), command_fact(ml, markets_old)]
    prepared = {"commands": prepared_commands, "official_add": old_add, "sentinel_before": baseline,
        "before": {"sentinel_installed_count": 0, "target_marketplace_absent": True,
                   "target_cache_absent": True, "target_cache_path": str(cache)},
        "sentinel_after": baseline, "sentinel_phases": {name: baseline for name in
            ("after_marketplace_add", "after_plugin_add", "after_plugin_list")}}
    commands = [command_fact(ml, markets_old), command_fact(old_pl, old_list), command_fact(ml, markets_old),
        command_fact([codex, "plugin", "marketplace", "remove", market]), command_fact(ml, markets_empty),
        command_fact([codex, "plugin", "marketplace", "add", new]), command_fact(ml, markets_new),
        command_fact([codex, "plugin", "add", plugin, "--json"], new_add), command_fact(ml, markets_new),
        command_fact(old_pl, new_list), command_fact(ml, markets_new), command_fact(old_pl, disabled),
        command_fact(ml, markets_new), command_fact([codex, "plugin", "remove", plugin]),
        command_fact(old_pl, {"installed": []}), command_fact(ml, markets_new),
        command_fact([codex, "plugin", "marketplace", "remove", market]), command_fact(ml, markets_empty)]
    phases = ("before", "after_old_list", "after_old_marketplace_remove", "after_new_marketplace_add",
              "after_new_plugin_add", "after_new_plugin_list", "after_disable", "after_plugin_remove",
              "after_marketplace_remove")
    result = {"commands": commands, "installed_new": {"path": new_path},
              "sentinel_phases": {name: baseline for name in phases}}
    return subject, prepared, result


class UpgradeControls(unittest.TestCase):
    def test_compact_consumer_uses_only_paired_same_thread_window(self):
        source, thread = fixture_path("hooks.json"), "T"
        inv = {row["eventName"]: row for row in inventory(source)["data"][0]["hooks"]}
        rows = []
        def rpc(i, method, params, result):
            rows.extend([{"direction": "request", "message": {"id": i, "method": method, "params": params}},
                         {"direction": "response", "message": {"id": i, "result": result}}])
        def event(method, params):
            rows.append({"direction": "response", "message": {"method": method, "params": params}})
        def turn(i, value):
            rpc(i, "turn/start", {"threadId": thread}, {"turn": {"id": value}})
            event("turn/started", {"threadId": thread, "turn": {"id": value}})
            event("turn/completed", {"threadId": thread, "turn": {"id": value, "status": "completed"}})
        turn(1, "baseline")
        rpc(2, "thread/compact/start", {"threadId": thread}, {})
        event("turn/started", {"threadId": thread, "turn": {"id": "C"}})
        for phase in ("started", "completed"):
            event("hook/" + phase, {"threadId": thread, "turnId": "C", "run":
                hook("hc", source, "preCompact", "completed", 1) if phase == "completed"
                else hook("hc", source, "preCompact")})
        for phase in ("started", "completed"):
            event("item/" + phase, {"threadId": thread, "turnId": "C", "item": {"id": "I", "type": "contextCompaction"}})
        event("thread/status/changed", {"threadId": thread, "status": {"type": "idle"}})
        turn(3, "recovery")
        rows = [json.loads(json.dumps(row)) for row in rows]
        with self.assertRaises(ValueError):
            U.host.compact_complete([r["message"] for r in rows if r["direction"] == "response"], thread, inv)
        U._verify_compact_window(rows, thread, "baseline", "recovery", inv)
        notifications_first = copy.deepcopy(rows)
        response_index = next(i for i, row in enumerate(notifications_first)
                              if row.get("direction") == "response" and row.get("message", {}).get("id") == 2)
        response = notifications_first.pop(response_index)
        recovery_index = next(i for i, row in enumerate(notifications_first)
                              if row.get("direction") == "request" and row.get("message", {}).get("id") == 3)
        notifications_first.insert(recovery_index, response)
        U._verify_compact_window(notifications_first, thread, "baseline", "recovery", inv)
        for mutation in ("wrong_thread", "duplicate_compact", "missing_idle", "missing_response", "extra_turn", "late_compact"):
            bad = copy.deepcopy(rows)
            request_index = next(i for i, row in enumerate(bad) if row.get("message", {}).get("method") == "thread/compact/start")
            if mutation == "wrong_thread":
                bad[request_index]["message"]["params"]["threadId"] = "other"
            elif mutation == "duplicate_compact":
                duplicate = copy.deepcopy(bad[request_index:request_index + 2])
                duplicate[0]["message"]["id"] = duplicate[1]["message"]["id"] = 99
                bad[request_index:request_index] = duplicate
            elif mutation == "missing_idle":
                bad = [row for row in bad if row.get("message", {}).get("method") != "thread/status/changed"]
            elif mutation == "missing_response":
                bad.pop(request_index + 1)
            elif mutation == "extra_turn":
                bad.insert(request_index, {"direction": "request", "message": {"id": 99, "method": "turn/start", "params": {"threadId": thread}}})
            else:
                pair = bad[request_index:request_index + 2]
                del bad[request_index:request_index + 2]
                bad.extend(pair)
            with self.subTest(mutation=mutation), self.assertRaises(U.UpgradeError):
                U._verify_compact_window(bad, thread, "baseline", "recovery", inv)

    def test_verify_replay_requires_ancestor_consumer_only_and_current_preflight(self):
        old_commit, new_commit = "a" * 40, "b" * 40
        old = b"import os\nVALUE=1\ndef prepare(): pass\ndef verify(): pass\ndef main(): pass\n"
        new = b"import os\nVALUE=1\ndef prepare(): pass\ndef _verify_compact_window(): pass\ndef _verify_replay_subject(): pass\ndef verify(): return True\ndef main(): pass\n"
        state = {"old": old, "new": new, "paths": b"tools/validation/native_upgrade_acceptance.py\ntests/test_native_upgrade_acceptance.py\n", "ancestor": True}
        def git(argv, **_kwargs):
            args = argv[3:]
            if args == ["rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, (new_commit + "\n").encode(), b"")
            if args[:2] == ["merge-base", "--is-ancestor"]:
                return subprocess.CompletedProcess(argv, 0 if state["ancestor"] else 1, b"", b"")
            if args[0] == "diff":
                return subprocess.CompletedProcess(argv, 0, state["paths"], b"")
            if args[0] == "show":
                return subprocess.CompletedProcess(argv, 0, state["old"] if args[1].startswith(old_commit) else state["new"], b"")
            raise AssertionError("unexpected git request")
        subject = {"toolkit_commit": new_commit, "tool_sha256": "c" * 64}
        with mock.patch.object(U.subprocess, "run", side_effect=git), mock.patch.object(U, "preflight", side_effect=lambda *_: subject.copy()) as preflight:
            actual, verifier, verifier_sha = U._verify_replay_subject({"toolkit_commit": old_commit}, Path(fixture_path("probe")))
            self.assertEqual(old_commit, actual["toolkit_commit"])
            self.assertEqual(hashlib.sha256(old).hexdigest(), actual["tool_sha256"])
            self.assertEqual((new_commit, "c" * 64), (verifier, verifier_sha))
            self.assertEqual(new_commit, preflight.call_args.args[0]["toolkit_commit"])
            with mock.patch.object(U, "preflight", side_effect=U.UpgradeError("current preflight refused")):
                with self.assertRaises(U.UpgradeError):
                    U._verify_replay_subject({"toolkit_commit": old_commit}, Path(fixture_path("probe")))
            same, verifier, verifier_sha = U._verify_replay_subject({"toolkit_commit": new_commit}, Path(fixture_path("probe")))
            self.assertEqual((new_commit, new_commit, "c" * 64), (same["toolkit_commit"], verifier, verifier_sha))
            for mutation in ("not_ancestor", "extra_path", "producer_changed", "imports_changed", "duplicate", "shadow",
                             "decorator", "default", "keyword_default"):
                state.update(old=old, new=new, paths=b"tools/validation/native_upgrade_acceptance.py\n", ancestor=True)
                if mutation == "not_ancestor":
                    state["ancestor"] = False
                elif mutation == "extra_path":
                    state["paths"] += b"tools/validation/stop_host_acceptance.py\n"
                elif mutation == "producer_changed":
                    state["new"] = new.replace(b"def prepare(): pass", b"def prepare(): return 1")
                elif mutation == "imports_changed":
                    state["new"] = new.replace(b"import os", b"import sys")
                elif mutation == "duplicate":
                    state["new"] += b"def verify(): pass\n"
                elif mutation == "shadow":
                    state["new"] += b"verify = 1\n"
                elif mutation == "decorator":
                    state["new"] = new.replace(b"def _verify_compact_window", b"@alter_producer()\ndef _verify_compact_window")
                elif mutation == "default":
                    state["new"] = new.replace(b"def _verify_compact_window():", b"def _verify_compact_window(x=alter_producer()):")
                else:
                    state["new"] = new.replace(b"def _verify_compact_window():", b"def _verify_compact_window(*, x=alter_producer()):")
                with self.subTest(mutation=mutation), self.assertRaises(U.UpgradeError):
                    U._verify_replay_subject({"toolkit_commit": old_commit}, Path(fixture_path("probe")))

    def test_live_close_must_precede_actual_cold_constructor(self):
        events = []
        live = mock.Mock()
        live.owned.process.pid = 123
        live.close.side_effect = lambda: (events.append("live-close") or {"owned_process_exited": True,
            "owned_tree_no_running_members": True, "process_group_cleanup_error": None})
        cold = mock.Mock()
        cold.owned.process.pid = 456
        cold.log = io.StringIO()
        result = {"cleanup": []}
        def create(*_args, **_kwargs):
            events.append("cold-start")
            return cold
        with mock.patch.object(U, "UpgradeClient", side_effect=create) as factory:
            U._finish_live_for_cold(live, result, "Darwin")
            U._start_finished_cold({}, Path(tempfile.gettempdir()), Path(tempfile.gettempdir()), "new", result)
            self.assertEqual(["live-close", "cold-start"], events)
            self.assertEqual(456, json.loads(cold.log.getvalue())["pid"])
            factory.assert_called_once()
        for failure in ({"owned_process_exited": False, "owned_tree_no_running_members": True},
                        {"owned_process_exited": True, "owned_tree_no_running_members": False}):
            failed = {"cleanup": []}
            live.close.side_effect = None
            live.close.return_value = failure
            with mock.patch.object(U, "UpgradeClient") as factory, self.assertRaises(U.UpgradeError):
                U._finish_live_for_cold(live, failed, "Darwin")
                U._start_finished_cold({}, Path(tempfile.gettempdir()), Path(tempfile.gettempdir()), "new", failed)
            factory.assert_not_called()

    def test_cold_marker_write_or_flush_failure_closes_owned_client(self):
        for operation in ("write", "flush"):
            with self.subTest(operation=operation):
                cold = mock.Mock()
                cold.owned.process.pid = 456
                cold.log = mock.Mock()
                getattr(cold.log, operation).side_effect = OSError("synthetic marker failure")
                cold.close.return_value = {"owned_process_exited": True, "owned_tree_no_running_members": True,
                    "process_group_cleanup_error": None, "cleanup_complete": True, "job_close_confirmed": True}
                result = {"cleanup": [{"role": "live", "closed_monotonic_ns": 1, "facts":
                    {"owned_process_exited": True, "owned_tree_no_running_members": True}}]}
                with mock.patch.object(U, "UpgradeClient", return_value=cold), \
                     self.assertRaisesRegex(OSError, "synthetic marker failure"):
                    U._start_finished_cold({}, Path(tempfile.gettempdir()), Path(tempfile.gettempdir()), "new", result)
                cold.close.assert_called_once()
                self.assertEqual(["live", "cold"], [row["role"] for row in result["cleanup"]])
                self.assertTrue(result["cleanup"][1]["facts"]["owned_process_exited"])
        cold = mock.Mock()
        cold.owned.process.pid = 456
        cold.log.write.side_effect = OSError("synthetic marker failure")
        cold.close.side_effect = RuntimeError("synthetic close failure")
        result = {"cleanup": [{"role": "live", "closed_monotonic_ns": 1, "facts":
            {"owned_process_exited": True, "owned_tree_no_running_members": True}}]}
        with mock.patch.object(U, "UpgradeClient", return_value=cold), \
             self.assertRaisesRegex(OSError, "synthetic marker failure"):
            U._start_finished_cold({}, Path(tempfile.gettempdir()), Path(tempfile.gettempdir()), "new", result)
        cold.close.assert_called_once()
        self.assertEqual({"role": "cold", "cleanup_unknown": "RuntimeError"}, result["cleanup"][1])

    def test_lifecycle_markers_refuse_equal_reversed_or_wrong_pid(self):
        events = ("transition_started", "transition_completed", "disable_completed", "plugin_removed", "marketplace_removed")
        rows = [{"direction": "local", "event": event, "pid": 123, "monotonic_ns": index + 1}
                for index, event in enumerate(events)]
        self.assertEqual(set(events), set(U._marks(rows)))
        for mutation in ("equal", "reversed", "wrong_pid"):
            bad = copy.deepcopy(rows)
            if mutation == "equal":
                bad[1]["monotonic_ns"] = bad[0]["monotonic_ns"]
            elif mutation == "reversed":
                bad[1]["monotonic_ns"] = bad[0]["monotonic_ns"] - 1
            else:
                bad[1]["pid"] = 456
            with self.assertRaises(U.UpgradeError, msg=mutation):
                U._marks(bad)

    def test_old_scope_never_writes_bytecode_in_consumed_carriers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "synthetic-home"
            home.mkdir()
            state_path = root / "synthetic-state.json"
            state_path.write_text(json.dumps({"marker": "synthetic", "pending": ["R1"],
                                              "ancestor": ["A1"], "waiting": ["W1"]}))
            state_before = U.sha(state_path)
            carriers = []
            for name in ("fixed-one", "fixed-two", "old-negative"):
                carrier = root / name
                scripts = carrier / "scripts"
                scripts.mkdir(parents=True)
                (scripts / "context_guard.py").write_text(
                    "import os\nimport cg_eager\n"
                    "def _open_windows_committed_state(path):\n"
                    "    return os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))\n"
                    "def validate_state_integrity(state):\n"
                    "    assert state['marker'] == 'synthetic' and cg_eager.VALUE == 1\n"
                    "def current_scope_projection(state):\n"
                    "    import cg_lazy\n"
                    "    assert cg_lazy.VALUE == 2\n"
                    "    return {'current_item_ids': set(state['pending']), "
                    "'ancestor_constraint_ids': set(state['ancestor']), "
                    "'waiting_conditions': state['waiting']}\n")
                (scripts / "cg_eager.py").write_text("VALUE = 1\n")
                (scripts / "cg_lazy.py").write_text("VALUE = 2\n")
                carriers.append(carrier)
            expected = {"current": ["R1"], "ancestor": ["A1"], "waiting": 1}
            for carrier in carriers[:2]:
                files_before = U.source_files(carrier)
                objects_before = U._cache_identity(carrier)
                self.assertEqual(expected, U._old_scope(carrier, state_path, home))
                self.assertEqual(files_before, U.source_files(carrier))
                self.assertEqual(objects_before, U._cache_identity(carrier))
                self.assertEqual([], list(carrier.rglob("*.pyc")))
                self.assertEqual(state_before, U.sha(state_path))
            real_command = U.scheduler._command
            def old_without_b(native, source, argv, **kwargs):
                self.assertEqual(["-I", "-B", "-c"], argv[1:4])
                self.assertEqual("1", kwargs["env"].get("PYTHONDONTWRITEBYTECODE"))
                return real_command(native, source, [argv[0], "-I", *argv[3:]], **kwargs)
            old_files = U.source_files(carriers[2])
            old_objects = U._cache_identity(carriers[2])
            with mock.patch.object(U.scheduler, "_command", side_effect=old_without_b):
                self.assertEqual(expected, U._old_scope(carriers[2], state_path, home))
            self.assertGreaterEqual(len(list(carriers[2].rglob("*.pyc"))), 2)
            self.assertNotEqual(old_files, U.source_files(carriers[2]))
            self.assertNotEqual(old_objects, U._cache_identity(carriers[2]))
            self.assertEqual(state_before, U.sha(state_path))

    def test_artifact_loader_never_writes_bytecode_in_reviewed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixed, old = root / "fixed", root / "old-negative"
            for carrier in (fixed, old):
                (carrier / "scripts").mkdir(parents=True)
                (carrier / "scripts/artifact_identity.py").write_text("VALUE = 42\n")
            before_files, before_objects = U.source_files(fixed), U._cache_identity(fixed)
            with mock.patch.object(U.sys, "dont_write_bytecode", False):
                self.assertEqual(42, U._load_artifacts_no_pyc(fixed).VALUE)
                self.assertFalse(U.sys.dont_write_bytecode)
                self.assertEqual(42, U.native.load_artifacts(old).VALUE)
            self.assertEqual(before_files, U.source_files(fixed))
            self.assertEqual(before_objects, U._cache_identity(fixed))
            self.assertEqual([], list(fixed.rglob("*.pyc")))
            self.assertEqual(1, len(list(old.rglob("*.pyc"))))

    def test_pre_disable_sample_rejects_dual_trust_and_replays_order(self):
        old_source, new_source = fixture_path("old", "hooks.json"), fixture_path("new", "hooks.json")
        old = inventory(old_source)["data"][0]["hooks"]
        new = inventory(new_source)["data"][0]["hooks"]
        for row in new:
            row["trustStatus"] = "untrusted"
        value = {"data": [{"hooks": old + new}]}
        projection = U._pre_disable_projection(value, old_source, new_source)
        rows = [{"direction": "local", "event": "transition_completed", "pid": 123, "monotonic_ns": 1},
                {"direction": "request", "message": {"id": 1, "method": "hooks/list", "params": {}}},
                {"direction": "response", "message": {"id": 1, "result": value}},
                {"direction": "observation", "event": "pre_disable_sample", "pid": 123, "monotonic_ns": 4},
                {"direction": "observation", "event": "old_identity_disabled", "pid": 123, "monotonic_ns": 5}]
        U._verify_pre_disable(rows, {"pre_disable_inventory": projection}, old_source, new_source, 0, 4, 123)
        for index, field, replacement in ((0, "monotonic_ns", 4), (0, "monotonic_ns", 6),
                                    (3, "monotonic_ns", 5), (3, "monotonic_ns", 999),
                                    (4, "pid", 124), (0, "pid", 124), (3, "pid", 124)):
            bad_rows = copy.deepcopy(rows)
            bad_rows[index][field] = replacement
            with self.subTest(index=index, field=field, value=replacement), self.assertRaises(U.UpgradeError):
                U._verify_pre_disable(bad_rows, {"pre_disable_inventory": projection}, old_source, new_source, 0, 4, 123)
        bad = copy.deepcopy(value)
        bad["data"][0]["hooks"][-1]["trustStatus"] = "trusted"
        with self.assertRaises(U.UpgradeError):
            U._pre_disable_projection(bad, old_source, new_source)
        with self.assertRaises(U.UpgradeError):
            U._verify_pre_disable(rows, {"pre_disable_inventory": projection}, old_source, new_source, 0, 3, 123)
        bad_rows = copy.deepcopy(rows)
        bad_rows[2]["message"]["result"] = bad
        with self.assertRaises(U.UpgradeError):
            U._verify_pre_disable(bad_rows, {"pre_disable_inventory": projection}, old_source, new_source, 0, 4, 123)

    def test_observe_producer_to_independent_consumer_with_fake_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home, old, new, workspace = (root / name for name in ("home", "old", "new", "workspace"))
            for path in (home, old, new, workspace):
                path.mkdir()
            product = root / "product"
            product.mkdir()
            codex = root / "codex"
            codex.write_text("synthetic")
            (workspace / "native-read.txt").write_text("synthetic read")
            market, stable = "codex-context-guard", "context-guard@codex-context-guard"
            installed = home / "plugins/cache" / market / "context-guard/0.15.1"
            new_installed = home / "plugins/cache" / market / "context-guard" / U.NEW_VERSION
            installed.mkdir(parents=True)
            new_installed.mkdir(parents=True)
            data = home / "plugins/data/context-guard-codex-context-guard"
            state_path = data / "sessions-v2/C/state.json"
            state_path.parent.mkdir(parents=True)
            state_path.write_text("synthetic state")
            old_source, new_source = str(installed / "hooks/hooks.json"), str(new_installed / "hooks/hooks.json")
            old_hooks, new_hooks = inventory(old_source)["data"][0]["hooks"], inventory(new_source)["data"][0]["hooks"]
            sentinel_facts = {"marketplace": "cg-u01-sentinel-test", "cache_marker": {"path": fixture_path("cache")},
                              "data_marker": {"path": fixture_path("data")}}
            platform_name = "Windows" if U.platform.system() == "Windows" else "Darwin"
            expected_read = ("Get-Content -LiteralPath native-read.txt" if platform_name == "Windows"
                             else "cat native-read.txt")
            subject = {"home": str(home), "workspace": str(workspace), "old_artifact": str(old),
                       "new_artifact": str(new), "product_root": str(product), "codex": str(codex),
                       "old_data_root": str(data), "new_data_root": str(data), "old_version": "0.15.1",
                       "transition_strategy": "observe-open", "platform": platform_name, "sentinel": sentinel_facts,
                       "read_file_sha256": U.sha(workspace / "native-read.txt")}
            prepared = {"schema": U.REPORT, "stage": "prepare", "status": "pending", "subject": subject,
                        "sentinel_after": sentinel_facts, "installed": {"path": str(installed)},
                        "official_add": {"installedPath": str(installed)}}
            prepared_path = root / "prepare.json"
            prepared_path.write_text(json.dumps(prepared))
            plan = {**subject, "sentinel": {}}
            state = {"session": {"id": "C"}, "requirements": [
                {"id": "R1", "sha256": "a" * 64, "status": "pending", "work_unit_id": "WU1"}],
                "mode": {"active": True}, "compactions": [], "pending": {}}
            state_path.write_text(json.dumps(state))
            world = {"new": False, "snapshots": 0, "instances": 0, "scenario": "pass", "turns": [], "events": []}

            def marker(turn, seq):
                return {"id": "P" + str(seq), "turn_id": turn,
                        "sha256": hashlib.sha256("请仅回复观察结束。".encode()).hexdigest(),
                        "record_sha256": "f" * 64, "core_event_seq": seq}
            def snapshots(_home, _old_root, _new_root, _thread):
                world["snapshots"] += 1
                turns = ["T0"] + list(world["turns"])
                snap = {"present": True, "state_sha256": U.sha(state_path),
                        "prompts": [marker(turn, index + 1) for index, turn in enumerate(turns)]}
                return {"old": snap, "new": copy.deepcopy(snap)}

            class FakeClient:
                def __init__(self, _plan, outdir, sources=None, **_kwargs):
                    world["instances"] += 1
                    self.plan = _plan
                    self.is_cold = world["instances"] == 2
                    world["events"].append("cold_start" if self.is_cold else "live_start")
                    self.owned = mock.Mock()
                    self.owned.process.pid = 456 if self.is_cold else 123
                    self.owned.process.poll.return_value = None
                    self.log = (outdir / "rpc.jsonl").open("x", encoding="utf-8")
                    self.rows = []
                    self.approved = U._inventory(inventory(new_source if self.is_cold else old_source),
                                                 {new_source if self.is_cold else old_source: U.NEW_VERSION if self.is_cold else "0.15.1"})
                    self.initial_approved = dict(self.approved)
                    self.observation_thread = self.observation_inventory = self.guard_diagnostic = None
                    self.seq = 0
                    self.rpc("hooks/list", {})

                def emit(self, direction, message):
                    self.log.write(json.dumps({"direction": direction, "message": message}) + "\n")
                    self.log.flush()
                    if direction == "response":
                        self.rows.append(message)

                def hooks(self, event, turn=None, source=None):
                    for phase in ("started", "completed"):
                        run = hook(event, source or new_source, event, "completed", 1) if phase == "completed" else hook(event, source or new_source, event)
                        params = {"threadId": "C", "run": run}
                        if turn:
                            params["turnId"] = turn
                        self.emit("response", {"method": "hook/" + phase, "params": params})

                def rpc(self, method, params):
                    self.seq += 1
                    request_id = self.seq
                    self.emit("request", {"id": request_id, "method": method, "params": params})
                    value = {"data": [{"hooks": new_hooks if world["new"] else old_hooks}]} if method == "hooks/list" else {}
                    if method == "thread/resume" and world["scenario"] == "resume_rejected":
                        self.emit("response", {"id": request_id, "error": {"redacted": True}})
                        raise ValueError("RPC rejected: thread/resume")
                    self.emit("response", {"id": request_id, "result": value})
                    if method == "thread/resume":
                        self.hooks("sessionStart")
                    if method == "thread/archive" and world["scenario"] != "missing_end":
                        self.hooks("sessionEnd")
                    return value

                def start(self):
                    self.seq += 1
                    self.emit("request", {"id": self.seq, "method": "thread/start", "params": {}})
                    self.emit("response", {"id": self.seq, "result": {"thread": {"id": "C"}}})
                    return "C"

                def observed_turn(self, _thread, prompt):
                    turn = "T2" if self.is_cold else "T1" if world["new"] else "T0"
                    source = new_source if world["new"] else old_source
                    self.seq += 1
                    self.emit("request", {"id": self.seq, "method": "turn/start", "params": {
                        "threadId": "C", "input": [{"type": "text", "text": prompt}]}})
                    self.emit("response", {"id": self.seq, "result": {"turn": {"id": turn}}})
                    if turn == "T1" and world["scenario"] == "live_guard":
                        self.guard_diagnostic = {"schema": "cg-u01-guard-diagnostic/v1", "stage": "receive",
                            "method": "hook/started", "event": "userPromptSubmit", "source_class": "old",
                            "event_source_approved": False, "source_matches": False, "handler_matches": False,
                            "order_matches": False, "mode_matches": False, "target_thread_matches": True,
                            "old_inventory_order_matches": False}
                        raise U.UpgradeError("synthetic guard")
                    begin = len(self.rows)
                    if turn == "T0":
                        self.hooks("preToolUse", turn, source)
                        item = {"id": "read", "type": "commandExecution", "command": expected_read, "cwd": str(workspace)}
                        for phase in ("started", "completed"):
                            self.emit("response", {"method": "item/" + phase, "params": {"threadId": "C", "turnId": turn,
                                "item": {**item, **({"exitCode": 0} if phase == "completed" else {})}}})
                        self.hooks("postToolUse", turn, source)
                    self.hooks("stop", turn, source)
                    self.emit("response", {"method": "turn/completed", "params": {"threadId": "C", "turn": {"id": turn, "status": "completed"}}})
                    if turn != "T0":
                        world["turns"].append(turn)
                        state_path.write_text(json.dumps({**state, "synthetic_turns": world["turns"]}))
                    return turn, [{"direction": "response", "message": message} for message in self.rows[begin:]]

                def close(self):
                    world["events"].append("cold_close" if self.is_cold else "live_close")
                    self.log.close()
                    return {"owned_process_exited": True, "owned_tree_no_running_members": True,
                            "process_group_cleanup_error": None, "cleanup_complete": True, "job_close_confirmed": True}

            old_row = {"pluginId": stable, "name": "context-guard", "marketplaceName": market, "version": "0.15.1",
                       "installed": True, "enabled": True, "source": {"source": "local", "path": str(old)},
                       "marketplaceSource": {"sourceType": "local", "source": str(old)}}
            new_row = {**old_row, "version": U.NEW_VERSION, "source": {"source": "local", "path": str(new)},
                       "marketplaceSource": {"sourceType": "local", "source": str(new)}}
            def command(_native, _root, argv, **_kwargs):
                if argv[1:4] == ["plugin", "marketplace", "remove"]:
                    value = {}
                elif argv[1:4] == ["plugin", "marketplace", "add"]:
                    world["new"] = True
                    value = {}
                elif argv[1:4] == ["plugin", "marketplace", "list"]:
                    source = str(new if world["new"] else old)
                    value = {"marketplaces": [{"name": sentinel_facts["marketplace"]}, {"name": market,
                        "root": source, "marketplaceSource": {"sourceType": "local", "source": source}}]}
                elif argv[1:3] == ["plugin", "add"]:
                    value = {"pluginId": stable, "name": "context-guard", "marketplaceName": market,
                             "version": U.NEW_VERSION, "installedPath": str(new_installed)}
                else:
                    value = {"installed": [new_row if world["new"] else old_row]}
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
            manager = mock.Mock()
            manager.distribution_manifest.return_value = {"public": "b" * 64}
            with mock.patch.object(U.time, "monotonic_ns", return_value=275218187000000) as coarse_clock, \
                 mock.patch.object(U, "UpgradeClient", FakeClient), \
                 mock.patch.object(U, "_sentinel_files", return_value=sentinel_facts), \
                 mock.patch.object(U, "source_files", return_value={"public": "b" * 64}), \
                 mock.patch.object(U, "_cache_identity", return_value="b" * 64), \
                 mock.patch.object(U, "_official_install_identity", return_value=installed), \
                 mock.patch.object(U, "_state_at", return_value=(data, state)), \
                 mock.patch.object(U, "_root_snapshots", side_effect=snapshots), \
                 mock.patch.object(U.native, "official_identity", return_value=new_installed), \
                 mock.patch.object(U.native, "exact_artifact_parity"), \
                 mock.patch.object(U.native, "load_artifacts", return_value=manager), \
                 mock.patch.object(U.scheduler, "_command", side_effect=command), \
                 mock.patch.object(U, "preflight", return_value=subject), \
                 mock.patch.object(U, "_verify_replay_subject", side_effect=lambda plan, probe: (U.preflight(plan, probe), "c" * 40, "d" * 64)), \
                 mock.patch.object(U, "_verify_prepared"):
                for scenario, expected in (("pass", "observation_complete"), ("live_guard", "unsupported_continuity"),
                                           ("resume_rejected", "unsupported_continuity"), ("missing_end", "failed")):
                    world.update(new=False, snapshots=0, instances=0, scenario=scenario, turns=[], events=[])
                    output = root / ("output-" + scenario)
                    result = U._run_observation(plan, output, subject, prepared, installed)
                    self.assertEqual(expected, result["status"], (scenario, result.get("failure")))
                    self.assertLess(world["events"].index("live_close"), world["events"].index("cold_start"))
                    if expected != "failed":
                        self.assertEqual(expected, U.verify(plan, output, prepared_path)["status"])
                coarse_clock.assert_not_called()

    def test_historical_inventory_is_limited_to_the_observed_thread(self):
        old_source, new_source = fixture_path("old", "hooks.json"), fixture_path("new", "hooks.json")
        old = U._inventory(inventory(old_source), {old_source: "0.16.1"})
        new = U._inventory(inventory(new_source), {new_source: U.NEW_VERSION})
        client = object.__new__(U.UpgradeClient)
        client.rows, client.pending, client.log, client.q = [], {}, io.StringIO(), U.queue.Queue()
        client.approved, client.initial_approved = new, old
        client.initial_sources, client.guard_diagnostic = {old_source: "0.16.1"}, None
        client.observation_thread, client.observation_inventory = "C", {**old, **new}
        def notification(thread):
            return {"method": "hook/started", "params": {"threadId": thread,
                    "run": hook("run", old_source, "stop")}}
        client.q.put(notification("C"))
        client.receive(U.time.monotonic() + 1)
        client.q.put(notification("other"))
        with self.assertRaises(U.UpgradeError):
            client.receive(U.time.monotonic() + 1)
        self.assertFalse(client.guard_diagnostic["target_thread_matches"])
        self.assertEqual(1, len(client.rows))

    def test_root_trace_requires_new_turn_marker_and_handles_shared_roots(self):
        marker = {"id": "P1", "turn_id": "TURN", "sha256": hashlib.sha256("请仅回复观察结束。".encode()).hexdigest(),
                  "record_sha256": "a" * 64, "core_event_seq": 1}
        empty = {"present": True, "state_sha256": "b" * 64, "prompts": []}
        with_turn = {"present": True, "state_sha256": "c" * 64, "prompts": [marker]}
        absent = {"present": False, "prompts": []}
        before, after = {"old": empty, "new": absent}, {"old": with_turn, "new": absent}
        self.assertEqual("old", U._root_turn_trace(before, after, "T", "TURN", shared=False)["actual_root"])
        self.assertEqual("shared", U._root_turn_trace({"old": empty, "new": empty},
            {"old": with_turn, "new": with_turn}, "T", "TURN", shared=True)["actual_root"])
        for a, b, shared in ((before, before, False), (before, {"old": with_turn, "new": with_turn}, False),
                             (after, after, False), ({"old": empty, "new": absent},
                                                     {"old": with_turn, "new": absent}, True)):
            with self.assertRaises(U.UpgradeError):
                U._root_turn_trace(a, b, "T", "TURN", shared=shared)
        wrong = copy.deepcopy(with_turn)
        wrong["prompts"][0]["sha256"] = "e" * 64
        with self.assertRaises(U.UpgradeError):
            U._root_turn_trace(before, {"old": wrong, "new": absent}, "T", "TURN", shared=False)

    def test_all_auth_homes_bound_before_plan_read_with_limit_32(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            homes = [root / ("home-" + str(index)) for index in range(34)]
            for home in homes:
                home.mkdir()
            with mock.patch.object(U, "_read_json", side_effect=AssertionError("must not read")) as reader:
                for count in (9, 32):
                    chosen, others = U._invocation_paths(root / "plan.json", root / "result", homes[0],
                                                         homes[1:count + 1], None)
                    self.assertEqual(homes[0], chosen)
                    self.assertEqual(count, len(others))
                with self.assertRaises(U.UpgradeError):
                    U._invocation_paths(root / "plan.json", root / "result", homes[0], homes[1:34], None)
                with self.assertRaises(U.UpgradeError):
                    U._invocation_paths(root / "plan.json", root / "result", homes[0], [homes[1], homes[1]], None)
                child = homes[1] / "nested"
                child.mkdir()
                with self.assertRaises(U.UpgradeError):
                    U._invocation_paths(root / "plan.json", root / "result", homes[0], [homes[1], child], None)
                with self.assertRaises(U.UpgradeError):
                    U._invocation_paths(homes[9] / "plan.json", root / "result", homes[0], homes[1:10], None)
                reader.assert_not_called()

    def test_cold_session_start_must_be_real_new_source_pair_before_first_stop(self):
        source = fixture_path("new", "hooks", "hooks.json")
        inv = U._inventory(inventory(source), {source: U.NEW_VERSION})
        def pair(event_name, turn=None):
            result = []
            for phase in ("started", "completed"):
                run = hook(event_name, source, event_name, "completed", 1) if phase == "completed" else hook(event_name, source, event_name)
                params = {"threadId": "T", "run": run}
                if turn is not None:
                    params["turnId"] = turn
                result.append({"direction": "response", "message": {"method": "hook/" + phase, "params": params}})
            return result
        resume = [{"direction": "request", "message": {"id": 1, "method": "thread/resume", "params": {"threadId": "T"}}},
                  {"direction": "response", "message": {"id": 1, "result": {}}}]
        turn = [{"direction": "request", "message": {"id": 2, "method": "turn/start", "params": {"threadId": "T"}}},
                {"direction": "response", "message": {"id": 2, "result": {"turn": {"id": "U"}}}}]
        stop = pair("stop", "U")
        end = [{"direction": "response", "message": {"method": "turn/completed", "params": {
            "threadId": "T", "turn": {"id": "U", "status": "completed"}}}}]
        self.assertEqual(("before_first_turn", True), U._cold_session_phase(
            resume + pair("sessionStart") + turn + stop + end, inv, "T", "U", source))
        self.assertEqual(("during_first_turn", False), U._cold_session_phase(
            resume + turn + pair("sessionStart") + stop + end, inv, "T", "U", source))
        cross = pair("sessionStart")
        self.assertEqual(("during_first_turn", True), U._cold_session_phase(
            resume + cross[:1] + turn + cross[1:] + stop + end, inv, "T", "U", source))
        bad_cases = [resume + turn + stop + end, resume + turn + stop + pair("sessionStart") + end,
                     resume + turn + pair("sessionStart")[:1] + stop + end]
        wrong_thread = pair("sessionStart")
        wrong_thread[0]["message"]["params"]["threadId"] = "other"
        wrong_thread[1]["message"]["params"]["threadId"] = "other"
        bad_cases.append(resume + turn + wrong_thread + stop + end)
        wrong_source = pair("sessionStart")
        for row in wrong_source:
            row["message"]["params"]["run"]["sourcePath"] = fixture_path("other", "hooks.json")
        bad_cases.append(resume + turn + wrong_source + stop + end)
        for bad in bad_cases:
            with self.assertRaises(U.UpgradeError):
                U._cold_session_phase(bad, inv, "T", "U", source)

    def test_cancelled_scope_requires_exact_bound_controls_and_no_new_debt(self):
        original = {"id": "R1", "sha256": "a" * 64, "work_unit_id": "WU1", "status": "pending", "prompt_id": "P1"}
        cancel_sha = hashlib.sha256("取消当前任务。".encode()).hexdigest()
        before = {"session": {"id": "T"}, "requirements": [original]}
        after = {"session": {"id": "T"}, "requirements": [copy.deepcopy(original),
            {"id": "R2", "sha256": cancel_sha, "work_unit_id": "WU1", "prompt_id": "P2", "status": "answered"}],
            "prompts": [{"id": "P2", "sha256": cancel_sha, "record_sha256": "f" * 64,
                         "core_event_seq": 4, "origin": "human"}],
            "root_controls": [{"kind": "cancel", "source_prompt_id": "P2", "scope_kind": "current_unit",
                "source_record_sha256": "f" * 64, "source_seq": 4,
                "work_unit_id": "WU1", "catalog_sha256": "c" * 64,
                "items": [{"id": "R1", "source_sha256": "a" * 64, "work_unit_id": "WU1"}]}],
            "work_units": [{"id": "WU1", "status": "historical_unresolved"}]}
        scope = {"current": [], "ancestor": [], "waiting": 0}
        proof = U._cancel_evidence(before, after, scope)
        proof["state_sha256"] = "d" * 64
        U._check_cancel_evidence(proof, before, "T")
        for change in ("wrong_id", "wrong_hash", "wrong_unit", "wrong_prompt", "wrong_sequence",
                       "new_debt", "no_cancel", "open_scope"):
            bad, bad_scope = copy.deepcopy(after), copy.deepcopy(scope)
            if change == "wrong_id":
                bad["root_controls"][0]["items"][0]["id"] = "R9"
            elif change == "wrong_hash":
                bad["root_controls"][0]["items"][0]["source_sha256"] = "b" * 64
            elif change == "wrong_unit":
                bad["work_units"][0]["status"] = "active"
            elif change == "wrong_prompt":
                bad["root_controls"][0]["source_record_sha256"] = "e" * 64
            elif change == "wrong_sequence":
                bad["root_controls"][0]["source_seq"] = 5
            elif change == "new_debt":
                bad["requirements"].append({"id": "R3", "sha256": "e" * 64, "work_unit_id": "WU1",
                                            "prompt_id": "P3", "status": "pending"})
            elif change == "no_cancel":
                bad["root_controls"] = []
            else:
                bad_scope["current"] = ["R1"]
            with self.assertRaises(U.UpgradeError, msg=change):
                U._cancel_evidence(before, bad, bad_scope)
        forged = copy.deepcopy(proof)
        forged["after"]["root_controls"][0]["items"][0]["source_sha256"] = "b" * 64
        with self.assertRaises(U.UpgradeError):
            U._check_cancel_evidence(forged, before, "T")
        changed_before, changed_after = copy.deepcopy(before), copy.deepcopy(after)
        changed_before["requirements"][0]["work_unit_id"] = "WU9"
        for row in changed_after["requirements"]:
            row["work_unit_id"] = "WU9"
        changed_after["root_controls"][0]["work_unit_id"] = "WU9"
        changed_after["root_controls"][0]["items"][0]["work_unit_id"] = "WU9"
        changed_after["work_units"][0]["id"] = "WU9"
        forged = U._cancel_evidence(changed_before, changed_after, scope)
        forged["state_sha256"] = "d" * 64
        with self.assertRaises(U.UpgradeError):
            U._check_cancel_evidence(forged, before, "T")

    def test_old_disable_requires_both_scoped_readbacks_and_cache_identity(self):
        subject, _prepared, _ = lifecycle_facts()
        subject.update(old_version="0.16.1", transition_strategy="finish-old")
        old_market = U.OLD_MARKETS["0.16.1"]
        old = {"pluginId": "context-guard@" + old_market, "version": "0.16.1", "installed": True,
               "marketplaceName": old_market, "enabled": False,
               "source": {"source": "local", "path": subject["old_artifact"]},
               "marketplaceSource": {"sourceType": "local", "source": subject["old_artifact"]}}
        new = {"pluginId": "context-guard@" + U.NEW_MARKET, "version": U.NEW_VERSION, "installed": True,
               "marketplaceName": U.NEW_MARKET, "enabled": True,
               "source": {"source": "local", "path": subject["new_artifact"]},
               "marketplaceSource": {"sourceType": "local", "source": subject["new_artifact"]}}
        cache = {"files_sha256": U.digest({"file": "a" * 64}), "objects_sha256": "b" * 64}
        reads = []
        for market, row, tick in ((old_market, old, 21), (U.NEW_MARKET, new, 22)):
            reads.append({"argv": [subject["codex"], "plugin", "list", "--marketplace", market, "--json"],
                          "started_monotonic_ns": tick - 1, "completed_monotonic_ns": tick,
                          "observation": {"installed": [row]}})
        result = {"commands": reads, "new_inventory": [], "after": {"fresh_thread": "F"}, "old_cache_preservation":
                  {"before": cache, "after_new_install": cache, "after_old_disable": cache}}
        live = [{"direction": "local", "pid": 1}, {"direction": "local", "pid": 1, "monotonic_ns": 10},
                {"direction": "observation", "event": "pre_disable_sample", "pid": 1, "monotonic_ns": 15},
                {"direction": "observation", "event": "old_identity_disabled", "pid": 1, "monotonic_ns": 30},
                {"direction": "local", "pid": 1, "monotonic_ns": 40}]
        marks = {"transition_started": 0, "transition_completed": 1, "disable_completed": 4}
        installed = Path(fixture_path("old-cache"))
        with mock.patch.object(U, "source_files", return_value={"file": "a" * 64}), \
             mock.patch.object(U, "_cache_identity", return_value="b" * 64), \
                 mock.patch.object(U, "_thread_start_index", return_value=4), \
             mock.patch.object(U, "_verify_pre_disable"), \
             mock.patch.object(U, "_inventory_in_journal"):
            U._verify_old_disable(subject, result, live, marks, fixture_path("new-hook"), installed)
            for tick in (30, 29):
                bad_live = copy.deepcopy(live)
                bad_live[4]["monotonic_ns"] = tick
                with self.subTest(disable_completed=tick), self.assertRaises(U.UpgradeError):
                    U._verify_old_disable(subject, result, bad_live, marks, fixture_path("new-hook"), installed)
            for index in (0, 1):
                bad = copy.deepcopy(result)
                bad["commands"][index]["started_monotonic_ns"] = 14
                bad["commands"][index]["completed_monotonic_ns"] = 15
                with self.subTest(early_readback=index), self.assertRaises(U.UpgradeError):
                    U._verify_old_disable(subject, bad, live, marks, fixture_path("new-hook"), installed)
            for change in ("old_enabled", "stable_disabled", "cache_changed", "wrong_source"):
                bad = copy.deepcopy(result)
                if change == "old_enabled":
                    bad["commands"][0]["observation"]["installed"][0]["enabled"] = True
                elif change == "stable_disabled":
                    bad["commands"][1]["observation"]["installed"][0]["enabled"] = False
                elif change == "cache_changed":
                    bad["old_cache_preservation"]["after_old_disable"]["objects_sha256"] = "d" * 64
                else:
                    bad["commands"][0]["observation"]["installed"][0]["source"]["path"] = fixture_path("other")
                with self.assertRaises(U.UpgradeError, msg=change):
                    U._verify_old_disable(subject, bad, live, marks, fixture_path("new-hook"), installed)

    def test_rejected_hook_emits_only_bounded_diagnostic(self):
        source = fixture_path("isolated", "cache", "old", "hooks", "hooks.json")
        original = U._inventory(inventory(source), {source: "0.16.1"})
        updated = copy.deepcopy(original)
        updated[("userPromptSubmit", source)]["displayOrder"] += 9
        client = object.__new__(U.UpgradeClient)
        client.rows, client.pending, client.log, client.q = [], {}, io.StringIO(), U.queue.Queue()
        client.approved, client.initial_approved = updated, original
        client.initial_sources, client.guard_diagnostic = {source: "0.16.1"}, None
        run = hook("private-run-id", source, "userPromptSubmit")
        synthetic_secret = uuid.uuid4().hex
        synthetic_prompt = uuid.uuid4().hex
        run.update(displayOrder=original[("userPromptSubmit", source)]["displayOrder"],
                   secret=synthetic_secret, prompt=synthetic_prompt)
        client.q.put({"method": "hook/started", "params": {"threadId": "private-thread-id", "run": run}})
        with self.assertRaises(U.UpgradeError):
            client.receive(U.time.monotonic() + 1)
        diagnostic = client.guard_diagnostic
        self.assertFalse(diagnostic["order_matches"])
        self.assertTrue(diagnostic["old_inventory_order_matches"])
        self.assertEqual("old", diagnostic["source_class"])
        for private_value in ("private-run-id", "private-thread-id", synthetic_secret, synthetic_prompt, source):
            self.assertNotIn(private_value, json.dumps(diagnostic))
        self.assertEqual("", client.log.getvalue())

    def test_artifact_walk_uses_complete_path_metadata_when_cached_fields_are_zero(self):
        # Windows DirEntry metadata can omit identity and link count. The
        # artifact is still a real regular single-link file; never accept or
        # reject it from those incomplete cached fields.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "public.txt"
            target.write_bytes(b"synthetic public artifact\n")
            cached = mock.Mock()
            cached.st_mode = target.lstat().st_mode
            cached.st_file_attributes = 0
            cached.st_nlink = cached.st_dev = cached.st_ino = 0
            entry = mock.Mock(name="cached directory entry")
            entry.name, entry.path = target.name, str(target)
            entry.stat.return_value = cached
            scan = mock.MagicMock()
            scan.__enter__.return_value = [entry]
            expected = {"public.txt": U.sha(target)}
            with mock.patch.object(U.os, "scandir", return_value=scan):
                self.assertEqual(expected, U.source_files(root))

    def test_inventory_requires_nine_trusted_per_exact_source(self):
        source = fixture_path("isolated", "cache", "old", "hooks", "hooks.json")
        good = inventory(source)
        self.assertEqual(9, len(U._inventory(good, {source: "0.16.1"})))
        for change in ("untrusted", "source", "duplicate"):
            bad = copy.deepcopy(good)
            rows = bad["data"][0]["hooks"]
            if change == "untrusted":
                rows[0]["trustStatus"] = "untrusted"
            elif change == "source":
                rows[0]["sourcePath"] = "/other/hooks.json"
            else:
                rows[0] = copy.deepcopy(rows[1])
            with self.assertRaises(U.UpgradeError):
                U._inventory(bad, {source: "0.16.1"})

    def test_windows_source_case_normalizes_without_accepting_path_traversal(self):
        expected = r"C:\fixture\cache\hooks\hooks.json"
        with mock.patch.object(U.platform, "system", return_value="Windows"):
            self.assertEqual(expected, U._source_key(r"c:\fixture\CACHE\hooks\hooks.json", [expected]))
            self.assertIsNone(U._source_key(r"C:\fixture\cache\..\hooks\hooks.json", [expected]))
            with self.assertRaises(U.UpgradeError):
                U._require_distinct_sources(expected, r"c:\fixture\CACHE\hooks\hooks.json")

    def test_archive_requires_real_same_thread_paired_end_with_3s_budget(self):
        source, thread = fixture_path("isolated", "cache", "old", "hooks", "hooks.json"), "thread-1"
        inv = U._inventory(inventory(source), {source: "0.16.1"})
        rows = [{"direction": "request", "message": {"id": 1, "method": "thread/archive", "params": {"threadId": thread}}},
                {"direction": "response", "message": {"method": "hook/started", "params": {"threadId": thread,
                    "run": hook("r", source, "sessionEnd")}}},
                {"direction": "response", "message": {"method": "hook/completed", "params": {"threadId": thread,
                    "run": hook("r", source, "sessionEnd", "completed", 3000)}}},
                {"direction": "response", "message": {"id": 1, "result": {}}}]
        U.verify_archive(rows, inv, thread)
        zero = copy.deepcopy(rows)
        zero[-2]["message"]["params"]["run"]["durationMs"] = 0
        U.verify_archive(zero, inv, thread)
        for mutate in ("unsubscribe", "unpaired", "slow", "negative", "thread", "source", "archive_error"):
            bad = copy.deepcopy(rows)
            if mutate == "unsubscribe":
                bad[0]["message"]["method"] = "thread/unsubscribe"
            elif mutate == "unpaired":
                bad.pop(1)
            elif mutate == "slow":
                bad[-2]["message"]["params"]["run"]["durationMs"] = 3001
            elif mutate == "negative":
                bad[-2]["message"]["params"]["run"]["durationMs"] = -1
            elif mutate == "thread":
                bad[-2]["message"]["params"]["threadId"] = "other"
            elif mutate == "source":
                bad[-2]["message"]["params"]["run"]["sourcePath"] = "/other"
            else:
                bad[-1]["message"] = {"id": 1, "error": {"message": "refused"}}
            with self.assertRaises(U.UpgradeError, msg=mutate):
                U.verify_archive(bad, inv, thread)

    def test_continuity_checks_same_session_and_exact_pending_digest(self):
        state = {"session": {"id": "thread"}, "requirements": [
            {"id": "R1", "sha256": "a" * 64, "status": "pending"}]}
        U.validate_continuity(state, copy.deepcopy(state))
        for key in ("session", "hash", "pending"):
            bad = copy.deepcopy(state)
            if key == "session":
                bad["session"]["id"] = "different"
            elif key == "hash":
                bad["requirements"][0]["sha256"] = "b" * 64
            else:
                bad["requirements"][0]["status"] = "pass"
            with self.assertRaises(U.UpgradeError):
                U.validate_continuity(state, bad)

    def test_state_projection_never_persists_prompt_or_private_fields(self):
        state = {"session": {"id": "thread", "private": "do-not-keep"},
                 "requirements": [{"id": "R1", "sha256": "a" * 64, "status": "pending", "work_unit_id": "WU1",
                                   "text": "do-not-keep"}],
                 "mode": {"active": True}, "compactions": [{"private": "do-not-keep"}],
                 "pending": {"recovery": {"state": "consumed", "packet": "do-not-keep"}},
                 "prompts": [{"text": "do-not-keep"}]}
        projection = U._state_projection(state)
        self.assertNotIn("do-not-keep", json.dumps(projection))
        self.assertEqual(1, projection["compactions_count"])
        self.assertEqual("consumed", projection["recovery_state"])

    def test_rpc_projection_does_not_keep_unrelated_content(self):
        client = object.__new__(U.UpgradeClient)
        client.pending = {1: "thread/start", 2: "hooks/list"}
        response = client._projection({"id": 1, "result": {"thread": {"id": "t", "secret": "do-not-keep"},
                                                            "auth": "do-not-keep"}})
        self.assertEqual({"id": 1, "result": {"thread": {"id": "t"}}}, response)
        client.pending[3] = "thread/start"
        response = client._projection({"id": 3, "result": {"thread": {"id": "t", "private": "do-not-keep"},
            "model": "gpt-6.1-sol", "modelProvider": "openai", "extra": "do-not-keep"}})
        self.assertEqual({"id": 3, "result": {"thread": {"id": "t"}, "model": "gpt-6.1-sol",
                                               "modelProvider": "openai"}}, response)
        client.pending[4] = "thread/start"
        response = client._projection({"id": 4, "result": {"thread": {"id": "t"},
                                                            "model": "do-not-keep\nprivate"}})
        self.assertNotIn("model", response["result"])
        client.pending[5] = "thread/start"
        response = client._projection({"id": 5, "result": {"thread": {"id": "t"},
            "model": ("sk-" + "syntheticSecretExample123456"), "modelProvider": ("sk-" + "syntheticSecretExample123456")}})
        self.assertEqual({"id": 5, "result": {"thread": {"id": "t"}}}, response)
        client.pending[6] = "thread/resume"
        response = client._projection({"id": 6, "error": {"code": -32600, "message": "do-not-keep",
                                                           "data": {"secret": "do-not-keep"}}})
        self.assertEqual({"id": 6, "error": {"redacted": True, "code": -32600}}, response)
        self.assertEqual({"method": "thread/resume", "code": -32600}, client.last_rpc_failure)
        client.pending[7] = "thread/resume"
        response = client._projection({"id": 7, "error": {"code": "do-not-keep", "message": "do-not-keep"}})
        self.assertEqual({"id": 7, "error": {"redacted": True}}, response)
        event = client._projection({"method": "item/completed", "params": {"threadId": "t",
            "turnId": "u", "item": {"id": "i", "type": "commandExecution", "cwd": "/w",
                                      "command": "do-not-keep", "exitCode": 0, "output": "do-not-keep"}}})
        self.assertNotIn("do-not-keep", json.dumps(event))
        self.assertEqual("<unapproved>", event["params"]["item"]["command"])
        message = client._projection({"method": "item/completed", "params": {
            "item": {"type": "agentMessage", "text": "do-not-keep"}}})
        self.assertNotIn("do-not-keep", json.dumps(message))

    def test_read_tool_requires_exact_completed_command_and_real_hooks(self):
        source, thread, turn = fixture_path("isolated", "cache", "old", "hooks", "hooks.json"), "thread-1", "turn-1"
        inv = U._inventory(inventory(source), {source: "0.16.1"})
        rows = []
        def add_hook(event):
            for phase in ("started", "completed"):
                run = hook(event, source, event, "completed", 1) if phase == "completed" else hook(event, source, event)
                rows.append({"direction": "response", "message": {"method": "hook/" + phase,
                    "params": {"threadId": thread, "turnId": turn, "run": run}}})
        add_hook("preToolUse")
        for phase in ("started", "completed"):
            item = {"id": "read", "type": "commandExecution", "command": "cat native-read.txt", "cwd": fixture_path("workspace")}
            if phase == "completed":
                item["exitCode"] = 0
            rows.append({"direction": "response", "message": {"method": "item/" + phase,
                "params": {"threadId": thread, "turnId": turn, "item": item}}})
        add_hook("postToolUse")
        U.verify_read_tool(rows, inv, thread, turn, "cat native-read.txt", Path(fixture_path("workspace")))
        bad = copy.deepcopy(rows)
        bad[3]["message"]["params"]["item"]["exitCode"] = 1
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(bad, inv, thread, turn, "cat native-read.txt", Path(fixture_path("workspace")))

    def test_actual_posix_wrapper_is_projected_and_verified_without_widening(self):
        expected = "cat native-read.txt"
        wrapper = "/bin/zsh -c 'cat native-read.txt'"
        # The preceding candidate projected the expected string only on exact
        # equality, so this observed wrapper was rejected by that decoder.
        self.assertNotEqual(wrapper, expected)
        source, thread, turn = fixture_path("old", "hooks", "hooks.json"), "t", "u"
        cwd = fixture_path("workspace")
        inv = U._inventory(inventory(source), {source: "0.16.1"})
        client = object.__new__(U.UpgradeClient)
        client.pending = {}
        def hook_rows(event):
            return [{"direction": "response", "message": {"method": "hook/" + phase,
                "params": {"threadId": thread, "turnId": turn, "run":
                    hook(event, source, event, "completed", 1) if phase == "completed" else hook(event, source, event)}}}
                    for phase in ("started", "completed")]
        def projected(phase, raw, *, item_id="read", workdir=cwd):
            item = {"id": item_id, "type": "commandExecution", "cwd": workdir, "command": raw,
                    "aggregatedOutput": "do-not-keep"}
            if phase == "completed":
                item["exitCode"] = 0
            with mock.patch.object(U.platform, "system", return_value="Darwin"):
                value = client._projection({"method": "item/" + phase,
                    "params": {"threadId": thread, "turnId": turn, "item": item}})
            self.assertNotIn("do-not-keep", json.dumps(value))
            return {"direction": "response", "message": value}
        prefix, suffix = hook_rows("preToolUse"), hook_rows("postToolUse")
        for raw in (expected, wrapper, "/bin/zsh -lc 'cat native-read.txt'"):
            a, b = projected("started", raw), projected("completed", raw)
            self.assertEqual(raw, a["message"]["params"]["item"]["command"])
            U.verify_read_tool(prefix + [a, b] + suffix, inv, thread, turn, expected, Path(cwd))
        bad_commands = (wrapper + "; whoami", wrapper + " > file", wrapper + " $(whoami)",
                        "/bin/zsh -c 'cat native-read.txt; whoami'", "/bin/zsh -c 'cat other.txt'",
                        "/bin/zsh -c 'cat native-read.txt > file'", "/bin/zsh -c 'cat $(whoami)'",
                        "zsh -c 'cat native-read.txt'", "/tmp/zsh -c 'cat native-read.txt'",
                        "/bin/zsh -c \"/bin/zsh -c 'cat native-read.txt'\"", "do-not-keep")
        for raw in bad_commands:
            a = projected("started", raw)
            self.assertEqual("<unapproved>", a["message"]["params"]["item"]["command"])
            with self.assertRaises(U.UpgradeError, msg=raw):
                U.verify_read_tool(prefix + [a, projected("completed", raw)] + suffix,
                                   inv, thread, turn, expected, Path(cwd))
            tampered = [projected("started", expected), projected("completed", expected)]
            for row in tampered:
                row["message"]["params"]["item"]["command"] = raw
            with self.assertRaises(U.UpgradeError, msg=raw):
                U.verify_read_tool(prefix + tampered + suffix, inv, thread, turn, expected, Path(cwd))
        for b in (projected("completed", expected), projected("completed", wrapper, item_id="other"),
                  projected("completed", wrapper, workdir=fixture_path("different"))):
            with self.assertRaises(U.UpgradeError):
                U.verify_read_tool(prefix + [projected("started", wrapper), b] + suffix,
                                   inv, thread, turn, expected, Path(cwd))
        rows = prefix + [projected("started", expected), projected("completed", expected)] + suffix
        client = object.__new__(U.UpgradeClient)
        client.pending = {}
        projected = client._projection({"method": "item/started", "params": {
            "threadId": thread, "turnId": turn,
            "item": {"type": "mcpToolCall", "id": "other", "arguments": "do-not-keep"}}})
        self.assertNotIn("do-not-keep", json.dumps(projected))
        journal = copy.deepcopy(rows)
        journal.insert(4, {"direction": "response", "message": projected})
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(journal, inv, thread, turn, "cat native-read.txt", Path(fixture_path("workspace")))
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(rows[2:], inv, thread, turn, "cat native-read.txt", Path(fixture_path("workspace")))
        reordered = rows[0:2] + rows[4:6] + rows[2:4]
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(reordered, inv, thread, turn, "cat native-read.txt", Path(fixture_path("workspace")))
        bad = copy.deepcopy(rows)
        bad[2]["message"]["params"]["item"]["command"] = "cat other.txt"
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(bad, inv, thread, turn, "cat native-read.txt", Path(fixture_path("workspace")))
        bad = copy.deepcopy(rows)
        bad.insert(4, {"direction": "response", "message": {"method": "item/started",
                   "params": {"threadId": thread, "turnId": turn,
                              "item": {"type": "unknownTool", "id": "other"}}}})
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(bad, inv, thread, turn, "cat native-read.txt", Path(fixture_path("workspace")))

    def test_windows_powershell_wrapper_retains_only_the_controlled_read(self):
        expected = "Get-Content -LiteralPath native-read.txt"
        shell = (r"C:\Program Files\WindowsApps\OpenAI.CodexPrimaryRuntime.v26-1104-709-0"
                 r"_26.1104.709.0_x64__3k8sg7r9htsxt\dependencies\native\powershell\pwsh.exe")
        wrapper = f'"{shell}" -NoProfile -Command \'{expected}\''
        escaped = wrapper.replace(shell, shell.replace("\\", "\\\\"))
        good = (expected, wrapper, escaped, wrapper.replace(shell, "\\\\?\\" + shell))
        bad = (wrapper + " ; whoami", wrapper.replace("native-read.txt", "other.txt"),
               wrapper.replace("native-read.txt", "native-read.txt > output.txt"),
               wrapper.replace(shell, r"C:\temporary\pwsh.exe"),
               f"powershell -Command '{expected}'", wrapper.replace("-NoProfile ", ""),
               wrapper.replace("C:\\", "C:\\\\"))
        client = object.__new__(U.UpgradeClient)
        client.pending = {}
        with mock.patch.object(U.platform, "system", return_value="Windows"):
            for raw in good + bad:
                with self.subTest(command=raw):
                    self.assertEqual(raw in good, U._approved_read_command(raw, expected))
                    item = {"type": "commandExecution", "id": "read", "command": raw,
                            "aggregatedOutput": "do-not-keep"}
                    projected = client._projection({"method": "item/started", "params": {"item": item}})
                    self.assertEqual(raw if raw in good else "<unapproved>", projected["params"]["item"]["command"])
                    self.assertNotIn("do-not-keep", json.dumps(projected))

    def test_unanswered_command_approval_records_only_its_classification(self):
        client = object.__new__(U.UpgradeClient)
        client.rows = []
        client.q = U.queue.Queue()
        client.q.put({"id": 5, "method": "item/commandExecution/requestApproval",
                      "params": {"reason": "do-not-keep"}})
        with self.assertRaisesRegex(U.UpgradeError, "unexpected app-server input"):
            client.receive(U.time.monotonic() + 1)
        self.assertEqual({"method": "item/commandExecution/requestApproval", "reason": "server_approval_required"},
                         client.last_rpc_failure)
        self.assertEqual([], client.rows)

    def test_disable_requires_official_write_and_post_write_empty_inventory(self):
        source = fixture_path("isolated", "cache", "new", "hooks", "hooks.json")
        new_inv = U._inventory(inventory(source), {source: U.NEW_VERSION})
        params = {"edits": [{"keyPath": 'plugins."context-guard@codex-context-guard".enabled',
                             "value": False, "mergeStrategy": "upsert"}], "reloadUserConfig": True}
        rows = [{"direction": "local", "event": "transition_completed"},
                {"direction": "request", "message": {"id": 1, "method": "config/batchWrite", "params": params}},
                {"direction": "response", "message": {"id": 1, "result": {}}},
                {"direction": "request", "message": {"id": 2, "method": "hooks/list", "params": {}}},
                {"direction": "response", "message": {"id": 2, "result": {"data": [{"hooks": []}]}}},
                {"direction": "local", "event": "disable_completed"}]
        marks = {"transition_completed": 0, "disable_completed": 5}
        U._verify_disable_rpc(rows, marks, source, new_inv, [], "0.16.1")
        bad = copy.deepcopy(rows)
        bad[4]["message"]["result"]["data"][0]["hooks"] = inventory(source)["data"][0]["hooks"]
        with self.assertRaises(U.UpgradeError):
            U._verify_disable_rpc(bad, marks, source, new_inv, [], "0.16.1")
        bad = copy.deepcopy(rows)
        bad[2]["message"] = {"id": 1, "error": {"redacted": True}}
        with self.assertRaises(U.UpgradeError):
            U._verify_disable_rpc(bad, marks, source, new_inv, [], "0.16.1")
        bad = copy.deepcopy(rows)
        bad.insert(3, {"direction": "request", "message": {"id": 3, "method": "config/batchWrite", "params": {}}})
        bad.insert(4, {"direction": "response", "message": {"id": 3, "result": {}}})
        with self.assertRaises(U.UpgradeError):
            U._verify_disable_rpc(bad, {"transition_completed": 0, "disable_completed": 7}, source,
                                  new_inv, [], "0.16.1")

    def test_official_lifecycle_consumer_rejects_forged_or_missing_facts(self):
        subject, prepared, result = lifecycle_facts()
        with mock.patch.object(U, "_sentinel_files", return_value=subject["sentinel"]):
            U._verify_cli_lifecycle(subject, prepared, result)
            for mutation in ("disabled", "unrelated", "wrong_source", "extra_remove", "no_market_remove"):
                bad = copy.deepcopy(result)
                if mutation == "disabled":
                    bad["commands"][11]["observation"]["installed"][0]["enabled"] = True
                elif mutation == "unrelated":
                    bad["sentinel_phases"]["after_disable"] = {}
                elif mutation == "wrong_source":
                    bad["commands"][6]["observation"]["marketplaces"][1]["root"] = "/wrong"
                elif mutation == "extra_remove":
                    bad["commands"].append(command_fact([subject["codex"], "plugin", "remove", "unrelated"]))
                else:
                    bad["commands"].pop(16)
                with self.assertRaises(U.UpgradeError, msg=mutation):
                    U._verify_cli_lifecycle(subject, prepared, bad)
            for mutation in ("unscoped_prepare", "missing_cache", "registered_old", "unscoped_remove", "wrong_scope"):
                bad_prepare, bad_result = copy.deepcopy(prepared), copy.deepcopy(result)
                if mutation == "unscoped_prepare":
                    bad_prepare["commands"][2]["argv"] = [subject["codex"], "plugin", "list", "--json"]
                elif mutation == "missing_cache":
                    del bad_prepare["before"]["target_cache_absent"]
                elif mutation == "registered_old":
                    bad_prepare["commands"][1]["observation"]["marketplaces"].append({"name": "codex-context-guard"})
                elif mutation == "unscoped_remove":
                    bad_result["commands"][14]["argv"] = [subject["codex"], "plugin", "list", "--json"]
                else:
                    bad_result["commands"][14]["observation"]["installed"] = [
                        {"pluginId": "other@other", "marketplaceName": "other"}]
                with self.assertRaises(U.UpgradeError, msg=mutation):
                    U._verify_cli_lifecycle(subject, bad_prepare, bad_result)
            for target, index in (("prepare", 7), ("run", 1), ("run", 9), ("run", 11)):
                for field in ("source", "marketplaceSource"):
                    bad_prepare, bad_result = copy.deepcopy(prepared), copy.deepcopy(result)
                    receipt = bad_prepare if target == "prepare" else bad_result
                    entry = receipt["commands"][index]["observation"]["installed"][0]
                    entry[field]["source" if field == "source" else "sourceType"] = "remote"
                    with self.subTest(target=target, index=index, field=field), self.assertRaises(U.UpgradeError):
                        U._verify_cli_lifecycle(subject, bad_prepare, bad_result)

    def test_market_root_only_projection_and_all_lifecycle_readbacks(self):
        subject, prepared, result = lifecycle_facts()
        codex = subject["codex"]
        argv = [codex, "plugin", "marketplace", "list", "--json"]
        selected = {U.NEW_MARKET}
        for receipt in (prepared, result):
            for fact in receipt["commands"]:
                if fact["argv"] == argv:
                    for entry in fact["observation"]["marketplaces"]:
                        entry.pop("marketplaceSource", None)
                    raw = subprocess.CompletedProcess(argv, 0, json.dumps(fact["observation"]).encode(), b"")
                    fact["observation"] = U._project_cli(argv, raw, selected)
        with mock.patch.object(U, "_sentinel_files", return_value=subject["sentinel"]):
            U._verify_cli_lifecycle(subject, prepared, result)
            for receipt_name, original in (("prepare", prepared), ("run", result)):
                for index, fact in enumerate(original["commands"]):
                    if fact["argv"] != argv:
                        continue
                    selected_entries = [entry for entry in fact["observation"]["marketplaces"]
                                        if entry["name"] == U.NEW_MARKET]
                    if not selected_entries:
                        continue
                    for mutation in ("missing_root", "wrong_root", "duplicate", "null", "empty", "remote", "conflict"):
                        bad_prepare, bad_result = copy.deepcopy(prepared), copy.deepcopy(result)
                        target = bad_prepare if receipt_name == "prepare" else bad_result
                        entries = target["commands"][index]["observation"]["marketplaces"]
                        entry = next(item for item in entries if item["name"] == U.NEW_MARKET)
                        if mutation == "missing_root":
                            del entry["root"]
                        elif mutation == "wrong_root":
                            entry["root"] = fixture_path("other")
                        elif mutation == "duplicate":
                            entries.append(copy.deepcopy(entry))
                        else:
                            entry["marketplaceSource"] = {"null": None, "empty": {},
                                "remote": {"sourceType": "git", "source": entry["root"]},
                                "conflict": {"sourceType": "local", "source": fixture_path("other")}}[mutation]
                        with self.subTest(receipt=receipt_name, index=index, mutation=mutation), self.assertRaises(U.UpgradeError):
                            U._verify_cli_lifecycle(subject, bad_prepare, bad_result)
        for origin in (None, {}, {"sourceType": "git", "source": "remote"}):
            data = {"marketplaces": [{"name": U.NEW_MARKET, "root": subject["old_artifact"],
                                      "marketplaceSource": origin}]}
            raw = subprocess.CompletedProcess(argv, 0, json.dumps(data).encode(), b"")
            with self.assertRaises(U.UpgradeError):
                U._project_cli(argv, raw, selected)

    def test_market_sequence_preserves_old_0161_identity(self):
        subject, _, _ = lifecycle_facts()
        subject["old_version"] = "0.16.1"
        codex, old, new = subject["codex"], subject["old_artifact"], subject["new_artifact"]
        sentinel_name, old_market = subject["sentinel"]["marketplace"], U.OLD_MARKETS["0.16.1"]
        listing = [codex, "plugin", "marketplace", "list", "--json"]
        def read(markets):
            return command_fact(listing, {"marketplaces": [{"name": sentinel_name}] + markets})
        old_row = {"name": old_market, "root": old}
        new_row = {"name": U.NEW_MARKET, "root": new}
        commands = [read([old_row]), command_fact([codex, "plugin", "marketplace", "add", new]),
                    read([old_row, new_row]), command_fact([codex, "plugin", "marketplace", "remove", U.NEW_MARKET]),
                    read([old_row])]
        U._verify_market_sequence(commands, subject, prepared=False)
        for index, mutation in ((0, "preexisting"), (2, "missing_old"), (2, "wrong_old"), (4, "missing_old")):
            bad = copy.deepcopy(commands)
            entries = bad[index]["observation"]["marketplaces"]
            if mutation == "preexisting":
                entries.append(new_row)
            elif mutation == "missing_old":
                entries[:] = [row for row in entries if row["name"] != old_market]
            else:
                next(row for row in entries if row["name"] == old_market)["root"] = new
            with self.subTest(index=index, mutation=mutation), self.assertRaises(U.UpgradeError):
                U._verify_market_sequence(bad, subject, prepared=False)

    def test_final_readback_preserves_wrapper_marketplace_root(self):
        wrapper = fixture_path("wrapper")
        package = str(Path(wrapper) / "artifact")
        plan = {"old_version": "0.16.1", "old_marketplace_root": wrapper, "old_artifact": package}
        market = U.OLD_0161_WRAPPER_MARKET
        entries = {market: {"name": market, "root": wrapper,
                            "marketplaceSource": {"sourceType": "local", "source": wrapper}}}
        U._verify_retained_old_market(entries, plan)
        with self.assertRaises(U.UpgradeError):
            U._verify_retained_old_market({}, plan)
        entries[market]["root"] = package
        entries[market]["marketplaceSource"]["source"] = package
        with self.assertRaises(U.UpgradeError):
            U._verify_retained_old_market(entries, plan)

    def test_official_command_records_failure_before_return_without_output(self):
        argv = ["/safe/codex", "plugin", "list", "--marketplace", "cg-u01-sentinel-test", "--json"]
        for response in (U.scheduler.SchedulerBatchError("synthetic timeout"),
                         subprocess.CompletedProcess(argv, 4, b"synthetic private stdout", b"synthetic private stderr")):
            result = {"commands": []}
            with mock.patch.object(U.scheduler, "_command", side_effect=response if isinstance(response, Exception)
                                   else None, return_value=response):
                with self.assertRaises((U.scheduler.SchedulerBatchError, U.UpgradeError)):
                    U._run_official(result, argv, {}, {"cg-u01-sentinel-test"}, "prepare")
            fact = result["commands"][0]
            self.assertEqual(argv, fact["argv"])
            self.assertEqual("prepare", fact["stage"])
            self.assertEqual("failed", fact["status"])
            self.assertIn("failure_type", fact)
            self.assertNotIn("synthetic", json.dumps(fact))

    def test_complete_finish_old_consumer_and_missing_session_end_negative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "result"
            (output / "live").mkdir(parents=True)
            subject, prepared, result = lifecycle_facts()
            old_path = prepared["official_add"]["installedPath"]
            new_path = result["installed_new"]["path"]
            old_source, new_source = str(Path(old_path) / "hooks/hooks.json"), str(Path(new_path) / "hooks/hooks.json")
            old_hooks, new_hooks = inventory(old_source)["data"][0]["hooks"], inventory(new_source)["data"][0]["hooks"]
            subject.update({"product_commit": "a" * 40, "toolkit_commit": "b" * 40,
                            "product_root": fixture_path("product"), "workspace": fixture_path("workspace"),
                            "old_data_root": str(Path(subject["home"]) / "old-data"),
                            "new_data_root": str(Path(subject["home"]) / "new-data"),
                            "transition_strategy": "finish-old", "platform": "Darwin", "read_file_sha256": "c" * 64})
            prepared.update({"schema": U.REPORT, "status": "pending", "stage": "prepare", "subject": subject,
                             "installed": {"path": old_path}})
            prepared_path = root / "prepare.json"
            prepared_path.write_text(json.dumps(prepared))
            rows = []

            def request(i, method, params, response=None):
                rows.append({"direction": "request", "message": {"id": i, "method": method, "params": params}})
                rows.append({"direction": "response", "message": {"id": i, "result": response or {}}})

            def event(method, thread, turn, data):
                params = {"threadId": thread, **({"turnId": turn} if turn else {}), **data}
                rows.append({"direction": "response", "message": {"method": method, "params": params}})

            def hook_pair(thread, turn, event_name, source):
                event("hook/started", thread, turn, {"run": hook(event_name + thread, source, event_name)})
                event("hook/completed", thread, turn, {"run": hook(event_name + thread, source, event_name, "completed", 1)})

            def turn(i, thread, turn_id, source, read=False, prompt=None):
                params = {"threadId": thread}
                if prompt is not None:
                    params["input"] = [{"type": "text", "text": prompt}]
                request(i, "turn/start", params, {"turn": {"id": turn_id}})
                event("turn/started", thread, None, {"turn": {"id": turn_id}})
                if read:
                    hook_pair(thread, turn_id, "preToolUse", source)
                    item = {"id": "read", "type": "commandExecution", "command": "cat native-read.txt",
                            "cwd": subject["workspace"]}
                    event("item/started", thread, turn_id, {"item": item})
                    event("item/completed", thread, turn_id, {"item": {**item, "exitCode": 0}})
                    hook_pair(thread, turn_id, "postToolUse", source)
                hook_pair(thread, turn_id, "stop", source)
                event("turn/completed", thread, None, {"turn": {"id": turn_id, "status": "completed"}})

            def archive(i, thread, source):
                rows.append({"direction": "request", "message": {"id": i, "method": "thread/archive",
                             "params": {"threadId": thread}}})
                hook_pair(thread, None, "sessionEnd", source)
                rows.append({"direction": "response", "message": {"id": i, "result": {}}})

            def mark(name, tick, pid=123):
                rows.append({"direction": "local", "event": name, "pid": pid, "monotonic_ns": tick})

            request(1, "hooks/list", {}, {"data": [{"hooks": old_hooks}]})
            request(100, "thread/start", {}, {"thread": {"id": "A"}})
            request(101, "thread/start", {}, {"thread": {"id": "B"}})
            turn(2, "A", "A1", old_source, read=True)
            turn(3, "B", "B1", old_source)
            request(4, "thread/compact/start", {"threadId": "A"})
            event("turn/started", "A", None, {"turn": {"id": "C1"}})
            hook_pair("A", "C1", "preCompact", old_source)
            event("item/started", "A", "C1", {"item": {"id": "compact", "type": "contextCompaction"}})
            event("item/completed", "A", "C1", {"item": {"id": "compact", "type": "contextCompaction"}})
            event("thread/status/changed", "A", None, {"status": {"type": "idle"}})
            turn(5, "A", "A2", old_source)
            turn(50, "A", "AC", old_source, prompt="取消当前任务。")
            turn(51, "B", "BC", old_source, prompt="取消当前任务。")
            archive(6, "A", old_source)
            archive(7, "B", old_source)
            mark("transition_started", 35)
            mark("transition_completed", 115)
            request(8, "hooks/list", {}, {"data": [{"hooks": new_hooks}]})
            request(102, "thread/start", {}, {"thread": {"id": "F"}})
            turn(9, "F", "F1", new_source, read=True)
            request(52, "thread/compact/start", {"threadId": "F"})
            event("turn/started", "F", None, {"turn": {"id": "FC"}})
            hook_pair("F", "FC", "preCompact", new_source)
            event("item/started", "F", "FC", {"item": {"id": "compact-f", "type": "contextCompaction"}})
            event("item/completed", "F", "FC", {"item": {"id": "compact-f", "type": "contextCompaction"}})
            event("thread/status/changed", "F", None, {"status": {"type": "idle"}})
            turn(53, "F", "F2", new_source)
            request(54, "thread/unsubscribe", {"threadId": "F"})
            journal = output / "live/rpc.jsonl"
            journal.write_text("".join(json.dumps(row) + "\n" for row in rows))
            live_rows = rows
            rows = []
            request(201, "hooks/list", {}, {"data": [{"hooks": new_hooks}]})
            rows.append({"direction": "observation", "event": "cold_client_started", "pid": 456,
                         "started_monotonic_ns": 119, "monotonic_ns": 120})
            request(202, "thread/resume", {"threadId": "F", "cwd": subject["workspace"],
                                            "sandbox": "read-only", "approvalPolicy": "on-request", "excludeTurns": True})
            hook_pair("F", None, "sessionStart", new_source)
            turn(203, "F", "F3", new_source)
            turn(205, "F", "F4", new_source, prompt="取消当前任务。")
            archive(204, "F", new_source)
            disable = {"edits": [{"keyPath": 'plugins."context-guard@codex-context-guard".enabled',
                                  "value": False, "mergeStrategy": "upsert"}], "reloadUserConfig": True}
            request(11, "config/batchWrite", disable)
            request(12, "hooks/list", {}, {"data": [{"hooks": []}]})
            mark("disable_completed", 125, 456)
            mark("plugin_removed", 155, 456)
            mark("marketplace_removed", 185, 456)
            (output / "cold").mkdir()
            (output / "cold/rpc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
            rows = live_rows
            pending = [{"id": "R1", "sha256": "a" * 64, "status": "pending", "work_unit_id": "WU1"}]

            def snapshot(thread, count, recovery):
                return {"session": {"id": thread}, "requirements": pending, "mode": {"active": True},
                        "compactions_count": count, "recovery_state": recovery}

            for name, value in {"before-compact.json": snapshot("A", 0, None),
                "before-a.json": snapshot("A", 1, "consumed"), "before-b.json": snapshot("B", 0, None),
                "retained-a.json": snapshot("A", 1, "consumed"), "retained-b.json": snapshot("B", 0, None),
                "fresh-after-transition.json": snapshot("F", 0, None),
                "fresh-after-compact.json": snapshot("F", 1, "consumed"),
                "fresh-after-cold.json": snapshot("F", 1, "consumed")}.items():
                (output / name).write_text(json.dumps(value))
            for name, thread in (("a", "A"), ("b", "B"), ("fresh", "F")):
                original = {"id": "R1", "sha256": "a" * 64, "work_unit_id": "WU1", "status": "pending"}
                cancel_sha = hashlib.sha256("取消当前任务。".encode()).hexdigest()
                before_state = {"session": {"id": thread}, "requirements": [original]}
                after_state = {"session": {"id": thread}, "requirements": [original,
                    {"id": "R2", "sha256": cancel_sha, "work_unit_id": "WU1", "prompt_id": "P2", "status": "answered"}],
                    "prompts": [{"id": "P2", "sha256": cancel_sha, "record_sha256": "f" * 64,
                                 "core_event_seq": 4, "origin": "human"}],
                    "root_controls": [{"kind": "cancel", "source_prompt_id": "P2", "scope_kind": "current_unit",
                        "source_record_sha256": "f" * 64, "source_seq": 4,
                        "work_unit_id": "WU1", "catalog_sha256": "c" * 64,
                        "items": [{"id": "R1", "source_sha256": "a" * 64, "work_unit_id": "WU1"}]}],
                    "work_units": [{"id": "WU1", "status": "historical_unresolved"}]}
                proof = U._cancel_evidence(before_state, after_state, {"current": [], "ancestor": [], "waiting": 0})
                proof["state_sha256"] = "d" * 64
                filename = "fresh-cancel.json" if name == "fresh" else "cancel-" + name + ".json"
                (output / filename).write_text(json.dumps(proof))
            data_facts = {"synthetic": "a" * 64}
            result.update({"schema": U.REPORT, "status": "pending", "stage": "open_transition",
                "subject": subject, "pending": ["independent_consumer"], "old_inventory": old_hooks,
                "new_inventory": new_hooks, "disabled_inventory": [],
                "before": {"thread_a": "A", "thread_b": "B", "turn_a": "A1", "turn_b": "B1",
                    "post_compact_turn": "A2", "cancel_turns": {"a": "AC", "b": "BC"},
                    "data_root": subject["old_data_root"], "app_server_pid": 123,
                    "read_command": "cat native-read.txt", "read_file_sha256": "c" * 64,
                    "state_a_sha256": "d" * 64, "state_b_sha256": "e" * 64},
                "old_data_after_transition": {"thread_a_sha256": "d" * 64, "thread_b_sha256": "e" * 64},
                "after": {"fresh_thread": "F", "fresh_turn": "F1", "fresh_compact_turn": "F2",
                          "fresh_cold_turn": "F3", "fresh_cancel_turn": "F4", "cold_session_start_phase": "before_first_turn",
                          "cold_session_started_before_first_turn": True,
                          "data_root": subject["new_data_root"]},
                "installed_new": {"path": new_path, "source": subject["new_artifact"], "version": U.NEW_VERSION,
                                  "files": {"public": "b" * 64}},
                "selected_data_before_removal": data_facts, "selected_data_after_removal": data_facts,
                "cleanup": [{"role": "live", "pid": 123, "closed_monotonic_ns": 118,
                             "facts": {"owned_process_exited": True, "owned_tree_no_running_members": True,
                                       "process_group_cleanup_error": None}},
                            {"role": "cold", "pid": 456, "closed_monotonic_ns": 190,
                             "facts": {"owned_process_exited": True, "owned_tree_no_running_members": True,
                                       "process_group_cleanup_error": None}}]})
            for index, item in enumerate(result["commands"]):
                item["started_monotonic_ns"] = 10 + 10 * index
                item["completed_monotonic_ns"] = 11 + 10 * index
            result["artifacts"] = {p.relative_to(output).as_posix(): U.sha(p) for p in output.rglob("*") if p.is_file()}
            (output / "result.json").write_text(json.dumps(result))
            manager = mock.Mock()
            manager.distribution_manifest.return_value = {"public": "b" * 64}
            with mock.patch.object(U, "preflight", return_value=subject), \
                 mock.patch.object(U, "_verify_replay_subject", side_effect=lambda plan, probe: (U.preflight(plan, probe), "c" * 40, "d" * 64)), \
                 mock.patch.object(U.native, "load_artifacts", return_value=manager), \
                 mock.patch.object(U, "_selected_states", return_value=data_facts), \
                 mock.patch.object(U, "_sentinel_files", return_value=subject["sentinel"]):
                accepted = U.verify({}, output, prepared_path)
                self.assertEqual("cancelled_old_before_transition", accepted["observed_boundary"])
                for mutation in ("same_pid", "role_swap", "premature_cold", "duplicate_cleanup"):
                    bad = copy.deepcopy(result)
                    if mutation == "same_pid":
                        bad["cleanup"][1]["pid"] = bad["cleanup"][0]["pid"]
                    elif mutation == "role_swap":
                        bad["cleanup"][0]["role"], bad["cleanup"][1]["role"] = "cold", "live"
                    elif mutation == "premature_cold":
                        bad["cleanup"][0]["closed_monotonic_ns"] = 120
                    else:
                        bad["cleanup"].append(copy.deepcopy(bad["cleanup"][0]))
                    (output / "result.json").write_text(json.dumps(bad))
                    with self.assertRaises(U.UpgradeError, msg=mutation):
                        U.verify({}, output, prepared_path)
                cold_path = output / "cold/rpc.jsonl"
                original_cold = cold_path.read_text()
                for mutation in ("resume_missing_flag", "resume_wrong_cwd", "same_pid", "startup_before_close",
                                 "early_disable", "turn_after_disable"):
                    altered = [json.loads(line) for line in original_cold.splitlines()]
                    resume = next(row["message"]["params"] for row in altered if row.get("direction") == "request"
                                  and row.get("message", {}).get("method") == "thread/resume")
                    if mutation == "resume_missing_flag":
                        del resume["excludeTurns"]
                    elif mutation == "resume_wrong_cwd":
                        resume["cwd"] = fixture_path("wrong-workspace")
                    elif mutation == "same_pid":
                        next(row for row in altered if row.get("event") == "cold_client_started")["pid"] = 123
                    elif mutation == "startup_before_close":
                        next(row for row in altered if row.get("event") == "cold_client_started")["started_monotonic_ns"] = 117
                    elif mutation == "early_disable":
                        pair = [row for row in altered if row.get("message", {}).get("id") == 11]
                        altered = [row for row in altered if row.get("message", {}).get("id") != 11]
                        index = next(i for i, row in enumerate(altered) if row.get("message", {}).get("method") == "thread/archive")
                        altered[index:index] = pair
                    else:
                        altered.append({"direction": "request", "message": {"id": 999, "method": "turn/start", "params": {}}})
                    cold_path.write_text("".join(json.dumps(row) + "\n" for row in altered))
                    bad = copy.deepcopy(result)
                    bad["artifacts"]["cold/rpc.jsonl"] = U.sha(cold_path)
                    (output / "result.json").write_text(json.dumps(bad))
                    with self.subTest(mutation=mutation), self.assertRaises(U.UpgradeError):
                        U.verify({}, output, prepared_path)
                cold_path.write_text(original_cold)
                wrong_live = [json.loads(line) for line in journal.read_text().splitlines()]
                wrong_live.append({"direction": "request", "message": {"id": 11, "method": "config/batchWrite",
                                   "params": disable}})
                wrong_live.append({"direction": "response", "message": {"id": 11, "result": {}}})
                original_live = journal.read_text()
                journal.write_text("".join(json.dumps(row) + "\n" for row in wrong_live))
                bad = copy.deepcopy(result)
                bad["artifacts"]["live/rpc.jsonl"] = U.sha(journal)
                (output / "result.json").write_text(json.dumps(bad))
                with self.assertRaises(U.UpgradeError):
                    U.verify({}, output, prepared_path)
                journal.write_text(original_live)
                without_marker = [json.loads(line) for line in original_cold.splitlines()
                                  if json.loads(line).get("event") != "cold_client_started"]
                cold_path.write_text("".join(json.dumps(row) + "\n" for row in without_marker))
                bad = copy.deepcopy(result)
                bad["artifacts"]["cold/rpc.jsonl"] = U.sha(cold_path)
                (output / "result.json").write_text(json.dumps(bad))
                with self.assertRaises(U.UpgradeError):
                    U.verify({}, output, prepared_path)
                cold_path.write_text(original_cold)
                moved = [json.loads(line) for line in original_cold.splitlines()]
                pair = [row for row in moved if row.get("message", {}).get("id") == 201]
                moved = [row for row in moved if row.get("message", {}).get("id") != 201]
                resume_end = next(i for i, row in enumerate(moved) if row.get("direction") == "response"
                                  and row.get("message", {}).get("id") == 202)
                moved[resume_end + 1:resume_end + 1] = pair
                cold_path.write_text("".join(json.dumps(row) + "\n" for row in moved))
                bad = copy.deepcopy(result)
                bad["artifacts"]["cold/rpc.jsonl"] = U.sha(cold_path)
                (output / "result.json").write_text(json.dumps(bad))
                with self.assertRaises(U.UpgradeError):
                    U.verify({}, output, prepared_path)
                cold_path.write_text(original_cold)
                original_cancel = (output / "cancel-a.json").read_text()
                forged_cancel = json.loads(original_cancel)
                forged_cancel["after"]["root_controls"][0]["items"][0]["source_sha256"] = "e" * 64
                (output / "cancel-a.json").write_text(json.dumps(forged_cancel))
                bad = copy.deepcopy(result)
                bad["artifacts"]["cancel-a.json"] = U.sha(output / "cancel-a.json")
                (output / "result.json").write_text(json.dumps(bad))
                with self.assertRaises(U.UpgradeError):
                    U.verify({}, output, prepared_path)
                (output / "cancel-a.json").write_text(original_cancel)
                forged_cancel = json.loads(original_cancel)
                for section in ("before", "after"):
                    for row in forged_cancel[section]["requirements"]:
                        row["work_unit_id"] = "WU9"
                forged_cancel["after"]["root_controls"][0]["work_unit_id"] = "WU9"
                forged_cancel["after"]["root_controls"][0]["items"][0]["work_unit_id"] = "WU9"
                forged_cancel["after"]["work_units"][0]["id"] = "WU9"
                forged_cancel["initial_pending"][0]["work_unit_id"] = "WU9"
                forged_cancel["covered"][0]["work_unit_id"] = "WU9"
                (output / "cancel-a.json").write_text(json.dumps(forged_cancel))
                bad = copy.deepcopy(result)
                bad["artifacts"]["cancel-a.json"] = U.sha(output / "cancel-a.json")
                (output / "result.json").write_text(json.dumps(bad))
                with self.assertRaises(U.UpgradeError):
                    U.verify({}, output, prepared_path)
                (output / "cancel-a.json").write_text(original_cancel)
                missing_fresh_hook = [row for row in rows if not (row.get("direction") == "response"
                    and row.get("message", {}).get("method") == "hook/completed"
                    and row["message"].get("params", {}).get("threadId") == "F"
                    and row["message"]["params"].get("run", {}).get("eventName") == "postToolUse")]
                journal.write_text("".join(json.dumps(row) + "\n" for row in missing_fresh_hook))
                bad = copy.deepcopy(result)
                bad["artifacts"]["live/rpc.jsonl"] = U.sha(journal)
                (output / "result.json").write_text(json.dumps(bad))
                with self.assertRaises(U.UpgradeError):
                    U.verify({}, output, prepared_path)
                journal.write_text("".join(json.dumps(row) + "\n" for row in rows))
                for value in ("failed", None, "arbitrary"):
                    bad = copy.deepcopy(result)
                    bad["status"] = value
                    (output / "result.json").write_text(json.dumps(bad))
                    with self.assertRaises(U.UpgradeError):
                        U.verify({}, output, prepared_path)
                for value in (None, ""):
                    bad = copy.deepcopy(result)
                    bad["failure"] = value
                    (output / "result.json").write_text(json.dumps(bad))
                    with self.assertRaises(U.UpgradeError):
                        U.verify({}, output, prepared_path)
                bad = copy.deepcopy(result)
                bad["disabled_inventory"] = new_hooks
                (output / "result.json").write_text(json.dumps(bad))
                with self.assertRaises(U.UpgradeError):
                    U.verify({}, output, prepared_path)
                bad = copy.deepcopy(result)
                bad["commands"][5]["started_monotonic_ns"] = 116
                bad["commands"][5]["completed_monotonic_ns"] = 117
                (output / "result.json").write_text(json.dumps(bad))
                with self.assertRaises(U.UpgradeError):
                    U.verify({}, output, prepared_path)
                missing = [row for row in rows if not (row.get("direction") == "response"
                    and row.get("message", {}).get("method") == "hook/completed"
                    and row["message"].get("params", {}).get("threadId") == "B"
                    and row["message"]["params"].get("run", {}).get("eventName") == "sessionEnd")]
                journal.write_text("".join(json.dumps(row) + "\n" for row in missing))
                bad = copy.deepcopy(result)
                bad["artifacts"]["live/rpc.jsonl"] = U.sha(journal)
                (output / "result.json").write_text(json.dumps(bad))
                with self.assertRaises(U.UpgradeError):
                    U.verify({}, output, prepared_path)

                # Independent observation of one deliberately open task is not
                # allowed to masquerade as the supported cancellation boundary.
                rows[:] = []
                request(301, "hooks/list", {}, {"data": [{"hooks": old_hooks}]})
                request(302, "thread/start", {}, {"thread": {"id": "A"}})
                turn(303, "A", "A1", old_source, read=True)
                mark("transition_started", 35)
                mark("transition_completed", 115)
                request(104, "hooks/list", {}, {"data": [{"hooks": new_hooks}]})
                turn(105, "A", "A3", new_source, prompt="请仅回复观察结束。")
                request(106, "thread/unsubscribe", {"threadId": "A"})
                journal.write_text("".join(json.dumps(row) + "\n" for row in rows))
                rows[:] = []
                request(201, "hooks/list", {}, {"data": [{"hooks": new_hooks}]})
                rows.append({"direction": "observation", "event": "cold_client_started", "pid": 456, "monotonic_ns": 120})
                request(202, "thread/resume", {"threadId": "A", "cwd": subject["workspace"],
                                                "sandbox": "read-only", "approvalPolicy": "on-request", "excludeTurns": True})
                hook_pair("A", None, "sessionStart", new_source)
                turn(203, "A", "A4", new_source, prompt="请仅回复观察结束。")
                archive(204, "A", new_source)
                (output / "cold").mkdir(exist_ok=True)
                (output / "cold/rpc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
                for name in ("old-before.json", "old-after-live.json", "old-after-cold.json"):
                    (output / name).write_text(json.dumps(snapshot("A", 0, None)))
                subject["transition_strategy"] = "observe-open"
                prepared["subject"] = subject
                prepared_path.write_text(json.dumps(prepared))
                observation_commands = [copy.deepcopy(result["commands"][i]) for i in (0, 1, 3, 5, 7, 9, 15)]
                def marker(turn, seq):
                    return {"id": "P" + str(seq), "turn_id": turn,
                            "sha256": hashlib.sha256("请仅回复观察结束。".encode()).hexdigest(),
                            "record_sha256": "f" * 64, "core_event_seq": seq}
                def roots(turns):
                    return {"old": {"present": True, "state_sha256": hashlib.sha256(str(turns).encode()).hexdigest(),
                                    "prompts": [marker(turn, i + 1) for i, turn in enumerate(turns)]},
                            "new": {"present": False, "prompts": []}}
                live_trace = U._root_turn_trace(roots(["A1"]), roots(["A1", "A3"]), "A", "A3", shared=False)
                cold_trace = U._root_turn_trace(roots(["A1", "A3"]), roots(["A1", "A3", "A4"]), "A", "A4", shared=False)
                (output / "live-roots.json").write_text(json.dumps(live_trace))
                (output / "cold-roots.json").write_text(json.dumps(cold_trace))
                for name, raw_sha in (("old-before.json", live_trace["before"]["old"]["state_sha256"]),
                                      ("old-after-live.json", live_trace["after"]["old"]["state_sha256"]),
                                      ("old-after-cold.json", cold_trace["after"]["old"]["state_sha256"])):
                    (output / name).write_text(json.dumps({"source_state_sha256": raw_sha, "state": snapshot("A", 0, None)}))
                observation = {"schema": U.REPORT, "stage": "observe_open", "status": "observation_complete",
                    "subject": subject, "pending": ["independent_consumer"], "commands": observation_commands,
                    "old_inventory": old_hooks, "new_inventory": new_hooks, "sentinel_after": subject["sentinel"],
                    "before": {"thread": "A", "turn": "A1", "old_data_root": subject["old_data_root"],
                        "read_command": "cat native-read.txt", "read_file_sha256": "c" * 64,
                        "state_sha256": live_trace["before"]["old"]["state_sha256"], "app_server_pid": 123},
                    "installed_new": result["installed_new"],
                    "data_observations": {"old_root": subject["old_data_root"], "new_root": subject["new_data_root"],
                        "new_after_live": "absent", "new_after_cold": "absent"},
                    "live_observation": {"status": "observed", "turn": "A3", "stop_sources": ["new"],
                                         "actual_root": "old", "ledger_compatibility": "preserved"},
                    "cold_observation": {"status": "observed", "turn": "A4", "stop_sources": ["new"],
                        "session_start_source": "new", "session_start_phase": "before_first_turn",
                        "session_started_before_first_turn": True, "late_archive": "observed", "actual_root": "old",
                        "ledger_compatibility": "preserved"},
                    "cleanup": [{"role": "old_live", "pid": 123, "closed_monotonic_ns": 119, "facts": result["cleanup"][0]["facts"]},
                                {"role": "cold", "pid": 456, "closed_monotonic_ns": 130, "facts": result["cleanup"][1]["facts"]}]}
                observation["installed_new"] = {**result["installed_new"], "old_cache_exists": False}
                required = ("live/rpc.jsonl", "cold/rpc.jsonl", "old-before.json", "old-after-live.json", "old-after-cold.json",
                            "live-roots.json", "cold-roots.json")
                observation["artifacts"] = {name: U.sha(output / name) for name in required}
                (output / "result.json").write_text(json.dumps(observation))
                with mock.patch.object(U, "source_files", return_value={"public": "b" * 64}):
                    accepted = U.verify({}, output, prepared_path)
                    self.assertEqual("observation_complete", accepted["status"])
                    for stream in ("cold", "live"):
                        path = output / (stream + "/rpc.jsonl")
                        original = path.read_text()
                        injected = [{"direction": "request", "message": {"id": 999, "method": "config/batchWrite",
                                     "params": disable}}, {"direction": "response", "message": {"id": 999, "result": {}}}]
                        path.write_text(original + "".join(json.dumps(row) + "\n" for row in injected))
                        bad = copy.deepcopy(observation)
                        bad["artifacts"][stream + "/rpc.jsonl"] = U.sha(path)
                        (output / "result.json").write_text(json.dumps(bad))
                        with self.subTest(stream=stream), self.assertRaises(U.UpgradeError):
                            U.verify({}, output, prepared_path)
                        path.write_text(original)
                    for mutation in ("missing", "negative", "reversed", "cross_command", "late_remove"):
                        bad = copy.deepcopy(observation)
                        commands = bad["commands"]
                        if mutation == "missing":
                            del commands[-1]["started_monotonic_ns"]
                        elif mutation == "negative":
                            commands[-1]["started_monotonic_ns"] = -3
                            commands[-1]["completed_monotonic_ns"] = -2
                        elif mutation == "reversed":
                            commands[-1]["started_monotonic_ns"] = commands[-1]["completed_monotonic_ns"] + 1
                        elif mutation == "cross_command":
                            commands[-1]["started_monotonic_ns"] = commands[-2]["completed_monotonic_ns"] - 1
                        else:
                            original_times = [(row["started_monotonic_ns"], row["completed_monotonic_ns"]) for row in commands]
                            remove = next(i for i, row in enumerate(commands) if row["argv"][1:4] == ["plugin", "marketplace", "remove"])
                            item = commands.pop(remove)
                            plugin_add = next(i for i, row in enumerate(commands) if row["argv"][1:3] == ["plugin", "add"])
                            commands.insert(plugin_add + 1, item)
                            for row, (start, end) in zip(commands, original_times):
                                row["started_monotonic_ns"], row["completed_monotonic_ns"] = start, end
                        (output / "result.json").write_text(json.dumps(bad))
                        with self.subTest(mutation=mutation), self.assertRaises(U.UpgradeError):
                            U.verify({}, output, prepared_path)
                    contradiction = copy.deepcopy(live_trace)
                    contradiction["after"]["new"] = {"present": True, "state_sha256": "1" * 64, "prompts": []}
                    (output / "live-roots.json").write_text(json.dumps(contradiction))
                    bad = copy.deepcopy(observation)
                    bad["artifacts"]["live-roots.json"] = U.sha(output / "live-roots.json")
                    (output / "result.json").write_text(json.dumps(bad))
                    with self.assertRaises(U.UpgradeError):
                        U.verify({}, output, prepared_path)
                    (output / "live-roots.json").write_text(json.dumps(live_trace))
                    mismatched_live, mismatched_cold = copy.deepcopy(live_trace), copy.deepcopy(cold_trace)
                    mismatched_live["after"]["old"]["state_sha256"] = "1" * 64
                    mismatched_cold["before"] = copy.deepcopy(mismatched_live["after"])
                    (output / "live-roots.json").write_text(json.dumps(mismatched_live))
                    (output / "cold-roots.json").write_text(json.dumps(mismatched_cold))
                    bad = copy.deepcopy(observation)
                    for phase in ("live", "cold"):
                        bad["artifacts"][phase + "-roots.json"] = U.sha(output / (phase + "-roots.json"))
                    (output / "result.json").write_text(json.dumps(bad))
                    with self.assertRaises(U.UpgradeError):
                        U.verify({}, output, prepared_path)
                    (output / "live-roots.json").write_text(json.dumps(live_trace))
                    (output / "cold-roots.json").write_text(json.dumps(cold_trace))
                    new_live_after = {"old": roots(["A1"])["old"], "new": {
                        "present": True, "state_sha256": "1" * 64, "prompts": [marker("A3", 1)]}}
                    new_cold_after = copy.deepcopy(new_live_after)
                    new_cold_after["new"] = {"present": True, "state_sha256": "2" * 64,
                                              "prompts": [marker("A3", 1), marker("A4", 2)]}
                    live_new_trace = U._root_turn_trace(roots(["A1"]), new_live_after, "A", "A3", shared=False)
                    cold_new_trace = U._root_turn_trace(new_live_after, new_cold_after, "A", "A4", shared=False)
                    (output / "live-roots.json").write_text(json.dumps(live_new_trace))
                    (output / "cold-roots.json").write_text(json.dumps(cold_new_trace))
                    for phase, raw_sha in (("live", "1" * 64), ("cold", "2" * 64)):
                        (output / ("new-after-" + phase + ".json")).write_text(json.dumps(
                            {"source_state_sha256": raw_sha, "state": snapshot("A", 0, None)}))
                        (output / ("old-after-" + phase + ".json")).write_text(json.dumps(
                            {"source_state_sha256": roots(["A1"])["old"]["state_sha256"], "state": snapshot("A", 0, None)}))
                    new_root = copy.deepcopy(observation)
                    for phase in ("live", "cold"):
                        new_root["data_observations"]["new_after_" + phase] = "observed"
                        new_root[phase + "_observation"]["actual_root"] = "new"
                        new_root["artifacts"]["new-after-" + phase + ".json"] = U.sha(output / ("new-after-" + phase + ".json"))
                        new_root["artifacts"]["old-after-" + phase + ".json"] = U.sha(output / ("old-after-" + phase + ".json"))
                        new_root["artifacts"][phase + "-roots.json"] = U.sha(output / (phase + "-roots.json"))
                    (output / "result.json").write_text(json.dumps(new_root))
                    self.assertEqual("observation_complete", U.verify({}, output, prepared_path)["status"])
                    for lost in ([], [{"id": "R1", "sha256": "e" * 64, "status": "pending", "work_unit_id": "WU1"}]):
                        missing_new = snapshot("A", 0, None)
                        missing_new["requirements"] = lost
                        (output / "new-after-live.json").write_text(json.dumps(
                            {"source_state_sha256": "1" * 64, "state": missing_new}))
                        bad = copy.deepcopy(new_root)
                        bad["live_observation"]["ledger_compatibility"] = "lost"
                        bad["status"] = "unsupported_continuity"
                        bad["artifacts"]["new-after-live.json"] = U.sha(output / "new-after-live.json")
                        (output / "result.json").write_text(json.dumps(bad))
                        self.assertEqual("unsupported_continuity", U.verify({}, output, prepared_path)["status"])
                        bad["status"] = "observation_complete"
                        (output / "result.json").write_text(json.dumps(bad))
                        with self.assertRaises(U.UpgradeError):
                            U.verify({}, output, prepared_path)
                    (output / "live-roots.json").write_text(json.dumps(live_trace))
                    (output / "cold-roots.json").write_text(json.dumps(cold_trace))
                    for phase, trace in (("live", live_trace), ("cold", cold_trace)):
                        (output / ("old-after-" + phase + ".json")).write_text(json.dumps(
                            {"source_state_sha256": trace["after"]["old"]["state_sha256"], "state": snapshot("A", 0, None)}))
                    (output / "new-after-live.json").unlink()
                    (output / "new-after-cold.json").unlink()
                    (output / "result.json").write_text(json.dumps(observation))
                    ambiguous_prepared, ambiguous_result = copy.deepcopy(prepared), copy.deepcopy(observation)
                    local_path = str(Path(subject["home"]) / "plugins/cache/codex-context-guard/context-guard/local")
                    ambiguous_prepared["installed"]["path"] = local_path
                    ambiguous_prepared["official_add"]["installedPath"] = local_path
                    ambiguous_prepared["commands"][5]["observation"]["installedPath"] = local_path
                    ambiguous_result["installed_new"]["path"] = local_path
                    add_row = next(row for row in ambiguous_result["commands"] if row["argv"][1:3] == ["plugin", "add"])
                    add_row["observation"]["installedPath"] = local_path
                    prepared_path.write_text(json.dumps(ambiguous_prepared))
                    (output / "result.json").write_text(json.dumps(ambiguous_result))
                    with self.assertRaises(U.UpgradeError):
                        U.verify({}, output, prepared_path)
                    prepared_path.write_text(json.dumps(prepared))
                    (output / "result.json").write_text(json.dumps(observation))
                    for mutation in ("missing", "untrusted", "wrong_source", "after_resume", "wrong_pid"):
                        altered = copy.deepcopy(rows)
                        if mutation == "missing":
                            altered = [row for row in altered if row.get("message", {}).get("id") != 201]
                        elif mutation in ("untrusted", "wrong_source"):
                            response = next(row for row in altered if row.get("direction") == "response"
                                            and row.get("message", {}).get("id") == 201)
                            item = response["message"]["result"]["data"][0]["hooks"][0]
                            if mutation == "untrusted":
                                item["trustStatus"] = "untrusted"
                            else:
                                item["sourcePath"] = fixture_path("wrong", "hooks.json")
                        elif mutation == "wrong_pid":
                            marker_row = next(row for row in altered if row.get("event") == "cold_client_started")
                            marker_row["pid"] = 999
                        else:
                            pair = [row for row in altered if row.get("message", {}).get("id") == 201]
                            altered = [row for row in altered if row.get("message", {}).get("id") != 201]
                            resume_index = next(i for i, row in enumerate(altered)
                                                if row.get("direction") == "request" and row.get("message", {}).get("id") == 202)
                            altered[resume_index + 1:resume_index + 1] = pair
                        (output / "cold/rpc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in altered))
                        bad = copy.deepcopy(observation)
                        bad["artifacts"]["cold/rpc.jsonl"] = U.sha(output / "cold/rpc.jsonl")
                        (output / "result.json").write_text(json.dumps(bad))
                        with self.assertRaises(U.UpgradeError, msg=mutation):
                            U.verify({}, output, prepared_path)
                    (output / "cold/rpc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
                    missing_start = [row for row in rows if not (row.get("direction") == "response"
                        and row.get("message", {}).get("params", {}).get("run", {}).get("eventName") == "sessionStart")]
                    (output / "cold/rpc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in missing_start))
                    pending_observation = copy.deepcopy(observation)
                    pending_observation["cold_observation"].update(status="session_start_unobserved",
                        session_start_source=None, session_start_phase=None, session_started_before_first_turn=None)
                    pending_observation["status"] = "observation_pending"
                    pending_observation["artifacts"]["cold/rpc.jsonl"] = U.sha(output / "cold/rpc.jsonl")
                    (output / "result.json").write_text(json.dumps(pending_observation))
                    self.assertEqual("observation_pending", U.verify({}, output, prepared_path)["status"])
                    pending_observation["status"] = "observation_complete"
                    (output / "result.json").write_text(json.dumps(pending_observation))
                    with self.assertRaises(U.UpgradeError):
                        U.verify({}, output, prepared_path)
                    (output / "cold/rpc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
                    observation["cold_observation"]["turn"] = "other"
                    (output / "result.json").write_text(json.dumps(observation))
                    with self.assertRaises(U.UpgradeError):
                        U.verify({}, output, prepared_path)
                    rejected_rows = copy.deepcopy(rows[:next(i for i, row in enumerate(rows)
                        if row.get("direction") == "response" and row.get("message", {}).get("id") == 202) + 1])
                    rejected_rows[-1]["message"] = {"id": 202, "error": {"redacted": True}}
                    (output / "cold/rpc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rejected_rows))
                    unsupported_trace = {"thread": "A", "turn": None, "actual_root": "unknown",
                                         "before": live_trace["after"], "after": live_trace["after"]}
                    (output / "cold-roots.json").write_text(json.dumps(unsupported_trace))
                    (output / "old-after-cold.json").write_text(json.dumps({"source_state_sha256":
                        live_trace["after"]["old"]["state_sha256"], "state": snapshot("A", 0, None)}))
                    observation["cold_observation"] = {"status": "unsupported_resume", "actual_root": "unknown",
                                                       "ledger_compatibility": "unobserved"}
                    observation["status"] = "unsupported_continuity"
                    observation["artifacts"]["cold/rpc.jsonl"] = U.sha(output / "cold/rpc.jsonl")
                    observation["artifacts"]["cold-roots.json"] = U.sha(output / "cold-roots.json")
                    observation["artifacts"]["old-after-cold.json"] = U.sha(output / "old-after-cold.json")
                    (output / "result.json").write_text(json.dumps(observation))
                    self.assertEqual("unsupported_continuity", U.verify({}, output, prepared_path)["status"])
                    rejected_rows[-1]["message"]["error"]["code"] = -32600
                    (output / "cold/rpc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rejected_rows))
                    observation["artifacts"]["cold/rpc.jsonl"] = U.sha(output / "cold/rpc.jsonl")
                    (output / "result.json").write_text(json.dumps(observation))
                    self.assertEqual("unsupported_continuity", U.verify({}, output, prepared_path)["status"])
                    rejected_rows[-1]["message"]["error"]["message"] = "do-not-keep"
                    (output / "cold/rpc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rejected_rows))
                    observation["artifacts"]["cold/rpc.jsonl"] = U.sha(output / "cold/rpc.jsonl")
                    (output / "result.json").write_text(json.dumps(observation))
                    with self.assertRaises(U.UpgradeError):
                        U.verify({}, output, prepared_path)
                    del rejected_rows[-1]["message"]["error"]["message"]
                    (output / "cold/rpc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rejected_rows))
                    observation["artifacts"]["cold/rpc.jsonl"] = U.sha(output / "cold/rpc.jsonl")
                    observation["status"] = "observation_complete"
                    (output / "result.json").write_text(json.dumps(observation))
                    with self.assertRaises(U.UpgradeError):
                        U.verify({}, output, prepared_path)

    def test_protected_output_rejected_without_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cache = root / "cache"
            cache.mkdir()
            marker = cache / "sentinel"
            marker.write_bytes(b"unchanged")
            with self.assertRaises(U.UpgradeError):
                U._new_outside(cache / "result.json", [cache])
            self.assertEqual([marker], list(cache.iterdir()))
            self.assertEqual(b"unchanged", marker.read_bytes())

    def test_credential_names_are_rejected_before_content_read_or_tree_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            credential = root / "auth.json"
            credential.write_text("synthetic private placeholder")
            (root / "ordinary.txt").write_text("safe")
            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("must not read")):
                with self.assertRaises(U.UpgradeError):
                    U.sha(credential)
            with mock.patch.object(U.native, "installed_object_snapshot") as snapshot:
                with self.assertRaises(U.UpgradeError):
                    U.source_files(root)
                snapshot.assert_not_called()
            with mock.patch.object(Path, "read_text", side_effect=AssertionError("must not read")):
                with self.assertRaises(U.UpgradeError):
                    U._read_json(credential)
            netrc = root / ".netrc"
            netrc.write_text("synthetic")
            with mock.patch.object(Path, "read_text", side_effect=AssertionError("must not read")):
                with self.assertRaises(U.UpgradeError):
                    U._read_json(netrc)

    def test_zip_central_directory_rejects_credential_member_before_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory).resolve() / "public.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("safe/file.txt", "public")
                z.writestr("hidden/auth.json", "synthetic private placeholder")
            with mock.patch.object(U, "sha", side_effect=AssertionError("must not hash")) as file_hash:
                with self.assertRaises(U.UpgradeError):
                    U._zip_metadata(archive)
                file_hash.assert_not_called()

    def test_old_git_export_pins_line_endings_and_exact_payload(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            item = tarfile.TarInfo("public.txt")
            item.size = len(b"public\n")
            archive.addfile(item, io.BytesIO(b"public\n"))
        payload = buffer.getvalue()
        response = subprocess.CompletedProcess([], 0, payload, b"")
        with mock.patch.object(U.scheduler, "_command", return_value=response) as command, \
             mock.patch.object(U, "OLD_0151_EXPORT_SHA256", hashlib.sha256(payload).hexdigest()):
            result = U._old_provenance(Path(fixture_path("product")), Path(fixture_path("old")),
                                       "0.15.1", {}, {"public.txt": hashlib.sha256(b"public\n").hexdigest()})
            self.assertEqual("published_tag_source_export", result["kind"])
            self.assertEqual(["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf",
                              "archive", "--format=tar", U.OLD_0151_COMMIT], command.call_args.args[2])
            with self.assertRaises(U.UpgradeError):
                U._old_provenance(Path(fixture_path("product")), Path(fixture_path("old")),
                                  "0.15.1", {}, {"public.txt": hashlib.sha256(b"public\r\n").hexdigest()})

    def test_snapshot_provider_ctime_differs_but_per_provider_changes_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            document, archive = root / "data.json", root / "public.zip"
            document.write_text('{"synthetic":true}')
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("data.txt", "public")
            real_fstat = os.fstat

            def copy_stat(actual):
                return types.SimpleNamespace(**{name: getattr(actual, name) for name in
                    ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")})

            def shifted(change_second=False, replace=False):
                count = 0
                def read(fd):
                    nonlocal count
                    count += 1
                    actual = real_fstat(fd)
                    result = copy_stat(actual)
                    result.st_ctime_ns = actual.st_ctime_ns + 100 + (1 if change_second and count > 1 else 0)
                    if replace:
                        result.st_ino = actual.st_ino + 1
                    return result
                return read

            with mock.patch.object(U.os, "fstat", side_effect=shifted()):
                self.assertEqual(hashlib.sha256(document.read_bytes()).hexdigest(), U.sha(document))
                self.assertTrue(U._read_json(document)["synthetic"])
                identity = U._zip_metadata(archive)
                U._zip_exact(archive, identity, {"data.txt": hashlib.sha256(b"public").hexdigest()})
            for provider in (shifted(change_second=True), shifted(replace=True)):
                with mock.patch.object(U.os, "fstat", side_effect=provider):
                    with self.assertRaises(U.UpgradeError):
                        U.sha(document)
            with mock.patch.object(U.os, "fstat", side_effect=shifted(replace=True)), \
                 mock.patch.object(U.zipfile, "ZipFile", side_effect=AssertionError("must not read")) as reader:
                with self.assertRaises(U.UpgradeError):
                    U._zip_metadata(archive)
                with self.assertRaises(U.UpgradeError):
                    U._zip_exact(archive, identity, {})
                reader.assert_not_called()
            real_read, real_lstat = os.read, Path.lstat
            read_finished = False
            def tracked_read(fd, size):
                nonlocal read_finished
                value = real_read(fd, size)
                if not value:
                    read_finished = True
                return value
            def changed_path(path, *args, **kwargs):
                actual = real_lstat(path, *args, **kwargs)
                if path == document and read_finished:
                    result = copy_stat(actual)
                    result.st_ctime_ns = actual.st_ctime_ns + 1
                    return result
                return actual
            with mock.patch.object(U.os, "read", side_effect=tracked_read), \
                 mock.patch.object(Path, "lstat", autospec=True, side_effect=changed_path):
                with self.assertRaises(U.UpgradeError):
                    U.sha(document)

    def test_windows_executable_path_mode_alias_preserves_other_identity_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            paths = [root / ("public" + suffix) for suffix in (".exe", ".com", ".bat", ".cmd", ".json")]
            with mock.patch.object(U.os, "name", "nt"):
                self.assertEqual([True, True, True, True, False], [U._windows_executable(path) for path in paths])
            path = paths[0]
            path.write_bytes(b"synthetic public binary")
            path.chmod(0o700)
            real_fstat = os.fstat
            def make_mode_alias(fd):
                actual = real_fstat(fd)
                result = types.SimpleNamespace(**{name: getattr(actual, name) for name in
                    ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")})
                result.st_mode &= ~0o111
                return result
            with mock.patch.object(U, "_windows_executable", return_value=True), \
                 mock.patch.object(U.os, "fstat", side_effect=make_mode_alias):
                self.assertEqual(hashlib.sha256(b"synthetic public binary").hexdigest(), U.sha(path))
            actual = path.lstat()
            for field, change in (("st_dev", 1), ("st_ino", 1), ("st_nlink", 1), ("st_size", 1),
                                  ("st_mtime_ns", 1), ("st_mode", 0o200), ("st_mode", 0o10000)):
                altered = types.SimpleNamespace(**{name: getattr(actual, name) for name in
                    ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")})
                setattr(altered, field, getattr(altered, field) ^ change)
                self.assertNotEqual(U._common_identity(actual, windows_executable=True),
                                    U._common_identity(altered, windows_executable=True), field)
            other = types.SimpleNamespace(**{name: getattr(actual, name) for name in
                ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")})
            other.st_mode &= ~0o111
            self.assertNotEqual(U._common_identity(actual), U._common_identity(other))

    def test_json_hardlink_alias_refused_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            protected = root / "private.json"
            protected.write_text('{"synthetic":true}')
            alias = root / "external-plan.json"
            try:
                os.link(protected, alias)
            except OSError:
                self.skipTest("hard-link capability unavailable")
            with mock.patch.object(U.native, "open_snapshot_file", side_effect=AssertionError("must not read")) as opened:
                with self.assertRaises(U.UpgradeError):
                    U._read_json(alias)
                opened.assert_not_called()

    def test_plan_and_cli_inside_auth_home_refused_before_content_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home, other = root / "home", root / "other-home"
            home.mkdir()
            other.mkdir()
            secret_plan = home / "config.json"
            secret_plan.write_text("synthetic")
            fake_cli = home / "codex.exe"
            fake_cli.write_text("synthetic")
            with mock.patch.object(Path, "read_text", side_effect=AssertionError("must not read")):
                with self.assertRaises(U.UpgradeError):
                    U._invocation_paths(secret_plan, root / "output", home, [other], None)
            with mock.patch.object(U, "sha", side_effect=AssertionError("must not hash")) as file_hash:
                with self.assertRaises(U.UpgradeError):
                    U._cli_scope(fake_cli, root / "daily", [home, other])
                file_hash.assert_not_called()
            with self.assertRaises(U.UpgradeError):
                U._data_candidate(home, str(home / ".ssh"), "synthetic root")

    def test_linked_ancestor_is_rejected_before_file_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = root / "real"
            real.mkdir()
            (real / "child").mkdir()
            alias = root / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("symbolic link capability unavailable")
            with self.assertRaises(U.UpgradeError):
                U._absolute_real(str(alias / "child"), "fixture")

    def test_complete_preflight_binds_both_heads_and_never_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            product, home, workspace, old, new = (root / x for x in ("product", "home", "ws", "old", "new"))
            for path in (product, home, workspace, old, new):
                path.mkdir(mode=0o700)
            other_home = root / "other-home"
            other_home.mkdir(mode=0o700)
            read_fixture = workspace / "native-read.txt"
            read_fixture.write_text("synthetic read")
            (old / ".codex-plugin").mkdir()
            (old / ".agents/plugins").mkdir(parents=True)
            (old / "hooks").mkdir()
            (old / ".codex-plugin/plugin.json").write_text(json.dumps({"name": "context-guard", "version": "0.16.1"}))
            (old / ".agents/plugins/marketplace.json").write_text(json.dumps({"name": "codex-context-guard-v016"}))
            (old / "hooks/hooks.json").write_text(json.dumps({"hooks": {e[0].upper() + e[1:]: [] for e in U.EVENTS}}))
            archive, codex = root / "release.zip", root / "codex"
            archive.write_bytes(b"synthetic release")
            old_archive = root / "old.zip"
            old_archive.write_bytes(b"synthetic old release")
            codex.write_bytes(b"synthetic binary")
            codex.chmod(0o700)
            old_files = {"fixture": "a" * 64}
            plan = {"schema": U.PLAN, "product_root": str(product), "home": str(home),
                    "workspace": str(workspace), "old_artifact": str(old), "new_artifact": str(new),
                    "other_homes": [str(other_home)],
                    "release_zip": str(archive), "codex": str(codex), "old_version": "0.16.1",
                    "transition_strategy": "observe-open",
                    "old_release_zip": str(old_archive),
                    "old_data_root": str(home / "old-data"), "new_data_root": str(home / "new-data"),
                    "product_commit": "a" * 40, "toolkit_commit": "b" * 40,
                    "release_zip_sha256": U.sha(archive), "codex_sha256": U.sha(codex),
                    "read_file_sha256": U.sha(read_fixture),
                    "old_tree_sha256": U.digest(old_files), "runtime_sha256": "d" * 64,
                    "cli_version": "codex-cli 0.165.0", "sentinel": sentinel(home)}
            out = root / "result"
            manager = mock.Mock()
            manager.distribution_manifest.return_value = old_files
            with mock.patch.object(U.platform, "system", return_value="Darwin"), \
                 mock.patch.object(U, "_private_directory"), \
                 mock.patch.object(U.native, "verify_exact_source") as verify, \
                 mock.patch.object(U.native, "load_artifacts", return_value=manager), \
                 mock.patch.object(U.native, "runtime_digest", return_value="d" * 64), \
                 mock.patch.object(U, "source_files", return_value=old_files), \
                 mock.patch.object(U, "_old_provenance", return_value={"kind": "synthetic"}), \
                 mock.patch.object(U, "_zip_metadata", side_effect=lambda path: U._stat_identity(path.lstat())), \
                 mock.patch.object(U, "_zip_exact") as parity:
                subject = U.preflight(plan, out)
                self.assertEqual("a" * 40, subject["product_commit"])
                self.assertEqual("b" * 40, subject["toolkit_commit"])
                self.assertEqual(2, verify.call_count)
                parity.assert_called_once()
                self.assertFalse(out.exists())
                self.assertNotIn("review_timeout_seconds", subject)
                plan["review_timeout_seconds"] = 1200
                self.assertEqual(1200, U.preflight(plan, out)["review_timeout_seconds"])
                for invalid in (0, 1201, True, "600", None):
                    with self.subTest(review_timeout=invalid), self.assertRaisesRegex(
                        U.UpgradeError, "review_timeout_seconds"
                    ):
                        U.preflight({**plan, "review_timeout_seconds": invalid}, out)
                del plan["review_timeout_seconds"]
                self.assertFalse(out.exists())
                plan["old_tree_sha256"] = "e" * 64
                with self.assertRaises(U.UpgradeError):
                    U.preflight(plan, out)
                self.assertFalse(out.exists())
                plan["old_tree_sha256"] = U.digest(old_files)
                plan["old_artifact"] = str(home)
                with mock.patch.object(U, "sha", side_effect=AssertionError("must not hash")) as hash_file:
                    with self.assertRaises(U.UpgradeError):
                        U.preflight(plan, out)
                    hash_file.assert_not_called()
                plan["old_artifact"] = str(old)
                plan["release_zip"] = str(archive)
                synthetic_private = home / "private-placeholder"
                synthetic_private.write_text("synthetic private content")
                synthetic_private.chmod(0o700)
                link_dir = root / "linked-public-name"
                link_dir.mkdir()
                linked_cli = link_dir / "codex"
                try:
                    os.link(synthetic_private, linked_cli)
                except OSError:
                    self.skipTest("hard-link capability unavailable")
                plan["codex"] = str(linked_cli)
                with mock.patch.object(U, "sha", side_effect=AssertionError("must not hash")) as hash_file:
                    with self.assertRaises(U.CapabilityPending):
                        U.prepare(plan, out)
                    hash_file.assert_not_called()
                plan["codex"] = str(codex)
                protected_archive = home / "public.zip"
                protected_archive.write_bytes(b"synthetic")
                plan["release_zip"] = str(protected_archive)
                with mock.patch.object(U, "sha", side_effect=AssertionError("must not hash")) as hash_file:
                    with self.assertRaises(U.UpgradeError):
                        U.preflight(plan, out)
                    hash_file.assert_not_called()

    def test_prepare_accepts_existing_non_target_home_and_stops_for_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home, old, out = root / "home", root / "old", root / "evidence"
            home.mkdir()
            old.mkdir()
            (home / "config.toml").write_text("synthetic = true\n")
            sentinel_spec = sentinel(home)
            (old / "fixture.txt").write_text("old bytes")
            codex = root / "codex"
            codex.write_text("synthetic CLI")
            market = "codex-context-guard-v016"
            plugin = "context-guard@" + market
            installed = home / "plugins/cache" / market / "context-guard/0.16.1"
            added = {"pluginId": plugin, "name": "context-guard", "marketplaceName": market,
                     "version": "0.16.1", "installedPath": str(installed)}
            row = {**added, "installed": True, "enabled": True,
                   "source": {"source": "local", "path": str(old)},
                   "marketplaceSource": {"sourceType": "local", "source": str(old)}}
            calls = []
            registered = []

            def run(_native, _root, argv, **kwargs):
                calls.append(argv)
                if argv[1:] == ["--version"]:
                    return subprocess.CompletedProcess(argv, 0, b"codex-cli 0.165.0\n", b"")
                if argv[2:5] == ["marketplace", "list", "--json"]:
                    markets = [{"name": sentinel_spec["marketplace"]}]
                    if registered:
                        markets.append({"name": market, "root": str(old)})
                    value = {"marketplaces": markets}
                elif argv[2:6] == ["list", "--marketplace", sentinel_spec["marketplace"], "--json"]:
                    value = {"installed": []}
                elif argv[2:4] == ["marketplace", "add"]:
                    registered.append(True)
                    value = {}
                elif argv[2] == "add":
                    installed.parent.mkdir(parents=True)
                    shutil.copytree(old, installed)
                    value = added
                else:
                    value = {"installed": [row]}
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")

            plan = {"home": str(home), "old_artifact": str(old), "codex": str(codex),
                    "old_version": "0.16.1", "cli_version": "codex-cli 0.165.0", "sentinel": sentinel_spec}
            with mock.patch.object(U, "preflight", return_value={"test": True}), \
                 mock.patch.object(U.scheduler, "_command", side_effect=run):
                result = U.prepare(plan, out)
            self.assertEqual("pending", result["status"], result)
            self.assertEqual(0, result["before"]["sentinel_installed_count"])
            self.assertTrue(result["before"]["target_cache_absent"])
            self.assertTrue(all("--marketplace" in argv for argv in calls if argv[1:3] == ["plugin", "list"]))
            self.assertIn("normal_hook_review", result["pending"])
            self.assertEqual("synthetic = true\n", (home / "config.toml").read_text())
            self.assertEqual(9, len(calls))

    def test_prepare_refuses_existing_marketplace_before_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home, old = root / "home", root / "old"
            home.mkdir()
            old.mkdir()
            codex = root / "codex"
            codex.write_text("synthetic")
            response = subprocess.CompletedProcess([], 0, b'{"marketplaces":[{"name":"codex-context-guard"}]}', b"")
            plan = {"home": str(home), "old_artifact": str(old), "codex": str(codex),
                    "old_version": "0.15.1", "cli_version": "codex-cli 0.165.0"}
            with mock.patch.object(U, "preflight", return_value={}), \
                 mock.patch.object(U.scheduler, "_command", side_effect=[
                     subprocess.CompletedProcess([], 0, b"codex-cli 0.165.0\n", b""), response]) as run:
                result = U.prepare(plan, root / "out")
            self.assertEqual("failed", result["status"])
            self.assertEqual(2, run.call_count)

    def test_missing_unrelated_sentinel_fails_before_transition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home, old, new, workspace = (root / x for x in ("home", "old", "new", "workspace"))
            for path in (home, old, new, workspace):
                path.mkdir()
            (workspace / "native-read.txt").write_text("synthetic read target")
            installed = home / "plugins/cache/codex-context-guard/context-guard/0.15.1"
            installed.mkdir(parents=True)
            codex = root / "codex"
            codex.write_text("synthetic")
            subject = {"toolkit_commit": "b" * 40,
                       "read_file_sha256": U.sha(workspace / "native-read.txt")}
            prepared = root / "prepare.json"
            prepared.write_text(json.dumps({"schema": U.REPORT, "stage": "prepare", "status": "pending",
                                            "subject": subject, "installed": {"path": str(installed)},
                                            "official_add": {}}))
            plan = {"home": str(home), "old_artifact": str(old), "new_artifact": str(new),
                    "workspace": str(workspace), "codex": str(codex), "old_version": "0.15.1",
                    "old_data_root": str(home / "old-data"), "transition_strategy": "finish-old"}
            process = mock.Mock(pid=123)
            process.poll.return_value = None
            client = mock.Mock()
            client.approved = {}
            client.owned.process = process
            client.start.side_effect = ["thread-a", "thread-b"]
            client.observed_turn.side_effect = [("turn-a", []), ("turn-b", []), ("turn-after-compact", [])]
            client.close.return_value = {"owned_process_exited": True}

            def state(_home, _root, thread):
                return home / "old-data", {"session": {"id": thread}, "compactions": [], "requirements": [
                    {"id": "R1", "sha256": "a" * 64, "status": "pending"}]}

            response = subprocess.CompletedProcess([], 0, b'{"installed": []}', b"")
            with mock.patch.object(U, "preflight", return_value=subject), \
                 mock.patch.object(U, "source_files", return_value={"x": "y"}), \
                 mock.patch.object(U, "_official_install_identity", return_value=installed), \
                 mock.patch.object(U, "_state_at", side_effect=state), \
                 mock.patch.object(U, "_paired", return_value=[{}]), \
                 mock.patch.object(U, "verify_read_tool"), \
                 mock.patch.object(U.host, "verify_recovery"), \
                 mock.patch.object(U, "UpgradeClient", return_value=client), \
                 mock.patch.object(U.scheduler, "_command", return_value=response) as command:
                result = U.run_open_transition(plan, root / "output", prepared)
            self.assertEqual("failed", result["status"])
            self.assertEqual(0, command.call_count)
            client.rpc.assert_not_called()
            self.assertTrue((root / "output/result.json").is_file())


class FakeSafeTransport(unittest.TestCase):
    def test_real_safe_producer_to_consumer_and_close_failure(self):
        for old_version, scenario in (("0.15.1", "pass"), ("0.15.1", "live_close_fails"),
                                      ("0.15.1", "wrong_stream"), ("0.17.0", "pass")):
            with self.subTest(old_version=old_version, scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                subject, prepared, template = lifecycle_facts(old_version)
                home, old, new, workspace, codex, product = [
                    base / x
                    for x in ("home", "old", "new", "workspace", "codex", "product")
                ]
                for p in (home, old, new, workspace, product):
                    p.mkdir()
                codex.write_text("synthetic-cli")
                read = workspace / "native-read.txt"
                read.write_text("synthetic read")
                maps = {
                    subject["home"]: str(home),
                    subject["old_artifact"]: str(old),
                    subject["new_artifact"]: str(new),
                    subject["codex"]: str(codex),
                }

                def replace(v):
                    if isinstance(v, str):
                        for a, b in maps.items():
                            v = v.replace(a, b)
                        return v
                    if isinstance(v, list):
                        return [replace(x) for x in v]
                    if isinstance(v, dict):
                        return {k: replace(x) for k, x in v.items()}
                    return v

                subject, prepared, template = map(
                    replace, (subject, prepared, template)
                )
                subject.update(
                    product_commit="a" * 40,
                    toolkit_commit="b" * 40,
                    product_root=str(product),
                    workspace=str(workspace),
                    old_data_root=str(home / "old-data"),
                    new_data_root=str(home / "new-data"),
                    transition_strategy="finish-old",
                    platform=U.platform.system(),
                    read_file_sha256=U.sha(read),
                )
                if old_version == "0.17.0":
                    subject["review_timeout_seconds"] = 1200
                old_cache = Path(prepared["official_add"]["installedPath"])
                old_cache.mkdir(parents=True)
                new_cache = Path(template["installed_new"]["path"])
                old_source, new_source = (
                    str(old_cache / "hooks/hooks.json"),
                    str(new_cache / "hooks/hooks.json"),
                )
                old_hooks, new_hooks = (
                    inventory(old_source)["data"][0]["hooks"],
                    inventory(new_source)["data"][0]["hooks"],
                )
                prepared.update(
                    schema=U.REPORT,
                    status="pending",
                    stage="prepare",
                    subject=subject,
                    installed={"path": str(old_cache)},
                )
                prepared_path = base / "prepare.json"
                prepared_path.write_text(json.dumps(prepared))
                plan = {**subject, "sentinel": subject["sentinel"]}
                commands = copy.deepcopy(template["commands"])
                world = {
                    "client_count": 0,
                    "events": [],
                    "new": False,
                    "disabled": False,
                    "cancelled": set(),
                    "compacted": set(),
                }
                for root, threads in (
                    (Path(subject["old_data_root"]), ("A", "B")),
                    (Path(subject["new_data_root"]), ("F",)),
                ):
                    for t in threads:
                        state_path = root / "sessions" / t / "state.json"
                        state_path.parent.mkdir(parents=True, exist_ok=True)
                        state_path.write_text("{}")

                def state_at(_home, root, thread):
                    original = {
                        "id": "R1",
                        "sha256": "a" * 64,
                        "work_unit_id": "WU1",
                        "status": "pending",
                    }
                    compact = thread in world["compacted"]
                    state = {
                        "session": {"id": thread},
                        "requirements": [original],
                        "compactions": [{}] if compact else [],
                        "pending": {"recovery": {"state": "consumed"}}
                        if compact
                        else {},
                        "mode": {"active": True},
                    }
                    if thread in world["cancelled"]:
                        cancel_sha = hashlib.sha256(
                            "取消当前任务。".encode()
                        ).hexdigest()
                        state["requirements"].append(
                            {
                                "id": "R2",
                                "sha256": cancel_sha,
                                "work_unit_id": "WU1",
                                "prompt_id": "P2",
                                "status": "answered",
                            }
                        )
                        state["prompts"] = [
                            {
                                "id": "P2",
                                "sha256": cancel_sha,
                                "record_sha256": "f" * 64,
                                "core_event_seq": 4,
                                "origin": "human",
                            }
                        ]
                        state["root_controls"] = [
                            {
                                "kind": "cancel",
                                "source_prompt_id": "P2",
                                "scope_kind": "current_unit",
                                "source_record_sha256": "f" * 64,
                                "source_seq": 4,
                                "work_unit_id": "WU1",
                                "catalog_sha256": "c" * 64,
                                "items": [
                                    {
                                        "id": "R1",
                                        "source_sha256": "a" * 64,
                                        "work_unit_id": "WU1",
                                    }
                                ],
                            }
                        ]
                        state["work_units"] = [
                            {"id": "WU1", "status": "historical_unresolved"}
                        ]
                    return Path(root), state

                class FakeClient:
                    def __init__(self, cplan, outdir, sources=None, **_kw):
                        world["client_count"] += 1
                        self.is_cold = world["client_count"] == 2
                        self.plan = cplan
                        self.rows = []
                        self.seq = 0
                        if self.is_cold and "live-closed" not in world["events"]:
                            raise RuntimeError("old owner still active")
                        world["events"].append(
                            "cold-start" if self.is_cold else "live-start"
                        )
                        self.owned = mock.Mock()
                        self.owned.process.pid = 456 if self.is_cold else 123
                        self.owned.process.poll.return_value = None
                        self.log = (
                            outdir /
                            "rpc.jsonl").open(
                            "x",
                            encoding="utf8")
                        self.guard_diagnostic = None
                        self.observation_inventory = self.observation_thread = None
                        self.approved = U._inventory(
                            inventory(new_source if self.is_cold else old_source),
                            {
                                new_source if self.is_cold else old_source: U.NEW_VERSION
                                if self.is_cold
                                else "0.15.1"
                            },
                        )
                        self.rpc("hooks/list", {"cwds": [str(workspace)]})

                    def emit(self, direction, message):
                        self.log.write(json.dumps(
                            {"direction": direction, "message": message}) + "\n")
                        self.log.flush()
                        if direction == "response":
                            self.rows.append(message)

                    def event(self, method, thread, turn, data):
                        self.emit(
                            "response",
                            {
                                "method": method,
                                "params": {
                                    "threadId": thread,
                                    **({"turnId": turn} if turn else {}),
                                    **data,
                                },
                            },
                        )

                    def hooks(self, thread, turn, event, source=None):
                        source = source or (
                            new_source if world["new"] else old_source)
                        for status in ("started", "completed"):
                            run = (
                                hook(
                                    event + thread,
                                    source,
                                    event,
                                    "completed",
                                    1) if status == "completed" else hook(
                                    event + thread,
                                    source,
                                    event))
                            self.event("hook/" + status, thread,
                                       turn, {"run": run})

                    def rpc(self, method, params):
                        self.seq += 1
                        rid = self.seq
                        self.emit(
                            "request", {
                                "id": rid, "method": method, "params": params})
                        if method == "thread/archive":
                            self.hooks(params["threadId"], None, "sessionEnd")
                        if method == "config/batchWrite":
                            if not self.is_cold:
                                raise RuntimeError("write in wrong process")
                            world["events"].append("cold-disable")
                            world["disabled"] = True
                        value = (
                            {
                                "data": [
                                    {
                                        "hooks": (
                                            []
                                            if world["disabled"]
                                            else new_hooks
                                            if world["new"]
                                            else old_hooks
                                        )
                                    }
                                ]
                            }
                            if method == "hooks/list"
                            else {}
                        )
                        self.emit("response", {"id": rid, "result": value})
                        if method == "thread/resume":
                            self.hooks(
                                params["threadId"], None, "sessionStart")
                        return value

                    def start(self):
                        thread = (
                            "F"
                            if world["new"]
                            else ("A" if not hasattr(self, "started") else "B")
                        )
                        self.started = True
                        self.seq += 1
                        self.emit(
                            "request", {
                                "id": self.seq, "method": "thread/start", "params": {}}, )
                        self.emit(
                            "response", {
                                "id": self.seq, "result": {
                                    "thread": {
                                        "id": thread}}}, )
                        return thread

                    def observed_turn(self, thread, prompt):
                        names = {
                            "A": ["A1", "A2", "AC"],
                            "B": ["B1", "BC"],
                            "F": ["F1", "F2", "F3", "F4"],
                        }
                        counters = world.setdefault("turncounts", {})
                        idx = counters.get(thread, 0)
                        counters[thread] = idx + 1
                        turn = names[thread][idx]
                        self.seq += 1
                        self.emit("request",
                                  {"id": self.seq,
                                   "method": "turn/start",
                                   "params": {"threadId": thread,
                                              "input": [{"type": "text",
                                                         "text": prompt}],
                                              },
                                   },
                                  )
                        self.emit(
                            "response",
                            {"id": self.seq, "result": {"turn": {"id": turn}}},
                        )
                        begin = len(self.rows)
                        self.event("turn/started", thread, None, {"turn": {"id": turn}})
                        if turn in ("A1", "F1"):
                            self.hooks(thread, turn, "preToolUse")
                            item = {
                                "id": "read",
                                "type": "commandExecution",
                                "command": (
                                    "Get-Content -LiteralPath native-read.txt"
                                    if U.platform.system() == "Windows"
                                    else "cat native-read.txt"
                                ),
                                "cwd": str(workspace),
                            }
                            self.event("item/started", thread,
                                       turn, {"item": item})
                            self.event(
                                "item/completed",
                                thread,
                                turn,
                                {"item": {**item, "exitCode": 0}},
                            )
                            self.hooks(thread, turn, "postToolUse")
                        self.hooks(thread, turn, "stop")
                        self.event(
                            "turn/completed",
                            thread,
                            None,
                            {"turn": {"id": turn, "status": "completed"}},
                        )
                        if prompt == "取消当前任务。":
                            world["cancelled"].add(thread)
                        return turn, [
                            {"direction": "response", "message": x}
                            for x in self.rows[begin:]
                        ]

                    def observed_compact(self, thread):
                        self.rpc("thread/compact/start", {"threadId": thread})
                        turn = "C" + thread
                        self.event("turn/started", thread,
                                   None, {"turn": {"id": turn}})
                        self.hooks(thread, turn, "preCompact")
                        for stage in ("started", "completed"):
                            self.event(
                                "item/" + stage,
                                thread,
                                turn,
                                {
                                    "item": {
                                        "id": "compact",
                                        "type": "contextCompaction",
                                    }
                                },
                            )
                        self.event(
                            "thread/status/changed",
                            thread,
                            None,
                            {"status": {"type": "idle"}},
                        )
                        world["compacted"].add(thread)

                    def close(self):
                        if not self.is_cold and scenario == "live_close_fails":
                            world["events"].append("live-close-failed")
                            self.log.close()
                            return {
                                "owned_process_exited": False,
                                "owned_tree_no_running_members": False,
                                "process_group_cleanup_error": None,
                            }
                        world["events"].append(
                            "cold-closed" if self.is_cold else "live-closed"
                        )
                        self.log.close()
                        return {
                            "owned_process_exited": True,
                            "owned_tree_no_running_members": True,
                            "process_group_cleanup_error": None,
                            "cleanup_complete": True,
                            "job_close_confirmed": True,
                        }

                def fake_command(_native, _root, argv, **_kw):
                    if not commands:
                        raise AssertionError("unexpected extra command")
                    fact = commands.pop(0)
                    if argv != fact["argv"]:
                        raise AssertionError("wrong command sequence")
                    if argv[1:4] == ["plugin", "marketplace", "add"]:
                        world["new"] = True
                    if argv[1:3] == ["plugin", "add"]:
                        new_cache.mkdir(parents=True)
                    if argv[1:3] == ["plugin", "remove"]:
                        shutil.rmtree(new_cache)
                    return subprocess.CompletedProcess(
                        argv, 0, json.dumps(
                            fact["observation"] or {}).encode(), b"")

                manager = mock.Mock()
                manager.distribution_manifest.return_value = {
                    "public": "b" * 64}
                files = {"public": "b" * 64}
                with (
                    mock.patch.object(U, "preflight", return_value=subject),
                    mock.patch.object(U, "_verify_replay_subject", side_effect=lambda plan, probe: (U.preflight(plan, probe), "c" * 40, "d" * 64)),
                    mock.patch.object(U, "UpgradeClient", FakeClient),
                    mock.patch.object(U, "_reviewed_sources", wraps=U._reviewed_sources) as review,
                    mock.patch.object(
                        U.scheduler, "_command", side_effect=fake_command
                    ),
                    mock.patch.object(U, "_state_at", side_effect=state_at),
                    mock.patch.object(
                        U,
                        "_old_scope",
                        return_value={"current": [], "ancestor": [], "waiting": 0},
                    ),
                    mock.patch.object(U, "source_files", return_value=files),
                    mock.patch.object(U, "_cache_identity", return_value="c" * 64),
                    mock.patch.object(
                        U, "_load_artifacts_no_pyc", return_value=manager
                    ),
                    mock.patch.object(U.native, "exact_artifact_parity"),
                    mock.patch.object(U.host, "verify_recovery"),
                    mock.patch.object(
                        U, "_sentinel_files", return_value=subject["sentinel"]
                    ),
                    mock.patch.object(
                        U, "_selected_states", return_value={"synthetic": "a" * 64}
                    ),
                ):
                    out = base / "out"
                    result = U.run_open_transition(plan, out, prepared_path)
                    if scenario == "pass":
                        timeout = subject.get("review_timeout_seconds", U.DEFAULT_REVIEW_TIMEOUT_SECONDS)
                        self.assertEqual(timeout, review.call_args.kwargs["timeout"])
                        marker = json.loads((out / "review-required.json").read_text())
                        self.assertEqual(timeout, marker["timeout_seconds_per_step"])
                    if scenario in ("pass", "wrong_stream"):
                        self.assertEqual("pending", result["status"], result)
                        if scenario == "wrong_stream":
                            log = out / "live/rpc.jsonl"
                            with log.open("a", encoding="utf8") as stream:
                                stream.write(
                                    json.dumps(
                                        {
                                            "direction": "request",
                                            "message": {
                                                "id": 999,
                                                "method": "config/batchWrite",
                                                "params": {},
                                            },
                                        }
                                    )
                                    + "\n"
                                )
                                stream.write(
                                    json.dumps(
                                        {
                                            "direction": "response",
                                            "message": {"id": 999, "result": {}},
                                        }
                                    )
                                    + "\n"
                                )
                            result["artifacts"]["live/rpc.jsonl"] = U.sha(log)
                            (out / "result.json").write_text(json.dumps(result))
                            with self.assertRaises(U.UpgradeError):
                                U.verify(plan, out, prepared_path)
                            continue
                        verified = U.verify(plan, out, prepared_path)
                        self.assertEqual(
                            "cancelled_old_before_transition",
                            verified["observed_boundary"],
                        )
                        self.assertLess(
                            world["events"].index("live-closed"),
                            world["events"].index("cold-start"),
                        )
                        self.assertLess(
                            world["events"].index("cold-start"),
                            world["events"].index("cold-disable"),
                        )
                        self.assertEqual([], commands)
                    else:
                        self.assertEqual("failed", result["status"], result)
                        self.assertNotIn("cold-start", world["events"])
                        with self.assertRaises(U.UpgradeError):
                            U.verify(plan, out, prepared_path)


class VersionTableContract(unittest.TestCase):
    """Pins the old/new version bindings the toolkit revision verifies.

    A release round updates NEW_VERSION and its OLD_* bindings in its own tool
    commit; every recorded run must name the exact pair it exercised. The
    stable-identity in-place route is the entry whose old marketplace name
    equals NEW_MARKET.
    """

    def test_stable_identity_in_place_version_is_accepted(self):
        self.assertIn("0.17.0", U.OLD_MARKETS)
        self.assertEqual(U.OLD_MARKETS["0.17.0"], U.NEW_MARKET)
        self.assertIn("0.17.0", U.OLD_ZIP_SHA256)
        self.assertRegex(U.OLD_ZIP_SHA256["0.17.0"], r"[0-9a-f]{64}")

    def test_existing_official_market_routes_keep_their_names(self):
        self.assertEqual(U.OLD_MARKETS["0.16.1"], "codex-context-guard-v016")
        self.assertEqual(U.OLD_MARKETS["0.15.1"], "codex-context-guard")
        self.assertEqual(U.NEW_MARKET, "codex-context-guard")
        self.assertNotIn(U.NEW_MARKET, set(U.OLD_MARKETS["0.16.1"]))

    def test_daily_wrapper_binds_separate_marketplace_and_unmodified_package(self):
        with tempfile.TemporaryDirectory() as directory:
            wrapper = Path(directory).resolve()
            package = wrapper / "artifact"
            package.mkdir()
            manifest = wrapper / ".agents/plugins/marketplace.json"
            manifest.parent.mkdir(parents=True)
            entry = {"name": "context-guard", "source": {"source": "local", "path": "./artifact"}}
            catalog = {"name": "codex-context-guard-v0161", "plugins": [entry]}
            manifest.write_text(json.dumps(catalog))
            self.assertEqual(U.sha(manifest), U._wrapper_manifest(wrapper, package))
            self.assertEqual("codex-context-guard-v0161", U._old_market({
                "old_version": "0.16.1", "old_marketplace_root": str(wrapper),
            }))
            row = {"source": {"source": "local", "path": str(package)},
                   "marketplaceSource": {"sourceType": "local", "source": str(wrapper)}}
            U._plugin_source(row, package, wrapper)
            with self.assertRaises(U.UpgradeError):
                U._plugin_source(row, package)
            with self.assertRaises(U.UpgradeError):
                U._old_market({"old_version": "0.17.0", "old_marketplace_root": str(wrapper)})
            for bad in ({**catalog, "name": "codex-context-guard-v016"},
                        {**catalog, "plugins": [entry, entry]},
                        {**catalog, "plugins": [{**entry, "source": {"source": "local", "path": "../artifact"}}]}):
                with self.subTest(catalog=bad):
                    manifest.write_text(json.dumps(bad))
                    with self.assertRaises(U.UpgradeError):
                        U._wrapper_manifest(wrapper, package)

    def test_zip_route_versions_and_source_export_route_stay_distinct(self):
        # 0.15.1 keeps its published-commit source-export route; only ZIP-route
        # versions may pass old_release_zip provenance.
        self.assertNotIn("0.15.1", U.OLD_ZIP_SHA256)

    def test_target_version_constant_is_a_pinned_release_shape(self):
        self.assertRegex(U.NEW_VERSION, r"[0-9]+\.[0-9]+\.[0-9]+")


if __name__ == "__main__":
    unittest.main()
