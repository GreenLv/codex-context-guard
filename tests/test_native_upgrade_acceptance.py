"""Cheap fail-closed controls; no real trust, model, install, or network."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
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


def lifecycle_facts():
    codex, old, new = "/fixture/codex", "/fixture/old", "/fixture/new"
    market, sentinel_name = "codex-context-guard", "cg-u01-sentinel-test"
    plugin = "context-guard@" + market
    baseline = {"marketplace": sentinel_name, "cache_marker": {"path": "/safe/cache"},
                "data_marker": {"path": "/safe/data"}}
    subject = {"codex": codex, "old_version": "0.15.1", "old_artifact": old,
               "new_artifact": new, "home": "/fixture/home", "sentinel": baseline}
    old_path, new_path = "/fixture/home/plugins/cache/codex-context-guard/context-guard/0.15.1", \
                         "/fixture/home/plugins/cache/codex-context-guard/context-guard/0.17.0"
    old_add = {"pluginId": plugin, "name": "context-guard", "marketplaceName": market,
               "version": "0.15.1", "installedPath": old_path}
    new_add = {**old_add, "version": "0.17.0", "installedPath": new_path}
    old_entry = {"pluginId": plugin, "name": "context-guard", "marketplaceName": market,
                 "version": "0.15.1", "installed": True, "enabled": True,
                 "source": {"source": "local", "path": old},
                 "marketplaceSource": {"sourceType": "local", "source": old}}
    new_entry = {**old_entry, "version": "0.17.0", "source": {"source": "local", "path": new},
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
        command_fact(ml, markets_empty), command_fact([codex, "plugin", "list", "--json"], {"installed": []}),
        command_fact([codex, "plugin", "marketplace", "add", old]), command_fact(ml, markets_old),
        command_fact([codex, "plugin", "add", plugin, "--json"], old_add), command_fact(ml, markets_old),
        command_fact(old_pl, old_list), command_fact(ml, markets_old)]
    prepared = {"commands": prepared_commands, "official_add": old_add, "sentinel_before": baseline,
        "sentinel_after": baseline, "sentinel_phases": {name: baseline for name in
            ("after_marketplace_add", "after_plugin_add", "after_plugin_list")}}
    commands = [command_fact(ml, markets_old), command_fact(old_pl, old_list), command_fact(ml, markets_old),
        command_fact([codex, "plugin", "marketplace", "remove", market]), command_fact(ml, markets_empty),
        command_fact([codex, "plugin", "marketplace", "add", new]), command_fact(ml, markets_new),
        command_fact([codex, "plugin", "add", plugin, "--json"], new_add), command_fact(ml, markets_new),
        command_fact(old_pl, new_list), command_fact(ml, markets_new), command_fact(old_pl, disabled),
        command_fact(ml, markets_new), command_fact([codex, "plugin", "remove", plugin]),
        command_fact([codex, "plugin", "list", "--json"], {"installed": []}), command_fact(ml, markets_new),
        command_fact([codex, "plugin", "marketplace", "remove", market]), command_fact(ml, markets_empty)]
    phases = ("before", "after_old_list", "after_old_marketplace_remove", "after_new_marketplace_add",
              "after_new_plugin_add", "after_new_plugin_list", "after_disable", "after_plugin_remove",
              "after_marketplace_remove")
    result = {"commands": commands, "installed_new": {"path": new_path},
              "sentinel_phases": {name: baseline for name in phases}}
    return subject, prepared, result


class UpgradeControls(unittest.TestCase):
    def test_inventory_requires_nine_trusted_per_exact_source(self):
        source = "/isolated/cache/old/hooks/hooks.json"
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

    def test_archive_requires_real_same_thread_paired_end_with_3s_budget(self):
        source, thread = "/isolated/cache/old/hooks/hooks.json", "thread-1"
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
                 "requirements": [{"id": "R1", "sha256": "a" * 64, "status": "pending",
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
        event = client._projection({"method": "item/completed", "params": {"threadId": "t",
            "turnId": "u", "item": {"id": "i", "type": "commandExecution", "cwd": "/w",
                                      "command": "do-not-keep", "exitCode": 0, "output": "do-not-keep"}}})
        self.assertNotIn("do-not-keep", json.dumps(event))
        self.assertEqual("<unapproved>", event["params"]["item"]["command"])
        message = client._projection({"method": "item/completed", "params": {
            "item": {"type": "agentMessage", "text": "do-not-keep"}}})
        self.assertNotIn("do-not-keep", json.dumps(message))

    def test_read_tool_requires_exact_completed_command_and_real_hooks(self):
        source, thread, turn = "/isolated/cache/old/hooks/hooks.json", "thread-1", "turn-1"
        inv = U._inventory(inventory(source), {source: "0.16.1"})
        rows = []
        def add_hook(event):
            for phase in ("started", "completed"):
                run = hook(event, source, event, "completed", 1) if phase == "completed" else hook(event, source, event)
                rows.append({"direction": "response", "message": {"method": "hook/" + phase,
                    "params": {"threadId": thread, "turnId": turn, "run": run}}})
        add_hook("preToolUse")
        for phase in ("started", "completed"):
            item = {"id": "read", "type": "commandExecution", "command": "cat native-read.txt", "cwd": "/workspace"}
            if phase == "completed":
                item["exitCode"] = 0
            rows.append({"direction": "response", "message": {"method": "item/" + phase,
                "params": {"threadId": thread, "turnId": turn, "item": item}}})
        add_hook("postToolUse")
        U.verify_read_tool(rows, inv, thread, turn, "cat native-read.txt", Path("/workspace"))
        bad = copy.deepcopy(rows)
        bad[3]["message"]["params"]["item"]["exitCode"] = 1
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(bad, inv, thread, turn, "cat native-read.txt", Path("/workspace"))
        client = object.__new__(U.UpgradeClient)
        client.pending = {}
        projected = client._projection({"method": "item/started", "params": {
            "threadId": thread, "turnId": turn,
            "item": {"type": "mcpToolCall", "id": "other", "arguments": "do-not-keep"}}})
        self.assertNotIn("do-not-keep", json.dumps(projected))
        journal = copy.deepcopy(rows)
        journal.insert(4, {"direction": "response", "message": projected})
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(journal, inv, thread, turn, "cat native-read.txt", Path("/workspace"))
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(rows[2:], inv, thread, turn, "cat native-read.txt", Path("/workspace"))
        reordered = rows[0:2] + rows[4:6] + rows[2:4]
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(reordered, inv, thread, turn, "cat native-read.txt", Path("/workspace"))
        bad = copy.deepcopy(rows)
        bad[2]["message"]["params"]["item"]["command"] = "cat other.txt"
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(bad, inv, thread, turn, "cat native-read.txt", Path("/workspace"))
        bad = copy.deepcopy(rows)
        bad.insert(4, {"direction": "response", "message": {"method": "item/started",
                   "params": {"threadId": thread, "turnId": turn,
                              "item": {"type": "unknownTool", "id": "other"}}}})
        with self.assertRaises(U.UpgradeError):
            U.verify_read_tool(bad, inv, thread, turn, "cat native-read.txt", Path("/workspace"))

    def test_disable_requires_official_write_and_post_write_empty_inventory(self):
        source = "/isolated/cache/new/hooks/hooks.json"
        new_inv = U._inventory(inventory(source), {source: "0.17.0"})
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

    def test_complete_finish_old_consumer_and_missing_session_end_negative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "result"
            (output / "live").mkdir(parents=True)
            subject, prepared, result = lifecycle_facts()
            old_path = prepared["official_add"]["installedPath"]
            new_path = result["installed_new"]["path"]
            old_source, new_source = old_path + "/hooks/hooks.json", new_path + "/hooks/hooks.json"
            old_hooks, new_hooks = inventory(old_source)["data"][0]["hooks"], inventory(new_source)["data"][0]["hooks"]
            subject.update({"product_commit": "a" * 40, "toolkit_commit": "b" * 40,
                            "product_root": "/fixture/product", "workspace": "/fixture/workspace",
                            "old_data_root": "/fixture/home/old-data", "new_data_root": "/fixture/home/new-data",
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

            def turn(i, thread, turn_id, source, read=False):
                request(i, "turn/start", {"threadId": thread}, {"turn": {"id": turn_id}})
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

            def mark(name, tick):
                rows.append({"direction": "local", "event": name, "pid": 123, "monotonic_ns": tick})

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
            archive(6, "A", old_source)
            archive(7, "B", old_source)
            mark("transition_started", 35)
            mark("transition_completed", 115)
            request(8, "hooks/list", {}, {"data": [{"hooks": new_hooks}]})
            request(102, "thread/start", {}, {"thread": {"id": "F"}})
            turn(9, "F", "F1", new_source)
            archive(10, "F", new_source)
            disable = {"edits": [{"keyPath": 'plugins."context-guard@codex-context-guard".enabled',
                                  "value": False, "mergeStrategy": "upsert"}], "reloadUserConfig": True}
            request(11, "config/batchWrite", disable)
            request(12, "hooks/list", {}, {"data": [{"hooks": []}]})
            mark("disable_completed", 125)
            mark("plugin_removed", 155)
            mark("marketplace_removed", 185)
            journal = output / "live/rpc.jsonl"
            journal.write_text("".join(json.dumps(row) + "\n" for row in rows))
            pending = [{"id": "R1", "sha256": "a" * 64, "status": "pending"}]

            def snapshot(thread, count, recovery):
                return {"session": {"id": thread}, "requirements": pending, "mode": {"active": True},
                        "compactions_count": count, "recovery_state": recovery}

            for name, value in {"before-compact.json": snapshot("A", 0, None),
                "before-a.json": snapshot("A", 1, "consumed"), "before-b.json": snapshot("B", 0, None),
                "retained-a.json": snapshot("A", 1, "consumed"), "retained-b.json": snapshot("B", 0, None),
                "fresh-after-transition.json": snapshot("F", 0, None)}.items():
                (output / name).write_text(json.dumps(value))
            data_facts = {"synthetic": "a" * 64}
            result.update({"schema": U.REPORT, "status": "pending", "stage": "open_transition",
                "subject": subject, "pending": ["independent_consumer"], "old_inventory": old_hooks,
                "new_inventory": new_hooks, "disabled_inventory": [],
                "before": {"thread_a": "A", "thread_b": "B", "turn_a": "A1", "turn_b": "B1",
                    "post_compact_turn": "A2", "data_root": subject["old_data_root"], "app_server_pid": 123,
                    "read_command": "cat native-read.txt", "read_file_sha256": "c" * 64,
                    "state_a_sha256": "d" * 64, "state_b_sha256": "e" * 64},
                "old_data_after_transition": {"thread_a_sha256": "d" * 64, "thread_b_sha256": "e" * 64},
                "after": {"fresh_thread": "F", "fresh_turn": "F1", "data_root": subject["new_data_root"]},
                "installed_new": {"path": new_path, "source": subject["new_artifact"], "version": "0.17.0",
                                  "files": {"public": "b" * 64}},
                "selected_data_before_removal": data_facts, "selected_data_after_removal": data_facts,
                "cleanup": [{"owned_process_exited": True, "owned_tree_no_running_members": True,
                             "process_group_cleanup_error": None}]})
            for index, item in enumerate(result["commands"]):
                item["started_monotonic_ns"] = 10 + 10 * index
                item["completed_monotonic_ns"] = 11 + 10 * index
            result["artifacts"] = {str(p.relative_to(output)): U.sha(p) for p in output.rglob("*") if p.is_file()}
            (output / "result.json").write_text(json.dumps(result))
            manager = mock.Mock()
            manager.distribution_manifest.return_value = {"public": "b" * 64}
            with mock.patch.object(U, "preflight", return_value=subject), \
                 mock.patch.object(U.native, "load_artifacts", return_value=manager), \
                 mock.patch.object(U, "_selected_states", return_value=data_facts), \
                 mock.patch.object(U, "_sentinel_files", return_value=subject["sentinel"]):
                accepted = U.verify({}, output, prepared_path)
                self.assertEqual("finish_old_before_transition", accepted["observed_boundary"])
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

                # A second synthetic receipt exercises an open A and a cold B;
                # it must never be conflated with the quiescent boundary above.
                old_archive_start = next(i for i, row in enumerate(rows)
                    if row.get("direction") == "request" and row.get("message", {}).get("method") == "thread/archive")
                rows[:] = rows[:old_archive_start]
                request(103, "thread/unsubscribe", {"threadId": "B"})
                mark("transition_started", 35)
                mark("transition_completed", 115)
                request(104, "hooks/list", {}, {"data": [{"hooks": new_hooks}]})
                turn(105, "A", "A3", new_source)
                archive(106, "A", new_source)
                request(107, "config/batchWrite", disable)
                request(108, "hooks/list", {}, {"data": [{"hooks": []}]})
                mark("disable_completed", 125)
                mark("plugin_removed", 155)
                mark("marketplace_removed", 185)
                journal.write_text("".join(json.dumps(row) + "\n" for row in rows))
                rows[:] = []
                request(201, "hooks/list", {}, {"data": [{"hooks": new_hooks}]})
                request(202, "thread/resume", {"threadId": "B"})
                hook_pair("B", None, "sessionStart", new_source)
                turn(203, "B", "B2", new_source)
                archive(204, "B", new_source)
                (output / "cold").mkdir()
                (output / "cold/rpc.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
                (output / "after-a.json").write_text(json.dumps(snapshot("A", 1, "consumed")))
                (output / "after-b.json").write_text(json.dumps(snapshot("B", 0, None)))
                subject["transition_strategy"] = "observe-open"
                prepared["subject"] = subject
                prepared_path.write_text(json.dumps(prepared))
                result["subject"] = subject
                result["after"] = {"thread_a": "A", "thread_b": "B", "turn_a": "A3", "turn_b": "B2",
                                   "data_root": subject["new_data_root"]}
                result["cleanup"].append(dict(result["cleanup"][0]))
                required = ("live/rpc.jsonl", "cold/rpc.jsonl", "before-compact.json", "before-a.json",
                            "before-b.json", "retained-a.json", "retained-b.json", "after-a.json", "after-b.json")
                result["artifacts"] = {name: U.sha(output / name) for name in required}
                (output / "result.json").write_text(json.dumps(result))
                accepted = U.verify({}, output, prepared_path)
                self.assertEqual("observed_open_and_cold_continuity", accepted["observed_boundary"])
                result["after"]["thread_b"] = "other"
                (output / "result.json").write_text(json.dumps(result))
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
                        markets.append({"name": market, "root": str(old),
                                        "marketplaceSource": {"sourceType": "local", "source": str(old)}})
                    value = {"marketplaces": markets}
                elif argv[2:4] == ["list", "--json"]:
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
                    "old_data_root": str(home / "old-data")}
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


if __name__ == "__main__":
    unittest.main()
