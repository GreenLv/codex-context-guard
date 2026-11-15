import contextlib
import copy
import importlib.util
import io
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "bt_refresh", HERE.parent / "tools/validation/native_between_turns_acceptance.py"
)
bt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bt)


class ConfigRefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        (self.root / "config.toml").write_text("[hooks.state]\n")
        self.ctx = {
            "home": self.root,
            "workspace": self.root,
            "new_root": self.root / "new",
            "windows_backend": None,
            "expected_model": "model",
            "daily": types.SimpleNamespace(_same_path=lambda a, b: a == b),
            "u": object(),
        }
        self.provider = {
            "model_provider": None,
            "endpoint_policy": "official_default",
            "custom_catalog": False,
        }
        self.layer = {
            "version": "opaque",
            "shape": {
                "entries": 1,
                "tables": 1,
                "hash_strings": 1,
                "combined_hashes": 0,
            },
            "provider": self.provider,
            "unique_active_base_user_layer": True,
        }
        self.receipt = {
            "schema": "cg-user-config-refresh/v1",
            "mode": bt.CONFIG_REFRESH,
            "server_pid": 42,
            "thread": "old",
            "file": bt.config_file_projection(self.root),
            "layer": self.layer,
            "resume_verified": True,
            "loaded_before": True,
            "loaded_after": True,
        }
        self.attempt = {
            "schema": "cg-config-refresh-attempt/v1",
            "server_pid": 42,
            "thread": "old",
            "file_before": self.receipt["file"],
            "layer": self.layer,
        }
        self.outcome = {
            "schema": "cg-config-refresh-outcome/v1",
            "server_pid": 42,
            "thread": "old",
            "batch_send_attempted": True,
            "file_after": self.receipt["file"],
            "file_state": "unchanged",
        }
        self.inv = {"target": True}
        self.rows = []

        def marker(name, n):
            self.rows.append(
                {"direction": "local", "event": name, "pid": 42, "monotonic_ns": n}
            )

        def pair(ident, method, params, result):
            self.rows.append(
                {
                    "direction": "request",
                    "message": {"id": ident, "method": method, "params": params},
                }
            )
            self.rows.append(
                {"direction": "response", "message": {"id": ident, "result": result}}
            )

        marker("apply_finished", 10)
        pair(1, "hooks/list", {"cwds": [str(self.root)]}, {"data": []})
        marker("new_trust_confirmed", 11)
        for ident in (2, 3):
            pair(ident, "config/read", {"cwd": None, "includeLayers": True}, self.layer)
        pair(
            4,
            "config/batchWrite",
            {"edits": [], "expectedVersion": "opaque", "reloadUserConfig": True},
            {
                "status": "ok",
                "version": "opaque",
                "file_matches": True,
                "overridden": False,
            },
        )
        pair(5, "config/read", {"cwd": None, "includeLayers": True}, self.layer)
        pair(
            7,
            "thread/loaded/list",
            {},
            {"controlled_thread_loaded": True, "complete": True},
        )
        pair(
            6,
            "thread/resume",
            {"threadId": "old"},
            {
                "thread": {"id": "old"},
                "model": "model",
                "modelProvider": "openai",
                "approvalPolicy": "on-request",
                "sandbox": {"type": "readOnly"},
                "cwd_matches": True,
            },
        )
        pair(
            8,
            "thread/loaded/list",
            {},
            {"controlled_thread_loaded": True, "complete": True},
        )
        marker("config_refresh_completed", 12)
        marker("old_continuation_complete", 13)

    def tearDown(self):
        self.tmp.cleanup()

    def validate(self, rows=None, receipt=None):
        with mock.patch.object(bt, "product_inventory", return_value=self.inv):
            rows = self.rows if rows is None else rows
            bt.validate_config_refresh_journal(
                self.ctx,
                rows,
                receipt or self.receipt,
                self.attempt,
                self.outcome,
                42,
                "old",
                0,
                len(rows) - 1,
                self.inv,
            )

    def test_consumer_positive_and_extra_or_reordered_rpc(self):
        self.validate()
        for mutation in (
            "duplicate",
            "wrong_version",
            "override",
            "unknown",
            "reorder",
            "wrong_thread",
            "missing_response",
            "closed",
            "loaded_false",
            "unsubscribe",
            "shell",
        ):
            rows = copy.deepcopy(self.rows)
            batch = next(
                i
                for i, row in enumerate(rows)
                if row.get("message", {}).get("method") == "config/batchWrite"
            )
            if mutation == "duplicate":
                rows[batch:batch] = copy.deepcopy(rows[batch : batch + 2])
            if mutation == "wrong_version":
                rows[batch]["message"]["params"]["expectedVersion"] = "other"
            if mutation == "override":
                rows[batch]["message"]["params"]["edits"] = [{"keyPath": "x"}]
            if mutation == "unknown":
                rows[batch]["message"]["method"] = "config/value/write"
            if mutation == "reorder":
                rows[batch], rows[batch - 2] = rows[batch - 2], rows[batch]
            if mutation == "wrong_thread":
                next(
                    row
                    for row in rows
                    if row.get("message", {}).get("method") == "thread/resume"
                )["message"]["params"]["threadId"] = "other"
            if mutation == "missing_response":
                del rows[batch + 1]
            if mutation == "closed":
                rows.insert(
                    batch,
                    {
                        "direction": "response",
                        "message": {
                            "method": "thread/closed",
                            "params": {"threadId": "old"},
                        },
                    },
                )
            if mutation == "loaded_false":
                index = next(
                    i
                    for i, row in enumerate(rows)
                    if row.get("message", {}).get("method") == "thread/loaded/list"
                )
                rows[index + 1]["message"]["result"]["controlled_thread_loaded"] = False
            if mutation in ("unsubscribe", "shell"):
                rows[batch]["message"]["method"] = (
                    "thread/unsubscribe"
                    if mutation == "unsubscribe"
                    else "thread/shellCommand"
                )
            with self.subTest(mutation=mutation), self.assertRaises(bt.Refused):
                self.validate(rows)

    def test_only_reviewed_platform_binary_is_accepted(self):
        for system in ("Darwin", "Windows"):
            plan = {
                "expected_cli_version": bt.REVIEWED_CLI_VERSION,
                "cli_sha256": bt.REVIEWED_CLI_SHA256[system],
            }
            with mock.patch.object(bt.platform, "system", return_value=system):
                bt.require_reviewed_cli(plan)
                for wrong in (
                    {**plan, "cli_sha256": "0" * 64},
                    {**plan, "cli_sha256": None},
                    {"expected_cli_version": bt.REVIEWED_CLI_VERSION},
                    {**plan, "expected_cli_version": "codex-cli 0.169.0"},
                ):
                    with self.assertRaises(bt.Refused):
                        bt.require_reviewed_cli(wrong)
        with mock.patch.object(bt.platform, "system", return_value="Linux"):
            with self.assertRaises(bt.Refused):
                bt.require_reviewed_cli({"expected_cli_version": bt.REVIEWED_CLI_VERSION, "cli_sha256": None})

    def test_file_or_receipt_drift_refused(self):
        changed = copy.deepcopy(self.receipt)
        changed["layer"]["shape"]["combined_hashes"] = 1
        with self.assertRaises(bt.Refused):
            self.validate(receipt=changed)
        (self.root / "config.toml").write_text("changed")
        with self.assertRaises(bt.Refused):
            self.validate()
        (self.root / "config.toml").write_bytes(b"x" * (8 * 1024 * 1024 + 1))
        with self.assertRaises(bt.Refused):
            bt.config_file_projection(self.root)

    def test_global_turn_scope_rejects_extra_or_wrong_identity(self):
        rows = [{"direction": "local", "event": "startup"}]
        def pair(ident, thread, turn):
            rows.extend([{"direction": "request", "message": {"id": ident, "method": "turn/start", "params": {"threadId": thread}}},
                         {"direction": "response", "message": {"id": ident, "result": {"turn": {"id": turn}}}}])
        def marker(name):
            rows.append({"direction": "local", "event": name})
        pair(1, "old", "t1")
        marker("old_turn_complete")
        marker("config_refresh_completed")
        pair(2, "old", "t2")
        marker("old_continuation_complete")
        pair(3, "fresh", "t3")
        marker("fresh_turn_complete")
        old = {"thread": "old", "old_turn": "t1", "new_turn": "t2"}
        fresh = {"thread": "fresh", "turn": "t3"}
        bt.validate_turn_request_scope(rows, old, fresh)
        extra = copy.deepcopy(rows)
        extra.extend(copy.deepcopy(rows[1:3]))
        with self.assertRaises(bt.Refused):
            bt.validate_turn_request_scope(extra, old, fresh)
        wrong = copy.deepcopy(rows)
        wrong[5]["message"]["params"]["threadId"] = "other"
        with self.assertRaises(bt.Refused):
            bt.validate_turn_request_scope(wrong, old, fresh)

    def test_active_layer_projection_does_not_expose_hashes(self):
        data = {
            "config": {"model_provider": None, "model_providers": {}},
            "layers": [
                {
                    "name": {
                        "type": "user",
                        "file": str(self.root / "config.toml"),
                        "profile": None,
                    },
                    "version": "opaque",
                    "config": {
                        "hooks": {
                            "state": {
                                "private-key": {"trusted_hash": "synthetic-secret"}
                            }
                        }
                    },
                }
            ],
        }
        projected = bt.config_layer_projection(data, self.ctx)
        self.assertNotIn("synthetic-secret", json.dumps(projected))
        self.assertNotIn("private-key", json.dumps(projected))
        data["layers"][0]["config"]["hooks"]["state"]["private-key"]["trusted_hash"] = (
            "a/b"
        )
        with self.assertRaises(bt.Refused):
            bt.config_layer_projection(data, self.ctx)
        data["layers"].append(copy.deepcopy(data["layers"][0]))
        with self.assertRaises(bt.Refused):
            bt.config_layer_projection(data, self.ctx)

    def test_resume_policy_projection(self):
        response = {
            "thread": {"id": "old", "history": "do not persist"},
            "model": "model",
            "modelProvider": "openai",
            "approvalPolicy": "on-request",
            "sandbox": {"type": "readOnly"},
            "cwd": str(self.root),
        }
        result = bt.resume_projection(response, self.ctx, "old")
        self.assertNotIn("history", json.dumps(result))
        for key, bad in (
            ("model", "other"),
            ("approvalPolicy", "never"),
            ("sandbox", {"type": "dangerFullAccess"}),
            ("cwd", "/other"),
        ):
            wrong = copy.deepcopy(response)
            wrong[key] = bad
            with self.subTest(key=key), self.assertRaises(bt.Refused):
                bt.resume_projection(wrong, self.ctx, "old")

    def test_private_receipt_fsyncs_file_and_posix_parent(self):
        import os
        import stat

        actual = os.fsync
        seen = []
        def record(fd):
            seen.append(stat.S_ISDIR(os.fstat(fd).st_mode))
            actual(fd)
        with mock.patch.object(bt.os, "fsync", side_effect=record):
            bt.durable_private_receipt(self.root / "receipt.json", {"safe": True})
        self.assertEqual(seen, [False, True] if os.name == "posix" else [False])

    def test_factory_refresh_sequence_and_conflict_stops(self):
        for scenario in (
            "success",
            "conflict",
            "conflict_post_unknown",
            "resume_failure",
            "post_unknown",
            "post_changed",
            "not_loaded",
            "receipt_failure",
        ):
            with self.subTest(scenario=scenario):
                sent = []
                root = self.root / scenario
                root.mkdir()
                (root / "config.toml").write_text("[hooks.state]\n")
                layer_raw = {
                    "config": {"model_provider": None, "model_providers": {}},
                    "layers": [
                        {
                            "name": {
                                "type": "user",
                                "file": str(root / "config.toml"),
                                "profile": None,
                            },
                            "version": "opaque",
                            "config": {
                                "hooks": {"state": {"x": {"trusted_hash": "private"}}}
                            },
                        }
                    ],
                }

                class Base:
                    def send(self, message):
                        if type(message.get("id")) is int:
                            self.pending[message["id"]] = message["method"]
                        sent.append(copy.deepcopy(message))

                    def _projection(self, message):
                        if "id" not in message:
                            params = message["params"]
                            run = {k: v for k, v in params["run"].items() if k != "entries"}
                            return {"method": message["method"], "params": {"threadId": params["threadId"], "turnId": params["turnId"], "run": run}}
                        self.pending.pop(message["id"], None)
                        raw = message["result"]
                        result = {"thread": {"id": raw["thread"]["id"]}} if "thread" in raw else {"turn": {"id": raw["turn"]["id"]}} if "turn" in raw else {}
                        return {"id": message["id"], "result": result}

                    def rpc(self, method, params):
                        self.sequence += 1
                        ident = self.sequence
                        self.send({"id": ident, "method": method, "params": params})
                        if method == "config/read":
                            result = (
                                layer_raw
                                if params["includeLayers"]
                                else {
                                    "config": {
                                        "model_provider": None,
                                        "model_providers": {},
                                    }
                                }
                            )
                        elif method == "config/batchWrite":
                            if scenario == "post_changed":
                                (root / "config.toml").write_text("changed")
                            result = {
                                "status": "conflict"
                                if scenario in ("conflict", "conflict_post_unknown")
                                else "ok",
                                "version": "opaque",
                                "filePath": str(root / "config.toml"),
                            }
                        elif method == "thread/loaded/list":
                            result = {"data": [] if scenario == "not_loaded" else ["old"], "nextCursor": None}
                        elif method == "thread/resume":
                            result = {
                                "thread": {"id": "old"},
                                "model": "wrong"
                                if scenario == "resume_failure"
                                else "model",
                                "modelProvider": "openai",
                                "approvalPolicy": "on-request",
                                "sandbox": {"type": "readOnly"},
                                "cwd": str(root),
                            }
                        elif method == "thread/start":
                            result = {"thread": {"id": "old"}, "model": "model", "modelProvider": "openai", "approvalPolicy": "on-request", "sandbox": {"type": "readOnly"}}
                        elif method == "turn/start":
                            result = {"turn": {"id": "turn1"}}
                        else:
                            result = {}
                        self._projection({"id": ident, "result": result})
                        return result

                class Owner:
                    def __init__(self):
                        self.process = types.SimpleNamespace(
                            pid=42, stdin=io.StringIO(), stdout=io.StringIO()
                        )

                    def close(self, _timeout):
                        return {
                            "owned_process_exited": True,
                            "owned_tree_no_running_members": True,
                            "process_group_cleanup_error": None,
                        }

                host = types.SimpleNamespace(
                    Client=Base,
                    OwnedProcess=types.SimpleNamespace(spawn=lambda *a, **k: Owner()),
                )
                ctx = {
                    **self.ctx,
                    "home": root,
                    "workspace": root,
                    "u": types.SimpleNamespace(UpgradeClient=Base, _source_key=lambda raw, sources: raw if raw in sources else None),
                    "host": host,
                    "output": root,
                    "old_root": root,
                    "cli": root / "cli",
                    "app_server_argv": ["cli", "app-server"],
                    "read_file": root / "README.md",
                }
                real_snapshot = bt.config_file_projection
                snapshots = []

                def snapshot(home):
                    snapshots.append(1)
                    if (scenario == "post_unknown" and len(snapshots) == 4) or (
                        scenario == "conflict_post_unknown" and len(snapshots) == 3
                    ):
                        raise OSError("synthetic")
                    return real_snapshot(home)

                with (
                    mock.patch.object(bt, "product_inventory", return_value={}),
                    mock.patch.object(
                        bt, "config_file_projection", side_effect=snapshot
                    ),
                    (mock.patch.object(bt, "durable_private_receipt", side_effect=OSError("sync failed"))
                     if scenario == "receipt_failure" else contextlib.nullcontext()),
                ):
                    client = bt.DailyClientFactory(ctx)()
                    try:
                        self.assertEqual(client.start(), "old")
                        client.rpc("turn/start", {"threadId": "old", "input": []})
                        self.assertEqual(client.active_diagnostic_turn, ("old", "turn1"))
                        source = str(root / "hooks.json")
                        hook = {"eventName": "stop", "sourcePath": source, "source": "plugin", "handlerType": "command", "displayOrder": 0,
                                "enabled": True, "trustStatus": "trusted", "key": "k", "currentHash": "h"}
                        client.approved = {("stop", source): hook}
                        run = {"id": "run1", "eventName": "stop", "sourcePath": source, "source": "plugin", "handlerType": "command",
                               "displayOrder": 0, "executionMode": "sync", "status": "failed", "durationMs": 1,
                               "entries": [{"kind": "error", "text": "hook exited with code 1"}]}
                        event = {"method": "hook/completed", "params": {"threadId": "old", "turnId": "turn1", "run": run}}
                        projected = client._projection(event)
                        self.assertIn("failure_diagnostic", projected["params"]["run"])
                        self.assertNotIn("hook exited with code 1", json.dumps(projected))
                        started = copy.deepcopy(projected)
                        started["method"] = "hook/started"
                        journal = [{"direction": "response", "message": x} for x in (started, projected)]
                        with self.assertRaises(ValueError):
                            bt.native_identity._paired(journal, client.approved, "old", "stop", turn="turn1")
                        with mock.patch.object(bt.hook_failure_diagnostics, "project_failed", side_effect=AssertionError("foreign content accessed")):
                            for foreign_thread, foreign_turn in (("other", "turn1"), ("old", "other")):
                                foreign = copy.deepcopy(event)
                                foreign["params"]["threadId"], foreign["params"]["turnId"] = foreign_thread, foreign_turn
                                self.assertNotIn("failure_diagnostic", client._projection(foreign)["params"]["run"])
                            client.active_diagnostic_turn = None
                            self.assertNotIn("failure_diagnostic", client._projection(event)["params"]["run"])
                        with mock.patch.object(Base, "observed_turn", return_value=("turn1", []), create=True):
                            client.active_diagnostic_turn = ("old", "turn1")
                            client.observed_turn("old", "synthetic")
                            self.assertIsNone(client.active_diagnostic_turn)
                        if scenario in (
                            "conflict",
                            "conflict_post_unknown",
                            "resume_failure",
                            "post_changed",
                            "not_loaded",
                        ):
                            with self.assertRaises(bt.Refused):
                                client.refresh_config_for_thread("old")
                        elif scenario in ("post_unknown", "receipt_failure"):
                            with self.assertRaises(OSError):
                                client.refresh_config_for_thread("old")
                        else:
                            receipt = client.refresh_config_for_thread("old")
                            self.assertTrue(
                                receipt["loaded_before"] and receipt["loaded_after"]
                            )
                            with self.assertRaises(bt.Refused):
                                client.refresh_config_for_thread("old")
                    finally:
                        client.close()
                methods = [item["method"] for item in sent]
                if scenario == "receipt_failure":
                    self.assertEqual(methods.count("config/batchWrite"), 0)
                    self.assertFalse((root / "config-refresh-outcome.json").exists())
                    continue
                self.assertEqual(methods.count("config/batchWrite"), 1)
                self.assertEqual(
                    methods.count("thread/resume"),
                    0
                    if scenario in ("conflict", "conflict_post_unknown", "post_changed", "not_loaded")
                    else 1,
                )
                attempt = json.loads((root / "config-refresh-attempt.json").read_text())
                outcome = json.loads((root / "config-refresh-outcome.json").read_text())
                self.assertTrue(outcome["batch_send_attempted"])
                self.assertEqual(
                    outcome["file_state"],
                    "unknown"
                    if scenario in ("post_unknown", "conflict_post_unknown")
                    else "changed"
                    if scenario == "post_changed"
                    else "unchanged",
                )
                self.assertNotIn("private", json.dumps(attempt))


if __name__ == "__main__":
    unittest.main()
