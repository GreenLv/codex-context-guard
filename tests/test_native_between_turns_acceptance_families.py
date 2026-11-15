import copy
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "orig", HERE / "test_native_between_turns_acceptance.py"
)
orig = importlib.util.module_from_spec(spec)
spec.loader.exec_module(orig)
bt = orig.bt
u = orig.u


class FamilyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def make_symlink(self, link, target, *, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                with self.subTest(capability="native symlink"):
                    self.skipTest("native symlink creation requires an unavailable Windows privilege")
                return False
            raise
        return True

    def tearDown(self):
        self.tmp.cleanup()

    def test_safe_bytes_compares_each_stat_provider_independently(self):
        path = self.root / "input.txt"
        path.write_bytes(b"evidence")
        actual = path.lstat()

        def snapshot(**changes):
            fields = {
                name: getattr(actual, name)
                for name in (
                    "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                    "st_mtime_ns", "st_ctime_ns",
                )
            }
            fields.update(changes)
            return types.SimpleNamespace(**fields)

        before = snapshot()
        opened = snapshot(st_ctime_ns=actual.st_ctime_ns + 100)
        cases = (
            ("stable provider difference", before, opened, opened, before, True),
            ("handle ctime changes", before, opened,
             snapshot(st_ctime_ns=opened.st_ctime_ns + 1), before, False),
            ("path ctime changes", before, opened, opened,
             snapshot(st_ctime_ns=before.st_ctime_ns + 1), False),
            ("path replacement", before, opened, opened,
             snapshot(st_ino=before.st_ino + 1), False),
            ("handle link count changes", before, opened,
             snapshot(st_ctime_ns=opened.st_ctime_ns, st_nlink=2), before, False),
            ("path reparse attribute appears", before, opened, opened,
             snapshot(st_file_attributes=0x400), False),
        )
        for name, first_path, first_handle, last_handle, last_path, accepted in cases:
            with (
                self.subTest(name=name),
                mock.patch.object(bt, "regular", return_value=path),
                # Provider mutation fixtures isolate identity checks from the
                # real OS opener, which has its own invocation regression.
                mock.patch.object(bt.native_io, "open_snapshot_file",
                                  side_effect=lambda p: os.open(p, os.O_RDONLY)),
                mock.patch.object(Path, "lstat", side_effect=[first_path, last_path]),
                mock.patch.object(bt.os, "fstat", side_effect=[first_handle, last_handle]),
            ):
                if accepted:
                    self.assertEqual(bt.safe_bytes(path), b"evidence")
                else:
                    with self.assertRaises(bt.Refused):
                        bt.safe_bytes(path)

        executable_mode = snapshot(st_mode=actual.st_mode | 0o111)
        self.assertEqual(
            bt._safe_common_identity(before, windows_executable=True),
            bt._safe_common_identity(executable_mode, windows_executable=True),
        )
        self.assertNotEqual(
            bt._safe_common_identity(before), bt._safe_common_identity(executable_mode)
        )

    def test_safe_bytes_uses_repository_no_follow_opener(self):
        path = self.root / "evidence.json"
        path.write_bytes(b"evidence")
        with mock.patch.object(bt.native_io, "open_snapshot_file", wraps=bt.native_io.open_snapshot_file) as opener:
            self.assertEqual(bt.safe_bytes(path), b"evidence")
        opener.assert_called_once_with(path)
        with mock.patch.object(bt.native_io, "open_snapshot_file", side_effect=OSError("reparse refused")):
            with self.assertRaises(OSError):
                bt.safe_bytes(path)

    def test_policy_root_symlink_parent_alias_is_not_same_path(self):
        (self.root / "data").mkdir()
        (self.root / "outer" / "child").mkdir(parents=True)
        (self.root / "outer" / "data").mkdir()
        link = self.root / "linked"
        if not self.make_symlink(link, self.root / "outer" / "child", directory=True):
            return
        raw = str(link / ".." / "data")
        # POSIX follows the symlink before the parent segment; Win32 may
        # normalize that segment first. Both platforms must reject this alias.
        if os.name != "nt":
            self.assertNotEqual(Path(raw).resolve(), (self.root / "data").resolve())
        self.assertFalse(orig.product_daily._same_path(raw, str(self.root / "data")))

    def test_hash_identity_does_not_use_bounded_record_reader(self):
        import hashlib
        path = self.root / "binary"
        path.write_bytes(b"verified executable identity")
        with mock.patch.object(bt, "safe_bytes", side_effect=bt.Refused("record limit")):
            self.assertEqual(bt.sha(path), hashlib.sha256(path.read_bytes()).hexdigest())

    def make_client(self, response, spawn_error=None, *, backend=None, config_windows=None):
        if backend is None and bt.platform.system() == "Windows":
            backend = "mxc"
            config_windows = {"sandbox": "mxc"}
        ctx = {
            "output": self.root,
            "old_root": self.root / "old",
            "new_root": self.root / "new",
            "home": self.root / "home",
            "workspace": self.root,
            "cli": self.root / "cli",
            "app_server_argv": ([str(self.root / "cli"), "-c", 'windows.sandbox="mxc"', "app-server"]
                                if backend else [str(self.root / "cli"), "app-server"]),
            "windows_backend": backend,
            "expected_model": "test-model",
            "read_file": self.root / "README.md",
        }
        requests = []
        self.last_ctx = ctx

        class Base:
            def rpc(self, method, params):
                requests.append((method, params))
                if method == "thread/start":
                    return response
                if method == "config/read":
                    config = {"model_provider": "openai", "model_providers": {}}
                    if config_windows is not None:
                        config["windows"] = config_windows
                    return {"config": config}
                return {}

            def send(self, message):
                return None

        class Spawn:
            @staticmethod
            def spawn(*a, **k):
                self.last_spawn = a[0]
                if spawn_error:
                    raise spawn_error
                return types.SimpleNamespace(
                    process=types.SimpleNamespace(pid=12, stdin=io.StringIO(), stdout=io.StringIO()),
                    close=lambda timeout: {
                        "cleanup_complete": True,
                        "owned_process_exited": True,
                        "owned_tree_no_running_members": True,
                        "process_group_cleanup_error": None,
                        "job_close_confirmed": True,
                        "job_assignment_confirmed": True,
                    },
                )

        ctx["u"] = types.SimpleNamespace(UpgradeClient=Base)
        ctx["host"] = types.SimpleNamespace(OwnedProcess=Spawn, Client=Base)
        with (
            mock.patch.object(bt, "product_inventory", return_value={}),
        ):
            client = bt.DailyClientFactory(ctx)()
        return client, requests, ctx

    def test_windows_backend_plan_and_real_factory_argv(self):
        with mock.patch.object(bt.platform, "system", return_value="Windows"):
            for value in (None, "elevated", "mxc --extra", 1):
                with self.subTest(value=value), self.assertRaises(bt.Refused):
                    bt.app_server_argv({"windows_backend": value}, self.root / "cli")
            with self.assertRaises(bt.Refused):
                bt.app_server_argv({}, self.root / "cli")
            expected = [str(self.root / "cli"), "-c", 'windows.sandbox="mxc"', "app-server"]
            self.assertEqual(bt.app_server_argv({"windows_backend": "mxc"}, self.root / "cli"), expected)
            client, _, _ = self.make_client({}, backend="mxc", config_windows={"sandbox": "mxc"})
            try:
                self.assertEqual(self.last_spawn, expected)
                self.assertEqual(client.launch_argv, expected)
            finally:
                client.close()
        with mock.patch.object(bt.platform, "system", return_value="Darwin"):
            self.assertEqual(bt.app_server_argv({}, self.root / "cli"), [str(self.root / "cli"), "app-server"])
            with self.assertRaises(bt.Refused):
                bt.app_server_argv({"windows_backend": "mxc"}, self.root / "cli")

    def test_windows_backend_readback_refuses_unknown_or_conflict(self):
        base = {"model_provider": None, "model_providers": {}}
        for windows in (None, {}, {"sandbox": "elevated"}, {"sandbox": None}, {"sandbox": "mxc --extra"}):
            with self.subTest(windows=windows), self.assertRaises(bt.Refused):
                bt.provider_projection({"config": {**base, "windows": windows}}, backend="mxc")
        result = bt.provider_projection({"config": {**base, "windows": {"sandbox": "mxc"}}}, backend="mxc")
        self.assertEqual(result["windows_sandbox"], "mxc")

    def test_windows_wrong_effective_config_refuses_without_fallback(self):
        with mock.patch.object(bt.platform, "system", return_value="Windows"):
            with self.assertRaises(bt.Refused):
                self.make_client({}, backend="mxc", config_windows={"sandbox": "elevated"})
        self.assertEqual(self.last_spawn, [str(self.root / "cli"), "-c", 'windows.sandbox="mxc"', "app-server"])
        self.assertTrue(self.last_ctx["startup_cleanup"]["client_cleanup_complete"])

    def test_real_client_thread_start_readonly_and_response_binding(self):
        response = {
            "modelProvider": "openai",
            "model": "test-model",
            "approvalPolicy": "on-request",
            "sandbox": {"type": "readOnly"},
            "thread": {"id": "T"},
        }
        client, requests, _ = self.make_client(response)
        try:
            self.assertEqual(client.start(), "T")
            params = requests[-1][1]
            self.assertEqual(params["sandbox"], "read-only")
            self.assertEqual(params["approvalPolicy"], "on-request")
            self.assertNotIn("windows.sandbox", str(params))
            for key, value in [
                ("approvalPolicy", "never"),
                ("sandbox", {"type": "workspaceWrite"}),
                ("model", "wrong"),
            ]:
                bad = dict(response)
                bad[key] = value
                client.rpc = lambda *a: bad
                with self.assertRaises(bt.Refused):
                    client.start()
        finally:
            client.close()

    def test_real_client_refuses_oversized_rpc_journal(self):
        client, _, _ = self.make_client({})
        try:
            client.rows = [{}] * 10000
            with self.assertRaises(bt.Refused):
                client.receive(0)
        finally:
            client.close()

    def test_constructor_spawn_cleanup_receipt_preserved(self):
        class SpawnError(Exception):
            pass

        exc = SpawnError()
        exc.cleanup = {"cleanup_complete": True, "owned_process_exited": True}
        with self.assertRaises(SpawnError):
            self.make_client({}, spawn_error=exc)
        self.assertTrue(self.last_ctx["startup_cleanup"]["cleanup_complete"])
        (self.root / "rpc.jsonl").unlink()
        with self.assertRaises(RuntimeError):
            self.make_client({}, spawn_error=RuntimeError())
        self.assertFalse(self.last_ctx["startup_cleanup"]["cleanup_complete"])

    def test_trust_review_family_and_unknown_status(self):
        src = self.root / "cache" / "0.17.3" / "hooks/hooks.json"
        base = src.parents[2]
        for field, value in [
            ("trustStatus", "modified"),
            ("trustStatus", "untrusted"),
            ("enabled", False),
        ]:
            data = orig.inv(src)
            data["data"][0]["hooks"][0][field] = value
            with self.assertRaises(bt.Pending):
                bt.product_inventory(u, data, base, [src])
        data = orig.inv(src)
        data["data"][0]["hooks"][0]["trustStatus"] = "unknown"
        with self.assertRaises(bt.Refused):
            bt.product_inventory(u, data, base, [src])
        data = orig.inv(src)
        data["data"][0]["hooks"][0]["trustStatus"] = "modified"
        data["data"][0]["hooks"][1]["eventName"] = data["data"][0]["hooks"][0][
            "eventName"
        ]
        with self.assertRaises(Exception) as cm:
            bt.product_inventory(u, data, base, [src])
        self.assertNotIsInstance(cm.exception, bt.Pending)
        self.assertEqual(len(bt.product_inventory(u, orig.inv(src), base, [src])), 9)

    def make_zip(self, path, name, content):
        with zipfile.ZipFile(path, "w") as z:
            z.writestr(name, content)

    def test_commit_distribution_and_old_zip_are_independently_bound(self):
        repo = self.root / "repo"
        repo.mkdir()
        target = self.root / "target"
        target.mkdir()
        old = self.root / "old"
        old.mkdir()
        newzip = self.root / "new.zip"
        oldzip = self.root / "old.zip"
        self.make_zip(newzip, "a", b"new")
        self.make_zip(oldzip, "a", b"old")

        def digest(b):
            return __import__("hashlib").sha256(b).hexdigest()

        sets = {
            repo: {"a": digest(b"new")},
            target: {"a": digest(b"new")},
            old: {"a": digest(b"old")},
        }
        art = types.SimpleNamespace(
            distribution_manifest=lambda p: sets[p], compare_artifact=lambda *a: None
        )
        scan = types.SimpleNamespace(source_files=lambda p: sets[p])
        host = types.SimpleNamespace(runtime=lambda p: "runtime")
        pin = {"zip_sha256": bt.sha(oldzip), "runtime_sha256": "runtime"}
        with mock.patch.dict(bt.OLD_RELEASES, {"0.17.3": pin}):
            bt.bind_artifact_subject(
                scan, art, host, repo, target, newzip, old, oldzip, "0.17.3"
            )
            sets[repo] = {"a": digest(b"other")}
            with self.assertRaises(bt.Refused):
                bt.bind_artifact_subject(
                    scan, art, host, repo, target, newzip, old, oldzip, "0.17.3"
                )
            sets[repo] = sets[target]
            self.make_zip(oldzip, "a", b"altered")
            sets[old] = {"a": digest(b"altered")}
            with self.assertRaises(bt.Refused):
                bt.bind_artifact_subject(
                    scan, art, host, repo, target, newzip, old, oldzip, "0.17.3"
                )

    def test_complete_preflight_mock_has_no_model_or_mutation(self):
        repo = self.root / "repo"
        home = self.root / "home"
        workspace = repo
        artifact = self.root / "artifact"
        old_artifact = self.root / "old-artifact"
        for path in (repo, home, artifact, old_artifact):
            path.mkdir()
        data = home / "data"
        data.mkdir()
        tool = repo / "tools/validation/daily_upgrade.py"
        tool.parent.mkdir(parents=True)
        tool.write_text("tool")
        producer = repo / "tools/validation/native_between_turns_acceptance.py"
        producer.write_text("producer fixture")
        cli = self.root / "codex"
        cli.write_text("cli")
        read = workspace / "README.md"
        read.write_text("public")
        oldroot = home / "plugins/cache/codex-context-guard/context-guard/0.17.3"
        (oldroot / "hooks").mkdir(parents=True)
        (oldroot / "hooks/hooks.json").write_text("old hooks")
        (old_artifact / "hooks").mkdir()
        (old_artifact / "hooks/hooks.json").write_text("old hooks")
        (artifact / ".codex-plugin").mkdir()
        (artifact / ".codex-plugin/plugin.json").write_text('{"version":"0.18.0"}')
        newzip = self.root / "new.zip"
        oldzip = self.root / "old.zip"
        self.make_zip(newzip, "new", b"new")
        self.make_zip(oldzip, "old", b"old")

        def digest(b):
            return __import__("hashlib").sha256(b).hexdigest()

        newfiles = {"new": digest(b"new")}
        oldfiles = {"old": digest(b"old")}
        art = types.SimpleNamespace(
            distribution_manifest=lambda p: oldfiles if p == old_artifact else newfiles,
            compare_artifact=lambda *a: None,
        )
        host = types.SimpleNamespace(
            runtime=lambda p: "a" * 64 if p in (old_artifact, oldroot) else "b" * 64
        )
        maint = self.root / "maintained.json"
        maint.write_text(
            json.dumps(
                {
                    "schema": "cg-daily-upgrade-plan/v2",
                    "transition_strategy": "between-turns",
                    "target_version": "0.18.0",
                    "artifact_dir": str(artifact),
                    "cli": str(cli),
                }
            )
        )
        daily = types.SimpleNamespace(
            _same_path=orig.product_daily._same_path,
            _daily_home=lambda: home,
            _load_plan=lambda p: {
                "mode": "between-turns",
                "old_artifact_dir": str(old_artifact),
            },
            _verify_between_turns_compatibility=lambda p, v: {
                "verdict": "compatible",
                "old_version": "0.17.3",
                "installed_slot": str(oldroot),
            },
            _helper_identities=lambda: {},
        )
        plan = {
            "schema": bt.PLAN,
            "transition_strategy": "between-turns",
            "declared_pause": True,
            "read_file_safe_for_model": True,
            "old_version": "0.17.3",
            "target_version": "0.18.0",
            "commit": "a" * 40,
            "tool_sha256": bt.sha(tool),
            "cli_sha256": bt.sha(cli),
            "zip_sha256": bt.sha(newzip),
            "runtime_sha256": "b" * 64,
            "old_runtime_sha256": "a" * 64,
            "maintained_plan_sha256": bt.sha(maint),
            "native_read_sha256": bt.sha(read),
            "repo": str(repo),
            "codex_home": str(home),
            "workspace": str(workspace),
            "data_root": str(data),
            "cli": str(cli),
            "maintained_tool": str(tool),
            "maintained_plan": str(maint),
            "zip": str(newzip),
            "artifact": str(artifact),
            "old_zip": str(oldzip),
            "read_file": str(read),
            "old_source_sha256": bt.sha(oldroot / "hooks/hooks.json"),
            "expected_cli_version": "codex-cli 0.169.0",
            "expected_model": "model",
            "witness_mode": "unknown",
            "_native_plan_sha256": "c" * 64,
        }
        if bt.platform.system() == "Windows":
            plan["windows_backend"] = "mxc"
        called = []
        selected_version = ["0.17.3"]

        def command(argv, **kwargs):
            called.append(argv)
            if argv[0] == "git":
                stdout = "a" * 40 + "\n" if "rev-parse" in argv else ""
                return types.SimpleNamespace(returncode=0, stdout=stdout)
            if argv[-1] == "--version":
                return types.SimpleNamespace(
                    returncode=0, stdout=b"codex-cli 0.169.0\n"
                )
            data = {
                "installed": [
                    {
                        "pluginId": bt.ENTRY,
                        "version": selected_version[0],
                        "installed": True,
                        "enabled": True,
                        "source": {"source": "local", "path": str(artifact)},
                        "marketplaceSource": {
                            "sourceType": "local",
                            "source": str(artifact),
                        },
                    }
                ]
            }
            return types.SimpleNamespace(returncode=0, stdout=json.dumps(data).encode())

        pin = {"zip_sha256": bt.sha(oldzip), "runtime_sha256": "a" * 64}

        def read(ctx, argv, timeout=30):
            return command(argv).stdout

        def scan(path):
            return oldfiles if path in (old_artifact, oldroot) else newfiles

        def private_fixture_directory(path):
            # This preflight fixture models ownership only inside its own
            # temporary tree. Native Windows DACL controls are separate.
            bt.require(Path(path).resolve().is_relative_to(self.root),
                       "private directory fixture escaped its temporary tree")

        with (
            mock.patch.object(u, "_private_directory", side_effect=private_fixture_directory),
            mock.patch.object(bt, "producer_path", return_value=producer),
            mock.patch.object(bt, "import_product", return_value=(u, host, art, daily)),
            mock.patch.object(bt.subprocess, "run", side_effect=command),
            mock.patch.object(bt, "owned_read", side_effect=read),
            mock.patch.object(u, "source_files", side_effect=scan),
            mock.patch.dict(bt.OLD_RELEASES, {"0.17.3": pin}),
        ):
            ctx = bt.preflight(plan, self.root / "result")
            self.assertEqual(ctx["files"], newfiles)
            self.assertFalse((self.root / "result").exists())
            load_plan = daily._load_plan
            try:
                for bad_dir in (str(self.root / "other"), str(self.root / "other" / ".." / "home" / "data")):
                    daily._load_plan = lambda p: {**load_plan(p), "data_dir": bad_dir}
                    with self.assertRaisesRegex(bt.Refused, "policy data root differs"):
                        bt.preflight(plan, self.root / "result")
            finally:
                daily._load_plan = load_plan
            with mock.patch.object(bt.platform, "system", return_value="Windows"):
                missing = dict(plan)
                missing.pop("windows_backend", None)
                bad_plans = (missing, {**plan, "windows_backend": None},
                             {**plan, "windows_backend": "elevated"},
                             {**plan, "windows_backend": "mxc", "extra_cli_flags": ["--other"]})
                for bad_plan in bad_plans:
                    with self.subTest(plan=bad_plan), self.assertRaises(bt.Refused):
                        bt.preflight(bad_plan, self.root / "result")
                winctx = bt.preflight({**plan, "windows_backend": "mxc"}, self.root / "result")
                self.assertEqual(winctx["app_server_argv"], [str(cli), "-c", 'windows.sandbox="mxc"', "app-server"])
                self.assertEqual(winctx["windows_backend"], "mxc")
                self.assertFalse((self.root / "result").exists())
            with (
                mock.patch.object(
                    bt, "producer_path", return_value=self.root / "foreign.py"
                ),
                self.assertRaises(bt.Refused),
            ):
                bt.preflight(plan, self.root / "result")
            self.assertTrue(
                all("app-server" not in argv and "add" not in argv for argv in called)
            )
            bad = {**plan, "unexpected_field": True}
            with self.assertRaises(bt.Refused):
                bt.preflight(bad, self.root / "result")

            # Post-result reconstruction accepts a genuinely absent old slot.
            import shutil

            shutil.rmtree(oldroot)
            newroot = home / "plugins/cache/codex-context-guard/context-guard/0.18.0"
            newroot.mkdir()
            result_dir = self.root / "result"
            result_dir.mkdir(mode=0o700)
            (result_dir / "maintained").mkdir(mode=0o700)
            selected_version[0] = "0.18.0"
            recovered = bt.preflight(plan, result_dir, after=True)
            self.assertFalse(recovered["old_root"].exists())
            self.assertTrue(recovered["new_root"].is_dir())
            self.assertTrue(
                all("app-server" not in argv and "add" not in argv for argv in called)
            )

    def test_official_readback_bom_is_supported_and_duplicates_refused(self):
        row = {
            "pluginId": bt.ENTRY,
            "version": "0.17.3",
            "installed": True,
            "enabled": True,
        }
        ctx = {"cli": self.root / "codex", "workspace": self.root, "home": self.root}
        result = types.SimpleNamespace(
            returncode=0,
            stdout=b"\xef\xbb\xbf" + json.dumps({"installed": [row]}).encode(),
        )
        with mock.patch.object(
            bt, "owned_read", side_effect=lambda *args: result.stdout
        ):
            self.assertEqual(bt.official_list(ctx, "0.17.3")["version"], "0.17.3")
        result.stdout = b'{"installed":[],"installed":[]}'
        with (
            mock.patch.object(
                bt, "owned_read", side_effect=lambda *args: result.stdout
            ),
            self.assertRaises(bt.Refused),
        ):
            bt.official_list(ctx, "0.17.3")
        row["version"] = "0.18.0"
        result.stdout = json.dumps({"installed": [row]}).encode()
        with (
            mock.patch.object(
                bt, "owned_read", side_effect=lambda *args: result.stdout
            ),
            self.assertRaises(bt.Refused),
        ):
            bt.official_list(ctx, "0.17.3")

    def test_verify_result_entry_read_only(self):
        import contextlib

        plan = self.root / "plan.json"
        plan.write_text("{}")
        out = self.root / "result"
        out.mkdir()
        result = out / "result.json"
        sidecar = out / "independent-verification.json"
        ctx = {"output": out}
        for status, has_sidecar in (
            ("passed_cli_native", False),
            ("provisional_cli_native", True),
        ):
            result.write_text(json.dumps({"status": status}))
            if sidecar.exists():
                sidecar.unlink()
            if has_sidecar:
                sidecar.write_text(
                    json.dumps(
                        {
                            "schema": "cg-between-turn-independent/v1",
                            "status": "passed",
                            "result_sha256": bt.sha(result),
                        }
                    )
                )
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "producer",
                        "--plan",
                        str(plan),
                        "--output",
                        str(out),
                        "--verify-result",
                    ],
                ),
                mock.patch.object(bt, "preflight", return_value=ctx) as preflight,
                mock.patch.object(bt, "independent_verify") as verify,
                mock.patch.object(
                    bt, "run", side_effect=AssertionError("run forbidden")
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(bt.main(), 0)
                self.assertTrue(preflight.call_args.kwargs["after"])
                verify.assert_called_once()
        sidecar.write_text(
            json.dumps(
                {
                    "schema": "cg-between-turn-independent/v1",
                    "status": "passed",
                    "result_sha256": "0" * 64,
                }
            )
        )
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "producer",
                    "--plan",
                    str(plan),
                    "--output",
                    str(out),
                    "--verify-result",
                ],
            ),
            mock.patch.object(bt, "preflight", return_value=ctx),
            self.assertRaises(bt.Refused),
        ):
            bt.main()

    def test_acceptance_items_and_scope_cannot_disappear(self):
        base = {
            "state": {"requirements": [{"id": "R001", "status": "pending"}]},
            "scope": {"current": ["R001", "A001"], "ancestor": []},
            "acceptance_pending": [
                {"id": "A001", "text_sha256": "a" * 64, "work_unit_id": "W1"}
            ],
        }
        bt.validate_projected_scope(base, copy.deepcopy(base))
        for change in ("missing", "hash", "scope"):
            bad = copy.deepcopy(base)
            if change == "missing":
                bad["acceptance_pending"] = []
            elif change == "hash":
                bad["acceptance_pending"][0]["text_sha256"] = "b" * 64
            else:
                bad["scope"]["current"] = ["R001"]
            with self.assertRaises(bt.Refused):
                bt.validate_projected_scope(base, bad)

    def test_nonfinite_json_and_rpc_byte_limit_are_refused(self):
        for raw in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.assertRaises(bt.Refused):
                bt.strict_json_bytes(raw)
        path = self.root / "journal.jsonl"
        path.write_bytes(b'{"x":NaN}\n')
        with self.assertRaises(bt.Refused):
            bt.strict_read_jsonl(path, 10)
        journal = bt.BoundedJournal(self.root / "rpc.jsonl", limit=4)
        try:
            journal.write("abcd")
            with self.assertRaises(bt.Refused):
                journal.write("x")
        finally:
            journal.close()

    def test_linked_output_parent_and_lstat_denial_refused(self):
        real = self.root / "real"
        real.mkdir()
        alias = self.root / "alias"
        if self.make_symlink(alias, real, directory=True):
            with self.assertRaises(bt.Refused):
                bt.check_path(alias / "result")
        original = Path.lstat

        def denied(path):
            if path == real:
                raise PermissionError("denied")
            return original(path)

        with (
            mock.patch.object(Path, "lstat", denied),
            self.assertRaises(PermissionError),
        ):
            bt.check_path(real / "result")

    def test_full_tree_extra_ignored_symlink_hardlink_refused(self):
        import shutil

        from scripts import artifact_identity as art

        target = self.root / "artifact"
        (target / ".codex-plugin").mkdir(parents=True)
        (target / ".codex-plugin/plugin.json").write_text(
            json.dumps({"name": "context-guard", "version": "0.17.3"}))
        (target / "README.md").write_text("Public synthetic release fixture\n")
        files = art.distribution_files(target)
        (target / ".codex-plugin/distribution-manifest.json").write_text(json.dumps({
            "schema": "cg-distribution-manifest/v1", "file_count": len(files), "files": files}))
        expected = art.distribution_manifest(target)
        self.assertEqual(u.source_files(target), expected)
        extra = target / "unexpected.txt"
        extra.write_text("extra")
        with self.assertRaises(Exception):
            art.compare_artifact(target, target)
        extra.unlink()
        ignored = target / "__pycache__"
        ignored.mkdir()
        (ignored / "extra.pyc").write_bytes(b"x")
        with self.assertRaises(Exception):
            art.compare_artifact(target, target)
        shutil.rmtree(ignored)
        alias = target / "symlink"
        if self.make_symlink(alias, target / "README.md"):
            with self.assertRaises(Exception):
                u.source_files(target)
            alias.unlink()
        os.link(target / "README.md", self.root / "outside-hardlink")
        with self.assertRaises(Exception):
            u.source_files(target)

    def test_owned_read_rejects_unknown_cleanup_without_raw_stderr(self):
        ctx = {"home": self.root, "repo": self.root}
        with (
            mock.patch.object(
                bt,
                "owned_execute",
                return_value=(
                    {
                        "exit_code": None,
                        "cleanup": {
                            "owned_process_exited": True,
                            "owned_tree_no_running_members": False,
                        },
                    },
                    b"private",
                ),
            ),
            self.assertRaises(bt.Refused),
        ):
            bt.owned_read(ctx, ["cli"])

    def test_activity_unknown_or_active_waits_until_clear_but_cleanup_unknown_stops(
        self,
    ):
        for states in (
            [{"status": "unknown"}, {"status": "active"}, {"status": "clear"}],
            [{"status": "active"}, {"status": "clear"}],
        ):
            observations = []
            calls = []

            def observe(*args, **kwargs):
                calls.append(kwargs)
                return states.pop(0)

            ctx = {
                "activity_wait": 30,
                "daily": types.SimpleNamespace(
                    _inventory_host_tools=lambda *a: {},
                    _scrubbed_env=lambda: {},
                    _runtime_activity=observe,
                ),
                "home": self.root,
                "compatibility": {"verdict": "compatible"},
            }
            result = bt.wait_for_activity(
                ctx, "0.17.3", observations, clock=lambda: 0, sleeper=lambda _: None
            )
            self.assertEqual(result["status"], "clear")
            self.assertEqual(observations[-1]["status"], "clear")
            self.assertTrue(
                all(
                    call["compatibility"] == ctx["compatibility"]
                    and call["allow_absent"] is False
                    for call in calls
                )
            )
        called = []
        ctx["daily"]._runtime_activity = lambda *a, **k: {
            "status": "unknown",
            "query_cleanup": "unconfirmed",
        }
        observations = []
        with self.assertRaises(bt.Pending):
            bt.wait_for_activity(
                ctx,
                "0.17.3",
                observations,
                clock=lambda: 0,
                sleeper=lambda _: called.append(True),
            )
        self.assertEqual(called, [])
        self.assertEqual(observations[0]["query_cleanup"], "unconfirmed")

    def test_activity_pending_does_not_authorize_repeat_after_add_intent(self):
        fixture = orig.Tests()
        fixture.setUp()
        try:
            fixture.write_receipts()
            ctx = fixture.ctx
            journal = ctx["tool_output"] / "apply-events.jsonl"
            events = [json.loads(row) for row in journal.read_text().splitlines()]
            journal.write_text(json.dumps(events[0]) + "\n")
            self.assertTrue(bt.no_add_attempted(ctx))
            with journal.open("a") as f:
                f.write(json.dumps(next(e for e in events if e.get("event") == "intent" and e.get("stage") == "plugin_add")) + "\n")
            self.assertFalse(bt.no_add_attempted(ctx))
            events[0]["prepared_sha256"] = "0" * 64
            journal.write_text(json.dumps(events[0]) + "\n")
            self.assertFalse(bt.no_add_attempted(ctx))
        finally:
            fixture.tearDown()

    def test_official_provider_projection_refuses_custom_endpoint_and_catalog(self):
        expected = {"config": {"model_provider": "openai", "model_providers": {}}}
        self.assertEqual(
            bt.provider_projection(expected)["endpoint_policy"], "official_default"
        )
        for field, value in (
            ("openai_base_url", "http://localhost:1234/v1"),
            ("chatgpt_base_url", "http://localhost:1234"),
            ("model_catalog_json", "/tmp/model.json"),
            ("model_providers", {"openai": {"base_url": "http://localhost"}}),
        ):
            bad = copy.deepcopy(expected)
            bad["config"][field] = value
            with self.assertRaises(bt.Refused):
                bt.provider_projection(bad)
        with mock.patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "hidden",
                "CODEX_OPENAI_BASE_URL": "hidden",
                "CODEX_CHATGPT_BASE_URL": "hidden",
                "CHATGPT_BASE_URL": "hidden",
                "HOME": "/keep",
            },
            clear=True,
        ):
            env = bt.filtered_env(self.root)
            self.assertEqual(env["HOME"], "/keep")
            self.assertTrue(
                all(
                    name not in env
                    for name in (
                        "OPENAI_BASE_URL",
                        "CODEX_OPENAI_BASE_URL",
                        "CODEX_CHATGPT_BASE_URL",
                        "CHATGPT_BASE_URL",
                    )
                )
            )

    def test_environment_credentials_and_unsafe_paths(self):
        with mock.patch.dict(
            os.environ,
            {"OPENAI_API_KEY": "hidden", "EXAMPLE_TOKEN": "hidden", "HOME": "/keep"},
            clear=True,
        ):
            env = bt.filtered_env(self.root)
            self.assertNotIn("OPENAI_API_KEY", env)
            self.assertNotIn("EXAMPLE_TOKEN", env)
            self.assertEqual(env["HOME"], "/keep")
        for name in (".env", "auth.json", "credential.json"):
            path = self.root / name
            path.write_text("secret")
            with self.assertRaises(bt.Refused):
                bt.regular(path)
        good = self.root / "public"
        good.write_text("x")
        link = self.root / "link"
        if self.make_symlink(link, good):
            with self.assertRaises(bt.Refused):
                bt.regular(link)
        hard = self.root / "hard"
        os.link(good, hard)
        with self.assertRaises(bt.Refused):
            bt.regular(good)
        bad = self.root / "duplicate.json"
        bad.write_text('{"x":1,"x":2}')
        with self.assertRaises(bt.Refused):
            bt.strict_read_json(bad)

    def test_linked_ancestor_is_refused(self):
        real = self.root / "real"
        real.mkdir()
        (real / "safe.txt").write_text("x")
        link = self.root / "linked"
        if self.make_symlink(link, real, directory=True):
            with self.assertRaises(bt.Refused):
                bt.regular(link / "safe.txt")

    def test_plan_and_helper_drift_before_apply_never_call_resume(self):
        for drift in ("plan", "helper"):
            fixture = orig.Tests()
            fixture.setUp()
            try:
                if drift == "plan":
                    (fixture.p / "plan").write_text("changed")
                else:
                    fixture.daily._helper_identities = lambda: {"helper": "changed"}
                result = fixture.execute()
                self.assertEqual(result["stage"], "apply")
                self.assertEqual(result["status"], "failed")
                self.assertEqual(fixture.calls, [])
            finally:
                fixture.tearDown()

    def test_controlled_thread_item_requires_current_turn_identity(self):
        for method in ("item/started", "item/completed"):
            for turn_id in (None, "other-turn"):
                params = {
                    "threadId": "controlled",
                    "item": {"id": "x", "type": "commandExecution"},
                }
                if turn_id is not None:
                    params["turnId"] = turn_id
                row = {
                    "direction": "response",
                    "message": {"method": method, "params": params},
                }
                with self.assertRaises(bt.Refused):
                    bt.audit_turn_tools(
                        [row], "controlled", "expected", allow_read=False
                    )
        benign = {
            "direction": "response",
            "message": {
                "method": "item/started",
                "params": {
                    "threadId": "controlled",
                    "turnId": "expected",
                    "item": {"type": "agentMessage"},
                },
            },
        }
        bt.audit_turn_tools([benign], "controlled", "expected", allow_read=False)
        other = {
            "direction": "response",
            "message": {
                "method": "item/started",
                "params": {
                    "threadId": "unrelated",
                    "item": {"type": "commandExecution"},
                },
            },
        }
        bt.audit_turn_tools([other], "controlled", "expected", allow_read=False)

    def test_false_exit_code_is_not_success(self):
        ctx = {
            "workspace": self.root,
            "u": types.SimpleNamespace(_paired=lambda *a, **k: [{}]),
        }

        def event(method, run=None, item=None):
            return {
                "direction": "response",
                "message": {
                    "method": method,
                    "params": {
                        "threadId": "T",
                        "turnId": "R",
                        "run": run or {},
                        "item": item or {},
                    },
                },
            }

        pre = event("hook/completed", run={"eventName": "preToolUse"})
        post = event("hook/started", run={"eventName": "postToolUse"})
        item = {
            "id": "I",
            "type": "commandExecution",
            "command": "cat README.md",
            "cwd": str(self.root),
        }
        rows = [
            pre,
            event("item/started", item=item),
            event("item/completed", item={**item, "exitCode": False}),
            post,
        ]
        with self.assertRaises(bt.Refused):
            bt.verify_read_tool(ctx, rows, {}, "T", "R", "cat README.md")

    @unittest.skipIf(os.name == "nt", "POSIX mode check; Windows DACL refusal has its own regression")
    def test_public_output_parent_rejected(self):
        parent = self.root / "public"
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)
        with self.assertRaises(Exception):
            u._new_outside(parent / "result", [])
        parent.chmod(0o700)
        u._new_outside(parent / "result", [])

    def test_state_integrity_validation_is_mandatory(self):
        root = self.root / "data"
        path = root / "sessions-v2" / "T" / "state.json"
        path.parent.mkdir(parents=True)
        path.write_text("{}")
        fake = types.SimpleNamespace(
            _state_at_bound=lambda *a: (root, {"session": {"id": "T"}}, bt.sha(path)),
            sha=bt.sha,
            _old_scope=mock.Mock(side_effect=ValueError("invalid guard integrity")),
        )
        old = self.root / "old"
        old.mkdir()
        ctx = {
            "u": fake,
            "home": self.root,
            "data_root": root,
            "old_root": old,
            "new_root": self.root / "new",
        }
        with self.assertRaises(ValueError):
            bt.snapshot(ctx, "T")
        fake._old_scope.assert_called_once()
        fake._old_scope = mock.Mock(return_value={"current": []})
        self.assertEqual(bt.snapshot(ctx, "T")["scope"], {"current": []})
        fake.sha = lambda p: "f" * 64
        with self.assertRaises(bt.Refused):
            bt.snapshot(ctx, "T")

    def test_owned_command_timeout_and_uncertain_cleanup_never_pass(self):
        class Process:
            returncode = None

            def __init__(self):
                self.stdout = io.BytesIO()
                self.stderr = io.BytesIO()

            def poll(self):
                return None

        class Owner:
            def __init__(self, cleanup):
                self.process = Process()
                self.cleanup = cleanup

            def close(self, timeout):
                return self.cleanup

        def run(cleanup):
            owner = Owner(cleanup)
            native = types.SimpleNamespace(
                load_process_tree=lambda: types.SimpleNamespace(
                    OwnedProcess=types.SimpleNamespace(spawn=lambda *a, **k: owner)
                )
            )
            ctx = {
                "u": types.SimpleNamespace(native=native),
                "repo": self.root,
                "home": self.root,
            }
            return bt.owned_execute(ctx, ["fake"], timeout=0.001)[0]

        for cleanup in (
            {
                "cleanup_complete": True,
                "owned_process_exited": True,
                "owned_tree_no_running_members": True,
                "process_group_cleanup_error": None,
                "job_close_confirmed": True,
                "job_assignment_confirmed": True,
            },
            {"cleanup_complete": False},
        ):
            fact = run(cleanup)
            self.assertIsNone(fact["exit_code"])
            self.assertEqual(fact["failure"], "TimeoutExpired")
            self.assertEqual(fact["cleanup"], cleanup)

    def test_modified_and_disabled_recover_with_verify_only(self):
        for field, value in (("trustStatus", "modified"), ("enabled", False)):
            fixture = orig.Tests()
            fixture.setUp()
            try:
                fixture.resume_status = "hook_trust_pending"
                source = fixture.new / "hooks/hooks.json"
                pending = orig.inv(source)
                pending["data"][0]["hooks"][0][field] = value
                replies = [pending, orig.inv(source)]

                def inventory(sources):
                    fixture.client.calls.append("inventory")
                    return bt.product_inventory(
                        u, replies.pop(0), fixture.new.parent, [source]
                    )

                fixture.client.inventory_for = inventory
                result = fixture.execute()
                self.assertEqual(result["status"], "passed_cli_native")
                self.assertEqual(fixture.calls, ["--resume", "--verify"])
            finally:
                fixture.tearDown()

    def test_timeout_before_or_after_recorded_add_keeps_evidence_and_never_retries(
        self,
    ):
        for observed_add in (False, True):
            fixture = orig.Tests()
            fixture.setUp()
            try:
                calls = []

                def timed_out(ctx, action, verify_output=None):
                    calls.append(action)
                    ctx["tool_output"].mkdir()
                    (ctx["tool_output"] / "apply-events.jsonl").write_text(
                        json.dumps(
                            {
                                "event": "fact",
                                "stage": "plugin_add" if observed_add else "pre_add",
                            }
                        )
                        + "\n"
                    )
                    return {
                        "exit_code": None,
                        "failure": "TimeoutExpired",
                        "cleanup": {
                            "owned_process_exited": True,
                            "owned_tree_no_running_members": True,
                            "process_group_cleanup_error": None,
                            "cleanup_complete": True,
                            "job_close_confirmed": True,
                            "job_assignment_confirmed": True,
                        },
                    }

                result = fixture.execute(apply=timed_out)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(calls, ["--resume"])
                saved = json.loads(
                    (fixture.ctx["output"] / "maintained-call.json").read_text()
                )
                self.assertEqual(saved["failure"], "TimeoutExpired")
                self.assertTrue(
                    (fixture.ctx["tool_output"] / "apply-events.jsonl").exists()
                )
            finally:
                fixture.tearDown()

    def test_windows_private_directory_dacl_must_pass(self):
        class Driver:
            def private_parent(self, path):
                return False

        with (
            mock.patch.object(u.os, "name", "nt"),
            mock.patch.object(u.shutil, "which", return_value="powershell.exe"),
            mock.patch.object(u.scheduler, "_Windows", Driver),
        ):
            with self.assertRaises(Exception):
                u._private_directory(self.root)

    def test_product_activity_signature_matches_keyword_bound_call(self):
        import inspect

        from tools.validation import daily_upgrade as daily

        bound = inspect.signature(daily._runtime_activity).bind(
            self.root,
            "0.17.3",
            {},
            compatibility={"verdict": "compatible"},
            allow_absent=False,
        )
        self.assertFalse(bound.arguments["allow_absent"])

    def test_cleanup_shape_is_platform_aware(self):
        posix = {
            "owned_process_exited": True,
            "owned_tree_no_running_members": True,
            "process_group_cleanup_error": None,
        }
        with mock.patch.object(bt.platform, "system", return_value="Darwin"):
            self.assertTrue(bt.cleanup_confirmed(posix))
        with mock.patch.object(bt.platform, "system", return_value="Windows"):
            self.assertFalse(bt.cleanup_confirmed(posix))
            missing_error = {
                k: v for k, v in posix.items() if k != "process_group_cleanup_error"
            }
            self.assertFalse(
                bt.cleanup_confirmed(
                    {
                        **missing_error,
                        "cleanup_complete": True,
                        "job_close_confirmed": True,
                        "job_assignment_confirmed": True,
                    }
                )
            )
            self.assertFalse(
                bt.cleanup_confirmed(
                    {
                        **posix,
                        "cleanup_complete": True,
                        "job_close_confirmed": True,
                        "job_assignment_confirmed": False,
                    }
                )
            )
            self.assertTrue(
                bt.cleanup_confirmed(
                    {
                        **posix,
                        "cleanup_complete": True,
                        "job_close_confirmed": True,
                        "job_assignment_confirmed": True,
                    }
                )
            )

    def test_duplicate_and_truncated_jsonl_refused(self):
        path = self.root / "journal.jsonl"
        for raw in ('{"event":"begin","event":"fact"}\n', '{"event":"begin"}'):
            path.write_text(raw)
            with self.assertRaises(bt.Refused):
                bt.strict_read_jsonl(path, 20)

    def test_fact_before_intent_and_extra_begin_are_refused(self):
        fixture = orig.Tests()
        fixture.setUp()
        try:
            fixture.write_receipts()
            path = fixture.ctx["tool_output"] / "apply-events.jsonl"
            events = [json.loads(x) for x in path.read_text().splitlines()]
            intent = next(i for i, e in enumerate(events) if e.get("event") == "intent" and e.get("stage") == "plugin_add")
            swapped = copy.deepcopy(events)
            swapped[intent], swapped[intent + 1] = swapped[intent + 1], swapped[intent]
            for bad in (swapped, [events[0], events[0], *events[1:]]):
                path.write_text("".join(json.dumps(x) + "\n" for x in bad))
                apply_path = fixture.ctx["tool_output"] / "apply.json"
                applied = json.loads(apply_path.read_text())
                applied["commands"] = [e for e in bad if e.get("event") == "fact"]
                apply_path.write_text(json.dumps(applied))
                with self.assertRaises(bt.Refused):
                    bt.verify_maintained(
                        fixture.ctx,
                        fixture.plan,
                        fixture.ctx["tool_output"] / "verify.json",
                        "passed",
                    )
        finally:
            fixture.tearDown()

    def test_exact_single_successful_add_is_required_for_entire_receipt_family(self):
        for scenario in (
            "note_only",
            "failed_fact",
            "duplicate_pair",
            "wrong_argv",
            "missing_fact_status",
            "boolean_exit",
            "valid_pass",
            "valid_pending",
        ):
            fixture = orig.Tests()
            fixture.setUp()
            try:
                fixture.resume_status = (
                    "hook_trust_pending" if scenario == "valid_pending" else "passed"
                )
                fixture.write_receipts()
                out = fixture.ctx["tool_output"]
                journal = out / "apply-events.jsonl"
                rows = [json.loads(line) for line in journal.read_text().splitlines()]
                intent = next(i for i, e in enumerate(rows) if e.get("event") == "intent" and e.get("stage") == "plugin_add")
                fact = intent + 1
                if scenario == "note_only":
                    rows[intent:fact + 1] = [{"event": "note", "stage": "plugin_add", "message": "already current"}]
                elif scenario == "failed_fact":
                    rows[fact]["exit_code"] = 1
                elif scenario == "duplicate_pair":
                    rows[fact + 1:fact + 1] = copy.deepcopy(rows[intent:fact + 1])
                elif scenario == "wrong_argv":
                    rows[intent]["argv"][-1] = "wrong"
                    rows[fact]["argv"][-1] = "wrong"
                elif scenario == "missing_fact_status":
                    rows[fact].pop("status")
                elif scenario == "boolean_exit":
                    rows[fact]["exit_code"] = False
                journal.write_text("".join(json.dumps(row) + "\n" for row in rows))
                applied = out / "apply.json"
                doc = json.loads(applied.read_text())
                doc["commands"] = [r for r in rows if r.get("event") == "fact"]
                applied.write_text(json.dumps(doc))
                if scenario in ("valid_pass", "valid_pending"):
                    result = bt.verify_maintained(
                        fixture.ctx,
                        fixture.plan,
                        out / "verify.json",
                        fixture.resume_status,
                    )
                    self.assertEqual(result["journal_add_count"], 1)
                else:
                    with self.assertRaises(bt.Refused, msg=scenario):
                        bt.verify_maintained(
                            fixture.ctx,
                            fixture.plan,
                            out / "verify.json",
                            fixture.resume_status,
                        )
            finally:
                fixture.tearDown()

    def test_target_preexisting_at_boundary_refused_before_resume(self):
        fixture = orig.Tests()
        fixture.setUp()
        try:
            fixture.new.mkdir()
            result = fixture.execute()
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["stage"], "apply")
            self.assertIn("target cache appeared", result["reason"])
            self.assertEqual(fixture.calls, [])
        finally:
            fixture.tearDown()

    def test_real_read_fact_family_and_tampering(self):
        cases = ("valid", "valid_refused_gap", "valid_retry_before_add", "preflight_command", "preflight_stage", "preflight_order",
                 "preflight_status", "preflight_exit", "preflight_missing", "preflight_wrong_source", "preflight_missing_source",
                 "preflight_missing_market", "preflight_alias_source", "preflight_relative_source", "preflight_missing_old", "preflight_target_version", "policy_missing", "policy_interpreter",
                 "policy_script", "policy_data", "policy_verb", "policy_extra", "policy_status", "policy_exit",
                 "policy_late", "policy_duplicate", "read_inside_intent", "extra_mutation", "gap_registered",
                 "gap_nonempty", "gap_wrong_status", "apply_read_failed", "version_drift", "mutation_cwd", "valid_summary")
        for scenario in cases:
            fixture = orig.Tests()
            fixture.setUp()
            try:
                fixture.normalized["data_dir"] = str(fixture.ctx["data_root"])
                fixture.write_receipts()
                out = fixture.ctx["tool_output"]
                path = out / "apply-events.jsonl"
                original = [json.loads(x) for x in path.read_text().splitlines()]
                states = [e for e in original if e.get("stage") == "apply_state"]
                preflight = [e for e in original if e.get("stage") == "preflight"]
                policy = next(e for e in original if e.get("stage") == "policy_readback")
                pi = next(e for e in original if e.get("stage") == "plugin_add" and e["event"] == "intent")
                pf = next(e for e in original if e.get("stage") == "plugin_add" and e["event"] == "fact")
                cli = str(fixture.ctx["cli"])
                def mutation(stage, argv):
                    return [{"event": "intent", "stage": stage, "argv": argv},
                            {"event": "fact", "stage": stage, "argv": argv, "cwd": str(fixture.repo),
                             "status": "completed", "exit_code": 0, "stderr_nonempty": False, "observation": None}]
                remove = mutation("marketplace_remove", [cli, "plugin", "marketplace", "remove", "codex-context-guard"])
                add = mutation("marketplace_add", [cli, "plugin", "marketplace", "add", str(fixture.ctx["artifact"])])
                gap = copy.deepcopy(states[:3])
                gap[1]["observation"] = {"marketplaces": []}
                if scenario in ("valid_refused_gap", "gap_registered", "gap_nonempty", "gap_wrong_status"):
                    gap[2].update(status="refused_empty_readback", exit_code=1, observation={"installed": []})
                if scenario == "gap_registered":
                    gap[1]["observation"] = {"marketplaces": [{"name": "codex-context-guard"}]}
                if scenario == "gap_nonempty":
                    gap[2]["observation"] = {"installed": [{"name": "x"}]}
                if scenario == "gap_wrong_status":
                    gap[2]["status"] = "unknown"
                rows = [original[0], *copy.deepcopy(states[:3]), *remove, *gap, *add,
                        *copy.deepcopy(states[:3]), *copy.deepcopy(preflight), copy.deepcopy(policy),
                        copy.deepcopy(pi), copy.deepcopy(pf), *copy.deepcopy(states[3:]), original[-1]]
                pre = next(i for i, e in enumerate(rows) if e.get("stage") == "preflight")
                pol = next(i for i, e in enumerate(rows) if e.get("stage") == "policy_readback")
                intent = next(i for i, e in enumerate(rows) if e.get("stage") == "plugin_add" and e["event"] == "intent")
                if scenario == "valid_retry_before_add":
                    retry = [*copy.deepcopy(states[:3]),
                             {"event": "note", "stage": "marketplace_remove", "message": "already at target"},
                             {"event": "note", "stage": "marketplace_add", "message": "already registered"},
                             *copy.deepcopy(preflight), copy.deepcopy(policy)]
                    rows[intent:intent] = retry
                if scenario == "preflight_command":
                    rows[pre]["argv"] = [cli, "plugin", "remove", bt.ENTRY]
                if scenario == "preflight_stage":
                    rows[pre]["stage"] = "apply_state"
                if scenario == "preflight_order":
                    rows[pre], rows[pre + 1] = rows[pre + 1], rows[pre]
                if scenario == "preflight_status":
                    rows[pre]["status"] = "failed"
                if scenario == "preflight_exit":
                    rows[pre]["exit_code"] = 1
                if scenario == "preflight_missing":
                    rows.pop(pre)
                if scenario == "preflight_wrong_source":
                    rows[pre + 1]["observation"]["marketplaces"][0]["root"] = str(fixture.p / "third")
                if scenario == "preflight_alias_source":
                    rows[pre + 1]["observation"]["marketplaces"][0]["root"] = str(fixture.p / "other" / ".." / "artifact")
                if scenario == "preflight_relative_source":
                    rows[pre + 1]["observation"]["marketplaces"][0]["root"] = "artifact"
                if scenario == "preflight_missing_source":
                    del rows[pre + 1]["observation"]["marketplaces"][0]["root"]
                if scenario == "preflight_missing_market":
                    rows[pre + 1]["observation"]["marketplaces"] = []
                if scenario == "preflight_missing_old":
                    rows[pre + 2]["observation"]["installed"] = []
                if scenario == "preflight_target_version":
                    rows[pre + 2]["observation"]["installed"][0]["version"] = "0.18.0"
                if scenario == "policy_missing":
                    rows.pop(pol)
                if scenario == "policy_interpreter":
                    rows[pol]["argv"][0] = "other-python"
                if scenario == "policy_script":
                    rows[pol]["argv"][3] = str(fixture.new / "scripts/context_guard.py")
                if scenario == "policy_data":
                    rows[pol]["argv"][6] += "-other"
                if scenario == "policy_verb":
                    rows[pol]["argv"][-1] = "set"
                if scenario == "policy_extra":
                    rows[pol]["argv"].append("--extra")
                if scenario == "policy_status":
                    rows[pol]["status"] = "failed"
                if scenario == "policy_exit":
                    rows[pol]["exit_code"] = 1
                if scenario == "policy_late":
                    rows.insert(intent + 2, rows.pop(pol))
                if scenario == "policy_duplicate":
                    rows.insert(pol, copy.deepcopy(rows[pol]))
                if scenario == "read_inside_intent":
                    rows.insert(intent + 1, copy.deepcopy(states[0]))
                if scenario == "extra_mutation":
                    rows.insert(intent, {"event": "intent", "stage": "plugin_remove", "argv": [cli, "plugin", "remove", bt.ENTRY]})
                if scenario == "apply_read_failed":
                    rows[1]["exit_code"] = 1
                if scenario == "version_drift":
                    rows[pre]["observation"]["version"] = "codex-cli 0.1.0"
                if scenario == "mutation_cwd":
                    rows[intent + 1]["cwd"] = str(fixture.root if hasattr(fixture, "root") else fixture.p / "other")
                if scenario == "valid_summary":
                    rows[intent + 1].update(summary_parse_failed=True, stdout_sha256="f" * 64, stdout_bytes=0)
                path.write_text("".join(json.dumps(e) + "\n" for e in rows))
                apply_path = out / "apply.json"
                applied = json.loads(apply_path.read_text())
                applied["commands"] = [e for e in rows if e.get("event") == "fact"]
                apply_path.write_text(json.dumps(applied))
                if scenario in ("valid", "valid_refused_gap", "valid_retry_before_add", "valid_summary"):
                    self.assertEqual(bt.verify_maintained(fixture.ctx, fixture.plan, out / "verify.json", "passed")["journal_add_count"], 1)
                else:
                    with self.assertRaises(bt.Refused, msg=scenario):
                        bt.verify_maintained(fixture.ctx, fixture.plan, out / "verify.json", "passed")
            finally:
                fixture.tearDown()

    def test_independent_consumer_positive_and_evidence_tamper(self):
        fixture = orig.Tests()
        fixture.setUp()
        try:
            fixture.write_receipts()
            ctx = fixture.ctx
            out = ctx["output"]
            plan = fixture.plan
            ctx["u"] = u
            ctx["native_plan_path"] = fixture.p / "plan"
            plan["_native_plan_sha256"] = bt.sha(ctx["native_plan_path"])
            plan["expected_model"] = "test-model"
            plan["expected_cli_version"] = "codex-cli 0.169.0"
            oldsrc = str(ctx["old_root"] / "hooks/hooks.json")
            newsrc = str(ctx["new_root"] / "hooks/hooks.json")
            oldhooks = orig.inv(oldsrc)["data"][0]["hooks"]
            newhooks = orig.inv(newsrc)["data"][0]["hooks"]
            before = {
                "root": "data",
                "sha256": "1" * 64,
                "state": u._state_projection(orig.state("t1")),
                "acceptance_pending": [],
                "scope": {"current": ["R001"], "ancestor": []},
                "turns": ["t1"],
            }
            after = {
                "root": "data",
                "sha256": "2" * 64,
                "state": u._state_projection(orig.state("t2")),
                "acceptance_pending": [],
                "scope": {"current": ["R001"], "ancestor": []},
                "turns": ["t1", "t2"],
            }

            def put(name, data):
                (out / name).write_text(json.dumps(data))

            put("server.json", {"pid": 42, "argv": ctx["app_server_argv"],
                                "windows_backend": ctx["windows_backend"], "os_backend_observation": "unobserved"})
            put("old-trust.json", {"hooks": oldhooks})
            put("new-trust.json", {"hooks": newhooks})
            put("old-state.json", before)
            put("old-after.json", after)
            put(
                "between-turn-boundary.json",
                {
                    "user_declared_pause": True,
                    "server_pid": 42,
                    "thread": "old",
                    "runtime_activity_samples": [{"status": "clear"}],
                },
            )
            put(
                "official-readback.json",
                {
                    "pluginId": bt.ENTRY,
                    "version": "0.18.0",
                    "installed": True,
                    "enabled": True,
                    "target_source_verified": True,
                },
            )
            put(
                "maintained-call.json",
                {
                    "argv": [
                        sys.executable,
                        str(ctx["tool"]),
                        "--plan",
                        str(ctx["maintained_plan"]),
                        "--output",
                        str(ctx["tool_output"]),
                        "--resume",
                    ],
                    "exit_code": 0,
                    "start_ns": 25,
                    "end_ns": 35,
                    "cleanup": {
                        "cleanup_complete": True,
                        "owned_process_exited": True,
                        "owned_tree_no_running_members": True,
                        "process_group_cleanup_error": None,
                        "job_close_confirmed": True,
                        "job_assignment_confirmed": True,
                    },
                },
            )
            rows = []

            def req(id, method, params):
                rows.append(
                    {
                        "direction": "request",
                        "message": {"id": id, "method": method, "params": params},
                    }
                )

            def response(id, result):
                rows.append(
                    {"direction": "response", "message": {"id": id, "result": result}}
                )

            def event(method, params):
                rows.append(
                    {
                        "direction": "response",
                        "message": {"method": method, "params": params},
                    }
                )

            def marker(name, t):
                rows.append(
                    {"direction": "local", "event": name, "pid": 42, "monotonic_ns": t}
                )

            def config(id):
                req(
                    id,
                    "config/read",
                    {"cwd": str(ctx["workspace"]), "includeLayers": False},
                )
                value = {
                        "model_provider": None,
                        "endpoint_policy": "official_default",
                        "custom_catalog": False,
                    }
                if ctx["windows_backend"] == "mxc":
                    value["windows_sandbox"] = "mxc"
                response(id, value)

            def start(id, thread):
                req(
                    id,
                    "thread/start",
                    {"sandbox": "read-only", "approvalPolicy": "on-request"},
                )
                response(
                    id,
                    {
                        "thread": {"id": thread},
                        "sandbox": {"type": "readOnly"},
                        "approvalPolicy": "on-request",
                        "modelProvider": "openai",
                        "model": "test-model",
                    },
                )

            def pair(thread, turn, name, source):
                run = {
                    "id": thread + turn + name,
                    "eventName": name,
                    "sourcePath": source,
                    "source": "plugin",
                    "handlerType": "command",
                    "displayOrder": 0,
                    "executionMode": "sync",
                }
                event("hook/started", {"threadId": thread, "turnId": turn, "run": run})
                event(
                    "hook/completed",
                    {
                        "threadId": thread,
                        "turnId": turn,
                        "run": {**run, "status": "completed", "durationMs": 1},
                    },
                )

            def turnend(thread, turn):
                event(
                    "turn/completed",
                    {"threadId": thread, "turn": {"id": turn, "status": "completed"}},
                )

            config(101)
            start(1, "old")
            req(11, "turn/start", {"threadId": "old"})
            response(11, {"turn": {"id": "t1"}})
            pair("old", "t1", "userPromptSubmit", oldsrc)
            pair("old", "t1", "stop", oldsrc)
            turnend("old", "t1")
            marker("old_turn_complete", 10)
            marker("apply_started", 20)
            marker("apply_finished", 40)
            config(102)
            req(12, "turn/start", {"threadId": "old"})
            response(12, {"turn": {"id": "t2"}})
            pair("old", "t2", "userPromptSubmit", oldsrc)
            pair("old", "t2", "stop", oldsrc)
            turnend("old", "t2")
            marker("old_continuation_complete", 50)
            config(103)
            start(2, "fresh")
            req(13, "turn/start", {"threadId": "fresh"})
            response(13, {"turn": {"id": "t3"}})
            pair("fresh", "t3", "userPromptSubmit", newsrc)
            pair("fresh", "t3", "preToolUse", newsrc)
            item = {
                "id": "read",
                "type": "commandExecution",
                "cwd": str(ctx["workspace"]),
                "command": bt.read_command("README.md"),
            }
            event("item/started", {"threadId": "fresh", "turnId": "t3", "item": item})
            event(
                "item/completed",
                {"threadId": "fresh", "turnId": "t3", "item": {**item, "exitCode": 0}},
            )
            pair("fresh", "t3", "postToolUse", newsrc)
            pair("fresh", "t3", "stop", newsrc)
            turnend("fresh", "t3")
            marker("fresh_turn_complete", 60)
            (out / "rpc.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
            names = [
                "server.json",
                "old-trust.json",
                "old-state.json",
                "old-after.json",
                "new-trust.json",
                "rpc.jsonl",
                "between-turn-boundary.json",
                "maintained-call.json",
                "official-readback.json",
                "maintained/prepare.json",
                "maintained/apply.json",
                "maintained/verify.json",
                "maintained/apply-events.jsonl",
            ]
            subject = {
                k: plan[k]
                for k in (
                    "commit",
                    "old_version",
                    "target_version",
                    "zip_sha256",
                    "runtime_sha256",
                    "tool_sha256",
                    "cli_sha256",
                )
            }
            subject.update(
                native_plan_sha256=plan["_native_plan_sha256"],
                producer_sha256=bt.sha(Path(bt.__file__).resolve()),
                helper_closure_sha256=u.digest(ctx["daily"]._helper_identities()),
                app_server_argv=ctx["app_server_argv"],
                windows_backend=ctx["windows_backend"],
            )
            result = {
                "schema": bt.REPORT,
                "status": "provisional_cli_native",
                "declared_pause": True,
                "login_budget": 0,
                "platform": bt.platform.system(),
                "evidence_scope": "owned app-server real-model CLI threads",
                "gui": "unobserved",
                "cli_version": plan["expected_cli_version"],
                "model": plan["expected_model"],
                "subject": subject,
                "evidence": {name: bt.sha(out / name) for name in names},
                "cleanup": {
                    "owned_process_exited": True,
                    "owned_tree_no_running_members": True,
                    "process_group_cleanup_error": None,
                    "cleanup_complete": True,
                    "job_close_confirmed": True,
                    "job_assignment_confirmed": True,
                    "client_cleanup_complete": True,
                    "reader_started": True,
                    "reader_stopped": True,
                    "reader_failure": None,
                    "io_closed": {"stdin": True, "stdout": True, "log": True, "err": True},
                },
                "gates": {
                    "old_model": {
                        "status": "passed",
                        "thread": "old",
                        "old_turn": "t1",
                        "new_turn": "t2",
                        "pid": 42,
                    },
                    "fresh_model": {
                        "status": "passed",
                        "thread": "fresh",
                        "turn": "t3",
                        "pid": 42,
                    },
                    "new_trust": {"status": "passed", "count": 9},
                    "maintained_apply": {"status": "passed"},
                },
            }
            put("result.json", result)
            with (
                mock.patch.object(
                    bt, "snapshot", return_value={"root": "data", "sha256": "2" * 64}
                ),
                mock.patch.object(
                    bt, "final_subject_readback", return_value={"installed": True}
                ),
            ):
                self.assertTrue(bt.independent_verify(ctx, plan, out))
                server_path, rpc_path = out / "server.json", out / "rpc.jsonl"
                original_server, original_rpc = server_path.read_bytes(), rpc_path.read_bytes()
                original_argv = ctx["app_server_argv"]
                original_backend = ctx["windows_backend"]
                original_plan_backend = plan.get("windows_backend")
                win_argv = [str(ctx["cli"]), "-c", 'windows.sandbox="mxc"', "app-server"]
                win_rows = copy.deepcopy(rows)
                for row in win_rows:
                    response = row.get("message", {}).get("result", {})
                    if "endpoint_policy" in response:
                        response["windows_sandbox"] = "mxc"
                    item = row.get("message", {}).get("params", {}).get("item", {})
                    if item.get("type") == "commandExecution":
                        item["command"] = "Get-Content -LiteralPath README.md"
                win_result = copy.deepcopy(result)
                win_result["platform"] = "Windows"
                win_result["subject"]["app_server_argv"] = win_argv
                win_result["subject"]["windows_backend"] = "mxc"
                ctx["app_server_argv"] = win_argv
                ctx["windows_backend"] = "mxc"
                plan["windows_backend"] = "mxc"
                put("server.json", {"pid": 42, "argv": win_argv, "windows_backend": "mxc", "os_backend_observation": "unobserved"})
                rpc_path.write_text("".join(json.dumps(r) + "\n" for r in win_rows))
                for name in ("server.json", "rpc.jsonl"):
                    win_result["evidence"][name] = bt.sha(out / name)
                put("result.json", win_result)
                with (mock.patch.object(bt.platform, "system", return_value="Windows"),
                      mock.patch.object(u, "_source_key", side_effect=lambda raw, sources: raw if raw in sources else None),
                      mock.patch.object(bt, "reported_path_matches", side_effect=lambda raw, trusted: raw == str(trusted))):
                    self.assertTrue(bt.independent_verify(ctx, plan, out))
                    for wrong_server in (
                        {"pid": 42, "argv": win_argv + ["--extra"], "windows_backend": "mxc", "os_backend_observation": "unobserved"},
                        {"pid": 42, "argv": win_argv, "windows_backend": "elevated", "os_backend_observation": "unobserved"},
                        {"pid": 42, "argv": win_argv, "windows_backend": "mxc", "os_backend_observation": "observed"},
                    ):
                        put("server.json", wrong_server)
                        win_result["evidence"]["server.json"] = bt.sha(server_path)
                        put("result.json", win_result)
                        with self.assertRaises(bt.Refused):
                            bt.independent_verify(ctx, plan, out)
                    put("server.json", {"pid": 42, "argv": win_argv, "windows_backend": "mxc", "os_backend_observation": "unobserved"})
                    win_result["evidence"]["server.json"] = bt.sha(server_path)
                    for wrong in (None, "elevated", "mxc --extra"):
                        changed = copy.deepcopy(win_rows)
                        response = next(r["message"]["result"] for r in changed if "windows_sandbox" in r.get("message", {}).get("result", {}))
                        response["windows_sandbox"] = wrong
                        rpc_path.write_text("".join(json.dumps(r) + "\n" for r in changed))
                        win_result["evidence"]["rpc.jsonl"] = bt.sha(rpc_path)
                        put("result.json", win_result)
                        with self.assertRaises(bt.Refused):
                            bt.independent_verify(ctx, plan, out)
                server_path.write_bytes(original_server)
                rpc_path.write_bytes(original_rpc)
                ctx["app_server_argv"] = original_argv
                ctx["windows_backend"] = original_backend
                if original_plan_backend is None:
                    del plan["windows_backend"]
                else:
                    plan["windows_backend"] = original_plan_backend
                put("result.json", result)
                for key, value in (
                    ("cleanup", None),
                    ("declared_pause", False),
                    ("login_budget", 1),
                    ("gui", "passed"),
                    ("schema", "wrong"),
                ):
                    tampered = copy.deepcopy(result)
                    tampered[key] = value
                    put("result.json", tampered)
                    with self.assertRaises(bt.Refused):
                        bt.independent_verify(ctx, plan, out)
                for failure in ('queue_full', 'ValueError'):
                    tampered = copy.deepcopy(result)
                    tampered['cleanup']['reader_failure'] = failure
                    put('result.json', tampered)
                    with self.assertRaises(bt.Refused):
                        bt.independent_verify(ctx, plan, out)
                tampered = copy.deepcopy(result)
                del tampered["subject"]["windows_backend"]
                put("result.json", tampered)
                with self.assertRaises(bt.Refused):
                    bt.independent_verify(ctx, plan, out)
                put("result.json", result)
                with mock.patch.object(ctx["daily"], "_helper_identities", return_value={"helper": "changed"}):
                    with self.assertRaises(bt.Refused):
                        bt.independent_verify(ctx, plan, out)
                put("result.json", result)
                # A default selector still requires both actual thread starts
                # to report the official provider and the selected model.
                rpc_path = out / "rpc.jsonl"
                original_rpc = rpc_path.read_bytes()
                for thread in ("old", "fresh"):
                    for field, value in (("modelProvider", "other"), ("model", "other")):
                        altered = copy.deepcopy(rows)
                        row = next(r for r in altered if r.get("message", {}).get("result", {}).get("thread", {}).get("id") == thread)
                        row["message"]["result"][field] = value
                        rpc_path.write_text("".join(json.dumps(r) + "\n" for r in altered))
                        result["evidence"]["rpc.jsonl"] = bt.sha(rpc_path)
                        put("result.json", result)
                        with self.assertRaises(bt.Refused):
                            bt.independent_verify(ctx, plan, out)
                rpc_path.write_bytes(original_rpc)
                result["evidence"]["rpc.jsonl"] = bt.sha(rpc_path)
                put("result.json", result)
                for name in (
                    "rpc.jsonl",
                    "old-after.json",
                    "maintained/verify.json",
                    "maintained/apply-events.jsonl",
                ):
                    path = out / name
                    original = path.read_bytes()
                    path.write_bytes(original + b" ")
                    with self.assertRaises(bt.Refused):
                        bt.independent_verify(ctx, plan, out)
                    path.write_bytes(original)
                # Re-hashing corrupted evidence cannot make semantic drift pass.
                rpc_path = out / "rpc.jsonl"
                original_rpc = rpc_path.read_bytes()
                altered = copy.deepcopy(rows)
                next(
                    r
                    for r in altered
                    if r.get("message", {}).get("method") == "thread/start"
                )["message"]["params"]["sandbox"] = "workspace-write"
                rpc_path.write_text("".join(json.dumps(r) + "\n" for r in altered))
                result["evidence"]["rpc.jsonl"] = bt.sha(rpc_path)
                put("result.json", result)
                with self.assertRaises(bt.Refused):
                    bt.independent_verify(ctx, plan, out)
                rpc_path.write_bytes(original_rpc)
                result["evidence"]["rpc.jsonl"] = bt.sha(rpc_path)
                put("result.json", result)
                after_path = out / "old-after.json"
                original_after = after_path.read_bytes()
                changed = copy.deepcopy(after)
                changed["state"]["requirements"] = []
                after_path.write_text(json.dumps(changed))
                result["evidence"]["old-after.json"] = bt.sha(after_path)
                put("result.json", result)
                with self.assertRaises(Exception):
                    bt.independent_verify(ctx, plan, out)
                after_path.write_bytes(original_after)
                result["evidence"]["old-after.json"] = bt.sha(after_path)
                put("result.json", result)
                official_path = out / "official-readback.json"
                official_original = official_path.read_bytes()
                altered_official = json.loads(official_original)
                altered_official["version"] = "0.99.0"
                official_path.write_text(json.dumps(altered_official))
                result["evidence"]["official-readback.json"] = bt.sha(official_path)
                put("result.json", result)
                with self.assertRaises(bt.Refused):
                    bt.independent_verify(ctx, plan, out)
                official_path.write_bytes(official_original)
                result["evidence"]["official-readback.json"] = bt.sha(official_path)
                put("result.json", result)
                # A controlled-thread item with missing or unknown turnId must
                # remain a refusal even if its journal digest is recomputed.
                for missing_or_unknown in (None, "unknown-turn"):
                    changed_rows = copy.deepcopy(rows)
                    params = {
                        "threadId": "old",
                        "item": {"id": "unexpected", "type": "commandExecution"},
                    }
                    if missing_or_unknown is not None:
                        params["turnId"] = missing_or_unknown
                    rogue = {
                        "direction": "response",
                        "message": {"method": "item/started", "params": params},
                    }
                    position = next(
                        i
                        for i, r in enumerate(changed_rows)
                        if r.get("event") == "old_turn_complete"
                    )
                    changed_rows.insert(position, rogue)
                    rpc_path.write_text(
                        "".join(json.dumps(r) + "\n" for r in changed_rows)
                    )
                    result["evidence"]["rpc.jsonl"] = bt.sha(rpc_path)
                    put("result.json", result)
                    with self.assertRaises(bt.Refused):
                        bt.independent_verify(ctx, plan, out)
                rpc_path.write_bytes(original_rpc)
                result["evidence"]["rpc.jsonl"] = bt.sha(rpc_path)
                put("result.json", result)
                nativeplan = ctx["native_plan_path"]
                original = nativeplan.read_bytes()
                nativeplan.write_bytes(b"changed")
                with self.assertRaises(bt.Refused):
                    bt.independent_verify(ctx, plan, out)
                nativeplan.write_bytes(original)
                result["gates"]["fresh_model"]["pid"] = 43
                put("result.json", result)
                with self.assertRaises(bt.Refused):
                    bt.independent_verify(ctx, plan, out)
        finally:
            fixture.tearDown()


if __name__ == "__main__":
    unittest.main()
