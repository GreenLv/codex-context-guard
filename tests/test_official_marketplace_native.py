"""Official workflow controls use only synthetic sources and a fake CLI."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import jsonschema

from scripts import artifact_identity as identity
from tools.validation import native_acceptance as native

ROOT = Path(__file__).resolve().parents[1]


class OfficialMarketplaceNativeTests(unittest.TestCase):
    def exercise(self, failure="none"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            for name, body in {"scripts/core.py": b"synthetic core\n",
                ".codex-plugin/plugin.json": b'{"version":"0.16.0"}\n'}.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
            files = identity.distribution_files(root)
            (root / identity.DISTRIBUTION_MANIFEST_RELATIVE).write_text(json.dumps({
                "schema":"cg-distribution-manifest/v1", "file_count":len(files), "files":files}))
            files = identity.distribution_manifest(root)
            self.commands, self.homes, self.lists = [], [], 0
            state = {}

            def run(subject, *args, env=None):
                self.commands.append(args)
                stdout = ""
                if args[:3] == ("git", "remote", "get-url"):
                    stdout = "https://github.com/example/repo.git"
                elif args[-1:] == ("--version",):
                    stdout = "codex synthetic"
                elif "scripts/build_release_artifact.py" in args:
                    output = Path(args[-1])
                    with zipfile.ZipFile(output, "w") as archive:
                        for name in files:
                            archive.writestr(name, (root / name).read_bytes())
                elif "scripts/smoke_installed.py" in args:
                    if failure == "smoke":
                        raise native.NativeRunError("synthetic smoke failure")
                elif args[1:3] == ("plugin", "marketplace"):
                    state["source"] = Path(args[-1])
                elif args[1:3] == ("plugin", "add"):
                    home = Path(env["CODEX_HOME"])
                    self.homes.append(home)
                    self.assertNotEqual(env["HOME"], env["CODEX_HOME"])
                    self.assertEqual(Path(env["TMPDIR"]).parent, home.parent)
                    self.assertNotIn(home, Path(env["TMPDIR"]).parents)
                    self.assertNotIn("OPENAI_API_KEY", env)
                    cache = home / "plugins/cache/codex-context-guard-v016/context-guard/0.16.0"
                    shutil.copytree(state["source"], cache)
                    (home / "config.toml").write_bytes(b"synthetic-config\n")
                    (home / "plugins/installed_plugins.json").write_bytes(b"synthetic-registry\n")
                    (home / "synthetic-empty").mkdir()
                    state["cache"] = cache
                    state["add"] = {"pluginId":native.OFFICIAL_PLUGIN,"name":"context-guard",
                        "marketplaceName":"codex-context-guard-v016","version":"0.16.0",
                        "installedPath":str(cache)}
                    stdout = json.dumps(state["add"])
                elif args[1:3] == ("plugin", "list"):
                    self.lists += 1
                    entries = []
                    if "add" in state:
                        entry = {key:state["add"][key] for key in
                            ("pluginId", "name", "marketplaceName", "version")}
                        entry.update(installed=True, enabled=True,
                            source={"source":"local","path":str(state["source"])},
                            marketplaceSource={"sourceType":"local","source":str(state["source"])})
                        if failure == "wrong_version":
                            entry["version"] = "0.15.1"
                        elif failure == "wrong_source":
                            entry["marketplaceSource"]["source"] = "/different-synthetic-source"
                        elif failure == "disabled":
                            entry["enabled"] = False
                        entries = [entry, entry] if failure == "duplicate" else [entry]
                    if self.lists == 3:
                        if failure == "drift":
                            (state["cache"] / "scripts/core.py").write_bytes(b"drifted")
                        elif failure == "home_change":
                            (Path(env["CODEX_HOME"]) / "unexpected").write_bytes(b"changed")
                        elif failure == "mode":
                            (Path(env["CODEX_HOME"]) / "config.toml").chmod(0o400)
                        elif failure == "directory_add":
                            (Path(env["CODEX_HOME"]) / "new-empty").mkdir()
                        elif failure == "directory_delete":
                            (Path(env["CODEX_HOME"]) / "synthetic-empty").rmdir()
                        elif failure == "file_delete":
                            (Path(env["CODEX_HOME"]) / "config.toml").unlink()
                        elif failure == "config":
                            (Path(env["CODEX_HOME"]) / "config.toml").write_bytes(b"changed-config")
                        elif failure == "registry":
                            (Path(env["CODEX_HOME"]) / "plugins/installed_plugins.json").write_bytes(b"changed-registry")
                        elif failure == "read_failure":
                            raise native.NativeRunError("synthetic status read failure")
                        elif failure == "same_byte_rewrite":
                            target = Path(env["CODEX_HOME"]) / "config.toml"
                            replacement = target.with_suffix(".tmp")
                            replacement.write_bytes(target.read_bytes())
                            replacement.replace(target)
                        elif failure == "old_object":
                            old = Path(env["CODEX_HOME"]) / "plugins/cache/codex-context-guard/context-guard/0.15.1/synthetic-preservation-control"
                            saved = old.read_bytes()
                            old.unlink()
                            old.write_bytes(saved)
                    stdout = json.dumps({"installed":entries,"available":[]})
                else:
                    raise AssertionError(args)
                return subprocess.CompletedProcess(args, 0, stdout, "")

            explicit_zip = None
            if failure in {"prebuilt", "wrong_zip"}:
                explicit_zip = Path(directory) / "prebuilt.zip"
                with zipfile.ZipFile(explicit_zip, "w") as archive:
                    for name in files:
                        archive.writestr(name, b"drift" if failure == "wrong_zip" and name == "scripts/core.py" else (root / name).read_bytes())
            with mock.patch.object(native, "load_artifacts", return_value=identity), \
                    mock.patch.object(native, "verify_exact_source"), \
                    mock.patch.object(native, "run", side_effect=run), \
                    contextlib.redirect_stderr(io.StringIO()):
                result = native.portable_acceptance(root, "a" * 40, "synthetic-codex", None, release_zip=explicit_zip)
            schema = json.loads((ROOT / "tools/validation/native-acceptance-v2.schema.json").read_text())
            jsonschema.Draft202012Validator(schema).validate(result)
            self.assertTrue(all(not home.exists() for home in self.homes))
            return result

    def test_full_documented_workflow_only_installs_once_and_second_reads(self):
        result = self.exercise()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["gate_profile"], "portable_runtime")
        self.assertEqual(sum(args[1:3] == ("plugin", "add") for args in self.commands), 1)
        self.assertEqual(self.lists, 3)
        gate = next(g for g in result["gates"] if g["id"] == "strict_second_noop")
        self.assertIn("not absence of writes", gate["note"])

    def test_explicit_prebuilt_zip_is_not_rebuilt_and_is_bound(self):
        result = self.exercise("prebuilt")
        self.assertEqual(result["status"], "passed")
        self.assertFalse(any("scripts/build_release_artifact.py" in args for args in self.commands))
        self.assertEqual(result["artifact"]["kind"], "release_zip")
        self.assertEqual(len(result["artifact"]["sha256"]), 64)
        self.assertGreater(result["artifact"]["size_bytes"], 0)
        result = self.exercise("wrong_zip")
        self.assertEqual(result["status"], "failed")
        self.assertFalse(any("plugin" in args for args in self.commands))

    def test_wrong_identity_ambiguity_source_or_state_cannot_pass(self):
        for failure in ("wrong_version", "wrong_source", "disabled", "duplicate", "drift", "home_change", "old_object", "smoke", "mode", "directory_add", "directory_delete", "file_delete", "config", "registry", "read_failure"):
            with self.subTest(failure=failure):
                result = self.exercise(failure)
                self.assertEqual(result["status"], "failed")
                self.assertFalse(any(g["id"] == "old_cache_fixture_object_preservation" and g["status"] == "passed" for g in result["gates"]))

    @unittest.skipIf(os.name == "nt", "Windows replacement mode follows native filesystem semantics")
    def test_same_byte_rewrite_keeps_original_final_state_contract(self):
        result = self.exercise("same_byte_rewrite")
        self.assertEqual(result["status"], "passed")

    @unittest.skipUnless(os.name == "posix", "POSIX detached-directory holder control")
    def test_portable_rejects_detached_holder_with_empty_replacement_home(self):
        snapshot, opener = native.installed_object_snapshot, native.open_snapshot_file
        home_calls, displaced, empty = [], [], []

        def observing(home):
            if home.name != "home":
                return snapshot(home)
            home_calls.append(home)
            if len(home_calls) != 2:
                return snapshot(home)

            def swapping(path, **kwargs):
                if not displaced:
                    holder = home.parent
                    saved = holder.with_name(holder.name + "-regression-displaced")
                    holder.rename(saved)
                    displaced.append(saved)
                    home.mkdir(parents=True)
                return opener(path, **kwargs)

            try:
                with mock.patch.object(native, "open_snapshot_file", side_effect=swapping):
                    return snapshot(home)
            finally:
                empty.append(not any(home.iterdir()))

        try:
            with mock.patch.object(native, "installed_object_snapshot", side_effect=observing):
                result = self.exercise()
            self.assertEqual(empty, [True])
            self.assertEqual(result["status"], "failed")
            self.assertFalse(any(g["id"] == "strict_second_noop" and g["status"] == "passed" for g in result["gates"]))
        finally:
            for saved in displaced:
                shutil.rmtree(saved)

    def test_zero_object_identity_is_not_preservation_evidence(self):
        with mock.patch.object(native, "installed_object_snapshot", return_value={".":("directory", 0o700)}), \
                mock.patch.object(Path, "stat", return_value=types.SimpleNamespace(st_ino=0, st_dev=0)) as observed:
            with self.assertRaisesRegex(native.NativeRunError, "capability unavailable"):
                native.strict_cache_objects(Path("/synthetic"))
        self.assertEqual(observed.call_count, 1)

    def test_parity_rejects_extra_file_even_if_runtime_roots_match(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "public").write_bytes(b"abc")
            (root / "extra").write_bytes(b"private synthetic")
            with self.assertRaisesRegex(native.NativeRunError, "full release-file"):
                native.exact_artifact_parity(root, {"public":hashlib.sha256(b"abc").hexdigest()})
