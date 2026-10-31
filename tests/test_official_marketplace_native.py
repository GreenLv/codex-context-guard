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
from pathlib import Path, PureWindowsPath
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


class OfficialWindowsPathIdentityTests(unittest.TestCase):
    """Windows syntax simulations only; the fixture performs no Windows I/O."""

    def setUp(self):
        self.observed = []
        self.linked = False
        owner = self

        class TrustedWindowsPath(PureWindowsPath):
            def is_symlink(self):
                owner.observed.append(str(self))
                return owner.linked

        self.source = TrustedWindowsPath(r"C:\Isolated Run\source")
        self.home = TrustedWindowsPath(r"C:\Isolated Run\home")
        self.cache = self.home / "plugins/cache/codex-context-guard-v016/context-guard"
        self.installed = self.cache / "0.16.0"
        self.added = dict(pluginId=native.OFFICIAL_PLUGIN, name="context-guard",
                          marketplaceName="codex-context-guard-v016", version="0.16.0",
                          installedPath=str(self.installed))
        self.entry = {key: self.added[key] for key in
                      ("pluginId", "name", "marketplaceName", "version")}
        self.entry.update(installed=True, enabled=True,
                          source={"source": "local", "path": str(self.source)},
                          marketplaceSource={"sourceType": "local", "source": str(self.source)})

    def identity(self):
        with (mock.patch.object(native.platform, "system", return_value="Windows"),
              mock.patch.object(native, "Path",
                                side_effect=AssertionError("untrusted JSON reached Path"))):
            return native.official_identity({"installed": [self.entry]}, self.added,
                                            self.source, self.home, "0.16.0")

    def test_source_spellings_keep_both_exact_local_record_shapes(self):
        variants = [str(self.source), "c:/isolated run/source", r"C:\ISOLATED RUN/source",
                    r"\\?\C:\Isolated Run\source", "//?/c:/isolated run/source/"]
        for record, field in (("source", "path"), ("marketplaceSource", "source")):
            for value in variants:
                with self.subTest(record=record, value=value):
                    self.entry[record][field] = value
                    self.observed.clear()
                    self.assertEqual(self.identity(), self.installed)
                    self.assertEqual(self.observed, [str(self.installed)])
            self.entry[record][field] = str(self.source)

    def test_cache_spellings_return_only_trusted_version_or_local_path(self):
        for name in ("0.16.0", "local"):
            expected = self.cache / name
            for value in (str(expected), str(expected).upper().replace("\\", "/"),
                          "\\\\?\\" + str(expected), "//?/" + str(expected).replace("\\", "/")):
                with self.subTest(name=name, value=value):
                    self.added["installedPath"] = value
                    self.observed.clear()
                    self.assertEqual(self.identity(), expected)
                    self.assertEqual(self.observed, [str(expected)])

    def test_unsafe_or_different_source_domains_are_rejected_before_filesystem_use(self):
        bad = [None, True, {}, [], "", "source", r"C:source", r"\Isolated Run\source",
               r"\\server\share\source", r"\\?\UNC\server\share\source",
               r"\\.\C:\Isolated Run\source", r"\\?\GLOBALROOT\Device\source",
               r"\??\C:\Isolated Run\source", r"D:\Isolated Run\source",
               r"C:\Isolated Run\other", r"C:\Isolated Run\.\source",
               r"C:\Isolated Run\other\..\source", r"C:\Isolated Run\source:stream",
               r"C:\Isolated Run\NUL", r"C:\Isolated Run\COM1.txt",
               r"C:\Isolated Run\source.", "C:/Isolated Run/source ",
               "C:/Isolated Run/source\0", "C:/Isolated Run/sour?ce"]
        for record, field in (("source", "path"), ("marketplaceSource", "source")):
            for value in bad:
                with self.subTest(record=record, value=value):
                    self.entry[record][field] = value
                    self.observed.clear()
                    with self.assertRaises(native.NativeRunError):
                        self.identity()
                    self.assertEqual(self.observed, [])
            self.entry[record][field] = str(self.source)

    def test_extra_fields_wrong_tags_and_wrong_objects_keep_original_oracle(self):
        for record, tag in (("source", "source"), ("marketplaceSource", "sourceType")):
            original = dict(self.entry[record])
            for value in (None, [], {**original, "extra": True},
                          {**original, tag: "git"}, {tag: "local"}):
                with self.subTest(record=record, value=value):
                    self.entry[record] = value
                    self.observed.clear()
                    with self.assertRaises(native.NativeRunError):
                        self.identity()
                    self.assertEqual(self.observed, [])
            self.entry[record] = original
        # CLI envelope metadata retains its existing additive contract.
        self.entry["metadata"] = {"synthetic": True}
        self.added["metadata"] = {"synthetic": True}
        self.assertEqual(self.identity(), self.installed)

    def test_untrusted_installed_path_is_never_dereferenced(self):
        good = str(self.installed)
        bad = [None, {}, [], "", "0.16.0", r"C:relative", r"\home\0.16.0",
               r"\\server\share\0.16.0", "\\\\?\\UNC\\server\\share\\0.16.0",
               "\\\\.\\" + good, "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1",
               good.replace("home", "another-home"), str(self.cache), str(self.cache / "0.15.1"),
               good + r"\child", good + ":stream", good + ".", good + " ",
               str(self.cache) + r"\other\..\0.16.0", str(self.cache) + r"\.\0.16.0",
               str(self.cache / "CON"), str(self.cache / "LPT1.txt")]
        for value in bad:
            with self.subTest(value=value):
                self.added["installedPath"] = value
                self.observed.clear()
                with self.assertRaises(native.NativeRunError):
                    self.identity()
                self.assertEqual(self.observed, [])

    def test_trusted_cache_symlink_still_refused(self):
        self.linked = True
        self.added["installedPath"] = "\\\\?\\" + str(self.installed)
        with self.assertRaises(native.NativeRunError):
            self.identity()
        self.assertEqual(self.observed, [str(self.installed)])

    def test_flow_passes_trusted_cache_to_unchanged_parity_and_reparse_checks(self):
        self.added["installedPath"] = "\\\\?\\" + str(self.installed).upper()
        result = subprocess.CompletedProcess([], 0, json.dumps({"installed": [self.entry]}), "")
        for reject in (False, True):
            with self.subTest(reject=reject):
                with (mock.patch.object(native.platform, "system", return_value="Windows"),
                      mock.patch.object(native, "Path", side_effect=AssertionError("JSON reached Path")),
                      mock.patch.object(native, "run", return_value=result),
                      mock.patch.object(native, "exact_artifact_parity",
                                        side_effect=native.NativeRunError("synthetic reparse rejection")
                                        if reject else None) as parity):
                    if reject:
                        with self.assertRaisesRegex(native.NativeRunError, "reparse rejection"):
                            native.documented_official_flow(self.source, "synthetic-codex", self.home,
                                self.source, {}, {}, "0.16.0", self.added)
                    else:
                        _, installed = native.documented_official_flow(self.source, "synthetic-codex", self.home,
                            self.source, {}, {}, "0.16.0", self.added)
                        self.assertEqual(installed, self.installed)
                    parity.assert_called_once_with(self.installed, {})

    def test_unsafe_trusted_path_domain_cannot_be_used_as_equality_authority(self):
        for value in (r"\\server\share\..\source", r"\\?\UNC\server\share:stream\source",
                      r"C:\CON\source", r"C:\NUL .txt\source", r"C:\COM¹\source",
                      r"C:\source:stream", r"C:\other\..\source"):
            with self.subTest(value=value):
                self.assertFalse(native._official_path_matches(value, value, windows=True))


class OfficialControlledUncIdentityTests(unittest.TestCase):
    """Exact UNC compatibility only; all filesystem operations are synthetic."""

    setUp = OfficialWindowsPathIdentityTests.setUp
    identity = OfficialWindowsPathIdentityTests.identity
    roots = (r"\\server\share\Isolated Run", r"\\?\UNC\server\share\Isolated Run")

    def bind(self, root, name="0.16.0"):
        concrete = type(self.source)
        self.source = concrete(root) / "source"
        self.home = concrete(root) / "home"
        self.cache = self.home / "plugins/cache/codex-context-guard-v016/context-guard"
        self.installed = self.cache / name
        self.added["installedPath"] = str(self.installed)
        self.entry["source"]["path"] = str(self.source)
        self.entry["marketplaceSource"]["source"] = str(self.source)
        self.observed.clear()

    def test_exact_controlled_unc_and_extended_unc_keep_old_acceptance(self):
        for root in self.roots:
            for name in ("0.16.0", "local"):
                with self.subTest(root=root, name=name):
                    self.bind(root, name)
                    self.assertEqual(self.identity(), self.installed)
                    self.assertEqual(self.observed, [str(self.installed)])

    @staticmethod
    def aliases(value):
        # All these are nonliteral or cross-source spellings, even if some
        # could name the same Windows object. No such identity is inferred.
        alternate = (value[8:] if value.startswith("\\\\?\\UNC\\") else value[2:])
        prefix_alias = ("\\\\" + alternate if value.startswith("\\\\?\\UNC\\")
                        else "\\\\?\\UNC\\" + alternate)
        return (value.lower(), value.upper(), value.replace("\\", "/"), prefix_alias,
                value + "\\", value.replace("server", "other-server", 1),
                value.replace("share", "other-share", 1), value + ":stream",
                chr(92).join((value.rpartition(chr(92))[0], "other", "..",
                              value.rpartition(chr(92))[2])))

    def test_unc_source_aliases_or_other_sources_fail_without_path_io(self):
        for root in self.roots:
            for record, field in (("source", "path"), ("marketplaceSource", "source")):
                for index in range(9):
                    self.bind(root)
                    value = self.aliases(str(self.source))[index]
                    with self.subTest(root=root, record=record, value=value):
                        self.entry[record][field] = value
                        with self.assertRaises(native.NativeRunError):
                            self.identity()
                        self.assertEqual(self.observed, [])

    def test_unc_installed_aliases_or_other_caches_fail_without_path_io(self):
        for root in self.roots:
            self.bind(root)
            values = self.aliases(str(self.installed)) + (str(self.cache / "0.15.1"),
                       str(self.installed / "child"), str(self.cache),
                       str(self.installed).replace("home", "other-home", 1))
            for value in values:
                with self.subTest(root=root, value=value):
                    self.added["installedPath"] = value
                    self.observed.clear()
                    with self.assertRaises(native.NativeRunError):
                        self.identity()
                    self.assertEqual(self.observed, [])

    def test_exact_but_unsafe_unc_cannot_be_trusted_authority(self):
        values = [r"\\server", r"\\server" + chr(92), r"\\server\share\..\source",
                  r"\\server\share\.\source", r"\\server\share\source:stream",
                  r"\\server\NUL\source", r"\\server\share\COM1.txt",
                  r"\\.\share\source", r"\\?\GLOBALROOT\Device\source",
                  r"\\?\UNC\server", r"\\?\UNC\server\share\..\source",
                  r"\\?\UNC\server\share:stream\source", r"\\server\share\source.",
                  "\\\\server\\share\\source\0"]
        for value in values:
            with self.subTest(value=value):
                self.assertFalse(native._official_path_matches(value, value, windows=True))

    def test_unc_exact_match_keeps_nested_fields_and_trusted_symlink_checks(self):
        for root in self.roots:
            self.bind(root)
            self.entry["marketplaceSource"]["extra"] = True
            with self.assertRaises(native.NativeRunError):
                self.identity()
            self.assertEqual(self.observed, [])
            self.entry["marketplaceSource"].pop("extra")
            self.linked = True
            with self.assertRaises(native.NativeRunError):
                self.identity()
            self.assertEqual(self.observed, [str(self.installed)])
            self.linked = False


class OfficialPosixPathIdentityTests(unittest.TestCase):
    def test_posix_source_text_contract_and_cache_symlink_rejection_are_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            source, home = Path(directory) / "source", Path(directory) / "home"
            cache = home / "plugins/cache/codex-context-guard-v016/context-guard"
            installed = cache / "0.16.0"
            installed.mkdir(parents=True)
            added = dict(pluginId=native.OFFICIAL_PLUGIN, name="context-guard",
                         marketplaceName="codex-context-guard-v016", version="0.16.0",
                         installedPath=str(installed))
            entry = {key: added[key] for key in ("pluginId", "name", "marketplaceName", "version")}
            entry.update(installed=True, enabled=True, source={"source":"local", "path":str(source)},
                         marketplaceSource={"sourceType":"local", "source":str(source)})
            with mock.patch.object(native.platform, "system", return_value="Darwin"):
                self.assertEqual(native.official_identity({"installed":[entry]}, added, source, home,
                                                          "0.16.0"), installed)
                for value in (str(source).upper(), str(source) + "/", "//?/C:/source"):
                    entry["marketplaceSource"]["source"] = value
                    with self.assertRaises(native.NativeRunError):
                        native.official_identity({"installed":[entry]}, added, source, home, "0.16.0")
                entry["marketplaceSource"]["source"] = str(source)
                with mock.patch.object(Path, "is_symlink", return_value=True):
                    with self.assertRaises(native.NativeRunError):
                        native.official_identity({"installed":[entry]}, added, source, home, "0.16.0")
