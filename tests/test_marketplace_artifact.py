"""Synthetic release integrity regressions without Codex or a user HOME."""
from __future__ import annotations

import errno
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scripts import artifact_identity as identity

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_builder", ROOT / "scripts/build_release_artifact.py")
assert spec and spec.loader
# The CLI's script directory supplies its one read-only local dependency.

sys.path.insert(0, str(ROOT / "scripts"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
sys.path.pop(0)


class MarketplaceArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "source"
        for rel, body in {"scripts/core.py": b"print('synthetic')\n",
                          ".codex-plugin/plugin.json": b'{"version":"0.16.0"}\n',
                          "LICENSE": b"fixture\n"}.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        self.seal()

    def seal(self):
        files = identity.distribution_files(self.root)
        (self.root / identity.DISTRIBUTION_MANIFEST_RELATIVE).write_text(json.dumps({
            "schema": "cg-distribution-manifest/v1", "file_count": len(files), "files": files}))

    def test_nonempty_exact_manifest_and_zip_exclude_git_metadata(self):
        (self.root / ".git").mkdir()
        (self.root / ".git/config").write_bytes(b"synthetic-private-metadata")
        output = Path(self.tmp.name) / "release.zip"
        builder.build(self.root, output)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(set(archive.namelist()), set(identity.distribution_manifest(self.root)))
            self.assertFalse(any(".git/" in name or "manage_plugin.py" in name for name in archive.namelist()))
            self.assertEqual(archive.read("scripts/core.py"), b"print('synthetic')\n")

    def test_known_file_set_and_digest_include_marketplace_and_manifest(self):
        market = self.root / ".agents/plugins/marketplace.json"
        market.parent.mkdir(parents=True)
        market.write_bytes(b"abc")
        self.seal()
        files = identity.distribution_manifest(self.root)
        self.assertEqual(set(files), {".agents/plugins/marketplace.json",
            ".codex-plugin/plugin.json", ".codex-plugin/distribution-manifest.json",
            "scripts/core.py", "LICENSE"})
        self.assertEqual(files[".agents/plugins/marketplace.json"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        manifest = self.root / ".codex-plugin/distribution-manifest.json"
        import hashlib
        self.assertEqual(files[".codex-plugin/distribution-manifest.json"],
                         hashlib.sha256(manifest.read_bytes()).hexdigest())
        market.write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "reviewed sha256"):
            identity.distribution_manifest(self.root)

    def test_runtime_ignore_domain_matches_all_path_components(self):
        before = identity.tree_manifest(self.root)
        for component in identity.IGNORED_TREE_NAMES | {"nested.pyc", "nested.pyo"}:
            target = self.root / "scripts" / component / "payload.txt"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"ignored synthetic bytes")
        self.assertEqual(identity.tree_manifest(self.root), before)

    def test_manifest_byte_change_changes_runtime_identity(self):
        before = identity.tree_manifest(self.root)
        manifest = self.root / identity.DISTRIBUTION_MANIFEST_RELATIVE
        manifest.write_bytes(manifest.read_bytes() + b" ")
        after = identity.tree_manifest(self.root)
        self.assertIn(identity.DISTRIBUTION_MANIFEST_RELATIVE, before)
        self.assertNotEqual(before[identity.DISTRIBUTION_MANIFEST_RELATIVE],
                            after[identity.DISTRIBUTION_MANIFEST_RELATIVE])
        self.assertNotEqual(before, after)

    def test_repeat_pack_is_byte_identical_with_fixed_portable_permissions(self):
        first = Path(self.tmp.name) / "first.zip"
        second = Path(self.tmp.name) / "second.zip"
        builder.build(self.root, first)
        with mock.patch.object(zipfile.time, "localtime", return_value=(2030, 12, 31, 23, 59, 58, 0, 0, 0)):
            builder.build(self.root, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            for entry in archive.infolist():
                self.assertEqual(entry.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(entry.external_attr >> 16, 0o100644)

    def test_packager_refuses_even_reviewed_removed_installer(self):
        (self.root / "scripts" / ("manage" + "_plugin.py")).write_bytes(b"removed")
        self.seal()
        output = Path(self.tmp.name) / "release.zip"
        with self.assertRaisesRegex(RuntimeError, "removed installer"):
            builder.build(self.root, output)
        self.assertFalse(output.exists())

    def test_missing_corrupt_or_linked_manifest_is_refused(self):
        path = self.root / identity.DISTRIBUTION_MANIFEST_RELATIVE
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            identity.distribution_manifest(self.root)
        path.write_text("not json")
        with self.assertRaises(ValueError):
            identity.distribution_manifest(self.root)
        path.unlink()
        try:
            path.symlink_to(self.root / "LICENSE")
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314 or exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
                self.skipTest("fixture symlink capability unavailable")
            raise
        with self.assertRaisesRegex(RuntimeError, "links"):
            identity.distribution_manifest(self.root)

    def test_drift_missing_file_and_unreviewed_private_file_are_refused(self):
        target = self.root / "scripts/core.py"
        for mutation in ("bytes", "missing", "private"):
            with self.subTest(mutation=mutation):
                target.write_bytes(b"print('synthetic')\n")
                extra = self.root / "scripts/.env"
                extra.unlink(missing_ok=True)
                self.seal()
                if mutation == "bytes":
                    target.write_bytes(b"tampered")
                elif mutation == "missing":
                    target.unlink()
                else:
                    extra.write_bytes(b"synthetic-private")
                with self.assertRaisesRegex(RuntimeError, "reviewed sha256"):
                    identity.distribution_manifest(self.root)

    def test_linked_file_and_ancestor_are_refused_without_external_read(self):
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        (outside / "external").write_bytes(b"external sentinel")
        link = self.root / "scripts/link"
        try:
            link.symlink_to(outside / "external")
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314 or exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
                self.skipTest("fixture symlink capability unavailable")
            raise
        with self.assertRaisesRegex(RuntimeError, "links"):
            identity.distribution_files(self.root)
        link.unlink()
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "links"):
            identity.distribution_files(self.root)
        with self.assertRaisesRegex(RuntimeError, "links"):
            identity.safe_file(self.root, "scripts/link/external")

    def test_packager_never_overwrites_or_writes_inside_source(self):
        output = Path(self.tmp.name) / "release.zip"
        output.write_bytes(b"existing")
        before = output.stat()
        with self.assertRaises(FileExistsError):
            builder.build(self.root, output)
        self.assertEqual(output.read_bytes(), b"existing")
        self.assertEqual(output.stat().st_ino, before.st_ino)
        with self.assertRaisesRegex(RuntimeError, "outside"):
            builder.build(self.root, self.root / "release.zip")

    def test_packager_refuses_nested_git_metadata_even_if_reviewed(self):
        target = self.root / "docs/nested/.git/private.md"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"synthetic metadata")
        self.seal()
        output = Path(self.tmp.name) / "release.zip"
        with self.assertRaisesRegex(RuntimeError, "Git metadata"):
            builder.build(self.root, output)
        self.assertFalse(output.exists())

    def test_library_import_does_not_change_embedding_bytecode_policy(self):
        import sys
        runtime = Path(self.tmp.name) / "library-source/scripts"
        shutil.copytree(ROOT / "scripts", runtime, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copytree(ROOT / "assets", runtime.parent / "assets")
        code = "import importlib.util,sys; assert not sys.dont_write_bytecode; p=sys.argv[1]; spec=importlib.util.spec_from_file_location('context_guard',p); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); assert not sys.dont_write_bytecode; print('policy-preserved')"
        env = {"PATH":os.defpath,"HOME":str(Path(self.tmp.name) / "os-home")}
        result = subprocess.run([sys.executable,"-c",code,str(runtime / "context_guard.py")], env=env, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "policy-preserved")

    def test_removed_installer_is_absent_and_has_no_python_importers(self):
        removed = "manage" + "_plugin"
        self.assertFalse((ROOT / "scripts" / (removed + ".py")).exists())
        for area in ("scripts", "tools"):
            for path in (ROOT / area).rglob("*.py"):
                body = path.read_text(encoding="utf-8")
                self.assertNotIn("from scripts." + removed, body)
                self.assertNotIn('"scripts/' + removed + '.py"', body)

    def test_candidate_hooks_use_distinct_marketplace_and_accept_local(self):
        hooks = json.loads((ROOT / "hooks/hooks.json").read_text())["hooks"]
        for groups in hooks.values():
            for group in groups:
                for hook in group["hooks"]:
                    for field in ("command", "commandWindows"):
                        body = hook[field]
                        self.assertIn("codex-context-guard-v016", body)
                        self.assertIn("local", body)
                        self.assertNotIn("manage" + "_plugin.py", body)

    @unittest.skipIf(os.name == "nt", "POSIX synthetic Hook resolver")
    def test_local_fallback_executes_only_candidate_marketplace(self):
        hooks = json.loads((ROOT / "hooks/hooks.json").read_text())["hooks"]
        command = hooks["UserPromptSubmit"][0]["hooks"][0]["command"]
        home = Path(self.tmp.name) / "synthetic-home"
        candidate = home / "plugins/cache/codex-context-guard-v016/context-guard/local/scripts"
        candidate.mkdir(parents=True)
        script = candidate / "run_context_guard.sh"
        script.write_text("printf 'candidate-local\\n'\n")
        old = home / "plugins/cache/codex-context-guard/context-guard/0.15.1/scripts"
        old.mkdir(parents=True)
        (old / "run_context_guard.sh").write_text("printf 'old-marketplace\\n'\n")
        env = {"PATH": os.defpath, "HOME": str(home), "CODEX_HOME": str(home),
               "PLUGIN_ROOT": str(Path(self.tmp.name) / "missing/local")}
        result = subprocess.run(["/bin/sh", "-c", command], env=env, text=True,
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "candidate-local")
        script.unlink()
        result = subprocess.run(["/bin/sh", "-c", command], env=env, text=True,
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("old-marketplace", result.stdout)

    def test_real_hook_does_not_generate_bytecode_or_break_full_parity(self):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory).resolve()
            installed = outer / "installed"
            installed.mkdir()
            for name in identity.distribution_manifest(ROOT):
                target = installed / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            project = outer / "project"
            project.mkdir()
            for configured in (False, True):
                home = outer / ("configured" if configured else "unconfigured")
                home.mkdir()
                if configured:
                    (home / "context-guard").mkdir()
                    (home / "context-guard/interpreter.conf").write_text(str(Path(sys.executable).resolve()) + "\n")
                environment = {"PATH": str(Path(sys.executable).parent) + os.pathsep + os.defpath,
                    "HOME": str(outer / "os-home"), "USERPROFILE": str(outer / "os-home"),
                    "CODEX_HOME": str(home), "PLUGIN_DATA": str(outer / "data"),
                    "TMPDIR": str(outer)}
                if os.name == "nt":
                    environment.update({key:os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT") if key in os.environ})
                    shell = shutil.which("powershell") or shutil.which("pwsh")
                    if shell is None:
                        self.skipTest("Windows PowerShell fixture unavailable")
                    command = [shell, "-NoProfile", "-NonInteractive", "-File", str(installed / "scripts/run-context-guard.ps1"), "hook"]
                else:
                    command = ["/bin/sh", str(installed / "scripts/run_context_guard.sh"), "hook"]
                self.assertNotIn("PYTHONDONTWRITEBYTECODE", environment)
                for event in ("UserPromptSubmit", "PreCompact", "Stop", "SessionEnd"):
                    result = subprocess.run(command, input=json.dumps({"hook_event_name":event, "session_id":"synthetic-bytecode", "cwd":str(project), "prompt":"hello", "trigger":"manual", "last_assistant_message":"waiting"}),
                        env=environment, text=True, capture_output=True, timeout=30, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIsInstance(json.loads(result.stdout), dict)
                    self.assertFalse(list(installed.rglob("*.pyc")))
                    identity.compare_artifact(ROOT, installed)
                # Execute the genuine recovery command from the last Hook's
                # persisted packet, without a launcher or an environment guard.
                packet = json.loads((Path(environment["PLUGIN_DATA"]) / "sessions-v2/synthetic-bytecode/recovery.json").read_text())["packet"]
                command_line = next(line for line in packet.splitlines() if "context_guard.py" in line and " recovery-page " in line)
                direct = subprocess.run(command_line, shell=True, env=environment, text=True, capture_output=True, check=False)
                self.assertEqual(direct.returncode, 0, direct.stderr)
                self.assertFalse(list(installed.rglob("*.pyc")))
                identity.compare_artifact(ROOT, installed)
                bootstrap = "import sys; p=sys.argv[1]; n={'__name__':'fixture_router','__file__':p}; exec(compile(open(p,encoding='utf-8').read(),p,'exec'),n); n['_delegate_subprocess'](sys.stdin.buffer.read(),disable_maintenance=sys.argv[2]=='1')"
                for disable, event in ((False, "Stop"), (True, "SessionEnd")):
                    delegated = subprocess.run([sys.executable, "-c", bootstrap, str(installed / "scripts/cg_hook.py"), "1" if disable else "0"], input=json.dumps({"hook_event_name":event,"session_id":"synthetic-bytecode","cwd":str(project),"last_assistant_message":"waiting"}), env=environment, text=True, capture_output=True, check=False)
                    self.assertEqual(delegated.returncode, 0, delegated.stderr)
                    self.assertFalse(list(installed.rglob("*.pyc")))
                    identity.compare_artifact(ROOT, installed)

    def test_reparse_attributes_reject_roots_and_leaf_before_reads(self):
        original = Path.lstat
        original_read = Path.read_bytes
        for relative in (".", "scripts", ".codex-plugin", "docs", ".agents", ".agents/plugins", "scripts/core.py"):
            target = self.root if relative == "." else self.root / relative
            if relative != "." and not target.exists():
                target.mkdir(parents=True)
            for field in ("st_reparse_tag", "st_file_attributes"):
                def shaped(path, **kwargs):
                    info = original(path, **kwargs)
                    if path == target:
                        return types.SimpleNamespace(st_mode=info.st_mode, st_reparse_tag=1 if field == "st_reparse_tag" else 0, st_file_attributes=0x400 if field == "st_file_attributes" else 0)
                    return info
                def read_safe(path):
                    if path == target:
                        raise AssertionError("unexpected content read")
                    return original_read(path)
                with self.subTest(path=relative, field=field), mock.patch.object(Path, "lstat", shaped), mock.patch.object(Path, "read_bytes", read_safe):
                    with self.assertRaisesRegex(RuntimeError, "reparse"):
                        identity.distribution_files(self.root)

    def test_reparse_directory_is_rejected_before_target_enumeration(self):
        original_stat, original_iterdir = Path.lstat, Path.iterdir
        for operation in ("runtime", "distribution", "compare"):
            for field in ("st_reparse_tag", "st_file_attributes"):
                with self.subTest(operation=operation, field=field), tempfile.TemporaryDirectory() as temporary:
                    source = Path(temporary) / "source"
                    shutil.copytree(self.root, source)
                    if operation == "compare":
                        scan = Path(temporary) / "installed"
                        shutil.copytree(source, scan)
                    else:
                        scan = source
                    target = scan / ("docs/nested/blocked" if operation == "distribution" else "scripts/nested/blocked")
                    target.mkdir(parents=True)
                    (target / "outside-sentinel.md").write_bytes(b"must not be enumerated")
                    entered = []

                    def shaped(path, **kwargs):
                        info = original_stat(path, **kwargs)
                        if path == target:
                            return types.SimpleNamespace(st_mode=info.st_mode,
                                st_reparse_tag=1 if field == "st_reparse_tag" else 0,
                                st_file_attributes=0x400 if field == "st_file_attributes" else 0)
                        return info

                    def enumerate_level(path):
                        entered.append(path)
                        if path == target:
                            raise AssertionError("entered a rejected reparse directory")
                        return original_iterdir(path)

                    def unchecked_recursive_provider(path, pattern):
                        # Model a provider that treats the shaped reparse entry
                        # as a traversable directory. Draining this generator
                        # reaches the sentinel before a consumer can inspect it.
                        if not path.exists():
                            return
                        for child in enumerate_level(path):
                            if pattern == "*" or child.name.endswith(".md"):
                                yield child
                            if identity.stat.S_ISDIR(original_stat(child).st_mode):
                                yield from unchecked_recursive_provider(child, pattern)

                    with mock.patch.object(Path, "lstat", shaped), \
                            mock.patch.object(Path, "iterdir", enumerate_level), \
                            mock.patch.object(Path, "rglob", unchecked_recursive_provider):
                        with self.assertRaisesRegex(RuntimeError, "reparse"):
                            if operation == "runtime":
                                identity.tree_manifest(source)
                            elif operation == "distribution":
                                identity.distribution_files(source)
                            else:
                                identity.compare_artifact(source, scan)
                    self.assertIn(target.parent, entered)
                    self.assertNotIn(target, entered)

    def test_artifact_inspection_cannot_close_install_or_noop_gates(self):
        from tools.validation import native_acceptance as native
        installed = Path(self.tmp.name) / "installed"
        shutil.copytree(self.root, installed)
        with mock.patch.object(native, "load_artifacts", return_value=identity), \
                mock.patch.object(native, "verify_exact_source"), \
                mock.patch.object(native, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            result = native.portable_acceptance(self.root, "a" * 40, "unused", None, installed)
        self.assertEqual(result["status"], "pending")
        for gate in ("official_marketplace_install", "strict_second_noop", "old_cache_object_preservation"):
            self.assertIn(gate, result["pending_gates"])
        self.assertEqual(run.call_count, 1)
        self.assertIn("scripts/smoke_installed.py", run.call_args.args)
        with self.assertRaisesRegex(native.NativeRunError, "installation required"):
            native.inspect_installed_artifact(self.root, "a" * 40, "unused", None)

    def test_historical_namespace_profile_fails_before_side_effects(self):
        from tools.validation import commentary_live_runner as runner
        with self.assertRaisesRegex(ValueError, "installer retired"):
            runner.preflight({})

    @unittest.skipUnless(hasattr(os, "mkfifo"), "fixture FIFO unavailable")
    def test_special_file_refused(self):
        target = self.root / "scripts/fifo"
        os.mkfifo(target)
        with self.assertRaisesRegex(RuntimeError, "regular"):
            identity.tree_manifest(self.root)
