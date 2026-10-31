"""Controlled real-entrypoint regressions; no CLI, user HOME or network access."""
from __future__ import annotations

import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path, PureWindowsPath
from unittest import mock

from tools.validation import native_acceptance as native


class PortableStrictNoopTests(unittest.TestCase):
    def exercise(self, module=native, mutation="none"):
        calls = []
        manager = mock.Mock()
        manager.tree_manifest.return_value = {"scripts/example.py": "a" * 64}
        manager.source_plugin_version.return_value = "0.16.0"
        manager.plugin_cache_root.side_effect = lambda home: home / "plugins/cache"

        def runner(root, *args, env=None):
            del root
            if "scripts/manage_plugin.py" in args:
                apply = "--apply" in args
                calls.append(apply)
                home = Path(env["CODEX_HOME"])
                target = home / "context-guard/interpreter.conf"
                registry = home / "plugins/installed_plugins.json"
                staging = home / "upstreams/context-guard/staging/LICENSE"
                if len(calls) == 1:
                    for path in (target, registry, staging):
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(b"installed")
                elif apply:
                    if mutation == "content":
                        target.write_bytes(b"damaged")
                    elif mutation == "rewrite":
                        temporary = target.with_suffix(".tmp")
                        temporary.write_bytes(target.read_bytes())
                        temporary.replace(target)
                    elif mutation == "mode":
                        target.chmod(0o400)
                    elif mutation == "registry":
                        registry.write_bytes(b"changed")
                    elif mutation == "staging":
                        staging.write_bytes(b"changed")
                    elif mutation == "add":
                        (home / "unexpected").write_bytes(b"new")
                    elif mutation == "delete":
                        registry.unlink()
                    elif mutation == "directory":
                        (home / "unexpected-empty").mkdir()
                    elif mutation == "error":
                        raise module.NativeRunError("controlled apply failure")
            out = "https://github.com/example/context-guard.git" if args[:2] == ("git", "remote") else "fixture"
            return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

        stderr = io.StringIO()
        with mock.patch.object(module, "load_manager", return_value=manager), \
                mock.patch.object(module, "verify_exact_source"), \
                mock.patch.object(module, "run", side_effect=runner), \
                contextlib.redirect_stderr(stderr):
            result = module.portable_acceptance(Path("/controlled-source"), "a" * 40,
                                                "controlled-codex", None)
        self.last_stderr = stderr.getvalue()
        return result, calls

    def test_second_call_is_apply_and_unchanged_nonempty_domain_passes(self):
        result, calls = self.exercise()
        self.assertEqual(calls, [True, True])
        self.assertEqual(result["status"], "passed")
        self.assertIn("strict_second_noop", [g["id"] for g in result["gates"]])

    def test_same_byte_rewrite_preserves_the_historical_state_contract(self):
        result, calls = self.exercise(mutation="rewrite")
        self.assertEqual(calls, [True, True])
        self.assertEqual(result["status"], "passed")

    def test_changed_state_and_object_set_changes_cannot_pass(self):
        for mutation in ("content", "mode", "registry", "staging", "add",
                         "delete", "directory", "error"):
            with self.subTest(mutation=mutation):
                if mutation == "mode" and os.name == "nt":
                    self.skipTest("Windows read-only mode changes alter cleanup semantics")
                result, calls = self.exercise(mutation=mutation)
                self.assertEqual(calls, [True, True])
                self.assertEqual(result["status"], "failed")
                self.assertNotIn("strict_second_noop", [g["id"] for g in result["gates"]])
                self.assertEqual(result["cleanup"]["status"], "passed")

    def test_empty_domain_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            with self.assertRaisesRegex(native.NativeRunError, "no installed files"):
                native.installed_object_snapshot(Path(directory))

    def test_symlink_never_read(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory)
            target = home / "control"
            target.write_bytes(b"controlled")
            try:
                (home / "link").symlink_to(target)
            except OSError:
                self.skipTest("platform cannot create test symlink")
            with self.assertRaisesRegex(native.NativeRunError, "links and reparse"):
                native.installed_object_snapshot(home)

    def test_real_hardlink_rejected_before_open(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory)
            target = home / "control"
            target.write_bytes(b"controlled")
            try:
                os.link(target, home / "alias")
            except OSError:
                self.skipTest("platform cannot create controlled hard link")
            with mock.patch.object(native, "open_snapshot_file") as opener:
                with self.assertRaisesRegex(native.NativeRunError, "hard links"):
                    native.installed_object_snapshot(home)
                opener.assert_not_called()

    def test_real_regular_replacement_between_lstat_and_open_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory)
            target = home / "control"
            target.write_bytes(b"controlled")
            original = native.open_snapshot_file

            def replace_then_open(path, **kwargs):
                replacement = path.with_suffix(".tmp")
                replacement.write_bytes(b"replacement")
                replacement.replace(path)
                return original(path, **kwargs)

            with mock.patch.object(native, "open_snapshot_file", side_effect=replace_then_open):
                with self.assertRaisesRegex(native.NativeRunError, "identity changed"):
                    native.installed_object_snapshot(home)

    def test_real_symlink_substitution_at_open_never_reads_target(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory) / "home"
            home.mkdir()
            target = home / "control"
            target.write_bytes(b"controlled")
            outside = Path(directory) / "outside"
            outside.write_bytes(b"must not read")
            probe = home / "probe"
            try:
                probe.symlink_to(outside)
            except OSError:
                self.skipTest("platform cannot create controlled symlink")
            probe.unlink()
            original = native.open_snapshot_file

            def replace_then_open(path, **kwargs):
                path.unlink()
                path.symlink_to(outside)
                return original(path, **kwargs)

            with mock.patch.object(native, "open_snapshot_file", side_effect=replace_then_open), \
                    mock.patch.object(native.os, "read", side_effect=AssertionError("unexpected read")):
                with self.assertRaisesRegex(native.NativeRunError, "snapshot object unreadable"):
                    native.installed_object_snapshot(home)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "platform has no FIFO fixture API")
    def test_real_special_object_rejected_without_open(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory)
            os.mkfifo(home / "fifo")
            with mock.patch.object(native, "open_snapshot_file") as opener:
                with self.assertRaisesRegex(native.NativeRunError, "special objects"):
                    native.installed_object_snapshot(home)
                opener.assert_not_called()

    def test_oserror_is_redacted_without_exception_context(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory)
            (home / "control").write_bytes(b"controlled")
            with mock.patch.object(native, "open_snapshot_file",
                                   side_effect=PermissionError(13, "denied", "/private-home/secret")):
                with self.assertRaises(native.NativeRunError) as caught:
                    native.installed_object_snapshot(home)
            self.assertEqual(str(caught.exception), "strict no-op snapshot object unreadable")
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertNotIn("private-home", str(caught.exception))

        with mock.patch.object(native, "open_snapshot_file",
                               side_effect=PermissionError(13, "denied", "/private-home/secret")):
            result, _ = self.exercise()
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("private-home", self.last_stderr)
        self.assertIn("snapshot object unreadable", self.last_stderr)

    def test_windows_opener_route_and_cross_provider_ctime(self):
        target = Path("controlled")
        runtime = mock.Mock()
        runtime._open_windows_committed_state.return_value = 37
        with mock.patch.object(native.os, "name", "nt"), \
                mock.patch.object(native, "load_snapshot_runtime", return_value=runtime):
            self.assertEqual(native.open_snapshot_file(target), 37)
        runtime._open_windows_committed_state.assert_called_once_with(target)
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory)
            (home / "control").write_bytes(b"controlled")
            fstat = os.fstat

            def alternate_ctime(fd):
                info = fstat(fd)
                return types.SimpleNamespace(**{name: getattr(info, name) for name in
                    ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")},
                    st_ctime_ns=info.st_ctime_ns + 1)

            with mock.patch.object(native.os, "fstat", side_effect=alternate_ctime):
                self.assertIn("control", native.installed_object_snapshot(home))

    @unittest.skipUnless(os.name == "posix", "POSIX stat injection control")
    def test_reparse_rejected_before_open(self):
        path = Path("/controlled")
        info = types.SimpleNamespace(st_mode=0o100600, st_reparse_tag=1)
        with mock.patch.object(native.os, "stat", return_value=info), \
                mock.patch.object(native, "open_snapshot_file") as opener:
            with self.assertRaisesRegex(native.NativeRunError, "links and reparse"):
                native.installed_object_snapshot(path)
            opener.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "real POSIX descriptor controls")
    def test_real_ancestor_swaps_never_read_external_file(self):
        for depth in range(3):
            for phase in ("before_directory_open", "before_enumeration", "before_file_open"):
                with self.subTest(depth=depth, phase=phase), \
                        tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
                    root = Path(temporary)
                    home = root / "home"
                    nested = home / "product" / "nested"
                    nested.mkdir(parents=True)
                    (nested / "control").write_bytes(b"owned")
                    victim = [home, home / "product", nested][depth]
                    victim_id = (victim.stat().st_dev, victim.stat().st_ino)
                    parent_id = (victim.parent.stat().st_dev, victim.parent.stat().st_ino)
                    outside = root / "outside"
                    outside.mkdir()
                    # All possible path-based continuations find an outside file.
                    for relative in ("control", "nested/control", "product/nested/control"):
                        file = outside / relative
                        file.parent.mkdir(parents=True, exist_ok=True)
                        file.write_bytes(b"outside sentinel")
                    outside_ids = {(f.stat().st_dev, f.stat().st_ino)
                                   for f in outside.rglob("*") if f.is_file()}
                    displaced = root / "displaced"
                    original_open, original_listdir, original_read = os.open, os.listdir, os.read
                    reads, swapped = [], False

                    def swap():
                        nonlocal swapped
                        if not swapped:
                            victim.rename(displaced)
                            victim.symlink_to(outside, target_is_directory=True)
                            swapped = True

                    def key(fd):
                        info = os.fstat(fd)
                        return info.st_dev, info.st_ino

                    def opening(name, flags, *args, **kwargs):
                        fd = kwargs.get("dir_fd")
                        if (phase == "before_directory_open" and fd is not None
                                and name == victim.name and key(fd) == parent_id):
                            swap()
                        if (phase == "before_file_open" and fd is not None
                                and not flags & os.O_DIRECTORY and not swapped):
                            swap()
                        return original_open(name, flags, *args, **kwargs)

                    def listing(fd):
                        if phase == "before_enumeration" and key(fd) == victim_id:
                            swap()
                        return original_listdir(fd)

                    def reading(fd, count):
                        if key(fd) in outside_ids:
                            reads.append(True)
                        return original_read(fd, count)

                    try:
                        with mock.patch.object(native.os, "open", side_effect=opening), \
                                mock.patch.object(native.os, "listdir", side_effect=listing), \
                                mock.patch.object(native.os, "read", side_effect=reading):
                            with self.assertRaises(native.NativeRunError):
                                native.installed_object_snapshot(home)
                        self.assertTrue(swapped)
                        self.assertEqual(reads, [])
                    finally:
                        if swapped:
                            victim.unlink()
                            displaced.rename(victim)

    @unittest.skipUnless(os.name == "posix", "POSIX capability control")
    def test_posix_missing_capability_fails_before_read(self):
        with mock.patch.object(native, "POSIX_SNAPSHOT_CAPABLE", False), \
                mock.patch.object(native.os, "read") as reading:
            with self.assertRaisesRegex(native.NativeRunError, "capability unavailable"):
                native.installed_object_snapshot(Path("/controlled"))
            reading.assert_not_called()

    def test_windows_local_volume_root_contract(self):
        self.assertEqual(native.windows_snapshot_ancestors(PureWindowsPath("C:/home/product")),
                         (PureWindowsPath("C:/"), PureWindowsPath("C:/home")))
        for path in ("C:relative", "relative", "//server/share/home", "//?/C:/home", "C:/a/../b"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(native.NativeRunError, "root capability"):
                    native.windows_snapshot_ancestors(PureWindowsPath(path))

    def test_windows_retained_handle_model_and_close_failure(self):
        # Model only: real Win32 rename/share semantics require Windows execution.
        for case in ("positive", "swap_blocked", "identity_mismatch", "reparse", "close_failure"):
            with self.subTest(case=case), \
                    tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
                home = Path(temporary) / "home"
                product = home / "product"
                product.mkdir(parents=True)
                (product / "control").write_bytes(b"owned")
                backend = mock.Mock()
                held, opened, closed, reads = {}, [], [], []
                original_iterdir = Path.iterdir
                original_open = os.open

                def identity(path):
                    info = path.lstat()
                    return {"volume_serial": info.st_dev, "file_id": str(info.st_ino),
                            "kind": "directory", "reparse_tag": 0}

                def acquire(path, access):
                    self.assertEqual(access, 0x20080)
                    handle = len(opened) + 1
                    held[handle] = path
                    opened.append(handle)
                    return "api", handle

                def handle_identity(api, handle):
                    result = identity(held[handle])
                    if held[handle] == product and case == "reparse":
                        result["reparse_tag"] = 1
                    return result

                def path_identity(path):
                    result = identity(path)
                    if path == product and case == "identity_mismatch":
                        result["file_id"] = "wrong"
                    return result

                def close(api, handle):
                    closed.append(handle)
                    path = held.pop(handle)
                    return {"return_value": int(not (path == product and case == "close_failure"))}

                def listing(path):
                    self.assertTrue(all(parent in held.values() for parent in (path, *path.parents)))
                    if path == product and case == "swap_blocked":
                        # Model enforces the no-SHARE_DELETE property. Not native evidence.
                        raise PermissionError(32, "modeled pinned directory rename denied")
                    return original_iterdir(path)

                def opening(path, **kwargs):
                    self.assertIsNone(kwargs["dir_fd"])
                    self.assertTrue(all(parent in held.values() for parent in path.parents))
                    reads.append(path.name)
                    return original_open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))

                backend.open_windows_handle.side_effect = acquire
                backend.windows_handle_identity.side_effect = handle_identity
                backend.windows_object_identity.side_effect = path_identity
                backend.close_windows_handle.side_effect = close
                with mock.patch.object(native.os, "name", "nt"), \
                        mock.patch.object(native, "load_snapshot_windows", return_value=backend), \
                        mock.patch.object(native, "windows_snapshot_ancestors",
                                          return_value=tuple(reversed(home.parents))), \
                        mock.patch.object(Path, "iterdir", autospec=True, side_effect=listing), \
                        mock.patch.object(native, "open_snapshot_file", side_effect=opening):
                    if case == "positive":
                        self.assertIn("product/control", native.installed_object_snapshot(home))
                    else:
                        with self.assertRaises(native.NativeRunError):
                            native.installed_object_snapshot(home)
                self.assertCountEqual(opened, closed)
                self.assertEqual(held, {})
                if case in {"swap_blocked", "identity_mismatch", "reparse"}:
                    self.assertEqual(reads, [])

    def test_credential_material_refuses_before_open_or_hash(self):
        for name in ("auth.json", "AUTH.JSON", "nested/auth.json", "nested/auth.json.bak",
                     "credentials.json", "nested/credentials.toml", "token.json", ".env",
                     "nested/.env.production", "id_ed25519", "nested/private.pem", "private.key",
                     ".git-credentials", ".docker/config.json"):
            with self.subTest(name=name), \
                    tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
                home = Path(temporary)
                file = home / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b"synthetic credential body must not be read")
                with mock.patch.object(native, "open_snapshot_file") as opener, \
                        mock.patch.object(native.hashlib, "sha256") as hashing:
                    with self.assertRaisesRegex(native.NativeRunError, "refuses credential material") as caught:
                        native.installed_object_snapshot(home)
                    opener.assert_not_called()
                    hashing.assert_not_called()
                self.assertNotIn(str(home), str(caught.exception))
                self.assertNotIn("synthetic credential", str(caught.exception))

    def test_real_private_backend_imports_do_not_write_bytecode(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            clone = Path(temporary)
            source = Path(__file__).parents[1]
            for directory in ("scripts", "assets"):
                shutil.copytree(source / directory, clone / directory,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            for relative in ("tools/validation/native_acceptance.py",
                             "tools/validation/incident_readonly_child.py"):
                target = clone / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / relative, target)
            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            code = """import pathlib, sys
root = pathlib.Path(sys.argv[1])
path = root / 'tools/validation/native_acceptance.py'
ns = {'__file__': str(path), '__name__': 'private_snapshot_import'}
exec(compile(path.read_bytes(), str(path), 'exec'), ns)
assert sys.dont_write_bytecode is False
ns['load_snapshot_runtime']()
ns['load_snapshot_windows']()
assert sys.dont_write_bytecode is False
assert not list(root.rglob('__pycache__'))
"""
            result = subprocess.run([sys.executable, "-c", code, str(clone)], env=environment,
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(clone.rglob("__pycache__")), [])

    def test_backend_import_failure_restores_bytecode_policy(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            module = Path(temporary) / "broken.py"
            module.write_text("raise RuntimeError('controlled import failure')\n")
            before = sys.dont_write_bytecode
            with self.assertRaisesRegex(RuntimeError, "controlled import failure"):
                native.load_snapshot_module("controlled_broken_snapshot", module)
            self.assertIs(sys.dont_write_bytecode, before)
            self.assertEqual(list(Path(temporary).rglob("__pycache__")), [])

    @unittest.skipUnless(os.name == "posix", "POSIX detached-ancestor regression")
    def test_portable_rejects_detached_holder_with_empty_replacement_home(self):
        snapshot, opener = native.installed_object_snapshot, native.open_snapshot_file
        snapshots, displaced, empty = [], [], []

        def observing(home):
            snapshots.append(home)
            if len(snapshots) != 2:
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
                result, calls = self.exercise()
            self.assertEqual(calls, [True, True])
            self.assertEqual(empty, [True])
            self.assertEqual(result["status"], "failed")
            self.assertFalse(any(g["id"] == "strict_second_noop" and g["status"] == "passed"
                                 for g in result["gates"]))
            self.assertIn("ancestor pathname changed", self.last_stderr)
        finally:
            for saved in displaced:
                shutil.rmtree(saved)

    def test_real_manager_dry_run_skips_transaction_and_binding_apply_rewrites(self):
        manager = native.load_manager(Path(__file__).parents[1])
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory) / "codex-home"
            home.mkdir()
            argv = ["manager", "--repo-root", str(Path(__file__).parents[1]),
                    "--codex-home", str(home), "--codex", "controlled-codex"]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.dict(os.environ), \
                    mock.patch.object(manager, "codex_version", return_value=(999, 0, 0)), \
                    mock.patch.object(manager, "same_version_drift_preflight"), \
                    mock.patch.object(manager, "ensure_marketplace") as marketplace, \
                    mock.patch.object(manager, "ensure_plugin") as plugin, \
                    mock.patch.object(manager, "_run_install_transaction") as transaction, \
                    mock.patch.object(manager, "prepare_gui_interpreter_binding", wraps=manager.prepare_gui_interpreter_binding) as prepare, \
                    mock.patch.object(manager, "write_gui_interpreter_binding", wraps=manager.write_gui_interpreter_binding) as write, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(manager.main(), 0)
                transaction.assert_not_called()
                prepare.assert_not_called()
                write.assert_not_called()
                self.assertFalse(marketplace.call_args.args[-1])
                self.assertFalse(plugin.call_args.args[-1])
                argv.append("--apply")
                self.assertEqual(manager.main(), 0)
                before = native.installed_object_snapshot(home)
                self.assertEqual(manager.main(), 0)
                after = native.installed_object_snapshot(home)
                self.assertEqual(transaction.call_count, 2)
                self.assertEqual(prepare.call_count, 2)
                self.assertEqual(write.call_count, 2)
                # The writer ran twice, but HOME-13 compares final state only.
                self.assertEqual(before, after)
                self.assertEqual((home / "context-guard/interpreter.conf").read_bytes(),
                                 (str(Path(sys.executable).resolve()) + os.linesep).encode())


if __name__ == "__main__":
    unittest.main()
