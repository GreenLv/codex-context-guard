import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.validation import runtime_activity as activity


def hooks():
    return {"hooks": {"event" + str(i): [{"hooks": [{
        "command": "sh -c 'exact-inline-" + str(i) + "'",
        "commandWindows": "$exactInline" + str(i),
    }]}] for i in range(9)}}


class Classification(unittest.TestCase):
    def observe(self, *args, **kwargs):
        # These fixtures patch POSIX snapshots on every host; native Windows
        # queries are exercised separately against the real PowerShell helper.
        return activity.observe(*args, platform_name="darwin", **kwargs)

    def setUp(self):
        self.slot = "/synthetic/profile/plugins/cache/codex-context-guard/context-guard/0.17.3"
        self.path = self.slot + "/scripts/cg_hook.py"
        self.inline = activity._inline_commands(hooks(), "command")

    def check(self, command):
        return activity._posix_classify(command, [self.slot], self.inline)

    def test_exact_runtime_and_launcher(self):
        self.assertEqual(self.check("/usr/bin/python3 -B -S " + self.path + " hook"), "runtime_python")
        self.assertEqual(self.check("python3 -X utf8 " + self.path + " hook"), "runtime_python")
        self.assertEqual(self.check("/bin/sh " + self.slot + "/scripts/run_context_guard.sh hook"), "runtime_launcher")
        self.assertEqual(self.check("python3 " + self.slot + "/scripts/context_guard.py cleanup"), "runtime_python")

    def test_other_home_and_echo_do_not_match(self):
        self.assertIsNone(self.check("python3 /different/profile/scripts/cg_hook.py hook"))
        self.assertIsNone(self.check("/bin/echo " + self.path))
        self.assertIsNone(self.check("python3 -c 'print(\"" + self.path + "\")'"))
        self.assertIsNone(self.check("sh -c 'echo " + self.path + "'"))
        self.assertIsNone(self.check("sh -c 'echo /synthetic/path with spaces/a.py'"))

    def test_nested_launcher_and_unreadable_identity(self):
        self.assertEqual(self.check("sh -c 'sh " + self.slot + "/scripts/run_context_guard.sh hook'"), "runtime_launcher")
        self.assertEqual(self.check("???"), "ambiguous_unreadable_command")
        self.assertEqual(self.check("(python3)"), "ambiguous_unreadable_command")

    def test_exact_inline_is_ambiguous_not_global_idle(self):
        self.assertEqual(self.check("sh -c exact-inline-0"), "ambiguous_inline_hook_home")
        self.assertIsNone(self.check("sh -c 'echo exact-inline-0'"))

    def test_identity_change_and_candidate_arrival_refuse_clear(self):
        row = {"pid": 4, "ppid": 3, "start": "a", "category": "runtime_python"}
        self.assertEqual(activity._reconcile({4: row}, {4: dict(row, start="b")})["status"], "unknown")
        self.assertEqual(activity._reconcile({}, {4: row})["status"], "unknown")
        self.assertEqual(activity._reconcile({4: row}, {4: row})["status"], "active")
        self.assertEqual(activity._reconcile({}, {})["status"], "clear")

    def test_ps_ignores_exact_self_pid_and_detects_child(self):
        line = "10 3 501 Sun Nov 15 05:00:01 2026 python3 " + self.path + " hook\n"
        self.assertEqual(activity._parse_ps(line.encode(), {10}, [self.slot], self.inline), {})
        self.assertEqual(activity._parse_ps(line.encode(), set(), [self.slot], self.inline)[10]["category"], "runtime_python")

    def test_missing_verified_hooks_is_unknown(self):
        result = self.observe(Path('/unavailable/profile'), '0.17.3', {'ps': {'path': '/bin/ps'}})
        self.assertEqual(result['status'], 'unknown')

    def test_local_slot_is_selected_and_missing_slot_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            base = home / 'plugins/cache/codex-context-guard/context-guard'
            (base / 'local').mkdir(parents=True)
            with mock.patch.object(activity, '_ps_snapshot', return_value={}) as query:
                result = self.observe(home, '0.17.3', {'ps': {'path': '/bin/ps'}}, hooks=hooks())
            self.assertEqual(result['status'], 'clear')
            self.assertEqual(query.call_args.args[1], [str(base / 'local')])
            (base / 'local').rmdir()
            self.assertEqual(self.observe(home, '0.17.3', {'ps': {'path': '/bin/ps'}}, hooks=hooks())['status'], 'unknown')

    def test_query_failure_and_malformed_output_unknown(self):
        with mock.patch.object(activity, '_ps_snapshot', side_effect=activity.ObservationError('failed')):
            self.assertEqual(self.observe(Path('/unavailable/profile'), '0.17.3', {'ps': {'path': '/bin/ps'}}, hooks=hooks())['status'], 'unknown')
        with self.assertRaises(activity.ObservationError):
            activity._parse_ps(b'not a snapshot\n', set(), [self.slot], self.inline)

    def test_environment_scrubs_credential_overrides_preserves_os(self):
        with mock.patch.dict(os.environ, {'PATH': '/bin', 'SYSTEMROOT': 'C:\\Windows', 'EXAMPLE_TOKEN': 'not-real'}, clear=True):
            env = activity._scrub_env()
            self.assertEqual(env['PATH'], '/bin')
            self.assertEqual(env['SYSTEMROOT'], 'C:\\Windows')
            self.assertNotIn('EXAMPLE_TOKEN', env)

    def test_absent_slot_explicit_only_and_fail_closed_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            slot = home / 'plugins/cache/codex-context-guard/context-guard/0.17.3'
            args = {'ps': {'path': '/bin/ps'}}
            with mock.patch.object(activity, '_ps_snapshot', return_value={}) as query:
                self.assertEqual(self.observe(home, '0.17.3', args, hooks=hooks(), slots=[slot])['status'], 'unknown')
                self.assertEqual(self.observe(home, '0.17.3', args, hooks=hooks(), allow_absent=True)['status'], 'unknown')
                self.assertEqual(self.observe(home, '0.17.3', args, hooks=hooks(), slots=[], allow_absent=True)['status'], 'unknown')
                self.assertEqual(self.observe(home, '0.17.3', args, hooks=hooks(), slots=[home / 'other'], allow_absent=True)['status'], 'unknown')
                self.assertEqual(self.observe(home, '0.17.3', args, hooks=hooks(), slots=[slot], allow_absent=True)['status'], 'clear')
                self.assertEqual(query.call_args.args[1], [str(slot)])
                slot.parent.mkdir(parents=True)
                with mock.patch.object(Path, 'lstat', side_effect=PermissionError):
                    self.assertEqual(self.observe(home, '0.17.3', args, hooks=hooks(), slots=[slot], allow_absent=True)['status'], 'unknown')
                try:
                    slot.symlink_to(home, target_is_directory=True)
                except OSError as exc:
                    if getattr(exc, 'winerror', None) == 1314:
                        self.skipTest('native symlink creation requires an unavailable Windows privilege')
                    raise
                self.assertEqual(self.observe(home, '0.17.3', args, hooks=hooks(), slots=[slot], allow_absent=True)['status'], 'unknown')
                slot.unlink()

    def test_query_timeout_unconfirmed_cleanup_is_explicit(self):
        child = mock.Mock(pid=321, returncode=None)
        child.communicate.side_effect = subprocess.TimeoutExpired('synthetic', 1)
        owner = mock.Mock(process=child)
        owner.close.return_value = {'owned_process_exited': False, 'owned_tree_no_running_members': False,
                                    'process_group_cleanup_error': 'denied'}
        with mock.patch.object(activity.OwnedProcess, 'spawn', return_value=owner):
            with self.assertRaises(activity.ObservationError) as raised:
                activity._query(['synthetic'])
        self.assertEqual(raised.exception.query_cleanup, 'unconfirmed')
        owner.close.assert_called_once()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            slot = home / 'plugins/cache/codex-context-guard/context-guard/0.17.3'
            with mock.patch.object(activity, '_ps_snapshot', side_effect=raised.exception):
                result = self.observe(home, '0.17.3', {'ps': {'path': '/bin/ps'}},
                                          hooks=hooks(), slots=[slot], allow_absent=True)
            self.assertEqual(result['status'], 'unknown')
            self.assertEqual(result['query_cleanup'], 'unconfirmed')

    def test_reparse_slot_is_never_an_absent_or_regular_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            slot = home / 'plugins/cache/codex-context-guard/context-guard/0.17.3'
            slot.mkdir(parents=True)
            original = Path.lstat
            def metadata(path, *args, **kwargs):
                if path == slot:
                    return SimpleNamespace(st_mode=stat.S_IFDIR, st_reparse_tag=0, st_file_attributes=0x400)
                return original(path, *args, **kwargs)
            with mock.patch.object(Path, 'lstat', metadata), mock.patch.object(activity, '_ps_snapshot') as query:
                result = self.observe(home, '0.17.3', {'ps': {'path': '/bin/ps'}},
                                          hooks=hooks(), slots=[slot], allow_absent=True)
            self.assertEqual(result['status'], 'unknown')
            query.assert_not_called()


class NativeMac(unittest.TestCase):
    def await_clear(self, *args, **kwargs):
        deadline = time.monotonic() + 5
        while True:
            result = activity.observe(*args, **kwargs)
            if result['status'] == 'clear' or time.monotonic() >= deadline:
                return result
            self.assertNotEqual(result.get('query_cleanup'), 'unconfirmed', result)
            time.sleep(.05)

    @unittest.skipUnless(os.environ.get('CG_RUNTIME_NATIVE_TEST') == '1' and sys.platform == 'darwin', 'opt-in native macOS test')
    def test_timeout_owned_query_tree_is_reaped(self):
        children = []
        original = activity.OwnedProcess.spawn
        def spawn(*args, **kwargs):
            owned = original(*args, **kwargs)
            children.append(owned.process)
            return owned
        with mock.patch.object(activity.OwnedProcess, 'spawn', side_effect=spawn), mock.patch.object(activity, 'TIMEOUT', .2):
            with self.assertRaises(activity.ObservationError) as raised:
                activity._query(['/bin/sh', '-c', 'sleep 30'])
        self.assertEqual(raised.exception.query_cleanup, 'confirmed')
        self.assertIsNotNone(children[0].poll())
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)

    @unittest.skipUnless(os.environ.get('CG_RUNTIME_NATIVE_TEST') == '1' and sys.platform == 'darwin', 'opt-in native macOS test')
    def test_pruned_slot_still_detects_running_script(self):
        with tempfile.TemporaryDirectory(prefix='cg-pruned-fixture-') as tmp:
            home = Path(tmp).resolve()
            slot = home / 'plugins/cache/codex-context-guard/context-guard/0.17.3'
            script = slot / 'scripts/cg_hook.py'
            script.parent.mkdir(parents=True)
            ready = home / 'ready'
            script.write_text('import pathlib,sys,time\npathlib.Path(sys.argv[1]).touch()\ntime.sleep(5)\n')
            args = {'ps': {'path': '/bin/ps'}}
            child = subprocess.Popen([sys.executable, '-B', str(script), str(ready)])
            try:
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(ready.exists())
                script.unlink()
                script.parent.rmdir()
                slot.rmdir()
                self.assertEqual(activity.observe(home, '0.17.3', args, hooks=hooks(), slots=[slot])['status'], 'unknown')
                result = activity.observe(home, '0.17.3', args, hooks=hooks(), slots=[slot], allow_absent=True)
                self.assertIn(result['status'], ('active', 'unknown'), result)
                self.assertTrue(any(row['pid'] == child.pid and row['category'] == 'runtime_python'
                                    for row in result['candidates']), result)
                self.assertEqual(child.wait(timeout=8), 0)
                self.assertEqual(self.await_clear(home, '0.17.3', args, hooks=hooks(), slots=[slot], allow_absent=True)['status'], 'clear')
            finally:
                if child.poll() is None:
                    child.wait(timeout=8)
        self.assertFalse(home.exists())
    @unittest.skipUnless(os.environ.get('CG_RUNTIME_NATIVE_TEST') == '1' and sys.platform == 'darwin', 'opt-in native macOS test')
    def test_clear_and_owned_python_positive(self):
        with tempfile.TemporaryDirectory(prefix='cg-activity-fixture-') as tmp:
            home = Path(tmp).resolve()
            slot = home / 'plugins/cache/codex-context-guard/context-guard/0.17.3'
            script = slot / 'scripts/cg_hook.py'
            script.parent.mkdir(parents=True)
            ready = home / 'ready'
            script.write_text('import pathlib,sys,time\npathlib.Path(sys.argv[1]).touch()\ntime.sleep(4)\n')
            args = {'ps': {'path': '/bin/ps'}}
            before = self.await_clear(home, '0.17.3', args, hooks=hooks())
            self.assertEqual(before['status'], 'clear', before)
            child = subprocess.Popen([sys.executable, '-B', str(script), str(ready)])
            try:
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(ready.exists())
                during = activity.observe(home, '0.17.3', args, hooks=hooks())
                self.assertIn(during['status'], ('active', 'unknown'), during)
                self.assertTrue(any(row['pid'] == child.pid for row in during['candidates']))
                self.assertEqual(child.wait(timeout=8), 0)
                after = self.await_clear(home, '0.17.3', args, hooks=hooks())
                self.assertEqual(after['status'], 'clear', after)
            finally:
                if child.poll() is None:
                    child.wait(timeout=8)
        self.assertFalse(home.exists())

    @unittest.skipUnless(os.environ.get('CG_RUNTIME_NATIVE_TEST') == '1' and sys.platform == 'darwin', 'opt-in native macOS test')
    def test_inline_hook_without_visible_home_is_unknown(self):
        with tempfile.TemporaryDirectory(prefix='cg-inline-fixture-') as tmp:
            home = Path(tmp).resolve()
            (home / 'plugins/cache/codex-context-guard/context-guard/0.17.3').mkdir(parents=True)
            definitions = hooks()
            for groups in definitions['hooks'].values():
                groups[0]['hooks'][0]['command'] = "sh -c 'sleep 3; :'"
            child = subprocess.Popen(['/bin/sh', '-c', 'sleep 3; :'])
            try:
                time.sleep(.15)
                result = activity.observe(home, '0.17.3', {'ps': {'path': '/bin/ps'}}, hooks=definitions)
                self.assertEqual(result['status'], 'unknown', result)
                self.assertTrue(any(row['pid'] == child.pid and row['category'] == 'ambiguous_inline_hook_home'
                                    for row in result['candidates']), result)
            finally:
                self.assertEqual(child.wait(timeout=8), 0)
        self.assertFalse(home.exists())


if __name__ == '__main__':
    unittest.main()
