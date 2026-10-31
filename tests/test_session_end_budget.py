"""SessionEnd early same-process anchors, finite maintenance and queue safety.

Fake-clock/route controls only; these do not replace the complete native
1200/1200/10000-file command's unchanged three-second acceptance gate.
"""

import contextlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("cg_session_end_budget", SCRIPTS / "context_guard.py")
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)
import cg_hook as router  # noqa: E402


class Clock:
    def __init__(self, now=100.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Stream:
    def __init__(self, raw=b"", on_read=None):
        self.buffer = io.BytesIO(raw)
        if on_read:
            original = self.buffer.read

            def read(*args):
                on_read()
                return original(*args)
            self.buffer.read = read

    def write(self, value):
        return self.buffer.write(value.encode("utf-8") if isinstance(value, str) else value)

    def flush(self):
        pass


class SessionEndBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.env = mock.patch.dict(os.environ, {
            "HOME": str(self.root / "os-home"), "USERPROFILE": str(self.root / "os-home"),
            "CODEX_HOME": str(self.root / "codex-home"), "CONTEXT_GUARD_DATA_DIR": str(self.data),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.payload = {"hook_event_name": "SessionEnd", "session_id": "budget", "cwd": str(self.root)}
        self.state = cg.new_state(self.payload)
        self.state["mode"]["active"] = True
        self.session = self.data / "sessions-v2/budget"

    def handler(self, start, save_cost=0, recovery_cost=0):
        clock = Clock()
        order = []

        def save(*_):
            order.append("save")
            clock.advance(save_cost)

        def recovery(*_):
            order.append("recovery")
            clock.advance(recovery_cost)

        with mock.patch.object(cg.time, "monotonic", clock), \
                mock.patch.object(cg, "save_state", side_effect=save), \
                mock.patch.object(cg, "write_recovery", side_effect=recovery), \
                mock.patch.object(cg, "cleanup_old_sessions", side_effect=lambda *a, **k: order.append("cleanup")) as cleanup:
            cg.handle_session_end(self.session, self.state, self.payload, budget_started_at=start)
        return clock, order, cleanup

    def test_quantum_is_at_most_one_second_after_state_and_recovery(self):
        clock, order, cleanup = self.handler(100.0, .1, .2)
        self.assertEqual(order, ["save", "recovery", "cleanup"])
        self.assertLessEqual(cleanup.call_args.kwargs["deadline"] - clock.now, 1.0)
        self.assertAlmostEqual(cleanup.call_args.kwargs["deadline"], 101.3)

    def test_state_recovery_elapsed_reduces_shared_three_second_cap(self):
        for save_cost, recovery_cost in ((0, 0), (1.5, 1.0), (2, 1)):
            with self.subTest(save=save_cost, recovery=recovery_cost):
                clock, order, cleanup = self.handler(100.0, save_cost, recovery_cost)
                self.assertEqual(order[:2], ["save", "recovery"])
                if clock.now >= 102.65:
                    cleanup.assert_not_called()
                else:
                    self.assertAlmostEqual(cleanup.call_args.kwargs["deadline"], min(clock.now + 1, 102.65))

    def test_none_invalid_and_expired_handler_budget_never_means_unlimited(self):
        for start in (None, True, False, "100", object(), -1, float("nan"), float("inf"), 101.0, 97.0):
            with self.subTest(start=repr(start)):
                _, order, cleanup = self.handler(start)
                self.assertEqual(order, ["save", "recovery"])
                cleanup.assert_not_called()

    def test_future_handler_start_stays_disabled_after_slow_mandatory_save(self):
        clock, order, cleanup = self.handler(100.1, save_cost=.2)
        self.assertAlmostEqual(clock.now, 100.2)
        self.assertEqual(order, ["save", "recovery"])
        cleanup.assert_not_called()

    def test_mandatory_save_and_recovery_failure_do_not_run_cleanup(self):
        for failing in ("save_state", "write_recovery"):
            with self.subTest(failing=failing), \
                    mock.patch.object(cg, "save_state"), mock.patch.object(cg, "write_recovery"), \
                    mock.patch.object(cg, failing, side_effect=OSError("private write failed")), \
                    mock.patch.object(cg, "cleanup_old_sessions") as cleanup:
                with self.assertRaises(OSError):
                    cg.handle_session_end(self.session, self.state, self.payload, budget_started_at=100)
                cleanup.assert_not_called()

    def test_dispatch_omitted_disabled_valid_and_expired_lock_contract(self):
        omitted = object()
        for value, expected, wait in ((omitted, 100.0, 1.2), (None, None, 1.2),
                                      (True, None, 1.2), (float("nan"), None, 1.2),
                                      (float("inf"), None, 1.2), (101.0, None, 1.2),
                                      (98.0, 98.0, .65), (97.0, 97.0, 0)):
            with self.subTest(value=repr(value)):
                captured = []

                @contextlib.contextmanager
                def lock(_path, timeout):
                    captured.append(timeout)
                    yield

                with mock.patch.object(cg.time, "monotonic", return_value=100.0), \
                        mock.patch.object(cg, "write_session_dir", return_value=self.session), \
                        mock.patch.object(cg, "session_lock", side_effect=lock), \
                        mock.patch.object(cg, "load_state", return_value=self.state), \
                        mock.patch.object(cg, "handle_session_end", return_value={}) as handler:
                    kwargs = {} if value is omitted else {"budget_started_at": value}
                    cg.dispatch(self.payload, **kwargs)
                self.assertAlmostEqual(captured[0], wait)
                self.assertEqual(handler.call_args.kwargs["budget_started_at"], expected)

    def test_safe_dispatch_omission_and_explicit_none_are_distinct(self):
        clock = Clock()
        with mock.patch.object(cg.time, "monotonic", clock), \
                mock.patch.object(cg, "dispatch", return_value={}) as dispatch:
            cg.safe_dispatch(self.payload)
            self.assertEqual(dispatch.call_args.kwargs["budget_started_at"], 100.0)
            clock.advance(10)
            cg.safe_dispatch(self.payload)
            self.assertEqual(dispatch.call_args.kwargs["budget_started_at"], 110.0)
            cg.safe_dispatch(self.payload, budget_started_at=None)
            self.assertIsNone(dispatch.call_args.kwargs["budget_started_at"])

    def test_command_hook_anchor_precedes_stdin_and_preserves_explicit_disable(self):
        raw = json.dumps(self.payload).encode()
        for disabled in (False, True):
            clock = Clock()
            with mock.patch.object(cg.time, "monotonic", clock), \
                    mock.patch.object(sys, "stdin", Stream(raw, lambda: clock.advance(1.0))), \
                    mock.patch.object(cg, "console_write"), \
                    mock.patch.object(cg, "safe_dispatch", return_value={}) as dispatch:
                cg.command_hook(**({"budget_started_at": None} if disabled else {}))
            self.assertEqual(clock.now, 101.0)
            self.assertEqual(dispatch.call_args.kwargs["budget_started_at"], None if disabled else 100.0)

    def test_router_anchor_precedes_stdin_heavy_import_and_is_fresh_each_call(self):
        clock = Clock()
        seen = []
        raw = json.dumps({**self.payload, "prompt": "中文 🧪"}, ensure_ascii=False).encode()

        def main(**kwargs):
            seen.append((kwargs["budget_started_at"], sys.stdin.buffer.read()))
            return 0

        module = types.SimpleNamespace(main=main)
        loader = types.SimpleNamespace(exec_module=lambda _module: clock.advance(.8))
        spec = types.SimpleNamespace(loader=loader)
        for begin in (100.0, 200.0):
            clock.now = begin
            with mock.patch.object(router.time, "monotonic", clock), \
                    mock.patch.object(sys, "stdin", Stream(raw, lambda: clock.advance(.4))), \
                    mock.patch.object(sys, "stdout", Stream()), \
                    mock.patch.object(importlib.util, "spec_from_file_location", return_value=spec), \
                    mock.patch.object(importlib.util, "module_from_spec", return_value=module):
                with self.assertRaises(SystemExit) as caught:
                    router.main()
                self.assertEqual(caught.exception.code, 0)
        self.assertEqual(seen, [(100.0, raw), (200.0, raw)])

    def test_stdin_import_and_state_cost_reach_actual_core_deadline(self):
        clock = Clock()
        raw = json.dumps(self.payload).encode()
        module = types.SimpleNamespace(main=cg.main)
        loader = types.SimpleNamespace(exec_module=lambda _: clock.advance(2.0))

        @contextlib.contextmanager
        def lock(*_args, **_kwargs):
            yield

        stdout = Stream()
        with mock.patch.object(cg.time, "monotonic", clock), \
                mock.patch.object(sys, "stdin", Stream(raw, lambda: clock.advance(.4))), \
                mock.patch.object(sys, "stdout", stdout), \
                mock.patch.object(importlib.util, "spec_from_file_location", return_value=types.SimpleNamespace(loader=loader)), \
                mock.patch.object(importlib.util, "module_from_spec", return_value=module), \
                mock.patch.object(cg, "write_session_dir", return_value=self.session), \
                mock.patch.object(cg, "session_lock", side_effect=lock), \
                mock.patch.object(cg, "load_state", return_value=self.state), \
                mock.patch.object(cg, "save_state", side_effect=lambda *_: clock.advance(.1)), \
                mock.patch.object(cg, "write_recovery", side_effect=lambda *_: clock.advance(.1)), \
                mock.patch.object(cg, "cleanup_old_sessions") as cleanup:
            with self.assertRaises(SystemExit) as caught:
                router.main()
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(json.loads(stdout.buffer.getvalue()), {})
        self.assertAlmostEqual(clock.now, 102.6)
        self.assertAlmostEqual(cleanup.call_args.kwargs["deadline"], 102.65)

    def test_session_end_import_fallback_explicitly_disables_child_maintenance(self):
        raw = json.dumps(self.payload).encode()
        with mock.patch.object(importlib.util, "spec_from_file_location", side_effect=OSError("broken import")), \
                mock.patch.object(router, "_delegate_subprocess") as fallback:
            router._delegate(raw, budget_started_at=100.0)
        fallback.assert_called_once_with(raw, disable_maintenance=True)
        # Execute the real fallback bootstrap against an owned stand-in. It
        # must pass explicit None; omission deliberately fails this stand-in.
        (self.root / "context_guard.py").write_text(
            "import json,sys\n"
            "UNSET=object()\n"
            "def main(*,budget_started_at=UNSET):\n"
            "    assert budget_started_at is None\n"
            "    json.dump(json.load(sys.stdin),sys.stdout)\n"
            "    return 0\n", encoding="utf-8")
        stdout = Stream()
        with mock.patch.object(router, "_SCRIPT_DIR", str(self.root)), \
                mock.patch.object(sys, "stdout", stdout), mock.patch.object(sys, "stderr", Stream()):
            with self.assertRaises(SystemExit) as caught:
                router._delegate_subprocess(raw, disable_maintenance=True)
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(json.loads(stdout.buffer.getvalue()), self.payload)

    def test_early_session_end_route_keeps_main_python_floor(self):
        raw = json.dumps(self.payload).encode()
        stdout = Stream()
        loader = types.SimpleNamespace(exec_module=lambda _: None)
        with mock.patch.object(importlib.util, "spec_from_file_location", return_value=types.SimpleNamespace(loader=loader)), \
                mock.patch.object(importlib.util, "module_from_spec", return_value=types.SimpleNamespace(main=cg.main)), \
                mock.patch.object(cg.sys, "version_info", (3, 9, 18)), \
                mock.patch.object(sys, "stdout", stdout):
            with self.assertRaises(SystemExit) as caught:
                router._delegate(raw, budget_started_at=100.0)
        self.assertEqual(caught.exception.code, 2)
        self.assertIn(b"Python 3.10+ required", stdout.buffer.getvalue())

    def test_ordinary_pretool_still_allows_without_delegation_or_state(self):
        raw = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "git status --porcelain"}}).encode()
        stdout = Stream()
        with mock.patch.object(sys, "stdin", Stream(raw)), mock.patch.object(sys, "stdout", stdout), \
                mock.patch.object(router, "_delegate") as delegate:
            router.main()
        delegate.assert_not_called()
        self.assertEqual(json.loads(stdout.buffer.getvalue()), {})
        self.assertFalse(self.data.exists())

    def test_cold_session_end_does_not_load_pretool_classification_adapters(self):
        code = (
            "import json,sys\n"
            "from pathlib import Path\n"
            "blocked=('cg_actions','cg_codex_adapter','cg_protocol')\n"
            "for name in blocked: sys.modules[name]=None\n"
            "import cg_hook\n"
            "try: cg_hook.main()\n"
            "except SystemExit as exc: assert exc.code == 0, exc.code\n"
            "assert all(sys.modules[name] is None for name in blocked)\n"
            "import os\n"
            "state=json.loads((Path(os.environ['CONTEXT_GUARD_DATA_DIR'])/'sessions-v2/budget/state.json').read_bytes())\n"
            "assert state['session']['ended_at']\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], input=json.dumps(self.payload).encode(),
            env={**os.environ, "PYTHONPATH": str(SCRIPTS)}, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), {})

    def test_expired_cleanup_does_not_read_or_rewrite_existing_pending(self):
        names = [f"queued-{i:04d}" for i in range(4097)]
        cg._write_cleanup_state(self.data, "", names)
        before = {p.name: p.read_bytes() for p in (self.data / "sessions-v2/.locks").iterdir()}
        with mock.patch.object(cg.time, "monotonic", return_value=100.0), \
                mock.patch.object(cg, "_read_cleanup_state") as read:
            self.assertEqual(cg.cleanup_old_sessions(self.data, deadline=99.0), 0)
        read.assert_not_called()
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.data / "sessions-v2/.locks").iterdir()})

    def test_4097_pending_transaction_finishes_but_orphan_work_can_wait(self):
        names = [f"queued-{i:04d}" for i in range(4097)]
        orphan = cg._cleanup_pending_chunk_path(self.data, 999)
        cg.atomic_write_json(orphan, {"old": True})
        with mock.patch.object(cg.time, "monotonic", return_value=100.0):
            cg._write_cleanup_state(self.data, "", names, deadline=99.0)
        self.assertEqual(cg._read_cleanup_state(self.data), ("", names))
        self.assertTrue(orphan.exists())
        self.assertEqual(cg._CLEANUP_CURSOR_MAX_PENDING, 4096)
        self.assertEqual(cg._CLEANUP_CURSOR_MAX_CHUNKS, 1024)
        cg._write_cleanup_state(self.data, "", names)
        self.assertFalse(orphan.exists())

    def test_registered_partial_directory_progress_and_candidate_locks_stay_nonblocking(self):
        payload = {"hook_event_name": "UserPromptSubmit", "session_id": "expired", "cwd": str(self.root), "prompt": "fixture"}
        cg.dispatch(payload)
        candidate = self.data / "sessions-v2/expired"
        path = candidate / "state.json"
        state = json.loads(path.read_bytes())
        state["session"]["ended_at"] = "2000-01-01T00:00:00Z"
        state["content_hash"] = cg.state_content_hash(state)
        path.write_text(json.dumps(state), encoding="utf-8")
        bulk = candidate / "bulk"
        bulk.mkdir()
        for index in range(30):
            (bulk / f"file-{index:02d}").write_text("fixture", encoding="utf-8")
        clock = Clock()
        unlink = Path.unlink
        lock = cg.session_lock
        waits = []

        def slow_unlink(path, *args, **kwargs):
            result = unlink(path, *args, **kwargs)
            if path.parent == bulk:
                clock.advance(.2)
            return result

        @contextlib.contextmanager
        def recorded_lock(path, timeout, *, create_directory=True):
            waits.append((timeout, create_directory))
            with lock(path, timeout=timeout, create_directory=create_directory) as guard:
                yield guard

        with mock.patch.object(cg.time, "monotonic", clock), \
                mock.patch.object(Path, "unlink", slow_unlink), \
                mock.patch.object(cg, "session_lock", side_effect=recorded_lock):
            cg.cleanup_old_sessions(self.data, deadline=101.0)
        self.assertTrue((candidate / cg.CLEANUP_PARTIAL_MARKER).exists())
        self.assertLess(len(list(bulk.iterdir())), 30)
        self.assertGreater(len(list(bulk.iterdir())), 0)
        self.assertIn("expired", cg._read_cleanup_state(self.data)[1])
        self.assertTrue(waits and all(wait == 0.0 and create is False
                                     for wait, create in waits))
        cg.cleanup_old_sessions(self.data, deadline=cg.time.monotonic() + 1.0)
        self.assertFalse(candidate.exists())

    @unittest.skipIf(os.name == "nt", "POSIX launcher; Windows route uses the native wire suite")
    def test_posix_configured_and_path_keep_session_end_site_flags_and_unicode(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copyfile(SCRIPTS / "run_context_guard.sh", scripts / "run_context_guard.sh")
        (scripts / "context_guard.py").write_text("raise RuntimeError('wrong heavy entry')\n", encoding="utf-8")
        (scripts / "cg_hook.py").write_text(
            "import json,sys\n"
            "p=json.load(sys.stdin); p['no_site']=sys.flags.no_site\n"
            "json.dump(p,sys.stdout,ensure_ascii=False)\n", encoding="utf-8")
        bindir = self.root / "bin"
        bindir.mkdir()
        command = bindir / "python3.14"
        command.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + ' "$@"\n', encoding="utf-8")
        command.chmod(0o700)
        conf = Path(os.environ["CODEX_HOME"]) / "context-guard/interpreter.conf"
        conf.parent.mkdir(parents=True)
        for configured in (False, True):
            if configured:
                conf.write_text(sys.executable + "\n", encoding="utf-8")
            for event, no_site in (("SessionEnd", 0), ("PostToolUse", 1)):
                with self.subTest(configured=configured, event=event):
                    payload = {"hook_event_name": event, "prompt": "中文 🧪"}
                    env = {**os.environ, "PATH": str(bindir) + ":/usr/bin:/bin", "PYTHONIOENCODING": "utf-8"}
                    proc = subprocess.run(["/bin/sh", str(scripts / "run_context_guard.sh"), "hook", event],
                                          input=json.dumps(payload, ensure_ascii=False).encode(),
                                          capture_output=True, env=env, timeout=30)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertEqual(json.loads(proc.stdout), {**payload, "no_site": no_site})


if __name__ == "__main__":
    unittest.main()
