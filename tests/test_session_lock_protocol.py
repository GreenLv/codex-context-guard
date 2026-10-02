#!/usr/bin/env python3
"""Session lock protocol 2 regressions (CGN-01, CGN-08).

The mutex linearizes on a kernel lock over the stable ``<session>/.lock``
inode, never on file age or path existence. Contention tests use real child
processes and filesystem barriers, not monkeypatched ideal states. The
Windows byte-range semantics (``msvcrt.locking``) are implemented behind the
same helpers but need native Windows confirmation; POSIX-only observations
are marked explicitly.
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)

# Runs inside a child process: mode-specific behaviour driven by files so the
# parent can build deterministic barriers without shared memory.
WORKER = textwrap.dedent(
    """
    import importlib.util, json, sys, time
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("context_guard", sys.argv[1])
    cg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cg)
    session_dir = Path(sys.argv[2])
    out = Path(sys.argv[3])
    go = Path(sys.argv[4])
    timeout = float(sys.argv[5])
    try:
        with cg.session_lock(session_dir, timeout=timeout):
            out.write_text("acquired", encoding="ascii")
            if go.name == "-":
                out.write_text("released", encoding="ascii")
                raise SystemExit(0)
            deadline = time.monotonic() + 15
            while not go.exists():
                if time.monotonic() > deadline:
                    out.write_text("barrier-expired", encoding="ascii")
                    raise SystemExit(1)
                time.sleep(0.01)
        out.write_text("released", encoding="ascii")
    except TimeoutError as exc:
        out.write_text("TimeoutError", encoding="ascii")
    except Exception as exc:  # noqa: BLE001
        out.write_text(type(exc).__name__, encoding="ascii")
        raise SystemExit(1)
    """
)


class SessionLockProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.session_dir = self.root / "private" / "sessions" / "lock-proto"
        self.session_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _spawn(self, session_dir: Path, out: Path, go: Path, timeout: float):
        return subprocess.Popen(
            [sys.executable, "-c", WORKER, str(MODULE_PATH), str(session_dir),
             str(out), str(go), str(timeout)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _try_acquire(self, session_dir: Path, out: Path, timeout: float):
        return subprocess.Popen(
            [sys.executable, "-c", WORKER, str(MODULE_PATH), str(session_dir),
             str(out), "-", str(timeout)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _wait_for(self, path: Path, value: str, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if path.read_text(encoding="ascii") == value:
                    return
            except FileNotFoundError:
                pass
            time.sleep(0.01)
        self.fail(f"child never reported {value!r}: {path}")

    def test_two_processes_never_hold_lock_simultaneously(self) -> None:
        ready, go = self.root / "ready", self.root / "go"
        holder = self._spawn(self.session_dir, ready, go, 5.0)
        try:
            self._wait_for(ready, "acquired")
            contender_out = self.root / "contender"
            contender = self._try_acquire(self.session_dir, contender_out, 0.5)
            contender.wait(timeout=10)
            self.assertEqual(contender_out.read_text(encoding="ascii"),
                             "TimeoutError")
        finally:
            go.write_text("1", encoding="ascii")
            holder.wait(timeout=10)
        self._wait_for(ready, "released")
        # A stable lock file remains; a later writer acquires normally.
        contender_out = self.root / "contender2"
        contender = self._try_acquire(self.session_dir, contender_out, 5.0)
        contender.wait(timeout=10)
        self.assertIn(contender_out.read_text(encoding="ascii"),
                      {"acquired", "released"})

    def test_aged_lock_file_is_never_stolen_from_live_holder(self) -> None:
        """CGN-01 regression: old code unlinked a 31s-old lock and entered."""
        ready, go = self.root / "ready", self.root / "go"
        holder = self._spawn(self.session_dir, ready, go, 5.0)
        try:
            self._wait_for(ready, "acquired")
            lock_path = self.session_dir / ".lock"
            aged = time.time() - 31
            os.utime(lock_path, (aged, aged))
            contender_out = self.root / "contender"
            contender = self._spawn(self.session_dir, contender_out,
                                    self.root / "unused", 1.0)
            contender.wait(timeout=10)
            self.assertEqual(contender_out.read_text(encoding="ascii"),
                             "TimeoutError")
        finally:
            go.write_text("1", encoding="ascii")
            holder.wait(timeout=10)

    def test_lock_file_persists_with_owner_record(self) -> None:
        ready, go = self.root / "ready", self.root / "go"
        holder = self._spawn(self.session_dir, ready, go, 5.0)
        self._wait_for(ready, "acquired")
        record = json.loads((self.session_dir / ".lock").read_text(encoding="ascii"))
        self.assertEqual(record["lock_protocol"], 2)
        go.write_text("1", encoding="ascii")
        holder.wait(timeout=10)
        self.assertTrue((self.session_dir / ".lock").exists())

    def test_commit_ownership_check_blocks_write_after_lock_replacement(self) -> None:
        """A dispossessed writer fails closed instead of committing (N07)."""
        empty = cg.new_state({"session_id": "ownership-check"})
        cg.secure_directory(self.session_dir)
        state_file = self.session_dir / "state.json"
        with cg.session_lock(self.session_dir):
            lock_path = self.session_dir / ".lock"
            lock_path.unlink()
            lock_path.write_text("replacement holder", encoding="ascii")
            with self.assertRaises(cg.LockOwnershipError):
                cg.save_state(self.session_dir, empty)
        self.assertFalse(state_file.exists())

    def test_killed_holder_releases_within_deadline(self) -> None:
        ready, go = self.root / "ready", self.root / "go"
        holder = self._spawn(self.session_dir, ready, go, 30.0)
        self._wait_for(ready, "acquired")
        holder.send_signal(signal.SIGKILL)
        holder.wait(timeout=10)
        start = time.monotonic()
        with cg.session_lock(self.session_dir, timeout=5.0):
            self.assertLess(time.monotonic() - start, 4.0)
        record = json.loads((self.session_dir / ".lock").read_text(encoding="ascii"))
        self.assertEqual(record["pid"], os.getpid())

    def test_fresh_legacy_record_is_refused(self) -> None:
        lock_path = self.session_dir / ".lock"
        lock_path.write_text(f"{os.getpid()} {time.time()}", encoding="ascii")
        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            with cg.session_lock(self.session_dir, timeout=2.0):
                pass
        self.assertLess(time.monotonic() - start, 2.0)
        # The refuse path must not overwrite the legacy record.
        self.assertTrue(
            cg.LEGACY_LOCK_CONTENT_RE.fullmatch(
                lock_path.read_text(encoding="ascii").strip()
            )
        )

    def test_aged_legacy_record_is_taken_over(self) -> None:
        lock_path = self.session_dir / ".lock"
        lock_path.write_text(f"{os.getpid()} {time.time()}", encoding="ascii")
        aged = time.time() - 31
        os.utime(lock_path, (aged, aged))
        with cg.session_lock(self.session_dir, timeout=2.0):
            record = json.loads(lock_path.read_text(encoding="ascii"))
            self.assertEqual(record["lock_protocol"], 2)

    def test_legacy_sabotage_cannot_commit_protocol2_state(self) -> None:
        """POSIX observation of the declared old->new boundary.

        A protocol-1 simulator (the exact old algorithm) steals the lock file
        of a suspended protocol-2 holder; the holder's state write must fail
        closed. Old code committed successfully here.
        """
        if os.name == "nt":
            self.skipTest("POSIX unlink semantics required (Windows pending)")
        legacy_simulator = textwrap.dedent(
            """
            import os, sys, time
            from pathlib import Path
            lock_path = Path(sys.argv[1])
            marker = Path(sys.argv[2])
            deadline = time.monotonic() + 15
            descriptor = None
            while descriptor is None and time.monotonic() < deadline:
                try:
                    descriptor = os.open(str(lock_path),
                                         os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    os.write(descriptor, b"legacy")
                except (FileExistsError, PermissionError):
                    try:
                        if time.time() - lock_path.stat().st_mtime > 30:
                            lock_path.unlink()
                            continue
                    except FileNotFoundError:
                        pass
                    time.sleep(0.02)
            marker.write_text("legacy-entered", encoding="ascii")
            time.sleep(2.0)
            if descriptor is not None:
                os.close(descriptor)
                lock_path.unlink()
            """
        )
        ready, go = self.root / "ready", self.root / "go"
        go_event = threading.Event()
        holder_ready = threading.Event()
        holder_error: list[str] = []
        holder_done = threading.Event()

        def hold() -> None:
            try:
                with cg.session_lock(self.session_dir, timeout=5.0):
                    holder_ready.set()
                    self.assertTrue(go_event.wait(timeout=15))
                    empty = cg.new_state({"session_id": "sabotage"})
                    try:
                        cg.save_state(self.session_dir, empty)
                        holder_error.append("save_state committed after takeover")
                    except cg.LockOwnershipError:
                        pass
            finally:
                holder_done.set()

        thread = threading.Thread(target=hold)
        thread.start()
        self.assertTrue(holder_ready.wait(timeout=10))
        lock_path = self.session_dir / ".lock"
        aged = time.time() - 31
        os.utime(lock_path, (aged, aged))
        marker = self.root / "legacy-marker"
        simulator = subprocess.Popen(
            [sys.executable, "-c", legacy_simulator, str(lock_path), str(marker)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            self._wait_for(marker, "legacy-entered", timeout=15)
        finally:
            go_event.set()
            thread.join(timeout=20)
            simulator.wait(timeout=20)
        self.assertEqual(holder_error, [])
        self.assertFalse((self.session_dir / "state.json").exists())

    def test_lock_wait_respects_small_budget_under_contention(self) -> None:
        ready, go = self.root / "ready", self.root / "go"
        holder = self._spawn(self.session_dir, ready, go, 5.0)
        self._wait_for(ready, "acquired")
        start = time.monotonic()
        try:
            with cg.session_lock(self.session_dir, timeout=1.2):
                self.fail("contended acquisition must not succeed")
        except TimeoutError:
            pass
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2.0)
        go.write_text("1", encoding="ascii")
        holder.wait(timeout=10)

    def test_save_failure_leaves_no_success_state(self) -> None:
        empty = cg.new_state({"session_id": "save-failure"})
        cg.secure_directory(self.session_dir)
        original = cg.atomic_write_json
        seen: list[Path] = []

        def failing_write(path: Path, value: object) -> None:
            seen.append(path)
            if path.name == "state.json":
                raise OSError("simulated disk failure")
            original(path, value)

        with self.assertRaises(OSError):
            with cg.session_lock(self.session_dir):
                cg.atomic_write_json = failing_write  # type: ignore[assignment]
                try:
                    cg.save_state(self.session_dir, empty)
                finally:
                    cg.atomic_write_json = original  # type: ignore[assignment]
        self.assertFalse((self.session_dir / "state.json").exists())


if __name__ == "__main__":
    unittest.main()
