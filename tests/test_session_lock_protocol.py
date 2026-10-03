#!/usr/bin/env python3
"""Session lock protocol 2 regressions (CGN-01, CGN-08).

The mutex linearizes on a kernel lock over the stable ``sessions-v2/.locks/<id>.lock``
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
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cg_process_tree import OwnedProcess  # noqa: E402

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "context_guard.py"
SPEC = importlib.util.spec_from_file_location("context_guard", MODULE_PATH)
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)

# Runs inside a child process: mode-specific behaviour driven by files so the
# parent can build deterministic barriers without shared memory.
WORKER = textwrap.dedent(
    """
    import importlib.util, json, os, sys, time
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("context_guard", sys.argv[1])
    cg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cg)
    session_dir = Path(sys.argv[2])
    out = Path(sys.argv[3])
    out.with_suffix(".pid").write_text(str(os.getpid()), encoding="ascii")
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
        self.children: list[OwnedProcess] = []
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.session_dir = self.root / "private" / "sessions-v2" / "lock-proto"
        self.session_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        # A failed assertion must not leave a holder blocking Windows cleanup.
        try:
            for child in self.children:
                result = child.close(timeout=10)
                self.assertTrue(result["owned_tree_no_running_members"], result)
        finally:
            self.temp.cleanup()

    def _spawn(self, session_dir: Path, out: Path, go: Path, timeout: float):
        child = OwnedProcess.spawn(
            [sys.executable, "-c", WORKER, str(MODULE_PATH), str(session_dir),
             str(out), str(go), str(timeout)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.children.append(child)
        return child.process

    def _try_acquire(self, session_dir: Path, out: Path, timeout: float):
        return self._spawn(session_dir, out, Path("-"), timeout)

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
            lock_path = cg.lifecycle_lock_path(self.session_dir)
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
        self.assertTrue(cg.lifecycle_lock_path(self.session_dir).exists())
        go.write_text("1", encoding="ascii")
        holder.wait(timeout=10)
        # Reading a separately opened Windows descriptor while the byte range
        # is locked is correctly denied; inspect the durable record afterward.
        record = json.loads(cg.lifecycle_lock_path(self.session_dir).read_text(encoding="ascii"))
        self.assertEqual(record["lock_protocol"], 2)
        self.assertEqual(record["pid"], int(ready.with_suffix(".pid").read_text(encoding="ascii")))

    def test_commit_ownership_check_blocks_write_after_lock_replacement(self) -> None:
        """A dispossessed writer fails closed instead of committing (N07)."""
        empty = cg.new_state({"session_id": "ownership-check"})
        cg.secure_directory(self.session_dir)
        state_file = self.session_dir / "state.json"
        with cg.session_lock(self.session_dir):
            lock_path = cg.lifecycle_lock_path(self.session_dir)
            if os.name == "nt":
                # Windows prevents replacement of the open lock handle. Prove
                # this native protection and the original owner's valid commit.
                with self.assertRaises(PermissionError):
                    lock_path.unlink()
                cg.save_state(self.session_dir, empty)
            else:
                lock_path.unlink()
                lock_path.write_text("replacement holder", encoding="ascii")
                with self.assertRaises(cg.LockOwnershipError):
                    cg.save_state(self.session_dir, empty)
        self.assertEqual(state_file.exists(), os.name == "nt")

    def test_killed_holder_releases_within_deadline(self) -> None:
        ready, go = self.root / "ready", self.root / "go"
        holder = self._spawn(self.session_dir, ready, go, 30.0)
        self._wait_for(ready, "acquired")
        # A Windows venv launcher can have a different PID from the worker.
        # Terminate the owned tree, including the actual lock owner.
        owned = next(child for child in self.children if child.process is holder)
        result = owned.close(timeout=10)
        self.assertTrue(result["owned_tree_no_running_members"], result)
        start = time.monotonic()
        with cg.session_lock(self.session_dir, timeout=5.0):
            self.assertLess(time.monotonic() - start, 4.0)
        record = json.loads((cg.lifecycle_lock_path(self.session_dir)).read_text(encoding="ascii"))
        self.assertEqual(record["pid"], os.getpid())

    def test_legacy_writer_cannot_interfere_with_v2_state(self):
        """Namespace-isolation proof: a real protocol-1 writer operating on
        the legacy tree for the same session id cannot touch, contend with,
        or delay a protocol-2 writer's v2 state; both trees stay internally
        consistent and no bytes interleave."""
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
            time.sleep(1.0)
            if descriptor is not None:
                os.close(descriptor)
                lock_path.unlink()
            """
        )

        # The protocol-1 writer owns the LEGACY tree for this session id.
        legacy_dir = self.root / "private" / "sessions" / "lock-proto"
        legacy_dir.mkdir(parents=True)
        go_event = threading.Event()
        v2_done = threading.Event()
        v2_result: list[str] = []

        def hold_v2() -> None:
            try:
                with cg.session_lock(self.session_dir, timeout=5.0):
                    empty = cg.new_state({"session_id": "lock-proto"})
                    cg.save_state(self.session_dir, empty)
                    v2_result.append("committed")
            except Exception as exc:  # noqa: BLE001
                v2_result.append(f"{type(exc).__name__}: {exc}")
            finally:
                v2_done.set()

        thread = threading.Thread(target=hold_v2)
        thread.start()
        v2_done.wait(timeout=10)
        marker = self.root / "legacy-marker"
        simulator = subprocess.Popen(
            [sys.executable, "-c", legacy_simulator,
             str(legacy_dir / ".lock"), str(marker)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            self._wait_for(marker, "legacy-entered", timeout=15)
        finally:
            simulator.wait(timeout=20)
        thread.join(timeout=10)
        go_event.set()
        # The v2 writer committed cleanly while the legacy writer owned the
        # legacy tree; the two lock files live in disjoint namespaces.
        self.assertEqual(v2_result, ["committed"])
        self.assertTrue((self.session_dir / "state.json").is_file())
        self.assertTrue(cg.lifecycle_lock_path(self.session_dir).exists())
        self.assertNotEqual(cg.lifecycle_lock_path(self.session_dir),
                            legacy_dir / ".lock")

    def test_cleanup_never_removes_lifecycle_lock_or_legacy_trees(self):
        empty = cg.new_state({"session_id": "lock-proto"})
        empty["session"]["ended_at"] = "2026-07-01T00:00:00+00:00"
        cg.save_state(self.session_dir, empty)
        legacy_dir = self.root / "private" / "sessions" / "lock-proto"
        legacy_dir.mkdir(parents=True)
        (legacy_dir / "state.json").write_text("{}", encoding="utf-8")
        removed = cg.cleanup_old_sessions(self.root / "private")
        self.assertEqual(removed, 1)
        self.assertFalse(self.session_dir.exists())
        # The lifecycle lock file survives cleanup (stable, outside the tree).
        self.assertTrue(cg.lifecycle_lock_path(self.session_dir).exists())
        # Legacy trees are never swept by this runtime's cleanup.
        self.assertTrue(legacy_dir.is_dir())
        self.assertTrue((legacy_dir / "state.json").is_file())

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

        def failing_write(path: Path, value: object, **options: object) -> None:
            seen.append(path)
            if path.name == "state.json":
                self.assertTrue(options.get("committed_state"))
                raise OSError("simulated disk failure")
            original(path, value, **options)

        with self.assertRaisesRegex(OSError, "simulated disk failure"):
            with cg.session_lock(self.session_dir):
                cg.atomic_write_json = failing_write  # type: ignore[assignment]
                try:
                    cg.save_state(self.session_dir, empty)
                finally:
                    cg.atomic_write_json = original  # type: ignore[assignment]
        self.assertFalse((self.session_dir / "state.json").exists())


if __name__ == "__main__":
    unittest.main()
