#!/usr/bin/env python3
"""Phase-2 focused tests: import-poison, three-state classification, router
routes, delegate wire contract.

The production fast path lives in cg_hook.py (routed from
run_context_guard.sh / run-context-guard.ps1). Only provably SAFE
PreToolUse calls take it; CANDIDATE and AMBIGUOUS both delegate to the
heavy core. context_guard.py is the byte-compatible heavy core: it has NO
fast path and NO dependency on cg_actions/cg_protocol.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
ENTRY = SCRIPTS / "context_guard.py"
CG_HOOK = SCRIPTS / "cg_hook.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import cg_actions  # noqa: E402,F401 -- sys.path side effect


def _poisoned_import(poisoned, code):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SCRIPTS)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    poison_lines = "".join("sys.modules[%r] = None\n" % n for n in poisoned)
    full = "import sys\n" + poison_lines + code
    r = subprocess.run(
        [sys.executable, "-c", full],
        capture_output=True, text=True, env=env, timeout=30, cwd=str(REPO),
    )
    return r.returncode, r.stdout + r.stderr


class _BytesStream(io.BytesIO):
    """Stands in for sys.stdin/stdout/stderr in-process: accepts both str
    (text layer, e.g. print) and bytes (.buffer layer) writes."""

    @property
    def buffer(self):
        return self

    def write(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        return super().write(data)


class _FakeSubprocessModule:
    """Stands in for the stdlib subprocess module: cg_hook imports
    subprocess lazily inside _delegate, so tests inject this via
    sys.modules and observe every run() call."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.result


class ImportPoisonTests(unittest.TestCase):
    def test_cg_actions_importable_without_heavy_modules(self):
        rc, out = _poisoned_import(
            {"cg_ledger": None, "cg_release_policy": None, "context_guard": None},
            "import cg_actions\n"
            "assert hasattr(cg_actions, 'classify_pre_tool_state')\n"
            "assert hasattr(cg_actions, 'classify_pre_tool_action')\n"
            "print('OK')",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("OK", out)

    def test_context_guard_importable_without_heavy_modules(self):
        rc, out = _poisoned_import(
            {"cg_ledger": None, "cg_release_policy": None},
            "import context_guard\nassert hasattr(context_guard, 'dispatch')\nprint('OK')",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("OK", out)

    def test_cg_hook_importable_without_heavy_modules(self):
        rc, out = _poisoned_import(
            {"cg_ledger": None, "cg_release_policy": None, "context_guard": None},
            "import cg_hook\nassert callable(cg_hook.main)\nprint('OK')",
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("OK", out)


class HeavyCoreCompatTests(unittest.TestCase):
    def test_heavy_core_has_no_fast_path_dependency(self):
        """context_guard.py must not import the router fast-path pair
        (cg_actions / cg_codex_adapter / cg_hook); the fast path lives in
        cg_hook only. Since Phase 3 the heavy core DOES consume the protocol
        layer cg_stop3 -> cg_protocol on its Stop/migration/post-tool paths
        (frozen plan section 4.3 wiring), which is the sanctioned one-way
        direction cg_protocol <- cg_stop3 <- context_guard."""
        heavy_source = ENTRY.read_text(encoding="utf-8")
        self.assertNotIn("cg_actions", heavy_source)
        self.assertNotIn("cg_codex_adapter", heavy_source)
        self.assertNotIn("cg_hook", heavy_source)
        self.assertIn("cg_stop3", heavy_source)


# (description, tool_name, tool_input, expected_state)
CLASSIFICATION_TABLE = [
    # -- positive: provably safe
    ("safe shell echo", "bash", {"command": "echo hello"}, cg_actions.STATE_SAFE),
    ("safe shell read-only git", "bash", {"command": "git status --porcelain"}, cg_actions.STATE_SAFE),
    ("safe shell test runner", "shell", {"command": "python -m pytest -q"}, cg_actions.STATE_SAFE),
    ("safe read tool", "read", {"path": "docs/x.md"}, cg_actions.STATE_SAFE),
    ("safe grep tool", "grep", {"pattern": "needle"}, cg_actions.STATE_SAFE),
    ("safe mcp exec shell", "mcp_exec_command", {"command": "echo hi"}, cg_actions.STATE_SAFE),
    # -- negative: recognized mutation surfaces -> candidate
    ("mcp github create_release", "mcp__github__create_release", {"tag": "v0.12.0"}, cg_actions.STATE_CANDIDATE),
    ("mcp github update_release", "mcp__github__update_release", {"release_id": "1"}, cg_actions.STATE_CANDIDATE),
    ("mcp github delete_release", "mcp__github__delete_release", {"release_id": "1"}, cg_actions.STATE_CANDIDATE),
    ("mcp package publish", "mcp__pypi__publish_package", {}, cg_actions.STATE_CANDIDATE),
    ("mcp package yank", "mcp__pypi__yank_package", {}, cg_actions.STATE_CANDIDATE),
    ("apply_patch", "apply_patch", {"patch": "*** Begin Patch"}, cg_actions.STATE_CANDIDATE),
    ("mcp apply_patch", "mcp__edit__apply_patch", {}, cg_actions.STATE_CANDIDATE),
    ("shell git tag", "bash", {"command": "git tag v1.2.3"}, cg_actions.STATE_CANDIDATE),
    ("shell npm publish", "bash", {"command": "npm publish"}, cg_actions.STATE_CANDIDATE),
    ("shell gh release create", "bash", {"command": "gh release create v1 --notes x"}, cg_actions.STATE_CANDIDATE),
    ("shell bare git push", "bash", {"command": "git push"}, cg_actions.STATE_CANDIDATE),
    # -- Phase 4: text-position command words, dry-run simulation, and
    #    unknown non-mutation tools are provably safe (empty object fast
    #    path, zero heavy-core imports)
    ("text echo tag", "bash", {"command": "echo git tag v1.2.3"}, cg_actions.STATE_SAFE),
    ("search read publish", "bash", {"command": "rg -n npm publish README.md"}, cg_actions.STATE_SAFE),
    ("dry-run npm publish", "bash", {"command": "npm publish --dry-run"}, cg_actions.STATE_SAFE),
    ("dry-run git push", "bash", {"command": "git push --dry-run origin main"}, cg_actions.STATE_SAFE),
    ("read-only gh release view", "bash", {"command": "gh release view v1.2.3"}, cg_actions.STATE_SAFE),
    ("unknown mcp method", "mcp__whatever__anything", {}, cg_actions.STATE_SAFE),
    ("unknown tool", "totally_unknown_tool", {}, cg_actions.STATE_SAFE),
    # -- negative: structurally unreliable input -> ambiguous
    ("shell missing command", "bash", {}, cg_actions.STATE_AMBIGUOUS),
    ("shell tool_input not dict", "bash", "echo hello", cg_actions.STATE_AMBIGUOUS),
    ("shell command not str", "bash", {"command": 123}, cg_actions.STATE_AMBIGUOUS),
    ("shell command empty", "bash", {"command": "   "}, cg_actions.STATE_AMBIGUOUS),
    ("shell unterminated quote", "bash", {"command": 'echo "oops'}, cg_actions.STATE_AMBIGUOUS),
    ("shell backtick push", "bash", {"command": "git push `echo x`"}, cg_actions.STATE_CANDIDATE),
    ("runner envelope xargs", "bash", {"command": "xargs git push origin main"}, cg_actions.STATE_AMBIGUOUS_CANDIDATE),
    ("runner envelope find", "bash", {"command": "find . -name '*.py' -exec npm publish {} +"}, cg_actions.STATE_AMBIGUOUS_CANDIDATE),
    ("tool_name missing", None, {}, cg_actions.STATE_AMBIGUOUS),
    ("tool_name not str", 123, {}, cg_actions.STATE_AMBIGUOUS),
    ("tool_name blank", "   ", {"command": "echo"}, cg_actions.STATE_AMBIGUOUS),
]


class ClassificationTableTests(unittest.TestCase):
    def test_classification_table(self):
        for description, tool_name, tool_input, expected in CLASSIFICATION_TABLE:
            with self.subTest(description):
                self.assertEqual(
                    cg_actions.classify_pre_tool_state(tool_name, tool_input),
                    expected,
                )


class _RouterHarness(unittest.TestCase):
    """Shared in-process router harness with pinned streams and data dir."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp.name) / "private"
        self.data_dir.mkdir(parents=True)
        self.cwd = Path(self.temp.name) / "cwd"
        self.cwd.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def _run_router(self, raw_stdin: bytes):
        """Run cg_hook.main() in-process with pinned streams, stdin bytes,
        and CONTEXT_GUARD_DATA_DIR; returns (exit_code, stdout, stderr)."""
        import cg_hook

        stdin = _BytesStream(raw_stdin)
        stdout = _BytesStream()
        stderr = _BytesStream()
        with mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.data_dir)}
        ), mock.patch.object(sys, "stdin", stdin), mock.patch.object(
            sys, "stdout", stdout
        ), mock.patch.object(sys, "stderr", stderr):
            try:
                cg_hook.main()
                rc = 0
            except SystemExit as exc:
                rc = exc.code if isinstance(exc.code, int) else 0
        return rc, stdout.getvalue(), stderr.getvalue()

    def _payload_bytes(
        self,
        tool_name=None,
        tool_input=None,
        session_id="rt",
        canonical=True,
        event_name="PreToolUse",
    ):
        payload = {
            "session_id": session_id,
            "cwd": str(self.cwd),
            "tool_name": tool_name,
            "tool_input": tool_input,
        }
        if canonical:
            payload["hook_event_name"] = event_name
        else:
            payload["event"] = event_name
        return json.dumps(payload).encode("utf-8")


class RouterRouteTableTests(_RouterHarness):
    """Every classification row must route through cg_hook exactly as the
    three-state contract demands: SAFE → {} with zero subprocess; CANDIDATE
    and AMBIGUOUS → delegate to the heavy core (observed via a fake
    subprocess sentinel, so no heavy run is needed to prove the route).

    The routed state is derived through the SAME normalization the router
    uses (cg_codex_adapter coerces tool_name to str before classification),
    so unit-level AMBIGUOUS rows whose payloads normalize to usable strings
    route by their normalized class."""

    SENTINEL_STDOUT = b"HEAVY-STDOUT"
    SENTINEL_STDERR = b"HEAVY-STDERR"
    SENTINEL_RC = 7

    def _delegated_route(self, raw: bytes):
        fake = _FakeSubprocessModule(
            subprocess.CompletedProcess(
                args=[],
                stdout=self.SENTINEL_STDOUT,
                stderr=self.SENTINEL_STDERR,
                returncode=self.SENTINEL_RC,
            )
        )
        with mock.patch.dict(sys.modules, {"subprocess": fake}):
            rc, out, err = self._run_router(raw)
        return fake, rc, out, err

    def _routed_state(self, raw: bytes):
        """The three-state the router ACTUALLY acts on: adapter-normalized
        tool name/input, then classify_pre_tool_state."""
        from cg_codex_adapter import codex_to_protocol_event
        from cg_protocol import ProtocolEventType, ProtocolToolCall

        payload = json.loads(raw.decode("utf-8"))
        proto = codex_to_protocol_event(payload)
        if (
            proto is None
            or proto.event_type != ProtocolEventType.TOOL_PRE_EXECUTE
            or not isinstance(proto.payload, ProtocolToolCall)
        ):
            return None  # delegate: unresolvable
        return cg_actions.classify_pre_tool_state(
            proto.payload.tool_name, proto.payload.tool_input
        )

    def test_route_table_safe_rows_take_fast_path(self):
        """SAFE and generic-AMBIGUOUS rows both take the silent fast path:
        no subprocess, no heavy import, no private-state I/O."""
        for description, tool_name, tool_input, _expected in CLASSIFICATION_TABLE:
            with self.subTest(description):
                raw = self._payload_bytes(tool_name, tool_input, session_id="rt-safe")
                routed = self._routed_state(raw)
                if routed not in {cg_actions.STATE_SAFE, cg_actions.STATE_AMBIGUOUS}:
                    continue
                fake, rc, out, err = self._delegated_route(raw)
                self.assertEqual(rc, 0)
                self.assertEqual(out.strip(), b"{}")
                self.assertEqual(err, b"")
                self.assertEqual(fake.calls, [])
                self.assertEqual(list(self.data_dir.rglob("*")), [])

    def test_route_table_candidate_and_ambiguous_rows_delegate(self):
        """CANDIDATE and the runner envelope delegate to the heavy core."""
        for description, tool_name, tool_input, _expected in CLASSIFICATION_TABLE:
            with self.subTest(description):
                raw = self._payload_bytes(tool_name, tool_input, session_id="rt-deleg")
                routed = self._routed_state(raw)
                if routed not in {cg_actions.STATE_CANDIDATE, cg_actions.STATE_AMBIGUOUS_CANDIDATE}:
                    continue
                fake, rc, out, err = self._delegated_route(raw)
                self.assertEqual(rc, self.SENTINEL_RC)
                self.assertEqual(out, self.SENTINEL_STDOUT)
                self.assertEqual(err, self.SENTINEL_STDERR)
                self.assertEqual(len(fake.calls), 1)
                args, kwargs = fake.calls[0]
                self.assertEqual(os.path.basename(args[0][1]), "context_guard.py")
                self.assertEqual(args[0][-1], "hook")
                # The ORIGINAL stdin bytes must reach the heavy core untouched.
                self.assertEqual(kwargs.get("input"), raw)

    def test_alias_and_broken_payloads_delegate(self):
        """Without the canonical hook_event_name — and for unknown events,
        non-dict payloads, and empty objects — the router must delegate,
        never fast-path."""
        raw_alias = self._payload_bytes(
            "bash", {"command": "echo hello"}, canonical=False
        )
        cases = [
            ("event alias only", raw_alias),
            ("unknown event", self._payload_bytes("bash", {"command": "echo"}, event_name="TotallyUnknown")),
            ("empty object", b"{}"),
            ("json array payload", b'[{"hook_event_name": "PreToolUse"}]'),
            ("non-utf8 bytes", b"\xff\xfe not-json-at-all"),
        ]
        for description, raw in cases:
            with self.subTest(description):
                fake, rc, out, err = self._delegated_route(raw)
                self.assertEqual(len(fake.calls), 1, description)
                self.assertEqual(out, self.SENTINEL_STDOUT, description)
                self.assertEqual(fake.calls[0][1].get("input"), raw)


class RouterFastPathTests(_RouterHarness):
    def test_non_candidate_pre_tool_use_fast_path(self):
        rc, out, err = self._run_router(
            self._payload_bytes("bash", {"command": "echo hello"}, session_id="fp-echo")
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), b"{}")
        self.assertEqual(err, b"")
        self.assertEqual(list(self.data_dir.rglob("*")), [])

    def test_non_candidate_never_loads_heavy_core(self):
        raw = self._payload_bytes(
            "bash", {"command": "git status --porcelain"}, session_id="fp-git"
        )
        with mock.patch.dict(
            sys.modules,
            {"context_guard": None, "cg_ledger": None, "cg_release_policy": None},
        ):
            rc, out, err = self._run_router(raw)
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), b"{}")
        self.assertEqual(list(self.data_dir.rglob("*")), [])

    def test_candidate_pre_tool_use_delegates_to_heavy_core(self):
        """A candidate reaches the heavy core (state files prove the trip).
        Phase 4: this fresh session never activated a profile, so the
        heavy decision is the silent empty-object allow."""
        rc, out, err = self._run_router(
            self._payload_bytes("bash", {"command": "git tag v1.2.3"}, session_id="fp-tag")
        )
        self.assertEqual(rc, 0)
        decision = json.loads(out.decode("utf-8"))
        self.assertEqual(decision, {})
        self.assertTrue(list(self.data_dir.rglob("*")))

    def test_delegate_wire_contract(self):
        """stdout/stderr must stay separated and the exit code must
        propagate; the original stdin bytes must reach the heavy core
        byte-for-byte."""
        raw = self._payload_bytes(
            "bash", {"command": "git tag v9.9.9"}, session_id="fp-wire"
        )
        fake = _FakeSubprocessModule(
            subprocess.CompletedProcess(
                args=[], stdout=b"HEAVY-STDOUT", stderr=b"HEAVY-STDERR",
                returncode=7,
            )
        )
        with mock.patch.dict(sys.modules, {"subprocess": fake}):
            rc, out, err = self._run_router(raw)
        self.assertEqual(rc, 7)
        self.assertEqual(out, b"HEAVY-STDOUT")
        self.assertEqual(err, b"HEAVY-STDERR")
        args, kwargs = fake.calls[0]
        self.assertEqual(os.path.basename(args[0][1]), "context_guard.py")
        self.assertEqual(args[0][-1], "hook")
        self.assertEqual(kwargs.get("input"), raw)


class WireCompatTests(unittest.TestCase):
    def setUp(self):
        # Stateful events (SessionStart/Stop/...) must never touch the real
        # default data root; pin CONTEXT_GUARD_DATA_DIR to a temp dir.
        self.temp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp.name) / "private"
        self.data_dir.mkdir(parents=True)
        self.cwd = Path(self.temp.name) / "cwd"
        self.cwd.mkdir()
        self.env = mock.patch.dict(
            os.environ, {"CONTEXT_GUARD_DATA_DIR": str(self.data_dir)}
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_all_nine_events_dispatch(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("cg_wire", ENTRY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for event in [
            "UserPromptSubmit", "PreToolUse", "PostToolUse",
            "PreCompact", "SessionStart", "SessionEnd",
            "SubagentStart", "SubagentStop", "Stop",
        ]:
            payload = {
                "hook_event_name": event,
                "session_id": "wire-" + event,
                "cwd": str(self.cwd),
                "turn_id": "t1",
            }
            if event == "UserPromptSubmit":
                payload["prompt"] = "test"
            elif event == "PreToolUse":
                payload["tool_name"] = "bash"
                payload["tool_input"] = {"command": "echo t"}
            elif event == "PostToolUse":
                payload["tool_name"] = "bash"
                payload["tool_input"] = {"command": "echo t"}
                payload["tool_response"] = {"exit_code": 0}
            elif event == "Stop":
                payload["last_assistant_message"] = "done"
            result = mod.dispatch(payload)
            self.assertIsInstance(result, dict)
        # Positive isolation evidence: stateful events landed in the pinned
        # temp data root rather than the real default data root.
        self.assertTrue(any(self.data_dir.rglob("*")))

    def test_pre_tool_use_exception_fail_policy(self):
        """0.13 event-level fail policy: ordinary business candidates stay
        fail-open — a Guard-internal failure is never an authorization
        question, and (with no adopted release contract on disk) no state
        can strip tool capability. The runner envelope stays fail-open as
        before. The adopted-contract fail-closed branch is covered by the
        0.13 default-path suite."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("cg_wire2", ENTRY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with mock.patch.object(mod, "dispatch", side_effect=RuntimeError("test")):
            fail_open = mod.safe_dispatch(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "bash",
                    "tool_input": {"command": "git tag v1.2.3"},
                }
            )
        self.assertEqual(fail_open, {})
        with mock.patch.object(mod, "dispatch", side_effect=RuntimeError("test")):
            fail_open = mod.safe_dispatch(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "bash",
                    "tool_input": {"command": "xargs git push origin main"},
                }
            )
        self.assertEqual(fail_open, {})

    def test_malformed_payload_fail_policy(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("cg_wire3", ENTRY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        result = mod.safe_dispatch({"hook_event_name": "Unknown"})
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
