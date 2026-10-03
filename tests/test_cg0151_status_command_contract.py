"""CGI-20261003 checkpoint-status contract regression (CG-0151 D2).

The CLI subcommand and the PostToolUse recognition path share one explicit,
bounded option contract. These tests exercise real CLI subprocesses and the
Hook dispatch chain the same way the canonical incident reproducer does;
recognition never depends on a forged exit code.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

from tests.test_cg122_p0_counterexamples import P0Harness, cg


def status_command(harness: P0Harness, turn: str, options: list[str], *,
                   windows: bool = False,
                   script: Path | None = None,
                   executable: str | None = None,
                   data_dir: Path | None = None,
                   session: str = "p0",
                   token: str = "p0token") -> str:
    argv = [
        executable or sys.executable,
        str(script or Path(cg.__file__).resolve()),
        "checkpoint-status",
        "--data-dir", str(data_dir or harness.root / "private"),
        "--session-id", session,
        "--turn-id", turn,
        "--token", token,
        *options,
    ]
    return cg.shell_join(argv)


class StatusCommandContractTests(P0Harness):
    def ready(self):
        self.activate()
        self.prompt("请核对示例诊断结果。")
        state = self.state()
        self.turn = state["completion_attempt"]["turn_id"]
        return state

    def post(self, command: str, *, exit_code: int = 0) -> dict:
        return self.dispatch(
            "PostToolUse", tool_name="shell",
            tool_input={"command": command}, turn_id=self.turn,
            tool_response={"exit_code": exit_code},
        )

    def cli(self, options: list[str]) -> subprocess.CompletedProcess:
        argv = [
            sys.executable, str(Path(cg.__file__).resolve()),
            "checkpoint-status", "--data-dir", str(self.root / "private"),
            "--session-id", "p0", "--turn-id", self.turn,
            "--token", "p0token", *options,
        ]
        return subprocess.run(argv, capture_output=True, text=True,
                              check=False)

    # -- C01: exact mandatory bindings, CLI and Hook agree ---------------
    def test_c01_exact_mandatory_bindings_accepted_by_cli_and_hook(self):
        self.ready()
        completed = self.cli([])
        self.assertEqual(completed.returncode, 0, completed.stderr)
        json.loads(completed.stdout)
        command = status_command(self, self.turn, [])
        self.assertTrue(cg.is_exact_checkpoint_status_command(
            self.state(), {"tool_name": "shell",
                           "tool_input": {"command": command},
                           "turn_id": self.turn}))
        self.assertEqual(self.post(command), {})

    # -- C02: documented diagnostic options, orders and combinations -----
    def test_c02_supported_options_and_orders_accepted(self):
        self.ready()
        cases = [
            ["--commands"],
            ["--full"],
            ["--item", "R001"],
            ["--after-revision", "rev-1"],
            ["--after-revision", "rev-1", "--commands"],
            ["--full", "--after-revision", "rev-2"],
            ["--item", "R001", "--after-revision", "rev-3"],
            ["--commands", "--after-revision", "rev-4"],
        ]
        for index, options in enumerate(cases):
            with self.subTest(options=options):
                session = f"c02-{index}"
                self.activate(session)
                self.prompt("请核对示例诊断结果。", session)
                turn = self.state(session)["completion_attempt"]["turn_id"]
                command = status_command(self, turn, options, session=session)
                self.assertTrue(cg.is_exact_checkpoint_status_command(
                    self.state(session),
                    {"tool_name": "shell",
                     "tool_input": {"command": command}, "turn_id": turn}))
                self.assertEqual(
                    self.dispatch(
                        "PostToolUse", tool_name="shell",
                        tool_input={"command": command}, turn_id=turn,
                        session=session,
                        tool_response={"exit_code": 0}),
                    {})

    def test_c02b_equals_and_separated_forms_agree(self):
        self.ready()
        for spelled in (
            "--commands",
            "--item=R001",
            "--item R001",
            "--after-revision=rev-9",
            "--after-revision rev-9",
        ):
            with self.subTest(spelled=spelled):
                parts = spelled.split("=")
                if len(parts) == 2:
                    options = [parts[0], parts[1]]
                    command = status_command(self, self.turn, options)
                else:
                    options = spelled.split(" ")
                    command = status_command(self, self.turn, options)
                self.assertTrue(cg.is_exact_checkpoint_status_command(
                    self.state(),
                    {"tool_name": "shell",
                     "tool_input": {"command": command},
                     "turn_id": self.turn}))

    # -- C03: real failing diagnostic tool result is not malformed -------
    def test_c03_failed_cli_result_is_not_malformed_and_grants_nothing(self):
        self.ready()
        state = self.state()
        proofs_before = len(state.get("proofs", []))
        attempt_before = json.dumps(state.get("completion_attempt"), sort_keys=True)
        command = status_command(self, self.turn, ["--commands"])
        output = self.post(command, exit_code=1)
        self.assertEqual(output, {})
        state = self.state()
        self.assertEqual(len(state.get("proofs", [])), proofs_before)
        self.assertEqual(json.dumps(state.get("completion_attempt"),
                                    sort_keys=True), attempt_before)

    # -- C04: Unicode/space paths and PowerShell form ---------------------
    def test_c04_unicode_and_space_paths_and_powershell_form(self):
        self.ready()
        unicode_root = self.root / "私 有 目录"
        unicode_root.mkdir(parents=True, exist_ok=True)
        # A data-dir that is not the Guard's own root stays rejected even
        # when spelled with quoting; the shared root itself passes.
        base = status_command(self, self.turn, [])
        spaced = status_command(self, self.turn, [],
                                data_dir=unicode_root)
        self.assertNotEqual(base, spaced)
        self.assertIn("私 有 目录", spaced)
        self.assertFalse(cg.is_exact_checkpoint_status_command(
            self.state(), {"tool_name": "shell",
                           "tool_input": {"command": spaced},
                           "turn_id": self.turn}))
        self.assertTrue(cg.is_exact_checkpoint_status_command(
            self.state(), {"tool_name": "shell",
                           "tool_input": {"command": base},
                           "turn_id": self.turn}))

        windows_command = (
            "& " + status_command(self, self.turn, ["--commands"])
        )
        with mock.patch.object(cg.os, "name", "nt"):
            tokens = cg.private_control_command_tokens(windows_command,
                                                       windows=True)
            self.assertIsNotNone(tokens)
            self.assertEqual(tokens[0], sys.executable)
            self.assertEqual(tokens[2], "checkpoint-status")

    def test_c09_explicit_query_root_binds_all_commands_without_hook_environment(self):
        self.ready()
        source = self.root / 'private'
        spaced = self.root / 'other data root with spaces'
        __import__('shutil').copytree(source, spaced)
        def inventory(root):
            return {str(p.relative_to(root)): (p.stat().st_mode, p.stat().st_mtime_ns,
                    __import__('hashlib').sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
                    for p in root.rglob('*')}
        for root in (source, spaced):
            before = inventory(root)
            for key in (None, 'CONTEXT_GUARD_DATA_DIR', 'PLUGIN_DATA', 'CLAUDE_PLUGIN_DATA'):
                ambient = str(self.root / 'wrong ambient root')
                env = dict(os.environ)
                for name in ('CONTEXT_GUARD_DATA_DIR', 'PLUGIN_DATA', 'CLAUDE_PLUGIN_DATA'):
                    env.pop(name, None)
                if key is not None:
                    env[key] = ambient
                argv = [sys.executable, str(Path(cg.__file__).resolve()), 'checkpoint-status',
                        '--data-dir', str(root), '--session-id', 'p0', '--turn-id', self.turn,
                        '--token', 'p0token', '--commands']
                query = subprocess.run(argv, capture_output=True, text=True, env=env, check=False)
                self.assertEqual(query.returncode, 0)
                output = json.loads(query.stdout)
                self.assertEqual(set(output['advanced_commands']),
                                 {'status', 'stage_checkpoint', 'stage_disposition', 'register_proof'})
                for name, command in output['advanced_commands'].items():
                    tokens = cg.private_control_command_tokens(command, windows=os.name == 'nt')
                    self.assertEqual(tokens[tokens.index('--data-dir') + 1], str(root.resolve()))
                    self.assertEqual(tokens[tokens.index('--session-id') + 1], 'p0')
                    self.assertEqual(tokens[tokens.index('--turn-id') + 1], self.turn)
                    self.assertIn('--token=p0token', tokens)
                    if name == 'status':
                        returned = subprocess.run(tokens + ['--commands'], capture_output=True,
                                                  text=True, env=env, check=False)
                        self.assertEqual(returned.returncode, 0)
                        self.assertEqual(json.loads(returned.stdout)['revision'], output['revision'])
                self.assertEqual(inventory(root), before)
                self.assertFalse(Path(ambient).exists())

    def test_c10_encoder_explicit_space_root_and_hook_default_are_separate(self):
        self.ready()
        root = self.root / 'private'
        other = self.root / 'other data root with spaces'
        with mock.patch.object(cg, 'data_root', return_value=other):
            default = cg.advanced_command_context(self.state(), self.turn, 'p0token')
            explicit = cg.advanced_command_context(self.state(), self.turn, 'p0token', root=root)
            spaced = cg.advanced_command_context(self.state(), self.turn, 'p0token', root=other)
        for commands, expected in ((default, other), (explicit, root), (spaced, other)):
            for command in commands.values():
                argv = cg.private_control_command_tokens(command, windows=os.name == 'nt')
                self.assertEqual(argv[argv.index('--data-dir') + 1], str(expected.resolve()))
        with mock.patch.object(cg, 'data_root', side_effect=AssertionError('ambient root used')):
            self.assertEqual(cg.checkpoint_status(root, 'p0', self.turn, 'p0token', commands=True)
                             ['advanced_commands'], explicit)
        with self.assertRaises(RuntimeError):
            cg.checkpoint_status(other, 'p0', self.turn, 'p0token', commands=True)

    # -- C05: unknown, abbreviated, duplicate, missing/empty values ------
    def test_c05_contract_violations_rejected_everywhere(self):
        self.ready()
        base = ["--data-dir", str(self.root / "private"),
                "--session-id", "p0", "--turn-id", self.turn,
                "--token", "p0token"]
        script = str(Path(cg.__file__).resolve())
        cases = {
            "unknown-option": ["--unknown-status-option"],
            "abbreviation": ["--comm"],
            "duplicate-required": ["--session-id", "other"],
            "mode-conflict": ["--full", "--commands"],
            "flag-with-value": ["--commands=1"],
            "empty-value": ["--token="],
            "extra-positional": ["--full", "junk"],
            # F2 family: a separated value must not consume a following
            # option-like token; the CLI exits 2 and the Hook must agree.
            "missing-value-known-flag": ["--item", "--commands"],
            "missing-value-known-flag-revision": [
                "--after-revision", "--full"],
            "missing-value-unknown-flag": ["--item", "--unknown-later"],
            "missing-value-mandatory": ["--token", "--full"],
            "missing-value-trailing-dashdash": ["--item", "--"],
            "dash-value-separated": ["--item", "-R001"],
        }
        equals_only = {"missing-value-known-flag", "missing-value-known-flag-revision"}
        for label, extra in cases.items():
            with self.subTest(case=label):
                options = list(extra)
                if label == "duplicate-required":
                    options = ["--session-id", "other"] + base
                    argv = [sys.executable, script, "checkpoint-status",
                            *options]
                    tokens = cg.private_control_command_tokens(
                        cg.shell_join(argv), windows=False)
                    bindings = cg.parse_checkpoint_status_option_bindings(
                        tokens[3:])
                    self.assertIsNone(bindings)
                    # The CLI rejects the duplicate binding with exit 2
                    # instead of last-wins.
                    completed = subprocess.run(
                        [sys.executable, script, "checkpoint-status",
                         *base, "--session-id", "other"],
                        capture_output=True, text=True, check=False)
                    self.assertEqual(completed.returncode, 2,
                                     completed.stdout + completed.stderr)
                    continue
                if label == "extra-positional":
                    argv = [sys.executable, script, "checkpoint-status",
                            *base, *options]
                    completed = subprocess.run(
                        argv, capture_output=True, text=True, check=False)
                    self.assertEqual(completed.returncode, 2)
                    command = cg.shell_join(argv)
                else:
                    argv = [sys.executable, script, "checkpoint-status",
                            *base, *options]
                    completed = subprocess.run(
                        argv, capture_output=True, text=True, check=False)
                    self.assertEqual(completed.returncode, 2,
                                     (label, completed.stdout,
                                      completed.stderr))
                    command = cg.shell_join(argv)
                payload = {"tool_name": "shell",
                           "tool_input": {"command": command},
                           "turn_id": self.turn}
                self.assertFalse(
                    cg.is_exact_checkpoint_status_command(self.state(),
                                                          payload),
                    label)
                output = self.post(command)
                self.assertEqual(output.get("decision"), "block", label)
                self.assertIn("Malformed private control command",
                              output.get("reason", ""))
                if label in equals_only:
                    # The equals spelling of the same exotic value is the
                    # documented form and stays accepted.
                    flag = options[0]
                    equalized = status_command(
                        self, self.turn, [f"{flag}=--commands"])
                    self.assertTrue(cg.is_exact_checkpoint_status_command(
                        self.state(),
                        {"tool_name": "shell",
                         "tool_input": {"command": equalized},
                         "turn_id": self.turn}))

    # -- C06: wrong bindings and runtimes stay rejected ------------------
    def test_c06_wrong_binding_or_runtime_rejected_without_promotion(self):
        self.ready()
        state = self.state()
        proofs_before = len(state.get("proofs", []))
        requirements_before = json.dumps(state.get("requirements"),
                                         sort_keys=True)
        wrong = {
            "wrong-session": status_command(self, self.turn, []).replace(
                "--session-id p0", "--session-id other"),
            "wrong-turn": status_command(self, "stale-turn", []),
            "wrong-data-root": status_command(self, self.turn, []).replace(
                str(self.root / "private"), str(self.root / "elsewhere")),
            "wrong-token": status_command(self, self.turn, []).replace(
                "p0token", "stale-token"),
            "different-script": status_command(
                self, self.turn, [], script=Path("/not/the/guard.py")),
        }
        for label, command in wrong.items():
            with self.subTest(case=label):
                payload = {"tool_name": "shell",
                           "tool_input": {"command": command},
                           "turn_id": self.turn}
                if label == "wrong-token":
                    # The token check happens inside the shared attempt
                    # verification: the Hook reports the failure as a
                    # bounded private-control failure, never a pass.
                    with self.assertRaises(RuntimeError):
                        cg.is_exact_checkpoint_status_command(
                            self.state(), payload)
                else:
                    self.assertFalse(
                        cg.is_exact_checkpoint_status_command(self.state(),
                                                              payload), label)
        payload = {"tool_name": "shell",
                   "tool_input": {"command": wrong["wrong-token"]},
                   "turn_id": self.turn}
        output = self.post(wrong["wrong-token"])
        self.assertEqual(output.get("decision"), "block")
        self.assertNotIn("stale-token", output.get("reason", ""))
        state = self.state()
        self.assertEqual(len(state.get("proofs", [])), proofs_before)
        self.assertEqual(json.dumps(state.get("requirements"),
                                    sort_keys=True), requirements_before)

    # -- C07: shell chains and disguised commands -------------------------
    def test_c07_shell_chains_and_disguises_rejected(self):
        self.ready()
        plain = status_command(self, self.turn, ["--commands"])
        cases = {
            "pipe": plain + " | cat",
            "separator": plain + "; echo done",
            "command-substitution": "$(echo status) " + plain,
            "backgrounded": plain + " & echo done",
            "echo-prefix": f"echo {plain}",
        }
        for label, command in cases.items():
            with self.subTest(case=label):
                payload = {"tool_name": "shell",
                           "tool_input": {"command": command},
                           "turn_id": self.turn}
                self.assertFalse(
                    cg.is_exact_checkpoint_status_command(self.state(),
                                                          payload), label)
                output = self.post(command)
                self.assertEqual(output.get("decision"), "block", label)

    # -- C08: real CLI success inside the Pre/Post chain ------------------
    def test_c08_real_cli_success_then_post_chain_cold_read(self):
        self.ready()
        completed = self.cli(["--commands"])
        self.assertEqual(completed.returncode, 0, completed.stderr)
        inventory = json.loads(completed.stdout)
        self.assertIn("advanced_commands", inventory)
        command = cg.shell_join([
            sys.executable, str(Path(cg.__file__).resolve()),
            "checkpoint-status", "--data-dir", str(self.root / "private"),
            "--session-id", "p0", "--turn-id", self.turn,
            "--token", "p0token", "--commands",
        ])
        pre = self.dispatch("PreToolUse", tool_name="shell",
                            tool_input={"command": command},
                            turn_id=self.turn)
        self.assertNotEqual(pre.get("decision"), "block",
                            json.dumps(pre, ensure_ascii=False))
        post = self.post(command)
        self.assertEqual(post, {})
        state = self.state()
        # Cold read: persisted status stays queryable and consistent with
        # the direct CLI result. The discovery inventory is the caller's own
        # private tool path; the hook EVENT itself must stay silent, so no
        # binding reaches the user-visible receipt through PostToolUse.
        self.assertEqual(state["completion_attempt"]["turn_id"], self.turn)
        self.assertEqual(json.dumps(inventory.get("turn_id")), json.dumps(self.turn))
        self.assertEqual(post, {})
