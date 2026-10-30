"""Windows full code-mode source controls. All RPC/ACL evidence is synthetic.

The pinned shell file is inert and is never executed. Source CLI queries and
SDK doubles retain the original full mapper oracles; no Codex/model/login runs.
"""

from __future__ import annotations

import atexit
import copy
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from tools.validation import incident_code_mode_preflight as verification_bootstrap

_module_environment = None


def _ensure_private_module_environment():
    """Support unittest discovery/focused nodes without a caller-only marker.

    Install a module-owned fallback before its product/fixture imports. A
    dedicated preflight's existing private roots are reused, never torn down.
    """
    global _module_environment
    if not os.environ.get("CG_CODE_MODE_VERIFICATION_ROOT"):
        _module_environment = verification_bootstrap.private_environment()
        _module_environment.__enter__()
    private = Path(os.environ["CG_CODE_MODE_VERIFICATION_ROOT"]).resolve()
    for key in (
        "HOME",
        "USERPROFILE",
        "CODEX_HOME",
        "CONTEXT_GUARD_DATA_DIR",
        "TMPDIR",
        "TMP",
        "TEMP",
        "CTX",
        "DATA",
    ):
        value = os.environ.get(key)
        if not value or not Path(value).resolve().is_relative_to(private):
            raise ValueError(
                "effective module root escaped before product import/writes"
            )
    return private


def setUpModule():
    private = _ensure_private_module_environment()
    if not h.cg.data_root().resolve().is_relative_to(private):
        raise ValueError("effective module data root escaped before first dispatch")


def tearDownModule():
    global _module_environment
    if _module_environment is not None:
        owned, _module_environment = _module_environment, None
        owned.__exit__(None, None, None)


# This also protects imports under normal unittest/pytest collection. The
# module fixture can reopen the fallback if a cached module is run again.
_ensure_private_module_environment()
atexit.register(tearDownModule)

from tests import test_incident_host_full_v2 as full  # noqa: E402
from tests import test_native_cli_adoption as capability  # noqa: E402
from tests import test_native_code_mode_command as mac_controls  # noqa: E402
from tests.test_cg122_p0_counterexamples import P0Harness  # noqa: E402
from tools.validation import incident_host_acceptance as h  # noqa: E402
from tools.validation import native_cli_adoption as cli  # noqa: E402
from tools.validation import native_code_mode_command as cm  # noqa: E402


class SharedDualViewTests(unittest.TestCase):
    def case(self, *, redacted=False):
        o = mac_controls.CodeModeObservationTests()
        o.setUp()
        if redacted:
            o.command += " --token synthetic-token"
            o.stage["name"] = "status"
            o.trace[3]["payload"]["input"] = cm.fixture(o.command, o.plan["cwd"])
        return self.attach(o, redacted=redacted)

    def attach(self, o, *, redacted=False):
        result = json.loads(o.trace[4]["payload"]["output"].split("Output:\n")[1])
        display = (
            o.command.replace("--token synthetic-token", "--token=[REDACTED_SECRET]")
            if redacted
            else o.command
        )
        if cm.contract(o.plan) != cm.WINDOWS_CONTRACT:
            display = __import__("shlex").join(["/bin/zsh", "-lc", display])
        item = dict(
            type="commandExecution",
            id="exec-synthetic",
            command=display,
            cwd=o.plan["cwd"],
            source="unifiedExecStartup",
            status="inProgress",
            processId="42",
        )
        start = dict(
            method="item/started",
            emittedAtMs=1793328376150,
            params=dict(threadId="thread", turnId="turn", item=item),
        )
        end = dict(
            method="item/completed",
            emittedAtMs=1793328376175,
            params=dict(
                threadId="thread",
                turnId="turn",
                item=dict(
                    item,
                    status="completed",
                    exitCode=result["exit_code"],
                    aggregatedOutput=result["output"],
                ),
            ),
        )
        o.stage["rows"][4:4] = [start, end]
        for row in o.stage["rows"]:
            run = row.get("params", {}).get("run", {})
            if run.get("eventName") in ("preToolUse", "postToolUse"):
                label = (
                    "pre-tool-use"
                    if run["eventName"] == "preToolUse"
                    else "post-tool-use"
                )
                run["id"] = (
                    label
                    + ":"
                    + str(run["displayOrder"])
                    + ":"
                    + run["sourcePath"]
                    + ":exec-synthetic"
                )
        self.sync(o)
        return o

    @staticmethod
    def sync(o):
        o.rpc = o.rpc[:2] + [
            dict(direction="response", message=r) for r in o.stage["rows"]
        ]

    def test_unique_same_operation_views_and_code_only(self):
        self.assertEqual(self.case().observe()["exit_code"], 0)
        o = mac_controls.CodeModeObservationTests()
        o.setUp()
        self.assertEqual(o.observe()["exit_code"], 0)

    def test_redaction_requires_independent_bound_hook_token(self):
        o = self.case(redacted=True)
        with (
            mock.patch.object(h, "state_for", return_value={}),
            mock.patch.object(h, "hook_control_token", return_value="synthetic-token"),
        ):
            self.assertEqual(o.observe()["exit_code"], 0)
        with (
            mock.patch.object(h, "state_for", return_value={}),
            mock.patch.object(h, "hook_control_token", return_value="foreign-token"),
        ):
            with self.assertRaisesRegex(ValueError, "redaction control"):
                o.observe()
        o.stage.pop("name")
        with self.assertRaisesRegex(ValueError, "trusted control binding"):
            o.observe()

    def test_dual_mismatch_duplicate_foreign_wrapper_and_interval_family(self):
        for mutation in (
            "duplicate",
            "extra-start",
            "foreign-turn",
            "id",
            "source",
            "process",
            "stdout",
            "exit",
            "cwd",
            "wrapper",
            "extra-argv",
            "hook-id",
            "interval",
            "order",
        ):
            with self.subTest(mutation=mutation):
                o = self.case()
                a, b = o.stage["rows"][4], o.stage["rows"][5]
                if mutation == "duplicate":
                    o.stage["rows"][6:6] = [copy.deepcopy(a), copy.deepcopy(b)]
                elif mutation == "extra-start":
                    o.stage["rows"].insert(6, copy.deepcopy(a))
                elif mutation == "foreign-turn":
                    b["params"]["turnId"] = "foreign"
                elif mutation == "id":
                    b["params"]["item"]["id"] = "other"
                elif mutation == "source":
                    b["params"]["item"]["source"] = "unifiedExecInteraction"
                elif mutation == "process":
                    b["params"]["item"]["processId"] = "other"
                elif mutation == "stdout":
                    b["params"]["item"]["aggregatedOutput"] += "other"
                elif mutation == "exit":
                    b["params"]["item"]["exitCode"] = True
                elif mutation == "cwd":
                    b["params"]["item"]["cwd"] += "-other"
                elif mutation == "wrapper":
                    for r in (a, b):
                        r["params"]["item"]["command"] = r["params"]["item"][
                            "command"
                        ].replace("/bin/zsh", "/bin/bash")
                elif mutation == "extra-argv":
                    for r in (a, b):
                        r["params"]["item"]["command"] += " extra"
                elif mutation == "hook-id":
                    o.stage["rows"][2]["params"]["run"]["id"] = "foreign"
                elif mutation == "interval":
                    b["emittedAtMs"] += 1000
                elif mutation == "order":
                    o.stage["rows"][4], o.stage["rows"][5] = b, a
                self.sync(o)
                with self.assertRaises(ValueError):
                    o.observe()


class WindowsCodeModePureTests(unittest.TestCase):
    def setUp(self):
        self.o = mac_controls.CodeModeObservationTests()
        self.o.setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        shell = Path(self.tmp.name) / "Pinned Shell" / "pwsh.exe"
        shell.parent.mkdir()
        shell.write_bytes(b"inert synthetic shell; never executed")
        self.o.plan.update(
            schema=cm.WINDOWS_SCHEMA,
            platform="Windows",
            shell=dict(name="powershell", path=str(shell), sha256=h.base.sha(shell)),
            command_observation_contract=cm.adoption(windows=True),
        )
        self.body = self.o.command
        self.o.command = h.canonical_shell_command(self.body, self.o.plan)
        self.o.trace[3]["payload"]["input"] = cm.fixture(
            self.o.command, self.o.plan["cwd"]
        )

    def test_visible_actual_wrapper_and_both_terminal_forms(self):
        self.assertTrue(self.o.command.startswith('& "'))
        self.assertEqual(
            h.windows_display_tokens(self.o.command[2:]),
            [self.o.plan["shell"]["path"], "-Command", self.body],
        )
        self.assertEqual(self.o.observe()["exit_code"], 0)
        self.o.trace[4]["payload"]["output"] = self.o.two_block_output()
        self.assertEqual(self.o.observe()["exit_code"], 0)

    def test_bounded_host1_host2_only_and_real_post_required(self):
        for code in (1, 2, 0, 71, True, None):
            for blocked in (True, False):
                with self.subTest(code=code, blocked=blocked):
                    self.setUp()
                    raw = self.o.trace[4]["payload"]["output"]
                    prefix, payload = raw.split("Output:\n", 1)
                    value = json.loads(payload)
                    value["exit_code"] = code
                    self.o.trace[4]["payload"]["output"] = (
                        prefix + "Output:\n" + json.dumps(value)
                    )
                    if blocked:
                        self.o.stage["rows"][5]["params"]["run"]["status"] = "blocked"
                    args = dict(
                        subject=cm.pins(self.o.plan, self.o.command),
                        plan=self.o.plan,
                        stage=self.o.stage,
                        inventory=self.o.inventory,
                        rpc_bytes=self.o.encoded(self.o.rpc),
                        rollout_bytes=self.o.encoded(self.o.trace),
                        rollout_path=self.o.path,
                        command=self.o.command,
                        rejection=True,
                    )
                    if type(code) is int and code in (1, 2) and blocked:
                        self.assertEqual(cm.observe(**args)["exit_code"], code)
                    else:
                        with self.assertRaises(ValueError):
                            cm.observe(**args)

    def test_windows_dual_is_exact_inner_wrapper_not_guessed_api_outer(self):
        o = SharedDualViewTests().attach(self.o)
        self.assertEqual(o.observe()["exit_code"], 0)
        for row in o.stage["rows"]:
            if row.get("method") in ("item/started", "item/completed"):
                row["params"]["item"]["command"] = h.canonical_shell_command(
                    o.command, o.plan
                )
        SharedDualViewTests.sync(o)
        with self.assertRaises(ValueError):
            o.observe()

    def test_capture_refuses_windows_reparse_metadata(self):
        o = self.o
        home = Path(self.tmp.name) / "private-home"
        path = home / "sessions" / "rollout.jsonl"
        path.parent.mkdir(parents=True)
        o.plan["home"] = str(home)
        o.path = str(path)
        o.rpc[1]["message"]["result"]["thread"]["path"] = str(path)
        path.write_bytes(o.encoded(o.trace))
        journal = Path(self.tmp.name) / "rpc.jsonl"
        journal.write_bytes(o.encoded(o.rpc))
        record = dict(id=o.stage["thread"], path=str(path))
        evidence = cm.capture(o.plan, o.stage, record, journal, o.command)
        self.assertEqual(
            cm.consume(evidence, o.plan, o.stage, o.inventory, o.command)["exit_code"],
            0,
        )
        concrete = type(Path())

        class ReparsePath(concrete):
            def lstat(self, **kwargs):
                value = super().lstat(**kwargs)
                if str(self) != str(path):
                    return value
                attrs = {
                    name: getattr(value, name)
                    for name in dir(value)
                    if name.startswith("st_")
                }
                attrs["st_file_attributes"] = 0x400
                return __import__("types").SimpleNamespace(**attrs)

        with mock.patch.object(cm, "Path", ReparsePath):
            with self.assertRaisesRegex(ValueError, "reparse"):
                cm.capture(o.plan, o.stage, record, journal, o.command)

    def test_normal_unittest_entry_works_without_private_marker(self):
        # Reproduce the reviewed caller exactly as a fresh focused unittest
        # process. No conftest, no caller-filled marker, no native/model work.
        environment = dict(os.environ)
        environment.pop("CG_CODE_MODE_VERIFICATION_ROOT", None)
        process = __import__("subprocess").run(
            [
                __import__("sys").executable,
                "-B",
                "-m",
                "unittest",
                "tests.test_incident_host_full_code_mode.WindowsCodeModeFullTests.test_new_schema_retains_exact_readonly_filename_oracle",
            ],
            cwd=h.ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("Ran 1 test", process.stderr)
        self.assertNotIn("skipped", process.stderr)

    def test_module_owned_bootstrap_restores_existing_caller_environment(self):
        module = __import__("sys").modules[__name__]
        previous = {
            key: os.environ.get(key)
            for key in (
                "HOME",
                "USERPROFILE",
                "CODEX_HOME",
                "CONTEXT_GUARD_DATA_DIR",
                "TMPDIR",
            )
        }
        with (
            mock.patch.object(module, "_module_environment", None),
            mock.patch.dict(os.environ),
        ):
            os.environ.pop("CG_CODE_MODE_VERIFICATION_ROOT", None)
            private = _ensure_private_module_environment()
            self.assertEqual(h.cg.data_root().resolve(), private / "data")
            for key in previous:
                self.assertTrue(Path(os.environ[key]).resolve().is_relative_to(private))
            tearDownModule()
            self.assertEqual({key: os.environ.get(key) for key in previous}, previous)

    def test_wrong_actual_wrapper_never_replaced_by_environment_claim(self):
        self.o.trace[3]["payload"]["input"] = cm.fixture(self.body, self.o.plan["cwd"])
        with self.assertRaisesRegex(ValueError, "fixture/call binding"):
            self.o.observe()
        self.o.trace[3]["payload"]["input"] = cm.fixture(
            self.o.command.replace(" -Command ", " -NoProfile -Command "),
            self.o.plan["cwd"],
        )
        with self.assertRaises(ValueError):
            self.o.observe()


class WindowsCodeModeFullTests(P0Harness):
    def setUp(self):
        private = _ensure_private_module_environment()
        super().setUp()
        if (
            not self.root.resolve().is_relative_to(private)
            or h.cg.data_root().resolve() != self.root / "private"
        ):
            raise ValueError(
                "effective fixture root assertion failed before first dispatch"
            )

    ready = full.FullV2Tests.ready
    hook = full.FullV2Tests.hook
    stage = full.FullV2Tests.stage
    stop_fixture = full.FullV2Tests.stop_fixture
    full_host = full.FullV2Tests.full_host

    def full_code(self, *, host1=False):
        # Build the existing full source fixture and preserve every original
        # business record. Only replace the synthetic host observation channel.
        capture = full.FullV2Tests.full_capture(self)
        self.plan.update(
            schema=cm.WINDOWS_SCHEMA,
            gate_profile=h.PROFILE_FULL_CODE,
            cli_version=cli.VERSION,
            home=str(self.root / "home"),
            codex=str(self.root / "fake-cli"),
            command_observation_contract=cm.adoption(windows=True),
            manifest_sha256=h.base.sha(h.MANIFEST_FULL_CODE),
        )
        if os.name != "nt":
            self.plan["shell"]["path"] = "/" + self.plan["shell"]["path"]
        self.plan["toolkit"] = h.toolkit(self.plan)
        schemas = capability.schema_fixture()
        doc = json.loads(schemas["v2/ThreadStartResponse.json"])
        doc["properties"]["thread"]["properties"]["path"] = {"type": ["string", "null"]}
        schemas["v2/ThreadStartResponse.json"] = json.dumps(doc)
        with mock.patch.object(capability, "schema_fixture", return_value=schemas):
            self.plan["cli_adoption"] = cli.adoption(
                capability.receipt_fixture(self.plan, self.inventory)
            )
        capture["schema"] = "incident-host-capture/v2-full-code-mode"
        capture["plan_sha256"] = h.plan_identity(self.plan)
        rpc, trace = [], []
        locator = str(Path(self.plan["home"]) / "sessions/rollout.jsonl")

        def stamp(ms):
            return (
                datetime.fromtimestamp(ms / 1000, timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )

        for ordinal, name in enumerate(cm.COMMAND_STAGES):
            stage = capture["stages"][name]
            stage["name"] = name
            if name.startswith("baseline_"):
                stage["helper_argv"] = capture["baseline_tool_argv"][name]
            elif name == "readonly":
                stage["helper_argv"] = capture["readonly_tool_argv"]
            item = next(
                r["params"]["item"]
                for r in stage["rows"]
                if r.get("method") == "item/completed"
            )
            stage["rows"] = [
                r
                for r in stage["rows"]
                if r.get("method") not in ("item/started", "item/completed")
            ]
            if host1 and name in ("unknown", "missing"):
                item["exitCode"] = 1
                for r in stage["rows"]:
                    if (
                        r["method"] == "hook/completed"
                        and r["params"]["run"]["eventName"] == "postToolUse"
                    ):
                        r["params"]["run"]["entries"] = [
                            {"kind": "feedback", "text": "Synthetic parser refusal."}
                        ]
            base_ms = 1793328376000 + ordinal * 1000
            for i, r in enumerate(stage["rows"]):
                r["emittedAtMs"] = base_ms + (i if i < 6 else i + 20)
            stage["rows"].append(
                dict(
                    method="turn/completed",
                    params=dict(
                        threadId=stage["thread"],
                        turn=dict(id=stage["turn"], status="completed"),
                    ),
                )
            )
            if not rpc:
                rpc += [
                    dict(
                        direction="request",
                        message=dict(
                            id=1,
                            method="thread/start",
                            params=dict(cwd=self.plan["cwd"]),
                        ),
                    ),
                    dict(
                        direction="response",
                        message=dict(
                            id=1,
                            result=dict(thread=dict(id=stage["thread"], path=locator)),
                        ),
                    ),
                ]
                trace.append(
                    dict(
                        type="session_meta",
                        payload=dict(
                            id=stage["thread"],
                            cwd=self.plan["cwd"],
                            cli_version="0.165.0",
                        ),
                    )
                )
            rpc += [dict(direction="response", message=r) for r in stage["rows"]]
            command = h.expected_code_command(stage, self.inventory, self.plan)
            trace += [
                dict(
                    type="event_msg",
                    payload=dict(type="task_started", turn_id=stage["turn"]),
                ),
                dict(
                    type="turn_context",
                    payload=dict(turn_id=stage["turn"], cwd=self.plan["cwd"]),
                ),
                dict(
                    type="response_item",
                    timestamp=stamp(base_ms + 1),
                    payload=dict(
                        type="custom_tool_call",
                        name="exec",
                        status="completed",
                        call_id="call-" + name,
                        input=cm.fixture(command, self.plan["cwd"]) + "\n",
                    ),
                ),
                dict(
                    type="response_item",
                    timestamp=stamp(base_ms + 10),
                    payload=dict(
                        type="custom_tool_call_output",
                        call_id="call-" + name,
                        output=[
                            dict(
                                type="input_text",
                                text="Script completed\nWall time 0.7 seconds\nOutput:\n",
                            ),
                            dict(
                                type="input_text",
                                text=json.dumps(
                                    dict(
                                        exit_code=item["exitCode"],
                                        output=item["aggregatedOutput"],
                                        original_token_count=5.5,
                                    )
                                ),
                            ),
                        ],
                    ),
                ),
                dict(
                    type="event_msg",
                    payload=dict(type="task_complete", turn_id=stage["turn"]),
                ),
            ]
            stage["code_mode_evidence"] = dict(
                schema=cm.WINDOWS_CONTRACT,
                pins=cm.pins(self.plan, command),
                command=command,
                rpc=mac_controls.CodeModeObservationTests.encoded(rpc).decode(),
                rollout=mac_controls.CodeModeObservationTests.encoded(trace).decode(),
                rollout_path=locator,
            )
        capture["stop_result"].update(
            cli_version=cli.VERSION, cli_adoption=cli.identity(self.plan)
        )
        stop = Path(capture["stop_directory"])
        (stop / "plan.json").write_text(
            json.dumps(dict(self.plan, schema="stop-host-plan/v1"))
        )
        (stop / "result.json").write_text(json.dumps(capture["stop_result"]))
        self.final_rpc = mac_controls.CodeModeObservationTests.encoded(rpc)
        return capture

    def test_ten_gate_host1_and_host2_complete_production_mapper(self):
        for host1 in (False, True):
            with self.subTest(host1=host1):
                if host1:
                    # Each independent fixture owns its state and receipts.
                    other = WindowsCodeModeFullTests()
                    other.setUp()
                    self.addCleanup(other.doCleanups)
                    capture = other.full_code(host1=True)
                else:
                    capture = self.full_code()
                result = h.validate_result(h.map_capture(capture))
                self.assertEqual(result["status"], "passed")
                self.assertEqual(result["scenario_status"], "passed")
                self.assertEqual(result["required_gates"], list(h.GATES))
                self.assertEqual(result["native_acceptance"], "not_run")
                self.assertEqual(len(capture["stages"]), 13)
                self.assertEqual(
                    {
                        r["host_exit"]["value"]
                        for r in result["rejection_observations"].values()
                    },
                    {1 if host1 else 2},
                )

    def test_full_missing_stage_foreign_request_and_host1_feedback_controls(self):
        c = self.full_code(host1=True)
        for name in c["stages"]:
            bad = copy.deepcopy(c)
            del bad["stages"][name]
            with self.subTest(missing=name):
                try:
                    result = h.map_capture(bad)
                except (ValueError, KeyError):
                    continue
                self.assertNotEqual(result["status"], "passed")
        for key in ("stop_result", "fixture_restoration"):
            bad = copy.deepcopy(c)
            bad.pop(key)
            with self.subTest(missing=key):
                try:
                    result = h.map_capture(bad)
                except (ValueError, KeyError):
                    continue
                self.assertNotEqual(result["status"], "passed")
        stage = c["stages"]["unknown"]
        for r in stage["rows"]:
            if (
                r.get("method") == "hook/completed"
                and r["params"]["run"]["eventName"] == "postToolUse"
            ):
                r["params"]["run"]["entries"] = []
        evidence = stage["code_mode_evidence"]
        source = [json.loads(r) for r in evidence["rpc"].splitlines()]
        for r in source:
            m = r.get("message", {})
            if (
                m.get("method") == "hook/completed"
                and m["params"].get("turnId") == stage["turn"]
                and m["params"]["run"]["eventName"] == "postToolUse"
            ):
                m["params"]["run"]["entries"] = []
        evidence["rpc"] = mac_controls.CodeModeObservationTests.encoded(source).decode()
        with self.assertRaisesRegex(ValueError, "host1 requires silent Pre"):
            h.map_capture(c)

    def test_eight_archives_catalog_mapping_and_old_profiles_not_adopted(self):
        c = self.full_code()
        root = self.root
        (root / "rpc").mkdir()
        (root / "rpc/rpc.jsonl").write_bytes(self.final_rpc)
        for name in cm.COMMAND_STAGES:
            (root / ("rollout-" + name + ".jsonl")).write_text(
                c["stages"][name]["code_mode_evidence"]["rollout"]
            )
        h.write_new(root / "plan.json", c["plan"])
        h.write_new(root / "capture.json", c)
        catalog = {
            p.relative_to(root).as_posix(): h.base.sha(p)
            for p in root.rglob("*")
            if p.is_file()
        }
        h.write_new(root / "artifacts.json", catalog)
        result = h.map_bundle(root, root / "result.json")
        self.assertEqual(result["status"], "passed")
        for name in cm.COMMAND_STAGES:
            archive = root / ("rollout-" + name + ".jsonl")
            before = archive.read_bytes()
            archive.write_bytes(before + b" ")
            with self.assertRaises(ValueError):
                cm.verify_bundle_sources(root, c)
            archive.write_bytes(before)
        for schema, profile in (
            ("incident-host-plan/v1", h.PROFILE),
            ("incident-host-plan/v2", h.PROFILE_V2),
            ("incident-host-plan/v2-full", h.PROFILE_FULL),
        ):
            bad = dict(c["plan"], schema=schema, gate_profile=profile)
            with self.assertRaises(ValueError):
                h.profile_for_plan(bad)

    def test_new_generator_requires_complete_explicit_contracts(self):
        # Generator wiring only: the native capability boundary is an explicit
        # adapter double, not a claim that a synthetic receipt is native proof.
        self.full_code()
        home = Path(self.plan["home"])
        home.mkdir(exist_ok=True)
        receipt = copy.deepcopy(self.plan["cli_adoption"]["capability_receipt"])
        receipt["identity"]["cli_sha256"] = h.base.sha(Path(self.plan["python"]))
        receipt["evidence_scope"] = "native_zero_turn"
        capfile = self.root / "capability-adapter-double.json"
        capfile.write_text(json.dumps(receipt))
        planfile = self.root / "generated-plan.json"
        args = [
            "acceptance",
            "plan",
            "--codex",
            self.plan["python"],
            "--python",
            self.plan["python"],
            "--home",
            str(home),
            "--cwd",
            self.plan["cwd"],
            "--plugin-root",
            str(h.ROOT),
            "--data-root",
            str(home / "data"),
            "--model",
            "synthetic-never-dispatched",
            "--shell",
            self.plan["shell"]["path"],
            "--profile",
            h.PROFILE_FULL_CODE,
            "--gate-scope",
            "full",
            "--negative-observation",
            h.OBSERVATION_CONTRACTS["negative"],
            "--fixture-policy",
            h.OBSERVATION_CONTRACTS["readonly_fixture"],
            "--cli-adoption",
            cli.CONTRACT,
            "--cli-capability-receipt",
            str(capfile),
            "--plan-file",
            str(planfile),
            "--output",
            str(self.root / "generator-output"),
        ]
        with (
            mock.patch.object(__import__("sys"), "argv", args),
            mock.patch.object(h.platform, "system", return_value="Windows"),
            mock.patch.object(
                h, "prepared_source_identity", return_value=self.plan["source"]
            ),
            mock.patch.object(
                cli, "validate_receipt", return_value=receipt
            ) as capability_boundary,
            mock.patch.object(h, "preflight") as input_boundary,
            __import__("contextlib").redirect_stdout(__import__("io").StringIO()),
        ):
            self.assertEqual(h.main(), 0)
            generated = h.read_subject(planfile, strict=True)
            self.assertEqual(h.profile_for_plan(generated), h.PROFILE_FULL_CODE)
        capability_boundary.assert_called()
        input_boundary.assert_called_once()
        self.assertEqual(generated["gate_scope"], "full")
        self.assertEqual(generated["required_gates"], list(h.GATES))
        self.assertEqual(
            generated["command_observation_contract"], cm.adoption(windows=True)
        )
        for flag in (
            "--gate-scope",
            "--negative-observation",
            "--fixture-policy",
            "--cli-adoption",
        ):
            rejected = list(args)
            i = rejected.index(flag)
            del rejected[i : i + 2]
            rejected[rejected.index("--plan-file") + 1] = str(
                self.root / ("rejected-" + flag[2:] + ".json")
            )
            with (
                self.subTest(flag=flag),
                mock.patch.object(__import__("sys"), "argv", rejected),
                __import__("contextlib").redirect_stdout(__import__("io").StringIO()),
            ):
                self.assertEqual(h.main(), 2)
                self.assertFalse(
                    Path(rejected[rejected.index("--plan-file") + 1]).exists()
                )

    def test_new_collector_routes_thirteen_turns_eight_archives_and_failed_restore(
        self,
    ):
        # Routing/ownership only, with bounded synthetic process/ACL doubles.
        # All original business oracles run independently in full_code mapper
        # controls. No routing capture is mapped into a native PASS.
        self.full_code()
        for failure in (None, "baseline_granted"):
            output = self.root / ("route-" + str(failure))
            cwd = self.root / ("route-cwd-" + str(failure))
            cwd.mkdir()
            plan = dict(self.plan, cwd=str(cwd), output=str(output))
            restriction = dict(
                policy=h.child.READ_BASELINE_POLICY,
                sid="S-1-5-21-200",
                collector_sid="S-1-5-21-100",
                grant_complete=False,
                deny_complete=False,
                original_snapshot_sha256="e" * 64,
            )
            request = dict(
                schema="incident-readonly-request/v2", restriction=restriction
            )
            request["request_sha256"] = h.child.request_identity_v2(request)
            original_request = copy.deepcopy(request)
            stages, captures, events = [], [], []

            class Client:
                inventory = {}

                def __init__(self, *_):
                    self.sequence = 0
                    self.turn = 0
                    self.thread_records = {}

                def start(self, *_):
                    self.sequence += 1
                    thread = "thread-" + str(self.sequence)
                    self.thread_records[thread] = dict(
                        id=thread, path=str(Path(plan["home"]) / "sessions" / thread)
                    )
                    return thread

                def observed_turn(self, thread, prompt):
                    self.turn += 1
                    return dict(
                        thread=thread,
                        turn=str(self.turn),
                        rows=[],
                        prompt_sha256=__import__("hashlib")
                        .sha256(prompt.encode())
                        .hexdigest(),
                    )

                def close(self):
                    events.append("close")
                    return dict(
                        owned_process_exited=True, owned_tree_no_running_members=True
                    )

            def expected(stage, *_):
                stages.append(stage["name"])
                if stage["name"] in (
                    "baseline_original",
                    "baseline_granted",
                    "baseline_denied",
                    "readonly",
                ):
                    self.assertIsInstance(stage["helper_argv"], list)
                return "synthetic-canonical-" + stage["name"]

            def capture(_plan, stage, record, journal, command):
                self.assertEqual(record["id"], stage["thread"])
                self.assertEqual(journal, output / "rpc/rpc.jsonl")
                captures.append(stage["name"])
                return {
                    "rollout": json.dumps({"stage": stage["name"], "command": command})
                }

            def baseline(_s, _i, _p, _r, _a, name):
                if name == failure:
                    raise ValueError("synthetic baseline failure")
                return {"phase": name}

            def restore(_root, cloned):
                cloned["diagnostic"] = "restore-only"
                events.append("restore")

            with (
                mock.patch.object(h, "Client", Client),
                mock.patch.object(h, "copy_session"),
                mock.patch.object(h, "expected_code_command", side_effect=expected),
                mock.patch.object(cm, "capture", side_effect=capture),
                mock.patch.object(h, "command_observation", return_value={}),
                mock.patch.object(
                    h, "principal_observation", return_value=restriction["sid"]
                ),
                mock.patch.object(h, "make_fixture", return_value=request),
                mock.patch.object(h, "baseline_observation", side_effect=baseline),
                mock.patch.object(
                    h.child,
                    "apply_read_transaction",
                    side_effect=lambda _, r, p, **k: r.update({p + "_complete": True}),
                ),
                mock.patch.object(h.child, "restore", side_effect=restore),
                mock.patch.object(
                    h.child,
                    "restored_transaction_observation",
                    return_value={"status": "verified"},
                ),
                mock.patch.object(
                    h, "prepared_source_identity", return_value=plan["source"]
                ),
                mock.patch.object(
                    h.base, "runtime", return_value=plan["runtime_sha256"]
                ),
                mock.patch.object(cli, "validate", return_value=plan["cli_adoption"]),
                mock.patch.object(
                    h.base, "collect", return_value={"cleanups": [{}, {}]}
                ) as stop,
            ):
                result = h.collect(plan, output)
            self.assertEqual(events, ["close", "restore"])
            self.assertNotIn("diagnostic", request["restriction"])
            self.assertEqual(
                request["request_sha256"], original_request["request_sha256"]
            )
            if failure is None:
                self.assertEqual(captures, list(cm.COMMAND_STAGES))
                self.assertEqual(len(result["stages"]), 13)
                stop.assert_called_once_with(
                    dict(plan, schema="stop-host-plan/v1"), output / "stop"
                )
                self.assertEqual(len(result["cleanups"]), 3)
                self.assertNotIn("failure_class", result)
                self.assertEqual(
                    h.child.request_identity_v2(result["readonly_request"]),
                    result["readonly_request"]["request_sha256"],
                )
            else:
                stop.assert_not_called()
                self.assertEqual(result["failure_class"], "ValueError")
                self.assertNotIn("readonly", result["stages"])
            for name in captures:
                self.assertEqual(
                    json.loads((output / ("rollout-" + name + ".jsonl")).read_text())[
                        "stage"
                    ],
                    name,
                )

    def test_host1_parser_and_nonzero_do_not_weaken_under_code_mode(self):
        c = self.full_code(host1=True)
        for mutation in ("parser", "host71", "foreign-call", "extra-operation"):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(c)
                stage = bad["stages"]["unknown"]
                evidence = stage["code_mode_evidence"]
                trace = [json.loads(r) for r in evidence["rollout"].splitlines()]
                output = next(
                    r["payload"]
                    for r in trace
                    if r.get("type") == "response_item"
                    and r["payload"].get("type") == "custom_tool_call_output"
                    and r["payload"].get("call_id") == "call-unknown"
                )
                if mutation in ("parser", "host71"):
                    result = json.loads(output["output"][1]["text"])
                    if mutation == "parser":
                        result["output"] = "usage: unrelated\nwrong parser\n"
                    else:
                        result["exit_code"] = 71
                    output["output"][1]["text"] = json.dumps(result)
                elif mutation == "foreign-call":
                    output["call_id"] = "foreign"
                else:
                    call = next(
                        r
                        for r in trace
                        if r.get("type") == "response_item"
                        and r["payload"].get("type") == "custom_tool_call"
                        and r["payload"].get("call_id") == "call-unknown"
                    )
                    trace.insert(trace.index(call) + 1, copy.deepcopy(call))
                evidence["rollout"] = mac_controls.CodeModeObservationTests.encoded(
                    trace
                ).decode()
                with self.assertRaises(ValueError):
                    h.map_capture(bad)

    def test_new_schema_retains_exact_readonly_filename_oracle(self):
        c = self.full_code()
        argv = list(c["readonly_tool_argv"])
        argv[-1] += ".foreign"
        actual = {
            "command": h.canonical_shell_command(
                "& " + h.cg.shell_join(argv), self.plan
            )
        }
        with self.assertRaisesRegex(ValueError, "readonly tool argv differs"):
            h.readonly_helper_argv(actual, argv, self.plan)

    def test_preflight_bootstrap_and_duplicate_full_subject_controls(self):
        from tools.validation import incident_code_mode_preflight as preflight

        with preflight.private_environment() as root:
            self.assertEqual(h.cg.data_root().resolve(), root / "data")
            for key in (
                "HOME",
                "USERPROFILE",
                "CODEX_HOME",
                "CONTEXT_GUARD_DATA_DIR",
                "TMPDIR",
                "TMP",
                "TEMP",
            ):
                self.assertTrue(Path(os.environ[key]).resolve().is_relative_to(root))
        path = self.root / "duplicate.json"
        path.write_text(
            '{"schema":"incident-host-plan/v2-full-code-mode","gate_profile":"unknown","gate_profile":"incident_host/v2-full-code-mode"}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            h.read_subject(path)
