"""Synthetic offline controls; no model, HOME read, collector, or native claim."""

import copy
import json
import math
import os
import tempfile
import unittest
from pathlib import Path, PurePosixPath, PureWindowsPath
from unittest import mock

from tests import test_incident_host_acceptance as owning
from tests import test_native_cli_adoption as adoption_tests
from tests.test_cg122_p0_counterexamples import P0Harness
from tools.validation import incident_host_acceptance as original
from tools.validation import native_cli_adoption as cli
from tools.validation import native_code_mode_command as candidate


class CodeModeObservationTests(unittest.TestCase):
    def setUp(self):
        synthetic_root = Path(tempfile.gettempdir()) / "code-mode-synthetic"
        self.plan = dict(
            source=dict(
                head="a" * 40,
                prepared_source_sha256="e" * 64,
                dirty_paths=[],
                renamed_away=[],
            ),
            runtime_sha256="b" * 64,
            cli_sha256="c" * 64,
            cli_version="codex-cli 0.165.0",
            platform="Darwin",
            cwd=str(synthetic_root / "work"),
            home=str(synthetic_root / "home"),
        )
        self.command = "python /synthetic/status.py --commands"
        self.path = str(Path(self.plan["home"]) / "sessions" / "rollout.jsonl")
        self.inventory, selected = {}, []
        for j, name in enumerate(
            ("userPromptSubmit", "preToolUse", "postToolUse", "stop")
        ):
            hook = dict(
                key=name,
                eventName=name,
                sourcePath="/synthetic/plugin/hooks.json",
                source="plugin",
                handlerType="command",
                displayOrder=j,
                executionMode="sync",
                id=name,
                status="completed",
                durationMs=1,
                entries=[],
            )
            self.inventory[name] = dict(hook, **{"async": False})
            for k, method in enumerate(("hook/started", "hook/completed")):
                selected.append(
                    dict(
                        method=method,
                        emittedAtMs=1793328376000 + j * 100 + k,
                        params=dict(
                            threadId="thread", turnId="turn", run=copy.deepcopy(hook)
                        ),
                    )
                )
        selected.append(
            dict(
                method="turn/completed",
                params=dict(
                    threadId="thread", turn=dict(id="turn", status="completed")
                ),
            )
        )
        self.stage = dict(thread="thread", turn="turn", rows=selected)
        self.rpc = [
            dict(
                direction="request",
                message=dict(
                    id=1, method="thread/start", params=dict(cwd=self.plan["cwd"])
                ),
            ),
            dict(
                direction="response",
                message=dict(
                    id=1, result=dict(thread=dict(id="thread", path=self.path))
                ),
            ),
        ]
        self.rpc += [dict(direction="response", message=x) for x in selected]

        def row(kind, payload, timestamp="2026-10-30T02:46:16.000Z"):
            return dict(type=kind, payload=payload, timestamp=timestamp)

        self.trace = [
            row(
                "session_meta",
                dict(id="thread", cwd=self.plan["cwd"], cli_version="0.165.0"),
            ),
            row("event_msg", dict(type="task_started", turn_id="turn")),
            row("turn_context", dict(turn_id="turn", cwd=self.plan["cwd"])),
            row(
                "response_item",
                dict(
                    type="custom_tool_call",
                    status="completed",
                    name="exec",
                    call_id="call",
                    input=candidate.fixture(self.command, self.plan["cwd"]),
                ),
                "2026-10-30T02:46:16.050Z",
            ),
            row(
                "response_item",
                dict(
                    type="custom_tool_call_output",
                    call_id="call",
                    output="Script completed\nWall time 0.7 seconds\nOutput:\n"
                    + json.dumps(
                        dict(
                            exit_code=0,
                            output='{"synthetic":true}',
                            wall_time_seconds=0.1,
                        )
                    ),
                ),
                "2026-10-30T02:46:16.250Z",
            ),
            row("event_msg", dict(type="task_complete", turn_id="turn")),
        ]

    def observe(self):
        return candidate.observe(
            subject=candidate.pins(self.plan, self.command),
            plan=self.plan,
            stage=self.stage,
            inventory=self.inventory,
            rpc_bytes=self.encoded(self.rpc),
            rollout_bytes=self.encoded(self.trace),
            rollout_path=self.path,
            command=self.command,
        )

    @staticmethod
    def encoded(rows):
        return "".join(json.dumps(r) + "\n" for r in rows).encode()

    def two_block_output(self):
        header, payload = self.trace[4]["payload"]["output"].split("Output:\n", 1)
        return [
            {"type": "input_text", "text": header + "Output:\n"},
            {"type": "input_text", "text": payload},
        ]

    def test_ascii_js_edges_and_exact_two_text_block_positive_family(self):
        for edge in ("", "\n", "\r\n", " \t\r\n"):
            for blocks in (False, True):
                with self.subTest(edge=repr(edge), blocks=blocks):
                    self.setUp()
                    self.trace[3]["payload"]["input"] = (
                        edge + self.trace[3]["payload"]["input"] + edge
                    )
                    if blocks:
                        self.trace[4]["payload"]["output"] = self.two_block_output()
                    self.assertEqual(self.observe()["exit_code"], 0)

    def test_two_block_and_edge_negative_shape_family(self):
        for case in (
            "unicode-space",
            "unicode-zero-width",
            "unicode-bom",
            "vertical-tab",
            "form-feed",
            "NUL",
            "extra-statement",
            "internal-js-space",
            "extra-call",
            "wrong-block-type",
            "unknown-key",
            "nonstring-text",
            "empty-second",
            "empty-first",
            "one-block",
            "three-blocks",
            "object",
            "header-has-result",
            "header-running",
            "second-header",
            "duplicate-JSON",
            "prose-prefix",
            "unknown-result-key",
            "session-running",
            "over-budget",
            "exit71",
            "nonzero",
            "truncation",
        ):
            with self.subTest(case=case):
                self.setUp()
                blocks = self.two_block_output()
                js = self.trace[3]["payload"]
                invalid_edges = {
                    "unicode-space": "\u00a0",
                    "unicode-zero-width": "\u200b",
                    "unicode-bom": "\ufeff",
                    "vertical-tab": "\v",
                    "form-feed": "\f",
                    "NUL": "\0",
                }
                if case in invalid_edges:
                    js["input"] += invalid_edges[case]
                elif case == "extra-statement":
                    js["input"] += "\ntext(0);\n"
                elif case == "internal-js-space":
                    js["input"] = js["input"].replace("const r", "const  r")
                elif case == "extra-call":
                    self.trace.insert(4, copy.deepcopy(self.trace[3]))
                elif case == "wrong-block-type":
                    blocks[1]["type"] = "output_text"
                elif case == "unknown-key":
                    blocks[0]["role"] = "assistant"
                elif case == "nonstring-text":
                    blocks[1]["text"] = {"exit_code": 0}
                elif case == "empty-second":
                    blocks[1]["text"] = ""
                elif case == "empty-first":
                    blocks[0]["text"] = ""
                elif case == "one-block":
                    blocks.pop()
                elif case == "three-blocks":
                    blocks.append(copy.deepcopy(blocks[1]))
                elif case == "object":
                    blocks = {"blocks": blocks}
                elif case == "header-has-result":
                    blocks[0]["text"] += blocks[1]["text"]
                elif case == "header-running":
                    blocks[0]["text"] = (
                        "Script running\nWall time 0.7 seconds\nOutput:\n"
                    )
                elif case == "second-header":
                    blocks[1]["text"] = blocks[0]["text"] + blocks[1]["text"]
                elif case == "duplicate-JSON":
                    blocks[1]["text"] += blocks[1]["text"]
                elif case == "prose-prefix":
                    blocks[1]["text"] = "Result: " + blocks[1]["text"]
                else:
                    result = json.loads(blocks[1]["text"])
                    if case == "unknown-result-key":
                        result["unknown"] = 1
                    elif case == "session-running":
                        result["session_id"] = 42
                    elif case == "over-budget":
                        result["original_token_count"] = 6001
                    elif case == "exit71":
                        result.update(
                            exit_code=71,
                            original_token_count=14,
                            output="sandbox-exec: sandbox_apply: Operation not permitted\n",
                        )
                    elif case == "nonzero":
                        result["exit_code"] = 1
                    elif case == "truncation":
                        result["original_token_count"] = 20000
                    blocks[1]["text"] = json.dumps(result)
                output_index = 5 if case == "extra-call" else 4
                self.trace[output_index]["payload"]["output"] = blocks
                with self.assertRaises(ValueError):
                    self.observe()

    def test_absolute_synthetic_paths_and_windows_path_projection(self):
        self.assertTrue(Path(self.plan["cwd"]).is_absolute())
        self.assertTrue(Path(self.plan["home"]).is_absolute())
        self.assertTrue(Path(self.path).is_absolute())
        self.assertIn(Path(self.plan["home"]) / "sessions", Path(self.path).parents)
        self.assertFalse(PureWindowsPath("/synthetic/work").is_absolute())
        for path_type, anchor in (
            (PureWindowsPath, "C:/synthetic"),
            (PurePosixPath, "/synthetic"),
        ):
            with self.subTest(path_type=path_type.__name__):
                root = path_type(anchor)
                cwd, home = root / "work", root / "home"
                locator = home / "sessions" / "rollout.jsonl"
                self.assertTrue(cwd.is_absolute())
                self.assertTrue(home.is_absolute())
                self.assertTrue(locator.is_absolute())
                self.assertIn(home / "sessions", locator.parents)
                with mock.patch.object(candidate, "Path", path_type):
                    js = candidate.fixture(self.command, str(cwd))
                self.assertIn(json.dumps(str(cwd)), js)

    def test_positive_observation_and_old_direct_oracle_still_refuses(
        self,
    ):
        result = self.observe()
        self.assertEqual(result["scope"], "bound_command_observation")
        self.assertEqual(result["exit_code"], 0)
        with self.assertRaisesRegex(ValueError, "one ordinary command pair"):
            original.command_pair(self.stage, self.plan)

    def test_known_optional_token_count_retains_budget_type_and_unknown_field_checks(
        self,
    ):
        for count in (
            0,
            5,
            5.0,
            5.5,
            6000,
            6001,
            20000,
            -1,
            -0.5,
            float("nan"),
            float("inf"),
            float("-inf"),
            True,
            False,
            None,
            "5",
        ):
            with self.subTest(count=count):
                self.setUp()
                prefix, raw = self.trace[4]["payload"]["output"].split("Output:\n", 1)
                result = json.loads(raw)
                result["original_token_count"] = count
                self.trace[4]["payload"]["output"] = (
                    prefix + "Output:\n" + json.dumps(result)
                )
                if (
                    type(count) in (int, float)
                    and math.isfinite(count)
                    and 0 <= count <= candidate.MAX_OUTPUT_TOKENS
                ):
                    self.assertEqual(self.observe()["exit_code"], 0)
                else:
                    with self.assertRaisesRegex(ValueError, "token count|token budget"):
                        self.observe()
        for extra in ("unknown_metadata", "session_id"):
            with self.subTest(extra=extra):
                self.setUp()
                prefix, raw = self.trace[4]["payload"]["output"].split("Output:\n", 1)
                result = json.loads(raw)
                result.update(original_token_count=5)
                result[extra] = 1
                self.trace[4]["payload"]["output"] = (
                    prefix + "Output:\n" + json.dumps(result)
                )
                with self.assertRaises(ValueError):
                    self.observe()
        self.assertIn(
            '"max_output_tokens":6000',
            candidate.fixture(self.command, self.plan["cwd"]),
        )

    def test_rpc_ids_are_strict_positive_integer_unique_pairs(self):
        for side in (0, 1):
            for value in (True, False, 1.0, "1", None, 0, -1, "missing"):
                with self.subTest(side=side, value=value):
                    self.setUp()
                    if value == "missing":
                        self.rpc[side]["message"].pop("id")
                    else:
                        self.rpc[side]["message"]["id"] = value
                    with self.assertRaises(ValueError):
                        self.observe()
        for value in (True, 1.0, "1", None):
            with self.subTest(both=value):
                self.setUp()
                for row in self.rpc[:2]:
                    row["message"]["id"] = value
                with self.assertRaises(ValueError):
                    self.observe()
        for side in (0, 1):
            with self.subTest(duplicate=side):
                self.setUp()
                self.rpc.append(copy.deepcopy(self.rpc[side]))
                with self.assertRaisesRegex(ValueError, "duplicate RPC identity"):
                    self.observe()
        for value in (1, 2, 10001, 2**54):
            with self.subTest(valid=value):
                self.setUp()
                for row in self.rpc[:2]:
                    row["message"]["id"] = value
                self.assertEqual(self.observe()["exit_code"], 0)
        self.setUp()
        self.rpc[1]["message"]["id"] = 2
        with self.assertRaises(ValueError):
            self.observe()

    def test_string_identities_and_stage_source_types_cannot_coerce(self):
        for key in ("thread", "turn"):
            for value in (True, 1, 1.0, None, ""):
                with self.subTest(key=key, value=value):
                    self.setUp()
                    self.stage[key] = value
                    with self.assertRaisesRegex(ValueError, "string thread/turn"):
                        self.observe()
        self.setUp()
        # Equal-valued JSON numbers in the retained source are not identical
        # source bytes; the stage must match without Python numeric coercions.
        self.rpc[2] = copy.deepcopy(self.rpc[2])
        self.rpc[2]["message"]["params"]["run"]["displayOrder"] = 0.0
        with self.assertRaisesRegex(ValueError, "contiguous stage RPC"):
            self.observe()
        for value in (True, 1.0, None):
            with self.subTest(call=value):
                self.setUp()
                for row in self.trace[3:5]:
                    row["payload"]["call_id"] = value
                with self.assertRaises(ValueError):
                    self.observe()
        # Tool wall-clock duration remains a valid float, unlike an identity.
        self.setUp()
        self.assertEqual(self.observe()["exit_code"], 0)

    def test_adversarial_source_call_result_and_hook_controls(self):
        def mutate(case):
            a, b = self.trace[3]["payload"], self.trace[4]["payload"]
            if case == "store-only":
                a["input"] = a["input"].replace("text(r)", 'store("r",r)')
            elif case == "extra-side-effect":
                a["input"] += 'text("forged");'
            elif case == "multiple-calls":
                self.trace.insert(4, copy.deepcopy(self.trace[3]))
            elif case == "wrong-command":
                a["input"] = candidate.fixture("echo forged", self.plan["cwd"])
            elif case == "wrong-cwd":
                a["input"] = candidate.fixture(
                    self.command, str(Path(self.plan["cwd"]).parent / "other")
                )
            elif case == "wrong-call":
                b["call_id"] = "other"
            elif case == "unknown-tool-call":
                self.trace.insert(
                    4, dict(type="response_item", payload=dict(type="web_search_call"))
                )
            elif case == "output-before-call":
                self.trace[3], self.trace[4] = self.trace[4], self.trace[3]
            elif case == "wrong-tool":
                a["name"] = "other"
            elif case == "empty-output":
                b["output"] = "Script completed\nWall time 0.7 seconds\nOutput:\n"
            elif case == "nonzero":
                b["output"] = b["output"].replace('"exit_code": 0', '"exit_code": 1')
            elif case == "missing-exit":
                b["output"] = b["output"].replace('"exit_code": 0, ', "")
            elif case == "bool-exit":
                b["output"] = b["output"].replace(
                    '"exit_code": 0', '"exit_code": false'
                )
            elif case == "missing-stdout":
                b["output"] = b["output"].replace(
                    '"output": "{\\"synthetic\\":true}", ', ""
                )
            elif case == "truncated":
                b["output"] = b["output"].replace(
                    '"exit_code": 0', '"original_token_count": 20000, "exit_code": 0'
                )
            elif case == "running-session":
                b["output"] = b["output"].replace(
                    '"exit_code": 0', '"session_id": 42, "exit_code": 0'
                )
            elif case == "wrong-thread":
                self.trace[0]["payload"]["id"] = "other"
            elif case == "wrong-turn":
                self.trace[2]["payload"]["turn_id"] = "other"
            elif case == "missing-terminal":
                self.trace.pop()
            elif case == "duplicate-turn":
                self.trace += self.trace[1:]
            elif case == "wrong-server-path":
                self.rpc[1]["message"]["result"]["thread"]["path"] = "/other"
            elif case == "foreign-path":
                self.path = "/other"
                self.rpc[1]["message"]["result"]["thread"]["path"] = "/other"
            elif case == "foreign-stage":
                self.rpc.pop()
            elif case == "unpaired-hook":
                self.stage["rows"].pop(3)
            elif case == "blocked-hook":
                self.stage["rows"][3]["params"]["run"]["status"] = "blocked"
            elif case == "post-not-silent":
                self.stage["rows"][5]["params"]["run"]["entries"] = ["not silent"]
            elif case == "hook-outside-call":
                self.trace[3]["timestamp"] = "2026-10-30T02:46:16.150Z"
            elif case == "forged-agent-output":
                self.trace[4]["payload"]["type"] = "message"

        cases = (
            "store-only",
            "extra-side-effect",
            "multiple-calls",
            "wrong-command",
            "wrong-cwd",
            "wrong-call",
            "unknown-tool-call",
            "output-before-call",
            "wrong-tool",
            "empty-output",
            "nonzero",
            "missing-exit",
            "bool-exit",
            "missing-stdout",
            "truncated",
            "running-session",
            "wrong-thread",
            "wrong-turn",
            "missing-terminal",
            "duplicate-turn",
            "wrong-server-path",
            "foreign-path",
            "foreign-stage",
            "unpaired-hook",
            "blocked-hook",
            "post-not-silent",
            "hook-outside-call",
            "forged-agent-output",
        )
        for case in cases:
            with self.subTest(case=case):
                self.setUp()
                mutate(case)
                with self.assertRaises(ValueError):
                    self.observe()

    def test_toolkit_and_plan_pin_cannot_be_reused_after_input_change(self):
        subject = candidate.pins(self.plan, self.command)
        self.plan["source"]["head"] = "d" * 40
        with self.assertRaisesRegex(ValueError, "subject/toolkit"):
            candidate.observe(
                subject=subject,
                plan=self.plan,
                stage=self.stage,
                inventory=self.inventory,
                rpc_bytes=self.encoded(self.rpc),
                rollout_bytes=self.encoded(self.trace),
                rollout_path=self.path,
                command=self.command,
            )


@unittest.skipIf(
    os.name == "nt",
    "real command family requires POSIX recovery commands; pure JSON controls remain portable",
)
class CodeModeFamilyTests(P0Harness):
    ready = owning.IncidentHostTests.ready
    stage = owning.IncidentHostTests.stage
    hook = owning.IncidentHostTests.hook

    def retained_fixture(self):
        from tests.test_acceptance_identity import TempRepo

        self.adopted()
        execution = TempRepo()
        self.addCleanup(execution.temp.cleanup)
        tools = execution.root / "tools/validation"
        tools.mkdir(parents=True)
        for name in original.toolkit(self.plan):
            (tools / name).write_bytes(Path(original.__file__).with_name(name).read_bytes())
        # Old tools are retained as bytes, never imported or executed.
        with (tools / "native_code_mode_command.py").open("a") as stream:
            stream.write("\n# synthetic retained execution revision\n")
        execution.git("add", "-A")
        execution.git("commit", "-qm", "retained synthetic tools")
        self.plan.update(source=execution.identity(), runtime_sha256=original.base.runtime(execution.root),
                         repo=str(execution.root))
        self.plan["toolkit"] = {name: original.base.sha(tools / name)
                                for name in original.toolkit(self.plan)}
        self.plan["command_observation_contract"]["toolkit"] = {
            name: original.base.sha(tools / name) for name in candidate.TOOLKIT
        }
        schemas = adoption_tests.schema_fixture()
        doc = json.loads(schemas["v2/ThreadStartResponse.json"])
        doc["properties"]["thread"]["properties"]["path"] = {"type": ["string", "null"]}
        schemas["v2/ThreadStartResponse.json"] = json.dumps(doc)
        with mock.patch.object(adoption_tests, "schema_fixture", return_value=schemas):
            self.plan["cli_adoption"] = cli.adoption(
                adoption_tests.receipt_fixture(self.plan, self.inventory)
            )
        self.capture["plan_sha256"] = original.plan_identity(self.plan)
        with original.retained_execution_source(self.plan, execution.root):
            stage = self.transparent("status", ["--commands"])
        evidence = stage["code_mode_evidence"]
        (self.root / "rpc").mkdir()
        (self.root / "rpc/rpc.jsonl").write_text(evidence["rpc"])
        (self.root / "rollout-status.jsonl").write_text(evidence["rollout"])
        original.write_new(self.root / "capture.json", self.capture)
        catalog = {p.relative_to(self.root).as_posix(): original.base.sha(p)
                   for p in self.root.rglob("*") if p.is_file()}
        original.write_new(self.root / "artifacts.json", catalog)
        return execution

    def test_retained_catalog_mapping_preserves_execution_and_new_consumer_identities(self):
        execution = self.retained_fixture()
        plan_before = copy.deepcopy(self.plan)
        capture_before = (self.root / "capture.json").read_bytes()
        with self.assertRaises(ValueError):
            original.map_bundle(self.root, self.root / "ordinary-result.json")
        result = original.map_bundle(self.root, self.root / "derived-result.json",
                                     execution_source=execution.root)
        original.validate_result(result)
        self.assertEqual(result["gates"]["status_cli_posttool"], "passed")
        self.assertEqual(result["native_acceptance"], "not_run")
        self.assertEqual(result["execution_identity"]["source"], original.public_source(plan_before["source"]))
        self.assertEqual(result["execution_identity"]["toolkit"], plan_before["toolkit"])
        self.assertEqual(result["mapping_identity"]["toolkit"], original.toolkit(self.plan))
        self.assertNotEqual(result["execution_identity"]["toolkit"], result["mapping_identity"]["toolkit"])
        self.assertEqual(result["mapping_identity"]["retained_capture"]["execution_plan_sha256"],
                         self.capture["plan_sha256"])
        self.assertEqual(self.plan, plan_before)
        self.assertEqual((self.root / "capture.json").read_bytes(), capture_before)
        self.assertIsNone(candidate._retained_tools.get())
        for value in (None, True, False, "", "g" * 64, "a" * 63, "a" * 65, "missing"):
            for side in ("execution", "retained", "both"):
                with self.subTest(value=value, side=side):
                    bad = copy.deepcopy(result)
                    targets = []
                    if side in ("execution", "both"):
                        targets.append((bad["execution_identity"], "plan_sha256"))
                    if side in ("retained", "both"):
                        targets.append((bad["mapping_identity"]["retained_capture"], "execution_plan_sha256"))
                    for target, key in targets:
                        if value == "missing":
                            target.pop(key)
                        else:
                            target[key] = value
                    with self.assertRaises(ValueError):
                        original.validate_result(bad)
        for malformed in (None, True, [], "invalid"):
            bad = copy.deepcopy(result)
            bad["mapping_identity"] = malformed
            with self.assertRaises(ValueError):
                original.validate_result(bad)
        for malformed in (None, True, {}, {"schema": "other", "execution_plan_sha256": "a" * 64}):
            bad = copy.deepcopy(result)
            bad["mapping_identity"]["retained_capture"] = malformed
            with self.assertRaises(ValueError):
                original.validate_result(bad)
        bad = copy.deepcopy(result)
        bad["mapping_identity"]["retained_capture"]["execution_plan_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            original.validate_result(bad)

    def test_retained_source_dirty_foreign_runtime_and_toolkit_refused(self):
        execution = self.retained_fixture()
        for case in ("dirty", "foreign", "runtime", "toolkit"):
            with self.subTest(case=case):
                plan = copy.deepcopy(self.plan)
                if case == "dirty":
                    (execution.root / "unrelated.txt").write_text("changed")
                elif case == "foreign":
                    plan["source"]["head"] = "0" * 40
                elif case == "runtime":
                    plan["runtime_sha256"] = "0" * 64
                else:
                    plan["toolkit"]["native_code_mode_command.py"] = "0" * 64
                try:
                    with self.assertRaises(ValueError):
                        with original.retained_execution_source(plan, execution.root):
                            self.fail("invalid retained source was accepted")
                finally:
                    (execution.root / "unrelated.txt").unlink(missing_ok=True)
                self.assertIsNone(candidate._retained_tools.get())

    def test_retained_source_changes_before_export_refuse_publication_and_reset_scope(self):
        execution = self.retained_fixture()
        real_mapper = original.map_capture
        output = self.root / "not-published.json"

        def map_then_change(*args, **kwargs):
            result = real_mapper(*args, **kwargs)
            self.assertEqual(result["gates"]["status_cli_posttool"], "passed")
            with (execution.root / "tools/validation/native_code_mode_command.py").open("a") as stream:
                stream.write("\n# changed after mapping\n")
            return result

        with mock.patch.object(original, "map_capture", side_effect=map_then_change):
            with self.assertRaisesRegex(ValueError, "retained execution source identity"):
                original.map_bundle(self.root, output, execution_source=execution.root)
        self.assertFalse(output.exists())
        self.assertIsNone(candidate._retained_tools.get())

    def test_retained_readonly_helper_binds_execution_path_not_consumer_path(self):
        execution = self.retained_fixture()
        helper = execution.root / "tools/validation/incident_readonly_child.py"
        expected = [self.plan["python"], str(helper), "--request", str(self.root / "request.json")]
        item = {"command": original.cg.shell_join(expected)}
        with original.retained_execution_source(self.plan, execution.root):
            self.assertEqual(original.readonly_helper_argv(item, expected, self.plan), expected)
            foreign = list(expected)
            foreign[1] = str(Path(original.__file__).with_name("incident_readonly_child.py"))
            with self.assertRaisesRegex(ValueError, "readonly tool argv"):
                original.readonly_helper_argv({"command": original.cg.shell_join(foreign)}, foreign, self.plan)
        self.assertEqual(original.readonly_helper_argv(item, expected, self.plan), expected)
        changed = dict(self.plan, repo=str(original.ROOT))
        with self.assertRaisesRegex(ValueError, "readonly tool argv|execution helper"):
            original.readonly_helper_argv(item, expected, changed)

    def adopted(self):
        self.ready()
        self.plan.update(
            schema="incident-host-plan/v1-code-mode",
            gate_profile=original.PROFILE_CODE,
            platform="Darwin",
            cli_version=cli.VERSION,
            home=str(self.root / "home"),
            codex=str(self.root / "synthetic-cli"),
            command_observation_contract=candidate.adoption(),
            manifest_sha256=original.base.sha(original.MANIFEST_CODE),
        )
        self.plan["toolkit"] = original.toolkit(self.plan)
        schemas = adoption_tests.schema_fixture()
        doc = json.loads(schemas["v2/ThreadStartResponse.json"])
        doc["properties"]["thread"]["properties"]["path"] = {"type": ["string", "null"]}
        schemas["v2/ThreadStartResponse.json"] = json.dumps(doc)
        with mock.patch.object(adoption_tests, "schema_fixture", return_value=schemas):
            self.plan["cli_adoption"] = cli.adoption(
                adoption_tests.receipt_fixture(self.plan, self.inventory)
            )
        self.capture.update(
            schema="incident-host-capture/v1-code-mode",
            plan_sha256=original.plan_identity(self.plan),
        )
        self.assertEqual(original.profile_for_plan(self.plan), original.PROFILE_CODE)

    def transparent(self, name, options):
        stage = self.stage(name, query_options=options)
        direct = next(
            r["params"]["item"]
            for r in stage["rows"]
            if r["method"] == "item/completed"
        )
        stage.update(
            name=name,
            rows=[
                r
                for r in stage["rows"]
                if r["method"] not in ("item/started", "item/completed")
            ],
        )
        turn, thread = stage["turn"], stage["thread"]
        command = (
            original.discovery_command(stage, self.inventory, self.plan)
            + {
                "status": " --commands",
                "unknown": " --unknown-status-option",
                "missing": " --item --commands",
            }[name]
        )
        # Wrap the independently recovered exact command; executable aliases in
        # the old harness are accepted only by the unchanged executable oracle.
        original.status_argv(
            direct, stage, self.plan, legal=name == "status", inventory=self.inventory
        )
        for i, row in enumerate(stage["rows"]):
            row["emittedAtMs"] = 1793328376000 + i
        stage["rows"].append(
            dict(
                method="turn/completed",
                params=dict(threadId=thread, turn=dict(id=turn, status="completed")),
            )
        )
        path = self.plan["home"] + "/sessions/synthetic-rollout.jsonl"
        rpc = [
            dict(
                direction="request",
                message=dict(
                    id=1, method="thread/start", params=dict(cwd=self.plan["cwd"])
                ),
            ),
            dict(
                direction="response",
                message=dict(id=1, result=dict(thread=dict(id=thread, path=path))),
            ),
        ]
        rpc += [dict(direction="response", message=r) for r in stage["rows"]]
        trace = [
            dict(
                type="session_meta",
                payload=dict(id=thread, cwd=self.plan["cwd"], cli_version="0.165.0"),
            ),
            dict(type="event_msg", payload=dict(type="task_started", turn_id=turn)),
            dict(type="turn_context", payload=dict(turn_id=turn, cwd=self.plan["cwd"])),
            dict(
                type="response_item",
                timestamp="2026-10-30T02:46:15.000Z",
                payload=dict(
                    type="custom_tool_call",
                    status="completed",
                    name="exec",
                    call_id="call-" + name,
                    input=candidate.fixture(command, self.plan["cwd"]),
                ),
            ),
            dict(
                type="response_item",
                timestamp="2026-10-30T02:46:17.000Z",
                payload=dict(
                    type="custom_tool_call_output",
                    call_id="call-" + name,
                    output="Script completed\nWall time 0.7 seconds\nOutput:\n"
                    + json.dumps(
                        dict(
                            exit_code=direct["exitCode"],
                            output=direct["aggregatedOutput"],
                        )
                    ),
                ),
            ),
            dict(type="event_msg", payload=dict(type="task_complete", turn_id=turn)),
        ]
        stage["code_mode_evidence"] = dict(
            schema=candidate.CONTRACT,
            pins=candidate.pins(self.plan, command),
            command=command,
            rollout_path=path,
            rpc=CodeModeObservationTests.encoded(rpc).decode(),
            rollout=CodeModeObservationTests.encoded(trace).decode(),
        )
        return stage

    def test_full_status_state_oracle_and_both_negative_controls(self):
        self.adopted()
        status = self.transparent("status", ["--commands"])
        result = original.map_capture(self.capture)
        self.assertEqual(result["gates"]["status_cli_posttool"], "passed")
        original.validate_result(result)
        self.transparent("unknown", ["--unknown-status-option"])
        self.transparent("missing", ["--item", "--commands"])
        result = original.map_capture(self.capture)
        self.assertEqual(result["gates"]["status_negative_controls"], "passed")
        self.assertEqual(result["native_acceptance"], "not_run")
        item = original.command_observation(status, self.inventory, self.plan)
        bad = copy.deepcopy(item)
        bad["aggregatedOutput"] = "{}"
        with self.assertRaises(ValueError):
            original.status_output(bad, status, self.plan, inventory=self.inventory)

    def test_status_output_corruption_reaches_unchanged_full_state_oracle(self):
        self.adopted()
        stage = self.transparent("status", ["--commands"])
        evidence = stage["code_mode_evidence"]
        trace = [json.loads(r) for r in evidence["rollout"].splitlines()]
        output = trace[4]["payload"]["output"]
        nested = json.loads(output.split("Output:\n", 1)[1])
        actual = json.loads(nested["output"])
        for mutate in ("turn", "inventory", "token", "revision"):
            with self.subTest(mutate=mutate):
                altered = copy.deepcopy(actual)
                if mutate == "turn":
                    altered["turn_id"] = "foreign-turn"
                elif mutate == "inventory":
                    altered["advanced_commands"].pop("status")
                elif mutate == "token":
                    altered["advanced_commands"]["status"] = altered[
                        "advanced_commands"
                    ]["status"].replace("p0token", "wrongtoken")
                elif mutate == "revision":
                    altered["revision"] = "not-a-digest"
                nested["output"] = json.dumps(altered)
                trace[4]["payload"]["output"] = (
                    "Script completed\nWall time 0.7 seconds\nOutput:\n"
                    + json.dumps(nested)
                )
                evidence["rollout"] = CodeModeObservationTests.encoded(trace).decode()
                with self.assertRaises((ValueError, RuntimeError)):
                    original.map_capture(self.capture)

    def test_original_empty_store_only_record_cannot_be_promoted(self):
        self.adopted()
        stage = self.transparent("status", ["--commands"])
        trace = [
            json.loads(r) for r in stage["code_mode_evidence"]["rollout"].splitlines()
        ]
        trace[3]["payload"]["input"] = trace[3]["payload"]["input"].replace(
            "text(r)", 'store("diagnostic",r)'
        )
        trace[4]["payload"]["output"] = (
            "Script completed\nWall time 0.7 seconds\nOutput:\n"
        )
        stage["code_mode_evidence"]["rollout"] = CodeModeObservationTests.encoded(
            trace
        ).decode()
        with self.assertRaises(ValueError):
            original.map_capture(self.capture)

    def test_real_negative_post_silence_is_not_a_block(self):
        self.adopted()
        self.transparent("status", ["--commands"])
        stage = self.transparent("unknown", ["--unknown-status-option"])
        self.transparent("missing", ["--item", "--commands"])
        for row in stage["rows"]:
            if (
                row.get("method") == "hook/completed"
                and row["params"]["run"]["eventName"] == "postToolUse"
            ):
                row["params"]["run"]["status"] = "completed"
        rpc = [json.loads(r) for r in stage["code_mode_evidence"]["rpc"].splitlines()]
        for r in rpc:
            msg = r.get("message", {})
            if (
                msg.get("method") == "hook/completed"
                and msg["params"]["run"]["eventName"] == "postToolUse"
            ):
                msg["params"]["run"]["status"] = "completed"
        stage["code_mode_evidence"]["rpc"] = CodeModeObservationTests.encoded(
            rpc
        ).decode()
        with self.assertRaisesRegex(ValueError, "single completed real Hook"):
            original.map_capture(self.capture)

    def test_collector_exact_locator_and_cataloged_source_chain(self):
        self.adopted()
        stage = self.transparent("status", ["--commands"])
        evidence = stage["code_mode_evidence"]
        path = Path(evidence["rollout_path"])
        path.parent.mkdir(parents=True)
        path.write_text(evidence["rollout"])
        journal = self.root / "rpc" / "rpc.jsonl"
        journal.parent.mkdir()
        journal.write_text(evidence["rpc"])
        captured = candidate.capture(
            self.plan,
            stage,
            {"id": stage["thread"], "path": str(path)},
            journal,
            evidence["command"],
        )
        self.assertEqual(captured, evidence)
        (self.root / "rollout-status.jsonl").write_text(evidence["rollout"])
        candidate.verify_bundle_sources(self.root, self.capture)
        (self.root / "rollout-status.jsonl").write_text(evidence["rollout"] + " ")
        with self.assertRaisesRegex(ValueError, "cataloged RPC/rollout"):
            candidate.verify_bundle_sources(self.root, self.capture)
        with self.assertRaisesRegex(ValueError, "exact isolated rollout"):
            candidate.capture(
                self.plan,
                stage,
                {"id": "foreign", "path": str(path)},
                journal,
                evidence["command"],
            )

    def test_real_artifact_catalog_mapper_and_receipt_accept_new_profile(self):
        self.adopted()
        stage = self.transparent("status", ["--commands"])
        evidence = stage["code_mode_evidence"]
        directory = self.root
        (directory / "rpc").mkdir()
        (directory / "rpc/rpc.jsonl").write_text(evidence["rpc"])
        (directory / "rollout-status.jsonl").write_text(evidence["rollout"])
        original.write_new(directory / "capture.json", self.capture)
        catalog = {
            p.relative_to(directory).as_posix(): original.base.sha(p)
            for p in directory.rglob("*")
            if p.is_file()
        }
        original.write_new(directory / "artifacts.json", catalog)
        result = original.map_bundle(directory, directory / "result.json")
        original.validate_result(result)
        self.assertEqual(result["gate_profile"], original.PROFILE_CODE)
        self.assertEqual(result["gates"]["status_cli_posttool"], "passed")
        self.assertEqual(result["native_acceptance"], "not_run")

    def test_two_blocks_and_edge_LF_keep_full_status_oracle_and_exit71_failure(self):
        self.adopted()
        stage = self.transparent("status", ["--commands"])
        evidence = stage["code_mode_evidence"]
        trace = [json.loads(row) for row in evidence["rollout"].splitlines()]
        trace[3]["payload"]["input"] += "\n"
        header, terminal = trace[4]["payload"]["output"].split("Output:\n", 1)
        blocks = [
            {"type": "input_text", "text": header + "Output:\n"},
            {"type": "input_text", "text": terminal},
        ]
        trace[4]["payload"]["output"] = blocks
        evidence["rollout"] = CodeModeObservationTests.encoded(trace).decode()
        result = original.map_capture(self.capture)
        original.validate_result(result)
        self.assertEqual(result["gates"]["status_cli_posttool"], "passed")
        self.assertEqual(result["native_acceptance"], "not_run")
        # The actual observed host-failure shape reaches the real nonzero
        # oracle after both legal format surfaces are recognized.
        blocks[1]["text"] = json.dumps(
            dict(
                chunk_id="synthetic",
                wall_time_seconds=0,
                exit_code=71,
                original_token_count=14,
                output="sandbox-exec: sandbox_apply: Operation not permitted\n",
            )
        )
        evidence["rollout"] = CodeModeObservationTests.encoded(trace).decode()
        with self.assertRaisesRegex(ValueError, "successful complete result required"):
            original.map_capture(self.capture)

    def test_optional_metadata_does_not_relax_complete_status_json(self):
        self.adopted()
        stage = self.transparent("status", ["--commands"])
        evidence = stage["code_mode_evidence"]
        trace = [json.loads(row) for row in evidence["rollout"].splitlines()]
        prefix, raw = trace[4]["payload"]["output"].split("Output:\n", 1)
        nested = json.loads(raw)
        nested["original_token_count"] = 5.5
        trace[4]["payload"]["output"] = prefix + "Output:\n" + json.dumps(nested)
        evidence["rollout"] = CodeModeObservationTests.encoded(trace).decode()
        self.assertEqual(
            original.map_capture(self.capture)["gates"]["status_cli_posttool"], "passed"
        )
        nested["output"] = "Warning: truncated output\n" + nested["output"]
        trace[4]["payload"]["output"] = prefix + "Output:\n" + json.dumps(nested)
        evidence["rollout"] = CodeModeObservationTests.encoded(trace).decode()
        with self.assertRaises(ValueError):
            original.map_capture(self.capture)

    @unittest.skipIf(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        "POSIX root cannot prove write denial",
    )
    def test_production_make_fixture_readonly_connection_and_corrupt_witness(self):
        self.adopted()
        status = self.transparent("status", ["--commands"])
        item = original.command_observation(status, self.inventory, self.plan)
        fixture = self.root / "readonly-connection"
        fixture.mkdir()
        request = original.make_fixture(
            self.plan, status, item, fixture, inventory=self.inventory
        )
        self.addCleanup(original.child.restore, fixture, request["restriction"])
        record = original.child.witness(request)
        self.assertEqual(original.child.judge(record, request), "passed")
        argv = [
            self.plan["python"],
            str(original.ROOT / "tools/validation/incident_readonly_child.py"),
            "--request",
            str(self.root / "request.json"),
        ]
        command = original.cg.shell_join(argv)
        self.manifest["prompts"]["readonly"] = (
            "Run this exact ordinary tool command once: " + command
        )
        stage = self.stage("readonly")
        turn = stage["turn"]
        stage["name"] = "readonly"
        stage["rows"][2:2] = self.hook("preToolUse", turn) + self.hook(
            "postToolUse", turn
        )
        for i, row in enumerate(stage["rows"]):
            row["emittedAtMs"] = 1793328376000 + i
        stage["rows"].append(
            dict(
                method="turn/completed",
                params=dict(
                    threadId=stage["thread"], turn=dict(id=turn, status="completed")
                ),
            )
        )
        evidence = copy.deepcopy(status["code_mode_evidence"])
        trace = [json.loads(row) for row in evidence["rollout"].splitlines()]
        for row in trace:
            if "turn_id" in row["payload"]:
                row["payload"]["turn_id"] = turn
        trace[3]["payload"].update(
            input=candidate.fixture(command, self.plan["cwd"]), call_id="readonly-call"
        )
        trace[4]["payload"].update(
            call_id="readonly-call",
            output="Script completed\nWall time 0.7 seconds\nOutput:\n"
            + json.dumps(dict(exit_code=0, output=json.dumps(record))),
        )
        rpc = [json.loads(row) for row in evidence["rpc"].splitlines()][:2]
        rpc += [dict(direction="response", message=row) for row in stage["rows"]]
        evidence.update(
            command=command,
            pins=candidate.pins(self.plan, command),
            rollout=CodeModeObservationTests.encoded(trace).decode(),
            rpc=CodeModeObservationTests.encoded(rpc).decode(),
        )
        stage["code_mode_evidence"] = evidence
        self.capture.update(readonly_request=request, readonly_tool_argv=argv)
        result = original.map_capture(self.capture)
        original.validate_result(result)
        self.assertEqual(result["gates"]["restricted_child_readonly"], "passed")
        self.assertEqual(result["native_acceptance"], "not_run")
        altered = copy.deepcopy(record)
        altered["request_sha256"] = "0" * 64
        trace[4]["payload"]["output"] = (
            "Script completed\nWall time 0.7 seconds\nOutput:\n"
            + json.dumps(dict(exit_code=0, output=json.dumps(altered)))
        )
        evidence["rollout"] = CodeModeObservationTests.encoded(trace).decode()
        with self.assertRaises((ValueError, RuntimeError)):
            original.map_capture(self.capture)


if __name__ == "__main__":
    unittest.main()
