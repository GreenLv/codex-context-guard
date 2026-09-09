"""Composite execution plumbing tests; synthetic children are not native proof."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "host_composite", ROOT / "tools/validation/host_behavior_composite.py"
)
assert SPEC and SPEC.loader
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class Fixture:
    def __init__(self, root):
        self.root = root.resolve()
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self.subject = dict(
            source_commit="a" * 40,
            prepared_source_sha256="b" * 64,
            runtime_tree_sha256="c" * 64,
            plugin_version="1.2.3",
        )
        self.children = []
        for kind, owned in C.PARTITIONS.items():
            carrier = self.root / kind
            tools = carrier / "tools/validation"
            tools.mkdir(parents=True)
            result = {
                "schema": "native-acceptance/v2",
                "status": "pending",
                "product": "codex_context_guard",
                "gate_profile": "host_behavior",
                "subject": {
                    "kind": "prepared_host_behavior",
                    **{k: v for k, v in self.subject.items() if k != "plugin_version"},
                },
                "runtime_tree_sha256": "c" * 64,
                "platform": {
                    "os": "Darwin",
                    "shell": "real-host-capture",
                    "toolchain": {"python": "3.12.2", "codex": "codex-cli 0.153.4"},
                },
                "sessions": [{"session_id": kind, "scenarios": list(owned)}],
                "visibility": {"host_passed_reachable": False},
                "validation": {"schema": "synthetic-test-only"},
                "gates": [
                    {
                        "id": g,
                        "required": True,
                        "status": "passed" if g in owned else "pending",
                        "chain": "valid" if g in owned else "absent",
                        "exit_code": 0 if g in owned else 3,
                        "subject": {"kind": "runtime_tree", "id": "c" * 64},
                        "evidence": {
                            "mode": "reviewed_raw_mapping"
                            if g in owned
                            else "no_host_events"
                        },
                    }
                    for g in C.GATES
                ],
            }
            (tools / C.ADAPTERS[kind]).write_text(
                "def adapt(path, runtime, expected):\n"
                '    return {"subject": {}}, {"fresh_test_token": True}\n'
            )
            (tools / "host_capture.py").write_text(
                "# Synthetic unused test dependency.\n"
            )
            (tools / "host_behavior.py").write_text(
                "import json\nRESULT = json.loads(" + repr(json.dumps(result)) + ")\n"
                "class Validator:\n"
                "    def __init__(self, subject, version): pass\n"
                "    def validate(self, bundle, reviewed_mapping=None):\n"
                '        assert reviewed_mapping == {"fresh_test_token": True}\n'
                "        return RESULT\n"
            )
            manifest = carrier / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {"subject": self.subject, "capture": {"setup_sha256": "d" * 64}}
                )
            )
            result_file = carrier / "result.json"
            result_file.write_text(json.dumps(result))
            self.children.append(
                {
                    "kind": kind,
                    "carrier_root": str(carrier),
                    "runtime_root": str(self.runtime),
                    "tool_sha256": {
                        p.name: C.sha(p.read_bytes()) for p in tools.glob("*.py")
                    },
                    "manifest": str(manifest),
                    "manifest_sha256": C.sha(manifest.read_bytes()),
                    "result": str(result_file),
                    "result_sha256": C.sha(result_file.read_bytes()),
                    "gates": list(owned),
                }
            )
        self.m = {
            "schema": C.MANIFEST_SCHEMA,
            "validator_sha256": C.sha(Path(C.__file__).read_bytes()),
            "subject": self.subject,
            "platform": {"os": "macos", "python": "3.12.2", "codex": "0.153.4"},
            "children": self.children,
        }
        self.path = self.root / "composite.json"

    def run(self):
        self.path.write_text(json.dumps(self.m))
        return C.compose(self.path, C.sha(self.path.read_bytes()))


class CompositeTests(unittest.TestCase):
    def test_fresh_two_child_replays_cover_six_distinct_gates(self):
        with tempfile.TemporaryDirectory() as d:
            result = Fixture(Path(d)).run()
            self.assertEqual(result["status"], "passed")
            self.assertEqual({g["id"] for g in result["gates"]}, set(C.GATES))
            self.assertEqual(len(result["sessions"]), 2)
            self.assertEqual(result["scope"]["whole_p4"], "pending")
            self.assertTrue(
                all(g["evidence"]["source_result_sha256"] for g in result["gates"])
            )
            self.assertEqual(len(result["validation"]["children"]), 2)

    def test_subject_and_platform_mismatch_reject(self):
        for field, value in [
            ("subject", {"source_commit": "f" * 40}),
            ("platform", {"os": "windows"}),
        ]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as d:
                f = Fixture(Path(d))
                f.m[field].update(value)
                with self.assertRaises(C.CompositeError):
                    f.run()

    def test_changed_original_tool_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            f = Fixture(Path(d))
            p = Path(f.children[0]["carrier_root"]) / "tools/validation/host_capture.py"
            p.write_text(p.read_text() + "# changed\n")
            with self.assertRaisesRegex(C.CompositeError, "tool inventory"):
                f.run()

    def test_child_hash_and_rehashed_forged_result_reject(self):
        for update_hash in [False, True]:
            with (
                self.subTest(update_hash=update_hash),
                tempfile.TemporaryDirectory() as d,
            ):
                f = Fixture(Path(d))
                child = f.children[0]
                p = Path(child["result"])
                result = json.loads(p.read_text())
                result["status"] = "passed"
                p.write_text(json.dumps(result))
                if update_hash:
                    child["result_sha256"] = C.sha(p.read_bytes())
                with self.assertRaises(C.CompositeError):
                    f.run()

    def test_gate_duplicate_missing_or_expanded_partition_reject(self):
        for gates in [["hook_trust"], ["hook_trust"] * 3, list(C.GATES)]:
            with self.subTest(gates=gates), tempfile.TemporaryDirectory() as d:
                f = Fixture(Path(d))
                f.children[0]["gates"] = gates
                with self.assertRaisesRegex(C.CompositeError, "partition"):
                    f.run()

    def test_serialized_receipt_cannot_be_submitted_as_child_authority(self):
        with tempfile.TemporaryDirectory() as d:
            f = Fixture(Path(d))
            f.children[0]["receipt"] = {"mapped_gates": list(C.GATES)}
            with self.assertRaisesRegex(C.CompositeError, "shape"):
                f.run()
        with tempfile.TemporaryDirectory() as d:
            f = Fixture(Path(d))
            c = f.children[0]
            p = Path(c["manifest"])
            p.write_text(
                json.dumps(
                    {"schema": "serialized-receipt", "mapped_gates": list(C.GATES)}
                )
            )
            c["manifest_sha256"] = C.sha(p.read_bytes())
            with self.assertRaises(C.CompositeError):
                f.run()

    def test_failed_or_conflicted_unowned_gate_is_not_hidden(self):
        with tempfile.TemporaryDirectory() as d:
            f = Fixture(Path(d))
            c = f.children[0]
            result = json.loads(Path(c["result"]).read_text())
            for g in result["gates"]:
                if g["id"] not in c["gates"]:
                    g.update(status="failed", chain="contradicted")
                    break
            with self.assertRaisesRegex(C.CompositeError, "absent pending"):
                C.check_result(f.m, c, result)

    def test_platform_aliases_are_explicit_and_version_bound(self):
        value = {
            "os": "Darwin",
            "shell": "real-host-capture",
            "toolchain": {"python": "3.12.2", "codex": "codex-cli 0.153.4"},
        }
        self.assertEqual(
            C.normalize_platform(value),
            {"os": "macos", "python": "3.12.2", "codex": "0.153.4"},
        )
        invalid = copy.deepcopy(value)
        invalid["toolchain"]["codex"] = "other 0.153.4"
        with self.assertRaises(C.CompositeError):
            C.normalize_platform(invalid)

    def test_wrong_manifest_identity_and_duplicate_json_keys_reject(self):
        with tempfile.TemporaryDirectory() as d:
            f = Fixture(Path(d))
            f.path.write_text(json.dumps(f.m))
            with self.assertRaises(C.CompositeError):
                C.compose(f.path, "0" * 64)
            f.path.write_text('{"schema":1,"schema":2}')
            with self.assertRaisesRegex(C.CompositeError, "duplicate"):
                C.compose(f.path, C.sha(f.path.read_bytes()))


if __name__ == "__main__":
    unittest.main()
