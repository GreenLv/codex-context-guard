"""0.17.2 evidence-reuse contract: per-node input-bound reuse decisions."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools" / "validation"
SPEC = importlib.util.spec_from_file_location(
    "behavior_evidence_reuse", TOOLS / "behavior_evidence_reuse.py")
assert SPEC is not None and SPEC.loader is not None
reuse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reuse)


class BehaviorEvidenceReuseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "scripts" / "product.py").write_text("a = 1\n",
                                                          encoding="utf-8")
        (self.root / "tests" / "test_product.py").write_text("b = 2\n",
                                                             encoding="utf-8")
        (self.root / "tools").mkdir()
        (self.root / "tools" / "runner.py").write_text("c = 3\n",
                                                       encoding="utf-8")

    def record(self, **overrides):
        spec = [{"node": "tests.test_product.test_one",
                 "code": ["scripts/product.py"],
                 "tests": ["tests/test_product.py"],
                 "runner": ["tools/runner.py"]}]
        spec = [{**spec[0], **overrides.get("spec", {})}]
        record = reuse.build_record(spec, root=self.root)
        record = {**record, **overrides.get("record", {})}
        return record

    def test_unchanged_inputs_reuse_and_acceptance_established(self):
        record = self.record()
        verdict = reuse.evaluate(record, self.root)
        self.assertEqual(verdict["reusable_count"], 1)
        self.assertEqual(verdict["stale_count"], 0)
        self.assertEqual(verdict["acceptance"], "established")
        self.assertEqual(verdict["entries"][0]["changed_inputs"], [])

    def test_changed_code_test_or_runner_bytes_are_stale_with_named_input(self):
        for group, path in (("code", "scripts/product.py"),
                            ("tests", "tests/test_product.py"),
                            ("runner", "tools/runner.py")):
            with self.subTest(group=group):
                record = self.record()
                (self.root / path).write_text("changed\n", encoding="utf-8")
                verdict = reuse.evaluate(record, self.root)
                entry = verdict["entries"][0]
                self.assertEqual(entry["verdict"], "stale")
                self.assertEqual(entry["changed_inputs"], [f"{group}:{path}"])
                self.assertEqual(verdict["acceptance"], "not_established")
                (self.root / path).write_text({"code": "a = 1\n",
                                               "tests": "b = 2\n",
                                               "runner": "c = 3\n"}[group],
                                              encoding="utf-8")

    def test_missing_bound_file_is_stale_fail_closed(self):
        record = self.record()
        (self.root / "scripts" / "product.py").unlink()
        verdict = reuse.evaluate(record, self.root)
        self.assertEqual(verdict["entries"][0]["changed_inputs"],
                         ["code:scripts/product.py:missing"])
        self.assertEqual(verdict["entries"][0]["verdict"], "stale")

    def test_environment_change_is_stale_but_platform_family_matches_host(self):
        record = self.record()
        record["entries"][0]["environment"]["python"] = "3.9.0"
        verdict = reuse.evaluate(record, self.root)
        self.assertEqual(verdict["entries"][0]["changed_inputs"],
                         ["environment:python"])

    def test_partial_reuse_never_establishes_the_record(self):
        record = self.record(spec={"node": "tests.test_product.test_one"})
        second = dict(record["entries"][0])
        second["node"] = "tests.test_product.test_two"
        second["code"] = {"scripts/product.py": "0" * 64}
        record["entries"].append(second)
        verdict = reuse.evaluate(record, self.root)
        self.assertEqual(verdict["reusable_count"], 1)
        self.assertEqual(verdict["stale_count"], 1)
        self.assertEqual(verdict["acceptance"], "not_established")

    def test_unrecognized_record_shape_is_refused(self):
        for bad in ({}, {"schema": "other"}, {"schema": reuse.RECORD_SCHEMA}):
            with self.subTest(bad=bool(bad)):
                with self.assertRaises(ValueError):
                    reuse.evaluate(bad, self.root)

    def test_cli_refuses_unreadable_records_and_reports_stale_nodes(self):
        record = self.record()
        record_path = self.root / "record.json"
        record_path.write_text(json.dumps(record), encoding="utf-8")
        (self.root / "tools" / "runner.py").write_text("drift\n",
                                                       encoding="utf-8")
        out = self.root / "verdict.json"
        proc = __import__("subprocess").run(
            [sys.executable, "-B", str(TOOLS / "behavior_evidence_reuse.py"),
             "--record", str(record_path), "--root", str(self.root),
             "--json-out", str(out)],
            text=True, capture_output=True, timeout=60)
        # A stale record is a nonzero outcome: silence is never reuse.
        self.assertEqual(proc.returncode, 1)
        verdict = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(verdict["acceptance"], "not_established")
        self.assertIn("runner:tools/runner.py", proc.stdout)
        bad = self.root / "bad.json"
        bad.write_text("{", encoding="utf-8")
        proc = __import__("subprocess").run(
            [sys.executable, "-B", str(TOOLS / "behavior_evidence_reuse.py"),
             "--record", str(bad), "--root", str(self.root)],
            text=True, capture_output=True, timeout=60)
        self.assertEqual(proc.returncode, 2)

    def test_under_bound_or_malformed_records_are_refused(self):
        # A missing environment never fails open, and malformed shapes are
        # refused cleanly (ValueError, exit 2) instead of crashing.
        for mutate in (
                lambda e: e.pop("environment"),
                lambda e: e["environment"].pop("machine"),
                lambda e: e.update(runner=None),
                lambda e: e.update(code={}),
                lambda e: e.update(code={"../escape": "0" * 64}),
                lambda e: e.update(code={"scripts/product.py": "zz"})):
            with self.subTest():
                record = self.record()
                mutate(record["entries"][0])
                with self.assertRaises(ValueError):
                    reuse.evaluate(record, self.root)

    def test_build_record_refuses_missing_files_upfront(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            reuse.build_record([{
                "node": "n", "code": ["scripts/absent.py"],
                "tests": ["tests/test_product.py"],
                "runner": ["tools/runner.py"]}])


if __name__ == "__main__":
    unittest.main()
