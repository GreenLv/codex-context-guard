#!/usr/bin/env python3
"""Contract tests for the private incident-corpus tooling and public fixtures."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "incident_corpus.py"
FIXTURES = ROOT / "tests" / "fixtures" / "incidents" / "public_incidents.json"
RUNTIME = ROOT / "scripts" / "context_guard.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("incident_corpus", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IncidentCorpusTests(unittest.TestCase):
    def test_public_fixture_contract_and_taxonomy(self) -> None:
        tool = load_tool()
        fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
        self.assertEqual({item["root_cause"] for item in fixtures}, tool.ROOT_CAUSES)
        for fixture in fixtures:
            self.assertEqual(tool.validate_record(fixture, public=True), [])

    def test_current_runtime_passes_public_benchmark_without_false_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "benchmark",
                    "--fixtures",
                    str(FIXTURES),
                    "--runtime",
                    str(RUNTIME),
                    "--report-dir",
                    temporary,
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            generated = sorted(Path(temporary).iterdir())
            self.assertEqual(
                [item.name for item in generated],
                [
                    "stop-2-0-0.json",
                    "stop-2-0-0.manifest.json",
                    "stop-2-0-0.md",
                ],
            )
            self.assertTrue(
                all((os.stat(item).st_mode & 0o777) == 0o600 for item in generated)
            )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["plugin_stop_protocol"], "2.0.0")
        self.assertEqual(report["fixtures"], report["passed"])
        self.assertEqual(report["false_continuations"], 0)
        self.assertIsInstance(report["diagnostic_accuracy"], float)

    def test_append_only_ingest_validate_and_summary_excludes_documented_only(self) -> None:
        tool = load_tool()
        fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))[0]
        fixture.update({"reproduction_status": "documented_only", "public_reviewed": True, "public_fixture_id": "public-CGI-2026-001"})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "corpus"
            source = Path(temporary) / "record.json"
            source.write_text(json.dumps(fixture), encoding="utf-8")
            args = type("Args", (), {"root": str(root), "record": str(source)})()
            self.assertEqual(tool.command_ingest(args), 0)
            self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)
            record_path = root / "records" / "CGI-2026-001.json"
            self.assertEqual(os.stat(record_path).st_mode & 0o777, 0o600)
            records, errors = tool.load_records(root)
            self.assertEqual(errors, [])
            report = tool.summarize(records)
            self.assertEqual(report["documented_only"], 1)
            self.assertEqual(report["eligible_denominator"], 0)
            exported = Path(temporary) / "public.json"
            export_args = type(
                "Args", (), {"root": str(root), "output": str(exported)}
            )()
            self.assertEqual(tool.command_export_public(export_args), 0)
            self.assertEqual(os.stat(exported).st_mode & 0o777, 0o600)
            public = json.loads(exported.read_text(encoding="utf-8"))
            self.assertEqual(len(public), 1)
            self.assertNotIn("public_reviewed", public[0])
            with self.assertRaises(ValueError):
                tool.command_ingest(args)


if __name__ == "__main__":
    unittest.main()
