"""Adversarial negative controls for the coverage validator (schema v3).

Each test forges one manipulation the acceptance scope forbids — a swapped
case id, a fabricated successor, a fake locator file, a method owned by the
wrong class, a pass verdict over pending platform evidence, a tampered
title — and proves the validator rejects it. Count-only validation would
accept several of these forgeries.
"""

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import check_incident_coverage as cic  # noqa: E402


def load_pair():
    index = json.loads((REPO_ROOT / "tests/fixtures/incidents/"
                        "library_case_index.json").read_text(encoding="utf-8"))
    coverage = json.loads(
        (REPO_ROOT / "tests/fixtures/incidents/"
         "historical_case_coverage.json").read_text(encoding="utf-8"))
    return index, coverage


def pending_windows_case(table):
    """Build a negative-control state independently of live acceptance status."""
    row = next(row for row in table["cases"]
               if row["id"] == "CGI-20260913-codex-archive-043")
    row.update(final_verdict="pending", windows_result="pending",
               missing_evidence=["synthetic missing Windows receipt"],
               owner="coordinator")
    row.pop("windows_evidence", None)
    return row


class CoverageForgeryTests(unittest.TestCase):
    def setUp(self):
        self.index, self.base = load_pair()

    def forge(self):
        return copy.deepcopy(self.base)

    def test_baseline_table_is_valid(self):
        self.assertEqual(cic.validate_coverage(self.index, self.base), [])
        errors: list[str] = []
        cic.WINDOWS_NOT_REQUIRED_FROZEN = set(
            self.index.get("windows_not_required_case_ids") or [])
        try:
            verdicts = cic.validate_rows(self.base["cases"]
                                         + self.base["legacy"],
                                         REPO_ROOT, errors)
        finally:
            cic.WINDOWS_NOT_REQUIRED_FROZEN = None
        self.assertEqual(errors, [])
        self.assertEqual(sum(verdicts.values()), 52)

    def test_swapped_case_id_rejected(self):
        forged = self.forge()
        forged["cases"][0]["id"] = "CGI-20990101-codex-not-in-library"
        errors = cic.validate_coverage(self.index, forged)
        self.assertTrue(any("id set differs" in error for error in errors),
                        errors)

    def test_tampered_title_rejected(self):
        forged = self.forge()
        forged["cases"][0]["title"] = "Unrelated forged summary"
        errors = cic.validate_coverage(self.index, forged)
        self.assertTrue(any("title differs" in error for error in errors),
                        errors)

    def test_fabricated_successor_rejected(self):
        forged = self.forge()
        for row in forged["cases"]:
            if row["status"] == "superseded":
                row["successor"] = "CGI-20260913-codex-archive-009"
                break
        errors = cic.validate_coverage(self.index, forged)
        self.assertTrue(any("not the library's real successor" in error
                            for error in errors), errors)

    def test_active_row_claiming_successor_rejected(self):
        forged = self.forge()
        for row in forged["cases"]:
            if row["status"] == "active":
                row["successor"] = "CGI-20260913-codex-archive-022"
                break
        errors = cic.validate_coverage(self.index, forged)
        self.assertTrue(any("must not claim a successor" in error
                            for error in errors), errors)

    def test_fake_locator_file_rejected(self):
        errors: list[str] = []
        cic.resolve_locator(REPO_ROOT,
                            "tests/does_not_exist.py::NoSuchClass::test_not_real",
                            errors)
        self.assertTrue(any("file missing" in error for error in errors))

    def test_wrong_class_method_ownership_rejected(self):
        errors: list[str] = []
        # The method exists, but on a different class than claimed.
        cic.resolve_locator(
            REPO_ROOT,
            "tests/test_incident_library_regression.py::SilentAllowCases::"
            "test_cgi_2026_009_017_026_default_path_allows_ordinary_business",
            errors)
        self.assertTrue(any("not owned by class" in error for error in errors))

    def test_pass_over_pending_platform_evidence_rejected(self):
        forged = self.forge()
        row = pending_windows_case(forged)
        row["final_verdict"] = "executed_pass"
        errors: list[str] = []
        cic.validate_rows(forged["cases"], REPO_ROOT, errors)
        self.assertTrue(
            any("executed_pass requires windows passed or not_required" in e
                or "cannot coexist" in e for e in errors), errors)

    def test_pending_without_missing_evidence_rejected(self):
        forged = self.forge()
        row = pending_windows_case(forged)
        row["missing_evidence"] = []
        errors: list[str] = []
        cic.validate_rows(forged["cases"], REPO_ROOT, errors)
        self.assertTrue(any("pending without missing_evidence" in error
                            for error in errors), errors)

    def test_not_applicable_shortcut_rejected(self):
        forged = self.forge()
        for row in forged["cases"]:
            if row["status"] == "active":
                row["final_verdict"] = "not_applicable"
                break
        errors: list[str] = []
        cic.validate_rows(forged["cases"], REPO_ROOT, errors)
        self.assertTrue(any("not_applicable requires" in error
                            for error in errors), errors)


class PlatformEnumAndExecutionControls(unittest.TestCase):
    """Review round-2 counterexamples: platform failures promoted to pass,
    and a required second locator whose failure the runner never saw."""

    @classmethod
    def setUpClass(cls):
        cls.index, cls.table = load_pair()

    def forge(self):
        import copy
        return copy.deepcopy(self.table)

    def test_failed_platform_cannot_be_executed_pass(self):
        for field in ("windows_result", "macos_result"):
            with self.subTest(field=field):
                forged = self.forge()
                row = pending_windows_case(forged)
                row.update(windows_result="failed" if field == "windows_result"
                           else row.get("windows_result"),
                           macos_result="failed" if field == "macos_result"
                           else row.get("macos_result"),
                           final_verdict="executed_pass",
                           source_result="passed", missing_evidence=[])
                errors = []
                cic.validate_rows(forged["cases"], REPO_ROOT, errors)
                self.assertTrue(
                    any("cannot coexist" in e for e in errors), errors)

    def test_out_of_vocabulary_result_rejected(self):
        forged = self.forge()
        row = next(r for r in forged["cases"] if r["status"] == "active")
        row["source_result"] = "unknown"
        errors = []
        cic.validate_rows(forged["cases"], REPO_ROOT, errors)
        self.assertTrue(any("outside the closed vocabulary" in e
                            for e in errors), errors)

    def test_pending_requires_an_unpassed_platform(self):
        forged = self.forge()
        row = pending_windows_case(forged)
        row["windows_result"] = "passed"
        errors = []
        cic.validate_rows(forged["cases"], REPO_ROOT, errors)
        self.assertTrue(any("needs at least one unpassed platform" in e
                            for e in errors), errors)

    def test_every_required_locator_executes_and_fails_loudly(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            (root / "tests/test_two.py").write_text(
                "import unittest\n"
                "class TestProbe(unittest.TestCase):\n"
                " def test_pass(self): self.assertTrue(True)\n"
                " def test_fail(self): self.fail('required test fails')\n")
            row = dict(id="probe", status="active",
                       test_locator="tests/test_two.py::TestProbe::test_pass "
                                    "and ::test_fail")
            errors: list[str] = []
            receipts = cic.execute_receipts(root, [row], errors)
            receipt = receipts["probe"]
            self.assertEqual(len(receipt["nodeids"]), 2)
            self.assertIn("tests/test_two.py::TestProbe::test_fail",
                          receipt["results"])
            self.assertEqual(receipt["results"][
                "tests/test_two.py::TestProbe::test_fail"], 1)
            self.assertTrue(any("required nodeid not passed" in e
                                for e in errors), errors)

    def test_nodeid_expansion_inherits_file_and_class(self):
        nodeids = cic.locator_nodeids(
            "tests/a.py::A::m1 and ::m2; tests/b.py::B::m3")
        self.assertEqual(nodeids, ["tests/a.py::A::m1", "tests/a.py::A::m2",
                                   "tests/b.py::B::m3"])

    def test_empty_nodeid_collection_rejected(self):
        row = dict(id="empty", status="active", test_locator="notes.md only")
        errors: list[str] = []
        receipts = cic.execute_receipts(REPO_ROOT, [row], errors)
        self.assertFalse(receipts["empty"]["executed"])
        self.assertTrue(any("no executable in-repo nodeid" in e
                            for e in errors))

    def test_receipts_bind_test_file_bytes(self):
        """Receipt digests must match current file bytes (stale guard)."""
        import hashlib
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            (root / "tests/test_bind.py").write_text(
                "import unittest\nclass B(unittest.TestCase):\n"
                " def test_ok(self): self.assertTrue(True)\n")
            row = dict(id="bind", status="active",
                       test_locator="tests/test_bind.py::B::test_ok")
            errors: list[str] = []
            receipts = cic.execute_receipts(root, [row], errors)
            digest = receipts["bind"]["file_digests"][
                "tests/test_bind.py::B::test_ok"]
            self.assertEqual(
                digest,
                hashlib.sha256((root / "tests/test_bind.py").read_bytes())
                .hexdigest())
            # Mutating the file afterwards makes the receipt stale.
            (root / "tests/test_bind.py").write_text(
                "import unittest\nclass B(unittest.TestCase):\n"
                " def test_ok(self): self.assertTrue(True)\n# changed\n")
            current = hashlib.sha256(
                (root / "tests/test_bind.py").read_bytes()).hexdigest()
            self.assertNotEqual(digest, current)


class RequiredNodeOutcomeControls(unittest.TestCase):
    """A required nodeid must actually PASS: skip/xfail/zero-collection are
    not executed assertions even when pytest exits 0."""

    def run_receipt(self, source, method="test_native"):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            (root / "tests/test_outcome.py").write_text(source)
            row = dict(id="probe", status="active",
                       test_locator=f"tests/test_outcome.py::TestProbe::{method}")
            errors: list[str] = []
            receipts = cic.execute_receipts(root, [row], errors)
            key = f"tests/test_outcome.py::TestProbe::{method}"
            return (receipts["probe"]["outcomes"][key], errors)

    def test_teardown_error_rejected(self):
        """Review r4 counterexample: pass surface + nonzero exit must fail."""
        outcome, errors = self.run_receipt(
            "class TestProbe:\n"
            " def test_native(self): pass\n"
            " def teardown_method(self): raise RuntimeError('cleanup failed')\n")
        self.assertIn(outcome, ("error", "failed"))
        self.assertTrue(any("not passed" in e for e in errors), errors)

    def test_setup_error_rejected(self):
        outcome, errors = self.run_receipt(
            "import pytest\n"
            "@pytest.fixture\n"
            "def boom():\n"
            " raise RuntimeError('setup')\n"
            "class TestProbe:\n"
            " def test_native(self, boom): pass\n")
        self.assertIn(outcome, ("error", "failed"))
        self.assertTrue(any("not passed" in e for e in errors))

    def test_call_failure_rejected(self):
        outcome, errors = self.run_receipt(
            "class TestProbe:\n"
            " def test_native(self): self.fail('call failed')\n")
        self.assertEqual(outcome, "failed")
        self.assertTrue(any("not passed (failed)" in e for e in errors))

    def test_xpass_rejected(self):
        outcome, errors = self.run_receipt(
            "import unittest\nclass TestProbe(unittest.TestCase):\n"
            " @unittest.expectedFailure\n"
            " def test_native(self): self.assertTrue(True)\n")
        self.assertIn(outcome, ("xpassed", "failed"))
        self.assertTrue(any("not passed" in e for e in errors), errors)

    def test_passing_required_nodeid_accepted(self):
        outcome, errors = self.run_receipt(
            "import unittest\nclass TestProbe(unittest.TestCase):\n"
            " def test_native(self): self.assertTrue(True)\n")
        self.assertEqual(outcome, "passed")
        self.assertEqual(errors, [])


class FrozenWaiverControls(unittest.TestCase):
    def setUp(self):
        self.index, self.table = load_pair()

    def test_required_windows_cannot_self_waive(self):
        import copy

        forged = copy.deepcopy(self.table)
        row = pending_windows_case(forged)
        row.update(windows_result="not_required", source_result="passed",
                   macos_result="passed", final_verdict="executed_pass",
                   missing_evidence=[])
        errors: list[str] = []
        cic.WINDOWS_NOT_REQUIRED_FROZEN = set(
            self.index.get("windows_not_required_case_ids") or [])
        try:
            cic.validate_rows(forged["cases"], REPO_ROOT, errors)
        finally:
            cic.WINDOWS_NOT_REQUIRED_FROZEN = None
        self.assertTrue(any("frozen applicability waiver" in e
                            for e in errors), errors)

    def test_legitimate_not_required_still_accepted(self):
        errors: list[str] = []
        cic.WINDOWS_NOT_REQUIRED_FROZEN = set(
            self.index.get("windows_not_required_case_ids") or [])
        try:
            verdicts = cic.validate_rows(self.table["cases"]
                                         + self.table["legacy"],
                                         REPO_ROOT, errors)
        finally:
            cic.WINDOWS_NOT_REQUIRED_FROZEN = None
        self.assertEqual(errors, [])
        self.assertEqual(sum(verdicts.values()), 52)


class DefaultCliAndIdentityControls(unittest.TestCase):
    def test_default_cli_runs_without_execute(self):
        import subprocess

        completed = subprocess.run(
            [sys.executable, "scripts/check_incident_coverage.py", "."],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=300)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)
        self.assertIn('"valid": true', completed.stdout)

    def test_canonical_identity_matches_handoff_encoding(self):
        """The checker delegates to the ONE v2 implementation; this control
        recomputes the canonical encoding independently (HEAD-bound, NUL
        status with untracked-files=all, explicit bindings) and requires
        byte equality with both the checker and the CLI tool."""
        import hashlib

        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
                              capture_output=True, text=True).stdout.strip()
        raw = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z",
             "--untracked-files=all"], cwd=REPO_ROOT, capture_output=True
        ).stdout
        entries = [item for item in raw.split(b"\0") if item]
        digest = hashlib.sha256()
        digest.update(b"prepared-source/v2\0")
        digest.update(head.encode())
        digest.update(b"\0")
        index = 0
        while index < len(entries):
            entry = entries[index]
            xy = entry[:2].decode()
            path = entry[3:].decode("utf-8", "surrogateescape")
            index += 1
            if "R" in xy or "C" in xy:
                index += 1  # origin path handled by the canonical impl
            target = REPO_ROOT / path
            digest.update(path.encode())
            digest.update(b"\0")
            digest.update(hashlib.sha256(target.read_bytes()).digest()
                          if target.is_file() else b"deleted")
            digest.update(b"\0")
        identity = cic.prepared_source_identity(REPO_ROOT)
        self.assertEqual(identity["head"], head)
        self.assertEqual(identity["prepared_source_sha256"],
                         digest.hexdigest())
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "ai", REPO_ROOT / "tools/validation/acceptance_identity.py")
        ai = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ai)
        self.assertEqual(ai.prepared_source_identity(REPO_ROOT)
                         ["prepared_source_sha256"],
                         identity["prepared_source_sha256"])
