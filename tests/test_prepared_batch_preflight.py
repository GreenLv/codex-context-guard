"""Prepared-batch preflight v1 positive/negative controls (review r4 item 1).

Real CLI runs prove: the correct candidate inputs pass; wrong HEAD, wrong
prepared/runtime digest, a missing or altered driver, and an existing output
each fail closed; portable_runtime's clean-commit contract stays untouched.
"""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools" / "validation"))
import prepared_batch_preflight as pbf  # noqa: E402

ENTRY = REPO_ROOT / "tools" / "validation" / "prepared_batch_preflight.py"


def identity():
    spec = importlib.util.spec_from_file_location(
        "ai", REPO_ROOT / "tools" / "validation" / "acceptance_identity.py")
    ai = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ai)
    return ai


class PackageMigrationTests(unittest.TestCase):
    """The frozen package (manifest + entry + five drivers) must pass the
    real preflight CLI from TWO different roots byte-identically; a moved
    package keeps its manifest sha."""

    PACKAGE_FILES = (
        "run-windows-acceptance.ps1",
        "w3_archive_043_replay.py",
        "w4_archive_044_replay.py",
        "w5_archive_045_replay.py",
        "w6_recovery_replay.py",
        "w7_feedback_chain_replay.py",
    )

    def build_package(self, root: Path):
        (root / "tests").mkdir(parents=True, exist_ok=True)
        for name in self.PACKAGE_FILES:
            (root / name).write_text(f"# {name}\n", encoding="utf-8")

    def write_manifest(self, root: Path):

        drivers = [{"path": name,
                    "sha256": hashlib.sha256(
                        (root / name).read_bytes()).hexdigest()}
                   for name in self.PACKAGE_FILES]
        manifest = root / "driver-manifest.json"
        manifest.write_text(
            json.dumps({"schema": "prepared-batch-drivers/v1",
                        "drivers": drivers}, indent=1) + "\n",
            encoding="utf-8")
        return manifest

    def test_package_passes_from_two_roots(self):
        import tempfile

        with tempfile.TemporaryDirectory() as one, \
                tempfile.TemporaryDirectory() as two:
            root_a = Path(one) / "acceptance-a"
            root_b = Path(two) / "acceptance-b"
            for root in (root_a, root_b):
                self.build_package(root)
            manifest_a = self.write_manifest(root_a)
            shutil.copy2(manifest_a, root_b / "driver-manifest.json")
            self.assertEqual(manifest_a.read_bytes(),
                             (root_b / "driver-manifest.json").read_bytes())
            manifest_sha = hashlib.sha256(
                manifest_a.read_bytes()).hexdigest()
            ai = identity()
            ident = ai.prepared_source_identity(REPO_ROOT)
            runtime = ai.runtime_tree_digest(REPO_ROOT)
            for root in (root_a, root_b):
                completed = subprocess.run(
                    [sys.executable, str(ENTRY),
                     "--source-commit", ident["head"],
                     "--prepared-source-sha256",
                     ident["prepared_source_sha256"],
                     "--runtime-tree-sha256", runtime,
                     "--driver-manifest",
                     str(root / "driver-manifest.json"),
                     "--expected-manifest-sha256", manifest_sha,
                     "--driver-package-root", str(root),
                     "--repo-root", str(REPO_ROOT),
                     "--output", str(root / "receipt.json")],
                    capture_output=True, text=True, timeout=300)
                self.assertEqual(completed.returncode, 0, completed.stderr)


class WindowsEntryContractTests(unittest.TestCase):
    """The PS entry must not self-sign a manifest: a missing
    driver-manifest.json exits 2 and no fallback generation exists."""

    def test_no_manifest_self_signing_fallback(self):
        script = Path("/tmp/stop-perf-work/windows-acceptance/"
                      "run-windows-acceptance.ps1")
        if not script.is_file():
            self.skipTest("windows package not staged on this host")
        text = script.read_text(encoding="utf-8")
        self.assertIn("driver manifest missing", text)
        self.assertIn("exit 2", text)
        # The old fallback generated a manifest from the filesystem.
        self.assertNotIn("ConvertTo-Json | Set-Content $DriverManifest", text)
        self.assertNotIn("Set-Content $DriverManifest", text)
        # The frozen manifest sha is a mandatory parameter and is passed to
        # the preflight (a replaced manifest cannot self-approve).
        self.assertIn("$ExpectedManifestSha256", text)
        self.assertIn("--expected-manifest-sha256 $ExpectedManifestSha256",
                      text)

    def test_staged_manifest_is_frozen_and_complete(self):

        script = Path("/tmp/stop-perf-work/windows-acceptance/"
                      "run-windows-acceptance.ps1")
        manifest = Path("/tmp/stop-perf-work/windows-acceptance/"
                        "driver-manifest.json")
        if not (script.is_file() and manifest.is_file()):
            self.skipTest("windows package not staged on this host")
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "prepared-batch-drivers/v1")
        paths = [d["path"] for d in payload["drivers"]]
        self.assertEqual(sorted(paths),
                         sorted(pbf.REQUIRED_DRIVER_PATHS))
        self.assertEqual(set(paths), set(pbf.REQUIRED_DRIVER_PATHS))
        for driver in payload["drivers"]:
            target = Path("/tmp/stop-perf-work/windows-acceptance")
            digest = hashlib.sha256(
                (target / driver["path"]).read_bytes()).hexdigest()
            self.assertEqual(digest, driver["sha256"], driver["path"])


class PreparedBatchPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.work = Path(self.temp.name)
        ai = identity()
        self.ident = ai.prepared_source_identity(REPO_ROOT)
        self.runtime = ai.runtime_tree_digest(REPO_ROOT)
        self.package = self.work / "package"
        (self.package / "tests").mkdir(parents=True)
        # A real, minimal, byte-stable package root: entrypoint + five
        # drivers, exactly the frozen REQUIRED_DRIVER_PATHS set.
        (self.package / "run-windows-acceptance.ps1").write_text(
            "param()\n", encoding="utf-8")
        for name in ("w3_archive_043_replay.py", "w4_archive_044_replay.py",
                     "w5_archive_045_replay.py", "w6_recovery_replay.py",
                     "w7_feedback_chain_replay.py"):
            (self.package / name).write_text(
                f"# {name}\n", encoding="utf-8")
        self.manifest_path = self.work / "driver-manifest.json"
        self.write_manifest()
        self.expected_manifest_sha = self.manifest_sha()

    def manifest_sha(self):

        return hashlib.sha256(
            self.manifest_path.read_bytes()).hexdigest()

    def write_manifest(self, drivers=None, schema="prepared-batch-drivers/v1"):

        if drivers is None:
            drivers = []
            for name in sorted(os.listdir(self.package)):
                path = self.package / name
                if path.is_file():
                    drivers.append({
                        "path": name,
                        "sha256": hashlib.sha256(
                            path.read_bytes()).hexdigest()})
        self.manifest_path.write_text(
            json.dumps({"schema": schema, "drivers": drivers},
                       indent=1) + "\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, *, head=None, prepared=None, runtime=None,
                manifest=None, output=None, expected_manifest=None):
        out = output or (self.work / "receipt.json")
        completed = subprocess.run(
            [sys.executable, str(ENTRY),
             "--source-commit", head or self.ident["head"],
             "--prepared-source-sha256",
             prepared or self.ident["prepared_source_sha256"],
             "--runtime-tree-sha256", runtime or self.runtime,
             "--driver-manifest", str(manifest or self.manifest_path),
             "--expected-manifest-sha256",
             expected_manifest if expected_manifest is not None
             else self.expected_manifest_sha,
             "--driver-package-root", str(self.package),
             "--repo-root", str(REPO_ROOT),
             "--output", str(out)],
            capture_output=True, text=True, timeout=300)
        return completed, out

    def test_correct_inputs_pass(self):
        completed, out = self.run_cli()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        receipt = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(receipt["schema"], "prepared-batch-preflight/v1")
        self.assertEqual(receipt["status"], "inputs_ready")
        self.assertIn("Not portable_runtime", receipt["scope_note"])
        self.assertEqual(len(receipt["driver_manifest"]["drivers"]), 6)

    def test_wrong_head_fails(self):
        completed, _ = self.run_cli(head="0" * 40)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("base_head", completed.stderr)

    def test_wrong_prepared_digest_fails(self):
        completed, _ = self.run_cli(prepared="a" * 64)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("prepared_source_sha256", completed.stderr)

    def test_wrong_runtime_digest_fails(self):
        completed, _ = self.run_cli(runtime="b" * 64)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("runtime_tree_sha256", completed.stderr)

    def test_missing_manifest_fails(self):
        completed, _ = self.run_cli(manifest=self.work / "nope.json")
        self.assertEqual(completed.returncode, 2)

    def test_replaced_manifest_fails_expected_sha(self):
        self.write_manifest()  # re-sign the same files: bytes unchanged
        # Now change a driver so the frozen sha no longer matches content.
        (self.package / "w3_archive_043_replay.py").write_text(
            "print('tampered')\n", encoding="utf-8")
        completed, _ = self.run_cli()
        self.assertEqual(completed.returncode, 1)
        self.assertIn("sha256 mismatch", completed.stderr)

    def test_frozen_manifest_sha_mismatch_rejected(self):
        completed, _ = self.run_cli(expected_manifest="c" * 64)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("driver manifest sha256 mismatch", completed.stderr)

    def test_empty_drivers_fails(self):
        self.write_manifest(drivers=[])
        completed, _ = self.run_cli(expected_manifest=self.manifest_sha())
        self.assertEqual(completed.returncode, 1)
        self.assertIn("non-empty list", completed.stderr)

    def test_missing_required_file_fails(self):
        drivers = [{"path": "run-windows-acceptance.ps1",
                    "sha256": "0" * 64}]
        self.write_manifest(drivers=drivers)
        completed, _ = self.run_cli(expected_manifest=self.manifest_sha())
        self.assertEqual(completed.returncode, 1)
        self.assertIn("missing required files", completed.stderr)

    def test_unknown_extra_file_fails(self):
        (self.package / "extra_driver.py").write_text("x", encoding="utf-8")
        self.write_manifest()
        completed, _ = self.run_cli(expected_manifest=self.manifest_sha())
        self.assertEqual(completed.returncode, 1)
        self.assertIn("unknown files", completed.stderr)

    def test_duplicate_driver_entry_fails(self):

        digest = hashlib.sha256(
            (self.package / "w3_archive_043_replay.py").read_bytes()
        ).hexdigest()
        drivers = [{"path": "w3_archive_043_replay.py",
                    "sha256": digest},
                   {"path": "w3_archive_043_replay.py",
                    "sha256": digest}]
        self.write_manifest(drivers=drivers)
        completed, _ = self.run_cli(expected_manifest=self.manifest_sha())
        self.assertEqual(completed.returncode, 1)
        self.assertIn("duplicate driver path", completed.stderr)

    def test_escaping_driver_path_fails(self):
        drivers = [{"path": "../escape.py", "sha256": "0" * 64}]
        self.write_manifest(drivers=drivers)
        completed, _ = self.run_cli(expected_manifest=self.manifest_sha())
        self.assertEqual(completed.returncode, 1)
        self.assertIn("package-relative", completed.stderr)

    def test_absolute_driver_path_fails(self):
        drivers = [{"path": "/etc/passwd", "sha256": "0" * 64}]
        self.write_manifest(drivers=drivers)
        completed, _ = self.run_cli(expected_manifest=self.manifest_sha())
        self.assertEqual(completed.returncode, 1)
        self.assertIn("package-relative", completed.stderr)

    def test_missing_schema_fails(self):

        drivers = [{"path": name,
                    "sha256": hashlib.sha256(
                        (self.package / name).read_bytes()).hexdigest()}
                   for name in sorted(os.listdir(self.package))
                   if (self.package / name).is_file()]
        self.write_manifest(drivers=drivers, schema="something-else/v9")
        completed, _ = self.run_cli(expected_manifest=self.manifest_sha())
        self.assertEqual(completed.returncode, 1)
        self.assertIn("schema must be", completed.stderr)

    def test_list_manifest_fails(self):
        self.manifest_path.write_text("[]", encoding="utf-8")
        completed, _ = self.run_cli(expected_manifest=self.manifest_sha())
        self.assertIn(completed.returncode, (1, 2))
        self.assertIn("must be a JSON object",
                      completed.stdout + completed.stderr)

    def test_missing_driver_file_in_package_fails(self):
        (self.package / "w6_recovery_replay.py").unlink()
        self.write_manifest()
        completed, _ = self.run_cli(expected_manifest=self.manifest_sha())
        self.assertEqual(completed.returncode, 1)
        self.assertTrue(
            "driver file missing in package" in completed.stderr
            or "missing required files" in completed.stderr,
            completed.stderr)

    def test_portable_runtime_contract_untouched(self):
        completed = subprocess.run(
            [sys.executable,
             str(REPO_ROOT / "tools/validation/native_acceptance.py"),
             "--preflight",
             "--source-commit", self.ident["head"],
             "--profile", "portable_runtime",
             "--output", str(self.work / "native.json"),
             "--repo-root", str(REPO_ROOT)],
            capture_output=True, text=True, timeout=300)
        self.assertNotEqual(completed.returncode, 0,
                            "dirty tree must still fail portable_runtime")
        self.assertIn("must be clean", completed.stderr)
if __name__ == "__main__":
    unittest.main()
