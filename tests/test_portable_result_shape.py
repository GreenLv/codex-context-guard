"""Consumer examples for the portable native-acceptance/v2 standard shape.

The portable producer emits the standard closed shape — artifact bound to
its real archive bytes (filename, digest, size) and git head, capability
boundaries in gate notes — so a generic product-neutral consumer can
validate it directly. The consumer lives outside this repository and is
injected only through the ``CG_GENERIC_NATIVE_CONSUMER`` environment
variable; the product-schema and real-output-path checks run everywhere.
Historical receipts are never rewritten and never re-validated here.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.validation import native_acceptance as native

REPO = Path(__file__).resolve().parents[1]
CONSUMER = os.environ.get("CG_GENERIC_NATIVE_CONSUMER", "")
PRODUCT_SCHEMA = REPO / "tools" / "validation" / "native-acceptance-v2.schema.json"

DIGEST = "a" * 64
COMMIT = "b" * 40


def build_release_zip(directory: Path) -> tuple[Path, dict[str, str]]:
    """A real reviewed-manifest-shaped archive, hashed like the producer sees it."""
    files = {".codex-plugin/plugin.json": "e" * 64, "hooks/hooks.json": "f" * 64}
    archive = directory / "context-guard-0.17.4.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        for name in files:
            zipped.writestr(name, f"fixture bytes for {name}\n")
    for name, body in ((name, f"fixture bytes for {name}\n".encode()) for name in files):
        files[name] = hashlib.sha256(body).hexdigest()
    return archive, files


def portable_document(archive: Path, files: dict[str, str]) -> dict:
    gates = [native.gate("exact_release_zip", DIGEST, passed=True),
             native.gate("isolated_install", DIGEST, passed=True,
                         note="official marketplace commands in internally created fresh "
                              "HOME; local marketplace source retained only during this "
                              "isolated gate, no long-term refresh or startup claim")]
    return native.finish_portable_result(
        status="passed", gates=gates, archive_path=archive,
        zip_bytes=archive.read_bytes(), files=files,
        digest=DIGEST, source_commit=COMMIT,
        repository_url="https://github.com/GreenLv/codex-context-guard",
        toolchain={"python": "3.12.2", "codex": "0.169.0"},
        cleanup="passed", started="2026-11-15T00:00:00.000000Z",
        finished="2026-11-15T00:05:00.000000Z",
        run_url="https://github.com/GreenLv/codex-context-guard/actions/runs/1")


class PortableProducerShape(unittest.TestCase):
    """The real producer output path, validated against the product schema."""

    def test_finish_binds_the_real_archive_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, files = build_release_zip(Path(temporary))
            document = portable_document(archive, files)
            body = archive.read_bytes()
            self.assertEqual(document["artifact"]["filename"], archive.name)
            self.assertEqual(document["artifact"]["sha256"],
                             hashlib.sha256(body).hexdigest())
            self.assertEqual(document["artifact"]["size_bytes"], len(body))
            self.assertEqual(document["artifact"]["file_count"], len(files))
            self.assertEqual(document["artifact"]["git_head"], COMMIT)
            self.assertNotIn("limitations", document)
            self.assertNotIn("kind", document["artifact"])

    def test_standard_shape_satisfies_the_product_schema(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # jsonschema is validation-only, not a runtime floor
            self.skipTest("jsonschema unavailable")
        schema = json.loads(PRODUCT_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        with tempfile.TemporaryDirectory() as temporary:
            archive, files = build_release_zip(Path(temporary))
            document = portable_document(archive, files)
        errors = list(Draft202012Validator(schema).iter_errors(document))
        self.assertEqual(errors, [], [error.message for error in errors])

    def test_result_document_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, files = build_release_zip(Path(temporary))
            left, right = portable_document(archive, files), portable_document(archive, files)
        self.assertEqual(json.dumps(left, sort_keys=True),
                         json.dumps(right, sort_keys=True))


@unittest.skipUnless(CONSUMER and Path(CONSUMER).is_file(),
                     "CG_GENERIC_NATIVE_CONSUMER must point at the generic consumer")
class GenericConsumerShape(unittest.TestCase):
    """Direct positive and negative examples against the generic consumer."""

    def run_consumer(self, document: dict) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "result.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.run([sys.executable, "-B", CONSUMER, str(path), "--json"],
                                  capture_output=True, timeout=60)

    def test_standard_shape_is_directly_consumable(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, files = build_release_zip(Path(temporary))
            document = portable_document(archive, files)
        result = self.run_consumer(document)
        payload = json.loads(result.stdout.decode())
        self.assertTrue(payload["valid"], payload)
        self.assertEqual(payload["schema"], "native-acceptance/v2")
        self.assertEqual(payload["gate_profile"], "portable_runtime")
        self.assertEqual(payload["commit"], COMMIT)
        self.assertEqual(payload["artifact_sha256"], document["artifact"]["sha256"])

    def test_legacy_producer_shape_is_rejected_without_loosening(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, files = build_release_zip(Path(temporary))
            legacy = portable_document(archive, files)
        legacy["limitations"] = ["historical top-level boundary text"]
        legacy["artifact"] = {"kind": "release_zip", "sha256": "c" * 64,
                              "size_bytes": 928085, "file_count": 107}
        result = self.run_consumer(legacy)
        payload = json.loads(result.stdout.decode())
        self.assertFalse(payload["valid"])
        self.assertIn("must contain exactly", payload["error"])


if __name__ == "__main__":
    unittest.main()
