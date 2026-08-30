#!/usr/bin/env python3
"""Contract tests for the portable conformance fixture assets.

The semantics fixture is validated against its JSON Schema with a
standard-library mini-validator that supports exactly the keyword set the
schema uses (the Hook runtime and repository tests stay dependency-free).
The privacy hygiene scan keeps synthetic-only content in the shared fixture.
"""

from __future__ import annotations

import importlib.util
import json
import math
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "tests" / "fixtures" / "conformance" / "context_guard_semantics_v1.schema.json"
FIXTURE = ROOT / "tests" / "fixtures" / "conformance" / "context_guard_semantics_v1.json"
CASES = ROOT / "tests" / "fixtures" / "conformance" / "digest_v3" / "cases.json"
EXPECTED = ROOT / "tests" / "fixtures" / "conformance" / "digest_v3" / "expected.json"
LEDGER = ROOT / "docs" / "upstream-deltas.json"

ENCODER = ROOT / "scripts" / "reference_digest_encoder.py"
_ENCODER_SPEC = importlib.util.spec_from_file_location("reference_digest_encoder", ENCODER)
enc = importlib.util.module_from_spec(_ENCODER_SPEC)
_ENCODER_SPEC.loader.exec_module(enc)


def _resolve(schema: dict, root: dict):
    while "$ref" in schema:
        pointer = schema["$ref"]
        assert pointer.startswith("#/"), pointer
        target = root
        for part in pointer[2:].split("/"):
            target = target[part]
        rest = {k: v for k, v in schema.items() if k != "$ref"}
        schema = {**target, **rest} if rest else target
    return schema


def validate(instance, schema: dict, root: dict, path: str) -> list[str]:
    schema = _resolve(schema, root)
    errors: list[str] = []
    if "oneOf" in schema:
        matches = 0
        for branch in schema["oneOf"]:
            if not validate(instance, branch, root, path):
                matches += 1
        if matches != 1:
            errors.append(f"{path}: matched {matches} oneOf branches, expected exactly 1")
            return errors
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']}")
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(instance, dict):
            errors.append(f"{path}: expected object, got {type(instance).__name__}")
            return errors
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in properties:
                errors.extend(validate(value, properties[key], root, f"{path}.{key}"))
            elif additional is False:
                errors.append(f"{path}: unexpected property {key!r}")
            elif isinstance(additional, dict):
                errors.extend(validate(value, additional, root, f"{path}.{key}"))
    elif kind == "array":
        if not isinstance(instance, list):
            errors.append(f"{path}: expected array, got {type(instance).__name__}")
            return errors
        if len(instance) < schema.get("minItems", 0):
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: more than {schema['maxItems']} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                errors.extend(validate(item, item_schema, root, f"{path}[{index}]"))
    elif kind == "string":
        if not isinstance(instance, str):
            errors.append(f"{path}: expected string, got {type(instance).__name__}")
            return errors
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: {instance!r} does not match {schema['pattern']!r}")
    elif kind == "integer":
        # JSON Schema integer semantics: numerically integral numbers (1.0,
        # 1e0) validate; non-integral or non-finite numbers do not.
        if isinstance(instance, bool) or not isinstance(instance, (int, float)):
            errors.append(f"{path}: expected integer, got {type(instance).__name__}")
            return errors
        if isinstance(instance, float) and (
            not math.isfinite(instance) or not instance.is_integer()
        ):
            errors.append(
                f"{path}: expected a numerically integral number, got {instance!r}"
            )
            return errors
        number = int(instance) if isinstance(instance, float) else instance
        if "minimum" in schema and number < schema["minimum"]:
            errors.append(f"{path}: {instance} below minimum {schema['minimum']}")
        if "maximum" in schema and number > schema["maximum"]:
            errors.append(f"{path}: {instance} above maximum {schema['maximum']}")
    elif kind == "boolean":
        if not isinstance(instance, bool):
            errors.append(f"{path}: expected boolean, got {type(instance).__name__}")
    elif kind == "null":
        if instance is not None:
            errors.append(f"{path}: expected null, got {instance!r}")
    return errors


PRIVATE_PATTERNS = (
    re.compile(r"/Users/"),
    re.compile(r"/home/"),
    re.compile(r"C:\\\\", re.IGNORECASE),
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{8,}"),
    re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"(?i)(api[_-]?key|password|secret)\s*[:=]\s*\S+"),
)


class ValidatorKeywordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = json.loads(SCHEMA.read_text(encoding="utf-8"))
        cls.typed_value = cls.root["$defs"]["typedValue"]

    def test_integer_maximum_is_enforced(self) -> None:
        schema = {
            "type": "integer",
            "minimum": -9007199254740991,
            "maximum": 9007199254740991,
        }
        self.assertEqual(validate(0, schema, schema, "v"), [])
        self.assertNotEqual(validate(2**53, schema, schema, "v"), [])
        self.assertNotEqual(validate(-(2**53), schema, schema, "v"), [])

    def test_integer_semantics_accept_integral_decimals(self) -> None:
        integer_schema = {
            "type": "integer",
            "minimum": -9007199254740991,
            "maximum": 9007199254740991,
        }
        self.assertEqual(validate(1.0, integer_schema, integer_schema, "v"), [])
        self.assertEqual(validate(1e0, integer_schema, integer_schema, "v"), [])
        self.assertNotEqual(validate(1.5, integer_schema, integer_schema, "v"), [])
        self.assertNotEqual(
            validate(9007199254740992.0, integer_schema, integer_schema, "v"), []
        )
        self.assertNotEqual(validate(float("nan"), integer_schema, integer_schema, "v"), [])

    def test_schema_patterns_reject_trailing_newlines(self) -> None:
        typed = self.root["$defs"]["typedValue"]
        self.assertNotEqual(validate({"k": "e", "v": "ok\n"}, typed, self.root, "v"), [])
        self.assertNotEqual(validate({"k": "x", "v": "ab\n"}, typed, self.root, "v"), [])
        self.assertEqual(validate({"k": "e", "v": "ok"}, typed, self.root, "v"), [])

    def test_typed_wrapper_payloads_are_discriminated(self) -> None:
        invalid = [
            {"k": "i", "v": 9007199254740992},
            {"k": "s", "v": 7},
            {"k": "b", "v": "not-bool"},
            {"k": "x", "v": 7},
            {"k": "e", "v": "Not An Enum"},
            {"k": "x", "v": "abc"},
            {"k": "s", "v": "x", "evil": 1},
            {"k": "q", "v": "x"},
        ]
        for instance in invalid:
            self.assertNotEqual(
                validate(instance, self.typed_value, self.root, "v"),
                [],
                f"expected rejection: {instance!r}",
            )
        valid = [
            True,
            False,
            5,
            "plain-string",
            {"k": "i", "v": 5},
            {"k": "b", "v": False},
            {"k": "s", "v": "x"},
            {"k": "e", "v": "success"},
            {"k": "x", "v": "ab" * 32},
        ]
        for instance in valid:
            self.assertEqual(
                validate(instance, self.typed_value, self.root, "v"),
                [],
                f"expected acceptance: {instance!r}",
            )


class SemanticsFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_validates_against_schema(self) -> None:
        errors = validate(self.fixture, self.schema, self.schema, "fixture")
        self.assertEqual(errors, [])

    def test_case_ids_are_unique(self) -> None:
        case_ids = [case["id"] for case in self.fixture["cases"]]
        self.assertEqual(len(case_ids), len(set(case_ids)))

    def test_reason_codes_come_from_the_declared_vocabulary(self) -> None:
        vocabulary = set(self.fixture["reasonCodeVocabulary"])
        for case in self.fixture["cases"]:
            for code in case["expect"]["reason_codes"]:
                self.assertIn(code, vocabulary, f"{case['id']}: {code}")

    def test_vocabulary_is_fully_covered_by_cases(self) -> None:
        used = {
            code
            for case in self.fixture["cases"]
            for code in case["expect"]["reason_codes"]
        }
        unused = set(self.fixture["reasonCodeVocabulary"]) - used
        self.assertEqual(unused, set(), f"vocabulary entries without a case: {sorted(unused)}")

    def test_expected_category_coverage(self) -> None:
        categories = {case["category"] for case in self.fixture["cases"]}
        expected = {
            "authority",
            "capture",
            "stop",
            "boundary",
            "evidence-binding",
            "state-verification",
            "replay",
            "recovery",
            "observability",
            "unicode-paths",
            "goal",
        }
        self.assertEqual(categories, expected)

    def test_fixture_content_is_synthetic_only(self) -> None:
        for case in self.fixture["cases"]:
            blob = json.dumps(case, ensure_ascii=False)
            for pattern in PRIVATE_PATTERNS:
                self.assertIsNone(
                    pattern.search(blob),
                    f"{case['id']}: content matched private-data pattern {pattern.pattern!r}",
                )


class DigestFixturePairTests(unittest.TestCase):
    def test_digest_fixture_pair_is_consistent(self) -> None:
        cases = json.loads(CASES.read_text(encoding="utf-8"))
        expected = json.loads(EXPECTED.read_text(encoding="utf-8"))["expected"]
        results = enc.compute_all(cases["vectors"])
        self.assertEqual(results, expected)

    def test_digest_fixture_inputs_are_synthetic_only(self) -> None:
        blob = CASES.read_text(encoding="utf-8")
        # The frozen locator vectors (L1-L3) legitimately carry Windows
        # path *shapes* as synthetic golden inputs; they are the only
        # sanctioned occurrences, so they are removed before the path-pattern
        # scan. Credential, token, and UUID patterns always apply.
        vectors = json.loads(blob)["vectors"]
        raw_locators = [
            vector["input"]["raw"]
            for vector in vectors
            if vector["kind"] == "locator"
        ]
        self.assertEqual(len(raw_locators), 3)
        scrubbed = blob
        for raw in raw_locators:
            scrubbed = scrubbed.replace(json.dumps(raw), "<synthetic-locator>")
        for pattern in PRIVATE_PATTERNS:
            self.assertIsNone(
                pattern.search(scrubbed),
                f"digest fixture matched private-data pattern {pattern.pattern!r}",
            )


class LedgerContractTests(unittest.TestCase):
    def test_ledger_is_valid_json_with_required_facts(self) -> None:
        ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
        self.assertEqual(ledger["source"]["product"], "codex-context-guard")
        self.assertEqual(ledger["source"]["version"], "v0.9.4")
        self.assertEqual(ledger["target"]["product"], "dsh-completion-guard")
        dispositions = set(ledger["dispositions"])
        required_fields = {
            "capability",
            "sourceFact",
            "disposition",
            "planStatus",
            "implementationStatus",
            "nativeAcceptance",
            "releaseReadback",
        }
        capabilities = set()
        for entry in ledger["entries"]:
            missing = required_fields - set(entry)
            self.assertEqual(missing, set(), f"{entry.get('capability')}: missing {missing}")
            self.assertIn(entry["disposition"], dispositions)
            capabilities.add(entry["capability"])
        # The v0.8.8 -> v0.9.4 delta set must be fully dispositioned.
        self.assertLessEqual(
            {
                "stop-protocol-2",
                "proof-protocol-1",
                "classifier-2.3.2-quoted-completion",
                "utf8-stdin-decoding",
                "managed-cache-fallback",
                "installer-missing-cache-messaging",
                "privacy-token-value-classifier",
                "incident-corpus",
            },
            capabilities,
        )


if __name__ == "__main__":
    unittest.main()
