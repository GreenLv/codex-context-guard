"""Small stdlib validator for the frozen core schema subset (not general JSON Schema)."""

from __future__ import annotations

import json
from pathlib import Path


def load_strict(text: str):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def bad_constant(_):
        raise ValueError("nonfinite_number")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=bad_constant)


def validate(value, spec, path="$"):
    if "anyOf" in spec:
        for option in spec["anyOf"]:
            try:
                validate(value, option, path)
                return
            except ValueError:
                pass
        raise ValueError(path + ": no_matching_schema")
    if "const" in spec and value != spec["const"]:
        raise ValueError(path + ": wrong_constant")
    if "enum" in spec and value not in spec["enum"]:
        raise ValueError(path + ": unknown_enum")
    kind = spec.get("type")
    if kind:
        kinds = kind if isinstance(kind, list) else [kind]
        matches = {
            "null": value is None,
            "boolean": type(value) is bool,
            "integer": type(value) is int,
            "string": isinstance(value, str),
            "array": isinstance(value, list),
            "object": isinstance(value, dict),
        }
        if not any(matches.get(k, False) for k in kinds):
            raise ValueError(path + ": wrong_type")
    if isinstance(value, dict):
        fields = spec.get("properties", {})
        if spec.get("additionalProperties") is False and set(value) - set(fields):
            raise ValueError(path + ": unknown_fields")
        if set(spec.get("required", [])) - set(value):
            raise ValueError(path + ": missing_fields")
        for key, child in value.items():
            if key in fields:
                validate(child, fields[key], path + "." + key)
    elif isinstance(value, list) and "items" in spec:
        for child in value:
            validate(child, spec["items"], path + "[]")
    elif isinstance(value, str):
        import re

        if len(value) < spec.get("minLength", 0) or (
            "pattern" in spec and not re.fullmatch(spec["pattern"], value)
        ):
            raise ValueError(path + ": invalid_string")
        value.encode("utf-8", "strict")
    elif type(value) is int:
        if not spec.get("minimum", value) <= value <= spec.get("maximum", value):
            raise ValueError(path + ": number_out_of_range")


def validate_snapshot(value):
    schema = (
        Path(__file__).resolve().parent.parent
        / "assets"
        / "core-observation-v2.schema.json"
    )
    validate(value, load_strict(schema.read_text(encoding="utf-8")))
