#!/usr/bin/env python3
"""Reference encoder for Context Guard digest v3 canonical manifests.

This script is the canonical cross-language gate asset for the semantic
compatibility plan. It implements, byte for byte, the digest derivation
contract frozen in ``docs/SEMANTIC_COMPATIBILITY.md``:

- typed token value language (``b:``/``i:``/``s:``/``e:``/``x:``),
- length-prefixed ``field()`` primitive with an explicit presence byte,
- canonical set/map/bindings collection language (sorted, duplicate-rejecting),
- sessionRefDigest / hostLockDigest / evidenceFact / evidenceSha256 /
  binding record + bindingDigest / predParams / certificationDigest
  manifests with closed field allowlists and domain separators,
- the ``ccg.locator.v1`` opaque-locator digest.

Golden values are never hand-copied: ``tests/fixtures/conformance/digest_v3``
holds machine-readable inputs (``cases.json``) and encoder-generated expected
digests (``expected.json``). The ``--check`` command recomputes every vector
and fails on any difference; ``--write`` regenerates ``expected.json``.

The ``field()`` primitive deliberately performs no name-grammar validation
(only length limits): manifest-level builders enforce the snake_case grammar
before hashing. That layering is what the two-layer collision regression
tests rely on.

Python 3.10+, standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
from pathlib import Path

FIXTURE_VERSION = "3"

# Frozen v3 length limits. Everything is rejected before a u32BE is written.
MAX_ENCODED_NAME_BYTES = 256
MAX_SEMANTIC_KEY_BYTES = 64
MAX_PACKAGE_NAME_BYTES = 128
MAX_VALUE_BYTES = 4096
MAX_FIELDS_PER_RECORD = 128
MAX_PRED_PARAMS_BYTES = 4096

# snake_case dynamic-key grammar (capability names, res:/obs:/req: tuple keys,
# predParams parameter names).
DYNAMIC_KEY_RE = re.compile(r"^[a-z0-9_]{1,64}$")
PACKAGE_NAME_RE = re.compile(r"^[@a-z0-9._/-]{1,128}$")
ENUM_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
HEX_RE = re.compile(r"^[0-9a-f]+$")

# Closed canonical surface enumeration with cardinality=1 for evidenceFact v3.
SURFACE_ENUM = ("artifact", "ui", "visual", "scope")
OUTCOME_ENUM = ("success", "failure", "unknown", "durability-unknown")
EVIDENCE_ROLE_ENUM = ("resolution", "effect", "state")
PRED_PARAMS_KIND_ENUM = ("inline", "manifest")
# evidenceFact v3 parseStatus tokens known at freeze time; the plan keeps the
# set extensible behind the snake_case grammar until a versioned bump.
PARSE_STATUS_RE = re.compile(r"^[a-z0-9_]{1,64}$")

# Frozen canonical key vocabulary (product manifests draw per-action
# allowlists from this set). Encoder-only test vectors may declare their own
# allowlist (symbol/accent/aa/b) via cases.json.
PRODUCT_KEY_VOCABULARY = frozenset(
    {
        "repository",
        "remote",
        "refspec",
        "upstream_oid",
        "pre_head_oid",
        "post_head_oid",
        "tracking_ref_oid",
        "pull_mode",
        "branch",
        "change_set_digest",
        "local_oid",
        "remote_oid",
        "package_id",
        "version",
        "integrity_digest",
        "profile",
        "artifact_id",
        "scope",
        "pre_digest",
        "post_digest",
        "service_id",
        "pre_generation",
        "new_generation",
        "health",
        "registry",
        "executable",
        "expected_outcome",
        "min_matches",
    }
)


class DigestError(ValueError):
    """Raised for any input the v3 contract requires to fail closed."""


# Closed input manifests: each digest branch accepts exactly these keys and
# rejects unknown fields before hashing (missing required keys fail on their
# typed accessors).
SESSION_KEYS = frozenset(
    {"version", "id", "createdAt", "parentSession", "seedLength", "agentPreset", "origin", "delegationDepth"}
)
HOST_LOCK_KEYS = frozenset({"manifestVersion", "supportedGoalVersions", "capabilities", "packages"})
CAPABILITY_KEYS = frozenset({"name", "value"})
PACKAGE_KEYS = frozenset({"name", "version", "integrity"})
FACT_KEYS = frozenset(
    {
        "id", "outcome", "method", "operations", "executables", "subjects",
        "surfaces", "semanticAction", "evidenceRole", "resolvedTarget",
        "observedState", "parseStatus", "reasonCode", "adapterId", "adapterVersion",
    }
)
BINDING_COMMON_KEYS = frozenset(
    {
        "item", "semanticAction", "requestedTarget", "resolvedTarget",
        "observedState", "predId", "predVersion", "predParamsKind",
        "resolutionEvidenceId", "effectEvidenceId", "stateEvidenceIds",
    }
)
BINDING_INLINE_KEYS = frozenset({"predParams", "predParamsAllowlist"})
BINDING_MANIFEST_KEYS = frozenset(
    {"predParamsRef", "predParamsManifest", "predParamsManifestAllowlist"}
)
CERTIFICATE_KEYS = frozenset(
    {
        "stopProtocolVersion", "certificateVersion", "epoch", "sessionRefDigest",
        "hostLockDigest", "contractRevision", "contractSha256", "goalRef",
        "openDigest", "evidenceSha256", "bindingDigest",
    }
)
GOAL_REF_KEYS = frozenset({"id", "revision"})


def _require_exact_keys(record: object, allowed: frozenset[str], label: str) -> None:
    if not isinstance(record, dict):
        raise DigestError(f"{label} must be an object")
    unexpected = set(record) - allowed
    if unexpected:
        raise DigestError(f"{label} has unknown fields: {sorted(unexpected)}")


# ---------------------------------------------------------------------------
# typed token value language
# ---------------------------------------------------------------------------


def typed_token(value: object) -> bytes:
    """Encode a typed value into its canonical token bytes."""
    if isinstance(value, bool):
        return (b"b:1" if value else b"b:0")
    if isinstance(value, int) or isinstance(value, float):
        number = _canonical_int(value, "integer token")
        text = str(number)
        if text.startswith("-0") or (len(text) > 1 and text.startswith("0")):
            raise DigestError(f"integer token must not carry redundant zeros: {text!r}")
        return ("i:" + text).encode("utf-8")
    if isinstance(value, str):
        # Strict UTF-8 here rejects lone surrogates before they can enter a
        # digest (Node would silently replace them with U+FFFD).
        try:
            return ("s:" + value).encode("utf-8")
        except UnicodeEncodeError as exc:
            raise DigestError(f"string value is not valid Unicode scalar data: {exc}") from exc
    if isinstance(value, dict):
        if set(value) != {"k", "v"}:
            raise DigestError(
                f"typed token wrapper must carry exactly k and v: {sorted(value)}"
            )
        kind = value.get("k")
        raw = value.get("v")
        if kind == "e":
            token = _expect_enum_token(raw)
            return ("e:" + token).encode("utf-8")
        if kind == "x":
            token = _expect_hex(raw)
            return ("x:" + token).encode("utf-8")
        if kind == "i":
            return typed_token(_canonical_int(raw, "typed.i token"))
        if kind == "b":
            return typed_token(raw if isinstance(raw, bool) else _bad_typed(value))
        if kind == "s":
            return typed_token(raw if isinstance(raw, str) else _bad_typed(value))
        raise DigestError(f"unknown typed token kind: {kind!r}")
    raise DigestError(f"unsupported typed value: {value!r}")


def _bad_typed(value: object) -> None:
    raise DigestError(f"typed token kind does not match payload: {value!r}")


def _expect_enum_token(raw: object) -> str:
    if not isinstance(raw, str) or not ENUM_TOKEN_RE.fullmatch(raw):
        raise DigestError(f"invalid enum token: {raw!r}")
    return raw


def _expect_hex(raw: object) -> str:
    if (
        not isinstance(raw, str)
        or len(raw) == 0
        or len(raw) % 2 != 0
        or not HEX_RE.fullmatch(raw)
    ):
        raise DigestError(f"digest token must be lowercase hex: {raw!r}")
    return raw


def parse_typed_input(value: object) -> bytes:
    """Coerce a cases.json scalar into typed token bytes.

    Plain JSON booleans/integers/strings map to b:/i:/s:; explicit typed
    values use {"k": "e"|"x", "v": ...}.
    """
    return typed_token(value)


# ---------------------------------------------------------------------------
# field primitive (no grammar checks here — that is manifest-level)
# ---------------------------------------------------------------------------


def field(name: str, token: bytes | None) -> bytes:
    """Encode one field: u32BE(nameLen) || name || presence || u32BE(valueLen) || value.

    ``token=None`` encodes the absent (null-domain) form: presence byte 0x00
    and a zero value length. Names containing NUL/control bytes are accepted
    at this layer on purpose; manifest builders reject them via grammar so
    the raw-primitive collision test can prove the length prefixes make
    ``field(maliciousName, "s:z")`` and two concatenated short fields
    byte-distinct.
    """
    name_bytes = name.encode("utf-8")
    if not name_bytes or len(name_bytes) > MAX_ENCODED_NAME_BYTES:
        raise DigestError(
            f"encoded field name must be 1..{MAX_ENCODED_NAME_BYTES} bytes: {name!r}"
        )
    if token is None:
        return (
            struct.pack(">I", len(name_bytes))
            + name_bytes
            + b"\x00"
            + struct.pack(">I", 0)
        )
    if len(token) > MAX_VALUE_BYTES:
        raise DigestError(
            f"field value exceeds {MAX_VALUE_BYTES} bytes: {name!r}"
        )
    return (
        struct.pack(">I", len(name_bytes))
        + name_bytes
        + b"\x01"
        + struct.pack(">I", len(token))
        + token
    )


def opt_field(name: str, raw: object, enc) -> bytes:
    """Presence is decided before any stringification of ``raw``.

    ``enc`` is only evaluated on the present branch so a missing value can
    never be pre-evaluated into a token (golden vectors B/C pin this).
    """
    if raw is None:
        return field(name, None)
    return field(name, enc(raw))


def _check_field_count(count: int) -> None:
    if count > MAX_FIELDS_PER_RECORD:
        raise DigestError(
            f"canonical record exceeds {MAX_FIELDS_PER_RECORD} fields: {count}"
        )


# ---------------------------------------------------------------------------
# canonical collection language
# ---------------------------------------------------------------------------


def encode_set(name: str, items: list[bytes]) -> bytes:
    """Repeat same-name fields sorted by full typed value bytes; reject duplicates."""
    if len(items) != len(set(items)):
        raise DigestError(f"set {name!r} contains duplicate members")
    return b"".join(field(name, item) for item in sorted(items))


def encode_map_rows(entries: list[tuple[str, bytes]], prefix: str = "") -> bytes:
    """Sort by semantic key utf8 bytes (never by encoded field bytes) and encode.

    Duplicate semantic keys fail closed. The prefix (``res:``/``obs:``/``req:``)
    is not part of the sort key; because it is constant per call the resulting
    order equals full-field-name order, which the pull-chain vectors pin.
    """
    keys = [key for key, _ in entries]
    if len(keys) != len(set(keys)):
        raise DigestError(f"duplicate semantic keys in map: {sorted(keys)}")
    for key in keys:
        key_bytes = key.encode("utf-8")
        if len(key_bytes) > MAX_SEMANTIC_KEY_BYTES:
            raise DigestError(f"semantic key exceeds {MAX_SEMANTIC_KEY_BYTES} bytes: {key!r}")
    rows = []
    for key, token in sorted(entries, key=lambda item: item[0].encode("utf-8")):
        rows.append(field(prefix + key, token))
    _check_field_count(len(rows))
    return b"".join(rows)


# ---------------------------------------------------------------------------
# sessionRefDigest v3
# ---------------------------------------------------------------------------


def _validate_session_types(header: dict) -> None:
    """SessionHeader schema check before hashing: types fail closed."""
    _int_field(header, "version")
    _int_field(header, "createdAt")
    _str_field(header, "id")
    for name in ("parentSession", "agentPreset", "origin"):
        value = header.get(name)
        if value is not None and not isinstance(value, str):
            raise DigestError(f"session field {name!r} must be a string or absent")
    for name in ("seedLength", "delegationDepth"):
        value = header.get(name)
        if value is not None:
            _canonical_int(value, f"session field {name!r}")


def session_ref_digest(header: dict) -> str:
    _require_exact_keys(header, SESSION_KEYS, "session header")
    _validate_session_types(header)
    parts = [b"ccg.sessionRefDigest.v3\n"]
    count = 0
    for name, token in (
        ("formatVersion", typed_token(_int_field(header, "version"))),
        ("id", typed_token(_str_field(header, "id"))),
        ("createdAt", typed_token(_int_field(header, "createdAt"))),
    ):
        parts.append(field(name, token))
        count += 1
    for name, enc in (
        ("parentSession", lambda v: ("s:" + v).encode("utf-8")),
        ("seedLength", lambda v: typed_token(v)),
        ("agentPreset", lambda v: ("s:" + v).encode("utf-8")),
        ("origin", lambda v: ("s:" + v).encode("utf-8")),
        ("delegationDepth", lambda v: typed_token(v)),
    ):
        raw = header.get(name)
        parts.append(opt_field(name, raw, enc))
        count += 1
    _check_field_count(count)
    return _sha256_hex(b"".join(parts))


def _canonical_int(value: object, label: str) -> int:
    """Frozen integer domain: finite, safe, numerically integral JSON numbers.

    Integral decimals (``1.0``, ``1e0``) normalize to the integer token,
    matching the TypeScript mirror (``Number.isSafeInteger``) and the JSON
    Schema ``integer`` numeric semantics; everything else fails closed.
    """
    if isinstance(value, bool):
        raise DigestError(f"{label} must be an integer, not a boolean")
    if isinstance(value, int):
        number = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise DigestError(f"{label} must be a numerically integral JSON number")
        number = int(value)
    else:
        raise DigestError(f"{label} must be an integer")
    if not (-(2**53 - 1) <= number <= 2**53 - 1):
        raise DigestError(f"{label} outside the frozen safe-integer domain")
    return number


def _int_field(record: dict, name: str) -> int:
    return _canonical_int(record.get(name), f"field {name!r}")


def _str_field(record: dict, name: str) -> str:
    value = record.get(name)
    if not isinstance(value, str):
        raise DigestError(f"field {name!r} must be a string")
    return value


# ---------------------------------------------------------------------------
# hostLockDigest v3
# ---------------------------------------------------------------------------


def host_lock_digest(manifest: dict) -> str:
    _require_exact_keys(manifest, HOST_LOCK_KEYS, "host lock manifest")
    parts = [b"ccg.hostLockDigest.v3\n"]
    count = 0
    parts.append(
        field("manifestVersion", typed_token(_int_field(manifest, "manifestVersion")))
    )
    count += 1

    versions = manifest.get("supportedGoalVersions")
    if not isinstance(versions, list) or not versions:
        raise DigestError("supportedGoalVersions must be a non-empty list")
    if any(not isinstance(v, str) for v in versions):
        raise DigestError("supportedGoalVersions entries must be strings")
    version_tokens = [typed_token(v) for v in versions]
    parts.append(encode_set("supportedGoalVersion", version_tokens))
    count += len(version_tokens)

    capabilities = manifest.get("capabilities", [])
    if not isinstance(capabilities, list):
        raise DigestError("capabilities must be a list")
    rows: list[tuple[str, bytes]] = []
    for entry in capabilities:
        _require_exact_keys(entry, CAPABILITY_KEYS, "capability row")
        name = _str_field(entry, "name")
        if not DYNAMIC_KEY_RE.fullmatch(name):
            raise DigestError(f"capability name must match snake_case grammar: {name!r}")
        token = typed_token(entry["value"])
        rows.append((name, token))
    seen = set()
    for name, token in sorted(rows, key=lambda item: (item[0].encode("utf-8"), item[1])):
        marker = (name, token)
        if marker in seen:
            raise DigestError(f"duplicate capability row: {marker!r}")
        seen.add(marker)
        parts.append(opt_field("cap:" + name, token, lambda v: v))
        count += 1

    packages = manifest.get("packages", [])
    if not isinstance(packages, list):
        raise DigestError("packages must be a list")
    names = [_str_field(entry, "name") for entry in packages]
    if len(names) != len(set(names)):
        raise DigestError("duplicate package rows")
    for entry in sorted(packages, key=lambda item: item["name"].encode("utf-8")):
        _require_exact_keys(entry, PACKAGE_KEYS, "package row")
        name = entry["name"]
        for label in ("version", "integrity"):
            value = entry.get(label)
            if value is not None and not isinstance(value, str):
                raise DigestError(f"package field {label!r} must be a string or absent")
        if not PACKAGE_NAME_RE.fullmatch(name):
            raise DigestError(f"invalid package name: {name!r}")
        version = entry.get("version")
        integrity = entry.get("integrity")
        parts.append(
            opt_field(
                "pkg:" + name,
                version,
                lambda v: typed_token(v),
            )
        )
        parts.append(
            opt_field(
                "integrity:" + name,
                integrity,
                lambda v: typed_token(v),
            )
        )
        count += 2
    _check_field_count(count)
    return _sha256_hex(b"".join(parts))


# ---------------------------------------------------------------------------
# evidenceFact v3
# ---------------------------------------------------------------------------


def evidence_fact_bytes(fact: dict, allowlist: frozenset[str] = PRODUCT_KEY_VOCABULARY) -> bytes:
    _require_exact_keys(fact, FACT_KEYS, "evidence fact")
    outcome = fact.get("outcome")
    if outcome not in OUTCOME_ENUM:
        raise DigestError(f"outcome must be a canonical enum member: {outcome!r}")
    role = fact.get("evidenceRole")
    if role not in EVIDENCE_ROLE_ENUM:
        raise DigestError(f"evidenceRole must be a canonical enum member: {role!r}")
    parse_status = fact.get("parseStatus")
    if not isinstance(parse_status, str) or not PARSE_STATUS_RE.fullmatch(parse_status):
        raise DigestError(f"invalid parseStatus: {parse_status!r}")
    if parse_status != "supported" and fact.get("reasonCode") is None:
        raise DigestError("reasonCode must be present when parseStatus is not supported")

    surfaces = fact.get("surfaces")
    if not isinstance(surfaces, list) or len(surfaces) != 1:
        raise DigestError("surfaces must carry exactly one canonical surface")
    surface = surfaces[0]
    if surface not in SURFACE_ENUM:
        raise DigestError(f"surface must be a canonical enum member: {surface!r}")

    res_entries = _tuple_entries(fact.get("resolvedTarget", {}), "resolvedTarget", allowlist)
    obs_entries = _tuple_entries(fact.get("observedState", {}), "observedState", allowlist)
    if role in ("resolution", "effect"):
        if not res_entries:
            raise DigestError(f"{role} fact requires a resolvedTarget")
        if obs_entries:
            raise DigestError(f"{role} fact must not carry observedState")
    else:  # state
        if not res_entries or not obs_entries:
            raise DigestError("state fact requires both resolvedTarget and observedState")

    parts = [b"ccg.evidenceFact.v3\n"]
    count = 0
    parts.append(field("id", typed_token(_str_field(fact, "id"))))
    parts.append(field("outcome", ("e:" + outcome).encode("utf-8")))
    parts.append(field("method", typed_token(_str_field(fact, "method"))))
    count += 3
    for list_name, field_name in (
        ("operations", "operation"),
        ("executables", "executable"),
        ("subjects", "subject"),
    ):
        values = fact.get(list_name, [])
        if not isinstance(values, list):
            raise DigestError(f"{list_name} must be a list")
        if any(not isinstance(v, str) for v in values):
            raise DigestError(f"{list_name} entries must be strings")
        tokens = [typed_token(v) for v in values]
        parts.append(encode_set(field_name, tokens))
        count += len(tokens)
    parts.append(field("surface", typed_token(surface)))
    parts.append(field("semanticAction", typed_token(_str_field(fact, "semanticAction"))))
    parts.append(field("evidenceRole", ("e:" + role).encode("utf-8")))
    parts.append(encode_map_rows(res_entries, "res:"))
    parts.append(encode_map_rows(obs_entries, "obs:"))
    parts.append(field("parseStatus", ("e:" + parse_status).encode("utf-8")))
    count += 4 + len(res_entries) + len(obs_entries)
    for opt_name in ("reasonCode", "adapterId", "adapterVersion"):
        value = fact.get(opt_name)
        if value is not None and not isinstance(value, str):
            raise DigestError(f"evidence fact field {opt_name!r} must be a string or absent")
    parts.append(opt_field("reasonCode", fact.get("reasonCode"), lambda v: typed_token(v)))
    parts.append(opt_field("adapterId", fact.get("adapterId"), lambda v: typed_token(v)))
    parts.append(opt_field("adapterVersion", fact.get("adapterVersion"), lambda v: typed_token(v)))
    count += 3
    _check_field_count(count)
    return b"".join(parts)


def evidence_fact_digest(fact: dict, allowlist: frozenset[str] = PRODUCT_KEY_VOCABULARY) -> str:
    return _sha256_hex(evidence_fact_bytes(fact, allowlist))


def _tuple_entries(
    tuple_value: object,
    label: str,
    allowlist: frozenset[str] | None = None,
) -> list[tuple[str, bytes]]:
    if tuple_value is None:
        tuple_value = {}
    if not isinstance(tuple_value, dict):
        raise DigestError(f"{label} must be an object")
    entries: list[tuple[str, bytes]] = []
    for key, value in tuple_value.items():
        if not DYNAMIC_KEY_RE.fullmatch(key):
            raise DigestError(f"{label} key must match snake_case grammar: {key!r}")
        if allowlist is not None and key not in allowlist:
            raise DigestError(f"{label} key is not in the frozen key vocabulary: {key!r}")
        entries.append((key, typed_token(value)))
    return entries


# ---------------------------------------------------------------------------
# evidenceSha256 v3
# ---------------------------------------------------------------------------


def evidence_sha256_bytes(facts: list[dict], allowlist: frozenset[str] = PRODUCT_KEY_VOCABULARY) -> bytes:
    parts = [b"ccg.evidenceSha256.v3\n"]
    seen = set()
    for entry in sorted(facts, key=lambda item: item["id"].encode("utf-8")):
        evidence_id = _str_field(entry, "id")
        if evidence_id in seen:
            raise DigestError(f"duplicate evidence id: {evidence_id!r}")
        seen.add(evidence_id)
        parts.append(field("id", typed_token(evidence_id)))
        parts.append(field("fact", typed_token({"k": "x", "v": evidence_fact_digest(entry, allowlist)})))
    _check_field_count(len(facts) * 2)
    return b"".join(parts)


def evidence_sha256_digest(facts: list[dict], allowlist: frozenset[str] = PRODUCT_KEY_VOCABULARY) -> str:
    return _sha256_hex(evidence_sha256_bytes(facts, allowlist))


# ---------------------------------------------------------------------------
# predParams v3
# ---------------------------------------------------------------------------


def pred_params_bytes(params: dict, allowlist: frozenset[str]) -> bytes:
    if not isinstance(params, dict):
        raise DigestError("predParams must be an object")
    _check_field_count(len(params))
    for name in params:
        if not DYNAMIC_KEY_RE.fullmatch(name):
            raise DigestError(f"predParams name must match snake_case grammar: {name!r}")
        if name not in allowlist:
            raise DigestError(f"predParams name is not in the frozen allowlist: {name!r}")
    parts = [b"ccg.predParams.v3\n"]
    for name in sorted(params, key=lambda item: item.encode("utf-8")):
        parts.append(field(name, typed_token(params[name])))
    payload = b"".join(parts)
    if len(payload) > MAX_PRED_PARAMS_BYTES:
        raise DigestError(
            f"predParams canonicalBytes exceed {MAX_PRED_PARAMS_BYTES} bytes"
        )
    return payload


def pred_params_digest(params: dict, allowlist: frozenset[str]) -> str:
    return _sha256_hex(pred_params_bytes(params, allowlist))


# ---------------------------------------------------------------------------
# binding record v3 + bindingDigest v3
# ---------------------------------------------------------------------------


def binding_record_bytes(binding: dict, allowlist: frozenset[str]) -> bytes:
    kind = binding.get("predParamsKind")
    if kind not in PRED_PARAMS_KIND_ENUM:
        raise DigestError(f"predParamsKind must be a canonical enum member: {kind!r}")
    # The predicate digest is always recomputed from the actual parameter
    # payload the binding (inline) or the referenced manifest entry (manifest)
    # carries — a digest string alone is never authoritative.
    if kind == "inline":
        params = binding.get("predParams")
        if not isinstance(params, dict):
            raise DigestError("inline binding requires the predParams payload")
        pred_allowlist = _resolve_allowlist(binding.get("predParamsAllowlist"))
    else:
        params = binding.get("predParamsManifest")
        if not isinstance(params, dict):
            raise DigestError("manifest binding requires the manifest entry payload")
        pred_allowlist = _resolve_allowlist(binding.get("predParamsManifestAllowlist"))
    branch_keys = BINDING_INLINE_KEYS if kind == "inline" else BINDING_MANIFEST_KEYS
    _require_exact_keys(binding, BINDING_COMMON_KEYS | branch_keys, "binding record")
    payload = pred_params_bytes(params, pred_allowlist)
    recomputed = _sha256_hex(payload)
    parts = [b"ccg.binding.v3\n"]
    count = 0
    parts.append(field("item", typed_token(_str_field(binding, "item"))))
    parts.append(field("semanticAction", typed_token(_str_field(binding, "semanticAction"))))
    count += 2
    parts.append(encode_map_rows(_tuple_entries(binding.get("requestedTarget", {}), "requestedTarget", allowlist), "req:"))
    parts.append(encode_map_rows(_tuple_entries(binding.get("resolvedTarget", {}), "resolvedTarget", allowlist), "res:"))
    parts.append(encode_map_rows(_tuple_entries(binding.get("observedState", {}), "observedState", allowlist), "obs:"))
    count += sum(
        len(binding.get(section) or {})
        for section in ("requestedTarget", "resolvedTarget", "observedState")
    )
    parts.append(field("predId", typed_token(_str_field(binding, "predId"))))
    parts.append(field("predVersion", typed_token(_int_field(binding, "predVersion"))))
    parts.append(field("predParamsKind", ("e:" + kind).encode("utf-8")))
    count += 3
    if kind == "inline":
        parts.append(field("predParams", payload))
    else:
        ref = binding.get("predParamsRef")
        if not isinstance(ref, str) or not ref:
            raise DigestError("manifest binding requires predParamsRef")
        parts.append(field("predParamsRef", typed_token(ref)))
    parts.append(field("predParamsDigest", typed_token({"k": "x", "v": recomputed})))
    count += 2
    resolution_id = binding.get("resolutionEvidenceId")
    if resolution_id is not None and not isinstance(resolution_id, str):
        raise DigestError("resolutionEvidenceId must be a string or absent")
    parts.append(
        opt_field(
            "resolutionEvidenceId",
            resolution_id,
            lambda v: typed_token(v),
        )
    )
    parts.append(field("effectEvidenceId", typed_token(_str_field(binding, "effectEvidenceId"))))
    count += 2
    state_ids = binding.get("stateEvidenceIds", [])
    if not isinstance(state_ids, list):
        raise DigestError("stateEvidenceIds must be a list")
    if any(not isinstance(v, str) for v in state_ids):
        raise DigestError("stateEvidenceIds entries must be strings")
    state_tokens = [typed_token(v) for v in state_ids]
    parts.append(encode_set("stateEvidenceId", state_tokens))
    count += len(state_tokens)
    _check_field_count(count)
    return b"".join(parts)


def binding_record_digest(binding: dict, allowlist: frozenset[str]) -> str:
    return _sha256_hex(binding_record_bytes(binding, allowlist))


def binding_digest(records: list[dict], allowlist: frozenset[str]) -> str:
    parts = [b"ccg.bindingDigest.v3\n"]
    seen = set()
    rows = []
    for record in records:
        marker = (_str_field(record, "item"), _str_field(record, "semanticAction"))
        if marker in seen:
            raise DigestError(f"duplicate (item, semanticAction) binding: {marker!r}")
        seen.add(marker)
        rows.append((marker, binding_record_digest(record, allowlist)))
    for _marker, digest in sorted(rows, key=lambda item: (item[0][0].encode("utf-8"), item[0][1].encode("utf-8"))):
        parts.append(field("binding", typed_token({"k": "x", "v": digest})))
    _check_field_count(len(records))
    return _sha256_hex(b"".join(parts))


# ---------------------------------------------------------------------------
# certificationDigest v3
# ---------------------------------------------------------------------------


def certification_digest(certificate: dict) -> str:
    _require_exact_keys(certificate, CERTIFICATE_KEYS, "certificate")
    parts = [b"ccg.certificationDigest.v3\n"]
    count = 0
    parts.append(field("stopProtocolVersion", typed_token(_str_field(certificate, "stopProtocolVersion"))))
    parts.append(field("certificateVersion", typed_token(_str_field(certificate, "certificateVersion"))))
    parts.append(field("epoch", typed_token(_int_field(certificate, "epoch"))))
    parts.append(field("sessionRefDigest", typed_token({"k": "x", "v": _str_field(certificate, "sessionRefDigest")})))
    parts.append(field("hostLockDigest", typed_token({"k": "x", "v": _str_field(certificate, "hostLockDigest")})))
    parts.append(field("contractRevision", typed_token(_int_field(certificate, "contractRevision"))))
    parts.append(field("contractSha256", typed_token({"k": "x", "v": _str_field(certificate, "contractSha256")})))
    count += 7
    goal_ref = certificate.get("goalRef")
    if goal_ref is not None:
        _require_exact_keys(goal_ref, GOAL_REF_KEYS, "goalRef")
        goal_id = goal_ref.get("id")
        goal_revision = goal_ref.get("revision")
        if not isinstance(goal_id, str):
            raise DigestError("goalRef must carry string id and integer revision together")
        goal_revision = _canonical_int(goal_revision, "goalRef.revision")
        parts.append(opt_field("goalRefId", goal_id, lambda v: typed_token(v)))
        parts.append(opt_field("goalRefRevision", goal_revision, lambda v: typed_token(v)))
    else:
        parts.append(opt_field("goalRefId", None, lambda v: typed_token(v)))
        parts.append(opt_field("goalRefRevision", None, lambda v: typed_token(v)))
    count += 2
    parts.append(field("openDigest", typed_token({"k": "x", "v": _str_field(certificate, "openDigest")})))
    parts.append(field("evidenceSha256", typed_token({"k": "x", "v": _str_field(certificate, "evidenceSha256")})))
    parts.append(field("bindingDigest", typed_token({"k": "x", "v": _str_field(certificate, "bindingDigest")})))
    count += 3
    _check_field_count(count)
    return _sha256_hex(b"".join(parts))


# ---------------------------------------------------------------------------
# locator v1
# ---------------------------------------------------------------------------


def locator_digest(raw_locator: str) -> str:
    if not isinstance(raw_locator, str):
        raise DigestError("locator input must be a string")
    return _sha256_hex(b"ccg.locator.v1\n" + raw_locator.encode("utf-8"))


# ---------------------------------------------------------------------------
# state-closure verification helper (verifier-side role matrix / binding merge)
# ---------------------------------------------------------------------------


def binding_state_closure(
    binding: dict,
    resolution: dict,
    effect: dict,
    states: list[dict],
    evidence_facts: list[dict] | None = None,
) -> None:
    """Verify the frozen role matrix and binding closure for one binding.

    Digest derivation stays pure; this mirrors the checks a proof verifier
    must run before accepting a binding. Raises DigestError on any violation.

    - resolution/effect facts: res: required, obs: forbidden.
    - state facts: res: and obs: both required; all three roles share a
      byte-identical full resolvedTarget (pull_mode included).
    - binding.res equals the facts' res rows; binding.obs equals the canonical
      union of state facts' obs with pairwise-disjoint key sets.
    - resolution/effect/state evidence ids are pairwise distinct and, when an
      evidence set is supplied, all present in it.
    """
    roles = {"resolution": resolution, "effect": effect}
    for expected_role, fact in roles.items():
        if fact.get("evidenceRole") != expected_role:
            raise DigestError(f"fact role mismatch: expected {expected_role}")
        if not fact.get("resolvedTarget"):
            raise DigestError(f"{expected_role} fact requires resolvedTarget")
        if fact.get("observedState"):
            raise DigestError(f"{expected_role} fact must not carry observedState")
    for state_fact in states:
        if state_fact.get("evidenceRole") != "state":
            raise DigestError("state list must only carry state facts")
        if not state_fact.get("resolvedTarget") or not state_fact.get("observedState"):
            raise DigestError("state fact requires both resolvedTarget and observedState")

    binding_res = encode_map_rows(
        _tuple_entries(binding.get("resolvedTarget", {}), "resolvedTarget", PRODUCT_KEY_VOCABULARY), "res:"
    )
    for fact in (resolution, effect, *states):
        fact_res = encode_map_rows(
            _tuple_entries(fact.get("resolvedTarget", {}), "resolvedTarget", PRODUCT_KEY_VOCABULARY), "res:"
        )
        if fact_res != binding_res:
            raise DigestError("binding.res must equal every fact's res rows byte for byte")

    merged: dict[str, bytes] = {}
    for state_fact in states:
        for key, token in _tuple_entries(state_fact.get("observedState", {}), "observedState", PRODUCT_KEY_VOCABULARY):
            if key in merged:
                raise DigestError(
                    "observedState key sets must be pairwise disjoint across state facts"
                )
            merged[key] = token
    if dict(_tuple_entries(binding.get("observedState", {}), "observedState", PRODUCT_KEY_VOCABULARY)) != merged:
        raise DigestError("binding.obs must equal the canonical union of state facts")

    ids = [
        binding.get("resolutionEvidenceId"),
        binding.get("effectEvidenceId"),
        *binding.get("stateEvidenceIds", []),
    ]
    present = [i for i in ids if i is not None]
    if any(not isinstance(i, str) for i in present):
        raise DigestError("evidence ids must be strings when present")
    if len(present) != len(set(present)):
        raise DigestError("resolution/effect/state evidence ids must be pairwise distinct")
    # Evidence-role pairing: each referenced id must name the fact playing
    # that role, so swapping resolution/effect ids (cross-pairing) is rejected
    # even though the id set itself stays distinct and complete.
    if binding.get("resolutionEvidenceId") != resolution.get("id"):
        raise DigestError("resolutionEvidenceId must name the resolution fact")
    if binding.get("effectEvidenceId") != effect.get("id"):
        raise DigestError("effectEvidenceId must name the effect fact")
    state_ids = set(binding.get("stateEvidenceIds", []))
    provided_state_ids = [fact.get("id") for fact in states]
    if len(provided_state_ids) != len(set(provided_state_ids)):
        raise DigestError("duplicate state fact id")
    if state_ids != set(provided_state_ids):
        raise DigestError("stateEvidenceIds must name exactly the referenced state facts")
    if evidence_facts is not None:
        known_facts: dict[str, dict] = {}
        for set_fact in evidence_facts:
            set_id = set_fact.get("id")
            if set_id in known_facts:
                raise DigestError(f"duplicate evidence id in evidence set: {set_id!r}")
            known_facts[set_id] = set_fact
        for role_fact, role_id in (
            (resolution, binding.get("resolutionEvidenceId")),
            (effect, binding.get("effectEvidenceId")),
        ):
            hashed_fact = known_facts.get(role_id)
            if hashed_fact is None:
                raise DigestError(f"evidence ids missing from evidenceSha256 set: {role_id!r}")
            if evidence_fact_digest(role_fact) != evidence_fact_digest(hashed_fact):
                raise DigestError(
                    f"evidence fact {role_id!r} content differs from the fact hashed into evidenceSha256"
                )
        provided_states: dict[str, dict] = {}
        for state_fact in states:
            state_id = state_fact.get("id")
            if state_id in provided_states:
                raise DigestError(f"duplicate state fact id: {state_id!r}")
            provided_states[state_id] = state_fact
        for state_id, provided_fact in provided_states.items():
            hashed_fact = known_facts.get(state_id)
            if hashed_fact is None:
                raise DigestError(f"evidence ids missing from evidenceSha256 set: {state_id!r}")
            if evidence_fact_digest(provided_fact) != evidence_fact_digest(hashed_fact):
                raise DigestError(
                    f"evidence fact {state_id!r} content differs from the fact hashed into evidenceSha256"
                )


# ---------------------------------------------------------------------------
# fixture driver
# ---------------------------------------------------------------------------


class _VectorContext:
    """Resolves {"ref": "<VECTOR_ID>"} dependencies between vectors."""

    def __init__(self, vectors: list[dict]) -> None:
        self.by_id = {v["id"]: v for v in vectors}
        self.computed: dict[str, object] = {}

    def resolve_digest(self, value: object) -> str:
        if isinstance(value, dict) and set(value) == {"ref"}:
            ref = value["ref"]
            if ref not in self.computed:
                raise DigestError(f"reference before computation: {ref!r}")
            return self.computed[ref]
        if isinstance(value, dict) and set(value) == {"k", "v"} and value.get("k") == "x":
            return _expect_hex(value["v"])
        if isinstance(value, str):
            return _expect_hex(value)
        raise DigestError(f"expected digest or reference: {value!r}")


def _resolve_allowlist(spec: object) -> frozenset[str]:
    # Frozen explicit-null rule: an absent or null keyAllowlist maps to the
    # product vocabulary, matching the contract-wide null=absent convention
    # for optional scalar fields (both implementations, pinned by tests).
    if spec is None or spec == "product":
        return frozenset(PRODUCT_KEY_VOCABULARY)
    if isinstance(spec, str):
        raise DigestError(f"unknown allowlist name: {spec!r}")
    if isinstance(spec, list) and all(isinstance(item, str) for item in spec):
        return frozenset(spec)
    raise DigestError("keyAllowlist must be 'product' or a list of names")


PRED_PARAMS_WRAPPER_KEYS = frozenset({"keyAllowlist", "params"})
ESH_WRAPPER_KEYS = frozenset({"facts"})
ESH_ENTRY_KEYS = frozenset({"id", "factRef"})
BINDING_DIGEST_WRAPPER_KEYS = frozenset({"bindings"})
BINDING_REF_KEYS = frozenset({"ref"})
LOCATOR_KEYS = frozenset({"raw"})


def compute_vector(vector: dict, ctx: _VectorContext) -> str:
    kind = vector["kind"]
    input_value = vector.get("input", {})
    if kind == "sessionRefDigest":
        return session_ref_digest(input_value)
    if kind == "hostLockDigest":
        return host_lock_digest(input_value)
    if kind == "evidenceFact":
        return evidence_fact_digest(input_value, _resolve_allowlist(input_value.get("keyAllowlist")))
    if kind == "evidenceSha256":
        _require_exact_keys(input_value, ESH_WRAPPER_KEYS, "evidenceSha256 input")
        for entry in input_value["facts"]:
            _require_exact_keys(entry, ESH_ENTRY_KEYS, "evidence entry")
        materialized = []
        for entry in input_value["facts"]:
            ref = entry["factRef"]
            fact_vector = ctx.by_id.get(ref)
            if fact_vector is None:
                raise DigestError(f"unknown factRef vector: {ref!r}")
            fact_input = fact_vector["input"]
            if fact_input.get("id") != entry["id"]:
                raise DigestError(f"factRef {ref!r} id does not match evidence entry id")
            materialized.append(fact_input)
        return evidence_sha256_digest(materialized)
    if kind == "predParams":
        _require_exact_keys(input_value, PRED_PARAMS_WRAPPER_KEYS, "predParams input")
        allowlist = _resolve_allowlist(input_value.get("keyAllowlist"))
        return pred_params_digest(input_value["params"], allowlist)
    if kind == "bindingRecord":
        allowlist = _resolve_allowlist(input_value.get("keyAllowlist"))
        binding = _materialize_binding(input_value, ctx, allowlist)
        binding.pop("keyAllowlist", None)
        return binding_record_digest(binding, allowlist)
    if kind == "bindingDigest":
        _require_exact_keys(input_value, BINDING_DIGEST_WRAPPER_KEYS, "bindingDigest input")
        for entry in input_value["bindings"]:
            _require_exact_keys(entry, BINDING_REF_KEYS, "binding reference")
        allowlist = _resolve_allowlist(input_value.get("keyAllowlist"))
        records = []
        for entry in input_value["bindings"]:
            record = _materialize_binding(ctx.by_id[entry["ref"]]["input"], ctx, allowlist)
            record.pop("keyAllowlist", None)
            records.append(record)
        return binding_digest(records, allowlist)
    if kind == "certificationDigest":
        cert = {
            "stopProtocolVersion": input_value["stopProtocolVersion"],
            "certificateVersion": input_value["certificateVersion"],
            "epoch": input_value["epoch"],
            "sessionRefDigest": ctx.resolve_digest(input_value["sessionRefDigest"]),
            "hostLockDigest": ctx.resolve_digest(input_value["hostLockDigest"]),
            "contractRevision": input_value["contractRevision"],
            "contractSha256": ctx.resolve_digest(input_value["contractSha256"]),
            "openDigest": ctx.resolve_digest(input_value["openDigest"]),
            "evidenceSha256": ctx.resolve_digest(input_value["evidenceSha256"]),
            "bindingDigest": ctx.resolve_digest(input_value["bindingDigest"]),
        }
        goal_ref = input_value.get("goalRef")
        cert["goalRef"] = goal_ref
        return certification_digest(cert)
    if kind == "locator":
        _require_exact_keys(input_value, LOCATOR_KEYS, "locator input")
        return locator_digest(input_value["raw"])
    raise DigestError(f"unknown vector kind: {kind!r}")


def _materialize_binding(binding_input: dict, ctx: _VectorContext, allowlist: frozenset[str]) -> dict:
    """Resolve vector references inside a binding input.

    The predicate payload always travels as the referenced predParams vector's
    actual parameter object, so the record digest is recomputed from real
    payload bytes in both the inline and manifest branches.
    """
    binding = dict(binding_input)
    kind = binding.get("predParamsKind")
    if kind == "inline":
        params_ref = binding.get("predParams")
        if isinstance(params_ref, dict) and set(params_ref) == {"ref"}:
            vector = ctx.by_id.get(params_ref["ref"])
            if vector is None or vector["kind"] != "predParams":
                raise DigestError(f"unknown predParams ref: {params_ref!r}")
            binding["predParams"] = vector["input"]["params"]
            binding["predParamsAllowlist"] = vector["input"].get("keyAllowlist")
    elif kind == "manifest":
        digest_ref = binding.get("predParamsDigestRef")
        if not isinstance(digest_ref, str) or not digest_ref:
            raise DigestError("manifest binding requires predParamsDigestRef")
        vector = ctx.by_id.get(digest_ref)
        if vector is None or vector["kind"] != "predParams":
            raise DigestError(f"unknown predParams manifest ref: {digest_ref!r}")
        binding["predParamsManifest"] = vector["input"]["params"]
        binding["predParamsManifestAllowlist"] = vector["input"].get("keyAllowlist")
        binding.pop("predParamsDigestRef", None)
    else:
        raise DigestError(f"predParamsKind must be a canonical enum member: {kind!r}")
    return binding


def compute_all(vectors: list[dict]) -> dict[str, str]:
    ctx = _VectorContext(vectors)
    results: dict[str, str] = {}
    for vector in vectors:
        results[vector["id"]] = compute_vector(vector, ctx)
        ctx.computed[vector["id"]] = results[vector["id"]]
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load_cases(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("fixture") != "context_guard_digest_v3":
        raise DigestError("cases.json fixture identifier mismatch")
    if str(data.get("digestVersion")) != FIXTURE_VERSION:
        raise DigestError("cases.json digestVersion mismatch")
    return data


def _serialize_expected(results: dict[str, str]) -> bytes:
    document = {
        "digestVersion": FIXTURE_VERSION,
        "fixture": "context_guard_digest_v3",
        "generator": "scripts/reference_digest_encoder.py",
        "expected": dict(sorted(results.items())),
    }
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    ).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        metavar="CASES_JSON",
        help="recompute every vector and fail on any difference vs expected.json",
    )
    parser.add_argument(
        "--write",
        metavar="CASES_JSON",
        help="recompute every vector and (re)write expected.json next to it",
    )
    parser.add_argument("--self-test", action="store_true", help="run internal primitive assertions")
    args = parser.parse_args(argv)

    if args.self_test:
        _self_test()
        print("reference_digest_encoder self-test ok")
        return 0

    if not args.check and not args.write:
        parser.error("one of --check, --write, or --self-test is required")

    cases_path = Path(args.check or args.write).resolve()
    vectors = _load_cases(cases_path)["vectors"]
    results = compute_all(vectors)

    expected_path = cases_path.parent / "expected.json"
    if args.write:
        expected_path.write_bytes(_serialize_expected(results))
        print(f"wrote {len(results)} expected digests to {expected_path}")
        return 0

    if not expected_path.is_file():
        print(f"FAIL: missing expected.json at {expected_path}", file=sys.stderr)
        return 1
    on_disk = json.loads(expected_path.read_text(encoding="utf-8")).get("expected", {})
    failures = []
    for vector_id, digest in sorted(results.items()):
        if on_disk.get(vector_id) != digest:
            failures.append(vector_id)
    if failures or set(on_disk) != set(results):
        extra = sorted(set(on_disk) - set(results))
        print(
            "FAIL: digest fixture mismatch"
            f" (differing: {failures}, unexpected: {extra})",
            file=sys.stderr,
        )
        return 1
    print(f"reference digest fixture ok: {len(results)} vectors byte-identical")
    return 0


def _self_test() -> None:
    """Internal assertions for the raw primitive and fail-closed edges."""
    # Length prefixes keep field(maliciousName, "s:z") byte-distinct from two
    # concatenated short fields even with control bytes in the name.
    left = field("a\x00b", b"s:z")
    right = field("a", b"s:x") + field("b", b"s:z")
    if left == right:
        raise DigestError("field primitive collision regression")
    # Lone surrogates must fail closed before hashing.
    try:
        typed_token({"k": "s", "v": "\ud800"})
    except DigestError:
        pass
    else:
        raise DigestError("lone surrogate must fail closed")
    # Absent fields encode with presence 0 and zero length.
    if field("x", None) != struct.pack(">I", 1) + b"x" + b"\x00" + struct.pack(">I", 0):
        raise DigestError("absent field encoding regression")
    # seedLength=0 present must differ from seedLength missing.
    base = {
        "version": 0,
        "id": "self-test",
        "createdAt": 1,
    }
    if session_ref_digest(base) == session_ref_digest({**base, "seedLength": 0}):
        raise DigestError("present zero value must differ from absent")


if __name__ == "__main__":
    sys.exit(main())
