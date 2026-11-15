"""Pure synthetic predicate prototype, NOT a native acceptance reader.

Callers must independently establish root/thread identity, stable live reads,
trusted runtime validation, original evidence/subject and all other native gates.
No file, process, model, configuration, installation or network I/O occurs here.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import re
from collections.abc import Callable
from typing import Any

LIMIT = 16 * 1024 * 1024
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z\Z")


class Refused(ValueError):
    pass


def require(value: bool, code: str) -> None:
    if not value:
        raise Refused(code)


def state_from_bytes(raw: bytes) -> dict[str, Any]:
    require(type(raw) is bytes and 0 < len(raw) <= LIMIT, "state_size")

    def pairs(rows):
        out = {}
        for key, value in rows:
            require(key not in out, "duplicate_key")
            out[key] = value
        return out

    try:
        value = json.loads(
            raw.decode("utf8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: require(False, "nonfinite"),
        )
    except (UnicodeError, ValueError):
        raise Refused("invalid_state_json") from None
    require(type(value) is dict and type(value.get("session")) is dict, "state_shape")
    return value


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf8")
    except (TypeError, ValueError, UnicodeError):
        raise Refused("uncanonicalizable_state") from None


def content_valid(state: dict[str, Any]) -> bool:
    supplied = state.get("content_hash")
    if not isinstance(supplied, str) or HEX64.fullmatch(supplied) is None:
        return False
    payload = {key: value for key, value in state.items() if key != "content_hash"}
    return hashlib.sha256(canonical(payload)).hexdigest() == supplied


def utc_time(value: Any) -> dt.datetime:
    require(type(value) is str and UTC.fullmatch(value) is not None, "utc_timestamp")
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise Refused("utc_timestamp") from None


def relation(
    preimage: bytes,
    current: bytes,
    *,
    recorded_pre_sha: str,
    stable_current_sha: str,
    recorded_root: str,
    current_root: str,
    thread: str,
    observed_at: str,
    validate_state: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    """Check exact preimage/live snapshots; no provenance or other-gate claim.

    validate_state must be the independently bound runtime's full integrity
    validator. Root equality here is only a placeholder for verified path and
    file-identity checks by a real reader.
    """
    require(
        type(recorded_pre_sha) is str
        and HEX64.fullmatch(recorded_pre_sha) is not None
        and type(stable_current_sha) is str
        and HEX64.fullmatch(stable_current_sha) is not None,
        "digest_shape",
    )
    require(type(preimage) is bytes and type(current) is bytes, "state_bytes")
    require(hashlib.sha256(preimage).hexdigest() == recorded_pre_sha, "preimage_sha")
    require(
        hashlib.sha256(current).hexdigest() == stable_current_sha, "live_snapshot_sha"
    )
    require(
        type(recorded_root) is str
        and bool(recorded_root)
        and type(current_root) is str
        and recorded_root == current_root,
        "root_identity",
    )
    require(
        type(thread) is str
        and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", thread) is not None,
        "thread_identity",
    )
    before, after = state_from_bytes(preimage), state_from_bytes(current)
    require(
        before["session"].get("id") == after["session"].get("id") == thread,
        "thread_identity",
    )
    require(content_valid(before) and content_valid(after), "state_content_hash")
    # A production caller supplies the exact validated runtime; copy to ensure
    # its validator cannot alter the comparison inputs.
    try:
        validate_state(copy.deepcopy(before))
        validate_state(copy.deepcopy(after))
    except Exception:  # noqa: BLE001 -- suppress untrusted private validator text.
        raise Refused("runtime_integrity") from None
    if preimage == current:
        return {
            "relation": "exact_raw_match",
            "pre_sha256": recorded_pre_sha,
            "current_sha256": stable_current_sha,
        }
    prior, later = before["session"], after["session"]
    require(
        "ended_at" in prior
        and prior["ended_at"] is None
        and "ended_at" in later
        and later["ended_at"] is not None
        and "updated_at" in prior
        and "updated_at" in later,
        "session_end_fields",
    )
    old_updated, ended = utc_time(prior["updated_at"]), utc_time(later["ended_at"])
    new_updated, captured = utc_time(later["updated_at"]), utc_time(observed_at)
    require(old_updated <= ended <= new_updated <= captured, "time_order")
    # Canonical full-object comparison after excluding exactly three fields.
    # This preserves every other key/value/type, including business, scope and
    # pending fields, and is stricter than comparing a projection or subset.
    old_normal, new_normal = copy.deepcopy(before), copy.deepcopy(after)
    for value in (old_normal, new_normal):
        value.pop("content_hash")
        value["session"].pop("ended_at")
        value["session"].pop("updated_at")
    require(canonical(old_normal) == canonical(new_normal), "other_state_change")
    return {
        "relation": "session_end_metadata_consistent",
        "pre_sha256": recorded_pre_sha,
        "current_sha256": stable_current_sha,
    }
