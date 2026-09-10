"""Response-delivery ledger: answer-delivery facts kept separate from completion.

Context Guard 0.13 frozen contract (plan section 4.5): a delivered final
answer is NOT a completed task. This module owns the canonical
``response-delivery/v1`` projection and its domain-separated digest so the
heavy core can record which requirements received a delivered final reply
without ever copying reply text or claiming semantic adequacy.

Boundaries:
  * stdlib-only, no heavy imports, no I/O, no policy prose;
  * the canonical projection carries EXACTLY: version, session/turn
    identity, root work-unit, UTF-8-byte-sorted deduplicated requirement
    ids, event source, reply SHA-256, and the delivery status — nothing
    else may enter the hashed projection;
  * digests are SHA-256 over ``context-guard/response-delivery/v1`` + NUL
    + canonical JSON (sorted keys, compact separators, Unicode preserved,
    NaN/float identity and implicit coercion rejected);
  * the reply digest is the SHA-256 of the adapter-extracted raw string's
    UTF-8 bytes — no newline or Unicode normalization is applied;
  * ``delivery_unknown`` is an evidence state: missing, empty, non-string,
    or conflicting reply sources never fabricate a digest, an ``answered``
    requirement, or a ``verified`` resolution.

Dependency direction (strictly one-way):
    cg_delivery  <-  context_guard.py (heavy core only; the Phase-2
    router fast path never imports it).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

DELIVERY_SCHEMA = "response-delivery/v1"
DELIVERY_DOMAIN = "context-guard/response-delivery/v1"

DELIVERY_STATUSES = ("delivered", "not_delivered", "delivery_unknown")
DELIVERY_RESOLUTIONS = ("open", "waiting", "verified", "not_applicable")
DELIVERY_SOURCES = ("stop_final_reply", "migration_reconstruction")

# Exact canonical-projection field set (plan section 4.5 P0 freeze). The
# resolution dimension is recorded beside the projection and is never part
# of the hashed identity.
PROJECTION_FIELDS = (
    "version",
    "session_id",
    "turn_id",
    "work_unit_id",
    "requirement_ids",
    "source",
    "reply_sha256",
    "delivery",
)
RECORD_METADATA_FIELDS = ("resolution", "delivery_sha256", "sequence", "recorded_at")
RECORD_FIELDS = PROJECTION_FIELDS + RECORD_METADATA_FIELDS
MAX_REQUIREMENT_ASSOCIATIONS = 16
MAX_DELIVERY_RECORDS = 512
MAX_DELIVERY_ID_LENGTH = 200

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ID_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._:@/-]{0,199}")


class DeliveryValueError(ValueError):
    """Raised when a delivery record violates the frozen canonical contract."""


def canonical_json_bytes(value: Any) -> bytes:
    """Canonical JSON: sorted keys, compact, Unicode preserved, strict types.

    Floats, NaN/Infinity, non-string object keys, and lone surrogates are
    rejected instead of silently coerced, so the same canonical input
    yields the same digest bytes on POSIX and Windows.
    """

    def walk(node: Any) -> None:
        if node is None or isinstance(node, (str, bool)) or (
            isinstance(node, int) and not isinstance(node, bool)
        ):
            return
        if isinstance(node, float):
            raise DeliveryValueError("float values have no canonical delivery identity")
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if isinstance(node, dict):
            for key, item in node.items():
                if not isinstance(key, str):
                    raise DeliveryValueError("delivery object keys must be strings")
                walk(item)
            return
        raise DeliveryValueError(
            f"unsupported delivery value type {type(node).__name__}"
        )

    walk(value)
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return text.encode("utf-8")
    except (ValueError, UnicodeEncodeError) as exc:
        raise DeliveryValueError(f"canonical delivery JSON failed: {exc}") from exc


def delivery_digest(projection: dict[str, Any]) -> str:
    """Domain-separated SHA-256 over the canonical projection bytes."""
    payload = DELIVERY_DOMAIN.encode("utf-8") + b"\x00" + canonical_json_bytes(
        projection
    )
    return hashlib.sha256(payload).hexdigest()


def idempotency_key(projection: dict[str, Any]) -> str:
    """Replay key: the trusted association plus the reply digest.

    Re-observing the same delivered event yields the same key, so replays
    never grow the ledger; a corrected reply in the same turn yields a
    different key and is appended in event order (latest wins).
    """
    association = {
        "version": DELIVERY_SCHEMA,
        "session_id": projection.get("session_id"),
        "turn_id": projection.get("turn_id"),
        "work_unit_id": projection.get("work_unit_id"),
        "requirement_ids": projection.get("requirement_ids"),
        "source": projection.get("source"),
        "reply_sha256": projection.get("reply_sha256"),
    }
    payload = DELIVERY_DOMAIN.encode("utf-8") + b"\x00idempotency\x00" + canonical_json_bytes(
        association
    )
    return hashlib.sha256(payload).hexdigest()


def _bounded_id(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise DeliveryValueError(f"delivery field {field} must be a string")
    text = value
    if not text or len(text) > MAX_DELIVERY_ID_LENGTH or any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in text
    ):
        raise DeliveryValueError(f"delivery field {field} is not a valid identity")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DeliveryValueError(f"delivery field {field} is not valid Unicode") from exc
    return text


def canonical_projection(
    *,
    session_id: Any,
    turn_id: Any,
    work_unit_id: Any,
    requirement_ids: Any,
    source: Any,
    reply_sha256: Any,
    delivery: Any,
) -> dict[str, Any]:
    """Build and validate the closed-world canonical projection.

    ``reply_sha256`` is nullable only for ``delivery_unknown``; a
    ``delivered`` projection without an exact reply digest is rejected.
    """
    if delivery not in DELIVERY_STATUSES:
        raise DeliveryValueError("delivery status is invalid")
    if source not in DELIVERY_SOURCES:
        raise DeliveryValueError("delivery event source is invalid")
    if reply_sha256 is None:
        if delivery == "delivered":
            raise DeliveryValueError("delivered delivery requires a reply digest")
    elif not (isinstance(reply_sha256, str) and _SHA256_RE.fullmatch(reply_sha256)):
        raise DeliveryValueError("delivery reply digest is invalid")
    if delivery == "delivery_unknown" and reply_sha256 is not None:
        raise DeliveryValueError("unknown delivery must not fabricate a reply digest")
    if not isinstance(requirement_ids, list) or len(requirement_ids) > MAX_REQUIREMENT_ASSOCIATIONS:
        raise DeliveryValueError("delivery requirement association is invalid")
    for item in requirement_ids:
        _bounded_id(item, "requirement_ids")
    ordered = sorted(set(requirement_ids), key=lambda item: item.encode("utf-8"))
    if len(ordered) != len(dict.fromkeys(requirement_ids)):
        raise DeliveryValueError("delivery requirement association is invalid")
    projection = {
        "version": DELIVERY_SCHEMA,
        "session_id": _bounded_id(session_id, "session_id"),
        "turn_id": _bounded_id(turn_id, "turn_id"),
        "work_unit_id": _bounded_id(work_unit_id, "work_unit_id", nullable=True),
        "requirement_ids": ordered,
        "source": source,
        "reply_sha256": reply_sha256,
        "delivery": delivery,
    }
    return projection


def build_record(
    projection: dict[str, Any],
    *,
    resolution: Any,
    sequence: int,
    recorded_at: str,
) -> dict[str, Any]:
    """Attach non-canonical metadata (resolution, digest, ordering)."""
    _validate_projection(projection)
    if resolution not in DELIVERY_RESOLUTIONS:
        raise DeliveryValueError("delivery resolution is invalid")
    if type(sequence) is not int or sequence < 1:
        raise DeliveryValueError("delivery sequence is invalid")
    if not isinstance(recorded_at, str) or not recorded_at:
        raise DeliveryValueError("delivery timestamp is invalid")
    record = dict(projection)
    record["resolution"] = resolution
    record["delivery_sha256"] = delivery_digest(projection)
    record["sequence"] = sequence
    record["recorded_at"] = recorded_at
    return record


def _validate_projection(raw: Any) -> None:
    if not isinstance(raw, dict) or set(raw) != set(PROJECTION_FIELDS):
        raise DeliveryValueError("delivery projection fields are invalid")
    if raw["version"] != DELIVERY_SCHEMA:
        raise DeliveryValueError("delivery record version is invalid")
    canonical = canonical_projection(**{key: raw[key] for key in PROJECTION_FIELDS if key != "version"})
    if raw != canonical:
        raise DeliveryValueError("delivery projection is not canonical")


def validate_record(raw: Any) -> None:
    """Closed-world validation of one persisted delivery record."""
    if not isinstance(raw, dict):
        raise DeliveryValueError("delivery record must be an object")
    missing = [field for field in RECORD_FIELDS if field not in raw]
    extra = [field for field in raw if field not in RECORD_FIELDS]
    if missing or extra:
        raise DeliveryValueError(
            f"delivery record fields are invalid: missing={missing}, extra={extra}"
        )
    _validate_projection({field: raw[field] for field in PROJECTION_FIELDS})
    projection = canonical_projection(
        session_id=raw["session_id"],
        turn_id=raw["turn_id"],
        work_unit_id=raw["work_unit_id"],
        requirement_ids=raw["requirement_ids"],
        source=raw["source"],
        reply_sha256=raw["reply_sha256"],
        delivery=raw["delivery"],
    )
    if raw["delivery_sha256"] != delivery_digest(projection):
        raise DeliveryValueError("delivery record digest mismatch")
    if raw["resolution"] not in DELIVERY_RESOLUTIONS:
        raise DeliveryValueError("delivery resolution is invalid")
    if type(raw["sequence"]) is not int or raw["sequence"] < 1:
        raise DeliveryValueError("delivery sequence is invalid")
    if not isinstance(raw["recorded_at"], str) or not raw["recorded_at"]:
        raise DeliveryValueError("delivery timestamp is invalid")


def validate_ledger(raw: Any) -> None:
    """Validate the persisted ``response_delivery`` ledger shape."""
    if not isinstance(raw, dict):
        raise DeliveryValueError("response delivery ledger must be an object")
    if set(raw) != {"schema", "sequence", "records"}:
        raise DeliveryValueError("response delivery ledger fields are invalid")
    if raw.get("schema") != DELIVERY_SCHEMA:
        raise DeliveryValueError("response delivery ledger schema is invalid")
    sequence = raw.get("sequence")
    if type(sequence) is not int or sequence < 0:
        raise DeliveryValueError("response delivery ledger sequence is invalid")
    records = raw.get("records")
    if not isinstance(records, list) or len(records) > MAX_DELIVERY_RECORDS:
        raise DeliveryValueError("response delivery ledger exceeds its record limit")
    seen_keys: set[str] = set()
    previous_sequence = 0
    for record in records:
        validate_record(record)
        if not previous_sequence < record["sequence"] <= sequence:
            raise DeliveryValueError("delivery record sequence is inconsistent")
        previous_sequence = record["sequence"]
        projection = {
            field: record[field]
            for field in PROJECTION_FIELDS
        }
        key = idempotency_key(projection)
        if key in seen_keys:
            raise DeliveryValueError("delivery record replay duplicates its idempotency key")
        seen_keys.add(key)


def latest_delivery_for_requirement(
    records: list[dict[str, Any]], requirement_id: str
) -> dict[str, Any] | None:
    """Latest delivery record associating the requirement (event order)."""
    latest: dict[str, Any] | None = None
    for record in records:
        if isinstance(record, dict) and requirement_id in record.get("requirement_ids", []):
            latest = record
    return latest
