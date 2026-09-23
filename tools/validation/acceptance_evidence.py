"""Offline transfer and evidence-index checks; no execution authority.

The input receipts are claims with explicit provenance. A valid shape never
establishes official Hook trust or host acceptance: owning native adapters
and independent readback must still validate their original capture.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

STAGES = ("accepted", "received", "digest_verified", "started", "completed")


def payload_identity(files: dict[str, bytes]) -> dict[str, Any]:
    if not files or any(not name or "/" in name or "\\" in name or name in {".", ".."}
                        for name in files):
        raise ValueError("invalid_payload_inventory")
    inventory = [{"name": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                 for name, raw in sorted(files.items())]
    digest = hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True).encode("utf-8")).hexdigest()
    return {"file_count": len(files), "byte_count": sum(map(len, files.values())), "sha256": digest}


def transfer_state(events: list[dict[str, Any]], request_id: str,
                   payload: dict[str, Any]) -> dict[str, Any]:
    """Idempotent identical retries; conflicts do not imply execution."""
    seen: dict[str, dict[str, Any]] = {}
    expected_stage = 0
    for event in events:
        if not isinstance(event, dict) or event.get("request_id") != request_id:
            return {"status": "unknown", "reason": "request_identity_mismatch"}
        if event.get("status") == "active_writer_conflict":
            return {"status": "unknown", "reason": "active_writer_conflict"}
        stage = event.get("stage")
        if stage not in STAGES or event.get("payload") != payload:
            return {"status": "unknown", "reason": "payload_or_stage_mismatch"}
        if stage in seen:
            if seen[stage] != event:
                return {"status": "unknown", "reason": "conflicting_retry"}
            continue
        if STAGES[expected_stage] != stage:
            return {"status": "unknown", "reason": "stage_predecessor_missing"}
        seen[stage] = event
        expected_stage += 1
    return {"status": STAGES[expected_stage - 1] if expected_stage else "unknown",
            "execution_reported": "completed" in seen,
            "acceptance": "not_established"}


def evidence_index(entries: list[dict[str, Any]], subject: dict[str, str],
                   required_gates: set[str]) -> dict[str, Any]:
    """Reject stale/unsourced claims before original-capture review."""
    if (set(subject) != {"commit", "runtime_sha256"}
            or not re.fullmatch(r"[0-9a-f]{40}", subject.get("commit", ""))
            or not re.fullmatch(r"[0-9a-f]{64}", subject.get("runtime_sha256", ""))):
        raise ValueError("invalid_subject")
    accepted = []
    rejected = []
    seen: set[str] = set()
    for entry in entries:
        gate = entry.get("gate")
        reason = None
        if not isinstance(gate, str) or gate in seen:
            reason = "duplicate_or_missing_gate"
        elif entry.get("subject") != subject:
            reason = "candidate_identity_mismatch"
        elif entry.get("provenance") not in {"host_observed", "derived", "reviewed"}:
            reason = "provenance_missing"
        elif gate == "hook_trust" and entry.get("provenance") != "host_observed":
            reason = "derived_trust_is_not_official_observation"
        elif not isinstance(entry.get("as_of"), str) or not entry["as_of"]:
            reason = "observation_time_missing"
        else:
            path = entry.get("source")
            if not isinstance(path, str) or Path(path).is_symlink() or not Path(path).is_file():
                reason = "source_missing"
            elif hashlib.sha256(Path(path).read_bytes()).hexdigest() != entry.get("source_sha256"):
                reason = "source_digest_mismatch"
        if isinstance(gate, str):
            seen.add(gate)
        if reason:
            accepted = [row for row in accepted if row["gate"] != gate]
            rejected.append({"gate": gate if gate in required_gates else "unknown", "reason": reason})
        else:
            accepted.append({"gate": gate, "provenance": entry["provenance"],
                             "source_sha256": entry["source_sha256"],
                             "status": "awaiting_original_capture_review"})
    return {"schema": "cg-evidence-index/v1", "subject": subject, "entries": accepted,
            "rejected": rejected, "missing": sorted(required_gates - {e["gate"] for e in accepted}),
            "acceptance": "not_established"}


def main(argv=None) -> int:
    """Offline receipt CLI; no send, authentication, model or native execution."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.input.is_symlink() or args.input.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('unsafe_input')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate_key')
                result[key] = value
            return result
        request = json.loads(args.input.read_text(encoding='utf-8'), object_pairs_hook=unique)
        if request.get('operation') == 'evidence_index':
            result = evidence_index(request['entries'], request['subject'], set(request['required_gates']))
        elif request.get('operation') == 'transfer_readback':
            files = {}
            for entry in request['files']:
                path = Path(entry['path'])
                name = entry['name']
                if name in files or path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
                    raise ValueError('unsafe_payload')
                files[name] = path.read_bytes()
            identity = payload_identity(files)
            result = transfer_state(request['events'], request['request_id'], identity)
            result['actual_payload'] = identity
        else:
            raise ValueError('unsupported_operation')
        # Preserve any prior receipt, including a failed one.
        with args.output.open('x', encoding='utf-8') as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2)
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        parser.error('invalid_or_unavailable_receipt_input_or_output')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
