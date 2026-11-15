"""Versioned full-state relation for a controlled, separately bound run.

No original result is modified; caller must already bind original evidence,
producer, helpers, artifact and private preimage. The original producer's
snapshot and _old_scope perform runtime integrity validation in owned children.
"""

import datetime as dt
import hashlib
from pathlib import Path

if __package__:
    from . import state_relation
else:
    import state_relation


def check_post_close(e78, ctx, after, current, thread, preimage_path):
    """Validate exact preimage and current snapshot, never substitute either."""
    preimage_path = e78.regular(Path(preimage_path))
    preimage = e78.safe_bytes(preimage_path, 16 * 1024 * 1024)
    recorded = after.get("sha256")
    e78.require(
        hashlib.sha256(preimage).hexdigest() == recorded,
        "full preimage differs from original old-after digest",
    )
    before = state_relation.state_from_bytes(preimage)
    runtime = ctx["old_root"] if ctx["old_root"].is_dir() else ctx["new_root"]
    # Pinned-runtime child validates the complete preimage before deriving scope;
    # this helper rechecks its source-state SHA across the child operation.
    scope = ctx["u"]._old_scope(runtime, preimage_path, ctx["home"])
    e78.require(
        hashlib.sha256(e78.safe_bytes(preimage_path, 16 * 1024 * 1024)).hexdigest()
        == recorded,
        "full preimage changed during scope validation",
    )
    projected = e78.project(
        ctx,
        {"root": after["root"], "sha256": recorded, "state": before, "scope": scope},
    )
    e78.require(projected == after, "full preimage projection differs")

    # Current was obtained by the original snapshot, which validates runtime
    # integrity and scope. Bind a fresh stable byte read to that same snapshot.
    root = Path(current["root"])
    candidates = [
        root / "sessions-v2" / thread / "state.json",
        root / "sessions" / thread / "state.json",
    ]
    present = [p for p in candidates if p.exists() or p.is_symlink()]
    e78.require(len(present) == 1, "state path ambiguous")
    live = e78.safe_bytes(e78.regular(present[0]), 16 * 1024 * 1024)
    e78.require(
        hashlib.sha256(live).hexdigest() == current["sha256"], "live state drift"
    )
    live_state = state_relation.state_from_bytes(live)
    e78.require(
        state_relation.canonical(live_state)
        == state_relation.canonical(current["state"]),
        "live parsed state differs from verified snapshot",
    )

    # _old_scope validated preimage and original snapshot validated current.
    # The predicate receives only identical deep-copied states from those two
    # independently validated sources; no caller-supplied success flag.
    accepted = {
        hashlib.sha256(state_relation.canonical(x)).hexdigest()
        for x in (before, current["state"])
    }

    def already_runtime_validated(value):
        e78.require(
            hashlib.sha256(state_relation.canonical(value)).hexdigest() in accepted,
            "state is not a runtime-validated input",
        )

    observed_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return state_relation.relation(
        preimage,
        live,
        recorded_pre_sha=recorded,
        stable_current_sha=current["sha256"],
        recorded_root=after["root"],
        current_root=current["root"],
        thread=thread,
        observed_at=observed_at,
        validate_state=already_runtime_validated,
    )
