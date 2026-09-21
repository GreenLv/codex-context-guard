"""Project actual Codex root records and observed host events through core v2.

The caller verifies immutable prompt records before supplying them. The only
host readiness/effect facts here come from PostToolUse evidence recorded from
one attributable operation with a structured result. This projection is
ephemeral Stop diagnosis and never an ordinary tool permission.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from cg_core_v2 import project


def _revision(prompt_id: str) -> int:
    match = re.fullmatch(r"P(\d{4,})", prompt_id)
    if match is None:
        raise ValueError("invalid_prompt_revision")
    return int(match.group(1))


def _span(source_id: str, text: str, start: int, end: int) -> dict[str, Any]:
    raw = text.encode("utf-8")
    return dict(source_id=source_id, start=start, end=end,
                sha256=hashlib.sha256(raw).hexdigest())


def project_current_action(
    state: dict[str, Any], roots: dict[str, dict[str, Any]],
    *, item: dict[str, Any], action: str, target: str, turn: str,
    constraint_kind: str = "exact", root_scope: str | None = None,
    resume_prefix: bool = False, root_constraint: str | None = None,
    resolved_constraint: str | None = None,
    condition_scope: tuple[str, str] | None = None,
    predicate_name: str | None = None,
    requested_postimage_sha256: str | None = None,
    return_snapshot: bool = False,
) -> dict[str, Any]:
    """Return core projection over the current real root/host event watermark.

    Root records, work units and PostToolUse evidence are all included in the
    event order. Unsupported interpretation stays unknown coverage. A Stop
    action may still be diagnosed while whole completion stays uncertified.
    """
    active = state.get("work_state", {}).get("active_work_unit_id")
    units = [u for u in state.get("work_units", []) if isinstance(u, dict)
             and u.get("prompt_id") in roots]
    unit_by_id = {str(u["id"]): u for u in units}
    if active not in unit_by_id or item.get("work_unit_id") != active:
        raise ValueError("action_unit_not_current")
    prompt_id = str(item.get("prompt_id") or "")
    root = roots.get(prompt_id)
    if not root:
        raise ValueError("action_root_not_current")
    text = root["text"]
    if not isinstance(text, str):
        raise ValueError("target_not_literal_root")
    if target.startswith("/"):
        pass
    elif re.match(r"^[A-Za-z]:[\\/]", target):
        from context_guard import canonical_windows_locator
        canonical, unsupported = canonical_windows_locator(target)
        if unsupported is not None or canonical != target:
            raise ValueError("target_not_canonical_windows_locator")
    else:
        raise ValueError("target_not_absolute_locator")
    if constraint_kind not in {"exact", "directory", "work_unit"}:
        raise ValueError("unsupported_target_constraint")
    if not root_scope or root_scope not in text:
        raise ValueError("action_scope_not_root")
    if constraint_kind in {"exact", "directory"}:
        if root_constraint is None:
            root_constraint = target
        if root_constraint not in text:
            raise ValueError("target_not_literal_root")
        constraint = root_constraint
    else:
        if target in text:
            raise ValueError("work_unit_scope_not_independent")
        constraint = root_scope
    raw = text.encode("utf-8")
    scope_at = text.find(root_scope)
    constraint_at = root_scope.find(constraint)
    if scope_at < 0:
        raise ValueError("target_not_in_action_scope")
    if constraint_at >= 0:
        # A repeated target belongs to this exact action span, rather than the
        # first identical bytes elsewhere in the root.
        target_at = scope_at + constraint_at
    else:
        # Bounded anaphora may name one unique object immediately from earlier
        # root context ("the file ... change it").  It is not legitimate when
        # multiple prior literals compete or when the only literal follows
        # the action span.
        positions = [
            match.start() for match in re.finditer(re.escape(constraint), text)
            if match.end() <= scope_at
        ]
        if len(positions) != 1:
            raise ValueError("target_not_in_action_scope")
        target_at = positions[0]
    target_start = len(text[:target_at].encode("utf-8"))
    target_end = target_start + len(constraint.encode("utf-8"))
    root_ids = {pid: f"root:{pid}" for pid in roots}
    prompt_units = {str(item["prompt_id"]): str(item["work_unit_id"])
                    for item in state.get("requirements", [])
                    if isinstance(item, dict) and item.get("prompt_id") in roots
                    and item.get("work_unit_id") in unit_by_id}
    if prompt_units.get(prompt_id) != active:
        raise ValueError("action_prompt_not_in_current_unit")
    watermark = state.get("core_event_sequence")
    if type(watermark) is not int or watermark < 1:
        raise ValueError("missing_event_watermark")
    events: list[tuple[int, str, dict[str, Any]]] = []
    for pid, uid in prompt_units.items():
        seq = roots[pid].get("core_event_seq")
        if type(seq) is int and 0 < seq <= watermark:
            events.append((seq, root_ids[pid],
                           dict(type="root", unit=uid, prompt_id=pid)))
    for evidence in state.get("evidence", []):
        if not isinstance(evidence, dict) or not isinstance(evidence.get("core_observation"), dict):
            continue
        fact = evidence["core_observation"]
        if fact.get("unit") not in unit_by_id or fact.get("prompt_id") not in roots:
            continue
        eid = str(evidence.get("id") or "")
        call_seq, result_seq = evidence.get("core_call_seq"), evidence.get("core_result_seq")
        if (type(call_seq) is not int or type(result_seq) is not int
                or not 0 < call_seq < result_seq <= watermark):
            continue
        events.append((call_seq, f"call:{eid}", dict(type="call", evidence=evidence)))
        events.append((result_seq, f"result:{eid}", dict(type="result", evidence=evidence)))
    events.sort(key=lambda row: row[0])
    sequence = {key: seq for seq, key, _ in events}
    if len({seq for seq, _, _ in events}) != len(events):
        raise ValueError("duplicate_event_sequence")
    sources: list[dict[str, Any]] = []
    facts: list[dict[str, Any]] = []
    readiness_ids: list[str] = []
    edit_observations: list[tuple[int, str, dict[str, Any]]] = []
    git_observations: list[tuple[int, str, dict[str, Any]]] = []
    for seq, key, event in events:
        if event["type"] == "root":
            pid = event["prompt_id"]
            record = roots[pid]
            root_text = record["text"]
            root_raw = root_text.encode("utf-8")
            root_source = dict(id=key, seq=seq, kind="root",
                                unit=event["unit"], revision=_revision(pid),
                                sha256=hashlib.sha256(root_raw).hexdigest(),
                                byte_length=len(root_raw), text=root_text,
                                call_id=None, turn=str(record.get("turn_id") or pid))
            if isinstance(record.get("locator_base"), str):
                root_source["locator_base"] = record["locator_base"]
                root_source["locator_flavor"] = record.get("locator_flavor", "posix")
            sources.append(root_source)
            continue
        evidence = event["evidence"]
        observed = evidence["core_observation"]
        eid = str(evidence["id"])
        uid = str(observed["unit"])
        # A later continuation may supply the Host selection for an earlier
        # still-active requirement in the same immutable work unit. The
        # observation keeps its own prompt provenance and append sequence;
        # its core fact is evaluated against the requirement revision.
        revision = _revision(prompt_id) if uid == active else _revision(str(observed["prompt_id"]))
        call_id = hashlib.sha256((eid + "\0" + observed["call_sha256"]).encode()).hexdigest()
        source_row = dict(id=key, seq=seq,
                            kind="host_call" if event["type"] == "call" else "host_result",
                            unit=uid, revision=revision,
                            sha256=str(observed["call_sha256"]), byte_length=0,
                            text=None, call_id=call_id,
                            turn=str(observed.get("turn") or ""))
        if event["type"] == "call":
            source_row["target"] = str(observed.get("canonical_target") if resolved_constraint is not None
                                       else observed["target"])
            source_row["target_kind"] = "filesystem"
            origin_pid = evidence.get("core_origin_prompt_id")
            if isinstance(origin_pid, str) and origin_pid in root_ids:
                source_row["origin_root_source_id"] = root_ids[origin_pid]
        sources.append(source_row)
        if event["type"] != "result":
            continue
        # A prior-root edit cannot prove a new edit requirement in the same
        # work unit. Commit/push lineage is different: its earlier sourced
        # repository selection is an intentional prerequisite.
        origin_pid = evidence.get("core_origin_prompt_id")
        origin_root = roots.get(origin_pid) if isinstance(origin_pid, str) else None
        if (action == "local_edit" and
                (origin_root is None or type(origin_root.get("core_event_seq")) is not int
                 or origin_root["core_event_seq"] < root["core_event_seq"])):
            continue
        observed_target = (observed.get("canonical_target") if resolved_constraint is not None
                           else observed.get("target"))
        if observed_target != target or uid != active or revision != _revision(prompt_id):
            continue
        if observed["kind"] == "git_readback" or observed["predicate"] in {
            "commit_attempt", "push_attempt"
        }:
            git_observations.append((seq, eid, observed))
        if observed["kind"] == "git_readback":
            continue
        fact_id = f"fact:{eid}"
        kind = "readiness" if observed["kind"] == "state_readback" else observed["kind"]
        predicate = "file_exists" if observed["kind"] == "state_readback" else observed["predicate"]
        facts.append(dict(id=fact_id, seq=seq, unit=uid, revision=revision,
                          source_id=key, call_source_id=f"call:{eid}",
                          kind=kind, target=target, predicate=predicate,
                          outcome=observed["outcome"], operation_id=None,
                          requirement_id=str(item["id"]), condition_id=None,
                          invalidates=[]))
        if (action == "test_verify" and predicate_name == "test_run_completed"
                and observed["kind"] == "action_event"
                and observed["predicate"] == "test_passed"
                and observed["outcome"] == "success"):
            # A passing test also completed a run. A nonzero terminal run
            # arrives with its own test_run_completed observation; neither
            # path turns a failed result into a test_passed fact.
            facts.append(dict(id=f"run-complete:{eid}", seq=seq, unit=uid,
                              revision=revision, source_id=key,
                              call_source_id=f"call:{eid}", kind="action_event",
                              target=target, predicate="test_run_completed",
                              outcome="success", operation_id=None,
                              requirement_id=str(item["id"]), condition_id=None,
                              invalidates=[]))
        if (action == "state_readback" and observed["kind"] == "state_readback"
                and observed.get("predicate") == "content_hash"
                and isinstance(observed.get("content_sha256"), str)):
            facts.append(dict(id=f"readback:{eid}", seq=seq, unit=uid,
                              revision=revision, source_id=key,
                              call_source_id=f"call:{eid}", kind="action_event",
                              target=target, predicate="readback_complete",
                              outcome=observed["outcome"], operation_id=None,
                              requirement_id=str(item["id"]), condition_id=None,
                              invalidates=[]))
        if observed["kind"] in {"state_readback", "action_event"}:
            edit_observations.append((seq, eid, observed))
        if kind == "readiness" and observed["outcome"] == "success":
            readiness_ids.append(fact_id)
    if action == "local_edit":
        before_hash: str | None = None
        pending_before: str | None = None
        pending_post: str | None = None
        for seq, eid, observed in sorted(edit_observations):
            if observed["kind"] == "action_event" and observed["predicate"] == "edit_applied":
                pending_before = before_hash if observed["outcome"] == "success" else None
                post_hash = observed.get("post_content_sha256")
                pending_post = (post_hash if observed["outcome"] == "success"
                                and isinstance(post_hash, str)
                                and re.fullmatch(r"[0-9a-f]{64}", post_hash) else None)
                # A later edit makes an earlier state readback historical.
                # The new effect needs its own subsequent current readback.
                facts.append(dict(id=f"edit-state:{eid}", seq=seq, unit=active,
                                  revision=_revision(prompt_id), source_id=f"result:{eid}",
                                  call_source_id=f"call:{eid}", kind="state_outcome",
                                  target=target, predicate="state_matches", outcome="failure",
                                  operation_id=None, requirement_id=str(item["id"]),
                                  condition_id=None, invalidates=[]))
            elif observed["kind"] == "state_readback":
                content_hash = observed.get("content_sha256")
                if observed["outcome"] != "success" or not isinstance(content_hash, str):
                    if pending_before is not None or pending_post is not None:
                        facts.append(dict(id=f"edit-state:{eid}", seq=seq, unit=active,
                                          revision=_revision(prompt_id), source_id=f"result:{eid}",
                                          call_source_id=f"call:{eid}", kind="state_outcome",
                                          target=target, predicate="state_matches", outcome="failure",
                                          operation_id=None, requirement_id=str(item["id"]),
                                          condition_id=None, invalidates=[]))
                    pending_before = None
                    pending_post = None
                    continue
                if pending_before is not None or pending_post is not None:
                    # A trusted FileChange Update records its stable postimage
                    # at the same Host result. A separate later readback must
                    # name the same bytes; an earlier read is optional.
                    state_matches = (pending_post == content_hash if pending_post is not None
                                     else content_hash != pending_before)
                    if requested_postimage_sha256 is not None:
                        state_matches = (state_matches
                                         and content_hash == requested_postimage_sha256)
                    facts.append(dict(id=f"edit-state:{eid}", seq=seq, unit=active,
                                      revision=_revision(prompt_id), source_id=f"result:{eid}",
                                      call_source_id=f"call:{eid}", kind="state_outcome",
                                      target=target, predicate="state_matches",
                                      outcome="success" if state_matches else "failure",
                                      operation_id=None, requirement_id=str(item["id"]),
                                      condition_id=None, invalidates=[]))
                before_hash = content_hash
                pending_before = None
                pending_post = None
    if action in {"local_commit", "remote_push"}:
        rows = sorted(git_observations)
        shows = [(seq, eid, obs) for seq, eid, obs in rows
                 if obs["predicate"] == "commit_identity" and obs["outcome"] == "success"]
        branches = [(seq, obs.get("git", {}).get("branch")) for seq, _, obs in rows
                    if obs["predicate"] == "branch_identity" and obs["outcome"] == "success"]
        commits = [(seq, eid) for seq, eid, obs in rows
                   if obs["predicate"] == "commit_attempt" and obs["outcome"] == "success"]
        pushes = [(seq, eid, obs) for seq, eid, obs in rows
                  if obs["predicate"] == "push_attempt" and obs["outcome"] == "success"]
        remote = [(seq, eid, obs) for seq, eid, obs in rows
                  if obs["predicate"] == "remote_ref" and obs["outcome"] == "success"]
        commit_pair = next(((before, after) for before in shows for after in shows
                            if before[0] < after[0]
                            and any(before[0] < commit_seq < after[0]
                                    for commit_seq, _ in commits)
                            and after[2]["git"]["parent"] == before[2]["git"]["oid"]
                            and after[2]["git"]["tree"] != before[2]["git"]["tree"]), None)
        if commit_pair and any(seq > commit_pair[1][0] and branch == "main"
                               for seq, branch in branches):
            before, after = commit_pair
            derived = None
            predicate = "commit_verified"
            if action == "local_commit":
                derived = after
            else:
                predicate = "push_verified"
                derived = next((row for row in remote
                                if any(after[0] < push_seq < row[0]
                                       and push_obs.get("git") == {"remote": "origin", "refspec": "main"}
                                       for push_seq, _, push_obs in pushes)
                                and row[2]["git"]["oid"] == after[2]["git"]["oid"]), None)
            if derived is not None:
                seq, eid, _ = derived
                facts.append(dict(id=f"git-state:{eid}", seq=seq, unit=active,
                                  revision=_revision(prompt_id), source_id=f"result:{eid}",
                                  call_source_id=f"call:{eid}", kind="state_outcome",
                                  target=target, predicate=predicate, outcome="success",
                                  operation_id=None, requirement_id=str(item["id"]),
                                  condition_id=None, invalidates=[]))
    if root_ids[prompt_id] not in sequence:
        raise ValueError("root_event_missing")
    unit_rows = [dict(id=str(u["id"]),
                      parent_id=u.get("parent_id") if u.get("parent_id") in unit_by_id else None,
                      required=True, source_id=root_ids[str(u["prompt_id"])])
                 for u in units]
    scope_start = len(text[:scope_at].encode("utf-8"))
    scope_end = scope_start + len(root_scope.encode("utf-8"))
    # Only adjacent punctuation and whitespace can be absorbed into the
    # action span. Another sentence, request, or unknown tail remains open.
    before, after = text[:scope_at], text[scope_at + len(root_scope):]
    if (not before.strip(" \t\r\n,，。.!?？；;：:")
            or resume_prefix):
        scope_start = 0
    if not after.strip(" \t\r\n,，。.!?？；;：:"):
        scope_end = len(raw)
    span = _span(root_ids[prompt_id], text, scope_start, scope_end)
    target_span = _span(root_ids[prompt_id], text, target_start, target_end)
    conditions = []
    if condition_scope is not None:
        condition_text, condition_kind = condition_scope
        condition_at = text.find(condition_text, scope_at)
        if condition_at < scope_at or condition_at >= scope_at + len(root_scope):
            raise ValueError("condition_not_in_action_scope")
        condition_start = len(text[:condition_at].encode("utf-8"))
        condition_end = condition_start + len(condition_text.encode("utf-8"))
        conditions.append(dict(id=f"condition:{item['id']}",
                               requirement_id=str(item["id"]),
                               source=_span(root_ids[prompt_id], text,
                                            condition_start, condition_end),
                               kind=condition_kind, status="pending",
                               operation_id=None, fact_ids=[]))
    selected_call = next((f["call_source_id"] for f in facts
                          if f["kind"] == "readiness" and f["outcome"] == "success"), None)
    origin = dict(root_constraint=constraint,
                  subject_kind="filesystem",
                  constraint_kind=constraint_kind,
                  selection_source_id=selected_call if constraint_kind == "work_unit" else None,
                  root_constraint_source=target_span,
                  implementation_choice=target,
                  host_selection=target, resolved=target,
                  observed=target)
    if resolved_constraint is not None:
        origin["resolved_constraint"] = resolved_constraint
        origin["selection_source_id"] = selected_call
    effective_predicate = predicate_name or {"test_verify": "test_passed", "local_commit": "commit_verified",
                                             "remote_push": "push_verified"}.get(action, "state_matches")
    requirement = dict(id=str(item["id"]), unit=active,
                       revision=_revision(prompt_id), seq=sequence[root_ids[prompt_id]],
                       source=span, kind="execution", action=action, target=target,
                       predicate=effective_predicate,
                       scope_sha256=hashlib.sha256(raw).hexdigest(),
                       required=True, status="pending", parent_id=None,
                       evidence_kind="state_outcome" if action in {"local_edit", "local_commit", "remote_push"} else "action_event",
                       condition_ids=[c["id"] for c in conditions],
                       target_origin=origin)
    action_row = dict(schema="current-action-basis/v1",
                      requirement_id=requirement["id"], unit=active,
                      revision=requirement["revision"], seq=watermark,
                      source=span, scope_sha256=requirement["scope_sha256"],
                      action=action, target=target,
                      predicate=requirement["predicate"], owner="assistant",
                      relation="direct", readiness_fact_ids=readiness_ids,
                      state="current")
    coverage = []
    for source in sources:
        if source["kind"] == "root" and source["byte_length"]:
            if source["id"] == root_ids[prompt_id]:
                partitions = ((0, scope_start, "unknown"),
                              (scope_start, scope_end, "interpreted"),
                              (scope_end, source["byte_length"], "unknown"))
            else:
                partitions = ((0, source["byte_length"], "unknown"),)
            for begin, end, kind in partitions:
                if begin < end:
                    coverage.append(dict(source=_span(source["id"], source["text"],
                                                      begin, end), kind=kind))
    observation = dict(schema="core-observation/v2", unit=active,
                       revision=requirement["revision"], as_of=watermark, turn=turn,
                       units=unit_rows, sources=sources, requirements=[requirement],
                       facts=facts, actions=[action_row],
                       intent=dict(source=span, kind="resume"),
                       completion_claim=False, proof_violation=False,
                       corrections_used=0, progress_changed=True,
                       goal_contract_adopted=False, release_state="not_adopted",
                       conditions=conditions, coverage=coverage)
    return observation if return_snapshot else project(observation)
