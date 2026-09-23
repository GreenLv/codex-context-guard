"""Versioned Host commentary observations, never answer or task completion.

Only a stable whole Host-selected transcript supplies messages. Root bindings
are verified by the caller against immutable prompts. No reply text is stored,
no final-reply heuristic is used, and no observation upgrades an old unknown.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import math
import os
import stat
from pathlib import Path
from typing import Any

SCHEMA = 'commentary-observation/v1'
SOURCE = 'codex-transcript-item-completed/v1'
MAX_BYTES = 512 * 1024 * 1024
MAX_LINE = 2 * 1024 * 1024
MAX_MESSAGES = 512
MAX_MESSAGE_IDENTITIES = 8192


def binding_module():
    spec = importlib.util.spec_from_file_location(
        "cg_commentary_binding", Path(__file__).with_name("cg_commentary_binding.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unknown(reason: str) -> dict[str, Any]:
    return {'schema': SCHEMA, 'source': SOURCE, 'status': 'unknown',
            'reason': reason, 'snapshot_sha256': None, 'watermark': None,
            'messages': [], 'answer_coverage': 'unknown', 'execution_closure': 'unchanged'}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_key')
        result[key] = value
    return result


def decode_record(raw):
    """Decode the transcript JSON domain, not the narrower review receipt.

    Finite numeric metadata is legal even when unrelated to messages. Semantic
    message fields are still type-checked by the observation projector.
    """
    def invalid_constant(_):
        raise ValueError('nonfinite_number')
    if len(raw) > MAX_LINE:
        raise ValueError('oversized_record')
    record = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                        parse_constant=invalid_constant)
    if not isinstance(record, dict):
        raise ValueError('invalid_record')
    stack = [(record, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > 32:
            raise ValueError('record_depth')
        if isinstance(value, dict):
            for key, child in value.items():
                key.encode('utf-8')
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            value.encode('utf-8')
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError('nonfinite_number')
    return record


def message_event(record):
    """One source-shape boundary shared by observation and private rereads.

    Unrelated records may have any payload. Once an item-completed record is
    selected, malformed message structure is unavailable, never a tool answer.
    """
    if not isinstance(record, dict):
        raise ValueError('invalid_record')
    if record.get('type') != 'event_msg':
        return None
    event = record.get('payload')
    if not isinstance(event, dict):
        raise ValueError('invalid_event_payload')
    if event.get('type') != 'item_completed':
        return None
    item = event.get('item')
    if not isinstance(item, dict):
        raise ValueError('invalid_completed_item')
    if item.get('type') != 'AgentMessage':
        return None
    content = item.get('content')
    if (not isinstance(content, list) or not content or any(
            not isinstance(c, dict) or set(c) != {'type', 'text'}
            or c.get('type') != 'Text' or not isinstance(c.get('text'), str) for c in content)):
        raise ValueError('unsupported_message_content')
    return event, item


def _project_records(records, session_id: str, roots: list[dict[str, Any]], *, review_roots=None, trace_source=None) -> dict[str, Any]:
    """Process one decoded record at a time; retain only bounded messages."""
    try:
        first = next(records)
        meta = first.get('payload')
        if (first.get('type') != 'session_meta' or not isinstance(meta, dict)
                or meta.get('id') != session_id
                or meta.get('session_id', session_id) != session_id):
            return unknown('session_mismatch')
        by_turn: dict[str, list[dict[str, Any]]] = {}
        for root in roots:
            turn = root.get('turn_id')
            if isinstance(turn, str) and turn and root.get('origin') == 'human':
                by_turn.setdefault(turn, []).append(root)
        messages: dict[str, dict[str, Any]] = {}
        users, texts, user_identities = [], {}, {}
        binder = binding_module() if trace_source is not None else None
        last_ordinal = -1
        for record in records:
            if binder is not None:
                user = binder.user_event(record, session_id)
                if user is not None:
                    user_id = user['params']['item']['id']
                    if user_id in user_identities and user_identities[user_id] != user:
                        return unknown('conflicting_user_identity')
                    user_identities[user_id] = user
                    users.append(user)
                    if len(users) > MAX_MESSAGE_IDENTITIES:
                        return unknown('user_source_budget')
            ordinal = record.get('ordinal')
            if ordinal is not None:
                if type(ordinal) is not int or ordinal <= last_ordinal:
                    return unknown('nonmonotonic_watermark')
                last_ordinal = ordinal
            selected = message_event(record)
            if selected is None:
                continue
            event, item = selected
            if (event.get('thread_id') != session_id or item.get('role', 'assistant') != 'assistant'
                    or event.get('agent_id') or item.get('agent_id')):
                return unknown('foreign_message_source')
            mid, turn = item.get('id'), event.get('turn_id')
            start, end = event.get('started_at_ms'), event.get('completed_at_ms')
            if (not isinstance(mid, str) or not mid or len(mid) > 200
                    or not isinstance(turn, str) or not turn or len(turn) > 200
                    or type(start) is not int or type(end) is not int or start < 0 or end < start):
                return unknown('incomplete_message_identity')
            text = ''.join(c['text'] for c in item['content'])
            phase = item.get('phase')
            candidates = by_turn.get(turn, [])
            bound = candidates[0] if binder is None and len(candidates) == 1 and phase == 'commentary' else None
            row = {'message_id': mid, 'turn_id': turn, 'phase': phase if phase in
                   {'commentary', 'final_answer'} else None, 'started_at_ms': start, 'completed_at_ms': end,
                   'reply_sha256': sha(text.encode('utf-8')), 'observation': 'message_completed',
                   'association': 'unique_root_candidate' if bound else 'unknown',
                   'root_id': bound['id'] if bound else None,
                   'root_sha256': bound['sha256'] if bound else None,
                   'question_candidates': sorted(bound.get('question_ids', [])) if bound else [],
                   'answer_coverage': 'unknown', 'execution_closure': 'unchanged'}
            if mid in messages and messages[mid] != row:
                return unknown('conflicting_message_identity')
            messages[mid] = row
            if binder is not None:
                texts[mid] = text
                if sum(len(t.encode('utf-8')) for t in texts.values()) > 2 * 1024 * 1024:
                    return unknown('binding_text_budget')
            if len(messages) > MAX_MESSAGE_IDENTITIES:
                return unknown('message_limit')
        if not messages:
            return unknown('no_supported_message_events')
        if binder is not None:
            if len(roots) > 64 or len(messages) > 64:
                return unknown('binding_root_budget')
            attempts = (len(messages) * sum(bool(r.get('question_ids')) for r in roots)
                        + len(messages) ** 2)
            if attempts * sum(len(raw) for raw in trace_source['payloads'].values()) > 128 * 1024 * 1024:
                return unknown('binding_work_budget')
            for mid, row in messages.items():
                association = binder.bind(trace_source, users, roots, row, texts[mid], session_id)
                if association is not None:
                    root, proof = association
                    row.update(association='source_bound_input_response', root_id=root['id'],
                               root_sha256=root['sha256'], question_candidates=sorted(root['question_ids']),
                               source_binding=proof)
            # An unbound commentary might be a correction. Exclude it only
            # with explicit request/response input lineage before the question.
            unbound = [r for r in messages.values() if r['phase'] == 'commentary' and r['root_id'] is None]
            invalid_roots = set()
            for row in messages.values():
                if row['root_id'] is None:
                    continue
                root = next(r for r in roots if r['id'] == row['root_id'])
                proofs = []
                for earlier in unbound:
                    if earlier['turn_id'] != row['turn_id']:
                        continue
                    proof = binder.prior_progress(trace_source, root, row, earlier,
                                                  texts[earlier['message_id']], session_id)
                    if proof is None:
                        invalid_roots.add(row['root_id'])
                    else:
                        proofs.append(proof)
                if proofs:
                    row['source_binding']['excluded_prior_messages'] = sorted(proofs, key=lambda p: p['message_id'])
            for row in messages.values():
                if row['root_id'] in invalid_roots:
                    row.update(association='unknown', root_id=None, root_sha256=None, question_candidates=[])
                    row.pop('source_binding', None)
        ordered = sorted(messages.values(), key=lambda r: (r['completed_at_ms'], r['message_id']))
        selected_messages = ordered[-MAX_MESSAGES:]
        overflow = set()
        if review_roots is not None:
            groups = {root: [] for root in review_roots}
            for row in ordered:
                if row['root_id'] in groups:
                    groups[row['root_id']].append(row)
            overflow = {root for root, rows in groups.items() if len(rows) > MAX_MESSAGES}
            selected_messages = [row for row in ordered if row['root_id'] in groups
                                 and row['root_id'] not in overflow]
        result = {'schema': SCHEMA, 'source': SOURCE, 'status': 'observed', 'reason': None,
                'snapshot_sha256': None, 'watermark': None,
                'messages': selected_messages,
                'message_count': len(messages), 'messages_omitted': len(messages) - len(selected_messages),
                'root_candidate_count': sum(r['association'] == 'unique_root_candidate' for r in messages.values()),
                'answer_coverage': 'unknown', 'execution_closure': 'unchanged'}
        if review_roots is not None:
            # Ephemeral review result only; never written as a display sidecar.
            result['review_overflow_roots'] = sorted(overflow)
        return result
    except (UnicodeError, ValueError, TypeError, KeyError, OverflowError, StopIteration, RecursionError):
        return unknown('invalid_snapshot')



def scan(handle, session_id: str, roots: list[dict[str, Any]], *, prefix_bytes: int = 0, review_roots=None, trace_source=None) -> dict[str, Any]:
    """Bound memory by one JSON line plus message catalog, not file length.

    Re-scan the whole retained prefix, so an earlier conflicting event cannot
    hide behind a tail/checkpoint. No persisted checkpoint grants authority.
    """
    digest = hashlib.sha256()
    prefix_digest = hashlib.sha256()
    progress = {'bytes': 0, 'records': 0}
    def records():
        while True:
            line = handle.readline(MAX_LINE + 1)
            if not line:
                return
            remaining_prefix = max(0, prefix_bytes - progress['bytes'])
            prefix_digest.update(line[:remaining_prefix])
            digest.update(line)
            progress['bytes'] += len(line)
            if progress['bytes'] > MAX_BYTES or len(line) > MAX_LINE or not line.endswith(b'\n'):
                raise ValueError('incomplete_or_oversized_record')
            record = decode_record(line)
            progress['records'] += 1
            yield record
    iterator = records()
    try:
        result = _project_records(iterator, session_id, roots, review_roots=review_roots, trace_source=trace_source)
        # Even a semantic unknown is bound to the complete scanned snapshot.
        # A decoder failure terminates the generator and is detected below by
        # the byte count/read boundary; it never supplies observed messages.
        for _ in iterator:
            pass
        result['snapshot_sha256'] = digest.hexdigest()
        result['watermark'] = progress['records']
        result['scanned_bytes'] = progress['bytes']
        result['prefix_sha256'] = prefix_digest.hexdigest()
        return result
    except (OSError, UnicodeError, ValueError, RecursionError):
        return unknown('invalid_stream')


def project(raw: bytes, session_id: str, roots: list[dict[str, Any]]) -> dict[str, Any]:
    """In-memory fixture adapter using the exact streaming production parser."""
    if not raw or len(raw) > MAX_BYTES or not raw.endswith(b'\n'):
        return unknown('incomplete_or_oversized_snapshot')
    result = scan(io.BytesIO(raw), session_id, roots)
    return result if result.get('scanned_bytes') == len(raw) else unknown('incomplete_snapshot')


def _safe_path(path: Path, sessions_root: Path) -> None:
    if not path.is_absolute() or '..' in path.parts or path.suffix != '.jsonl':
        raise ValueError('unsafe_path')
    relative = path.relative_to(sessions_root)
    if not relative.parts:
        raise ValueError('unsafe_path')
    for candidate in (sessions_root, *sessions_root.parents):
        if candidate.is_symlink():
            raise ValueError('symlink')
    cursor = sessions_root
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError('symlink')


def file_identity(s) -> dict[str, int]:
    return {'device': s.st_dev, 'inode': s.st_ino, 'bytes': s.st_size,
            'mtime_ns': s.st_mtime_ns, 'ctime_ns': getattr(s, 'st_ctime_ns', 0)}


def stable_snapshot(path_before, handle_before, handle_after, path_after) -> bool:
    """Compare each stat provider to itself, then bind their common fields.

    Windows CPython can expose different ctime values through lstat/fstat.
    ctime still participates in BOTH same-provider stability checks; it is
    never discarded as a change detector. File identity, size and mtime bind
    the path to the opened object across providers. Content/prefix hashes are
    separate mandatory checks, not replaced by these metadata comparisons.
    """
    def signature(value):
        return (file_identity(value), getattr(value, 'st_mode', None),
                getattr(value, 'st_nlink', None), getattr(value, 'st_reparse_tag', None))
    def common(value):
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                getattr(value, 'st_mode', None), getattr(value, 'st_nlink', None))
    return (signature(path_before) == signature(path_after)
            and signature(handle_before) == signature(handle_after)
            and common(path_before) == common(handle_before))


def observe(path: Path, sessions_root: Path, session_id: str,
            roots: list[dict[str, Any]], *, prior: dict[str, Any] | None = None, review_roots=None) -> dict[str, Any]:
    try:
        _safe_path(path, sessions_root)
        binder = binding_module()
        trace_source = binder.snapshot(session_id)
        before_path = path.lstat()
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_BYTES:
                raise ValueError('unsafe_file')
            prefix_bytes = 0
            if prior is not None:
                identity = prior.get('file_identity')
                prefix_bytes = prior.get('scanned_bytes')
                if (not isinstance(identity, dict) or type(prefix_bytes) is not int
                        or prefix_bytes < 0 or prefix_bytes > MAX_BYTES
                        or not isinstance(prior.get('snapshot_sha256'), str)
                        or len(prior['snapshot_sha256']) != 64):
                    return unknown('invalid_checkpoint')
                if (before.st_dev, before.st_ino) != (identity.get('device'), identity.get('inode')):
                    return unknown('snapshot_replaced')
                if before.st_size < prefix_bytes:
                    return unknown('snapshot_truncated')
            result = scan(handle, session_id, roots, prefix_bytes=prefix_bytes, review_roots=review_roots, trace_source=trace_source)
            after = os.fstat(handle.fileno())
        after_path = path.lstat()
        identity = file_identity(before)
        if not stable_snapshot(before_path, before, after, after_path):
            return unknown('snapshot_changed')
        if result.get('scanned_bytes') != before.st_size:
            return unknown('incomplete_snapshot')
        if prior is not None and result.get('prefix_sha256') != prior['snapshot_sha256']:
            return unknown('snapshot_prefix_changed')
        if trace_source is not None:
            after_trace = binder.snapshot(session_id)
            if (after_trace is None or after_trace['hashes'] != trace_source['hashes']
                    or after_trace['identities'] != trace_source['identities']):
                return unknown('trace_changed_during_observation')
            result['trace_as_of'] = trace_source['hashes']
        result['file_identity'] = identity
        return result
    except (OSError, ValueError):
        return unknown('snapshot_unavailable')
