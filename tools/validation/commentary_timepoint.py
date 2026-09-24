"""Bounded private product-state timepoints for a native commentary run.

The only copied product byte is state.json. Other dependencies stay at their
original locations, are allowlisted and pinned, and are re-read on replay.
The review capture key is neither read nor copied by this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

from tools.validation import commentary_fixture as fixture

SCHEMA = "cg-commentary-timepoint/v1"
STATE_LIMIT = 1024 * 1024
DEPENDENCY_LIMIT = 8 * 1024 * 1024
DEPENDENCY_COUNT = 64
TRANSCRIPT_LIMIT = 512 * 1024 * 1024
RPC_LIMIT = 32 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class TimepointError(ValueError):
    """A timepoint is absent, unstable, changed, or bound to another run."""


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def _regular(path, limit):
    if not path.is_absolute() or '..' in path.parts:
        raise TimepointError('unsafe_timepoint_path')
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
            raise TimepointError('linked_timepoint_path')
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size > limit):
        raise TimepointError('unbounded_timepoint_file')
    return before


def _stable_bytes(path, limit):
    before = _regular(path, limit)
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    after = _regular(path, limit)
    if (len(raw) > limit or len(raw) != before.st_size or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns)):
        raise TimepointError('timepoint_source_changed')
    return raw


def _dependencies(directory):
    names = {}
    total = 0
    for folder, kind in ((directory / 'prompts', 'prompts'),
                         (directory / 'prompts/units', 'units'),
                         (directory / 'answer-reviews', 'reviews')):
        if (folder.is_symlink() or
                (hasattr(folder, 'is_junction') and folder.is_junction())
                or not folder.is_dir()):
            raise TimepointError('timepoint_dependency_directory_missing')
        with os.scandir(folder) as entries:
            for entry in entries:
                path = Path(entry.path)
                if kind == 'prompts' and entry.name == 'units' and entry.is_dir(follow_symlinks=False):
                    continue
                if kind == 'reviews' and entry.name == 'capture.key':
                    continue  # Secret remains at its original location.
                allowed = (
                    re.fullmatch(r'P[0-9]{4,8}\.json', entry.name) if kind != 'reviews'
                    else (entry.name == 'policy.json' or re.fullmatch(
                        r'(?:capture-[0-9a-f]{32}|(?:attempt|revoked)-[0-9a-f]{64})\.json',
                        entry.name)))
                if not allowed or not entry.is_file(follow_symlinks=False):
                    raise TimepointError('unexpected_timepoint_dependency')
                if len(names) >= DEPENDENCY_COUNT:
                    raise TimepointError('timepoint_dependency_budget')
                raw = _stable_bytes(path, DEPENDENCY_LIMIT - total)
                total += len(raw)
                if total > DEPENDENCY_LIMIT:
                    raise TimepointError('timepoint_dependency_budget')
                names[path.relative_to(directory).as_posix()] = _hash(raw)
    if not names:
        raise TimepointError('empty_timepoint_dependencies')
    return names


def _prefix(path, *, limit, length=None):
    before = _regular(path, limit)
    if length is None:
        length = before.st_size
    if type(length) is not int or not 0 < length <= before.st_size:
        raise TimepointError('timepoint_prefix_missing')
    value = hashlib.sha256()
    with path.open('rb') as stream:
        remaining = length
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                raise TimepointError('timepoint_prefix_truncated')
            value.update(block)
            remaining -= len(block)
    after = _regular(path, limit)
    if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or after.st_size < length
            or (length == before.st_size and after.st_size != before.st_size)):
        raise TimepointError('timepoint_prefix_replaced')
    return {'bytes': length, 'sha256': value.hexdigest()}


def _request_binding(runtime, directory, home, state, question_id):
    rows = [item for item in state.get('requirements', []) if item.get('id') == question_id]
    if len(rows) != 1:
        raise TimepointError('timepoint_question_missing')
    request = runtime.answer_review_request(directory, state, rows[0],
                                            codex_home=home)
    if request.get('subject', {}).get('question_id') != question_id:
        raise TimepointError('timepoint_review_subject_changed')
    relevant = {name: request[name] for name in
                ('subject', 'messages', 'answer_texts', 'question_catalog')}
    return {'relevant_sha256': _hash(_canonical(relevant)),
            'as_of': request['as_of'], 'subject': request['subject'],
            'message_ids': [row['message_id'] for row in request['messages']],
            'answer_sha256': {key: _hash(value.encode())
                              for key, value in request['answer_texts'].items()}}


def _projection(observer, directory, state, question_id, main_ids):
    return fixture.product_review_checkpoint(
        observer.runtime, state, session_dir=directory,
        codex_home=observer.plan['codex_home'], question_id=question_id,
        main_ids=main_ids,
        expected_coverage=observer.plan.get('review_coverage', 'complete'),
        expected_main_current=(None if observer.plan.get('review_coverage') == 'partial'
                               else True))


def capture(observer, run_dir, stage, projection, journal_path, anchor):
    if stage not in {'review', 'cold'} or not isinstance(anchor, str) or not anchor:
        raise TimepointError('invalid_timepoint_stage')
    directory = observer._product_directory(observer.thread)
    state_path = directory / 'state.json'
    raw = _stable_bytes(state_path, STATE_LIMIT)
    state = json.loads(raw)
    observer.runtime.validate_state_integrity(state)
    if _projection(observer, directory, state, observer.question_id,
                   observer.main_ids) != projection:
        raise TimepointError('timepoint_projection_changed')
    deps = _dependencies(directory)
    transcript = Path(state['session']['transcript_path'])
    home = Path(observer.plan['codex_home'])
    if not transcript.is_relative_to(home / 'sessions'):
        raise TimepointError('foreign_timepoint_transcript')
    rollout = _prefix(transcript, limit=TRANSCRIPT_LIMIT)
    request = _request_binding(observer.runtime, directory, home, state,
                               observer.question_id)
    if (request['subject'].get('session_id') != observer.thread
            or request['subject'].get('turn_id') != observer.turn
            or request['as_of'].get('snapshot_sha256') != rollout['sha256']):
        raise TimepointError('timepoint_review_source_unbound')
    seal_raw = _stable_bytes(Path(run_dir) / 'review-barrier.json', 65536)
    seal = json.loads(seal_raw)
    if (seal.get('schema') != 'cg-review-barrier/v1'
            or seal.get('projection') != projection):
        raise TimepointError('timepoint_review_seal_unbound')
    journal = _prefix(journal_path, limit=RPC_LIMIT)
    if (_stable_bytes(state_path, STATE_LIMIT) != raw
            or _dependencies(directory) != deps
            or _prefix(transcript, limit=TRANSCRIPT_LIMIT) != rollout
            or _request_binding(observer.runtime, directory, home, state,
                                observer.question_id) != request):
        raise TimepointError('timepoint_changed_during_capture')
    root = Path(run_dir)
    state_copy = root / f'timepoint-{stage}-state.json'
    meta_path = root / f'timepoint-{stage}.json'
    if state_copy.exists() or meta_path.exists():
        raise TimepointError('timepoint_already_exists')
    with state_copy.open('xb') as stream:
        os.chmod(state_copy, 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    meta = {'schema': SCHEMA, 'stage': stage, 'thread': observer.thread,
            'turn': observer.turn, 'runtime_tree_sha256': observer.plan['runtime_tree_sha256'],
            'source_tree_sha256': observer.plan['source_tree_sha256'],
            'binary_sha256': observer.plan['binary_sha256'],
            'namespace': observer.plan['namespace'],
            'runtime_root': str(observer.runtime_root),
            'anchor': anchor, 'question_id': observer.question_id,
            'main_ids': observer.main_ids, 'state_sha256': _hash(raw),
            'dependencies': deps, 'transcript_path': str(transcript),
            'transcript_prefix': rollout, 'rpc_prefix': journal,
            'review_request': request, 'review_seal_sha256': _hash(seal_raw),
            'projection': projection}
    with meta_path.open('xb') as stream:
        os.chmod(meta_path, 0o600)
        stream.write(_canonical(meta) + b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    return {'path': str(meta_path), 'sha256': _hash(meta_path.read_bytes())}


def verify(observer, run_dir, stage, descriptor, projection, journal_path,
           anchor, *, after_boundary, before_boundary):
    if (stage not in {'review', 'cold'} or not isinstance(descriptor, dict)
            or set(descriptor) != {'path', 'sha256'}
            or descriptor['path'] != str(Path(run_dir) / f'timepoint-{stage}.json')
            or not HEX64.fullmatch(descriptor['sha256'])):
        raise TimepointError('timepoint_descriptor_mismatch')
    raw = _stable_bytes(Path(descriptor['path']), 65536)
    if _hash(raw) != descriptor['sha256']:
        raise TimepointError('timepoint_manifest_hash_changed')
    meta = json.loads(raw)
    if (meta.get('schema') != SCHEMA or meta.get('stage') != stage
            or meta.get('thread') != observer.thread or meta.get('turn') != observer.turn
            or meta.get('runtime_tree_sha256') != observer.plan['runtime_tree_sha256']
            or meta.get('source_tree_sha256') != observer.plan['source_tree_sha256']
            or meta.get('binary_sha256') != observer.plan['binary_sha256']
            or meta.get('namespace') != observer.plan['namespace']
            or meta.get('runtime_root') != str(observer.runtime_root)
            or meta.get('anchor') != anchor
            or meta.get('question_id') != projection['question_id']
            or meta.get('main_ids') != projection['main_ids']
            or meta.get('projection') != projection):
        raise TimepointError('timepoint_subject_mismatch')
    state_path = Path(run_dir) / f'timepoint-{stage}-state.json'
    state_raw = _stable_bytes(state_path, STATE_LIMIT)
    if _hash(state_raw) != meta['state_sha256']:
        raise TimepointError('timepoint_state_changed')
    state = json.loads(state_raw)
    observer.runtime.validate_state_integrity(state)
    seal_raw = _stable_bytes(Path(run_dir) / 'review-barrier.json', 65536)
    if (_hash(seal_raw) != meta.get('review_seal_sha256')
            or json.loads(seal_raw).get('projection') != projection):
        raise TimepointError('timepoint_review_seal_changed')
    if (state.get('session', {}).get('id') != observer.thread
            or _hash(fixture.canonical(state.get('requirements')))
            != projection['requirements_sha256']):
        raise TimepointError('timepoint_state_projection_mismatch')
    directory = observer._product_directory(observer.thread)
    if _dependencies(directory) != meta['dependencies']:
        raise TimepointError('timepoint_dependencies_changed')
    transcript = Path(meta['transcript_path'])
    if (str(transcript) != state['session']['transcript_path']
            or not transcript.is_relative_to(Path(observer.plan['codex_home']) / 'sessions')
            or _prefix(transcript, limit=TRANSCRIPT_LIMIT,
                       length=meta['transcript_prefix']['bytes'])
            != meta['transcript_prefix']
            or meta['review_request']['as_of']['snapshot_sha256']
            != meta['transcript_prefix']['sha256']):
        raise TimepointError('timepoint_transcript_prefix_changed')
    rpc = meta['rpc_prefix']
    if (type(rpc.get('bytes')) is not int
            or not after_boundary <= rpc['bytes'] <= before_boundary
            or _prefix(journal_path, limit=RPC_LIMIT, length=rpc['bytes']) != rpc):
        raise TimepointError('timepoint_event_order_changed')
    # Product source readers scan to EOF. A final-run read here would import
    # post-suite events into the historical stage. The product computation was
    # performed during capture, with exact as-of bytes bound above; replay
    # verifies that retained result instead of claiming a later re-execution.
    return projection, state, meta['review_request']


def final_cold_readback(observer, question_id, main_ids, cold_state):
    """Fresh-process read of the later product state; never equate it to review."""
    directory = observer._product_directory(observer.thread)
    program = """
import importlib.util, json, sys
from pathlib import Path
root, directory, home, thread, question, mains = json.load(sys.stdin)
spec = importlib.util.spec_from_file_location('cg_timepoint_final_runtime',
                                               Path(root) / 'scripts/context_guard.py')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
source_path = Path(directory) / 'state.json'
if source_path.is_symlink() or source_path.stat().st_size > 1024 * 1024:
    raise ValueError('final_product_state_unsafe')
with source_path.open('rb') as stream:
    source_bytes = stream.read(1024 * 1024 + 1)
if len(source_bytes) > 1024 * 1024:
    raise ValueError('final_product_state_unbounded')
state = json.loads(source_bytes)
module.validate_state_integrity(state)
if state.get('session', {}).get('id') != thread:
    raise ValueError('final_session_changed')
scope = module.current_scope_projection(state, session_dir=Path(directory),
                                        codex_home=Path(home))
with source_path.open('rb') as stream:
    after_bytes = stream.read(1024 * 1024 + 1)
if after_bytes != source_bytes:
    raise ValueError('final_product_state_changed_during_read')
questions = [row for row in state['requirements'] if row.get('id') == question]
main = [row for row in state['requirements'] if row.get('id') in mains]
if len(questions) != 1 or len(main) != len(mains):
    raise ValueError('final_obligation_identity_lost')
result = {'question_coverage': scope['answer_reviews'].get(question, {}).get('coverage'),
          'question_current': question in scope['current_item_ids'],
          'main_ids': sorted(row['id'] for row in main),
          'main_statuses': {row['id']: row['status'] for row in main},
          'main_current_ids': sorted(row['id'] for row in main
                                     if row['id'] in scope['current_item_ids']),
          'other_current_ids': sorted(item for item in scope['current_item_ids']
                                      if item not in set(mains) | {question}),
          'requirements_statuses': {row['id']: row['status']
                                    for row in state['requirements']},
          'acceptance_statuses': {row['id']: row['status']
                                  for row in state.get('acceptance_items', [])}}
print(json.dumps(result, sort_keys=True))
"""
    run = subprocess.run(
        [sys.executable, '-c', program],
        input=json.dumps([str(observer.runtime_root), str(directory),
                          observer.plan['codex_home'], observer.thread,
                          question_id, main_ids]),
        text=True, capture_output=True, timeout=15, check=False,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    if run.returncode != 0 or len(run.stdout) > 65536:
        raise TimepointError('final_product_read_failed')
    result = json.loads(run.stdout)
    old_requirements = {row['id']: row['status'] for row in cold_state['requirements']}
    old_acceptance = {row['id']: row['status']
                      for row in cold_state.get('acceptance_items', [])}
    terminal = {'pass', 'answered', 'superseded'}
    for earlier, later in ((old_requirements, result.get('requirements_statuses', {})),
                           (old_acceptance, result.get('acceptance_statuses', {}))):
        if (not set(earlier) <= set(later)
                or any(status in terminal and later[key] != status
                       for key, status in earlier.items())):
            raise TimepointError('final_product_obligation_regressed')
    if (result.get('question_coverage') != 'complete'
            or result.get('question_current') is not False
            or result.get('main_ids') != sorted(main_ids)
            or set(result.get('main_statuses', {})) != set(main_ids)
            or any(result['main_statuses'][key]
                   != result['requirements_statuses'].get(key) for key in main_ids)):
        raise TimepointError('final_product_obligation_regressed')
    main_statuses = result.pop('main_statuses')
    other_current = result.pop('other_current_ids')
    result.pop('requirements_statuses')
    result.pop('acceptance_statuses')
    result['main_statuses'] = main_statuses
    result['other_obligations_preserved'] = True
    result['new_or_other_current_count'] = len(other_current)
    result['main_closure'] = ('completed' if not other_current and all(
        value == 'pass' for value in main_statuses.values())
                              else 'unknown')
    return result
