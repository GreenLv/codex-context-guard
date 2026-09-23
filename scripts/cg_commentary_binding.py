"""Read-only bindings from host-selected transcript and official trace sources.

No caller supplies an edge, root selection, source path or acceptance flag.
The host's trace-root environment and immutable prompt catalog are inputs.
This is the same local-file trust boundary as the transcript reader, not an
OS sandbox. Missing or ambiguous provenance never becomes review authority.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import re
from pathlib import Path


def trace_module():
    spec = importlib.util.spec_from_file_location(
        "cg_binding_trace", Path(__file__).with_name("cg_commentary_trace.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot(session):
    """Discover the exact official session bundle; never accept caller paths."""
    source = os.environ.get("CODEX_ROLLOUT_TRACE_ROOT")
    if not source:
        return None
    trace = trace_module()
    root = Path(source)
    if not root.is_absolute() or any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError("unsafe_trace_root")
    candidates = []
    # Bound enumeration before reading any candidate. A resumed session with
    # multiple trace bundles has no inferred latest/nearest bundle authority.
    entries = []
    for entry in root.iterdir():
        entries.append(entry)
        if len(entries) > 1024:
            raise ValueError("trace_directory_budget")
    for entry in entries:
        if not entry.name.startswith("trace-") or not entry.name.endswith("-" + session):
            continue
        raw = trace.stable_read(entry, "manifest.json")
        manifest = trace.decode(raw)
        if (not isinstance(manifest, dict)
                or type(manifest.get("schema_version")) is not int
                or manifest["schema_version"] != 1
                or manifest.get("root_thread_id") != session
                or manifest.get("rollout_id") != session
                or manifest.get("raw_event_log") != "trace.jsonl"
                or manifest.get("payloads_dir") != "payloads"
                or entry.name != "trace-" + str(manifest.get("trace_id")) + "-" + session):
            raise ValueError("trace_manifest_mismatch")
        events, payloads, hashes = trace.load_snapshot(entry, "trace.jsonl")
        if not events or events[0].get("payload") != {
            "type": "rollout_started", "trace_id": manifest["trace_id"], "root_thread_id": session
        } or any(event.get("rollout_id") != session for event in events):
            raise ValueError("trace_rollout_mismatch")
        if trace.stable_read(entry, "manifest.json") != raw:
            raise ValueError("trace_manifest_changed")
        hashes["manifest.json"] = hashlib.sha256(raw).hexdigest()
        identities = {}
        for relative in hashes:
            status = (entry / relative).lstat()
            identities[relative] = [status.st_dev, status.st_ino]
        candidates.append({"events": events, "payloads": payloads, "hashes": hashes,
                           "identities": identities,
                           "collector_sha256": hashlib.sha256(trace.canonical({
                               name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                               for name in ('context_guard.py', 'cg_commentary.py',
                                            'cg_commentary_binding.py', 'cg_commentary_trace.py')})).hexdigest()})
    if len(candidates) != 1:
        raise ValueError("nonunique_trace_bundle")
    return candidates[0]


def user_event(record, session):
    """Translate only the official completed UserMessage shape."""
    if record.get("type") != "event_msg":
        return None
    event = record.get("payload", {})
    if not isinstance(event, dict) or event.get("type") != "item_completed":
        return None
    item = event.get("item", {})
    if not isinstance(item, dict) or item.get("type") != "UserMessage":
        return None
    if (event.get("thread_id") != session or event.get("agent_id") or item.get("agent_id")
            or not isinstance(item.get("id"), str) or not item["id"]
            or not isinstance(event.get("turn_id"), str) or not event["turn_id"]):
        raise ValueError("unbound_user_source")
    return {"method": "item/completed", "params": {
        "threadId": session, "turnId": event["turn_id"], "item": {
            "type": "userMessage", "id": item["id"], "clientId": item.get("client_id"),
            "content": item.get("content")}}}


def bind(source, users, roots, row, text, session):
    """Full exact candidate matching, never a latest-root or fuzzy fallback."""
    trace = trace_module()
    if row["phase"] != "commentary":
        return None
    matches = []
    for root in roots:
        if (root.get("turn_id") != row["turn_id"] or not root.get("question_ids")
                or not isinstance(root.get("text"), str)):
            continue
        raw = root["text"]
        # The product validates both text hash and immutable record hash;
        # the latter also binds the root's turn and source metadata.
        if sum(r.get("text") == raw for r in roots) != 1:
            continue
        relevant = []
        for event in users:
            content = event["params"]["item"].get("content")
            if isinstance(content, list) and len(content) == 1 and isinstance(content[0], dict):
                part = dict(content[0])
                if part.get("text_elements") == []:
                    del part["text_elements"]
                if part == {"type": "text", "text": raw}:
                    relevant.append(event)
        relevant = {trace.canonical(event): event for event in relevant}
        if len(relevant) != 1:
            continue
        user = next(iter(relevant.values()))
        client = user["params"]["item"]["clientId"]
        if not isinstance(client, str) or not client:
            continue
        notification = {"method": "item/completed", "params": {
            "threadId": session, "turnId": row["turn_id"], "item": {
                "type": "agentMessage", "id": row["message_id"],
                "phase": "commentary", "text": text}}}
        try:
            result = trace.reduce_pair(
                [*users, *source["events"]], source["payloads"], thread=session,
                turn=row["turn_id"], client_id=client, question=raw, commentary=notification)
        except ValueError:
            continue
        pair = result["pair"]
        selected = [e for e in source["events"]
                    if e.get("payload", {}).get("inference_call_id") == pair["inference_call_id"]]
        selected_paths = {ref["path"] for e in selected for key in ("request_payload", "response_payload")
                          if isinstance(ref := e["payload"].get(key), dict)}
        proof = {"schema": "commentary-source-binding/v1", **pair,
                 "collector_sha256": source['collector_sha256'],
                 "root_record_sha256": root.get("record_sha256"),
                 "client_id": client, "user_sha256": hashlib.sha256(trace.canonical(user)).hexdigest(),
                 "trace_events_sha256": hashlib.sha256(trace.canonical(selected)).hexdigest(),
                 "manifest_sha256": source["hashes"]["manifest.json"],
                 "file_identities": {p: source["identities"][p]
                                     for p in sorted(selected_paths | {"manifest.json", "trace.jsonl"})},
                 "payload_hashes": {
                     ref["path"]: result["payload_hashes"][ref["path"]]
                     for e in selected for key in ("request_payload", "response_payload")
                     if isinstance(ref := e["payload"].get(key), dict)}}
        matches.append((root, proof))
    return matches[0] if len(matches) == 1 else None


def prior_progress(source, root, answer, earlier, text, session):
    """Prove a prior response was consumed before this exact new user input.

    This compares explicit model input lineage, never notification order or
    wall clocks. An incremental chain must have unique completed response IDs
    and a single causal child at every edge before it can exclude progress.
    """
    trace = trace_module()
    try:
        current, _, _ = trace.attempt_pair(
            source['events'], source['payloads'], kind='inference',
            call_id=answer['source_binding']['inference_call_id'], thread=session, turn=answer['turn_id'])
        inputs = current.get('input')
        if not isinstance(inputs, list):
            return None
        question = {'type': 'message', 'role': 'user',
                    'content': [{'type': 'input_text', 'text': root['text']}]}
        questions = [n for n, item in enumerate(inputs) if isinstance(item, dict)
                     and item.get('type') == question['type'] and item.get('role') == 'user'
                     and item.get('content') == question['content']]
        expected = {'type': 'message', 'role': 'assistant', 'id': earlier['message_id'],
                    'phase': 'commentary', 'content': [{'type': 'output_text', 'text': text}]}
        if current.get('previous_response_id') is not None:
            return _incremental_prior_progress(
                source, root, answer, earlier, expected, session, trace,
                answer['source_binding']['inference_call_id'], current,
            )
        positions = [n for n, item in enumerate(inputs) if _progress_output(item, expected)]
        if len(questions) != 1 or len(positions) != 1 or positions[0] >= questions[0]:
            return None
        calls = {e['payload'].get('inference_call_id') for e in source['events']
                 if e['payload'].get('type') == 'inference_completed'
                 and e.get('thread_id') == session and e.get('codex_turn_id') == earlier['turn_id']}
        proofs = []
        for call in calls:
            request, response, hashes = trace.attempt_pair(
                source['events'], source['payloads'], kind='inference', call_id=call,
                thread=session, turn=earlier['turn_id'])
            outputs = response.get('output_items', [])
            if not isinstance(outputs, list) or not any(_progress_output(x, expected) for x in outputs):
                continue
            prior = request.get('input')
            if (not isinstance(prior, list) or not prior or request.get('previous_response_id')
                    or len(prior) > positions[0] or inputs[:len(prior)] != prior
                    or sum(_progress_output(x, expected) for x in outputs) != 1):
                continue
            # Bind every explicit earlier input byte and the actual output,
            # plus the identity of the later consuming request. No root choice
            # is accepted from a caller or inferred from text similarity.
            proofs.append({'message_id': earlier['message_id'], 'inference_call_id': call,
                           'response_id': response['response_id'], 'payload_hashes': hashes,
                           'consuming_call_id': answer['source_binding']['inference_call_id']})
        return proofs[0] if len(proofs) == 1 else None
    except (ValueError, KeyError, TypeError):
        return None


def _progress_output(item, expected):
    if not isinstance(item, dict) or any(item.get(k) != v for k, v in expected.items()):
        return False
    extra = set(item) - set(expected)
    return not extra or (extra == {'internal_chat_message_metadata_passthrough'}
                         and isinstance(item['internal_chat_message_metadata_passthrough'], dict))


def _incremental_prior_progress(source, root, answer, earlier, expected,
                                session, trace, answer_call, answer_request):
    """Prove one prior message precedes the new question across response IDs."""
    events, payloads = source['events'], source['payloads']
    starts, completed, children = {}, {}, {}
    inference = [e for e in events if isinstance(e.get('payload', {}).get('type'), str)
                 and e['payload']['type'].startswith('inference_')]
    if len(inference) > 512:
        return None
    for event in inference:
        part = event['payload']
        kind, call = part.get('type'), part.get('inference_call_id')
        if not isinstance(call, str) or not call or type(event.get('seq')) is not int:
            return None
        if kind == 'inference_started':
            if call in starts:
                return None
            ref = part.get('request_payload')
            path = ref.get('path') if isinstance(ref, dict) else None
            if (not isinstance(path, str)
                    or not re.fullmatch(r'payloads/[1-9][0-9]{0,12}\.json', path)
                    or ref.get('kind') != {'type': 'inference_request'}
                    or ref.get('raw_payload_id') != 'raw_payload:' + path[9:-5]
                    or not isinstance(payloads.get(path), bytes)):
                return None
            request = trace.decode(payloads[path])
            if not isinstance(request, dict) or not isinstance(request.get('input'), list):
                return None
            previous = request.get('previous_response_id')
            if previous is not None:
                if not isinstance(previous, str) or not previous:
                    return None
                children.setdefault(previous, []).append(call)
            starts[call] = (event, request)
        elif kind == 'inference_completed':
            response_id = part.get('response_id')
            if not isinstance(response_id, str) or not response_id:
                return None
            completed.setdefault(response_id, []).append(event)
    question = {'type': 'message', 'role': 'user',
                'content': [{'type': 'input_text', 'text': root['text']}]}
    def is_question(item):
        return (isinstance(item, dict) and item.get('type') == 'message'
                and item.get('role') == 'user' and item.get('content') == question['content'])
    if sum(is_question(x) for x in answer_request['input']) != 1:
        return None
    answer_started = starts.get(answer_call)
    answer_response_id = answer['source_binding'].get('response_id')
    answer_done = completed.get(answer_response_id, [])
    if (answer_started is None or answer_started[1] != answer_request
            or len(answer_done) != 1
            or answer_done[0]['payload'].get('inference_call_id') != answer_call
            or not answer_started[0]['seq'] < answer_done[0]['seq']
            or any(e.get('rollout_id') != session or e.get('thread_id') != session
                   or e.get('codex_turn_id') != answer['turn_id']
                   for e in (answer_started[0], answer_done[0]))):
        return None
    chain, visited, matches = [], set(), []
    child_call, child_request = answer_call, answer_request
    previous = child_request.get('previous_response_id')
    while previous is not None:
        if (not isinstance(previous, str) or not previous or previous in visited
                or len(chain) >= 128 or len(completed.get(previous, [])) != 1
                or children.get(previous) != [child_call]):
            return None
        visited.add(previous)
        done = completed[previous][0]
        parent_call = done['payload'].get('inference_call_id')
        started = starts.get(parent_call)
        child_started = starts.get(child_call)
        if (started is None or child_started is None
                or any(e.get('rollout_id') != session or e.get('thread_id') != session
                       or e.get('codex_turn_id') != answer['turn_id']
                       for e in (done, started[0], child_started[0]))
                or not started[0]['seq'] < done['seq'] < child_started[0]['seq']):
            return None
        parent_request, response, hashes = trace.attempt_pair(
            events, payloads, kind='inference', call_id=parent_call,
            thread=session, turn=answer['turn_id'])
        if (parent_request != started[1]
                or response.get('response_id') != previous
                or not isinstance(response.get('output_items'), list)
                or any(is_question(x) for x in parent_request['input'])):
            return None
        count = sum(_progress_output(x, expected) for x in response['output_items'])
        if count:
            if count != 1 or earlier['turn_id'] != answer['turn_id']:
                return None
            matches.append((parent_call, previous, hashes))
        chain.append({'call_id': parent_call, 'response_id': previous,
                      'payload_hashes': hashes['payload_hashes']})
        child_call, child_request = parent_call, parent_request
        previous = parent_request.get('previous_response_id')
    if len(matches) != 1:
        return None
    call, response_id, hashes = matches[0]
    return {'message_id': earlier['message_id'], 'inference_call_id': call,
            'response_id': response_id, 'payload_hashes': hashes,
            'consuming_call_id': answer_call,
            'causal_hops': len(chain),
            'causal_chain_sha256': hashlib.sha256(trace.canonical(chain)).hexdigest()}
