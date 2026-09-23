"""Synthetic official-shaped source files; never native provenance evidence."""
import json
import os
from unittest import mock


def prepare(product):
    host = product.host
    question = product.state['requirements'][-1]
    metadata = next(p for p in product.state['prompts'] if p['id'] == question['prompt_id'])
    from tests.test_answer_review import cg
    prompt = cg.read_prompt_record(product.directory, metadata)['text']
    answer = host.rows[-1]['payload']['item']
    user = {'type': 'event_msg', 'payload': {
        'type': 'item_completed', 'thread_id': host.session_id, 'turn_id': host.turn_id,
        'item': {'type': 'UserMessage', 'id': 'user1', 'client_id': 'client1',
                 'content': [{'type': 'text', 'text': prompt, 'text_elements': []}]}}}
    host.rows.insert(-1, user)
    host.write_rows()
    root = host.root / 'official-trace'
    bundle = root / ('trace-fixture-' + host.session_id)
    (bundle / 'payloads').mkdir(parents=True)
    manifest = {'schema_version': 1, 'trace_id': 'fixture', 'rollout_id': host.session_id,
                'root_thread_id': host.session_id, 'started_at_unix_ms': 1,
                'raw_event_log': 'trace.jsonl', 'payloads_dir': 'payloads'}
    (bundle / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    request = {'input': [{'type': 'message', 'role': 'user',
                         'content': [{'type': 'input_text', 'text': prompt}]}]}
    response = {'response_id': 'answer-response', 'output_items': [{
        'type': 'message', 'role': 'assistant', 'id': answer['id'], 'phase': 'commentary',
        'content': [{'type': 'output_text', 'text': ''.join(c['text'] for c in answer['content'])}]}]}
    def ref(n, kind):
        return {'raw_payload_id': 'raw_payload:' + str(n), 'kind': {'type': kind},
                'path': f'payloads/{n}.json'}
    payloads = [
        {'type': 'rollout_started', 'trace_id': 'fixture', 'root_thread_id': host.session_id},
        {'type': 'inference_started', 'inference_call_id': 'answer-attempt',
         'thread_id': host.session_id, 'codex_turn_id': host.turn_id,
         'request_payload': ref(1, 'inference_request')},
        {'type': 'inference_completed', 'inference_call_id': 'answer-attempt',
         'response_id': 'answer-response', 'response_payload': ref(2, 'inference_response')}]
    rows = [{'schema_version': 1, 'seq': n, 'rollout_id': host.session_id,
             'thread_id': host.session_id, 'codex_turn_id': host.turn_id, 'payload': p}
            for n, p in enumerate(payloads, 1)]
    (bundle / 'trace.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')
    for n, payload in enumerate((request, response), 1):
        (bundle / f'payloads/{n}.json').write_text(json.dumps(payload), encoding='utf-8')
    patch = mock.patch.dict(os.environ, CODEX_ROLLOUT_TRACE_ROOT=str(root))
    patch.start()
    product.addCleanup(patch.stop)
    product.trace_bundle = bundle


def add_progress(product):
    """Actual response bytes included in the later model request, before user input."""
    host, bundle = product.host, product.trace_bundle
    main = {'type': 'message', 'role': 'user', 'content': [
        {'type': 'input_text', 'text': '请运行 /work/suite.py 的测试并持续执行直到完成。'}]}
    progress = {'type': 'message', 'role': 'assistant', 'id': 'main-progress', 'phase': 'commentary',
                'content': [{'type': 'output_text', 'text': 'I will run the test suite.'}]}
    host.rows.insert(-2, {'type': 'event_msg', 'payload': {
        'type': 'item_completed', 'thread_id': host.session_id, 'turn_id': host.turn_id,
        'started_at_ms': 0, 'completed_at_ms': 0,
        'item': {'type': 'AgentMessage', 'id': progress['id'], 'phase': 'commentary',
                 'content': [{'type': 'Text', 'text': progress['content'][0]['text']}]}}})
    host.write_rows()
    question_path = bundle / 'payloads/1.json'
    question = json.loads(question_path.read_text())
    question['input'] = [main, progress, *question['input']]
    question_path.write_text(json.dumps(question), encoding='utf-8')
    (bundle / 'payloads/3.json').write_text(json.dumps({'input': [main]}), encoding='utf-8')
    (bundle / 'payloads/4.json').write_text(json.dumps({
        'response_id': 'main-response', 'output_items': [progress]}), encoding='utf-8')
    path = bundle / 'trace.jsonl'
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    import copy
    old = copy.deepcopy(rows[1:])
    for row, n, field in zip(old, (3, 4), ('request_payload', 'response_payload')):
        row['payload']['inference_call_id'] = 'main-attempt'
        ref = row['payload'][field]
        ref.update(raw_payload_id=f'raw_payload:{n}', path=f'payloads/{n}.json')
        if field == 'response_payload':
            row['payload']['response_id'] = 'main-response'
    rows = [rows[0], *old, *rows[1:]]
    for n, row in enumerate(rows, 1):
        row['seq'] = n
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')


def prepare_with_progress(product):
    prepare(product)
    add_progress(product)
