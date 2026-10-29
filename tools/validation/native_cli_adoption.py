"""Explicit CLI 0.165 adoption; zero-turn protocol readiness is not acceptance.

Only tools consume this contract. Old plans without adoption keep their old
version rules. A receipt retains generated protocol and accepted read-only RPC
bytes so consumers recompute capability instead of trusting a passed boolean.
Startup notifications retain header projections only, never payload values or hashes.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

CONTRACT = 'codex-cli-0165/v1'
VERSION = 'codex-cli 0.165.0'
RECEIPT = 'native-cli-capability/v1'
SUBJECT = 'native-cli-capability-subject/v1'
ROOT = Path(__file__).resolve().parents[2]
IDENTITY_KEYS = ('codex', 'cli_sha256', 'cli_version', 'platform', 'home', 'cwd', 'plugin_root',
                 'runtime_sha256', 'source', 'shell', 'python', 'python_sha256', 'python_version')
SCHEMAS = ('ClientRequest.json', 'ServerNotification.json',
           'v1/InitializeResponse.json', 'v2/HooksListResponse.json',
           'v2/EnvironmentInfoResponse.json', 'v2/ThreadStartResponse.json',
           'v2/ThreadResumeResponse.json', 'v2/TurnStartResponse.json')
REQUESTS = {
    'initialize': ('clientInfo', 'capabilities'), 'hooks/list': ('cwds',),
    'environment/info': ('environmentId',),
    'thread/start': ('cwd', 'sandbox', 'approvalPolicy', 'model', 'developerInstructions'),
    'thread/resume': ('threadId', 'cwd', 'sandbox', 'approvalPolicy'),
    'turn/start': ('threadId', 'input', 'effort'),
    'thread/compact/start': ('threadId',),
}
STARTUP_METHOD = 'remoteControl/status/changed'
STARTUP_FIELDS = ('environmentId', 'installationId', 'serverName', 'status')
STARTUP_LIMIT = 8
PROJECTION_SCOPE = {
    'schema': 'capability-startup-header-projections/v1',
    'scope': 'validated_headers_only_not_raw_rpc',
    'payload_values_and_hashes': 'discarded_not_retained',
    'hook_or_model_evidence': False,
}
NOTIFICATIONS = {
    'hook/started': ('threadId', 'turnId', 'run'),
    'hook/completed': ('threadId', 'turnId', 'run'),
    'turn/started': ('threadId', 'turn'), 'turn/completed': ('threadId', 'turn'),
    'item/started': ('threadId', 'turnId', 'item'),
    'item/completed': ('threadId', 'turnId', 'item'),
    'thread/status/changed': ('threadId', 'status'),
}


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strict_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate capability field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def resolve(node, document):
    visited = set()
    while '$ref' in node:
        ref = node['$ref']
        require(ref.startswith('#/definitions/') and ref.count('/') == 2,
                'unsupported capability schema reference')
        require(ref not in visited, 'cyclic capability schema reference')
        visited.add(ref)
        node = document['definitions'][ref.rsplit('/', 1)[-1]]
    return node


def fields(node, document, names):
    node = resolve(node, document)
    require(isinstance(node, dict) and all(name in node.get('properties', {}) for name in names),
            'consumed protocol fields unavailable: ' + ','.join(names))
    return node


def method_schema(document, method):
    candidates = [node for node in document.get('oneOf', [])
                  if node.get('properties', {}).get('method', {}).get('enum') == [method]]
    require(len(candidates) == 1, 'consumed protocol method unavailable: ' + method)
    return candidates[0]


def variant(document, method):
    return method_schema(document, method)['properties']['params']


def accepts(value, node, document):
    """Bounded subset used by generated request/response schemas, not an oracle.

    In particular required nested fields, enums and union alternatives must
    accept the payload the existing collector actually sends. Presence of a
    similarly named method alone is insufficient.
    """
    node = resolve(node, document)
    if 'enum' in node and value not in node['enum']:
        return False
    for keyword in ('oneOf', 'anyOf', 'allOf'):
        if keyword in node:
            results = [accepts(value, option, document) for option in node[keyword]]
            if ((keyword == 'oneOf' and sum(results) != 1)
                    or (keyword == 'anyOf' and not any(results))
                    or (keyword == 'allOf' and not all(results))):
                return False
    types = {'string': isinstance(value, str), 'object': isinstance(value, dict),
             'array': isinstance(value, list), 'boolean': type(value) is bool,
             'integer': type(value) is int, 'number': type(value) in (int, float), 'null': value is None}
    if 'type' in node and not any(types.get(kind, False) for kind in
                                  (node['type'] if isinstance(node['type'], list) else [node['type']])):
        return False
    if isinstance(value, dict):
        props = node.get('properties', {})
        if not set(node.get('required', [])) <= set(value):
            return False
        if node.get('additionalProperties') is False and not set(value) <= set(props):
            return False
        if any(not accepts(item, props[key], document) for key, item in value.items() if key in props):
            return False
    if isinstance(value, list) and 'items' in node and any(not accepts(item, node['items'], document) for item in value):
        return False
    if isinstance(value, str) and (len(value) < node.get('minLength', 0)
                                 or len(value) > node.get('maxLength', len(value))):
        return False
    return True


def startup_projection(message, document, sequence):
    """Validate the one adopted startup family, then discard all parameter values.

    emittedAtMs is observed transport metadata, not a generated payload field.
    Neither it nor any remote identity/status value enters retained evidence.
    """
    require(type(sequence) is int and 1 <= sequence <= 3, 'capability waiting id differs')
    require(isinstance(message, dict) and set(message) in
            ({'method', 'params'}, {'method', 'params', 'emittedAtMs'})
            and message.get('method') == STARTUP_METHOD,
            'unexpected capability notification envelope')
    if 'emittedAtMs' in message:
        require(type(message['emittedAtMs']) is int and message['emittedAtMs'] >= 0,
                'invalid capability notification timestamp')
    params = message['params']
    require(isinstance(params, dict) and set(params) <= set(STARTUP_FIELDS)
            and accepts(message, method_schema(document, STARTUP_METHOD), document),
            'unsupported capability startup notification')
    return {'method': STARTUP_METHOD, 'top_level_keys': sorted(message),
            'params_fields': sorted(params), 'before_response_id': sequence}


def validate_projections(value, response_count):
    require(type(response_count) is int and response_count in (2, 3), 'capability response count differs')
    require(isinstance(value, dict) and set(value) == set(PROJECTION_SCOPE) | {'observations'}
            and all(value.get(k) == v for k, v in PROJECTION_SCOPE.items())
            and value['hook_or_model_evidence'] is False,
            'capability projection scope differs')
    rows = value['observations']
    require(isinstance(rows, list) and len(rows) <= STARTUP_LIMIT, 'capability notification limit')
    previous = 1
    for row in rows:
        require(isinstance(row, dict) and set(row) ==
                {'method', 'top_level_keys', 'params_fields', 'before_response_id'}
                and row['method'] == STARTUP_METHOD
                and row['top_level_keys'] in (['method', 'params'], ['emittedAtMs', 'method', 'params'])
                and row['params_fields'] in (['installationId', 'serverName', 'status'], list(STARTUP_FIELDS))
                and type(row['before_response_id']) is int
                and previous <= row['before_response_id'] <= response_count,
                'capability projection headers differ')
        previous = row['before_response_id']


def validate_initialize(result, document, home):
    require(isinstance(result, dict) and set(result) ==
            {'codexHome', 'userAgent', 'platformFamily', 'platformOs'}
            and accepts(result, document, document), 'initialize capability unavailable')
    require(isinstance(result['codexHome'], str) and Path(result['codexHome']).is_absolute()
            and Path(result['codexHome']).resolve() == Path(home).resolve(),
            'initialize capability HOME differs')


def validate_schemas(bundle):
    require(isinstance(bundle, dict) and set(bundle) == set(SCHEMAS)
            and all(isinstance(raw, str) for raw in bundle.values())
            and sum(len(raw.encode()) for raw in bundle.values()) < 8 * 1024 * 1024,
            'capability schema bundle differs')
    documents = {name: strict_json(raw) for name, raw in bundle.items()}
    for filename, methods in (('ClientRequest.json', REQUESTS),
                              ('ServerNotification.json', NOTIFICATIONS)):
        doc = documents[filename]
        for method, names in methods.items():
            fields(variant(doc, method), doc, names)
    request = documents['ClientRequest.json']
    samples = {
        'initialize': {'clientInfo': {'name': 'stop-host-acceptance', 'version': '1'}, 'capabilities': {'experimentalApi': True}},
        'hooks/list': {'cwds': ['/synthetic/workspace']}, 'environment/info': {'environmentId': 'local'},
        'thread/start': {'cwd': '/synthetic/workspace', 'sandbox': 'workspace-write', 'approvalPolicy': 'on-request',
                         'model': 'synthetic-model', 'developerInstructions': 'synthetic instructions'},
        'thread/resume': {'threadId': 'synthetic-thread', 'cwd': '/synthetic/workspace',
                          'sandbox': 'workspace-write', 'approvalPolicy': 'on-request'},
        'turn/start': {'threadId': 'synthetic-thread', 'input': [{'type': 'text', 'text': 'synthetic input'}], 'effort': 'medium'},
        'thread/compact/start': {'threadId': 'synthetic-thread'},
    }
    require(all(accepts(value, variant(request, method), request) for method, value in samples.items()),
            'actual collector request shape unsupported')
    turn = fields(variant(request, 'turn/start'), request, ('effort',))
    effort = resolve(turn['properties']['effort'], request)
    options = effort.get('anyOf', [effort])
    require(any(resolve(x, request).get('type') == 'string'
                and ('enum' not in resolve(x, request) or 'medium' in resolve(x, request)['enum'])
                and resolve(x, request).get('minLength', 0) <= len('medium') for x in options),
            'medium effort capability unavailable')
    notification = documents['ServerNotification.json']
    startup = fields(variant(notification, STARTUP_METHOD), notification, STARTUP_FIELDS)
    require(set(startup.get('properties', {})) == set(STARTUP_FIELDS)
            and set(startup.get('required', [])) == {'installationId', 'serverName', 'status'},
            'startup notification schema differs')
    init = documents['v1/InitializeResponse.json']
    require(set(init.get('properties', {})) == {'codexHome', 'userAgent', 'platformFamily', 'platformOs'}
            and set(init.get('required', [])) == set(init['properties']), 'initialize schema differs')
    run = resolve(variant(notification, 'hook/completed'), notification)['properties']['run']
    run = fields(run, notification, ('id', 'eventName', 'sourcePath', 'source', 'handlerType',
                                    'displayOrder', 'executionMode', 'status', 'durationMs', 'entries'))
    require({'completed', 'blocked'} <= set(resolve(run['properties']['status'], notification).get('enum', [])),
            'consumed Hook statuses unavailable')
    item = resolve(resolve(variant(notification, 'item/completed'), notification)['properties']['item'], notification)
    for kind, names in (('commandExecution', ('command', 'exitCode', 'aggregatedOutput', 'status')),
                        ('contextCompaction', ('id',))):
        choices = [x for x in item.get('oneOf', [])
                   if x.get('properties', {}).get('type', {}).get('enum') == [kind]]
        require(len(choices) == 1, 'consumed item capability unavailable')
        fields(choices[0], notification, names)
    for name in ('ThreadStartResponse', 'ThreadResumeResponse'):
        doc = documents['v2/' + name + '.json']
        fields(doc, doc, ('thread', 'model', 'approvalPolicy', 'sandbox'))
        fields(doc['properties']['thread'], doc, ('id',))
    doc = documents['v2/TurnStartResponse.json']
    fields(doc, doc, ('turn',))
    fields(doc['properties']['turn'], doc, ('id', 'status'))
    doc = documents['v2/HooksListResponse.json']
    fields(doc, doc, ('data',))
    metadata = fields(doc['definitions']['HookMetadata'], doc,
                      ('key', 'eventName', 'sourcePath', 'source', 'displayOrder',
                       'currentHash', 'trustStatus', 'enabled'))
    commands = [x for x in metadata.get('oneOf', [])
                if x.get('properties', {}).get('handlerType', {}).get('enum') == ['command']]
    require(len(commands) == 1, 'command Hook capability unavailable')
    fields(commands[0], doc, ('handlerType', 'command', 'async'))
    doc = documents['v2/EnvironmentInfoResponse.json']
    fields(doc, doc, ('shell',))
    fields(doc['properties']['shell'], doc, ('name', 'path'))
    return documents


def validate_receipt(receipt, subject):
    require(isinstance(receipt, dict) and set(receipt) ==
            {'schema', 'identity', 'schema_bundle', 'schema_sha256', 'rpc', 'rpc_sha256',
             'cleanup', 'producer_sha256', 'generator_returncode', 'stderr_sha256', 'app_server_returncode',
             'capability_directory', 'catalog_sha256', 'evidence_scope'},
            'closed capability receipt required')
    require(receipt['schema'] == RECEIPT and receipt['producer_sha256'] == sha(Path(__file__))
            and type(receipt['generator_returncode']) is int and receipt['generator_returncode'] == 0,
            'capability producer or generator differs')
    identity = receipt['identity']
    require(isinstance(identity, dict) and set(identity) == set(IDENTITY_KEYS), 'closed capability identity required')
    require(receipt['evidence_scope'] in ('native_zero_turn', 'synthetic'), 'capability scope unavailable')
    for key in IDENTITY_KEYS:
        require(identity.get(key) == subject.get(key), 'capability input differs: ' + key)
    require(identity.get('cli_version') == VERSION
            and isinstance(identity.get('cli_sha256'), str)
            and re.fullmatch(r'[0-9a-f]{64}', identity['cli_sha256']), 'capability CLI identity differs')
    documents = validate_schemas(receipt['schema_bundle'])
    require(receipt['schema_sha256'] == digest(receipt['schema_bundle'])
            and receipt['rpc_sha256'] == digest(receipt['rpc'])
            and re.fullmatch(r'[0-9a-f]{64}', receipt['stderr_sha256']), 'capability bytes changed')
    rpc = receipt['rpc']
    require(isinstance(rpc, list) and len(rpc) in (5, 7), 'capability RPC count differs')
    expected = [('initialize', {'clientInfo': {'name': 'stop-host-acceptance', 'version': '1'},
                                 'capabilities': {'experimentalApi': True}}),
                ('hooks/list', {'cwds': [subject['cwd']]})]
    if subject['platform'] == 'Windows':
        expected.append(('environment/info', {'environmentId': 'local'}))
    cursor = 0
    for sequence, (method, params) in enumerate(expected, 1):
        request = rpc[cursor]
        require(isinstance(request, dict) and isinstance(request.get('message'), dict)
                and type(request['message'].get('id')) is int
                and request == {'direction': 'request', 'message': {'id': sequence, 'method': method, 'params': params}},
                'capability request differs or invokes a thread/turn')
        response = rpc[cursor + 1]
        require(response.get('direction') == 'response'
                and set(response.get('message', {})) == {'id', 'result'}
                and type(response['message']['id']) is int and response['message']['id'] == sequence, 'capability response differs')
        result = response['message']['result']
        filename = {'initialize': 'v1/InitializeResponse.json', 'hooks/list': 'v2/HooksListResponse.json',
                    'environment/info': 'v2/EnvironmentInfoResponse.json'}[method]
        require(accepts(result, documents[filename], documents[filename]), 'read-only capability response shape unsupported')
        if method == 'initialize':
            validate_initialize(result, documents[filename], subject['home'])
        elif method == 'hooks/list':
            from tools.validation import stop_host_acceptance as base
            require(isinstance(result, dict) and set(result) == {'data'} and len(result['data']) == 1,
                    'Hook inventory capability unavailable')
            entry = result['data'][0]
            require(isinstance(entry, dict) and set(entry) <= {'cwd', 'errors', 'warnings', 'hooks'}
                    and not entry.get('errors') and not entry.get('warnings')
                    and isinstance(entry.get('hooks'), list), 'Hook inventory errors')
            hooks = entry['hooks']
            require(len(hooks) == 9 and {h.get('eventName') for h in hooks} == base.EVENTS,
                    'nine product Hook shapes required')
            for hook in hooks:
                require(hook.get('source') == 'plugin' and hook.get('handlerType') == 'command'
                        and Path(hook['sourcePath']).resolve() == Path(subject['plugin_root']) / 'hooks/hooks.json'
                        and isinstance(hook.get('key'), str) and hook['key']
                        and isinstance(hook.get('currentHash'), str) and hook['currentHash']
                        and type(hook.get('enabled')) is bool and type(hook.get('async', False)) is bool
                        and type(hook.get('displayOrder')) is int
                        and hook.get('trustStatus') in ('managed', 'untrusted', 'trusted', 'modified'),
                        'Hook inventory shape differs')
        else:
            require(isinstance(result, dict) and set(result) == {'shell'}
                    and result['shell'] == {k: subject['shell'][k] for k in ('name', 'path')},
                    'official shell capability differs')
        cursor += 2
        if method == 'initialize':
            require(rpc[cursor] == {'direction': 'request', 'message': {'method': 'initialized', 'params': {}}},
                    'initialized capability missing')
            cursor += 1
    require(cursor == len(rpc), 'extra capability RPC')
    cleanup = receipt['cleanup']
    require(isinstance(cleanup, dict) and set(cleanup) == {'owned_process_exited', 'process_group_kill_attempted',
            'process_group_cleanup_error', 'owned_tree_empty', 'owned_tree_no_running_members',
            'process_group_absent', 'process_group_signal_denied', 'process_group_query_denied', 'escaped_descendants'}
            and cleanup.get('owned_process_exited') is True
            and cleanup.get('owned_tree_no_running_members') is True
            and cleanup.get('process_group_cleanup_error') is None
            and cleanup.get('process_group_kill_attempted') is True
            and all(type(cleanup[key]) is bool for key in
                    ('owned_tree_empty', 'process_group_signal_denied', 'process_group_query_denied'))
            and (cleanup['process_group_absent'] is None or type(cleanup['process_group_absent']) is bool)
            and cleanup['escaped_descendants'] == 'not_established', 'capability owned cleanup incomplete')
    require(type(receipt['app_server_returncode']) is int, 'capability process return code unavailable')
    validate_artifacts(receipt)
    return receipt


def validate_artifacts(receipt):
    """Consume retained producer originals, never just embedded booleans."""
    directory = Path(receipt['capability_directory'])
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink()
            and ROOT not in directory.resolve().parents and directory.resolve() != ROOT,
            'private regular capability directory required')
    for parent in directory.parents:
        require(not parent.is_symlink(), 'linked capability directory ancestor')
    paths = list(directory.rglob('*'))
    require(len(paths) <= 4096 and all(not path.is_symlink() and (path.is_file() or path.is_dir())
            and not getattr(path.lstat(), 'st_file_attributes', 0) & 0x400 for path in paths),
            'linked or special capability artifact')
    files = {path.relative_to(directory).as_posix(): path for path in paths if path.is_file()}
    require(sum(path.stat().st_size for path in files.values()) <= 64 * 1024 * 1024,
            'capability artifact budget')
    required = {'rpc.jsonl', 'cleanup.json', 'commands.json', 'producer.py', 'version.stdout',
                'version.stderr', 'generator.stdout', 'generator.stderr', 'stderr.txt',
                'receipt.json', 'artifacts.json', 'notification-projections.json'} | {'protocol/' + name for name in SCHEMAS}
    require(required <= set(files) and all(name in required or name.startswith('protocol/')
            and name.endswith('.json') for name in files), 'capability artifact inventory differs')
    require(sha(files['artifacts.json']) == receipt['catalog_sha256'], 'capability catalog changed')
    catalog = strict_json(files['artifacts.json'].read_text(encoding='utf-8'))
    require(isinstance(catalog, dict) and set(catalog) == set(files) - {'artifacts.json', 'receipt.json'}
            and all(sha(files[name]) == value for name, value in catalog.items()),
            'capability artifact hash mismatch')
    validate_projections(strict_json(files['notification-projections.json'].read_text(encoding='utf-8')),
                         3 if receipt['identity']['platform'] == 'Windows' else 2)
    require(strict_json(files['receipt.json'].read_text(encoding='utf-8')) == receipt,
            'embedded capability receipt differs from original')
    require({name: files['protocol/' + name].read_text(encoding='utf-8') for name in SCHEMAS}
            == receipt['schema_bundle'], 'capability schema original differs')
    require([strict_json(line) for line in files['rpc.jsonl'].read_text(encoding='utf-8').splitlines()]
            == receipt['rpc'], 'capability RPC original differs')
    require(strict_json(files['cleanup.json'].read_text(encoding='utf-8')) ==
            {'cleanup': receipt['cleanup'], 'app_server_returncode': receipt['app_server_returncode']},
            'capability cleanup original differs')
    require(sha(files['producer.py']) == receipt['producer_sha256']
            and sha(files['stderr.txt']) == receipt['stderr_sha256'], 'capability producer/stderr original differs')
    commands = strict_json(files['commands.json'].read_text(encoding='utf-8'))
    cli = receipt['identity']['codex']
    require(commands == {
        'version': {'argv': [cli, '--version'], 'returncode': 0,
                    'stdout_sha256': sha(files['version.stdout']), 'stderr_sha256': sha(files['version.stderr'])},
        'generator': {'argv': [cli, 'app-server', 'generate-json-schema', '--experimental', '--out', str(directory / 'protocol')],
                      'returncode': receipt['generator_returncode'], 'stdout_sha256': sha(files['generator.stdout']),
                      'stderr_sha256': sha(files['generator.stderr'])},
        'app_server': {'argv': [cli, 'app-server'], 'returncode': receipt['app_server_returncode']}},
        'capability command originals differ')
    require(files['version.stdout'].read_text(encoding='utf-8').strip() == VERSION,
            'capability version original differs')


def validate(subject, *, legacy_versions, default=None, require_native=False):
    adoption = subject.get('cli_adoption')
    if adoption is None:
        require('cli_adoption' not in subject, 'null CLI adoption rejected')
        require(subject.get('cli_version', default) in legacy_versions, 'unsupported planned CLI version')
        return None
    require(isinstance(adoption, dict) and set(adoption) ==
            {'schema', 'cli_version', 'cli_sha256', 'capability_receipt_sha256', 'capability_receipt'}
            and adoption['schema'] == CONTRACT and adoption['cli_version'] == subject.get('cli_version') == VERSION
            and adoption['cli_sha256'] == subject.get('cli_sha256'), 'explicit CLI adoption differs')
    validate_receipt(adoption['capability_receipt'], subject)
    require(not require_native or adoption['capability_receipt']['evidence_scope'] == 'native_zero_turn',
            'synthetic capability cannot enter native execution')
    require(adoption['capability_receipt_sha256'] == digest(adoption['capability_receipt']),
            'capability receipt digest changed')
    return adoption


def adoption(receipt):
    return {'schema': CONTRACT, 'cli_version': VERSION,
            'cli_sha256': receipt['identity']['cli_sha256'],
            'capability_receipt_sha256': digest(receipt), 'capability_receipt': receipt}


def identity(subject):
    value = subject.get('cli_adoption')
    return None if value is None else {**{key: value[key] for key in
            ('schema', 'cli_version', 'cli_sha256', 'capability_receipt_sha256')},
            'capability_evidence_scope': value['capability_receipt']['evidence_scope']}


def validate_export(execution):
    value = execution.get('cli_adoption')
    if value is None:
        require('cli_adoption' not in execution and execution.get('cli_version') == 'codex-cli 0.160.0',
                'unsupported incident execution CLI version')
        return
    require(isinstance(value, dict) and set(value) ==
            {'schema', 'cli_version', 'cli_sha256', 'capability_receipt_sha256', 'capability_evidence_scope'}
            and value['schema'] == CONTRACT and value['cli_version'] == execution.get('cli_version') == VERSION
            and value['cli_sha256'] == execution.get('cli_sha256')
            and value['capability_evidence_scope'] in ('native_zero_turn', 'synthetic')
            and all(isinstance(value[k], str) and re.fullmatch(r'[0-9a-f]{64}', value[k])
                    for k in ('cli_sha256', 'capability_receipt_sha256')), 'CLI adoption export differs')


def probe(plan, output):
    """Generate protocol and read inventory with the existing owned Client.

    The independent subclass permits untrusted inventory only on this path.
    It cannot start/resume a thread, run a turn or compact. Unknown inbound
    messages are rejected before persistence; environment/info retains shell
    name/path only. No authentication material is inspected or copied.
    """
    from tools.validation import stop_host_acceptance as base
    from tools.validation.acceptance_identity import prepared_source_identity

    require(isinstance(plan, dict) and set(plan) == set(IDENTITY_KEYS) | {'schema', 'repo'}
            and plan['schema'] == SUBJECT and Path(plan['repo']).resolve() == ROOT,
            'closed capability subject required; this is not a native execution plan')
    require(not output.exists() and output.is_absolute() and ROOT not in output.parents,
            'fresh private capability output required')
    for key in ('codex', 'home', 'cwd', 'plugin_root'):
        path = Path(plan[key])
        require(path.is_absolute() and path.exists() and not path.is_symlink(),
                'regular capability input required: ' + key)
    require(Path(plan['codex']).is_file() and sha(Path(plan['codex'])) == plan['cli_sha256'],
            'capability CLI bytes/version differs')
    require(plan['cli_version'] == VERSION and plan['source'] == prepared_source_identity(ROOT)
            and plan['runtime_sha256'] == base.runtime(ROOT)
            and plan['platform'] == platform.system(), 'capability source/runtime/platform differs')
    python = Path(plan['python'])
    require(python.is_absolute() and python.is_file() and not python.is_symlink()
            and python.samefile(sys.executable) and sha(python) == plan['python_sha256']
            and subprocess.check_output([str(python), '--version'], text=True, timeout=20).strip() == plan['python_version'],
            'capability Python differs')
    home, cwd, plugin = (Path(plan[k]).resolve() for k in ('home', 'cwd', 'plugin_root'))
    require(home in plugin.parents and home != (Path.home() / '.codex').resolve()
            and home not in output.parents and cwd not in output.parents
            and cwd != ROOT and ROOT not in cwd.parents, 'isolated capability scope required')
    if plan['platform'] == 'Windows':
        shell = Path(plan['shell']['path'])
        require(shell.is_absolute() and shell.is_file() and not shell.is_symlink()
                and sha(shell) == plan['shell']['sha256'] and plan['shell']['name'] == 'powershell',
                'capability shell bytes differ')
    output.mkdir(mode=0o700, parents=True)
    version_argv = [plan['codex'], '--version']
    version = subprocess.run(version_argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=20, check=False,
                             env={**os.environ, 'CODEX_HOME': plan['home']})
    (output / 'version.stdout').write_bytes(version.stdout)
    (output / 'version.stderr').write_bytes(version.stderr)
    commands = {'version': {'argv': version_argv, 'returncode': version.returncode,
                            'stdout_sha256': sha(output / 'version.stdout'), 'stderr_sha256': sha(output / 'version.stderr')}}
    (output / 'commands.json').write_text(canonical(commands) + '\n', encoding='utf-8')
    require(version.returncode == 0 and version.stdout.decode('utf-8').strip() == VERSION,
            'capability CLI version probe failed')
    schema_dir = output / 'protocol'
    generator_argv = [plan['codex'], 'app-server', 'generate-json-schema', '--experimental', '--out', str(schema_dir)]
    generator = subprocess.run(generator_argv, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45,
                               env={**os.environ, 'CODEX_HOME': plan['home']}, check=False)
    (output / 'generator.stdout').write_bytes(generator.stdout)
    (output / 'generator.stderr').write_bytes(generator.stderr)
    commands['generator'] = {'argv': generator_argv, 'returncode': generator.returncode,
                              'stdout_sha256': sha(output / 'generator.stdout'), 'stderr_sha256': sha(output / 'generator.stderr')}
    (output / 'commands.json').write_text(canonical(commands) + '\n', encoding='utf-8')
    require(generator.returncode == 0, 'protocol generation failed')
    bundle = {}
    for name in SCHEMAS:
        path = schema_dir / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size < 2 * 1024 * 1024,
                'protocol schema input unavailable')
        bundle[name] = path.read_text(encoding='utf-8')
    documents = validate_schemas(bundle)

    cleanup, app_server_returncode = None, None
    projections = {**PROJECTION_SCOPE, 'observations': []}
    def retain_projection_headers():
        (output / 'notification-projections.json').write_text(canonical(projections) + '\n', encoding='utf-8')
    retain_projection_headers()

    class InventoryClient(base.Client):
        def validate_inventory(self, product, expected_path):
            # Read-only structural inventory. Normal Client retains its exact
            # nine enabled/trusted assertion in its default implementation.
            return None

        def rpc(self, method, params):
            require(method in ('initialize', 'hooks/list', 'environment/info'),
                    'capability cannot start/resume a thread or turn')
            require(type(self.sequence) is int and self.sequence >= 0, 'capability sequence differs')
            self.capability_method = method
            return super().rpc(method, params)

        def send(self, message):
            require(type(self.sequence) is int and self.sequence >= 1, 'capability waiting id differs')
            if 'id' in message:
                require(type(message['id']) is int and message['id'] == self.sequence,
                        'capability outgoing id differs')
            else:
                require(message == {'method': 'initialized', 'params': {}},
                        'capability outgoing notification differs')
            return super().send(message)

        def reader(self):
            # Preserve duplicate-field rejection before projection or persistence.
            try:
                for line in self.owned.process.stdout:
                    require(len(line) <= 2 * 1024 * 1024, 'oversized RPC line')
                    self.q.put(strict_json(line), timeout=1)
            except Exception as exc:
                self.q.put({'reader_error': type(exc).__name__})

        def receive(self, deadline):
            require(type(self.sequence) is int and self.sequence >= 1, 'capability waiting id differs')
            while True:
                require(time.monotonic() < deadline, 'capability response deadline')
                message = self.q.get(timeout=max(.01, deadline - time.monotonic()))
                require(time.monotonic() < deadline, 'capability response deadline')
                if isinstance(message, dict) and 'method' in message:
                    require(len(projections['observations']) < STARTUP_LIMIT, 'capability notification limit')
                    header = startup_projection(message, documents['ServerNotification.json'], self.sequence)
                    projections['observations'].append(header)
                    retain_projection_headers()
                    del message
                    continue
                break
            require(isinstance(message, dict) and set(message) == {'id', 'result'}
                    and type(message['id']) is int and message['id'] == self.sequence, 'unexpected capability message')
            method = self.capability_method
            filename = {'initialize': 'v1/InitializeResponse.json', 'hooks/list': 'v2/HooksListResponse.json',
                        'environment/info': 'v2/EnvironmentInfoResponse.json'}[method]
            result = message['result']
            require(isinstance(result, dict) and set(result) <= set(documents[filename].get('properties', {})),
                    'unknown capability response fields')
            if method == 'initialize':
                validate_initialize(result, documents[filename], plan['home'])
            elif method == 'environment/info':
                require(isinstance(result.get('shell'), dict) and set(result['shell']) == {'name', 'path'},
                        'unknown shell capability fields')
                message = {'id': message['id'], 'result': {'shell': result['shell']}}
            elif method == 'hooks/list':
                metadata = documents[filename]['definitions']['HookMetadata']
                allowed = set(metadata['properties']) | {k for x in metadata['oneOf'] for k in x.get('properties', {})}
                require(isinstance(result.get('data'), list) and all(isinstance(row, dict)
                        and set(row) <= {'cwd', 'errors', 'warnings', 'hooks'}
                        and isinstance(row.get('hooks'), list)
                        and all(isinstance(hook, dict) and set(hook) <= allowed for hook in row['hooks'])
                        for row in result['data']), 'unknown inventory fields')
                require(len(result['data']) == 1 and not result['data'][0].get('errors')
                        and not result['data'][0].get('warnings')
                        and len(result['data'][0]['hooks']) == 9
                        and {hook.get('eventName') for hook in result['data'][0]['hooks']} == base.EVENTS
                        and all(hook.get('source') == 'plugin'
                                and Path(hook.get('sourcePath', '')).resolve() == plugin / 'hooks/hooks.json'
                                for hook in result['data'][0]['hooks']), 'unrelated inventory cannot enter capability journal')
            self.rows.append(message)
            self.log.write(json.dumps({'direction': 'response', 'message': message}) + '\n')
            self.log.flush()
            return message

        def start(self, *args, **kwargs):
            raise ValueError('capability cannot start a thread')

        def turn(self, *args, **kwargs):
            raise ValueError('capability cannot start a turn')

        def compact(self, *args, **kwargs):
            raise ValueError('capability cannot compact')

        def close(self):
            nonlocal cleanup, app_server_returncode
            cleanup = super().close()
            app_server_returncode = self.owned.process.poll() if self.owned else None
            return cleanup

    client = None
    try:
        client = InventoryClient(plan, output)
        if plan['platform'] == 'Windows':
            client.rpc('environment/info', {'environmentId': 'local'})
    finally:
        if client:
            client.close()
        if cleanup is not None:
            (output / 'cleanup.json').write_text(canonical({'cleanup': cleanup, 'app_server_returncode': app_server_returncode}) + '\n', encoding='utf-8')
    require(sha(Path(plan['codex'])) == plan['cli_sha256']
            and sha(python) == plan['python_sha256']
            and prepared_source_identity(ROOT) == plan['source']
            and base.runtime(ROOT) == plan['runtime_sha256'], 'input changed during capability probe')
    if plan['platform'] == 'Windows':
        require(sha(Path(plan['shell']['path'])) == plan['shell']['sha256'], 'shell changed during capability probe')
    rpc = [strict_json(line) for line in (output / 'rpc.jsonl').read_text(encoding='utf-8').splitlines()]
    commands['app_server'] = {'argv': [plan['codex'], 'app-server'], 'returncode': app_server_returncode}
    (output / 'commands.json').write_text(canonical(commands) + '\n', encoding='utf-8')
    (output / 'producer.py').write_bytes(Path(__file__).read_bytes())
    catalog = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob('*') if p.is_file()}
    (output / 'artifacts.json').write_text(canonical(catalog) + '\n', encoding='utf-8')
    receipt = {'schema': RECEIPT, 'identity': {key: plan.get(key) for key in
               ('codex', 'cli_sha256', 'cli_version', 'platform', 'home', 'cwd', 'plugin_root',
                'runtime_sha256', 'source', 'shell', 'python', 'python_sha256', 'python_version')}, 'schema_bundle': bundle,
               'schema_sha256': digest(bundle), 'rpc': rpc, 'rpc_sha256': digest(rpc),
               'cleanup': cleanup, 'producer_sha256': sha(Path(__file__)),
               'generator_returncode': generator.returncode, 'stderr_sha256': sha(output / 'stderr.txt'),
               'app_server_returncode': app_server_returncode, 'capability_directory': str(output),
               'catalog_sha256': sha(output / 'artifacts.json'), 'evidence_scope': 'native_zero_turn'}
    (output / 'receipt.json').write_text(canonical(receipt) + '\n', encoding='utf-8')
    validate_receipt(receipt, plan)
    return receipt


def main():
    import argparse

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subject', type=Path, required=True,
                        help='native-cli-capability-subject/v1 with exact CLI/source/runtime/HOME/workspace/Python/shell identities; not a host plan')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(args.subject.is_file() and not args.subject.is_symlink()
                and args.subject.stat().st_size < 16 * 1024 * 1024, 'regular bounded capability subject required')
        probe(strict_json(args.subject.read_text(encoding='utf-8')), args.output)
        print('cli_capability=ready; thread_requests=0; native_acceptance=not_run')
        return 0
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, subprocess.SubprocessError):
        print('cli_capability=failed; native_acceptance=not_run', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
