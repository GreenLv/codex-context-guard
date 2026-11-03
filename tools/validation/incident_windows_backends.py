"""Configuration and journal bindings for split Windows native acceptance.

The receipt is a configuration/readiness observation, not proof of the backend
that executed any particular command.  Actual sandbox behavior and actor
identity require separate native witnesses.  No model or login is requested.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

CONTRACT = {
    'schema': 'incident-windows-backends/v1',
    'roles': {'primary': 'mxc', 'acl': 'elevated',
              'stop_first': 'mxc', 'stop_cold': 'mxc'},
}
OFFICIAL_CONTRACT = {**CONTRACT, 'schema': 'incident-windows-backends/v3',
                     'model_provider': 'openai', 'compaction': 'one-explicit-stop/v1'}
OFFICIAL_MODEL = 'gpt-6.1-sol'
_OFFICIAL_ENV_OVERRIDES = (
    'OPENAI_API_KEY', 'CODEX_API_KEY', 'CODEX_ACCESS_TOKEN', 'OPENAI_BASE_URL',
    'CODEX_OPENAI_BASE_URL', 'CODEX_CHATGPT_BASE_URL', 'CHATGPT_BASE_URL',
)
_BINDING_SCHEMA = 'incident-windows-backend-binding/v1'
_METHODS = ('config/read', 'windowsSandbox/readiness')


def _require(condition, message):
    if not condition:
        raise ValueError(message)


class CompactionLimitError(ValueError):
    def __init__(self, reason, record):
        super().__init__(reason)
        self.record = record


class CompactionBudget:
    """Count distinct actual items at start; only the planned Stop may compact."""

    def __init__(self, role):
        self.role = role
        self.explicit_thread = None
        self.items = {}
        self.automatic_items = set()
        self.fault = None

    def summary(self):
        return {'role': self.role, 'actual_items': len(self.items),
                'completed_items': sum('item/completed' in phases for phases in self.items.values()),
                'unplanned_items': len(self.automatic_items),
                'explicit_requests': int(self.explicit_thread is not None)}

    def fail(self, reason):
        self.fault = CompactionLimitError(reason, self.summary())
        raise self.fault

    def check(self):
        if self.fault:
            raise self.fault

    def request(self, thread):
        self.check()
        if self.role != 'stop_first' or self.explicit_thread is not None or self.items:
            self.fail('explicit compaction exceeds the plan')
        _require(isinstance(thread, str) and bool(thread), 'compact thread unavailable')
        self.explicit_thread = thread

    def observe(self, message):
        self.check()
        method = message.get('method')
        if method not in ('item/started', 'item/completed'):
            return
        params = message.get('params', {})
        item = params.get('item', {})
        if item.get('type') != 'contextCompaction':
            return
        key = (params.get('threadId'), params.get('turnId'), item.get('id'))
        if not all(isinstance(part, str) and part for part in key):
            self.fail('compaction event identity unavailable')
        phases = self.items.setdefault(key, set())
        prior = set(phases)
        phases.add(method)
        if key[0] != self.explicit_thread or len(self.items) > 1:
            self.automatic_items.add(key)
        if len(self.items) > 1:
            self.fail('actual compaction exceeds the plan')
        if key[0] != self.explicit_thread:
            # Reserve the single allowed compaction for the recovery scenario.
            self.fail('unplanned automatic compaction started')
        if ((method == 'item/started' and prior)
                or (method == 'item/completed' and prior != {'item/started'})):
            self.fail('compaction lifecycle differs')

    def verify_terminal(self):
        self.check()
        expected = int(self.explicit_thread is not None)
        summary = self.summary()
        _require(summary['actual_items'] == summary['completed_items'] == expected,
                 'actual compaction lifecycle incomplete')


def replay_compactions(rows, role):
    budget = CompactionBudget(role)
    for row in rows:
        message = row['message']
        if row['direction'] == 'response':
            budget.observe(message)
        elif message.get('method') == 'thread/compact/start':
            budget.request(message['params']['threadId'])
    budget.verify_terminal()


def model_provider(plan):
    if plan.get('backend_contract') == OFFICIAL_CONTRACT:
        _require(plan.get('model') == OFFICIAL_MODEL and plan.get('effort') == 'medium'
                 and 'local_provider_endpoint' not in plan, 'official GPT plan differs')
        return 'openai'
    _require(plan.get('backend_contract', CONTRACT) == CONTRACT, 'unknown backend contract')
    return 'local_ollama'


def launch_flags(backend, plan=None):
    """Return fixed app-server CLI overrides, never an unsandboxed profile."""
    _require(type(backend) is str and backend in ('mxc', 'elevated'),
             'unknown Windows sandbox backend')
    flags = ['-c', f'windows.sandbox="{backend}"', '-c', 'features.prefer_mxc=false']
    if model_provider(plan or {}) == 'openai':
        flags += ['-c', 'model_provider="openai"', '-c', f'model="{OFFICIAL_MODEL}"',
                  '-c', 'features.code_mode=false', '-c', 'features.code_mode_only=false']
    return flags


def check_launch_environment(plan):
    if model_provider(plan) == 'openai':
        _require(not any(os.environ.get(key) for key in _OFFICIAL_ENV_OVERRIDES),
                 'official GPT environment override refused')


def launch_subject(plan):
    if model_provider(plan) == 'openai':
        return {'model_provider': 'openai', 'model': OFFICIAL_MODEL, 'effort': 'medium'}
    return {'local_provider_endpoint': plan['local_provider_endpoint']}


def validate_local_endpoint(value):
    _require(isinstance(value, str) and value and value == value.strip(),
             'local model endpoint unavailable')
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError('invalid local model endpoint') from exc
    _require(parsed.scheme == 'http' and parsed.hostname in ('localhost', '127.0.0.1', '::1')
             and port is not None and 0 < port <= 65535 and parsed.username is None
             and parsed.password is None and not parsed.query and not parsed.fragment,
             'model endpoint is not an uncredentialed loopback URL')
    return value


def project_config(result, plan=None):
    """Keep only non-secret fields needed to bind the selected configuration.

    This is a *projection* of config/read, not its complete original response.
    Only the provider selected by the frozen plan is accepted.
    """
    _require(isinstance(result, dict) and isinstance(result.get('config'), dict),
             'config/read response unavailable')
    config = result['config']
    windows, features = config.get('windows'), config.get('features')
    _require(isinstance(windows, dict) and isinstance(features, dict),
             'sandbox configuration unavailable')
    provider_id = model_provider(plan or {})
    _require(config.get('model_provider') == provider_id, 'model provider differs')
    model = config.get('model')
    _require(isinstance(model, str) and bool(model), 'configured model unavailable')
    providers = config.get('model_providers')
    mode, prefer = windows.get('sandbox'), features.get('prefer_mxc')
    _require(type(mode) is str and mode in ('mxc', 'elevated') and prefer is False,
             'sandbox configuration differs')
    projection = {'windows': {'sandbox': mode}, 'features': {'prefer_mxc': False},
                  'model': model, 'model_provider': provider_id}
    if provider_id == 'openai':
        _require(model == OFFICIAL_MODEL
                 and isinstance(providers, dict) and 'openai' not in providers
                 and config.get('openai_base_url') in (None, 'https://api.openai.com/v1')
                 and config.get('chatgpt_base_url') in (
                     None, 'https://chatgpt.com/backend-api', 'https://chatgpt.com/backend-api/')
                 and config.get('model_catalog_json') is None
                 and config.get('forced_login_method') in (None, 'chatgpt')
                 and all(features.get(key) is False for key in ('code_mode', 'code_mode_only')),
                 'official GPT provider or ordinary tool configuration differs')
        projection['features'].update(code_mode=False, code_mode_only=False)
        projection['model_providers'] = {}
        return {'config': projection}
    _require(isinstance(providers, dict) and isinstance(providers.get('local_ollama'), dict),
             'local provider configuration unavailable')
    provider = providers['local_ollama']
    for key in ('auth', 'aws', 'gateway_oauth', 'env_key', 'env_key_instructions',
                'experimental_bearer_token', 'http_headers', 'env_http_headers',
                'query_params', 'model_catalog_url', 'credential_file'):
        _require(provider.get(key) in (None, '', {}, []), 'provider contains forbidden fields')
    websocket_setting = provider.get('supports_websockets')
    _require(provider.get('wire_api') == 'responses'
             and provider.get('requires_openai_auth') is False
             and (websocket_setting is None or websocket_setting is False),
             'local provider protocol or authentication differs')
    endpoint = validate_local_endpoint(provider.get('base_url'))
    _require(urlsplit(endpoint).path == '/v1', 'local provider endpoint path differs')
    projection['model_providers'] = {'local_ollama': {
        'base_url': endpoint, 'wire_api': 'responses', 'requires_openai_auth': False}}
    return {'config': projection}


def _config(result, backend, plan):
    launch_flags(backend, plan)
    config = project_config(result, plan)['config']
    windows, features = config.get('windows'), config.get('features')
    _require(isinstance(windows, dict) and windows.get('sandbox') == backend,
             'configured Windows sandbox differs')
    _require(isinstance(features, dict) and features.get('prefer_mxc') is False,
             'prefer_mxc is not explicitly false')
    _require(config['model'] == plan.get('model'), 'model differs from plan')
    if model_provider(plan) == 'local_ollama':
        _require(config['model_providers']['local_ollama']['base_url'] ==
                 validate_local_endpoint(plan.get('local_provider_endpoint')),
                 'local endpoint differs from plan')


def _receipt(config, readiness, backend, plan):
    _config(config, backend, plan)
    _require(isinstance(readiness, dict) and readiness.get('status') == 'ready',
             'Windows sandbox readiness unavailable')
    return {'schema': _BINDING_SCHEMA, 'backend': backend,
            'windows_sandbox': backend, 'prefer_mxc': False,
            'readiness': 'ready', 'model_provider': model_provider(plan)}


def bind(client, backend):
    """Read configuration/readiness on an already owned app-server, without turns.

    The client must inherit this process environment unchanged.  In 0.165,
    readiness can trigger registered-Core refresh when the startup flag is 1;
    refuse that context rather than changing the flag or allowing a refresh.
    """
    launch_flags(backend)
    _require(os.environ.get('CODEX_WINDOWS_REGISTERED_CORE') != '1',
             'registered Core readiness may refresh setup')
    plan = client.plan
    _require(isinstance(plan, dict) and isinstance(plan.get('cwd'), str),
             'planned working directory unavailable')
    config = client.rpc('config/read', {'cwd': plan['cwd'], 'includeLayers': False})
    _config(config, backend, plan)
    readiness = client.rpc('windowsSandbox/readiness', None)
    return _receipt(config, readiness, backend, plan)


def validate_thread_result(result, plan):
    """Validate official start/resume response; this does not identify a backend."""
    _require(isinstance(plan, dict) and isinstance(plan.get('model'), str)
             and bool(plan['model']), 'planned model unavailable')
    _require(isinstance(result, dict) and result.get('model') == plan['model']
             and result.get('modelProvider') == model_provider(plan)
             and result.get('cwd') == plan.get('cwd')
             and result.get('approvalPolicy') == 'on-request'
             and isinstance(result.get('sandbox'), dict)
             and result['sandbox'].get('type') == 'workspaceWrite'
             and isinstance(result.get('thread'), dict)
             and isinstance(result['thread'].get('id'), str)
             and bool(result['thread']['id']), 'thread result differs from plan')


def _pairs(items):
    value = {}
    for key, item in items:
        _require(key not in value, 'duplicate JSON field in RPC journal')
        value[key] = item
    return value


def verify_journal(path, backend, plan):
    """Replay binding and thread RPCs from original direction/message envelopes.

    Journals prove official observations only, not launch flags, process
    environment, backend implementation, provider endpoint, or model execution.
    The caller independently binds those facts and preserves the raw journal.
    """
    launch_flags(backend)
    path = Path(path)
    _require(not path.is_symlink() and path.is_file()
             and path.stat().st_size <= 128 * 1024 * 1024, 'RPC journal unavailable')
    _require(isinstance(plan, dict) and isinstance(plan.get('cwd'), str),
             'planned working directory unavailable')
    rows = []
    pending = {}
    seen_ids = set()
    completed_ids = set()
    bindings = {}
    threads = set()
    selected = set(_METHODS) | {'thread/start', 'thread/resume', 'turn/start', 'thread/compact/start'}
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            _require(len(rows) < 100000 and len(line) <= 2 * 1024 * 1024,
                     'RPC journal exceeds bounds')
            row = json.loads(line, object_pairs_hook=_pairs)
            _require(isinstance(row, dict) and set(row) == {'direction', 'message'}
                     and row['direction'] in ('request', 'response')
                     and isinstance(row['message'], dict), 'invalid RPC envelope')
            rows.append(row)
            msg, direction = row['message'], row['direction']
            _require(not (direction == 'response' and 'id' in msg and 'method' in msg),
                     'server request or approval is not allowed')
            _require(not (direction == 'response' and msg.get('id') in completed_ids),
                     'duplicate selected RPC response')
            if direction == 'request' and 'id' in msg:
                request_id, method = msg['id'], msg.get('method')
                _require(type(request_id) in (int, str) and request_id not in seen_ids,
                         'duplicate or invalid request id')
                seen_ids.add(request_id)
                _require(not (isinstance(method, str) and
                              (method.startswith('thread/') or method.startswith('turn/'))
                              and method not in selected),
                         'unsupported model thread RPC')
                if method in selected:
                    params = msg.get('params')
                    if method == 'config/read':
                        _require(params == {'cwd': plan['cwd'], 'includeLayers': False}
                                 and method not in bindings, 'config/read subject differs')
                    elif method == 'windowsSandbox/readiness':
                        _require(params is None and 'config/read' in bindings
                                 and method not in bindings, 'readiness subject differs')
                    elif method in ('thread/start', 'thread/resume'):
                        _require(all(key in bindings for key in _METHODS)
                                 and isinstance(params, dict) and 'config' not in params
                                 and params.get('cwd') == plan['cwd']
                                 and params.get('sandbox') == 'workspace-write'
                                 and params.get('approvalPolicy') == 'on-request',
                                 'thread request differs from plan')
                        if method == 'thread/start':
                            _require(set(params) == {'cwd', 'sandbox', 'approvalPolicy',
                                                     'model', 'developerInstructions'}
                                     and params.get('model') == plan.get('model'),
                                     'thread model differs from plan')
                        else:
                            _require(set(params) == {'threadId', 'cwd', 'sandbox', 'approvalPolicy'}
                                     and isinstance(params.get('threadId'), str)
                                     and bool(params['threadId']), 'resume thread unavailable')
                    else:
                        _require(all(key in bindings for key in _METHODS)
                                 and isinstance(params, dict)
                                 and params.get('threadId') in threads,
                                 'model request is not bound to an observed thread')
                        if method == 'turn/start':
                            _require(set(params) == {'threadId', 'input', 'effort'}
                                     and params['effort'] == 'medium'
                                     and isinstance(params['input'], list),
                                     'turn overrides or effort differ')
                        else:
                            _require(set(params) == {'threadId'},
                                     'compaction request differs')
                    pending[request_id] = (method, params)
            elif direction == 'response' and 'id' in msg and msg['id'] in pending:
                method, params = pending.pop(msg['id'])
                completed_ids.add(msg['id'])
                _require('error' not in msg and isinstance(msg.get('result'), dict),
                         'RPC failed or has no result')
                if method in _METHODS:
                    _require(method not in bindings, 'duplicate binding response')
                    bindings[method] = msg['result']
                elif method in ('thread/start', 'thread/resume'):
                    validate_thread_result(msg['result'], plan)
                    thread = msg['result']['thread']['id']
                    if method == 'thread/resume':
                        _require(thread == params['threadId'], 'resumed thread differs')
                    else:
                        _require(thread not in threads, 'duplicate started thread')
                    threads.add(thread)
    _require(not pending and all(method in bindings for method in _METHODS),
             'incomplete binding or thread RPC')
    return _receipt(bindings['config/read'], bindings['windowsSandbox/readiness'], backend, plan), rows
