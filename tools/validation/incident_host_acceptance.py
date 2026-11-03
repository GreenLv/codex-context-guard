"""Versioned incident host acceptance with explicit model execution.

No authentication, installation, trust changes, permissions escalation or
approval responses. Prepared isolated HOME must already have nine trusted
Hooks. Missing observations stay pending. All captures are private; export
contains only gate IDs, statuses and immutable execution/mapping identities.

The Windows split full profile binds MXC status and Stop processes and an
independent elevated ACL process. Its run requires a separate zero-turn
preflight against the same plan and retains four process journals.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts import context_guard as cg  # noqa: E402
from tools.validation import incident_readonly_child as child  # noqa: E402
from tools.validation import incident_windows_backends as windows_backends  # noqa: E402
from tools.validation import native_cli_adoption as cli_adoption  # noqa: E402
from tools.validation import native_code_mode_command as code_mode  # noqa: E402
from tools.validation import stop_host_acceptance as base  # noqa: E402
from tools.validation.acceptance_identity import prepared_source_identity  # noqa: E402

PROFILE = 'incident_host/v1'
PROFILE_CODE = 'incident_host/v1-code-mode'
PROFILE_V2 = 'incident_host/v2'
PROFILE_FULL = 'incident_host/v2-full'
PROFILE_FULL_CODE = 'incident_host/v2-full-code-mode'
PROFILE_FULL_SPLIT = 'incident_host/v2-full-windows-backends'
SPLIT_VERSION = 'v2-full-windows-backends'
SPLIT_JOURNALS = {'primary': 'rpc', 'acl': 'probe-rpc',
                  'stop_first': 'stop/first', 'stop_cold': 'stop/cold'}
PRIMARY_STAGES = ('pending', 'pause', 'resume', 'typed', 'typed_resume', 'status', 'unknown', 'missing')
ACL_STAGES = ('principal', 'baseline_original', 'baseline_granted', 'baseline_denied', 'readonly')
OBSERVATION_CONTRACTS = {'negative': 'powershell-host-rejection/v1',
                         'readonly_fixture': 'read-baseline-specific-write-deny/v3'}
MANIFEST = Path(__file__).with_name('incident-host-scenarios.json')
MANIFEST_CODE = Path(__file__).with_name('incident-host-scenarios-code-mode.json')
MANIFEST_V2 = Path(__file__).with_name('incident-host-scenarios-v2.json')
MANIFEST_FULL = Path(__file__).with_name('incident-host-scenarios-v2-full.json')
MANIFEST_FULL_CODE = Path(__file__).with_name('incident-host-scenarios-v2-full-code-mode.json')
TOOLKIT = ('incident_host_acceptance.py', 'incident_readonly_child.py',
           'stop_host_acceptance.py', 'acceptance_identity.py', 'incident-host-scenarios.json',
           'incident-host-scenarios-v2.json', 'incident-host-scenarios-v2-full.json',
           'native_cli_adoption.py')
GATES = ('hook_trust', 'pause_same_unit', 'resume_provenance_pending',
         'typed_wait_retained', 'status_cli_posttool', 'status_negative_controls',
         'restricted_child_readonly', 'positive_negative_stop',
         'compaction_cold_resume', 'cleanup')


def is_code(profile):
    return profile in (PROFILE_CODE, PROFILE_FULL_CODE)


def is_full(profile):
    return profile in (PROFILE_FULL, PROFILE_FULL_CODE, PROFILE_FULL_SPLIT)


def is_v2(profile):
    return profile == PROFILE_V2 or is_full(profile)


def profile_version(profile):
    return profile.split('/', 1)[1]


def full_scope(value):
    base.require(isinstance(value, dict) and value.get('gate_scope') == 'full'
                 and value.get('required_gates') == list(GATES),
                 'full scope or required gate set differs')


def read_subject(path, *, strict=False):
    """New full subjects reject duplicate fields; consumed readers stay unchanged."""
    base.require(not path.is_symlink() and path.is_file(), 'regular input required')
    base.require(path.stat().st_size <= 16 * 1024 * 1024, 'input too large')
    raw = path.read_text(encoding='utf-8')
    value = json.loads(raw)
    def pairs(items):
        result = {}
        for key, item in items:
            base.require(key not in result, 'duplicate full subject field')
            result[key] = item
        return result
    # Inspect every pair too, so a duplicate cannot hide an earlier full marker.
    full = strict
    def inspect(items):
        nonlocal full
        for key, item in items:
            if (key == 'cli_adoption' or (key == 'gate_scope' and item == 'full') or
                (key == 'gate_profile' and is_full(item)) or
                (key == 'schema' and isinstance(item, str) and item.endswith(('/v2-full', '/v2-full-code-mode', '/' + SPLIT_VERSION)))):
                full = True
        return dict(items)
    json.loads(raw, object_pairs_hook=inspect)
    if full:
        value = json.loads(raw, object_pairs_hook=pairs)
    return value


class ObservationPending(RuntimeError):
    pass


def write_new(path, value):
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n'
    with path.open('x', encoding='utf-8') as stream:
        stream.write(raw)
    if os.name != 'nt':
        path.chmod(0o600)


def toolkit(plan=None, *, execution=False):
    profile = (plan or {}).get('gate_profile')
    names = TOOLKIT
    if is_code(profile):
        names += ('native_code_mode_command.py',
                  'incident-host-scenarios-v2-full-code-mode.json' if profile == PROFILE_FULL_CODE
                  else 'incident-host-scenarios-code-mode.json')
    if profile == PROFILE_FULL_CODE:
        names += ('incident_code_mode_preflight.py',)
    if profile == PROFILE_FULL_SPLIT:
        names += ('incident_windows_backends.py',)
    return {name: base.sha(code_mode.execution_tool(name) if execution else
                           Path(__file__).with_name(name)) for name in names}


def plan_identity(plan):
    return hashlib.sha256(cg.canonical_json(plan).encode()).hexdigest()


def profile_for_plan(plan):
    base.require(isinstance(plan, dict), 'plan object required')
    if 'cli_version' in plan or 'cli_adoption' in plan:
        cli_adoption.validate(plan, legacy_versions={'codex-cli 0.160.0'})
    split = plan.get('schema') == 'incident-host-plan/' + SPLIT_VERSION
    if split:
        base.require(plan.get('backend_contract') in (windows_backends.CONTRACT, windows_backends.OFFICIAL_CONTRACT)
                     and plan.get('cli_version') == cli_adoption.VERSION
                     and plan.get('toolkit') == toolkit(plan, execution=True)
                     and plan.get('manifest_sha256') == base.sha(MANIFEST_FULL),
                     'Windows split backend contract or pin differs')
        if windows_backends.model_provider(plan) == 'local_ollama':
            windows_backends.validate_local_endpoint(plan.get('local_provider_endpoint'))
    else:
        base.require(not {'backend_contract', 'local_provider_endpoint'} & plan.keys(),
                     'backend contract requires explicit split profile')
    if plan.get('schema') == 'incident-host-plan/v1-code-mode':
        base.require(plan.get('gate_profile') == PROFILE_CODE and not any(k in plan for k in
                     ('gate_scope', 'required_gates', 'observation_contracts', 'negative_parser_reference')),
                     'code-mode profile scope differs')
        code_mode.validate_plan(plan)
        base.require(plan.get('toolkit') == toolkit(plan, execution=True)
                     and plan.get('manifest_sha256') == base.sha(MANIFEST_CODE), 'code-mode fixture pin differs')
        return PROFILE_CODE
    full_code = plan.get('schema') == 'incident-host-plan/v2-full-code-mode'
    if full_code:
        code_mode.validate_plan(plan)
        base.require(plan.get('toolkit') == toolkit(plan, execution=True)
                     and plan.get('manifest_sha256') == base.sha(MANIFEST_FULL_CODE), 'Windows code-mode fixture pin differs')
    else:
        base.require('command_observation_contract' not in plan, 'code-mode contract requires explicit profile')
    full = split or plan.get('schema') in ('incident-host-plan/v2-full', 'incident-host-plan/v2-full-code-mode')
    if full:
        full_scope(plan)
    else:
        base.require(not any(k in plan for k in ('gate_scope', 'required_gates')),
                     'legacy profile cannot adopt full scope')
    if plan.get('schema') in (None, 'incident-host-plan/v1'):
        base.require(not any(k in plan for k in ('observation_contracts', 'negative_parser_reference'))
                     and plan.get('gate_profile', PROFILE) == PROFILE, 'v1 cannot adopt v2 observations')
        return PROFILE
    profile = PROFILE_FULL_SPLIT if split else PROFILE_FULL_CODE if full_code else PROFILE_FULL if full else PROFILE_V2
    base.require(plan.get('schema') == 'incident-host-plan/' + profile_version(profile)
                 and plan.get('gate_profile') == profile
                 and plan.get('observation_contracts') == OBSERVATION_CONTRACTS
                 and plan.get('platform') == 'Windows'
                 and plan.get('cli_version') in ('codex-cli 0.160.0', cli_adoption.VERSION),
                 'unknown observation adoption')
    reference = plan.get('negative_parser_reference')
    base.require(isinstance(reference, dict) and set(reference) ==
                 {'schema', 'python_sha256', 'script_sha256', 'runtime_sha256', 'cases'}
                 and reference['schema'] == 'incident-parser-reference/v1'
                 and isinstance(reference['cases'], dict)
                 and set(reference['cases']) == {'unknown', 'missing'}, 'parser reference unavailable')
    return profile


def parser_envelope(text, kind):
    errors = {'unknown': 'context_guard.py: error: unrecognized arguments: --unknown-status-option',
              'missing': 'context_guard.py checkpoint-status: error: argument --item: expected one argument'}
    base.require(kind in errors and isinstance(text, str) and len(text) <= 65536,
                 'parser kind/output invalid')
    normalized = text.replace('\r\n', '\n')
    base.require('\r' not in normalized, 'unknown parser line endings')
    lines = normalized.splitlines()
    base.require(len(lines) >= 2 and lines[-1] == errors[kind]
                 and lines[0].startswith('usage: context_guard.py ')
                 and all(line and line[0].isspace() for line in lines[1:-1]),
                 'parser output envelope differs')
    return {'usage_tokens': ' '.join(lines[:-1]).split(), 'error_line': lines[-1]}


def derive_parser_reference(plan):
    """Harmless parser failures precede every business command dispatch."""
    python, script = Path(plan['python']), Path(plan['plugin_root']) / 'scripts/context_guard.py'
    base.require(python.is_absolute() and python.is_file() and not python.is_symlink()
                 and base.sha(python) == plan.get('python_sha256')
                 and script.is_file() and not script.is_symlink()
                 and base.runtime(Path(plan['plugin_root'])) == plan['runtime_sha256'],
                 'parser reference executable/runtime drift')
    reference = {'schema': 'incident-parser-reference/v1', 'python_sha256': base.sha(python),
                 'script_sha256': base.sha(script), 'runtime_sha256': plan['runtime_sha256'], 'cases': {}}
    for kind, suffix in (('unknown', ['--unknown-status-option']), ('missing', ['--item', '--commands'])):
        argv = [str(python), '-B', str(script), 'checkpoint-status',
                '--data-dir', '__incident_parser_sentinel__', '--session-id', 'parser-sentinel',
                '--turn-id', 'parser-sentinel', '--token', 'parser-sentinel', *suffix]
        observed = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                                  timeout=20, check=False,
                                  env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        base.require(observed.returncode == 2 and not observed.stdout, 'sentinel parser failure differs')
        reference['cases'][kind] = parser_envelope(observed.stderr, kind)
    base.require(base.sha(python) == reference['python_sha256']
                 and base.sha(script) == reference['script_sha256'], 'parser bytes changed during reference')
    return reference


def host_parser_signature(plan, output, kind):
    reference = derive_parser_reference(plan)
    base.require(plan['negative_parser_reference'] == reference, 'captured parser reference differs')
    envelope = parser_envelope(output, kind)
    base.require(envelope == reference['cases'][kind], 'wrong source parser usage/error')
    return hashlib.sha256(cg.canonical_json(envelope).encode()).hexdigest()


def manifest_for_plan(plan):
    return {PROFILE_FULL_CODE: MANIFEST_FULL_CODE, PROFILE_CODE: MANIFEST_CODE, PROFILE: MANIFEST,
            PROFILE_V2: MANIFEST_V2, PROFILE_FULL: MANIFEST_FULL, PROFILE_FULL_SPLIT: MANIFEST_FULL}[profile_for_plan(plan)]


def helper_prompt(plan, argv, stage):
    manifest = base.read_json(manifest_for_plan(plan))
    template = manifest['helper_prompt_templates'][stage]
    return template.format(argv=cg.shell_join(argv))


def baseline_observation(stage, inventory, plan, request, expected, name):
    item = command_observation(stage, inventory, plan)
    argv = ordinary_command_argv(item['command'], windows=True, shell_identity=plan['shell'])
    base.require(isinstance(argv, list) and len(argv) == 5 and argv[-1] == '--baseline'
                 and expected[-1] == '--baseline'
                 and helper_argv_matches(argv[:4], expected[:4], windows=True)
                 and expected[0] == plan['python'] and expected[1] == execution_helper_path(plan)
                 and Path(expected[3]).absolute() == Path(plan['cwd']).absolute() /
                 ('incident-request-' + Path(plan['output']).name + '-' + name + '.json')
                 and item['exitCode'] == 0, 'baseline helper command differs')
    expected_prompt = helper_prompt(plan, expected, name)
    base.require(stage['prompt_sha256'] == hashlib.sha256(expected_prompt.encode()).hexdigest()
                 and request['phase'] == name, 'baseline prompt/request phase differs')
    record = json.loads(item['aggregatedOutput'])
    status = child.judge_baseline(record, request, require_read=name != 'baseline_original')
    base.require(status == ('observed' if name == 'baseline_original' else 'passed'),
                 'native actor read baseline failed')
    return record


def phase_request(request, phase):
    value = json.loads(json.dumps(request))
    value['phase'] = phase
    value.pop('request_sha256', None)
    value['request_sha256'] = child.request_identity_v2(value)
    return value


def preflight(plan_path, output):
    plan = read_subject(plan_path)
    profile = profile_for_plan(plan)
    if is_v2(profile):
        base.require(plan['negative_parser_reference'] == derive_parser_reference(plan),
                     'parser reference differs from pinned source')
    base.require(output.resolve() == Path(plan['output']).resolve(), 'output differs from plan')
    cli_adoption.validate(plan, legacy_versions={'codex-cli 0.160.0'}, require_native=True)
    base.require(plan.get('toolkit') == toolkit(plan), 'toolkit bytes changed')
    base.require(plan.get('manifest_sha256') == base.sha(manifest_for_plan(plan)), 'manifest changed')
    base.require(isinstance(plan.get('model'), str) and plan['model'].strip(), 'explicit model required')
    base.require(plan.get('effort') == 'medium', 'explicit medium effort required')
    base.require(plan.get('platform') == platform.system(), 'platform differs from plan')
    if plan['platform'] == 'Windows':
        verify_shell_file(plan.get('shell'))
    python = Path(plan['python'])
    base.require(python.is_absolute() and python.is_file() and not python.is_symlink(),
                 'regular Python required')
    base.require(base.sha(python) == plan['python_sha256'], 'Python changed')
    version = subprocess.check_output([str(python), '--version'], text=True, timeout=20).strip()
    base.require(version == plan['python_version'], 'Python version changed')
    base.require(plan['source']['dirty_paths'] == [] and plan['source']['renamed_away'] == [],
                 'native execution requires clean source')
    # Shared preflight enforces exact source/runtime/HOME/CLI/output boundaries.
    shared = dict(plan, schema='stop-host-plan/v1')
    temporary = output.parent / (output.name + '.preflight-plan.json')
    # Shared preflight input is an exclusive retained receipt.
    return _shared_preflight(shared, output, plan, temporary)


def _shared_preflight(shared, output, plan, temporary):
    # Reject private receipt destinations before writing anything.
    cwd, home = Path(plan['cwd']).resolve(), Path(plan['home']).resolve()
    target = output.resolve()
    base.require(target != ROOT and ROOT not in target.parents
                 and target != cwd and cwd not in target.parents
                 and target != home and home not in target.parents, 'private output scope rejected')
    base.require(cwd not in (ROOT, home) and ROOT not in cwd.parents,
                 'dedicated scenario workspace required')
    base.require(not (cwd / ('incident-readonly-' + output.name)).exists()
                 and not (cwd / ('incident-request-' + output.name + '.json')).exists()
                 and (not is_v2(profile_for_plan(plan)) or all(not (cwd /
                      ('incident-request-' + output.name + '-' + name + '.json')).exists()
                      for name in ('baseline_original', 'baseline_granted', 'baseline_denied'))), 'fixture output collision')
    output.parent.mkdir(parents=True, exist_ok=True)
    if temporary.exists():
        base.require(base.read_json(temporary) == shared, 'prior preflight subject differs')
    else:
        write_new(temporary, shared)
    base.preflight(temporary, output)
    return plan


def copy_session(plan, thread, destination):
    source = base.session_state_path(Path(plan['data_root']), thread).parent
    base.require(source.is_dir() and not source.is_symlink(), 'session unavailable')
    total = 0
    for p in source.rglob('*'):
        base.require(not p.is_symlink() and (p.is_file() or p.is_dir()), 'special session entry')
        if p.is_file():
            total += p.stat().st_size
            base.require(total <= 128 * 1024 * 1024, 'session budget')
    shutil.copytree(source, destination)
    state = cg.read_only_committed_state(destination)
    valid, _ = cg.read_only_authority_sources_valid(destination, state)
    base.require(valid, 'copied authority unavailable')
    return state


class Client(base.Client):
    def receive(self, deadline):
        try:
            return super().receive(deadline)
        except ValueError as exc:
            if str(exc) == 'unexpected server request':
                raise ObservationPending('official server request retained; no automatic approval') from exc
            raise

    def start(self, instructions=base.INSTRUCTIONS):
        if self.plan['platform'] == 'Windows':
            expected = verify_shell_file(self.plan.get('shell'))
            observed = self.rpc('environment/info', {'environmentId': 'local'}).get('shell')
            base.require(isinstance(observed, dict) and observed.get('name') == expected['name']
                         and isinstance(observed.get('path'), str)
                         and ntpath.normcase(ntpath.normpath(observed['path'])) ==
                         ntpath.normcase(ntpath.normpath(expected['path'])),
                         'official Windows default shell differs from plan')
        result = self.rpc('thread/start', {'cwd': self.plan['cwd'],
                          'sandbox': 'workspace-write', 'approvalPolicy': 'on-request',
                          'model': self.plan['model'], 'developerInstructions': instructions})
        base.require(result.get('model') == self.plan['model'], 'model configuration drift')
        base.require(result.get('approvalPolicy') == 'on-request', 'approval policy drift')
        base.require(result.get('sandbox', {}).get('type') == 'workspaceWrite', 'sandbox drift')
        if is_code(profile_for_plan(self.plan)):
            if not hasattr(self, 'thread_records'):
                self.thread_records = {}
            self.thread_records[result['thread']['id']] = result['thread']
        return result['thread']['id']

    def observed_turn(self, thread, prompt):
        begin = len(self.rows)
        response = self.rpc('turn/start', {'threadId': thread,
                            'input': [{'type': 'text', 'text': prompt}], 'effort': 'medium'})
        turn = response['turn']['id']
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            row = self.receive(deadline)
            if (row.get('method') == 'turn/completed'
                    and row['params'].get('threadId') == thread
                    and row['params']['turn']['id'] == turn):
                base.require(row['params']['turn']['status'] == 'completed', 'turn failed')
                return {'thread': thread, 'turn': turn, 'rows': self.rows[begin:],
                        'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest()}
        raise TimeoutError('incident turn')


class SplitClient(Client):
    config_read_id = None

    def __init__(self, plan, directory, *, role):
        self.role = role
        self.turn_count = self.compact_count = 0
        self.compaction_budget = (windows_backends.CompactionBudget(role)
                                  if windows_backends.model_provider(plan) == 'openai' else None)
        windows_backends.check_launch_environment(plan)
        super().__init__(plan, directory, app_server_flags=windows_backends.launch_flags(split_backend(role), plan))

    def close(self):
        pid = self.owned.process.pid if self.owned else None
        cleanup = super().close()
        return {**cleanup, 'role': self.role, 'pid': pid} if cleanup else None

    def journal_response(self, message):
        if self.config_read_id is not None and message.get('id') == self.config_read_id:
            # Persist only the allowlisted configuration projection. Raw Hook,
            # thread, turn, and tool RPCs are retained independently.
            base.require('method' not in message and 'error' not in message, 'config/read failed')
            return {'id': self.config_read_id,
                    'result': windows_backends.project_config(message.get('result'), self.plan)}
        return message

    def start(self, instructions=base.INSTRUCTIONS):
        if self.plan['schema'] == 'stop-host-plan/v1':
            return base.Client.start(self, instructions)
        return super().start(instructions)

    def receive(self, deadline):
        message = super().receive(deadline)
        if self.compaction_budget is not None:
            self.compaction_budget.observe(message)
        return message

    def rpc(self, method, params):
        if self.compaction_budget is not None:
            self.compaction_budget.check()
            if method in ('turn/start', 'thread/compact/start'):
                # Finish processing already queued events before spending more
                # budget, including events after the previous turn boundary.
                while not self.q.empty():
                    self.receive(time.monotonic())
        if method == 'turn/start':
            limit = {'primary': len(PRIMARY_STAGES), 'acl': len(ACL_STAGES),
                     'stop_first': 3, 'stop_cold': 2}[self.role]
            base.require(self.turn_count < limit and params.get('effort') == 'medium',
                         'split turn budget or effort differs')
            self.turn_count += 1
        if method == 'thread/compact/start':
            base.require(self.role == 'stop_first' and self.compact_count == 0, 'split compaction budget exhausted')
            if self.compaction_budget is not None:
                self.compaction_budget.request(params['threadId'])
            self.compact_count += 1
        if method == 'config/read':
            self.config_read_id = self.sequence + 1
        try:
            result = super().rpc(method, params)
        finally:
            self.config_read_id = None
        if method in ('thread/start', 'thread/resume'):
            windows_backends.validate_thread_result(result, self.plan)
        return result


def split_backend(role):
    base.require(role in SPLIT_JOURNALS, 'unknown split process role')
    return windows_backends.CONTRACT['roles'][role]


def open_split_client(plan, directory, role, bindings, cleanups):
    backend = split_backend(role)
    flags = windows_backends.launch_flags(backend, plan)
    client = SplitClient(plan, directory, role=role)
    try:
        bindings[role] = windows_backends.bind(client, backend)
        write_new(directory / 'launch.json', {'role': role, 'pid': client.owned.process.pid,
                  'argv': [plan['codex'], *flags, 'app-server'], **windows_backends.launch_subject(plan)})
        return client
    except BaseException:
        cleanups.append(client.close())
        raise


def split_cleanup(cleanup, role, pid):
    base.require(cleanup and all(cleanup.get(key) is True for key in
                 ('owned_process_exited', 'owned_tree_no_running_members',
                  'job_assignment_confirmed', 'job_close_confirmed', 'cleanup_complete'))
                 and not cleanup.get('process_group_cleanup_error')
                 and cleanup.get('role') == role and cleanup.get('pid') == pid, 'split owned cleanup failed')


def split_launch(directory, role, plan):
    launch = read_subject(directory / 'launch.json', strict=True)
    subject = windows_backends.launch_subject(plan)
    base.require(set(launch) == {'role', 'pid', 'argv', *subject} and launch['role'] == role
                 and type(launch['pid']) is int and launch['pid'] > 0
                 and all(launch[key] == value for key, value in subject.items())
                 and launch['argv'] == [plan['codex'], *windows_backends.launch_flags(split_backend(role), plan),
                                        'app-server'], 'split app-server launch differs')
    return launch['pid']


def split_preflight(plan, directory, *, record=False):
    """Exercise the same launch/readiness path before accepting any model turns."""
    roles = ('primary', 'acl')
    if record:
        directory.mkdir(mode=0o700)
        bindings, cleanups = {}, []
        for role in roles:
            target = directory / SPLIT_JOURNALS[role]
            target.mkdir()
            client = open_split_client(plan, target, role, bindings, cleanups)
            cleanups.append(client.close())
        write_new(directory / 'receipt.json', {'plan_sha256': plan_identity(plan),
                  'bindings': bindings, 'cleanups': cleanups})
    base.require(not directory.is_symlink() and directory.is_dir(), 'split preflight directory unavailable')
    receipt = read_subject(directory / 'receipt.json', strict=True)
    base.require(set(receipt) == {'plan_sha256', 'bindings', 'cleanups'}
                 and receipt['plan_sha256'] == plan_identity(plan)
                 and set(receipt['bindings']) == set(roles)
                 and len(receipt['cleanups']) == len(roles), 'split preflight receipt differs')
    pids = set()
    for role, cleanup in zip(roles, receipt['cleanups']):
        target = directory / SPLIT_JOURNALS[role]
        base.require(not target.is_symlink() and target.is_dir(), 'split preflight role unavailable')
        pid = split_launch(target, role, plan)
        split_cleanup(cleanup, role, pid)
        pids.add(pid)
        binding, rows = windows_backends.verify_journal(
            directory / SPLIT_JOURNALS[role] / 'rpc.jsonl', split_backend(role), plan)
        if windows_backends.model_provider(plan) == 'openai':
            windows_backends.replay_compactions(rows, role)
        base.require(binding == receipt['bindings'][role]
                     and all(row['message'].get('method') in
                             ('initialize', 'initialized', 'hooks/list', 'config/read', 'windowsSandbox/readiness')
                             for row in rows if row['direction'] == 'request'),
                     'split preflight must remain zero-turn')
    base.require(len(pids) == len(roles), 'split preflight process identity reused')


def split_turns(rows, *, include_drained=False):
    """Replay the exact response slices that observed_turn retained."""
    turns = []
    previous_request = previous_completion = None
    for i, row in enumerate(rows):
        req = row['message']
        if row['direction'] != 'request':
            continue
        prior = previous_request
        previous_request = i
        if req.get('method') != 'turn/start':
            continue
        thread, prompt = req['params']['threadId'], req['params']['input']
        base.require(isinstance(prompt, list) and len(prompt) == 1
                     and prompt[0].get('type') == 'text' and isinstance(prompt[0].get('text'), str)
                     and req['params']['effort'] == 'medium', 'split turn request differs')
        observed, turn = [], None
        if include_drained:
            # The official live collector records its start offset before rpc()
            # drains queued notifications, then sends turn/start. The prior
            # synchronous operation defines the beginning of that drain.
            base.require(prior is not None, 'split turn has no preceding operation')
            preceding = rows[prior]['message']
            if preceding.get('method') == 'thread/start':
                ack = [j for j in range(prior + 1, i)
                       if rows[j]['direction'] == 'response'
                       and rows[j]['message'].get('id') == preceding['id']]
                base.require(len(ack) == 1 and
                             rows[ack[0]]['message']['result']['thread']['id'] == thread,
                             'split initial turn has no matching thread response')
                boundary = ack[0]
            else:
                base.require(preceding.get('method') == 'turn/start'
                             and preceding['params']['threadId'] == thread
                             and previous_completion is not None
                             and prior < previous_completion < i,
                             'split turn has no matching previous completion')
                boundary = previous_completion
            for event in rows[boundary + 1:i]:
                message = event['message']
                base.require(event['direction'] == 'response' and 'id' not in message
                             and isinstance(message.get('method'), str), 'split drain is not notifications')
                observed.append(message)
        for j, event in enumerate(rows[i + 1:], i + 1):
            base.require(event['direction'] == 'response', 'split turn interrupted')
            message = event['message']
            observed.append(message)
            if message.get('id') == req['id']:
                turn = message['result']['turn']['id']
            if (turn and message.get('method') == 'turn/completed'
                    and message['params']['turn']['id'] == turn):
                base.require(message['params']['threadId'] == thread
                             and message['params']['turn']['status'] == 'completed', 'split turn incomplete')
                previous_completion = j
                break
        else:
            raise ValueError('split turn completion missing')
        turns.append((thread, turn, hashlib.sha256(prompt[0]['text'].encode()).hexdigest(), observed))
    base.require(len({turn[1] for turn in turns}) == len(turns), 'split turn reused')
    return turns


def split_inventory(rows, plan):
    matches = [row['message'] for row in rows if row['direction'] == 'request'
               and row['message'].get('method') == 'hooks/list']
    base.require(len(matches) == 1 and matches[0]['params'] == {'cwds': [plan['cwd']]},
                 'split Hook inventory request differs')
    replies = [row['message']['result']['data'] for row in rows if row['direction'] == 'response'
               and row['message'].get('id') == matches[0]['id']]
    base.require(len(replies) == 1 and len(replies[0]) == 1 and not replies[0][0].get('errors')
                 and not replies[0][0].get('warnings'), 'split Hook inventory unavailable')
    hooks = replies[0][0]['hooks']
    base.require(len(hooks) == len(base.EVENTS), 'split Hook count differs')
    return {hook['eventName']: hook for hook in hooks}


def verify_split_capture(directory, capture):
    plan = capture['plan']
    base.require(capture['origin'] == 'native' and directory.resolve() == Path(plan['output']).resolve()
                 and set(capture['backend_bindings']) == set(SPLIT_JOURNALS)
                 and len(capture['cleanups']) == len(SPLIT_JOURNALS), 'split capture sources unavailable')
    base.require(capture['stop_result']['cleanups'] == capture['cleanups'][2:],
                 'split Stop cleanups differ')
    stages = capture['stages']
    base.require(set(stages) == set(PRIMARY_STAGES + ACL_STAGES), 'split stages incomplete')
    pids, all_turns, journals = set(), set(), {}
    primary_threads, acl_threads, first_threads, cold_threads = set(), set(), set(), set()
    groups = {'primary': (PRIMARY_STAGES, primary_threads), 'acl': (ACL_STAGES, acl_threads),
              'stop_first': ((), first_threads), 'stop_cold': ((), cold_threads)}
    for (role, relative), cleanup in zip(SPLIT_JOURNALS.items(), capture['cleanups']):
        pid = split_launch(directory / relative, role, plan)
        split_cleanup(cleanup, role, pid)
        base.require(pid not in pids, 'split process identity reused')
        pids.add(pid)
        path = directory / relative / 'rpc.jsonl'
        binding, rows = windows_backends.verify_journal(path, split_backend(role), plan)
        base.require(binding == capture['backend_bindings'][role], 'split process binding differs')
        base.require(split_inventory(rows, plan) == capture['inventory'], 'split process Hook inventory differs')
        methods = [row['message'].get('method') for row in rows if row['direction'] == 'request']
        base.require(methods.count('thread/compact/start') == (1 if role == 'stop_first' else 0),
                     'split compaction budget differs')
        official = windows_backends.model_provider(plan) == 'openai'
        if official:
            windows_backends.replay_compactions(rows, role)
        names, threads = groups[role]
        turns = split_turns(rows, include_drained=official and bool(names))
        base.require(len(turns) == (len(names) if names else 3 if role == 'stop_first' else 2),
                     'split model turn count differs')
        for thread, turn, _, _ in turns:
            base.require(turn not in all_turns, 'split cross-process turn reused')
            all_turns.add(turn)
            threads.add(thread)
        for name, (thread, turn, prompt_sha, observed) in zip(names, turns):
            stage = stages[name]
            base.require((stage['thread'], stage['turn'], stage['prompt_sha256'], stage['rows']) ==
                         (thread, turn, prompt_sha, observed), 'split stage differs from owning journal')
        journals[role] = base.sha(path)
    base.require(len(primary_threads) == 2 and len(acl_threads) == len(first_threads) == 1
                 and len(cold_threads) == 2 and first_threads < cold_threads
                 and len(primary_threads | acl_threads | cold_threads) == 5, 'split thread roles overlap')
    return journals


def verify_split_fixture(status_stage, final_request, plan, inventory, directory):
    state = state_for(status_stage)
    argv = status_argv(command_observation(status_stage, inventory, plan), status_stage, plan, inventory=inventory)
    token = cg.parse_checkpoint_status_option_bindings(argv[3:])['--token'][0]
    if token == '[REDACTED_SECRET]':
        token = hook_control_token(status_stage, inventory, plan, state)
    thread, turn = status_stage['thread'], status_stage['turn']
    fixture = final_request['fixture']
    base.require(final_request['turn'] == turn and final_request['state_revision'] == state['content_hash']
                 and final_request['argv'] == [*argv[:3], '--data-dir', fixture, '--session-id', thread,
                                               '--turn-id', turn, '--token', token, '--commands'],
                 'split fixture differs from status authority')
    base.require(read_subject(directory / 'authored-readonly-request.json', strict=True) == final_request,
                 'split authored request differs')
    prefix = f'sessions-v2/{thread}/'
    clone = {name[len(prefix):]: (info['sha256'], info['size'])
             for name, info in final_request['inventory'].items()
             if name.startswith(prefix) and info['kind'] == 'file'}
    snapshot = {name: (info['sha256'], info['size'])
                for name, info in child.inventory(Path(status_stage['snapshot'])).items()
                if info['kind'] == 'file'}
    base.require(snapshot and clone == snapshot, 'split exact copied session bytes differ')


def canonical_shell_command(body, plan):
    """Visible pinned inner wrapper; never claim the API's default outer argv."""
    identity = verify_shell_file(plan.get('shell'))
    path = identity['path']
    base.require(not any(c in path for c in ('"', '$', '`', '\r', '\n', '\0')),
                 'unsupported canonical shell path')
    return '& "' + path + '" -Command ' + "'" + body.replace("'", "''") + "'"


def expected_code_command(stage, inventory, plan):
    name = stage.get('name')
    if name in ('status', 'unknown', 'missing'):
        suffix = {'status': ' --commands', 'unknown': ' --unknown-status-option',
                  'missing': ' --item --commands'}[name]
        body = discovery_command(stage, inventory, plan) + suffix
    elif plan.get('gate_profile') == PROFILE_FULL_CODE:
        base.require(name in ('principal', 'baseline_original', 'baseline_granted', 'baseline_denied', 'readonly'),
                     'unknown Windows code-mode stage')
        argv = ([plan['python'], execution_helper_path(plan), '--identity'] if name == 'principal'
                else stage.get('helper_argv'))
        base.require(isinstance(argv, list) and all(isinstance(x, str) for x in argv), 'independent helper argv required')
        prompt = helper_prompt(plan, argv, name)
        base.require(stage['prompt_sha256'] == hashlib.sha256(prompt.encode()).hexdigest(), 'helper command prompt differs')
        body = '& ' + cg.shell_join(argv)
    else:
        base.require(name == 'readonly', 'unknown code-mode command stage')
        body = stage.get('code_mode_evidence', {}).get('command')
        base.require(isinstance(body, str) and stage['prompt_sha256'] == hashlib.sha256(
                     ('Run this exact ordinary tool command once: ' + body).encode()).hexdigest(), 'readonly command prompt differs')
    return canonical_shell_command(body, plan) if plan.get('gate_profile') == PROFILE_FULL_CODE else body


def code_command(stage, inventory, plan, *, rejection=False):
    evidence = stage.get('code_mode_evidence')
    base.require(isinstance(evidence, dict), 'code-mode evidence unavailable')
    command = expected_code_command(stage, inventory, plan)
    observed = code_mode.consume(evidence, plan, stage, inventory, command, rejection=rejection)
    return {'command': command, 'cwd': plan['cwd'], 'exitCode': observed['exit_code'],
            'aggregatedOutput': observed['output'], 'observation_contract': code_mode.contract(plan)}


def discovery_command(stage, inventory, plan):
    hooks = base.paired_hooks(stage['rows'], stage['thread'], stage['turn'], inventory)
    prompts = [h for h in hooks if h['eventName'] == 'userPromptSubmit' and h['status'] == 'completed']
    base.require(len(prompts) == 1, 'trusted prompt discovery required')
    commands = []
    for entry in prompts[0].get('entries', []):
        if isinstance(entry, dict) and entry.get('kind') == 'context' and isinstance(entry.get('text'), str):
            for line in entry['text'].splitlines():
                try:
                    status_argv({'command': line + ' --commands'}, stage, plan)
                except ValueError:
                    continue
                commands.append(line)
    base.require(len(commands) == 1, 'unique exact discovery command required')
    hook_control_token(stage, inventory, plan, state_for(stage))
    return commands[0]


def command_observation(stage, inventory, plan):
    if is_code(profile_for_plan(plan)):
        return code_command(stage, inventory, plan)
    rows, thread, turn = stage['rows'], stage['thread'], stage['turn']
    for row in rows:
        if row.get('method') in ('hook/started', 'hook/completed'):
            run = row['params']['run']
            base.require(type(run.get('displayOrder')) is int and isinstance(run.get('id'), str),
                         'invalid raw Hook identity')
    hooks = base.paired_hooks(rows, thread, turn, inventory)
    for name in ('userPromptSubmit', 'preToolUse', 'postToolUse', 'stop'):
        selected = [h for h in hooks if h['eventName'] == name]
        base.require(len(selected) == 1 and selected[0]['status'] == 'completed',
                     'single completed ' + name + ' required')
        if name == 'postToolUse':
            base.require(type(selected[0].get('entries')) is list and not selected[0]['entries'],
                         'diagnostic PostToolUse not silent')
    b, start_index, end_index = command_pair(stage, plan)
    # Serial one-command turn permits scope attribution without inventing tool IDs.
    for name, low, high in (('preToolUse', -1, end_index), ('postToolUse', start_index, len(rows))):
        indices = [i for i, r in enumerate(rows) if r.get('method') == 'hook/completed'
                   and r.get('params', {}).get('threadId') == thread
                   and r['params'].get('turnId') == turn
                   and r['params']['run']['eventName'] == name]
        base.require(len(indices) == 1 and low < indices[0] < high, 'tool Hook order')
    return b


def command_pair(stage, plan, *, require_exit=True):
    rows, thread, turn = stage['rows'], stage['thread'], stage['turn']
    commands = [(i, x) for i, x in enumerate(rows)
                if x.get('method') in ('item/started', 'item/completed')
                and x.get('params', {}).get('threadId') == thread
                and x['params'].get('turnId') == turn
                and x['params'].get('item', {}).get('type') == 'commandExecution']
    base.require(len(commands) == 2, 'one ordinary command pair required')
    (start_index, start), (end_index, end) = commands
    a, b = start['params']['item'], end['params']['item']
    base.require(start['method'] == 'item/started' and end['method'] == 'item/completed'
                 and start_index < end_index and a['id'] == b['id']
                 and a['command'] == b['command'] and a['cwd'] == b['cwd'],
                 'command pair identity mismatch')
    base.require(Path(b['cwd']).resolve() == Path(plan['cwd']).resolve(), 'tool cwd drift')
    # CLI 0.160 distinguishes initial unified exec from follow-up interaction.
    # Both notifications must bind the same explicit model-initiated source.
    base.require(a.get('source') in ('agent', 'unifiedExecStartup')
                 and a.get('source') == b.get('source')
                 and b.get('status') in ('completed', 'failed'),
                 'ordinary model command required')
    if require_exit:
        base.require(type(b.get('exitCode')) is int and isinstance(b.get('aggregatedOutput'), str),
                     'CLI exit/output unavailable')
    return b, start_index, end_index



def rejection_observation(stage, inventory, plan, kind):
    """Malformed controls must be refused; absent execution is not CLI success."""
    profile = profile_for_plan(plan)
    rows, thread, turn = stage['rows'], stage['thread'], stage['turn']
    def finish(value, exit_code=None):
        if is_v2(profile):
            value.update(source_exit='not_observed', host_exit=
                         {'observed': exit_code is not None, 'value': exit_code})
        return value
    for row in rows:
        if row.get('method') in ('hook/started', 'hook/completed'):
            base.require(type(row['params']['run'].get('displayOrder')) is int, 'invalid rejection Hook identity')
    hooks = base.paired_hooks(rows, thread, turn, inventory)
    for name in ('userPromptSubmit',):
        selected = [h for h in hooks if h['eventName'] == name]
        base.require(len(selected) == 1 and selected[0]['status'] == 'completed', 'rejection boundary incomplete')
    pre = [h for h in hooks if h['eventName'] == 'preToolUse']
    post = [h for h in hooks if h['eventName'] == 'postToolUse']
    if is_code(profile):
        item = code_command(stage, inventory, plan, rejection=True)
        argv = status_argv(item, stage, plan, legal=False, inventory=inventory)
        expected = '--unknown-status-option' if kind == 'unknown' else '--item --commands'
        if profile == PROFILE_FULL_CODE and item['exitCode'] == 1:
            base.require(item['command'].startswith('& '), 'canonical visible shell wrapper required')
            outer = windows_display_tokens(item['command'][2:])
            base.require(outer and len(outer) == 3 and outer[1] == '-Command'
                         and outer[0] == plan['shell']['path'], 'host1 pinned actual wrapper differs')
            base.require(' '.join(argv[-1:] if kind == 'unknown' else argv[-2:]) == expected
                         and len(pre) == len(post) == 1 and pre[0]['status'] == 'completed'
                         and pre[0].get('entries') == [] and post[0]['status'] == 'blocked'
                         and isinstance(post[0].get('entries'), list) and post[0]['entries']
                         and all(isinstance(e, dict) and e.get('kind') == 'feedback'
                                 and isinstance(e.get('text'), str) and e['text'] for e in post[0]['entries']),
                         'host1 requires silent Pre and real blocked Post feedback')
            signature = host_parser_signature(plan, item['aggregatedOutput'], kind)
            return finish({'status': 'passed', 'branch': 'powershell_host1_parser_post_blocked',
                           'cli': 'observed', 'posttool': 'blocked', 'parser_kind': kind,
                           'parser_signature_sha256': signature}, 1)
        base.require(' '.join(argv[-1:] if kind == 'unknown' else argv[-2:]) == expected
                     and item['exitCode'] == 2 and len(post) == 1 and post[0]['status'] == 'blocked'
                     and type(post[0].get('entries')) is list, 'malformed CLI must fail and real Post must block')
        return finish({'status': 'passed', 'branch': 'cli2_post_blocked',
                       'cli': 'observed', 'posttool': 'blocked'}, 2)
    attempted = [r for r in rows if r.get('method') == 'item/started'
                 and r.get('params', {}).get('threadId') == thread
                 and r['params'].get('turnId') == turn
                 and r['params'].get('item', {}).get('type') == 'commandExecution']
    if not attempted:
        return finish({'status': 'pending', 'branch': 'attempt_not_observed',
                       'cli': 'not_observed', 'posttool': 'not_observed'})
    terminal = [r for r in rows if r.get('method') == 'item/completed'
                and r.get('params', {}).get('threadId') == thread
                and r['params'].get('turnId') == turn
                and r['params'].get('item', {}).get('type') == 'commandExecution']
    if not terminal:
        return finish({'status': 'pending', 'branch': 'terminal_not_observed',
                       'cli': 'not_observed', 'posttool': 'not_observed'})
    item, start_index, end_index = command_pair(stage, plan, require_exit=False)
    argv = status_argv(item, stage, plan, legal=False, inventory=inventory)
    expected = '--unknown-status-option' if kind == 'unknown' else '--item --commands'
    suffix = ' '.join(argv[-1:] if kind == 'unknown' else argv[-2:])
    base.require(suffix == expected and len(pre) == 1, 'rejection command differs')
    if pre[0]['status'] == 'blocked':
        base.require(not post and item['status'] == 'failed' and item.get('exitCode') is None,
                     'Pre refusal cannot certify CLI or Post execution')
        return finish({'status': 'pending', 'branch': 'pre_blocked',
                       'cli': 'not_observed', 'posttool': 'not_observed'})
    base.require(pre[0]['status'] == 'completed', 'unresolved Pre refusal')
    if item.get('exitCode') is None or not post:
        return finish({'status': 'pending', 'branch': 'execution_incomplete',
                       'cli': 'not_observed' if item.get('exitCode') is None else 'observed',
                       'posttool': 'not_observed' if not post else 'observed'}, item.get('exitCode'))
    if is_v2(profile) and type(item['exitCode']) is int and item['exitCode'] == 1:
        verify_shell_file(plan.get('shell'))
        outer = windows_display_tokens(item['command'])
        base.require(outer and len(outer) == 3 and outer[1] == '-Command'
                     and ntpath.normcase(ntpath.normpath(outer[0])) ==
                     ntpath.normcase(ntpath.normpath(plan['shell']['path'])), 'host1 requires pinned wrapper')
        base.require(len(post) == 1 and post[0]['status'] == 'blocked'
                     and isinstance(post[0].get('entries'), list) and post[0]['entries']
                     and all(isinstance(e, dict) and e.get('kind') == 'feedback'
                             and isinstance(e.get('text'), str) and e['text'] for e in post[0]['entries'])
                     and pre[0].get('entries') == [], 'host1 requires silent Pre and blocked Post feedback')
        indices = {event: [i for i, row in enumerate(rows)
                          if row.get('method') == 'hook/completed'
                          and row.get('params', {}).get('threadId') == thread
                          and row['params'].get('turnId') == turn
                          and row['params']['run']['eventName'] == event]
                   for event in ('preToolUse', 'postToolUse')}
        base.require(all(len(v) == 1 for v in indices.values())
                     and indices['preToolUse'][0] < end_index
                     and indices['postToolUse'][0] > start_index
                     and indices['preToolUse'][0] < indices['postToolUse'][0], 'host rejection Hook order')
        signature = host_parser_signature(plan, item.get('aggregatedOutput'), kind)
        return finish({'status': 'passed', 'branch': 'powershell_host1_parser_post_blocked',
                       'cli': 'observed', 'posttool': 'blocked', 'parser_kind': kind,
                       'parser_signature_sha256': signature}, 1)
    base.require(type(item['exitCode']) is int and item['exitCode'] == 2
                 and len(post) == 1 and post[0]['status'] == 'blocked',
                 'malformed CLI must fail and Post must block')
    base.require(type(post[0].get('entries')) is list, 'Post refusal entries unavailable')
    return finish({'status': 'passed', 'branch': 'cli2_post_blocked',
                   'cli': 'observed', 'posttool': 'blocked'}, 2)


def literal_shell_body(body, *, windows):
    """Reject expansion/operators while retaining quoted literal path bytes."""
    # CLI command display redacts this value; it is not an executable token.
    # Mask only the exact standalone token-option sentinel for syntax checking;
    # return/validate the original observed argv without reconstructing secrets.
    body = re.sub(r'(?<!\S)--token=\[REDACTED_SECRET\](?=\s|$)',
                  '--token=REDACTED_SECRET', body)
    if windows and body.lstrip().startswith('& '):
        body = body.lstrip()[2:].lstrip()
    quote = None
    escaped = False
    for char in body:
        if char in '\r\n':
            return False
        if escaped:
            escaped = False
            continue
        if quote == "'":
            if char == "'":
                quote = None
            continue
        if not windows and char == '\\':
            escaped = True
            continue
        if quote == '"':
            if char == '"':
                quote = None
            elif char in '$`':
                return False
            continue
        if char in {"'", '"'}:
            quote = char
        elif char in '$`<>;&|()*?[]{}#':
            return False
    return quote is None and not escaped


def windows_display_tokens(command):
    """Decode three native argv entries, plus the existing PS literal fixture."""
    literal = re.fullmatch(r"\s*(\"[^\"]+\"|'[^']+'|\S+)\s+-Command\s+'(.*)'\s*", command)
    if literal:
        shell, body = literal.groups()
        if "'" in body.replace("''", ''):
            return None
        return [shell.strip('\"\''), '-Command', body.replace("''", "'")]
    tokens = []
    index = 0
    while index < len(command):
        while index < len(command) and command[index] in ' \t':
            index += 1
        if index == len(command):
            break
        token, quoted = [], False
        while index < len(command) and (quoted or command[index] not in ' \t'):
            count = 0
            while index < len(command) and command[index] == '\\':
                count += 1
                index += 1
            if index < len(command) and command[index] == '"':
                token.extend('\\' * (count // 2))
                if count % 2:
                    token.append('"')
                else:
                    quoted = not quoted
                index += 1
            else:
                token.extend('\\' * count)
                if index < len(command) and (quoted or command[index] not in ' \t'):
                    token.append(command[index])
                    index += 1
        if quoted:
            return None
        tokens.append(''.join(token))
        if len(tokens) > 3:
            return None
    return tokens


def verify_shell_file(identity):
    base.require(isinstance(identity, dict) and set(identity) == {'name', 'path', 'sha256'}
                 and identity['name'] == 'powershell'
                 and isinstance(identity['path'], str)
                 and isinstance(identity['sha256'], str)
                 and re.fullmatch(r'[0-9a-f]{64}', identity['sha256']),
                 'bound Windows shell identity unavailable')
    shell = Path(identity['path'])
    base.require(shell.is_absolute() and not shell.is_symlink() and shell.is_file()
                 and shell.name.lower() in {'pwsh.exe', 'powershell.exe'}
                 and base.sha(shell) == identity['sha256'], 'bound Windows shell file differs')
    return identity


def ordinary_command_argv(command, *, windows, shell_identity=None):
    """Parse a direct invocation or one exact host shell wrapper, never execute it.

    POSIX startup wrappers and the existing Windows host-terminal PowerShell
    fixture are supported. cmd, extra shell options and nested wrappers are not.
    Expansion/redirection syntax stays unsupported even inside a wrapper.
    """
    if not isinstance(command, str) or len(command) > 65536:
        return None
    original = command
    shell_names = {'zsh', 'bash', 'sh', 'pwsh', 'pwsh.exe', 'powershell',
                   'powershell.exe', 'cmd', 'cmd.exe'}
    if windows:
        direct = cg.private_control_command_tokens(command, windows=True)
        if direct and ntpath.basename(direct[0]).lower() not in shell_names:
            return direct
    if windows and command.lstrip().startswith('& '):
        command = command.lstrip()[2:].lstrip()
    if cg.shell_control_operator_present(command):
        return None
    try:
        outer = windows_display_tokens(command) if windows else shlex.split(command)
    except ValueError:
        return None
    if not outer:
        return None
    shell = outer[0].replace('\\', '/').rsplit('/', 1)[-1].lower()
    if shell not in shell_names:
        return cg.private_control_command_tokens(original, windows=windows)
    if len(outer) != 3:
        return None
    if windows:
        if shell_identity is None:
            # Bare spellings exist only in old synthetic host fixtures.
            valid = outer[0].lower() in {'pwsh.exe', 'powershell.exe'}
        else:
            valid = (isinstance(shell_identity, dict)
                     and shell_identity.get('name') == 'powershell'
                     and isinstance(shell_identity.get('path'), str)
                     and isinstance(shell_identity.get('sha256'), str)
                     and re.fullmatch(r'[0-9a-f]{64}', shell_identity['sha256'])
                     and ntpath.isabs(shell_identity['path'])
                     and ntpath.normcase(ntpath.normpath(outer[0])) ==
                     ntpath.normcase(ntpath.normpath(shell_identity['path'])))
        valid = valid and outer[1] == '-Command'
    else:
        valid = outer[0] in {'/bin/zsh', '/bin/bash', '/bin/sh'} and outer[1] in {'-c', '-lc'}
    if not valid or not literal_shell_body(outer[2], windows=windows):
        return None
    argv = cg.private_control_command_tokens(outer[2], windows=windows)
    if not argv or argv[0].replace('\\', '/').rsplit('/', 1)[-1].lower() in shell_names:
        return None
    return argv


def status_argv(item, stage, plan, *, legal=True, inventory=None):
    argv = ordinary_command_argv(item['command'], windows=plan['platform'] == 'Windows',
                                 shell_identity=plan.get('shell'))
    base.require(argv and len(argv) > 3 and argv[2] == 'checkpoint-status', 'direct status command required')
    base.require(Path(argv[0]).resolve() == Path(plan['python']).resolve()
                 and Path(argv[1]).resolve() == Path(plan['plugin_root']) / 'scripts/context_guard.py',
                 'query executable drift')
    if not legal:
        normalized = list(argv[3:])
        if normalized[-1:] == ['--unknown-status-option']:
            normalized.pop()
        elif normalized[-2:] == ['--item', '--commands']:
            normalized.pop(-2)
        else:
            raise ValueError('negative query shape differs')
        binding = cg.parse_checkpoint_status_option_bindings(normalized)
        base.require(binding is not None, 'negative base binding malformed')
        base.require(binding['--session-id'] == [stage['thread']]
                     and binding['--turn-id'] == [stage['turn']]
                     and Path(binding['--data-dir'][0]).resolve() == Path(plan['data_root']).resolve(),
                     'negative binding drift')
        if is_v2(profile_for_plan(plan)):
            copied = state_for(stage)
            base.require(copied['session']['id'] == stage['thread'], 'negative copied session differs')
            token = binding['--token'][0]  # The shared parser requires exactly one nonempty token.
            if token == '[REDACTED_SECRET]':
                prompt = (inventory or {}).get('userPromptSubmit', {})
                base.require(isinstance(inventory, dict) and prompt.get('trustStatus') == 'trusted'
                             and prompt.get('enabled') is True and prompt.get('source') == 'plugin'
                             and prompt.get('handlerType') == 'command'
                             and Path(prompt.get('sourcePath', '')).resolve() ==
                             Path(plan['plugin_root']) / 'hooks/hooks.json',
                             'trusted Prompt discovery inventory required')
                token = hook_control_token(stage, inventory, plan, copied)
            cg.completion_attempt_for(copied, stage['turn'], token)
    if legal:
        binding = cg.parse_checkpoint_status_option_bindings(argv[3:])
        base.require(binding and binding['--commands'] == [''], 'commands mode required')
        base.require(binding['--session-id'] == [stage['thread']]
                     and binding['--turn-id'] == [stage['turn']]
                     and Path(binding['--data-dir'][0]).resolve() == Path(plan['data_root']).resolve(),
                     'query binding drift')
    return argv


def status_output(item, stage, plan, *, inventory=None):
    """Bind the observed successful query output, not a later Stop revision."""
    if is_code(profile_for_plan(plan)):
        terminal = code_command(stage, inventory, plan)
    else:
        terminal, _, _ = command_pair(stage, plan)
    base.require(terminal == item, 'status item differs from captured command')
    status_argv(item, stage, plan)
    base.require(item['exitCode'] == 0, 'legal status CLI failed')
    def unique_object(pairs):
        value = {}
        for key, entry in pairs:
            base.require(key not in value, 'duplicate status output field')
            value[key] = entry
        return value
    output = json.loads(item['aggregatedOutput'], object_pairs_hook=unique_object)
    base.require(isinstance(output, dict)
                 and isinstance(output.get('advanced_commands'), dict)
                 and set(output['advanced_commands']) ==
                 {'status', 'stage_checkpoint', 'stage_disposition', 'register_proof'}
                 and all(isinstance(v, str) for v in output['advanced_commands'].values())
                 and output.get('turn_id') == stage['turn']
                 and isinstance(output.get('revision'), str)
                 and re.fullmatch(r'[0-9a-f]{64}', output['revision']),
                 'commands output absent or unbound')
    snapshot = state_for(stage)
    base.require(snapshot['session']['id'] == stage['thread'], 'query snapshot session differs')
    names = {'status': 'checkpoint-status', 'stage_checkpoint': 'stage-checkpoint',
             'stage_disposition': 'stage-disposition', 'register_proof': 'register-proof'}
    for name, subcommand in names.items():
        argv = cg.private_control_command_tokens(output['advanced_commands'][name],
                                                 windows=plan['platform'] == 'Windows')
        base.require(argv and len(argv) > 3 and argv[2] == subcommand
                     and Path(argv[0]).resolve() == Path(plan['python']).resolve()
                     and Path(argv[1]).resolve() == Path(plan['plugin_root']) / 'scripts/context_guard.py',
                     'private inventory executable or command differs')
        options = argv[3:]
        if name == 'register_proof':
            base.require(options[-2:] == ['--manifest', '/path/to/proof.json'],
                         'private manifest placeholder differs')
            options = options[:-2]
        binding = cg.parse_checkpoint_status_option_bindings(options)
        base.require(binding and not any(binding[k] for k in
                     ('--full', '--commands', '--item', '--after-revision'))
                     and binding['--session-id'] == [stage['thread']]
                     and binding['--turn-id'] == [stage['turn']]
                     and Path(binding['--data-dir'][0]).resolve() == Path(plan['data_root']).resolve()
                     and binding['--token'][0] != '[REDACTED_SECRET]',
                     'private inventory binding differs')
        cg.completion_attempt_for(snapshot, stage['turn'], binding['--token'][0])
    return output


def hook_control_token(stage, inventory, plan, copied):
    """Take only the unique bound discovery command from the trusted Hook."""
    hooks = base.paired_hooks(stage['rows'], stage['thread'], stage['turn'], inventory)
    prompts = [run for run in hooks if run['eventName'] == 'userPromptSubmit']
    base.require(len(prompts) == 1 and prompts[0]['status'] == 'completed',
                 'private prompt Hook unavailable')
    entries = prompts[0].get('entries')
    base.require(isinstance(entries, list), 'private Hook context unavailable')
    candidates = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get('kind') != 'context' or not isinstance(entry.get('text'), str):
            continue
        for line in entry['text'].splitlines():
            if 'checkpoint-status' not in line:
                continue
            try:
                argv = status_argv({'command': line + ' --commands'}, stage, plan)
            except ValueError:
                continue
            candidates.append(cg.parse_checkpoint_status_option_bindings(argv[3:])['--token'][0])
    base.require(len(candidates) == 1 and candidates[0] != '[REDACTED_SECRET]',
                 'unique private Hook command unavailable')
    cg.completion_attempt_for(copied, stage['turn'], candidates[0])
    return candidates[0]


def same_helper_path(observed, expected, *, windows):
    """Only separator spelling varies for local absolute Windows helper paths.

    No filesystem resolution, dot segments, device/UNC names, 8.3 aliases,
    case folding, environment expansion or alternate streams. Exact POSIX
    paths remain available to the existing synthetic Windows fixtures.
    """
    if not isinstance(observed, str) or not isinstance(expected, str):
        return False
    if not windows:
        return observed == expected
    def spelling(value):
        if not re.match(r'^[A-Za-z]:[\\/]', value):
            return None
        parts = re.split(r'[\\/]+', value[2:].lstrip('\\/'))
        if (not parts or any(not part or part in ('.', '..') or part.endswith((' ', '.'))
                             or any(c in part for c in ':*?<>|"~')
                             or any(ord(c) < 32 for c in part) for part in parts)):
            return None
        return value[:2], tuple(parts)
    left, right = spelling(observed), spelling(expected)
    if left is not None and right is not None:
        return left == right
    return observed == expected and observed.startswith('/')


def helper_argv_matches(argv, expected, *, windows):
    """Match one principal/read-only invocation; non-path tokens stay exact."""
    if (not isinstance(argv, list) or not isinstance(expected, list)
            or len(argv) != len(expected) or len(expected) not in (3, 4)
            or not all(isinstance(v, str) for v in argv + expected)
            or expected[2] != ('--identity' if len(expected) == 3 else '--request')):
        return False
    paths = (0, 1) if len(expected) == 3 else (0, 1, 3)
    return all(same_helper_path(a, b, windows=windows) if i in paths else a == b
               for i, (a, b) in enumerate(zip(argv, expected)))


def execution_helper_path(plan):
    """Bind the executed helper to its captured repository, never mapper ROOT."""
    if 'repo' not in plan:
        # Historical synthetic fixtures have no versioned execution plan.
        base.require('schema' not in plan, 'execution repository unavailable')
        return str(ROOT / 'tools/validation/incident_readonly_child.py')
    repo = Path(plan['repo'])
    helper = repo / 'tools/validation/incident_readonly_child.py'
    base.require(repo.is_absolute() and not repo.is_symlink() and helper.is_file()
                 and not helper.is_symlink() and helper.resolve().is_relative_to(repo.resolve())
                 and not any(getattr(p.lstat(), 'st_file_attributes', 0) & 0x400
                             for p in (repo, repo / 'tools', repo / 'tools/validation', helper))
                 and base.sha(helper) == plan.get('toolkit', {}).get('incident_readonly_child.py'),
                 'execution helper bytes or path drift')
    return str(helper)


def readonly_helper_argv(item, expected, plan):
    windows = plan['platform'] == 'Windows'
    argv = ordinary_command_argv(item['command'], windows=windows,
                                 shell_identity=plan.get('shell'))
    matches = helper_argv_matches(argv, expected, windows=windows) and len(expected) == 4
    if matches and windows:
        matches = (same_helper_path(expected[0], plan['python'], windows=True)
                   and same_helper_path(expected[1], execution_helper_path(plan), windows=True))
    elif matches:
        helper = (Path(execution_helper_path(plan)) if 'repo' in plan else
                  code_mode.execution_tool('incident_readonly_child.py'))
        matches = (Path(argv[0]).resolve() == Path(plan['python']).resolve()
                   and Path(argv[1]).resolve() == helper.resolve())
    if matches and windows and plan.get('schema') in (
            'incident-host-plan/v1', 'incident-host-plan/v2', 'incident-host-plan/v2-full',
            'incident-host-plan/v2-full-code-mode', 'incident-host-plan/' + SPLIT_VERSION):
        request_path = Path(plan['cwd']) / ('incident-request-' + Path(plan['output']).name + '.json')
        matches = same_helper_path(expected[3], str(request_path), windows=True)
    base.require(matches, 'readonly tool argv differs')
    return argv


def principal_observation(stage, inventory, plan):
    item = command_observation(stage, inventory, plan)
    argv = ordinary_command_argv(item['command'], windows=True, shell_identity=plan.get('shell'))
    expected = [plan['python'], execution_helper_path(plan), '--identity']
    base.require(helper_argv_matches(argv, expected, windows=True)
                 and item['exitCode'] == 0, 'principal tool command differs')
    record = json.loads(item['aggregatedOutput'])
    base.require(isinstance(record, dict) and set(record) == {'schema', 'sid', 'pid', 'platform'}
                 and record['schema'] == 'incident-child-principal/v1'
                 and record['platform'] == 'Windows' and type(record['pid']) is int
                 and record['pid'] > 0 and isinstance(record['sid'], str)
                 and re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+', record['sid']),
                 'invalid observed child principal')
    return record['sid']


def make_fixture(plan, stage, item, root, *, inventory, principal=None, ownership=None):
    argv = status_argv(item, stage, plan)
    binding = cg.parse_checkpoint_status_option_bindings(argv[3:])
    command_observation(stage, inventory, plan)
    status_output(item, stage, plan, inventory=inventory)
    target = root / 'sessions-v2' / stage['thread']
    target.parent.mkdir(parents=True)
    copied = copy_session(plan, stage['thread'], target)
    base.require(copied['content_hash'] == state_for(stage)['content_hash'], 'query snapshot changed')
    token = binding['--token'][0]
    if token == '[REDACTED_SECRET]':
        # Only the trusted prompt Hook is an exact bound authority source.
        token = hook_control_token(stage, inventory, plan, copied)
    cg.completion_attempt_for(copied, stage['turn'], token)
    lock = root / 'sessions-v2' / '.locks' / (stage['thread'] + '.lock')
    lock.parent.mkdir()
    live_lock = Path(plan['data_root']) / 'sessions-v2' / '.locks' / lock.name
    base.require(live_lock.is_file() and not live_lock.is_symlink(), 'actual lock witness unavailable')
    shutil.copy2(live_lock, lock)
    # Rewrite only the cloned data-root argument; preserve exact session/turn/token.
    argv = [*argv[:3], '--data-dir', str(root), '--session-id', stage['thread'],
            '--turn-id', stage['turn'], '--token', token, '--commands']
    if plan['platform'] == 'Windows':
        base.require(isinstance(principal, str), 'observed Windows child principal required')
    v2 = is_v2(profile_for_plan(plan))
    restriction = (child.prepare_read_transaction(root, sid=principal, ownership=ownership)
                   if v2 else child.restrict(root, sid=principal))
    request = {'schema': 'incident-readonly-request/v2' if v2 else 'incident-readonly-request/v1', 'fixture': str(root),
               'lock': str(lock), 'argv': argv, 'restriction': restriction,
               'inventory': child.inventory(root), 'turn': stage['turn'],
               'state_revision': copied['content_hash']}
    request['request_sha256'] = child.request_identity_v2(request) if v2 else plan_identity(request)
    return request


def state_for(stage):
    return cg.read_only_committed_state(Path(stage['snapshot']))


def parked_wait(before, paused):
    base.require(paused['work_units'][-1]['id'] == before['work_units'][-1]['id'],
                 'work unit changed')
    base.require(paused['work_units'][-1]['status'] == 'awaiting_user', 'pause not parked')
    waits = [r for r in paused['wait_conditions'] if r['status'] == 'waiting']
    base.require(len(waits) == 1 and waits[0].get('subject_sha256') is None, 'ordinary pause required')
    return waits[0]


def resume_oracle(before, paused, resumed):
    wait = parked_wait(before, paused)
    base.require(resumed['work_units'][-1]['id'] == before['work_units'][-1]['id'], 'work unit changed')
    base.require(resumed['work_units'][-1]['status'] == 'active', 'resume not active')
    pending = {r['id'] for r in before['requirements'] if r['status'] == 'pending'}
    base.require(pending and pending <= {r['id'] for r in resumed['requirements']
                                        if r['status'] == 'pending'}, 'old pending lost')
    match = [r for r in resumed['wait_conditions'] if r['condition_id'] == wait['condition_id']]
    base.require(len(match) == 1 and match[0]['status'] == 'released'
                 and match[0]['raised_by_source'] == wait['raised_by_source']
                 and match[0]['source_clause_sha256'] == wait['source_clause_sha256']
                 and match[0]['released_by_source'] == resumed['prompts'][-1]['id'],
                 'resume provenance differs')


def typed_waits(state):
    waits = {r['condition_id']: r for r in state['wait_conditions']
             if r['status'] == 'waiting' and r.get('subject_sha256')}
    base.require(waits, 'typed wait absent')
    return waits


def pause_oracle(before, paused, resumed, typed, typed_before=None):
    resume_oracle(before, paused, resumed)
    current = typed_waits(typed)
    if typed_before is not None:
        base.require(all(k in current and current[k]['raised_by_source'] == v['raised_by_source']
                         and current[k]['subject_sha256'] == v['subject_sha256']
                         for k, v in typed_waits(typed_before).items()), 'typed wait provenance lost')


def verify_stage_state(stage):
    state = state_for(stage)
    base.require(state['session']['id'] == stage['thread'], 'state session differs')
    base.require(state['prompts'] and state['prompts'][-1]['sha256'] == stage['prompt_sha256'],
                 'prompt differs from captured authority')
    valid, _ = cg.read_only_authority_sources_valid(Path(stage['snapshot']), state)
    base.require(valid, 'snapshot authority unavailable')
    return state


def verify_stop_capture(directory, plan, receipt):
    if is_full(profile_for_plan(plan)) or 'cli_adoption' in plan:
        base.require(read_subject(directory / 'plan.json') == dict(plan, schema='stop-host-plan/v1'),
                     'full Stop execution plan differs')
    def responses(name):
        rows = [json.loads(line) for line in (directory / name / 'rpc.jsonl').read_text().splitlines()]
        return rows, [r['message'] for r in rows if r['direction'] == 'response']
    first_log, first = responses('first')
    _, cold = responses('cold')
    def turns(rows):
        compacts = {r['params']['turnId'] for r in rows if r.get('method') == 'item/completed'
                    and r.get('params', {}).get('item', {}).get('type') == 'contextCompaction'}
        return [(r['params']['threadId'], r['params']['turn']['id']) for r in rows
                if r.get('method') == 'turn/completed'
                and r['params']['turn']['status'] == 'completed'
                and r['params']['turn']['id'] not in compacts]
    a, b = turns(first), turns(cold)
    base.require(len(a) == 3 and len(b) == 2, 'base turn observations incomplete')
    # The compaction idle boundary need not emit a business turn/completed.
    # first: three positive business turns; cold: continuation and negative.
    inventory = next(r['result']['data'][0]['hooks'] for r in first
                     if 'result' in r and isinstance(r['result'], dict) and 'data' in r['result'])
    inventory = {h['eventName']: h for h in inventory}
    base.require(set(inventory) == base.EVENTS
                 and all(h.get('trustStatus') == 'trusted' and h.get('enabled') is True
                         and h.get('source') == 'plugin'
                         and Path(h['sourcePath']).resolve() == Path(plan['plugin_root']) / 'hooks/hooks.json'
                         for h in inventory.values()), 'base trusted inventory differs')
    positive = [base.hook_runs(first, t, u, inventory) for t, u in a[:3]]
    positive.append(base.hook_runs(cold, *b[0], inventory))
    negative = base.hook_runs(cold, *b[1], inventory)
    compact_index = next(i for i, r in enumerate(first_log)
                         if r['direction'] == 'request' and r['message'].get('method') == 'thread/compact/start')
    compact_rows = [r['message'] for r in first_log[compact_index + 1:] if r['direction'] == 'response']
    base.require(base.compact_complete(compact_rows, a[0][0], inventory), 'base compaction absent')
    base.require(any(r.get('method') == 'hook/completed' and r['params'].get('threadId') == b[0][0]
                     and r['params']['run']['eventName'] == 'sessionStart'
                     and r['params']['run']['status'] == 'completed' for r in cold), 'cold SessionStart absent')
    states = [base.read_json(directory / name) for name in
              ('before-compact.json', 'after-resume.json', 'negative-state.json')]
    for state in states:
        cg.validate_state_integrity(state)
    base.verdict(positive, negative, *states, receipt['cleanups'])
    base.require(base.read_json(directory / 'result.json') == receipt, 'base receipt differs')
    base.require(receipt['cli_sha256'] == plan['cli_sha256'], 'base CLI differs')
    if 'cli_adoption' in plan or 'cli_adoption' in receipt:
        base.require(receipt.get('cli_version') == plan.get('cli_version')
                     and receipt.get('cli_adoption') == cli_adoption.identity(plan),
                     'base CLI adoption differs')


def public_source(identity):
    result = {k: identity.get(k) for k in ('head', 'prepared_source_sha256')}
    base.require(isinstance(result['head'], str) and re.fullmatch(r'[0-9a-f]{40}', result['head'])
                 and isinstance(result['prepared_source_sha256'], str)
                 and re.fullmatch(r'[0-9a-f]{64}', result['prepared_source_sha256']), 'invalid source identity')
    return result


def retained_mapping_schema(profile, subject):
    if is_code(profile):
        return 'retained-code-mode-capture/v1'
    if profile == PROFILE_FULL_SPLIT and subject.get('backend_contract') == windows_backends.OFFICIAL_CONTRACT:
        return 'retained-windows-split-capture/v1'
    return None


def map_capture(capture, *, mapper_identity=None, directory=None):
    profile = profile_for_plan(capture['plan'])
    version = profile_version(profile)
    base.require(capture.get('schema') == 'incident-host-capture/' + version, 'wrong capture')
    base.require(capture.get('origin') in ('native', 'synthetic'), 'unknown execution origin')
    plan = capture['plan']
    cli_adoption.validate(plan, legacy_versions={'codex-cli 0.160.0'}, require_native=capture['origin'] == 'native')
    backend_journals = {}
    if profile == PROFILE_FULL_SPLIT:
        base.require(capture['origin'] == 'native', 'split acceptance requires a native capture')
        if not (capture.get('failure_class') or capture.get('pending_class')):
            base.require(directory is not None, 'split acceptance requires original journals')
            backend_journals = verify_split_capture(directory, capture)
        else:
            capture = {**capture, 'stages': {}, 'inventory': {}, 'cleanups': [], 'stop_result': None}
    else:
        base.require('backend_bindings' not in capture, 'backend bindings require split profile')
    if is_full(profile):
        full_scope(capture)
        base.require(plan.get('manifest_sha256') == base.sha(manifest_for_plan(plan)), 'full manifest adoption differs')
    else:
        base.require(not any(k in capture for k in ('gate_scope', 'required_gates')),
                     'legacy capture cannot adopt full scope')
    base.require(capture['plan_sha256'] == plan_identity(plan), 'plan binding changed')
    gates = {name: 'pending' for name in GATES}
    observations = {}
    inventory = capture.get('inventory', {})
    if set(inventory) == base.EVENTS:
        expected_path = Path(plan['plugin_root']) / 'hooks/hooks.json'
        base.require(all(v.get('trustStatus') == 'trusted' and v.get('enabled') is True
                         and v.get('source') == 'plugin' and v.get('handlerType') == 'command'
                         and v.get('eventName') == event and isinstance(v.get('key'), str)
                         and v['key'] and isinstance(v.get('currentHash'), str) and v['currentHash']
                         and type(v.get('displayOrder')) is int and type(v.get('async')) is bool
                         and Path(v.get('sourcePath', '')).resolve() == expected_path
                         for event, v in inventory.items()), 'untrusted or foreign Hook')
        gates['hook_trust'] = 'passed'
    stages = capture.get('stages', {})
    manifest = base.read_json(manifest_for_plan(plan))
    for name, stage in stages.items():
        base.require(name in manifest['prompts'] or name in ('readonly', 'principal')
                     or (is_v2(profile) and name in manifest['helper_prompt_templates']), 'unknown stage')
        if name in manifest['prompts']:
            expected = hashlib.sha256(manifest['prompts'][name].encode()).hexdigest()
            base.require(stage['prompt_sha256'] == expected, 'scenario prompt differs')
        verify_stage_state(stage)
    if all(name in stages for name in ('pending', 'pause', 'resume', 'typed', 'typed_resume')):
        base.require(len({stages[n]['thread'] for n in ('pending', 'pause', 'resume', 'typed', 'typed_resume')}) == 1
                     and len({stages[n]['turn'] for n in ('pending', 'pause', 'resume', 'typed', 'typed_resume')}) == 5,
                     'pause execution scope differs')
        for name in ('pending', 'pause', 'resume', 'typed', 'typed_resume'):
            s = stages[name]
            base.require(all(h['status'] == 'completed' for h in base.hook_runs(
                s['rows'], s['thread'], s['turn'], inventory)), 'pause Stop failed')
        pause_oracle(*(state_for(stages[n]) for n in ('pending', 'pause', 'resume', 'typed_resume', 'typed')))
        gates.update(pause_same_unit='passed', resume_provenance_pending='passed', typed_wait_retained='passed')
    if 'status' in stages:
        s = stages['status']
        item = command_observation(s, inventory, plan)
        status_output(item, s, plan, inventory=inventory)
        gates['status_cli_posttool'] = 'passed'
    if all(n in stages for n in ('status', 'unknown', 'missing')):
        base.require(len({stages[n]['thread'] for n in ('status', 'unknown', 'missing')}) == 1
                     and len({stages[n]['turn'] for n in ('status', 'unknown', 'missing')}) == 3,
                     'diagnostic execution scope differs')
        base.require(all(state_for(stages[n])['evidence'] == state_for(stages['status'])['evidence']
                         for n in ('unknown', 'missing')), 'diagnostic became business evidence')
        observations = {name: rejection_observation(stages[name], inventory, plan, name)
                        for name in ('unknown', 'missing')}
        if all(v['status'] == 'passed' for v in observations.values()):
            gates['status_negative_controls'] = 'passed'
    if is_v2(profile) and 'readonly' in stages:
        names = ('baseline_original', 'baseline_granted', 'baseline_denied')
        base.require(all(n in stages for n in (*names, 'principal')),
                     'native baseline stages unavailable')
        base.require(len({stages[n]['thread'] for n in (*names, 'principal', 'readonly')}) == 1
                     and len({stages[n]['turn'] for n in (*names, 'principal', 'readonly')}) == 5,
                     'native baseline actor scope differs')
        sid = principal_observation(stages['principal'], inventory, plan)
        requests = capture.get('baseline_requests', {})
        base.require(set(requests) == set(names) and set(capture.get('baseline_tool_argv', {})) == set(names),
                     'baseline bindings incomplete')
        snapshots = set()
        fixed_request = None
        flags = ((False, False), (True, False), (True, True))
        for name, (granted, denied) in zip(names, flags):
            request = requests[name]
            restriction = request['restriction']
            base.require(restriction.get('grant_complete') is granted
                         and restriction.get('deny_complete') is denied, 'baseline transaction phase differs')
            child.verify_original_snapshot(restriction)
            fixed = {k: v for k, v in request.items() if k not in ('request_sha256', 'phase', 'restriction')}
            if fixed_request is None:
                fixed_request = fixed
            base.require(fixed == fixed_request, 'baseline copied request subject differs')
            base.require(request['restriction']['sid'] == sid, 'baseline principal differs')
            snapshots.add(request['restriction']['original_snapshot_sha256'])
            baseline_observation(stages[name], inventory, plan, request,
                                 capture['baseline_tool_argv'][name], name)
        final_request = capture.get('readonly_request', {})
        base.require(final_request.get('schema') == 'incident-readonly-request/v2'
                     and final_request.get('phase') == 'readonly'
                     and final_request['restriction']['sid'] == sid
                     and snapshots == {final_request['restriction']['original_snapshot_sha256']},
                     'readonly transaction binding differs')
        base.require({k: v for k, v in final_request.items()
                      if k not in ('request_sha256', 'phase', 'restriction')} == fixed_request,
                     'final copied request subject differs')
        expected_principal = helper_prompt(plan, [plan['python'], execution_helper_path(plan), '--identity'], 'principal')
        base.require(stages['principal']['prompt_sha256'] == hashlib.sha256(expected_principal.encode()).hexdigest(),
                     'principal helper prompt differs')
        restoration = capture.get('fixture_restoration', {})
        base.require(restoration.get('status') == 'verified'
                     and restoration.get('original_snapshot_sha256') in snapshots,
                     'original fixture restoration unavailable')
        child.verify_original_snapshot(final_request['restriction'])
        base.require(set(restoration) == {'status', 'original_snapshot_sha256', 'collector_sid', 'descriptor_contracts', 'inventory'}
                     and restoration['collector_sid'] == final_request['restriction']['collector_sid']
                     and restoration['descriptor_contracts'] == {k: child.descriptor_contract(v) for k, v in
                                                                 final_request['restriction']['original_dacls'].items()}
                     and restoration['inventory'] == final_request['restriction']['original_inventory']
                     and base.read_json(Path(plan['output']) / 'fixture-restoration.json') == restoration,
                     'original restoration readback receipt differs')
        expected = helper_prompt(plan, capture['readonly_tool_argv'], 'readonly')
        base.require(stages['readonly']['prompt_sha256'] == hashlib.sha256(expected.encode()).hexdigest(),
                     'readonly helper prompt differs')
        if profile == PROFILE_FULL_SPLIT:
            verify_split_fixture(stages['status'], final_request, plan, inventory, directory)
    if 'readonly' in stages and capture.get('readonly_request'):
        item = command_observation(stages['readonly'], inventory, plan)
        readonly_helper_argv(item, capture['readonly_tool_argv'], plan)
        base.require(item['exitCode'] == 0, 'readonly child tool failed')
        record = json.loads(item['aggregatedOutput'])
        if plan['platform'] == 'Windows':
            base.require('principal' in stages and stages['principal']['thread'] == stages['readonly']['thread']
                         and stages['principal']['turn'] != stages['readonly']['turn'],
                         'principal observation scope differs')
            sid = principal_observation(stages['principal'], inventory, plan)
            base.require(capture['readonly_request']['restriction']['sid'] == sid,
                         'restriction differs from observed tool principal')
        gates['restricted_child_readonly'] = child.judge(record, capture['readonly_request'])
    stop = capture.get('stop_result')
    if stop and stop.get('status') == 'passed':
        # This is an independently validated base profile receipt, not a boolean.
        base.require(stop.get('schema') == 'stop-host-acceptance/v1'
                     and stop.get('source') == plan['source']
                     and stop.get('runtime_sha256') == plan['runtime_sha256'], 'base receipt subject differs')
        verify_stop_capture(Path(capture['stop_directory']), plan, stop)
        gates.update(positive_negative_stop='passed', compaction_cold_resume='passed')
    cleanups = capture.get('cleanups', [])
    if len(cleanups) == (len(SPLIT_JOURNALS) if profile == PROFILE_FULL_SPLIT else 1 if profile == PROFILE_V2 else 3):
        base.require(all(c and c.get('owned_process_exited') is True
                         and c.get('owned_tree_no_running_members') is True
                         and not c.get('process_group_cleanup_error') for c in cleanups), 'owned cleanup failed')
        gates['cleanup'] = 'passed'
    status = 'passed' if all(v == 'passed' for v in gates.values()) else 'pending'
    if any(v == 'failed' for v in gates.values()) or capture.get('failure_class'):
        status = 'failed'
    if capture.get('pending_class') and not (is_v2(profile) and capture.get('failure_class')):
        status = 'pending'
    result = {'schema': 'incident-host-acceptance/' + version, 'gate_profile': profile,
            'status': status, 'evidence_scope': capture['origin'], 'gates': gates,
            'rejection_observations': observations,
            'execution_identity': {'source': public_source(plan['source']), 'runtime_sha256': plan['runtime_sha256'],
                                   'cli_sha256': plan['cli_sha256'], 'cli_version': plan['cli_version'],
                                   'toolkit': plan['toolkit'], 'plan_sha256': capture['plan_sha256'],
                                   'platform': plan['platform'], 'model': plan.get('model'), 'effort': plan.get('effort')},
            'mapping_identity': {'source': public_source((mapper_identity or {}).get('source', prepared_source_identity(ROOT))),
                                 'toolkit': (mapper_identity or {}).get('toolkit', toolkit(plan))},
            'native_acceptance': status if capture['origin'] == 'native' else 'not_run',
            'limitations': ['Bounded live scenarios, not original incident state.',
                            'Read-only witness queries an exact session copy in a collector-owned fixture.',
                            'Hook statuses are official observations, not OS exit codes.',
                            'Configured model identity is not per-turn execution telemetry.']}

    if is_v2(profile):
        required = (list(GATES) if is_full(profile) else
                    ['hook_trust', 'status_cli_posttool', 'status_negative_controls', 'restricted_child_readonly', 'cleanup'])
        result['required_gates'] = required
        result['scenario_status'] = ('failed' if status == 'failed' else 'pending'
                                     if capture.get('pending_class') or any(gates[k] != 'passed' for k in required)
                                     else 'passed')
    if is_full(profile):
        result['gate_scope'] = 'full'
        result['execution_identity'].update(gate_scope='full', required_gates=list(GATES))
    if profile == PROFILE_FULL_SPLIT:
        result['execution_identity'].update(backend_contract=plan['backend_contract'],
                                            backend_journal_sha256=backend_journals)
    if is_code(profile):
        result['execution_identity']['command_observation_contract'] = plan['command_observation_contract']
    if 'cli_adoption' in plan:
        result['execution_identity']['cli_adoption'] = cli_adoption.identity(plan)
    return result


def validate_result(result):
    profile = result.get('gate_profile')
    base.require(profile in (PROFILE, PROFILE_CODE, PROFILE_V2, PROFILE_FULL, PROFILE_FULL_CODE, PROFILE_FULL_SPLIT)
                 and result.get('schema') == 'incident-host-acceptance/' +
                 profile_version(profile), 'wrong result profile')
    execution = result.get('execution_identity', {})
    base.require(isinstance(execution, dict), 'invalid execution identity')
    mapping = result.get('mapping_identity')
    base.require(isinstance(mapping, dict), 'invalid mapping identity')
    if 'retained_capture' in mapping:
        schema = retained_mapping_schema(profile, execution)
        plan_sha = execution.get('plan_sha256')
        base.require(schema is not None and isinstance(plan_sha, str)
                     and re.fullmatch(r'[0-9a-f]{64}', plan_sha)
                     and mapping['retained_capture'] == {'schema': schema, 'execution_plan_sha256': plan_sha},
                     'retained capture identity differs')
    if is_code(profile):
        expected = code_mode.adoption(windows=profile == PROFILE_FULL_CODE)
        if 'retained_capture' in mapping:
            original_tools = execution.get('toolkit', {})
            expected['toolkit'] = {name: original_tools.get(name) for name in code_mode.TOOLKIT}
            base.require(all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value)
                             for value in expected['toolkit'].values()),
                         'retained execution toolkit unavailable')
        base.require(execution.get('command_observation_contract') == expected,
                     'code-mode result contract differs')
    else:
        base.require('command_observation_contract' not in execution, 'code-mode export requires profile')
    if profile == PROFILE_FULL_SPLIT:
        journals = execution.get('backend_journal_sha256')
        base.require(execution.get('backend_contract') in (
                         windows_backends.CONTRACT, windows_backends.OFFICIAL_CONTRACT)
                     and execution.get('cli_version') == cli_adoption.VERSION
                     and result.get('evidence_scope') == 'native' and isinstance(journals, dict)
                     and (set(journals) == set(SPLIT_JOURNALS)
                          or (not journals and result.get('status') != 'passed'))
                     and all(isinstance(v, str) and re.fullmatch(r'[0-9a-f]{64}', v)
                             for v in journals.values())
                     and len(set(journals.values())) == len(journals), 'split backend result proof differs')
        windows_backends.model_provider(execution)
    else:
        base.require(not {'backend_contract', 'backend_journal_sha256'} & execution.keys(),
                     'backend export requires split profile')
    if ('cli_adoption' in execution or execution.get('cli_version') == cli_adoption.VERSION
            or is_full(profile)):
        cli_adoption.validate_export(execution)
        base.require(result.get('evidence_scope') != 'native'
                     or execution.get('cli_adoption', {}).get('capability_evidence_scope', 'native_zero_turn') == 'native_zero_turn',
                     'synthetic capability cannot certify native result')
    if is_v2(profile):
        observations = result.get('rejection_observations', {})
        base.require(isinstance(observations, dict) and set(observations) <= {'unknown', 'missing'},
                     'invalid rejection export kinds')
        for kind, value in observations.items():
            base.require(isinstance(value, dict) and set(value) <=
                         {'status', 'branch', 'cli', 'posttool', 'parser_kind', 'parser_signature_sha256',
                          'host_exit', 'source_exit'} and value.get('source_exit') == 'not_observed',
                         'non-allowlisted rejection export or source exit')
            host = value.get('host_exit')
            base.require(isinstance(host, dict) and set(host) == {'observed', 'value'}
                         and type(host['observed']) is bool
                         and ((host['observed'] and type(host['value']) is int and host['value'] in (1, 2))
                              or (not host['observed'] and host['value'] is None)), 'invalid observed host exit')
            if value.get('branch') == 'powershell_host1_parser_post_blocked':
                base.require(value.get('status') == 'passed' and host == {'observed': True, 'value': 1}
                             and value.get('parser_kind') == kind
                             and isinstance(value.get('parser_signature_sha256'), str)
                             and re.fullmatch(r'[0-9a-f]{64}', value['parser_signature_sha256']),
                             'unbound host parser export')
    base.require(result.get('status') in ('passed', 'failed', 'pending'), 'invalid result status')
    base.require(result.get('evidence_scope') in ('native', 'synthetic'), 'invalid result scope')
    gates = result.get('gates')
    base.require(isinstance(gates, dict) and set(gates) == set(GATES)
                 and all(v in ('passed', 'failed', 'pending') for v in gates.values()), 'invalid result gates')
    base.require(result['status'] != 'passed' or set(gates.values()) == {'passed'}, 'partial green result')
    if is_v2(profile):
        required = (list(GATES) if is_full(profile) else
                    ['hook_trust', 'status_cli_posttool', 'status_negative_controls', 'restricted_child_readonly', 'cleanup'])
        base.require(result.get('required_gates') == required and result.get('scenario_status') in ('passed', 'pending', 'failed')
                     and (result['scenario_status'] != 'passed' or all(gates[k] == 'passed' for k in required)),
                     'invalid affected scenario result')
    else:
        base.require(not any(k in result for k in ('required_gates', 'scenario_status')), 'v1 scenario override rejected')
    if is_full(profile):
        full_scope(result)
        full_scope(result.get('execution_identity', {}))
        base.require(result['scenario_status'] == result['status'], 'full scenario status differs')
        identity = result['execution_identity']
        base.require(isinstance(identity.get('plan_sha256'), str)
                     and re.fullmatch(r'[0-9a-f]{64}', identity['plan_sha256'])
                     and identity.get('platform') == 'Windows', 'full execution identity differs')
    else:
        base.require('gate_scope' not in result and not any(k in result.get('execution_identity', {})
                     for k in ('gate_scope', 'required_gates')), 'legacy result cannot adopt full scope')
    native = result.get('native_acceptance')
    base.require(native == ('not_run' if result['evidence_scope'] == 'synthetic' else result['status']),
                 'native result scope mismatch')
    allowed = {'schema', 'gate_profile', 'status', 'evidence_scope', 'gates',
               'execution_identity', 'mapping_identity', 'native_acceptance', 'limitations',
               'capture_catalog_sha256', 'failure_class', 'rejection_observations', 'required_gates', 'scenario_status', 'gate_scope'}
    base.require(set(result) <= allowed and isinstance(result.get('execution_identity'), dict)
                 and isinstance(result.get('mapping_identity'), dict), 'non-allowlisted export')
    return result


def collect(plan, output, *, supplemental=False):
    profile = profile_for_plan(plan)
    cli_adoption.validate(plan, legacy_versions={'codex-cli 0.160.0'}, require_native=True)
    base.require(not (is_full(profile) and supplemental), 'full profile cannot supplement')
    split = profile == PROFILE_FULL_SPLIT
    official = split and windows_backends.model_provider(plan) == 'openai'
    if split:
        split_preflight(plan, output.with_name(output.name + '.backend-preflight'))
    output.mkdir(mode=0o700)
    capture = {'schema': 'incident-host-capture/' + profile_version(profile), 'origin': 'native',
               'plan': plan, 'plan_sha256': plan_identity(plan), 'stages': {}, 'cleanups': []}
    if is_full(profile):
        capture.update(gate_scope='full', required_gates=list(GATES))
    if split:
        capture['backend_bindings'] = {}
    write_new(output / 'plan.json', plan)
    client = probe = None
    request = None
    fixture = Path(plan['cwd']) / ('incident-readonly-' + output.name)
    try:
        (output / 'rpc').mkdir()
        if split:
            (output / 'probe-rpc').mkdir()
            client = open_split_client(plan, output / 'rpc', 'primary', capture['backend_bindings'], capture['cleanups'])
            probe = open_split_client(plan, output / 'probe-rpc', 'acl', capture['backend_bindings'], capture['cleanups'])
            base.require(client.inventory == probe.inventory, 'split Hook inventories differ')
        else:
            client = Client(plan, output / 'rpc')
        capture['inventory'] = client.inventory
        manifest = base.read_json(manifest_for_plan(plan))
        def turn(name, thread, prompt=None, helper_argv=None):
            base.require(name not in capture['stages'], 'duplicate collected stage')
            actor = probe if split and name in ACL_STAGES else client
            stage = actor.observed_turn(thread, prompt or manifest['prompts'][name])
            dest = output / ('snapshot-' + name)
            copy_session(plan, thread, dest)
            stage['snapshot'] = str(dest)
            if is_code(profile):
                stage['name'] = name
                if helper_argv is not None:
                    stage['helper_argv'] = helper_argv
                if name in (code_mode.COMMAND_STAGES if profile == PROFILE_FULL_CODE else ('status', 'unknown', 'missing', 'readonly')):
                    command = (expected_code_command(stage, client.inventory, plan) if profile == PROFILE_FULL_CODE
                               else discovery_command(stage, client.inventory, plan) +
                               {'status': ' --commands', 'unknown': ' --unknown-status-option',
                                'missing': ' --item --commands'}[name] if name != 'readonly' else spelling)
                    stage['code_mode_evidence'] = code_mode.capture(plan, stage, client.thread_records[thread],
                                                                   output / 'rpc/rpc.jsonl', command)
                    archive = output / ('rollout-' + name + '.jsonl')
                    with archive.open('xb') as stream:
                        stream.write(stage['code_mode_evidence']['rollout'].encode())
                    if os.name != 'nt':
                        archive.chmod(0o600)
            capture['stages'][name] = stage
            if official:
                verify_stage_state(stage)
            return stage
        if not supplemental and profile != PROFILE_V2:
            thread = client.start()
            states = {}
            for name in ('pending', 'pause', 'resume', 'typed', 'typed_resume'):
                stage = turn(name, thread)
                if official:
                    base.require(all(h['status'] == 'completed' for h in base.hook_runs(
                        stage['rows'], stage['thread'], stage['turn'], client.inventory)), 'pause Stop failed')
                    states[name] = state_for(stage)
                    if name == 'pending':
                        base.require(any(r['status'] == 'pending' for r in states[name]['requirements']),
                                     'pending work absent')
                    elif name == 'pause':
                        parked_wait(states['pending'], states[name])
                    elif name == 'resume':
                        resume_oracle(states['pending'], states['pause'], states[name])
                    elif name == 'typed':
                        typed_waits(states[name])
                    else:
                        pause_oracle(states['pending'], states['pause'], states['resume'],
                                     states[name], states['typed'])
        instructions = ('This is a bounded diagnostic test. Use exactly one ordinary shell tool per turn. '
                        'Use the exact latest Context Guard checkpoint-status binding from its recovery packet. '
                        'Run the specified query as a standalone command, no helper or shell chain. '
                        'Keep all diagnostic output private. Final answer: 诊断结束，验收仍等待。')
        if is_code(profile):
            instructions += base.read_json(manifest_for_plan(plan))['transparent_fixture_instructions'].format(
                cwd=json.dumps(plan['cwd'], ensure_ascii=True),
                shell=json.dumps(plan.get('shell', {}).get('path'), ensure_ascii=True))
        status_thread = client.start(instructions)
        s = turn('status', status_thread)
        item = command_observation(s, client.inventory, plan)
        status_output(item, s, plan, inventory=client.inventory)
        probe_instructions = ('Execute exactly the requested standalone ordinary shell command. '
                                    'Do not escalate permissions. Keep output private. '
                                    'Final answer: 只读探针结束，验收仍等待。')
        if is_code(profile):
            probe_instructions += base.read_json(manifest_for_plan(plan))['transparent_fixture_instructions'].format(
                cwd=json.dumps(plan['cwd'], ensure_ascii=True),
                shell=json.dumps(plan.get('shell', {}).get('path'), ensure_ascii=True))
        probe_thread = (probe or client).start(probe_instructions)
        principal = None
        if plan['platform'] == 'Windows':
            identity_argv = [plan['python'], str(ROOT / 'tools/validation/incident_readonly_child.py'), '--identity']
            observed = turn('principal', probe_thread, 'Run this exact ordinary tool command once: & '
                            + cg.shell_join(identity_argv), helper_argv=identity_argv)
            principal = principal_observation(observed, client.inventory, plan)
        fixture.mkdir(mode=0o700)
        ownership = {k: plan[k] for k in ('cwd', 'output', 'repo', 'home', 'plugin_root', 'data_root')}
        ownership.update(created_exclusively=True,
                         root_identity=[fixture.lstat().st_dev, fixture.lstat().st_ino])
        request = make_fixture(plan, s, item, fixture, inventory=client.inventory, principal=principal,
                               ownership=ownership if is_v2(profile) else None)
        transaction = request['restriction']
        if is_v2(profile):
            capture['baseline_requests'], capture['baseline_tool_argv'] = {}, {}
            baseline_record, current = None, None
            for name in ('baseline_original', 'baseline_granted', 'baseline_denied'):
                if name != 'baseline_original':
                    child.apply_read_transaction(fixture, transaction,
                                                 'grant' if name == 'baseline_granted' else 'deny',
                                                 baseline_record=baseline_record, baseline_request=current)
                current = phase_request(request, name)
                path = Path(plan['cwd']) / ('incident-request-' + output.name + '-' + name + '.json')
                write_new(path, current)
                argv = [plan['python'], execution_helper_path(plan), '--request', str(path), '--baseline']
                capture['baseline_requests'][name] = current
                capture['baseline_tool_argv'][name] = argv
                observed = turn(name, probe_thread, helper_prompt(plan, argv, name), helper_argv=argv)
                baseline_record = baseline_observation(observed, client.inventory, plan, current, argv, name)
            request = phase_request(request, 'readonly')
        request_path = Path(plan['cwd']) / ('incident-request-' + output.name + '.json')
        write_new(request_path, request)
        capture['readonly_request'] = request
        for name in ('unknown', 'missing'):
            observed = turn(name, status_thread)
            if split:
                base.require(rejection_observation(observed, client.inventory, plan, name)['status'] == 'passed',
                             'split negative control failed')
                if official:
                    base.require(state_for(observed)['evidence'] == state_for(s)['evidence'],
                                 'diagnostic became business evidence')
        tool_argv = [plan['python'], str(ROOT / 'tools/validation/incident_readonly_child.py'),
                     '--request', str(request_path)]
        capture['readonly_tool_argv'] = tool_argv
        # The same probe thread supplies the Windows principal and actual witness.
        spelling = cg.shell_join(tool_argv)
        if plan['platform'] == 'Windows':
            spelling = '& ' + spelling
        observed = turn('readonly', probe_thread, helper_prompt(plan, tool_argv, 'readonly')
                        if is_v2(profile) else 'Run this exact ordinary tool command once: ' + spelling,
                        helper_argv=tool_argv)
        if split:
            item = command_observation(observed, probe.inventory, plan)
            readonly_helper_argv(item, tool_argv, plan)
            base.require(item['exitCode'] == 0
                         and child.judge(json.loads(item['aggregatedOutput']), request) == 'passed',
                         'split readonly witness failed')
            with (output / 'authored-readonly-request.json').open('xb') as stream:
                stream.write(request_path.read_bytes())
            base.require(read_subject(output / 'authored-readonly-request.json', strict=True) == request,
                         'split signed request changed')
        cleanup = client.close()
        capture['cleanups'].append(cleanup)
        client = None
        if official:
            split_cleanup(cleanup, 'primary', split_launch(output / SPLIT_JOURNALS['primary'], 'primary', plan))
        if probe:
            cleanup = probe.close()
            capture['cleanups'].append(cleanup)
            probe = None
            if official:
                split_cleanup(cleanup, 'acl', split_launch(output / SPLIT_JOURNALS['acl'], 'acl', plan))
        if profile != PROFILE_V2:
            shared = dict(plan, schema='stop-host-plan/v1')
            capture['stop_directory'] = str(output / 'stop')
            if split:
                def stop_client(p, directory):
                    return open_split_client(p, directory, 'stop_' + directory.name,
                                             capture['backend_bindings'], capture['cleanups'])
                capture['stop_result'] = base.collect(shared, output / 'stop', client_factory=stop_client,
                                                      fail_fast=official)
            else:
                capture['stop_result'] = base.collect(shared, output / 'stop')
            capture['cleanups'].extend(capture['stop_result']['cleanups'])
            if split and capture['stop_result']['status'] != 'passed':
                kind = capture['stop_result'].get('failure', '').partition(':')[0]
                if kind == 'ObservationPending':
                    raise ObservationPending('official Stop server request retained')
                raise ValueError('split Stop collection failed')
        base.require(prepared_source_identity(ROOT) == plan['source'], 'source changed during run')
        base.require(base.runtime(Path(plan['plugin_root'])) == plan['runtime_sha256'], 'runtime changed during run')
    except (Exception, KeyboardInterrupt) as exc:
        capture['failure_class' if is_v2(profile) and not isinstance(exc, ObservationPending)
                else 'pending_class'] = type(exc).__name__
        # Exception text can contain raw prompts/private commands; private only.
        write_new(output / 'failure.json', {'type': type(exc).__name__, 'detail': str(exc),
                    ('compaction' if isinstance(exc, windows_backends.CompactionLimitError) else 'restriction'):
                    getattr(exc, 'record', None)})
    finally:
        for actor in (client, probe):
            if actor:
                try:
                    capture['cleanups'].append(actor.close())
                except Exception as exc:
                    capture['failure_class'] = type(exc).__name__
        if request:
            try:
                # Restore mutates diagnostics; preserve the exact signed tool request.
                restriction = json.loads(json.dumps(request['restriction']))
                if not restriction.get('restoration_error') and restriction.get('restoration') != 'verified':
                    child.restore(fixture, restriction)
                base.require(not restriction.get('restoration_error'), 'fixture restoration failed')
                if is_v2(profile):
                    capture['fixture_restoration'] = child.restored_transaction_observation(fixture, restriction)
                    write_new(output / 'fixture-restoration.json', capture['fixture_restoration'])
            except Exception as exc:
                capture['pending_class'] = type(exc).__name__
        write_new(output / 'capture.json', capture)
    return capture


@contextmanager
def retained_execution_source(plan, source):
    """Pin the original execution tools without loading or executing old code.

    Only offline mapping adopts this scope. New collection and default mapping
    keep current-toolkit equality. The original plan/capture remain untouched.
    """
    source = Path(source)
    base.require(source.is_absolute() and not source.is_symlink()
                 and source.resolve() != ROOT.resolve()
                 and code_mode._retained_tools.get() is None,
                 'distinct retained execution source required')
    def verify():
        base.require(prepared_source_identity(source) == plan.get('source')
                     and plan['source'].get('dirty_paths') == []
                     and plan['source'].get('renamed_away') == [],
                     'retained execution source identity differs')
        base.require(base.runtime(source) == plan.get('runtime_sha256'),
                     'retained execution runtime differs')
        base.require(toolkit(plan, execution=True) == plan.get('toolkit'),
                     'retained execution toolkit differs')
    tools = source / 'tools/validation'
    base.require(tools.is_dir() and not tools.is_symlink(), 'retained tools unavailable')
    token = code_mode._retained_tools.set(tools)
    try:
        verify()
        profile_for_plan(plan)
        yield verify
    finally:
        code_mode._retained_tools.reset(token)


def map_bundle(directory, output, *, execution_source=None):
    if execution_source is None:
        return _map_bundle(directory, output)
    plan = read_subject(directory / 'capture.json', strict=True).get('plan', {})
    schema = retained_mapping_schema(plan.get('gate_profile'), plan)
    base.require(schema is not None, 'profile does not allow retained mapping')
    with retained_execution_source(plan, execution_source) as verify:
        return _map_bundle(directory, output, retained_verify=verify, retained_schema=schema)


def _map_bundle(directory, output, *, retained_verify=None, retained_schema=None):
    base.require(not output.exists() and output.resolve() != ROOT and ROOT not in output.resolve().parents
                 and directory.resolve() != ROOT
                 and ROOT not in directory.resolve().parents, 'private capture outside source required')
    capture = read_subject(directory / 'capture.json')
    catalog = read_subject(directory / 'artifacts.json', strict=is_full(profile_for_plan(capture.get('plan', {}))))
    if is_full(profile_for_plan(capture.get('plan', {}))):
        base.require(read_subject(directory / 'plan.json') == capture['plan'], 'full plan readback differs')
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
    base.require(set(catalog) == actual - {'artifacts.json', 'result.json'}, 'incomplete artifact catalog')
    for name, digest in catalog.items():
        target = directory / name
        base.require(target.resolve().is_relative_to(directory.resolve()) and not target.is_symlink()
                     and target.is_file() and base.sha(target) == digest, 'capture artifact changed')
    base.require(catalog.get('capture.json') == base.sha(directory / 'capture.json'), 'capture not catalogued')
    if capture.get('stop_directory'):
        base.require(Path(capture['stop_directory']).resolve() == directory.resolve() / 'stop', 'base capture escaped')
    if is_code(profile_for_plan(capture['plan'])):
        code_mode.verify_bundle_sources(directory, capture)
    for s in capture.get('stages', {}).values():
        p = Path(s['snapshot']).resolve()
        base.require(p.is_relative_to(directory.resolve()), 'snapshot outside bundle')
    try:
        result = map_capture(capture, directory=directory)
    except (ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
        minimal = {**capture, 'stages': {}, 'inventory': {}, 'cleanups': [],
                   'stop_result': None, 'failure_class': type(exc).__name__}
        minimal.pop('pending_class', None)
        result = map_capture(minimal)
        result['failure_class'] = type(exc).__name__
    if retained_verify is not None:
        retained_verify()
        result['mapping_identity']['retained_capture'] = {
            'schema': retained_schema,
            'execution_plan_sha256': capture['plan_sha256'],
        }
    validate_result(result)
    result['capture_catalog_sha256'] = base.sha(directory / 'artifacts.json')
    write_new(output, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    run = sub.add_parser('run')
    run.add_argument('--plan', type=Path, required=True)
    run.add_argument('--output', type=Path, required=True)
    run.add_argument('--preflight', action='store_true')
    mapping = sub.add_parser('map')
    mapping.add_argument('--capture-dir', type=Path, required=True)
    mapping.add_argument('--output', type=Path, required=True)
    mapping.add_argument('--execution-source', type=Path,
                         help='Original clean execution checkout for retained code-mode or official Windows split captures')
    make = sub.add_parser('plan')
    for name in ('codex', 'python', 'home', 'cwd', 'plugin-root', 'data-root', 'output'):
        make.add_argument('--' + name, type=Path, required=True)
    make.add_argument('--shell', type=Path)
    make.add_argument('--model', required=True)
    make.add_argument('--local-provider-endpoint')
    make.add_argument('--official-gpt', action='store_true',
                      help='Bind the split profile to built-in OpenAI GPT-6.1 Sol / Medium')
    make.add_argument('--profile', choices=(PROFILE, PROFILE_CODE, PROFILE_V2, PROFILE_FULL_CODE,
                                            PROFILE_FULL_SPLIT), default=PROFILE)
    make.add_argument('--gate-scope', choices=('full',))
    make.add_argument('--negative-observation')
    make.add_argument('--fixture-policy')
    make.add_argument('--plan-file', type=Path, required=True)
    make.add_argument('--cli-adoption', choices=(cli_adoption.CONTRACT,))
    make.add_argument('--cli-capability-receipt', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'plan':
            base.require(bool(args.cli_adoption) == bool(args.cli_capability_receipt),
                         'CLI adoption requires an independently prepared capability receipt')
            win_code = args.profile == PROFILE_FULL_CODE
            split = args.profile == PROFILE_FULL_SPLIT
            v2 = is_v2(args.profile)
            codemode = is_code(args.profile)
            base.require(not (codemode or split) or args.cli_adoption == cli_adoption.CONTRACT,
                         'selected profile requires CLI adoption')
            full = args.gate_scope == 'full'
            base.require((args.local_provider_endpoint is not None) == (split and not args.official_gpt)
                         and (not args.official_gpt or (split and args.model == windows_backends.OFFICIAL_MODEL)),
                         'select the split loopback endpoint or explicit official GPT model')
            base.require(not (win_code or split) or full, 'selected Windows profile requires explicit full scope')
            base.require(not full or v2, 'full scope requires explicit v2 adoption')
            base.require((v2 and args.negative_observation == OBSERVATION_CONTRACTS['negative']
                          and args.fixture_policy == OBSERVATION_CONTRACTS['readonly_fixture'])
                         or (not v2 and args.negative_observation is None and args.fixture_policy is None),
                         'observation contract adoption must be explicit and complete')
            profile = PROFILE_FULL if args.profile == PROFILE_V2 and full else args.profile
            plan = {'schema': 'incident-host-plan/' + profile_version(profile), 'repo': str(ROOT),
                    'source': prepared_source_identity(ROOT), 'runtime_sha256': base.runtime(ROOT),
                    'cli_version': cli_adoption.VERSION if args.cli_adoption else 'codex-cli 0.160.0',
                    'platform': platform.system(),
                    'model': args.model, 'effort': 'medium', 'fresh_data_root': True, 'output': str(args.output.resolve()), 'toolkit': toolkit(), 'manifest_sha256': base.sha(MANIFEST_FULL if full else MANIFEST_V2 if v2 else MANIFEST)}
            if codemode:
                plan.update(gate_profile=PROFILE_FULL_CODE if win_code else PROFILE_CODE, command_observation_contract=code_mode.adoption(windows=win_code))
                plan.update(toolkit=toolkit(plan), manifest_sha256=base.sha(MANIFEST_FULL_CODE if win_code else MANIFEST_CODE))
            if v2:
                base.require(platform.system() == 'Windows', 'v2 observation requires Windows')
                plan.update(gate_profile=profile, observation_contracts=dict(OBSERVATION_CONTRACTS))
                if full:
                    plan.update(gate_scope='full', required_gates=list(GATES))
            if split:
                contract = windows_backends.OFFICIAL_CONTRACT if args.official_gpt else windows_backends.CONTRACT
                plan.update(backend_contract=contract, toolkit=toolkit(plan))
                if not args.official_gpt:
                    plan['local_provider_endpoint'] = windows_backends.validate_local_endpoint(args.local_provider_endpoint)
            for key in ('codex', 'python', 'home', 'cwd', 'plugin_root', 'data_root'):
                plan[key] = str(getattr(args, key).resolve(strict=key != 'data_root'))
            if plan['platform'] == 'Windows':
                base.require(args.shell is not None and args.shell.is_absolute()
                             and not args.shell.is_symlink(), 'explicit Windows default shell required')
                plan['shell'] = {'name': 'powershell', 'path': str(args.shell),
                                 'sha256': base.sha(args.shell)}
                verify_shell_file(plan['shell'])
            else:
                base.require(args.shell is None, 'Windows shell input on non-Windows plan')
            plan['cli_sha256'] = base.sha(Path(plan['codex']))
            plan['python_sha256'] = base.sha(Path(plan['python']))
            plan['python_version'] = subprocess.check_output([plan['python'], '--version'], text=True).strip()
            if args.cli_adoption:
                receipt = read_subject(args.cli_capability_receipt, strict=True)
                cli_adoption.validate_receipt(receipt, plan)
                base.require(receipt['evidence_scope'] == 'native_zero_turn', 'synthetic capability cannot enter native plan')
                plan['cli_adoption'] = cli_adoption.adoption(receipt)
            if v2:
                plan['negative_parser_reference'] = derive_parser_reference(plan)
            args.plan_file.parent.mkdir(parents=True, exist_ok=True)
            write_new(args.plan_file, plan)
            preflight(args.plan_file, args.output)
            print(json.dumps({'preflight_argv': [plan['python'], str(Path(__file__).resolve()), 'run',
                             '--plan', str(args.plan_file.resolve()), '--output', str(args.output.resolve()),
                             '--preflight'], 'run_argv': [plan['python'], str(Path(__file__).resolve()), 'run',
                             '--plan', str(args.plan_file.resolve()), '--output', str(args.output.resolve())]}))
            return 0
        if args.action == 'map':
            result = map_bundle(args.capture_dir, args.output, execution_source=args.execution_source)
        else:
            plan = preflight(args.plan, args.output)
            if args.preflight:
                if profile_for_plan(plan) == PROFILE_FULL_SPLIT:
                    directory = args.output.with_name(args.output.name + '.backend-preflight')
                    split_preflight(plan, directory, record=not directory.exists())
                print('incident_host_preflight=passed; model_calls=0; native_acceptance=not_run')
                return 0
            collect(plan, args.output)
            catalog = {p.relative_to(args.output).as_posix(): base.sha(p)
                       for p in args.output.rglob('*') if p.is_file()}
            write_new(args.output / 'artifacts.json', catalog)
            result = map_bundle(args.output, args.output / 'result.json')
        if is_full(result['gate_profile']):
            validate_result(result)
        print('incident_host_acceptance=' + result['status'] + '; evidence_scope='
              + result['evidence_scope'] + '; native_acceptance=' + result['native_acceptance']
              + ('; affected_scenario=' + result['scenario_status'] if result['gate_profile'] == PROFILE_V2 else ''))
        selected = result['scenario_status'] if result['gate_profile'] == PROFILE_V2 else result['status']
        return 0 if selected == 'passed' else 1
    except (Exception, KeyboardInterrupt) as exc:
        # Never echo a private command, token, path, prompt or exception detail.
        print('incident_host_acceptance=failed; error_class=' + type(exc).__name__)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
