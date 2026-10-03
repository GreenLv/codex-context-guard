"""Two incident native supplement, incident_host/v1 (explicit model execution).

No authentication, installation, trust changes, permissions escalation or
approval responses. Prepared isolated HOME must already have nine trusted
Hooks. Missing observations stay pending. All captures are private; export
contains only gate IDs, statuses and immutable execution/mapping identities.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts import context_guard as cg  # noqa: E402
from tools.validation import incident_readonly_child as child  # noqa: E402
from tools.validation import stop_host_acceptance as base  # noqa: E402
from tools.validation.acceptance_identity import prepared_source_identity  # noqa: E402

PROFILE = 'incident_host/v1'
MANIFEST = Path(__file__).with_name('incident-host-scenarios.json')
TOOLKIT = ('incident_host_acceptance.py', 'incident_readonly_child.py',
           'stop_host_acceptance.py', 'acceptance_identity.py', 'incident-host-scenarios.json')
GATES = ('hook_trust', 'pause_same_unit', 'resume_provenance_pending',
         'typed_wait_retained', 'status_cli_posttool', 'status_negative_controls',
         'restricted_child_readonly', 'positive_negative_stop',
         'compaction_cold_resume', 'cleanup')


class ObservationPending(RuntimeError):
    pass


def write_new(path, value):
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n'
    with path.open('x', encoding='utf-8') as stream:
        stream.write(raw)
    if os.name != 'nt':
        path.chmod(0o600)


def toolkit():
    return {name: base.sha(Path(__file__).with_name(name)) for name in TOOLKIT}


def plan_identity(plan):
    return hashlib.sha256(cg.canonical_json(plan).encode()).hexdigest()


def preflight(plan_path, output):
    plan = base.read_json(plan_path)
    base.require(plan.get('schema') == 'incident-host-plan/v1', 'wrong incident plan')
    base.require(output.resolve() == Path(plan['output']).resolve(), 'output differs from plan')
    base.require(plan.get('cli_version') == 'codex-cli 0.160.0', 'CLI 0.160.0 plan required')
    base.require(plan.get('toolkit') == toolkit(), 'toolkit bytes changed')
    base.require(plan.get('manifest_sha256') == base.sha(MANIFEST), 'manifest changed')
    base.require(isinstance(plan.get('model'), str) and plan['model'].strip(), 'explicit model required')
    base.require(plan.get('effort') == 'medium', 'explicit medium effort required')
    base.require(plan.get('platform') == platform.system(), 'platform differs from plan')
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
                 and not (cwd / ('incident-request-' + output.name + '.json')).exists(), 'fixture output collision')
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
        result = self.rpc('thread/start', {'cwd': self.plan['cwd'],
                          'sandbox': 'workspace-write', 'approvalPolicy': 'on-request',
                          'model': self.plan['model'], 'developerInstructions': instructions})
        base.require(result.get('model') == self.plan['model'], 'model configuration drift')
        base.require(result.get('approvalPolicy') == 'on-request', 'approval policy drift')
        base.require(result.get('sandbox', {}).get('type') == 'workspaceWrite', 'sandbox drift')
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


def command_observation(stage, inventory, plan):
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
    base.require(b.get('source', 'agent') == 'agent' and b.get('status') in ('completed', 'failed'),
                 'ordinary model command required')
    if require_exit:
        base.require(type(b.get('exitCode')) is int and isinstance(b.get('aggregatedOutput'), str),
                     'CLI exit/output unavailable')
    return b, start_index, end_index



def rejection_observation(stage, inventory, plan, kind):
    """Malformed controls must be refused; absent execution is not CLI success."""
    rows, thread, turn = stage['rows'], stage['thread'], stage['turn']
    for row in rows:
        if row.get('method') in ('hook/started', 'hook/completed'):
            base.require(type(row['params']['run'].get('displayOrder')) is int, 'invalid rejection Hook identity')
    hooks = base.paired_hooks(rows, thread, turn, inventory)
    for name in ('userPromptSubmit',):
        selected = [h for h in hooks if h['eventName'] == name]
        base.require(len(selected) == 1 and selected[0]['status'] == 'completed', 'rejection boundary incomplete')
    pre = [h for h in hooks if h['eventName'] == 'preToolUse']
    post = [h for h in hooks if h['eventName'] == 'postToolUse']
    attempted = [r for r in rows if r.get('method') == 'item/started'
                 and r.get('params', {}).get('threadId') == thread
                 and r['params'].get('turnId') == turn
                 and r['params'].get('item', {}).get('type') == 'commandExecution']
    if not attempted:
        return {'status': 'pending', 'branch': 'attempt_not_observed',
                'cli': 'not_observed', 'posttool': 'not_observed'}
    terminal = [r for r in rows if r.get('method') == 'item/completed'
                and r.get('params', {}).get('threadId') == thread
                and r['params'].get('turnId') == turn
                and r['params'].get('item', {}).get('type') == 'commandExecution']
    if not terminal:
        return {'status': 'pending', 'branch': 'terminal_not_observed',
                'cli': 'not_observed', 'posttool': 'not_observed'}
    item, _, _ = command_pair(stage, plan, require_exit=False)
    argv = status_argv(item, stage, plan, legal=False)
    expected = '--unknown-status-option' if kind == 'unknown' else '--item --commands'
    suffix = ' '.join(argv[-1:] if kind == 'unknown' else argv[-2:])
    base.require(suffix == expected and len(pre) == 1, 'rejection command differs')
    if pre[0]['status'] == 'blocked':
        base.require(not post and item['status'] == 'failed' and item.get('exitCode') is None,
                     'Pre refusal cannot certify CLI or Post execution')
        return {'status': 'pending', 'branch': 'pre_blocked',
                'cli': 'not_observed', 'posttool': 'not_observed'}
    base.require(pre[0]['status'] == 'completed', 'unresolved Pre refusal')
    if item.get('exitCode') is None or not post:
        return {'status': 'pending', 'branch': 'execution_incomplete',
                'cli': 'not_observed' if item.get('exitCode') is None else 'observed',
                'posttool': 'not_observed' if not post else 'observed'}
    base.require(type(item['exitCode']) is int and item['exitCode'] == 2
                 and len(post) == 1 and post[0]['status'] == 'blocked',
                 'malformed CLI must fail and Post must block')
    base.require(type(post[0].get('entries')) is list, 'Post refusal entries unavailable')
    return {'status': 'passed', 'branch': 'cli2_post_blocked', 'cli': 'observed', 'posttool': 'blocked'}


def status_argv(item, stage, plan, *, legal=True):
    argv = cg.private_control_command_tokens(item['command'], windows=plan['platform'] == 'Windows')
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
    if legal:
        binding = cg.parse_checkpoint_status_option_bindings(argv[3:])
        base.require(binding and binding['--commands'] == [''], 'commands mode required')
        base.require(binding['--session-id'] == [stage['thread']]
                     and binding['--turn-id'] == [stage['turn']]
                     and Path(binding['--data-dir'][0]).resolve() == Path(plan['data_root']).resolve(),
                     'query binding drift')
    return argv


def make_fixture(plan, stage, item, root):
    argv = status_argv(item, stage, plan)
    binding = cg.parse_checkpoint_status_option_bindings(argv[3:])
    target = root / 'sessions-v2' / stage['thread']
    target.parent.mkdir(parents=True)
    copied = copy_session(plan, stage['thread'], target)
    base.require(copied['content_hash'] == state_for(stage)['content_hash'], 'query snapshot changed')
    cg.completion_attempt_for(copied, stage['turn'], binding['--token'][0])
    lock = root / 'sessions-v2' / '.locks' / (stage['thread'] + '.lock')
    lock.parent.mkdir()
    live_lock = Path(plan['data_root']) / 'sessions-v2' / '.locks' / lock.name
    base.require(live_lock.is_file() and not live_lock.is_symlink(), 'actual lock witness unavailable')
    shutil.copy2(live_lock, lock)
    # Rewrite only the cloned data-root argument; preserve exact session/turn/token.
    argv = [*argv[:3], '--data-dir', str(root), '--session-id', stage['thread'],
            '--turn-id', stage['turn'], '--token', binding['--token'][0], '--commands']
    restriction = child.restrict(root)
    request = {'schema': 'incident-readonly-request/v1', 'fixture': str(root),
               'lock': str(lock), 'argv': argv, 'restriction': restriction,
               'inventory': child.inventory(root), 'turn': stage['turn'],
               'state_revision': copied['content_hash']}
    request['request_sha256'] = plan_identity(request)
    return request


def state_for(stage):
    return cg.read_only_committed_state(Path(stage['snapshot']))


def pause_oracle(before, paused, resumed, typed, typed_before=None):
    unit = before['work_units'][-1]['id']
    base.require(paused['work_units'][-1]['id'] == resumed['work_units'][-1]['id'] == unit,
                 'work unit changed')
    base.require(paused['work_units'][-1]['status'] == 'awaiting_user', 'pause not parked')
    base.require(resumed['work_units'][-1]['status'] == 'active', 'resume not active')
    pending = {r['id'] for r in before['requirements'] if r['status'] == 'pending'}
    base.require(pending and pending <= {r['id'] for r in resumed['requirements']
                                        if r['status'] == 'pending'}, 'old pending lost')
    waits = [r for r in paused['wait_conditions'] if r['status'] == 'waiting']
    base.require(len(waits) == 1 and waits[0].get('subject_sha256') is None, 'ordinary pause required')
    match = [r for r in resumed['wait_conditions'] if r['condition_id'] == waits[0]['condition_id']]
    base.require(len(match) == 1 and match[0]['status'] == 'released'
                 and match[0]['raised_by_source'] == waits[0]['raised_by_source']
                 and match[0]['source_clause_sha256'] == waits[0]['source_clause_sha256']
                 and match[0]['released_by_source'] == resumed['prompts'][-1]['id'],
                 'resume provenance differs')
    if typed_before is not None:
        old = {r['condition_id']: r for r in typed_before['wait_conditions']
               if r['status'] == 'waiting' and r.get('subject_sha256')}
        current = {r['condition_id']: r for r in typed['wait_conditions']}
        base.require(old and all(k in current and current[k]['status'] == 'waiting'
                     and current[k]['raised_by_source'] == v['raised_by_source']
                     and current[k]['subject_sha256'] == v['subject_sha256']
                     for k, v in old.items()), 'typed wait provenance lost')
    base.require(any(r['status'] == 'waiting' and r.get('subject_sha256')
                     for r in typed['wait_conditions']), 'typed wait released')


def verify_stop_capture(directory, plan, receipt):
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


def public_source(identity):
    result = {k: identity.get(k) for k in ('head', 'prepared_source_sha256')}
    base.require(isinstance(result['head'], str) and re.fullmatch(r'[0-9a-f]{40}', result['head'])
                 and isinstance(result['prepared_source_sha256'], str)
                 and re.fullmatch(r'[0-9a-f]{64}', result['prepared_source_sha256']), 'invalid source identity')
    return result


def map_capture(capture, *, mapper_identity=None):
    base.require(capture.get('schema') == 'incident-host-capture/v1', 'wrong capture')
    base.require(capture.get('origin') in ('native', 'synthetic'), 'unknown execution origin')
    plan = capture['plan']
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
    manifest = base.read_json(MANIFEST)
    for name, stage in stages.items():
        base.require(name in manifest['prompts'] or name == 'readonly', 'unknown stage')
        if name != 'readonly':
            expected = hashlib.sha256(manifest['prompts'][name].encode()).hexdigest()
            base.require(stage['prompt_sha256'] == expected, 'scenario prompt differs')
        state = state_for(stage)
        base.require(state['session']['id'] == stage['thread'], 'state session differs')
        base.require(state['prompts'] and state['prompts'][-1]['sha256'] == stage['prompt_sha256'],
                     'prompt differs from captured authority')
        valid, _ = cg.read_only_authority_sources_valid(Path(stage['snapshot']), state)
        base.require(valid, 'snapshot authority unavailable')
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
        status_argv(item, s, plan)
        base.require(item['exitCode'] == 0, 'legal status CLI failed')
        output = json.loads(item['aggregatedOutput'])
        base.require(isinstance(output.get('advanced_commands'), dict)
                     and set(output['advanced_commands']) == {'status', 'stage_checkpoint', 'stage_disposition', 'register_proof'}
                     and output.get('turn_id') == s['turn']
                     and isinstance(output.get('revision'), str) and len(output['revision']) == 64,
                     'commands output absent or unbound')
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
    if 'readonly' in stages and capture.get('readonly_request'):
        item = command_observation(stages['readonly'], inventory, plan)
        argv = cg.private_control_command_tokens(item['command'], windows=plan['platform'] == 'Windows')
        base.require(argv == capture['readonly_tool_argv'] and len(argv) == 4
                     and Path(argv[0]).resolve() == Path(plan['python']).resolve()
                     and Path(argv[1]).resolve() == ROOT / 'tools/validation/incident_readonly_child.py'
                     and argv[2] == '--request', 'readonly tool argv differs')
        base.require(item['exitCode'] == 0, 'readonly child tool failed')
        record = json.loads(item['aggregatedOutput'])
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
    if len(cleanups) == 3:
        base.require(all(c and c.get('owned_process_exited') is True
                         and c.get('owned_tree_no_running_members') is True
                         and not c.get('process_group_cleanup_error') for c in cleanups), 'owned cleanup failed')
        gates['cleanup'] = 'passed'
    status = 'passed' if all(v == 'passed' for v in gates.values()) else 'pending'
    if any(v == 'failed' for v in gates.values()) or capture.get('failure_class'):
        status = 'failed'
    if capture.get('pending_class'):
        status = 'pending'
    return {'schema': 'incident-host-acceptance/v1', 'gate_profile': PROFILE,
            'status': status, 'evidence_scope': capture['origin'], 'gates': gates,
            'rejection_observations': observations,
            'execution_identity': {'source': public_source(plan['source']), 'runtime_sha256': plan['runtime_sha256'],
                                   'cli_sha256': plan['cli_sha256'], 'cli_version': plan['cli_version'],
                                   'toolkit': plan['toolkit'], 'plan_sha256': capture['plan_sha256'],
                                   'platform': plan['platform'], 'model': plan.get('model'), 'effort': plan.get('effort')},
            'mapping_identity': {'source': public_source((mapper_identity or {}).get('source', prepared_source_identity(ROOT))),
                                 'toolkit': (mapper_identity or {}).get('toolkit', toolkit())},
            'native_acceptance': status if capture['origin'] == 'native' else 'not_run',
            'limitations': ['Bounded live scenarios, not original incident state.',
                            'Read-only witness queries an exact session copy in a collector-owned fixture.',
                            'Hook statuses are official observations, not OS exit codes.',
                            'Configured model identity is not per-turn execution telemetry.']}


def validate_result(result):
    base.require(result.get('schema') == 'incident-host-acceptance/v1'
                 and result.get('gate_profile') == PROFILE, 'wrong result profile')
    base.require(result.get('status') in ('passed', 'failed', 'pending'), 'invalid result status')
    base.require(result.get('evidence_scope') in ('native', 'synthetic'), 'invalid result scope')
    gates = result.get('gates')
    base.require(isinstance(gates, dict) and set(gates) == set(GATES)
                 and all(v in ('passed', 'failed', 'pending') for v in gates.values()), 'invalid result gates')
    base.require(result['status'] != 'passed' or set(gates.values()) == {'passed'}, 'partial green result')
    native = result.get('native_acceptance')
    base.require(native == ('not_run' if result['evidence_scope'] == 'synthetic' else result['status']),
                 'native result scope mismatch')
    allowed = {'schema', 'gate_profile', 'status', 'evidence_scope', 'gates',
               'execution_identity', 'mapping_identity', 'native_acceptance', 'limitations',
               'capture_catalog_sha256', 'failure_class', 'rejection_observations'}
    base.require(set(result) <= allowed and isinstance(result.get('execution_identity'), dict)
                 and isinstance(result.get('mapping_identity'), dict), 'non-allowlisted export')
    return result


def collect(plan, output):
    output.mkdir(mode=0o700)
    capture = {'schema': 'incident-host-capture/v1', 'origin': 'native',
               'plan': plan, 'plan_sha256': plan_identity(plan), 'stages': {}, 'cleanups': []}
    write_new(output / 'plan.json', plan)
    client = None
    request = None
    fixture = Path(plan['cwd']) / ('incident-readonly-' + output.name)
    try:
        (output / 'rpc').mkdir()
        client = Client(plan, output / 'rpc')
        capture['inventory'] = client.inventory
        manifest = base.read_json(MANIFEST)
        def turn(name, thread, prompt=None):
            stage = client.observed_turn(thread, prompt or manifest['prompts'][name])
            dest = output / ('snapshot-' + name)
            copy_session(plan, thread, dest)
            stage['snapshot'] = str(dest)
            capture['stages'][name] = stage
            return stage
        thread = client.start()
        for name in ('pending', 'pause', 'resume', 'typed', 'typed_resume'):
            turn(name, thread)
        instructions = ('This is a bounded diagnostic test. Use exactly one ordinary shell tool per turn. '
                        'Use the exact latest Context Guard checkpoint-status binding from its recovery packet. '
                        'Run the specified query as a standalone command, no helper or shell chain. '
                        'Keep all diagnostic output private. Final answer: 诊断结束，验收仍等待。')
        status_thread = client.start(instructions)
        s = turn('status', status_thread)
        item = command_observation(s, client.inventory, plan)
        fixture.mkdir(mode=0o700)
        request = make_fixture(plan, s, item, fixture)
        request_path = Path(plan['cwd']) / ('incident-request-' + output.name + '.json')
        write_new(request_path, request)
        capture['readonly_request'] = request
        for name in ('unknown', 'missing'):
            turn(name, status_thread)
        tool_argv = [plan['python'], str(ROOT / 'tools/validation/incident_readonly_child.py'),
                     '--request', str(request_path)]
        capture['readonly_tool_argv'] = tool_argv
        # New thread avoids no-helper developer instruction conflict.
        probe_thread = client.start('Execute exactly the requested standalone ordinary shell command. '
                                    'Do not escalate permissions. Keep output private. '
                                    'Final answer: 只读探针结束，验收仍等待。')
        spelling = cg.shell_join(tool_argv)
        if plan['platform'] == 'Windows':
            spelling = '& ' + spelling
        turn('readonly', probe_thread, 'Run this exact ordinary tool command once: ' + spelling)
        capture['cleanups'].append(client.close())
        client = None
        shared = dict(plan, schema='stop-host-plan/v1')
        capture['stop_directory'] = str(output / 'stop')
        capture['stop_result'] = base.collect(shared, output / 'stop')
        capture['cleanups'].extend(capture['stop_result']['cleanups'])
        base.require(prepared_source_identity(ROOT) == plan['source'], 'source changed during run')
        base.require(base.runtime(Path(plan['plugin_root'])) == plan['runtime_sha256'], 'runtime changed during run')
    except (Exception, KeyboardInterrupt) as exc:
        capture['pending_class'] = type(exc).__name__
        # Exception text can contain raw prompts/private commands; private only.
        write_new(output / 'failure.json', {'type': type(exc).__name__, 'detail': str(exc),
                                               'restriction': getattr(exc, 'record', None)})
    finally:
        if client:
            try:
                capture['cleanups'].append(client.close())
            except Exception as exc:
                capture['failure_class'] = type(exc).__name__
        if request:
            try:
                child.restore(fixture, request['restriction'])
            except Exception as exc:
                capture['pending_class'] = type(exc).__name__
        write_new(output / 'capture.json', capture)
    return capture


def map_bundle(directory, output):
    base.require(not output.exists() and output.resolve() != ROOT and ROOT not in output.resolve().parents
                 and directory.resolve() != ROOT
                 and ROOT not in directory.resolve().parents, 'private capture outside source required')
    capture = base.read_json(directory / 'capture.json')
    catalog = base.read_json(directory / 'artifacts.json')
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
    base.require(set(catalog) == actual - {'artifacts.json', 'result.json'}, 'incomplete artifact catalog')
    for name, digest in catalog.items():
        target = directory / name
        base.require(target.resolve().is_relative_to(directory.resolve()) and not target.is_symlink()
                     and target.is_file() and base.sha(target) == digest, 'capture artifact changed')
    base.require(catalog.get('capture.json') == base.sha(directory / 'capture.json'), 'capture not catalogued')
    if capture.get('stop_directory'):
        base.require(Path(capture['stop_directory']).resolve() == directory.resolve() / 'stop', 'base capture escaped')
    for s in capture.get('stages', {}).values():
        p = Path(s['snapshot']).resolve()
        base.require(p.is_relative_to(directory.resolve()), 'snapshot outside bundle')
    try:
        result = map_capture(capture)
    except (ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
        minimal = {**capture, 'stages': {}, 'inventory': {}, 'cleanups': [],
                   'stop_result': None, 'failure_class': type(exc).__name__}
        minimal.pop('pending_class', None)
        result = map_capture(minimal)
        result['failure_class'] = type(exc).__name__
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
    make = sub.add_parser('plan')
    for name in ('codex', 'python', 'home', 'cwd', 'plugin-root', 'data-root', 'output'):
        make.add_argument('--' + name, type=Path, required=True)
    make.add_argument('--model', required=True)
    make.add_argument('--plan-file', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'plan':
            plan = {'schema': 'incident-host-plan/v1', 'repo': str(ROOT),
                    'source': prepared_source_identity(ROOT), 'runtime_sha256': base.runtime(ROOT),
                    'cli_version': 'codex-cli 0.160.0', 'platform': platform.system(),
                    'model': args.model, 'effort': 'medium', 'fresh_data_root': True, 'output': str(args.output.resolve()), 'toolkit': toolkit(), 'manifest_sha256': base.sha(MANIFEST)}
            for key in ('codex', 'python', 'home', 'cwd', 'plugin_root', 'data_root'):
                plan[key] = str(getattr(args, key).resolve(strict=key != 'data_root'))
            plan['cli_sha256'] = base.sha(Path(plan['codex']))
            plan['python_sha256'] = base.sha(Path(plan['python']))
            plan['python_version'] = subprocess.check_output([plan['python'], '--version'], text=True).strip()
            args.plan_file.parent.mkdir(parents=True, exist_ok=True)
            write_new(args.plan_file, plan)
            preflight(args.plan_file, args.output)
            print(json.dumps({'preflight_argv': [plan['python'], str(Path(__file__).resolve()), 'run',
                             '--plan', str(args.plan_file.resolve()), '--output', str(args.output.resolve()),
                             '--preflight'], 'run_argv': [plan['python'], str(Path(__file__).resolve()), 'run',
                             '--plan', str(args.plan_file.resolve()), '--output', str(args.output.resolve())]}))
            return 0
        if args.action == 'map':
            result = map_bundle(args.capture_dir, args.output)
        else:
            plan = preflight(args.plan, args.output)
            if args.preflight:
                print('incident_host_preflight=passed; model_calls=0; native_acceptance=not_run')
                return 0
            collect(plan, args.output)
            catalog = {p.relative_to(args.output).as_posix(): base.sha(p)
                       for p in args.output.rglob('*') if p.is_file()}
            write_new(args.output / 'artifacts.json', catalog)
            result = map_bundle(args.output, args.output / 'result.json')
        print('incident_host_acceptance=' + result['status'] + '; evidence_scope='
              + result['evidence_scope'] + '; native_acceptance=' + result['native_acceptance'])
        return 0 if result['status'] == 'passed' else 1
    except (Exception, KeyboardInterrupt) as exc:
        # Never echo a private command, token, path, prompt or exception detail.
        print('incident_host_acceptance=failed; error_class=' + type(exc).__name__)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
