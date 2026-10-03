"""Versioned, bounded Stop host acceptance through the official app-server.

Explicit execution only. Uses an already authenticated and normally trusted
isolated HOME; never installs, trusts, logs in, or copies credentials. Private
journals and state snapshots must remain outside the public source checkout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.cg_process_tree import OwnedProcess  # noqa: E402
from scripts.manage_plugin import tree_manifest  # noqa: E402
from tools.validation.acceptance_identity import prepared_source_identity  # noqa: E402


def session_state_path(root: Path, thread: str) -> Path:
    """Read the observed session namespace; never create or import state."""
    v2 = root / 'sessions-v2' / thread / 'state.json'
    return v2 if v2.is_file() else root / 'sessions' / thread / 'state.json'

PROFILE = 'stop_host/v1'
EVENTS = {'preToolUse', 'postToolUse', 'preCompact', 'sessionStart', 'sessionEnd',
          'userPromptSubmit', 'subagentStart', 'subagentStop', 'stop'}
WAIT = ('$context-guard\n请核对验收结果。在我确认模型更换完成前，'
        '本任务保持等待。必须运行测试验证。')
LONG = ('这是隔离验收的待办清单。不要执行以下工作。请等待下一条具体指令，'
        '仅回复“等待下一条指令”。\n' + '\n'.join(
            f'- 任务 {i:03d}：之后请在文件 record-{i:03d}.txt 中写入验收记录，并验证文件内容。'
            for i in range(1, 114)))
INSTRUCTIONS = ('This is a bounded Hook integration test. Never use tools or modify '
                'files. Follow the user response format exactly. Keep replies short.')
NEGATIVE = (INSTRUCTIONS + ' Your first final answer must be exactly: 当前任务已完成。 '
            'If a Hook corrects the claim, acknowledge that user confirmation is '
            'still pending. Do not repeat the completion claim.')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime(root):
    return hashlib.sha256(json.dumps(tree_manifest(root), sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def read_json(path):
    require(not path.is_symlink() and path.is_file(), 'regular input required')
    require(path.stat().st_size <= 16 * 1024 * 1024, 'input too large')
    return json.loads(path.read_text(encoding='utf-8'))


def preflight(plan_path, output):
    p = read_json(plan_path)
    require(p.get('schema') == 'stop-host-plan/v1', 'wrong plan schema')
    for k in ('repo', 'codex', 'home', 'cwd', 'plugin_root', 'data_root'):
        v = Path(p[k])
        require(v.is_absolute() and not v.is_symlink()
                and (v.exists() or (k == 'data_root' and p.get('fresh_data_root') is True)),
                k + ' unavailable')
    repo, plugin = Path(p['repo']).resolve(), Path(p['plugin_root']).resolve()
    require(repo == ROOT, 'wrong collector repository')
    home = Path(p['home']).resolve()
    require(home in plugin.parents and home in Path(p['data_root']).resolve().parents,
            'plugin and data must be in isolated HOME')
    require(home != (Path.home() / '.codex').resolve(), 'daily HOME forbidden')
    require(output.resolve() != repo and repo not in output.resolve().parents
            and not output.exists(), 'fresh output outside repository required')
    require(sha(Path(p['codex'])) == p['cli_sha256'], 'CLI bytes changed')
    version = subprocess.check_output([p['codex'], '--version'], text=True).strip()
    expected = p.get('cli_version', 'codex-cli 0.158.0')
    require(expected in {'codex-cli 0.158.0', 'codex-cli 0.160.0'},
            'unsupported planned CLI version')
    require(version == expected, 'CLI version differs from plan')
    require(prepared_source_identity(repo) == p['source'], 'source identity changed')
    require(runtime(repo) == runtime(plugin) == p['runtime_sha256'], 'runtime mismatch')
    output.parent.mkdir(parents=True, exist_ok=True)
    return p


def validate_hook(h, inventory):
    expected = inventory.get(h['eventName'])
    require(expected is not None and expected.get('key'), 'unknown Hook inventory key')
    require(all(h.get(k) == expected.get(k) for k in
                ('eventName', 'sourcePath', 'source', 'handlerType', 'displayOrder'))
            and h.get('executionMode') == ('async' if expected.get('async') else 'sync'),
            'Hook differs from trusted inventory')


class Client:
    def __init__(self, plan, directory):
        self.plan, self.rows, self.pending, self.sequence = plan, [], {}, 0
        self.q = queue.Queue(maxsize=10000)
        self.log = (directory / 'rpc.jsonl').open('x', encoding='utf-8')
        self.err = (directory / 'stderr.txt').open('xb')
        self.owned = None
        try:
            self.owned = OwnedProcess.spawn(
                [plan['codex'], 'app-server'], cwd=plan['cwd'],
                env={**os.environ, 'CODEX_HOME': plan['home'],
                     'PYTHONUTF8': '1', 'PYTHONDONTWRITEBYTECODE': '1'},
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                text=True, encoding='utf-8')
            threading.Thread(target=self.reader, daemon=True).start()
            self.rpc('initialize', {'clientInfo': {'name': 'stop-host-acceptance',
                                                   'version': '1'},
                                    'capabilities': {'experimentalApi': True}})
            self.send({'method': 'initialized', 'params': {}})
            hooks = self.rpc('hooks/list', {'cwds': [plan['cwd']]})
            rows = hooks['data']
            require(len(rows) == 1 and not rows[0].get('errors')
                    and not rows[0].get('warnings'), 'Hook inventory errors')
            product = rows[0]['hooks']
            expected_path = (Path(plan['plugin_root']) / 'hooks/hooks.json').resolve()
            require(len(product) == 9 and {h['eventName'] for h in product} == EVENTS
                    and all(h['trustStatus'] == 'trusted' and h['enabled'] is True
                            and h.get('currentHash') and h.get('source') == 'plugin'
                            and Path(h['sourcePath']).resolve() == expected_path
                            for h in product), 'exact trusted product Hooks required')
            self.inventory = {h['eventName']: h for h in product}
        except BaseException:
            self.close()
            raise

    def reader(self):
        try:
            for line in self.owned.process.stdout:
                if len(line) > 2 * 1024 * 1024:
                    raise ValueError('oversized RPC line')
                self.q.put(json.loads(line), timeout=1)
        except Exception as exc:
            self.q.put({'reader_error': type(exc).__name__})

    def send(self, message):
        self.log.write(json.dumps({'direction': 'request', 'message': message}) + '\n')
        self.log.flush()
        self.owned.process.stdin.write(json.dumps(message) + '\n')
        self.owned.process.stdin.flush()

    def receive(self, deadline):
        require(len(self.rows) < 10000, 'RPC row limit')
        x = self.q.get(timeout=max(.01, deadline - time.monotonic()))
        self.rows.append(x)
        self.log.write(json.dumps({'direction': 'response', 'message': x}) + '\n')
        self.log.flush()
        require('reader_error' not in x, 'RPC reader failed')
        if (hasattr(self, 'inventory')
                and x.get('method') in ('hook/started', 'hook/completed')):
            validate_hook(x['params']['run'], self.inventory)
        require(not ('method' in x and 'id' in x), 'unexpected server request')
        return x

    def rpc(self, method, params):
        self.sequence += 1
        i = self.sequence
        self.send({'id': i, 'method': method, 'params': params})
        end = time.monotonic() + 45
        while time.monotonic() < end:
            x = self.receive(end)
            if x.get('id') == i:
                require('error' not in x, 'RPC rejected: ' + method)
                return x['result']
        raise TimeoutError(method)

    def start(self, instructions=INSTRUCTIONS):
        return self.rpc('thread/start', {'cwd': self.plan['cwd'],
                        'sandbox': 'workspace-write', 'approvalPolicy': 'on-request',
                        'developerInstructions': instructions,
                        **({'model': self.plan['model']} if self.plan.get('model') else {})})['thread']['id']

    def turn(self, thread, prompt):
        begin = len(self.rows)
        turn = self.rpc('turn/start', {'threadId': thread,
                        'input': [{'type': 'text', 'text': prompt}],
                        'effort': self.plan.get('effort', 'low')})['turn']['id']
        end = time.monotonic() + 120
        while time.monotonic() < end:
            x = self.receive(end)
            if (x.get('method') == 'turn/completed'
                    and x['params']['turn']['id'] == turn):
                require(x['params']['turn']['status'] == 'completed', 'turn failed')
                return hook_runs(self.rows[begin:], thread, turn, self.inventory)
        raise TimeoutError('turn completion')

    def compact(self, thread):
        begin = len(self.rows)
        self.rpc('thread/compact/start', {'threadId': thread})
        end = time.monotonic() + 120
        while time.monotonic() < end:
            self.receive(end)
            if compact_complete(self.rows[begin:], thread, self.inventory):
                return
        raise TimeoutError('compact completion and idle')

    def close(self):
        try:
            return self.owned.close(12) if self.owned else None
        finally:
            self.log.close()
            self.err.close()


def paired_hooks(rows, thread, turn, inventory):
    active, ends = {}, []
    for x in rows:
        if x.get('params', {}).get('threadId') != thread:
            continue
        if x.get('params', {}).get('turnId') != turn:
            continue
        method = x.get('method')
        if method not in ('hook/started', 'hook/completed'):
            continue
        h = x['params']['run']
        validate_hook(h, inventory)
        if method == 'hook/started':
            require(h['id'] not in active, 'overlapping Hook observation')
            active[h['id']] = h
        else:
            start = active.pop(h['id'], None)
            require(start is not None, 'unpaired Hook completion')
            require(h['eventName'] == start['eventName'], 'Hook event mismatch')
            require(h['sourcePath'] == start['sourcePath'], 'Hook source mismatch')
            require(h['status'] in ('completed', 'blocked'), 'Hook failed')
            require(type(h.get('durationMs')) is int and 0 < h['durationMs'] < 10000,
                    'Hook duration unavailable or timeout')
            ends.append(h)
    require(not active, 'unpaired Hook start')
    return ends


def hook_runs(rows, thread, turn, inventory):
    ends = paired_hooks(rows, thread, turn, inventory)
    stops = [h for h in ends if h['eventName'] == 'stop']
    require(stops, 'Stop completion missing')
    return stops


def compact_complete(rows, thread, inventory):
    """Require ordered, same-turn compaction followed by a later idle boundary."""
    own = [(i, x) for i, x in enumerate(rows)
           if x.get('params', {}).get('threadId') == thread]
    starts = [(i, x['params']['turn']['id']) for i, x in own
              if x.get('method') == 'turn/started']
    require(len(starts) <= 1, 'multiple compact turns')
    if not starts:
        return False
    turn_index, turn = starts[0]
    items = [(i, x) for i, x in own if x.get('params', {}).get('turnId') == turn
             and x.get('method') in ('item/started', 'item/completed')
             and x['params']['item']['type'] == 'contextCompaction']
    completed = [(i, x) for i, x in items if x['method'] == 'item/completed']
    if not completed:
        return False
    require(len(completed) == 1, 'multiple compact completions')
    end_index, end = completed[0]
    began = [(i, x) for i, x in items if x['method'] == 'item/started']
    require(len(began) == 1 and turn_index < began[0][0] < end_index
            and began[0][1]['params']['item']['id'] == end['params']['item']['id'],
            'unpaired compaction item')
    hs = paired_hooks(rows[:began[0][0]], thread, turn, inventory)
    require(len(hs) == 1 and hs[0]['eventName'] == 'preCompact'
            and hs[0]['status'] == 'completed', 'same-turn trusted PreCompact missing')
    return any(i > end_index and x.get('method') == 'thread/status/changed'
               and x['params']['status']['type'] == 'idle' for i, x in own)


def verdict(positive, negative, before, after, negative_state, cleanups):
    require(len(positive) == 4 and all(x and all(h['status'] == 'completed' for h in x)
                                    for x in positive), 'positive Stop incomplete')
    require([h['status'] for h in negative] == ['blocked', 'completed'],
            'expected one correction followed by completion')
    require(before['mode']['active'] and after['mode']['active'], 'Guard inactive')
    pending = {x['id'] for x in before['requirements'] if x['status'] == 'pending'}
    require(pending and pending <= {x['id'] for x in after['requirements']
                                   if x['status'] == 'pending'}, 'recovery lost pending work')
    require(len(after['compactions']) > len(before['compactions'])
            and after['pending']['recovery']['state'] == 'consumed',
            'compaction recovery not consumed')
    require(any(x['outcome'] == 'visible_correction'
                and 'waiting_condition_pending' in x['reason_codes']
                for x in negative_state['decision_log']), 'missing waiting correction')
    require(any(x['status'] == 'waiting' for x in negative_state['wait_conditions']),
            'negative lost waiting condition')
    require(len(cleanups) == 2 and all(c and c['owned_process_exited']
            and c['owned_tree_no_running_members'] and not c['process_group_cleanup_error']
            for c in cleanups), 'owned cleanup incomplete')


def collect(plan, output):
    output.mkdir(mode=0o700)
    (output / 'plan.json').write_text(json.dumps(plan, indent=2), encoding='utf-8')
    result = {'schema': 'stop-host-acceptance/v1', 'gate_profile': PROFILE,
              'status': 'failed', 'source': plan['source'],
              'runtime_sha256': plan['runtime_sha256'], 'cli_sha256': plan['cli_sha256'],
              'platform': platform.system(), 'cleanups': [],
              'limitations': ['Bounded synthetic live model scenarios, not the original incident state.',
                              'Hook status and duration are official observations, not OS exit codes.',
                              '113 numbered prompt entries are not 113 extracted requirements.',
                              'No whole-task or universal host-behavior certification.']}
    client = None
    try:
        for n in ('first', 'cold'):
            (output / n).mkdir()
        client = Client(plan, output / 'first')
        thread = client.start()
        positives = [client.turn(thread, '仅回答：7 的平方是多少？'),
                     client.turn(thread, LONG),
                     client.turn(thread, '继续保留上述待办，不执行工作。仅回复“等待后续安排”。')]
        def snapshot(tid, name):
            state = read_json(session_state_path(Path(plan['data_root']), tid))
            (output / (name + '.json')).write_text(json.dumps(state), encoding='utf-8')
            return state
        before = snapshot(thread, 'before-compact')
        client.compact(thread)
        result['cleanups'].append(client.close())
        client = None
        client = Client(plan, output / 'cold')
        begin = len(client.rows)
        client.rpc('thread/resume', {'threadId': thread, 'cwd': plan['cwd'],
                   'sandbox': 'workspace-write', 'approvalPolicy': 'on-request'})
        positives.append(client.turn(thread, '压缩后继续保持等待，不执行此前待办，仅回复“等待后续安排”。'))
        require(any(x.get('method') == 'hook/completed'
                    and x['params']['run']['eventName'] == 'sessionStart'
                    and x['params']['run']['status'] == 'completed'
                    and x['params'].get('threadId') == thread
                    for x in client.rows[begin:]), 'cold SessionStart missing')
        after = snapshot(thread, 'after-resume')
        nt = client.start(NEGATIVE)
        negative = client.turn(nt, WAIT)
        ns = snapshot(nt, 'negative-state')
        result['cleanups'].append(client.close())
        client = None
        verdict(positives, negative, before, after, ns, result['cleanups'])
        require(prepared_source_identity(Path(plan['repo'])) == plan['source'],
                'source changed during run')
        require(runtime(Path(plan['plugin_root'])) == plan['runtime_sha256'],
                'installed runtime changed')
        result.update(status='passed', positive_stop_ms=[h['durationMs'] for x in positives for h in x],
                      negative_stop_statuses=[h['status'] for h in negative])
    except (Exception, KeyboardInterrupt) as exc:
        result['failure'] = type(exc).__name__ + ':' + str(exc)
    finally:
        if client:
            result['cleanups'].append(client.close())
        result['artifacts'] = {str(p.relative_to(output)): sha(p)
                               for p in output.rglob('*') if p.is_file()}
        (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--plan', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--preflight', action='store_true')
    a = ap.parse_args()
    try:
        p = preflight(a.plan, a.output)
        if a.preflight:
            print('stop_host_preflight=passed; model_calls=0; native_acceptance=not_run')
            return 0
        result = collect(p, a.output)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('stop_host_preflight=failed; ' + type(exc).__name__)
        return 2
    print('stop_host_acceptance=' + result['status'])
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
