"""Split Windows backend contracts; all process and journal evidence is synthetic."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import test_incident_host_full_v2 as full
from tests.test_cg122_p0_counterexamples import P0Harness
from tools.validation import incident_host_acceptance as host
from tools.validation import incident_windows_backends as backend


class BackendBindingTests(unittest.TestCase):
    """No Codex, model, Windows sandbox, or real credentials are used."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.plan = {'cwd': str(Path(self.temp.name).resolve()), 'model': 'local-model',
                     'local_provider_endpoint': 'http://127.0.0.1:11434/v1'}
        environment = mock.patch.dict(os.environ, {'CODEX_WINDOWS_REGISTERED_CORE': '0'})
        environment.start()
        self.addCleanup(environment.stop)

    def config(self, mode):
        return {'config': {'windows': {'sandbox': mode},
                           'features': {'prefer_mxc': False},
                           'model': self.plan['model'], 'model_provider': 'local_ollama',
                           'model_providers': {'local_ollama': {
                               'base_url': self.plan['local_provider_endpoint'],
                               'wire_api': 'responses', 'requires_openai_auth': False}}},
                'origins': {}}

    def client(self, config, readiness):
        class Client:
            def __init__(inner):
                inner.plan = self.plan
                inner.calls = []

            def rpc(inner, method, params):
                inner.calls.append((method, params))
                return {'config/read': config,
                        'windowsSandbox/readiness': readiness}[method]

        return Client()

    def test_launch_flags_select_only_exact_reviewed_modes(self):
        for mode in ('mxc', 'elevated'):
            with self.subTest(mode=mode):
                self.assertEqual(backend.launch_flags(mode),
                                 ['-c', f'windows.sandbox="{mode}"',
                                  '-c', 'features.prefer_mxc=false'])
        for mode in ('', 'disabled', 'MXC', 'mxc -c extra', None, True):
            with self.subTest(mode=mode), self.assertRaises((ValueError, TypeError)):
                backend.launch_flags(mode)

    def test_bind_requires_effective_config_and_ready_backend(self):
        for mode in ('mxc', 'elevated'):
            with self.subTest(mode=mode):
                client = self.client(self.config(mode), {'status': 'ready'})
                receipt = backend.bind(client, mode)
                self.assertEqual(client.calls, [
                    ('config/read', {'cwd': self.plan['cwd'], 'includeLayers': False}),
                    ('windowsSandbox/readiness', None),
                ])
                self.assertEqual(receipt, {
                    'schema': 'incident-windows-backend-binding/v1',
                    'backend': mode, 'windows_sandbox': mode,
                    'prefer_mxc': False, 'readiness': 'ready',
                    'model_provider': 'local_ollama',
                })

    def test_bind_rejects_spoofed_or_incomplete_readiness(self):
        bad = []
        changed = self.config('elevated')
        bad.append((changed, {'status': 'ready'}))
        changed = self.config('mxc')
        changed['config']['features']['prefer_mxc'] = True
        bad.append((changed, {'status': 'ready'}))
        changed = self.config('mxc')
        changed['config']['features']['prefer_mxc'] = 0
        bad.append((changed, {'status': 'ready'}))
        changed = self.config('mxc')
        del changed['config']['windows']['sandbox']
        bad.append((changed, {'status': 'ready'}))
        changed = self.config('mxc')
        changed['config']['model_provider'] = 'foreign'
        bad.append((changed, {'status': 'ready'}))
        for field, value in (('base_url', 'https://remote.example/v1'),
                             ('wire_api', 'chat'), ('requires_openai_auth', True),
                             ('http_headers', {'Authorization': 'synthetic'}),
                             ('model_catalog_url', 'https://remote.example/catalog'),
                             ('supports_websockets', True)):
            changed = self.config('mxc')
            changed['config']['model_providers']['local_ollama'][field] = value
            bad.append((changed, {'status': 'ready'}))
        changed = self.config('mxc')
        changed['config']['model'] = 'other-model'
        bad.append((changed, {'status': 'ready'}))
        for readiness in ({}, {'status': 'updateRequired'}, {'status': True}):
            bad.append((self.config('mxc'), readiness))
        for index, (config, readiness) in enumerate(bad):
            with self.subTest(index=index), self.assertRaises((ValueError, KeyError, TypeError)):
                backend.bind(self.client(config, readiness), 'mxc')

    def journal(self, mode):
        params = {'cwd': self.plan['cwd'], 'sandbox': 'workspace-write',
                  'approvalPolicy': 'on-request', 'model': self.plan['model'],
                  'developerInstructions': 'synthetic test'}
        result = {'thread': {'id': 'synthetic-thread'}, 'model': self.plan['model'],
                  'modelProvider': 'local_ollama', 'approvalPolicy': 'on-request',
                  'cwd': self.plan['cwd'], 'sandbox': {'type': 'workspaceWrite'}}
        return [
            {'direction': 'request', 'message': {'id': 1, 'method': 'config/read',
             'params': {'cwd': self.plan['cwd'], 'includeLayers': False}}},
            {'direction': 'response', 'message': {'id': 1, 'result': self.config(mode)}},
            {'direction': 'request', 'message': {'id': 2, 'method': 'windowsSandbox/readiness',
             'params': None}},
            {'direction': 'response', 'message': {'id': 2, 'result': {'status': 'ready'}}},
            {'direction': 'request', 'message': {'id': 3, 'method': 'thread/start', 'params': params}},
            {'direction': 'response', 'message': {'id': 3, 'result': result}},
        ]

    def write_journal(self, rows):
        path = Path(self.temp.name) / 'rpc.jsonl'
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        return path

    def test_journal_binds_replies_to_one_exact_subject(self):
        for mode in ('mxc', 'elevated'):
            with self.subTest(mode=mode):
                rows = self.journal(mode)
                receipt, replay = backend.verify_journal(self.write_journal(rows), mode, self.plan)
                self.assertEqual(replay, rows)
                self.assertEqual(receipt, backend.bind(self.client(self.config(mode), {'status': 'ready'}), mode))

    def test_journal_rejects_config_spoofing_and_thread_drift(self):
        original = self.journal('mxc')
        mutations = []
        bad = copy.deepcopy(original)
        bad[1]['message']['result']['config']['windows']['sandbox'] = 'elevated'
        mutations.append(bad)
        bad = copy.deepcopy(original)
        bad[3]['message']['result']['status'] = 'updateRequired'
        mutations.append(bad)
        bad = copy.deepcopy(original)
        bad[0]['message']['params']['cwd'] = 'foreign'
        mutations.append(bad)
        bad = copy.deepcopy(original)
        bad[4]['message']['params']['config'] = {'windows.sandbox': 'elevated'}
        mutations.append(bad)
        bad = copy.deepcopy(original)
        bad[4]['message']['params']['sandbox_permissions'] = 'require_escalated'
        mutations.append(bad)
        bad = copy.deepcopy(original)
        bad[5]['message']['result']['sandbox']['type'] = 'readOnly'
        mutations.append(bad)
        bad = copy.deepcopy(original)
        bad[5]['message']['result']['approvalPolicy'] = 'never'
        mutations.append(bad)
        for field, value in (('model', 'foreign-model'), ('modelProvider', 'foreign'), ('cwd', 'foreign')):
            bad = copy.deepcopy(original)
            bad[5]['message']['result'][field] = value
            mutations.append(bad)
        bad = copy.deepcopy(original)
        bad[3]['message']['id'] = 999
        mutations.append(bad)
        bad = copy.deepcopy(original)
        bad.insert(4, {'direction': 'response', 'message': {
            'id': 99, 'method': 'item/commandExecution/requestApproval', 'params': {}}})
        mutations.append(bad)
        bad = copy.deepcopy(original)
        bad += [{'direction': 'request', 'message': {'id': 4, 'method': 'turn/start', 'params': {
            'threadId': 'other-thread', 'input': [], 'effort': 'medium'}}},
            {'direction': 'response', 'message': {'id': 4, 'result': {'turn': {'id': 'turn'}}}}]
        mutations.append(bad)
        bad = copy.deepcopy(original)
        bad += [{'direction': 'request', 'message': {'id': 4, 'method': 'turn/start', 'params': {
            'threadId': 'synthetic-thread', 'input': [], 'effort': 'medium', 'sandbox': 'danger-full-access'}}},
            {'direction': 'response', 'message': {'id': 4, 'result': {'turn': {'id': 'turn'}}}}]
        mutations.append(bad)
        for index, rows in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises((ValueError, KeyError, TypeError)):
                backend.verify_journal(self.write_journal(rows), 'mxc', self.plan)

    def test_registered_core_refresh_is_not_probed(self):
        client = self.client(self.config('mxc'), {'status': 'ready'})
        with mock.patch.dict(os.environ, {'CODEX_WINDOWS_REGISTERED_CORE': '1'}):
            with self.assertRaises(ValueError):
                backend.bind(client, 'mxc')
        self.assertEqual(client.calls, [])

    def split_fixture(self):
        directory = Path(self.temp.name) / 'capture'
        directory.mkdir()
        plan = dict(self.plan, codex='synthetic-codex', output=str(directory))
        inventory = {name: {'eventName': name} for name in host.base.EVENTS}
        cleanups = [dict(owned_process_exited=True, owned_tree_no_running_members=True,
                         job_assignment_confirmed=True, job_close_confirmed=True,
                         cleanup_complete=True, role=role, pid=n)
                    for n, role in enumerate(host.SPLIT_JOURNALS, 1)]
        capture = {'origin': 'native', 'plan': plan, 'inventory': inventory,
                   'backend_bindings': {}, 'cleanups': cleanups,
                   'stop_result': {'cleanups': cleanups[2:]}, 'stages': {}}
        groups = {
            'primary': (host.PRIMARY_STAGES, ['p0'] * 5 + ['p1'] * 3),
            'acl': (host.ACL_STAGES, ['a0'] * 5),
            'stop_first': (('s0', 's1', 's2'), ['stop0'] * 3),
            'stop_cold': (('s3', 's4'), ['stop0', 'stop1']),
        }
        for n, (role, relative) in enumerate(host.SPLIT_JOURNALS.items(), 1):
            mode = backend.CONTRACT['roles'][role]
            subdir = directory / relative
            subdir.mkdir(parents=True)
            (subdir / 'launch.json').write_text(json.dumps({
                'role': role, 'pid': n, 'argv': [plan['codex'], *backend.launch_flags(mode), 'app-server'],
                'local_provider_endpoint': plan['local_provider_endpoint'],
            }), encoding='utf-8')
            rows = self.journal(mode)[:4]
            rows += [
                {'direction': 'request', 'message': {'id': 10, 'method': 'hooks/list',
                 'params': {'cwds': [plan['cwd']]}}},
                {'direction': 'response', 'message': {'id': 10, 'result': {'data': [
                    {'hooks': list(inventory.values())}]}}},
            ]
            names, threads = groups[role]
            for ix, thread in enumerate(dict.fromkeys(threads)):
                method = 'thread/resume' if role == 'stop_cold' and thread == 'stop0' else 'thread/start'
                params = {'cwd': plan['cwd'], 'sandbox': 'workspace-write',
                          'approvalPolicy': 'on-request'}
                if method == 'thread/resume':
                    params['threadId'] = thread
                else:
                    params.update(model=plan['model'], developerInstructions='synthetic test')
                rows += [
                    {'direction': 'request', 'message': {'id': 20 + ix, 'method': method, 'params': params}},
                    {'direction': 'response', 'message': {'id': 20 + ix, 'result': {
                        'thread': {'id': thread}, 'model': plan['model'], 'modelProvider': 'local_ollama',
                        'cwd': plan['cwd'], 'approvalPolicy': 'on-request',
                        'sandbox': {'type': 'workspaceWrite'}}}},
                ]
            if role == 'stop_first':
                rows += [
                    {'direction': 'request', 'message': {'id': 30, 'method': 'thread/compact/start',
                     'params': {'threadId': 'stop0'}}},
                    {'direction': 'response', 'message': {'id': 30, 'result': {}}},
                ]
            for i, (name, thread) in enumerate(zip(names, threads)):
                turn, prompt, request_id = f'{role}-turn-{i}', f'synthetic {name}', 40 + i
                observed = [
                    {'id': request_id, 'result': {'turn': {'id': turn}}},
                    {'method': 'turn/completed', 'params': {'threadId': thread,
                     'turn': {'id': turn, 'status': 'completed'}}},
                ]
                rows.append({'direction': 'request', 'message': {'id': request_id,
                            'method': 'turn/start', 'params': {'threadId': thread,
                            'input': [{'type': 'text', 'text': prompt}], 'effort': 'medium'}}})
                rows.extend({'direction': 'response', 'message': message} for message in observed)
                if role in ('primary', 'acl'):
                    capture['stages'][name] = {'thread': thread, 'turn': turn,
                        'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest(), 'rows': observed}
            (subdir / 'rpc.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')
            capture['backend_bindings'][role] = backend.bind(self.client(self.config(mode), {'status': 'ready'}), mode)
        return directory, capture

    def test_split_replay_binds_four_processes_to_their_stages(self):
        directory, capture = self.split_fixture()
        observed = host.verify_split_capture(directory, capture)
        self.assertEqual(set(observed), set(backend.CONTRACT['roles']))
        for role, relative in host.SPLIT_JOURNALS.items():
            self.assertEqual(observed[role], hashlib.sha256((directory / relative / 'rpc.jsonl').read_bytes()).hexdigest())

    def test_split_replay_rejects_forged_roles_and_stage_evidence(self):
        directory, capture = self.split_fixture()
        for name in ('missing_binding', 'wrong_backend_receipt', 'swapped_stage', 'wrong_prompt',
                     'missing_cleanup', 'cleanup_pid', 'cleanup_role'):
            bad = copy.deepcopy(capture)
            if name == 'missing_binding':
                del bad['backend_bindings']['acl']
            elif name == 'wrong_backend_receipt':
                bad['backend_bindings']['acl'] = copy.deepcopy(bad['backend_bindings']['primary'])
            elif name == 'swapped_stage':
                bad['stages']['status'] = copy.deepcopy(bad['stages']['principal'])
            elif name == 'wrong_prompt':
                bad['stages']['status']['prompt_sha256'] = '0' * 64
            elif name == 'missing_cleanup':
                bad['cleanups'][1]['owned_tree_no_running_members'] = False
            elif name == 'cleanup_pid':
                bad['cleanups'][1]['pid'] = bad['cleanups'][0]['pid']
            else:
                bad['cleanups'][1]['role'] = 'primary'
            with self.subTest(name=name), self.assertRaises((ValueError, KeyError, TypeError)):
                host.verify_split_capture(directory, bad)

        acl_launch = directory / host.SPLIT_JOURNALS['acl'] / 'launch.json'
        original = json.loads(acl_launch.read_text())
        for mutation in ('role', 'pid', 'argv'):
            bad = copy.deepcopy(original)
            if mutation == 'role':
                bad['role'] = 'primary'
            elif mutation == 'pid':
                bad['pid'] = 1
            else:
                bad['argv'] = [capture['plan']['codex'], *backend.launch_flags('mxc'), 'app-server']
            acl_launch.write_text(json.dumps(bad), encoding='utf-8')
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, KeyError, TypeError)):
                host.verify_split_capture(directory, capture)
        acl_launch.write_text(json.dumps(original), encoding='utf-8')

    def test_split_replay_rejects_missing_thread_and_approval_request(self):
        directory, capture = self.split_fixture()
        path = directory / host.SPLIT_JOURNALS['acl'] / 'rpc.jsonl'
        original = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        cases = []
        handshake = next(row['message']['id'] for row in original
                         if row['direction'] == 'request' and row['message'].get('method') == 'thread/start')
        cases.append([row for row in original if row['message'].get('id') != handshake])
        bad = copy.deepcopy(original)
        bad.append({'direction': 'response', 'message': {
            'id': 99, 'method': 'item/commandExecution/requestApproval', 'params': {}}})
        cases.append(bad)
        for index, rows in enumerate(cases):
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
            with self.subTest(index=index), self.assertRaises((ValueError, KeyError, TypeError)):
                host.verify_split_capture(directory, capture)

    def test_split_fixture_requires_exact_copied_bytes_and_authored_request(self):
        root = Path(self.temp.name)
        snapshot = root / 'snapshot'
        snapshot.mkdir()
        (snapshot / 'state.json').write_bytes(b'{"synthetic":true}\n')
        stage = {'thread': 'thread', 'turn': 'turn', 'snapshot': str(snapshot)}
        argv = ['python', 'script', 'checkpoint-status', '--data-dir', 'source',
                '--session-id', 'thread', '--turn-id', 'turn', '--token', 'fixture-token', '--commands']
        data = (snapshot / 'state.json').read_bytes()
        request = {'fixture': 'fixture', 'turn': 'turn', 'state_revision': 'bound-revision',
                   'argv': [*argv[:3], '--data-dir', 'fixture', '--session-id', 'thread',
                            '--turn-id', 'turn', '--token', 'fixture-token', '--commands'],
                   'inventory': {'sessions-v2/thread/state.json': {
                       'kind': 'file', 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}}}
        path = root / 'authored-readonly-request.json'
        path.write_text(json.dumps(request), encoding='utf-8')
        with mock.patch.object(host, 'state_for', return_value={'content_hash': 'bound-revision'}), \
             mock.patch.object(host, 'command_observation', return_value={}), \
             mock.patch.object(host, 'status_argv', return_value=argv):
            host.verify_split_fixture(stage, request, self.plan, {}, root)
            altered = copy.deepcopy(request)
            altered['inventory']['sessions-v2/thread/state.json']['sha256'] = '0' * 64
            path.write_text(json.dumps(altered), encoding='utf-8')
            with self.assertRaises(ValueError):
                host.verify_split_fixture(stage, altered, self.plan, {}, root)
            path.write_text(json.dumps(request), encoding='utf-8')
            with self.assertRaises(ValueError):
                host.verify_split_fixture(stage, altered, self.plan, {}, root)


class WindowsBackendContractTests(P0Harness):
    ready = full.FullV2Tests.ready
    hook = full.FullV2Tests.hook
    stage = full.FullV2Tests.stage
    v2_host = full.FullV2Tests.v2_host
    stop_fixture = full.FullV2Tests.stop_fixture
    full_host = full.FullV2Tests.full_host
    full_capture = full.FullV2Tests.full_capture

    def test_legacy_full_plan_capture_and_result_reject_split_fields(self):
        capture = self.full_capture()
        original = host.validate_result(host.map_capture(capture))
        self.assertEqual(original['status'], 'passed')
        self.assertEqual(original['native_acceptance'], 'not_run')

        legacy_plan = copy.deepcopy(capture['plan'])
        legacy_plan['backend_contract'] = {'schema': 'forged'}
        with self.assertRaises((ValueError, KeyError)):
            host.profile_for_plan(legacy_plan)

        legacy_capture = copy.deepcopy(capture)
        legacy_capture['backend_bindings'] = {'primary': {'schema': 'forged'}}
        with self.assertRaises((ValueError, KeyError)):
            host.map_capture(legacy_capture)

        legacy_result = copy.deepcopy(original)
        legacy_result['execution_identity']['backend_contract'] = {'schema': 'forged'}
        legacy_result['execution_identity']['backend_journal_sha256'] = {'primary': '0' * 64}
        with self.assertRaises((ValueError, KeyError)):
            host.validate_result(legacy_result)


if __name__ == '__main__':
    unittest.main()
