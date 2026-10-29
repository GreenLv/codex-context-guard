"""Synthetic CLI capability and real consumer controls; no model/native pass."""
import copy
import hashlib
import io
import json
import platform
import subprocess
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests import test_incident_host_acceptance as host_tests
from tests import test_incident_host_full_v2 as full_tests
from tests.test_cg122_p0_counterexamples import P0Harness
from tools.validation import incident_host_acceptance as h
from tools.validation import incident_host_supplement as supplement
from tools.validation import native_cli_adoption as a
from tools.validation import stop_host_acceptance as base


def schema_fixture():
    """Small synthetic protocol, not a copied native schema or receipt."""
    def obj(names):
        return {'type': 'object', 'properties': {name: {} for name in names}}
    requests = {
        'initialize': ('clientInfo', 'capabilities'), 'hooks/list': ('cwds',),
        'environment/info': ('environmentId',),
        'thread/start': ('cwd', 'sandbox', 'approvalPolicy', 'model', 'developerInstructions'),
        'thread/resume': ('threadId', 'cwd', 'sandbox', 'approvalPolicy'),
        'turn/start': ('threadId', 'input', 'effort'), 'thread/compact/start': ('threadId',),
    }
    notifications = {
        'hook/started': ('threadId', 'turnId', 'run'), 'hook/completed': ('threadId', 'turnId', 'run'),
        'turn/started': ('threadId', 'turn'), 'turn/completed': ('threadId', 'turn'),
        'item/started': ('threadId', 'turnId', 'item'), 'item/completed': ('threadId', 'turnId', 'item'),
        'thread/status/changed': ('threadId', 'status'),
    }
    def methods(values):
        return {'oneOf': [{'properties': {'method': {'enum': [method]}, 'params': obj(names)}}
                          for method, names in values.items()]}
    request, notification = methods(requests), methods(notifications)
    turn = next(x for x in request['oneOf'] if x['properties']['method']['enum'] == ['turn/start'])
    turn['properties']['params']['properties']['effort'] = {'anyOf': [{'type': 'string', 'minLength': 1}, {'type': 'null'}]}
    for row in notification['oneOf']:
        method = row['properties']['method']['enum'][0]
        props = row['properties']['params']['properties']
        if method.startswith('hook/'):
            props['run'] = obj(('id', 'eventName', 'sourcePath', 'source', 'handlerType',
                                'displayOrder', 'executionMode', 'status', 'durationMs', 'entries'))
            props['run']['properties']['status'] = {'enum': ['completed', 'blocked']}
        if method.startswith('item/'):
            props['item'] = {'oneOf': []}
            for kind, names in (('commandExecution', ('command', 'exitCode', 'aggregatedOutput', 'status')),
                                ('contextCompaction', ('id',))):
                node = obj((*names, 'type'))
                node['properties']['type'] = {'enum': [kind]}
                props['item']['oneOf'].append(node)
    metadata = obj(('key', 'eventName', 'sourcePath', 'source', 'displayOrder', 'currentHash', 'trustStatus', 'enabled'))
    command = obj(('command', 'handlerType', 'async'))
    command['properties']['handlerType'] = {'enum': ['command']}
    metadata['oneOf'] = [command]
    schemas = {'ClientRequest.json': request, 'ServerNotification.json': notification,
               'v1/InitializeResponse.json': obj(('userAgent', 'platformFamily', 'platformOs')),
               'v2/HooksListResponse.json': {**obj(('data',)), 'definitions': {'HookMetadata': metadata}},
               'v2/EnvironmentInfoResponse.json': {'properties': {'shell': obj(('name', 'path'))}}}
    for name in ('ThreadStartResponse', 'ThreadResumeResponse'):
        schemas['v2/' + name + '.json'] = obj(('thread', 'model', 'approvalPolicy', 'sandbox'))
        schemas['v2/' + name + '.json']['properties']['thread'] = obj(('id',))
    schemas['v2/TurnStartResponse.json'] = {'properties': {'turn': obj(('id', 'status'))}}
    return {name: json.dumps(value) for name, value in schemas.items()}


def receipt_fixture(plan, inventory):
    hooks = [dict(value, trustStatus='untrusted') for value in inventory.values()]
    rpc = []
    for sequence, (method, params, result) in enumerate((
            ('initialize', {'clientInfo': {'name': 'stop-host-acceptance', 'version': '1'},
                            'capabilities': {'experimentalApi': True}}, {'userAgent': 'synthetic-cli'}),
            ('hooks/list', {'cwds': [plan['cwd']]}, {'data': [{'hooks': hooks, 'errors': [], 'warnings': []}]})), 1):
        rpc.extend([{'direction': 'request', 'message': {'id': sequence, 'method': method, 'params': params}},
                    {'direction': 'response', 'message': {'id': sequence, 'result': result}}])
        if sequence == 1:
            rpc.append({'direction': 'request', 'message': {'method': 'initialized', 'params': {}}})
    if plan['platform'] == 'Windows':
        rpc.extend([{'direction': 'request', 'message': {'id': 3, 'method': 'environment/info', 'params': {'environmentId': 'local'}}},
                    {'direction': 'response', 'message': {'id': 3, 'result': {'shell': {k: plan['shell'][k] for k in ('name', 'path')}}}}])
    bundle = schema_fixture()
    receipt = {'schema': a.RECEIPT, 'identity': {key: plan.get(key) for key in
            ('codex', 'cli_sha256', 'cli_version', 'platform', 'home', 'cwd', 'plugin_root',
             'runtime_sha256', 'source', 'shell', 'python', 'python_sha256', 'python_version')},
            'schema_bundle': bundle, 'schema_sha256': a.digest(bundle), 'rpc': rpc, 'rpc_sha256': a.digest(rpc),
            'cleanup': {'owned_process_exited': True, 'owned_tree_no_running_members': True,
                        'process_group_cleanup_error': None, 'process_group_kill_attempted': True,
                        'owned_tree_empty': True, 'process_group_absent': True,
                        'process_group_signal_denied': False, 'process_group_query_denied': False,
                        'escaped_descendants': 'not_established'},
            'producer_sha256': a.sha(Path(a.__file__)), 'generator_returncode': 0, 'stderr_sha256': '0' * 64,
            'app_server_returncode': -15, 'evidence_scope': 'synthetic'}
    directory = Path(plan['cwd']) / ('capability-fixture-' + uuid.uuid4().hex)
    directory.mkdir()
    for name, raw in bundle.items():
        target = directory / 'protocol' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(raw)
    for name in ('version.stderr', 'generator.stdout', 'generator.stderr', 'stderr.txt'):
        (directory / name).write_bytes(b'')
    (directory / 'version.stdout').write_text(a.VERSION + '\n')
    (directory / 'producer.py').write_bytes(Path(a.__file__).read_bytes())
    (directory / 'rpc.jsonl').write_text(''.join(a.canonical(row) + '\n' for row in rpc))
    (directory / 'cleanup.json').write_text(a.canonical({'cleanup': receipt['cleanup'], 'app_server_returncode': -15}))
    (directory / 'commands.json').write_text(a.canonical({
        'version': {'argv': [plan['codex'], '--version'], 'returncode': 0,
                    'stdout_sha256': a.sha(directory / 'version.stdout'), 'stderr_sha256': a.sha(directory / 'version.stderr')},
        'generator': {'argv': [plan['codex'], 'app-server', 'generate-json-schema', '--experimental', '--out', str(directory / 'protocol')],
                      'returncode': 0, 'stdout_sha256': a.sha(directory / 'generator.stdout'), 'stderr_sha256': a.sha(directory / 'generator.stderr')},
        'app_server': {'argv': [plan['codex'], 'app-server'], 'returncode': -15}}))
    catalog = {p.relative_to(directory).as_posix(): a.sha(p) for p in directory.rglob('*') if p.is_file()}
    (directory / 'artifacts.json').write_text(a.canonical(catalog))
    receipt.update(capability_directory=str(directory), catalog_sha256=a.sha(directory / 'artifacts.json'),
                   stderr_sha256=a.sha(directory / 'stderr.txt'))
    (directory / 'receipt.json').write_text(a.canonical(receipt))
    return receipt


class AdoptionConsumerTests(P0Harness):
    ready = host_tests.IncidentHostTests.ready
    def adopt(self):
        self.plan.update(cli_version=a.VERSION, home=str(self.root / 'home'), codex=str(self.root / 'codex'))
        receipt = receipt_fixture(self.plan, self.inventory)
        self.plan['cli_adoption'] = a.adoption(receipt)
        self.capture['plan_sha256'] = h.plan_identity(self.plan)
        return receipt

    def test_v1_mapper_and_result_require_exact_explicit_adoption(self):
        self.ready()
        self.adopt()
        self.assertEqual(h.profile_for_plan(self.plan), h.PROFILE)
        result = h.map_capture(self.capture)
        h.validate_result(result)
        self.assertEqual(result['execution_identity']['cli_adoption'], a.identity(self.plan))
        self.assertEqual(result['native_acceptance'], 'not_run')
        for target in (self.plan, result['execution_identity']):
            original = target.pop('cli_adoption')
            with self.assertRaises(ValueError):
                h.profile_for_plan(self.plan) if target is self.plan else h.validate_result(result)
            target['cli_adoption'] = original

    def test_closed_adoption_and_raw_receipt_negative_family(self):
        self.ready()
        self.adopt()
        mutations = [lambda p: p['cli_adoption'].update(schema='unknown/v9'),
                     lambda p: p['cli_adoption'].update(cli_sha256='a' * 64),
                     lambda p: p['cli_adoption'].update(capability_receipt_sha256='a' * 64),
                     lambda p: p['cli_adoption']['capability_receipt']['identity'].update(home='foreign'),
                     lambda p: p['cli_adoption']['capability_receipt'].update(producer_sha256='a' * 64),
                     lambda p: p['cli_adoption']['capability_receipt']['cleanup'].update(owned_process_exited=False),
                     lambda p: p['cli_adoption']['capability_receipt']['rpc'][0]['message'].update(method='turn/start'),
                     lambda p: p.update(cli_version='codex-cli 0.160.0'),
                     lambda p: p.update(cli_adoption=None)]
        for index, mutate in enumerate(mutations):
            plan = copy.deepcopy(self.plan)
            mutate(plan)
            # Re-hashing attacker-controlled bytes cannot repair their meaning.
            if isinstance(plan.get('cli_adoption'), dict) and index != 2:
                plan['cli_adoption']['capability_receipt_sha256'] = a.digest(plan['cli_adoption']['capability_receipt'])
                receipt = plan['cli_adoption']['capability_receipt']
                receipt['rpc_sha256'] = a.digest(receipt['rpc'])
                plan['cli_adoption']['capability_receipt_sha256'] = a.digest(receipt)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                h.profile_for_plan(plan)

    def test_duplicate_adoption_and_schema_fields_rejected(self):
        self.ready()
        self.adopt()
        path = self.root / 'duplicate.json'
        path.write_text(json.dumps(self.plan)[:-1] + ',"cli_version":"codex-cli 0.160.0"}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            h.read_subject(path)
        bundle = schema_fixture()
        for filename in ('ClientRequest.json', 'ServerNotification.json'):
            changed = copy.deepcopy(bundle)
            doc = json.loads(changed[filename])
            doc['oneOf'].pop()
            changed[filename] = json.dumps(doc)
            with self.assertRaises(ValueError):
                a.validate_schemas(changed)

    def test_retained_artifact_originals_are_required_and_recomputed(self):
        self.ready()
        self.adopt()
        def path(receipt, name):
            return Path(receipt['capability_directory']) / name
        def embedded_rpc(receipt):
            receipt['rpc'][1]['message']['result']['userAgent'] = 'forged embedded value'
            receipt['rpc_sha256'] = a.digest(receipt['rpc'])
        def embedded_cleanup(receipt):
            receipt['cleanup']['owned_tree_empty'] = False
        def wrong_actual_rc(receipt):
            directory = Path(receipt['capability_directory'])
            command = json.loads((directory / 'commands.json').read_text())
            command['generator']['returncode'] = 1
            (directory / 'commands.json').write_text(a.canonical(command))
            catalog = {p.relative_to(directory).as_posix(): a.sha(p) for p in directory.rglob('*')
                       if p.is_file() and p.name not in ('artifacts.json', 'receipt.json')}
            (directory / 'artifacts.json').write_text(a.canonical(catalog))
            receipt['catalog_sha256'] = a.sha(directory / 'artifacts.json')
            (directory / 'receipt.json').write_text(a.canonical(receipt))
        mutations = {
            'missing catalog': lambda r: path(r, 'artifacts.json').unlink(),
            'missing cleanup': lambda r: path(r, 'cleanup.json').unlink(),
            'missing producer': lambda r: path(r, 'producer.py').unlink(),
            'embedded RPC rehashed without original': embedded_rpc,
            'embedded cleanup without original': embedded_cleanup,
            'schema original replaced': lambda r: path(r, 'protocol/ClientRequest.json').write_text('{}'),
            'actual generator failed despite rehashed catalog': wrong_actual_rc,
            'unknown identity': lambda r: r['identity'].update(secret='never accepted'),
            'unknown cleanup': lambda r: r['cleanup'].update(secret='never accepted'),
        }
        for name, mutate in mutations.items():
            receipt = receipt_fixture(self.plan, self.inventory)
            mutate(receipt)
            with self.subTest(case=name), self.assertRaises(ValueError):
                a.validate_receipt(receipt, self.plan)

    def test_legacy_versions_remain_strict(self):
        a.validate({}, legacy_versions={'codex-cli 0.158.0', 'codex-cli 0.160.0'}, default='codex-cli 0.158.0')
        self.ready()
        self.assertEqual(h.profile_for_plan(self.plan), h.PROFILE)
        self.plan['cli_version'] = a.VERSION
        with self.assertRaises(ValueError):
            h.profile_for_plan(self.plan)
        with self.assertRaises(ValueError):
            a.validate(self.plan, legacy_versions={'codex-cli 0.158.0', 'codex-cli 0.160.0'})

    def test_synthetic_originals_cannot_enter_native_preflight_or_collector(self):
        self.ready()
        home, cwd = self.root / 'home', self.root / 'workspace'
        plugin, data = home / 'plugin', home / 'data'
        for path in (plugin, data, cwd):
            path.mkdir(parents=True)
        cli = self.root / 'cli'
        cli.write_bytes(b'synthetic executable bytes; no CLI run')
        self.plan.update(schema='incident-host-plan/v1', repo=str(h.ROOT), home=str(home), cwd=str(cwd),
                         plugin_root=str(plugin), data_root=str(data), codex=str(cli),
                         output=str(self.root / 'capture'), cli_version=a.VERSION, cli_sha256=a.sha(cli),
                         python_sha256=a.sha(Path(self.plan['python'])), python_version='Python synthetic',
                         manifest_sha256=base.sha(h.MANIFEST), model='gpt-6.1-sol', effort='medium')
        for hook in self.inventory.values():
            hook['sourcePath'] = str(plugin / 'hooks/hooks.json')
        self.plan['cli_adoption'] = a.adoption(receipt_fixture(self.plan, self.inventory))
        path = self.root / 'plan.json'
        path.write_text(json.dumps(self.plan))
        with mock.patch.object(base.subprocess, 'check_output', side_effect=lambda argv, **k: a.VERSION if argv[0] == str(cli) else 'Python synthetic'), \
                mock.patch.object(base, 'prepared_source_identity', return_value=self.plan['source']), \
                mock.patch.object(base, 'runtime', return_value=self.plan['runtime_sha256']):
            with self.assertRaisesRegex(ValueError, 'synthetic capability'):
                h.preflight(path, Path(self.plan['output']))
            shared = dict(self.plan, schema='stop-host-plan/v1')
            shared_path = self.root / 'stop-plan.json'
            shared_path.write_text(json.dumps(shared))
            with self.assertRaisesRegex(ValueError, 'synthetic capability'):
                base.preflight(shared_path, self.root / 'stop-output')
            del shared['cli_adoption']
            shared_path.write_text(json.dumps(shared))
            with self.assertRaises(ValueError):
                base.preflight(shared_path, self.root / 'stop-output')
        with mock.patch.object(base, 'Client') as client:
            with self.assertRaisesRegex(ValueError, 'synthetic capability'):
                base.collect(dict(self.plan, schema='stop-host-plan/v1'), self.root / 'synthetic-stop')
            with self.assertRaisesRegex(ValueError, 'synthetic capability'):
                h.collect(self.plan, self.root / 'synthetic-incident')
            client.assert_not_called()

    def test_probe_real_client_rpc_path_never_requests_thread_or_turn(self):
        self.ready()
        home = self.root / 'capability-home'
        plugin = home / 'plugin'
        cwd = self.root / 'capability-workspace'
        plugin.mkdir(parents=True)
        cwd.mkdir()
        cli = self.root / 'fake-cli'
        cli.write_bytes(b'synthetic CLI; never executed')
        self.plan.update(home=str(home), cwd=str(cwd), plugin_root=str(plugin), codex=str(cli),
                         cli_sha256=a.sha(cli), cli_version=a.VERSION, platform=platform.system(),
                         python=str(Path(sys.executable).resolve()),
                         python_sha256=a.sha(Path(sys.executable).resolve()), python_version='Python synthetic')
        for hook in self.inventory.values():
            hook['sourcePath'] = str(plugin / 'hooks/hooks.json')
        fixture = receipt_fixture(self.plan, self.inventory)
        responses = [row['message'] for row in fixture['rpc'] if row['direction'] == 'response']
        stdin = io.StringIO()
        owned = SimpleNamespace(process=SimpleNamespace(stdout=iter(json.dumps(x) + '\n' for x in responses), stdin=stdin,
                                                        poll=lambda: -15),
                                close=lambda seconds: fixture['cleanup'])
        def generate(argv, **kwargs):
            if argv == [str(cli), '--version']:
                return subprocess.CompletedProcess(argv, 0, (a.VERSION + '\n').encode(), b'')
            expected = [str(cli), 'app-server', 'generate-json-schema', '--experimental', '--out',
                        str(self.root / 'capability-output' / 'protocol')]
            if argv != expected:
                raise AssertionError('unexpected fake CLI argv')
            directory = Path(argv[-1])
            for name, raw in fixture['schema_bundle'].items():
                target = directory / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(raw)
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        real_check_output = subprocess.check_output
        def version_probe(argv, **kwargs):
            if argv == [str(cli), '--version']:
                return a.VERSION
            if argv == [self.plan['python'], '--version']:
                return 'Python synthetic'
            return real_check_output(argv, **kwargs)
        # Replace this helper's module binding, never the shared subprocess.run
        # function used by Git/source identity and unrelated consumers.
        probe_subprocess = SimpleNamespace(run=generate, check_output=version_probe,
                                          DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE)
        from tools.validation.acceptance_identity import (
            prepared_source_identity as actual_identity,
        )
        before_identity = actual_identity(h.ROOT)
        before_names = {p.name for p in h.ROOT.iterdir()}
        formal = [*self.plan['toolkit']]
        before_toolkit = {name: hashlib.sha256((h.ROOT / 'tools/validation' / name).read_bytes()).hexdigest()
                          for name in formal}
        with self.assertRaisesRegex(AssertionError, 'unexpected fake CLI'):
            generate(['git', '-C', str(h.ROOT), 'rev-parse', 'HEAD'])
        with self.assertRaisesRegex(AssertionError, 'unexpected fake CLI'):
            generate(['git', '-C', str(h.ROOT), 'status', '--porcelain=v1', '--untracked-files=all'])
        with mock.patch.object(base.OwnedProcess, 'spawn', return_value=owned), \
                mock.patch.object(a, 'subprocess', probe_subprocess), \
                mock.patch.object(base.subprocess, 'check_output', side_effect=version_probe), \
                mock.patch('tools.validation.acceptance_identity.prepared_source_identity', return_value=self.plan['source']), \
                mock.patch.object(base, 'prepared_source_identity', return_value=self.plan['source']), \
                mock.patch.object(base, 'runtime', return_value=self.plan['runtime_sha256']):
            self.assertEqual(actual_identity(h.ROOT), before_identity)
            subject = {key: self.plan.get(key) for key in a.IDENTITY_KEYS}
            subject.update(schema=a.SUBJECT, repo=str(h.ROOT))
            receipt = a.probe(subject, self.root / 'capability-output')
            self.plan.update(schema='incident-host-plan/v1', repo=str(h.ROOT), output=str(self.root / 'native-output'),
                             model='gpt-6.1-sol', effort='medium', manifest_sha256=base.sha(h.MANIFEST),
                             data_root=str(home / 'data'), cli_adoption=a.adoption(receipt))
            (home / 'data').mkdir()
            path = self.root / 'actual-consumer-plan.json'
            path.write_text(json.dumps(self.plan))
            self.assertEqual(h.preflight(path, Path(self.plan['output'])), self.plan)
            shared = json.loads((self.root / 'native-output.preflight-plan.json').read_text())
            self.assertEqual(shared['cli_adoption'], self.plan['cli_adoption'])
            with mock.patch.object(base, 'Client', side_effect=RuntimeError('synthetic test; no model')):
                result = base.collect(shared, self.root / 'stop-consumer')
            self.assertEqual(result['cli_adoption'], a.identity(self.plan))
            self.assertEqual(actual_identity(h.ROOT), before_identity)
        self.assertEqual({p.name for p in h.ROOT.iterdir()}, before_names)
        self.assertEqual({name: hashlib.sha256((h.ROOT / 'tools/validation' / name).read_bytes()).hexdigest()
                          for name in formal}, before_toolkit)
        self.assertFalse((h.ROOT / 'HEAD').exists())
        self.assertFalse((h.ROOT / '--untracked-files=all').exists())
        self.assertEqual([json.loads(line)['method'] for line in stdin.getvalue().splitlines()],
                         ['initialize', 'initialized', 'hooks/list'] + (['environment/info'] if self.plan['platform'] == 'Windows' else []))
        self.assertEqual(receipt['rpc'], fixture['rpc'])
        a.validate_receipt(receipt, self.plan)
        # The independent inventory route does not relax normal trust.
        client = object.__new__(base.Client)
        with self.assertRaisesRegex(ValueError, 'exact trusted'):
            client.validate_inventory([row for row in fixture['rpc'][4]['message']['result']['data'][0]['hooks']],
                                      plugin / 'hooks/hooks.json')


class FullAdoptionTests(P0Harness):
    ready = host_tests.IncidentHostTests.ready
    full_host = full_tests.FullV2Tests.full_host
    def test_full_profile_and_result_adopt_same_cli_without_changing_gates(self):
        self.full_host()
        self.plan.update(home=str(self.root / 'home'), codex=str(self.root / 'codex'), cli_version=a.VERSION)
        self.plan['cli_adoption'] = a.adoption(receipt_fixture(self.plan, self.inventory))
        self.capture['plan_sha256'] = h.plan_identity(self.plan)
        self.assertEqual(h.profile_for_plan(self.plan), h.PROFILE_FULL)
        result = h.map_capture(self.capture)
        h.validate_result(result)
        self.assertEqual(result['required_gates'], list(h.GATES))
        self.assertEqual(result['gate_scope'], 'full')
        self.assertEqual(result['execution_identity']['cli_adoption'], a.identity(self.plan))
        for mutate in (lambda p: p.pop('cli_adoption'), lambda p: p.update(platform='Darwin')):
            bad = copy.deepcopy(self.plan)
            mutate(bad)
            with self.assertRaises(ValueError):
                h.profile_for_plan(bad)
        old = copy.deepcopy(self.plan)
        old.update(schema='incident-host-plan/v1', manifest_sha256=base.sha(h.MANIFEST), output='old-output')
        for key in ('gate_profile', 'gate_scope', 'required_gates', 'observation_contracts', 'negative_parser_reference'):
            old.pop(key, None)
        original = {'plan': old, 'plan_sha256': h.plan_identity(old)}
        changed = copy.deepcopy(old)
        changed['cli_adoption'] = a.adoption(receipt_fixture(changed, self.inventory))
        self.assertEqual(h.profile_for_plan(changed), h.PROFILE)
        with self.assertRaisesRegex(ValueError, 'cli_adoption'):
            supplement.retained_components(original, changed)


if __name__ == '__main__':
    unittest.main()
