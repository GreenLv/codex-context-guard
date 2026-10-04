"""Explicit full v2 scope regressions; all RPC/ACL observations are synthetic."""
import contextlib
import copy
import io
import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

from tests import test_incident_host_acceptance as host_tests
from tests.test_cg122_p0_counterexamples import P0Harness, cg
from tools.validation import incident_host_acceptance as h
from tools.validation import incident_host_supplement as supplement
from tools.validation import incident_readonly_child as child
from tools.validation import stop_host_acceptance as base


class FullV2Tests(P0Harness):
    ready = host_tests.IncidentHostTests.ready
    hook = host_tests.IncidentHostTests.hook
    stage = host_tests.IncidentHostTests.stage
    v2_host = host_tests.IncidentHostTests.v2_host
    stop_fixture = host_tests.IncidentHostTests.stop_fixture

    def full_host(self):
        self.ready()
        shell = self.root / 'bound-shell' / 'pwsh.exe'
        shell.parent.mkdir(exist_ok=True)
        shell.write_bytes(b'synthetic shell identity; never executed')
        self.plan.update(schema='incident-host-plan/v2', gate_profile=h.PROFILE_V2,
                         observation_contracts=dict(h.OBSERVATION_CONTRACTS), platform='Windows',
                         python_sha256=base.sha(Path(self.plan['python'])),
                         runtime_sha256=base.runtime(h.ROOT),
                         shell={'name': 'powershell', 'path': str(shell), 'sha256': base.sha(shell)})
        self.plan['negative_parser_reference'] = h.derive_parser_reference(self.plan)
        self.plan.update(schema='incident-host-plan/v2-full', gate_profile=h.PROFILE_FULL,
                         gate_scope='full', required_gates=list(h.GATES),
                         manifest_sha256=base.sha(h.MANIFEST_FULL))
        self.capture.update(schema='incident-host-capture/v2-full', gate_scope='full',
                            required_gates=list(h.GATES), plan_sha256=h.plan_identity(self.plan))
        self.manifest = base.read_json(h.MANIFEST_FULL)

    def full_capture(self):
        from tests.test_incident_fixture_v3 import FixtureV3Tests
        fixture = FixtureV3Tests('test_snapshot_precedes_exact_read_grant_and_whole_restore')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.full_host()
        self.plan.update(repo=str(h.ROOT), output=str(fixture.output), cwd=str(fixture.cwd))
        self.capture.update(schema='incident-host-capture/v2-full', plan_sha256=h.plan_identity(self.plan), stages={})
        for name in ('pending', 'pause', 'resume', 'typed', 'typed_resume'):
            self.stage(name)
        self.stage('status', query_options=['--commands'])
        for name, options in [('unknown', ['--unknown-status-option']), ('missing', ['--item', '--commands'])]:
            self.stage(name, query_options=options)
        def stage(name, argv, record):
            prompt = h.helper_prompt(self.plan, argv, name)
            self.manifest['prompts'][name] = prompt
            value = self.stage(name, query_options=['--commands'])
            for row in value['rows']:
                item = row.get('params', {}).get('item')
                if item and item.get('type') == 'commandExecution':
                    item['command'] = '& ' + cg.shell_join(argv)
                    if row['method'] == 'item/completed':
                        item.update(exitCode=0, status='completed', aggregatedOutput=json.dumps(record))
            return value
        stage('principal', [self.plan['python'], h.execution_helper_path(self.plan), '--identity'],
              {'schema': 'incident-child-principal/v1', 'platform': 'Windows', 'pid': 42, 'sid': fixture.sid})
        actual_run = subprocess.run
        def run(argv, **kwargs):
            return fixture.apply(argv, **kwargs) if argv[0] == 'icacls' else actual_run(argv, **kwargs)
        with fixture.patches(run):
            transaction = fixture.prepare()
            self.capture['baseline_requests'], self.capture['baseline_tool_argv'] = {}, {}
            for name in ('baseline_original', 'baseline_granted', 'baseline_denied'):
                if name == 'baseline_granted':
                    fixture.grant(transaction)
                elif name == 'baseline_denied':
                    req = fixture.request(transaction, 'baseline_granted')
                    child.apply_read_transaction(fixture.root, transaction, 'deny',
                                                 baseline_record=fixture.observed(req), baseline_request=req)
                req = h.phase_request(fixture.request(transaction, name), name)
                argv = [self.plan['python'], h.execution_helper_path(self.plan), '--request',
                        str(fixture.cwd / ('incident-request-' + fixture.output.name + '-' + name + '.json')), '--baseline']
                self.capture['baseline_requests'][name] = req
                self.capture['baseline_tool_argv'][name] = argv
                stage(name, argv, fixture.observed(req, readable=name != 'baseline_original'))
            req = h.phase_request(fixture.request(transaction, 'readonly'), 'readonly')
            argv = [self.plan['python'], h.execution_helper_path(self.plan), '--request',
                    str(fixture.cwd / ('incident-request-' + fixture.output.name + '.json'))]
            value = {'schema': 'incident-readonly-child/v2', 'request_sha256': req['request_sha256'],
                     'platform': 'Windows', 'pid': 42, 'ppid': 43, 'euid': None, 'sid': fixture.sid,
                     'baseline': fixture.observed(req), 'write_attempts': [{'errno': 13}, {'errno': 1}],
                     'before': req['inventory'], 'after': req['inventory'], 'cli_exit_code': 0,
                     'query_stdout': json.dumps({'advanced_commands': {}, 'turn_id': req['turn'],
                                                  'revision': req['state_revision']}), 'query_stderr': ''}
            stage('readonly', argv, value)
            child.restore(fixture.root, transaction)
            receipt = child.restored_transaction_observation(fixture.root, transaction)
        h.write_new(fixture.output / 'fixture-restoration.json', receipt)
        self.capture.update(readonly_request=req, readonly_tool_argv=argv, fixture_restoration=receipt)
        stop = self.stop_fixture()
        h.write_new(stop / 'plan.json', dict(self.plan, schema='stop-host-plan/v1'))
        self.capture['plan_sha256'] = h.plan_identity(self.plan)
        return self.capture

    def test_full_ten_gate_production_mapper_and_missing_stages(self):
        capture = self.full_capture()
        result = h.validate_result(h.map_capture(capture))
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['scenario_status'], 'passed')
        self.assertEqual(result['required_gates'], list(h.GATES))
        self.assertEqual(result['native_acceptance'], 'not_run')
        for stage in capture['stages']:
            bad = copy.deepcopy(capture)
            del bad['stages'][stage]
            with self.subTest(stage=stage):
                try:
                    observed = h.map_capture(bad)
                except (ValueError, KeyError):
                    continue
                self.assertNotEqual(observed['status'], 'passed')
        for key in ('inventory', 'stop_result', 'cleanups'):
            bad = copy.deepcopy(capture)
            bad.pop(key)
            with self.subTest(key=key):
                try:
                    observed = h.map_capture(bad)
                except ValueError:
                    continue
                self.assertNotEqual(observed['status'], 'passed')
        stop_plan = Path(capture['stop_directory']) / 'plan.json'
        original = stop_plan.read_bytes()
        for field, value in [('home', 'foreign'), ('model', 'foreign'), ('runtime_sha256', '0' * 64),
                             ('cli_sha256', '0' * 64), ('source', {})]:
            bad = dict(capture['plan'], schema='stop-host-plan/v1', **{field: value})
            stop_plan.write_text(json.dumps(bad))
            with self.subTest(field=field), self.assertRaises(ValueError):
                h.map_capture(capture)
        stop_plan.write_bytes(original)

    def test_full_result_gate_and_export_matrix(self):
        healthy = h.map_capture(self.full_capture())
        h.validate_result(healthy)
        for gate in h.GATES:
            for value in ('pending', 'failed', 'unknown', True, False, 1, None):
                bad = copy.deepcopy(healthy)
                bad['gates'][gate] = value
                with self.subTest(gate=gate, value=value), self.assertRaises(ValueError):
                    h.validate_result(bad)
            bad = copy.deepcopy(healthy)
            del bad['gates'][gate]
            with self.assertRaises(ValueError):
                h.validate_result(bad)
        for field, values in [('gate_scope', ['affected', 'unknown', True, None]),
                              ('required_gates', [list(h.GATES[:-1]), list(reversed(h.GATES)), True, None]),
                              ('gate_profile', [h.PROFILE_V2, h.PROFILE, 'unknown']),
                              ('schema', ['incident-host-acceptance/v2', 'unknown']),
                              ('scenario_status', ['pending', 'failed', True]),
                              ('native_acceptance', ['passed', True])]:
            for value in values:
                bad = copy.deepcopy(healthy)
                bad[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    h.validate_result(bad)
        for value in (None, [], True, 'full'):
            bad = copy.deepcopy(healthy)
            bad['execution_identity'] = value
            with self.assertRaises(ValueError):
                h.validate_result(bad)
        native = dict(healthy, evidence_scope='native', native_acceptance='passed')
        h.validate_result(native)  # Export consistency only, never real native evidence.
        for field in ('gate_scope', 'required_gates', 'plan_sha256', 'platform', 'cli_version'):
            bad = copy.deepcopy(healthy)
            del bad['execution_identity'][field]
            with self.subTest(identity=field), self.assertRaises(ValueError):
                h.validate_result(bad)

    def test_plan_capture_scope_downgrade_and_legacy_supplement_refusal(self):
        self.full_host()
        h.profile_for_plan(self.plan)
        for field, values in [('gate_scope', ['affected', 'unknown', True, None]),
                              ('required_gates', [[], list(h.GATES[:-1]), list(reversed(h.GATES)), True]),
                              ('schema', ['incident-host-plan/v2', 'incident-host-plan/v1', 'unknown']),
                              ('gate_profile', [h.PROFILE_V2, h.PROFILE, True])]:
            for value in values:
                bad = copy.deepcopy(self.plan)
                bad[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    h.profile_for_plan(bad)
        for field in ('gate_scope', 'required_gates'):
            bad = copy.deepcopy(self.capture)
            del bad[field]
            with self.assertRaises(ValueError):
                h.map_capture(bad)
        for schema in ('incident-host-capture/v2', 'incident-host-capture/v1'):
            with self.assertRaises(ValueError):
                h.map_capture(dict(self.capture, schema=schema))
        with self.assertRaisesRegex(ValueError, 'supplement'):
            h.collect(self.plan, self.root / 'never-created', supplemental=True)
        self.assertFalse((self.root / 'never-created').exists())
        path = self.root / 'full-plan.json'
        h.write_new(path, self.plan)
        with self.assertRaisesRegex(ValueError, 'full scope'):
            supplement.prepare(self.root, path, self.root / 'never-envelope', {})
        current = h.map_capture(self.capture)
        for compose in (supplement.compose, supplement.compose_v2):
            with self.assertRaisesRegex(ValueError, 'full capture/result'):
                compose({}, {}, {}, self.capture, current)

    def test_full_duplicate_json_and_legacy_readers(self):
        self.full_host()
        plan = json.dumps(self.plan)
        for raw in (plan[:-1] + ', "gate_scope":"affected"}',
                    plan[:-1] + ', "required_gates":[]}',
                    '{"schema":"incident-host-capture/v2-full","stages":{"status":{},"status":{}}}'):
            path = self.root / ('duplicate-' + str(len(raw)) + '.json')
            path.write_text(raw)
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                h.read_subject(path)
        path = self.root / 'legacy.json'
        path.write_text('{"schema":"incident-host-plan/v1","field":1,"field":2}')
        self.assertEqual(h.read_subject(path)['field'], 2)
        with self.assertRaisesRegex(ValueError, 'duplicate input field'):
            supplement.prepare(self.root, path, self.root / 'never-legacy-envelope', {})
        catalog = self.root / 'catalog.json'
        catalog.write_text('{"stage.json":"a","stage.json":"b"}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            h.read_subject(catalog, strict=True)

    def test_full_cli_requires_whole_result(self):
        healthy = h.map_capture(self.full_capture())
        for gate in h.GATES:
            result = copy.deepcopy(healthy)
            result['gates'][gate] = 'pending'
            result.update(status='pending', scenario_status='pending')
            with mock.patch.object(h, 'map_bundle', return_value=result), \
                 mock.patch.object(sys, 'argv', ['acceptance', 'map', '--capture-dir', str(self.root),
                                                '--output', str(self.root / 'unused.json')]), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(h.main(), 1)
        with mock.patch.object(h, 'map_bundle', return_value=healthy), \
             mock.patch.object(sys, 'argv', ['acceptance', 'map', '--capture-dir', str(self.root),
                                            '--output', str(self.root / 'unused.json')]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.main(), 0)

    def test_full_collector_routes_all_existing_scenes_and_restores(self):
        self.full_host()
        for fail_at in (None, 'baseline_granted', 'baseline_denied'):
            with self.subTest(fail_at=fail_at):
                output = self.root / ('collector-' + str(fail_at))
                cwd = self.root / ('workspace-' + str(fail_at))
                cwd.mkdir()
                plan = dict(self.plan, repo=str(h.ROOT), output=str(output), cwd=str(cwd),
                            home=str(self.root / 'isolated-home'))
                log = []
                class Client:
                    inventory = {}
                    def __init__(self, *_):
                        self.sequence = self.turn = 0
                    def start(self, *_):
                        self.sequence += 1
                        return 'thread-' + str(self.sequence)
                    def observed_turn(self, thread, prompt):
                        self.turn += 1
                        log.append(('turn', thread, prompt))
                        return {'thread': thread, 'turn': str(self.turn), 'rows': []}
                    def close(self):
                        log.append(('close',))
                        return {'owned_process_exited': True, 'owned_tree_no_running_members': True}
                restriction = {'policy': child.READ_BASELINE_POLICY, 'sid': 'S-1-5-21-200',
                               'collector_sid': 'S-1-5-21-100', 'grant_complete': False, 'deny_complete': False,
                               'original_snapshot_sha256': 'a' * 64}
                request = {'schema': 'incident-readonly-request/v2', 'restriction': restriction}
                def apply(root, transaction, phase, **kwargs):
                    log.append(('apply', phase, kwargs['baseline_request']['phase']))
                    self.assertEqual(kwargs['baseline_record']['phase'], kwargs['baseline_request']['phase'])
                    transaction[phase + '_complete'] = True
                def observed(stage, inventory, plan, current, argv, name):
                    log.append(('baseline', name, stage['thread']))
                    self.assertEqual(argv[-1], '--baseline')
                    child.v2_request(current)
                    if name == fail_at:
                        raise ValueError('synthetic baseline failure')
                    return {'phase': name}
                with mock.patch.object(h, 'Client', Client), \
                     mock.patch.object(h, 'copy_session'), \
                     mock.patch.object(h, 'command_observation', return_value={}), \
                     mock.patch.object(h, 'principal_observation', return_value=restriction['sid']), \
                     mock.patch.object(h, 'make_fixture', return_value=request), \
                     mock.patch.object(h, 'baseline_observation', side_effect=observed), \
                     mock.patch.object(child, 'apply_read_transaction', side_effect=apply), \
                     mock.patch.object(child, 'restore', side_effect=lambda *_: log.append(('restore',))), \
                     mock.patch.object(child, 'restored_transaction_observation', return_value={
                         'status': 'verified', 'original_snapshot_sha256': 'a' * 64}), \
                     mock.patch.object(h, 'prepared_source_identity', return_value=plan['source']), \
                     mock.patch.object(h.base, 'runtime', return_value=plan['runtime_sha256']), \
                     mock.patch.object(h.base, 'collect', return_value={'cleanups': [
                         {'owned_process_exited': True, 'owned_tree_no_running_members': True}] * 2}) as stop:
                    capture = h.collect(plan, output, supplemental=False)
                if fail_at is None:
                    stop.assert_called_once()
                    self.assertEqual(stop.call_args.args[0], dict(plan, schema='stop-host-plan/v1'))
                    self.assertEqual(len(capture['cleanups']), 3)
                else:
                    stop.assert_not_called()
                self.assertEqual([e[0] for e in log].count('close'), 1)
                self.assertEqual([e[0] for e in log].count('restore'), 1)
                self.assertLess(log.index(('close',)), log.index(('restore',)))
                self.assertEqual({e[2] for e in log if e[0] == 'baseline'}, {'thread-3'})
                self.assertIn('pending', capture['stages'])
                if fail_at is None:
                    self.assertEqual([e for e in log if e[0] == 'apply'],
                                     [('apply', 'grant', 'baseline_original'), ('apply', 'deny', 'baseline_granted')])
                    self.assertEqual(set(capture['stages']), {'pending', 'pause', 'resume', 'typed', 'typed_resume', 'status', 'principal', 'baseline_original',
                        'baseline_granted', 'baseline_denied', 'unknown', 'missing', 'readonly'})
                    self.assertNotIn('failure_class', capture)
                    self.assertTrue(capture['readonly_request']['restriction']['grant_complete'])
                    self.assertTrue(capture['readonly_request']['restriction']['deny_complete'])
                else:
                    self.assertEqual(capture['failure_class'], 'ValueError')
                    self.assertNotIn('readonly', capture['stages'])
                    self.assertTrue((output / 'failure.json').is_file())
                self.assertEqual(capture['fixture_restoration']['status'], 'verified')
                # Collector routing uses synthetic dependencies only, never native acceptance.

    def test_full_preflight_manifest_and_shared_boundary(self):
        self.full_host()
        self.plan.update(manifest_sha256=base.sha(h.MANIFEST_FULL), model='synthetic-never-dispatched',
                         effort='medium', python_version=subprocess.check_output([self.plan['python'], '--version'], text=True).strip(),
                         output=str(self.root / 'native-output'))
        plan_file = self.root / 'v2-preflight.json'
        h.write_new(plan_file, self.plan)
        with mock.patch.object(h.platform, 'system', return_value='Windows'), \
             mock.patch.object(h, '_shared_preflight', return_value=self.plan) as shared:
            self.assertEqual(h.preflight(plan_file, Path(self.plan['output'])), self.plan)
            shared.assert_called_once()
            self.assertEqual(shared.call_args.args[0]['schema'], 'stop-host-plan/v1')
            bad = dict(self.plan, manifest_sha256=base.sha(h.MANIFEST))
            wrong = self.root / 'v2-wrong-manifest.json'
            h.write_new(wrong, bad)
            with self.assertRaises(ValueError):
                h.preflight(wrong, Path(self.plan['output']))
        self.assertFalse(Path(self.plan['output']).exists())


    def test_full_bundle_catalog_and_plan_readback(self):
        capture = self.full_capture()
        h.write_new(self.root / 'plan.json', capture['plan'])
        h.write_new(self.root / 'capture.json', capture)
        catalog = {p.relative_to(self.root).as_posix(): base.sha(p)
                   for p in self.root.rglob('*') if p.is_file()}
        h.write_new(self.root / 'artifacts.json', catalog)
        result = h.map_bundle(self.root, self.root / 'result.json')
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['native_acceptance'], 'not_run')
        with self.assertRaises(ValueError):
            h.map_bundle(self.root, self.root / 'result.json')
        raw = (self.root / 'plan.json').read_bytes()
        wrong = dict(capture['plan'], gate_scope='affected')
        (self.root / 'plan.json').write_text(json.dumps(wrong))
        with self.assertRaises(ValueError):
            h.map_bundle(self.root, self.root / 'second-result.json')
        (self.root / 'plan.json').write_bytes(raw)

    def test_full_cli_plan_adoption_is_explicit_and_pins_manifest(self):
        self.full_host()
        for name in ('home', 'workspace'):
            (self.root / name).mkdir()
        common = ['acceptance', 'plan', '--codex', self.plan['python'], '--python', self.plan['python'],
                  '--home', str(self.root / 'home'), '--cwd', str(self.root / 'workspace'),
                  '--plugin-root', str(h.ROOT), '--data-root', str(self.root / 'home' / 'data'),
                  '--model', 'synthetic-never-dispatched', '--shell', self.plan['shell']['path']]
        adopted = ['--profile', h.PROFILE_V2, '--negative-observation', h.OBSERVATION_CONTRACTS['negative'],
                   '--fixture-policy', h.OBSERVATION_CONTRACTS['readonly_fixture']]
        for full in (False, True):
            path = self.root / ('plan-' + str(full) + '.json')
            args = common + adopted + (['--gate-scope', 'full'] if full else [])
            args += ['--plan-file', str(path), '--output', str(self.root / ('output-' + str(full)))]
            with mock.patch.object(sys, 'argv', args), \
                 mock.patch.object(h.platform, 'system', return_value='Windows'), \
                 mock.patch.object(h, 'preflight') as preflight, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(h.main(), 0)
            preflight.assert_called_once()
            plan = h.read_subject(path)
            self.assertEqual(h.profile_for_plan(plan), h.PROFILE_FULL if full else h.PROFILE_V2)
            self.assertEqual(plan['manifest_sha256'], base.sha(h.MANIFEST_FULL if full else h.MANIFEST_V2))
            if full:
                h.full_scope(plan)
            else:
                self.assertNotIn('gate_scope', plan)
                self.assertNotIn('required_gates', plan)
        for options in (['--gate-scope', 'full'],
                        ['--profile', h.PROFILE_V2, '--gate-scope', 'full']):
            path = self.root / ('rejected-' + str(len(options)) + '.json')
            args = common + options + ['--plan-file', str(path), '--output', str(self.root / 'unused')]
            with mock.patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(h.main(), 2)
            self.assertFalse(path.exists())
