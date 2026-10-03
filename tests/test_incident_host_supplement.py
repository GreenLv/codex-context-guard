"""Composition contract controls
synthetic inputs never certify native runs."""
import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from tests import test_incident_host_acceptance as owning
from tools.validation import incident_host_acceptance as h
from tools.validation import incident_host_supplement as s
from tools.validation import incident_readonly_child as child


class SupplementTests(unittest.TestCase):
    def setUp(self):
        self.plan = {'schema': 'incident-host-plan/v1', 'source': {'head': 'a' * 40,
                     'prepared_source_sha256': 'b' * 64, 'dirty_paths': [], 'renamed_away': []},
                     'runtime_sha256': 'c' * 64, 'cli_sha256': 'd' * 64,
                     'cli_version': 'codex-cli 0.160.0', 'toolkit': h.toolkit(),
                     'platform': 'Windows', 'manifest_sha256': h.base.sha(h.MANIFEST),
                     'output': '/original'}
        self.new = {**self.plan, 'output': '/supplement'}
        self.original = {'plan': self.plan, 'origin': 'synthetic',
                         'stages': {k: {} for k in ('pending', 'pause', 'resume', 'typed',
                                                   'typed_resume', 'status')}, 'inventory': {}}
        def result(plan, gates):
            return {'schema': 'incident-host-acceptance/v1', 'gate_profile': h.PROFILE, 'status': 'pending',
                    'evidence_scope': 'synthetic', 'native_acceptance': 'not_run', 'gates': gates,
                    'execution_identity': {'source': h.public_source(plan['source']),
                                           'plan_sha256': h.plan_identity(plan)},
                    'mapping_identity': {}}
        self.prior = result(self.plan, {k: 'passed' if k in s.RETAINED else 'pending' for k in h.GATES})
        self.current = result(self.new, {k: 'passed' if k in s.MISSING or k in
                              ('hook_trust', 'status_cli_posttool') else 'pending' for k in h.GATES})
        self.capture = {'plan': self.new, 'plan_sha256': h.plan_identity(self.new),
                        'origin': 'synthetic', 'stages': {k: {} for k in
                        ('status', 'unknown', 'missing', 'readonly')}, 'inventory': {}}
        self.envelope = {'new_plan': self.new, 'new_plan_sha256': h.plan_identity(self.new),
                         'base_hashes': {'capture.json': 'e' * 64}}

    def compose(self, capture=None, current=None):
        return s.compose(self.envelope, self.original, self.prior,
                         capture or self.capture, current or self.current)

    def test_retained_subjects_and_missing_only_join_not_native(self):
        before = copy.deepcopy(self.original)
        result = self.compose()
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['native_acceptance'], 'not_run')
        self.assertEqual(self.original, before)
        self.assertEqual({k for k, v in result['gate_subjects'].items() if v == 'original'}, s.RETAINED)
        self.assertEqual(result['original_execution_identity'], self.prior['execution_identity'])

    def test_runtime_plan_original_gate_and_duplicate_drift_rejected(self):
        for key in ('runtime_sha256', 'platform', 'model', 'effort', 'shell', 'manifest_sha256'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                s.contract(self.original, self.prior, {**self.new, key: 'different'})
        for key in s.RETAINED | s.MISSING:
            bad = copy.deepcopy(self.prior)
            bad['gates'][key] = 'pending' if key in s.RETAINED else 'passed'
            with self.subTest(gate=key), self.assertRaises(ValueError):
                s.contract(self.original, bad, self.new)
        bad = copy.deepcopy(self.capture)
        bad['stages']['pause'] = {}
        with self.assertRaises(ValueError):
            self.compose(bad)
        bad = copy.deepcopy(self.current)
        bad['gates']['pause_same_unit'] = 'passed'
        with self.assertRaises(ValueError):
            self.compose(current=bad)

    def test_pending_missing_observation_or_restore_failure_never_green(self):
        for gate in s.MISSING:
            bad = copy.deepcopy(self.current)
            bad['gates'][gate] = 'pending'
            self.assertEqual(self.compose(current=bad)['status'], 'pending')
        bad = copy.deepcopy(self.capture)
        bad['pending_class'] = 'RestorationError'
        self.assertEqual(self.compose(bad)['gates']['cleanup'], 'pending')
        bad = copy.deepcopy(self.capture)
        bad['origin'] = 'native'
        with self.assertRaises(ValueError):
            self.compose(bad)
        bad = copy.deepcopy(self.capture)
        bad['inventory']['foreign'] = {}
        with self.assertRaises(ValueError):
            self.compose(bad)
        bad = copy.deepcopy(self.current)
        bad['execution_identity']['plan_sha256'] = 'f' * 64
        with self.assertRaises(ValueError):
            self.compose(current=bad)

    @unittest.skipIf(os.name == 'nt' or (hasattr(os, 'geteuid') and os.geteuid() == 0),
                     'POSIX synthetic chain; native Windows ACL verified separately')
    def test_end_to_end_synthetic_bundle_prepare_and_composed_map(self):
        case = owning.IncidentHostTests('test_full_synthetic_capture_mapping_export_and_inverted_controls')
        case.setUp()
        self.addCleanup(case.doCleanups)
        self.addCleanup(case.tearDown)
        case.ready()
        case.plan.update(schema='incident-host-plan/v1', output=str(case.root / 'old'),
                         manifest_sha256=h.base.sha(h.MANIFEST))
        case.capture['plan_sha256'] = h.plan_identity(case.plan)
        for name in ('pending', 'pause', 'resume', 'typed', 'typed_resume'):
            case.stage(name)
        status = case.stage('status', query_options=['--commands'])
        old = copy.deepcopy(case.capture)
        fixture = case.root / 'restricted'
        fixture.mkdir()
        request = h.make_fixture(case.plan, status,
                                 h.command_observation(status, case.inventory, case.plan),
                                 fixture, inventory=case.inventory)
        try:
            record = child.witness(request)
            self.assertEqual(child.judge(record, request), 'passed')
            for name, options in [('unknown', ['--unknown-status-option']),
                                  ('missing', ['--item', '--commands'])]:
                case.stage(name, query_options=options)
            stage = copy.deepcopy(status)
            argv = [case.plan['python'], str(h.ROOT / 'tools/validation/incident_readonly_child.py'),
                    '--request', str(case.root / 'request.json')]
            for row in stage['rows']:
                if row['method'] in ('item/started', 'item/completed'):
                    row['params']['item']['command'] = h.cg.shell_join(argv)
                    if row['method'] == 'item/completed':
                        row['params']['item']['aggregatedOutput'] = json.dumps(record)
            case.capture.update(readonly_request=request, readonly_tool_argv=argv)
            case.capture['stages']['readonly'] = stage
            stop = case.stop_fixture()
            new = copy.deepcopy(case.capture)
            new['stages'] = {k: v for k, v in new['stages'].items()
                             if k in ('status', 'unknown', 'missing', 'readonly')}
            new['plan'] = {**case.plan, 'output': str(case.root / 'new')}
            new['plan_sha256'] = h.plan_identity(new['plan'])
            for directory, capture in [(case.root / 'old', old), (case.root / 'new', new)]:
                directory.mkdir()
                for name, observed in capture['stages'].items():
                    target = directory / ('snapshot-' + name)
                    shutil.copytree(observed['snapshot'], target)
                    observed['snapshot'] = str(target)
                if capture.get('stop_result'):
                    shutil.copytree(stop, directory / 'stop')
                    capture['stop_directory'] = str(directory / 'stop')
                h.write_new(directory / 'capture.json', capture)
                h.write_new(directory / 'plan.json', capture['plan'])
                h.write_new(directory / 'artifacts.json',
                            {f.relative_to(directory).as_posix(): h.base.sha(f)
                             for f in directory.rglob('*') if f.is_file()})
                h.write_new(directory / 'result.json', h.map_capture(capture))
            base_dir = case.root / 'old'
            new_dir = case.root / 'new'
            contract = case.root / 'contract.json'
            s.prepare(base_dir, new_dir / 'plan.json', contract,
                      {name: h.base.sha(base_dir / name) for name in
                       ('artifacts.json', 'result.json', 'plan.json')})
            envelope, original, prior = s.inputs(contract)
            supplement, result, _ = s.bundle(new_dir)
            composed = s.compose(envelope, original, prior, supplement, result)
            self.assertEqual(composed['status'], 'passed')
            self.assertEqual(composed['native_acceptance'], 'not_run')
            before = (base_dir / 'capture.json').read_bytes()
            self.assertEqual(before, (base_dir / 'capture.json').read_bytes())
            bad = copy.deepcopy(envelope)
            bad['base_hashes']['capture.json'] = '0' * 64
            tampered = case.root / 'tampered.json'
            h.write_new(tampered, bad)
            with self.assertRaises(ValueError):
                s.inputs(tampered)
            with self.assertRaises(ValueError):
                s.prepare(base_dir, new_dir / 'plan.json', contract, envelope['base_hashes'])
        finally:
            child.restore(fixture, request['restriction'])

    def test_duplicate_json_catalog_and_unbound_snapshot_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'duplicate.json'
            path.write_text('{"source":1,"source":2}')
            with self.assertRaises(ValueError):
                s.read(path)
            path.unlink()
            capture = {'stages': {'status': {'snapshot': str(root.parent)}}}
            for name, value in [('plan.json', {}), ('capture.json', capture)]:
                (root / name).write_text(json.dumps(value))
            catalog = {name: h.base.sha(root / name) for name in ('plan.json', 'capture.json')}
            (root / 'artifacts.json').write_text(json.dumps(catalog))
            with self.assertRaises(ValueError):
                s.bundle(root)
            catalog['capture.json'] = '0' * 64
            (root / 'artifacts.json').write_text(json.dumps(catalog))
            with self.assertRaises(ValueError):
                s.bundle(root)


if __name__ == '__main__':
    unittest.main()
