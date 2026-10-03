"""Explicit incident_host_supplement/v1: retain a partial native batch unchanged.

Runs only missing diagnostics/read-only/Stop/compaction observations. A new
status anchor is necessary for fresh turn-bound control; original passed gates
retain their original subjects. No models run in prepare/map/preflight.
"""
from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.validation import incident_host_acceptance as h  # noqa: E402

SCHEMA = 'incident-host-supplement/v1'
RETAINED = {'hook_trust', 'pause_same_unit', 'resume_provenance_pending',
            'typed_wait_retained', 'status_cli_posttool'}
MISSING = set(h.GATES) - RETAINED


def read(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            h.base.require(key not in result, 'duplicate input field')
            result[key] = value
        return result
    h.base.require(path.stat().st_size <= 128 * 1024 * 1024, 'input budget')
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)


def bundle(directory):
    directory = directory.absolute()
    h.base.require(directory != ROOT and ROOT not in directory.parents, 'private bundle required')
    paths = [directory, *directory.rglob('*')]
    for path in paths:
        info = path.lstat()
        h.base.require((stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                       and not getattr(info, 'st_file_attributes', 0) & 0x400,
                       'linked or special bundle')
    catalog = read(directory / 'artifacts.json')
    files = {p.relative_to(directory).as_posix() for p in paths if p.is_file()}
    h.base.require(set(catalog) == files - {'artifacts.json', 'result.json'}, 'incomplete catalog')
    for name, digest in catalog.items():
        target = directory / name
        h.base.require(target.resolve().is_relative_to(directory.resolve())
                       and target.is_file() and h.base.sha(target) == digest, 'artifact drift')
    capture = read(directory / 'capture.json')
    for stage in capture.get('stages', {}).values():
        h.base.require(Path(stage['snapshot']).resolve().is_relative_to(directory.resolve()),
                       'snapshot escaped')
    if capture.get('stop_directory'):
        h.base.require(Path(capture['stop_directory']).resolve() == directory.resolve() / 'stop',
                       'Stop bundle escaped')
    result = h.map_capture(capture)
    h.validate_result(result)
    identity = {name: h.base.sha(directory / name) for name in
                ('capture.json', 'artifacts.json', 'plan.json')}
    h.base.require(read(directory / 'plan.json') == capture['plan'], 'bundle plan drift')
    if (directory / 'result.json').exists():
        identity['result.json'] = h.base.sha(directory / 'result.json')
    return capture, result, identity


def contract(base_capture, base_result, new_plan):
    h.validate_result(base_result)
    old = base_capture['plan']
    h.base.require(base_result['evidence_scope'] == base_capture['origin'], 'scope drift')
    h.base.require({k for k, v in base_result['gates'].items() if v == 'passed'} == RETAINED
                   and all(base_result['gates'][k] == 'pending' for k in MISSING),
                   'original gate set differs')
    h.base.require(set(base_capture['stages']) ==
                   {'pending', 'pause', 'resume', 'typed', 'typed_resume', 'status'},
                   'original stage set differs')
    for key in ('runtime_sha256', 'plugin_root', 'home', 'cwd', 'data_root', 'python',
                'python_sha256', 'python_version', 'codex', 'cli_sha256', 'cli_version',
                'platform', 'model', 'effort', 'shell', 'manifest_sha256'):
        h.base.require(old.get(key) == new_plan.get(key), 'supplement execution binding differs: ' + key)
    h.base.require(new_plan['schema'] == old['schema'] == 'incident-host-plan/v1'
                   and new_plan['output'] != old['output'], 'supplement plan scope differs')
    h.base.require(new_plan['manifest_sha256'] == h.base.sha(h.MANIFEST), 'scenario bytes drift')


def prepare(base_dir, plan_file, output, expected):
    capture, result, identity = bundle(base_dir)
    h.base.require(all(identity.get(k) == v for k, v in expected.items()), 'original input pin differs')
    h.base.require(set(expected) == {'artifacts.json', 'result.json', 'plan.json'}, 'original pins incomplete')
    plan = read(plan_file)
    contract(capture, result, plan)
    h.write_new(output, {'schema': SCHEMA, 'base_directory': str(base_dir.absolute()),
                        'base_hashes': identity, 'base_plan_sha256': capture['plan_sha256'],
                        'retained_gates': sorted(RETAINED), 'missing_gates': sorted(MISSING),
                        'new_plan_sha256': h.plan_identity(plan), 'new_plan': plan,
                        'supplement_entry_sha256': h.base.sha(Path(__file__))})


def inputs(path):
    envelope = read(path)
    h.base.require(set(envelope) == {'schema', 'base_directory', 'base_hashes', 'base_plan_sha256',
                                    'retained_gates', 'missing_gates', 'new_plan_sha256',
                                    'new_plan', 'supplement_entry_sha256'}
                   and envelope['schema'] == SCHEMA, 'invalid supplemental contract')
    capture, result, identity = bundle(Path(envelope['base_directory']))
    plan = envelope['new_plan']
    h.base.require(identity == envelope['base_hashes']
                   and capture['plan_sha256'] == envelope['base_plan_sha256']
                   and h.plan_identity(plan) == envelope['new_plan_sha256']
                   and envelope['retained_gates'] == sorted(RETAINED)
                   and envelope['missing_gates'] == sorted(MISSING)
                   and envelope['supplement_entry_sha256'] == h.base.sha(Path(__file__)),
                   'supplement input drift')
    contract(capture, result, plan)
    return envelope, capture, result


def compose(envelope, original, prior, capture, current):
    plan = envelope['new_plan']
    h.validate_result(current)
    h.base.require(capture['plan'] == plan and capture['plan_sha256'] == envelope['new_plan_sha256']
                   and capture['origin'] == original['origin']
                   and set(capture['stages']) <= {'status', 'unknown', 'missing', 'readonly', 'principal'},
                   'supplement subject, scope or stages drift')
    contract(original, prior, plan)
    h.base.require(current['execution_identity']['plan_sha256'] == envelope['new_plan_sha256']
                   and current['execution_identity']['source'] == h.public_source(plan['source']),
                   'supplement result identity differs')
    h.base.require(current['gates']['hook_trust'] == prior['gates']['hook_trust']
                   and capture['inventory'] == original['inventory'], 'Hook inventory drift')
    h.base.require(not any(current['gates'][k] != 'pending' for k in
                   ('pause_same_unit', 'resume_provenance_pending', 'typed_wait_retained')),
                   'duplicate original gate observation')
    gates = {k: prior['gates'][k] if k in RETAINED else current['gates'][k] for k in h.GATES}
    if capture.get('pending_class') or capture.get('failure_class'):
        gates['cleanup'] = 'pending'
    status = 'passed' if set(gates.values()) == {'passed'} else 'pending'
    if 'failed' in gates.values():
        status = 'failed'
    return {'schema': 'incident-host-composed/v1', 'profile': SCHEMA, 'status': status,
            'gates': gates, 'evidence_scope': capture['origin'],
            'native_acceptance': status if capture['origin'] == 'native' else 'not_run',
            'original_execution_identity': prior['execution_identity'],
            'supplement_execution_identity': current['execution_identity'],
            'mapping_identity': current['mapping_identity'],
            'gate_subjects': {k: 'original' if k in RETAINED else 'supplement' for k in h.GATES},
            'original_hashes': envelope['base_hashes'],
            'supplement_plan_sha256': envelope['new_plan_sha256'],
            'limitations': ['Original passed observations are immutable and retain their execution subjects.',
                            'A fresh status anchor supports only the new negative/read-only observations.',
                            'Replay never becomes native observation; both captures must be native.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--base-dir', type=Path, required=True)
    prep.add_argument('--plan', type=Path, required=True)
    prep.add_argument('--output', type=Path, required=True)
    for name in ('catalog', 'result', 'plan'):
        prep.add_argument('--base-' + name + '-sha256', required=True)
    for action in ('run', 'map'):
        command = sub.add_parser(action)
        command.add_argument('--contract', type=Path, required=True)
        command.add_argument('--output', type=Path, required=True)
        if action == 'run':
            command.add_argument('--preflight', action='store_true')
        else:
            command.add_argument('--capture-dir', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(args.base_dir, args.plan, args.output,
                {'artifacts.json': args.base_catalog_sha256, 'result.json': args.base_result_sha256,
                 'plan.json': args.base_plan_sha256})
        return 0
    envelope, original, prior = inputs(args.contract)
    plan = envelope['new_plan']
    if args.action == 'run':
        h.base.require(args.output.resolve() == Path(plan['output']).resolve(), 'output differs')
        h.base.require(args.output.resolve() != ROOT and ROOT not in args.output.resolve().parents,
                       'private output outside source required')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.parent / (args.output.name + '.supplement-plan.json')
        if temporary.exists():
            h.base.require(read(temporary) == plan, 'preflight plan differs')
        else:
            h.write_new(temporary, plan)
        h.preflight(temporary, args.output)
        if args.preflight:
            print('supplement_preflight=passed; models=0; inputs_only')
            return 0
        h.collect(plan, args.output, supplemental=True)
        h.write_new(args.output / 'artifacts.json',
                    {p.relative_to(args.output).as_posix(): h.base.sha(p)
                     for p in args.output.rglob('*') if p.is_file()})
        directory = args.output
        output = args.output / 'result.json'
    else:
        directory, output = args.capture_dir, args.output
    capture, current, _ = bundle(directory)
    h.write_new(output, compose(envelope, original, prior, capture, current))
    return 0 if set(current['gates'][k] for k in MISSING) == {'passed'} else 1


if __name__ == '__main__':
    raise SystemExit(main())
