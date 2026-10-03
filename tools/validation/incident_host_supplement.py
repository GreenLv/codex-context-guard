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
SCHEMA_V2 = 'incident-host-supplement/v2'
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


def bundle(directory, *, map_whole=True):
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
    result = h.map_capture(capture) if map_whole else None
    if result is not None:
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


def contract_v2(original, prior, plan):
    h.validate_result(prior)
    h.base.require(h.profile_for_plan(plan) == h.PROFILE_V2
                   and original['plan']['schema'] == 'incident-host-plan/v1'
                   and prior['gate_profile'] == h.PROFILE
                   and {k for k, v in prior['gates'].items() if v == 'passed'} == RETAINED
                   and all(prior['gates'][k] == 'pending' for k in MISSING)
                   and set(original['stages']) == {'pending', 'pause', 'resume', 'typed', 'typed_resume', 'status'},
                   'v2 retained base differs')
    old = original['plan']
    for key in ('runtime_sha256', 'plugin_root', 'home', 'cwd', 'data_root', 'python',
                'python_sha256', 'python_version', 'codex', 'cli_sha256', 'cli_version',
                'platform', 'model', 'effort', 'shell'):
        h.base.require(old.get(key) == plan.get(key), 'v2 input binding differs: ' + key)
    h.base.require(plan['output'] != old['output']
                   and old['manifest_sha256'] == h.base.sha(h.MANIFEST)
                   and plan['manifest_sha256'] == h.base.sha(h.MANIFEST_V2)
                   and h.base.read_json(h.MANIFEST)['prompts'] == h.base.read_json(h.MANIFEST_V2)['prompts'],
                   'v2 manifest/output differs')


def retained_components(capture, plan):
    old = capture['plan']
    h.base.require(old['schema'] == 'incident-host-plan/v1'
                   and capture.get('plan_sha256') == h.plan_identity(old)
                   and old['manifest_sha256'] == h.base.sha(h.MANIFEST), 'retained component profile differs')
    for key in ('runtime_sha256', 'plugin_root', 'home', 'cwd', 'data_root', 'python',
                'python_sha256', 'python_version', 'codex', 'cli_sha256', 'cli_version',
                'platform', 'model', 'effort', 'shell'):
        h.base.require(old.get(key) == plan.get(key), 'retained component input differs: ' + key)
    try:
        whole = h.map_capture(capture)
    except (ValueError, KeyError, TypeError, OSError, RuntimeError):
        whole_status = 'failed'
    else:
        whole_status = whole['status']
    h.base.require(whole_status == 'failed', 'retained failed whole cannot be relabeled')
    receipt = capture.get('stop_result')
    h.base.require(isinstance(receipt, dict) and receipt.get('schema') == 'stop-host-acceptance/v1'
                   and receipt.get('status') == 'passed' and receipt.get('source') == old['source']
                   and receipt.get('runtime_sha256') == old['runtime_sha256'], 'retained Stop subject differs')
    h.verify_stop_capture(Path(capture['stop_directory']), old, receipt)
    return {'whole_status': 'failed', 'gates': {'positive_negative_stop': 'passed',
                                             'compaction_cold_resume': 'passed'},
            'execution_identity': {'source': h.public_source(old['source']),
                                   'runtime_sha256': old['runtime_sha256'],
                                   'plan_sha256': capture['plan_sha256'], 'toolkit': old['toolkit']}}


def prepare_v2(base_dir, plan_file, output, expected, retained_dir, retained_expected):
    original, prior, identity = bundle(base_dir)
    plan = read(plan_file)
    contract_v2(original, prior, plan)
    h.base.require(set(expected) == {'artifacts.json', 'result.json', 'plan.json'}
                   and all(identity.get(k) == v for k, v in expected.items()), 'original v2 input pins differ')
    h.base.require(retained_dir is not None and isinstance(retained_expected, dict), 'retained component input required')
    retained, _, hashes = bundle(retained_dir, map_whole=False)
    required = {'artifacts.json', 'capture.json', 'plan.json'} | ({'result.json'} if 'result.json' in hashes else set())
    h.base.require(set(retained_expected) == required
                   and all(hashes.get(k) == v for k, v in retained_expected.items())
                   and retained['origin'] == original['origin'], 'retained component pins/origin differ')
    components = retained_components(retained, plan)
    h.write_new(output, {'schema': SCHEMA_V2, 'base_directory': str(base_dir.absolute()),
                        'base_hashes': identity, 'base_plan_sha256': original['plan_sha256'],
                        'retained_directory': str(retained_dir.absolute()), 'retained_hashes': hashes,
                        'retained_components': components, 'new_plan_sha256': h.plan_identity(plan),
                        'new_plan': plan, 'supplement_entry_sha256': h.base.sha(Path(__file__))})


def inputs_v2(envelope):
    h.base.require(set(envelope) == {'schema', 'base_directory', 'base_hashes', 'base_plan_sha256',
                                    'retained_directory', 'retained_hashes', 'retained_components',
                                    'new_plan_sha256', 'new_plan', 'supplement_entry_sha256'}, 'v2 envelope shape differs')
    original, prior, hashes = bundle(Path(envelope['base_directory']))
    retained, _, retained_hashes = bundle(Path(envelope['retained_directory']), map_whole=False)
    plan = envelope['new_plan']
    h.base.require(hashes == envelope['base_hashes'] and retained_hashes == envelope['retained_hashes']
                   and original['plan_sha256'] == envelope['base_plan_sha256']
                   and h.plan_identity(plan) == envelope['new_plan_sha256']
                   and h.base.sha(Path(__file__)) == envelope['supplement_entry_sha256']
                   and retained['origin'] == original['origin'], 'v2 envelope subject drift')
    contract_v2(original, prior, plan)
    h.base.require(retained_components(retained, plan) == envelope['retained_components'], 'retained component drift')
    return envelope, original, prior


def compose_v2(envelope, original, prior, capture, current):
    plan = envelope['new_plan']
    contract_v2(original, prior, plan)
    h.validate_result(current)
    stages = {'status', 'unknown', 'missing', 'principal', 'readonly',
              'baseline_original', 'baseline_granted', 'baseline_denied'}
    h.base.require(capture['plan'] == plan and capture['plan_sha256'] == envelope['new_plan_sha256']
                   and capture['origin'] == original['origin']
                   and set(capture['stages']) <= stages and not capture.get('stop_result')
                   and current['execution_identity']['plan_sha256'] == envelope['new_plan_sha256']
                   and current['execution_identity']['source'] == h.public_source(plan['source'])
                   and capture['inventory'] == original['inventory'], 'v2 supplement scope/identity differs')
    components = envelope['retained_components']
    h.base.require(components['whole_status'] == 'failed'
                   and components['gates'] == {'positive_negative_stop': 'passed', 'compaction_cold_resume': 'passed'}
                   and all(current['gates'][k] == 'pending' for k in
                           ('pause_same_unit', 'resume_provenance_pending', 'typed_wait_retained',
                            'positive_negative_stop', 'compaction_cold_resume')),
                   'duplicate or unbound component observation')
    gates = {k: prior['gates'][k] if k in RETAINED else
             components['gates'][k] if k in components['gates'] else current['gates'][k] for k in h.GATES}
    if capture.get('pending_class') or capture.get('failure_class'):
        gates['cleanup'] = 'pending'
    status = 'failed' if 'failed' in gates.values() or current['status'] == 'failed' else (
        'passed' if set(gates.values()) == {'passed'} else 'pending')
    return {'schema': 'incident-host-composed/v2', 'profile': SCHEMA_V2, 'status': status,
            'gates': gates, 'evidence_scope': capture['origin'],
            'native_acceptance': status if capture['origin'] == 'native' else 'not_run',
            'original_execution_identity': prior['execution_identity'],
            'retained_component_execution_identity': components['execution_identity'],
            'retained_whole_status': 'failed', 'supplement_execution_identity': current['execution_identity'],
            'mapping_identity': current['mapping_identity'],
            'gate_subjects': {k: 'original' if k in RETAINED else 'retained_component' if k in components['gates']
                              else 'supplement' for k in h.GATES},
            'original_hashes': envelope['base_hashes'], 'retained_hashes': envelope['retained_hashes'],
            'supplement_plan_sha256': envelope['new_plan_sha256'],
            'limitations': ['Mixed-subject bounded supplement, not all gates freshly executed on new source.',
                            'The original retained failed whole remains failed.',
                            'Exact-source release acceptance remains separate.']}


def prepare(base_dir, plan_file, output, expected, *, retained_dir=None, retained_expected=None):
    plan = read(plan_file)
    if h.profile_for_plan(plan) == h.PROFILE_V2:
        return prepare_v2(base_dir, plan_file, output, expected, retained_dir, retained_expected)
    h.base.require(retained_dir is None and retained_expected is None, 'v1 retained override rejected')
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
    if envelope.get('schema') == SCHEMA_V2:
        return inputs_v2(envelope)
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
    if envelope.get('schema') == SCHEMA_V2:
        return compose_v2(envelope, original, prior, capture, current)
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
    prep.add_argument('--retained-dir', type=Path)
    for name in ('catalog', 'capture', 'plan', 'result'):
        prep.add_argument('--retained-' + name + '-sha256')
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
                 'plan.json': args.base_plan_sha256}, retained_dir=args.retained_dir,
                retained_expected=({key: value for key, value in {
                    'artifacts.json': args.retained_catalog_sha256, 'capture.json': args.retained_capture_sha256,
                    'plan.json': args.retained_plan_sha256, 'result.json': args.retained_result_sha256}.items()
                    if value is not None} if args.retained_dir else None))
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
    result = compose(envelope, original, prior, capture, current)
    h.write_new(output, result)
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
