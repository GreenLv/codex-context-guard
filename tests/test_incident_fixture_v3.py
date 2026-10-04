"""Synthetic v3 transaction/actor tests; no native Windows ACL acceptance."""
import base64
import copy
import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from tests import test_incident_acl_family as legacy
from tools.validation import incident_host_acceptance as host
from tools.validation import incident_readonly_child as child


class InheritanceAPIDouble:
    """Independent bounded disk model; no actual Windows API or SID identities."""
    principals = ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-19')
    collector = 'S-1-5-21-101-202-303-1001'
    actor = 'S-1-5-21-101-202-303-1004'

    def __init__(self, root):
        self.root = Path(root)
        self.values, self.writes = {}, []
        self.before_write = None
        self.bad_readback = False
        self.fail_write = None

    @staticmethod
    def ace(sid, flags=3):
        revision, authority, *parts = map(int, sid.split('-')[1:])
        raw = bytes([revision, len(parts)]) + authority.to_bytes(6, 'big')
        raw += b''.join(struct.pack('<I', p) for p in parts)
        return struct.pack('<BBHI', 0, flags, 8 + len(raw), 0x1f01ff) + raw

    @staticmethod
    def sd(control, aces):
        body = b''.join(aces)
        return base64.b64encode(struct.pack('<BBHIIII', 1, 0, control | 0x8000, 0, 0, 0, 20)
                                + struct.pack('<BBHHH', 2, 0, len(body) + 8, len(aces), 0) + body).decode()

    def inheritance(self, path):
        aces = child.descriptor_contract(self.descriptor(path.parent))['aces']
        result = []
        for value in aces:
            ace = bytearray.fromhex(value)
            if ace[1] & (2 if path.is_dir() else 1):
                ace[1] = 19 if path.is_dir() else 16
                result.append(bytes(ace))
        return result

    def cascade(self, ancestor):
        for path in sorted(child.fixture_paths(self.root), key=lambda p: (len(p.parts), str(p))):
            if ancestor not in path.parents:
                continue
            current = child.descriptor_contract(self.descriptor(path))
            if current['dacl_control'] & 0x1000:
                continue
            explicit = [bytes.fromhex(a) for a in current['aces'] if not bytes.fromhex(a)[1] & 16]
            self.values[str(path)] = self.sd(0x404, explicit + self.inheritance(path))

    def write(self, path, planned, *, raw=False, security_information=None):
        path = Path(path)
        if path != self.root and self.root not in path.parents:
            raise AssertionError('double write escaped owned family')
        if self.before_write is not None:
            self.before_write(path, planned)
        if self.fail_write is not None:
            self.fail_write(path, planned, len(self.writes))
        contract = child.descriptor_contract(planned)
        named = not raw and bool(contract['dacl_control'] & 0x400)
        flags = (child.restoration_strategy(planned)[1] if named else 4)
        if security_information is not None:
            flags = security_information
        if named and flags == 4 and child.descriptor_contract(self.descriptor(path))['dacl_control'] != 0x1404:
            raise ValueError('protected-current model preflight refuses lost protection')
        aces = [bytes.fromhex(a) for a in contract['aces']]
        if named and flags not in (4, 0x80000000):
            explicit = [a for a in aces if not a[1] & 16]
            aces = explicit if contract['dacl_control'] & 0x1000 else explicit + self.inheritance(path)
            actual = self.sd(contract['dacl_control'], aces)
        else:
            # Raw SetFileSecurity does not promise to retain AUTO_INHERITED.
            actual = self.sd(contract['dacl_control'] & ~0x400, aces) if raw else planned
        if self.bad_readback:
            actual = self.sd(contract['dacl_control'], [self.ace(self.principals[2], 0)])
            self.bad_readback = False
        self.values[str(path)] = actual
        if named and path.is_dir():
            self.cascade(path)
        result = {'api': 'SetNamedSecurityInfoW' if named else 'SetFileSecurityW',
                  'security_information': flags,
                  'return_value': 0 if named else 1, 'winerror': 0}
        self.writes.append({'path': str(path), 'planned': planned, 'actual': actual, 'native_result': result})
        return result

    def descriptor(self, path, planned=None):
        path = Path(path)
        if planned is not None:
            return self.write(path, planned)
        key = str(path)
        if key not in self.values:
            self.values[key] = self.sd(4, [self.ace(p, 3 if path.is_dir() else 0) for p in self.principals])
        return self.values[key]

    def protect(self, path, before):
        path = Path(path)
        contract = child.descriptor_contract(before)
        if contract['dacl_control'] != 0x404 or child.descriptor_contract(self.descriptor(path)) != contract:
            raise ValueError('protection-only source model preimage differs')
        planned = self.sd(0x1404, [bytes.fromhex(a) for a in contract['aces']])
        # Conditional capability model only; Windows native support remains unknown.
        return self.write(path, planned, security_information=0x80000000)

    def patches(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(mock.patch.object(child, 'current_sid', return_value=self.collector))
        stack.enter_context(mock.patch.object(child, 'windows_descriptor', side_effect=self.descriptor))
        stack.enter_context(mock.patch.object(child, 'protect_windows_dacl', side_effect=self.protect))
        double = self
        class Setter:
            def __call__(self, path, flags, buffer):
                if flags != 4:
                    raise AssertionError('raw API security information changed')
                double.write(path, base64.b64encode(buffer.raw[:-1]).decode(), raw=True)
                return 1
        class API:
            SetFileSecurityW = Setter()
        stack.enter_context(mock.patch.object(legacy.ctypes, 'WinDLL', return_value=API(), create=True))
        return stack


class FirstConversionAPIDouble(InheritanceAPIDouble):
    """Root's non-identifying 3-to-3 legacy conversion counterexample only.

    This is an independent, deliberately narrow synthetic rule; not a Windows
    implementation or a reconstruction of private native descriptors.
    """
    principals = ('S-1-5-18', 'S-1-5-32-544', 'S-1-3-4')

    def descriptor(self, path, planned=None):
        path = Path(path)
        if planned is not None:
            return self.write(path, planned)
        key = str(path)
        if key not in self.values:
            self.values[key] = self.sd(4, [self.ace(p, 3 if path.is_dir() else 0)
                                          for p in self.principals])
        return self.values[key]

    def write(self, path, planned, *, raw=False, security_information=None):
        self.prewrite = {str(p): self.descriptor(p) for p in child.fixture_paths(self.root)}
        return super().write(path, planned, raw=raw, security_information=security_information)

    def cascade(self, ancestor):
        for path in sorted(child.fixture_paths(self.root), key=lambda p: (len(p.parts), str(p))):
            if ancestor not in path.parents:
                continue
            current = child.descriptor_contract(self.descriptor(path))
            if current['dacl_control'] & 0x1000:
                continue
            explicit = [bytes.fromhex(a) for a in current['aces'] if not bytes.fromhex(a)[1] & 16]
            if not current['dacl_control'] & 0x400:
                legacy = []
                for a in child.descriptor_contract(self.prewrite[str(path.parent)])['aces']:
                    raw = bytearray.fromhex(a)
                    if raw[1] & (2 if path.is_dir() else 1):
                        raw[1] = 3 if path.is_dir() else 0
                        legacy.append(bytes(raw))
                explicit = [a for a in explicit if a not in legacy]
            self.values[str(path)] = self.sd(0x404, explicit + self.inheritance(path))


class MatrixInheritanceFamilyTests(unittest.TestCase):
    def run_cell(self, kind='directory', control=0x1004, actor_shape='missing', *, fault=None,
                 profile='full32', double_class=InheritanceAPIDouble):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        cwd, output = base / 'workspace', base / 'output'
        cwd.mkdir()
        output.mkdir()
        double = double_class(cwd / 'incident-readonly-output')
        if fault:
            fault(double, output)
        with double.patches():
            result = legacy.matrix_cell({'kind': kind, 'control': control, 'actor_shape': actor_shape},
                                       double.actor, double.collector, base / 'source', output, cwd,
                                       profile=profile)
        return double, result, output

    def assert_s0(self, double, result):
        record = result['s0_record']
        self.assertEqual(set(record['original_dacls']), {str(p) for p in child.fixture_paths(double.root)})
        self.assertEqual(child.inventory(double.root), record['original_inventory'])
        for path, expected in record['original_dacls'].items():
            self.assertEqual(child.descriptor_contract(double.descriptor(path)), child.descriptor_contract(expected))

    def test_legacy_native_equivalent_first_parent_is_three_not_six(self):
        for kind in ('file', 'directory'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'root'
                root.mkdir()
                legacy.matrix_topology(root, kind)
                double = FirstConversionAPIDouble(root)
                with double.patches():
                    before = legacy.matrix_observe(root)
                    parent = double.sd(0x1404, [double.ace(p) for p in
                                               (double.collector, *double.principals[:2])])
                    wrong = legacy.matrix_setup_expected(root, root, parent, before)
                    double.descriptor(root, parent)
                    self.assertEqual(child.descriptor_contract(double.descriptor(root)),
                                     child.descriptor_contract(parent))
                    for path in child.fixture_paths(root)[1:]:
                        self.assertEqual(len(child.descriptor_contract(wrong[str(path)])['aces']),
                                         3 * (len(path.relative_to(root).parts) + 1))
                        actual = child.descriptor_contract(double.descriptor(path))
                        self.assertEqual(actual['dacl_control'], 0x404)
                        self.assertEqual(actual['aces'], [double.ace(p, 19 if path.is_dir() else 16).hex()
                                                        for p in (double.collector, *double.principals[:2])])
                    with self.assertRaises(ValueError):
                        legacy.matrix_check_family(root, wrong, before['inventory'])

    def test_controlled_preimage_closes_first_conversion_without_classifying_S0(self):
        for kind, control, shape, profile in (
                ('file', 0x1004, 'missing', 'full32'), ('directory', 0x1004, 'inherited', 'protected8'),
                ('file', 0x1404, 'missing', 'full32'), ('directory', 0x1404, 'inherited', 'protected8')):
            def fault(double, output):
                first, parent_checked = [], []
                def before(path, planned):
                    saved = json.loads((output / 'setup-original/fixture-original-transaction.json').read_text())
                    self.assertEqual(set(saved['objects']), {str(p) for p in child.fixture_paths(double.root)})
                    if not first:
                        first.append(str(path))
                        self.assertTrue(all(child.descriptor_contract(v)['dacl_control'] == 4
                                            for v in saved['original_dacls'].values()))
                        for p, value in saved['original_dacls'].items():
                            self.assertEqual(child.descriptor_contract(double.descriptor(p)), child.descriptor_contract(value))
                    if (path == double.root and not parent_checked
                            and child.descriptor_contract(planned)['dacl_control'] == 0x1404):
                        parent_checked.append(True)
                        seed = double.sd(0x1404, [double.ace(p, 0) for p in
                                                  (double.collector, *double.principals[:2])])
                        for p in child.fixture_paths(double.root)[1:]:
                            self.assertEqual(child.descriptor_contract(double.descriptor(p)), child.descriptor_contract(seed))
                double.before_write = before
            with self.subTest(kind=kind, control=control, shape=shape, profile=profile):
                double, result, _ = self.run_cell(kind, control, shape, profile=profile,
                                                 double_class=FirstConversionAPIDouble, fault=fault)
                self.assertIn('s1_record', result)
                self.assertEqual(result['status'], 'passed', result.get('failure'))
                self.assert_s0(double, result)
                self.assertEqual(sum(r['phase'] == 'setup_s0' for r in result['restorations']), 1)
                seeds = [t for t in result['setup_transitions'] if t['phase'] == 'controlled_seed']
                self.assertEqual({t['path'] for t in seeds}, {p.relative_to(double.root).as_posix()
                                                            for p in child.fixture_paths(double.root)[1:]})
                self.assertEqual([len(Path(t['path']).parts) for t in seeds],
                                 sorted((len(Path(t['path']).parts) for t in seeds), reverse=True))
                ai = [t for t in result['setup_transitions'] if t['phase'] == 'controlled_AI']
                self.assertEqual([len(Path(t['path']).parts) for t in ai],
                                 sorted(len(Path(t['path']).parts) for t in ai))

    def test_full32_and_protected8_share_protected_target_construction(self):
        for control in (0x1004, 0x1404):
            oracles = []
            for profile in ('full32', 'protected8'):
                double, result, _ = self.run_cell(control=control, profile=profile)
                target = next(e for e in result['setup'] if e['phase'] == 'target')
                self.assertEqual(target['native_result']['api'], 'SetNamedSecurityInfoW' if control == 0x1404 else 'SetFileSecurityW')
                self.assertEqual(target['native_result']['security_information'], 0x80000000 if control == 0x1404 else 4)
                self.assertEqual(len(target['steps']), 2 if control == 0x1404 else 1)
                intermediate = child.descriptor_contract(target['steps'][0]['actual'])
                final = child.descriptor_contract(target['actual'])
                self.assertEqual(intermediate['dacl_control'], 0x404 if control == 0x1404 else 0x1404)
                self.assertEqual(len(intermediate['aces']), 7 if control == 0x1404 else 4)
                if control == 0x1404:
                    self.assertEqual(intermediate['aces'], final['aces'])
                self.assertEqual(final, child.descriptor_contract(result['target_plan']))
                oracles.append((intermediate, final))
                self.assert_s0(double, result)
            self.assertEqual(oracles[0], oracles[1])

    def test_control_only_AI_failure_stays_failed_in_both_profiles(self):
        for profile in ('full32', 'protected8'):
            for mode in ('api', 'readback'):
                def fault(double, _output):
                    def write(path, planned, _count):
                        contract = child.descriptor_contract(planned)
                        if (path == double.root / 'target' and contract['dacl_control'] == 0x1404
                                and any(bytes.fromhex(a)[1] & 16 for a in contract['aces'])):
                            double.fail_write = None
                            if mode == 'api':
                                raise child.DACLWriteError({'api': 'SetNamedSecurityInfoW', 'security_information': 0x80000000,
                                                            'return_value': 5, 'winerror': 5})
                            double.bad_readback = True
                    double.fail_write = write
                with self.subTest(profile=profile, mode=mode):
                    double, result, _ = self.run_cell(control=0x1404, profile=profile, fault=fault)
                    self.assertEqual(result['status'], 'failed')
                    self.assertNotIn('s1_record', result)
                    self.assert_s0(double, result)
                    self.assertEqual([r['phase'] for r in result['restorations']], ['setup_s0'])

    def test_ready_drift_is_refused_before_any_reconciliation_write(self):
        original = legacy.matrix_ready_descendants
        double_holder = []
        writes_before = []
        def fault(double, _output):
            double_holder.append(double)
        def ready(root, target, result, output, inventory):
            double = double_holder[0]
            nested = target / 'nested'
            current = child.descriptor_contract(double.descriptor(nested))
            double.values[str(nested)] = double.sd(current['dacl_control'],
                [double.ace('S-1-5-21-101-202-303-1099', 0), *[bytes.fromhex(a) for a in current['aces']]])
            writes_before.append(len(double.writes))
            with self.assertRaises(ValueError):
                original(root, target, result, output, inventory)
            self.assertEqual(len(double.writes), writes_before[0])
            raise ValueError('pre-phase drift refused by declared preceding family')
        with mock.patch.object(legacy, 'matrix_ready_descendants', side_effect=ready):
            double, result, _ = self.run_cell(fault=fault)
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('s1_record', result)
        self.assert_s0(double, result)

    def test_intermediate_whole_family_failure_prevents_raw_final(self):
        def fault(double, _output):
            def write(path, planned, _count):
                contract = child.descriptor_contract(planned)
                if (path == double.root / 'target' and contract['dacl_control'] == 0x1404
                        and len(contract['aces']) == 4):
                    double.fail_write = None
                    double.values[str(double.root / 'sibling')] = double.sd(0x404, [double.ace('S-1-5-19', 0)])
            double.fail_write = write
        double, result, _ = self.run_cell(fault=fault)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(any(w['path'] == str(double.root / 'target') and
                             child.descriptor_contract(w['planned'])['dacl_control'] == 0x1004 for w in double.writes))
        self.assertNotIn('s1_record', result)
        self.assert_s0(double, result)

    def test_protected_non_ai_all_actor_forms_and_owned_descendants(self):
        for kind in ('file', 'directory'):
            for actor in ('missing', 'explicit', 'inherited', 'deny'):
                with self.subTest(kind=kind, actor=actor):
                    double, result, _ = self.run_cell(kind, actor_shape=actor)
                    self.assertEqual(result['status'], 'passed', result.get('failure'))
                    self.assert_s0(double, result)
                    self.assertEqual([r['phase'] for r in result['restorations']], ['v3', 'v2', 'setup_s0'])
                    for restoration in result['restorations']:
                        self.assertEqual(restoration['outside_guard_actual'], result['outside_guards'])
                        for call in restoration['api']:
                            self.assertEqual(set(call['family_actual']['raw_dacls']),
                                             set(result['s0_record']['original_dacls']))
                    intermediate = next(e for e in result['setup'] if e['phase'] == 'target')['steps'][0]
                    self.assertTrue(all(not bytes.fromhex(a)[1] & 16 for a in
                                        child.descriptor_contract(intermediate['planned'])['aces']))
                    self.assertEqual(child.descriptor_contract(result['target_plan'])['dacl_control'], 0x1004)

    def test_full32_conditional_capability_exact_restores_and_unknown_native(self):
        for cell in legacy.matrix_cells():
            with self.subTest(cell=cell):
                double, result, _ = self.run_cell(**cell, double_class=FirstConversionAPIDouble)
                self.assertEqual(result['status'], 'passed', result.get('failure'))
                self.assert_s0(double, result)
                self.assertEqual([r['phase'] for r in result['restorations']], ['v3', 'v2', 'setup_s0'])
                for restore in result['restorations']:
                    self.assertEqual(restore['status'], 'verified')
                    self.assertEqual(restore['outside_guard_actual'], result['outside_guards'])
                if cell['control'] == 0x1404:
                    plan = legacy.matrix_probe_plan(cell, double.actor, double.collector)
                    self.assertEqual(plan['protected_AI_feasibility'], 'unknown')
                    target_writes = [w for w in double.writes if w['path'] == str(double.root / 'target')]
                    self.assertFalse(any(w['native_result']['api'] == 'SetFileSecurityW' and
                        child.descriptor_contract(w['planned'])['dacl_control'] == 0x1404 for w in target_writes))
                    self.assertFalse(any(w['native_result']['security_information'] == 0x80000004 and
                        any(bytes.fromhex(a)[1] & 16 for a in child.descriptor_contract(w['planned'])['aces'])
                        for w in target_writes))

    def test_raw14_AI_loss_and_full_protected_tail_loss_stay_negative(self):
        for kind in ('file', 'directory'):
            for shape in ('missing', 'inherited'):
                with self.subTest(kind=kind, shape=shape):
                    double, result, _ = self.run_cell(kind, 0x1404, shape)
                    planned = result['target_plan']
                    target = double.root / 'target'
                    double.write(target, planned, raw=True)
                    actual = child.descriptor_contract(double.descriptor(target))
                    expected = child.descriptor_contract(planned)
                    self.assertEqual(actual['dacl_control'], 0x1004)
                    self.assertEqual(actual['aces'], expected['aces'])
                    double.write(target, planned, security_information=0x80000004)
                    actual = child.descriptor_contract(double.descriptor(target))
                    self.assertEqual(actual['aces'], [a for a in expected['aces'] if not bytes.fromhex(a)[1] & 16])
                    self.assertNotEqual(actual, expected)

    def test_control_only_semantic_drift_fails_before_S1_and_restores_S0_once(self):
        for drift in ('AI', 'ACE_flags', 'order', 'outside'):
            original = InheritanceAPIDouble.protect
            def protect(double, path, before):
                result = original(double, path, before)
                contract = child.descriptor_contract(double.descriptor(path))
                aces = [bytearray.fromhex(a) for a in contract['aces']]
                control = contract['dacl_control']
                if drift == 'AI':
                    control &= ~0x400
                elif drift == 'ACE_flags':
                    for a in aces:
                        a[1] &= ~16
                elif drift == 'order':
                    aces.reverse()
                else:
                    double.values[str(double.root.parent)] = double.sd(4, [double.ace('S-1-5-19', 0)])
                double.values[str(path)] = double.sd(control, aces)
                return result
            with self.subTest(drift=drift), mock.patch.object(InheritanceAPIDouble, 'protect', protect):
                double, result, _ = self.run_cell(control=0x1404)
                self.assertEqual(result['status'], 'failed')
                self.assertNotIn('s1_record', result)
                self.assertEqual([r['phase'] for r in result['restorations']], ['setup_s0'])
                self.assert_s0(double, result)
                if drift == 'outside':
                    self.assertIn('restoration_error', result)

    def test_lost_protected_S1_refuses_DACL_only_restore_without_retry(self):
        original = legacy.matrix_restore
        attempts = []
        def restore(root, record, output, label):
            attempts.append(label)
            if label == 'v3':
                path = root / 'target'
                contract = child.descriptor_contract(child.windows_descriptor(path))
                changed = InheritanceAPIDouble.sd(0x404, [bytes.fromhex(a) for a in contract['aces']])
                double_holder[0].values[str(path)] = changed
            return original(root, record, output, label)
        double_holder = []
        with mock.patch.object(legacy, 'matrix_restore', side_effect=restore):
            double, result, _ = self.run_cell(control=0x1404, fault=lambda d, o: double_holder.append(d))
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(attempts, ['v3', 'setup_s0'])
        self.assertEqual(result['restorations'][0]['status'], 'failed')
        self.assert_s0(double, result)

    def test_independent_legacy_A_seven_to_four_counterexample(self):
        for kind in ('file', 'directory'):
            with self.subTest(kind=kind):
                double, result, _ = self.run_cell(kind)
                target = double.root / 'target'
                planned = result['target_plan']
                contract = child.descriptor_contract(planned)
                old_intermediate = double.sd(0x1404, [bytes.fromhex(a) for a in contract['aces']])
                with double.patches():
                    double.write(target, old_intermediate, security_information=0x80000004)
                    self.assertNotEqual(child.descriptor_contract(double.descriptor(target)),
                                        child.descriptor_contract(old_intermediate))

    def test_independent_B_setup_error_has_durable_full_preimage_before_first_write(self):
        for kind in ('file', 'directory'):
            def fault(double, output):
                def before(path, planned):
                    saved = json.loads((output / 'setup-original/fixture-original-transaction.json').read_text())
                    self.assertTrue((double.root / 'target').exists())
                    self.assertEqual(set(saved['objects']), {str(p) for p in child.fixture_paths(double.root)})
                    if not double.writes:
                        for key, original in saved['original_dacls'].items():
                            self.assertEqual(child.descriptor_contract(double.descriptor(key)),
                                             child.descriptor_contract(original))
                    if path == double.root / 'target':
                        double.before_write = None
                        raise OSError('independent B target setup failure')
                double.before_write = before
            with self.subTest(kind=kind):
                double, result, _ = self.run_cell(kind, fault=fault)
                self.assertEqual(result['status'], 'failed')
                self.assertNotIn('restoration_error', result)
                self.assert_s0(double, result)

    def test_API_success_bad_readback_and_interrupt_keep_failure_and_rollback(self):
        for failure in ('bad_readback', 'interrupt'):
            def fault(double, _output):
                def before(path, planned):
                    if path == double.root / 'target':
                        double.before_write = None
                        if failure == 'interrupt':
                            raise KeyboardInterrupt('bounded synthetic interrupt')
                        double.bad_readback = True
                double.before_write = before
            with self.subTest(failure=failure):
                double, result, _ = self.run_cell(fault=fault)
                self.assertEqual(result['status'], 'failed')
                self.assertIn('failed_observation', result)
                self.assert_s0(double, result)

    def test_storage_failure_boundaries_never_become_pass(self):
        for boundary in ('s0', 's1', 'protect_observed', 'restore_observed', 'restore_terminal', 'final'):
            original = child.durable_snapshot
            injected = []
            def durable(path, record):
                path = Path(path)
                selected = {
                    's0': path.name == 'fixture-original-transaction.json' and path.parent.name == 'setup-original',
                    's1': path.name == 'fixture-original-transaction.json' and path.parent.name == 'output',
                    'protect_observed': path.name.endswith('-protect-observed.json'),
                    'restore_observed': path.name == 'v3-restore-1.json',
                    'restore_terminal': path.name == 'v3-terminal.json',
                    'final': path.name == 'matrix-cell.json',
                }[boundary]
                if selected and not injected:
                    injected.append(str(path))
                    raise OSError('synthetic receipt/fsync failure: ' + boundary)
                return original(path, record)
            with self.subTest(boundary=boundary), mock.patch.object(child, 'durable_snapshot', side_effect=durable):
                double, result, _ = self.run_cell()
                self.assertTrue(injected)
                self.assertEqual(result['status'], 'failed')
                if boundary == 's0':
                    self.assertEqual(double.writes, [])
                    self.assertTrue(result['s0_not_formed'])
                else:
                    self.assert_s0(double, result)
                if boundary == 'restore_terminal':
                    self.assertEqual(result['restorations'][0]['status'], 'failed')
                    self.assertIn('receipt_failure', result['restorations'][0])

    def test_ready_S1_drift_rejected_before_business_write_and_S0_restored(self):
        original = child.prepare_read_transaction
        def prepare(root, **kwargs):
            record = original(root, **kwargs)
            target = Path(root) / 'target'
            changed = InheritanceAPIDouble.sd(0x1004, [InheritanceAPIDouble.ace('S-1-5-19', 0)])
            child.windows_descriptor(target, changed)
            return record
        with mock.patch.object(child, 'prepare_read_transaction', side_effect=prepare):
            double, result, _ = self.run_cell()
        self.assertEqual(result['status'], 'failed')
        self.assertIn('rejected_s1_record', result)
        self.assertNotIn('s1_record', result)
        self.assert_s0(double, result)

    def test_grant_and_deny_failures_restore_S1_before_S0(self):
        for phase in ('grant', 'deny'):
            original = child.write_windows_dacl
            called = []
            def writer(path, planned):
                denial = any(bytes.fromhex(a)[0] == 1 for a in child.descriptor_contract(planned)['aces'])
                if ('deny' if denial else 'grant') == phase and not called:
                    called.append(str(path))
                    original(path, planned)
                    raise OSError('successful mutation followed by synthetic ' + phase + ' failure')
                return original(path, planned)
            with self.subTest(phase=phase), mock.patch.object(child, 'write_windows_dacl', side_effect=writer):
                double, result, _ = self.run_cell()
                self.assertEqual(result['status'], 'failed')
                self.assertTrue(called)
                self.assertEqual([r['phase'] for r in result['restorations']], ['failure_s1', 'setup_s0'])
                self.assertTrue(all(r['status'] == 'verified' for r in result['restorations']))
                self.assert_s0(double, result)

    def test_restore_API_or_readback_failure_retained_without_retry(self):
        for stage in ('v3', 'v2', 'setup_s0'):
            for mode in ('api', 'readback'):
                original = legacy.matrix_restore
                injected = []
                def restore(root, record, output, label):
                    if label != stage:
                        return original(root, record, output, label)
                    injected.append(label)
                    real = child.windows_descriptor
                    fired = []
                    def descriptor(path, planned=None):
                        if planned is not None and not fired:
                            fired.append(str(path))
                            if mode == 'api':
                                raise child.DACLWriteError({'api': 'SetFileSecurityW', 'security_information': 4,
                                                            'return_value': 0, 'winerror': 5})
                            real(path, planned)
                            changed = InheritanceAPIDouble.sd(4, [InheritanceAPIDouble.ace('S-1-5-19', 0)])
                            real(path, changed)
                            strategy, flags = child.restoration_strategy(planned)
                            return {'api': 'SetFileSecurityW' if strategy == 'raw-explicit' else 'SetNamedSecurityInfoW',
                                    'security_information': flags, 'return_value': 1 if strategy == 'raw-explicit' else 0,
                                    'winerror': 0}
                        return real(path, planned) if planned is not None else real(path)
                    with mock.patch.object(child, 'windows_descriptor', side_effect=descriptor):
                        return original(root, record, output, label)
                with self.subTest(stage=stage, mode=mode), mock.patch.object(legacy, 'matrix_restore', side_effect=restore):
                    double, result, _ = self.run_cell()
                    self.assertEqual(result['status'], 'failed')
                    self.assertEqual(injected, [stage])
                    self.assertIn('restoration_error', result)
                    self.assertEqual(next(r for r in result['restorations'] if r['phase'] == stage)['status'], 'failed')
                    if stage != 'setup_s0':
                        self.assert_s0(double, result)

    def test_legacy_deny_failure_and_final_receipt_keep_first_failure_record(self):
        original_write = child.write_windows_dacl
        original_save = child.durable_snapshot
        denials = []
        def writer(path, planned):
            if any(bytes.fromhex(a)[0] == 1 for a in child.descriptor_contract(planned)['aces']):
                denials.append(str(path))
                if len(denials) == 2:
                    original_write(path, planned)
                    raise OSError('synthetic legacy deny failure after mutation')
            return original_write(path, planned)
        def durable(path, record):
            if Path(path).name == 'matrix-cell.json':
                raise OSError('synthetic terminal receipt failure')
            return original_save(path, record)
        with mock.patch.object(child, 'write_windows_dacl', side_effect=writer), \
             mock.patch.object(child, 'durable_snapshot', side_effect=durable):
            double, result, _ = self.run_cell()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['failure']['step'], 'deny_v2')
        self.assertEqual(result['receipt_failure']['step'], 'receipt')
        self.assertEqual(result['failed_record']['policy'], 'specific-write-deny/v2')
        self.assertEqual(result['failed_record']['operations'][-1]['status'], 'failed')
        self.assertEqual([r['phase'] for r in result['restorations']], ['v3', 'failure_s1', 'setup_s0'])
        self.assert_s0(double, result)

    def test_fixed_probes_preserve_strict_production_protected_AI_limit(self):
        for control in (0x1004, 0x1404):
            double, result, _ = self.run_cell(control=control, profile='protected8')
            self.assertEqual(child.descriptor_contract(next(e for e in result['setup'] if e['phase'] == 'target')['actual']),
                             child.descriptor_contract(result['target_plan']))
            if control == 0x1004:
                self.assertEqual(result['status'], 'passed')
            else:
                self.assertEqual(result['status'], 'passed')
                self.assertEqual(legacy.matrix_probe_plan(
                    {'kind': 'directory', 'control': control, 'actor_shape': 'missing'},
                    double.actor, double.collector)['protected_AI_feasibility'], 'unknown')
            self.assert_s0(double, result)

    def test_legacy_mixed_B_preimages_cannot_restore_inherited_family(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / 'root'
        root.mkdir()
        double = InheritanceAPIDouble(root)
        s0_root = double.descriptor(root)
        with double.patches():
            changed_parent = double.sd(0x1404, [double.ace(p) for p in
                                               (double.collector, *double.principals[:2])])
            double.descriptor(root, changed_parent)
            target = root / 'target'
            target.write_bytes(b'legacy mixed-stage target')
            mixed_target = double.sd(0x404, double.inheritance(target))
            double.values[str(target)] = mixed_target
            double.descriptor(root, s0_root)
            double.write(target, mixed_target)
            self.assertNotEqual(child.descriptor_contract(double.descriptor(target)),
                                child.descriptor_contract(mixed_target))

    def test_fixed_eight_probe_preflight_pins_and_phase_oracles_are_zero_API(self):
        from types import SimpleNamespace
        cells = legacy.matrix_probes()
        self.assertEqual(len(cells), 8)
        self.assertEqual({(c['kind'], c['control'], c['actor_shape']) for c in cells},
                         {(k, c, a) for k in ('file', 'directory') for c in (0x1004, 0x1404)
                          for a in ('missing', 'inherited')})
        self.assertEqual(len(legacy.matrix_cells()), 32)
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(actor_sid=InheritanceAPIDouble.actor, collector_sid=InheritanceAPIDouble.collector,
                                   expected_source_commit='a' * 40, cell_profile='protected8',
                                   expected_helper_sha256=hashlib.sha256(Path(child.__file__).read_bytes()).hexdigest(),
                                   expected_runner_sha256=hashlib.sha256(Path(legacy.__file__).read_bytes()).hexdigest(),
                                   output=str(Path(directory) / 'result'), fixture_parent=directory)
            with mock.patch.object(legacy.subprocess, 'check_output', side_effect=['a' * 40, b'']), \
                 mock.patch.object(child, 'windows_descriptor') as api, \
                 mock.patch.object(child, 'current_sid') as token:
                report = legacy.matrix_preflight(args)
                api.assert_not_called()
                token.assert_not_called()
            self.assertFalse(Path(args.output).exists())
            self.assertEqual(len(report['probe_plan']), 8)
            self.assertEqual(report['cells'], cells)
            self.assertEqual(report['inputs_sha256'], hashlib.sha256(json.dumps(
                report['inputs'], sort_keys=True, separators=(',', ':')).encode()).hexdigest())
            for plan in report['probe_plan']:
                phases = {p['name']: p for p in plan['phases']}
                if plan['control'] == 0x1404:
                    intermediate, final = phases['materialize_AI'], phases['protect_control_only']
                    self.assertEqual(intermediate['expected']['dacl_control'], 0x404)
                    self.assertEqual(intermediate['security_information'], 0x20000004)
                    self.assertEqual(final['security_information'], 0x80000000)
                    self.assertEqual(final['pDacl'], 'NULL')
                    self.assertEqual(intermediate['expected']['aces'], final['expected']['aces'])
                else:
                    intermediate, final = phases['protect_intermediate'], phases['raw_final']
                    self.assertEqual(intermediate['expected']['dacl_control'], 0x1404)
                    self.assertEqual(len(intermediate['expected']['aces']), 4)
                    self.assertTrue(all(not bytes.fromhex(a)[1] & 16 for a in intermediate['expected']['aces']))
                    self.assertEqual(final['security_information'], 4)
                self.assertEqual(final['expected']['dacl_control'], plan['control'])
                self.assertEqual(len(final['expected']['aces']), 8 if plan['actor_shape'] == 'inherited' else 7)
                self.assertEqual(plan['protected_AI_feasibility'], 'unknown')
            for name, value in (('expected_runner_sha256', 'b' * 64), ('collector_sid', args.actor_sid),
                                ('collector_sid', None)):
                bad = copy.copy(args)
                setattr(bad, name, value)
                with self.subTest(name=name, value=value), \
                     mock.patch.object(legacy.subprocess, 'check_output', side_effect=['a' * 40, b'']), \
                     self.assertRaises(ValueError):
                    legacy.matrix_preflight(bad)


class FixtureV3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.cwd = self.base / 'workspace'
        self.cwd.mkdir()
        self.output = self.base / 'result'
        self.output.mkdir()
        self.root = self.cwd / ('incident-readonly-' + self.output.name)
        self.root.mkdir()
        (self.root / 'nested').mkdir()
        (self.root / 'nested' / 'lock').write_bytes(b'lock')
        self.sid = 'S-1-5-21-200'
        self.collector = 'S-1-5-21-100'
        self.ownership = {k: str(v) for k, v in {'cwd': self.cwd, 'output': self.output,
                         'repo': host.ROOT, 'home': self.base / 'home',
                         'plugin_root': self.base / 'home/cache', 'data_root': self.base / 'home/data'}.items()}
        self.ownership.update(created_exclusively=True,
                              root_identity=[self.root.stat().st_dev, self.root.stat().st_ino])
        self.original = {str(p): legacy.ACLFamilyTests.descriptor_value(str(p))
                         for p in child.fixture_paths(self.root)}
        self.descriptors = dict(self.original)
        self.events = []

    def descriptor(self, path, value=None):
        if value is not None:
            self.events.append(('restore', str(path)))
            self.descriptors[str(path)] = value
            strategy, flags = child.restoration_strategy(value)
            return {'api': 'SetFileSecurityW' if strategy == 'raw-explicit' else 'SetNamedSecurityInfoW',
                    'security_information': flags, 'return_value': 1 if strategy == 'raw-explicit' else 0,
                    'winerror': 0}
        return self.descriptors[str(path)]

    @staticmethod
    def actor_ace(sid, mask, ace_type=0, flags=0):
        parts = list(map(int, sid.split('-')[2:]))
        sid_raw = bytes([1, len(parts) - 1]) + parts[0].to_bytes(6, 'big') + struct.pack('<' + 'I' * (len(parts) - 1), *parts[1:])
        return (struct.pack('<BBHI', ace_type, flags, 8 + len(sid_raw), mask) + sid_raw).hex()

    @staticmethod
    def with_aces(value, aces):
        raw = base64.b64decode(value)
        offset = struct.unpack_from('<I', raw, 16)[0]
        revision = raw[offset]
        body = b''.join(bytes.fromhex(ace) for ace in aces)
        acl = struct.pack('<BBHHH', revision, 0, 8 + len(body), len(aces), 0) + body
        return base64.b64encode(raw[:offset] + acl).decode()

    @classmethod
    def add_actor(cls, value, sid, mask, ace_type=0, flags=0):
        aces = child.descriptor_contract(value)['aces']
        ace = cls.actor_ace(sid, mask, ace_type, flags)
        # New deny at the head; new grant before inherited ACEs. Preserve the
        # original relative order instead of rebuilding a normalized ACL.
        position = 0 if ace_type == 1 and not flags & 0x10 else next(
            (i for i, a in enumerate(aces) if bytes.fromhex(a)[1] & 0x10), len(aces))
        aces.insert(position, ace)
        return cls.with_aces(value, aces)

    def apply(self, path, planned):
        # Synthetic API double, not a CLI process or native acceptance.
        self.assertTrue((self.output / 'fixture-original-transaction.json').is_file())
        self.assertNotEqual(self.sid, self.collector)
        phase = 'deny' if any(bytes.fromhex(a)[:2] == b'\x01\x00'
                              and child.ace_sid(bytes.fromhex(a)) == self.sid
                              for a in child.descriptor_contract(planned)['aces']) else 'grant'
        self.events.append(('api', phase, str(path), planned))
        self.descriptors[str(path)] = planned
        strategy, flags = child.restoration_strategy(planned)
        return {'api': 'SetFileSecurityW' if strategy == 'raw-explicit' else 'SetNamedSecurityInfoW',
                'security_information': flags, 'return_value': 1 if strategy == 'raw-explicit' else 0,
                'winerror': 0}

    def patches(self, runner=None, *, writer=None):
        stack = __import__('contextlib').ExitStack()
        stack.enter_context(mock.patch.object(child, 'current_sid', return_value=self.collector))
        stack.enter_context(mock.patch.object(child, 'windows_descriptor', side_effect=self.descriptor))
        stack.enter_context(mock.patch.object(child, 'write_windows_dacl', side_effect=writer or self.apply))
        if runner is not None:
            stack.enter_context(mock.patch.object(child.subprocess, 'run', side_effect=runner))
        return stack

    def prepare(self):
        return child.prepare_read_transaction(self.root, sid=self.sid, ownership=self.ownership)

    def request(self, record, phase):
        request = {'schema': 'incident-readonly-request/v2', 'fixture': str(self.root),
                   'lock': str(self.root / 'nested/lock'), 'argv': ['python', 'guard', 'checkpoint-status', '--commands'],
                   'restriction': copy.deepcopy(record), 'inventory': child.inventory(self.root),
                   'turn': 'synthetic', 'state_revision': 'a' * 64, 'phase': phase}
        request['request_sha256'] = host.plan_identity(request)
        return request

    def observed(self, request, *, readable=True):
        checks = {n: ({'ok': True} if readable else {'ok': False, 'exception': 'PermissionError',
                   'errno': 13, 'winerror': 5}) for n in ('resolve', 'stat', 'list', 'read_files')}
        if readable:
            checks['read_files']['count'] = sum(v['kind'] == 'file' for v in request['inventory'].values())
        return {'schema': 'incident-read-baseline/v1', 'request_sha256': request['request_sha256'],
                'sid': self.sid, 'pid': 42, 'platform': 'Windows', 'checks': checks,
                'inventory': request['inventory'] if readable else None}

    def grant(self, record):
        req = self.request(record, 'baseline_original')
        return child.apply_read_transaction(self.root, record, 'grant',
                                           baseline_record=self.observed(req, readable=False), baseline_request=req)

    def test_snapshot_precedes_exact_read_grant_and_whole_restore(self):
        with self.patches():
            record = self.prepare()
            self.assertEqual(self.events, [])
            self.assertEqual(record['sid'], self.sid)
            self.assertEqual(record['collector_sid'], self.collector)
            self.grant(record)
            req = self.request(record, 'baseline_granted')
            child.apply_read_transaction(self.root, record, 'deny', baseline_record=self.observed(req), baseline_request=req)
            self.assertTrue(record['grant_complete'] and record['deny_complete'])
            self.assertEqual(record['commands'], [])
            operations = record['operations']
            self.assertEqual(len(operations), len(self.original) * 2)
            self.assertTrue(all(o['status'] == 'verified' for o in operations))
            self.assertEqual({o['phase'] for o in operations}, {'grant', 'deny'})
            self.assertTrue(all('argv' not in o and 'exit_code' not in o for o in operations))
            for operation in operations:
                directory = (self.root / operation['path']).is_dir()
                if operation['phase'] == 'deny':
                    wanted = 0x10156 if directory else 0x10116
                    actors = [bytes.fromhex(a) for a in child.descriptor_contract(operation['actual'])['aces']
                              if child.ace_sid(bytes.fromhex(a)) == self.sid
                              and bytes.fromhex(a)[:2] == b'\x01\x00']
                    self.assertEqual(len(actors), 1)
                    self.assertEqual(struct.unpack_from('<I', actors[0], 4)[0], wanted)
            self.assertTrue(list(self.output.glob('fixture-*-op-*-observed.json')))
            child.restore(self.root, record)
            self.assertEqual(self.descriptors, self.original)

    def test_partial_grant_deny_and_bad_readback_restore_every_original(self):
        for failure in ('grant_api', 'grant_readback', 'deny_api', 'deny_readback',
                        'deny_duplicate', 'deny_split', 'interrupt'):
            with self.subTest(failure=failure):
                fixture = FixtureV3Tests('test_snapshot_precedes_exact_read_grant_and_whole_restore')
                fixture.setUp()
                try:
                    calls = []
                    def apply(path, planned):
                        result = fixture.apply(path, planned)
                        phase = fixture.events[-1][1]
                        calls.append(phase)
                        inject = (failure.startswith('deny') and phase == 'deny') or (
                            failure.startswith('grant') and phase == 'grant' and len(calls) == 2)
                        if inject and failure.endswith('api'):
                            raise child.DACLWriteError({'api': result['api'],
                                'security_information': result['security_information'],
                                'return_value': 0, 'winerror': 5})
                        if inject and failure.endswith('readback'):
                            fixture.descriptors[str(path)] = fixture.add_actor(
                                planned, 'S-1-5-21-999', 1)
                        if inject and failure in ('deny_duplicate', 'deny_split'):
                            aces = child.descriptor_contract(planned)['aces']
                            if failure == 'deny_duplicate':
                                aces.insert(0, fixture.actor_ace(fixture.sid, 2, 1))
                            else:
                                mask = struct.unpack_from('<I', bytes.fromhex(aces[0]), 4)[0]
                                aces[:1] = [fixture.actor_ace(fixture.sid, 2, 1),
                                            fixture.actor_ace(fixture.sid, mask & ~2, 1)]
                            fixture.descriptors[str(path)] = fixture.with_aces(planned, aces)
                        if failure == 'interrupt' and len(calls) == 2:
                            raise KeyboardInterrupt()
                        return result
                    with fixture.patches(writer=apply):
                        record = fixture.prepare()
                        with self.assertRaises(child.RestrictionError) as caught:
                            fixture.grant(record)
                            req = fixture.request(record, 'baseline_granted')
                            child.apply_read_transaction(fixture.root, record, 'deny',
                                baseline_record=fixture.observed(req), baseline_request=req)
                        self.assertEqual(caught.exception.record['restoration'], 'verified')
                        self.assertEqual(fixture.descriptors, fixture.original)
                        failed = record['operations'][-1]
                        self.assertEqual(failed['status'], 'failed')
                        self.assertIsNotNone(failed['actual'])
                        self.assertIn('reason', record['application_failure'])
                        self.assertTrue(list(fixture.output.glob('fixture-*-op-*-failure.json')))
                finally:
                    fixture.doCleanups()

    def deny_case(self, directory, *, existing=False):
        seed = next(iter(self.original.values()))
        mask = 0x10156 if directory else 0x10116
        read = 0x1200a9 if directory else 0x120089
        others = [self.actor_ace('S-1-5-21-999', 2, 1), self.actor_ace('S-1-5-21-998', 4, 1),
                  self.actor_ace('S-1-5-21-997', 0x1f01ff)]
        actor = self.actor_ace(self.sid, read | mask)
        inherited = self.actor_ace(self.sid, 2, 1, flags=0x10)
        before_aces = ([self.actor_ace(self.sid, 2, 1)] if existing else []) + others[:2] + [others[2], actor, inherited]
        expected = ([self.actor_ace(self.sid, mask, 1)] if existing else []) + others[:2] + [
            others[2], self.actor_ace(self.sid, read), inherited]
        if not existing:
            expected.insert(0, self.actor_ace(self.sid, mask, 1))
        return self.with_aces(seed, before_aces), self.with_aces(seed, expected), expected, mask

    def test_exact_file_directory_deny_and_documented_explicit_grant_removal(self):
        for directory in (False, True):
            for existing in (False, True):
                with self.subTest(directory=directory, existing=existing):
                    before, after, _, mask = self.deny_case(directory, existing=existing)
                    self.assertEqual(mask, 0x10156 if directory else 0x10116)
                    child.check_write_deny(before, after, self.sid, directory=directory)
                    aces = child.descriptor_contract(after)['aces']
                    self.assertEqual(struct.unpack_from('<I', bytes.fromhex(aces[0]), 4)[0], mask)
                    if not existing:
                        # A single new deny can sit anywhere within the explicit
                        # deny block; all prior ACEs retain their relative order.
                        at_end = aces[1:3] + aces[:1] + aces[3:]
                        child.check_write_deny(before, self.with_aces(after, at_end), self.sid, directory=directory)
        for unverified in (0, 1, None, 'directory'):
            before, after, _, _ = self.deny_case(False)
            with self.subTest(unverified=unverified), self.assertRaises(ValueError):
                child.check_write_deny(before, after, self.sid, directory=unverified)

    def test_wrong_type_bits_generic_rights_and_ordered_ace_drift_reject(self):
        for directory in (False, True):
            before, after, aces, mask = self.deny_case(directory)
            changes = {}
            for name, changed_mask in [('wrong_DC', mask ^ 0x40), ('generic_W', mask | 0x40000000),
                                       ('SYNCHRONIZE', mask | 0x100000), ('READ_CONTROL', mask | 0x20000),
                                       ('generic_only', 0x40000000)]:
                changes[name] = [self.actor_ace(self.sid, changed_mask, 1)] + aces[1:]
            changes['duplicate'] = [aces[0], aces[0]] + aces[1:]
            changes['split'] = [self.actor_ace(self.sid, 2, 1), self.actor_ace(self.sid, mask & ~2, 1)] + aces[1:]
            changes['other_ACE_changed'] = aces[:1] + [self.actor_ace('S-1-5-21-999', 8, 1)] + aces[2:]
            changes['other_order_changed'] = aces[:1] + [aces[2], aces[1]] + aces[3:]
            changes['deny_after_grants'] = aces[1:5] + aces[:1] + aces[5:]
            changes['inherited_deny_changed'] = aces[:-1] + [self.actor_ace(self.sid, 4, 1, flags=0x10)]
            changes['actor_read_removed'] = aces[:4] + [self.actor_ace(self.sid, 1)] + aces[5:]
            for name, changed in changes.items():
                with self.subTest(directory=directory, name=name), self.assertRaises(ValueError):
                    child.check_write_deny(before, self.with_aces(after, changed), self.sid, directory=directory)
            raw = bytearray(base64.b64decode(after))
            struct.pack_into('<H', raw, 2, struct.unpack_from('<H', raw, 2)[0] ^ 0x1000)
            with self.subTest(directory=directory, name='control'), self.assertRaises(ValueError):
                child.check_write_deny(before, base64.b64encode(raw).decode(), self.sid, directory=directory)

    def test_same_sid_existing_denies_duplicate_split_and_reordering_reject(self):
        before, after, aces, _ = self.deny_case(False, existing=True)
        raw = child.descriptor_contract(before)['aces']
        # Two distinct explicit flag groups remain distinct and ordered.
        raw.insert(1, self.actor_ace(self.sid, 4, 1, flags=3))
        aces.insert(1, self.actor_ace(self.sid, 4, 1, flags=3))
        before, after = self.with_aces(before, raw), self.with_aces(after, aces)
        child.check_write_deny(before, after, self.sid, directory=False)
        for name, changed in [('duplicate', aces[:1] + aces),
                              ('split', [self.actor_ace(self.sid, 2, 1), self.actor_ace(self.sid, 0x10114, 1)] + aces[1:]),
                              ('reorder', [aces[1], aces[0]] + aces[2:])]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                child.check_write_deny(before, self.with_aces(after, changed), self.sid, directory=False)
        duplicate_original = raw[:2] + [raw[1]] + raw[2:]
        with self.assertRaisesRegex(ValueError, 'ambiguous original actor deny'):
            child.check_write_deny(self.with_aces(before, duplicate_original), after, self.sid, directory=False)

    def test_phase_actor_and_positive_baseline_required_before_deny(self):
        with self.patches():
            record = self.prepare()
            req = self.request(record, 'baseline_original')
            bad = self.observed(req)
            bad['sid'] = self.collector
            with self.assertRaises(ValueError):
                child.apply_read_transaction(self.root, record, 'grant', baseline_record=bad, baseline_request=req)
            self.assertEqual(self.events, [])
            self.grant(record)
            req = self.request(record, 'baseline_granted')
            before = len(self.events)
            with self.assertRaises(ValueError):
                child.apply_read_transaction(self.root, record, 'deny', baseline_record=self.observed(req, readable=False), baseline_request=req)
            self.assertEqual(len(self.events), before)
            child.restore(self.root, record)

    def test_ownership_hardlink_reparse_and_original_snapshot_reject(self):
        with self.patches():
            for key, value in [('created_exclusively', False), ('root_identity', [0, 0]), ('home', str(self.root))]:
                old = self.ownership[key]
                self.ownership[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.prepare()
                self.ownership[key] = old
            outside = self.base / 'outside'
            os.link(self.root / 'nested/lock', outside)
            with self.assertRaises(ValueError):
                self.prepare()
            outside.unlink()
            link = self.root / 'link'
            try:
                link.symlink_to(self.base, target_is_directory=True)
            except OSError:
                pass
            else:
                with self.assertRaises(ValueError):
                    self.prepare()
                link.unlink()
            record = self.prepare()
            Path(record['original_snapshot_path']).write_text('changed')
            with self.assertRaises(ValueError):
                self.grant(record)
            self.assertEqual(self.events, [])

    def test_actor_is_observed_before_resolve_failure_and_all_reads_retained(self):
        with self.patches():
            record = self.prepare()
        req = self.request(record, 'baseline_original')
        order = []
        def sid():
            order.append('sid')
            return self.sid
        def denied(*args, **kwargs):
            order.append('resolve')
            raise PermissionError(13, 'synthetic fixture denied')
        with mock.patch.object(child, 'current_sid', side_effect=sid), \
             mock.patch.object(child.platform, 'system', return_value='Windows'), \
             mock.patch.object(Path, 'resolve', side_effect=denied):
            observed = child.baseline(req)
            witness = child.witness(req)
        self.assertEqual(order[:2], ['sid', 'resolve'])
        self.assertEqual(observed['sid'], self.sid)
        self.assertFalse(observed['checks']['resolve']['ok'])
        self.assertEqual(set(observed['checks']), {'resolve', 'stat', 'list', 'read_files'})
        self.assertEqual(child.judge_baseline(observed, req, require_read=False), 'observed')
        self.assertEqual(child.judge_baseline(observed, req), 'failed')
        self.assertEqual(witness['schema'], 'incident-readonly-child/v2')
        self.assertEqual(witness['sid'], self.sid)
        self.assertEqual(child.judge(witness, req), 'failed')

    def test_baseline_type_scope_and_query_write_negative_family(self):
        with self.patches():
            record = self.prepare()
            self.grant(record)
            req = self.request(record, 'baseline_granted')
            child.apply_read_transaction(self.root, record, 'deny', baseline_record=self.observed(req), baseline_request=req)
        req = self.request(record, 'readonly')
        baseline = self.observed(req)
        value = {'schema': 'incident-readonly-child/v2', 'request_sha256': req['request_sha256'],
                 'platform': 'Windows', 'pid': 42, 'ppid': 43, 'euid': None, 'sid': self.sid,
                 'baseline': baseline, 'write_attempts': [{'errno': 13}, {'errno': 1}],
                 'before': req['inventory'], 'after': req['inventory'], 'cli_exit_code': 0,
                 'query_stdout': json.dumps({'advanced_commands': {}, 'turn_id': req['turn'],
                                              'revision': req['state_revision']}), 'query_stderr': ''}
        self.assertEqual(child.judge(value, req), 'passed')
        for key, changed in [('sid', self.collector), ('pid', True), ('cli_exit_code', 1),
                             ('request_sha256', 'bad'), ('after', {}), ('write_attempts', [{'errno': 0}, {'errno': 13}])]:
            bad = dict(value, **{key: changed})
            with self.subTest(key=key):
                try:
                    self.assertNotEqual(child.judge(bad, req), 'passed')
                except ValueError:
                    pass
        bad = copy.deepcopy(value)
        bad['baseline']['checks']['read_files']['count'] = True
        with self.assertRaises(ValueError):
            child.judge(bad, req)
        with self.patches():
            child.restore(self.root, record)

    def test_v2_shared_canonical_unicode_roundtrip_and_byte_mutations(self):
        with self.patches():
            transaction = self.prepare()
        for label, payload in [('ascii', 'plain'), ('path', '中文'), ('replacement', '\ufffd'),
                               ('receipt', {'commands': [{'output': '已处理 1 文件\r\n'}]}),
                               ('nested', {'a': [None, {'中文': '😀'}]}), ('crlf', 'a\r\nb')]:
            with self.subTest(label=label):
                request = self.request(transaction, 'baseline_original')
                request['unicode_case'] = payload
                if label in ('path', 'replacement'):
                    request['fixture'] += payload
                request['request_sha256'] = child.request_identity_v2(request)
                # Both wire spellings decode to the same exact v2 JSON value.
                for ascii_wire in (True, False):
                    wire = json.loads(json.dumps(request, ensure_ascii=ascii_wire))
                    self.assertEqual(child.v2_request(wire), json.loads(json.dumps(request)))
                    phase = host.phase_request(wire, 'baseline_granted')
                    self.assertEqual(child.v2_request(phase), phase)
                    self.assertEqual(child.judge_baseline(self.observed(phase), phase), 'passed')
                for field, changed in [('unicode_case', 'changed'), ('phase', 'readonly'),
                                       ('fixture', request['fixture'] + 'x'),
                                       ('argv', request['argv'] + ['extra']), ('inventory', {})]:
                    bad = copy.deepcopy(request)
                    bad[field] = changed
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        child.v2_request(bad)
                crlf = copy.deepcopy(request)
                crlf['unicode_case'] = 'a\r\nb'
                crlf['request_sha256'] = child.request_identity_v2(crlf)
                crlf['unicode_case'] = 'a\nb'
                with self.assertRaises(ValueError):
                    child.v2_request(crlf)
        with self.patches():
            child.restore(self.root, transaction)

    def test_unicode_v2_witness_judge_legacy_conversion_preserves_outer_subject(self):
        with self.patches():
            record = self.prepare()
            self.grant(record)
            req = self.request(record, 'baseline_granted')
            child.apply_read_transaction(self.root, record, 'deny', baseline_record=self.observed(req), baseline_request=req)
        req = self.request(record, 'readonly')
        req['restriction']['operations'][0]['private_note'] = '本地化回执\r\n\ufffd'
        req['nested'] = {'中文': ['😀']}
        req['request_sha256'] = child.request_identity_v2(req)
        value = {'schema': 'incident-readonly-child/v2', 'request_sha256': req['request_sha256'],
                 'platform': 'Windows', 'pid': 42, 'ppid': 43, 'euid': None, 'sid': self.sid,
                 'baseline': self.observed(req), 'write_attempts': [{'errno': 13}, {'errno': 1}],
                 'before': req['inventory'], 'after': req['inventory'], 'cli_exit_code': 0,
                 'query_stdout': json.dumps({'advanced_commands': {}, 'turn_id': req['turn'],
                                              'revision': req['state_revision']}), 'query_stderr': ''}
        before = copy.deepcopy((req, value))
        self.assertEqual(child.judge(value, req), 'passed')
        self.assertEqual((req, value), before)
        # The old validator still rejects a literal-Unicode digest for a v1 request.
        old = dict(req, schema='incident-readonly-request/v1')
        old['request_sha256'] = host.plan_identity({k: v for k, v in old.items() if k != 'request_sha256'})
        with self.assertRaisesRegex(ValueError, 'request digest invalid'):
            child.judge(dict(value, schema=child.SCHEMA), old)
        with self.patches():
            child.restore(self.root, record)


@contextmanager
def platform_newline_sink(newline):
    """Simulate text translation only; binary writes retain exact bytes."""
    original = Path.open

    def open_with_translation(path, mode='r', *args, **kwargs):
        if mode == 'x' and kwargs.get('encoding') == 'utf-8':
            return io.TextIOWrapper(original(path, 'xb'), encoding='utf-8', newline=newline)
        return original(path, mode, *args, **kwargs)

    with mock.patch.object(Path, 'open', open_with_translation):
        yield


class DurableSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name)

    def test_exact_utf8_bytes_and_digest_under_lf_and_crlf_text_platforms(self):
        record = {'z': ['中文', 'é', '🧭', '  \t spaces  ', 'inside\r\nstring\nend\r'],
                  'a': {'empty': '', 'blank': ' \n '}}
        expected = (json.dumps(record, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
        actual_fsync = os.fsync
        for index, newline in enumerate(('\n', '\r\n')):
            path = self.output / ('snapshot-' + str(index) + '.json')

            def sync_after_flush(fd):
                self.assertEqual(path.read_bytes(), expected)
                return actual_fsync(fd)

            with self.subTest(newline=newline), platform_newline_sink(newline), \
                 mock.patch.object(child.os, 'fsync', side_effect=sync_after_flush) as synced:
                digest = child.durable_snapshot(path, record)
                self.assertEqual(path.read_bytes(), expected)
                self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(json.loads(path.read_bytes()), record)
                synced.assert_called_once()

    def test_exclusive_duplicate_preserves_existing_original_bytes(self):
        path = self.output / 'snapshot.json'
        digest = child.durable_snapshot(path, {'original': '中文\r\n  '})
        before = (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        with platform_newline_sink('\r\n'), self.assertRaises(FileExistsError):
            child.durable_snapshot(path, {'replacement': True})
        self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns), before)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_short_write_never_returns_a_full_payload_digest(self):
        original = Path.open
        path = self.output / 'short.json'

        def open_short(target, mode='r', *args, **kwargs):
            stream = original(target, mode, *args, **kwargs)
            if target == path and mode in ('x', 'xb'):
                proxy = mock.Mock(wraps=stream)
                proxy.__enter__ = mock.Mock(return_value=proxy)
                proxy.__exit__ = mock.Mock(side_effect=stream.__exit__)
                proxy.write.side_effect = lambda raw: stream.write(raw[:-1])
                return proxy
            return stream

        with mock.patch.object(Path, 'open', open_short), \
             mock.patch.object(child.os, 'fsync') as synced, \
             self.assertRaisesRegex(OSError, 'snapshot write incomplete'):
            child.durable_snapshot(path, {'value': 'not complete'})
        synced.assert_not_called()
        self.assertTrue(path.is_file())
        self.assertFalse(path.read_bytes().endswith(b'\n'))

    def test_fsync_failure_is_not_reported_as_a_durable_digest(self):
        path = self.output / 'unsynced.json'
        with mock.patch.object(child.os, 'fsync', side_effect=OSError('sync unavailable')), \
             self.assertRaisesRegex(OSError, 'sync unavailable'):
            child.durable_snapshot(path, {'value': 'retained for diagnosis'})
        self.assertTrue(path.is_file())

    def test_all_transaction_stage_hashes_match_disk_with_newline_simulation(self):
        for newline in ('\n', '\r\n'):
            with self.subTest(newline=newline):
                fixture = FixtureV3Tests()
                fixture.setUp()
                self.addCleanup(fixture.doCleanups)
                receipts = []
                writer = child.durable_snapshot

                def save(path, record):
                    digest = writer(path, record)
                    raw = Path(path).read_bytes()
                    self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
                    self.assertNotIn(b'\r\n', raw)
                    receipts.append(Path(path).name)
                    return digest

                with fixture.patches(), platform_newline_sink(newline), \
                     mock.patch.object(child, 'durable_snapshot', side_effect=save), \
                     mock.patch.object(child.os, 'fsync', wraps=os.fsync) as synced:
                    record = fixture.prepare()
                    child.verify_original_snapshot(record)
                    fixture.grant(record)
                    req = fixture.request(record, 'baseline_granted')
                    child.apply_read_transaction(fixture.root, record, 'deny',
                                                 baseline_record=fixture.observed(req), baseline_request=req)
                    child.verify_original_snapshot(record)
                    child.restore(fixture.root, record)
                    self.assertEqual(fixture.descriptors, fixture.original)
                self.assertEqual([n for n in receipts if '-op-' not in n and '-restore-' not in n],
                                 ['fixture-original-transaction.json',
                                  'fixture-grant-receipt.json', 'fixture-deny-receipt.json'])
                self.assertEqual(sum('-op-' in n for n in receipts),
                                 len(fixture.original) * 2 * 3)
                self.assertEqual(sum('-restore-' in n for n in receipts), len(fixture.original) * 3 + 2)
                self.assertEqual(synced.call_count, len(receipts))

    def test_snapshot_newline_tampering_is_rejected_without_repair_or_rehash(self):
        fixture = FixtureV3Tests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with fixture.patches(), platform_newline_sink('\r\n'):
            record = fixture.prepare()
        child.verify_original_snapshot(record)
        path = Path(record['original_snapshot_path'])
        original, digest = path.read_bytes(), record['original_snapshot_sha256']
        variants = {'structural-crlf': original.replace(b'\n', b'\r\n'),
                    'missing-final-lf': original[:-1], 'extra-whitespace': original + b' '}
        for label, raw in variants.items():
            with self.subTest(tampering=label):
                self.assertNotEqual(raw, original)
                self.assertEqual(json.loads(raw), json.loads(original))
                path.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, 'original snapshot changed'):
                    child.verify_original_snapshot(record)
                with self.assertRaises(FileExistsError):
                    child.durable_snapshot(path, record)
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(record['original_snapshot_sha256'], digest)
        path.write_bytes(original)
        child.verify_original_snapshot(record)


class ExactACLPlansTests(unittest.TestCase):
    """Portable source contracts; these do not execute a Windows API."""
    sid = 'S-1-5-21-200'

    def case(self, directory, control, shape):
        before = legacy.ACLFamilyTests.descriptor_value('other', control=0x8000 | control)
        aces = child.descriptor_contract(before)['aces']
        if shape == 'explicit':
            aces.append(FixtureV3Tests.actor_ace(self.sid, 0x1f01ff))
        elif shape == 'inherited':
            aces.append(FixtureV3Tests.actor_ace(self.sid, 0x1f01ff, flags=0x10))
        elif shape == 'deny':
            aces.insert(0, FixtureV3Tests.actor_ace(self.sid, 0x10156 if directory else 0x10116, 1))
        return child.descriptor_with_aces(before, aces)

    def test_file_directory_four_controls_four_actor_shapes_32_source_cells(self):
        cells = 0
        for directory in (False, True):
            for control in (4, 0x404, 0x1004, 0x1404):
                for shape in ('missing', 'explicit', 'inherited', 'deny'):
                    with self.subTest(directory=directory, control=control, shape=shape):
                        before = self.case(directory, control, shape)
                        granted = child.planned_acl_change(before, self.sid, 'grant', directory)
                        denied = child.planned_acl_change(granted, self.sid, 'deny', directory)
                        child.check_read_grant(before, granted, self.sid, directory)
                        child.check_write_deny(granted, denied, self.sid, directory=directory)
                        for value in (granted, denied):
                            old, new = child.descriptor_contract(before), child.descriptor_contract(value)
                            self.assertEqual(new['dacl_control'], control)
                            self.assertEqual([a for a in old['aces'] if child.ace_sid(bytes.fromhex(a)) != self.sid],
                                             [a for a in new['aces'] if child.ace_sid(bytes.fromhex(a)) != self.sid])
                        inherited = [a for a in child.descriptor_contract(before)['aces'] if bytes.fromhex(a)[1] & 0x10]
                        self.assertEqual(inherited, [a for a in child.descriptor_contract(denied)['aces'] if bytes.fromhex(a)[1] & 0x10])
                        fixture = FixtureV3Tests()
                        fixture.setUp()
                        try:
                            fixture.original = {str(p): self.case(p.is_dir(), control, shape)
                                                for p in child.fixture_paths(fixture.root)}
                            fixture.descriptors = dict(fixture.original)
                            target = fixture.root if directory else fixture.root / 'nested/lock'
                            with fixture.patches():
                                record = fixture.prepare()
                                fixture.grant(record)
                                self.assertEqual(child.descriptor_contract(fixture.descriptors[str(target)]),
                                                 child.descriptor_contract(granted))
                                request = fixture.request(record, 'baseline_granted')
                                child.apply_read_transaction(fixture.root, record, 'deny',
                                    baseline_record=fixture.observed(request), baseline_request=request)
                                self.assertEqual(child.descriptor_contract(fixture.descriptors[str(target)]),
                                                 child.descriptor_contract(denied))
                                child.restore(fixture.root, record)
                                self.assertEqual(fixture.descriptors, fixture.original)
                                self.assertEqual(child.inventory(fixture.root), record['original_inventory'])
                                self.assertEqual(record['commands'], [])
                        finally:
                            fixture.doCleanups()
                        cells += 1
        self.assertEqual(cells, 32)

    def test_old_icacls_control_and_parent_ace_counterexamples_remain_rejected(self):
        for directory in (False, True):
            before = self.case(directory, 4, 'missing')
            granted = child.planned_acl_change(before, self.sid, 'grant', directory)
            denied = child.planned_acl_change(granted, self.sid, 'deny', directory)
            for phase, original, exact in (('grant', before, granted), ('deny', granted, denied)):
                aces = child.descriptor_contract(exact)['aces']
                aces.append(FixtureV3Tests.actor_ace('S-1-5-21-999', 0x1301bf, flags=0x10))
                raw = bytearray(base64.b64decode(child.descriptor_with_aces(exact, aces)))
                struct.pack_into('<H', raw, 2, 0x8404)
                inherited = base64.b64encode(raw).decode()
                with self.subTest(directory=directory, phase=phase), self.assertRaises(ValueError):
                    if phase == 'grant':
                        child.check_read_grant(original, inherited, self.sid, directory)
                    else:
                        child.check_write_deny(original, inherited, self.sid, directory=directory)

    def test_ambiguous_duplicate_split_order_type_sid_and_descriptor_family(self):
        before = self.case(False, 4, 'explicit')
        aces = child.descriptor_contract(before)['aces']
        bads = [child.descriptor_with_aces(before, aces + aces[-1:]),
                child.descriptor_with_aces(before, [FixtureV3Tests.actor_ace(self.sid, 2, 1),
                                                   FixtureV3Tests.actor_ace(self.sid, 4, 1)] + aces),
                child.descriptor_with_aces(before, aces + [FixtureV3Tests.actor_ace(self.sid, 2, 1)]),
                'bad', base64.b64encode(b'bad').decode()]
        for value in bads:
            with self.subTest(value=value), self.assertRaises(ValueError):
                child.planned_acl_change(value, self.sid, 'grant', False)
        for directory in (0, None, 'file'):
            with self.assertRaises(ValueError):
                child.planned_acl_change(before, self.sid, 'deny', directory)
        for sid in ('', 'S-1-5', 'S-1-05-21-200', 'S-1-5-4294967296'):
            with self.assertRaises(ValueError):
                child.planned_acl_change(before, sid, 'grant', False)
        for phase, policy in (('grant', 'specific-write-deny/v2'), ('other', child.READ_BASELINE_POLICY), ('deny', 'old')):
            with self.assertRaises(ValueError):
                child.planned_acl_change(before, self.sid, phase, False, policy)

    def test_read_write_and_persistence_failures_retain_phase_and_restore(self):
        for fault in ('readback', 'intent', 'observed', 'verified', 'phase_receipt', 'native_result', 'side_effect'):
            with self.subTest(fault=fault):
                fixture = FixtureV3Tests()
                fixture.setUp()
                try:
                    original_save = child.operation_snapshot
                    durable = child.durable_snapshot
                    original_read = fixture.descriptor
                    wrote = False
                    reads_failed = 0
                    def write(path, planned):
                        nonlocal wrote
                        result = fixture.apply(path, planned)
                        wrote = True
                        if fault == 'native_result':
                            return None
                        if fault == 'side_effect':
                            other = fixture.root
                            fixture.descriptors[str(other)] = fixture.add_actor(
                                fixture.descriptors[str(other)], 'S-1-5-21-999', 1)
                        return result
                    def read(path, value=None):
                        nonlocal reads_failed
                        if value is None and fault == 'readback' and wrote and not reads_failed:
                            reads_failed += 1
                            raise OSError('injected readback unavailable')
                        return original_read(path, value)
                    def save(record, operation, suffix):
                        if suffix == fault:
                            raise OSError('injected persistence unavailable')
                        return original_save(record, operation, suffix)
                    def persist(path, record):
                        if fault == 'phase_receipt' and Path(path).name == 'fixture-grant-receipt.json':
                            raise OSError('injected phase receipt unavailable')
                        return durable(path, record)
                    with fixture.patches(writer=write), \
                         mock.patch.object(child, 'windows_descriptor', side_effect=read), \
                         mock.patch.object(child, 'operation_snapshot', side_effect=save), \
                         mock.patch.object(child, 'durable_snapshot', side_effect=persist):
                        record = fixture.prepare()
                        with self.assertRaises(child.RestrictionError):
                            fixture.grant(record)
                        self.assertEqual(record['restoration'], 'verified')
                        self.assertEqual(fixture.descriptors, fixture.original)
                        self.assertEqual(record['application_failure']['phase'], 'grant')
                        self.assertFalse(record['grant_complete'])
                        if fault in ('verified', 'phase_receipt'):
                            self.assertEqual(record['application_failure']['step'], 'receipt')
                        self.assertNotIn('argv', record['operations'][-1])
                        self.assertEqual(record['commands'], [])
                        if fault == 'intent':
                            self.assertFalse(wrote)
                        else:
                            self.assertIsNotNone(record['operations'][-1]['actual'])
                finally:
                    fixture.doCleanups()

    def test_production_restore_records_success_api_failure_and_readback_failure(self):
        for fault in ('ok', 'api', 'readback', 'final_readback', 'persist'):
            fixture = FixtureV3Tests()
            fixture.setUp()
            try:
                with fixture.patches():
                    record = fixture.prepare()
                    fixture.grant(record)
                    immutable = copy.deepcopy(record)
                    frozen_request = fixture.request(record, 'baseline_granted')
                    original = fixture.descriptor
                    durable = child.durable_snapshot
                    reads = 0
                    def api(path, value=None):
                        nonlocal reads
                        if value is None and path == fixture.root:
                            reads += 1
                            if (fault == 'readback' and reads == 1) or (fault == 'final_readback' and reads == 2):
                                raise OSError(5, 'injected restoration descriptor readback failure')
                        result = original(path, value)
                        if value is not None and path == fixture.root and fault == 'api':
                            raise child.DACLWriteError({**result, 'return_value': 0, 'winerror': 5})
                        return result
                    def persist(path, value):
                        if fault == 'persist' and '-restore-' in Path(path).name:
                            raise OSError(28, 'injected restoration evidence storage failure')
                        return durable(path, value)
                    with mock.patch.object(child, 'windows_descriptor', side_effect=api), \
                         mock.patch.object(child, 'durable_snapshot', side_effect=persist):
                        if fault == 'ok':
                            child.restore(fixture.root, record)
                            self.assertEqual({k: record[k] for k in immutable}, immutable)
                            receipts = list(fixture.output.glob('fixture-restore-*-receipt.json'))
                            self.assertEqual(len(receipts), 1)
                            diagnostics = json.loads(receipts[0].read_text())
                            self.assertEqual(diagnostics['status'], 'verified')
                        else:
                            with self.assertRaises(OSError):
                                child.restore(fixture.root, record)
                            diagnostics = record['restoration_diagnostics']
                            self.assertEqual(diagnostics['status'], 'failed')
                    if fault == 'persist':
                        self.assertNotEqual(fixture.descriptors, fixture.original)
                        self.assertTrue(all(o['native_result'] is None for o in diagnostics['operations']))
                    else:
                        self.assertEqual(fixture.descriptors, fixture.original)
                    child.v2_request(frozen_request)
                    child.verify_original_snapshot(record)
                    self.assertEqual(len(diagnostics['operations']), len(fixture.original))
                    operation = diagnostics['operations'][0]
                    self.assertEqual(operation['phase'], 'restore')
                    self.assertEqual(operation['path'], '.')
                    self.assertNotIn('argv', operation)
                    self.assertNotIn('exit_code', operation)
                    if fault == 'api':
                        self.assertEqual(operation['native_result']['winerror'], 5)
                        self.assertEqual(operation['failure']['winerror'], 5)
                        self.assertEqual(operation['failure']['step'], 'write')
                        self.assertIsNotNone(operation['actual'])
                    elif fault == 'readback':
                        self.assertEqual(operation['readback_failure']['step'], 'readback')
                        self.assertEqual(operation['readback_failure']['errno'], 5)
                        self.assertIsNone(operation['actual'])
                    elif fault == 'final_readback':
                        self.assertEqual(diagnostics['final_readback_failure']['path'], '.')
                    elif fault == 'persist':
                        self.assertTrue(diagnostics['persistence_errors'])
                    else:
                        self.assertTrue(all(o['status'] == 'verified' and o['actual'] is not None
                                            and o['native_result']['winerror'] == 0 for o in diagnostics['operations']))
            finally:
                fixture.doCleanups()

    def test_changed_object_or_new_hardlink_rejects_unsafe_restore(self):
        for fault in ('replace', 'hardlink'):
            fixture = FixtureV3Tests()
            fixture.setUp()
            try:
                def write(path, planned):
                    result = fixture.apply(path, planned)
                    if fault == 'replace':
                        replacement = fixture.base / 'replacement'
                        replacement.write_bytes(path.read_bytes())
                        replacement.replace(path)
                    else:
                        os.link(path, fixture.base / 'outside-hardlink')
                    return result
                with fixture.patches(writer=write):
                    record = fixture.prepare()
                    with self.assertRaises(child.RestrictionError):
                        fixture.grant(record)
                    self.assertIn('restoration_error', record)
                    self.assertFalse(record['grant_complete'])
            finally:
                fixture.doCleanups()


if __name__ == '__main__':
    unittest.main()
