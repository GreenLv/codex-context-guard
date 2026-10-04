"""Tools-only ACL contract tests; mocked API checks are not native evidence."""
import base64
import copy
import ctypes
import errno
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.validation import incident_readonly_child as child


class ACLFamilyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'nested').mkdir()
        (self.root / 'nested' / 'lock').write_bytes(b'lock')
        self.sid = 'S-1-5-21-123'
        self.original = {str(p): self.descriptor_value(str(p)) for p in child.fixture_paths(self.root)}
        self.descriptors = dict(self.original)

    @staticmethod
    def descriptor_value(seed, control=0x8004, padding=0):
        sid = b'\x01\x01' + b'\x00' * 5 + b'\x05' + hashlib.sha256(seed.encode()).digest()[:4]
        ace = struct.pack('<BBHI', 0, 3, 8 + len(sid), 0x1f01ff) + sid
        acl = struct.pack('<BBHHH', 2, 0, 8 + len(ace), 1, 0) + ace
        header = struct.pack('<BBHIIII', 1, 0, control, 0, 0, 0, 20 + padding)
        return base64.b64encode(header + b'\x00' * padding + acl).decode()

    def test_descriptor_layout_diff_allowed_but_ace_and_controls_exact(self):
        before = self.descriptor_value('principal')
        shifted = self.descriptor_value('principal', padding=12)
        self.assertNotEqual(before, shifted)
        self.assertEqual(child.descriptor_contract(before), child.descriptor_contract(shifted))
        for changed in (self.descriptor_value('other-principal'),
                        self.descriptor_value('principal', control=0x8404),
                        self.descriptor_value('principal', control=0x9004),
                        self.descriptor_value('principal', control=0x8044)):
            self.assertNotEqual(child.descriptor_contract(before), child.descriptor_contract(changed))
        for bad in ('bad', base64.b64encode(b'bad').decode()):
            with self.assertRaises(ValueError):
                child.descriptor_contract(bad)

    def test_saved_control_models_choose_strategy_before_mutation(self):
        for control, expected in [(0x8004, ('raw-explicit', 4)),
                                  (0x9004, ('raw-explicit', 4)),
                                  (0x8404, ('auto-inherited', 4 | 0x20000000)),
                                  (0x9404, ('auto-inherited', 4 | 0x80000000))]:
            self.assertEqual(child.restoration_strategy(self.descriptor_value('sid', control)), expected)
        for control in (0x8104, 0x800c, 0x8044):
            descriptor = self.descriptor_value('sid', control)
            with self.subTest(control=control), self.assertRaises(ValueError):
                child.restoration_strategy(descriptor)
            with mock.patch.object(child, 'current_sid', return_value=self.sid), \
                 mock.patch.object(child, 'windows_descriptor', return_value=descriptor), \
                 mock.patch.object(child.subprocess, 'run') as runner:
                with self.assertRaises(ValueError):
                    child.windows_restrict(self.root)
                runner.assert_not_called()

    def descriptor(self, path, value=None):
        if value is None:
            return self.descriptors[str(path)]
        self.descriptors[str(path)] = value
        strategy, flags = child.restoration_strategy(value)
        return {'api': 'SetFileSecurityW' if strategy == 'raw-explicit' else 'SetNamedSecurityInfoW',
                'security_information': flags, 'return_value': 1 if strategy == 'raw-explicit' else 0,
                'winerror': 0}

    def apply(self, path, planned):
        self.descriptors[str(path)] = planned
        strategy, flags = child.restoration_strategy(planned)
        return {'api': 'SetFileSecurityW' if strategy == 'raw-explicit' else 'SetNamedSecurityInfoW',
                'security_information': flags, 'return_value': 1 if strategy == 'raw-explicit' else 0,
                'winerror': 0}

    def restricted(self, runner=None):
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor', side_effect=self.descriptor), \
             mock.patch.object(child, 'write_windows_dacl', side_effect=runner or self.apply):
            record = child.windows_restrict(self.root)
        self.addCleanup(shutil.rmtree, record['operation_output'])
        return record

    def test_exact_bits_bottom_up_and_original_dacl_restore(self):
        record = self.restricted()
        self.assertEqual(record['commands'], [])
        operations = record['operations']
        self.assertEqual(operations[-1]['path'], '.')
        self.assertEqual(operations[0]['path'], 'nested/lock')
        self.assertTrue(all(o['status'] == 'verified' for o in operations))
        for operation in operations:
            actual = child.descriptor_contract(operation['actual'])
            self.assertEqual(actual, child.descriptor_contract(operation['planned']))
            actor = [bytes.fromhex(a) for a in actual['aces']
                     if child.ace_sid(bytes.fromhex(a)) == self.sid]
            self.assertEqual(len(actor), 1)
            self.assertEqual(struct.unpack_from('<I', actor[0], 4)[0],
                             0x10156 if (self.root / operation['path']).is_dir() else 0x10116)
        restored = []
        def put(path, value=None):
            if value is not None:
                restored.append(path)
            return self.descriptor(path, value)
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor', side_effect=put):
            child.restore(self.root, record)
        self.assertEqual(restored[0], self.root)
        self.assertEqual(self.descriptors, self.original)

    def test_explicit_child_sid_keeps_collector_restoration_identity(self):
        target = 'S-1-5-21-999'
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor', side_effect=self.descriptor), \
             mock.patch.object(child, 'write_windows_dacl', side_effect=self.apply):
            record = child.windows_restrict(self.root, sid=target)
            self.assertEqual(record['sid'], target)
            self.assertEqual(record['collector_sid'], self.sid)
            self.addCleanup(shutil.rmtree, record['operation_output'])
            self.assertTrue(all(any(child.ace_sid(bytes.fromhex(a)) == target
                                    for a in child.descriptor_contract(o['actual'])['aces'])
                                for o in record['operations']))
            child.restore(self.root, record)
        self.assertEqual(self.descriptors, self.original)

    def test_object_replacement_rejected_before_restore_api(self):
        record = self.restricted()
        lock = self.root / 'nested' / 'lock'
        replaced = self.root / 'nested' / 'replacement'
        replaced.write_bytes(b'lock')
        replaced.replace(lock)
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor') as api:
            with self.assertRaises(ValueError):
                child.restore(self.root, record)
            api.assert_not_called()

    def test_successful_restore_keeps_bound_request_metadata_immutable(self):
        record = self.restricted()
        before = copy.deepcopy(record)
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor', side_effect=self.descriptor):
            child.restore(self.root, record)
        self.assertEqual({k: record[k] for k in before}, before)
        self.assertEqual(set(record) - set(before), {'restoration_diagnostics'})
        self.assertEqual(record['restoration_diagnostics']['status'], 'verified')

    def test_invalid_original_descriptor_and_explicit_empty_sid_never_mutate(self):
        for sid in ('', 'S-1-'):
            with self.subTest(sid=sid), mock.patch.object(child, 'current_sid', return_value=self.sid), \
                 mock.patch.object(child.subprocess, 'run') as runner:
                with self.assertRaises(ValueError):
                    child.windows_restrict(self.root, sid=sid)
                runner.assert_not_called()
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor', return_value='invalid'), \
             mock.patch.object(child.subprocess, 'run') as runner:
            with self.assertRaises(ValueError):
                child.windows_restrict(self.root)
            runner.assert_not_called()

    def test_partial_failure_restores_every_saved_object(self):
        count = 0
        def fail(path, planned):
            nonlocal count
            count += 1
            result = self.apply(path, planned)
            if count == 2:
                raise child.DACLWriteError({**result, 'return_value': 0, 'winerror': 5})
            return result
        with self.assertRaises(child.RestrictionError) as raised:
            self.restricted(fail)
        record = raised.exception.record
        self.addCleanup(shutil.rmtree, record['operation_output'])
        self.assertEqual(record['operations'][-1]['native_result']['winerror'], 5)
        self.assertEqual(record['restoration'], 'verified')
        self.assertEqual(self.descriptors, self.original)

    def test_failure_before_mutation_and_unrecoverable_restore_fail_closed(self):
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor', side_effect=OSError('save')), \
             mock.patch.object(child.subprocess, 'run') as runner:
            with self.assertRaises(OSError):
                child.windows_restrict(self.root)
            runner.assert_not_called()
        def fail(path, planned):
            raise OSError('injected write failure')
        with mock.patch.object(child, 'restore', side_effect=OSError('restore')):
            with self.assertRaises(child.RestrictionError) as raised:
                self.restricted(fail)
        self.addCleanup(shutil.rmtree, raised.exception.record['operation_output'])
        self.assertEqual(raised.exception.record['restoration_error'], 'OSError')

    def test_restore_rejects_root_principal_path_and_dacl_drift(self):
        record = self.restricted()
        for key, value in [('root', str(self.root / 'nested')), ('collector_sid', 'S-1-5-99'),
                           ('original_dacls', {}), ('policy', 'old-recursive')]:
            with self.subTest(key=key), mock.patch.object(child, 'current_sid', return_value=self.sid), \
                 mock.patch.object(child, 'windows_descriptor') as api:
                with self.assertRaises(ValueError):
                    child.restore(self.root, {**record, key: value})
                api.assert_not_called()
        def drift(path, value=None):
            return self.descriptor(path, value) if value is not None else self.descriptor_value('drift')
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor', side_effect=drift):
            with self.assertRaises(OSError):
                child.restore(self.root, record)
        self.assertTrue(all('readback_failure' in o for o in record['restoration_diagnostics']['operations']))

    def test_nested_special_object_and_invalid_principal_rejected_before_mutation(self):
        with mock.patch.object(child, 'current_sid', return_value='bad'), \
             mock.patch.object(child, 'windows_descriptor') as api:
            with self.assertRaises(ValueError):
                child.windows_restrict(self.root)
            api.assert_not_called()
        if os.name != 'nt':
            (self.root / 'nested' / 'linked').symlink_to(self.root / 'nested' / 'lock')
            with self.assertRaises(ValueError):
                child.fixture_paths(self.root)


@unittest.skipUnless(os.name == 'nt', 'actual Windows DACL mechanism required')
class WindowsACLMechanismTests(unittest.TestCase):
    @__import__('contextlib').contextmanager
    def owned_fixture(self):
        tmp = Path(tempfile.mkdtemp(prefix='cg-acl-native-evidence-'))
        try:
            yield str(tmp)
        except BaseException:
            print('retained_acl_fixture=' + str(tmp), flush=True)
            raise
        else:
            evidence = Path(tempfile.mkdtemp(prefix='cg-acl-native-result-'))
            for artifact in tmp.glob('*.json'):
                shutil.copy2(artifact, evidence / artifact.name)
            (evidence / 'sha256.json').write_text(json.dumps(
                {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                 for f in evidence.glob('*.json')}, indent=2))
            print('acl_native_evidence=' + str(evidence), flush=True)
            shutil.rmtree(tmp)

    def snapshot(self, root, name, record=None):
        snapshots = {}
        for path in child.fixture_paths(root):
            try:
                raw = child.windows_descriptor(path)
                snapshots[str(path.relative_to(root))] = {'raw': raw, 'contract': child.descriptor_contract(raw)}
            except Exception as exc:
                snapshots[str(path.relative_to(root))] = {'error': type(exc).__name__}
        (root.parent / (name + '.json')).write_text(json.dumps(
            {'objects': snapshots, 'inventory': child.inventory(root), 'restriction': record}, indent=2))

    def test_real_nested_child_denial_and_exact_restore(self):
        with self.owned_fixture() as tmp:
            root = Path(tmp) / 'fixture'
            (root / 'nested' / 'deep').mkdir(parents=True)
            lock = root / 'nested' / 'deep' / 'lock'
            lock.write_bytes(b'lock')
            (root / 'read').write_bytes(b'read')
            paths = child.fixture_paths(root)
            before = child.inventory(root)
            dacls = {str(p): child.windows_descriptor(p) for p in paths}
            self.snapshot(root, 'before')
            record = child.restrict(root)
            worker = Path(tmp) / 'worker.py'
            worker.write_text(
                "import sys,json,errno\nfrom pathlib import Path\n"
                "sys.path.insert(0,sys.argv[2])\n"
                "from tools.validation.incident_readonly_child import current_sid\n"
                "root=Path(sys.argv[1]);reads=[]\n"
                "for p in [root,*root.rglob('*')]:\n"
                " if p.is_dir():list(p.iterdir())\n"
                " else:p.read_bytes()\n"
                " reads.append(str(p.relative_to(root)))\n"
                "writes=[]\n"
                "for p in [root/'new',root/'nested'/'new',root/'nested'/'deep'/'lock']:\n"
                " try:\n"
                "  with p.open('ab') as f:f.write(b'forbidden')\n"
                "  writes.append(0)\n"
                " except OSError as e:writes.append(e.errno)\n"
                "print(json.dumps({'sid':current_sid(),'reads':reads,'writes':writes}))\n")
            try:
                query = subprocess.run([sys.executable, '-B', str(worker), str(root),
                                        str(Path(child.__file__).resolve().parents[2])],
                                       capture_output=True, text=True, timeout=30)
                self.assertEqual(query.returncode, 0, query.stderr)
                result = json.loads(query.stdout)
                self.assertEqual(result['sid'], record['sid'])
                (root.parent / 'child-result.json').write_text(json.dumps(result, indent=2))
                self.assertEqual(len(result['reads']), len(paths))
                self.assertTrue(all(x in (errno.EACCES, errno.EPERM) for x in result['writes']))
                self.assertEqual(child.inventory(root), before)
            finally:
                try:
                    child.restore(root, record)
                finally:
                    self.snapshot(root, 'after', record)
            self.assertEqual({str(p): child.descriptor_contract(child.windows_descriptor(p)) for p in paths},
                             {k: child.descriptor_contract(v) for k, v in dacls.items()})
            self.assertEqual(child.inventory(root), before)

    def test_original_inherited_and_protected_controls_restore(self):
        from ctypes import wintypes
        for protected, auto in ((False, True), (True, True), (True, False)):
            with self.subTest(protected=protected, auto=auto), self.owned_fixture() as tmp:
                root = Path(tmp) / 'fixture'
                (root / 'nested').mkdir(parents=True)
                (root / 'nested' / 'lock').write_bytes(b'fixed')
                # Fixture-only setup deliberately creates the two distinct
                # original inheritance families before saving the baseline.
                raw = base64.b64decode(child.windows_descriptor(root))
                buffer = ctypes.create_string_buffer(raw)
                api = ctypes.WinDLL('advapi32', use_last_error=True)
                get_dacl = api.GetSecurityDescriptorDacl
                get_dacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                     ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
                get_dacl.restype = wintypes.BOOL
                acl = ctypes.c_void_p()
                present, defaulted = wintypes.BOOL(), wintypes.BOOL()
                self.assertTrue(get_dacl(buffer, ctypes.byref(present), ctypes.byref(acl),
                                        ctypes.byref(defaulted)))
                setter = api.SetNamedSecurityInfoW
                setter.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                                   ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
                setter.restype = wintypes.DWORD
                self.assertEqual(setter(str(root), 1, 4 | 0x20000000, None, None, acl, None), 0)
                if protected:
                    self.assertEqual(setter(str(root), 1, 4 | 0x80000000, None, None, acl, None), 0)
                if not auto:
                    raw = base64.b64decode(child.windows_descriptor(root))
                    raw_buffer = ctypes.create_string_buffer(raw)
                    raw_setter = api.SetFileSecurityW
                    raw_setter.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
                    raw_setter.restype = wintypes.BOOL
                    self.assertTrue(raw_setter(str(root), 4, raw_buffer))
                control = child.descriptor_contract(child.windows_descriptor(root))['dacl_control']
                self.assertEqual(bool(control & 0x1000), protected)
                self.assertEqual(bool(control & 0x400), auto)
                self.snapshot(root, 'before')
                paths = child.fixture_paths(root)
                before = {str(path): child.descriptor_contract(child.windows_descriptor(path)) for path in paths}
                record = child.restrict(root)
                try:
                    self.assertEqual(child.inventory(root), record['original_inventory'])
                finally:
                    try:
                        child.restore(root, record)
                    finally:
                        self.snapshot(root, 'after', record)
                self.assertEqual({str(path): child.descriptor_contract(child.windows_descriptor(path))
                                  for path in paths}, before)

    def test_actual_partial_apply_restores_original_dacls(self):
        with self.owned_fixture() as tmp:
            root = Path(tmp) / 'fixture'
            root.mkdir()
            (root / 'file').write_bytes(b'fixed')
            before = child.inventory(root)
            paths = child.fixture_paths(root)
            dacls = {str(p): child.windows_descriptor(p) for p in paths}
            real_write = child.write_windows_dacl
            count = 0
            first_mutation = {}
            def fail_second(path, planned):
                nonlocal count
                count += 1
                if count == 2:
                    self.assertTrue(first_mutation.get('dacl_changed'))
                    raise OSError('injected before second native write')
                result = real_write(path, planned)
                applied = child.windows_descriptor(path)
                first_mutation.update(path=str(path), native_result=result,
                                      before=dacls[str(path)], after=applied,
                                      dacl_changed=child.descriptor_contract(applied) !=
                                      child.descriptor_contract(dacls[str(path)]))
                (root.parent / 'first-mutation.json').write_text(json.dumps(first_mutation, indent=2))
                self.assertTrue(first_mutation['dacl_changed'])
                return result
            self.snapshot(root, 'before')
            with mock.patch.object(child, 'write_windows_dacl', side_effect=fail_second):
                with self.assertRaises(child.RestrictionError) as raised:
                    child.restrict(root)
            self.snapshot(root, 'after', raised.exception.record)
            self.assertEqual(count, 2)
            self.assertEqual(raised.exception.record['commands'], [])
            self.assertIsNone(raised.exception.record['operations'][-1]['native_result'])
            self.addCleanup(shutil.rmtree, raised.exception.record['operation_output'])
            self.assertTrue(first_mutation['dacl_changed'])
            self.assertEqual(raised.exception.record['restoration'], 'verified')
            self.assertEqual({str(p): child.descriptor_contract(child.windows_descriptor(p)) for p in paths},
                             {k: child.descriptor_contract(v) for k, v in dacls.items()})
            self.assertEqual(child.inventory(root), before)


class NativeWriterBindingTests(unittest.TestCase):
    """ctypes call doubles check routing/status only, never native acceptance."""
    setUp = ACLFamilyTests.setUp
    descriptor_value = staticmethod(ACLFamilyTests.descriptor_value)
    descriptor = ACLFamilyTests.descriptor
    apply = ACLFamilyTests.apply
    restricted = ACLFamilyTests.restricted

    def test_exact_four_control_flags_and_true_api_failure_metadata(self):
        from ctypes import wintypes
        from types import SimpleNamespace
        target = self.root / 'nested/lock'
        for control in (4, 0x404, 0x1004, 0x1404):
            for failed in (False, True):
                with self.subTest(control=control, failed=failed):
                    def get_dacl(buffer, present, acl, defaulted):
                        ctypes.cast(present, ctypes.POINTER(wintypes.BOOL))[0] = 1
                        ctypes.cast(acl, ctypes.POINTER(ctypes.c_void_p))[0] = 100
                        return 1
                    api = SimpleNamespace(GetFileSecurityW=mock.Mock(),
                                          GetSecurityDescriptorDacl=mock.Mock(side_effect=get_dacl),
                                          SetFileSecurityW=mock.Mock(return_value=0 if failed else 1),
                                          SetNamedSecurityInfoW=mock.Mock(return_value=5 if failed else 0))
                    before = self.descriptor_value('other', control=control | 0x8000)
                    planned = child.planned_acl_change(before, self.sid, 'grant', False)
                    with mock.patch.object(ctypes, 'WinDLL', return_value=api, create=True), \
                         mock.patch.object(ctypes, 'get_last_error', return_value=5, create=True):
                        if failed:
                            with self.assertRaises(child.DACLWriteError) as caught:
                                child.write_windows_dacl(target, planned)
                            result = caught.exception.native_result
                            self.assertEqual(result['winerror'], 5)
                            with self.assertRaises(ValueError):
                                child.check_native_result(result, planned)
                        else:
                            result = child.write_windows_dacl(target, planned)
                            child.check_native_result(result, planned)
                        strategy, flags = child.restoration_strategy(planned)
                        self.assertEqual(result['security_information'], flags)
                        selected = api.SetFileSecurityW if strategy == 'raw-explicit' else api.SetNamedSecurityInfoW
                        other = api.SetNamedSecurityInfoW if strategy == 'raw-explicit' else api.SetFileSecurityW
                        selected.assert_called_once()
                        other.assert_not_called()
                        args = selected.call_args.args
                        self.assertEqual(args[0], str(target))
                        self.assertEqual(args[1 if strategy == 'raw-explicit' else 2], flags)
                        if strategy != 'raw-explicit':
                            self.assertEqual((args[1], args[3], args[4], args[6]), (1, None, None, None))

    def test_legacy_new_snapshot_cannot_be_rebound_but_old_record_still_restores(self):
        record = self.restricted()
        drifted = copy.deepcopy(record)
        name = next(iter(drifted['original_dacls']))
        drifted['original_dacls'][name] = self.descriptor_value('replacement')
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor') as api:
            with self.assertRaises(ValueError):
                child.restore(self.root, drifted)
            api.assert_not_called()
        old = {k: v for k, v in record.items() if k not in (
            'operations', 'operation_output', 'operation_output_identity',
            'original_snapshot_sha256', 'original_snapshot_path')}
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor', side_effect=self.descriptor):
            child.restore(self.root, old)
        self.assertEqual(self.descriptors, self.original)


def matrix_cells():
    return [{'kind': kind, 'control': control, 'actor_shape': shape}
            for kind in ('file', 'directory') for control in (4, 0x404, 0x1004, 0x1404)
            for shape in ('missing', 'explicit', 'inherited', 'deny')]


def matrix_preflight(args):
    """No Windows APIs, token acquisition, models or credential operations."""
    repo = Path(child.__file__).resolve().parents[2]
    child.sid_bytes(args.actor_sid)
    if args.actor_sid in ('S-1-5-18', 'S-1-5-32-544', 'S-1-3-4'):
        raise ValueError('ordinary actor SID required')
    if not __import__('re').fullmatch('[0-9a-f]{40}', args.expected_source_commit):
        raise ValueError('full source commit required')
    if not __import__('re').fullmatch('[0-9a-f]{64}', args.expected_helper_sha256):
        raise ValueError('full helper digest required')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
    helper_sha = hashlib.sha256(Path(child.__file__).read_bytes()).hexdigest()
    if head != args.expected_source_commit or helper_sha != args.expected_helper_sha256:
        raise ValueError('mechanism source identity changed')
    if subprocess.check_output(['git', 'status', '--porcelain=v1', '--untracked-files=no'], cwd=repo):
        raise ValueError('mechanism source has tracked changes')
    output = Path(args.output).absolute()
    parent = Path(args.fixture_parent).resolve(strict=True)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError('exclusive output unavailable')
    for path in (output.parent.resolve(strict=True), parent):
        if path == repo or repo in path.parents or path in repo.parents:
            raise ValueError('mechanism storage overlaps source')
        if not path.is_dir() or not os.access(path, os.W_OK):
            raise ValueError('mechanism storage unavailable')
    return {'schema': 'incident-acl-mechanism-matrix/v1', 'source_commit': head,
            'helper_sha256': helper_sha, 'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'platform': sys.platform, 'cells': matrix_cells(), 'output': str(output),
            'fixture_parent': str(parent), 'actor_sid': args.actor_sid,
            'ordinary_actor_execution': 'not_run', 'models': 'not_run',
            'scope': 'target-only DACL APIs, collector readback and exact fixture restoration'}


def matrix_ace(sid, mask=0x1f01ff, ace_type=0, flags=0):
    raw = child.sid_bytes(sid)
    return (struct.pack('<BBHI', ace_type, flags, 8 + len(raw), mask) + raw).hex()


def matrix_descriptor(control, aces):
    body = b''.join(bytes.fromhex(a) for a in aces)
    return base64.b64encode(struct.pack('<BBHIIII', 1, 0, control | 0x8000, 0, 0, 0, 20)
                            + struct.pack('<BBHHH', 2, 0, 8 + len(body), len(aces), 0) + body).decode()


def matrix_setup_write(path, descriptor):
    """Fixture setup only; exact disk controls are checked after the real call."""
    control = child.descriptor_contract(descriptor)['dacl_control']
    if control & 0x400:
        return child.windows_descriptor(path, descriptor)
    from ctypes import wintypes
    api = ctypes.WinDLL('advapi32', use_last_error=True)
    setter = api.SetFileSecurityW
    setter.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    setter.restype = wintypes.BOOL
    flags = 4 | (0x80000000 if control & 0x1000 else 0x20000000)
    buffer = ctypes.create_string_buffer(base64.b64decode(descriptor))
    result = int(setter(str(path), flags, buffer))
    observed = {'api': 'SetFileSecurityW', 'security_information': flags,
                'return_value': result, 'winerror': 0 if result else ctypes.get_last_error()}
    if not result:
        raise child.DACLWriteError(observed)
    return observed


def matrix_observe(root):
    return {'raw_dacls': {str(p): child.windows_descriptor(p) for p in child.fixture_paths(root)},
            'inventory': child.inventory(root)}


def matrix_setup_operation(root, path, planned, result, output):
    entry = {'path': path.relative_to(root).as_posix(), 'before': child.windows_descriptor(path), 'planned': planned,
             'native_result': None, 'actual': None}
    result['setup'].append(entry)
    number = str(len(result['setup']))
    child.durable_snapshot(output / ('setup-' + number + '-intent.json'), entry)
    try:
        entry['native_result'] = matrix_setup_write(path, planned)
    except BaseException as exc:
        entry['native_result'] = getattr(exc, 'native_result', None)
        entry['failure'] = child.acl_failure(exc, 'setup', 'write')
        raise
    finally:
        try:
            entry['actual'] = child.windows_descriptor(path)
        except Exception as exc:
            entry['readback_error'] = child.acl_failure(exc, 'setup', 'readback')
        child.durable_snapshot(output / ('setup-' + number + '-observed.json'), entry)
    if child.descriptor_contract(entry['actual']) != child.descriptor_contract(planned):
        raise ValueError('native original fixture differs from requested control or ACE shape')


def matrix_restore(root, record, output, label):
    # Forward every call to the actual API. This spy retains real restoration
    # return values and per-object readbacks, rather than synthesizing success.
    real = child.windows_descriptor
    events = []
    def observed(path, descriptor=None):
        if descriptor is None:
            return real(path)
        event = {'path': path.relative_to(root).as_posix(), 'planned': descriptor,
                 'native_result': None, 'actual': None}
        try:
            event['native_result'] = real(path, descriptor)
        except BaseException as exc:
            event['native_result'] = getattr(exc, 'native_result', None)
            event['failure'] = child.acl_failure(exc, 'restore', 'write')
            raise
        finally:
            try:
                event['actual'] = real(path)
            except Exception as exc:
                event['readback_error'] = child.acl_failure(exc, 'restore', 'readback')
            events.append(event)
            child.durable_snapshot(output / (label + '-restore-' + str(len(events)) + '.json'), event)
        return event['native_result']
    with mock.patch.object(child, 'windows_descriptor', side_effect=observed):
        child.restore(root, record)
    return events


def matrix_cell(cell, actor_sid, collector_sid, repo, output, cwd):
    root = cwd / ('incident-readonly-' + output.name)
    root.mkdir()
    result = {**cell, 'fixture': str(root), 'status': 'failed', 'step': 'setup',
              'ordinary_actor_execution': 'not_run', 'setup': []}
    original_root = child.windows_descriptor(root)
    setup_originals = {str(root): original_root}
    setup_objects = {str(root): [root.stat().st_dev, root.stat().st_ino]}
    setup_inventory = child.inventory(root)
    result['initial_root'] = original_root
    active = None
    try:
        parent_aces = [matrix_ace(s, flags=3) for s in (collector_sid, 'S-1-5-18', 'S-1-5-32-544')]
        if cell['actor_shape'] == 'inherited':
            parent_aces.append(matrix_ace(actor_sid, flags=3))
        parent_plan = matrix_descriptor(0x1404, parent_aces)
        matrix_setup_operation(root, root, parent_plan, result, output)
        target = root / 'target'
        if cell['kind'] == 'directory':
            target.mkdir()
        else:
            target.write_bytes(b'owned mechanism fixture\n')
        setup_originals[str(target)] = child.windows_descriptor(target)
        setup_objects[str(target)] = [target.stat().st_dev, target.stat().st_ino]
        setup_inventory = child.inventory(root)
        inherited = child.descriptor_contract(child.windows_descriptor(target))['aces']
        inherited = [a for a in inherited if bytes.fromhex(a)[1] & 0x10]
        if cell['actor_shape'] == 'inherited' and not any(child.ace_sid(bytes.fromhex(a)) == actor_sid for a in inherited):
            raise ValueError('native inherited actor fixture unavailable')
        aces = [matrix_ace(s) for s in (collector_sid, 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-4')]
        if cell['actor_shape'] == 'explicit':
            aces.append(matrix_ace(actor_sid))
        elif cell['actor_shape'] == 'deny':
            aces.insert(0, matrix_ace(actor_sid, 0x10156 if target.is_dir() else 0x10116, 1))
        target_plan = matrix_descriptor(cell['control'], aces + inherited)
        matrix_setup_operation(root, target, target_plan, result, output)
        ownership = {k: str(v) for k, v in {'cwd': cwd, 'output': output, 'repo': repo,
                     'home': repo, 'plugin_root': repo, 'data_root': repo}.items()}
        # There is no Codex HOME or installation in this mechanism-only fixture.
        # The unused protected-tree fields all bind to the source checkout.
        ownership.update(created_exclusively=True, root_identity=[root.stat().st_dev, root.stat().st_ino])
        active = child.prepare_read_transaction(root, sid=actor_sid, ownership=ownership)
        result['original'] = matrix_observe(root)
        expected = dict(active['original_dacls'])
        for phase in ('grant', 'deny'):
            result['step'] = phase
            before = expected[str(target)]
            planned = child.planned_acl_change(before, actor_sid, phase, target.is_dir())
            child.apply_acl_change(root, active, target, before, planned, phase, expected)
            result[phase] = matrix_observe(root)
        result['step'] = 'restore_v3'
        result['v3_restore_api'] = matrix_restore(root, active, output, 'v3')
        result['v3_restored'] = matrix_observe(root)
        result['v3_record'] = active
        # v2 has no read baseline. Test its shared target mutation separately,
        # without inventing an actor request or marking the full family granted.
        legacy_output = output / 'legacy'
        legacy_output.mkdir()
        active = {k: copy.deepcopy(v) for k, v in active.items() if k in (
            'family', 'root', 'sid', 'collector_sid', 'original_dacls', 'original_inventory',
            'objects', 'original_restore_strategies')}
        active.update(policy='specific-write-deny/v2', commands=[], operations=[],
                      operation_output=str(legacy_output),
                      operation_output_identity=[legacy_output.stat().st_dev, legacy_output.stat().st_ino])
        snapshot = legacy_output / 'fixture-original-transaction.json'
        active['original_snapshot_sha256'] = child.durable_snapshot(snapshot, active)
        active['original_snapshot_path'] = str(snapshot)
        expected = dict(active['original_dacls'])
        result['step'] = 'deny_v2'
        before = expected[str(target)]
        planned = child.planned_acl_change(before, actor_sid, 'deny', target.is_dir(), active['policy'])
        child.apply_acl_change(root, active, target, before, planned, 'deny', expected)
        result['v2_deny'] = matrix_observe(root)
        result['step'] = 'restore_v2'
        result['v2_restore_api'] = matrix_restore(root, active, legacy_output, 'v2')
        result['v2_restored'] = matrix_observe(root)
        result['v2_record'] = active
        result.update(status='passed', step='verified')
    except BaseException as exc:
        result['failure'] = child.acl_failure(exc, 'matrix', result['step'])
        if active is not None:
            result['failed_record'] = active
            # Save the failure and actual state before any restoration attempt.
            try:
                result['failed_observation'] = matrix_observe(root)
            except Exception as observation:
                result['observation_error'] = type(observation).__name__
            child.durable_snapshot(output / 'matrix-before-restoration-failure.json', result)
            try:
                result['failure_restore_api'] = matrix_restore(root, active, output, 'failure')
                result['failure_restored'] = matrix_observe(root)
            except Exception as restoration:
                result['restoration_error'] = type(restoration).__name__
        else:
            # Restore only these exclusively created objects from observations
            # captured before their setup writes; no next cell may run.
            try:
                result['failed_observation'] = matrix_observe(root)
            except Exception as observation:
                result['observation_error'] = type(observation).__name__
            child.durable_snapshot(output / 'setup-before-restoration-failure.json', result)
            fallback = {'family': 'windows-acl', 'policy': 'specific-write-deny/v2',
                        'root': str(root), 'sid': actor_sid, 'collector_sid': collector_sid,
                        'original_dacls': setup_originals, 'objects': setup_objects,
                        'original_inventory': setup_inventory, 'commands': [],
                        'operation_output': str(output),
                        'operation_output_identity': [output.stat().st_dev, output.stat().st_ino],
                        'original_restore_strategies': {}}
            try:
                fallback_output = output / 'setup-restoration'
                fallback_output.mkdir()
                fallback_output = fallback_output.resolve(strict=True)
                fallback.update(operation_output=str(fallback_output),
                                operation_output_identity=[fallback_output.stat().st_dev, fallback_output.stat().st_ino],
                                original_restore_strategies={p: child.restoration_strategy(d)
                                                             for p, d in setup_originals.items()})
                original = fallback_output / 'fixture-original-transaction.json'
                fallback['original_snapshot_sha256'] = child.durable_snapshot(original, fallback)
                fallback['original_snapshot_path'] = str(original)
                result['setup_restore_api'] = matrix_restore(root, fallback, fallback_output, 'setup-failure')
                result['setup_restored'] = matrix_observe(root)
            except Exception as restoration:
                result['restoration_error'] = type(restoration).__name__
            result['setup_restore_record'] = fallback
        if isinstance(exc, KeyboardInterrupt):
            result['interrupted'] = True
    child.durable_snapshot(output / 'matrix-cell.json', result)
    return result


def matrix_run_cells(report, actor_sid, collector_sid, repo, output, cwd):
    cells = matrix_cells()
    for number, cell in enumerate(cells, 1):
        cell_output = output / ('cell-' + str(number).zfill(2))
        cell_output.mkdir()
        result = matrix_cell(cell, actor_sid, collector_sid, repo, cell_output, cwd)
        report['results'].append(result)
        if result['status'] != 'passed' or result.get('restoration_error'):
            break
    report['attempted_cells'] = len(report['results'])
    report['remaining_cells'] = [{**cell, 'status': 'not_run'} for cell in cells[len(report['results']):]]
    report['passed_cells'] = sum(c['status'] == 'passed' for c in report['results'])
    report['status'] = 'passed' if report['passed_cells'] == len(cells) else 'failed'


def mechanism_matrix_main(argv):
    parser = __import__('argparse').ArgumentParser(description='Explicit zero-model Windows DACL mechanism matrix')
    parser.add_argument('--mechanism-matrix', action='store_true', required=True)
    parser.add_argument('--actor-sid', required=True)
    parser.add_argument('--expected-source-commit', required=True)
    parser.add_argument('--expected-helper-sha256', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--fixture-parent', required=True)
    parser.add_argument('--preflight', action='store_true')
    args = parser.parse_args(argv)
    report = matrix_preflight(args)
    if args.preflight:
        report['status'] = 'preflight_passed'
        print(json.dumps(report, indent=2))
        return 0
    if os.name != 'nt':
        raise ValueError('actual matrix requires Windows; source preflight is not native acceptance')
    collector_sid = child.current_sid()
    child.sid_bytes(collector_sid)
    if collector_sid == args.actor_sid:
        raise ValueError('collector cannot stand in for ordinary actor')
    output = Path(report['output'])
    output.mkdir()
    # Exclusive, private fixture workspace; retain all cells for Root readback.
    cwd = Path(tempfile.mkdtemp(prefix='cg-acl-matrix-owned-', dir=report['fixture_parent']))
    report.update(collector_sid=collector_sid, fixture_workspace=str(cwd), status='running', results=[])
    child.durable_snapshot(output / 'matrix-input.json', report)
    repo = Path(child.__file__).resolve().parents[2]
    matrix_run_cells(report, args.actor_sid, collector_sid, repo, output, cwd)
    child.durable_snapshot(output / 'matrix-result.json', report)
    index = {p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(output.rglob('*')) if p.is_file()}
    child.durable_snapshot(output / 'matrix-index.json', index)
    print(json.dumps({'status': report['status'], 'passed_cells': report['passed_cells'],
                      'attempted_cells': report['attempted_cells'], 'remaining_cells': len(report['remaining_cells']),
                      'total_cells': 32, 'ordinary_actor_execution': 'not_run', 'output': str(output)}))
    return 0 if report['status'] == 'passed' else 1


class MatrixSourceContractsTests(unittest.TestCase):
    def test_setup_api_failure_restores_owned_scene_then_stops_batch(self):
        for restore_failed in (False, True):
            with self.subTest(restore_failed=restore_failed), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                output, cwd = base / 'output', base / 'workspace'
                output.mkdir()
                cwd.mkdir()
                descriptors, originals = {}, {}
                setup_calls = []
                restored = []
                def descriptor(path, value=None):
                    name = str(path)
                    if name not in descriptors:
                        descriptors[name] = ACLFamilyTests.descriptor_value(name)
                        originals[name] = descriptors[name]
                    if value is None:
                        return descriptors[name]
                    descriptors[name] = value
                    restored.append(name)
                    strategy, flags = child.restoration_strategy(value)
                    result = {'api': 'SetFileSecurityW' if strategy == 'raw-explicit' else 'SetNamedSecurityInfoW',
                              'security_information': flags,
                              'return_value': 1 if strategy == 'raw-explicit' else 0, 'winerror': 0}
                    if restore_failed and len(restored) == 1:
                        raise child.DACLWriteError({**result, 'return_value': 0, 'winerror': 5})
                    return result
                def setup(path, planned):
                    setup_calls.append(str(path))
                    descriptors[str(path)] = planned
                    if len(setup_calls) == 2:
                        raise child.DACLWriteError({'api': 'SetFileSecurityW', 'security_information': 4,
                                                    'return_value': 0, 'winerror': 5})
                    return {'api': 'SetNamedSecurityInfoW', 'security_information': 0x80000004,
                            'return_value': 0, 'winerror': 0}
                report = {'results': []}
                with mock.patch.object(child, 'current_sid', return_value='S-1-5-21-100'), \
                     mock.patch.object(child, 'windows_descriptor', side_effect=descriptor), \
                     mock.patch(__name__ + '.matrix_setup_write', side_effect=setup):
                    matrix_run_cells(report, 'S-1-5-21-200', 'S-1-5-21-100', base / 'source', output, cwd)
                self.assertEqual(report['attempted_cells'], 1)
                self.assertEqual(len(report['remaining_cells']), 31)
                self.assertEqual(len(setup_calls), 2)
                self.assertEqual(len(restored), 2)
                self.assertEqual(descriptors, originals)
                result = report['results'][0]
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(result['setup'][1]['native_result']['winerror'], 5)
                self.assertEqual('restoration_error' in result, restore_failed)

    def test_failed_cell_and_failed_restore_stop_without_later_mutations(self):
        for restoration_failed in (False, True):
            with self.subTest(restoration_failed=restoration_failed), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                mutations = []
                def failed(cell, *args):
                    mutations.append(cell)
                    return {**cell, 'status': 'failed',
                            **({'restoration_error': 'OSError'} if restoration_failed else {'restoration': 'verified'})}
                report = {'results': []}
                with mock.patch(__name__ + '.matrix_cell', side_effect=failed) as invoke:
                    matrix_run_cells(report, 'S-1-5-21-200', 'S-1-5-21-100', output, output, output)
                self.assertEqual(invoke.call_count, 1)
                self.assertEqual(len(mutations), 1)
                self.assertEqual(report['attempted_cells'], 1)
                self.assertEqual(report['passed_cells'], 0)
                self.assertEqual(len(report['remaining_cells']), 31)
                self.assertTrue(all(c['status'] == 'not_run' for c in report['remaining_cells']))
                self.assertEqual(report['status'], 'failed')
                self.assertEqual(sorted(p.name for p in output.iterdir()), ['cell-01'])

    def test_32_cells_are_unique_and_preflight_does_not_execute_acl_or_actor(self):
        from types import SimpleNamespace
        cells = matrix_cells()
        self.assertEqual(len(cells), 32)
        self.assertEqual(len({(c['kind'], c['control'], c['actor_shape']) for c in cells}), 32)
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(actor_sid='S-1-5-21-200', expected_source_commit='a' * 40,
                                   expected_helper_sha256=hashlib.sha256(Path(child.__file__).read_bytes()).hexdigest(),
                                   output=str(Path(directory) / 'new-result'), fixture_parent=directory)
            with mock.patch.object(subprocess, 'check_output', side_effect=['a' * 40, b'']), \
                 mock.patch.object(child, 'current_sid') as actor, \
                 mock.patch.object(child, 'windows_descriptor') as api:
                report = matrix_preflight(args)
                actor.assert_not_called()
                api.assert_not_called()
                self.assertEqual(report['ordinary_actor_execution'], 'not_run')
                self.assertFalse(Path(args.output).exists())
            for fault in ('source', 'helper', 'dirty', 'output', 'sid'):
                bad = copy.copy(args)
                replies = ['a' * 40, b'']
                if fault == 'source':
                    replies[0] = 'b' * 40
                elif fault == 'helper':
                    bad.expected_helper_sha256 = 'b' * 64
                elif fault == 'dirty':
                    replies[1] = b' M tools/validation/incident_readonly_child.py'
                elif fault == 'output':
                    bad.output = directory
                else:
                    bad.actor_sid = 'S-1-5-18'
                with self.subTest(fault=fault), mock.patch.object(subprocess, 'check_output', side_effect=replies), \
                     mock.patch.object(child, 'windows_descriptor') as api, self.assertRaises(ValueError):
                    matrix_preflight(bad)
                api.assert_not_called()


if __name__ == '__main__':
    if '--mechanism-matrix' in sys.argv:
        raise SystemExit(mechanism_matrix_main(sys.argv[1:]))
    unittest.main()
