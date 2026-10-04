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

    def handle_double(self, path, fault=None):
        from types import SimpleNamespace
        seed = base64.b64decode(self.descriptor_value('other', control=0x8404))
        inherited = bytearray(seed[28:])
        inherited[1] |= 16
        before = base64.b64encode(seed[:20] + struct.pack('<BBHHH', 2, 0,
            8 + len(seed[28:]) + len(inherited), 2, 0) + seed[28:] + inherited).decode()
        identity = {'volume_serial': 0x100000001, 'file_id': '0102030405060708090a0b0c0d0e0f10',
                    'kind': 'directory' if path.is_dir() else 'file', 'reparse_tag': 0}
        model = SimpleNamespace(value=before, identity=identity, handles={}, reads={}, error=0, events=[])
        def create(name, access, share, attributes, creation, flags, template):
            self.assertEqual((name, share, attributes, creation, template), (str(path), 3, None, 3, None))
            self.assertEqual(flags, 0x02200000 if path.is_dir() else 0x00200000)
            self.assertIn(access, (0x20080, 0x60080))
            if fault == 'open' and access == 0x60080:
                model.error = 5
                return ctypes.c_void_p(-1).value
            handle = 2**40 + 8 + len(model.handles)
            model.handles[handle] = access
            return handle
        def info(handle, number, pointer, size):
            self.assertIn(handle, model.handles)
            if fault == 'unsupported_id' and number == 18:
                model.error = 50
                return 0
            if number == 18:
                self.assertEqual(size, 24)
                raw = bytearray.fromhex(identity['file_id'])
                if fault == 'high_id' and model.handles[handle] == 0x60080:
                    raw[15] ^= 1
                value = struct.pack('<Q', identity['volume_serial'] + (fault == 'volume')) + raw
            elif number == 9:
                self.assertEqual(size, 8)
                attributes = 0x10 if path.is_dir() else 0
                if fault == 'type':
                    attributes ^= 0x10
                if fault == 'reparse':
                    attributes |= 0x400
                value = struct.pack('<II', attributes, 1 if fault == 'reparse' else 0)
            else:
                raise AssertionError('unselected identity class')
            ctypes.memmove(pointer, bytes(value), size)
            return 1
        def descriptor(handle, flags, buffer, size, needed):
            self.assertEqual(flags, 4)
            raw = base64.b64decode(model.value)
            if fault == 'preimage' and not model.events:
                raw = bytearray(raw)
                raw[-1] ^= 1
                raw = bytes(raw)
            ctypes.cast(needed, ctypes.POINTER(ctypes.c_uint32))[0] = len(raw)
            if buffer is None:
                model.error = 122
                return 0
            if fault == 'readback' and model.events:
                model.error = 5
                return 0
            self.assertEqual(size, len(raw))
            ctypes.memmove(buffer, raw, len(raw))
            return 1
        def extract(buffer, present, acl, defaulted):
            from ctypes import wintypes
            if fault == 'extract_error':
                model.error = 13
                return 0
            ctypes.cast(present, ctypes.POINTER(wintypes.BOOL))[0] = fault != 'absent_dacl'
            ctypes.cast(defaulted, ctypes.POINTER(wintypes.BOOL))[0] = 0
            offset = struct.unpack_from('<I', buffer.raw, 16)[0]
            pointer = ctypes.addressof(buffer) + offset
            if fault == 'null_dacl':
                pointer = 0
            elif fault == 'foreign_dacl':
                pointer += 1
            ctypes.cast(acl, ctypes.POINTER(ctypes.c_void_p))[0] = pointer
            return 1
        def setter(handle, kind, flags, owner, group, dacl, sacl):
            self.assertEqual(model.handles[handle], 0x60080)
            self.assertEqual((kind, flags, owner, group, sacl), (1, 0x80000004, None, None, None))
            self.assertTrue(dacl.value)
            raw_before = base64.b64decode(before)
            offset = struct.unpack_from('<I', raw_before, 16)[0]
            self.assertEqual(ctypes.string_at(dacl, len(raw_before) - offset), raw_before[offset:])
            model.events.append('setter')
            if fault in ('DWORD5', 'DWORD5_close'):
                model.error = 0  # DWORD result is independent of stale last_error.
                return 5
            if fault == 'success_no_effect':
                return 0
            raw = bytearray(base64.b64decode(model.value))
            struct.pack_into('<H', raw, 2, 0x9004 if fault == 'AI_loss' else 0x9404)
            if fault == 'ACE_flags':
                raw[29] ^= 16
            if fault == 'tail_loss':
                raw = raw[:28 + struct.unpack_from('<H', raw, 30)[0]]
                struct.pack_into('<HH', raw, 22, len(raw) - 20, 1)
            model.value = base64.b64encode(raw).decode()
            return 0
        def close(handle):
            if fault in ('close', 'DWORD5_close') and model.handles[handle] == 0x60080:
                model.error = 32
                return 0
            return 1
        model.api = SimpleNamespace(CreateFileW=mock.Mock(side_effect=create),
            GetFileInformationByHandleEx=mock.Mock(side_effect=info),
            GetKernelObjectSecurity=mock.Mock(side_effect=descriptor),
            GetSecurityDescriptorDacl=mock.Mock(side_effect=extract),
            SetSecurityInfo=mock.Mock(side_effect=setter), CloseHandle=mock.Mock(side_effect=close),
            SetNamedSecurityInfoW=mock.Mock(return_value=5), SetFileSecurityW=mock.Mock())
        return model, before

    def invoke_handle(self, path, model, before, fault=None):
        events = []
        def observe(stage, value):
            events.append((stage, copy.deepcopy(value)))
            if fault == stage:
                raise OSError('synthetic ' + stage + ' persistence failure')
            if fault == 'interrupt' and stage == 'preflight':
                raise KeyboardInterrupt('synthetic preflight interruption')
        with mock.patch.object(ctypes, 'WinDLL', return_value=model.api, create=True), \
             mock.patch.object(ctypes, 'get_last_error', side_effect=lambda: model.error, create=True), \
             mock.patch.object(child, 'windows_descriptor', side_effect=lambda p: model.value):
            try:
                result = child.protect_windows_dacl(path, before, model.identity, observe)
            except BaseException as exc:
                return exc, events
        return result, events

    def test_control_only_ABI_NULL_and_preimage_rejection(self):
        for path in (self.root / 'nested/lock', self.root / 'nested'):
            with self.subTest(kind='directory' if path.is_dir() else 'file'):
                model, before = self.handle_double(path)
                result, events = self.invoke_handle(path, model, before)
                self.assertEqual(result, {'api': 'SetSecurityInfo', 'security_information': 0x80000004,
                                          'return_value': 0, 'winerror': 0})
                model.api.SetSecurityInfo.assert_called_once()
                model.api.SetNamedSecurityInfoW.assert_not_called()
                model.api.SetFileSecurityW.assert_not_called()
                self.assertEqual([s for s, _ in events], ['intent', 'opened', 'preflight', 'observed', 'closed'])
                self.assertEqual(events[2][1]['identity_before'], model.identity)
                self.assertEqual(child.descriptor_contract(events[2][1]['handle_before']), child.descriptor_contract(before))
                self.assertEqual(child.descriptor_contract(events[3][1]['actual'])['dacl_control'], 0x1404)
                closed = [c.args[0] for c in model.api.CloseHandle.call_args_list]
                self.assertEqual(set(closed), set(model.handles))
                self.assertEqual(len(closed), len(set(closed)))
                for flags in (4, 0x80000000, 0x20000004, True):
                    with self.subTest(flags=flags), self.assertRaises(ValueError):
                        child.set_protected_handle(model.api, next(iter(model.handles)), before, flags)
                with self.assertRaises(ValueError):
                    child.set_protected_handle(model.api, next(iter(model.handles)), before, owner=ctypes.c_void_p(100))
                for invalid in ('not-base64', self.descriptor_value('other', control=0x9404)):
                    with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                        child.set_protected_handle(model.api, next(iter(model.handles)), invalid)
                self.assertEqual(model.api.SetSecurityInfo.call_count, 1)

    def test_handle_open_identity_preimage_and_persistence_fail_before_setter(self):
        for fault in ('open', 'unsupported_id', 'high_id', 'volume', 'type', 'reparse', 'preimage',
                      'intent', 'opened', 'preflight', 'interrupt',
                      'extract_error', 'absent_dacl', 'null_dacl', 'foreign_dacl'):
            with self.subTest(fault=fault):
                path = self.root / 'nested/lock'
                model, before = self.handle_double(path, fault)
                result, _events = self.invoke_handle(path, model, before, fault)
                self.assertIsInstance(result, BaseException)
                model.api.SetSecurityInfo.assert_not_called()
                model.api.SetNamedSecurityInfoW.assert_not_called()
                self.assertEqual(len(model.api.CloseHandle.call_args_list), len(model.handles))
                if fault in ('unsupported_id', 'high_id', 'volume', 'type', 'reparse', 'preimage', 'preflight', 'interrupt'):
                    self.assertTrue(model.api.CloseHandle.called)

    def test_handle_DWORD5_actual_drift_close_and_observed_errors_remain_failure(self):
        for fault in ('DWORD5', 'DWORD5_close', 'AI_loss', 'ACE_flags', 'tail_loss', 'success_no_effect', 'readback', 'close', 'observed', 'closed'):
            with self.subTest(fault=fault):
                path = self.root / 'nested/lock'
                model, before = self.handle_double(path, fault)
                result, events = self.invoke_handle(path, model, before, fault)
                self.assertIsInstance(result, BaseException)
                model.api.SetSecurityInfo.assert_called_once()
                model.api.SetNamedSecurityInfoW.assert_not_called()
                model.api.SetFileSecurityW.assert_not_called()
                self.assertEqual(len(model.api.CloseHandle.call_args_list), len(model.handles))
                self.assertIn('observed', [s for s, _ in events])
                lifecycle = result.handle_lifecycle
                if fault.startswith('DWORD5'):
                    self.assertIsInstance(result, child.DACLWriteError)
                    self.assertEqual(result.native_result['winerror'], 5)
                    self.assertEqual(child.descriptor_contract(lifecycle['actual'])['dacl_control'], 0x404)
                    self.assertEqual(lifecycle['failure']['stage'], 'setter')
                    if fault == 'DWORD5_close':
                        self.assertEqual(lifecycle['secondary_errors'][0]['winerror'], 32)
                if fault == 'close':
                    self.assertEqual(result.winerror, 32)
                if fault == 'readback':
                    self.assertTrue(lifecycle['readback_errors'])

    def test_handle_DWORD5_plus_observation_and_close_failures_preserves_primary(self):
        path = self.root / 'nested/lock'
        model, before = self.handle_double(path, 'DWORD5_close')
        result, events = self.invoke_handle(path, model, before, 'observed')
        self.assertIsInstance(result, child.DACLWriteError)
        self.assertEqual(result.winerror, 5)
        self.assertEqual(result.native_result['return_value'], 5)
        lifecycle = result.handle_lifecycle
        self.assertEqual(lifecycle['failure']['stage'], 'setter')
        self.assertEqual({e['stage'] for e in lifecycle['secondary_errors']}, {'observed_persistence', 'close'})
        self.assertEqual(child.descriptor_contract(lifecycle['actual']), child.descriptor_contract(before))
        self.assertEqual(len(model.api.CloseHandle.call_args_list), len(model.handles))
        self.assertEqual(events[-1][0], 'closed')

    def test_protected_current_inherited_tail_uses_only_DACL_and_refuses_control_drift(self):
        from ctypes import wintypes
        from types import SimpleNamespace
        target = self.root / 'nested/lock'
        raw = bytearray.fromhex(child.descriptor_contract(self.descriptor_value('other'))['aces'][0])
        raw[1] |= 16
        before = matrix_descriptor(0x1404, [raw.hex()])
        planned = child.planned_acl_change(before, self.sid, 'grant', False)
        def get_dacl(buffer, present, acl, defaulted):
            ctypes.cast(present, ctypes.POINTER(wintypes.BOOL))[0] = 1
            ctypes.cast(acl, ctypes.POINTER(ctypes.c_void_p))[0] = 100
            return 1
        api = SimpleNamespace(GetFileSecurityW=mock.Mock(), GetSecurityDescriptorDacl=mock.Mock(side_effect=get_dacl),
                              SetNamedSecurityInfoW=mock.Mock(return_value=0), SetFileSecurityW=mock.Mock())
        real = child.windows_descriptor
        with mock.patch.object(ctypes, 'WinDLL', return_value=api, create=True), \
             mock.patch.object(child, 'windows_descriptor', return_value=before):
            result = real(target, planned)
        child.check_native_result(result, planned)
        self.assertEqual(result['security_information'], 4)
        api.SetNamedSecurityInfoW.assert_called_once()
        self.assertEqual(api.SetNamedSecurityInfoW.call_args.args[1:5], (1, 4, None, None))
        api.SetFileSecurityW.assert_not_called()
        api.SetNamedSecurityInfoW.reset_mock()
        for control in (4, 0x404, 0x1004):
            drifted = matrix_descriptor(control, [raw.hex()])
            with self.subTest(control=control), mock.patch.object(ctypes, 'WinDLL', return_value=api, create=True), \
                 mock.patch.object(child, 'windows_descriptor', return_value=drifted), self.assertRaises(ValueError):
                real(target, planned)
        api.SetNamedSecurityInfoW.assert_not_called()

    def test_real_shared_writer_success_tail_loss_has_twelve_strict_rejections(self):
        from ctypes import wintypes
        from types import SimpleNamespace
        real = child.windows_descriptor
        for directory in (False, True):
            for shape in ('missing', 'inherited'):
                for phase in ('grant', 'deny', 'restore'):
                    with self.subTest(directory=directory, shape=shape, phase=phase):
                        explicit = [matrix_ace('S-1-5-18'), matrix_ace('S-1-5-32-544'), matrix_ace('S-1-5-19'), matrix_ace('S-1-3-4')]
                        inherited = [matrix_ace(sid, flags=0x13 if directory else 0x10)
                                     for sid in ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-19')]
                        if shape == 'inherited':
                            inherited.append(matrix_ace(self.sid, flags=0x13 if directory else 0x10))
                        before = matrix_descriptor(0x1404, explicit + inherited)
                        if phase == 'deny':
                            before = child.planned_acl_change(before, self.sid, 'grant', directory)
                        planned = (before if phase == 'restore' else
                                   child.planned_acl_change(before, self.sid, phase, directory))
                        actual = before
                        def get_dacl(buffer, present, acl, defaulted):
                            ctypes.cast(present, ctypes.POINTER(wintypes.BOOL))[0] = 1
                            ctypes.cast(acl, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(buffer) + 20
                            return 1
                        def setter(path, kind, flags, owner, group, acl, sacl):
                            nonlocal actual
                            self.assertEqual((kind, flags, owner, group, sacl), (1, 4, None, None, None))
                            header = ctypes.string_at(acl, 8)
                            size, count = struct.unpack_from('<HH', header, 2)
                            raw, pos, aces = ctypes.string_at(acl, size), 8, []
                            for _ in range(count):
                                length = struct.unpack_from('<H', raw, pos + 2)[0]
                                ace = raw[pos:pos + length]
                                if not ace[1] & 16:
                                    aces.append(ace.hex())
                                pos += length
                            actual = matrix_descriptor(0x1404, aces)
                            return 0  # API success does not establish exact readback.
                        api = SimpleNamespace(GetFileSecurityW=mock.Mock(), GetSecurityDescriptorDacl=mock.Mock(side_effect=get_dacl),
                                              SetNamedSecurityInfoW=mock.Mock(side_effect=setter), SetFileSecurityW=mock.Mock())
                        target = self.root / 'nested' if directory else self.root / 'nested/lock'
                        with mock.patch.object(ctypes, 'WinDLL', return_value=api, create=True), \
                             mock.patch.object(child, 'windows_descriptor', side_effect=lambda p: actual):
                            result = real(target, planned)
                            readback = child.windows_descriptor(target)
                        child.check_native_result(result, planned)
                        self.assertNotEqual(child.descriptor_contract(readback), child.descriptor_contract(planned))
                        self.assertEqual(child.descriptor_contract(readback)['aces'],
                                         [a for a in child.descriptor_contract(planned)['aces'] if not bytes.fromhex(a)[1] & 16])
                        if phase == 'grant':
                            with self.assertRaises(ValueError):
                                child.check_read_grant(before, readback, self.sid, directory)
                        elif phase == 'deny':
                            with self.assertRaises(ValueError):
                                child.check_write_deny(before, readback, self.sid, directory=directory)
                        api.SetFileSecurityW.assert_not_called()

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
    cells = [{'kind': kind, 'control': control, 'actor_shape': shape}
             for kind in ('file', 'directory') for control in (4, 0x404, 0x1004, 0x1404)
             for shape in ('missing', 'explicit', 'inherited', 'deny')]
    failure = {'kind': 'file', 'control': 0x1404, 'actor_shape': 'missing'}
    return [failure, *[c for c in cells if c != failure]]


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
    profile = getattr(args, 'cell_profile', 'full32')
    cells = matrix_profile_cells(profile)
    runner_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    expected_runner = getattr(args, 'expected_runner_sha256', None)
    collector = getattr(args, 'collector_sid', None)
    if expected_runner is not None and expected_runner != runner_sha:
        raise ValueError('mechanism runner identity changed')
    if profile == 'protected8':
        if expected_runner is None or collector is None:
            raise ValueError('protected probes require fixed runner and collector pins')
        child.sid_bytes(collector)
        if collector == args.actor_sid:
            raise ValueError('collector cannot stand in for ordinary actor')
    probe_plan = [matrix_probe_plan(c, args.actor_sid, collector) for c in cells] if profile == 'protected8' else None
    inputs = {'source_commit': head, 'helper_sha256': helper_sha, 'runner_sha256': runner_sha,
              'cell_profile': profile, 'cells': cells, 'actor_sid': args.actor_sid,
              'collector_sid': collector, 'output': str(output), 'fixture_parent': str(parent)}
    return {'schema': 'incident-acl-mechanism-matrix/v1', 'source_commit': head,
            'inputs': inputs, 'inputs_sha256': hashlib.sha256(json.dumps(inputs, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(),
            'cell_profile': profile, 'collector_sid_pin': collector,
            'probe_plan': probe_plan,
            'probe_plan_sha256': hashlib.sha256(json.dumps(probe_plan, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest() if probe_plan is not None else None,
            'helper_sha256': helper_sha, 'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'platform': sys.platform, 'cells': cells, 'output': str(output),
            'fixture_parent': str(parent), 'actor_sid': args.actor_sid,
            'ordinary_actor_execution': 'not_run', 'models': 'not_run',
            'scope': 'owned-family setup, target-only grant/deny, whole-family S1/S0 restoration; outside guards read-only'}


def matrix_ace(sid, mask=0x1f01ff, ace_type=0, flags=0):
    raw = child.sid_bytes(sid)
    return (struct.pack('<BBHI', ace_type, flags, 8 + len(raw), mask) + raw).hex()


def matrix_descriptor(control, aces):
    body = b''.join(bytes.fromhex(a) for a in aces)
    return base64.b64encode(struct.pack('<BBHIIII', 1, 0, control | 0x8000, 0, 0, 0, 20)
                            + struct.pack('<BBHHH', 2, 0, 8 + len(body), len(aces), 0) + body).decode()


def matrix_setup_write(path, descriptor, *, record_step=None, protected_ai_probe=False, expected_identity=None, observe_handle=None):
    """Fixture setup only; exact disk controls are checked after the real call."""
    control = child.descriptor_contract(descriptor)['dacl_control']
    if protected_ai_probe:
        if control != 0x1404 or record_step is None:
            raise ValueError('protected AI setup requires durable fixed stages')
        intermediate = matrix_descriptor(0x404, child.descriptor_contract(descriptor)['aces'])
        intent = record_step('protect', intermediate)
        primary = None
        try:
            intent['native_result'] = child.windows_descriptor(path, intermediate)
        except BaseException as exc:
            primary = exc
            intent['native_result'] = getattr(exc, 'native_result', None)
            intent['failure'] = child.acl_failure(exc, 'setup_materialize_AI', 'write')
            raise
        finally:
            try:
                intent['actual'] = child.windows_descriptor(path)
            except Exception as exc:
                intent['readback_error'] = child.acl_failure(exc, 'setup_materialize_AI', 'readback')
            try:
                record_step('protect_observed', intent)
            except BaseException as exc:
                intent['observation_failure'] = child.acl_failure(exc, 'setup_materialize', 'observed')
                if primary is None:
                    raise
                primary.materialization_observation_failure = intent['observation_failure']
        child.check_native_result(intent['native_result'], intermediate)
        if child.descriptor_contract(intent['actual']) != child.descriptor_contract(intermediate):
            raise ValueError('complete unprotected AI materialization differs')
        final_intent = record_step('control_only', descriptor)
        primary = None
        try:
            final_intent['native_result'] = child.protect_windows_dacl(path, intermediate, expected_identity, observe_handle)
            return final_intent['native_result']
        except BaseException as exc:
            primary = exc
            final_intent['native_result'] = getattr(exc, 'native_result', None)
            final_intent['failure'] = child.acl_failure(exc, 'setup_protect_control', 'write')
            final_intent['handle_lifecycle'] = getattr(exc, 'handle_lifecycle', None)
            raise
        finally:
            try:
                final_intent['actual'] = child.windows_descriptor(path)
            except Exception as exc:
                final_intent['readback_error'] = child.acl_failure(exc, 'setup_protect_control', 'readback')
            try:
                record_step('control_only_observed', final_intent)
            except BaseException as exc:
                final_intent['observation_failure'] = child.acl_failure(exc, 'setup_protect_control', 'observed')
                if primary is None:
                    raise
                primary.control_observation_failure = final_intent['observation_failure']
    if control & 0x400:
        return child.windows_descriptor(path, descriptor)
    if control == 0x1004:
        if record_step is None:
            raise ValueError('protected non-AI setup requires durable step observations')
        explicit = [a for a in child.descriptor_contract(descriptor)['aces']
                    if not bytes.fromhex(a)[1] & 0x10]
        protected = matrix_descriptor(0x1404, explicit)
        intent = record_step('protect', protected)
        primary = None
        try:
            intent['native_result'] = child.windows_descriptor(path, protected)
        except BaseException as exc:
            primary = exc
            intent['native_result'] = getattr(exc, 'native_result', None)
            intent['failure'] = child.acl_failure(exc, 'setup_protect', 'write')
            raise
        finally:
            try:
                intent['actual'] = child.windows_descriptor(path)
            except Exception as exc:
                intent['readback_error'] = child.acl_failure(exc, 'setup_protect', 'readback')
            try:
                record_step('protect_observed', intent)
            except BaseException as exc:
                intent['observation_failure'] = child.acl_failure(exc, 'setup_materialize', 'observed')
                if primary is None:
                    raise
                primary.materialization_observation_failure = intent['observation_failure']
        child.check_native_result(intent['native_result'], protected)
        if child.descriptor_contract(intent['actual']) != child.descriptor_contract(protected):
            raise ValueError('protected setup DACL differs before raw non-AI write')
    from ctypes import wintypes
    api = ctypes.WinDLL('advapi32', use_last_error=True)
    setter = api.SetFileSecurityW
    setter.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    setter.restype = wintypes.BOOL
    flags = 4  # Keep raw DACL flags distinct from the SD's 0x8004/0x9004 control.
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
    entry = {'path': path.relative_to(root).as_posix(), 'phase': result.get('setup_phase', 'direct'),
             'before': child.windows_descriptor(path), 'planned': planned,
             'native_result': None, 'actual': None}
    result['setup'].append(entry)
    number = str(len(result['setup']))
    child.durable_snapshot(output / ('setup-' + number + '-intent.json'), entry)
    def step(label, value):
        if label in ('protect', 'control_only'):
            strategy, flags = child.restoration_strategy(value)
            observed = {'phase': label, 'planned': value, 'before': child.windows_descriptor(path),
                        'selected_api': 'SetSecurityInfo' if label == 'control_only' else ('SetNamedSecurityInfoW' if strategy != 'raw-explicit' else 'SetFileSecurityW'),
                        'security_information': 0x80000004 if label == 'control_only' else flags,
                        'pDacl': 'complete verified handle preimage ACL' if label == 'control_only' else 'complete planned ACL',
                        'native_result': None, 'actual': None}
            entry.setdefault('steps', []).append(observed)
            child.durable_snapshot(output / ('setup-' + number + '-' + label + '-intent.json'), observed)
            return observed
        child.durable_snapshot(output / ('setup-' + number + '-' + label.replace('_', '-') + '.json'), value)
        if label == 'control_only_observed':
            return
        transition = result.get('current_setup_transition')
        if transition is not None:
            observed = matrix_assert_setup_state(root, transition['intermediate'], result)
            result['family_observations'].append({'phase': transition['phase'] + '_protect', 'observation': observed})
            child.durable_snapshot(output / ('setup-' + number + '-protect-family.json'), observed)
    lifecycle_sequence = 0
    def observe_handle(stage, value):
        nonlocal lifecycle_sequence
        lifecycle_sequence += 1
        if stage == 'preflight':
            transition = result['current_setup_transition']
            value['family_preflight'] = matrix_assert_setup_state(root, transition['intermediate'], result)
        elif stage == 'observed':
            value['family_actual'] = matrix_observe(root)
            value['outside_guard_actual'] = matrix_guards(root, root.parent)
        child.durable_snapshot(output / ('setup-' + number + '-handle-' + str(lifecycle_sequence) + '-' + stage + '.json'), value)
        entry['handle_lifecycle'] = copy.deepcopy(value)
    primary = None
    try:
        probe = (path != root
                 and result.get('setup_phase', 'target') == 'target'
                 and child.descriptor_contract(planned)['dacl_control'] == 0x1404)
        if probe:
            entry['native_result'] = matrix_setup_write(path, planned, record_step=step, protected_ai_probe=True,
                expected_identity=result['s0_record']['native_target_identity'], observe_handle=observe_handle)
        else:
            entry['native_result'] = matrix_setup_write(path, planned, record_step=step)
    except BaseException as exc:
        primary = exc
        entry['native_result'] = getattr(exc, 'native_result', None)
        entry['failure'] = child.acl_failure(exc, 'setup', 'write')
        raise
    finally:
        try:
            entry['actual'] = child.windows_descriptor(path)
        except Exception as exc:
            entry['readback_error'] = child.acl_failure(exc, 'setup', 'readback')
        try:
            child.durable_snapshot(output / ('setup-' + number + '-observed.json'), entry)
        except BaseException as exc:
            entry['observation_failure'] = child.acl_failure(exc, 'setup', 'observed')
            if primary is None:
                raise
            primary.setup_observation_failure = entry['observation_failure']
    if probe:
        if entry['native_result'] != {'api': 'SetSecurityInfo', 'security_information': 0x80000004,
                                      'return_value': 0, 'winerror': 0}:
            raise ValueError('control-only native protection result differs')
    else:
        child.check_native_result(entry['native_result'], planned)
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
            try:
                event['family_actual'] = matrix_observe(root)
            except Exception as exc:
                event['family_readback_error'] = child.acl_failure(exc, 'restore', 'readback')
            events.append(event)
            child.durable_snapshot(output / (label + '-restore-' + str(len(events)) + '.json'), event)
        return event['native_result']
    with mock.patch.object(child, 'windows_descriptor', side_effect=observed):
        child.restore(root, record)
    return events


def matrix_probes():
    return [{'kind': kind, 'control': control, 'actor_shape': shape}
            for kind in ('file', 'directory') for control in (0x1004, 0x1404)
            for shape in ('missing', 'inherited')]


def matrix_profile_cells(profile):
    if profile == 'full32':
        return matrix_cells()
    if profile == 'protected8':
        return matrix_probes()
    raise ValueError('unknown mechanism profile')


def matrix_topology(root, kind):
    target = root / 'target'
    if kind == 'directory':
        target.mkdir()
        (target / 'nested').mkdir()
        (target / 'nested' / 'leaf').write_bytes(b'owned target descendant\n')
    elif kind == 'file':
        target.write_bytes(b'owned mechanism fixture\n')
    else:
        raise ValueError('unknown owned object kind')
    (root / 'sibling').write_bytes(b'owned sibling\n')
    (root / 'branch').mkdir()
    (root / 'branch' / 'leaf').write_bytes(b'owned sibling descendant\n')
    return target


def matrix_guards(root, cwd):
    # No ACL writes or content edits outside this exclusively owned root.
    paths = [cwd, *sorted(p for p in cwd.iterdir() if p != root)]
    return {str(p): {'identity': [p.lstat().st_dev, p.lstat().st_ino],
                     'dacl': child.descriptor_contract(child.windows_descriptor(p))}
            for p in paths}


def matrix_stable_observation(root):
    before = matrix_observe(root)
    after = matrix_observe(root)
    if before != after:
        raise ValueError('whole-family snapshot changed during bounded read')
    return after


def matrix_setup_snapshot(root, actor_sid, collector_sid, output):
    output = output.resolve(strict=True)
    observation = matrix_stable_observation(root)
    paths = child.fixture_paths(root)
    if any(child.restoration_strategy(d) != ('raw-explicit', 4)
           for d in observation['raw_dacls'].values()):
        raise ValueError('S0 requires preselected raw-explicit rollback eligibility')
    if set(observation['raw_dacls']) != {str(p) for p in paths}:
        raise ValueError('whole-family snapshot topology differs')
    record = {'family': 'windows-acl', 'policy': 'specific-write-deny/v2',
              'root': str(root), 'sid': actor_sid, 'collector_sid': collector_sid,
              'native_target_identity': child.windows_object_identity(root / 'target'),
              'original_dacls': observation['raw_dacls'],
              'original_inventory': observation['inventory'],
              'objects': {str(p): [p.lstat().st_dev, p.lstat().st_ino] for p in paths},
              'original_restore_strategies': {p: child.restoration_strategy(d)
                                             for p, d in observation['raw_dacls'].items()},
              'commands': [], 'operations': [], 'operation_output': str(output),
              'operation_output_identity': [output.stat().st_dev, output.stat().st_ino]}
    child.check_fixture_identity(root, record)
    if matrix_observe(root) != observation:
        raise ValueError('whole-family preimage changed before durable snapshot')
    snapshot = output / 'fixture-original-transaction.json'
    record['original_snapshot_sha256'] = child.durable_snapshot(snapshot, record)
    record['original_snapshot_path'] = str(snapshot)
    child.verify_original_snapshot(record)
    return record


def matrix_inherited_aces(parent_descriptor, directory):
    result = []
    for value in child.descriptor_contract(parent_descriptor)['aces']:
        raw = bytearray.fromhex(value)
        if not raw[1] & (2 if directory else 1):
            continue
        # The controlled fixture uses OI|CI ordinary ACEs, never generic masks.
        if raw[1] & 3 != 3 or raw[1] & ~(3 | 0x10):
            raise ValueError('unexpected controlled-parent inheritance flags')
        raw[1] = 0x13 if directory else 0x10
        result.append(raw.hex())
    return result


def matrix_setup_expected(root, target, planned, before, *, raw_final=False):
    expected = dict(before['raw_dacls'])
    expected[str(target)] = planned
    if raw_final or not child.descriptor_contract(planned)['dacl_control'] & 0x400:
        return expected
    for path in sorted(child.fixture_paths(root), key=lambda p: (len(p.parts), str(p))):
        if target not in path.parents:
            continue
        if any(ancestor != target and target in ancestor.parents
               and child.descriptor_contract(expected[str(ancestor)])['dacl_control'] & 0x1000
               for ancestor in path.parents if str(ancestor) in expected):
            continue
        current = child.descriptor_contract(expected[str(path)])
        if current['dacl_control'] & 0x1000:
            continue
        explicit = [a for a in current['aces'] if not bytes.fromhex(a)[1] & 0x10]
        expected[str(path)] = matrix_descriptor(
            0x404, explicit + matrix_inherited_aces(expected[str(path.parent)], path.is_dir()))
    return expected


def matrix_check_family(root, expected, inventory):
    observed = matrix_observe(root)
    if set(observed['raw_dacls']) != set(expected):
        raise ValueError('whole-family object set changed')
    differences = {p: observed['raw_dacls'][p] for p, d in expected.items()
                   if child.descriptor_contract(d) != child.descriptor_contract(observed['raw_dacls'][p])}
    if differences or observed['inventory'] != inventory:
        raise ValueError('whole-family DACL or inventory differs from declared phase')
    return observed


def matrix_seed_descriptor(collector_sid):
    # A deliberate owned-fixture assignment, never classification of old ACEs.
    return matrix_descriptor(0x1404, [matrix_ace(sid) for sid in
                                    (collector_sid, 'S-1-5-18', 'S-1-5-32-544')])


def matrix_assert_setup_state(root, expected, result):
    original = result['s0_record']
    child.check_fixture_identity(root, original)
    observed = matrix_check_family(root, expected, original['original_inventory'])
    if matrix_guards(root, root.parent) != result['outside_guards']:
        raise ValueError('external guard changed during declared setup transition')
    return observed


def matrix_setup_transition(root, path, planned, expected, result, output, phase):
    matrix_assert_setup_state(root, expected, result)
    before = {'raw_dacls': expected, 'inventory': result['s0_record']['original_inventory']}
    staged = (child.descriptor_contract(planned)['dacl_control'] == 0x1004
              or (phase == 'target' and child.descriptor_contract(planned)['dacl_control'] == 0x1404))
    intermediate = None
    if staged:
        contract = child.descriptor_contract(planned)
        if contract['dacl_control'] == 0x1404:
            materialized = matrix_descriptor(0x404, contract['aces'])
        else:
            explicit = [a for a in contract['aces'] if not bytes.fromhex(a)[1] & 0x10]
            materialized = matrix_descriptor(0x1404, explicit)
        intermediate = matrix_setup_expected(root, path, materialized, before)
        after = dict(intermediate)
        after[str(path)] = planned
    else:
        after = matrix_setup_expected(root, path, planned, before)
    transition = {'phase': phase, 'path': path.relative_to(root).as_posix(),
                  'before': dict(expected), 'intermediate': intermediate, 'after': after}
    result.setdefault('setup_transitions', []).append(transition)
    result['current_setup_transition'] = transition
    result['setup_phase'] = phase
    child.durable_snapshot(output / ('transition-' + str(len(result['setup_transitions'])) + '-intent.json'), transition)
    matrix_setup_operation(root, path, planned, result, output)
    observed = matrix_assert_setup_state(root, after, result)
    result['family_observations'].append({'phase': phase, 'observation': observed})
    child.durable_snapshot(output / ('transition-' + str(len(result['setup_transitions'])) + '-observed.json'), observed)
    result['declared_setup_expected'] = after
    return after


def matrix_probe_plan(cell, actor_sid, collector_sid):
    directory = cell['kind'] == 'directory'
    parent = [matrix_ace(sid, flags=3) for sid in (collector_sid, 'S-1-5-18', 'S-1-5-32-544')]
    if cell['actor_shape'] == 'inherited':
        parent.append(matrix_ace(actor_sid, flags=3))
    parent_sd = matrix_descriptor(0x1404, parent)
    explicit = [matrix_ace(sid) for sid in (collector_sid, 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-4')]
    tail = matrix_inherited_aces(parent_sd, directory)
    intermediate = matrix_descriptor(0x404 if cell['control'] == 0x1404 else 0x1404,
                                     explicit + tail if cell['control'] == 0x1404 else explicit)
    final = matrix_descriptor(cell['control'], explicit + tail)
    grant = child.planned_acl_change(final, actor_sid, 'grant', directory)
    deny = child.planned_acl_change(grant, actor_sid, 'deny', directory)
    seed = matrix_seed_descriptor(collector_sid)
    seed_aces = child.descriptor_contract(seed)['aces']
    seed_paths = (['target/nested/leaf', 'branch/leaf', 'target/nested', 'branch', 'sibling', 'target']
                  if directory else ['branch/leaf', 'branch', 'sibling', 'target'])
    ai_paths = (['branch', 'sibling', 'target', 'branch/leaf', 'target/nested', 'target/nested/leaf']
                if directory else ['branch', 'sibling', 'target', 'branch/leaf'])
    return {**cell, 'ordinary_actor_execution': 'not_run',
            'protected_AI_feasibility': 'unknown',
            'scope': {'owned_root': 'cwd/incident-readonly-output-name', 'target': 'target',
                      'outside_ancestor_and_siblings': 'read-only guards',
                      'full_family_S0_and_S1': 'durable before their first mutation'},
            'phases': [
                {'name': 'controlled_seed', 'paths_bottom_up': seed_paths, 'api': 'SetNamedSecurityInfoW',
                 'security_information': 0x80000004, 'expected': child.descriptor_contract(seed),
                 'before': 'complete immutable S0; each preceding declared whole family must match'},
                {'name': 'parent_setup', 'path': '.', 'api': 'SetNamedSecurityInfoW',
                 'security_information': 0x80000004, 'expected': child.descriptor_contract(parent_sd)},
                {'name': 'controlled_AI', 'paths_top_down': ai_paths, 'api': 'SetNamedSecurityInfoW',
                 'security_information': 0x20000004,
                 'file_expected': child.descriptor_contract(matrix_descriptor(0x404,
                    seed_aces + matrix_inherited_aces(parent_sd, False))),
                 'directory_expected': child.descriptor_contract(matrix_descriptor(0x404,
                    seed_aces + matrix_inherited_aces(parent_sd, True)))},
                {'name': 'materialize_AI' if cell['control'] == 0x1404 else 'protect_intermediate',
                 'path': 'target', 'api': 'SetNamedSecurityInfoW',
                 'security_information': 0x20000004 if cell['control'] == 0x1404 else 0x80000004, 'expected': child.descriptor_contract(intermediate)},
                {'name': 'protect_control_only' if cell['control'] == 0x1404 else 'raw_final',
                 'path': 'target', 'api': 'SetSecurityInfo' if cell['control'] == 0x1404 else 'SetFileSecurityW',
                 'security_information': 0x80000004 if cell['control'] == 0x1404 else 4,
                 'pDacl': 'complete verified handle preimage ACL' if cell['control'] == 0x1404 else 'complete planned ACL',
                 'handle_access': 0x60080 if cell['control'] == 0x1404 else None,
                 'identity': 'S0-frozen volume64 and FileId128' if cell['control'] == 0x1404 else None, 'expected': child.descriptor_contract(final)},
                {'name': 'ready_descendants', 'paths': ['target/nested', 'target/nested/leaf'] if directory else [],
                 'api': 'SetNamedSecurityInfoW', 'security_information': 0x20000004,
                 'expected': {name: child.descriptor_contract(matrix_descriptor(0x404,
                    seed_aces + matrix_inherited_aces(final, is_directory))) for name, is_directory in
                    ([('target/nested', True), ('target/nested/leaf', False)] if directory else [])}},
                {'name': 'grant', 'path': 'target', 'expected': child.descriptor_contract(grant)},
                {'name': 'deny', 'path': 'target', 'expected': child.descriptor_contract(deny)},
                {'name': 'restore_v3', 'expected': 'exact complete S1'},
                {'name': 'deny_v2', 'path': 'target', 'expected': child.descriptor_contract(
                    child.planned_acl_change(final, actor_sid, 'deny', directory, 'specific-write-deny/v2'))},
                {'name': 'restore_v2', 'expected': 'exact complete S1'},
                {'name': 'rollback_setup', 'expected': 'exact complete S0, including owned family and outside guards'}],
            'native_returns': {'SetNamedSecurityInfoW': {'return_value': 0, 'winerror': 0},
                               'SetFileSecurityW': {'return_value': 'nonzero', 'winerror': 0}},
            'failure_policy': 'persist before restoration; one declared attempt per stage; fail-stop without fallback'}


def matrix_ready_descendants(root, target, result, output, inventory):
    # Raw final cannot propagate. Close the declared owned inheritance graph
    # before S1, instead of capturing an unrestorable intermediate descendant.
    expected = result.get('declared_setup_expected')
    if expected is None or inventory != result['s0_record']['original_inventory']:
        raise ValueError('declared preceding setup family required')
    matrix_assert_setup_state(root, expected, result)
    for path in sorted(child.fixture_paths(root), key=lambda p: (len(p.parts), str(p))):
        if target not in path.parents:
            continue
        current = child.descriptor_contract(expected[str(path)])
        if current['dacl_control'] & 0x1000:
            raise ValueError('fresh owned descendant unexpectedly protected')
        explicit = [a for a in current['aces'] if not bytes.fromhex(a)[1] & 0x10]
        planned = matrix_descriptor(0x404, explicit + matrix_inherited_aces(
            expected[str(path.parent)], path.is_dir()))
        expected = matrix_setup_transition(root, path, planned, expected, result, output, 'ready_descendant')
    return expected


def matrix_cell(cell, actor_sid, collector_sid, repo, output, cwd, *, profile='full32'):
    root = cwd / ('incident-readonly-' + output.name)
    root.mkdir()
    result = {**cell, 'fixture': str(root), 'status': 'failed', 'step': 'topology',
              'cell_profile': profile, 'ordinary_actor_execution': 'not_run', 'setup': [],
              'family_observations': [], 'restorations': [], 'persistence_errors': []}
    s0 = s1 = active = None
    guards = None
    s1_verified = False
    failed = False
    def persist(name, value):
        try:
            return child.durable_snapshot(output / name, value)
        except BaseException as exc:
            result['persistence_errors'].append(child.acl_failure(exc, 'matrix', 'observed'))
            raise
    def observe(label, value):
        result['family_observations'].append({'phase': label, 'observation': value})
        persist(label + '-family.json', value)
    def restore_stage(label, record):
        entry = {'phase': label, 'original_snapshot_sha256': record['original_snapshot_sha256'],
                 'status': 'failed'}
        result['restorations'].append(entry)
        try:
            entry['api'] = matrix_restore(root, record, Path(record.get('operation_output') or record['ownership']['output']), label)
            entry['actual'] = matrix_check_family(root, record['original_dacls'], record['original_inventory'])
            entry['outside_guard_actual'] = matrix_guards(root, cwd)
            if guards is not None and entry['outside_guard_actual'] != guards:
                raise ValueError('external ancestor or sibling guard changed')
            entry['status'] = 'verified'
        except BaseException as exc:
            entry['failure'] = child.acl_failure(exc, label, 'readback')
            try:
                entry['failure_observation'] = matrix_observe(root)
            except BaseException as observation:
                entry['observation_failure'] = child.acl_failure(observation, label, 'readback')
            result.setdefault('restoration_errors', []).append(entry['failure'])
            result['restoration_error'] = type(exc).__name__
        finally:
            try:
                persist(label + '-terminal.json', entry)
            except BaseException as exc:
                entry['status'] = 'failed'
                entry['receipt_failure'] = child.acl_failure(exc, label, 'receipt')
                result.setdefault('restoration_errors', []).append(entry['receipt_failure'])
                result['restoration_error'] = type(exc).__name__
        return entry['status'] == 'verified'
    try:
        target = matrix_topology(root, cell['kind'])
        guards = matrix_guards(root, cwd)
        result['outside_guards'] = guards
        persist('outside-guards.json', guards)
        s0_output = output / 'setup-original'
        s0_output.mkdir()
        result['step'] = 'snapshot_s0'
        s0 = matrix_setup_snapshot(root, actor_sid, collector_sid, s0_output)
        result['s0_record'] = s0
        result['initial_root'] = s0['original_dacls'][str(root)]
        observe('s0', matrix_observe(root))
        result['step'] = 'setup'
        expected = dict(s0['original_dacls'])
        seed = matrix_seed_descriptor(collector_sid)
        descendants = [p for p in child.fixture_paths(root) if p != root]
        # Every original byte remains in S0. These explicit declared assignments
        # avoid guessing how unmarked/default legacy ACEs will be converted.
        for path in sorted(descendants, key=lambda p: (-len(p.parts), str(p))):
            expected = matrix_setup_transition(root, path, seed, expected, result, output, 'controlled_seed')
        parent_aces = [matrix_ace(s, flags=3) for s in (collector_sid, 'S-1-5-18', 'S-1-5-32-544')]
        if cell['actor_shape'] == 'inherited':
            parent_aces.append(matrix_ace(actor_sid, flags=3))
        parent_plan = matrix_descriptor(0x1404, parent_aces)
        expected = matrix_setup_transition(root, root, parent_plan, expected, result, output, 'parent_setup')
        seed_aces = child.descriptor_contract(seed)['aces']
        for path in sorted(descendants, key=lambda p: (len(p.parts), str(p))):
            planned = matrix_descriptor(0x404, seed_aces + matrix_inherited_aces(
                expected[str(path.parent)], path.is_dir()))
            expected = matrix_setup_transition(root, path, planned, expected, result, output, 'controlled_AI')
        inherited = matrix_inherited_aces(parent_plan, target.is_dir())
        actual_inherited = [a for a in child.descriptor_contract(child.windows_descriptor(target))['aces']
                            if bytes.fromhex(a)[1] & 0x10]
        if actual_inherited != inherited:
            raise ValueError('target inherited ACE bytes differ from fixed parent plan')
        aces = [matrix_ace(s) for s in (collector_sid, 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-4')]
        if cell['actor_shape'] == 'explicit':
            aces.append(matrix_ace(actor_sid))
        elif cell['actor_shape'] == 'deny':
            aces.insert(0, matrix_ace(actor_sid, 0x10156 if target.is_dir() else 0x10116, 1))
        target_plan = matrix_descriptor(cell['control'], aces + inherited)
        result['target_plan'] = target_plan
        expected = matrix_setup_transition(root, target, target_plan, expected, result, output, 'target')
        if target.is_dir():
            expected = matrix_ready_descendants(root, target, result, output, s0['original_inventory'])
        if matrix_guards(root, cwd) != guards:
            raise ValueError('external guard changed during setup')
        ownership = {k: str(v) for k, v in {'cwd': cwd, 'output': output, 'repo': repo,
                     'home': repo, 'plugin_root': repo, 'data_root': repo}.items()}
        ownership.update(created_exclusively=True, root_identity=[root.stat().st_dev, root.stat().st_ino])
        matrix_assert_setup_state(root, expected, result)
        ready = matrix_stable_observation(root)
        result['step'] = 'snapshot_s1'
        candidate_s1 = child.prepare_read_transaction(root, sid=actor_sid, ownership=ownership)
        if (candidate_s1['original_dacls'] != ready['raw_dacls']
                or candidate_s1['original_inventory'] != ready['inventory']
                or matrix_stable_observation(root) != ready):
            result['rejected_s1_record'] = candidate_s1
            raise ValueError('ready S1 differs from coherent whole-family read')
        s1 = candidate_s1
        result['s1_record'] = s1
        active = s1
        observe('s1', matrix_check_family(root, s1['original_dacls'], s1['original_inventory']))
        expected = dict(s1['original_dacls'])
        for phase in ('grant', 'deny'):
            result['step'] = phase
            before = expected[str(target)]
            planned = child.planned_acl_change(before, actor_sid, phase, target.is_dir())
            child.apply_acl_change(root, active, target, before, planned, phase, expected)
            observe(phase, matrix_check_family(root, expected, s1['original_inventory']))
        result['step'] = 'restore_v3'
        s1_verified = restore_stage('v3', active)
        if not s1_verified:
            raise OSError('v3 S1 restoration unverified')
        result['v3_record'] = active
        legacy_output = (output / 'legacy').resolve()
        legacy_output.mkdir()
        active = {k: copy.deepcopy(v) for k, v in s1.items() if k in (
            'family', 'root', 'sid', 'collector_sid', 'original_dacls', 'original_inventory',
            'objects', 'original_restore_strategies')}
        active.update(policy='specific-write-deny/v2', commands=[], operations=[],
                      operation_output=str(legacy_output),
                      operation_output_identity=[legacy_output.stat().st_dev, legacy_output.stat().st_ino])
        snapshot = legacy_output / 'fixture-original-transaction.json'
        active['original_snapshot_sha256'] = child.durable_snapshot(snapshot, active)
        active['original_snapshot_path'] = str(snapshot)
        result['step'] = 'deny_v2'
        s1_verified = False
        expected = dict(active['original_dacls'])
        before = expected[str(target)]
        planned = child.planned_acl_change(before, actor_sid, 'deny', target.is_dir(), active['policy'])
        child.apply_acl_change(root, active, target, before, planned, 'deny', expected)
        observe('deny_v2', matrix_check_family(root, expected, s1['original_inventory']))
        result['step'] = 'restore_v2'
        s1_verified = restore_stage('v2', active)
        if not s1_verified:
            raise OSError('v2 S1 restoration unverified')
        result['v2_record'] = active
        result['step'] = 'verified'
    except BaseException as exc:
        failed = True
        result['failure'] = child.acl_failure(exc, 'matrix', result['step'])
        if getattr(exc, 'close_failure', None) is not None:
            result['failure']['query_close_failure'] = exc.close_failure
        if active is not None:
            result['failed_record'] = active
        if isinstance(exc, KeyboardInterrupt):
            result['interrupted'] = True
        try:
            result['failed_observation'] = matrix_observe(root)
            persist('matrix-before-restoration-failure.json', result)
        except BaseException as observation:
            result['observation_error'] = type(observation).__name__
    finally:
        if s1 is not None and not s1_verified:
            # A failed declared restore is retained, never retried until it passes.
            prior = any(e['phase'] in ('v3', 'v2') and e['status'] == 'failed' for e in result['restorations'])
            if not prior:
                s1_verified = restore_stage('failure_s1', s1)
        if s0 is not None:
            result['setup_restore_record'] = s0
            if not restore_stage('setup_s0', s0):
                failed = True
        else:
            result['s0_not_formed'] = True
        if result['persistence_errors'] or result.get('restoration_errors'):
            failed = True
        result['status'] = 'failed' if failed else 'passed'
        try:
            persist('matrix-cell.json', result)
        except BaseException as exc:
            result['status'] = 'failed'
            result['receipt_failure'] = child.acl_failure(exc, 'matrix', 'receipt')
            result.setdefault('failure', result['receipt_failure'])
    return result


def matrix_run_cells(report, actor_sid, collector_sid, repo, output, cwd):
    profile = report.get('cell_profile', 'full32')
    cells = matrix_profile_cells(profile)
    if 'cells' in report and report['cells'] != cells:
        raise ValueError('selected cells differ from fixed profile')
    for number, cell in enumerate(cells, 1):
        cell_output = output / ('cell-' + str(number).zfill(2))
        cell_output.mkdir()
        if profile == 'full32':
            result = matrix_cell(cell, actor_sid, collector_sid, repo, cell_output, cwd)
        else:
            result = matrix_cell(cell, actor_sid, collector_sid, repo, cell_output, cwd, profile=profile)
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
    parser.add_argument('--cell-profile', choices=('full32', 'protected8'), default='full32')
    parser.add_argument('--expected-runner-sha256')
    parser.add_argument('--collector-sid')
    args = parser.parse_args(argv)
    report = matrix_preflight(args)
    report['argv'] = list(argv)
    report['argv_sha256'] = hashlib.sha256(json.dumps(list(argv), separators=(',', ':')).encode()).hexdigest()
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
    if args.collector_sid is not None and collector_sid != args.collector_sid:
        raise ValueError('collector differs from preflight pin')
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
                      'total_cells': len(report['cells']), 'ordinary_actor_execution': 'not_run', 'output': str(output)}))
    return 0 if report['status'] == 'passed' else 1


class MatrixSourceContractsTests(unittest.TestCase):
    def test_full32_exact_stable_failure_first_permutation_and_other_profile(self):
        original = [{'kind': k, 'control': c, 'actor_shape': a}
                    for k in ('file', 'directory') for c in (4, 0x404, 0x1004, 0x1404)
                    for a in ('missing', 'explicit', 'inherited', 'deny')]
        current = matrix_cells()
        self.assertEqual(original[12], {'kind': 'file', 'control': 0x1404, 'actor_shape': 'missing'})
        self.assertEqual(current, [original[12], *original[:12], *original[13:]])
        expected = {(k, c, a) for k in ('file', 'directory') for c in (4, 0x404, 0x1004, 0x1404)
                    for a in ('missing', 'explicit', 'inherited', 'deny')}
        self.assertEqual({(c['kind'], c['control'], c['actor_shape']) for c in current}, expected)
        self.assertEqual(len(current), len(expected))
        self.assertEqual(matrix_profile_cells('full32'), current)
        self.assertEqual(matrix_profile_cells('protected8'), [{'kind': k, 'control': c, 'actor_shape': a}
            for k in ('file', 'directory') for c in (0x1004, 0x1404) for a in ('missing', 'inherited')])

    def test_non_ai_setup_raw_flags_four_and_protected_step_receipts(self):
        from types import SimpleNamespace
        for control in (4, 0x1004):
            with self.subTest(control=control), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / 'file'
                target.write_bytes(b'owned source setup control')
                before = ACLFamilyTests.descriptor_value('other')
                planned = matrix_descriptor(control, child.descriptor_contract(before)['aces'])
                descriptor = before
                def native_raw(path, flags, buffer):
                    nonlocal descriptor
                    descriptor = planned
                    return 1
                raw = mock.Mock(side_effect=native_raw)
                api = SimpleNamespace(SetFileSecurityW=raw)
                def observe(path, value=None):
                    nonlocal descriptor
                    if value is None:
                        return descriptor
                    descriptor = value
                    return {'api': 'SetNamedSecurityInfoW', 'security_information': 0x80000004,
                            'return_value': 0, 'winerror': 0}
                result = {'setup': []}
                with mock.patch.object(ctypes, 'WinDLL', return_value=api, create=True), \
                     mock.patch.object(child, 'windows_descriptor', side_effect=observe):
                    matrix_setup_operation(root, target, planned, result, root)
                raw.assert_called_once()
                self.assertEqual(raw.call_args.args[1], 4)
                self.assertEqual(child.descriptor_contract(descriptor), child.descriptor_contract(planned))
                if control == 0x1004:
                    step = result['setup'][0]['steps'][0]
                    self.assertEqual(step['native_result']['security_information'], 0x80000004)
                    self.assertEqual(child.descriptor_contract(step['actual'])['dacl_control'], 0x1404)
                    self.assertTrue((root / 'setup-1-protect-observed.json').is_file())
                else:
                    self.assertNotIn('steps', result['setup'][0])

    def test_setup_api_failure_restores_owned_scene_then_stops_batch(self):
        from tests.test_incident_fixture_v3 import InheritanceAPIDouble
        for restore_failed in (False, True):
            with self.subTest(restore_failed=restore_failed), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                output, cwd = base / 'output', base / 'workspace'
                output.mkdir()
                cwd.mkdir()
                double = InheritanceAPIDouble(cwd / 'incident-readonly-cell-01')
                injected = []
                phase = None
                real_setup = matrix_setup_operation
                def setup(root, path, planned, result, output):
                    nonlocal phase
                    phase = result['setup_phase']
                    return real_setup(root, path, planned, result, output)
                def failure(path, planned, count):
                    if phase == 'target' and path == double.root / 'target' and not injected:
                        injected.append('target')
                        raise child.DACLWriteError({'api': 'SetFileSecurityW', 'security_information': 4,
                                                    'return_value': 0, 'winerror': 5})
                    if restore_failed and injected == ['target'] and path == double.root:
                        injected.append('restore')
                        # Failed restoration remains failed even when its unchanged
                        # readback happens to match. Other family objects still restore.
                        double.fail_write = None
                        raise child.DACLWriteError({'api': 'SetFileSecurityW', 'security_information': 4,
                                                    'return_value': 0, 'winerror': 5})
                double.fail_write = failure
                report = {'results': []}
                with double.patches(), mock.patch(__name__ + '.matrix_setup_operation', side_effect=setup):
                    matrix_run_cells(report, double.actor, double.collector, base / 'source', output, cwd)
                self.assertEqual(report['attempted_cells'], 1)
                self.assertEqual(len(report['remaining_cells']), 31)
                result = report['results'][0]
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(next(e for e in result['setup'] if e['phase'] == 'target')['native_result']['winerror'], 5)
                self.assertEqual('restoration_error' in result, restore_failed)
                if not restore_failed:
                    for name, saved in result['s0_record']['original_dacls'].items():
                        self.assertEqual(child.descriptor_contract(double.descriptor(name)),
                                         child.descriptor_contract(saved))
                    self.assertEqual(child.inventory(double.root), result['s0_record']['original_inventory'])

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
