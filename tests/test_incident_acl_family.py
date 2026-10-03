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

    def apply(self, argv, **kwargs):
        self.descriptors[argv[1]] = 'restricted'
        return mock.Mock(returncode=0, stdout=b'ok', stderr=b'')

    def restricted(self, runner=None):
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor', side_effect=self.descriptor), \
             mock.patch.object(child.subprocess, 'run', side_effect=runner or self.apply):
            return child.windows_restrict(self.root)

    def test_exact_bits_bottom_up_and_original_dacl_restore(self):
        record = self.restricted()
        argv = [c['argv'] for c in record['commands']]
        self.assertEqual(argv[-1][1], str(self.root))
        self.assertEqual(argv[0][1], str(self.root / 'nested' / 'lock'))
        self.assertTrue(all('/T' not in a and '/C' not in a and '/inheritance:r' not in a
                            and '/grant:r' not in a for a in argv))
        self.assertTrue(all(a[-1] == '*' + self.sid +
                            (' :(WD,AD,WEA,WA,DE,DC)' if Path(a[1]).is_dir()
                             else ' :(WD,AD,WEA,WA,DE)').replace(' ', '') for a in argv))
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
             mock.patch.object(child.subprocess, 'run', side_effect=self.apply):
            record = child.windows_restrict(self.root, sid=target)
            self.assertEqual(record['sid'], target)
            self.assertEqual(record['collector_sid'], self.sid)
            self.assertTrue(all('*' + target + ':' in c['argv'][-1] for c in record['commands']))
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
        self.assertEqual(record, before)

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
        def fail(argv, **kwargs):
            nonlocal count
            count += 1
            self.apply(argv)
            return mock.Mock(returncode=5 if count == 2 else 0, stdout=b'partial', stderr=b'denied')
        with self.assertRaises(child.RestrictionError) as raised:
            self.restricted(fail)
        record = raised.exception.record
        self.assertEqual(record['commands'][-1]['exit_code'], 5)
        self.assertEqual(record['restoration'], 'verified')
        self.assertEqual(self.descriptors, self.original)

    def test_failure_before_mutation_and_unrecoverable_restore_fail_closed(self):
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor', side_effect=OSError('save')), \
             mock.patch.object(child.subprocess, 'run') as runner:
            with self.assertRaises(OSError):
                child.windows_restrict(self.root)
            runner.assert_not_called()
        def fail(argv, **kwargs):
            return mock.Mock(returncode=5, stdout=b'', stderr=b'fail')
        with mock.patch.object(child, 'restore', side_effect=OSError('restore')):
            with self.assertRaises(child.RestrictionError) as raised:
                self.restricted(fail)
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
        with mock.patch.object(child, 'current_sid', return_value=self.sid), \
             mock.patch.object(child, 'windows_descriptor', return_value='wrong'):
            with self.assertRaises(ValueError):
                child.restore(self.root, record)

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
            real_run = child.subprocess.run
            count = 0
            first_mutation = {}
            def fail_second(argv, **kwargs):
                nonlocal count
                if str(argv[0]).lower() != 'icacls':
                    return real_run(argv, **kwargs)
                count += 1
                if count == 2:
                    self.assertTrue(first_mutation.get('dacl_changed'))
                    return subprocess.CompletedProcess(argv, 5, b'forced second ACL failure', b'')
                result = real_run(argv, **kwargs)
                self.assertEqual(result.returncode, 0, result.stderr)
                path = Path(argv[1])
                applied = child.windows_descriptor(path)
                first_mutation.update(argv=argv, exit_code=result.returncode,
                                      before=dacls[str(path)], after=applied,
                                      dacl_changed=child.descriptor_contract(applied) !=
                                      child.descriptor_contract(dacls[str(path)]))
                (root.parent / 'first-mutation.json').write_text(json.dumps(first_mutation, indent=2))
                self.assertTrue(first_mutation['dacl_changed'])
                return result
            self.snapshot(root, 'before')
            with mock.patch.object(child.subprocess, 'run', side_effect=fail_second):
                with self.assertRaises(child.RestrictionError) as raised:
                    child.restrict(root)
            self.snapshot(root, 'after', raised.exception.record)
            self.assertEqual(count, 2)
            self.assertEqual([c['exit_code'] for c in raised.exception.record['commands']], [0, 5])
            self.assertTrue(first_mutation['dacl_changed'])
            self.assertEqual(raised.exception.record['restoration'], 'verified')
            self.assertEqual({str(p): child.descriptor_contract(child.windows_descriptor(p)) for p in paths},
                             {k: child.descriptor_contract(v) for k, v in dacls.items()})
            self.assertEqual(child.inventory(root), before)


if __name__ == '__main__':
    unittest.main()
