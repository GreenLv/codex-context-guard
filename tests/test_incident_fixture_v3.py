"""Synthetic v3 transaction/actor tests; no native Windows ACL acceptance."""
import base64
import copy
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import test_incident_acl_family as legacy
from tools.validation import incident_host_acceptance as host
from tools.validation import incident_readonly_child as child


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

    def apply(self, argv, **kwargs):
        self.events.append(('command', argv))
        self.assertTrue((self.output / 'fixture-original-transaction.json').is_file())
        self.assertNotEqual(self.sid, self.collector)
        self.assertEqual(argv[:1], ['icacls'])
        directory = Path(argv[1]).is_dir()
        bits = argv[-1].split(':', 1)[1].strip('()').split(',')
        self.assertEqual(argv[-1].split(':', 1)[0], '*' + self.sid)
        rights = {'RD': 1, 'WD': 2, 'AD': 4, 'REA': 8, 'WEA': 16, 'X': 32,
                  'DC': 64, 'RA': 128, 'WA': 256, 'DE': 65536, 'RC': 131072, 'S': 1048576}
        mask = 0
        for bit in bits:
            mask |= rights[bit]
        aces = child.descriptor_contract(self.descriptors[argv[1]])['aces']
        if argv[2] == '/grant':
            self.assertEqual(bits, ['RD', 'REA', 'RA', 'RC', 'S'] + (['X'] if directory else []))
            matching = [i for i, value in enumerate(aces) if bytes.fromhex(value)[:2] == b'\x00\x00'
                        and child.ace_sid(bytes.fromhex(value)) == self.sid]
            if matching:
                self.assertEqual(len(matching), 1)
                raw = bytearray.fromhex(aces[matching[0]])
                struct.pack_into('<I', raw, 4, struct.unpack_from('<I', raw, 4)[0] | mask)
                aces[matching[0]] = raw.hex()
                self.descriptors[argv[1]] = self.with_aces(self.descriptors[argv[1]], aces)
            else:
                self.descriptors[argv[1]] = self.add_actor(self.descriptors[argv[1]], self.sid, mask)
        else:
            self.assertEqual(argv[2], '/deny')
            self.assertEqual(bits, ['WD', 'AD', 'WEA', 'WA', 'DE'] + (['DC'] if directory else []))
            # Independent fixture semantics from the actual requested rights:
            # remove same rights from actor explicit grants; merge one exact
            # explicit deny, or insert it before existing explicit grants.
            result, merged = [], False
            for value in aces:
                raw = bytearray.fromhex(value)
                if child.ace_sid(raw) == self.sid and not raw[1] & 0x10:
                    old_mask = struct.unpack_from('<I', raw, 4)[0]
                    if raw[0] == 0:
                        remaining = old_mask & ~mask
                        if not remaining:
                            continue
                        struct.pack_into('<I', raw, 4, remaining)
                    elif raw[1] == 0:
                        self.assertFalse(merged)
                        struct.pack_into('<I', raw, 4, old_mask | mask)
                        merged = True
                result.append(raw.hex())
            if not merged:
                result.insert(0, self.actor_ace(self.sid, mask, ace_type=1))
            self.descriptors[argv[1]] = self.with_aces(self.descriptors[argv[1]], result)
        return mock.Mock(returncode=0, stdout=b'ok', stderr=b'')

    def patches(self, runner=None):
        stack = __import__('contextlib').ExitStack()
        stack.enter_context(mock.patch.object(child, 'current_sid', return_value=self.collector))
        stack.enter_context(mock.patch.object(child, 'windows_descriptor', side_effect=self.descriptor))
        stack.enter_context(mock.patch.object(child.subprocess, 'run', side_effect=runner or self.apply))
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
            commands = [v[1] for v in self.events if v[0] == 'command']
            grants = [v for v in commands if v[2] == '/grant']
            self.assertEqual(len(grants), len(self.original))
            self.assertTrue(all(v[-1] == '*' + self.sid + (':(RD,REA,RA,RC,S,X)' if Path(v[1]).is_dir()
                                                         else ':(RD,REA,RA,RC,S)') for v in grants))
            denies = [v for v in commands if v[2] == '/deny']
            self.assertEqual(len(denies), len(self.original))
            self.assertEqual({Path(v[1]).is_dir() for v in denies}, {False, True})
            for argv in denies:
                wanted = 0x10156 if Path(argv[1]).is_dir() else 0x10116
                actors = [bytes.fromhex(a) for a in child.descriptor_contract(self.descriptors[argv[1]])['aces']
                          if child.ace_sid(bytes.fromhex(a)) == self.sid and bytes.fromhex(a)[:2] == b'\x01\x00']
                self.assertEqual(len(actors), 1)
                self.assertEqual(struct.unpack_from('<I', actors[0], 4)[0], wanted)
            self.assertTrue(all('/T' not in v and '/grant:r' not in v for v in commands))
            child.restore(self.root, record)
            self.assertEqual(self.descriptors, self.original)

    def test_partial_grant_deny_and_bad_readback_restore_every_original(self):
        for failure in ('grant_nonzero', 'grant_readback', 'deny_nonzero', 'deny_readback', 'deny_duplicate', 'deny_split', 'interrupt'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as extra:
                # Each case retains exclusive snapshots and failure receipts.
                self.output = Path(extra)
                self.ownership['output'] = str(self.output)
                original_name = self.root.name
                wanted = self.cwd / ('incident-readonly-' + self.output.name)
                self.root.rename(wanted)
                self.root = wanted
                self.ownership['root_identity'] = [wanted.stat().st_dev, wanted.stat().st_ino]
                self.original = {str(p): legacy.ACLFamilyTests.descriptor_value(str(p)) for p in child.fixture_paths(wanted)}
                self.descriptors = dict(self.original)
                calls = []
                def apply(argv, **kwargs):
                    calls.append(argv)
                    result = self.apply(argv, **kwargs)
                    if failure == 'grant_readback' and argv[2] == '/grant':
                        self.descriptors[argv[1]] = self.add_actor(self.descriptors[argv[1]], 'S-1-5-21-999', 1)
                    if failure == 'deny_readback' and argv[2] == '/deny':
                        self.descriptors[argv[1]] = self.add_actor(self.descriptors[argv[1]], self.sid, 1, ace_type=1)
                    if failure == 'deny_duplicate' and argv[2] == '/deny':
                        self.descriptors[argv[1]] = self.add_actor(self.descriptors[argv[1]], self.sid, 2, ace_type=1)
                    if failure == 'deny_split' and argv[2] == '/deny':
                        aces = child.descriptor_contract(self.descriptors[argv[1]])['aces']
                        raw = bytes.fromhex(aces[0])
                        mask = struct.unpack_from('<I', raw, 4)[0]
                        aces[:1] = [self.actor_ace(self.sid, 2, 1), self.actor_ace(self.sid, mask & ~2, 1)]
                        self.descriptors[argv[1]] = self.with_aces(self.descriptors[argv[1]], aces)
                    if ((failure == 'grant_nonzero' and len(calls) == 2)
                            or (failure == 'deny_nonzero' and argv[2] == '/deny')):
                        return mock.Mock(returncode=5, stdout=b'', stderr=b'partial')
                    if failure == 'interrupt' and len(calls) == 2:
                        raise KeyboardInterrupt()
                    return result
                with self.patches(apply):
                    record = self.prepare()
                    with self.assertRaises(child.RestrictionError) as caught:
                        self.grant(record)
                        req = self.request(record, 'baseline_granted')
                        child.apply_read_transaction(self.root, record, 'deny', baseline_record=self.observed(req), baseline_request=req)
                    self.assertEqual(caught.exception.record['restoration'], 'verified')
                    self.assertEqual(self.descriptors, self.original)
                self.root.rename(self.cwd / original_name)
                self.root = self.cwd / original_name

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
        req['restriction']['commands'][0]['output'] = '本地化回执\r\n\ufffd'
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


if __name__ == '__main__':
    unittest.main()
