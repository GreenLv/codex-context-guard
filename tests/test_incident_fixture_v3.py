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
                self.assertEqual(sum('-restore-' in n for n in receipts), len(fixture.original) * 2 + 2)
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
