"""Stat-provider boundaries retain replacement and tamper detection on all hosts."""
import copy
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests import test_host_terminal_wire as wire
from tests.test_cg142_commentary import message, obs, raw


def changed(value, **updates):
    fields = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
    return SimpleNamespace(**{**fields, **updates})


class StatContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.path = self.root / 'source.jsonl'
        self.path.write_bytes(raw(message()))
        self.real_fstat = os.fstat

    def shifted_fstat(self, fd):
        value = self.real_fstat(fd)
        return changed(value, st_ctime_ns=value.st_ctime_ns + 1006700)

    def test_cross_api_ctime_difference_preserves_real_observation_and_anchor(self):
        with self.path.open('rb') as handle:
            expected_ctime = self.real_fstat(handle.fileno()).st_ctime_ns + 1006700
        with patch.object(obs.os, 'fstat', side_effect=self.shifted_fstat):
            result = obs.observe(self.path, self.root, 's1', [])
            self.assertEqual(result['status'], 'observed')
            self.assertEqual(result['file_identity']['ctime_ns'], expected_ctime)
            anchor = {k: result[k] for k in ('file_identity', 'snapshot_sha256', 'scanned_bytes')}
            self.assertEqual(obs.observe(self.path, self.root, 's1', [], prior=anchor)['status'], 'observed')

    def test_same_provider_changes_and_cross_api_binding_disagreements_fail(self):
        base = self.path.lstat()
        handle = changed(base, st_ctime_ns=base.st_ctime_ns + 1006700)
        for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink'):
            for which in ('path', 'handle'):
                with self.subTest(field=field, which=which):
                    after_path, after_handle = base, handle
                    if which == 'path':
                        after_path = changed(base, **{field: getattr(base, field) + 1})
                    else:
                        after_handle = changed(handle, **{field: getattr(handle, field) + 1})
                    self.assertFalse(obs.stable_snapshot(base, handle, after_handle, after_path))
        for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_mode', 'st_nlink'):
            other = changed(handle, **{field: getattr(handle, field) + 1})
            self.assertFalse(obs.stable_snapshot(base, other, other, base))

    def test_actual_reader_rejects_handle_ctime_change_during_scan(self):
        with self.path.open("rb") as handle:
            before = self.real_fstat(handle.fileno())
        with patch.object(obs.os, 'fstat', side_effect=[before, changed(before, st_ctime_ns=before.st_ctime_ns + 1)]):
            self.assertEqual(obs.observe(self.path, self.root, 's1', [])['reason'], 'snapshot_changed')

    def test_cross_api_tolerance_does_not_weaken_content_or_replacement_checks(self):
        with patch.object(obs.os, 'fstat', side_effect=self.shifted_fstat):
            result = obs.observe(self.path, self.root, 's1', [])
            anchor = {k: result[k] for k in ('file_identity', 'snapshot_sha256', 'scanned_bytes')}
            self.path.write_bytes(raw(message(text='x')))
            self.assertEqual(obs.observe(self.path, self.root, 's1', [], prior=anchor)['reason'], 'snapshot_truncated')
            self.path.write_bytes(raw(message()))
            replacement = self.root / 'replacement'
            replacement.write_bytes(self.path.read_bytes())
            replacement.replace(self.path)
            self.assertEqual(obs.observe(self.path, self.root, 's1', [], prior=anchor)['reason'], 'snapshot_replaced')
            result = obs.observe(self.path, self.root, 's1', [])
            anchor = {k: result[k] for k in ('file_identity', 'snapshot_sha256', 'scanned_bytes')}
            original = self.path.read_bytes()
            self.path.write_bytes(original.replace(b'Only', b'Else'))
            self.assertEqual(obs.observe(self.path, self.root, 's1', [], prior=anchor)['reason'], 'snapshot_prefix_changed')
            self.path.write_bytes(raw(message(), message(text='conflict')))
            self.assertEqual(obs.observe(self.path, self.root, 's1', [])['reason'], 'conflicting_message_identity')

    def test_sidecar_and_freshness_use_consistent_provider_without_closing_work(self):
        h = wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        h.start('Context Guard 是这个插件的名称吗？')
        item = message(turn=h.turn_id)
        item['payload']['thread_id'] = h.session_id
        h.rows.append(item)
        h.write_rows()
        directory = h.root / 'private/sessions' / h.session_id
        original = copy.deepcopy(h.state()['requirements'])
        with patch.object(obs.os, 'fstat', side_effect=self.shifted_fstat):
            wire.cg.dispatch(h.event('PreCompact'))
            result = wire.cg.commentary_summary(directory, h.state())
            self.assertEqual(result['status'], 'observed')
            self.assertEqual(result['recorded_messages'], 1)
            self.assertEqual(result['freshness'], 'unchanged_snapshot')
            self.assertEqual(result['answer_coverage'], 'unknown')
        self.assertEqual(h.state()['requirements'], original)

    def test_unquoted_windows_path_with_following_prose_remains_ambiguous(self):
        target = r'C:\fixture\suite.py'
        self.assertEqual(wire.cg.root_absolute_locator_mentions(f'请运行 {target} 的测试。'), (set(), True))
        self.assertEqual(wire.cg.root_absolute_locator_mentions(f'请运行 "{target}" 的测试。'), ({target}, False))
