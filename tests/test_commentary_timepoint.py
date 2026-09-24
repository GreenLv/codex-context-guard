"""Private timepoint capture must bind a stage without copying review secrets."""

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.validation import commentary_timepoint as timepoint


class FakeRuntime:
    def validate_state_integrity(self, state):
        if state.get('integrity') != 'ok':
            raise ValueError('bad_state')

    def answer_review_request(self, directory, state, item, *, codex_home):
        snapshot = hashlib.sha256(Path(state['session']['transcript_path']).read_bytes()).hexdigest()
        return {'subject': {'question_id': item['id'],
                            'session_id': state['session']['id'],
                            'turn_id': 'turn-1'},
                'messages': [{'message_id': state.get('answer', 'first')}],
                'answer_texts': {'one': state.get('answer', 'first')},
                'question_catalog': [item['id']],
                'as_of': {'source': 'fixture', 'snapshot_sha256': snapshot,
                          'watermark': 1}}


class FakeObserver:
    def __init__(self, root):
        self.thread, self.turn = 'thread-1', 'turn-1'
        self.question_id, self.main_ids = 'Q1', ['M1']
        self.plan = {'codex_home': str(root / 'home'),
                     'runtime_tree_sha256': 'b' * 64,
                     'source_tree_sha256': 'e' * 64,
                     'binary_sha256': 'f' * 64,
                     'namespace': 'cg-candidate-fixture',
                     'review_coverage': 'complete'}
        self.runtime = FakeRuntime()
        self.runtime_root = root / 'runtime'

    def _product_directory(self, thread):
        assert thread == self.thread
        return Path(self.plan['codex_home']) / 'plugins/data/context-guard-fixture/sessions' / thread


class TimepointTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.observer = FakeObserver(self.root)
        self.directory = self.observer._product_directory(self.observer.thread)
        for name in ('prompts/units', 'answer-reviews'):
            (self.directory / name).mkdir(parents=True)
        (self.directory / 'prompts/P0001.json').write_text('{"fixture":1}')
        (self.directory / 'prompts/units/P0001.json').write_text('{"fixture":2}')
        (self.directory / 'answer-reviews/policy.json').write_text('{"fixture":3}')
        (self.directory / 'answer-reviews/capture.key').write_bytes(b'private-key-never-copy')
        self.transcript = Path(self.observer.plan['codex_home']) / 'sessions/day/rollout.jsonl'
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_bytes(b'{"first":true}\n')
        self.state = {'session': {'id': self.observer.thread,
                                  'transcript_path': str(self.transcript)},
                      'requirements': [{'id': 'Q1'}, {'id': 'M1'}],
                      'integrity': 'ok'}
        (self.directory / 'state.json').write_text(json.dumps(self.state))
        self.run = self.root / 'run'
        self.run.mkdir()
        self.rpc = self.run / 'rpc.jsonl'
        self.rpc.write_bytes(b'{"event":"review"}\n')
        self.projection = {'question_id': 'Q1', 'main_ids': ['M1'],
                           'requirements_sha256': hashlib.sha256(timepoint.fixture.canonical(
                               self.state['requirements'])).hexdigest(),
                           'product_projection_sha256': 'd' * 64,
                           'native_acceptance': 'not_established'}
        (self.run / 'review-barrier.json').write_text(json.dumps({
            'schema': 'cg-review-barrier/v1', 'projection': self.projection}))

    def capture(self, stage='review', anchor='call-1'):
        with mock.patch.object(timepoint, '_projection', return_value=self.projection):
            return timepoint.capture(self.observer, self.run, stage,
                                     self.projection, self.rpc, anchor)

    def verify(self, descriptor, stage='review', anchor='call-1'):
        with mock.patch.object(timepoint, '_projection', return_value=self.projection):
            return timepoint.verify(
                self.observer, self.run, stage, descriptor, self.projection,
                self.rpc, anchor, after_boundary=len(b'{"event":"review"}\n'),
                before_boundary=self.rpc.stat().st_size + 1)

    def test_bound_snapshot_survives_unrelated_append_without_copying_key(self):
        descriptor = self.capture()
        self.rpc.write_bytes(self.rpc.read_bytes() + b'{"event":"suite"}\n')
        self.transcript.write_bytes(self.transcript.read_bytes() + b'{"later":true}\n')
        projection, state, binding = self.verify(descriptor)
        self.assertEqual(projection, self.projection)
        self.assertEqual(state, self.state)
        self.assertEqual(binding['message_ids'], ['first'])
        self.assertNotIn(b'private-key-never-copy',
                         (self.run / 'timepoint-review.json').read_bytes()
                         + (self.run / 'timepoint-review-state.json').read_bytes())
        self.assertEqual(len(list(self.run.glob('timepoint-*'))), 2)

    def test_late_root_or_control_does_not_recompute_historical_projection(self):
        descriptor = self.capture()
        self.rpc.write_bytes(self.rpc.read_bytes() + b'{"event":"suite"}\n')
        self.transcript.write_bytes(self.transcript.read_bytes()
                                    + b'{"later_root":"run another action"}\n')
        with mock.patch.object(timepoint, '_projection',
                               side_effect=AssertionError('late source was read')):
            projection, _state, _binding = timepoint.verify(
                self.observer, self.run, 'review', descriptor, self.projection,
                self.rpc, 'call-1', after_boundary=len(b'{"event":"review"}\n'),
                before_boundary=self.rpc.stat().st_size + 1)
        self.assertEqual(projection, self.projection)

    def test_stage_subject_runtime_hash_and_dependency_swaps_fail(self):
        descriptor = self.capture()
        for stage, anchor in (('cold', 'call-1'), ('review', 'other')):
            with self.subTest(stage=stage, anchor=anchor), self.assertRaises(timepoint.TimepointError):
                self.verify(descriptor, stage=stage, anchor=anchor)
        self.observer.plan['runtime_tree_sha256'] = 'e' * 64
        with self.assertRaisesRegex(timepoint.TimepointError, 'subject_mismatch'):
            self.verify(descriptor)
        self.observer.plan['runtime_tree_sha256'] = 'b' * 64
        (self.directory / 'prompts/P0001.json').write_text('{"fixture":9}')
        with self.assertRaisesRegex(timepoint.TimepointError, 'dependencies_changed'):
            self.verify(descriptor)
        (self.directory / 'prompts/P0001.json').unlink()
        with self.assertRaises(timepoint.TimepointError):
            self.verify(descriptor)

    def test_tamper_prefix_and_budget_fail_closed(self):
        descriptor = self.capture()
        meta = Path(descriptor['path'])
        meta.write_bytes(meta.read_bytes() + b' ')
        with self.assertRaisesRegex(timepoint.TimepointError, 'manifest_hash_changed'):
            self.verify(descriptor)
        meta.write_bytes(meta.read_bytes()[:-1])
        self.transcript.write_bytes(b'{"first":nope}\n')
        with self.assertRaisesRegex(timepoint.TimepointError, 'transcript_prefix_changed'):
            self.verify(descriptor)
        (self.directory / 'state.json').write_bytes(b'x' * (timepoint.STATE_LIMIT + 1))
        with self.assertRaisesRegex(timepoint.TimepointError, 'unbounded_timepoint_file'):
            self.capture('cold', 'compact-1')

    def test_seal_state_and_source_identity_changes_fail(self):
        descriptor = self.capture()
        seal = self.run / 'review-barrier.json'
        original = seal.read_bytes()
        seal.write_bytes(original + b' ')
        with self.assertRaisesRegex(timepoint.TimepointError, 'review_seal_changed'):
            self.verify(descriptor)
        seal.write_bytes(original)
        state_copy = self.run / 'timepoint-review-state.json'
        state_copy.write_bytes(state_copy.read_bytes() + b' ')
        with self.assertRaisesRegex(timepoint.TimepointError, 'state_changed'):
            self.verify(descriptor)
        state_copy.write_bytes(state_copy.read_bytes()[:-1])
        self.observer.plan['source_tree_sha256'] = '0' * 64
        with self.assertRaisesRegex(timepoint.TimepointError, 'subject_mismatch'):
            self.verify(descriptor)

    def test_dependency_count_and_link_are_rejected(self):
        folder = self.directory / 'answer-reviews'
        for index in range(timepoint.DEPENDENCY_COUNT + 1):
            (folder / f'attempt-{index:064x}.json').write_text('{}')
        with self.assertRaisesRegex(timepoint.TimepointError, 'dependency_budget'):
            self.capture()
        for path in folder.glob('attempt-*.json'):
            path.unlink()
        link = folder / ('capture-' + 'f' * 32 + '.json')
        try:
            link.symlink_to(folder / 'policy.json')
        except OSError:
            self.skipTest('fixture filesystem cannot create symlink')
        with self.assertRaisesRegex(timepoint.TimepointError,
                                    'linked_timepoint_path|unexpected_timepoint_dependency'):
            self.capture()

    def test_final_cold_checks_old_obligations_and_unknown_closure(self):
        old = {'requirements': [{'id': 'Q1', 'status': 'answered'},
                                {'id': 'M1', 'status': 'pending'}],
               'acceptance_items': [{'id': 'A1', 'status': 'pass'}]}
        base = {'question_coverage': 'complete', 'question_current': False,
                'main_ids': ['M1'], 'main_statuses': {'M1': 'pending'},
                'main_current_ids': ['M1'], 'other_current_ids': [],
                'requirements_statuses': {'Q1': 'answered', 'M1': 'pending'},
                'acceptance_statuses': {'A1': 'pass'}}

        def readback(value):
            with mock.patch.object(timepoint.subprocess, 'run', return_value=
                                   subprocess.CompletedProcess([], 0, json.dumps(value), '')):
                return timepoint.final_cold_readback(self.observer, 'Q1', ['M1'], old)

        self.assertEqual(readback(base)['main_closure'], 'unknown')
        completed = {**base, 'main_statuses': {'M1': 'pass'},
                     'requirements_statuses': {'Q1': 'answered', 'M1': 'pass'}}
        self.assertEqual(readback(completed)
                         ['main_closure'], 'completed')
        self.assertEqual(readback({**completed,
                                   'other_current_ids': ['NEW1']})['main_closure'], 'unknown')
        for changed in ({**base, 'requirements_statuses': {'M1': 'pending'}},
                        {**base, 'acceptance_statuses': {'A1': 'pending'}},
                        {**base, 'question_current': True}):
            with self.subTest(changed=changed), self.assertRaises(timepoint.TimepointError):
                readback(changed)


if __name__ == '__main__':
    unittest.main()
