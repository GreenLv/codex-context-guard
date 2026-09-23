"""Observation never manufactures answer coverage, including real Hook entrypoints."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import test_host_terminal_wire as wire

spec = importlib.util.spec_from_file_location('cg_commentary', Path(__file__).resolve().parents[1] / 'scripts/cg_commentary.py')
obs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(obs)


def message(mid='m1', turn='t1', text='Only one of two requested points.', phase='commentary'):
    return {'type': 'event_msg', 'payload': {'type': 'item_completed', 'thread_id': 's1',
            'turn_id': turn, 'started_at_ms': 1, 'completed_at_ms': 2,
            'item': {'type': 'AgentMessage', 'id': mid, 'phase': phase,
                     'content': [{'type': 'Text', 'text': text}]}}}


def raw(*messages):
    rows = [{'type': 'session_meta', 'payload': {'id': 's1', 'session_id': 's1'}}, *messages]
    return ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows).encode()


class CommentaryTests(unittest.TestCase):
    def setUp(self):
        self.roots = [{'id': 'P1', 'turn_id': 't1', 'origin': 'human', 'sha256': 'a'*64,
                       'question_ids': ['R1']}]

    def test_observation_association_coverage_and_closure_are_separate(self):
        for text in ('Both requested points.', 'One point.', 'I will answer later.',
                     'Correction: the previous explanation was wrong.', 'R1 is fully answered.'):
            result = obs.project(raw(message(text=text)), 's1', self.roots)
            row = result['messages'][0]
            self.assertEqual(row['association'], 'unique_root_candidate')
            self.assertEqual(row['question_candidates'], ['R1'])
            self.assertEqual(row['answer_coverage'], 'unknown')
            self.assertEqual(row['execution_closure'], 'unchanged')
            self.assertNotIn(text, json.dumps(result))

    def test_duplicate_order_late_and_correction_never_rebind(self):
        first, correction = message(), message('m2', text='Correction.')
        once = obs.project(raw(first), 's1', self.roots)
        twice = obs.project(raw(first, first), 's1', self.roots)
        self.assertEqual(once['messages'], twice['messages'])
        before = obs.project(raw(first, correction), 's1', self.roots)
        after = obs.project(raw(correction, first), 's1', self.roots)
        self.assertEqual(before['messages'], after['messages'])
        self.assertEqual(len(before['messages']), 2)
        late = obs.project(raw(first), 's1', [{**self.roots[0], 'turn_id': 'new-turn'}])
        self.assertEqual(late['messages'][0]['association'], 'unknown')
        conflict = message(text='Different content with same ID')
        self.assertEqual(obs.project(raw(first, conflict), 's1', self.roots)['status'], 'unknown')

    def test_wrong_source_phase_roots_truncation_and_watermark(self):
        for change in ('thread', 'subagent', 'role', 'time'):
            event = message()
            if change=='thread':
                event['payload']['thread_id']='other'
            if change=='subagent':
                event['payload']['agent_id']='child'
            if change=='role':
                event['payload']['item']['role']='user'
            if change=='time':
                event['payload']['completed_at_ms']=0
            self.assertEqual(obs.project(raw(event), 's1', self.roots)['status'], 'unknown')
        for phase in (None, 'analysis', 'final_answer'):
            row = obs.project(raw(message(phase=phase)), 's1', self.roots)['messages'][0]
            self.assertEqual(row['association'], 'unknown')
        duplicate_roots = self.roots + [{**self.roots[0], 'id': 'P2'}]
        self.assertEqual(obs.project(raw(message()), 's1', duplicate_roots)['messages'][0]['association'], 'unknown')
        self.assertEqual(obs.project(raw(message())[:-1], 's1', self.roots)['status'], 'unknown')
        a, b = message(), message('m2')
        a['ordinal'], b['ordinal'] = 9, 8
        self.assertEqual(obs.project(raw(a,b), 's1', self.roots)['status'], 'unknown')
        self.assertEqual(obs.project(b'{"type":"x","type":"y"}\n', 's1', [])['status'], 'unknown')
        nested = b'[' * 2000 + b'0' + b']' * 2000 + b'\n'
        self.assertEqual(obs.project(nested, 's1', [])['status'], 'unknown')

    def test_precompact_and_resume_read_actual_snapshot_without_closure(self):
        h=wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        h.start('请解释来源绑定和等待条件。')
        # start includes a control root in the same turn; a unique question
        # association must not be invented for this ambiguous native shape.
        event=message(turn=h.turn_id)
        event['payload']['thread_id']=h.session_id
        h.rows.append(event)
        h.write_rows()
        directory=h.root / 'private/sessions' / h.session_id
        original=copy.deepcopy(h.state()['requirements'])
        for kind,extra in [('PreCompact', {}), ('SessionStart', {'source':'compact'}), ('SessionStart', {'source':'resume'})]:
            wire.cg.dispatch(h.event(kind, **extra))
            report=json.loads((directory/'commentary-observation.json').read_text())
            self.assertEqual(report['status'], 'observed')
            self.assertEqual(report['messages'][0]['answer_coverage'], 'unknown')
            self.assertEqual(h.state()['requirements'], original)
        # A new unknown snapshot cannot reuse a convenient earlier observation.
        h.transcript.write_bytes(h.transcript.read_bytes()[:-1])
        wire.cg.dispatch(h.event('PreCompact'))
        self.assertEqual(json.loads((directory/'commentary-observation.json').read_text())['status'], 'unknown')

    def test_reader_rejects_foreign_path_and_unstable_snapshot(self):
        h=wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        self.assertEqual(obs.observe(h.transcript, h.cwd, 's1', [])['status'], 'unknown')
        with patch.object(obs.os, 'fstat') as check:
            check.side_effect = OSError('not readable')
            self.assertEqual(obs.observe(h.transcript, h.home/'sessions', 's1', [])['status'], 'unknown')

    def test_unique_new_root_associates_but_legacy_or_corrupt_root_does_not(self):
        h=wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        wire.cg.dispatch(h.event('UserPromptSubmit', prompt='context-guard on'))
        h.turn_id='question-turn'
        wire.cg.dispatch(h.event('UserPromptSubmit', prompt='Context Guard 是这个插件的名称吗？'))
        event=message(turn=h.turn_id)
        event['payload']['thread_id']=h.session_id
        h.rows.append(event)
        h.write_rows()
        directory=h.root/'private/sessions'/h.session_id
        result=wire.cg.commentary_observation(directory,h.state(),h.event('PreCompact'))
        self.assertEqual(result['messages'][0]['association'],'unique_root_candidate')
        self.assertTrue(result['messages'][0]['question_candidates'])
        legacy=[{**self.roots[0], 'turn_id':None}]
        self.assertEqual(obs.project(raw(message()),'s1',legacy)['messages'][0]['association'],'unknown')
        prompt=directory/h.state()['prompts'][-1]['file']
        prompt.write_text('{}',encoding='utf-8')
        result=wire.cg.commentary_observation(directory,h.state(),h.event('PreCompact'))
        self.assertEqual(result['reason'],'root_integrity_unavailable')

    def test_concurrent_change_and_oversize_are_unknown(self):
        from types import SimpleNamespace
        h=wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        before=h.transcript.stat()
        changed=SimpleNamespace(st_dev=before.st_dev,st_ino=before.st_ino,
                                st_size=before.st_size,st_mtime_ns=before.st_mtime_ns+1)
        with patch.object(obs.os,'fstat',side_effect=[before,changed]):
            self.assertEqual(obs.observe(h.transcript,h.home/'sessions','s1',[])['status'],'unknown')
        with patch.object(obs,'MAX_BYTES',1):
            self.assertEqual(obs.observe(h.transcript,h.home/'sessions','s1',[])['status'],'unknown')
        empty=obs.project(raw(),'s1',[])
        self.assertEqual(empty['reason'],'no_supported_message_events')

    def test_streaming_large_file_and_anchor_mutations(self):
        h=wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        # More than the former total cap, bounded individual records.
        padding=json.dumps({'type':'response_item','payload':{'text':'x'*65536}}).encode()+b'\n'
        with h.transcript.open('wb') as handle:
            handle.write(raw(message()))
            for _ in range(270):
                handle.write(padding)
        result=obs.observe(h.transcript,h.home/'sessions','s1',self.roots)
        self.assertEqual(result['status'],'observed')
        self.assertGreater(result['scanned_bytes'],16*1024*1024)
        anchor={k:result[k] for k in ('file_identity','snapshot_sha256','scanned_bytes')}
        with h.transcript.open('ab') as handle:
            handle.write(json.dumps(message('m2')).encode()+b'\n')
        appended=obs.observe(h.transcript,h.home/'sessions','s1',self.roots,prior=anchor)
        self.assertEqual(len(appended['messages']),2)
        h.transcript.write_bytes(raw(message()))
        self.assertEqual(obs.observe(h.transcript,h.home/'sessions','s1',self.roots,prior=anchor)['reason'],'snapshot_truncated')
        replacement=h.transcript.with_suffix('.replacement')
        replacement.write_bytes(raw(message()))
        replacement.replace(h.transcript)
        self.assertEqual(obs.observe(h.transcript,h.home/'sessions','s1',self.roots,prior=anchor)['reason'],'snapshot_replaced')

    def test_prefix_change_and_earlier_conflict_are_not_hidden_by_tail(self):
        h=wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        h.transcript.write_bytes(raw(message(text='before')))
        result=obs.observe(h.transcript,h.home/'sessions','s1',self.roots)
        anchor={k:result[k] for k in ('file_identity','snapshot_sha256','scanned_bytes')}
        h.transcript.write_bytes(raw(message(text='after!')))
        self.assertEqual(obs.observe(h.transcript,h.home/'sessions','s1',self.roots,prior=anchor)['reason'],'snapshot_prefix_changed')
        h.transcript.write_bytes(raw(message(text='before'),message(text='after!')))
        self.assertEqual(obs.observe(h.transcript,h.home/'sessions','s1',self.roots,prior=anchor)['reason'],'conflicting_message_identity')

    def test_visible_snapshot_is_not_current_coverage_and_invalid_digest_is_unknown(self):
        h=wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        h.start('Context Guard 是这个插件的名称吗？')
        event=message(turn=h.turn_id)
        event['payload']['thread_id']=h.session_id
        h.rows.append(event)
        h.write_rows()
        directory=h.root/'private/sessions'/h.session_id
        wire.cg.dispatch(h.event('PreCompact'))
        state=h.state()
        summary=wire.cg.commentary_summary(directory,state)
        self.assertEqual(summary['recorded_messages'],1)
        self.assertEqual(summary['answer_coverage'],'unknown')
        self.assertIn('Recorded message snapshot',wire.cg.recovery_packet(directory,state))
        self.assertIn('Recorded message snapshot',wire.cg.diagnose_context(state,session_dir=directory))
        self.assertIn('Recorded message snapshot',wire.cg.status_context(state,session_dir=directory))
        status=wire.cg.checkpoint_status_snapshot(state,h.turn_id,session_dir=directory)
        self.assertEqual(status['commentary_observation'],summary)
        with h.transcript.open('ab') as handle:
            handle.write(json.dumps(message('later')).encode()+b'\n')
        self.assertEqual(wire.cg.commentary_summary(directory,state)['freshness'],'source_changed')
        refreshed=wire.cg.checkpoint_status_snapshot(state,h.turn_id,session_dir=directory,
                                                    after_revision=status['revision'])
        self.assertFalse(refreshed.get('unchanged',False))
        report=directory/'commentary-observation.json'
        content=json.loads(report.read_text())
        content['answer_coverage']='complete'
        report.write_text(json.dumps(content),encoding='utf-8')
        self.assertEqual(wire.cg.commentary_summary(directory,state)['status'],'unknown')
        wire.cg.dispatch(h.event('PreCompact'))
        self.assertEqual(wire.cg.commentary_summary(directory,h.state())['status'],'unknown')

    def test_display_limit_keeps_total_and_checks_omitted_identity_conflicts(self):
        messages=[message(f'm{i:04}') for i in range(513)]
        result=obs.project(raw(*messages),'s1',self.roots)
        self.assertEqual(result['status'],'observed')
        self.assertEqual(result['message_count'],513)
        self.assertEqual(len(result['messages']),512)
        self.assertEqual(result['messages_omitted'],1)
        conflict=message('m0000',text='Changed omitted message')
        result=obs.project(raw(*messages,conflict),'s1',self.roots)
        self.assertEqual(result['reason'],'conflicting_message_identity')
        with patch.object(obs,'MAX_MESSAGE_IDENTITIES',2):
            self.assertEqual(obs.project(raw(*messages[:3]),'s1',self.roots)['reason'],'message_limit')

    def test_integrity_anchor_survives_repeated_truncation_reports(self):
        h=wire.HostTerminalWireTests()
        h.setUp()
        self.addCleanup(h.doCleanups)
        h.start('Context Guard 是这个插件的名称吗？')
        event=message(turn=h.turn_id)
        event['payload']['thread_id']=h.session_id
        h.rows.append(event)
        h.write_rows()
        directory=h.root/'private/sessions'/h.session_id
        wire.cg.dispatch(h.event('PreCompact'))
        report=directory/'commentary-observation.json'
        anchor=json.loads(report.read_text())['integrity_anchor']
        h.rows=h.rows[:1]
        h.write_rows()
        for _ in range(2):
            wire.cg.dispatch(h.event('PreCompact'))
            result=json.loads(report.read_text())
            self.assertEqual(result['status'],'unknown')
            self.assertEqual(result['reason'],'snapshot_truncated')
            self.assertEqual(result['integrity_anchor'],anchor)
            self.assertEqual(result['messages'],[])
